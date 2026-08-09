package mipstack

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// ipDefaultReceiveCapacity bounds retained raw payload and metadata per
	// protocol socket.
	ipDefaultReceiveCapacity = 4 * 1024 * 1024
	// ipDatagramMetadataSize accounts for endpoints, header options, and queue
	// storage. Empty payloads must still consume capacity.
	ipDatagramMetadataSize = 96
)

// ipDatagram is one validated, reassembled protocol payload.
type ipDatagram struct {
	payload []byte
	source  netip.Addr
	target  netip.Addr
	options ipPacketOptions
}

// IPInfo is a point-in-time diagnostic snapshot of one IP protocol socket.
// Traffic byte counters measure protocol payload; receive-queue byte values
// also include the stack's per-datagram accounting overhead.
type IPInfo struct {
	// LocalAddress is the bound local address; an unspecified address denotes
	// a wildcard binding.
	LocalAddress netip.Addr
	// RemoteAddress is the connected peer, or an invalid address for an
	// unconnected socket.
	RemoteAddress netip.Addr
	// Protocol is the IANA IP protocol number carried by the socket.
	Protocol uint8
	// Closed reports whether the socket was closed when the snapshot was taken.
	Closed bool
	// ReceiveQueuePackets is the number of complete payloads awaiting a read.
	ReceiveQueuePackets int
	// ReceiveQueueBytes is the accounted payload and metadata retained by the
	// receive queue.
	ReceiveQueueBytes int
	// ReceiveQueueCapacity is the configured accounting-byte limit of the
	// receive queue, not an exact heap-allocation limit.
	ReceiveQueueCapacity int
	// PacketsSent counts successfully emitted protocol payloads.
	PacketsSent uint64
	// BytesSent counts successfully emitted protocol payload bytes.
	BytesSent uint64
	// PacketsReceived counts protocol payloads accepted into the receive queue.
	PacketsReceived uint64
	// BytesReceived counts protocol payload bytes accepted into the receive
	// queue.
	BytesReceived uint64
	// PacketsDropped counts payloads rejected because the socket was closed or
	// its receive queue lacked capacity.
	PacketsDropped uint64
	// ICMPErrors counts matching asynchronous ICMP errors delivered to the
	// socket.
	ICMPErrors uint64
	// PathMTU is the complete-IP-packet PMTU for a connected unicast peer, or
	// zero when no such path exists.
	PathMTU int
	// HopLimit is the default unicast IPv4 TTL or IPv6 Hop Limit.
	HopLimit int
	// MulticastHopLimit is the default multicast IPv4 TTL or IPv6 Hop Limit.
	MulticastHopLimit int
	// MulticastLoopback reports whether transmitted multicast is delivered to
	// matching local memberships.
	MulticastLoopback bool
	// Broadcast reports whether IPv4 broadcast output is permitted.
	Broadcast bool
	// TrafficClass is the default IPv4 TOS or IPv6 Traffic Class byte.
	TrafficClass uint8
	// FlowLabel is the effective IPv6 Flow Label; it is zero for IPv4 sockets.
	FlowLabel uint32
	// LastError is the most recently recorded socket operation or asynchronous
	// network error.
	LastError error
}

// ipKey identifies one specific or wildcard raw protocol binding.
type ipKey struct {
	address  netip.Addr
	protocol byte
}

// ipEndpoints is the optional raw-protocol dispatcher retained by Stack. Its
// concrete implementation is created only by DialIP or ListenIP, allowing raw
// socket parsing, queues, and typed methods to be removed from TCP/UDP-only
// binaries.
type ipEndpoints interface {
	// deliver dispatches one protocol payload to matching raw sockets.
	deliver(stack *Stack, packet ipPacket) bool
	// deliverError dispatches one correlated ICMP error to matching sockets.
	deliverError(stack *Stack, networkError ICMPError) bool
	// updateConfig closes raw sockets invalidated by new network policy.
	updateConfig(stack *Stack, network *networkState)
	// closeAll closes every raw socket retained by the dispatcher.
	closeAll()
}

// ipEndpointState owns raw-protocol fan-out maps. Stack.mu protects them.
type ipEndpointState struct {
	bindings map[ipKey]map[*IPConn]struct{}
}

// IPConn is a connected or unconnected userspace IP protocol socket. It
// exchanges protocol payloads; mipstack owns the IPv4 or IPv6 header.
type IPConn struct {
	stack    *Stack
	net      string
	protocol byte
	v6       bool
	dual     bool
	local    netip.Addr
	remote   netip.Addr

	closed chan struct{}
	once   sync.Once

	mu                sync.Mutex
	receive           datagramQueue[ipDatagram]
	receiveSpare      []byte
	receiveNotify     chan struct{}
	receiveCapacity   int
	queuedBytes       int
	readDeadline      socketDeadline
	writeDeadline     socketDeadline
	errors            chan error
	recentTargets     recentDestinationCache[netip.Addr]
	defaultOptions    ipPacketOptions
	multicastHopLimit byte
	multicastLoopback bool
	broadcast         bool
	lastError         error
	packetsSent       atomic.Uint64
	bytesSent         atomic.Uint64
	packetsReceived   atomic.Uint64
	bytesReceived     atomic.Uint64
	packetsDropped    atomic.Uint64
	icmpErrors        atomic.Uint64
}

// ListenIP creates an unconnected IPv4 or IPv6 protocol socket. Network must
// be an IP network with a numeric or well-known protocol, such as ip4:icmp or
// ip:99. An empty Local selects the network's wildcard address; a generic ip
// wildcard is dual-stack when both address families are configured.
func (s *Stack) ListenIP(ctx context.Context, network string, local netip.Addr) (*IPConn, error) {
	local = local.Unmap()
	target := ipNetAddr(local)
	wrap := func(err error) (*IPConn, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	protocol, err := parseIPNetwork(network, local)
	if err != nil {
		return wrap(err)
	}
	if local.IsValid() && (local.IsMulticast() || local.Zone() != "") {
		return wrap(errors.New("mipstack: invalid IP listen address"))
	}
	if local.IsValid() && !local.IsUnspecified() && !s.isLocal(local) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	if err := ctx.Err(); err != nil {
		return wrap(err)
	}
	if err := s.ready(); err != nil {
		return wrap(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wrap(ErrClosed)
	}
	state := s.network.Load()
	family := network[:strings.LastIndexByte(network, ':')]
	local, dual, err := listenAddress(state, family, "ip", local)
	if err != nil {
		return wrap(err)
	}
	if !local.IsUnspecified() && !networkStateHasLocal(state, local) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	connection := newIPConn(s, network, protocol, local, netip.Addr{})
	connection.dual = dual
	s.ipEndpointStateLocked().register(connection)
	s.stats.activeIPSockets.Add(1)
	return connection, nil
}

// DialIP creates a connected IPv4 or IPv6 protocol socket. Network must be an
// IP network with a numeric or well-known protocol, such as ip6:ipv6-icmp or
// ip:99. An invalid or unspecified source selects a managed address using the
// route table.
func (s *Stack) DialIP(ctx context.Context, network string, source, remote netip.Addr) (net.Conn, error) {
	remote = remote.Unmap()
	target := ipNetAddr(remote)
	wrap := func(local net.Addr, err error) (net.Conn, error) {
		return nil, socketOperationError("dial", network, local, target, err)
	}
	protocol, err := parseIPNetwork(network, remote)
	if err != nil {
		return wrap(nil, err)
	}
	if !remote.IsValid() || remote.IsUnspecified() || remote.Zone() != "" {
		return wrap(nil, errors.New("mipstack: invalid IP destination"))
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	if err := s.ready(); err != nil {
		return wrap(nil, err)
	}
	source = source.Unmap()
	if source.IsValid() && source.Zone() != "" {
		return wrap(nil, syscall.EINVAL)
	}
	family := network[:strings.LastIndexByte(network, ':')]
	if source.IsValid() && source.IsUnspecified() && source.Is6() != remote.Is6() && family != "ip" {
		addressFamily := "IPv6"
		if remote.Is4() {
			addressFamily = "IPv4"
		}
		return wrap(ipNetAddr(source), &net.AddrError{Err: "non-" + addressFamily + " address", Addr: source.String()})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wrap(nil, ErrClosed)
	}
	local, err := s.sourceForRequested(remote, source)
	if err != nil {
		return wrap(ipNetAddr(source), err)
	}
	connection := newIPConn(s, network, protocol, local, remote)
	s.ipEndpointStateLocked().register(connection)
	s.stats.activeIPSockets.Add(1)
	return connection, nil
}

// parseIPNetwork implements the numeric netip DialIP network form introduced
// by the net package without requiring a newer Go toolchain at build time.
func parseIPNetwork(network string, address netip.Addr) (byte, error) {
	separator := strings.LastIndexByte(network, ':')
	if separator < 0 {
		return 0, net.UnknownNetworkError(network)
	}
	family, protocolName := network[:separator], network[separator+1:]
	switch family {
	case "ip":
	case "ip4":
		if address.IsValid() && address.Is6() {
			return 0, syscall.EAFNOSUPPORT
		}
	case "ip6":
		if address.IsValid() && address.Is4() {
			return 0, syscall.EAFNOSUPPORT
		}
	default:
		return 0, net.UnknownNetworkError(network)
	}
	var protocol byte
	switch strings.ToLower(protocolName) {
	case "icmp":
		protocol = protocolICMPv4
	case "igmp":
		protocol = 2
	case "tcp":
		protocol = protocolTCP
	case "udp":
		protocol = protocolUDP
	case "ipv6-icmp":
		protocol = protocolICMPv6
	default:
		for _, character := range protocolName {
			if character < '0' || character > '9' {
				return 0, &net.AddrError{Err: "unknown IP protocol specified", Addr: protocolName}
			}
		}
		value, err := strconv.ParseUint(protocolName, 10, 8)
		if err != nil {
			return 0, &net.AddrError{Err: "unknown IP protocol specified", Addr: protocolName}
		}
		protocol = byte(value)
	}
	if err := validateIPProtocol(protocol); err != nil {
		return 0, err
	}
	return protocol, nil
}

// validateIPProtocol rejects values that cannot identify a payload header.
func validateIPProtocol(protocol byte) error {
	if protocol == 0 {
		return errors.New("mipstack: invalid IP protocol")
	}
	return nil
}

// newIPConn allocates one unregistered protocol socket.
func newIPConn(stack *Stack, network string, protocol byte, local, remote netip.Addr) *IPConn {
	defaults := DatagramSocketDefaults{ReceiveBuffer: ipDefaultReceiveCapacity, HopLimit: 64, MulticastHopLimit: 1}
	if stack != nil {
		defaults = stack.network.Load().ipDefaults
	}
	connection := &IPConn{
		stack: stack, net: network, protocol: protocol, v6: local.Is6(), local: local, remote: remote,
		closed: make(chan struct{}), receiveNotify: make(chan struct{}, 1), receiveCapacity: defaults.ReceiveBuffer,
		errors: make(chan error, 8),
		defaultOptions: ipPacketOptions{
			hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
			flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
		},
		multicastHopLimit: byte(defaults.MulticastHopLimit), multicastLoopback: !defaults.DisableMulticastLoopback,
		broadcast: !defaults.DisableBroadcast,
	}
	return connection
}

// ipEndpointStateLocked returns the lazily allocated raw dispatcher while
// Stack.mu is held.
func (s *Stack) ipEndpointStateLocked() *ipEndpointState {
	if s.ip == nil {
		state := &ipEndpointState{bindings: make(map[ipKey]map[*IPConn]struct{})}
		s.ip = state
		return state
	}
	return s.ip.(*ipEndpointState)
}

// register adds a connection to protocol fan-out while Stack.mu is held.
func (state *ipEndpointState) register(connection *IPConn) {
	key := ipKey{address: connection.local, protocol: connection.protocol}
	bindings := state.bindings[key]
	if bindings == nil {
		bindings = make(map[*IPConn]struct{})
		state.bindings[key] = bindings
	}
	bindings[connection] = struct{}{}
}

// deliver copies a valid protocol payload to every matching raw socket. It
// reports a consumer even when that socket's bounded queue drops the payload.
func (state *ipEndpointState) deliver(stack *Stack, packet ipPacket) bool {
	stack.mu.RLock()
	if stack.ip != state {
		stack.mu.RUnlock()
		return false
	}
	connections := state.connectionsForLocked(packet.target, packet.protocol)
	stack.mu.RUnlock()
	accepted := false
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	for _, connection := range connections {
		if connection.remote.IsValid() && connection.remote != packet.source {
			continue
		}
		accepted = true
		connection.enqueue(packet.payload, packet.source, packet.target, options)
	}
	return accepted
}

// connectionsForLocked returns exact, family-wildcard, and dual-stack raw
// bindings while Stack.mu is held.
func (state *ipEndpointState) connectionsForLocked(address netip.Addr, protocol byte) []*IPConn {
	connections := make([]*IPConn, 0)
	for connection := range state.bindings[ipKey{address: address, protocol: protocol}] {
		connections = append(connections, connection)
	}
	wildcard := netip.IPv4Unspecified()
	if address.Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	for connection := range state.bindings[ipKey{address: wildcard, protocol: protocol}] {
		connections = append(connections, connection)
	}
	if address.Is4() {
		for connection := range state.bindings[ipKey{address: netip.IPv6Unspecified(), protocol: protocol}] {
			if connection.dual {
				connections = append(connections, connection)
			}
		}
	}
	return connections
}

// deliverError correlates an ICMP quote with recent writes by matching raw
// protocol sockets before it changes shared path state.
func (state *ipEndpointState) deliverError(stack *Stack, networkError ICMPError) bool {
	stack.mu.RLock()
	if stack.ip != state {
		stack.mu.RUnlock()
		return false
	}
	connections := state.connectionsForLocked(networkError.QuotedSource, networkError.QuotedProtocol)
	stack.mu.RUnlock()
	accepted := false
	networkError.QuotedPayload = append([]byte(nil), networkError.QuotedPayload...)
	for _, connection := range connections {
		if !connection.acceptsError(networkError.QuotedTarget) {
			continue
		}
		accepted = true
		connection.deliverError(networkError.QuotedTarget, networkError)
	}
	if accepted && networkError.MTU != 0 && stack.observePathMTU(networkError.QuotedTarget, networkError.MTU) {
		stack.notifyTCPPathMTU(networkError.QuotedTarget, nil)
	}
	return accepted
}

// empty reports whether no raw protocol bindings remain.
func (state *ipEndpointState) empty() bool { return len(state.bindings) == 0 }

// connections returns all raw sockets while Stack.mu is held.
func (state *ipEndpointState) connections() []*IPConn {
	var connections []*IPConn
	for _, bindings := range state.bindings {
		for connection := range bindings {
			connections = append(connections, connection)
		}
	}
	return connections
}

// updateConfig closes raw sockets whose binding or route was removed.
func (state *ipEndpointState) updateConfig(stack *Stack, network *networkState) {
	stack.mu.RLock()
	if stack.ip != state {
		stack.mu.RUnlock()
		return
	}
	connections := state.connections()
	stack.mu.RUnlock()
	for _, connection := range connections {
		if connection.dual && !networkStateHasFamily(network, false) && !networkStateHasFamily(network, true) ||
			!connection.dual && connection.local.IsUnspecified() && !networkStateHasFamily(network, connection.v6) ||
			!connection.local.IsUnspecified() && !networkStateHasLocal(network, connection.local) {
			stack.closeIP(connection)
			continue
		}
		if connection.remote.IsValid() {
			if !network.hasOutputPath(connection.remote) {
				stack.closeIP(connection)
			}
		}
	}
}

// closeAll publishes stack closure to every socket in a detached raw
// dispatcher.
func (state *ipEndpointState) closeAll() {
	connections := state.connections()
	state.bindings = nil
	for _, connection := range connections {
		connection.closeFromStack()
	}
}

// remove unregisters a raw socket while Stack.mu is held.
func (state *ipEndpointState) remove(connection *IPConn) bool {
	key := ipKey{address: connection.local, protocol: connection.protocol}
	bindings := state.bindings[key]
	if _, exists := bindings[connection]; !exists {
		return false
	}
	delete(bindings, connection)
	if len(bindings) == 0 {
		delete(state.bindings, key)
	}
	return true
}

// enqueue copies one payload unless the configured receive capacity is full.
func (c *IPConn) enqueue(payload []byte, source, target netip.Addr, options ipPacketOptions) {
	size := ipDatagramMetadataSize + len(payload)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		c.stack.stats.inboundDroppedPackets.Add(1)
		c.packetsDropped.Add(1)
		return
	default:
	}
	if size > c.receiveCapacity || c.queuedBytes > c.receiveCapacity-size {
		c.mu.Unlock()
		c.stack.stats.inboundDroppedPackets.Add(1)
		c.packetsDropped.Add(1)
		return
	}
	var retained []byte
	if len(payload) != 0 {
		if cap(c.receiveSpare) >= len(payload) {
			retained = c.receiveSpare[:len(payload)]
			c.receiveSpare = nil
			copy(retained, payload)
		} else {
			retained = append([]byte(nil), payload...)
		}
	}
	datagram := ipDatagram{payload: retained, source: source, target: target, options: options}
	c.receive.push(datagram)
	c.queuedBytes += size
	c.packetsReceived.Add(1)
	c.bytesReceived.Add(uint64(len(payload)))
	c.notifyReceiveLocked()
	c.mu.Unlock()
}

// notifyReceiveLocked keeps one edge notification armed while queued data
// remains and removes a stale token when the queue becomes empty.
func (c *IPConn) notifyReceiveLocked() {
	if c.receive.len() != 0 {
		select {
		case c.receiveNotify <- struct{}{}:
		default:
		}
		return
	}
	select {
	case <-c.receiveNotify:
	default:
	}
}

// ReadFrom implements net.PacketConn.
func (c *IPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, datagram, _, err := c.readDatagram(buffer)
	address := ipNetAddr(datagram.source)
	if err != nil {
		return n, address, c.operationError("read", err)
	}
	return n, address, nil
}

// ReadFromIP acts like ReadFrom but returns an IPAddr.
func (c *IPConn) ReadFromIP(buffer []byte) (int, *net.IPAddr, error) {
	n, datagram, _, err := c.readDatagram(buffer)
	address := ipNetAddr(datagram.source)
	if err != nil {
		return n, address, c.operationError("read", err)
	}
	return n, address, nil
}

// ReadMsgIP reads one protocol payload and Linux-compatible packet info,
// hop-limit, and traffic-class ancillary data.
func (c *IPConn) ReadMsgIP(buffer, oob []byte) (n, oobn, flags int, address *net.IPAddr, err error) {
	var datagram ipDatagram
	var truncated bool
	n, datagram, truncated, err = c.readDatagram(buffer)
	address = ipNetAddr(datagram.source)
	if truncated {
		flags |= linuxMessageTruncated
	}
	if err != nil {
		err = c.operationError("read", err)
		return
	}
	control, controlErr := controlMessageForRead(datagram.target, datagram.options)
	if controlErr != nil {
		err = c.operationError("read", controlErr)
		return
	}
	oobn = copy(oob, control)
	if oobn < len(control) {
		flags |= linuxMessageControlTruncated
	}
	return
}

// Read receives from a connected remote endpoint.
func (c *IPConn) Read(buffer []byte) (int, error) {
	n, _, _, err := c.readDatagram(buffer)
	if err != nil {
		return n, c.operationError("read", err)
	}
	return n, nil
}

// readDatagram returns one payload without adding the public operation wrapper.
func (c *IPConn) readDatagram(buffer []byte) (n int, datagram ipDatagram, truncated bool, err error) {
	for {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, net.ErrClosed
		default:
		}
		timeout := c.readDeadline.wait()
		select {
		case <-timeout:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		default:
		}
		if queued, ok := c.receive.pop(); ok {
			datagram = queued
			c.queuedBytes -= ipDatagramMetadataSize + len(datagram.payload)
			c.notifyReceiveLocked()
			c.mu.Unlock()
			n = copy(buffer, datagram.payload)
			if cap(datagram.payload) != 0 && cap(datagram.payload) <= datagramReusablePayloadLimit {
				c.mu.Lock()
				select {
				case <-c.closed:
				default:
					if cap(datagram.payload) > cap(c.receiveSpare) {
						c.receiveSpare = datagram.payload[:0]
					}
				}
				c.mu.Unlock()
			}
			return n, datagram, n < len(datagram.payload), nil
		}
		notified := c.receiveNotify
		c.mu.Unlock()
		select {
		case <-notified:
		case err = <-c.errors:
			return 0, ipDatagram{}, false, err
		case <-timeout:
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, ipDatagram{}, false, net.ErrClosed
		}
	}
}

// WriteTo sends one payload to an unconnected destination.
func (c *IPConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	ipAddress, ok := address.(*net.IPAddr)
	if !ok {
		return 0, c.operationErrorTo("write", address, syscall.EINVAL)
	}
	return c.WriteToIP(payload, ipAddress)
}

// WriteToIP acts like WriteTo but accepts an IPAddr directly.
func (c *IPConn) WriteToIP(payload []byte, address *net.IPAddr) (int, error) {
	netAddress := ipAddrNet(address)
	if c.remote.IsValid() {
		return 0, c.operationErrorTo("write", netAddress, net.ErrWriteToConnected)
	}
	target, err := ipAddr(address)
	if err != nil {
		return 0, c.operationErrorTo("write", netAddress, err)
	}
	n, err := c.writeTo(payload, target, netip.Addr{}, ipPacketOptions{})
	if err != nil {
		return n, c.operationErrorTo("write", netAddress, err)
	}
	return n, nil
}

// Write sends one payload to the connected endpoint.
func (c *IPConn) Write(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", errors.New("mipstack: IP socket is not connected"))
	}
	n, err := c.writeTo(payload, c.remote, netip.Addr{}, ipPacketOptions{})
	if err != nil {
		return n, c.operationError("write", err)
	}
	return n, nil
}

// WritePathMTUProbe sends one connected protocol payload without IPv4 or
// IPv6 source fragmentation. The complete packet may exceed the confirmed
// PMTU but cannot exceed the first-hop MTU.
func (c *IPConn) WritePathMTUProbe(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", errors.New("mipstack: IP socket is not connected"))
	}
	if c.remote.IsMulticast() || c.stack.network.Load().broadcastDestination(c.remote) {
		return 0, c.operationError("write", syscall.EOPNOTSUPP)
	}
	n, err := c.writeToWith(payload, c.remote, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbePayload)
	if err != nil {
		return n, c.operationError("write", err)
	}
	return n, nil
}

// WritePathMTUProbeTo is the unconnected netip form of WritePathMTUProbe.
func (c *IPConn) WritePathMTUProbeTo(payload []byte, target netip.Addr) (int, error) {
	if c.remote.IsValid() {
		return 0, c.operationErrorTo("write", ipNetAddr(target), net.ErrWriteToConnected)
	}
	if target.IsMulticast() || c.stack.network.Load().broadcastDestination(target) {
		return 0, c.operationErrorTo("write", ipNetAddr(target), syscall.EOPNOTSUPP)
	}
	n, err := c.writeToWith(payload, target, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbePayload)
	if err != nil {
		return n, c.operationErrorTo("write", ipNetAddr(target), err)
	}
	return n, nil
}

// ConfirmPathMTU records application-level acknowledgement of a connected
// protocol probe. mtu is the complete IP packet size, not the payload size.
func (c *IPConn) ConfirmPathMTU(mtu int) error {
	if !c.remote.IsValid() {
		return c.operationError("set", errors.New("mipstack: IP socket is not connected"))
	}
	if err := c.stack.ConfirmPathMTU(c.remote, mtu); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

// ConfirmPathMTUFor is the unconnected form of ConfirmPathMTU.
func (c *IPConn) ConfirmPathMTUFor(target netip.Addr, mtu int) error {
	if c.remote.IsValid() {
		return c.setOperationError(net.ErrWriteToConnected)
	}
	if err := c.stack.ConfirmPathMTU(target, mtu); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

// WriteMsgIP writes one payload with Linux-compatible source, hop-limit, and
// traffic-class ancillary data. Like net.IPConn, it requires an unconnected
// socket and a non-nil destination.
func (c *IPConn) WriteMsgIP(payload, oob []byte, address *net.IPAddr) (n, oobn int, err error) {
	netAddress := ipAddrNet(address)
	if c.remote.IsValid() {
		return 0, 0, c.operationErrorTo("write", netAddress, net.ErrWriteToConnected)
	}
	target, err := ipAddr(address)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	target, err = c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	// Match net.IPConn: destination conversion precedes poll state, while an
	// expired deadline or closed descriptor precedes ancillary-data parsing.
	if err = (socketWriteState{deadline: &c.writeDeadline, closed: c.closed}).err(); err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	source, options, err := parseControlMessageForWrite(oob, target.Is6())
	if err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	n, err = c.writeTo(payload, target, source, options)
	if err != nil {
		return n, 0, c.operationErrorTo("write", netAddress, err)
	}
	return n, len(oob), nil
}

// writeTo selects a source, repairs ICMPv6 checksum, and emits one ordinary
// fragmentable payload.
func (c *IPConn) writeTo(payload []byte, target netip.Addr, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	return c.writeToWith(payload, target, packetInfoSource, options, c.writePayload)
}

// writeToWith keeps routing, checksums, deadlines, accounting, and ICMP
// correlation shared between ordinary writes and PLPMTUD probes.
func (c *IPConn) writeToWith(payload []byte, target netip.Addr, packetInfoSource netip.Addr, options ipPacketOptions, write func(netip.Addr, netip.Addr, []byte, ipPacketOptions, bool) error) (int, error) {
	var err error
	target, err = c.validateWriteTarget(target)
	if err != nil {
		return 0, err
	}
	state, options := c.writeStateAndOptions(options)
	if err := state.err(); err != nil {
		return 0, err
	}
	requestedSource := c.local
	packetInfoSource = packetInfoSource.Unmap()
	if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() {
		if !c.local.IsUnspecified() && packetInfoSource != c.local {
			return 0, syscall.EADDRNOTAVAIL
		}
		requestedSource = packetInfoSource
	}
	source, nonUnicast, err := c.stack.sourceForOutput(target, requestedSource)
	if err != nil {
		return 0, err
	}
	if c.protocol == protocolICMPv6 && len(payload) >= 4 {
		payload = append([]byte(nil), payload...)
		payload[2], payload[3] = 0, 0
		binary.BigEndian.PutUint16(payload[2:4], transportChecksum(source, target, protocolICMPv6, payload))
	}
	if err = write(source, target, payload, options, nonUnicast); err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, err
	}
	if !nonUnicast {
		c.rememberTarget(target)
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(payload)))
	return len(payload), nil
}

// writePayload emits ordinary output against the confirmed path MTU and
// permits source fragmentation.
func (c *IPConn) writePayload(source, target netip.Addr, payload []byte, options ipPacketOptions, nonUnicast bool) error {
	if nonUnicast {
		return c.writeNonUnicastPayload(source, target, payload, options)
	}
	state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed}
	return c.stack.writeIPPayloadUntilOptions(source, target, c.protocol, payload, true, options, state)
}

// writePathMTUProbePayload emits explicitly unfragmented output against the
// first-hop MTU.
func (c *IPConn) writePathMTUProbePayload(source, target netip.Addr, payload []byte, options ipPacketOptions, _ bool) error {
	state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed}
	return c.stack.writeIPPayloadUntilOptionsForMTU(source, target, c.protocol, payload, false, options, c.stack.network.Load().mtu, state)
}

// Close unregisters the protocol socket and wakes blocked operations.
func (c *IPConn) Close() error {
	if c.stack.closeIP(c) {
		return nil
	}
	return c.operationError("close", net.ErrClosed)
}

// closeFromStack publishes closure and releases payload-bearing and
// error-correlation state.
func (c *IPConn) closeFromStack() {
	c.once.Do(func() {
		c.mu.Lock()
		c.readDeadline.stop()
		c.writeDeadline.stop()
		c.receive.clear()
		c.receiveSpare = nil
		c.queuedBytes = 0
		c.recentTargets = nil
		c.lastError = nil
	drainErrors:
		for {
			select {
			case <-c.errors:
			default:
				break drainErrors
			}
		}
		close(c.closed)
		c.mu.Unlock()
	})
}

// LocalAddr returns the bound protocol address.
func (c *IPConn) LocalAddr() net.Addr { return ipNetAddr(c.local) }

// RemoteAddr returns the connected peer, or nil for an unconnected socket.
func (c *IPConn) RemoteAddr() net.Addr { return c.remoteAddr() }

// Info returns a diagnostic snapshot of the protocol socket and its receive
// queue.
func (c *IPConn) Info() IPInfo {
	c.mu.Lock()
	flowLabel := c.defaultOptions.flowLabel
	if !c.v6 && !c.dual {
		flowLabel = 0
	}
	info := IPInfo{
		LocalAddress: c.local, RemoteAddress: c.remote, Protocol: c.protocol,
		ReceiveQueuePackets: c.receive.len(), ReceiveQueueBytes: c.queuedBytes, ReceiveQueueCapacity: c.receiveCapacity,
		HopLimit: int(c.defaultOptions.hopLimit), TrafficClass: c.defaultOptions.trafficClass,
		MulticastHopLimit: int(c.multicastHopLimit), MulticastLoopback: c.multicastLoopback, Broadcast: c.broadcast,
		FlowLabel: flowLabel,
		LastError: c.lastError,
	}
	select {
	case <-c.closed:
		info.Closed = true
	default:
	}
	c.mu.Unlock()
	info.PacketsSent, info.BytesSent = c.packetsSent.Load(), c.bytesSent.Load()
	info.PacketsReceived, info.BytesReceived = c.packetsReceived.Load(), c.bytesReceived.Load()
	info.PacketsDropped, info.ICMPErrors = c.packetsDropped.Load(), c.icmpErrors.Load()
	if c.remote.IsValid() && !c.remote.IsMulticast() && !c.stack.network.Load().broadcastDestination(c.remote) {
		info.PathMTU = c.stack.mtuFor(c.remote)
	}
	return info
}

// remoteAddr returns the connected peer without wrapping a nil pointer in a
// non-nil net.Addr interface.
func (c *IPConn) remoteAddr() net.Addr {
	if !c.remote.IsValid() {
		return nil
	}
	return ipNetAddr(c.remote)
}

// SetDeadline updates both read and write deadlines.
func (c *IPConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
	}
	c.readDeadline.set(deadline)
	c.writeDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

// SetReadDeadline updates pending and future reads.
func (c *IPConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
	}
	c.readDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline updates pending and future writes.
func (c *IPConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
	}
	c.writeDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

// SetReadBuffer changes the approximate retained-memory receive capacity.
func (c *IPConn) SetReadBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	if bytes < ipDatagramMetadataSize {
		bytes = ipDatagramMetadataSize
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
	}
	c.receiveCapacity = bytes
	c.mu.Unlock()
	return nil
}

// SetWriteBuffer is a validated no-op because writes are synchronously handed
// to the embedding packet device.
func (c *IPConn) SetWriteBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
		c.mu.Unlock()
		return nil
	}
}

// SetHopLimit changes the default IPv4 TTL or IPv6 Hop Limit for subsequent
// writes. Zero is valid only on a dedicated IPv6 socket; it is ambiguous on a
// dual-stack socket because IPv4 TTL zero is invalid. Per-packet message
// control data may override the value.
func (c *IPConn) SetHopLimit(hopLimit int) error {
	if hopLimit < 0 || hopLimit > 255 || hopLimit == 0 && (!c.v6 || c.dual) {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
		c.defaultOptions.hopLimit, c.defaultOptions.hopLimitSet = byte(hopLimit), true
		c.mu.Unlock()
		return nil
	}
}

// SetTrafficClass changes the default IPv4 TOS or IPv6 Traffic Class byte.
func (c *IPConn) SetTrafficClass(value int) error {
	if value < 0 || value > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
		c.defaultOptions.trafficClass = byte(value)
		c.mu.Unlock()
		return nil
	}
}

// SetFlowLabel changes the default IPv6 Flow Label. Zero explicitly disables
// automatic labeling for this socket.
func (c *IPConn) SetFlowLabel(label uint32) error {
	if label > ipv6MaximumFlowLabel {
		return c.setOperationError(syscall.EINVAL)
	}
	if !c.v6 && !c.dual {
		return c.setOperationError(syscall.EAFNOSUPPORT)
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	default:
		c.defaultOptions.flowLabel, c.defaultOptions.flowLabelSet = label, true
		c.mu.Unlock()
		return nil
	}
}

// rememberTarget records a successful write for later ICMP quote validation.
func (c *IPConn) rememberTarget(target netip.Addr) {
	target = target.Unmap()
	if c.remote.IsValid() {
		return
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	c.recentTargets.remember(target, time.Now())
	c.mu.Unlock()
}

// acceptsError reports whether ICMP quoted a recent write to target.
func (c *IPConn) acceptsError(target netip.Addr) bool {
	target = target.Unmap()
	if c.remote.IsValid() {
		return target == c.remote
	}
	c.mu.Lock()
	exists := c.recentTargets.contains(target, time.Now())
	c.mu.Unlock()
	return exists
}

// deliverError queues one correlated asynchronous network error.
func (c *IPConn) deliverError(target netip.Addr, err error) {
	operationError := &net.OpError{
		Op: "read", Net: c.net, Source: c.LocalAddr(), Addr: ipNetAddr(target), Err: err,
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	c.lastError = operationError
	select {
	case c.errors <- operationError:
	default:
	}
	c.mu.Unlock()
	c.icmpErrors.Add(1)
}

// writeStateAndOptions reads the output defaults and returns the independent
// deadline and close signals observed by a blocked host-queue write.
func (c *IPConn) writeStateAndOptions(options ipPacketOptions) (socketWriteState, ipPacketOptions) {
	c.mu.Lock()
	options = options.withDefaults(c.defaultOptions)
	c.mu.Unlock()
	return socketWriteState{deadline: &c.writeDeadline, closed: c.closed}, options
}

// operationError wraps an error for the bound or connected socket.
func (c *IPConn) operationError(operation string, err error) error {
	return socketOperationError(operation, c.net, c.LocalAddr(), c.remoteAddr(), err)
}

// operationErrorTo wraps an error for one explicit destination.
func (c *IPConn) operationErrorTo(operation string, target net.Addr, err error) error {
	return socketOperationError(operation, c.net, c.LocalAddr(), target, err)
}

// setOperationError uses standard deadline and socket-option metadata.
func (c *IPConn) setOperationError(err error) error {
	return socketOperationError("set", c.net, nil, c.LocalAddr(), err)
}

// ipNetAddr converts a valid address to IPAddr and preserves nil for no peer.
func ipNetAddr(address netip.Addr) *net.IPAddr {
	if !address.IsValid() {
		return nil
	}
	return &net.IPAddr{IP: net.IP(address.AsSlice()), Zone: address.Zone()}
}

// ipAddrNet avoids storing a typed nil pointer in net.OpError.Addr.
func ipAddrNet(address *net.IPAddr) net.Addr {
	if address == nil {
		return nil
	}
	return address
}

// ipAddr converts an IPAddr without name resolution.
func ipAddr(address *net.IPAddr) (netip.Addr, error) {
	if address == nil || address.Zone != "" {
		return netip.Addr{}, syscall.EINVAL
	}
	result, ok := netip.AddrFromSlice(address.IP)
	if !ok {
		return netip.Addr{}, syscall.EINVAL
	}
	result = result.Unmap()
	if !result.IsValid() || result.IsUnspecified() {
		return netip.Addr{}, syscall.EINVAL
	}
	return result, nil
}

// validateWriteTarget normalizes one raw-IP destination and mirrors net's
// address-family conversion before deadline and ancillary-data processing.
func (c *IPConn) validateWriteTarget(target netip.Addr) (netip.Addr, error) {
	target = target.Unmap()
	if !target.IsValid() || target.IsUnspecified() || target.Zone() != "" {
		return netip.Addr{}, syscall.EINVAL
	}
	if !c.dual && target.Is6() != c.v6 {
		family := "IPv4"
		if c.v6 {
			family = "IPv6"
		}
		return netip.Addr{}, &net.AddrError{Err: "non-" + family + " address", Addr: target.String()}
	}
	return target, nil
}

// Verify the standard connection interfaces implemented without an OS fd.
var _ net.Conn = (*IPConn)(nil)
var _ net.PacketConn = (*IPConn)(nil)
