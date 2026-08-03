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
	deliver(stack *Stack, packet ipPacket) bool
	updateConfig(stack *Stack, network *networkState)
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

	mu              sync.Mutex
	receive         []ipDatagram
	receiveNotify   chan struct{}
	receiveCapacity int
	queuedBytes     int
	readDeadline    time.Time
	writeDeadline   time.Time
	readChanged     chan struct{}
	writeChanged    chan struct{}
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
	if !remote.IsValid() || remote.IsUnspecified() || remote.IsMulticast() || remote.Zone() != "" {
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
	return &IPConn{
		stack: stack, net: network, protocol: protocol, v6: local.Is6(), local: local, remote: remote,
		closed: make(chan struct{}), receiveNotify: make(chan struct{}), receiveCapacity: ipDefaultReceiveCapacity,
		readChanged: make(chan struct{}), writeChanged: make(chan struct{}),
	}
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
	connections := make([]*IPConn, 0)
	for connection := range state.bindings[ipKey{address: packet.target, protocol: packet.protocol}] {
		connections = append(connections, connection)
	}
	wildcard := netip.IPv4Unspecified()
	if packet.target.Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	for connection := range state.bindings[ipKey{address: wildcard, protocol: packet.protocol}] {
		connections = append(connections, connection)
	}
	if packet.target.Is4() {
		for connection := range state.bindings[ipKey{address: netip.IPv6Unspecified(), protocol: packet.protocol}] {
			if connection.dual {
				connections = append(connections, connection)
			}
		}
	}
	stack.mu.RUnlock()
	accepted := false
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass}
	for _, connection := range connections {
		if connection.remote.IsValid() && connection.remote != packet.source {
			continue
		}
		accepted = true
		connection.enqueue(packet.payload, packet.source, packet.target, options)
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
			if _, routed := network.routeFor(connection.remote); !routed {
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
		return
	default:
	}
	if size > c.receiveCapacity || c.queuedBytes > c.receiveCapacity-size {
		c.mu.Unlock()
		c.stack.stats.inboundDroppedPackets.Add(1)
		return
	}
	datagram := ipDatagram{payload: append([]byte(nil), payload...), source: source, target: target, options: options}
	wasEmpty := len(c.receive) == 0
	c.receive = append(c.receive, datagram)
	c.queuedBytes += size
	if wasEmpty {
		notified := c.receiveNotify
		c.receiveNotify = make(chan struct{})
		close(notified)
	}
	c.mu.Unlock()
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
		if len(c.receive) != 0 {
			datagram = c.receive[0]
			c.receive[0] = ipDatagram{}
			c.receive = c.receive[1:]
			if len(c.receive) == 0 {
				c.receive = nil
			}
			c.queuedBytes -= ipDatagramMetadataSize + len(datagram.payload)
			c.mu.Unlock()
			n = copy(buffer, datagram.payload)
			return n, datagram, n < len(datagram.payload), nil
		}
		deadline, changed, notified := c.readDeadline, c.readChanged, c.receiveNotify
		c.mu.Unlock()
		timer, timeout := deadlineTimer(deadline)
		select {
		case <-notified:
			stopTimer(timer)
		case <-timeout:
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		case <-changed:
			stopTimer(timer)
		case <-c.closed:
			stopTimer(timer)
			return 0, ipDatagram{}, false, net.ErrClosed
		}
	}
}

// WriteTo sends one payload to an unconnected destination.
func (c *IPConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	ipAddress, ok := address.(*net.IPAddr)
	if !ok || ipAddress == nil {
		return 0, c.operationErrorTo("write", address, syscall.EINVAL)
	}
	return c.WriteToIP(payload, ipAddress)
}

// WriteToIP acts like WriteTo but accepts an IPAddr directly.
func (c *IPConn) WriteToIP(payload []byte, address *net.IPAddr) (int, error) {
	target, err := ipAddr(address)
	if err != nil {
		return 0, c.operationErrorTo("write", address, err)
	}
	if c.remote.IsValid() {
		return 0, c.operationErrorTo("write", address, net.ErrWriteToConnected)
	}
	n, err := c.writeTo(payload, target, address, netip.Addr{}, ipPacketOptions{})
	if err != nil {
		return n, c.operationErrorTo("write", address, err)
	}
	return n, nil
}

// Write sends one payload to the connected endpoint.
func (c *IPConn) Write(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", errors.New("mipstack: IP socket is not connected"))
	}
	n, err := c.writeTo(payload, c.remote, c.remoteAddr(), netip.Addr{}, ipPacketOptions{})
	if err != nil {
		return n, c.operationError("write", err)
	}
	return n, nil
}

// WriteMsgIP writes one payload with Linux-compatible source, hop-limit, and
// traffic-class ancillary data. A connected socket requires a nil address.
func (c *IPConn) WriteMsgIP(payload, oob []byte, address *net.IPAddr) (n, oobn int, err error) {
	var target netip.Addr
	var netAddress net.Addr
	if c.remote.IsValid() {
		if address != nil {
			return 0, 0, c.operationErrorTo("write", address, net.ErrWriteToConnected)
		}
		target, netAddress = c.remote, c.remoteAddr()
	} else {
		target, err = ipAddr(address)
		if err != nil {
			return 0, 0, c.operationErrorTo("write", address, err)
		}
		netAddress = address
	}
	source, options, err := parseControlMessageForWrite(oob, target.Is6())
	if err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	n, err = c.writeTo(payload, target, netAddress, source, options)
	if err != nil {
		return n, 0, c.operationErrorTo("write", netAddress, err)
	}
	return n, len(oob), nil
}

// writeTo selects a source, repairs ICMPv6 checksum, and emits one payload.
func (c *IPConn) writeTo(payload []byte, target netip.Addr, address net.Addr, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	target = target.Unmap()
	if !target.IsValid() || target.IsUnspecified() || target.IsMulticast() || !c.dual && target.Is6() != c.v6 || target.Zone() != "" {
		return 0, syscall.EINVAL
	}
	deadline, _, closed := c.writeState()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	requestedSource := c.local
	packetInfoSource = packetInfoSource.Unmap()
	if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() {
		if !c.local.IsUnspecified() && packetInfoSource != c.local {
			return 0, syscall.EADDRNOTAVAIL
		}
		requestedSource = packetInfoSource
	}
	source, err := c.stack.sourceForRequested(target, requestedSource)
	if err != nil {
		return 0, err
	}
	if c.protocol == protocolICMPv6 && len(payload) >= 4 {
		payload = append([]byte(nil), payload...)
		payload[2], payload[3] = 0, 0
		binary.BigEndian.PutUint16(payload[2:4], transportChecksum(source, target, protocolICMPv6, payload))
	}
	if err = c.stack.writeIPPayloadUntilOptions(source, target, c.protocol, payload, true, options, c.writeState); err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			return 0, messageTooLong(c.network(), c.LocalAddr(), address)
		}
		return 0, err
	}
	return len(payload), nil
}

// Close unregisters the protocol socket and wakes blocked operations.
func (c *IPConn) Close() error {
	if c.stack.closeIP(c) {
		return nil
	}
	return c.operationError("close", net.ErrClosed)
}

// closeFromStack publishes closure and releases queued payloads.
func (c *IPConn) closeFromStack() {
	c.once.Do(func() {
		c.mu.Lock()
		c.receive = nil
		c.queuedBytes = 0
		close(c.closed)
		c.mu.Unlock()
	})
}

// LocalAddr returns the bound protocol address.
func (c *IPConn) LocalAddr() net.Addr { return ipNetAddr(c.local) }

// RemoteAddr returns the connected peer, or nil for an unconnected socket.
func (c *IPConn) RemoteAddr() net.Addr { return c.remoteAddr() }

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
	readChanged, writeChanged := c.readChanged, c.writeChanged
	c.readDeadline, c.writeDeadline = deadline, deadline
	c.readChanged, c.writeChanged = make(chan struct{}), make(chan struct{})
	c.mu.Unlock()
	close(readChanged)
	close(writeChanged)
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
	changed := c.readChanged
	c.readDeadline, c.readChanged = deadline, make(chan struct{})
	c.mu.Unlock()
	close(changed)
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
	changed := c.writeChanged
	c.writeDeadline, c.writeChanged = deadline, make(chan struct{})
	c.mu.Unlock()
	close(changed)
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

// writeState snapshots the write deadline and closure notification.
func (c *IPConn) writeState() (time.Time, <-chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.writeDeadline, c.writeChanged, true
	default:
		return c.writeDeadline, c.writeChanged, false
	}
}

// network returns the standard protocol network label.
func (c *IPConn) network() string { return c.net }

// operationError wraps an error for the bound or connected socket.
func (c *IPConn) operationError(operation string, err error) error {
	return socketOperationError(operation, c.network(), c.LocalAddr(), c.remoteAddr(), err)
}

// operationErrorTo wraps an error for one explicit destination.
func (c *IPConn) operationErrorTo(operation string, target net.Addr, err error) error {
	return socketOperationError(operation, c.network(), c.LocalAddr(), target, err)
}

// setOperationError uses standard deadline and socket-option metadata.
func (c *IPConn) setOperationError(err error) error {
	return socketOperationError("set", c.network(), nil, c.LocalAddr(), err)
}

// ipNetAddr converts a valid address to IPAddr and preserves nil for no peer.
func ipNetAddr(address netip.Addr) *net.IPAddr {
	if !address.IsValid() {
		return nil
	}
	return &net.IPAddr{IP: net.IP(address.AsSlice()), Zone: address.Zone()}
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
	if !result.IsValid() || result.IsUnspecified() || result.IsMulticast() {
		return netip.Addr{}, syscall.EINVAL
	}
	return result, nil
}

// Verify the standard connection interfaces implemented without an OS fd.
var _ net.Conn = (*IPConn)(nil)
var _ net.PacketConn = (*IPConn)(nil)
