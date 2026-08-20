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

// ICMPv4Filter is a Linux-compatible ICMP_FILTER receive-type mask. A set bit
// blocks the corresponding representable ICMPv4 type, so the zero value
// accepts every type. Linux exposes 32 bits and x/net/ipv4 consequently uses
// the low five bits of method arguments; received types above 31 are outside
// the kernel mask and are always accepted.
type ICMPv4Filter struct {
	blocked uint32
}

// Accept clears the mask bit selected by the low five bits of typ. Received
// ICMPv4 types above 31 remain unconditionally accepted by the socket.
func (f *ICMPv4Filter) Accept(typ uint8) {
	f.blocked &^= uint32(1) << (typ & 31)
}

// Block sets the mask bit selected by the low five bits of typ. Received
// ICMPv4 types above 31 remain unconditionally accepted by the socket.
func (f *ICMPv4Filter) Block(typ uint8) {
	f.blocked |= uint32(1) << (typ & 31)
}

// SetAll blocks every representable ICMPv4 type when block is true and
// accepts every type otherwise.
func (f *ICMPv4Filter) SetAll(block bool) {
	if block {
		f.blocked = ^uint32(0)
	} else {
		f.blocked = 0
	}
}

// WillBlock reports the mask bit selected by the low five bits of typ. It may
// therefore report true for typ above 31 even though such received types are
// outside Linux's mask and remain accepted.
func (f *ICMPv4Filter) WillBlock(typ uint8) bool {
	return f.blocked&(uint32(1)<<(typ&31)) != 0
}

// ICMPv6Filter is an RFC 3542 ICMP6_FILTER receive-type mask. Its 256 bits
// cover every value of the ICMPv6 Type field. A set bit blocks that type, so
// the zero value accepts every type.
type ICMPv6Filter struct {
	blocked [8]uint32
}

// Accept permits packets whose ICMPv6 type has the supplied value.
func (f *ICMPv6Filter) Accept(typ uint8) {
	f.blocked[typ>>5] &^= uint32(1) << (typ & 31)
}

// Block rejects packets whose ICMPv6 type has the supplied value.
func (f *ICMPv6Filter) Block(typ uint8) {
	f.blocked[typ>>5] |= uint32(1) << (typ & 31)
}

// SetAll blocks every ICMPv6 type when block is true and accepts every type
// otherwise.
func (f *ICMPv6Filter) SetAll(block bool) {
	value := uint32(0)
	if block {
		value = ^uint32(0)
	}
	for index := range f.blocked {
		f.blocked[index] = value
	}
}

// WillBlock reports whether packets with the supplied ICMPv6 type are
// rejected.
func (f *ICMPv6Filter) WillBlock(typ uint8) bool {
	return f.blocked[typ>>5]&(uint32(1)<<(typ&31)) != 0
}

// ipDatagram is one validated, reassembled protocol payload.
type ipDatagram struct {
	payload []byte
	source  netip.Addr
	target  netip.Addr
	options ipPacketOptions
}

// IPConnInfo is a point-in-time diagnostic snapshot of one IP protocol socket.
// Traffic byte counters measure the representation exposed by the socket:
// protocol payloads by default or complete packets when the corresponding
// header option is enabled. Receive-queue byte values also include the stack's
// per-datagram accounting overhead.
type IPConnInfo struct {
	// LocalAddress is the bound local address; an unspecified address denotes
	// a wildcard binding.
	LocalAddress netip.Addr
	// RemoteAddress is the connected peer, or an invalid address for an
	// unconnected socket.
	RemoteAddress netip.Addr
	// Protocol is the IANA IP protocol number carried by the socket.
	Protocol uint8
	// IPHeaderIncludedOnWrite reports whether writes contain complete IP
	// packets rather than protocol payloads.
	IPHeaderIncludedOnWrite bool
	// IPHeaderIncludedOnRead reports whether reads return complete reassembled
	// IP packets rather than protocol payloads.
	IPHeaderIncludedOnRead bool
	// Closed reports whether the socket was closed when the snapshot was taken.
	Closed bool
	// ReceiveQueuePackets is the number of complete messages awaiting a read.
	ReceiveQueuePackets int
	// ReceiveQueueBytes is the accounted payload and metadata retained by the
	// receive queue.
	ReceiveQueueBytes int
	// ReceiveQueueCapacity is the configured accounting-byte limit of the
	// combined payload and error queues, not an exact heap-allocation limit.
	ReceiveQueueCapacity int
	// ReceiveErrors reports whether asynchronous network errors are reserved
	// for ReadError instead of being returned by ordinary reads.
	ReceiveErrors bool
	// ErrorQueueEntries is the number of asynchronous network errors awaiting
	// ReadError or, when ReceiveErrors is false, an ordinary read.
	ErrorQueueEntries int
	// ErrorQueueBytes is the accounted metadata and quoted packet data retained
	// by the asynchronous error queue.
	ErrorQueueBytes int
	// ErrorsDropped counts asynchronous network errors discarded because the
	// configured receive-buffer budget was exhausted.
	ErrorsDropped uint64
	// PacketsSent counts successfully emitted socket messages.
	PacketsSent uint64
	// BytesSent counts successfully emitted bytes in the write representation.
	BytesSent uint64
	// PacketsReceived counts socket messages accepted into the receive queue.
	PacketsReceived uint64
	// BytesReceived counts bytes accepted in the configured read representation.
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
	// PathMTUDiscovery is the Linux-compatible source-fragmentation and PMTU
	// policy used by subsequent writes.
	PathMTUDiscovery PathMTUDiscovery
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

// ipEndpointInlineFanout is the number of matching raw sockets collected
// without allocation. Larger fan-outs grow normally and are never truncated.
const ipEndpointInlineFanout = 8

// ipConnICMPFilter retains a receive mask only for sockets that block at
// least one ICMP type. A socket's fixed protocol selects either the first word
// as the Linux ICMPv4 mask or all eight words as the RFC 3542 ICMPv6 mask.
type ipConnICMPFilter struct {
	blocked [8]uint32
}

// IPConn is a connected or unconnected userspace IP protocol socket. It
// exchanges protocol payloads by default.
// SocketOptions.IPHeaderIncludedOnWrite and
// SocketOptions.IPHeaderIncludedOnRead independently expose complete packets
// on the write and read sides. ICMP receive filters and raw IPv6 checksum
// processing may be selected at creation and updated through IPConn methods.
type IPConn struct {
	stack                   *Stack
	net                     string
	protocol                byte
	v6                      bool
	dual                    bool
	receiveErrors           bool
	ipHeaderIncludedOnWrite atomic.Bool
	local                   netip.Addr
	remote                  netip.Addr

	datagramSocketWriteControl

	mu                     sync.Mutex
	receive                datagramQueue[ipDatagram]
	receiveSpare           []byte
	receiveNotify          chan struct{}
	receiveCapacity        int
	queuedBytes            int
	errorState             *datagramSocketErrorState
	readDeadline           datagramSocketDeadline
	recentTargets          recentDestinationCache[netip.Addr]
	pathMTUDiscovery       PathMTUDiscovery
	icmpFilter             *ipConnICMPFilter
	ipv6ChecksumOffset     int
	packetsSent            atomic.Uint64
	bytesSent              atomic.Uint64
	packetsReceived        atomic.Uint64
	bytesReceived          atomic.Uint64
	packetsDropped         atomic.Uint64
	defaultOptions         ipPacketOptions
	ipHeaderIncludedOnRead bool
	multicastHopLimit      byte
	multicastLoopback      bool
	broadcast              bool
}

// ipWriteParameters is one validated output-policy snapshot shared by
// contiguous and scatter/gather writes.
type ipWriteParameters struct {
	source           netip.Addr
	target           netip.Addr
	options          ipPacketOptions
	pathMTUDiscovery PathMTUDiscovery
	checksumOffset   int
	nonUnicast       bool
}

// ipPayloadWriter emits one prepared protocol payload under a per-call queue
// wait policy.
type ipPayloadWriter func(source, target netip.Addr, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, nonUnicast, dontWait bool) error

// ListenIP creates an unconnected IPv4 or IPv6 protocol socket. Network must
// be an IP network with a numeric or well-known protocol, such as ip4:icmp or
// ip:99. An empty Local selects the network's wildcard address; a generic ip
// wildcard is dual-stack when both address families are configured.
func (s *Stack) ListenIP(ctx context.Context, network string, local netip.Addr) (*IPConn, error) {
	return s.listenIP(ctx, network, local, socketOptionSet{})
}

// listenIP contains protocol-socket construction shared by Stack and
// ListenConfig.
func (s *Stack) listenIP(ctx context.Context, network string, local netip.Addr, options socketOptionSet) (*IPConn, error) {
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
	if err = options.validateFamily(socketOptionIPListen, local.Is6(), dual); err != nil {
		return wrap(err)
	}
	if err = options.validateIPSocket(protocol, local.Is6(), dual); err != nil {
		return wrap(err)
	}
	if !local.IsUnspecified() && !networkStateHasLocal(state, local) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	connection := newIPConn(s, network, protocol, local, netip.Addr{}, options)
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
	return s.dialIP(ctx, network, source, remote, socketOptionSet{})
}

// dialIP contains connected protocol-socket construction shared by Stack and
// Dialer.
func (s *Stack) dialIP(ctx context.Context, network string, source, remote netip.Addr, options socketOptionSet) (net.Conn, error) {
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
	if err = options.validateFamily(socketOptionIPDial, remote.Is6(), false); err != nil {
		return wrap(nil, err)
	}
	if err = options.validateIPSocket(protocol, remote.Is6(), false); err != nil {
		return wrap(nil, err)
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
	connection := newIPConn(s, network, protocol, local, remote, options)
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
		protocol = ProtocolICMPv4
	case "igmp":
		protocol = 2
	case "tcp":
		protocol = ProtocolTCP
	case "udp":
		protocol = ProtocolUDP
	case "ipv6-icmp":
		protocol = ProtocolICMPv6
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

// newIPConn allocates one unregistered protocol socket after applying explicit
// creation policies to the latest Stack defaults.
func newIPConn(stack *Stack, network string, protocol byte, local, remote netip.Addr, options socketOptionSet) *IPConn {
	defaults := DatagramSocketDefaults{ReceiveBuffer: ipDefaultReceiveCapacity, HopLimit: 64, MulticastHopLimit: 1}
	if stack != nil {
		defaults = stack.network.Load().ipDefaults
	}
	defaults = applyDatagramSocketOptions(defaults, options.datagram, ipDatagramMetadataSize)
	checksumOffset := -1
	if local.Is6() && protocol == ProtocolICMPv6 {
		checksumOffset = 2
	}
	if checksum := options.ip.ipv6Checksum; checksum.set {
		if checksum.value.enabled {
			checksumOffset = checksum.value.offset
		} else {
			checksumOffset = -1
		}
	}
	connection := &IPConn{
		stack: stack, net: network, protocol: protocol, v6: local.Is6(), local: local, remote: remote,
		datagramSocketWriteControl: datagramSocketWriteControl{closed: make(chan struct{})},
		receiveCapacity:            defaults.ReceiveBuffer,
		ipHeaderIncludedOnRead:     options.ip.headerIncludedOnRead,
		defaultOptions: ipPacketOptions{
			hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
			flowLabel: defaults.FlowLabel, hopLimitSet: options.datagram.hopLimit.set,
			trafficClassSet: options.datagram.trafficClass.set, flowLabelSet: defaults.FlowLabel != 0 || options.datagram.flowLabel.set,
		},
		receiveErrors:     defaults.ReceiveErrors,
		pathMTUDiscovery:  defaults.PathMTUDiscovery,
		multicastHopLimit: byte(defaults.MulticastHopLimit), multicastLoopback: !defaults.DisableMulticastLoopback,
		broadcast: !defaults.DisableBroadcast, ipv6ChecksumOffset: checksumOffset,
	}
	if filter := options.ip.icmpV4Filter.value; protocol == ProtocolICMPv4 && filter != (ICMPv4Filter{}) {
		connection.icmpFilter = &ipConnICMPFilter{}
		connection.icmpFilter.blocked[0] = filter.blocked
	} else if filter := options.ip.icmpV6Filter.value; protocol == ProtocolICMPv6 && filter != (ICMPv6Filter{}) {
		connection.icmpFilter = &ipConnICMPFilter{blocked: filter.blocked}
	}
	connection.ipHeaderIncludedOnWrite.Store(options.ip.headerIncludedOnWrite)
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
	var connectionStorage [ipEndpointInlineFanout]*IPConn
	connections := state.connectionsForLocked(connectionStorage[:0], packet.target, packet.protocol)
	stack.mu.RUnlock()
	accepted := false
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	for _, connection := range connections {
		if connection.remote.IsValid() && connection.remote != packet.source {
			continue
		}
		accepted = true
		connection.enqueuePacket(packet, options)
	}
	return accepted
}

// connectionsForLocked appends exact, family-wildcard, and dual-stack raw
// bindings to storage while Stack.mu is held.
func (state *ipEndpointState) connectionsForLocked(storage []*IPConn, address netip.Addr, protocol byte) []*IPConn {
	connections := storage
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
	var connectionStorage [ipEndpointInlineFanout]*IPConn
	connections := state.connectionsForLocked(connectionStorage[:0], networkError.QuotedSource, networkError.QuotedProtocol)
	stack.mu.RUnlock()
	accepted := false
	acceptedPathMTU := false
	for _, connection := range connections {
		if !connection.acceptsError(networkError.QuotedTarget) {
			continue
		}
		accepted = true
		acceptedPathMTU = acceptedPathMTU || connection.acceptsPathMTU()
		connectionError := cloneICMPError(networkError)
		connection.deliverError(networkError.QuotedTarget, connectionError)
	}
	if acceptedPathMTU && networkError.MTU != 0 && stack.observePathMTU(networkError.QuotedTarget, networkError.MTU) {
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

// enqueuePacket applies per-socket receive policy and selects the configured
// read representation without retaining both the protocol payload and
// complete packet.
func (c *IPConn) enqueuePacket(packet ipPacket, options ipPacketOptions) {
	payload := packet.payload
	if c.ipHeaderIncludedOnRead {
		payload = packet.original
	}
	size := ipDatagramMetadataSize + len(payload)
	c.mu.Lock()
	filter := c.icmpFilter
	blocked := filter != nil && len(packet.payload) != 0 && (packet.source.Is4() && c.protocol == ProtocolICMPv4 && packet.payload[0] < 32 && filter.blocked[0]&(uint32(1)<<packet.payload[0]) != 0 ||
		packet.source.Is6() && c.protocol == ProtocolICMPv6 && filter.blocked[packet.payload[0]>>5]&(uint32(1)<<(packet.payload[0]&31)) != 0)
	if blocked || packet.source.Is6() && c.protocol != ProtocolICMPv6 && c.ipv6ChecksumOffset >= 0 &&
		(c.ipv6ChecksumOffset > len(packet.payload)-2 || transportChecksum(packet.source, packet.target, c.protocol, packet.payload) != 0) {
		c.mu.Unlock()
		return
	}
	select {
	case <-c.closed:
		c.mu.Unlock()
		c.stack.stats.inboundDroppedPackets.Add(1)
		c.packetsDropped.Add(1)
		return
	default:
	}
	if size > c.receiveCapacity || c.queuedBytes+c.errorState.bytes() > c.receiveCapacity-size {
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
	datagram := ipDatagram{payload: retained, source: packet.source, target: packet.target, options: options}
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
	if c.receiveNotify == nil {
		return
	}
	if c.receive.len() != 0 || !c.receiveErrors && c.errorState.len() != 0 {
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

// receiveNotificationLocked returns the shared edge notification, allocating
// it only when an empty receive path is about to block.
func (c *IPConn) receiveNotificationLocked() <-chan struct{} {
	if c.receiveNotify == nil {
		c.receiveNotify = make(chan struct{}, 1)
	}
	return c.receiveNotify
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

// ReadMsgIP reads one socket message and Linux-compatible packet info,
// hop-limit, and traffic-class ancillary data. An IPHeaderIncludedOnRead
// socket returns a complete reassembled IP packet instead of a protocol
// payload.
func (c *IPConn) ReadMsgIP(buffer, oob []byte) (n, oobn, flags int, address *net.IPAddr, err error) {
	var datagram ipDatagram
	var truncated bool
	n, datagram, truncated, err = c.readDatagram(buffer)
	address = ipNetAddr(datagram.source)
	if truncated {
		flags |= MessageFlagTruncated
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
		flags |= MessageFlagControlTruncated
	}
	return
}

// ReadBatch reads one or more IP protocol messages using the SocketMessage layout
// shared by x/net/ipv4 and x/net/ipv6. The first message follows the socket's
// blocking and deadline semantics; after it succeeds, the method drains only
// messages already queued. MessageFlagDontWait also makes the first read
// nonblocking.
func (c *IPConn) ReadBatch(messages []SocketMessage, flags int) (int, error) {
	if flags&^(MessageFlagPeek|MessageFlagDontWait|MessageFlagTruncated|MessageFlagErrorQueue) != 0 {
		return 0, c.operationError("read", syscall.EOPNOTSUPP)
	}
	if flags&MessageFlagErrorQueue != 0 {
		return c.readErrorBatch(messages, flags)
	}
	for index := range messages {
		wait := index == 0 && flags&MessageFlagDontWait == 0
		err := c.readBatchMessage(&messages[index], flags, wait, index == 0)
		if err != nil {
			// recvmmsg reports a completed prefix without the error that stopped
			// the next message. A retry starting at index exposes that error.
			if index != 0 {
				return index, nil
			}
			return index, err
		}
	}
	return len(messages), nil
}

// readBatchMessage receives one scatter/gather message without waiting when
// wait is false. consumeErrors is false after a successful prefix so an
// asynchronous error remains available to the next socket operation.
func (c *IPConn) readBatchMessage(message *SocketMessage, flags int, wait, consumeErrors bool) error {
	if _, err := messageBufferLength(message.Buffers); err != nil {
		return c.operationError("read", err)
	}
	n, datagram, truncated, err := c.readDatagramBuffers(message.Buffers, wait, consumeErrors, flags&MessageFlagPeek != 0, flags&MessageFlagTruncated != 0)
	if err != nil {
		return c.operationError("read", err)
	}
	control, err := controlMessageForRead(datagram.target, datagram.options)
	if err != nil {
		return c.operationError("read", err)
	}
	resultFlags := 0
	if truncated {
		resultFlags |= MessageFlagTruncated
	}
	oobn := copy(message.OOB, control)
	if oobn < len(control) {
		resultFlags |= MessageFlagControlTruncated
	}
	message.N, message.NN, message.Flags, message.Addr = n, oobn, resultFlags, ipNetAddr(datagram.source)
	return nil
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
		timeout := c.readDeadline.channel()
		select {
		case <-timeout:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		default:
		}
		queued, ok := c.receive.pop()
		if ok {
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
		if !c.receiveErrors {
			queuedError, queued := c.errorState.pop()
			if queued {
				c.notifyReceiveLocked()
				c.mu.Unlock()
				return 0, ipDatagram{}, false, queuedError.err
			}
		}
		notified := c.receiveNotificationLocked()
		if timeout == nil {
			timeout = c.readDeadline.wait()
		}
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, ipDatagram{}, false, net.ErrClosed
		}
	}
}

// readDatagramBuffers is the scatter/gather and nonblocking form used by
// ReadBatch. It returns EAGAIN without consuming state when wait is false and
// neither a payload nor an ordinary-read error is ready.
func (c *IPConn) readDatagramBuffers(buffers [][]byte, wait, consumeErrors, peek, returnLength bool) (n int, datagram ipDatagram, truncated bool, err error) {
	for {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, net.ErrClosed
		default:
		}
		timeout := c.readDeadline.channel()
		select {
		case <-timeout:
			c.mu.Unlock()
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		default:
		}
		var queued ipDatagram
		var ok bool
		if peek {
			queued, ok = c.receive.peek()
		} else {
			queued, ok = c.receive.pop()
		}
		if ok {
			datagram = queued
			if !peek {
				c.queuedBytes -= ipDatagramMetadataSize + len(datagram.payload)
				c.notifyReceiveLocked()
			}
			n = copyMessagePayload(buffers, datagram.payload)
			truncated = n < len(datagram.payload)
			if truncated && returnLength {
				n = len(datagram.payload)
			}
			c.mu.Unlock()
			if !peek && cap(datagram.payload) != 0 && cap(datagram.payload) <= datagramReusablePayloadLimit {
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
			return n, datagram, truncated, nil
		}
		if !c.receiveErrors && consumeErrors {
			var queued queuedSocketError
			queued, ok = c.errorState.pop()
			if ok {
				// Linux MSG_PEEK preserves queued payloads but consumes a pending
				// socket error returned by the ordinary receive path.
				c.notifyReceiveLocked()
				c.mu.Unlock()
				return 0, ipDatagram{}, false, queued.err
			}
		}
		if !wait {
			c.mu.Unlock()
			return 0, ipDatagram{}, false, syscall.EAGAIN
		}
		notified := c.receiveNotificationLocked()
		if timeout == nil {
			timeout = c.readDeadline.wait()
		}
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return 0, ipDatagram{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, ipDatagram{}, false, net.ErrClosed
		}
	}
}

// readErrorBatch consumes a prefix of the asynchronous error queue. Linux
// MSG_ERRQUEUE is nonblocking regardless of socket deadlines or MSG_DONTWAIT.
func (c *IPConn) readErrorBatch(messages []SocketMessage, flags int) (int, error) {
	for index := range messages {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", net.ErrClosed)
		default:
		}
		ok, err := c.errorState.readMessage(&messages[index], flags)
		if !ok {
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", syscall.EAGAIN)
		}
		if err != nil {
			c.mu.Unlock()
			if index != 0 {
				return index, nil
			}
			return 0, c.operationError("read", err)
		}
		c.notifyReceiveLocked()
		c.mu.Unlock()
	}
	return len(messages), nil
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
	var n int
	if c.ipHeaderIncludedOnWrite.Load() {
		n, err = c.writeHeaderIncluded(payload, target, netip.Addr{}, ipPacketOptions{}, false)
	} else {
		n, err = c.writeTo(payload, target, netip.Addr{}, ipPacketOptions{})
	}
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
	var n int
	var err error
	if c.ipHeaderIncludedOnWrite.Load() {
		n, err = c.writeHeaderIncluded(payload, c.remote, netip.Addr{}, ipPacketOptions{}, false)
	} else {
		n, err = c.writeTo(payload, c.remote, netip.Addr{}, ipPacketOptions{})
	}
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
	n, err := c.writeToWith(payload, c.remote, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbePayload, false)
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
	n, err := c.writeToWith(payload, target, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbePayload, false)
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
	if err = (socketWriteState{datagram: &c.datagramSocketWriteControl}).err(); err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	source, options, err := parseControlMessageForWrite(oob, target.Is6())
	if err != nil {
		return 0, 0, c.operationErrorTo("write", netAddress, err)
	}
	if c.ipHeaderIncludedOnWrite.Load() {
		n, err = c.writeHeaderIncluded(payload, target, source, options, false)
	} else {
		n, err = c.writeTo(payload, target, source, options)
	}
	if err != nil {
		return n, 0, c.operationErrorTo("write", netAddress, err)
	}
	return n, len(oob), nil
}

// WriteBatch writes a prefix of IP protocol messages using scatter/gather
// payloads. MessageFlagDontWait bypasses packet-queue waiting; other flags are
// unsupported.
func (c *IPConn) WriteBatch(messages []SocketMessage, flags int) (int, error) {
	if flags&^MessageFlagDontWait != 0 {
		return 0, c.operationError("write", syscall.EOPNOTSUPP)
	}
	dontWait := flags&MessageFlagDontWait != 0
	if c.ipHeaderIncludedOnWrite.Load() {
		return c.writeHeaderIncludedBatch(messages, dontWait)
	}
	for index := range messages {
		message := &messages[index]
		n, oobn, err := c.writeBatchMessage(message, dontWait)
		if err != nil {
			// sendmmsg reports a completed prefix without the error that stopped
			// the next message. A retry starting at index exposes that error.
			if index != 0 {
				return index, nil
			}
			return index, err
		}
		message.N, message.NN, message.Flags = n, oobn, 0
	}
	return len(messages), nil
}

// writeBatchMessage validates one destination and sends a scatter/gather
// payload through the ordinary ancillary-data and output policy.
func (c *IPConn) writeBatchMessage(message *SocketMessage, dontWait bool) (int, int, error) {
	var target netip.Addr
	var address net.Addr
	if c.remote.IsValid() {
		if message.Addr != nil {
			return 0, 0, c.operationErrorTo("write", message.Addr, net.ErrWriteToConnected)
		}
		target, address = c.remote, c.remoteAddr()
	} else {
		address = message.Addr
		ipAddress, ok := address.(*net.IPAddr)
		if !ok || ipAddress == nil {
			return 0, 0, c.operationErrorTo("write", address, syscall.EINVAL)
		}
		var err error
		target, err = ipAddr(ipAddress)
		if err != nil {
			return 0, 0, c.operationErrorTo("write", address, err)
		}
	}
	validated, err := c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", address, err)
	}
	maximum := 65535
	if validated.Is4() {
		maximum -= 20
	}
	payloadSize, err := messageBufferLength(message.Buffers)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", address, err)
	}
	if payloadSize > maximum {
		return 0, 0, c.operationErrorTo("write", address, syscall.EMSGSIZE)
	}
	if len(message.Buffers) == 1 {
		if err = (socketWriteState{datagram: &c.datagramSocketWriteControl}).err(); err != nil {
			return 0, 0, c.operationErrorTo("write", address, err)
		}
		source, options, parseErr := parseControlMessageForWrite(message.OOB, validated.Is6())
		if parseErr != nil {
			return 0, 0, c.operationErrorTo("write", address, parseErr)
		}
		n, writeErr := c.writeToWith(message.Buffers[0], validated, source, options, c.writePayload, dontWait)
		if writeErr != nil {
			return n, 0, c.operationErrorTo("write", address, writeErr)
		}
		return n, len(message.OOB), nil
	}
	if err = (socketWriteState{datagram: &c.datagramSocketWriteControl}).err(); err != nil {
		return 0, 0, c.operationErrorTo("write", address, err)
	}
	source, options, err := parseControlMessageForWrite(message.OOB, validated.Is6())
	if err != nil {
		return 0, 0, c.operationErrorTo("write", address, err)
	}
	n, err := c.writeBuffersTo(message.Buffers, payloadSize, validated, source, options, dontWait)
	if err != nil {
		return n, 0, c.operationErrorTo("write", address, err)
	}
	return n, len(message.OOB), nil
}

// writeHeaderIncludedBatch writes complete IP packets after WriteBatch has
// selected the header-included representation once for the whole operation.
func (c *IPConn) writeHeaderIncludedBatch(messages []SocketMessage, dontWait bool) (int, error) {
	for index := range messages {
		message := &messages[index]
		n, oobn, err := c.writeHeaderIncludedBatchMessage(message, dontWait)
		if err != nil {
			if index != 0 {
				return index, nil
			}
			return index, err
		}
		message.N, message.NN, message.Flags = n, oobn, 0
	}
	return len(messages), nil
}

// writeHeaderIncludedBatchMessage validates and writes one complete IP packet.
func (c *IPConn) writeHeaderIncludedBatchMessage(message *SocketMessage, dontWait bool) (int, int, error) {
	var target netip.Addr
	var address net.Addr
	if c.remote.IsValid() {
		if message.Addr != nil {
			return 0, 0, c.operationErrorTo("write", message.Addr, net.ErrWriteToConnected)
		}
		target, address = c.remote, c.remoteAddr()
	} else {
		address = message.Addr
		ipAddress, ok := address.(*net.IPAddr)
		if !ok || ipAddress == nil {
			return 0, 0, c.operationErrorTo("write", address, syscall.EINVAL)
		}
		var err error
		target, err = ipAddr(ipAddress)
		if err != nil {
			return 0, 0, c.operationErrorTo("write", address, err)
		}
	}
	validated, err := c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", address, err)
	}
	payloadSize, err := messageBufferLength(message.Buffers)
	if err != nil {
		return 0, 0, c.operationErrorTo("write", address, err)
	}
	if payloadSize > 65535 {
		return 0, 0, c.operationErrorTo("write", address, syscall.EMSGSIZE)
	}
	if err = (socketWriteState{datagram: &c.datagramSocketWriteControl}).err(); err != nil {
		return 0, 0, c.operationErrorTo("write", address, err)
	}
	source, options, err := parseControlMessageForWrite(message.OOB, validated.Is6())
	if err != nil {
		return 0, 0, c.operationErrorTo("write", address, err)
	}
	payload := message.Buffers[0]
	if len(message.Buffers) != 1 {
		payload, err = gatherMessagePayload(message.Buffers, 65535)
		if err != nil {
			return 0, 0, c.operationErrorTo("write", address, err)
		}
	}
	n, err := c.writeHeaderIncluded(payload, validated, source, options, dontWait)
	if err != nil {
		return n, 0, c.operationErrorTo("write", address, err)
	}
	return n, len(message.OOB), nil
}

// writeTo selects a source, repairs ICMPv6 checksum, and emits one ordinary
// fragmentable payload.
func (c *IPConn) writeTo(payload []byte, target netip.Addr, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	return c.writeToWith(payload, target, packetInfoSource, options, c.writePayload, false)
}

// writeHeaderIncluded validates and queues one caller-supplied IPv4 or IPv6
// packet. target selects the route while the supplied IP header remains the
// packet delivered on the wire, matching Linux header-included raw sockets.
func (c *IPConn) writeHeaderIncluded(input []byte, target, packetInfoSource netip.Addr, options ipPacketOptions, dontWait bool) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options)
	if err != nil {
		return 0, err
	}
	if len(input) > c.stack.network.Load().mtu {
		return 0, syscall.EMSGSIZE
	}
	packet, packetTarget, hopLimit, err := c.prepareHeaderIncludedPacket(input, parameters.source, parameters.target)
	if err != nil {
		return 0, err
	}
	state := socketWriteState{datagram: &c.datagramSocketWriteControl, dontWait: dontWait}
	if parameters.nonUnicast {
		c.mu.Lock()
		_, external, loopback, policyErr := nonUnicastOutputPolicy(parameters.target, c.multicastHopLimit, c.multicastLoopback, c.broadcast, ipPacketOptions{hopLimit: hopLimit, hopLimitSet: true})
		c.mu.Unlock()
		if policyErr != nil {
			return 0, policyErr
		}
		err = c.stack.writeNonUnicastPacketUntil(len(packet), external, loopback, state, func(destination []byte) bool {
			copy(destination, packet)
			return true
		})
	} else {
		err = c.stack.writeCompletePacketUntil(packet, parameters.target, state)
	}
	if err != nil {
		return 0, err
	}
	if !parameters.nonUnicast {
		c.rememberTarget(packetTarget)
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(input)))
	return len(input), nil
}

// prepareHeaderIncludedPacket copies and applies the limited IPv4 mutations
// made by Linux raw_send_hdrinc. IPv6 and transport headers remain unchanged.
func (c *IPConn) prepareHeaderIncludedPacket(input []byte, selectedSource, routeTarget netip.Addr) ([]byte, netip.Addr, byte, error) {
	if len(input) == 0 || !routeTarget.IsValid() {
		return nil, netip.Addr{}, 0, syscall.EINVAL
	}
	packet := append([]byte(nil), input...)
	switch packet[0] >> 4 {
	case 4:
		if !routeTarget.Is4() || len(packet) < 20 || len(packet) > 65535 {
			return nil, netip.Addr{}, 0, syscall.EINVAL
		}
		headerSize := int(packet[0]&0x0f) * 4
		if headerSize < 20 || headerSize > len(packet) {
			return nil, netip.Addr{}, 0, syscall.EINVAL
		}
		if binary.BigEndian.Uint32(packet[12:16]) == 0 {
			value := selectedSource.As4()
			copy(packet[12:16], value[:])
		}
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		if binary.BigEndian.Uint16(packet[4:6]) == 0 {
			binary.BigEndian.PutUint16(packet[4:6], uint16(c.stack.ipv4ID.Add(1)))
		}
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerSize]))
		return packet, netip.AddrFrom4([4]byte(packet[16:20])), packet[8], nil
	case 6:
		if !routeTarget.Is6() || len(packet) < 40 {
			return nil, netip.Addr{}, 0, syscall.EINVAL
		}
		return packet, netip.AddrFrom16([16]byte(packet[24:40])), packet[7], nil
	default:
		return nil, netip.Addr{}, 0, syscall.EINVAL
	}
}

// prepareWrite snapshots socket policy and selects the source for one output
// operation without retaining any caller payload.
func (c *IPConn) prepareWrite(target, packetInfoSource netip.Addr, options ipPacketOptions) (ipWriteParameters, error) {
	target, err := c.validateWriteTarget(target)
	if err != nil {
		return ipWriteParameters{}, err
	}
	writeState, options, pathMTUDiscovery, checksumOffset := c.writeStateAndOptions(options)
	if err = writeState.err(); err != nil {
		return ipWriteParameters{}, err
	}
	requestedSource := c.local
	packetInfoSource = packetInfoSource.Unmap()
	if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() {
		if !c.local.IsUnspecified() && packetInfoSource != c.local {
			return ipWriteParameters{}, syscall.EADDRNOTAVAIL
		}
		requestedSource = packetInfoSource
	}
	source, nonUnicast, err := c.stack.sourceForOutput(target, requestedSource)
	if err != nil {
		return ipWriteParameters{}, err
	}
	if !source.Is6() {
		checksumOffset = -1
	}
	return ipWriteParameters{
		source: source, target: target, options: options,
		pathMTUDiscovery: pathMTUDiscovery, checksumOffset: checksumOffset, nonUnicast: nonUnicast,
	}, nil
}

// setIPv6PayloadChecksum writes one RFC 3542 checksum into an owned
// upper-layer payload. A negative offset leaves the payload unchanged.
func setIPv6PayloadChecksum(payload []byte, source, target netip.Addr, protocol byte, offset int) error {
	if offset < 0 || !source.Is6() || !target.Is6() {
		return nil
	}
	if offset > len(payload)-2 {
		return syscall.EINVAL
	}
	payload[offset], payload[offset+1] = 0, 0
	value := transportChecksum(source, target, protocol, payload)
	if protocol == ProtocolUDP && value == 0 {
		// RFC 768 assigns an all-zero UDP checksum field to the disabled
		// state. IPv6 forbids that state, so Linux rawv6 uses negative zero.
		value = 0xffff
	}
	binary.BigEndian.PutUint16(payload[offset:offset+2], value)
	return nil
}

// writeToWith keeps routing, checksums, deadlines, accounting, and ICMP
// correlation shared between ordinary writes and PLPMTUD probes.
func (c *IPConn) writeToWith(payload []byte, target netip.Addr, packetInfoSource netip.Addr, options ipPacketOptions, write ipPayloadWriter, dontWait bool) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options)
	if err != nil {
		return 0, err
	}
	if parameters.checksumOffset >= 0 {
		payload = append([]byte(nil), payload...)
		if err = setIPv6PayloadChecksum(payload, parameters.source, parameters.target, c.protocol, parameters.checksumOffset); err != nil {
			return 0, err
		}
	}
	err = write(parameters.source, parameters.target, payload, parameters.options, parameters.pathMTUDiscovery, parameters.nonUnicast, dontWait)
	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, err
	}
	if !parameters.nonUnicast {
		c.rememberTarget(parameters.target)
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(payload)))
	return len(payload), nil
}

// writeBuffersTo sends one validated scatter/gather protocol payload. A
// fitting unicast packet is assembled directly in queue-owned storage;
// fragmentation and non-unicast output retain the established path.
func (c *IPConn) writeBuffersTo(buffers [][]byte, payloadSize int, target, packetInfoSource netip.Addr, options ipPacketOptions, dontWait bool) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options)
	if err != nil {
		return 0, err
	}
	maximum := 65535
	if parameters.target.Is4() {
		maximum -= 20
	}
	if payloadSize > maximum {
		return 0, syscall.EMSGSIZE
	}
	if parameters.nonUnicast {
		payload, gatherErr := gatherMessagePayload(buffers, maximum)
		if gatherErr != nil {
			return 0, gatherErr
		}
		if checksumErr := setIPv6PayloadChecksum(payload, parameters.source, parameters.target, c.protocol, parameters.checksumOffset); checksumErr != nil {
			return 0, checksumErr
		}
		err = c.writeNonUnicastPayload(parameters.source, parameters.target, payload, parameters.options, parameters.pathMTUDiscovery, dontWait)
	} else {
		mtu, fragmentation := c.stack.pathMTUOutputPolicy(parameters.target, parameters.pathMTUDiscovery)
		err = c.writePayloadBuffersForMTU(parameters.source, parameters.target, buffers, payloadSize, parameters.options, fragmentation, mtu, parameters.checksumOffset, dontWait)
	}
	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, err
	}
	if !parameters.nonUnicast {
		c.rememberTarget(parameters.target)
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(payloadSize))
	return payloadSize, nil
}

// writePayload emits ordinary output against the confirmed path MTU and
// permits source fragmentation.
func (c *IPConn) writePayload(source, target netip.Addr, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, nonUnicast, dontWait bool) error {
	if nonUnicast {
		return c.writeNonUnicastPayload(source, target, payload, options, pathMTUDiscovery, dontWait)
	}
	state := socketWriteState{datagram: &c.datagramSocketWriteControl, dontWait: dontWait}
	mtu, fragmentation := c.stack.pathMTUOutputPolicy(target, pathMTUDiscovery)
	return c.stack.writeIPPayloadUntilOptionsForMTU(source, target, c.protocol, payload, fragmentation, options, mtu, state)
}

// writePayloadBuffersForMTU is the allocation-free scatter/gather form of
// writePayload for a fitting packet. Fragmentation joins the payload once and
// then uses the existing fragment writer.
func (c *IPConn) writePayloadBuffersForMTU(source, target netip.Addr, buffers [][]byte, payloadSize int, options ipPacketOptions, fragmentation sourceFragmentation, mtu, checksumOffset int, dontWait bool) error {
	headerSize := ipHeaderSize(source, target, payloadSize)
	if headerSize == 0 {
		return syscall.EMSGSIZE
	}
	if headerSize+payloadSize > mtu {
		if !fragmentation.allow {
			return syscall.EMSGSIZE
		}
		payload, err := gatherMessagePayload(buffers, payloadSize)
		if err != nil {
			return err
		}
		if err = setIPv6PayloadChecksum(payload, source, target, c.protocol, checksumOffset); err != nil {
			return err
		}
		state := socketWriteState{datagram: &c.datagramSocketWriteControl, dontWait: dontWait}
		return c.stack.writeIPPayloadUntilOptionsForMTU(source, target, c.protocol, payload, fragmentation, options, mtu, state)
	}
	if source.Is6() && !options.flowLabelSet {
		var prefix [6]byte
		prefixSize := copyMessageBuffers(prefix[:], buffers)
		options.flowLabel = c.stack.automaticFlowLabel(source, target, c.protocol, prefix[:prefixSize])
		options.flowLabelSet = true
	}
	identification := uint16(0)
	if source.Is4() && fragmentation.requiresIPv4ID() {
		identification = uint16(c.stack.ipv4ID.Add(1))
	}
	queue, loopback := c.stack.outputQueueFor(target)
	state := socketWriteState{datagram: &c.datagramSocketWriteControl, dontWait: dontWait}
	slot, err := c.stack.reservePacketUntil(queue, loopback, state)
	if err != nil {
		return err
	}
	packet, reusable := queue.acquireBuffer(headerSize + payloadSize)
	if !marshalIPHeader(packet, source, target, c.protocol, identification, fragmentation.dontFragment, options) {
		queue.releaseBuffer(packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EMSGSIZE
	}
	payload := packet[headerSize:]
	if copied := copyMessageBuffers(payload, buffers); copied != payloadSize {
		queue.releaseBuffer(packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EINVAL
	}
	if err = setIPv6PayloadChecksum(payload, source, target, c.protocol, checksumOffset); err != nil {
		queue.releaseBuffer(packet, reusable)
		queue.releaseReserved(slot)
		return err
	}
	if !queue.enqueueReservedPacket(slot, packet, reusable) {
		return ErrClosed
	}
	c.stack.recordOutput(loopback)
	return nil
}

// writePathMTUProbePayload emits explicitly unfragmented output against the
// first-hop MTU.
func (c *IPConn) writePathMTUProbePayload(source, target netip.Addr, payload []byte, options ipPacketOptions, _ PathMTUDiscovery, _, dontWait bool) error {
	state := socketWriteState{datagram: &c.datagramSocketWriteControl, dontWait: dontWait}
	return c.stack.writeIPPayloadUntilOptionsForMTU(source, target, c.protocol, payload, sourceFragmentation{dontFragment: true}, options, c.stack.network.Load().mtu, state)
}

// Close unregisters the protocol socket and wakes blocked operations.
func (c *IPConn) Close() error {
	if c.stack.closeIP(c) {
		return nil
	}
	return c.operationError("close", net.ErrClosed)
}

// closeFromStack publishes closure exactly once and releases payload-bearing
// and error-correlation state.
func (c *IPConn) closeFromStack() {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	c.readDeadline.stop()
	c.writeDeadline.stop()
	c.receive.clear()
	c.errorState.releaseRetained()
	c.receiveSpare = nil
	c.receiveNotify = nil
	c.queuedBytes = 0
	c.recentTargets = recentDestinationCache[netip.Addr]{}
	c.icmpFilter = nil
	close(c.closed)
	c.mu.Unlock()
}

// LocalAddr returns the bound protocol address.
func (c *IPConn) LocalAddr() net.Addr { return ipNetAddr(c.local) }

// RemoteAddr returns the connected peer, or nil for an unconnected socket.
func (c *IPConn) RemoteAddr() net.Addr { return c.remoteAddr() }

// Info returns a diagnostic snapshot of the protocol socket and its receive
// queue.
func (c *IPConn) Info() IPConnInfo {
	c.mu.Lock()
	flowLabel := c.defaultOptions.flowLabel
	if !c.v6 && !c.dual {
		flowLabel = 0
	}
	errorEntries, errorBytes := c.errorState.len(), c.errorState.bytes()
	var lastError error
	var icmpErrors, errorsDropped uint64
	if c.errorState != nil {
		lastError = c.errorState.lastError
		icmpErrors, errorsDropped = c.errorState.icmpErrors, c.errorState.dropped
	}
	info := IPConnInfo{
		LocalAddress: c.local, RemoteAddress: c.remote, Protocol: c.protocol,
		IPHeaderIncludedOnWrite: c.ipHeaderIncludedOnWrite.Load(), IPHeaderIncludedOnRead: c.ipHeaderIncludedOnRead,
		ReceiveQueuePackets: c.receive.len(), ReceiveQueueBytes: c.queuedBytes, ReceiveQueueCapacity: c.receiveCapacity,
		ReceiveErrors: c.receiveErrors, ErrorQueueEntries: errorEntries, ErrorQueueBytes: errorBytes,
		HopLimit: int(c.defaultOptions.hopLimit), TrafficClass: c.defaultOptions.trafficClass,
		PathMTUDiscovery:  c.pathMTUDiscovery,
		MulticastHopLimit: int(c.multicastHopLimit), MulticastLoopback: c.multicastLoopback, Broadcast: c.broadcast,
		FlowLabel: flowLabel,
		LastError: lastError, ICMPErrors: icmpErrors, ErrorsDropped: errorsDropped,
	}
	select {
	case <-c.closed:
		info.Closed = true
	default:
	}
	c.mu.Unlock()
	info.PacketsSent, info.BytesSent = c.packetsSent.Load(), c.bytesSent.Load()
	info.PacketsReceived, info.BytesReceived = c.packetsReceived.Load(), c.bytesReceived.Load()
	info.PacketsDropped = c.packetsDropped.Load()
	if c.remote.IsValid() && !c.remote.IsMulticast() && !c.stack.network.Load().broadcastDestination(c.remote) {
		info.PathMTU = c.stack.mtuFor(c.remote)
	}
	return info
}

// SetIPHeaderIncludedOnWrite controls whether subsequent writes contain
// complete IP packets rather than protocol payloads.
func (c *IPConn) SetIPHeaderIncludedOnWrite(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.ipHeaderIncludedOnWrite.Store(enabled)
		return nil
	}
}

// SetICMPv4Filter atomically replaces the receive-type filter used by an
// IPv4 ICMP socket. Packets already queued for reading are not reconsidered.
func (c *IPConn) SetICMPv4Filter(filter ICMPv4Filter) error {
	if c.v6 && !c.dual {
		return c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol != ProtocolICMPv4 {
		return c.setOperationError(syscall.ENOPROTOOPT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		if c.icmpFilter == nil {
			if filter == (ICMPv4Filter{}) {
				return nil
			}
			c.icmpFilter = &ipConnICMPFilter{}
		}
		c.icmpFilter.blocked[0] = filter.blocked
		if filter == (ICMPv4Filter{}) {
			c.icmpFilter = nil
		}
		return nil
	}
}

// ICMPv4Filter returns an independent snapshot of the socket's current
// receive-type filter.
func (c *IPConn) ICMPv4Filter() (ICMPv4Filter, error) {
	if c.v6 && !c.dual {
		return ICMPv4Filter{}, c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol != ProtocolICMPv4 {
		return ICMPv4Filter{}, c.setOperationError(syscall.ENOPROTOOPT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return ICMPv4Filter{}, c.setOperationError(net.ErrClosed)
	default:
		if c.icmpFilter == nil {
			return ICMPv4Filter{}, nil
		}
		return ICMPv4Filter{blocked: c.icmpFilter.blocked[0]}, nil
	}
}

// SetICMPv6Filter atomically replaces the receive-type filter used by an
// ICMPv6 socket. Packets already queued for reading are not reconsidered.
func (c *IPConn) SetICMPv6Filter(filter ICMPv6Filter) error {
	if !c.v6 {
		return c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol != ProtocolICMPv6 {
		return c.setOperationError(syscall.ENOPROTOOPT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		if c.icmpFilter == nil {
			if filter == (ICMPv6Filter{}) {
				return nil
			}
			c.icmpFilter = &ipConnICMPFilter{}
		}
		c.icmpFilter.blocked = filter.blocked
		if filter == (ICMPv6Filter{}) {
			c.icmpFilter = nil
		}
		return nil
	}
}

// ICMPv6Filter returns an independent snapshot of the socket's current
// receive-type filter.
func (c *IPConn) ICMPv6Filter() (ICMPv6Filter, error) {
	if !c.v6 {
		return ICMPv6Filter{}, c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol != ProtocolICMPv6 {
		return ICMPv6Filter{}, c.setOperationError(syscall.ENOPROTOOPT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return ICMPv6Filter{}, c.setOperationError(net.ErrClosed)
	default:
		if c.icmpFilter == nil {
			return ICMPv6Filter{}, nil
		}
		return ICMPv6Filter{blocked: c.icmpFilter.blocked}, nil
	}
}

// SetIPv6Checksum controls RFC 3542 checksum insertion and verification for
// ordinary upper-layer payloads on a non-ICMPv6 socket. When enabled, offset
// must be the even, non-negative byte offset of a 16-bit checksum field. When
// disabled, offset is ignored. Complete-packet writes remain caller-owned.
func (c *IPConn) SetIPv6Checksum(enabled bool, offset int) error {
	if !c.v6 {
		return c.setOperationError(syscall.EAFNOSUPPORT)
	}
	if c.protocol == ProtocolICMPv6 || enabled && (offset < 0 || offset&1 != 0) {
		return c.setOperationError(syscall.EINVAL)
	}
	if !enabled {
		offset = -1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.ipv6ChecksumOffset = offset
		return nil
	}
}

// IPv6Checksum reports the checksum policy applied to IPv6 receive
// verification and ordinary payload writes. A disabled policy reports offset
// zero. ICMPv6 always reports enabled processing at offset 2.
func (c *IPConn) IPv6Checksum() (enabled bool, offset int, err error) {
	if !c.v6 {
		return false, 0, c.setOperationError(syscall.EAFNOSUPPORT)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, 0, c.setOperationError(net.ErrClosed)
	default:
		if c.ipv6ChecksumOffset < 0 {
			return false, 0, nil
		}
		return true, c.ipv6ChecksumOffset, nil
	}
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

// SetReadBuffer changes the approximate retained-memory capacity shared by the
// payload and asynchronous-error receive queues. Existing entries are retained
// when shrinking.
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

// SetReceiveErrors controls whether asynchronous network errors are reserved
// for ReadError. When disabled, the default, ordinary reads return queued
// errors after any already queued payloads.
func (c *IPConn) SetReceiveErrors(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.receiveErrors = enabled
		c.notifyReceiveLocked()
		return nil
	}
}

// ReceiveErrors reports whether asynchronous errors are reserved for
// ReadError instead of being returned by ordinary reads.
func (c *IPConn) ReceiveErrors() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.receiveErrors, nil
	}
}

// ReadError returns the oldest queued asynchronous network error without
// blocking. An empty queue reports EAGAIN, like a Linux MSG_ERRQUEUE read on a
// nonblocking descriptor. SetReceiveErrors(true) prevents ordinary reads from
// racing this method for queued errors.
func (c *IPConn) ReadError() (*net.OpError, error) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, c.operationError("read", net.ErrClosed)
	default:
	}
	queued, ok := c.errorState.pop()
	if !ok {
		c.mu.Unlock()
		return nil, c.operationError("read", syscall.EAGAIN)
	}
	c.notifyReceiveLocked()
	c.mu.Unlock()
	return queued.err, nil
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

// SetPathMTUDiscovery changes the Linux-compatible IP_MTU_DISCOVER policy for
// subsequent protocol-payload writes.
func (c *IPConn) SetPathMTUDiscovery(mode PathMTUDiscovery) error {
	if !mode.valid() {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.pathMTUDiscovery = mode
		return nil
	}
}

// PathMTUDiscovery returns the Linux-compatible IP_MTU_DISCOVER policy used by
// subsequent protocol-payload writes.
func (c *IPConn) PathMTUDiscovery() (PathMTUDiscovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return PathMTUDiscoveryDont, c.setOperationError(net.ErrClosed)
	default:
		return c.pathMTUDiscovery, nil
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
	c.recentTargets.remember(target, monotonicStampAt(c.stack.timestampEpoch, time.Now()))
	c.mu.Unlock()
}

// acceptsError reports whether ICMP quoted a recent write to target.
func (c *IPConn) acceptsError(target netip.Addr) bool {
	target = target.Unmap()
	if c.remote.IsValid() {
		return target == c.remote
	}
	c.mu.Lock()
	exists := c.recentTargets.contains(target, monotonicStampAt(c.stack.timestampEpoch, time.Now()))
	c.mu.Unlock()
	return exists
}

// acceptsPathMTU reports whether this socket accepts ICMP PMTU updates under
// its current Linux IP_MTU_DISCOVER policy.
func (c *IPConn) acceptsPathMTU() bool {
	c.mu.Lock()
	accepted := c.pathMTUDiscovery.acceptsPathMTU()
	c.mu.Unlock()
	return accepted
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
	if c.errorState == nil {
		c.errorState = &datagramSocketErrorState{}
	}
	errorState := c.errorState
	errorState.lastError = operationError
	size := socketErrorSize(err)
	if size > c.receiveCapacity || c.queuedBytes+errorState.queuedBytes > c.receiveCapacity-size {
		errorState.icmpErrors++
		errorState.dropped++
		c.mu.Unlock()
		return
	}
	var payload []byte
	var networkError ICMPError
	if errors.As(err, &networkError) {
		payload = networkError.QuotedPayload
		if c.ipHeaderIncludedOnWrite.Load() && len(networkError.QuotedPacket) != 0 {
			payload = networkError.QuotedPacket
		}
	}
	errorState.push(queuedSocketError{err: operationError, payload: payload, size: size})
	errorState.icmpErrors++
	c.notifyReceiveLocked()
	c.mu.Unlock()
}

// writeStateAndOptions reads the output defaults, PMTU policy, and raw IPv6
// checksum offset and returns the independent deadline and close signals
// observed by a blocked host-queue write.
func (c *IPConn) writeStateAndOptions(options ipPacketOptions) (socketWriteState, ipPacketOptions, PathMTUDiscovery, int) {
	c.mu.Lock()
	options = options.withDefaults(c.defaultOptions)
	pathMTUDiscovery := c.pathMTUDiscovery
	checksumOffset := c.ipv6ChecksumOffset
	c.mu.Unlock()
	return socketWriteState{datagram: &c.datagramSocketWriteControl}, options, pathMTUDiscovery, checksumOffset
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
