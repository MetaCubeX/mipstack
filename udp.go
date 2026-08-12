package mipstack

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// udpHeaderSize is the fixed UDP header length.
	udpHeaderSize = 8
	// udpDefaultReceiveCapacity bounds retained payload and queue metadata per
	// socket unless the application selects another value.
	udpDefaultReceiveCapacity = 4 * 1024 * 1024
	// udpDatagramMetadataSize conservatively accounts for the slice and source
	// address retained alongside each payload. In particular, empty datagrams
	// must consume capacity so they cannot grow the queue without bound.
	udpDatagramMetadataSize = 96
)

// udpDatagram is one validated inbound payload and its source endpoint.
type udpDatagram struct {
	payload []byte
	source  netip.AddrPort
	target  netip.Addr
	options ipPacketOptions
}

// UDPInfo is a point-in-time diagnostic snapshot of one UDP socket. Traffic
// byte counters measure UDP payload; receive-queue byte values also include
// the stack's per-datagram accounting overhead.
type UDPInfo struct {
	// LocalAddress is the bound local endpoint; an unspecified address denotes
	// a wildcard binding.
	LocalAddress netip.AddrPort
	// RemoteAddress is the connected peer, or an invalid endpoint for an
	// unconnected socket.
	RemoteAddress netip.AddrPort
	// Closed reports whether the socket was closed when the snapshot was taken.
	Closed bool
	// ReceiveQueuePackets is the number of complete datagrams awaiting a read.
	ReceiveQueuePackets int
	// ReceiveQueueBytes is the accounted payload and metadata retained by the
	// receive queue.
	ReceiveQueueBytes int
	// ReceiveQueueCapacity is the configured accounting-byte limit of the
	// combined datagram and error queues, not an exact heap-allocation limit.
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
	// PacketsSent counts successfully emitted UDP datagrams.
	PacketsSent uint64
	// BytesSent counts successfully emitted UDP payload bytes.
	BytesSent uint64
	// PacketsReceived counts datagrams accepted into the receive queue.
	PacketsReceived uint64
	// BytesReceived counts UDP payload bytes accepted into the receive queue.
	BytesReceived uint64
	// PacketsDropped counts datagrams rejected because the socket was closed or
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

// udpReuseEndpoints is the optional REUSEPORT dispatcher retained by Stack.
// The concrete registry is linked only when its public listen entry point is
// referenced.
type udpReuseEndpoints interface {
	// empty reports whether the registry contains no sockets.
	empty() bool
	// connections returns a snapshot of all registered sockets.
	connections() []*UDPConn
	// contains reports whether the registry owns a socket.
	contains(connection *UDPConn) bool
	// overlaps reports whether a binding conflicts with any registry entry.
	overlaps(address netip.Addr, port uint16, dual bool) bool
	// connection selects a socket for one local and remote endpoint pair.
	connection(binding, local, remote netip.AddrPort) *UDPConn
	// add registers a socket in its reuse-port group.
	add(connection *UDPConn)
	// remove unregisters a socket and reports whether it was present.
	remove(connection *UDPConn) bool
}

// udpSocketBinding supplies the registration policy shared by ListenUDP and
// ListenUDPReusePort.
type udpSocketBinding interface {
	// available reports whether the requested socket binding can be registered.
	available(stack *Stack, address netip.Addr, port uint16, dual bool) bool
	// register publishes one validated socket binding.
	register(stack *Stack, connection *UDPConn) error
}

// exclusiveUDPSocketBinding is the default one-owner bind policy.
type exclusiveUDPSocketBinding struct{}

// UDPConn is a connected or unconnected userspace UDP socket.
type UDPConn struct {
	stack *Stack
	net   string
	port  uint16
	v6    bool
	dual  bool
	// forwarded authorizes this socket's intercepted nonlocal address as an
	// explicit output source while promiscuous admission remains enabled.
	forwarded bool
	local     netip.Addr
	remote    netip.AddrPort

	closed chan struct{}
	once   sync.Once

	mu                sync.Mutex
	receive           datagramQueue[udpDatagram]
	receiveSpare      []byte
	receiveNotify     chan struct{}
	receiveCapacity   int
	queuedBytes       int
	errorQueue        datagramQueue[queuedSocketError]
	errorQueuedBytes  int
	receiveErrors     bool
	readDeadline      socketDeadline
	writeDeadline     socketDeadline
	recentTargets     recentDestinationCache[netip.AddrPort]
	defaultOptions    ipPacketOptions
	pathMTUDiscovery  PathMTUDiscovery
	multicastHopLimit byte
	multicastLoopback bool
	broadcast         bool
	automaticLabel    uint32
	lastError         error
	packetsSent       atomic.Uint64
	bytesSent         atomic.Uint64
	packetsReceived   atomic.Uint64
	bytesReceived     atomic.Uint64
	packetsDropped    atomic.Uint64
	icmpErrors        atomic.Uint64
	errorsDropped     atomic.Uint64
}

// udpWriteParameters is one validated output-policy snapshot shared by
// contiguous and scatter/gather writes.
type udpWriteParameters struct {
	source           netip.Addr
	target           netip.AddrPort
	options          ipPacketOptions
	pathMTUDiscovery PathMTUDiscovery
	nonUnicast       bool
}

// newUDPConn creates an unregistered UDP socket.
func newUDPConn(stack *Stack, network string, port uint16, v6 bool, local netip.Addr, remote netip.AddrPort) *UDPConn {
	defaults := DatagramSocketDefaults{ReceiveBuffer: udpDefaultReceiveCapacity, HopLimit: 64, MulticastHopLimit: 1}
	if stack != nil {
		defaults = stack.network.Load().udpDefaults
	}
	connection := &UDPConn{
		stack: stack, net: network, port: port, v6: v6, local: local, remote: remote,
		closed: make(chan struct{}), receiveNotify: make(chan struct{}, 1), receiveCapacity: defaults.ReceiveBuffer,
		defaultOptions: ipPacketOptions{
			hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
			flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
		},
		pathMTUDiscovery:  defaults.PathMTUDiscovery,
		multicastHopLimit: byte(defaults.MulticastHopLimit), multicastLoopback: !defaults.DisableMulticastLoopback,
		broadcast: !defaults.DisableBroadcast,
	}
	if remote.IsValid() && stack != nil && local.Is6() && remote.Addr().Is6() && defaults.FlowLabel == 0 {
		connection.automaticLabel = stack.automaticTransportFlowLabel(local, remote.Addr(), protocolUDP, port, remote.Port())
	}
	return connection
}

// available implements exclusive UDP binding.
func (exclusiveUDPSocketBinding) available(stack *Stack, address netip.Addr, port uint16, dual bool) bool {
	return stack.udpReuse == nil || !stack.udpReuse.overlaps(address, port, dual)
}

// register adds one exclusive UDP socket while Stack.mu is held.
func (exclusiveUDPSocketBinding) register(stack *Stack, connection *UDPConn) error {
	stack.udp[udpKey{address: connection.local, port: connection.port}] = connection
	return nil
}

// handleUDP validates and dispatches one unicast, broadcast, or multicast UDP
// datagram according to its already classified IP destination.
func (s *Stack) handleUDP(packet ipPacket, destination inboundDestinationClass) error {
	udp := packet.payload
	if len(udp) < udpHeaderSize {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length < udpHeaderSize || length > len(udp) {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	checksumValue := binary.BigEndian.Uint16(udp[6:8])
	if packet.source.Is6() && checksumValue == 0 || checksumValue != 0 && transportChecksum(packet.source, packet.target, protocolUDP, udp[:length]) != 0 {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	sourcePort := binary.BigEndian.Uint16(udp[0:2])
	targetPort := binary.BigEndian.Uint16(udp[2:4])
	source := netip.AddrPortFrom(packet.source, sourcePort)
	target := netip.AddrPortFrom(packet.target, targetPort)
	packet.payload = udp[:length]
	if destination == inboundDestinationMulticast {
		s.mu.RLock()
		multicast := s.multicast
		s.mu.RUnlock()
		if multicast != nil {
			multicast.deliverUDP(packet, sourcePort, targetPort)
		}
		return nil
	}
	if destination == inboundDestinationBroadcast {
		s.deliverBroadcastUDP(packet, source, targetPort)
		return nil
	}
	localDestination := destination == inboundDestinationLocalUnicast
	s.mu.RLock()
	connection := s.udpForwardedConnectionLocked(target, source)
	if connection == nil && localDestination {
		connection = s.udpOrdinaryConnectionLocked(target, source)
	}
	forwarder := s.udpForwarder
	s.mu.RUnlock()
	if connection == nil {
		options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
		if forwarder != nil && forwarder.handlePacket(packet, TransportFlow{Source: source, Destination: target}, options) {
			return nil
		}
		if !localDestination {
			return nil
		}
		_ = s.sendPortUnreachable(packet)
		return nil
	}
	if (!connection.local.IsUnspecified() && packet.target != connection.local) || (connection.remote.IsValid() && source != connection.remote) {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	connection.enqueue(udp[udpHeaderSize:length], source, packet.target, ipPacketOptions{
		hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel,
	})
	return nil
}

// deliverBroadcastUDP copies one IPv4 broadcast to every eligible wildcard
// binding. Unlike unicast REUSEPORT dispatch, Linux fans a broadcast out to
// every member of a matching reuse group.
func (s *Stack) deliverBroadcastUDP(packet ipPacket, source netip.AddrPort, targetPort uint16) {
	s.mu.RLock()
	var matchedStorage [8]*UDPConn
	matched := matchedStorage[:0]
	consider := func(connection *UDPConn) {
		if connection.forwarded || connection.port != targetPort || !connection.local.IsUnspecified() ||
			connection.local.Is6() && !connection.dual ||
			connection.remote.IsValid() && connection.remote != source {
			return
		}
		matched = append(matched, connection)
	}
	for _, connection := range s.udp {
		consider(connection)
	}
	if s.udpReuse != nil {
		for _, connection := range s.udpReuse.connections() {
			consider(connection)
		}
	}
	s.mu.RUnlock()
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	for _, connection := range matched {
		connection.enqueue(packet.payload[udpHeaderSize:], source, packet.target, options)
	}
}

// udpConnectionLocked selects an exact binding before a family wildcard and
// a dual-stack wildcard. REUSEPORT groups hash the complete flow tuple.
func (s *Stack) udpConnectionLocked(local, remote netip.AddrPort) *UDPConn {
	if connection := s.udpForwardedConnectionLocked(local, remote); connection != nil {
		return connection
	}
	return s.udpOrdinaryConnectionLocked(local, remote)
}

// udpForwardedConnectionLocked selects a connected forwarded flow before an
// unconnected forwarded endpoint bound to the original destination.
func (s *Stack) udpForwardedConnectionLocked(local, remote netip.AddrPort) *UDPConn {
	if connection := s.udpForwarded[udpFlowKey{local: local, remote: remote}]; connection != nil {
		return connection
	}
	return s.udpForwarded[udpFlowKey{local: local}]
}

// udpOrdinaryConnectionLocked selects an ordinary exact, wildcard, or
// REUSEPORT binding without considering forwarded four-tuples.
func (s *Stack) udpOrdinaryConnectionLocked(local, remote netip.AddrPort) *UDPConn {
	if connection := s.udp[udpKey{address: local.Addr(), port: local.Port()}]; connection != nil {
		return connection
	}
	if s.udpReuse != nil {
		if connection := s.udpReuse.connection(local, local, remote); connection != nil {
			return connection
		}
	}
	wildcard := netip.IPv4Unspecified()
	if local.Addr().Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	wildcardLocal := netip.AddrPortFrom(wildcard, local.Port())
	if connection := s.udp[udpKey{address: wildcard, port: local.Port()}]; connection != nil {
		return connection
	}
	if s.udpReuse != nil {
		if connection := s.udpReuse.connection(wildcardLocal, local, remote); connection != nil {
			return connection
		}
	}
	if local.Addr().Is4() {
		dualLocal := netip.AddrPortFrom(netip.IPv6Unspecified(), local.Port())
		if connection := s.udp[udpKey{address: dualLocal.Addr(), port: local.Port()}]; connection != nil && connection.dual {
			return connection
		}
		if s.udpReuse != nil {
			if connection := s.udpReuse.connection(dualLocal, local, remote); connection != nil && connection.dual {
				return connection
			}
		}
	}
	return nil
}

// acceptUDP registers one handler-approved connected endpoint and queues its
// triggering datagram before making the flow visible to concurrent input.
func (f *UDPForwarder) acceptUDP(request *UDPForwarderRequest) (*UDPConn, error) {
	stack := f.stack
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.udpForwarder != f {
		return nil, net.ErrClosed
	}
	state := stack.network.Load()
	local, remote := request.flow.Destination, request.flow.Source
	if !state.acceptsInboundDestination(local.Addr()) {
		return nil, syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(remote.Addr()); !routed {
		return nil, syscall.ENETUNREACH
	}
	key := udpFlowKey{local: local, remote: remote}
	if stack.udpForwardedConnectionLocked(local, remote) != nil || networkStateHasLocal(state, local.Addr()) && stack.udpOrdinaryConnectionLocked(local, remote) != nil {
		return nil, syscall.EADDRINUSE
	}
	network := "udp4"
	if local.Addr().Is6() {
		network = "udp6"
	}
	connection := newUDPConn(stack, network, local.Port(), local.Addr().Is6(), local.Addr(), remote)
	connection.forwarded = true
	connection.enqueue(request.Payload(), remote, local.Addr(), request.options)
	if stack.udpForwarded == nil {
		stack.udpForwarded = make(map[udpFlowKey]*UDPConn)
	}
	stack.udpForwarded[key] = connection
	stack.stats.activeUDPSockets.Add(1)
	return connection, nil
}

// listenUDP registers one handler-approved unconnected endpoint and queues its
// triggering datagram before making the local binding visible to concurrent
// input.
func (f *UDPForwarder) listenUDP(request *UDPForwarderRequest) (*UDPConn, error) {
	stack := f.stack
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.udpForwarder != f {
		return nil, net.ErrClosed
	}
	state := stack.network.Load()
	local, remote := request.flow.Destination, request.flow.Source
	if !state.acceptsInboundDestination(local.Addr()) {
		return nil, syscall.EADDRNOTAVAIL
	}
	key := udpFlowKey{local: local}
	for existing := range stack.udpForwarded {
		if existing.local == local {
			return nil, syscall.EADDRINUSE
		}
	}
	if networkStateHasLocal(state, local.Addr()) &&
		!stack.udpEndpointAvailableLocked(exclusiveUDPSocketBinding{}, local.Addr(), local.Port(), false) {
		return nil, syscall.EADDRINUSE
	}
	network := "udp4"
	if local.Addr().Is6() {
		network = "udp6"
	}
	connection := newUDPConn(stack, network, local.Port(), local.Addr().Is6(), local.Addr(), netip.AddrPort{})
	connection.forwarded = true
	connection.enqueue(request.Payload(), remote, local.Addr(), request.options)
	if stack.udpForwarded == nil {
		stack.udpForwarded = make(map[udpFlowKey]*UDPConn)
	}
	stack.udpForwarded[key] = connection
	stack.stats.activeUDPSockets.Add(1)
	return connection, nil
}

// validateUDPForwarderReply normalizes one caller-selected source and checks
// only properties required to serialize a reverse-flow UDP datagram.
func validateUDPForwarderReply(flow TransportFlow, payload []byte, source netip.AddrPort) (netip.AddrPort, error) {
	address := source.Addr()
	if !source.IsValid() {
		return netip.AddrPort{}, syscall.EINVAL
	}
	address = address.WithZone("").Unmap()
	if address.Is6() != flow.Source.Addr().Unmap().Is6() {
		return netip.AddrPort{}, syscall.EINVAL
	}
	if err := validateUDPForwarderReplyPayload(address.Is6(), payload); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(address, source.Port()), nil
}

// validateUDPForwarderReplyPayload checks the address-family datagram limit.
func validateUDPForwarderReplyPayload(ipv6 bool, payload []byte) error {
	maximumPayload := 65535 - udpHeaderSize
	if !ipv6 {
		maximumPayload -= 20
	}
	if len(payload) > maximumPayload {
		return syscall.EMSGSIZE
	}
	return nil
}

// replyUDPFlow sends one reverse-flow response from a validated caller-selected
// source without retaining a registered endpoint after the write completes.
func (f *UDPForwarder) replyUDPFlow(flow TransportFlow, payload []byte, source netip.AddrPort) (int, error) {
	local, remote := flow.Destination, flow.Source
	state := f.stack.network.Load()
	if !state.acceptsInboundDestination(local.Addr()) {
		return 0, syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(remote.Addr()); !routed {
		return 0, syscall.ENETUNREACH
	}
	defaults := state.udpDefaults
	options := ipPacketOptions{
		hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
		flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
	}
	if err := f.stack.tryWriteUDPDatagram(source.Addr(), remote.Addr(), source.Port(), remote.Port(), payload, options, defaults.PathMTUDiscovery); err != nil {
		return 0, err
	}
	return len(payload), nil
}

// acceptsLocal reports whether an ICMP quote belongs to this socket's local
// address binding.
func (c *UDPConn) acceptsLocal(address netip.Addr) bool {
	return c.local.IsUnspecified() || c.local == address.Unmap()
}

// enqueue copies and retains a datagram unless the configured receive
// capacity is full. The capacity check precedes allocation on the drop path.
func (c *UDPConn) enqueue(payload []byte, source netip.AddrPort, target netip.Addr, options ipPacketOptions) {
	size := udpDatagramSize(payload)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		c.stack.stats.inboundDroppedPackets.Add(1)
		c.packetsDropped.Add(1)
		return
	default:
	}
	if size > c.receiveCapacity || c.queuedBytes+c.errorQueuedBytes > c.receiveCapacity-size {
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
	datagram := udpDatagram{payload: retained, source: source, target: target, options: options}
	c.receive.push(datagram)
	c.queuedBytes += size
	c.packetsReceived.Add(1)
	c.bytesReceived.Add(uint64(len(payload)))
	c.notifyReceiveLocked()
	c.mu.Unlock()
}

// notifyReceiveLocked keeps one edge notification armed while queued data
// remains and removes a stale token when the queue becomes empty.
func (c *UDPConn) notifyReceiveLocked() {
	if c.receive.len() != 0 || !c.receiveErrors && c.errorQueue.len() != 0 {
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

// udpDatagramSize returns the approximate retained-memory cost of a payload.
func udpDatagramSize(payload []byte) int {
	return udpDatagramMetadataSize + len(payload)
}

// ReadFrom returns the next complete datagram or socket error.
func (c *UDPConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, source, _, _, _, err := c.readDatagram(buffer)
	var address net.Addr
	if source.IsValid() {
		address = net.UDPAddrFromAddrPort(source)
	}
	if err != nil {
		return n, address, c.operationError("read", c.remoteAddr(), err)
	}
	return n, address, nil
}

// ReadFromUDP acts like ReadFrom but returns a UDPAddr.
func (c *UDPConn) ReadFromUDP(buffer []byte) (int, *net.UDPAddr, error) {
	n, source, _, _, _, err := c.readDatagram(buffer)
	var address *net.UDPAddr
	if source.IsValid() {
		address = net.UDPAddrFromAddrPort(source)
	}
	if err != nil {
		return n, address, c.operationError("read", c.remoteAddr(), err)
	}
	return n, address, nil
}

// ReadFromUDPAddrPort acts like ReadFrom but returns a netip.AddrPort.
func (c *UDPConn) ReadFromUDPAddrPort(buffer []byte) (int, netip.AddrPort, error) {
	n, source, _, _, _, err := c.readDatagram(buffer)
	if err != nil {
		return n, source, c.operationError("read", c.remoteAddr(), err)
	}
	return n, source, nil
}

// ReadMsgUDP reads one datagram and Linux-compatible packet-info ancillary
// data. The control message identifies the local destination address.
func (c *UDPConn) ReadMsgUDP(buffer, oob []byte) (n, oobn, flags int, address *net.UDPAddr, err error) {
	var source netip.AddrPort
	n, oobn, flags, source, err = c.readMsgUDPAddrPort(buffer, oob)
	if source.IsValid() {
		address = net.UDPAddrFromAddrPort(source)
	}
	return
}

// ReadMsgUDPAddrPort is the netip.AddrPort form of ReadMsgUDP.
func (c *UDPConn) ReadMsgUDPAddrPort(buffer, oob []byte) (n, oobn, flags int, source netip.AddrPort, err error) {
	return c.readMsgUDPAddrPort(buffer, oob)
}

// readMsgUDPAddrPort reads one datagram and encodes its local destination as
// Linux IP_PKTINFO or IPV6_PKTINFO.
func (c *UDPConn) readMsgUDPAddrPort(buffer, oob []byte) (n, oobn, flags int, source netip.AddrPort, err error) {
	var target netip.Addr
	var options ipPacketOptions
	var truncated bool
	n, source, target, options, truncated, err = c.readDatagram(buffer)
	if truncated {
		flags |= MessageTruncated
	}
	if err != nil {
		err = c.operationError("read", c.remoteAddr(), err)
		return
	}
	control, controlErr := controlMessageForRead(target, options)
	if controlErr != nil {
		err = c.operationError("read", c.remoteAddr(), controlErr)
		return
	}
	oobn = copy(oob, control)
	if oobn < len(control) {
		flags |= MessageControlTruncated
	}
	return
}

// ReadBatch reads one or more UDP messages using the Message layout shared by
// x/net/ipv4 and x/net/ipv6. The first message follows the socket's blocking
// and deadline semantics; after it succeeds, the method drains only messages
// already queued. MessageDontWait also makes the first read nonblocking.
func (c *UDPConn) ReadBatch(messages []Message, flags int) (int, error) {
	if flags&^MessageDontWait != 0 {
		return 0, c.operationError("read", c.remoteAddr(), syscall.EOPNOTSUPP)
	}
	for index := range messages {
		wait := index == 0 && flags&MessageDontWait == 0
		err := c.readBatchMessage(&messages[index], wait, index == 0)
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
func (c *UDPConn) readBatchMessage(message *Message, wait, consumeErrors bool) error {
	if _, err := messageBufferLength(message.Buffers); err != nil {
		return c.operationError("read", c.remoteAddr(), err)
	}
	n, source, target, options, truncated, err := c.readDatagramBuffers(message.Buffers, wait, consumeErrors)
	if err != nil {
		return c.operationError("read", c.remoteAddr(), err)
	}
	control, err := controlMessageForRead(target, options)
	if err != nil {
		return c.operationError("read", c.remoteAddr(), err)
	}
	flags := 0
	if truncated {
		flags |= MessageTruncated
	}
	oobn := copy(message.OOB, control)
	if oobn < len(control) {
		flags |= MessageControlTruncated
	}
	message.N, message.NN, message.Flags = n, oobn, flags
	if source.IsValid() {
		message.Addr = net.UDPAddrFromAddrPort(source)
	} else {
		message.Addr = nil
	}
	return nil
}

// Read receives the next datagram from a connected remote endpoint.
func (c *UDPConn) Read(buffer []byte) (int, error) {
	n, _, _, _, _, err := c.readDatagram(buffer)
	if err != nil {
		return n, c.operationError("read", c.remoteAddr(), err)
	}
	return n, nil
}

// readDatagram returns one datagram without adding the public net.OpError
// wrapper. truncated reports that the payload did not fit in buffer.
func (c *UDPConn) readDatagram(buffer []byte) (n int, source netip.AddrPort, target netip.Addr, options ipPacketOptions, truncated bool, err error) {
	return c.readDatagramBuffers([][]byte{buffer}, true, true)
}

// readDatagramBuffers is the scatter/gather and nonblocking form used by
// ReadBatch. It returns EAGAIN without consuming state when wait is false and
// neither a datagram nor an ordinary-read error is ready.
func (c *UDPConn) readDatagramBuffers(buffers [][]byte, wait, consumeErrors bool) (n int, source netip.AddrPort, target netip.Addr, options ipPacketOptions, truncated bool, err error) {
	for {
		c.mu.Lock()
		select {
		case <-c.closed:
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, net.ErrClosed
		default:
		}
		timeout := c.readDeadline.wait()
		select {
		case <-timeout:
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
		default:
		}
		if datagram, ok := c.receive.pop(); ok {
			c.queuedBytes -= udpDatagramSize(datagram.payload)
			c.notifyReceiveLocked()
			c.mu.Unlock()
			n = copyMessagePayload(buffers, datagram.payload)
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
			return n, datagram.source, datagram.target, datagram.options, n < len(datagram.payload), nil
		}
		if !c.receiveErrors && consumeErrors {
			if queued, ok := c.errorQueue.pop(); ok {
				c.errorQueuedBytes -= queued.size
				c.notifyReceiveLocked()
				c.mu.Unlock()
				return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, queued.err
			}
		}
		if !wait {
			c.mu.Unlock()
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, syscall.EAGAIN
		}
		notified := c.receiveNotify
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, net.ErrClosed
		}
	}
}

// WriteTo sends one datagram, fragmenting its IP payload when required.
func (c *UDPConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	netAddress := address
	if udp, ok := address.(*net.UDPAddr); ok {
		netAddress = udpNetAddr(udp)
		if c.remote.IsValid() {
			return 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
		}
	}
	target, err := udpAddrPort(address)
	if err != nil {
		return 0, c.operationError("write", netAddress, err)
	}
	if c.remote.IsValid() {
		return 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
	}
	n, err := c.writeTo(payload, target)
	if err != nil {
		return n, c.operationError("write", netAddress, err)
	}
	return n, nil
}

// WriteToUDP acts like WriteTo but accepts a UDPAddr directly.
func (c *UDPConn) WriteToUDP(payload []byte, address *net.UDPAddr) (int, error) {
	netAddress := udpNetAddr(address)
	if c.remote.IsValid() {
		return 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
	}
	if address == nil {
		return 0, c.operationError("write", nil, errors.New("mipstack: UDP destination is required"))
	}
	return c.writeToUDPAddrPort(payload, address.AddrPort(), address)
}

// WriteToUDPAddrPort acts like WriteTo but accepts a netip.AddrPort directly.
func (c *UDPConn) WriteToUDPAddrPort(payload []byte, address netip.AddrPort) (int, error) {
	netAddress := addrPortUDPAddr{address}
	if c.remote.IsValid() {
		return 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
	}
	target := netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	n, err := c.writeTo(payload, target)
	if err != nil {
		return n, c.operationError("write", netAddress, err)
	}
	return n, nil
}

// writeToUDPAddrPort applies unconnected-socket validation and the public
// operation wrapper shared by the typed WriteTo methods.
func (c *UDPConn) writeToUDPAddrPort(payload []byte, target netip.AddrPort, address net.Addr) (int, error) {
	if c.remote.IsValid() {
		return 0, c.operationError("write", address, net.ErrWriteToConnected)
	}
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	n, err := c.writeTo(payload, target)
	if err != nil {
		return n, c.operationError("write", address, err)
	}
	return n, nil
}

// Write sends one datagram to the connected remote endpoint.
func (c *UDPConn) Write(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", nil, errors.New("mipstack: UDP socket is not connected"))
	}
	n, err := c.writeTo(payload, c.remote)
	if err != nil {
		return n, c.operationError("write", c.remoteAddr(), err)
	}
	return n, nil
}

// WritePathMTUProbe sends one connected UDP datagram without IPv4 or IPv6
// fragmentation, permitting a size above the confirmed PMTU up to the
// configured first-hop MTU. The application must confirm delivery separately.
func (c *UDPConn) WritePathMTUProbe(payload []byte) (int, error) {
	if !c.remote.IsValid() {
		return 0, c.operationError("write", nil, errors.New("mipstack: UDP socket is not connected"))
	}
	if c.remote.Addr().IsMulticast() || c.stack.network.Load().broadcastDestination(c.remote.Addr()) {
		return 0, c.operationError("write", c.remoteAddr(), syscall.EOPNOTSUPP)
	}
	n, err := c.writeToFromWith(payload, c.remote, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbeDatagram)
	if err != nil {
		return n, c.operationError("write", c.remoteAddr(), err)
	}
	return n, nil
}

// WritePathMTUProbeTo is the unconnected netip form of WritePathMTUProbe.
func (c *UDPConn) WritePathMTUProbeTo(payload []byte, target netip.AddrPort) (int, error) {
	if c.remote.IsValid() {
		return 0, c.operationError("write", net.UDPAddrFromAddrPort(target), net.ErrWriteToConnected)
	}
	if target.Addr().IsMulticast() || c.stack.network.Load().broadcastDestination(target.Addr()) {
		return 0, c.operationError("write", net.UDPAddrFromAddrPort(target), syscall.EOPNOTSUPP)
	}
	n, err := c.writeToFromWith(payload, target, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbeDatagram)
	if err != nil {
		return n, c.operationError("write", net.UDPAddrFromAddrPort(target), err)
	}
	return n, nil
}

// ConfirmPathMTU records application-level acknowledgement of a connected
// UDP probe. mtu is the complete IP packet size, not the UDP payload size.
func (c *UDPConn) ConfirmPathMTU(mtu int) error {
	if !c.remote.IsValid() {
		return c.setOperationError(syscall.ENOTCONN)
	}
	if err := c.stack.ConfirmPathMTU(c.remote.Addr(), mtu); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

// ConfirmPathMTUFor is the unconnected form of ConfirmPathMTU.
func (c *UDPConn) ConfirmPathMTUFor(target netip.Addr, mtu int) error {
	if c.remote.IsValid() {
		return c.setOperationError(net.ErrWriteToConnected)
	}
	if err := c.stack.ConfirmPathMTU(target, mtu); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

// WriteMsgUDP writes a payload using Linux-compatible packet-info ancillary
// data. A connected socket requires a nil address.
func (c *UDPConn) WriteMsgUDP(payload, oob []byte, address *net.UDPAddr) (n, oobn int, err error) {
	netAddress := udpNetAddr(address)
	var target netip.AddrPort
	if c.remote.IsValid() {
		if address != nil {
			return 0, 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
		}
		target = c.remote
	} else {
		if address == nil {
			return 0, 0, c.operationError("write", nil, errors.New("mipstack: UDP destination is required"))
		}
		target = address.AddrPort()
	}
	n, oobn, err = c.writeMsgUDPAddrPort(payload, oob, target)
	if err != nil {
		return n, oobn, c.operationError("write", netAddress, err)
	}
	return n, oobn, nil
}

// WriteMsgUDPAddrPort is the netip.AddrPort form of WriteMsgUDP. A connected
// socket requires an invalid address.
func (c *UDPConn) WriteMsgUDPAddrPort(payload, oob []byte, address netip.AddrPort) (n, oobn int, err error) {
	netAddress := addrPortUDPAddr{address}
	if c.remote.IsValid() {
		if address.IsValid() {
			return 0, 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
		}
		address = c.remote
	} else {
		if !address.IsValid() {
			return 0, 0, c.operationError("write", netAddress, errors.New("mipstack: UDP destination is required"))
		}
	}
	n, oobn, err = c.writeMsgUDPAddrPort(payload, oob, address)
	if err != nil {
		return n, oobn, c.operationError("write", netAddress, err)
	}
	return n, oobn, nil
}

// WriteBatch writes a prefix of UDP messages using scatter/gather payloads.
// Flags other than zero are unsupported because packet-queue backpressure and
// deadlines are expressed by the socket rather than an operating-system fd.
func (c *UDPConn) WriteBatch(messages []Message, flags int) (int, error) {
	if flags != 0 {
		return 0, c.operationError("write", c.remoteAddr(), syscall.EOPNOTSUPP)
	}
	for index := range messages {
		message := &messages[index]
		n, oobn, err := c.writeBatchMessage(message)
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
func (c *UDPConn) writeBatchMessage(message *Message) (int, int, error) {
	var target netip.AddrPort
	var address net.Addr
	if c.remote.IsValid() {
		if message.Addr != nil {
			return 0, 0, c.operationError("write", message.Addr, net.ErrWriteToConnected)
		}
		target, address = c.remote, c.remoteAddr()
	} else {
		address = message.Addr
		var err error
		target, err = udpAddrPort(address)
		if err != nil {
			return 0, 0, c.operationError("write", address, err)
		}
		target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	}
	validated, err := c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, c.operationError("write", address, err)
	}
	maximum := 65535 - udpHeaderSize
	if validated.Addr().Is4() {
		maximum -= 20
	}
	payloadSize, err := messageBufferLength(message.Buffers)
	if err != nil {
		return 0, 0, c.operationError("write", address, err)
	}
	if payloadSize > maximum {
		return 0, 0, c.operationError("write", address, syscall.EMSGSIZE)
	}
	if len(message.Buffers) == 1 {
		n, oobn, err := c.writeMsgUDPAddrPort(message.Buffers[0], message.OOB, validated)
		if err != nil {
			return n, oobn, c.operationError("write", address, err)
		}
		return n, oobn, nil
	}
	if err = (socketWriteState{deadline: &c.writeDeadline, closed: c.closed}).err(); err != nil {
		return 0, 0, c.operationError("write", address, err)
	}
	source, options, err := parseControlMessageForWrite(message.OOB, validated.Addr().Is6())
	if err != nil {
		return 0, 0, c.operationError("write", address, err)
	}
	n, err := c.writeBuffersToFrom(message.Buffers, payloadSize, validated, source, options)
	if err != nil {
		return n, 0, c.operationError("write", address, err)
	}
	return n, len(message.OOB), nil
}

// writeMsgUDPAddrPort parses packet-info source selection and sends one
// datagram without wrapping errors. oobn is reported only when the complete
// message was accepted.
func (c *UDPConn) writeMsgUDPAddrPort(payload, oob []byte, target netip.AddrPort) (n, oobn int, err error) {
	target, err = c.validateWriteTarget(target)
	if err != nil {
		return 0, 0, err
	}
	// net converts the destination before entering poll.SendMsg, then poll
	// reports an expired deadline or closed descriptor before the kernel parses
	// ancillary data. Preserve that observable error precedence.
	if err = (socketWriteState{deadline: &c.writeDeadline, closed: c.closed}).err(); err != nil {
		return 0, 0, err
	}
	source, options, err := parseControlMessageForWrite(oob, target.Addr().Is6())
	if err != nil {
		return 0, 0, err
	}
	n, err = c.writeToFrom(payload, target, source, options)
	if err != nil {
		return n, 0, err
	}
	return n, len(oob), nil
}

// writeTo sends one datagram without adding the public net.OpError wrapper.
func (c *UDPConn) writeTo(payload []byte, target netip.AddrPort) (int, error) {
	return c.writeToFrom(payload, target, netip.Addr{}, ipPacketOptions{})
}

// writeToFrom sends one datagram with an optional packet-info source address.
func (c *UDPConn) writeToFrom(payload []byte, target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	return c.writeToFromWith(payload, target, packetInfoSource, options, c.writeDatagram)
}

// prepareWrite snapshots socket policy and selects the source for one output
// operation without retaining any caller payload.
func (c *UDPConn) prepareWrite(target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions) (udpWriteParameters, error) {
	target, err := c.validateWriteTarget(target)
	if err != nil {
		return udpWriteParameters{}, err
	}
	writeState, options, pathMTUDiscovery := c.writeStateAndOptions(options)
	if err = writeState.err(); err != nil {
		return udpWriteParameters{}, err
	}
	requestedSource := c.local
	packetInfoSource = packetInfoSource.Unmap()
	if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() {
		if !c.local.IsUnspecified() && packetInfoSource != c.local {
			return udpWriteParameters{}, syscall.EADDRNOTAVAIL
		}
		requestedSource = packetInfoSource
	}
	var source netip.Addr
	nonUnicast := false
	if c.forwarded {
		if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() && packetInfoSource != c.local {
			return udpWriteParameters{}, syscall.EADDRNOTAVAIL
		}
		state := c.stack.network.Load()
		if !state.acceptsInboundDestination(c.local) {
			return udpWriteParameters{}, syscall.EADDRNOTAVAIL
		}
		if _, routed := state.routeFor(target.Addr()); !routed {
			return udpWriteParameters{}, syscall.ENETUNREACH
		}
		source = c.local
	} else {
		source, nonUnicast, err = c.stack.sourceForOutput(target.Addr(), requestedSource)
		if err != nil {
			return udpWriteParameters{}, err
		}
	}
	return udpWriteParameters{
		source: source.Unmap(), target: target, options: options,
		pathMTUDiscovery: pathMTUDiscovery, nonUnicast: nonUnicast,
	}, nil
}

// writeToFromWith keeps source selection, checksums, deadlines, accounting,
// and ICMP correlation shared while leaving optional output policies
// independently reachable by the linker.
func (c *UDPConn) writeToFromWith(payload []byte, target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions, write func(netip.Addr, netip.Addr, uint16, uint16, []byte, ipPacketOptions, PathMTUDiscovery, bool) error) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options)
	if err != nil {
		return 0, err
	}
	maximumPayload := 65535 - udpHeaderSize
	if parameters.target.Addr().Is4() {
		maximumPayload -= 20
	}
	if len(payload) > maximumPayload {
		return 0, syscall.EMSGSIZE
	}
	writeErr := write(parameters.source, parameters.target.Addr(), c.port, parameters.target.Port(), payload, parameters.options, parameters.pathMTUDiscovery, parameters.nonUnicast)
	if writeErr != nil {
		if errors.Is(writeErr, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, writeErr
	}
	if !parameters.nonUnicast {
		c.rememberTarget(parameters.target)
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(payload)))
	return len(payload), nil
}

// writeBuffersToFrom sends one validated scatter/gather payload. The common
// unicast, unfragmented case copies directly into queue-owned packet storage;
// uncommon fragmentation and non-unicast cases retain the established path.
func (c *UDPConn) writeBuffersToFrom(buffers [][]byte, payloadSize int, target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions) (int, error) {
	parameters, err := c.prepareWrite(target, packetInfoSource, options)
	if err != nil {
		return 0, err
	}
	maximumPayload := 65535 - udpHeaderSize
	if parameters.target.Addr().Is4() {
		maximumPayload -= 20
	}
	if payloadSize > maximumPayload {
		return 0, syscall.EMSGSIZE
	}
	if parameters.nonUnicast {
		payload, gatherErr := gatherMessagePayload(buffers, maximumPayload)
		if gatherErr != nil {
			return 0, gatherErr
		}
		err = c.writeNonUnicastDatagram(parameters.source, parameters.target.Addr(), c.port, parameters.target.Port(), payload, parameters.options, parameters.pathMTUDiscovery)
	} else {
		mtu, fragmentation := c.stack.pathMTUOutputPolicy(parameters.target.Addr(), parameters.pathMTUDiscovery)
		err = c.writeDatagramBuffersForMTU(parameters.source, parameters.target.Addr(), c.port, parameters.target.Port(), buffers, payloadSize, parameters.options, fragmentation, mtu)
	}
	if err != nil {
		return 0, err
	}
	if !parameters.nonUnicast {
		c.rememberTarget(parameters.target)
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(payloadSize))
	return payloadSize, nil
}

// writeDatagram emits ordinary UDP output against the confirmed path MTU and
// permits source fragmentation.
func (c *UDPConn) writeDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, nonUnicast bool) error {
	if nonUnicast {
		return c.writeNonUnicastDatagram(source, target, sourcePort, targetPort, payload, options, pathMTUDiscovery)
	}
	mtu, fragmentation := c.stack.pathMTUOutputPolicy(target, pathMTUDiscovery)
	return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, fragmentation, mtu)
}

// tryWriteUDPDatagram atomically queues one best-effort UDP datagram or all of
// its source fragments without waiting for device capacity.
func (s *Stack) tryWriteUDPDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery) error {
	udpSize := udpHeaderSize + len(payload)
	if udpSize > 65535 {
		return syscall.EMSGSIZE
	}
	datagram := make([]byte, udpSize)
	marshalUDPDatagram(datagram, source, target, sourcePort, targetPort, payload)
	mtu, fragmentation := s.pathMTUOutputPolicy(target, pathMTUDiscovery)
	packets, err := s.ipPayloadPacketsForMTU(source, target, protocolUDP, datagram, fragmentation, options, mtu)
	if err != nil {
		return err
	}
	return s.tryWritePackets(packets)
}

// writePathMTUProbeDatagram is retained only when an application references
// the UDP packetization-layer probing API.
func (c *UDPConn) writePathMTUProbeDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, _ PathMTUDiscovery, _ bool) error {
	return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, sourceFragmentation{dontFragment: true}, c.stack.network.Load().mtu)
}

// writeDatagramForMTU serializes the common unfragmented case directly into
// its final IP packet. Only datagrams that actually require source
// fragmentation need a separate contiguous UDP segment.
func (c *UDPConn) writeDatagramForMTU(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, fragmentation sourceFragmentation, mtu int) error {
	udpSize := udpHeaderSize + len(payload)
	ipSize := ipHeaderSize(source, target, udpSize)
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = c.automaticLabel
		if options.flowLabel == 0 || !c.remote.IsValid() || target != c.remote.Addr() || sourcePort != c.port || targetPort != c.remote.Port() {
			options.flowLabel = c.stack.automaticTransportFlowLabel(source, target, protocolUDP, sourcePort, targetPort)
		}
		options.flowLabelSet = true
	}
	if ipSize+udpSize <= mtu {
		identification := uint16(0)
		if source.Is4() && fragmentation.requiresIPv4ID() {
			identification = uint16(c.stack.ipv4ID.Add(1))
		}
		queue, loopback := c.stack.outputQueueFor(target)
		state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed}
		slot, err := c.stack.reservePacketUntil(queue, loopback, state)
		if err != nil {
			return err
		}
		packet, reusable := queue.acquireBuffer(ipSize + udpSize)
		if !marshalIPHeader(packet, source, target, protocolUDP, identification, fragmentation.dontFragment, options) {
			queue.releaseBuffer(packet, reusable)
			queue.releaseReserved(slot)
			return syscall.EMSGSIZE
		}
		udp := packet[ipSize:]
		marshalUDPDatagram(udp, source, target, sourcePort, targetPort, payload)
		if !queue.enqueueReservedPacket(slot, packet, reusable) {
			return ErrClosed
		}
		c.stack.recordOutput(loopback)
		return nil
	}
	if !fragmentation.allow {
		return syscall.EMSGSIZE
	}
	var udpHeader [udpHeaderSize]byte
	binary.BigEndian.PutUint16(udpHeader[0:2], sourcePort)
	binary.BigEndian.PutUint16(udpHeader[2:4], targetPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(udpSize))
	value := transportChecksumParts(source, target, protocolUDP, udpSize, udpHeader[:], payload)
	if value == 0 {
		value = 0xffff
	}
	binary.BigEndian.PutUint16(udpHeader[6:8], value)
	state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed}
	return c.stack.writeIPFragmentsUntilOptionsForMTU(source, target, protocolUDP, udpHeader[:], payload, options, mtu, state)
}

// writeDatagramBuffersForMTU is the allocation-free scatter/gather form of
// writeDatagramForMTU for a fitting packet. Fragmentation falls back to one
// contiguous payload because the fragment writer streams contiguous regions.
func (c *UDPConn) writeDatagramBuffersForMTU(source, target netip.Addr, sourcePort, targetPort uint16, buffers [][]byte, payloadSize int, options ipPacketOptions, fragmentation sourceFragmentation, mtu int) error {
	udpSize := udpHeaderSize + payloadSize
	ipSize := ipHeaderSize(source, target, udpSize)
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	if ipSize+udpSize > mtu {
		if !fragmentation.allow {
			return syscall.EMSGSIZE
		}
		payload, err := gatherMessagePayload(buffers, payloadSize)
		if err != nil {
			return err
		}
		return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, fragmentation, mtu)
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = c.automaticLabel
		if options.flowLabel == 0 || !c.remote.IsValid() || target != c.remote.Addr() || sourcePort != c.port || targetPort != c.remote.Port() {
			options.flowLabel = c.stack.automaticTransportFlowLabel(source, target, protocolUDP, sourcePort, targetPort)
		}
		options.flowLabelSet = true
	}
	identification := uint16(0)
	if source.Is4() && fragmentation.requiresIPv4ID() {
		identification = uint16(c.stack.ipv4ID.Add(1))
	}
	queue, loopback := c.stack.outputQueueFor(target)
	state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed}
	slot, err := c.stack.reservePacketUntil(queue, loopback, state)
	if err != nil {
		return err
	}
	packet, reusable := queue.acquireBuffer(ipSize + udpSize)
	if !marshalIPHeader(packet, source, target, protocolUDP, identification, fragmentation.dontFragment, options) {
		queue.releaseBuffer(packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EMSGSIZE
	}
	udp := packet[ipSize:]
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], targetPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpSize))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	if copied := copyMessageBuffers(udp[udpHeaderSize:], buffers); copied != payloadSize {
		queue.releaseBuffer(packet, reusable)
		queue.releaseReserved(slot)
		return syscall.EINVAL
	}
	checksumValue := transportChecksum(source, target, protocolUDP, udp)
	if checksumValue == 0 {
		checksumValue = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksumValue)
	if !queue.enqueueReservedPacket(slot, packet, reusable) {
		return ErrClosed
	}
	c.stack.recordOutput(loopback)
	return nil
}

// marshalUDPDatagram writes one UDP header, payload, and checksum into dst.
func marshalUDPDatagram(dst []byte, source, target netip.Addr, sourcePort, targetPort uint16, payload []byte) {
	binary.BigEndian.PutUint16(dst[0:2], sourcePort)
	binary.BigEndian.PutUint16(dst[2:4], targetPort)
	binary.BigEndian.PutUint16(dst[4:6], uint16(len(dst)))
	binary.BigEndian.PutUint16(dst[6:8], 0)
	copy(dst[udpHeaderSize:], payload)
	value := transportChecksum(source, target, protocolUDP, dst)
	if value == 0 {
		value = 0xffff
	}
	binary.BigEndian.PutUint16(dst[6:8], value)
}

// rememberTarget records an actual WriteTo destination for ICMP tuple
// validation. The oldest entries are discarded when the bound is reached.
func (c *UDPConn) rememberTarget(target netip.AddrPort) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
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

// acceptsError reports whether ICMP quoted a recent datagram from this
// unconnected socket to the exact remote endpoint.
func (c *UDPConn) acceptsError(target netip.AddrPort) bool {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if c.remote.IsValid() {
		return target == c.remote
	}
	c.mu.Lock()
	exists := c.recentTargets.contains(target, time.Now())
	c.mu.Unlock()
	return exists
}

// acceptsPathMTU reports whether this socket accepts ICMP PMTU updates under
// its current Linux IP_MTU_DISCOVER policy.
func (c *UDPConn) acceptsPathMTU() bool {
	c.mu.Lock()
	accepted := c.pathMTUDiscovery.acceptsPathMTU()
	c.mu.Unlock()
	return accepted
}

// deliverError queues a destination-associated asynchronous network error.
func (c *UDPConn) deliverError(target netip.AddrPort, err error) {
	operationError := &net.OpError{
		Op: "read", Net: c.net, Source: c.LocalAddr(),
		Addr: net.UDPAddrFromAddrPort(target), Err: err,
	}
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	c.lastError = operationError
	size := socketErrorSize(err)
	if size > c.receiveCapacity || c.queuedBytes+c.errorQueuedBytes > c.receiveCapacity-size {
		c.mu.Unlock()
		c.icmpErrors.Add(1)
		c.errorsDropped.Add(1)
		return
	}
	c.errorQueue.push(queuedSocketError{err: operationError, size: size})
	c.errorQueuedBytes += size
	c.notifyReceiveLocked()
	c.mu.Unlock()
	c.icmpErrors.Add(1)
}

// udpAddrPort converts a net.Addr without performing name resolution.
func udpAddrPort(address net.Addr) (netip.AddrPort, error) {
	if address == nil {
		return netip.AddrPort{}, errors.New("mipstack: UDP destination is required")
	}
	if udp, ok := address.(*net.UDPAddr); ok {
		if udp == nil {
			return netip.AddrPort{}, errors.New("mipstack: UDP destination is required")
		}
		return udp.AddrPort(), nil
	}
	result, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return netip.AddrPort{}, errors.New("mipstack: invalid UDP destination")
	}
	return result, nil
}

// validateWriteTarget normalizes one UDP destination and applies the address
// conversion errors that net reports before deadline and ancillary-data work.
func (c *UDPConn) validateWriteTarget(target netip.AddrPort) (netip.AddrPort, error) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	address := target.Addr()
	if !target.IsValid() || address.IsUnspecified() || address.Zone() != "" {
		return netip.AddrPort{}, errors.New("mipstack: invalid UDP destination")
	}
	if !c.dual && address.Is6() != c.v6 {
		family := "IPv4"
		if c.v6 {
			family = "IPv6"
		}
		return netip.AddrPort{}, &net.AddrError{Err: "non-" + family + " address", Addr: address.String()}
	}
	return target, nil
}

// addrPortUDPAddr preserves the netip argument in operation errors just as
// the standard library's AddrPort-based UDP methods do.
type addrPortUDPAddr struct{ netip.AddrPort }

// Network returns the UDP network name required by net.Addr.
func (addrPortUDPAddr) Network() string { return "udp" }

// udpNetAddr avoids storing a typed nil pointer in net.OpError.Addr.
func udpNetAddr(address *net.UDPAddr) net.Addr {
	if address == nil {
		return nil
	}
	return address
}

// Close unregisters the socket and wakes blocked reads.
func (c *UDPConn) Close() error {
	if c.stack.closeUDP(c) {
		return nil
	}
	return c.operationError("close", c.remoteAddr(), net.ErrClosed)
}

// closeFromStack publishes closure exactly once and releases payload-bearing
// and error-correlation state.
func (c *UDPConn) closeFromStack() {
	c.once.Do(func() {
		c.mu.Lock()
		c.readDeadline.stop()
		c.writeDeadline.stop()
		c.receive.clear()
		c.errorQueue.clear()
		c.receiveSpare = nil
		c.queuedBytes = 0
		c.errorQueuedBytes = 0
		c.recentTargets = nil
		c.lastError = nil
		close(c.closed)
		c.mu.Unlock()
	})
}

// LocalAddr returns the unspecified family address and allocated port.
func (c *UDPConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(c.local, c.port))
}

// RemoteAddr returns the connected UDP endpoint, or nil for an unconnected
// packet socket.
func (c *UDPConn) RemoteAddr() net.Addr { return c.remoteAddr() }

// Info returns a diagnostic snapshot of the socket and its receive queue.
func (c *UDPConn) Info() UDPInfo {
	c.mu.Lock()
	automaticFlowLabel := !c.defaultOptions.flowLabelSet
	flowLabel := c.defaultOptions.flowLabel
	if !c.v6 && !c.dual {
		flowLabel = 0
	}
	info := UDPInfo{
		LocalAddress: netip.AddrPortFrom(c.local, c.port), RemoteAddress: c.remote,
		ReceiveQueuePackets: c.receive.len(), ReceiveQueueBytes: c.queuedBytes, ReceiveQueueCapacity: c.receiveCapacity,
		ReceiveErrors: c.receiveErrors, ErrorQueueEntries: c.errorQueue.len(), ErrorQueueBytes: c.errorQueuedBytes,
		HopLimit: int(c.defaultOptions.hopLimit), TrafficClass: c.defaultOptions.trafficClass,
		PathMTUDiscovery:  c.pathMTUDiscovery,
		MulticastHopLimit: int(c.multicastHopLimit), MulticastLoopback: c.multicastLoopback, Broadcast: c.broadcast,
		FlowLabel: flowLabel, LastError: c.lastError,
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
	info.ErrorsDropped = c.errorsDropped.Load()
	if c.remote.IsValid() && !c.remote.Addr().IsMulticast() && !c.stack.network.Load().broadcastDestination(c.remote.Addr()) {
		info.PathMTU = c.stack.mtuFor(c.remote.Addr())
		if c.remote.Addr().Is6() && automaticFlowLabel {
			info.FlowLabel = c.stack.automaticTransportFlowLabel(c.local, c.remote.Addr(), protocolUDP, c.port, c.remote.Port())
		}
	}
	return info
}

// remoteAddr returns the connected remote address when present.
func (c *UDPConn) remoteAddr() net.Addr {
	if !c.remote.IsValid() {
		return nil
	}
	return net.UDPAddrFromAddrPort(c.remote)
}

// SetDeadline updates both read and write deadlines.
func (c *UDPConn) SetDeadline(deadline time.Time) error {
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

// SetReadDeadline updates the next ReadFrom deadline.
func (c *UDPConn) SetReadDeadline(deadline time.Time) error {
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

// SetWriteDeadline updates the next WriteTo deadline.
func (c *UDPConn) SetWriteDeadline(deadline time.Time) error {
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

// SetReadBuffer changes the approximate memory capacity shared by the datagram
// and asynchronous-error receive queues. Existing entries are retained when
// the capacity shrinks; later arrivals are dropped until enough space becomes
// available.
func (c *UDPConn) SetReadBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	if bytes < udpDatagramMetadataSize {
		bytes = udpDatagramMetadataSize
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
// errors after any already queued datagrams.
func (c *UDPConn) SetReceiveErrors(enabled bool) error {
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
func (c *UDPConn) ReceiveErrors() (bool, error) {
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
func (c *UDPConn) ReadError() (*net.OpError, error) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil, c.operationError("read", c.remoteAddr(), net.ErrClosed)
	default:
	}
	queued, ok := c.errorQueue.pop()
	if !ok {
		c.mu.Unlock()
		return nil, c.operationError("read", c.remoteAddr(), syscall.EAGAIN)
	}
	c.errorQueuedBytes -= queued.size
	c.notifyReceiveLocked()
	c.mu.Unlock()
	return queued.err, nil
}

// SetWriteBuffer validates the standard socket option but otherwise has no
// work to do: UDP writes are synchronously handed to the embedding packet
// device and therefore have no per-socket transmit buffer to resize.
func (c *UDPConn) SetWriteBuffer(bytes int) error {
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
// subsequent UDP writes.
func (c *UDPConn) SetPathMTUDiscovery(mode PathMTUDiscovery) error {
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
// subsequent UDP writes.
func (c *UDPConn) PathMTUDiscovery() (PathMTUDiscovery, error) {
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
func (c *UDPConn) SetHopLimit(hopLimit int) error {
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
func (c *UDPConn) SetTrafficClass(value int) error {
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
func (c *UDPConn) SetFlowLabel(label uint32) error {
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

// writeStateAndOptions reads the output defaults and PMTU policy and returns
// the independent deadline and close signals observed by a blocked host-queue
// write.
func (c *UDPConn) writeStateAndOptions(options ipPacketOptions) (socketWriteState, ipPacketOptions, PathMTUDiscovery) {
	c.mu.Lock()
	options = options.withDefaults(c.defaultOptions)
	pathMTUDiscovery := c.pathMTUDiscovery
	c.mu.Unlock()
	return socketWriteState{deadline: &c.writeDeadline, closed: c.closed}, options, pathMTUDiscovery
}

// operationError wraps a UDP socket failure in the same public shape used by
// the standard net package.
func (c *UDPConn) operationError(operation string, target net.Addr, err error) error {
	return socketOperationError(operation, c.net, c.LocalAddr(), target, err)
}

// setOperationError wraps a deadline-setting failure using the local-address
// metadata shape of the standard net package.
func (c *UDPConn) setOperationError(err error) error {
	return socketOperationError("set", c.net, nil, c.LocalAddr(), err)
}

// socketOperationError constructs one net.OpError without wrapping an error
// that already carries complete operation metadata.
func socketOperationError(operation, network string, source, target net.Addr, err error) error {
	if err == nil {
		return nil
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) {
		return err
	}
	return &net.OpError{Op: operation, Net: network, Source: source, Addr: target, Err: err}
}

// Verify that UDPConn implements net.PacketConn.
var _ net.PacketConn = (*UDPConn)(nil)

// Verify that a connected UDPConn implements net.Conn.
var _ net.Conn = (*UDPConn)(nil)
