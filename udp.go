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
	// receive queue, not an exact heap-allocation limit.
	ReceiveQueueCapacity int
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

	errors chan error
	closed chan struct{}
	once   sync.Once

	mu                sync.Mutex
	receive           datagramQueue[udpDatagram]
	receiveSpare      []byte
	receiveNotify     chan struct{}
	receiveCapacity   int
	queuedBytes       int
	readDeadline      socketDeadline
	writeDeadline     socketDeadline
	recentTargets     recentDestinationCache[netip.AddrPort]
	defaultOptions    ipPacketOptions
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
}

// newUDPConn creates an unregistered UDP socket.
func newUDPConn(stack *Stack, network string, port uint16, v6 bool, local netip.Addr, remote netip.AddrPort) *UDPConn {
	defaults := DatagramSocketDefaults{ReceiveBuffer: udpDefaultReceiveCapacity, HopLimit: 64, MulticastHopLimit: 1}
	if stack != nil {
		defaults = stack.network.Load().udpDefaults
	}
	connection := &UDPConn{
		stack: stack, net: network, port: port, v6: v6, local: local, remote: remote,
		errors: make(chan error, 8), closed: make(chan struct{}), receiveNotify: make(chan struct{}, 1), receiveCapacity: defaults.ReceiveBuffer,
		defaultOptions: ipPacketOptions{
			hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
			flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
		},
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

// replyUDP sends one reverse-flow response without retaining a registered
// endpoint after the write completes.
func (f *UDPForwarder) replyUDP(request *UDPForwarderRequest, payload []byte) (int, error) {
	return f.replyUDPFlow(request.flow, payload)
}

// replyUDPFlow sends one reverse-flow response without retaining a registered
// endpoint after the write completes.
func (f *UDPForwarder) replyUDPFlow(flow TransportFlow, payload []byte) (int, error) {
	local, remote := flow.Destination, flow.Source
	state := f.stack.network.Load()
	if !state.acceptsInboundDestination(local.Addr()) {
		return 0, syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(remote.Addr()); !routed {
		return 0, syscall.ENETUNREACH
	}
	maximumPayload := 65535 - udpHeaderSize
	if local.Addr().Is4() {
		maximumPayload -= 20
	}
	if len(payload) > maximumPayload {
		return 0, syscall.EMSGSIZE
	}
	defaults := state.udpDefaults
	options := ipPacketOptions{
		hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
		flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
	}
	if err := f.stack.tryWriteUDPDatagram(local.Addr(), remote.Addr(), local.Port(), remote.Port(), payload, options); err != nil {
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
		flags |= linuxMessageTruncated
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
		flags |= linuxMessageControlTruncated
	}
	return
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
			return n, datagram.source, datagram.target, datagram.options, n < len(datagram.payload), nil
		}
		notified := c.receiveNotify
		c.mu.Unlock()
		select {
		case <-notified:
		case err := <-c.errors:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, err
		case <-timeout:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, net.ErrClosed
		}
	}
}

// WriteTo sends one datagram, fragmenting its IP payload when required.
func (c *UDPConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	target, err := udpAddrPort(address)
	if err != nil {
		return 0, c.operationError("write", address, err)
	}
	if c.remote.IsValid() {
		return 0, c.operationError("write", address, net.ErrWriteToConnected)
	}
	n, err := c.writeTo(payload, target)
	if err != nil {
		return n, c.operationError("write", address, err)
	}
	return n, nil
}

// WriteToUDP acts like WriteTo but accepts a UDPAddr directly.
func (c *UDPConn) WriteToUDP(payload []byte, address *net.UDPAddr) (int, error) {
	if address == nil {
		return 0, c.operationError("write", nil, errors.New("mipstack: UDP destination is required"))
	}
	return c.writeToUDPAddrPort(payload, address.AddrPort(), address)
}

// WriteToUDPAddrPort acts like WriteTo but accepts a netip.AddrPort directly.
func (c *UDPConn) WriteToUDPAddrPort(payload []byte, address netip.AddrPort) (int, error) {
	if c.remote.IsValid() {
		return 0, c.operationError("write", net.UDPAddrFromAddrPort(address), net.ErrWriteToConnected)
	}
	target := netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
	n, err := c.writeTo(payload, target)
	if err != nil {
		return n, c.operationError("write", net.UDPAddrFromAddrPort(address), err)
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
	var target netip.AddrPort
	if c.remote.IsValid() {
		if address != nil {
			return 0, 0, c.operationError("write", address, net.ErrWriteToConnected)
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
		var netAddress net.Addr = address
		if netAddress == nil {
			netAddress = c.remoteAddr()
		}
		return n, oobn, c.operationError("write", netAddress, err)
	}
	return n, oobn, nil
}

// WriteMsgUDPAddrPort is the netip.AddrPort form of WriteMsgUDP. A connected
// socket requires an invalid address.
func (c *UDPConn) WriteMsgUDPAddrPort(payload, oob []byte, address netip.AddrPort) (n, oobn int, err error) {
	if c.remote.IsValid() {
		if address.IsValid() {
			return 0, 0, c.operationError("write", net.UDPAddrFromAddrPort(address), net.ErrWriteToConnected)
		}
		address = c.remote
	} else {
		if !address.IsValid() {
			return 0, 0, c.operationError("write", nil, errors.New("mipstack: UDP destination is required"))
		}
	}
	n, oobn, err = c.writeMsgUDPAddrPort(payload, oob, address)
	if err != nil {
		return n, oobn, c.operationError("write", net.UDPAddrFromAddrPort(address), err)
	}
	return n, oobn, nil
}

// writeMsgUDPAddrPort parses packet-info source selection and sends one
// datagram without wrapping errors. oobn is reported only when the complete
// message was accepted.
func (c *UDPConn) writeMsgUDPAddrPort(payload, oob []byte, target netip.AddrPort) (n, oobn int, err error) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
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

// writeToFromWith keeps source selection, checksums, deadlines, accounting,
// and ICMP correlation shared while leaving optional output policies
// independently reachable by the linker.
func (c *UDPConn) writeToFromWith(payload []byte, target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions, write func(netip.Addr, netip.Addr, uint16, uint16, []byte, ipPacketOptions, bool) error) (int, error) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if !target.IsValid() || target.Addr().Is6() != c.v6 && !c.dual || target.Addr().IsUnspecified() {
		return 0, errors.New("mipstack: invalid UDP destination")
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
	var source netip.Addr
	nonUnicast := false
	if c.forwarded {
		if packetInfoSource.IsValid() && !packetInfoSource.IsUnspecified() && packetInfoSource != c.local {
			return 0, syscall.EADDRNOTAVAIL
		}
		state := c.stack.network.Load()
		if !state.acceptsInboundDestination(c.local) {
			return 0, syscall.EADDRNOTAVAIL
		}
		if _, routed := state.routeFor(target.Addr()); !routed {
			return 0, syscall.ENETUNREACH
		}
		source = c.local
	} else {
		var err error
		source, nonUnicast, err = c.stack.sourceForOutput(target.Addr(), requestedSource)
		if err != nil {
			return 0, err
		}
	}
	source = source.Unmap()
	maximumPayload := 65535 - udpHeaderSize
	if target.Addr().Is4() {
		maximumPayload -= 20
	}
	if len(payload) > maximumPayload {
		return 0, syscall.EMSGSIZE
	}
	writeErr := write(source, target.Addr(), c.port, target.Port(), payload, options, nonUnicast)
	if writeErr != nil {
		if errors.Is(writeErr, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, writeErr
	}
	if !nonUnicast {
		c.rememberTarget(target)
	}
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(payload)))
	return len(payload), nil
}

// writeDatagram emits ordinary UDP output against the confirmed path MTU and
// permits source fragmentation.
func (c *UDPConn) writeDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, nonUnicast bool) error {
	if nonUnicast {
		return c.writeNonUnicastDatagram(source, target, sourcePort, targetPort, payload, options)
	}
	return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, true, c.stack.mtuFor(target))
}

// tryWriteUDPDatagram atomically queues one best-effort UDP datagram or all of
// its source fragments without waiting for device capacity.
func (s *Stack) tryWriteUDPDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions) error {
	udpSize := udpHeaderSize + len(payload)
	if udpSize > 65535 {
		return syscall.EMSGSIZE
	}
	datagram := make([]byte, udpSize)
	marshalUDPDatagram(datagram, source, target, sourcePort, targetPort, payload)
	packets, err := s.ipPayloadPacketsWithOptions(source, target, protocolUDP, datagram, true, options)
	if err != nil {
		return err
	}
	return s.tryWritePackets(packets)
}

// writePathMTUProbeDatagram is retained only when an application references
// the UDP packetization-layer probing API.
func (c *UDPConn) writePathMTUProbeDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, _ bool) error {
	return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, false, c.stack.network.Load().mtu)
}

// writeDatagramForMTU serializes the common unfragmented case directly into
// its final IP packet. Only datagrams that actually require source
// fragmentation need a separate contiguous UDP segment.
func (c *UDPConn) writeDatagramForMTU(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, allowFragment bool, mtu int) error {
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
		if source.Is4() && allowFragment {
			identification = uint16(c.stack.ipv4ID.Add(1))
		}
		queue, loopback := c.stack.outputQueueFor(target)
		state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed}
		slot, err := c.stack.reservePacketUntil(queue, loopback, state)
		if err != nil {
			return err
		}
		packet, reusable := queue.acquireBuffer(ipSize + udpSize)
		if !marshalIPHeader(packet, source, target, protocolUDP, identification, !allowFragment, options) {
			queue.releaseBuffer(packet, reusable)
			queue.releaseReserved(slot)
			return syscall.EMSGSIZE
		}
		udp := packet[ipSize:]
		marshalUDPDatagram(udp, source, target, sourcePort, targetPort, payload)
		queue.enqueueReservedPacket(slot, packet, reusable)
		c.stack.recordOutput(loopback)
		return nil
	}
	if !allowFragment {
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

// deliverError queues a destination-associated asynchronous network error.
func (c *UDPConn) deliverError(target netip.AddrPort, err error) {
	operationError := &net.OpError{
		Op: "read", Net: c.net, Source: c.LocalAddr(),
		Addr: net.UDPAddrFromAddrPort(target), Err: err,
	}
	c.mu.Lock()
	c.lastError = operationError
	c.mu.Unlock()
	c.icmpErrors.Add(1)
	select {
	case c.errors <- operationError:
	default:
	}
}

// udpAddrPort converts a net.Addr without performing name resolution.
func udpAddrPort(address net.Addr) (netip.AddrPort, error) {
	if address == nil {
		return netip.AddrPort{}, errors.New("mipstack: UDP destination is required")
	}
	if udp, ok := address.(*net.UDPAddr); ok {
		return udp.AddrPort(), nil
	}
	result, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return netip.AddrPort{}, errors.New("mipstack: invalid UDP destination")
	}
	return result, nil
}

// Close unregisters the socket and wakes blocked reads.
func (c *UDPConn) Close() error {
	if c.stack.closeUDP(c) {
		return nil
	}
	return c.operationError("close", c.remoteAddr(), net.ErrClosed)
}

// closeFromStack publishes closure exactly once and releases queued payloads.
func (c *UDPConn) closeFromStack() {
	c.once.Do(func() {
		c.mu.Lock()
		c.readDeadline.stop()
		c.writeDeadline.stop()
		c.receive.clear()
		c.receiveSpare = nil
		c.queuedBytes = 0
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
		HopLimit: int(c.defaultOptions.hopLimit), TrafficClass: c.defaultOptions.trafficClass,
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

// SetReadBuffer changes the approximate memory capacity of the datagram
// receive queue. Existing datagrams are retained when the capacity shrinks;
// later arrivals are dropped until enough space becomes available.
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

// writeStateAndOptions reads the output defaults and returns the independent
// deadline and close signals observed by a blocked host-queue write.
func (c *UDPConn) writeStateAndOptions(options ipPacketOptions) (socketWriteState, ipPacketOptions) {
	c.mu.Lock()
	options = options.withDefaults(c.defaultOptions)
	c.mu.Unlock()
	return socketWriteState{deadline: &c.writeDeadline, closed: c.closed}, options
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
