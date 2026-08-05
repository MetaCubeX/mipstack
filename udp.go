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

// UDPInfo is a point-in-time diagnostic snapshot of one UDP socket.
type UDPInfo struct {
	LocalAddress         netip.AddrPort
	RemoteAddress        netip.AddrPort
	Closed               bool
	ReceiveQueuePackets  int
	ReceiveQueueBytes    int
	ReceiveQueueCapacity int
	PacketsSent          uint64
	BytesSent            uint64
	PacketsReceived      uint64
	BytesReceived        uint64
	PacketsDropped       uint64
	ICMPErrors           uint64
	PathMTU              int
	HopLimit             int
	TrafficClass         uint8
	FlowLabel            uint32
	LastError            error
}

// udpReuseEndpoints is the optional REUSEPORT dispatcher retained by Stack.
// The concrete registry is linked only when its public listen entry point is
// referenced.
type udpReuseEndpoints interface {
	empty() bool
	connections() []*UDPConn
	overlaps(address netip.Addr, port uint16, dual bool) bool
	connection(binding, local, remote netip.AddrPort) *UDPConn
	add(connection *UDPConn)
	remove(connection *UDPConn) bool
}

// udpSocketBinding supplies the registration policy shared by ListenUDP and
// ListenUDPReusePort.
type udpSocketBinding interface {
	available(stack *Stack, address netip.Addr, port uint16, dual bool) bool
	register(stack *Stack, connection *UDPConn) error
}

// exclusiveUDPSocketBinding is the default one-owner bind policy.
type exclusiveUDPSocketBinding struct{}

// UDPConn is a connected or unconnected userspace UDP socket.
type UDPConn struct {
	stack  *Stack
	net    string
	port   uint16
	v6     bool
	dual   bool
	local  netip.Addr
	remote netip.AddrPort

	errors chan error
	closed chan struct{}
	once   sync.Once

	mu              sync.Mutex
	receive         datagramQueue[udpDatagram]
	receiveNotify   chan struct{}
	receiveCapacity int
	queuedBytes     int
	readDeadline    time.Time
	writeDeadline   time.Time
	readChanged     chan struct{}
	writeChanged    chan struct{}
	readTimers      deadlineTimerCache
	recentTargets   recentDestinationCache[netip.AddrPort]
	defaultOptions  ipPacketOptions
	automaticLabel  uint32
	lastError       error
	packetsSent     atomic.Uint64
	bytesSent       atomic.Uint64
	packetsReceived atomic.Uint64
	bytesReceived   atomic.Uint64
	packetsDropped  atomic.Uint64
	icmpErrors      atomic.Uint64
}

// newUDPConn creates an unregistered UDP socket.
func newUDPConn(stack *Stack, network string, port uint16, v6 bool, local netip.Addr, remote netip.AddrPort) *UDPConn {
	defaults := DatagramSocketDefaults{ReceiveBuffer: udpDefaultReceiveCapacity, HopLimit: 64}
	if stack != nil {
		defaults = stack.network.Load().udpDefaults
	}
	connection := &UDPConn{
		stack: stack, net: network, port: port, v6: v6, local: local, remote: remote,
		errors: make(chan error, 8), closed: make(chan struct{}), receiveNotify: make(chan struct{}, 1), receiveCapacity: defaults.ReceiveBuffer,
		readChanged: make(chan struct{}), writeChanged: make(chan struct{}),
		defaultOptions: ipPacketOptions{
			hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
			flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
		},
	}
	if !remote.IsValid() {
		connection.recentTargets = make(recentDestinationCache[netip.AddrPort])
	} else if stack != nil && local.Is6() && remote.Addr().Is6() && defaults.FlowLabel == 0 {
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

// handleUDP validates and dispatches one UDP datagram.
func (s *Stack) handleUDP(packet ipPacket) error {
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
	s.mu.RLock()
	connection := s.udpConnectionLocked(target, source)
	s.mu.RUnlock()
	if connection == nil {
		return s.sendPortUnreachable(packet)
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

// udpConnectionLocked selects an exact binding before a family wildcard and
// a dual-stack wildcard. REUSEPORT groups hash the complete flow tuple.
func (s *Stack) udpConnectionLocked(local, remote netip.AddrPort) *UDPConn {
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
	datagram := udpDatagram{payload: append([]byte(nil), payload...), source: source, target: target, options: options}
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
		if datagram, ok := c.receive.pop(); ok {
			c.queuedBytes -= udpDatagramSize(datagram.payload)
			c.notifyReceiveLocked()
			c.mu.Unlock()
			n = copy(buffer, datagram.payload)
			return n, datagram.source, datagram.target, datagram.options, n < len(datagram.payload), nil
		}
		deadline, changed, notified := c.readDeadline, c.readChanged, c.receiveNotify
		c.mu.Unlock()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			select {
			case <-changed:
				continue
			default:
				return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
			}
		}
		timer, timeout := c.readTimers.timer(deadline)
		select {
		case <-notified:
			c.readTimers.release(timer, false)
		case err := <-c.errors:
			c.readTimers.release(timer, false)
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, err
		case <-timeout:
			c.readTimers.release(timer, true)
			return 0, netip.AddrPort{}, netip.Addr{}, ipPacketOptions{}, false, os.ErrDeadlineExceeded
		case <-changed:
			c.readTimers.release(timer, false)
			continue
		case <-c.closed:
			c.readTimers.release(timer, false)
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
	netAddress := net.UDPAddrFromAddrPort(address)
	return c.writeToUDPAddrPort(payload, address, netAddress)
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
	n, err := c.writeToFromWith(payload, c.remote, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbeDatagram)
	if err != nil {
		return n, c.operationError("write", c.remoteAddr(), err)
	}
	return n, nil
}

// WritePathMTUProbeTo is the unconnected netip form of WritePathMTUProbe.
func (c *UDPConn) WritePathMTUProbeTo(payload []byte, target netip.AddrPort) (int, error) {
	address := net.UDPAddrFromAddrPort(target)
	if c.remote.IsValid() {
		return 0, c.operationError("write", address, net.ErrWriteToConnected)
	}
	n, err := c.writeToFromWith(payload, target, netip.Addr{}, ipPacketOptions{}, c.writePathMTUProbeDatagram)
	if err != nil {
		return n, c.operationError("write", address, err)
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
	var netAddress net.Addr
	if c.remote.IsValid() {
		if address != nil {
			return 0, 0, c.operationError("write", address, net.ErrWriteToConnected)
		}
		target, netAddress = c.remote, c.remoteAddr()
	} else {
		if address == nil {
			return 0, 0, c.operationError("write", nil, errors.New("mipstack: UDP destination is required"))
		}
		target, netAddress = address.AddrPort(), address
	}
	return c.writeMsgUDPAddrPort(payload, oob, target, netAddress)
}

// WriteMsgUDPAddrPort is the netip.AddrPort form of WriteMsgUDP. A connected
// socket requires an invalid address.
func (c *UDPConn) WriteMsgUDPAddrPort(payload, oob []byte, address netip.AddrPort) (n, oobn int, err error) {
	var netAddress net.Addr
	if c.remote.IsValid() {
		if address.IsValid() {
			netAddress = net.UDPAddrFromAddrPort(address)
			return 0, 0, c.operationError("write", netAddress, net.ErrWriteToConnected)
		}
		address, netAddress = c.remote, c.remoteAddr()
	} else {
		if !address.IsValid() {
			return 0, 0, c.operationError("write", nil, errors.New("mipstack: UDP destination is required"))
		}
		netAddress = net.UDPAddrFromAddrPort(address)
	}
	return c.writeMsgUDPAddrPort(payload, oob, address, netAddress)
}

// writeMsgUDPAddrPort parses packet-info source selection and sends one
// datagram. oobn is reported only when the complete message was accepted.
func (c *UDPConn) writeMsgUDPAddrPort(payload, oob []byte, target netip.AddrPort, address net.Addr) (n, oobn int, err error) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	source, options, err := parseControlMessageForWrite(oob, target.Addr().Is6())
	if err != nil {
		return 0, 0, c.operationError("write", address, err)
	}
	n, err = c.writeToFrom(payload, target, source, options)
	if err != nil {
		return n, 0, c.operationError("write", address, err)
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
func (c *UDPConn) writeToFromWith(payload []byte, target netip.AddrPort, packetInfoSource netip.Addr, options ipPacketOptions, write func(netip.Addr, netip.Addr, uint16, uint16, []byte, ipPacketOptions) error) (int, error) {
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	if target.Addr().Is6() != c.v6 && !c.dual || target.Port() == 0 || target.Addr().IsUnspecified() {
		return 0, errors.New("mipstack: invalid UDP destination")
	}
	deadline, _, closed, options := c.writeStateAndOptions(options)
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
	source, err := c.stack.sourceForRequested(target.Addr(), requestedSource)
	if err != nil {
		return 0, err
	}
	source = source.Unmap()
	maximumPayload := 65535 - udpHeaderSize
	if target.Addr().Is4() {
		maximumPayload -= 20
	}
	if len(payload) > maximumPayload {
		return 0, syscall.EMSGSIZE
	}
	writeErr := write(source, target.Addr(), c.port, target.Port(), payload, options)
	if writeErr != nil {
		if errors.Is(writeErr, syscall.EMSGSIZE) {
			return 0, syscall.EMSGSIZE
		}
		return 0, writeErr
	}
	c.rememberTarget(target)
	c.packetsSent.Add(1)
	c.bytesSent.Add(uint64(len(payload)))
	return len(payload), nil
}

// writeDatagram emits ordinary UDP output against the confirmed path MTU and
// permits source fragmentation.
func (c *UDPConn) writeDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions) error {
	return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, true, c.stack.mtuFor(target))
}

// writePathMTUProbeDatagram is retained only when an application references
// the UDP packetization-layer probing API.
func (c *UDPConn) writePathMTUProbeDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions) error {
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
		packet := make([]byte, ipSize+udpSize)
		if !marshalIPHeader(packet, source, target, protocolUDP, identification, !allowFragment, options) {
			return syscall.EMSGSIZE
		}
		udp := packet[ipSize:]
		marshalUDPDatagram(udp, source, target, sourcePort, targetPort, payload)
		return c.stack.writePacketUntil(packet, c.writeState)
	}
	if !allowFragment {
		return syscall.EMSGSIZE
	}
	udp := make([]byte, udpSize)
	marshalUDPDatagram(udp, source, target, sourcePort, targetPort, payload)
	return c.stack.writeIPPayloadUntilOptionsForMTU(source, target, protocolUDP, udp, true, options, mtu, c.writeState)
}

// marshalUDPDatagram writes one UDP header, payload, and checksum into dst.
func marshalUDPDatagram(dst []byte, source, target netip.Addr, sourcePort, targetPort uint16, payload []byte) {
	binary.BigEndian.PutUint16(dst[0:2], sourcePort)
	binary.BigEndian.PutUint16(dst[2:4], targetPort)
	binary.BigEndian.PutUint16(dst[4:6], uint16(len(dst)))
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
		c.receive.clear()
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
	if c.remote.IsValid() {
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
	readChanged, writeChanged := c.readChanged, c.writeChanged
	c.readDeadline, c.writeDeadline = deadline, deadline
	c.readChanged, c.writeChanged = make(chan struct{}), make(chan struct{})
	c.mu.Unlock()
	close(readChanged)
	close(writeChanged)
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
	changed := c.readChanged
	c.readDeadline, c.readChanged = deadline, make(chan struct{})
	c.mu.Unlock()
	close(changed)
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
	changed := c.writeChanged
	c.writeDeadline, c.writeChanged = deadline, make(chan struct{})
	c.mu.Unlock()
	close(changed)
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

// writeState snapshots the write deadline, notification, and closure state.
func (c *UDPConn) writeState() (time.Time, <-chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.writeDeadline, c.writeChanged, true
	default:
		return c.writeDeadline, c.writeChanged, false
	}
}

// writeStateAndOptions reads the initial deadline and output defaults under
// one socket lock. A blocked host-queue write still rechecks writeState.
func (c *UDPConn) writeStateAndOptions(options ipPacketOptions) (time.Time, <-chan struct{}, bool, ipPacketOptions) {
	c.mu.Lock()
	defer c.mu.Unlock()
	options = options.withDefaults(c.defaultOptions)
	select {
	case <-c.closed:
		return c.writeDeadline, c.writeChanged, true, options
	default:
		return c.writeDeadline, c.writeChanged, false, options
	}
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
