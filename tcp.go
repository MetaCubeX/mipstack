package mipstack

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// tcpHeaderSize is the TCP header length without options.
	tcpHeaderSize = 20
	// tcpFlagFIN closes one stream direction.
	tcpFlagFIN = byte(0x01)
	// tcpFlagSYN synchronizes initial sequence numbers.
	tcpFlagSYN = byte(0x02)
	// tcpFlagRST resets a connection.
	tcpFlagRST = byte(0x04)
	// tcpFlagPSH requests prompt delivery to the peer application.
	tcpFlagPSH = byte(0x08)
	// tcpFlagACK marks the acknowledgement field as valid.
	tcpFlagACK = byte(0x10)
	// tcpFlagECE echoes received congestion or negotiates ECN on SYN.
	tcpFlagECE = byte(0x40)
	// tcpFlagCWR acknowledges an ECN congestion response or negotiates ECN on
	// an initial SYN.
	tcpFlagCWR = byte(0x80)
	// tcpReceiveCapacity bounds unread and out-of-order bytes per connection.
	tcpReceiveCapacity = 256 * 1024
	// tcpSendCapacity bounds unacknowledged and not-yet-transmitted application
	// bytes retained by one connection.
	tcpSendCapacity = 256 * 1024
	// tcpMaximumOutOfOrder bounds retained receive-range metadata.
	tcpMaximumOutOfOrder = 256
	// tcpInboundQueue bounds validated segments waiting for one actor.
	tcpInboundQueue = 256
	// tcpAcceptQueue bounds completed passive handshakes waiting for Accept.
	tcpAcceptQueue = 128
	// tcpSYNBacklog bounds half-open and completed but unaccepted connections
	// owned by one listener.
	tcpSYNBacklog = 256
	// tcpMaximumRetransmits bounds repeated transmission of one segment.
	tcpMaximumRetransmits = 12
	// tcpBlackHoleTimeouts requires repeated RTOs before inferring that ICMP
	// Packet Too Big messages are being filtered.
	tcpBlackHoleTimeouts = 2
	// tcpInitialRTO follows the RFC 6298 initial retransmission timeout.
	tcpInitialRTO = time.Second
	// tcpMinimumRTO avoids excessive retransmission on low-latency overlays.
	tcpMinimumRTO = 200 * time.Millisecond
	// tcpMaximumRTO bounds retry latency and zero-window probing.
	tcpMaximumRTO = 60 * time.Second
	// tcpDelayedACKTimeout bounds acknowledgement delay for in-order data and
	// non-critical receive-window growth.
	tcpDelayedACKTimeout = 25 * time.Millisecond
	// tcpTimeWaitDuration retains a completed tuple for twice the conventional
	// 30-second maximum segment lifetime.
	tcpTimeWaitDuration = 60 * time.Second
	// tcpFINWaitDuration bounds FIN_WAIT_2 resource retention.
	tcpFINWaitDuration = 60 * time.Second
	// tcpReceiveWindowScale uses TCP's largest valid shift so a caller may grow
	// the receive buffer after connection establishment without renegotiation.
	tcpReceiveWindowScale = uint8(14)
	// tcpInitialCongestionMSS is the RFC 6928 upper initial-window bound.
	tcpInitialCongestionMSS = 10
	// tcpDefaultKeepAliveIdle is the initial inactivity before probes.
	tcpDefaultKeepAliveIdle = 2 * time.Hour
	// tcpDefaultKeepAliveInterval spaces unanswered probes.
	tcpDefaultKeepAliveInterval = 75 * time.Second
	// tcpDefaultKeepAliveCount bounds unanswered probes.
	tcpDefaultKeepAliveCount = 9
	// tcpMaximumScaledWindow is the largest receive window representable by
	// TCP's 16-bit window and maximum negotiated scale.
	tcpMaximumScaledWindow = uint32(65535) << 14
)

// KeepAliveConfig configures TCP keepalive probing. Every field must be
// positive when supplied to SetKeepAliveConfig.
type KeepAliveConfig struct {
	Idle     time.Duration
	Interval time.Duration
	Count    int
}

// tcpSocketOptions is one lock-protected option snapshot.
type tcpSocketOptions struct {
	keepAlive       bool
	keepAliveConfig KeepAliveConfig
	idleTimeout     time.Duration
	noDelay         bool
}

// tcpSegment is a validated segment delivered to one connection actor.
type tcpSegment struct {
	sequence        uint32
	acknowledgement uint32
	flags           byte
	window          uint16
	ecn             byte
	options         []byte
	payload         []byte
}

// sentTCPSegment retains retransmission state for one sequence range.
type sentTCPSegment struct {
	sequence      uint32
	end           uint32
	flags         byte
	payload       []byte
	sentAt        time.Time
	transmissions int
	sacked        bool
	sackRetried   bool
	rackLost      bool
}

// tcpReceivedPiece retains one normalized out-of-order receive range.
type tcpReceivedPiece struct {
	sequence uint32
	payload  []byte
	fin      bool
}

// TCPConn is an active userspace TCP connection.
type TCPConn struct {
	stack *Stack
	key   tcpKey
	mtu   int
	net   string
	// passive is set before registration for connections created by a
	// listener. Such accepted connections do not prevent rebinding a closed
	// listener's local endpoint, matching the listener SO_REUSEADDR behavior
	// used by the standard library.
	passive bool

	inbound       chan tcpSegment
	networkError  chan error
	pathMTUUpdate chan struct{}
	sendNotify    chan struct{}
	windowUpdate  chan struct{}
	abortCh       chan struct{}
	done          chan struct{}
	connected     chan error
	lingerDone    chan struct{}
	abortOnce     sync.Once
	closeOnce     sync.Once
	lingerOnce    sync.Once
	readCallMu    sync.Mutex
	writeCallMu   sync.Mutex
	icmpSequence  atomic.Uint64

	abortMu  sync.Mutex
	abortErr error
	abortRST bool

	mu              sync.Mutex
	readBuffer      []byte
	readErr         error
	terminalErr     error
	userClosed      bool
	readClosed      bool
	writeClosed     bool
	readDeadline    time.Time
	writeDeadline   time.Time
	readChanged     chan struct{}
	writeChanged    chan struct{}
	readNotify      chan struct{}
	sendChanged     chan struct{}
	sendBuffer      []byte
	optionsChanged  chan struct{}
	receiveCapacity int
	sendCapacity    int
	keepAlive       bool
	keepAliveConfig KeepAliveConfig
	idleTimeout     time.Duration
	noDelay         bool
	linger          int

	// Handshake results are passed to established by the same actor goroutine.
	peerMSS           int
	peerWindowScale   uint8
	peerWindowScaling bool
	peerSACK          bool
	peerTimestamp     bool
	peerECN           bool
	recentTimestamp   uint32
	echoCongestion    bool
	sendCWR           bool
	receiveNext       uint32
	peerWindow        uint32
	peerWindowSeq     uint32
	peerWindowACK     uint32
}

// tcpListenKey identifies one specific or wildcard passive TCP endpoint.
type tcpListenKey struct {
	address netip.Addr
	port    uint16
}

// tcpPassiveEndpoints is the small data-plane surface retained by Stack.
// Its implementation is created only when an application uses TCP listeners,
// allowing listener-only protocol code to be removed from dial-only binaries.
type tcpPassiveEndpoints interface {
	portListened(local netip.Addr, port uint16) bool
	handleSegment(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error)
	updateConfig(stack *Stack, network *networkState)
	closeAll()
}

// tcpReuseEndpoints is implemented by the optional REUSEPORT registry. It is
// deliberately reached through an interface so ordinary listeners do not
// retain group selection and hashing code.
type tcpReuseEndpoints interface {
	empty() bool
	listeners() []*TCPListener
	overlaps(address netip.Addr, port uint16, dual bool) bool
	listener(binding, local, remote netip.AddrPort) *TCPListener
	add(listener *TCPListener)
	remove(listener *TCPListener) bool
}

// tcpPassiveState owns exclusive listeners and an optional REUSEPORT
// registry. Stack.mu protects every field.
type tcpPassiveState struct {
	exclusive map[tcpListenKey]*TCPListener
	reuse     tcpReuseEndpoints
	cookieMu  sync.Mutex
	cookieKey [16]byte
	cookieSet bool
}

// tcpListenerBinding supplies only the registration policy that differs
// between ordinary and REUSEPORT listeners; validation and construction stay
// in one shared Listen implementation.
type tcpListenerBinding interface {
	available(state *tcpPassiveState, address netip.Addr, port uint16, dual bool) bool
	register(state *tcpPassiveState, listener *TCPListener) error
}

// exclusiveTCPListenerBinding is the default one-owner bind policy.
type exclusiveTCPListenerBinding struct{}

// TCPListener is a passive userspace TCP endpoint.
type TCPListener struct {
	stack *Stack
	key   tcpListenKey
	local netip.AddrPort
	dual  bool
	net   string

	accept chan *TCPConn
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
	pending  map[*TCPConn]struct{}
}

// ListenTCP creates a passive TCP endpoint. Network must be tcp, tcp4, or
// tcp6. A wildcard with tcp uses one dual-stack endpoint when both families
// are configured. Port zero selects an automatic port.
func (s *Stack) ListenTCP(ctx context.Context, network string, local netip.AddrPort) (*TCPListener, error) {
	return s.listenTCP(ctx, network, local, exclusiveTCPListenerBinding{})
}

// listenTCP contains validation, automatic port allocation, and listener
// construction shared by the ordinary and optional REUSEPORT entry points.
func (s *Stack) listenTCP(ctx context.Context, network string, local netip.AddrPort, binding tcpListenerBinding) (*TCPListener, error) {
	address := local.Addr().Unmap()
	local = netip.AddrPortFrom(address, local.Port())
	target := tcpNetAddr(local)
	wrap := func(err error) (*TCPListener, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	if err := validateListenNetwork(network, "tcp", address); err != nil {
		return wrap(err)
	}
	if address.IsValid() && (address.IsMulticast() || address.Zone() != "") {
		return wrap(errors.New("mipstack: invalid TCP listen address"))
	}
	if address.IsValid() && !address.IsUnspecified() && !s.isLocal(address) {
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
	address, dual, err := listenAddress(state, network, "tcp", address)
	if err != nil {
		return wrap(err)
	}
	if !address.IsUnspecified() && !networkStateHasLocal(state, address) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	local = netip.AddrPortFrom(address, local.Port())
	passive := s.tcpPassiveStateLocked()
	defer func() {
		if passive.empty() && s.tcpPassive == passive {
			s.tcpPassive = nil
		}
	}()
	port := local.Port()
	if port == 0 {
		port, err = s.allocateTCPListenPortLocked(passive, binding, address, dual)
		if err != nil {
			return wrap(err)
		}
	} else if !s.tcpListenEndpointAvailableLocked(passive, binding, address, port, dual) {
		return wrap(syscall.EADDRINUSE)
	}
	local = netip.AddrPortFrom(address, port)
	key := tcpListenKey{address: address, port: port}
	listener := &TCPListener{
		stack: s, key: key, local: local, dual: dual, net: network, accept: make(chan *TCPConn, tcpAcceptQueue),
		closed: make(chan struct{}), changed: make(chan struct{}), pending: make(map[*TCPConn]struct{}),
	}
	if err = binding.register(passive, listener); err != nil {
		return wrap(err)
	}
	s.stats.activeTCPListeners.Add(1)
	return listener, nil
}

// tcpPassiveStateLocked returns the lazily allocated passive dispatcher while
// Stack.mu is held.
func (s *Stack) tcpPassiveStateLocked() *tcpPassiveState {
	if s.tcpPassive == nil {
		state := &tcpPassiveState{exclusive: make(map[tcpListenKey]*TCPListener)}
		s.tcpPassive = state
		return state
	}
	return s.tcpPassive.(*tcpPassiveState)
}

// allocateTCPListenPortLocked selects an unused passive endpoint while s.mu
// is held.
func (s *Stack) allocateTCPListenPortLocked(state *tcpPassiveState, binding tcpListenerBinding, address netip.Addr, dual bool) (uint16, error) {
	index := 0
	if address.Is6() {
		index = 1
	}
	return allocateAutomaticPort(&s.nextPort[index], func(port uint16) bool {
		return s.tcpListenEndpointAvailableLocked(state, binding, address, port, dual)
	})
}

// tcpListenEndpointAvailableLocked reports whether binding address and port
// would conflict with a listener or active local endpoint while s.mu is held.
func (s *Stack) tcpListenEndpointAvailableLocked(state *tcpPassiveState, binding tcpListenerBinding, address netip.Addr, port uint16, dual bool) bool {
	if !binding.available(state, address, port, dual) {
		return false
	}
	for key, connection := range s.tcp {
		if connection.passive {
			continue
		}
		local := key.local
		if local.Port() == port && listenAddressesOverlap(local.Addr(), false, address, dual) {
			return false
		}
	}
	return true
}

// available implements exclusive listener binding.
func (exclusiveTCPListenerBinding) available(state *tcpPassiveState, address netip.Addr, port uint16, dual bool) bool {
	return !state.overlaps(address, port, dual)
}

// register adds one exclusive listener while Stack.mu is held.
func (exclusiveTCPListenerBinding) register(state *tcpPassiveState, listener *TCPListener) error {
	state.exclusive[listener.key] = listener
	return nil
}

// empty reports whether the passive dispatcher has no listeners.
func (state *tcpPassiveState) empty() bool {
	return len(state.exclusive) == 0 && (state.reuse == nil || state.reuse.empty())
}

// listeners returns a snapshot while Stack.mu is held.
func (state *tcpPassiveState) listeners() []*TCPListener {
	listeners := make([]*TCPListener, 0, len(state.exclusive))
	for _, listener := range state.exclusive {
		listeners = append(listeners, listener)
	}
	if state.reuse != nil {
		listeners = append(listeners, state.reuse.listeners()...)
	}
	return listeners
}

// updateConfig closes listeners whose local binding no longer exists.
func (state *tcpPassiveState) updateConfig(stack *Stack, network *networkState) {
	stack.mu.RLock()
	if stack.tcpPassive != state {
		stack.mu.RUnlock()
		return
	}
	listeners := state.listeners()
	stack.mu.RUnlock()
	for _, listener := range listeners {
		address := listener.local.Addr()
		if listener.dual && !networkStateHasFamily(network, false) && !networkStateHasFamily(network, true) ||
			!listener.dual && address.IsUnspecified() && !networkStateHasFamily(network, address.Is6()) ||
			!address.IsUnspecified() && !networkStateHasLocal(network, address) {
			stack.closeTCPListener(listener)
		}
	}
}

// closeAll publishes stack closure to a detached passive dispatcher.
func (state *tcpPassiveState) closeAll() {
	for _, listener := range state.listeners() {
		listener.closeFromStack()
	}
}

// overlaps reports whether any passive binding covers an address and port.
func (state *tcpPassiveState) overlaps(address netip.Addr, port uint16, dual bool) bool {
	for key, listener := range state.exclusive {
		if key.port == port && listenAddressesOverlap(key.address, listener.dual, address, dual) {
			return true
		}
	}
	return state.reuse != nil && state.reuse.overlaps(address, port, dual)
}

// listener selects an exact binding before a family wildcard and a dual-stack
// wildcard. REUSEPORT groups apply their stable flow selection at each level.
func (state *tcpPassiveState) listener(local, remote netip.AddrPort) *TCPListener {
	if listener := state.exclusive[tcpListenKey{address: local.Addr(), port: local.Port()}]; listener != nil {
		return listener
	}
	if state.reuse != nil {
		if listener := state.reuse.listener(local, local, remote); listener != nil {
			return listener
		}
	}
	wildcard := netip.IPv4Unspecified()
	if local.Addr().Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	wildcardLocal := netip.AddrPortFrom(wildcard, local.Port())
	if listener := state.exclusive[tcpListenKey{address: wildcard, port: local.Port()}]; listener != nil {
		return listener
	}
	if state.reuse != nil {
		if listener := state.reuse.listener(wildcardLocal, local, remote); listener != nil {
			return listener
		}
	}
	if local.Addr().Is4() {
		dualLocal := netip.AddrPortFrom(netip.IPv6Unspecified(), local.Port())
		if listener := state.exclusive[tcpListenKey{address: dualLocal.Addr(), port: local.Port()}]; listener != nil && listener.dual {
			return listener
		}
		if state.reuse != nil {
			if listener := state.reuse.listener(dualLocal, local, remote); listener != nil && listener.dual {
				return listener
			}
		}
	}
	return nil
}

// portListened reports whether any listener owns a local endpoint.
func (state *tcpPassiveState) portListened(local netip.Addr, port uint16) bool {
	return state.overlaps(local, port, false)
}

// remove unregisters a listener while Stack.mu is held.
func (state *tcpPassiveState) remove(listener *TCPListener) bool {
	if state.exclusive[listener.key] == listener {
		delete(state.exclusive, listener.key)
		return true
	}
	if state.reuse != nil && state.reuse.remove(listener) {
		if state.reuse.empty() {
			state.reuse = nil
		}
		return true
	}
	return false
}

// Accept waits for and returns the next completed passive connection.
func (l *TCPListener) Accept() (net.Conn, error) { return l.AcceptTCP() }

// AcceptTCP waits for and returns the next completed passive connection.
func (l *TCPListener) AcceptTCP() (*TCPConn, error) {
	for {
		l.mu.Lock()
		deadline, changed := l.deadline, l.changed
		l.mu.Unlock()
		timer, timeout := deadlineTimer(deadline)
		select {
		case connection := <-l.accept:
			stopTimer(timer)
			l.mu.Lock()
			select {
			case <-l.closed:
				l.mu.Unlock()
				return nil, l.operationError("accept", net.ErrClosed)
			default:
			}
			delete(l.pending, connection)
			l.mu.Unlock()
			return connection, nil
		case <-changed:
			stopTimer(timer)
		case <-timeout:
			return nil, l.operationError("accept", os.ErrDeadlineExceeded)
		case <-l.closed:
			stopTimer(timer)
			return nil, l.operationError("accept", net.ErrClosed)
		}
	}
}

// Close stops listening without closing connections already returned by
// Accept.
func (l *TCPListener) Close() error {
	if l.stack.closeTCPListener(l) {
		return nil
	}
	return l.operationError("close", net.ErrClosed)
}

// Addr returns the bound TCP endpoint.
func (l *TCPListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.local) }

// SetDeadline sets the deadline for subsequent Accept calls.
func (l *TCPListener) SetDeadline(deadline time.Time) error {
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		return l.operationError("set", net.ErrClosed)
	default:
	}
	changed := l.changed
	l.deadline, l.changed = deadline, make(chan struct{})
	l.mu.Unlock()
	close(changed)
	return nil
}

// operationError wraps a listener failure in the standard net.OpError shape.
func (l *TCPListener) operationError(operation string, err error) error {
	return socketOperationError(operation, l.net, nil, l.Addr(), err)
}

// track reserves one listener backlog entry for connection.
func (l *TCPListener) track(connection *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	if len(l.pending) >= tcpSYNBacklog {
		return false
	}
	l.pending[connection] = struct{}{}
	return true
}

// removePending releases a failed handshake from the listener backlog.
func (l *TCPListener) removePending(connection *TCPConn) {
	l.mu.Lock()
	delete(l.pending, connection)
	l.mu.Unlock()
}

// enqueue publishes one completed passive handshake to Accept.
func (l *TCPListener) enqueue(connection *TCPConn) bool {
	select {
	case l.accept <- connection:
		return true
	case <-l.closed:
		return false
	default:
		return false
	}
}

// closeFromStack publishes listener closure and aborts connections not yet
// returned by Accept.
func (l *TCPListener) closeFromStack() {
	l.once.Do(func() {
		l.mu.Lock()
		close(l.closed)
		pending := make([]*TCPConn, 0, len(l.pending))
		for connection := range l.pending {
			pending = append(pending, connection)
		}
		l.pending = make(map[*TCPConn]struct{})
		l.mu.Unlock()
		for _, connection := range pending {
			connection.abort(net.ErrClosed)
		}
	})
}

// Verify that TCPListener implements net.Listener.
var _ net.Listener = (*TCPListener)(nil)

// DialTCP establishes an active IPv4 or IPv6 TCP connection. Network must be
// tcp, tcp4, or tcp6. A zero source selects both address and port
// automatically; an unspecified source address selects only the address.
func (s *Stack) DialTCP(ctx context.Context, network string, source, remote netip.AddrPort) (net.Conn, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	target := tcpNetAddr(remote)
	wrap := func(source net.Addr, err error) (net.Conn, error) {
		return nil, socketOperationError("dial", network, source, target, err)
	}
	if err := validateTransportNetwork(network, "tcp", remote.Addr()); err != nil {
		return wrap(nil, err)
	}
	if !remote.IsValid() || remote.Port() == 0 || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Zone() != "" {
		return wrap(nil, errors.New("mipstack: invalid TCP destination"))
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	if err := s.ready(); err != nil {
		return wrap(nil, err)
	}
	initialSequence, err := randomUint32()
	if err != nil {
		return wrap(nil, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return wrap(nil, ErrClosed)
	}
	local, err := s.localEndpointFor(network, remote, source)
	if err != nil {
		s.mu.Unlock()
		return wrap(nil, err)
	}
	localAddress := local.Addr()
	localNetAddress := net.TCPAddrFromAddrPort(local)
	connectionMTU := s.mtuFor(remote.Addr())
	if !s.tcpConnectionAvailableLocked() {
		s.mu.Unlock()
		return wrap(localNetAddress, ErrResourceLimit)
	}
	port := local.Port()
	if port == 0 {
		port, err = s.allocateTCPPortLocked(localAddress, remote)
		if err != nil {
			s.mu.Unlock()
			return wrap(localNetAddress, err)
		}
	} else {
		key := tcpKey{local: netip.AddrPortFrom(localAddress, port), remote: remote}
		if s.tcpPortListenedLocked(localAddress, port) {
			s.mu.Unlock()
			return wrap(localNetAddress, syscall.EADDRINUSE)
		}
		if _, exists := s.tcp[key]; exists {
			s.mu.Unlock()
			return wrap(localNetAddress, syscall.EADDRINUSE)
		}
	}
	key := tcpKey{local: netip.AddrPortFrom(localAddress.Unmap(), port), remote: remote}
	connection := newTCPConn(s, network, key, connectionMTU)
	connection.publishICMPSequenceRange(initialSequence, initialSequence+1)
	s.tcp[key] = connection
	s.stats.activeTCPConnections.Add(1)
	s.mu.Unlock()
	go connection.run(initialSequence)
	select {
	case err = <-connection.connected:
		if err != nil {
			return wrap(connection.LocalAddr(), err)
		}
		return connection, nil
	case <-ctx.Done():
		connection.abort(ctx.Err())
		return wrap(connection.LocalAddr(), ctx.Err())
	}
}

// newTCPConn allocates the shared active and passive connection state.
func newTCPConn(stack *Stack, network string, key tcpKey, mtu int) *TCPConn {
	return &TCPConn{
		stack: stack, net: network, key: key, mtu: mtu,
		inbound: make(chan tcpSegment, tcpInboundQueue), networkError: make(chan error, 8), pathMTUUpdate: make(chan struct{}, 1),
		sendNotify: make(chan struct{}, 1), windowUpdate: make(chan struct{}, 1),
		abortCh: make(chan struct{}), done: make(chan struct{}), connected: make(chan error, 1), lingerDone: make(chan struct{}),
		readChanged: make(chan struct{}), writeChanged: make(chan struct{}), readNotify: make(chan struct{}), sendChanged: make(chan struct{}),
		optionsChanged: make(chan struct{}, 1), noDelay: true, linger: -1,
		receiveCapacity: tcpReceiveCapacity, sendCapacity: tcpSendCapacity,
		keepAliveConfig: KeepAliveConfig{Idle: tcpDefaultKeepAliveIdle, Interval: tcpDefaultKeepAliveInterval, Count: tcpDefaultKeepAliveCount},
	}
}

// tcpNetAddr returns a standard TCP address when endpoint is valid.
func tcpNetAddr(endpoint netip.AddrPort) net.Addr {
	return net.TCPAddrFromAddrPort(endpoint)
}

// randomUint32 returns an unpredictable TCP initial sequence number.
func randomUint32() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(raw[:]), nil
}

// tcpTimestamp returns a wrapping millisecond clock suitable for TSval.
func (s *Stack) tcpTimestamp() uint32 {
	return uint32(time.Since(s.timestampEpoch)/time.Millisecond) + 1
}

// handleTCP validates a segment, dispatches it by four-tuple, or emits RST for
// an unbound destination.
func (s *Stack) handleTCP(packet ipPacket) error {
	tcp := packet.payload
	if len(tcp) < tcpHeaderSize || transportChecksum(packet.source, packet.target, protocolTCP, tcp) != 0 {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(tcp) || tcp[12]&0x0e != 0 {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	sourcePort := binary.BigEndian.Uint16(tcp[0:2])
	targetPort := binary.BigEndian.Uint16(tcp[2:4])
	raw := append([]byte(nil), tcp[tcpHeaderSize:]...)
	optionSize := headerSize - tcpHeaderSize
	segment := tcpSegment{
		sequence: binary.BigEndian.Uint32(tcp[4:8]), acknowledgement: binary.BigEndian.Uint32(tcp[8:12]),
		flags: tcp[13], window: binary.BigEndian.Uint16(tcp[14:16]), ecn: packet.ecn,
		options: raw[:optionSize], payload: raw[optionSize:],
	}
	key := tcpKey{local: netip.AddrPortFrom(packet.target, targetPort), remote: netip.AddrPortFrom(packet.source, sourcePort)}
	s.mu.RLock()
	connection := s.tcp[key]
	s.mu.RUnlock()
	if connection != nil {
		select {
		case connection.inbound <- segment:
		default:
			s.stats.inboundDroppedPackets.Add(1)
		}
		return nil
	}
	s.mu.RLock()
	passive := s.tcpPassive
	s.mu.RUnlock()
	if passive != nil {
		handled, err := passive.handleSegment(s, packet, segment, key)
		if handled || err != nil {
			return err
		}
	}
	if segment.flags&tcpFlagRST != 0 {
		return nil
	}
	if !s.allowControlResponse(controlResponseTCPReset) {
		return nil
	}
	var sequence, acknowledgement uint32
	flags := tcpFlagRST
	if segment.flags&tcpFlagACK != 0 {
		sequence = segment.acknowledgement
	} else {
		acknowledgement = segment.sequence + uint32(len(segment.payload))
		if segment.flags&tcpFlagSYN != 0 {
			acknowledgement++
		}
		if segment.flags&tcpFlagFIN != 0 {
			acknowledgement++
		}
		flags |= tcpFlagACK
	}
	return s.writeTCP(packet.target, packet.source, targetPort, sourcePort, sequence, acknowledgement, flags, 0, nil, nil)
}

// tcpConnectionAvailableLocked applies the optional embedding limit while
// s.mu is held. Zero deliberately means that allocation is memory-limited.
func (s *Stack) tcpConnectionAvailableLocked() bool {
	maximum := s.network.Load().maxTCPConnections
	return maximum == 0 || len(s.tcp) < maximum
}

// handleSegment admits a new passive open. Stack.handleTCP calls this through
// tcpPassiveEndpoints, so dial-only binaries do not retain this implementation.
func (state *tcpPassiveState) handleSegment(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error) {
	if key.remote.Port() == 0 {
		return false, nil
	}
	if segment.flags&tcpFlagSYN != 0 && segment.flags&(tcpFlagACK|tcpFlagRST|tcpFlagFIN) == 0 {
		return state.handleSYN(stack, packet, segment, key)
	}
	if segment.flags&tcpFlagACK != 0 && segment.flags&(tcpFlagSYN|tcpFlagRST) == 0 {
		return state.handleSYNCookieACK(stack, segment, key)
	}
	return false, nil
}

// handleSYN allocates the ordinary half-open state when capacity permits and
// falls back to a stateless SYN cookie under pressure.
func (state *tcpPassiveState) handleSYN(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error) {
	stack.mu.RLock()
	listener := state.listener(key.local, key.remote)
	stack.mu.RUnlock()
	if listener == nil {
		return false, nil
	}
	initialSequence, err := randomUint32()
	if err != nil {
		return true, err
	}
	stack.mu.Lock()
	if connection := stack.tcp[key]; connection != nil {
		stack.mu.Unlock()
		select {
		case connection.inbound <- segment:
		default:
			stack.stats.inboundDroppedPackets.Add(1)
		}
		return true, nil
	}
	if stack.tcpPassive != state {
		stack.mu.Unlock()
		return false, nil
	}
	listener = state.listener(key.local, key.remote)
	if listener != nil && stack.tcpConnectionAvailableLocked() {
		connection := newTCPConn(stack, listener.net, key, stack.mtuFor(packet.source))
		connection.passive = true
		connection.publishICMPSequenceRange(initialSequence, initialSequence+1)
		if listener.track(connection) {
			stack.tcp[key] = connection
			stack.stats.activeTCPConnections.Add(1)
			stack.mu.Unlock()
			go connection.runPassive(listener, segment, initialSequence)
			return true, nil
		}
	}
	stack.mu.Unlock()
	if listener == nil {
		return false, nil
	}
	return true, state.sendSYNCookie(stack, key, segment, time.Now())
}

// handleSYNCookieACK allocates connection state only after authenticating a
// final ACK produced from a stateless SYN-ACK.
func (state *tcpPassiveState) handleSYNCookieACK(stack *Stack, segment tcpSegment, key tcpKey) (bool, error) {
	stack.mu.RLock()
	listener := state.listener(key.local, key.remote)
	stack.mu.RUnlock()
	if listener == nil {
		return false, nil
	}
	initialSequence, options, valid := state.validateSYNCookie(key, segment, time.Now())
	if !valid {
		return false, nil
	}
	stack.mu.Lock()
	if connection := stack.tcp[key]; connection != nil {
		stack.mu.Unlock()
		select {
		case connection.inbound <- segment:
		default:
			stack.stats.inboundDroppedPackets.Add(1)
		}
		return true, nil
	}
	if stack.tcpPassive != state {
		stack.mu.Unlock()
		return false, nil
	}
	listener = state.listener(key.local, key.remote)
	if listener == nil {
		stack.mu.Unlock()
		return false, nil
	}
	if !stack.tcpConnectionAvailableLocked() {
		stack.mu.Unlock()
		return true, nil
	}
	connection := newTCPConn(stack, listener.net, key, stack.mtuFor(key.remote.Addr()))
	connection.passive = true
	connection.publishICMPSequenceRange(initialSequence+1, initialSequence+1)
	connection.peerMSS = options.mss
	connection.peerWindowScale = options.windowScale
	connection.peerWindowScaling = options.windowScaling
	connection.peerSACK = options.sack
	connection.peerTimestamp = options.timestamp
	connection.recentTimestamp = options.timestampNow
	connection.peerECN = options.ecn
	connection.receiveNext = segment.sequence
	connection.peerWindow = uint32(segment.window)
	if options.windowScaling {
		connection.peerWindow <<= options.windowScale
	}
	connection.peerWindowSeq = segment.sequence
	connection.peerWindowACK = segment.acknowledgement
	if !listener.track(connection) {
		stack.mu.Unlock()
		return true, nil
	}
	stack.tcp[key] = connection
	stack.stats.activeTCPConnections.Add(1)
	stack.mu.Unlock()
	go connection.runPassiveCookie(listener, segment, initialSequence)
	return true, nil
}

// writeTCP constructs and emits one non-fragmented TCP segment.
func (s *Stack) writeTCP(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte) error {
	return s.writeTCPWithMTU(source, target, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, payload, s.mtuFor(target))
}

// writeTCPWithMTU emits a segment using a connection actor's PMTU snapshot.
func (s *Stack) writeTCPWithMTU(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int) error {
	return s.writeTCPWithECN(source, target, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, payload, mtu, 0)
}

// writeTCPWithECN emits a segment with an explicit IP ECN codepoint.
func (s *Stack) writeTCPWithECN(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, ecn byte) error {
	headerSize := tcpHeaderSize + (len(options)+3)&^3
	if len(options) > 40 || headerSize > 60 {
		return errors.New("mipstack: invalid TCP options")
	}
	tcp := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], targetPort)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], acknowledgement)
	tcp[12], tcp[13] = byte(headerSize/4)<<4, flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	copy(tcp[tcpHeaderSize:headerSize], options)
	copy(tcp[headerSize:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(source, target, protocolTCP, tcp))
	packet := buildIPPacket(source, target, protocolTCP, tcp, s.nextPacketID(), true)
	if len(packet) == 0 || len(packet) > mtu {
		return messageTooLong("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, sourcePort)), net.TCPAddrFromAddrPort(netip.AddrPortFrom(target, targetPort)))
	}
	setPacketECN(packet, ecn)
	return s.writePacket(packet)
}

// deliverError queues a matching ICMP error without blocking packet input.
func (c *TCPConn) deliverError(err error) {
	var networkError ICMPError
	if errors.As(err, &networkError) && networkError.MTU != 0 {
		return
	}
	select {
	case c.networkError <- err:
	default:
	}
}

// publishICMPSequenceRange atomically exposes the transmitted sequence span
// used to authenticate asynchronous ICMP errors. Pure ACKs use the inclusive
// upper endpoint.
func (c *TCPConn) publishICMPSequenceRange(unacknowledged, next uint32) {
	c.icmpSequence.Store(uint64(unacknowledged)<<32 | uint64(next))
}

// acceptsICMPQuote reports whether the quoted TCP sequence belongs to data,
// control flags, or a pure ACK emitted by this connection.
func (c *TCPConn) acceptsICMPQuote(quoted []byte) bool {
	if len(quoted) < 8 {
		return false
	}
	sequenceRange := c.icmpSequence.Load()
	unacknowledged := uint32(sequenceRange >> 32)
	next := uint32(sequenceRange)
	sequence := binary.BigEndian.Uint32(quoted[4:8])
	return sequence-unacknowledged <= next-unacknowledged
}

// Read returns contiguous application bytes or the receive terminal state.
func (c *TCPConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	c.readCallMu.Lock()
	defer c.readCallMu.Unlock()
	n, err := c.read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, c.operationError("read", err)
	}
	return n, err
}

// read returns stream data without adding the public operation wrapper. The
// caller serializes it with other stream reads.
func (c *TCPConn) read(buffer []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.userClosed || c.readClosed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		if len(c.readBuffer) != 0 {
			n := copy(buffer, c.readBuffer)
			c.readBuffer = c.readBuffer[n:]
			if len(c.readBuffer) == 0 {
				c.readBuffer = nil
			}
			c.mu.Unlock()
			select {
			case c.windowUpdate <- struct{}{}:
			default:
			}
			return n, nil
		}
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return 0, err
		}
		deadline, changed, notified := c.readDeadline, c.readChanged, c.readNotify
		c.mu.Unlock()
		timer, timeout := deadlineTimer(deadline)
		select {
		case <-notified:
		case <-changed:
		case <-timeout:
			stopTimer(timer)
			return 0, os.ErrDeadlineExceeded
		case <-c.done:
		}
		stopTimer(timer)
	}
}

// WriteTo copies the receive stream into writer while preserving read
// ordering with concurrent calls to Read. It implements io.WriterTo.
func (c *TCPConn) WriteTo(writer io.Writer) (int64, error) {
	c.readCallMu.Lock()
	defer c.readCallMu.Unlock()
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		n, readErr := c.read(buffer)
		if n > 0 {
			written, writeErr := writer.Write(buffer[:n])
			if written < 0 || written > n {
				return total, c.operationError("writeto", errors.New("mipstack: invalid Write count"))
			}
			total += int64(written)
			if writeErr != nil {
				return total, c.operationError("writeto", writeErr)
			}
			if written != n {
				return total, c.operationError("writeto", io.ErrShortWrite)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, c.operationError("writeto", readErr)
		}
	}
}

// Write copies payload into the bounded TCP send buffer. It waits only for
// buffer space, not peer acknowledgement, matching standard net.Conn
// semantics. Bytes reported as written remain queued after a later timeout.
func (c *TCPConn) Write(payload []byte) (int, error) {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	written, err := c.write(payload)
	if err != nil {
		return written, c.operationError("write", err)
	}
	return written, nil
}

// write copies payload into the send buffer without adding the public
// operation wrapper. The caller serializes it with other stream writes.
func (c *TCPConn) write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(payload) {
		c.mu.Lock()
		if c.userClosed || c.writeClosed || c.terminalErr != nil {
			err := c.connectionErrorLocked()
			c.mu.Unlock()
			return written, err
		}
		available := c.sendCapacity - len(c.sendBuffer)
		if available > len(payload)-written {
			available = len(payload) - written
		}
		if available > 0 {
			c.sendBuffer = append(c.sendBuffer, payload[written:written+available]...)
			written += available
		}
		deadline, deadlineChanged, sendChanged := c.writeDeadline, c.writeChanged, c.sendChanged
		c.mu.Unlock()
		if available > 0 {
			c.notifySend()
		}
		if written == len(payload) {
			return written, nil
		}
		timer, timeout := deadlineTimer(deadline)
		select {
		case <-sendChanged:
			stopTimer(timer)
		case <-deadlineChanged:
			stopTimer(timer)
		case <-timeout:
			stopTimer(timer)
			return written, os.ErrDeadlineExceeded
		case <-c.done:
			stopTimer(timer)
			return written, c.connectionError()
		}
	}
	return written, nil
}

// ReadFrom copies a stream into c while preserving write ordering with
// concurrent calls to Write. It implements io.ReaderFrom without recursively
// entering io.Copy's ReaderFrom fast path.
func (c *TCPConn) ReadFrom(reader io.Reader) (int64, error) {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	buffer := make([]byte, 32*1024)
	var total int64
	emptyReads := 0
	for {
		n, readErr := reader.Read(buffer)
		if n < 0 || n > len(buffer) {
			return total, c.operationError("readfrom", errors.New("mipstack: invalid Read count"))
		}
		if n > 0 {
			emptyReads = 0
			written, writeErr := c.write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, c.operationError("readfrom", writeErr)
			}
			if written != n {
				return total, c.operationError("readfrom", io.ErrShortWrite)
			}
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return total, c.operationError("readfrom", io.ErrNoProgress)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, c.operationError("readfrom", readErr)
		}
	}
}

// CloseWrite queues FIN after all bytes already accepted by Write.
func (c *TCPConn) CloseWrite() error {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		err := c.connectionErrorLocked()
		c.mu.Unlock()
		return c.operationError("close", err)
	}
	if c.writeClosed {
		c.mu.Unlock()
		return nil
	}
	c.writeClosed = true
	c.mu.Unlock()
	c.notifySend()
	return nil
}

// CloseRead closes the application receive direction without resetting TCP.
func (c *TCPConn) CloseRead() error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		err := c.connectionErrorLocked()
		c.mu.Unlock()
		return c.operationError("close", err)
	}
	if !c.readClosed {
		c.readClosed = true
		c.readBuffer = nil
		c.readErr = net.ErrClosed
		c.notifyReadLocked()
	}
	c.mu.Unlock()
	select {
	case c.windowUpdate <- struct{}{}:
	default:
	}
	return nil
}

// Close releases application access and applies the SetLinger policy. The
// default queues FIN after accepted writes and finishes protocol processing in
// the background.
func (c *TCPConn) Close() error {
	closedNow := false
	needFIN := false
	linger := -1
	c.closeOnce.Do(func() {
		closedNow = true
		c.mu.Lock()
		needFIN = !c.writeClosed
		if needFIN {
			c.writeClosed = true
		}
		linger = c.linger
		c.userClosed = true
		c.readErr = net.ErrClosed
		c.readBuffer = nil
		if linger == 0 {
			c.sendBuffer = nil
			c.notifySendChangedLocked()
		}
		c.notifyReadLocked()
		c.mu.Unlock()
	})
	if !closedNow {
		return c.operationError("close", net.ErrClosed)
	}
	if linger == 0 {
		c.abort(net.ErrClosed)
		return nil
	}
	if needFIN {
		c.notifySend()
	}
	if linger > 0 {
		timer := time.NewTimer(tcpLingerDuration(linger))
		select {
		case <-c.lingerDone:
			stopTimer(timer)
		case <-c.done:
			stopTimer(timer)
		case <-timer.C:
			c.abort(net.ErrClosed)
		}
	}
	return nil
}

// LocalAddr returns the managed local TCP endpoint.
func (c *TCPConn) LocalAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.local) }

// RemoteAddr returns the connected remote TCP endpoint.
func (c *TCPConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.remote) }

// MultipathTCP reports whether this connection uses MPTCP. Mipstack currently
// implements ordinary TCP only, so the result is always false.
func (c *TCPConn) MultipathTCP() (bool, error) { return false, nil }

// network returns the standard network name for the connection family.
func (c *TCPConn) network() string { return c.net }

// operationError wraps a TCP socket failure in the same public shape used by
// the standard net package.
func (c *TCPConn) operationError(operation string, err error) error {
	return socketOperationError(operation, c.network(), c.LocalAddr(), c.RemoteAddr(), err)
}

// setOperationError wraps a deadline-setting failure using the local-address
// metadata shape of the standard net package.
func (c *TCPConn) setOperationError(err error) error {
	return socketOperationError("set", c.network(), nil, c.LocalAddr(), err)
}

// SetDeadline updates both application deadlines.
func (c *TCPConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	readChanged, writeChanged := c.readChanged, c.writeChanged
	c.readDeadline, c.writeDeadline = deadline, deadline
	c.readChanged, c.writeChanged = make(chan struct{}), make(chan struct{})
	c.mu.Unlock()
	close(readChanged)
	close(writeChanged)
	return nil
}

// SetReadDeadline updates the next Read deadline.
func (c *TCPConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	changed := c.readChanged
	c.readDeadline, c.readChanged = deadline, make(chan struct{})
	c.mu.Unlock()
	close(changed)
	return nil
}

// SetWriteDeadline updates the next Write deadline.
func (c *TCPConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	changed := c.writeChanged
	c.writeDeadline, c.writeChanged = deadline, make(chan struct{})
	c.mu.Unlock()
	close(changed)
	return nil
}

// SetKeepAlive enables or disables TCP keepalive probes.
func (c *TCPConn) SetKeepAlive(enabled bool) error {
	return c.updateSocketOptions(func() { c.keepAlive = enabled })
}

// SetKeepAlivePeriod sets both the idle delay and probe interval. Use
// SetKeepAliveConfig when different values or a custom probe count are needed.
func (c *TCPConn) SetKeepAlivePeriod(period time.Duration) error {
	if period <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() {
		c.keepAliveConfig.Idle = period
		c.keepAliveConfig.Interval = period
	})
}

// SetKeepAliveConfig replaces keepalive timing and probe count.
func (c *TCPConn) SetKeepAliveConfig(config KeepAliveConfig) error {
	if config.Idle <= 0 || config.Interval <= 0 || config.Count <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.keepAliveConfig = config })
}

// SetIdleTimeout closes the connection when no acceptable segment arrives for
// timeout. Zero disables the timeout.
func (c *TCPConn) SetIdleTimeout(timeout time.Duration) error {
	if timeout < 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.idleTimeout = timeout })
}

// SetNoDelay controls Nagle coalescing. The default is true, matching
// net.TCPConn.
func (c *TCPConn) SetNoDelay(noDelay bool) error {
	err := c.updateSocketOptions(func() { c.noDelay = noDelay })
	if err == nil {
		c.notifySend()
	}
	return err
}

// SetLinger controls how Close handles data waiting to be sent or
// acknowledged. A negative value completes in the background, zero performs
// an abortive close, and a positive value waits up to that many seconds before
// aborting the remaining transmission.
func (c *TCPConn) SetLinger(seconds int) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.linger = seconds
	c.mu.Unlock()
	return nil
}

// tcpLingerDuration converts a positive seconds value without overflowing a
// time.Duration on 64-bit platforms.
func tcpLingerDuration(seconds int) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	if int64(seconds) > int64(maximum)/int64(time.Second) {
		return maximum
	}
	return time.Duration(seconds) * time.Second
}

// SetReadBuffer changes the bounded application receive capacity.
func (c *TCPConn) SetReadBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.receiveCapacity = bytes
	c.mu.Unlock()
	select {
	case c.windowUpdate <- struct{}{}:
	default:
	}
	return nil
}

// SetWriteBuffer changes the bounded application send capacity.
func (c *TCPConn) SetWriteBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.sendCapacity = bytes
	c.notifySendChangedLocked()
	c.mu.Unlock()
	return nil
}

// updateSocketOptions applies one option update and wakes the actor.
func (c *TCPConn) updateSocketOptions(update func()) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	update()
	c.mu.Unlock()
	select {
	case c.optionsChanged <- struct{}{}:
	default:
	}
	return nil
}

// socketOptions returns one consistent option snapshot.
func (c *TCPConn) socketOptions() tcpSocketOptions {
	c.mu.Lock()
	defer c.mu.Unlock()
	return tcpSocketOptions{
		keepAlive: c.keepAlive, keepAliveConfig: c.keepAliveConfig,
		idleTimeout: c.idleTimeout, noDelay: c.noDelay,
	}
}

// abort publishes one actor termination request and its cause.
func (c *TCPConn) abort(err error) {
	c.abortWithReset(err, true)
}

// abortWithoutReset terminates local state without emitting from a source or
// route that the current configuration has already withdrawn.
func (c *TCPConn) abortWithoutReset(err error) {
	c.abortWithReset(err, false)
}

// abortWithReset publishes one actor termination request and its wire policy.
func (c *TCPConn) abortWithReset(err error, reset bool) {
	c.abortOnce.Do(func() {
		c.abortMu.Lock()
		c.abortErr = err
		c.abortRST = reset
		c.abortMu.Unlock()
		close(c.abortCh)
	})
}

// abortedError returns the cause stored before abortCh was closed.
func (c *TCPConn) abortedError() error {
	c.abortMu.Lock()
	defer c.abortMu.Unlock()
	if c.abortErr == nil {
		return net.ErrClosed
	}
	return c.abortErr
}

// resetAfterAbort reports whether the published local abort permits RST.
func (c *TCPConn) resetAfterAbort() bool {
	c.abortMu.Lock()
	defer c.abortMu.Unlock()
	return c.abortRST
}

// connectionError returns the application-visible terminal error.
func (c *TCPConn) connectionError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectionErrorLocked()
}

// connectionErrorLocked returns the terminal error while c.mu is held.
func (c *TCPConn) connectionErrorLocked() error {
	if c.terminalErr != nil {
		return c.terminalErr
	}
	return net.ErrClosed
}

// notifyReadLocked broadcasts a receive-state change while c.mu is held.
func (c *TCPConn) notifyReadLocked() {
	notified := c.readNotify
	c.readNotify = make(chan struct{})
	close(notified)
}

// notifySend wakes the connection actor after buffered data or CloseWrite.
func (c *TCPConn) notifySend() {
	select {
	case c.sendNotify <- struct{}{}:
	default:
	}
}

// notifySendChangedLocked wakes Writes waiting for send-buffer space while
// c.mu is held.
func (c *TCPConn) notifySendChangedLocked() {
	changed := c.sendChanged
	c.sendChanged = make(chan struct{})
	close(changed)
}

// notifyLingerDone publishes that every accepted byte and the local FIN have
// been cumulatively acknowledged. The actor may remain in FIN_WAIT or
// TIME_WAIT after a positive-linger Close has returned.
func (c *TCPConn) notifyLingerDone() {
	c.lingerOnce.Do(func() { close(c.lingerDone) })
}

// sendSnapshot returns unsent bytes at offset and the current logical end of
// the send buffer. Returned bytes are immutable until cumulatively ACKed.
func (c *TCPConn) sendSnapshot(offset, maximum int) ([]byte, int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := len(c.sendBuffer)
	if offset < 0 || offset >= total || maximum <= 0 {
		return nil, total, c.writeClosed
	}
	end := offset + maximum
	if end > total {
		end = total
	}
	return c.sendBuffer[offset:end], total, c.writeClosed
}

// acknowledgeSend releases cumulatively acknowledged data and wakes blocked
// writers.
func (c *TCPConn) acknowledgeSend(size int) {
	if size <= 0 {
		return
	}
	c.mu.Lock()
	if size > len(c.sendBuffer) {
		size = len(c.sendBuffer)
	}
	if size != 0 {
		c.sendBuffer = c.sendBuffer[size:]
		if len(c.sendBuffer) == 0 {
			c.sendBuffer = nil
		}
		c.notifySendChangedLocked()
	}
	c.mu.Unlock()
}

// discardingReads reports whether CloseRead has disabled application delivery
// while TCP must continue acknowledging the peer's stream.
func (c *TCPConn) discardingReads() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readClosed || c.userClosed
}

// appendReadBuffer retains as much contiguous data as the receive bound permits.
func (c *TCPConn) appendReadBuffer(payload []byte, outOfOrderBytes int) int {
	c.mu.Lock()
	available := c.receiveCapacity - len(c.readBuffer) - outOfOrderBytes
	if c.userClosed || c.readClosed {
		accepted := len(payload)
		c.mu.Unlock()
		return accepted
	}
	if available < 0 {
		available = 0
	}
	if len(payload) > available {
		payload = payload[:available]
	}
	c.readBuffer = append(c.readBuffer, payload...)
	if len(payload) != 0 {
		c.notifyReadLocked()
	}
	c.mu.Unlock()
	return len(payload)
}

// receiveWindow returns the currently advertised wire window.
func (c *TCPConn) receiveWindow(outOfOrderBytes int, scaled bool) uint16 {
	c.mu.Lock()
	available := c.receiveCapacity - len(c.readBuffer) - outOfOrderBytes
	if c.userClosed || c.readClosed {
		available = c.receiveCapacity - outOfOrderBytes
	}
	c.mu.Unlock()
	if available <= 0 {
		return 0
	}
	if scaled {
		available >>= tcpReceiveWindowScale
	}
	if available > 65535 {
		available = 65535
	}
	return uint16(available)
}

// setReadEOF publishes an orderly peer FIN after buffered data.
func (c *TCPConn) setReadEOF() {
	c.mu.Lock()
	if c.readErr == nil {
		c.readErr = io.EOF
		c.notifyReadLocked()
	}
	c.mu.Unlock()
}

// finish publishes the actor terminal state and wakes application calls.
func (c *TCPConn) finish(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	c.mu.Lock()
	c.terminalErr = err
	if c.readErr == nil {
		c.readErr = err
	}
	c.notifyReadLocked()
	c.notifySendChangedLocked()
	c.mu.Unlock()
}

// run owns the connection protocol state from SYN through termination.
func (c *TCPConn) run(initialSequence uint32) {
	defer c.stack.removeTCP(c)
	defer close(c.done)
	err := c.handshake(initialSequence)
	if err != nil {
		c.connected <- err
		c.finish(err)
		return
	}
	c.connected <- nil
	err = c.established(initialSequence + 1)
	c.finish(err)
}

// runPassive owns one server-side connection from SYN-ACK through
// termination.
func (c *TCPConn) runPassive(listener *TCPListener, syn tcpSegment, initialSequence uint32) {
	queued := false
	defer func() {
		if !queued {
			listener.removePending(c)
		}
	}()
	defer c.stack.removeTCP(c)
	defer close(c.done)
	if err := c.passiveHandshake(syn, initialSequence); err != nil {
		if errors.Is(err, net.ErrClosed) {
			_ = c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagRST|tcpFlagACK, 0, nil)
		}
		c.finish(err)
		return
	}
	if !listener.enqueue(c) {
		_ = c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagRST|tcpFlagACK, 0, nil)
		c.finish(syscall.ECONNABORTED)
		return
	}
	queued = true
	err := c.established(initialSequence + 1)
	c.finish(err)
}

// passiveHandshake replies to one valid SYN and waits for the final ACK with
// bounded retransmission.
func (c *TCPConn) passiveHandshake(syn tcpSegment, initialSequence uint32) error {
	localMSS := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	mss, scale, windowScaling, sack, timestamp, timestampValue := parseTCPOptions(syn.options, defaultTCPPeerMSS(c.key.remote.Addr()), 65535)
	c.peerMSS, c.peerWindowScale, c.peerWindowScaling, c.peerSACK = mss, scale, windowScaling, sack
	c.peerTimestamp, c.recentTimestamp = timestamp, timestampValue
	c.peerECN = syn.flags&(tcpFlagECE|tcpFlagCWR) == tcpFlagECE|tcpFlagCWR
	c.receiveNext = syn.sequence + 1
	c.peerWindow = uint32(syn.window)
	c.peerWindowSeq = syn.sequence
	c.peerWindowACK = 0

	rto := tcpInitialRTO
	attempts := 0
	timer := time.NewTimer(time.Hour)
	stopTimer(timer)
	defer timer.Stop()
	var timeout <-chan time.Time
	send := func() error {
		options := tcpPassiveSYNOptions(localMSS, sack, windowScaling, timestamp, c.stack.tcpTimestamp(), c.recentTimestamp)
		flags := byte(tcpFlagSYN | tcpFlagACK)
		if c.peerECN {
			flags |= tcpFlagECE
		}
		if err := c.stack.writeTCPWithMTU(c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(), initialSequence, c.receiveNext, flags, c.receiveWindow(0, false), options, nil, c.mtu); err != nil {
			return err
		}
		if attempts != 0 {
			c.stack.stats.tcpRetransmissions.Add(1)
		}
		attempts++
		resetTimer(timer, rto)
		timeout = timer.C
		return nil
	}
	if err := send(); err != nil {
		return err
	}
	for {
		select {
		case segment := <-c.inbound:
			if segment.flags&tcpFlagRST != 0 {
				if segment.sequence == c.receiveNext {
					return syscall.ECONNRESET
				}
				continue
			}
			if segment.flags&tcpFlagSYN != 0 && segment.flags&tcpFlagACK == 0 && segment.sequence+1 == c.receiveNext {
				if err := send(); err != nil {
					return err
				}
				continue
			}
			if segment.flags&tcpFlagACK == 0 || segment.acknowledgement != initialSequence+1 || segment.sequence != c.receiveNext {
				continue
			}
			if c.peerTimestamp {
				value, _, present := parseTCPTimestamp(segment.options)
				if !present || tcpSequenceLess(value, c.recentTimestamp) {
					continue
				}
				c.recentTimestamp = value
			}
			c.peerWindow = uint32(segment.window)
			if c.peerWindowScaling {
				c.peerWindow <<= c.peerWindowScale
			}
			c.peerWindowSeq = segment.sequence
			c.peerWindowACK = segment.acknowledgement
			stopTimer(timer)
			if len(segment.payload) != 0 || segment.flags&tcpFlagFIN != 0 {
				c.inbound <- segment
			}
			return nil
		case <-c.pathMTUUpdate:
			c.mtu = c.stack.mtuFor(c.key.remote.Addr())
			localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
			if localMSS < 1 {
				return errors.New("mipstack: MTU is too small for TCP")
			}
			if err := send(); err != nil {
				return err
			}
		case <-c.networkError:
			// Network errors during passive open are soft; the peer's retry and
			// the bounded SYN-ACK timeout decide whether the flow survives.
		case <-timeout:
			if attempts >= 6 {
				return os.ErrDeadlineExceeded
			}
			rto *= 2
			if rto > tcpMaximumRTO {
				rto = tcpMaximumRTO
			}
			if err := send(); err != nil {
				return err
			}
		case <-c.abortCh:
			return c.abortedError()
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

// handshake performs active open with bounded exponential SYN retransmission.
func (c *TCPConn) handshake(initialSequence uint32) error {
	localMSS := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	rto := tcpInitialRTO
	attempts := 0
	timer := time.NewTimer(time.Hour)
	stopTimer(timer)
	defer timer.Stop()
	var timeout <-chan time.Time
	send := func() error {
		options := tcpSYNOptions(localMSS, c.stack.tcpTimestamp())
		flags := byte(tcpFlagSYN)
		if attempts == 0 {
			flags |= tcpFlagECE | tcpFlagCWR
		}
		if err := c.stack.writeTCPWithMTU(c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(), initialSequence, 0, flags, c.receiveWindow(0, false), options, nil, c.mtu); err != nil {
			return err
		}
		if attempts != 0 {
			c.stack.stats.tcpRetransmissions.Add(1)
		}
		attempts++
		resetTimer(timer, rto)
		timeout = timer.C
		return nil
	}
	if err := send(); err != nil {
		return err
	}
	for {
		select {
		case segment := <-c.inbound:
			if segment.flags&tcpFlagRST != 0 {
				if segment.flags&tcpFlagACK != 0 && segment.acknowledgement == initialSequence+1 {
					return syscall.ECONNREFUSED
				}
				continue
			}
			if segment.flags&(tcpFlagSYN|tcpFlagACK) != tcpFlagSYN|tcpFlagACK || segment.acknowledgement != initialSequence+1 {
				continue
			}
			mss, scale, windowScaling, sack, timestamp, timestampValue := parseTCPOptions(segment.options, defaultTCPPeerMSS(c.key.remote.Addr()), 65535)
			c.peerMSS, c.peerWindowScale, c.peerSACK = mss, scale, sack
			c.peerWindowScaling = windowScaling
			c.peerTimestamp, c.recentTimestamp = timestamp, timestampValue
			c.peerECN = segment.flags&tcpFlagECE != 0 && segment.flags&tcpFlagCWR == 0
			c.receiveNext = segment.sequence + 1
			// The window in SYN and SYN-ACK is never scaled. The negotiated
			// shift applies only to later segments.
			c.peerWindow = uint32(segment.window)
			c.peerWindowSeq = segment.sequence
			c.peerWindowACK = segment.acknowledgement
			stopTimer(timer)
			return c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagACK, 0, nil)
		case <-c.pathMTUUpdate:
			c.mtu = c.stack.mtuFor(c.key.remote.Addr())
			localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
			if localMSS < 1 {
				return errors.New("mipstack: MTU is too small for TCP")
			}
			if err := send(); err != nil {
				return err
			}
		case err := <-c.networkError:
			return err
		case <-timeout:
			if attempts >= 6 {
				return os.ErrDeadlineExceeded
			}
			rto *= 2
			if rto > tcpMaximumRTO {
				rto = tcpMaximumRTO
			}
			if err := send(); err != nil {
				return err
			}
		case <-c.abortCh:
			return c.abortedError()
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

// The fields below are initialized by handshake before established runs and
// thereafter belong exclusively to the connection actor.
// established runs the serialized data, congestion, receive, and close state
// machine.
func (c *TCPConn) established(sendNext uint32) error {
	localMaximum := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	if c.peerTimestamp {
		localMaximum -= 12
	}
	peerMSS := clampMSS(c.peerMSS, localMaximum)
	var (
		sendUnacknowledged  = sendNext
		peerScale           = c.peerWindowScale
		peerSACK            = c.peerSACK
		peerWindow          = c.peerWindow
		peerWindowSequence  = c.peerWindowSeq
		peerWindowACK       = c.peerWindowACK
		receiveNext         = c.receiveNext
		congestionWindow    = initialTCPWindow(peerMSS)
		slowStartThreshold  = ^uint32(0) >> 1
		outstanding         []sentTCPSegment
		outOfOrder          []tcpReceivedPiece
		outOfOrderBytes     int
		localFINSent        bool
		localFINAcked       bool
		remoteFINReceived   bool
		duplicateACKs       int
		fastRecovery        bool
		recoveryPoint       uint32
		recentSACK          uint32
		tailProbeSent       bool
		consecutiveRTOs     int
		lastSoftError       error
		lastTimestampUpdate = time.Now()
		ecnRecoveryPoint    uint32
		controller          = newTCPCongestionController(c.stack.network.Load().congestionControl)
		rackLatestSent      time.Time
	)
	c.publishICMPSequenceRange(sendUnacknowledged, sendNext)
	rtt := rttEstimator{rto: tcpInitialRTO}
	retransmissionTimer := time.NewTimer(time.Hour)
	persistTimer := time.NewTimer(time.Hour)
	delayedACKTimer := time.NewTimer(time.Hour)
	livenessTimer := time.NewTimer(time.Hour)
	pathMTUTimer := time.NewTimer(time.Hour)
	var pacingTimer *time.Timer
	stopTimer(retransmissionTimer)
	stopTimer(persistTimer)
	stopTimer(delayedACKTimer)
	stopTimer(livenessTimer)
	stopTimer(pathMTUTimer)
	defer retransmissionTimer.Stop()
	defer persistTimer.Stop()
	defer delayedACKTimer.Stop()
	defer livenessTimer.Stop()
	defer pathMTUTimer.Stop()
	defer func() {
		if pacingTimer != nil {
			pacingTimer.Stop()
		}
	}()
	var retransmit, persist, delayedACK <-chan time.Time
	var liveness <-chan time.Time
	var pathMTUProbe, pacing <-chan time.Time
	var retransmissionProbe, retransmissionClose bool
	persistRTO := time.Second
	ackPending := false
	ackSegments := 0
	lastAdvertisedWindow := c.receiveWindow(0, c.peerWindowScaling)
	lastActivity := time.Now()
	lastKeepAlive := time.Time{}
	keepAliveProbes := 0
	armPathMTUProbe := func() {
		stopTimer(pathMTUTimer)
		pathMTUProbe = nil
		if expiry, exists := c.stack.pathMTUExpiry(c.key.remote.Addr()); exists {
			delay := time.Until(expiry)
			if delay < 0 {
				delay = 0
			}
			resetTimer(pathMTUTimer, delay)
			pathMTUProbe = pathMTUTimer.C
		}
	}
	armPacing := func(delay time.Duration) {
		if delay <= 0 {
			return
		}
		if pacingTimer == nil {
			pacingTimer = time.NewTimer(delay)
			pacing = pacingTimer.C
			return
		}
		resetTimer(pacingTimer, delay)
		pacing = pacingTimer.C
	}
	armLiveness := func() {
		stopTimer(livenessTimer)
		liveness = nil
		if localFINAcked && remoteFINReceived {
			return
		}
		options := c.socketOptions()
		var deadline time.Time
		if options.idleTimeout > 0 {
			deadline = lastActivity.Add(options.idleTimeout)
		}
		if options.keepAlive {
			keepAliveDeadline := lastActivity.Add(options.keepAliveConfig.Idle)
			if keepAliveProbes != 0 {
				keepAliveDeadline = lastKeepAlive.Add(options.keepAliveConfig.Interval)
			}
			if deadline.IsZero() || keepAliveDeadline.Before(deadline) {
				deadline = keepAliveDeadline
			}
		}
		if !deadline.IsZero() {
			delay := time.Until(deadline)
			if delay < 0 {
				delay = 0
			}
			resetTimer(livenessTimer, delay)
			liveness = livenessTimer.C
		}
	}

	armRetransmission := func() {
		stopTimer(retransmissionTimer)
		retransmit = nil
		retransmissionProbe = false
		retransmissionClose = false
		if len(outstanding) != 0 {
			index := firstUnsackedSegment(outstanding)
			deadline := outstanding[index].sentAt.Add(rtt.rto)
			if !tailProbeSent {
				probeIndex := lastUnsackedSegment(outstanding)
				probeDeadline := outstanding[probeIndex].sentAt.Add(tailLossProbeDelay(rtt.srtt, rtt.rto))
				if probeDeadline.Before(deadline) {
					deadline = probeDeadline
					retransmissionProbe = true
				}
			}
			delay := time.Until(deadline)
			if delay < 0 {
				delay = 0
			}
			resetTimer(retransmissionTimer, delay)
			retransmit = retransmissionTimer.C
		}
	}
	armClose := func(duration time.Duration) {
		resetTimer(retransmissionTimer, duration)
		retransmit = retransmissionTimer.C
		retransmissionProbe = false
		retransmissionClose = true
	}
	armPersist := func() {
		offset := int(sendNext - sendUnacknowledged)
		_, total, writeClosed := c.sendSnapshot(offset, 0)
		pending := offset < total || writeClosed && !localFINSent
		if pending && peerWindow == 0 && persist == nil {
			if persistRTO < rtt.rto {
				persistRTO = rtt.rto
			}
			resetTimer(persistTimer, persistRTO)
			persist = persistTimer.C
		} else if peerWindow != 0 || !pending {
			stopTimer(persistTimer)
			persist = nil
			persistRTO = time.Second
		}
	}
	clearDelayedACK := func() {
		stopTimer(delayedACKTimer)
		delayedACK = nil
		ackPending = false
		ackSegments = 0
	}
	sendACK := func() error {
		var options []byte
		if peerSACK {
			maximumBlocks := 4
			if c.peerTimestamp {
				maximumBlocks = 3
			}
			options = tcpSACKOptions(outOfOrder, recentSACK, maximumBlocks)
		}
		if err := c.sendSegmentWithOptions(sendNext, receiveNext, tcpFlagACK, outOfOrderBytes, options, nil); err != nil {
			return err
		}
		lastAdvertisedWindow = c.receiveWindow(outOfOrderBytes, c.peerWindowScaling)
		clearDelayedACK()
		return nil
	}
	sendChallengeACK := func() error {
		if !c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
			return nil
		}
		return sendACK()
	}
	scheduleACK := func(immediate, data bool) error {
		ackPending = true
		if data {
			ackSegments++
		}
		if immediate || ackSegments >= 2 {
			return sendACK()
		}
		if delayedACK == nil {
			resetTimer(delayedACKTimer, tcpDelayedACKTimeout)
			delayedACK = delayedACKTimer.C
		}
		return nil
	}
	fillWindow := func() error {
		if localFINSent {
			armPersist()
			return nil
		}
		windowFlight := sendNext - sendUnacknowledged
		congestionFlight := outstandingBytes(outstanding, false)
		for windowFlight < peerWindow && congestionFlight < congestionWindow {
			offset := int(sendNext - sendUnacknowledged)
			size := peerMSS
			if available := int(peerWindow - windowFlight); size > available {
				size = available
			}
			if available := int(congestionWindow - congestionFlight); size > available {
				size = available
			}
			if size <= 0 {
				break
			}
			payload, total, writeClosed := c.sendSnapshot(offset, size)
			if len(payload) == 0 {
				break
			}
			if delay := controller.pacingDelay(time.Now()); delay > 0 {
				armPacing(delay)
				break
			}
			if !c.socketOptions().noDelay && len(outstanding) != 0 && len(payload) < peerMSS && !writeClosed {
				break
			}
			flags := tcpFlagACK
			if offset+len(payload) == total {
				flags |= tcpFlagPSH
			}
			next := sendNext + uint32(len(payload))
			c.publishICMPSequenceRange(sendUnacknowledged, next)
			if err := c.sendNewDataSegment(sendNext, receiveNext, flags, outOfOrderBytes, payload); err != nil {
				return err
			}
			if ackPending {
				lastAdvertisedWindow = c.receiveWindow(outOfOrderBytes, c.peerWindowScaling)
				clearDelayedACK()
			}
			now := time.Now()
			controller.onSend(len(payload), now)
			outstanding = append(outstanding, sentTCPSegment{sequence: sendNext, end: sendNext + uint32(len(payload)), flags: flags, payload: payload, sentAt: now, transmissions: 1})
			sendNext = next
			windowFlight += uint32(len(payload))
			congestionFlight += uint32(len(payload))
		}
		offset := int(sendNext - sendUnacknowledged)
		_, total, writeClosed := c.sendSnapshot(offset, 0)
		if writeClosed && offset >= total && windowFlight < peerWindow && congestionFlight < congestionWindow {
			c.publishICMPSequenceRange(sendUnacknowledged, sendNext+1)
			if err := c.sendSegment(sendNext, receiveNext, tcpFlagACK|tcpFlagFIN, outOfOrderBytes, nil); err != nil {
				return err
			}
			outstanding = append(outstanding, sentTCPSegment{sequence: sendNext, end: sendNext + 1, flags: tcpFlagACK | tcpFlagFIN, sentAt: time.Now(), transmissions: 1})
			sendNext++
			localFINSent = true
			if ackPending {
				lastAdvertisedWindow = c.receiveWindow(outOfOrderBytes, c.peerWindowScaling)
				clearDelayedACK()
			}
		}
		if len(outstanding) != 0 {
			armRetransmission()
		} else if !localFINAcked {
			armRetransmission()
		}
		armPersist()
		return nil
	}
	retransmitSegment := func(index int, timeout bool) error {
		if len(outstanding) == 0 {
			return nil
		}
		if index < 0 || index >= len(outstanding) {
			index = firstUnsackedSegment(outstanding)
		}
		oldest := &outstanding[index]
		rackRetransmission := oldest.rackLost
		if oldest.transmissions >= tcpMaximumRetransmits {
			return tcpTimeoutError(lastSoftError)
		}
		if err := c.sendSegment(oldest.sequence, receiveNext, oldest.flags, outOfOrderBytes, oldest.payload); err != nil {
			return err
		}
		oldest.sentAt = time.Now()
		oldest.transmissions++
		oldest.sackRetried = !timeout
		oldest.rackLost = false
		c.stack.stats.tcpRetransmissions.Add(1)
		if !timeout && peerSACK {
			c.stack.stats.tcpSACKRetransmissions.Add(1)
			if rackRetransmission {
				c.stack.stats.tcpRACKRetransmissions.Add(1)
			}
		}
		tailProbeSent = true
		if timeout {
			slowStartThreshold = controller.onCongestion(congestionWindow, peerMSS)
			congestionWindow = uint32(peerMSS)
			fastRecovery = false
			for index := range outstanding {
				outstanding[index].sacked = false
				outstanding[index].sackRetried = false
				outstanding[index].rackLost = false
			}
			rtt.backoff()
		} else {
			if !fastRecovery {
				slowStartThreshold = controller.onCongestion(congestionWindow, peerMSS)
				congestionWindow = slowStartThreshold + uint32(3*peerMSS)
				fastRecovery = true
				recoveryPoint = sendNext
			}
		}
		if len(outstanding) != 0 {
			armRetransmission()
		}
		return nil
	}
	recoverSACKHoles := func(highest uint32, allSACKHoles bool) error {
		retransmitted := false
		for {
			index := firstUnretriedLoss(outstanding, highest, allSACKHoles)
			if index < 0 {
				return nil
			}
			size := outstanding[index].end - outstanding[index].sequence
			pipe := sackRecoveryPipe(outstanding, highest, allSACKHoles)
			if retransmitted && pipe+size > congestionWindow {
				return nil
			}
			if err := retransmitSegment(index, false); err != nil {
				return err
			}
			retransmitted = true
		}
	}
	applyPathMTU := func(retransmit bool) error {
		configured := c.stack.network.Load().congestionControl
		if configured != controller.algorithm {
			controller = newTCPCongestionController(configured)
			congestionWindow = initialTCPWindow(peerMSS)
			slowStartThreshold = ^uint32(0) >> 1
			if pacingTimer != nil {
				stopTimer(pacingTimer)
			}
			pacing = nil
		}
		mtu := c.stack.mtuFor(c.key.remote.Addr())
		c.mtu = mtu
		armPathMTUProbe()
		localMaximum := tcpMSSForMTU(mtu, c.key.local.Addr())
		if c.peerTimestamp {
			localMaximum -= 12
		}
		newMSS := clampMSS(c.peerMSS, localMaximum)
		if newMSS == peerMSS {
			return nil
		}
		if newMSS > peerMSS {
			peerMSS = newMSS
			controller.onMTUChange()
			if congestionWindow < uint32(peerMSS) {
				congestionWindow = uint32(peerMSS)
			}
			return nil
		}
		peerMSS = newMSS
		controller.onMTUChange()
		outstanding = splitTCPSegments(outstanding, peerMSS)
		if congestionWindow < uint32(peerMSS) {
			congestionWindow = uint32(peerMSS)
		}
		if retransmit && len(outstanding) != 0 {
			index := firstUnsackedSegment(outstanding)
			segment := &outstanding[index]
			if segment.transmissions >= tcpMaximumRetransmits {
				return tcpTimeoutError(lastSoftError)
			}
			if err := c.sendSegment(segment.sequence, receiveNext, segment.flags, outOfOrderBytes, segment.payload); err != nil {
				return err
			}
			segment.sentAt = time.Now()
			segment.transmissions++
			c.stack.stats.tcpRetransmissions.Add(1)
			armRetransmission()
		}
		return nil
	}
	armPathMTUProbe()
	armLiveness()
	for {
		select {
		case segment := <-c.inbound:
			segmentLength := uint32(len(segment.payload))
			if segment.flags&tcpFlagSYN != 0 {
				segmentLength++
			}
			if segment.flags&tcpFlagFIN != 0 {
				segmentLength++
			}
			receiveWindow := uint32(c.receiveWindow(outOfOrderBytes, c.peerWindowScaling))
			if c.peerWindowScaling {
				receiveWindow <<= tcpReceiveWindowScale
			}
			if !tcpSegmentAcceptable(segment.sequence, segmentLength, receiveNext, receiveWindow) {
				if segment.flags&tcpFlagRST == 0 {
					if err := sendChallengeACK(); err != nil {
						return err
					}
				}
				continue
			}
			timestampEcho := uint32(0)
			if c.peerTimestamp && segment.flags&tcpFlagRST == 0 {
				timestampValue, echo, present := parseTCPTimestamp(segment.options)
				if !present {
					continue
				}
				timestampEcho = echo
				if time.Since(lastTimestampUpdate) < 24*24*time.Hour && tcpSequenceLess(timestampValue, c.recentTimestamp) {
					if err := sendChallengeACK(); err != nil {
						return err
					}
					continue
				}
				segmentEnd := segment.sequence + uint32(len(segment.payload))
				if segment.flags&tcpFlagSYN != 0 || segment.flags&tcpFlagFIN != 0 {
					segmentEnd++
				}
				if tcpSequenceLessEqual(segment.sequence, receiveNext) && tcpSequenceGreaterEqual(segmentEnd, receiveNext) {
					c.recentTimestamp = timestampValue
					lastTimestampUpdate = time.Now()
				}
			}
			lastActivity = time.Now()
			lastKeepAlive = time.Time{}
			keepAliveProbes = 0
			armLiveness()
			if c.peerECN {
				if segment.flags&tcpFlagCWR != 0 {
					c.echoCongestion = false
				}
				if segment.ecn == 3 {
					c.echoCongestion = true
				}
			}
			if segment.flags&tcpFlagRST != 0 {
				if segment.sequence == receiveNext {
					return syscall.ECONNRESET
				}
				if err := sendChallengeACK(); err != nil {
					return err
				}
				continue
			}
			if segment.flags&tcpFlagSYN != 0 {
				if err := sendChallengeACK(); err != nil {
					return err
				}
				continue
			}
			if segment.flags&tcpFlagACK == 0 {
				continue
			}
			previousWindow := peerWindow
			ack := segment.acknowledgement
			if tcpSequenceGreater(ack, sendNext) || tcpSequenceLess(ack, sendUnacknowledged) {
				if err := sendChallengeACK(); err != nil {
					return err
				}
				continue
			}
			if tcpWindowUpdateAllowed(segment.sequence, ack, peerWindowSequence, peerWindowACK) {
				peerWindow = uint32(segment.window) << peerScale
				peerWindowSequence = segment.sequence
				peerWindowACK = ack
			}
			ackAdvanced := tcpSequenceGreater(ack, sendUnacknowledged)
			if c.peerECN && segment.flags&tcpFlagECE != 0 && len(outstanding) != 0 && (ecnRecoveryPoint == 0 || tcpSequenceGreaterEqual(ack, ecnRecoveryPoint)) {
				slowStartThreshold = controller.onCongestion(congestionWindow, peerMSS)
				congestionWindow = slowStartThreshold
				ecnRecoveryPoint = sendNext
				c.sendCWR = true
			}
			if tcpSequenceGreater(ack, sendUnacknowledged) {
				acknowledged := ack - sendUnacknowledged
				flightBeforeACK := outstandingBytes(outstanding, false)
				c.acknowledgeSend(int(acknowledged))
				sendUnacknowledged = ack
				c.publishICMPSequenceRange(sendUnacknowledged, sendNext)
				duplicateACKs = 0
				tailProbeSent = false
				consecutiveRTOs = 0
				lastSoftError = nil
				sampledRTT := false
				rttSample := time.Duration(0)
				if c.peerTimestamp && timestampEcho != 0 {
					delta := c.stack.tcpTimestamp() - timestampEcho
					if delta != 0 && time.Duration(delta)*time.Millisecond <= tcpMaximumRTO {
						rttSample = time.Duration(delta) * time.Millisecond
						rtt.observe(rttSample)
						sampledRTT = true
					}
				}
				for len(outstanding) != 0 && tcpSequenceGreaterEqual(ack, outstanding[0].end) {
					oldest := outstanding[0]
					if oldest.sentAt.After(rackLatestSent) {
						rackLatestSent = oldest.sentAt
					}
					if !sampledRTT && oldest.transmissions == 1 {
						rttSample = time.Since(oldest.sentAt)
						rtt.observe(rttSample)
						sampledRTT = true
					}
					if oldest.flags&tcpFlagFIN != 0 {
						localFINAcked = true
						c.notifyLingerDone()
					}
					outstanding = outstanding[1:]
				}
				if len(outstanding) == 0 {
					outstanding = nil
				}
				if len(outstanding) != 0 && tcpSequenceGreater(ack, outstanding[0].sequence) {
					skip := ack - outstanding[0].sequence
					if skip < uint32(len(outstanding[0].payload)) {
						outstanding[0].payload = outstanding[0].payload[skip:]
						outstanding[0].sequence = ack
					}
				}
				if fastRecovery {
					if tcpSequenceGreaterEqual(ack, recoveryPoint) {
						fastRecovery = false
						congestionWindow = slowStartThreshold
					} else {
						congestionWindow = slowStartThreshold + uint32(3*peerMSS)
					}
				} else {
					congestionWindow = controller.onACK(congestionWindow, acknowledged, peerMSS, time.Now(), rtt.srtt, rttSample, flightBeforeACK, congestionWindow < slowStartThreshold)
				}
				armRetransmission()
			}
			var highestSACK uint32
			hasSACK := false
			if peerSACK && len(outstanding) != 0 {
				blocks := parseTCPSACKOptions(segment.options, sendUnacknowledged, sendNext)
				var latestSACK time.Time
				highestSACK, hasSACK, latestSACK = applyTCPSACK(outstanding, blocks)
				if latestSACK.After(rackLatestSent) {
					rackLatestSent = latestSACK
				}
				markRACKLoss(outstanding, rackLatestSent, rackReorderingWindow(rtt.srtt))
			}
			if hasRACKLoss(outstanding) {
				if err := recoverSACKHoles(highestSACK, false); err != nil {
					return err
				}
			}
			if !ackAdvanced && ack == sendUnacknowledged && previousWindow == peerWindow && len(segment.payload) == 0 && segment.flags&tcpFlagFIN == 0 && len(outstanding) != 0 {
				duplicateACKs++
				if duplicateACKs == 3 {
					if hasSACK {
						if err := recoverSACKHoles(highestSACK, true); err != nil {
							return err
						}
					} else if err := retransmitSegment(firstUnsackedSegment(outstanding), false); err != nil {
						return err
					}
				} else if duplicateACKs > 3 {
					congestionWindow = growCongestionWindow(congestionWindow, uint32(peerMSS))
				}
			}
			if fastRecovery && hasSACK {
				if ackAdvanced || duplicateACKs >= 3 {
					if err := recoverSACKHoles(highestSACK, true); err != nil {
						return err
					}
				}
			}

			fin := segment.flags&tcpFlagFIN != 0
			if len(segment.payload) != 0 || fin {
				previousReceiveNext := receiveNext
				recentSACK = segment.sequence
				if !remoteFINReceived {
					_, closed := c.receiveTCPData(segment.sequence, segment.payload, fin, &receiveNext, &outOfOrder, &outOfOrderBytes)
					if closed {
						remoteFINReceived = true
						c.setReadEOF()
					}
				}
				immediateACK := fin || segment.sequence != previousReceiveNext || len(outOfOrder) != 0
				if err := scheduleACK(immediateACK, len(segment.payload) != 0); err != nil {
					return err
				}
			}
			if localFINAcked && remoteFINReceived {
				armClose(tcpTimeWaitDuration)
			} else if localFINAcked {
				armClose(tcpFINWaitDuration)
			}
			armLiveness()
			if err := fillWindow(); err != nil {
				return err
			}

		case <-c.sendNotify:
			if err := fillWindow(); err != nil {
				return err
			}

		case <-c.windowUpdate:
			if c.discardingReads() {
				outOfOrder = nil
				outOfOrderBytes = 0
			}
			window := c.receiveWindow(outOfOrderBytes, c.peerWindowScaling)
			if window > lastAdvertisedWindow {
				if err := scheduleACK(lastAdvertisedWindow == 0, false); err != nil {
					return err
				}
			}
			if err := fillWindow(); err != nil {
				return err
			}

		case <-retransmit:
			if retransmissionClose {
				return net.ErrClosed
			}
			if retransmissionProbe {
				index := lastUnsackedSegment(outstanding)
				segment := &outstanding[index]
				if segment.transmissions >= tcpMaximumRetransmits {
					return tcpTimeoutError(lastSoftError)
				}
				if err := c.sendSegment(segment.sequence, receiveNext, segment.flags, outOfOrderBytes, segment.payload); err != nil {
					return err
				}
				segment.sentAt = time.Now()
				segment.transmissions++
				tailProbeSent = true
				c.stack.stats.tcpRetransmissions.Add(1)
				c.stack.stats.tcpTailLossProbes.Add(1)
				armRetransmission()
				continue
			}
			consecutiveRTOs++
			if consecutiveRTOs >= tcpBlackHoleTimeouts {
				if mtu := nextBlackHoleMTU(c.mtu, c.key.remote.Addr().Is6()); mtu < c.mtu {
					if c.stack.observePathMTU(c.key.remote.Addr(), uint32(mtu)) {
						c.stack.stats.pathMTUBlackHoleReductions.Add(1)
						c.stack.notifyTCPPathMTU(c.key.remote.Addr(), c)
					}
					if err := applyPathMTU(false); err != nil {
						return err
					}
				}
				consecutiveRTOs = 0
			}
			if err := retransmitSegment(firstUnsackedSegment(outstanding), true); err != nil {
				return err
			}

		case <-persist:
			persist = nil
			sequence, flags := sendNext, byte(tcpFlagACK)
			var payload []byte
			if len(outstanding) != 0 {
				segment := &outstanding[firstUnsackedSegment(outstanding)]
				sequence, flags = segment.sequence, segment.flags
				if len(segment.payload) != 0 {
					payload = segment.payload[:1]
				}
			} else {
				offset := int(sendNext - sendUnacknowledged)
				payload, _, _ = c.sendSnapshot(offset, 1)
				if len(payload) != 0 {
					c.publishICMPSequenceRange(sendUnacknowledged, sendNext+1)
					outstanding = append(outstanding, sentTCPSegment{
						sequence: sendNext, end: sendNext + 1, flags: flags,
						payload: payload, sentAt: time.Now(), transmissions: 1,
					})
					sendNext++
				} else {
					sequence--
					if sequence-sendUnacknowledged > sendNext-sendUnacknowledged {
						c.publishICMPSequenceRange(sequence, sendNext)
					}
				}
			}
			if err := c.sendSegment(sequence, receiveNext, flags, outOfOrderBytes, payload); err != nil {
				return err
			}
			c.stack.stats.tcpZeroWindowProbes.Add(1)
			if len(outstanding) != 0 {
				armRetransmission()
			}
			persistRTO *= 2
			if persistRTO > tcpMaximumRTO {
				persistRTO = tcpMaximumRTO
			}
			armPersist()

		case <-delayedACK:
			if err := sendACK(); err != nil {
				return err
			}

		case <-c.pathMTUUpdate:
			if err := applyPathMTU(true); err != nil {
				return err
			}
		case <-pathMTUProbe:
			pathMTUProbe = nil
			if err := applyPathMTU(false); err != nil {
				return err
			}
			if err := fillWindow(); err != nil {
				return err
			}
		case <-pacing:
			pacing = nil
			if err := fillWindow(); err != nil {
				return err
			}
		case <-c.optionsChanged:
			keepAliveProbes = 0
			lastKeepAlive = time.Time{}
			armLiveness()
			if err := fillWindow(); err != nil {
				return err
			}
		case <-liveness:
			options := c.socketOptions()
			now := time.Now()
			if options.idleTimeout > 0 && !now.Before(lastActivity.Add(options.idleTimeout)) {
				return os.ErrDeadlineExceeded
			}
			if options.keepAlive {
				deadline := lastActivity.Add(options.keepAliveConfig.Idle)
				if keepAliveProbes != 0 {
					deadline = lastKeepAlive.Add(options.keepAliveConfig.Interval)
				}
				if !now.Before(deadline) {
					if keepAliveProbes >= options.keepAliveConfig.Count {
						return syscall.ETIMEDOUT
					}
					probeSequence := sendNext - 1
					if probeSequence-sendUnacknowledged > sendNext-sendUnacknowledged {
						c.publishICMPSequenceRange(probeSequence, sendNext)
					}
					if err := c.sendSegment(probeSequence, receiveNext, tcpFlagACK, outOfOrderBytes, nil); err != nil {
						return err
					}
					keepAliveProbes++
					lastKeepAlive = now
					c.stack.stats.tcpKeepAliveProbes.Add(1)
				}
			}
			armLiveness()
		case err := <-c.networkError:
			// ICMP failures on an established TCP flow are soft errors. TCP
			// retransmission and its bounded timeout decide whether the stream
			// is actually unusable.
			lastSoftError = err
			continue
		case <-c.abortCh:
			err := c.abortedError()
			if c.resetAfterAbort() {
				_ = c.sendSegment(sendNext, receiveNext, tcpFlagRST|tcpFlagACK, outOfOrderBytes, nil)
			}
			return err
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

// sendSegment emits a segment with the actor's current advertised window.
func (c *TCPConn) sendSegment(sequence, acknowledgement uint32, flags byte, outOfOrderBytes int, payload []byte) error {
	return c.sendSegmentWithOptions(sequence, acknowledgement, flags, outOfOrderBytes, nil, payload)
}

// sendNewDataSegment emits a first transmission with ECT when ECN was
// negotiated. Retransmissions and window probes use sendSegment and remain
// Not-ECT as required by RFC 3168.
func (c *TCPConn) sendNewDataSegment(sequence, acknowledgement uint32, flags byte, outOfOrderBytes int, payload []byte) error {
	return c.sendSegmentWithOptionsECN(sequence, acknowledgement, flags, outOfOrderBytes, nil, payload, true)
}

// sendSegmentWithOptions emits a segment with TCP options and the actor's
// current advertised window.
func (c *TCPConn) sendSegmentWithOptions(sequence, acknowledgement uint32, flags byte, outOfOrderBytes int, options, payload []byte) error {
	return c.sendSegmentWithOptionsECN(sequence, acknowledgement, flags, outOfOrderBytes, options, payload, false)
}

// sendSegmentWithOptionsECN emits a segment and marks only first-transmission
// data as ECN-capable.
func (c *TCPConn) sendSegmentWithOptionsECN(sequence, acknowledgement uint32, flags byte, outOfOrderBytes int, options, payload []byte, ecnCapable bool) error {
	if c.peerTimestamp {
		combined := make([]byte, 0, 12+len(options))
		combined = append(combined, tcpTimestampOptions(c.stack.tcpTimestamp(), c.recentTimestamp)...)
		combined = append(combined, options...)
		options = combined
	}
	if c.echoCongestion {
		flags |= tcpFlagECE
	}
	includeCWR := c.sendCWR && ecnCapable && len(payload) != 0
	if includeCWR {
		flags |= tcpFlagCWR
	}
	ecn := byte(0)
	if c.peerECN && ecnCapable && len(payload) != 0 {
		ecn = 2
	}
	err := c.stack.writeTCPWithECN(c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(), sequence, acknowledgement, flags, c.receiveWindow(outOfOrderBytes, c.peerWindowScaling), options, payload, c.mtu, ecn)
	if err == nil && includeCWR {
		c.sendCWR = false
	}
	return err
}

// rttEstimator implements the RFC 6298 smoothed RTT and variance calculation.
type rttEstimator struct {
	initialized bool
	srtt        time.Duration
	variation   time.Duration
	rto         time.Duration
}

// observe incorporates one non-retransmitted acknowledgement sample.
func (r *rttEstimator) observe(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if !r.initialized {
		r.srtt = sample
		r.variation = sample / 2
		r.initialized = true
	} else {
		difference := r.srtt - sample
		if difference < 0 {
			difference = -difference
		}
		r.variation = (3*r.variation + difference) / 4
		r.srtt = (7*r.srtt + sample) / 8
	}
	r.rto = r.srtt + 4*r.variation
	if r.rto < tcpMinimumRTO {
		r.rto = tcpMinimumRTO
	} else if r.rto > tcpMaximumRTO {
		r.rto = tcpMaximumRTO
	}
}

// backoff doubles RTO after a retransmission timeout.
func (r *rttEstimator) backoff() {
	r.rto *= 2
	if r.rto > tcpMaximumRTO {
		r.rto = tcpMaximumRTO
	}
}

// resetTimer safely replaces a timer deadline.
func resetTimer(timer *time.Timer, duration time.Duration) {
	stopTimer(timer)
	timer.Reset(duration)
}

// tcpMSSForMTU returns the largest transport payload fitting one IP packet.
func tcpMSSForMTU(mtu int, address netip.Addr) int {
	header := tcpHeaderSize + 40
	if address.Is4() {
		header = tcpHeaderSize + 20
	}
	maximum := mtu - header
	if maximum > 65535 {
		maximum = 65535
	}
	return maximum
}

// nextBlackHoleMTU selects the next conservative packet-size plateau after
// repeated retransmission timeouts without an ICMP Packet Too Big response.
func nextBlackHoleMTU(current int, ipv6 bool) int {
	if ipv6 {
		if current > ipv6MinimumMTU {
			return ipv6MinimumMTU
		}
		return current
	}
	for _, candidate := range [...]int{1500, 1280, 1006, 576, 296, 68} {
		if candidate < current {
			return candidate
		}
	}
	return current
}

// tcpTimeoutError preserves the last validated asynchronous network failure
// when TCP ultimately cannot recover it through retransmission.
func tcpTimeoutError(softError error) error {
	if softError != nil {
		return softError
	}
	return os.ErrDeadlineExceeded
}

// tcpSYNOptions advertises MSS, SACK, receive window scaling, and timestamps.
func tcpSYNOptions(mss int, timestamp uint32) []byte {
	return tcpPassiveSYNOptions(mss, true, true, true, timestamp, 0)
}

// tcpPassiveSYNOptions advertises only extensions offered by the initiating
// peer, while MSS is always present.
func tcpPassiveSYNOptions(mss int, sack, windowScaling, timestamp bool, timestampValue, timestampEcho uint32) []byte {
	options := []byte{2, 4, byte(mss >> 8), byte(mss)}
	if sack {
		options = append(options, 4, 2)
	}
	if windowScaling {
		options = append(options, 1, 3, 3, tcpReceiveWindowScale)
	}
	if timestamp {
		options = append(options, tcpTimestampOptions(timestampValue, timestampEcho)...)
	}
	return options
}

// parseTCPOptions extracts SYN options while ignoring unknown options.
func parseTCPOptions(options []byte, fallback, localMaximum int) (int, uint8, bool, bool, bool, uint32) {
	mss := fallback
	var scale uint8
	var windowScaling bool
	var sack bool
	var timestamp bool
	var timestampValue uint32
	for offset := 0; offset < len(options); {
		switch options[offset] {
		case 0:
			return clampMSS(mss, localMaximum), scale, windowScaling, sack, timestamp, timestampValue
		case 1:
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		switch options[offset] {
		case 2:
			if length == 4 {
				value := int(binary.BigEndian.Uint16(options[offset+2 : offset+4]))
				if value != 0 {
					mss = value
				}
			}
		case 3:
			if length == 3 {
				windowScaling = true
				scale = options[offset+2]
				if scale > 14 {
					scale = 14
				}
			}
		case 4:
			sack = length == 2
		case 8:
			if length == 10 {
				timestamp = true
				timestampValue = binary.BigEndian.Uint32(options[offset+2 : offset+6])
			}
		}
		offset += length
	}
	return clampMSS(mss, localMaximum), scale, windowScaling, sack, timestamp, timestampValue
}

// parseTCPTimestamp extracts one well-formed timestamp option.
func parseTCPTimestamp(options []byte) (uint32, uint32, bool) {
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == 0 {
			break
		}
		if kind == 1 {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		if kind == 8 && length == 10 {
			return binary.BigEndian.Uint32(options[offset+2 : offset+6]), binary.BigEndian.Uint32(options[offset+6 : offset+10]), true
		}
		offset += length
	}
	return 0, 0, false
}

// tcpTimestampOptions serializes TSval and the most recent peer TSval.
func tcpTimestampOptions(value, echo uint32) []byte {
	options := make([]byte, 12)
	options[0], options[1], options[2], options[3] = 1, 1, 8, 10
	binary.BigEndian.PutUint32(options[4:8], value)
	binary.BigEndian.PutUint32(options[8:12], echo)
	return options
}

// tcpSACKBlock is one half-open sequence range reported by a peer.
type tcpSACKBlock struct {
	left  uint32
	right uint32
}

// tcpSACKOptions reports up to four retained out-of-order ranges. The range
// containing the segment that triggered the ACK is placed first as required by
// RFC 2018.
func tcpSACKOptions(pieces []tcpReceivedPiece, recent uint32, maximumBlocks int) []byte {
	blocks := make([]tcpSACKBlock, 0, len(pieces))
	for _, piece := range pieces {
		right := piece.sequence + uint32(len(piece.payload))
		if piece.fin {
			right++
		}
		if right != piece.sequence {
			blocks = append(blocks, tcpSACKBlock{left: piece.sequence, right: right})
		}
	}
	if len(blocks) == 0 {
		return nil
	}
	recentIndex := -1
	for index, block := range blocks {
		if tcpSequenceGreaterEqual(recent, block.left) && tcpSequenceLess(recent, block.right) {
			recentIndex = index
			break
		}
	}
	if maximumBlocks < 1 {
		return nil
	}
	if maximumBlocks > 4 {
		maximumBlocks = 4
	}
	ordered := make([]tcpSACKBlock, 0, maximumBlocks)
	if recentIndex >= 0 {
		ordered = append(ordered, blocks[recentIndex])
	}
	for index := len(blocks) - 1; index >= 0 && len(ordered) < maximumBlocks; index-- {
		if index != recentIndex {
			ordered = append(ordered, blocks[index])
		}
	}
	options := make([]byte, 2+8*len(ordered))
	options[0], options[1] = 5, byte(len(options))
	for index, block := range ordered {
		offset := 2 + 8*index
		binary.BigEndian.PutUint32(options[offset:offset+4], block.left)
		binary.BigEndian.PutUint32(options[offset+4:offset+8], block.right)
	}
	return options
}

// parseTCPSACKOptions validates and merges SACK ranges within the current send
// window. DSACK ranges below the cumulative ACK are intentionally ignored.
func parseTCPSACKOptions(options []byte, acknowledged, sendNext uint32) []tcpSACKBlock {
	window := sendNext - acknowledged
	var blocks []tcpSACKBlock
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == 0 {
			break
		}
		if kind == 1 {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		if kind == 5 && length >= 10 && (length-2)%8 == 0 {
			for blockOffset := offset + 2; blockOffset < offset+length; blockOffset += 8 {
				left := binary.BigEndian.Uint32(options[blockOffset : blockOffset+4])
				right := binary.BigEndian.Uint32(options[blockOffset+4 : blockOffset+8])
				leftDistance, rightDistance := left-acknowledged, right-acknowledged
				if leftDistance < rightDistance && rightDistance <= window {
					blocks = append(blocks, tcpSACKBlock{left: left, right: right})
				}
			}
		}
		offset += length
	}
	sort.Slice(blocks, func(left, right int) bool { return blocks[left].left-acknowledged < blocks[right].left-acknowledged })
	merged := blocks[:0]
	for _, block := range blocks {
		if len(merged) == 0 || tcpSequenceLess(merged[len(merged)-1].right, block.left) {
			merged = append(merged, block)
			continue
		}
		if tcpSequenceGreater(block.right, merged[len(merged)-1].right) {
			merged[len(merged)-1].right = block.right
		}
	}
	return merged
}

// applyTCPSACK marks fully covered transmissions and returns the highest
// selectively acknowledged sequence plus the newest delivered send time.
func applyTCPSACK(outstanding []sentTCPSegment, blocks []tcpSACKBlock) (uint32, bool, time.Time) {
	var highest uint32
	var latest time.Time
	for blockIndex, block := range blocks {
		if blockIndex == 0 || tcpSequenceGreater(block.right, highest) {
			highest = block.right
		}
		for index := range outstanding {
			segment := &outstanding[index]
			if tcpSequenceGreaterEqual(segment.sequence, block.left) && tcpSequenceGreaterEqual(block.right, segment.end) {
				segment.sacked = true
				if segment.sentAt.After(latest) {
					latest = segment.sentAt
				}
			}
		}
	}
	return highest, len(blocks) != 0, latest
}

// firstUnsackedSegment returns the oldest known hole, falling back to the
// first segment when every segment is selectively acknowledged and the
// cumulative ACK may have been lost.
func firstUnsackedSegment(outstanding []sentTCPSegment) int {
	for index := range outstanding {
		if !outstanding[index].sacked {
			return index
		}
	}
	return 0
}

// lastUnsackedSegment returns the newest segment eligible for a tail-loss
// probe, falling back to the final segment when only a cumulative ACK is
// missing.
func lastUnsackedSegment(outstanding []sentTCPSegment) int {
	for index := len(outstanding) - 1; index >= 0; index-- {
		if !outstanding[index].sacked {
			return index
		}
	}
	return len(outstanding) - 1
}

// tailLossProbeDelay schedules one probe before the normal RTO after an RTT
// sample is available.
func tailLossProbeDelay(smoothedRTT, rto time.Duration) time.Duration {
	delay := 2 * smoothedRTT
	if smoothedRTT == 0 {
		delay = rto / 2
	}
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	if delay > rto {
		delay = rto
	}
	return delay
}

// firstUnretriedLoss returns the next RACK loss or, in full SACK recovery, the
// next hole below the highest selectively acknowledged sequence.
func firstUnretriedLoss(outstanding []sentTCPSegment, highest uint32, allSACKHoles bool) int {
	for index := range outstanding {
		segment := &outstanding[index]
		if !segment.sacked && !segment.sackRetried && (segment.rackLost || allSACKHoles && tcpSequenceLess(segment.sequence, highest)) {
			return index
		}
	}
	return -1
}

// outstandingBytes returns bytes currently counted in the congestion pipe.
func outstandingBytes(outstanding []sentTCPSegment, includeSACKed bool) uint32 {
	var bytes uint32
	for _, segment := range outstanding {
		if includeSACKed || !segment.sacked {
			bytes += segment.end - segment.sequence
		}
	}
	return bytes
}

// sackRecoveryPipe estimates bytes still consuming the congestion window.
// Confirmed RACK losses and, during full recovery, holes below the highest
// SACK edge leave the pipe until retransmitted.
func sackRecoveryPipe(outstanding []sentTCPSegment, highest uint32, allSACKHoles bool) uint32 {
	var bytes uint32
	for _, segment := range outstanding {
		if segment.sacked {
			continue
		}
		if (segment.rackLost || allSACKHoles && tcpSequenceLess(segment.sequence, highest)) && !segment.sackRetried {
			continue
		}
		bytes += segment.end - segment.sequence
	}
	return bytes
}

// rackReorderingWindow returns a conservative time allowance for legitimate
// packet reordering before RACK declares an older transmission lost.
func rackReorderingWindow(smoothedRTT time.Duration) time.Duration {
	window := smoothedRTT / 4
	if window < 10*time.Millisecond {
		window = 10 * time.Millisecond
	}
	if window > 200*time.Millisecond {
		window = 200 * time.Millisecond
	}
	return window
}

// markRACKLoss records transmissions sufficiently older than a newly
// delivered segment. SACKed and already retransmitted ranges are ignored.
func markRACKLoss(outstanding []sentTCPSegment, latest time.Time, reorderingWindow time.Duration) {
	if latest.IsZero() {
		return
	}
	for index := range outstanding {
		segment := &outstanding[index]
		if !segment.sacked && !segment.sackRetried && segment.sentAt.Add(reorderingWindow).Before(latest) {
			segment.rackLost = true
		}
	}
}

// hasRACKLoss reports whether the scoreboard contains a timed loss.
func hasRACKLoss(outstanding []sentTCPSegment) bool {
	for _, segment := range outstanding {
		if segment.rackLost && !segment.sackRetried {
			return true
		}
	}
	return false
}

// splitTCPSegments resegments unacknowledged payload after a PMTU reduction.
func splitTCPSegments(outstanding []sentTCPSegment, mss int) []sentTCPSegment {
	result := make([]sentTCPSegment, 0, len(outstanding))
	for _, segment := range outstanding {
		if len(segment.payload) <= mss {
			result = append(result, segment)
			continue
		}
		for offset := 0; offset < len(segment.payload); offset += mss {
			end := offset + mss
			if end > len(segment.payload) {
				end = len(segment.payload)
			}
			part := segment
			part.sequence = segment.sequence + uint32(offset)
			part.end = segment.sequence + uint32(end)
			part.payload = segment.payload[offset:end]
			if end != len(segment.payload) {
				part.flags &^= tcpFlagPSH | tcpFlagFIN
			}
			result = append(result, part)
		}
	}
	return result
}

// clampMSS applies local packet-size bounds to a peer MSS.
func clampMSS(value, maximum int) int {
	if value < 1 {
		value = 1
	}
	if value > maximum {
		value = maximum
	}
	return value
}

// defaultTCPPeerMSS returns the RFC default for a SYN without an MSS option.
func defaultTCPPeerMSS(address netip.Addr) int {
	if address.Is4() {
		return 536
	}
	return 1220
}

// initialTCPWindow applies the RFC 6928 byte and segment limits.
func initialTCPWindow(mss int) uint32 {
	window := 10 * mss
	minimum := 2 * mss
	if minimum < 14600 {
		minimum = 14600
	}
	if window > minimum {
		window = minimum
	}
	return uint32(window)
}

// growCongestionWindow adds delta without wrapping beyond TCP's maximum
// representable scaled receive window.
func growCongestionWindow(window, delta uint32) uint32 {
	if window >= tcpMaximumScaledWindow || delta >= tcpMaximumScaledWindow-window {
		return tcpMaximumScaledWindow
	}
	return window + delta
}

// receiveTCPData inserts one range and exposes all newly contiguous bytes.
func (c *TCPConn) receiveTCPData(sequence uint32, payload []byte, fin bool, receiveNext *uint32, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) (bool, bool) {
	finSequence := sequence + uint32(len(payload))
	if tcpSequenceLess(sequence, *receiveNext) {
		skip := *receiveNext - sequence
		if skip < uint32(len(payload)) {
			payload = payload[skip:]
			sequence = *receiveNext
		} else {
			payload = nil
			sequence = *receiveNext
			fin = fin && finSequence == *receiveNext
		}
	}
	if !c.storeTCPOutOfOrder(*receiveNext, sequence, payload, fin, outOfOrder, outOfOrderBytes) && tcpSequenceGreater(sequence, *receiveNext) {
		return false, false
	}
	delivered, remoteClosed := false, false
	for len(*outOfOrder) != 0 && !remoteClosed {
		piece := (*outOfOrder)[0]
		if tcpSequenceGreater(piece.sequence, *receiveNext) {
			break
		}
		*outOfOrder = (*outOfOrder)[1:]
		*outOfOrderBytes -= len(piece.payload)
		pieceFINSequence := piece.sequence + uint32(len(piece.payload))
		if tcpSequenceLess(piece.sequence, *receiveNext) {
			skip := *receiveNext - piece.sequence
			if skip < uint32(len(piece.payload)) {
				piece.payload = piece.payload[skip:]
				piece.sequence = *receiveNext
			} else {
				piece.payload = nil
				piece.sequence = *receiveNext
				piece.fin = piece.fin && pieceFINSequence == *receiveNext
			}
		}
		accepted := c.appendReadBuffer(piece.payload, *outOfOrderBytes)
		*receiveNext += uint32(accepted)
		delivered = delivered || accepted != 0
		if accepted != len(piece.payload) {
			remaining := append([]byte(nil), piece.payload[accepted:]...)
			*outOfOrder = append([]tcpReceivedPiece{{sequence: *receiveNext, payload: remaining, fin: piece.fin}}, *outOfOrder...)
			*outOfOrderBytes += len(remaining)
			break
		}
		if piece.fin {
			*receiveNext++
			remoteClosed = true
		}
	}
	if remoteClosed {
		*outOfOrder = nil
		*outOfOrderBytes = 0
	}
	return delivered || remoteClosed, remoteClosed
}

// tcpDataFragment is an uncovered portion of a newly received segment.
type tcpDataFragment struct {
	offset  uint32
	payload []byte
}

// storeTCPOutOfOrder retains only uncovered bytes within the receive window.
func (c *TCPConn) storeTCPOutOfOrder(receiveNext, sequence uint32, payload []byte, fin bool, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) bool {
	distance := sequence - receiveNext
	c.mu.Lock()
	available := c.receiveCapacity - len(c.readBuffer) - *outOfOrderBytes
	if c.userClosed || c.readClosed {
		available = c.receiveCapacity - *outOfOrderBytes
	}
	c.mu.Unlock()
	if available < 0 {
		available = 0
	}
	window := uint32(available)
	if distance >= window && !(distance == 0 && len(payload) == 0 && fin) {
		return false
	}
	originalPayloadSize := len(payload)
	if maximumPayload := int(window - distance); len(payload) > maximumPayload {
		payload = payload[:maximumPayload]
	}
	fin = fin && (distance == 0 && len(payload) == 0 || uint64(distance)+uint64(originalPayloadSize) < uint64(window))
	incomingFINSequence := sequence + uint32(originalPayloadSize)
	var existingFINSequence uint32
	hasExistingFIN := false
	for _, existing := range *outOfOrder {
		if existing.fin {
			existingFINSequence = existing.sequence + uint32(len(existing.payload))
			hasExistingFIN = true
			break
		}
	}
	if hasExistingFIN {
		fin = fin && incomingFINSequence == existingFINSequence
		payloadEnd := sequence + uint32(len(payload))
		if tcpSequenceGreater(payloadEnd, existingFINSequence) {
			if !tcpSequenceLess(sequence, existingFINSequence) {
				payload = nil
			} else {
				payload = payload[:existingFINSequence-sequence]
			}
		}
	}
	fragments := make([]tcpDataFragment, 0, 2)
	if len(payload) != 0 {
		fragments = append(fragments, tcpDataFragment{offset: distance, payload: payload})
	}
	for _, existing := range *outOfOrder {
		existingStart := existing.sequence - receiveNext
		existingEnd := existingStart + uint32(len(existing.payload))
		if existingStart == existingEnd {
			continue
		}
		next := make([]tcpDataFragment, 0, len(fragments)+1)
		for _, fragment := range fragments {
			fragmentEnd := fragment.offset + uint32(len(fragment.payload))
			if fragmentEnd <= existingStart || fragment.offset >= existingEnd {
				next = append(next, fragment)
				continue
			}
			if fragment.offset < existingStart {
				leftSize := existingStart - fragment.offset
				next = append(next, tcpDataFragment{offset: fragment.offset, payload: fragment.payload[:leftSize]})
			}
			if fragmentEnd > existingEnd {
				rightOffset := existingEnd - fragment.offset
				next = append(next, tcpDataFragment{offset: existingEnd, payload: fragment.payload[rightOffset:]})
			}
		}
		fragments = next
	}
	candidate := append([]tcpReceivedPiece(nil), (*outOfOrder)...)
	for _, fragment := range fragments {
		candidate = append(candidate, tcpReceivedPiece{sequence: receiveNext + fragment.offset, payload: append([]byte(nil), fragment.payload...)})
	}
	if fin && !hasExistingFIN {
		candidate = append(candidate, tcpReceivedPiece{sequence: incomingFINSequence, fin: true})
	}
	candidate = normalizeTCPReceivedPieces(receiveNext, candidate)
	bytes := 0
	for _, piece := range candidate {
		bytes += len(piece.payload)
	}
	if bytes > c.receiveCapacity || len(candidate) > tcpMaximumOutOfOrder {
		return false
	}
	*outOfOrder, *outOfOrderBytes = candidate, bytes
	return len(fragments) != 0 || fin
}

// normalizeTCPReceivedPieces sorts, merges, and truncates ranges at the first
// accepted FIN.
func normalizeTCPReceivedPieces(receiveNext uint32, pieces []tcpReceivedPiece) []tcpReceivedPiece {
	sort.SliceStable(pieces, func(left, right int) bool {
		leftOffset, rightOffset := pieces[left].sequence-receiveNext, pieces[right].sequence-receiveNext
		if leftOffset != rightOffset {
			return leftOffset < rightOffset
		}
		return len(pieces[left].payload) > len(pieces[right].payload)
	})
	var finOffset uint32
	hasFIN := false
	for _, piece := range pieces {
		if piece.fin {
			offset := piece.sequence - receiveNext + uint32(len(piece.payload))
			if !hasFIN || offset < finOffset {
				finOffset, hasFIN = offset, true
			}
		}
	}
	result := make([]tcpReceivedPiece, 0, len(pieces))
	for _, piece := range pieces {
		piece.fin = false
		pieceOffset := piece.sequence - receiveNext
		if hasFIN {
			if pieceOffset >= finOffset {
				continue
			}
			if pieceEnd := pieceOffset + uint32(len(piece.payload)); pieceEnd > finOffset {
				piece.payload = piece.payload[:finOffset-pieceOffset]
			}
		}
		if len(piece.payload) == 0 {
			continue
		}
		if len(result) == 0 {
			result = append(result, piece)
			continue
		}
		previous := &result[len(result)-1]
		previousEnd := previous.sequence + uint32(len(previous.payload))
		if previousEnd == piece.sequence {
			previous.payload = append(previous.payload, piece.payload...)
		} else if tcpSequenceGreater(previousEnd, piece.sequence) {
			skip := previousEnd - piece.sequence
			if skip < uint32(len(piece.payload)) {
				previous.payload = append(previous.payload, piece.payload[skip:]...)
			}
		} else {
			result = append(result, piece)
		}
	}
	if hasFIN {
		finSequence := receiveNext + finOffset
		if len(result) != 0 {
			last := &result[len(result)-1]
			if last.sequence+uint32(len(last.payload)) == finSequence {
				last.fin = true
				return result
			}
		}
		result = append(result, tcpReceivedPiece{sequence: finSequence, fin: true})
	}
	return result
}

// tcpSequenceLess compares sequence numbers modulo 2^32.
func tcpSequenceLess(left, right uint32) bool { return int32(left-right) < 0 }

// tcpSequenceGreater compares sequence numbers modulo 2^32.
func tcpSequenceGreater(left, right uint32) bool { return tcpSequenceLess(right, left) }

// tcpSequenceLessEqual compares sequence numbers modulo 2^32.
func tcpSequenceLessEqual(left, right uint32) bool { return !tcpSequenceGreater(left, right) }

// tcpSequenceGreaterEqual compares sequence numbers modulo 2^32.
func tcpSequenceGreaterEqual(left, right uint32) bool { return !tcpSequenceLess(left, right) }

// tcpSegmentAcceptable implements the RFC 9293 receive-window tests for a
// segment's first and last sequence numbers.
func tcpSegmentAcceptable(sequence, length, receiveNext, receiveWindow uint32) bool {
	if receiveWindow == 0 {
		return length == 0 && sequence == receiveNext
	}
	if sequence-receiveNext < receiveWindow {
		return true
	}
	return length != 0 && sequence+length-1-receiveNext < receiveWindow
}

// tcpWindowUpdateAllowed implements the RFC 9293 SND.WL1/SND.WL2 ordering
// rule so reordered ACKs cannot restore a stale advertised send window.
func tcpWindowUpdateAllowed(sequence, acknowledgement, lastSequence, lastAcknowledgement uint32) bool {
	return tcpSequenceGreater(sequence, lastSequence) ||
		sequence == lastSequence && tcpSequenceGreaterEqual(acknowledgement, lastAcknowledgement)
}

// Verify that TCPConn implements net.Conn.
var _ net.Conn = (*TCPConn)(nil)

// Verify the additional standard TCPConn interfaces.
var _ io.ReaderFrom = (*TCPConn)(nil)
var _ io.WriterTo = (*TCPConn)(nil)
