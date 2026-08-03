// Package mipstack implements the mihomo IP stack (MIPS), a small userspace
// IPv4/IPv6 endpoint stack for applications that exchange complete packets
// with an L3 link. It implements active and passive TCP, connected and
// unconnected UDP and IP protocol sockets, and the ICMP behavior required by
// those transports.
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// dynamicPortFirst is the first IANA dynamic client port.
	dynamicPortFirst = 49152
	// dynamicPortCount is the size of the IANA dynamic port range.
	dynamicPortCount = 1 << 14
	// fallbackPortFirst keeps well-known ports out of automatic allocation.
	fallbackPortFirst = 1024
	// fallbackPortCount is used only after the IANA dynamic range is exhausted.
	fallbackPortCount = dynamicPortFirst - fallbackPortFirst
	// defaultMTU matches the conventional Ethernet payload MTU.
	defaultMTU = 1500
	// ipv6MinimumMTU is both the minimum configured IPv6 link MTU and the
	// maximum complete ICMPv6 error size required by RFC 4443.
	ipv6MinimumMTU = 1280
	// outboundPacketQueue bounds packets waiting for the embedding link.
	outboundPacketQueue = 256
	// loopbackPacketQueue bounds asynchronous local delivery and prevents a
	// socket actor from recursively entering its own protocol handler.
	loopbackPacketQueue = 256
	// pathMTUMaximumEntries bounds destinations learned from authenticated
	// transport tuples so long-running proxy workloads cannot grow the cache
	// without limit.
	pathMTUMaximumEntries = 1024
	// pathMTULifetime eventually retries the controller-provided link MTU after
	// a transient lower-path constraint disappears.
	pathMTULifetime = 10 * time.Minute
	// controlResponseRate is the sustained number of unsolicited control
	// responses permitted per class and second.
	controlResponseRate = 100
	// controlResponseBurst permits short diagnostic bursts without allowing a
	// packet flood to monopolize the outbound queue.
	controlResponseBurst = 200
)

var (
	// ErrClosed is returned after the stack has been closed.
	ErrClosed = net.ErrClosed
	// ErrNotStarted is returned when packet or socket I/O is attempted before
	// Start.
	ErrNotStarted = errors.New("mipstack: stack is not started")
	// ErrNoPorts reports exhaustion of all automatically allocated,
	// non-privileged ports.
	ErrNoPorts = errors.New("mipstack: no automatic ports available")
	// ErrResourceLimit reports exhaustion of a bounded in-memory socket or
	// protocol resource.
	ErrResourceLimit = errors.New("mipstack: resource limit reached")
)

// Config configures a Stack.
type Config struct {
	// LocalAddresses lists addresses that may receive packets and be selected
	// as transport endpoints.
	LocalAddresses []netip.Prefix
	// MTU bounds packets emitted by Read. Zero selects 1500.
	MTU uint32
	// Routes optionally restrict admitted unicast destinations and provide a
	// preferred source. Nil installs one default route per configured address
	// family; a non-nil empty slice installs no routes.
	Routes []Route
	// MaxTCPConnections optionally bounds active, handshaking, and TIME_WAIT
	// connections. Zero leaves the number unbounded; per-listener queues and
	// per-connection buffers remain independently bounded.
	MaxTCPConnections int
	// CongestionControl selects the TCP congestion-control algorithm. The zero
	// value selects CUBIC.
	CongestionControl CongestionControl
}

// Stack converts raw IPv4/IPv6 packets to application TCP, UDP, and IP
// protocol sockets.
type Stack struct {
	network  atomic.Pointer[networkState]
	outbound chan []byte
	loopback chan []byte

	mu         sync.RWMutex
	started    bool
	closed     bool
	tcp        map[tcpKey]*TCPConn
	tcpPassive tcpPassiveEndpoints
	udp        map[udpKey]*UDPConn
	udpReuse   udpReuseEndpoints
	ip         ipEndpoints
	nextPort   [2]automaticPortCursor

	pathMTUMu sync.RWMutex
	pathMTU   map[netip.Addr]pathMTUEntry

	packetID       atomic.Uint32
	closeCh        chan struct{}
	timestampEpoch time.Time

	fragmentMu    sync.Mutex
	fragments     map[fragmentKey]*fragmentSet
	fragmentBytes int

	controlMu       sync.Mutex
	controlLimiters [controlResponseClassCount]tokenBucket
	stats           stackCounters
}

// StackStats is a point-in-time snapshot of stack activity. Counters are
// monotonic except ActiveTCPConnections, ActiveTCPListeners,
// ActiveUDPSockets, and ActiveIPSockets.
type StackStats struct {
	// InboundPackets counts complete packets presented to the stack.
	InboundPackets uint64
	// InboundDroppedPackets counts invalid packets and bounded-queue drops.
	InboundDroppedPackets uint64
	// OutboundPackets counts complete packets accepted by the device queue.
	OutboundPackets uint64
	// LoopbackPackets counts locally routed packets that bypassed the link.
	LoopbackPackets uint64
	// ActiveTCPConnections includes handshakes, established flows, and
	// TIME_WAIT actors.
	ActiveTCPConnections uint64
	// ActiveTCPListeners is the current number of passive TCP endpoints.
	ActiveTCPListeners uint64
	// ActiveUDPSockets is the current number of open packet sockets.
	ActiveUDPSockets uint64
	// ActiveIPSockets is the current number of open protocol sockets.
	ActiveIPSockets uint64
	// TCPRetransmissions counts all SYN, data, FIN, SACK, RACK, and tail-probe
	// retransmissions.
	TCPRetransmissions uint64
	// TCPSACKRetransmissions counts retransmissions selected by the SACK
	// scoreboard, including its RACK-confirmed subset.
	TCPSACKRetransmissions uint64
	// TCPRACKRetransmissions counts the time-based subset of SACK recovery.
	TCPRACKRetransmissions uint64
	// TCPTailLossProbes counts probes sent before the ordinary RTO.
	TCPTailLossProbes uint64
	// TCPZeroWindowProbes counts persist probes sent while the peer advertises
	// a closed receive window.
	TCPZeroWindowProbes uint64
	// TCPKeepAliveProbes counts probes sent after configured receive inactivity.
	TCPKeepAliveProbes uint64
	// PathMTUUpdates counts accepted destination PMTU reductions.
	PathMTUUpdates uint64
	// PathMTUBlackHoleReductions counts PMTU reductions inferred from repeated
	// TCP timeouts rather than ICMP.
	PathMTUBlackHoleReductions uint64
	// FragmentEvictions counts incomplete datagrams removed for capacity.
	FragmentEvictions uint64
	// FragmentTimeouts counts incomplete datagrams removed for age.
	FragmentTimeouts uint64
	// RateLimitedControlResponses counts suppressed TCP RST and challenge ACK,
	// ICMP unreachable, parameter-problem, and ICMP echo replies.
	RateLimitedControlResponses uint64
}

// stackCounters stores concurrently updated statistics.
type stackCounters struct {
	inboundPackets              atomic.Uint64
	inboundDroppedPackets       atomic.Uint64
	outboundPackets             atomic.Uint64
	loopbackPackets             atomic.Uint64
	activeTCPConnections        atomic.Uint64
	activeTCPListeners          atomic.Uint64
	activeUDPSockets            atomic.Uint64
	activeIPSockets             atomic.Uint64
	tcpRetransmissions          atomic.Uint64
	tcpSACKRetransmissions      atomic.Uint64
	tcpRACKRetransmissions      atomic.Uint64
	tcpTailLossProbes           atomic.Uint64
	tcpZeroWindowProbes         atomic.Uint64
	tcpKeepAliveProbes          atomic.Uint64
	pathMTUUpdates              atomic.Uint64
	pathMTUBlackHoleReductions  atomic.Uint64
	fragmentEvictions           atomic.Uint64
	fragmentTimeouts            atomic.Uint64
	rateLimitedControlResponses atomic.Uint64
}

// controlResponseClass separates independent control-plane token buckets.
type controlResponseClass uint8

const (
	// controlResponseTCPReset limits resets for unbound TCP tuples.
	controlResponseTCPReset controlResponseClass = iota
	// controlResponseTCPChallengeACK limits RFC 5961 acknowledgements for
	// suspicious segments on established tuples.
	controlResponseTCPChallengeACK
	// controlResponsePortUnreachable limits ICMP errors for unbound UDP ports.
	controlResponsePortUnreachable
	// controlResponseEchoReply limits ICMP echo replies.
	controlResponseEchoReply
	// controlResponseParameterProblem limits errors for unsupported IPv6
	// options and upper-layer protocols.
	controlResponseParameterProblem
	// controlResponseClassCount is the number of independent token buckets.
	controlResponseClassCount
)

// tokenBucket is one lock-protected control-response limiter.
type tokenBucket struct {
	tokens  float64
	updated time.Time
}

// pathMTUEntry is one learned destination MTU and its last confirmation.
type pathMTUEntry struct {
	mtu     int
	updated time.Time
}

// udpKey identifies one specific or wildcard local UDP endpoint.
type udpKey struct {
	address netip.Addr
	port    uint16
}

// tcpKey is the four-tuple used to dispatch inbound TCP segments.
type tcpKey struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

// automaticPortCursor remembers the next randomized position in the primary
// IANA range and its lower, non-privileged fallback range.
type automaticPortCursor struct {
	dynamic  uint16
	fallback uint16
}

// New constructs an inactive-socket stack.
func New(config Config) (*Stack, error) {
	state, err := buildNetworkState(config)
	if err != nil {
		return nil, err
	}
	ports4, err := randomAutomaticPortCursor()
	if err != nil {
		return nil, err
	}
	ports6, err := randomAutomaticPortCursor()
	if err != nil {
		return nil, err
	}
	stack := &Stack{
		outbound: make(chan []byte, outboundPacketQueue), loopback: make(chan []byte, loopbackPacketQueue),
		tcp: make(map[tcpKey]*TCPConn), udp: make(map[udpKey]*UDPConn),
		nextPort: [2]automaticPortCursor{ports4, ports6}, pathMTU: make(map[netip.Addr]pathMTUEntry),
		closeCh: make(chan struct{}), timestampEpoch: time.Now(), fragments: make(map[fragmentKey]*fragmentSet),
	}
	stack.network.Store(state)
	return stack, nil
}

// UpdateConfig atomically replaces addresses, routes, the link MTU, congestion
// control, and the optional TCP connection limit.
// Sockets bound to removed addresses or destinations without a remaining
// route are closed. Other TCP connections immediately reclamp their MSS.
func (s *Stack) UpdateConfig(config Config) error {
	state, err := buildNetworkState(config)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	previous := s.network.Swap(state)
	if previous == nil || previous.mtu != state.mtu {
		s.pathMTUMu.Lock()
		s.pathMTU = make(map[netip.Addr]pathMTUEntry)
		s.pathMTUMu.Unlock()
	}
	tcpConnections := make([]*TCPConn, 0, len(s.tcp))
	for _, connection := range s.tcp {
		tcpConnections = append(tcpConnections, connection)
	}
	tcpPassive := s.tcpPassive
	udpConnections := s.udpConnectionsLocked()
	ip := s.ip
	s.mu.Unlock()
	if tcpPassive != nil {
		tcpPassive.updateConfig(s, state)
	}
	for _, connection := range tcpConnections {
		_, routed := state.routeFor(connection.key.remote.Addr())
		if !networkStateHasLocal(state, connection.key.local.Addr()) {
			connection.abortWithoutReset(syscall.EADDRNOTAVAIL)
			continue
		}
		if !routed {
			connection.abortWithoutReset(syscall.ENETUNREACH)
			continue
		}
		select {
		case connection.pathMTUUpdate <- struct{}{}:
		default:
		}
	}
	for _, connection := range udpConnections {
		if connection.dual && !networkStateHasFamily(state, false) && !networkStateHasFamily(state, true) ||
			!connection.dual && connection.local.IsUnspecified() && !networkStateHasFamily(state, connection.v6) ||
			connection.local.IsValid() && !connection.local.IsUnspecified() && !networkStateHasLocal(state, connection.local) {
			s.closeUDP(connection)
			continue
		}
		if connection.remote.IsValid() {
			if _, routed := state.routeFor(connection.remote.Addr()); !routed {
				s.closeUDP(connection)
			}
		}
	}
	if ip != nil {
		ip.updateConfig(s, state)
	}
	return nil
}

// LocalAddresses returns an independent snapshot of all configured local
// addresses in configuration order.
func (s *Stack) LocalAddresses() []netip.Addr {
	return append([]netip.Addr(nil), s.network.Load().sources...)
}

// RouteFor returns the selected route for one unicast destination.
func (s *Stack) RouteFor(destination netip.Addr) (Route, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || destination.IsUnspecified() || destination.IsMulticast() || destination.Zone() != "" {
		return Route{}, syscall.EINVAL
	}
	route, exists := s.network.Load().routeFor(destination)
	if !exists {
		return Route{}, syscall.ENETUNREACH
	}
	return route, nil
}

// networkStateHasLocal reports membership in an immutable configuration.
func networkStateHasLocal(state *networkState, address netip.Addr) bool {
	_, exists := state.local[address.Unmap()]
	return exists
}

// networkStateHasFamily reports whether one configured source belongs to the
// requested address family.
func networkStateHasFamily(state *networkState, v6 bool) bool {
	for _, source := range state.sources {
		if source.Is6() == v6 {
			return true
		}
	}
	return false
}

// listenAddress validates a listen network and canonicalizes a generic
// wildcard to the same dual-stack IPv6 representation used by net.Listen.
func listenAddress(state *networkState, network, protocol string, address netip.Addr) (netip.Addr, bool, error) {
	if err := validateListenNetwork(network, protocol, address); err != nil {
		return netip.Addr{}, false, err
	}
	switch network {
	case protocol + "4":
		if !networkStateHasFamily(state, false) {
			return netip.Addr{}, false, syscall.EADDRNOTAVAIL
		}
		if !address.IsValid() {
			address = netip.IPv4Unspecified()
		}
		return address, false, nil
	case protocol + "6":
		if !networkStateHasFamily(state, true) {
			return netip.Addr{}, false, syscall.EADDRNOTAVAIL
		}
		if !address.IsValid() {
			address = netip.IPv6Unspecified()
		}
		return address, false, nil
	case protocol:
	}
	if address.IsValid() && !address.IsUnspecified() {
		return address, false, nil
	}
	have4 := networkStateHasFamily(state, false)
	have6 := networkStateHasFamily(state, true)
	if have6 {
		return netip.IPv6Unspecified(), have4, nil
	}
	if have4 {
		return netip.IPv4Unspecified(), false, nil
	}
	return netip.Addr{}, false, syscall.EADDRNOTAVAIL
}

// validateListenNetwork checks a listener's protocol name and an explicitly
// supplied address family before stack lifecycle or binding errors.
func validateListenNetwork(network, protocol string, address netip.Addr) error {
	switch network {
	case protocol:
		return nil
	case protocol + "4":
		if address.IsValid() && address.Is6() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	case protocol + "6":
		if address.IsValid() && address.Is4() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	default:
		return net.UnknownNetworkError(network)
	}
}

// mtuFor returns the unexpired destination PMTU, or the managed link MTU.
func (s *Stack) mtuFor(destination netip.Addr) int {
	destination = destination.Unmap()
	linkMTU := s.network.Load().mtu
	now := time.Now()
	s.pathMTUMu.RLock()
	entry, exists := s.pathMTU[destination]
	s.pathMTUMu.RUnlock()
	if exists && now.Sub(entry.updated) < pathMTULifetime && entry.mtu < linkMTU {
		return entry.mtu
	}
	if exists && now.Sub(entry.updated) >= pathMTULifetime {
		s.pathMTUMu.Lock()
		current, currentExists := s.pathMTU[destination]
		if currentExists && now.Sub(current.updated) >= pathMTULifetime {
			delete(s.pathMTU, destination)
		}
		s.pathMTUMu.Unlock()
	}
	return linkMTU
}

// pathMTUExpiry returns the time at which a destination PMTU should be probed
// upward. A past expiry remains actionable so a connection that raced cache
// expiry while starting is woken immediately; mtuFor then removes the entry.
func (s *Stack) pathMTUExpiry(destination netip.Addr) (time.Time, bool) {
	destination = destination.Unmap()
	linkMTU := s.network.Load().mtu
	s.pathMTUMu.RLock()
	entry, exists := s.pathMTU[destination]
	s.pathMTUMu.RUnlock()
	if !exists || entry.mtu >= linkMTU {
		return time.Time{}, false
	}
	return entry.updated.Add(pathMTULifetime), true
}

// notifyTCPPathMTU wakes all established and handshaking flows to one
// destination except an optional actor that is already applying the change.
// The PMTU lock is never held while acquiring the socket registry lock.
func (s *Stack) notifyTCPPathMTU(destination netip.Addr, except *TCPConn) {
	destination = destination.Unmap()
	s.mu.RLock()
	for key, connection := range s.tcp {
		if connection == nil || connection == except || key.remote.Addr() != destination {
			continue
		}
		select {
		case connection.pathMTUUpdate <- struct{}{}:
		default:
		}
	}
	s.mu.RUnlock()
}

// observePathMTU records a validated ICMP next-hop MTU reduction.
func (s *Stack) observePathMTU(destination netip.Addr, mtu uint32) bool {
	destination = destination.Unmap()
	minimum := uint32(68)
	if destination.Is6() {
		minimum = 1280
	}
	if !destination.IsValid() || mtu == 0 {
		return false
	}
	if mtu < minimum {
		mtu = minimum
	}
	if mtu >= uint32(s.network.Load().mtu) {
		return false
	}
	now := time.Now()
	s.pathMTUMu.Lock()
	defer s.pathMTUMu.Unlock()
	current, exists := s.pathMTU[destination]
	if exists && current.mtu <= int(mtu) && now.Sub(current.updated) < pathMTULifetime {
		current.updated = now
		s.pathMTU[destination] = current
		return false
	}
	if !exists && len(s.pathMTU) >= pathMTUMaximumEntries {
		var oldestAddress netip.Addr
		var oldest pathMTUEntry
		for address, entry := range s.pathMTU {
			if !oldestAddress.IsValid() || entry.updated.Before(oldest.updated) {
				oldestAddress, oldest = address, entry
			}
		}
		delete(s.pathMTU, oldestAddress)
	}
	s.pathMTU[destination] = pathMTUEntry{mtu: int(mtu), updated: now}
	s.stats.pathMTUUpdates.Add(1)
	return true
}

// Stats returns a consistent-enough lock-free snapshot of stack counters.
// Concurrent activity may become visible across adjacent fields at slightly
// different instants.
func (s *Stack) Stats() StackStats {
	return StackStats{
		InboundPackets:              s.stats.inboundPackets.Load(),
		InboundDroppedPackets:       s.stats.inboundDroppedPackets.Load(),
		OutboundPackets:             s.stats.outboundPackets.Load(),
		LoopbackPackets:             s.stats.loopbackPackets.Load(),
		ActiveTCPConnections:        s.stats.activeTCPConnections.Load(),
		ActiveTCPListeners:          s.stats.activeTCPListeners.Load(),
		ActiveUDPSockets:            s.stats.activeUDPSockets.Load(),
		ActiveIPSockets:             s.stats.activeIPSockets.Load(),
		TCPRetransmissions:          s.stats.tcpRetransmissions.Load(),
		TCPSACKRetransmissions:      s.stats.tcpSACKRetransmissions.Load(),
		TCPRACKRetransmissions:      s.stats.tcpRACKRetransmissions.Load(),
		TCPTailLossProbes:           s.stats.tcpTailLossProbes.Load(),
		TCPZeroWindowProbes:         s.stats.tcpZeroWindowProbes.Load(),
		TCPKeepAliveProbes:          s.stats.tcpKeepAliveProbes.Load(),
		PathMTUUpdates:              s.stats.pathMTUUpdates.Load(),
		PathMTUBlackHoleReductions:  s.stats.pathMTUBlackHoleReductions.Load(),
		FragmentEvictions:           s.stats.fragmentEvictions.Load(),
		FragmentTimeouts:            s.stats.fragmentTimeouts.Load(),
		RateLimitedControlResponses: s.stats.rateLimitedControlResponses.Load(),
	}
}

// allowControlResponse consumes one token from a control-response class.
func (s *Stack) allowControlResponse(class controlResponseClass) bool {
	now := time.Now()
	s.controlMu.Lock()
	bucket := &s.controlLimiters[class]
	if bucket.updated.IsZero() {
		bucket.tokens = controlResponseBurst
	} else {
		bucket.tokens += now.Sub(bucket.updated).Seconds() * controlResponseRate
		if bucket.tokens > controlResponseBurst {
			bucket.tokens = controlResponseBurst
		}
	}
	bucket.updated = now
	allowed := bucket.tokens >= 1
	if allowed {
		bucket.tokens--
	}
	s.controlMu.Unlock()
	if !allowed {
		s.stats.rateLimitedControlResponses.Add(1)
	}
	return allowed
}

// Start activates packet and socket I/O and starts background maintenance.
// Repeated calls do not start additional workers.
func (s *Stack) Start() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.mu.Unlock()
	go s.runFragmentCleaner()
	go s.runLoopback()
	return nil
}

// runLoopback serializes local delivery outside the sending socket actor.
func (s *Stack) runLoopback() {
	for {
		select {
		case packet := <-s.loopback:
			_ = s.handlePacket(packet)
		case <-s.closeCh:
			return
		}
	}
}

// ready reports whether the stack has started and has not closed.
func (s *Stack) ready() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	if !s.started {
		return ErrNotStarted
	}
	return nil
}

// sourceFor selects a local address in the destination's family. An address
// whose configured prefix contains the destination wins by longest prefix;
// otherwise the first address in that family is used as the default-route
// source.
func (s *Stack) sourceFor(destination netip.Addr) (netip.Addr, error) {
	return s.network.Load().sourceFor(destination, netip.Addr{})
}

// sourceForRequested validates an explicit source or selects one automatically.
func (s *Stack) sourceForRequested(destination, requested netip.Addr) (netip.Addr, error) {
	return s.network.Load().sourceFor(destination, requested)
}

// randomPortOffset randomizes the first candidate in one automatic range.
func randomPortOffset(count uint32) (uint16, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return uint16(binary.BigEndian.Uint32(raw[:]) % count), nil
}

// randomAutomaticPortCursor independently randomizes both allocation ranges.
func randomAutomaticPortCursor() (automaticPortCursor, error) {
	dynamic, err := randomPortOffset(dynamicPortCount)
	if err != nil {
		return automaticPortCursor{}, err
	}
	fallback, err := randomPortOffset(fallbackPortCount)
	if err != nil {
		return automaticPortCursor{}, err
	}
	return automaticPortCursor{dynamic: dynamic, fallback: fallback}, nil
}

// allocateAutomaticPort selects an available IANA dynamic port first, then
// falls back to the lower non-privileged range only after a complete scan.
func allocateAutomaticPort(cursor *automaticPortCursor, available func(uint16) bool) (uint16, error) {
	ranges := [...]struct {
		first  uint32
		count  uint32
		cursor *uint16
	}{
		{dynamicPortFirst, dynamicPortCount, &cursor.dynamic},
		{fallbackPortFirst, fallbackPortCount, &cursor.fallback},
	}
	for _, portRange := range ranges {
		start := uint32(*portRange.cursor)
		for offset := uint32(0); offset < portRange.count; offset++ {
			position := (start + offset) % portRange.count
			port := uint16(portRange.first + position)
			if !available(port) {
				continue
			}
			*portRange.cursor = uint16((position + 1) % portRange.count)
			return port, nil
		}
	}
	return 0, ErrNoPorts
}

// isLocal reports whether address belongs to this stack.
func (s *Stack) isLocal(address netip.Addr) bool {
	return networkStateHasLocal(s.network.Load(), address)
}

// allocateUDPPortLocked reserves one collision-free automatic local endpoint
// while s.mu is held.
func (s *Stack) allocateUDPPortLocked(binding udpSocketBinding, address netip.Addr, dual bool) (uint16, error) {
	index := 0
	if address.Is6() {
		index = 1
	}
	return allocateAutomaticPort(&s.nextPort[index], func(port uint16) bool {
		return s.udpEndpointAvailableLocked(binding, address, port, dual)
	})
}

// udpEndpointAvailableLocked reports whether address and port can be bound
// without overlapping a wildcard or exact endpoint while s.mu is held.
func (s *Stack) udpEndpointAvailableLocked(binding udpSocketBinding, address netip.Addr, port uint16, dual bool) bool {
	if !binding.available(s, address, port, dual) {
		return false
	}
	for key, connection := range s.udp {
		if key.port == port && listenAddressesOverlap(key.address, connection.dual, address, dual) {
			return false
		}
	}
	return true
}

// listenAddressesOverlap reports whether two single-interface bindings cover
// at least one common local address family and address.
func listenAddressesOverlap(left netip.Addr, leftDual bool, right netip.Addr, rightDual bool) bool {
	if leftDual || rightDual {
		if left.IsUnspecified() && right.IsUnspecified() {
			return true
		}
		if leftDual && right.Is4() || rightDual && left.Is4() {
			return true
		}
	}
	return left.Is6() == right.Is6() && (left.IsUnspecified() || right.IsUnspecified() || left == right)
}

// allocateTCPPortLocked selects a local port whose complete four-tuple is not
// active or in TIME_WAIT while s.mu is held.
func (s *Stack) allocateTCPPortLocked(local netip.Addr, remote netip.AddrPort) (uint16, error) {
	index := 0
	if remote.Addr().Is6() {
		index = 1
	}
	return allocateAutomaticPort(&s.nextPort[index], func(port uint16) bool {
		if s.tcpPortListenedLocked(local, port) {
			return false
		}
		key := tcpKey{local: netip.AddrPortFrom(local, port), remote: remote}
		if _, exists := s.tcp[key]; exists {
			return false
		}
		return true
	})
}

// tcpPortListenedLocked reports whether a wildcard or exact listener owns a
// local TCP endpoint while s.mu is held.
func (s *Stack) tcpPortListenedLocked(local netip.Addr, port uint16) bool {
	return s.tcpPassive != nil && s.tcpPassive.portListened(local, port)
}

// ListenUDP binds an unconnected UDP packet socket. Network must be udp, udp4,
// or udp6. A wildcard with udp uses one dual-stack endpoint when both families
// are configured. Port zero selects an automatic port.
func (s *Stack) ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error) {
	return s.listenUDP(ctx, network, local, exclusiveUDPSocketBinding{})
}

// listenUDP contains validation, automatic port allocation, and socket
// construction shared by the ordinary and optional REUSEPORT entry points.
func (s *Stack) listenUDP(ctx context.Context, network string, local netip.AddrPort, binding udpSocketBinding) (net.PacketConn, error) {
	address := local.Addr().Unmap()
	local = netip.AddrPortFrom(address, local.Port())
	target := udpNetAddr(local)
	wrap := func(err error) (net.PacketConn, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	if err := validateListenNetwork(network, "udp", address); err != nil {
		return wrap(err)
	}
	if address.IsValid() && (address.IsMulticast() || address.Zone() != "") {
		return wrap(errors.New("mipstack: invalid UDP listen address"))
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
	address, dual, err := listenAddress(state, network, "udp", address)
	if err != nil {
		return wrap(err)
	}
	if !address.IsUnspecified() && !networkStateHasLocal(state, address) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	local = netip.AddrPortFrom(address, local.Port())
	port := local.Port()
	if port == 0 {
		port, err = s.allocateUDPPortLocked(binding, address, dual)
		if err != nil {
			return wrap(err)
		}
	} else if !s.udpEndpointAvailableLocked(binding, address, port, dual) {
		return wrap(syscall.EADDRINUSE)
	}
	connection := newUDPConn(s, network, port, address.Is6(), address, netip.AddrPort{})
	connection.dual = dual
	if err = binding.register(s, connection); err != nil {
		return wrap(err)
	}
	s.stats.activeUDPSockets.Add(1)
	return connection, nil
}

// DialUDP creates a connected UDP socket for one IPv4 or IPv6 remote endpoint.
// Network must be udp, udp4, or udp6. A zero source selects both address and
// port automatically; an unspecified source address selects only the address.
func (s *Stack) DialUDP(ctx context.Context, network string, source, remote netip.AddrPort) (net.Conn, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	target := udpNetAddr(remote)
	wrap := func(source net.Addr, err error) (net.Conn, error) {
		return nil, socketOperationError("dial", network, source, target, err)
	}
	if err := validateTransportNetwork(network, "udp", remote.Addr()); err != nil {
		return wrap(nil, err)
	}
	if !remote.IsValid() || remote.Port() == 0 || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Zone() != "" {
		return wrap(nil, errors.New("mipstack: invalid UDP destination"))
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	if err := s.ready(); err != nil {
		return wrap(nil, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wrap(nil, ErrClosed)
	}
	local, err := s.localEndpointFor(network, remote, source)
	if err != nil {
		return wrap(nil, err)
	}
	localAddress := net.UDPAddrFromAddrPort(local)
	port := local.Port()
	if port == 0 {
		port, err = s.allocateUDPPortLocked(exclusiveUDPSocketBinding{}, local.Addr(), false)
		if err != nil {
			return wrap(localAddress, err)
		}
	} else if !s.udpEndpointAvailableLocked(exclusiveUDPSocketBinding{}, local.Addr(), port, false) {
		return wrap(localAddress, syscall.EADDRINUSE)
	}
	local = netip.AddrPortFrom(local.Addr(), port)
	connection := newUDPConn(s, network, port, remote.Addr().Is6(), local.Addr(), remote)
	s.udp[udpKey{address: local.Addr(), port: port}] = connection
	s.stats.activeUDPSockets.Add(1)
	return connection, nil
}

// validateTransportNetwork accepts the network names used by the net package's
// netip-based DialTCP and DialUDP methods and enforces an explicit IP family.
func validateTransportNetwork(network, protocol string, remote netip.Addr) error {
	switch network {
	case protocol:
		return nil
	case protocol + "4":
		if remote.IsValid() && remote.Is6() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	case protocol + "6":
		if remote.IsValid() && remote.Is4() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	default:
		return net.UnknownNetworkError(network)
	}
}

// localEndpointFor resolves and validates the local side of an active socket.
func (s *Stack) localEndpointFor(network string, remote, requested netip.AddrPort) (netip.AddrPort, error) {
	requestedAddress := requested.Addr()
	if requestedAddress.IsValid() {
		requestedAddress = requestedAddress.Unmap()
		if requestedAddress.Zone() != "" || requestedAddress.IsMulticast() {
			return netip.AddrPort{}, syscall.EINVAL
		}
		if requestedAddress.Is6() != remote.Addr().Is6() && (!requestedAddress.IsUnspecified() || network[len(network)-1] == '4' || network[len(network)-1] == '6') {
			family := "IPv6"
			if remote.Addr().Is4() {
				family = "IPv4"
			}
			return netip.AddrPort{}, &net.AddrError{Err: "non-" + family + " address", Addr: requestedAddress.String()}
		}
	}
	address, err := s.sourceForRequested(remote.Addr(), requestedAddress)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(address, requested.Port()), nil
}

// udpNetAddr returns a standard UDP address when endpoint is valid.
func udpNetAddr(endpoint netip.AddrPort) net.Addr {
	return net.UDPAddrFromAddrPort(endpoint)
}

// Read copies one complete outbound IP packet into buffers[0] at offset. Its
// data-plane signature matches tun.Device.Read, but Stack always has batch
// size one.
func (s *Stack) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	if err := s.ready(); err != nil {
		if errors.Is(err, ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	if len(buffers) == 0 || len(sizes) == 0 {
		return 0, errors.New("mipstack: Read requires one buffer and size")
	}
	if offset < 0 || offset > len(buffers[0]) {
		return 0, errors.New("mipstack: invalid Read offset")
	}
	select {
	case <-s.closeCh:
		return 0, os.ErrClosed
	default:
	}
	select {
	case packet := <-s.outbound:
		if len(packet) > len(buffers[0])-offset {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(buffers[0][offset:], packet)
		return 1, nil
	case <-s.closeCh:
		return 0, os.ErrClosed
	}
}

// Write delivers complete inbound IP packets from buffers at offset. Invalid,
// unrelated, and unsupported packets are silently discarded.
func (s *Stack) Write(buffers [][]byte, offset int) (int, error) {
	if err := s.ready(); err != nil {
		if errors.Is(err, ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	count := 0
	for _, buffer := range buffers {
		if offset < 0 || offset > len(buffer) {
			return count, errors.New("mipstack: invalid Write offset")
		}
		if len(buffer) == offset {
			continue
		}
		if err := s.handlePacket(buffer[offset:]); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// writePacket queues one complete outbound IP packet for Read.
func (s *Stack) writePacket(packet []byte) error {
	select {
	case <-s.closeCh:
		return ErrClosed
	default:
	}
	queue, loopback := s.outputQueue(packet)
	if loopback {
		select {
		case queue <- packet:
			s.recordOutput(true)
			return nil
		case <-s.closeCh:
			return ErrClosed
		default:
			// runLoopback is the sole consumer and may itself be emitting a
			// reply. Blocking it on its own full queue would deadlock all local
			// traffic, so overload is reported to the producing socket.
			return ErrResourceLimit
		}
	}
	select {
	case queue <- packet:
		s.recordOutput(false)
		return nil
	case <-s.closeCh:
		return ErrClosed
	}
}

// writePacketUntil queues a packet while observing a socket's mutable write
// deadline. The fast path allocates no timer when the packet queue has room.
func (s *Stack) writePacketUntil(packet []byte, state func() (time.Time, <-chan struct{}, bool)) error {
	queue, loopback := s.outputQueue(packet)
	if loopback {
		select {
		case queue <- packet:
			s.recordOutput(true)
			return nil
		case <-s.closeCh:
			return ErrClosed
		default:
			return ErrResourceLimit
		}
	}
	for {
		select {
		case queue <- packet:
			s.recordOutput(false)
			return nil
		case <-s.closeCh:
			return ErrClosed
		default:
		}
		deadline, changed, closed := state()
		if closed {
			return net.ErrClosed
		}
		timer, timeout := deadlineTimer(deadline)
		select {
		case queue <- packet:
			stopTimer(timer)
			s.recordOutput(false)
			return nil
		case <-changed:
			stopTimer(timer)
		case <-timeout:
			return os.ErrDeadlineExceeded
		case <-s.closeCh:
			stopTimer(timer)
			return ErrClosed
		}
	}
}

// outputQueue chooses local delivery when the destination belongs to this
// stack, otherwise the embedding link's packet queue.
func (s *Stack) outputQueue(packet []byte) (chan []byte, bool) {
	if destination, ok := packetDestination(packet); ok && s.isLocal(destination) {
		return s.loopback, true
	}
	return s.outbound, false
}

// recordOutput updates the appropriate queue statistic.
func (s *Stack) recordOutput(loopback bool) {
	if loopback {
		s.stats.loopbackPackets.Add(1)
	} else {
		s.stats.outboundPackets.Add(1)
	}
}

// handlePacket processes one packet supplied through Write.
func (s *Stack) handlePacket(packet []byte) error {
	s.stats.inboundPackets.Add(1)
	parsed, ok := parseIPPacket(packet)
	if !ok {
		if reassembled, pending := s.reassemblePacketStatus(packet, time.Now()); reassembled != nil {
			parsed, ok = parseIPPacket(reassembled)
		} else if pending {
			return nil
		}
	}
	limitedBroadcast := parsed.source.Is4() && parsed.source == netip.AddrFrom4([4]byte{255, 255, 255, 255})
	if !ok || !s.isLocal(parsed.target) || parsed.source.IsUnspecified() || parsed.source.IsMulticast() || limitedBroadcast {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if parsed.parameterError {
		return s.sendParameterProblem(parsed)
	}
	s.mu.RLock()
	ip := s.ip
	s.mu.RUnlock()
	rawDelivered := ip != nil && ip.deliver(s, parsed)
	switch parsed.protocol {
	case protocolTCP:
		return s.handleTCP(parsed)
	case protocolUDP:
		return s.handleUDP(parsed)
	case protocolICMPv4, protocolICMPv6:
		return s.handleICMP(parsed)
	default:
		if parsed.protocol == 59 {
			return nil
		}
		if rawDelivered {
			return nil
		}
		return s.sendProtocolUnreachable(parsed)
	}
}

// Close closes every socket and releases all stack resources.
func (s *Stack) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	tcpConnections := make([]*TCPConn, 0, len(s.tcp))
	for _, connection := range s.tcp {
		tcpConnections = append(tcpConnections, connection)
	}
	tcpPassive := s.tcpPassive
	udpConnections := s.udpConnectionsLocked()
	ip := s.ip
	s.tcp = make(map[tcpKey]*TCPConn)
	s.tcpPassive = nil
	s.udp = make(map[udpKey]*UDPConn)
	s.udpReuse = nil
	s.ip = nil
	s.stats.activeTCPConnections.Store(0)
	s.stats.activeTCPListeners.Store(0)
	s.stats.activeUDPSockets.Store(0)
	s.stats.activeIPSockets.Store(0)
	s.mu.Unlock()
	s.fragmentMu.Lock()
	s.fragments = make(map[fragmentKey]*fragmentSet)
	s.fragmentBytes = 0
	s.fragmentMu.Unlock()
	if tcpPassive != nil {
		tcpPassive.closeAll()
	}
	for _, connection := range tcpConnections {
		connection.abortWithoutReset(ErrClosed)
	}
	for _, connection := range udpConnections {
		connection.closeFromStack()
	}
	if ip != nil {
		ip.closeAll()
	}
	return nil
}

// closeTCPListener removes listener from passive dispatch and publishes its
// closure.
func (s *Stack) closeTCPListener(listener *TCPListener) bool {
	s.mu.Lock()
	removed := false
	state, ok := s.tcpPassive.(*tcpPassiveState)
	if ok && state.remove(listener) {
		s.stats.activeTCPListeners.Add(^uint64(0))
		removed = true
		if state.empty() {
			s.tcpPassive = nil
		}
	}
	s.mu.Unlock()
	listener.closeFromStack()
	return removed
}

// closeUDP removes connection from the UDP dispatcher and releases its port.
func (s *Stack) closeUDP(connection *UDPConn) bool {
	key := udpKey{address: connection.local, port: connection.port}
	s.mu.Lock()
	removed := false
	if s.udp[key] == connection {
		delete(s.udp, key)
		removed = true
	} else if s.udpReuse != nil && s.udpReuse.remove(connection) {
		removed = true
		if s.udpReuse.empty() {
			s.udpReuse = nil
		}
	}
	if removed {
		s.stats.activeUDPSockets.Add(^uint64(0))
	}
	s.mu.Unlock()
	connection.closeFromStack()
	return removed
}

// udpConnectionsLocked returns every exclusive and REUSEPORT socket while
// Stack.mu is held.
func (s *Stack) udpConnectionsLocked() []*UDPConn {
	connections := make([]*UDPConn, 0, len(s.udp))
	for _, connection := range s.udp {
		connections = append(connections, connection)
	}
	if s.udpReuse != nil {
		connections = append(connections, s.udpReuse.connections()...)
	}
	return connections
}

// closeIP removes a protocol socket from fan-out and publishes closure.
func (s *Stack) closeIP(connection *IPConn) bool {
	s.mu.Lock()
	removed := false
	state, ok := s.ip.(*ipEndpointState)
	if ok && state.remove(connection) {
		s.stats.activeIPSockets.Add(^uint64(0))
		removed = true
		if state.empty() {
			s.ip = nil
		}
	}
	s.mu.Unlock()
	connection.closeFromStack()
	return removed
}

// removeTCP removes a terminated connection and releases its port.
func (s *Stack) removeTCP(connection *TCPConn) {
	s.mu.Lock()
	if s.tcp[connection.key] == connection {
		delete(s.tcp, connection.key)
		s.stats.activeTCPConnections.Add(^uint64(0))
	}
	s.mu.Unlock()
}

// nextPacketID returns a process-local IPv4 identification value.
func (s *Stack) nextPacketID() uint16 {
	return uint16(s.packetID.Add(1))
}

// nextFragmentID returns an IPv6 fragment identification value.
func (s *Stack) nextFragmentID() uint32 {
	return s.packetID.Add(1)
}
