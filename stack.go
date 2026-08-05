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
	// recentDestinationMaximum bounds ICMP correlation state for one
	// connectionless socket.
	recentDestinationMaximum = 256
	// recentDestinationLifetime accepts delayed network errors without
	// retaining every destination used by a long-running socket.
	recentDestinationLifetime = 2 * time.Minute
	// datagramQueueRetain keeps a small metadata burst allocation after a queue
	// drains without pinning an application-sized receive queue on idle sockets.
	datagramQueueRetain = 4
	// deadlineTimerCacheLimit bounds stopped timers retained by concurrent
	// datagram readers. Additional readers allocate transient timers rather than
	// making one unusually concurrent socket retain them indefinitely.
	deadlineTimerCacheLimit = 4
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

// TCPSocketDefaults configures policies inherited by newly created TCP
// connections and listeners. Zero fields retain the package defaults.
type TCPSocketDefaults struct {
	// CongestionControl selects the algorithm used by new connections. The
	// zero value selects CUBIC. UpdateConfig also applies a changed value to
	// established connections without an explicit per-connection override.
	CongestionControl CongestionControl
	// ReceiveBuffer is the initial application receive capacity.
	ReceiveBuffer int
	// MaximumReceiveBuffer bounds automatic receive tuning.
	MaximumReceiveBuffer int
	// SendBuffer is the initial application send capacity.
	SendBuffer int
	// MaximumSendBuffer bounds automatic send tuning.
	MaximumSendBuffer int
	// AcceptQueue bounds completed connections waiting for Accept.
	AcceptQueue int
	// SYNBacklog bounds stateful handshakes before SYN cookies are used.
	SYNBacklog int
	// KeepAlive enables keepalive probes on new connections.
	KeepAlive bool
	// KeepAliveConfig supplies the default probe timing and retry count.
	KeepAliveConfig KeepAliveConfig
	// IdleTimeout closes a connection after receive inactivity. Zero disables it.
	IdleTimeout time.Duration
	// UserTimeout bounds how long transmitted data may remain unacknowledged,
	// or buffered data may remain unsent behind a zero window. Zero disables
	// this custom bound while retaining the normal TCP retry limits.
	UserTimeout time.Duration
	// DisableNoDelay makes new connections start with Nagle coalescing enabled.
	DisableNoDelay bool
	// TrafficClass supplies IPv4 TOS or IPv6 Traffic Class DSCP bits. TCP
	// controls the two ECN bits independently.
	TrafficClass uint8
	// FlowLabel fixes the IPv6 Flow Label on new connections. Zero selects a
	// stable RFC 6437-style label derived from the connection tuple.
	FlowLabel uint32
}

// DatagramSocketDefaults configures policies inherited by newly created UDP
// or IP protocol sockets. Zero fields retain the package defaults.
type DatagramSocketDefaults struct {
	// ReceiveBuffer is the approximate retained-memory receive capacity.
	ReceiveBuffer int
	// HopLimit is the default IPv4 TTL or IPv6 Hop Limit. Zero selects 64.
	HopLimit int
	// TrafficClass is the default IPv4 TOS or IPv6 Traffic Class byte.
	TrafficClass uint8
	// FlowLabel is the default IPv6 Flow Label. Zero selects a stable automatic
	// label for each destination flow.
	FlowLabel uint32
}

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
	// TCP supplies default socket and listener policies.
	TCP TCPSocketDefaults
	// UDP supplies defaults inherited by new UDP sockets.
	UDP DatagramSocketDefaults
	// IP supplies defaults inherited by new IP protocol sockets.
	IP DatagramSocketDefaults
}

// Stack converts raw IPv4/IPv6 packets to application TCP, UDP, and IP
// protocol sockets.
type Stack struct {
	network  atomic.Pointer[networkState]
	outbound packetQueue
	loopback packetQueue

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

	ipv4ID          atomic.Uint32
	ipv6FragmentID  atomic.Uint32
	closeCh         chan struct{}
	timestampEpoch  time.Time
	tcpISNSecret    [16]byte
	flowLabelSecret [16]byte

	fragmentMu    sync.Mutex
	fragments     map[fragmentKey]*fragmentSet
	fragmentBytes int
	fragmentWake  chan struct{}

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
	// InvalidIPPackets counts packets rejected by IP parsing or reassembly.
	InvalidIPPackets uint64
	// UnacceptedIPPackets counts valid packets whose source or destination is
	// not admissible for this endpoint stack.
	UnacceptedIPPackets uint64
	// NonlocalDestinationPackets is the unaccepted subset addressed elsewhere.
	NonlocalDestinationPackets uint64
	// InvalidSourcePackets is the unaccepted subset with a prohibited source.
	InvalidSourcePackets uint64
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
	// TCPInboundQueueDrops counts validated segments rejected by a connection's
	// byte-bounded actor queue.
	TCPInboundQueueDrops uint64
	// TCPInvalidSegments counts malformed headers and checksum failures.
	TCPInvalidSegments uint64
	// TCPSACKRetransmissions counts retransmissions selected by the SACK
	// scoreboard, including its RACK-confirmed subset.
	TCPSACKRetransmissions uint64
	// TCPRACKRetransmissions counts the time-based subset of SACK recovery.
	TCPRACKRetransmissions uint64
	// TCPTailLossProbes counts probes sent before the ordinary RTO.
	TCPTailLossProbes uint64
	// TCPSpuriousRecoveryUndos counts Eifel or DSACK evidence that safely
	// restored congestion state after an unnecessary retransmission.
	TCPSpuriousRecoveryUndos uint64
	// TCPZeroWindowProbes counts persist probes sent while the peer advertises
	// a closed receive window.
	TCPZeroWindowProbes uint64
	// TCPKeepAliveProbes counts probes sent after configured receive inactivity.
	TCPKeepAliveProbes uint64
	// TCPSYNCookiesSent counts stateless SYN-ACKs emitted under listener or
	// stack connection pressure.
	TCPSYNCookiesSent uint64
	// TCPSYNCookiesAccepted counts final ACKs that authenticated a recent SYN
	// cookie and entered a listener backlog.
	TCPSYNCookiesAccepted uint64
	// TCPSYNCookiesRejected counts candidate final ACKs that failed cookie
	// authentication while cookie validation was active.
	TCPSYNCookiesRejected uint64
	// TCPHandshakeTimeouts counts passive stateful handshakes that exhausted
	// their SYN-ACK retry budget.
	TCPHandshakeTimeouts uint64
	// TCPAcceptQueueDrops counts completed handshakes aborted because their
	// listener's accept queue was full.
	TCPAcceptQueueDrops uint64
	// PathMTUUpdates counts accepted destination PMTU reductions.
	PathMTUUpdates uint64
	// PathMTUProbes counts TCP packets sent above the confirmed effective MTU.
	PathMTUProbes uint64
	// PathMTUProbeSuccesses counts acknowledged upward TCP probes.
	PathMTUProbeSuccesses uint64
	// PathMTUProbeFailures counts isolated upward probes rejected by SACK
	// evidence without treating them as congestion loss.
	PathMTUProbeFailures uint64
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
	invalidIPPackets            atomic.Uint64
	unacceptedIPPackets         atomic.Uint64
	nonlocalDestinationPackets  atomic.Uint64
	invalidSourcePackets        atomic.Uint64
	outboundPackets             atomic.Uint64
	loopbackPackets             atomic.Uint64
	activeTCPConnections        atomic.Uint64
	activeTCPListeners          atomic.Uint64
	activeUDPSockets            atomic.Uint64
	activeIPSockets             atomic.Uint64
	tcpRetransmissions          atomic.Uint64
	tcpInboundQueueDrops        atomic.Uint64
	tcpInvalidSegments          atomic.Uint64
	tcpSACKRetransmissions      atomic.Uint64
	tcpRACKRetransmissions      atomic.Uint64
	tcpTailLossProbes           atomic.Uint64
	tcpSpuriousRecoveryUndos    atomic.Uint64
	tcpZeroWindowProbes         atomic.Uint64
	tcpKeepAliveProbes          atomic.Uint64
	tcpSYNCookiesSent           atomic.Uint64
	tcpSYNCookiesAccepted       atomic.Uint64
	tcpSYNCookiesRejected       atomic.Uint64
	tcpHandshakeTimeouts        atomic.Uint64
	tcpAcceptQueueDrops         atomic.Uint64
	pathMTUUpdates              atomic.Uint64
	pathMTUProbes               atomic.Uint64
	pathMTUProbeSuccesses       atomic.Uint64
	pathMTUProbeFailures        atomic.Uint64
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
	// controlResponseFragmentTimeout limits ICMP reassembly timeout errors.
	controlResponseFragmentTimeout
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

// recentDestinationCache retains bounded evidence that a connectionless
// socket actually sent to a destination quoted by an ICMP error. Callers own
// synchronization so the cache can share their existing socket mutex.
type recentDestinationCache[T comparable] map[T]time.Time

// remember records a successful transmission and evicts expired or oldest
// evidence when the bound is full.
func (c recentDestinationCache[T]) remember(destination T, now time.Time) {
	if _, exists := c[destination]; exists {
		c[destination] = now
		return
	}
	if len(c) >= recentDestinationMaximum {
		var oldest T
		var oldestTime time.Time
		haveOldest := false
		for candidate, updated := range c {
			if now.Sub(updated) >= recentDestinationLifetime {
				delete(c, candidate)
				continue
			}
			if !haveOldest || updated.Before(oldestTime) {
				oldest, oldestTime, haveOldest = candidate, updated, true
			}
		}
		if len(c) >= recentDestinationMaximum && haveOldest {
			delete(c, oldest)
		}
	}
	c[destination] = now
}

// contains reports recent transmission evidence and removes it after expiry.
func (c recentDestinationCache[T]) contains(destination T, now time.Time) bool {
	updated, exists := c[destination]
	if exists && now.Sub(updated) >= recentDestinationLifetime {
		delete(c, destination)
		return false
	}
	return exists
}

// datagramQueue is a compact FIFO whose small backing allocation survives an
// empty transition. A head index avoids moving queued payload metadata on each
// read; larger bursts are released when fully drained.
type datagramQueue[T any] struct {
	values []T
	head   int
}

func (q *datagramQueue[T]) len() int { return len(q.values) - q.head }

func (q *datagramQueue[T]) push(value T) {
	if q.head != 0 && len(q.values) == cap(q.values) {
		copy(q.values, q.values[q.head:])
		remaining := len(q.values) - q.head
		var zero T
		for index := remaining; index < len(q.values); index++ {
			q.values[index] = zero
		}
		q.values = q.values[:remaining]
		q.head = 0
	}
	q.values = append(q.values, value)
}

func (q *datagramQueue[T]) pop() (T, bool) {
	var zero T
	if q.head == len(q.values) {
		return zero, false
	}
	value := q.values[q.head]
	q.values[q.head] = zero
	q.head++
	if q.head == len(q.values) {
		if cap(q.values) <= datagramQueueRetain {
			q.values = q.values[:0]
		} else {
			q.values = nil
		}
		q.head = 0
	}
	return value, true
}

func (q *datagramQueue[T]) clear() {
	var zero T
	for index := range q.values {
		q.values[index] = zero
	}
	q.values = nil
	q.head = 0
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
	dynamic      uint16
	fallback     uint16
	dynamicStep  uint16
	fallbackStep uint16
	secret       [16]byte
}

// packetQueueEntry couples one packet with its fixed queue slot. The entry is
// stored inline in the bounded channel and does not allocate per packet.
type packetQueueEntry struct {
	packet []byte
	slot   uint16
}

// packetQueue uses one reusable slot per channel position. The free-slot
// channel is both a capacity semaphore and a one-producer wakeup mechanism;
// releasing one consumed packet cannot wake every writer waiting on a full
// host queue.
type packetQueue struct {
	packets chan packetQueueEntry
	free    chan uint16
	slots   []atomic.Uint64
}

// packetQueueTicket identifies one generation of a fixed queue slot. TCP uses
// it to avoid treating scheduler or embedding-link backpressure as packet
// loss, matching Linux's skb_still_in_host_queue check.
type packetQueueTicket struct {
	queue      *packetQueue
	slot       uint16
	generation uint64
	queuedAt   time.Time
}

// newPacketQueue constructs a bounded queue with every slot initially free.
func newPacketQueue(capacity int) packetQueue {
	queue := packetQueue{
		packets: make(chan packetQueueEntry, capacity),
		free:    make(chan uint16, capacity),
		slots:   make([]atomic.Uint64, capacity),
	}
	for slot := range queue.slots {
		queue.free <- uint16(slot)
	}
	return queue
}

// pending reports whether Read or local delivery has not consumed this exact
// slot generation. Reuse of the same bounded slot cannot revive an old ticket.
func (t packetQueueTicket) pending() bool {
	if t.queue == nil || int(t.slot) >= len(t.queue.slots) {
		return false
	}
	return t.queue.slots[t.slot].Load() == t.generation<<1|1
}

// tryReserve acquires one queue position without blocking.
func (q *packetQueue) tryReserve() (uint16, bool) {
	select {
	case slot := <-q.free:
		return slot, true
	default:
		return 0, false
	}
}

// releaseReserved returns a slot that was acquired but not published.
func (q *packetQueue) releaseReserved(slot uint16) { q.free <- slot }

// enqueueReserved publishes a packet after its caller has acquired slot.
// Since the packet channel and slot semaphore have equal capacities, a
// reserved slot always has a corresponding channel position.
func (q *packetQueue) enqueueReserved(slot uint16, packet []byte) packetQueueTicket {
	state := q.slots[slot].Load()
	generation := state>>1 + 1
	q.slots[slot].Store(generation<<1 | 1)
	queuedAt := time.Now()
	q.packets <- packetQueueEntry{packet: packet, slot: slot}
	return packetQueueTicket{queue: q, slot: slot, generation: generation, queuedAt: queuedAt}
}

// tryEnqueue publishes one packet only when a queue slot is immediately
// available.
func (q *packetQueue) tryEnqueue(packet []byte) (packetQueueTicket, bool) {
	slot, ok := q.tryReserve()
	if !ok {
		return packetQueueTicket{}, false
	}
	return q.enqueueReserved(slot, packet), true
}

// consume marks an entry as no longer pending before making its slot
// available to exactly one waiting producer.
func (q *packetQueue) consume(entry packetQueueEntry) []byte {
	state := q.slots[entry.slot].Load()
	q.slots[entry.slot].Store(state &^ 1)
	q.free <- entry.slot
	return entry.packet
}

// New constructs an inactive-socket stack.
func New(config Config) (*Stack, error) {
	state, err := buildNetworkState(config)
	if err != nil {
		return nil, err
	}
	// One OS-random read seeds independent port, fragment-ID, and RFC 6528
	// sequence spaces. Per-connection ISNs are derived from tcpISNSecret.
	var seed [88]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, err
	}
	ports4 := automaticPortCursor{
		dynamic:  uint16(binary.BigEndian.Uint32(seed[0:4]) % dynamicPortCount),
		fallback: uint16(binary.BigEndian.Uint32(seed[4:8]) % fallbackPortCount),
	}
	ports6 := automaticPortCursor{
		dynamic:  uint16(binary.BigEndian.Uint32(seed[8:12]) % dynamicPortCount),
		fallback: uint16(binary.BigEndian.Uint32(seed[12:16]) % fallbackPortCount),
	}
	copy(ports4.secret[:], seed[40:56])
	copy(ports6.secret[:], seed[56:72])
	ipv4ID := binary.BigEndian.Uint32(seed[16:20])
	ipv6FragmentID := binary.BigEndian.Uint32(seed[20:24])
	stack := &Stack{
		outbound: newPacketQueue(outboundPacketQueue), loopback: newPacketQueue(loopbackPacketQueue),
		tcp: make(map[tcpKey]*TCPConn), udp: make(map[udpKey]*UDPConn),
		nextPort: [2]automaticPortCursor{ports4, ports6}, pathMTU: make(map[netip.Addr]pathMTUEntry),
		closeCh: make(chan struct{}), timestampEpoch: time.Now(), fragments: make(map[fragmentKey]*fragmentSet), fragmentWake: make(chan struct{}, 1),
	}
	copy(stack.tcpISNSecret[:], seed[24:40])
	copy(stack.flowLabelSecret[:], seed[72:88])
	stack.ipv4ID.Store(ipv4ID)
	stack.ipv6FragmentID.Store(ipv6FragmentID)
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
	previous := s.network.Load()
	if previous == nil || previous.mtu != state.mtu {
		s.pathMTUMu.Lock()
		s.network.Store(state)
		s.pathMTU = make(map[netip.Addr]pathMTUEntry)
		s.pathMTUMu.Unlock()
	} else {
		s.network.Store(state)
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
		connection.updateDefaultCongestionControl(state.tcpDefaults.CongestionControl)
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
	s.pruneFragments(state)
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
	state := s.network.Load()
	if state.broadcastDestination(destination) {
		return Route{}, syscall.EACCES
	}
	route, exists := state.routeFor(destination)
	if !exists {
		return Route{}, syscall.ENETUNREACH
	}
	return route, nil
}

// PathMTU returns the currently confirmed packet size for one routed unicast
// destination. The result includes the IP header.
func (s *Stack) PathMTU(destination netip.Addr) (int, error) {
	if _, err := s.RouteFor(destination); err != nil {
		return 0, err
	}
	return s.mtuFor(destination), nil
}

// ConfirmPathMTU records packetization-layer acknowledgement of an
// unfragmented probe. Connectionless protocols must call this only after their
// own acknowledgement semantics prove delivery; queueing a packet is not
// confirmation.
func (s *Stack) ConfirmPathMTU(destination netip.Addr, mtu int) error {
	if _, err := s.RouteFor(destination); err != nil {
		return err
	}
	destination = destination.Unmap()
	minimum := 68
	if destination.Is6() {
		minimum = ipv6MinimumMTU
	}
	s.pathMTUMu.Lock()
	linkMTU := s.network.Load().mtu
	if mtu < minimum || mtu > linkMTU {
		s.pathMTUMu.Unlock()
		return syscall.EINVAL
	}
	// An expired lower cache entry is still the most recent packetization-
	// layer confirmation. Keep it as the lower bound of an application's
	// binary search instead of requiring the first successful probe to jump
	// directly to the link MTU.
	confirmed := linkMTU
	if current, exists := s.pathMTU[destination]; exists && current.mtu < confirmed {
		confirmed = current.mtu
	}
	if mtu < confirmed {
		s.pathMTUMu.Unlock()
		return syscall.EINVAL
	}
	changed := s.confirmPathMTULocked(destination, mtu, linkMTU, time.Now())
	s.pathMTUMu.Unlock()
	if changed {
		s.notifyTCPPathMTU(destination, nil)
	}
	return nil
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
	s.pathMTUMu.RLock()
	linkMTU := s.network.Load().mtu
	entry, exists := s.pathMTU[destination]
	s.pathMTUMu.RUnlock()
	if !exists {
		return linkMTU
	}
	now := time.Now()
	if exists && now.Sub(entry.updated) < pathMTULifetime && entry.mtu < linkMTU {
		return entry.mtu
	}
	if exists && now.Sub(entry.updated) >= pathMTULifetime {
		s.pathMTUMu.Lock()
		linkMTU = s.network.Load().mtu
		current, currentExists := s.pathMTU[destination]
		if currentExists && now.Sub(current.updated) >= pathMTULifetime {
			delete(s.pathMTU, destination)
			currentExists = false
		}
		s.pathMTUMu.Unlock()
		if currentExists && current.mtu < linkMTU {
			// Another ICMP update refreshed this entry after the stale read.
			return current.mtu
		}
	}
	return linkMTU
}

// pathMTUExpiry returns the time at which a destination PMTU should be probed
// upward. A past expiry remains actionable so a connection that raced cache
// expiry while starting is woken immediately; mtuFor then removes the entry.
func (s *Stack) pathMTUExpiry(destination netip.Addr) (time.Time, bool) {
	destination = destination.Unmap()
	s.pathMTUMu.RLock()
	linkMTU := s.network.Load().mtu
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
	if destination.Is6() && mtu < minimum {
		// RFC 8201 requires discarding a Packet Too Big value below the
		// IPv6 minimum link MTU rather than turning it into a 1280-byte hint.
		return false
	}
	if mtu < minimum {
		mtu = minimum
	}
	s.pathMTUMu.Lock()
	defer s.pathMTUMu.Unlock()
	if mtu >= uint32(s.network.Load().mtu) {
		return false
	}
	now := time.Now()
	current, exists := s.pathMTU[destination]
	if exists && now.Sub(current.updated) < pathMTULifetime {
		if current.mtu < int(mtu) {
			// A Packet Too Big message can only lower the confirmed PMTU.
			// A larger value neither proves the smaller path constraint still
			// exists nor authorizes an upward change.
			return false
		}
		if current.mtu == int(mtu) {
			current.updated = now
			s.pathMTU[destination] = current
			return false
		}
	}
	s.storePathMTULocked(destination, pathMTUEntry{mtu: int(mtu), updated: now})
	s.stats.pathMTUUpdates.Add(1)
	return true
}

// storePathMTULocked installs one entry while preserving the global cache
// bound. Callers hold pathMTUMu for writing.
func (s *Stack) storePathMTULocked(destination netip.Addr, entry pathMTUEntry) {
	if _, exists := s.pathMTU[destination]; !exists && len(s.pathMTU) >= pathMTUMaximumEntries {
		var oldestAddress netip.Addr
		var oldest pathMTUEntry
		for address, candidate := range s.pathMTU {
			if !oldestAddress.IsValid() || candidate.updated.Before(oldest.updated) {
				oldestAddress, oldest = address, candidate
			}
		}
		delete(s.pathMTU, oldestAddress)
	}
	s.pathMTU[destination] = entry
}

// confirmPathMTU raises a shared destination PMTU after packetization-layer
// acknowledgement and wakes sibling TCP flows on the same single-link path.
func (s *Stack) confirmPathMTU(destination netip.Addr, mtu int, except *TCPConn) bool {
	destination = destination.Unmap()
	if !destination.IsValid() || mtu <= 0 {
		return false
	}
	s.pathMTUMu.Lock()
	linkMTU := s.network.Load().mtu
	if mtu > linkMTU {
		s.pathMTUMu.Unlock()
		return false
	}
	changed := s.confirmPathMTULocked(destination, mtu, linkMTU, time.Now())
	s.pathMTUMu.Unlock()
	if changed {
		s.notifyTCPPathMTU(destination, except)
	}
	return changed
}

// confirmPathMTULocked raises one destination PMTU against the network
// snapshot protected by pathMTUMu. UpdateConfig publishes a changed link MTU
// under the same lock, so a confirmation cannot combine an old ceiling with
// a newly reset cache.
func (s *Stack) confirmPathMTULocked(destination netip.Addr, mtu, linkMTU int, now time.Time) bool {
	current, exists := s.pathMTU[destination]
	if exists && now.Sub(current.updated) < pathMTULifetime {
		if current.mtu > mtu {
			// Delivery of a smaller probe does not reconfirm the larger packet
			// size established by another flow.
			return false
		}
		if current.mtu == mtu {
			current.updated = now
			s.pathMTU[destination] = current
			return false
		}
	}
	if mtu >= linkMTU {
		delete(s.pathMTU, destination)
	} else {
		s.storePathMTULocked(destination, pathMTUEntry{mtu: mtu, updated: now})
	}
	return true
}

// Stats returns a consistent-enough lock-free snapshot of stack counters.
// Concurrent activity may become visible across adjacent fields at slightly
// different instants.
func (s *Stack) Stats() StackStats {
	return StackStats{
		InboundPackets:              s.stats.inboundPackets.Load(),
		InboundDroppedPackets:       s.stats.inboundDroppedPackets.Load(),
		InvalidIPPackets:            s.stats.invalidIPPackets.Load(),
		UnacceptedIPPackets:         s.stats.unacceptedIPPackets.Load(),
		NonlocalDestinationPackets:  s.stats.nonlocalDestinationPackets.Load(),
		InvalidSourcePackets:        s.stats.invalidSourcePackets.Load(),
		OutboundPackets:             s.stats.outboundPackets.Load(),
		LoopbackPackets:             s.stats.loopbackPackets.Load(),
		ActiveTCPConnections:        s.stats.activeTCPConnections.Load(),
		ActiveTCPListeners:          s.stats.activeTCPListeners.Load(),
		ActiveUDPSockets:            s.stats.activeUDPSockets.Load(),
		ActiveIPSockets:             s.stats.activeIPSockets.Load(),
		TCPRetransmissions:          s.stats.tcpRetransmissions.Load(),
		TCPInboundQueueDrops:        s.stats.tcpInboundQueueDrops.Load(),
		TCPInvalidSegments:          s.stats.tcpInvalidSegments.Load(),
		TCPSACKRetransmissions:      s.stats.tcpSACKRetransmissions.Load(),
		TCPRACKRetransmissions:      s.stats.tcpRACKRetransmissions.Load(),
		TCPTailLossProbes:           s.stats.tcpTailLossProbes.Load(),
		TCPSpuriousRecoveryUndos:    s.stats.tcpSpuriousRecoveryUndos.Load(),
		TCPZeroWindowProbes:         s.stats.tcpZeroWindowProbes.Load(),
		TCPKeepAliveProbes:          s.stats.tcpKeepAliveProbes.Load(),
		TCPSYNCookiesSent:           s.stats.tcpSYNCookiesSent.Load(),
		TCPSYNCookiesAccepted:       s.stats.tcpSYNCookiesAccepted.Load(),
		TCPSYNCookiesRejected:       s.stats.tcpSYNCookiesRejected.Load(),
		TCPHandshakeTimeouts:        s.stats.tcpHandshakeTimeouts.Load(),
		TCPAcceptQueueDrops:         s.stats.tcpAcceptQueueDrops.Load(),
		PathMTUUpdates:              s.stats.pathMTUUpdates.Load(),
		PathMTUProbes:               s.stats.pathMTUProbes.Load(),
		PathMTUProbeSuccesses:       s.stats.pathMTUProbeSuccesses.Load(),
		PathMTUProbeFailures:        s.stats.pathMTUProbeFailures.Load(),
		PathMTUBlackHoleReductions:  s.stats.pathMTUBlackHoleReductions.Load(),
		FragmentEvictions:           s.stats.fragmentEvictions.Load(),
		FragmentTimeouts:            s.stats.fragmentTimeouts.Load(),
		RateLimitedControlResponses: s.stats.rateLimitedControlResponses.Load(),
	}
}

// allowControlResponse consumes one token from a control-response class.
func (s *Stack) allowControlResponse(class controlResponseClass) bool {
	s.controlMu.Lock()
	now := time.Now()
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
		case entry := <-s.loopback.packets:
			packet := s.loopback.consume(entry)
			_ = s.handleInboundPacket(packet, time.Now())
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

// sourceForRequested validates an explicit source or selects one automatically.
func (s *Stack) sourceForRequested(destination, requested netip.Addr) (netip.Addr, error) {
	return s.network.Load().sourceFor(destination, requested)
}

// automaticFlowLabel derives one nonzero RFC 6437-style label from a stable
// per-stack secret and the fields available to identify an IPv6 flow.
func (s *Stack) automaticFlowLabel(source, target netip.Addr, protocol byte, payload []byte) uint32 {
	var selector [4]byte
	switch protocol {
	case protocolTCP, protocolUDP:
		if len(payload) >= 4 {
			copy(selector[:], payload[:4])
		}
	case protocolICMPv6:
		if len(payload) >= 6 {
			selector[0], selector[1] = payload[0], payload[1]
			copy(selector[2:4], payload[4:6])
		}
	}
	return s.flowLabel(source, target, protocol, selector)
}

// automaticTransportFlowLabel is automaticFlowLabel without requiring a
// serialized TCP or UDP header.
func (s *Stack) automaticTransportFlowLabel(source, target netip.Addr, protocol byte, sourcePort, targetPort uint16) uint32 {
	var selector [4]byte
	binary.BigEndian.PutUint16(selector[0:2], sourcePort)
	binary.BigEndian.PutUint16(selector[2:4], targetPort)
	return s.flowLabel(source, target, protocol, selector)
}

// flowLabel hashes one directional flow identity into IPv6's 20-bit field.
func (s *Stack) flowLabel(source, target netip.Addr, protocol byte, selector [4]byte) uint32 {
	var input [37]byte
	sourceValue, targetValue := source.As16(), target.As16()
	copy(input[0:16], sourceValue[:])
	copy(input[16:32], targetValue[:])
	input[32] = protocol
	copy(input[33:37], selector[:])
	label := uint32(sipHash24(s.flowLabelSecret, input[:])) & ipv6MaximumFlowLabel
	if label == 0 {
		label = 1
	}
	return label
}

// allocateAutomaticPort selects an available IANA dynamic port first, then
// falls back to the lower non-privileged range only after a complete scan.
func allocateAutomaticPort(cursor *automaticPortCursor, available func(uint16) bool) (uint16, error) {
	return allocateAutomaticPortWithOffsets(cursor, [2]uint32{}, available)
}

// allocateAutomaticPortWithOffsets combines a moving full-period cursor with
// keyed per-destination offsets, following RFC 6056's hash-based selection
// model without retaining a table for every remote endpoint.
func allocateAutomaticPortWithOffsets(cursor *automaticPortCursor, offsets [2]uint32, available func(uint16) bool) (uint16, error) {
	ranges := [...]struct {
		id     byte
		first  uint32
		count  uint32
		cursor *uint16
		step   *uint16
	}{
		{0, dynamicPortFirst, dynamicPortCount, &cursor.dynamic, &cursor.dynamicStep},
		{1, fallbackPortFirst, fallbackPortCount, &cursor.fallback, &cursor.fallbackStep},
	}
	for _, portRange := range ranges {
		if *portRange.step == 0 {
			*portRange.step = automaticPortStep(cursor.secret, portRange.id, portRange.count)
		}
		base := uint32(*portRange.cursor)
		start := (base + offsets[portRange.id]%portRange.count) % portRange.count
		for probe := uint32(0); probe < portRange.count; probe++ {
			position := (start + probe*uint32(*portRange.step)) % portRange.count
			port := uint16(portRange.first + position)
			if !available(port) {
				continue
			}
			// Advance the shared cursor independently of the destination offset.
			// For one destination this visits the complete range before returning
			// to a recently closed four-tuple retained by its peer in TIME_WAIT.
			*portRange.cursor = uint16((base + (probe+1)*uint32(*portRange.step)) % portRange.count)
			return port, nil
		}
	}
	return 0, ErrNoPorts
}

// automaticPortStep derives an unpredictable full-period traversal step.
func automaticPortStep(secret [16]byte, id byte, count uint32) uint16 {
	step := uint32(1) + uint32(sipHash24(secret, []byte{id})%uint64(count-1))
	for greatestCommonDivisor(step, count) != 1 {
		step++
		if step == count {
			step = 1
		}
	}
	return uint16(step)
}

// greatestCommonDivisor supports full-period automatic-port traversal.
func greatestCommonDivisor(left, right uint32) uint32 {
	for right != 0 {
		left, right = right, left%right
	}
	return left
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
	cursor := &s.nextPort[index]
	offsets := automaticTCPPortOffsets(cursor.secret, local, remote)
	return allocateAutomaticPortWithOffsets(cursor, offsets, func(port uint16) bool {
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

// automaticTCPPortOffsets separate the ephemeral sequence observed by each
// remote endpoint using the same tuple inputs recommended by RFC 6056.
func automaticTCPPortOffsets(secret [16]byte, local netip.Addr, remote netip.AddrPort) [2]uint32 {
	var input [35]byte
	if local.Is6() {
		input[0] = 6
	} else {
		input[0] = 4
	}
	localValue, remoteValue := local.As16(), remote.Addr().As16()
	copy(input[1:17], localValue[:])
	copy(input[17:33], remoteValue[:])
	binary.BigEndian.PutUint16(input[33:35], remote.Port())
	hash := sipHash24(secret, input[:])
	return [2]uint32{uint32(hash), uint32(hash >> 32)}
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
	target := net.UDPAddrFromAddrPort(local)
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
	target := net.UDPAddrFromAddrPort(remote)
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

// Read blocks for one complete outbound IP packet, then drains up to
// BatchSize packets into consecutive buffers at offset. On success it sets
// the corresponding packet lengths in sizes, matching tun.Device.Read.
func (s *Stack) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	if err := s.ready(); err != nil {
		if errors.Is(err, ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	if len(sizes) < len(buffers) {
		return 0, errors.New("mipstack: Read sizes shorter than buffers")
	}
	limit := len(buffers)
	if limit > deviceBatchSize {
		limit = deviceBatchSize
	}
	if limit == 0 {
		return 0, errors.New("mipstack: Read requires one buffer and size")
	}
	for index := 0; index < limit; index++ {
		if offset < 0 || offset > len(buffers[index]) {
			return 0, errors.New("mipstack: invalid Read offset")
		}
	}
	select {
	case <-s.closeCh:
		return 0, os.ErrClosed
	default:
	}
	readPacket := func(index int, entry packetQueueEntry) error {
		packet := s.outbound.consume(entry)
		if len(packet) > len(buffers[index])-offset {
			return io.ErrShortBuffer
		}
		sizes[index] = copy(buffers[index][offset:], packet)
		return nil
	}
	var first packetQueueEntry
	select {
	case first = <-s.outbound.packets:
	case <-s.closeCh:
		return 0, os.ErrClosed
	}
	if err := readPacket(0, first); err != nil {
		return 0, err
	}
	count := 1
	for count < limit {
		select {
		case entry := <-s.outbound.packets:
			if err := readPacket(count, entry); err != nil {
				return count, err
			}
			count++
		default:
			return count, nil
		}
	}
	return count, nil
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
	receivedAt := time.Now()
	count := 0
	for _, buffer := range buffers {
		if offset < 0 || offset > len(buffer) {
			return count, errors.New("mipstack: invalid Write offset")
		}
		if err := s.handleInboundPacket(buffer[offset:], receivedAt); err != nil {
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
		if _, queued := queue.tryEnqueue(packet); queued {
			s.recordOutput(true)
			return nil
		}
		select {
		case <-s.closeCh:
			return ErrClosed
		default:
			// runLoopback is the sole consumer and may itself be emitting a
			// reply. Blocking it on its own full queue would deadlock all local
			// traffic, so overload is reported to the producing socket.
			return ErrResourceLimit
		}
	}
	for {
		if _, queued := queue.tryEnqueue(packet); queued {
			s.recordOutput(false)
			return nil
		}
		select {
		case slot := <-queue.free:
			queue.enqueueReserved(slot, packet)
			s.recordOutput(false)
			return nil
		case <-s.closeCh:
			return ErrClosed
		}
	}
}

// tryWritePacket queues one best-effort control packet without waiting for
// device space. It is used when an already aborted TCP actor emits its final
// reset and must not retain connection state behind a stalled embedding link.
func (s *Stack) tryWritePacket(packet []byte) error {
	select {
	case <-s.closeCh:
		return ErrClosed
	default:
	}
	queue, loopback := s.outputQueue(packet)
	if _, queued := queue.tryEnqueue(packet); !queued {
		return ErrResourceLimit
	}
	s.recordOutput(loopback)
	return nil
}

// writePacketUntil queues a packet while observing a socket's mutable write
// deadline. The fast path allocates no timer when the packet queue has room.
func (s *Stack) writePacketUntil(packet []byte, state func() (time.Time, <-chan struct{}, bool)) error {
	_, err := s.writePacketUntilTicket(packet, state)
	return err
}

// writePacketUntilTicket is writePacketUntil plus the exact FIFO position
// used by TCP's host-queue-aware loss probing.
func (s *Stack) writePacketUntilTicket(packet []byte, state func() (time.Time, <-chan struct{}, bool)) (packetQueueTicket, error) {
	queue, loopback := s.outputQueue(packet)
	for {
		deadline, changed, closed := state()
		if closed {
			return packetQueueTicket{}, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			select {
			case <-changed:
				continue
			default:
				return packetQueueTicket{}, os.ErrDeadlineExceeded
			}
		}
		ticket, queued := queue.tryEnqueue(packet)
		if queued {
			s.recordOutput(loopback)
			return ticket, nil
		}
		if loopback {
			select {
			case <-s.closeCh:
				return packetQueueTicket{}, ErrClosed
			default:
				return packetQueueTicket{}, ErrResourceLimit
			}
		}
		timer, timeout := deadlineTimer(deadline)
		select {
		case slot := <-queue.free:
			stopTimer(timer)
			deadline, changed, closed = state()
			if closed {
				queue.releaseReserved(slot)
				return packetQueueTicket{}, net.ErrClosed
			}
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				select {
				case <-changed:
					queue.releaseReserved(slot)
					continue
				default:
					queue.releaseReserved(slot)
					return packetQueueTicket{}, os.ErrDeadlineExceeded
				}
			}
			ticket = queue.enqueueReserved(slot, packet)
			s.recordOutput(loopback)
			return ticket, nil
		case <-changed:
			stopTimer(timer)
		case <-timeout:
			return packetQueueTicket{}, os.ErrDeadlineExceeded
		case <-s.closeCh:
			stopTimer(timer)
			return packetQueueTicket{}, ErrClosed
		}
	}
}

// deadlineTimer returns a disabled channel for an unset deadline.
func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	duration := time.Until(deadline)
	if duration < 0 {
		duration = 0
	}
	timer := time.NewTimer(duration)
	return timer, timer.C
}

// stopTimer stops a non-nil timer.
func stopTimer(timer *time.Timer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

// deadlineTimerCache reuses a bounded number of stopped one-shot timers for a
// datagram socket. Each acquire returns a distinct timer, preserving the net
// package's concurrent Read guarantee without a process-wide pool.
type deadlineTimerCache struct {
	mu     sync.Mutex
	timers []*time.Timer
}

func (c *deadlineTimerCache) timer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	duration := time.Until(deadline)
	if duration < 0 {
		duration = 0
	}
	c.mu.Lock()
	last := len(c.timers) - 1
	if last < 0 {
		c.mu.Unlock()
		timer := time.NewTimer(duration)
		return timer, timer.C
	}
	timer := c.timers[last]
	c.timers[last] = nil
	c.timers = c.timers[:last]
	c.mu.Unlock()
	timer.Reset(duration)
	return timer, timer.C
}

func (c *deadlineTimerCache) release(timer *time.Timer, consumed bool) {
	if timer == nil {
		return
	}
	if consumed {
		// The select received this generation's value, so the channel is
		// already empty even though Stop reports an expired timer.
		timer.Stop()
	} else if !timer.Stop() {
		// Go 1.20 requires an expired value to be drained before Reset. This
		// timer belongs exclusively to the current read until it is cached.
		<-timer.C
	}
	c.mu.Lock()
	if len(c.timers) < deadlineTimerCacheLimit {
		c.timers = append(c.timers, timer)
	}
	c.mu.Unlock()
}

// ownedTimer is a reusable timer consumed by exactly one actor goroutine. Its
// active bit distinguishes a tick already received by select from an expired
// tick that still has to be drained before Reset under Go 1.20 timer semantics.
type ownedTimer struct {
	timer  *time.Timer
	active bool
}

func newOwnedTimer() *ownedTimer {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	return &ownedTimer{timer: timer}
}

// reset replaces the deadline and returns the stable timer channel.
func (t *ownedTimer) reset(duration time.Duration) <-chan time.Time {
	t.stop()
	if duration < 0 {
		duration = 0
	}
	t.timer.Reset(duration)
	t.active = true
	return t.timer.C
}

// consumed records that select received the current tick.
func (t *ownedTimer) consumed() { t.active = false }

// stop prevents the current generation and drains an unconsumed expired tick.
func (t *ownedTimer) stop() {
	if !t.active {
		return
	}
	t.active = false
	if !t.timer.Stop() {
		<-t.timer.C
	}
}

func (t *ownedTimer) close() {
	t.stop()
	t.timer.Stop()
}

// outputQueue chooses local delivery when the destination belongs to this
// stack, otherwise the embedding link's packet queue.
func (s *Stack) outputQueue(packet []byte) (*packetQueue, bool) {
	if destination, ok := packetDestination(packet); ok && s.isLocal(destination) {
		return &s.loopback, true
	}
	return &s.outbound, false
}

// recordOutput updates the appropriate queue statistic.
func (s *Stack) recordOutput(loopback bool) {
	if loopback {
		s.stats.loopbackPackets.Add(1)
	} else {
		s.stats.outboundPackets.Add(1)
	}
}

// handleInboundPacket validates and reassembles one L3 packet before
// dispatching it to ICMP, TCP, UDP, or a raw IP endpoint. receivedAt is shared
// by packets from one device batch so transport timing does not depend on
// parsing order.
func (s *Stack) handleInboundPacket(packet []byte, receivedAt time.Time) error {
	s.stats.inboundPackets.Add(1)
	parsed, ok := parseIPPacket(packet)
	if !ok {
		if fragment, valid := parseFragment(packet); valid && s.isLocal(fragment.key.target) &&
			!fragment.key.source.IsUnspecified() && !fragment.key.source.IsMulticast() && !fragment.key.source.Is4In6() {
			if fragment.truncated || fragment.parameter {
				s.discardFragment(fragment.key)
				s.stats.inboundDroppedPackets.Add(1)
				code, at := byte(3), uint32(0)
				if fragment.parameter && !fragment.truncated {
					code, at = fragment.parameterCode, fragment.parameterAt
				}
				return s.sendParameterProblem(ipPacket{
					source: fragment.key.source, target: fragment.key.target, original: fragment.original,
					parameterError: true, parameterCode: code, parameterAt: at,
				})
			}
		}
		if reassembled, pending := s.reassemblePacketStatus(packet, receivedAt); reassembled != nil {
			parsed, ok = parseIPPacket(reassembled)
		} else if pending {
			return nil
		}
	}
	network := s.network.Load()
	limitedBroadcast := parsed.source.Is4() && parsed.source == netip.AddrFrom4([4]byte{255, 255, 255, 255})
	foreignLoopback := parsed.source.IsLoopback() && !networkStateHasLocal(network, parsed.source)
	localDestination := ok && networkStateHasLocal(network, parsed.target)
	invalidSource := ok && (parsed.source.IsUnspecified() || parsed.source.IsMulticast() || parsed.source.Is4In6() || limitedBroadcast ||
		network.invalidInboundSource(parsed.source) || foreignLoopback)
	if !ok || !localDestination || invalidSource {
		s.stats.inboundDroppedPackets.Add(1)
		if !ok {
			s.stats.invalidIPPackets.Add(1)
		} else {
			s.stats.unacceptedIPPackets.Add(1)
			if !localDestination {
				s.stats.nonlocalDestinationPackets.Add(1)
			} else {
				s.stats.invalidSourcePackets.Add(1)
			}
		}
		return nil
	}
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if parsed.parameterError {
		s.stats.inboundDroppedPackets.Add(1)
		return s.sendParameterProblem(parsed)
	}
	s.mu.RLock()
	ip := s.ip
	s.mu.RUnlock()
	rawDelivered := ip != nil && ip.deliver(s, parsed)
	switch parsed.protocol {
	case protocolTCP:
		return s.handleTCP(parsed, receivedAt)
	case protocolUDP:
		return s.handleUDP(parsed)
	case protocolICMPv4:
		if parsed.source.Is4() {
			return s.handleICMP(parsed)
		}
	case protocolICMPv6:
		if parsed.source.Is6() {
			return s.handleICMP(parsed)
		}
	default:
	}
	if parsed.protocol == 59 || rawDelivered {
		return nil
	}
	return s.sendProtocolUnreachable(parsed)
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
