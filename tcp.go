package mipstack

import (
	"context"
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
	tcpReceiveCapacity = 1024 * 1024
	// tcpSendCapacity bounds unacknowledged and not-yet-transmitted application
	// bytes retained by one connection.
	tcpSendCapacity = 256 * 1024
	// tcpMaximumReceiveCapacity and tcpMaximumSendCapacity bound automatic
	// buffer growth. Capacity is allocated only as application data arrives;
	// the limits therefore permit high-bandwidth-delay paths without charging
	// every mostly idle proxy connection up front.
	tcpMaximumReceiveCapacity = 16 * 1024 * 1024
	tcpMaximumSendCapacity    = 16 * 1024 * 1024
	// tcpMaximumOutOfOrder bounds retained receive-range metadata. The limit
	// accommodates a full default window split near IPv6's minimum MTU while
	// still bounding adversarial sparse one-byte ranges.
	tcpMaximumOutOfOrder = 4096
	// tcpInboundByteCapacity bounds the dynamically allocated actor queue. Two
	// maximum receive windows accommodate data and scheduler-delayed ACK bursts
	// after automatic window growth without charging idle connections up front.
	tcpInboundByteCapacity = 2 * tcpMaximumReceiveCapacity
	// tcpInboundSegmentMetadata accounts for one queued segment value and the
	// backing allocation shared by its option and payload slices.
	tcpInboundSegmentMetadata = 128
	// tcpAcceptQueue bounds completed passive handshakes waiting for Accept.
	tcpAcceptQueue = 128
	// tcpSYNBacklog bounds half-open and completed but unaccepted connections
	// owned by one listener.
	tcpSYNBacklog = 256
	// tcpMaximumRTOs matches Linux's default tcp_retries2 budget for
	// consecutive retransmission timeouts without cumulative acknowledgement
	// progress. Fast recovery, tail probes, and PMTU resegmentation do not
	// consume it.
	tcpMaximumRTOs = 15
	// tcpActiveSYNMaximumAttempts is the initial SYN plus Linux's default six
	// active-open retransmissions.
	tcpActiveSYNMaximumAttempts = 7
	// tcpPassiveSYNMaximumAttempts is the initial SYN-ACK plus Linux's default
	// five passive-open retransmissions.
	tcpPassiveSYNMaximumAttempts = 6
	// tcpBlackHoleTimeouts enters optional black-hole probing only after the
	// default Linux tcp_retries1 budget has been exceeded. Earlier timeouts are
	// ordinary congestion evidence and must not make a busy path reduce its
	// packet size merely because ICMP Packet Too Big was absent.
	tcpBlackHoleTimeouts = 4
	// tcpInitialRTO follows the RFC 6298 initial retransmission timeout.
	tcpInitialRTO = time.Second
	// tcpMinimumRTO avoids excessive retransmission on low-latency overlays.
	tcpMinimumRTO = 200 * time.Millisecond
	// tcpMaximumRTO matches Linux's maximum retry and zero-window-probe RTO.
	// It also satisfies RFC 6298's requirement that an optional cap be at
	// least 60 seconds.
	tcpMaximumRTO = 120 * time.Second
	// tcpDelayedACKTimeout bounds acknowledgement delay for in-order data and
	// non-critical receive-window growth.
	tcpDelayedACKTimeout = 25 * time.Millisecond
	// tcpTimeWaitDuration retains a completed tuple for twice the conventional
	// 30-second maximum segment lifetime.
	tcpTimeWaitDuration = 60 * time.Second
	// tcpFINWaitDuration bounds orphaned FIN_WAIT_2 resource retention. A
	// connection retained by an application after CloseWrite has no such
	// timeout and may continue receiving until the peer closes.
	tcpFINWaitDuration = 60 * time.Second
	// tcpInitialCongestionMSS is the RFC 6928 upper initial-window bound.
	tcpInitialCongestionMSS = 10
	// tcpDuplicateACKThreshold is the RFC 5681 fast-retransmit threshold and
	// RFC 6675 packet-count loss threshold.
	tcpDuplicateACKThreshold = 3
	// tcpMinimumPeerMSS matches Linux's default tcp_min_snd_mss. Accepting a
	// one-byte advertised MSS lets an untrusted peer amplify ordinary buffered
	// writes into hundreds of thousands of packets and scoreboard entries.
	// A smaller path-derived MSS still wins when the managed MTU requires it.
	tcpMinimumPeerMSS = 48
	// tcpMaximumSACKSplitRanges bounds metadata created solely by adversarial
	// byte-granular SACK edges. Once reached, a partially covered transmission
	// remains unsacked and is conservatively retransmitted as a whole.
	tcpMaximumSACKSplitRanges = 1024
	// tcpDefaultKeepAliveIdle is the initial inactivity before probes.
	tcpDefaultKeepAliveIdle = 2 * time.Hour
	// tcpDefaultKeepAliveInterval spaces unanswered probes.
	tcpDefaultKeepAliveInterval = 75 * time.Second
	// tcpDefaultKeepAliveCount bounds unanswered probes.
	tcpDefaultKeepAliveCount = 9
	// tcpMaximumScaledWindow is the largest receive window representable by
	// TCP's 16-bit window and maximum negotiated scale.
	tcpMaximumScaledWindow = uint32(65535) << 14
	// tcpPLPMTUProbeThreshold matches Linux's default binary-search stopping
	// interval. Smaller packet-size gains do not justify another loss probe.
	tcpPLPMTUProbeThreshold = 8
	// tcpPLPMTUProbeMinimumInterval rate limits congestion-response suppression
	// after an isolated failed probe.
	tcpPLPMTUProbeMinimumInterval = time.Second
	// tcpAutoTuneMinimumInterval smooths short-RTT ACK and read batches across
	// normal userspace scheduling intervals.
	// It is an observation interval, not a wake-up timer; RTT normalization
	// still preserves the measured BDP on genuinely fast paths.
	tcpAutoTuneMinimumInterval = 10 * time.Millisecond
	// tcpHostQueueRetryInterval defers a loss timer while the candidate packet
	// is still waiting in mipstack's output FIFO. This mirrors Linux's local-
	// congestion retry without changing the packet's RACK transmission time.
	tcpHostQueueRetryInterval = 10 * time.Millisecond
	// tcpEifelClockGranularity is the timestamp and retransmission-timer clock
	// granularity used by the RFC 4015 response.
	tcpEifelClockGranularity = time.Millisecond
	// tcpRetransmissionHistoryLimit retains enough recent wire ranges to
	// distinguish late DSACK feedback from network duplication without making
	// a loss-heavy connection's memory use unbounded.
	tcpRetransmissionHistoryLimit = 128
	// tcpMinimumRTTWindow matches Linux's default tcp_min_rtt_wlen. RFC 8985
	// recommends a windowed minimum so RACK can adapt after migration to a
	// persistently longer path.
	tcpMinimumRTTWindow = 300 * time.Second
)

// KeepAliveConfig configures TCP keepalive probing. Every field must be
// positive when supplied to SetKeepAliveConfig.
type KeepAliveConfig struct {
	Idle     time.Duration
	Interval time.Duration
	Count    int
}

// TCPState identifies the current RFC 9293 connection state exposed by
// TCPConn.Info.
type TCPState uint8

const (
	// TCPStateClosed indicates that no connection state remains.
	TCPStateClosed TCPState = iota
	// TCPStateSYNReceived indicates a passive handshake awaiting its final ACK.
	TCPStateSYNReceived
	// TCPStateSYNSent indicates an active handshake awaiting a SYN-ACK.
	TCPStateSYNSent
	// TCPStateEstablished indicates bidirectional data transfer state.
	TCPStateEstablished
	// TCPStateFINWait1 indicates that the local FIN is not yet acknowledged.
	TCPStateFINWait1
	// TCPStateFINWait2 indicates that the local FIN is acknowledged while the peer remains open.
	TCPStateFINWait2
	// TCPStateCloseWait indicates that the peer closed first.
	TCPStateCloseWait
	// TCPStateClosing indicates simultaneous close awaiting the local FIN ACK.
	TCPStateClosing
	// TCPStateLastACK indicates a locally sent FIN after the peer closed first.
	TCPStateLastACK
	// TCPStateTimeWait indicates retained state after an active or simultaneous close.
	TCPStateTimeWait
)

// String returns the conventional RFC 9293 state name.
func (s TCPState) String() string {
	switch s {
	case TCPStateSYNReceived:
		return "SYN-RECEIVED"
	case TCPStateSYNSent:
		return "SYN-SENT"
	case TCPStateEstablished:
		return "ESTABLISHED"
	case TCPStateFINWait1:
		return "FIN-WAIT-1"
	case TCPStateFINWait2:
		return "FIN-WAIT-2"
	case TCPStateCloseWait:
		return "CLOSE-WAIT"
	case TCPStateClosing:
		return "CLOSING"
	case TCPStateLastACK:
		return "LAST-ACK"
	case TCPStateTimeWait:
		return "TIME-WAIT"
	default:
		return "CLOSED"
	}
}

// TCPInfo is a consistent point-in-time diagnostic snapshot of one TCP
// connection. Window, congestion, buffer, and path sizes are measured in
// bytes; PathMTU and MaximumSegmentSize include and exclude IP/TCP headers,
// respectively.
type TCPInfo struct {
	LocalAddress           netip.AddrPort
	RemoteAddress          netip.AddrPort
	State                  TCPState
	CongestionControl      CongestionControl
	RTT                    time.Duration
	MinimumRTT             time.Duration
	RTTVariation           time.Duration
	RetransmissionTimeout  time.Duration
	CongestionWindow       uint32
	SlowStartThreshold     uint32
	BytesInFlight          uint32
	PeerWindow             uint32
	ReceiveWindow          uint32
	MaximumSegmentSize     int
	PathMTU                int
	SendBufferSize         int
	SendBufferCapacity     int
	MaximumSendBuffer      int
	ReceiveBufferSize      int
	ReceiveBufferCapacity  int
	MaximumReceiveBuffer   int
	BytesSent              uint64
	BytesAcknowledged      uint64
	BytesReceived          uint64
	Retransmissions        uint64
	InboundQueueDrops      uint64
	InboundQueueBytes      int64
	InboundQueuePeak       int64
	InboundQueueCapacity   int
	FastRecovery           bool
	RetransmissionRecovery bool
	HyStartCSS             bool
	PathMTUDiscovery       bool
	PathMTUProbe           int
	WindowScaling          bool
	PeerWindowScale        uint8
	ReceiveWindowScale     uint8
	SACK                   bool
	Timestamps             bool
	ECN                    bool
	KeepAlive              bool
	KeepAliveConfig        KeepAliveConfig
	IdleTimeout            time.Duration
	UserTimeout            time.Duration
	NoDelay                bool
	TrafficClass           uint8
	SpuriousRecoveryUndos  uint64
	PathMTUProbes          uint64
	PathMTUProbeSuccesses  uint64
	PathMTUProbeFailures   uint64
	LastError              error
}

// tcpSocketOptions is one lock-protected option snapshot.
type tcpSocketOptions struct {
	keepAlive       bool
	keepAliveConfig KeepAliveConfig
	idleTimeout     time.Duration
	userTimeout     time.Duration
	noDelay         bool
	congestion      CongestionControl
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
	retainedBytes   int64
	receivedAt      time.Time
}

// tcpSegmentQueue is a byte-bounded FIFO with allocation proportional to
// actual traffic rather than a large channel allocation on every connection.
type tcpSegmentQueue struct {
	mu       sync.Mutex
	segments []tcpSegment
	head     int
	bytes    int64
	peak     int64
	closed   bool
	notify   chan struct{}
}

// newTCPSegmentQueue constructs an empty queue with an edge-triggered wakeup.
func newTCPSegmentQueue() tcpSegmentQueue {
	return tcpSegmentQueue{notify: make(chan struct{}, 1)}
}

// enqueue retains one segment if the byte bound permits it.
func (q *tcpSegmentQueue) enqueue(segment tcpSegment) bool {
	retained := int64(tcpInboundSegmentMetadata + len(segment.options) + len(segment.payload))
	q.mu.Lock()
	if q.closed || retained > tcpInboundByteCapacity || q.bytes > int64(tcpInboundByteCapacity)-retained {
		q.mu.Unlock()
		return false
	}
	empty := q.head == len(q.segments)
	segment.retainedBytes = retained
	q.segments = append(q.segments, segment)
	q.bytes += retained
	if q.bytes > q.peak {
		q.peak = q.bytes
	}
	if empty {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	q.mu.Unlock()
	return true
}

// prepend returns an actor-owned segment to the front when handshake state
// hands a data-bearing completion segment to the established state machine.
func (q *tcpSegmentQueue) prepend(segment tcpSegment) bool {
	retained := int64(tcpInboundSegmentMetadata + len(segment.options) + len(segment.payload))
	segment.retainedBytes = retained
	q.mu.Lock()
	if q.closed || retained > tcpInboundByteCapacity || q.bytes > int64(tcpInboundByteCapacity)-retained {
		q.mu.Unlock()
		return false
	}
	empty := q.head == len(q.segments)
	if q.head != 0 {
		q.head--
		q.segments[q.head] = segment
	} else {
		q.segments = append(q.segments, tcpSegment{})
		copy(q.segments[1:], q.segments[:len(q.segments)-1])
		q.segments[0] = segment
	}
	q.bytes += retained
	if empty {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	q.mu.Unlock()
	return true
}

// dequeue removes one segment and keeps a wakeup armed while work remains.
func (q *tcpSegmentQueue) dequeue() (tcpSegment, bool) {
	q.mu.Lock()
	if q.head == len(q.segments) {
		q.mu.Unlock()
		return tcpSegment{}, false
	}
	segment := q.segments[q.head]
	q.segments[q.head] = tcpSegment{}
	q.head++
	q.bytes -= segment.retainedBytes
	segment.retainedBytes = 0
	if q.head == len(q.segments) {
		q.segments = nil
		q.head = 0
	} else {
		if q.head >= 1024 && q.head*2 >= len(q.segments) {
			copy(q.segments, q.segments[q.head:])
			q.segments = q.segments[:len(q.segments)-q.head]
			q.head = 0
		}
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	q.mu.Unlock()
	return segment, true
}

// len returns the number of segments waiting for the actor.
func (q *tcpSegmentQueue) len() int {
	q.mu.Lock()
	length := len(q.segments) - q.head
	q.mu.Unlock()
	return length
}

// retainedBytes returns the approximate memory retained by queued segments.
func (q *tcpSegmentQueue) retainedBytes() int64 {
	q.mu.Lock()
	retained := q.bytes
	q.mu.Unlock()
	return retained
}

// peakBytes returns the largest approximate memory occupancy observed.
func (q *tcpSegmentQueue) peakBytes() int64 {
	q.mu.Lock()
	peak := q.peak
	q.mu.Unlock()
	return peak
}

// close releases every queued packet and rejects later delivery while
// retaining lifetime diagnostics.
func (q *tcpSegmentQueue) close() {
	q.mu.Lock()
	q.segments = nil
	q.head = 0
	q.bytes = 0
	q.closed = true
	q.mu.Unlock()
}

// tcpTimerBacklog gives receive work that was already queued when a timer
// expired one bounded turn ahead of that timer. Packets arriving during the
// turn are not added, so a continuously refilled queue cannot starve timers.
type tcpTimerBacklog struct {
	deadline  time.Time
	remaining int
}

// order reports whether to drain the captured receive snapshot or force the
// expired timer. A changed or newly expired deadline starts a fresh snapshot.
func (b *tcpTimerBacklog) order(queueLength int, deadline, now time.Time) (drain, forceTimer bool) {
	if deadline.IsZero() || now.Before(deadline) {
		b.deadline = time.Time{}
		b.remaining = 0
		return false, false
	}
	if b.deadline.IsZero() || !b.deadline.Equal(deadline) {
		b.deadline = deadline
		b.remaining = queueLength
	}
	return b.remaining != 0, b.remaining == 0
}

// consumed advances the fixed receive snapshot without counting later input.
func (b *tcpTimerBacklog) consumed() {
	if b.remaining > 0 {
		b.remaining--
	}
}

// tcpZeroWindowProbe is an allocation-free acknowledged byte used to elicit
// a current window advertisement from a peer.
var tcpZeroWindowProbe = [...]byte{0}

// tcpReceiveWindow retains the furthest receive sequence promised to the
// peer. Buffer occupancy may reduce newly available space, but it must not
// move an already advertised right edge backwards.
type tcpReceiveWindow struct {
	right uint32
	shift uint8
}

// newTCPReceiveWindow starts with the last window sent during the handshake
// and the scale advertised by this endpoint. A SYN-ACK is unscaled, while an
// active opener's final ACK is scaled.
func newTCPReceiveWindow(receiveNext uint32, initial uint16, scaled, initialScaled bool, scale uint8) tcpReceiveWindow {
	initialBytes := uint32(initial)
	window := tcpReceiveWindow{}
	if scaled {
		window.shift = scale
	}
	if initialScaled {
		initialBytes <<= window.shift
	}
	window.right = receiveNext + initialBytes
	return window
}

// tcpReceiveWindowScaleFor selects the smallest RFC 7323 scale capable of
// advertising the configured automatic receive ceiling. Keeping the scale
// minimal preserves window precision for deliberately small socket policies.
func tcpReceiveWindowScaleFor(maximum int) uint8 {
	if maximum <= 65535 {
		return 0
	}
	var scale uint8
	for scale < 14 && uint64(65535)<<scale < uint64(maximum) {
		scale++
	}
	return scale
}

// next returns the wire window that would be advertised with the currently
// available storage, without committing that promise until a segment is sent.
func (w *tcpReceiveWindow) next(receiveNext uint32, available, minimumIncrease int) (uint16, uint32) {
	if available < 0 {
		available = 0
	}
	maximum := uint32(65535) << w.shift
	if uint64(available) > uint64(maximum) {
		available = int(maximum)
	}
	desired := receiveNext + uint32(available>>w.shift)<<w.shift
	right := w.right
	if tcpSequenceGreater(desired, right) {
		increase := desired - right
		if minimumIncrease < 0 {
			minimumIncrease = 0
		}
		if increase >= uint32(minimumIncrease) {
			right = desired
		}
	}
	if tcpSequenceLess(right, receiveNext) {
		return 0, right
	}
	return uint16((right - receiveNext) >> w.shift), right
}

// advertise commits and returns the window carried by an outgoing segment.
func (w *tcpReceiveWindow) advertise(receiveNext uint32, available, minimumIncrease int) uint16 {
	window, right := w.next(receiveNext, available, minimumIncrease)
	w.right = right
	return window
}

// size returns the receive sequence space covered by prior advertisements.
func (w *tcpReceiveWindow) size(receiveNext uint32) uint32 {
	if tcpSequenceLess(w.right, receiveNext) {
		return 0
	}
	return w.right - receiveNext
}

// tcpReceiveWindowIncrease is the RFC 1122 receiver SWS threshold:
// min(one half of the receive buffer, one expected segment).
func tcpReceiveWindowIncrease(capacity, mss int) int {
	if capacity < 1 {
		return 0
	}
	threshold := capacity/2 + capacity%2
	if mss > 0 && threshold > mss {
		threshold = mss
	}
	return threshold
}

// tcpBufferAutoTune measures useful byte progress over an RTT. Receive tuning
// supplies application-consumed bytes; send tuning supplies acknowledged
// bytes. Queue or congestion-window size alone is not evidence that a larger
// application buffer improves throughput.
type tcpBufferAutoTune struct {
	updated time.Time
	bytes   uint64
}

// target returns twice the measured per-RTT progress, leaving one BDP queued
// while the preceding BDP is consumed or acknowledged.
func (t *tcpBufferAutoTune) target(now time.Time, rtt time.Duration, total uint64, maximum int) int {
	if rtt <= 0 {
		return 0
	}
	if t.updated.IsZero() {
		t.updated, t.bytes = now, total
		return 0
	}
	elapsed := now.Sub(t.updated)
	interval := rtt
	if interval < tcpAutoTuneMinimumInterval {
		interval = tcpAutoTuneMinimumInterval
	}
	if elapsed < interval {
		return 0
	}
	delta := total - t.bytes
	t.updated, t.bytes = now, total
	if delta == 0 {
		return 0
	}
	// Normalize a delayed observation to one RTT so a suspended userspace
	// actor cannot interpret many intervals of reads as one enormous BDP.
	perRTT := delta
	if elapsed > rtt {
		perRTT = uint64(float64(delta) * float64(rtt) / float64(elapsed))
	}
	if maximum <= 0 {
		return 0
	}
	if perRTT > uint64(maximum/2) {
		perRTT = uint64(maximum / 2)
	}
	return int(perRTT * 2)
}

// sentTCPSegment retains retransmission state for one sequence range.
type sentTCPSegment struct {
	sequence      uint32
	end           uint32
	flags         byte
	payload       []byte
	sentAt        time.Time
	timestamp     uint32
	firstSentAt   time.Time
	transmissions int
	sacked        bool
	sackRetried   bool
	rackLost      bool
	limited       bool
	cwr           bool
	sackSplit     bool
	mtuProbe      bool
	probeMTU      int
	hostQueue     packetQueueTicket
}

// tcpPLPMTU is one RFC 4821 binary-search episode. Sizes include the IP and
// TCP headers, matching the specification's Probe_Size definition.
type tcpPLPMTU struct {
	searchLow  int
	searchHigh int
	probeMTU   int
	probeStart uint32
	probeEnd   uint32
	nextProbe  time.Time
	searching  bool
	active     bool
}

// start begins an upward search without changing the confirmed effective MTU.
func (p *tcpPLPMTU) start(base, maximum int, now time.Time) {
	if maximum-base < tcpPLPMTUProbeThreshold {
		*p = tcpPLPMTU{}
		return
	}
	*p = tcpPLPMTU{searchLow: base, searchHigh: maximum, nextProbe: now, searching: true}
}

// candidate returns the midpoint packet size when another probe is useful.
func (p *tcpPLPMTU) candidate(now time.Time) (int, bool) {
	if !p.searching || p.active || now.Before(p.nextProbe) || p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		return 0, false
	}
	return p.searchLow + (p.searchHigh-p.searchLow+1)/2, true
}

// sent records the exact sequence interval carried by a probe.
func (p *tcpPLPMTU) sent(mtu int, start, end uint32) {
	p.probeMTU, p.probeStart, p.probeEnd, p.active = mtu, start, end, true
}

// success raises the confirmed lower bound and permits the next binary probe.
func (p *tcpPLPMTU) success(now time.Time) int {
	mtu := p.probeMTU
	p.searchLow = mtu
	p.active = false
	p.probeMTU = 0
	p.nextProbe = now
	if p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		p.searching = false
	}
	return mtu
}

// failed lowers the upper search bound after an isolated probe loss and
// enforces RFC 4821's TCP-friendly suppression headway.
func (p *tcpPLPMTU) failed(now time.Time, headway time.Duration) {
	if p.probeMTU > 0 && p.probeMTU-1 < p.searchHigh {
		p.searchHigh = p.probeMTU - 1
	}
	p.active = false
	p.probeMTU = 0
	if headway < tcpPLPMTUProbeMinimumInterval {
		headway = tcpPLPMTUProbeMinimumInterval
	}
	p.nextProbe = now.Add(headway)
	if p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		p.searching = false
	}
}

// inconclusive cancels one probe without narrowing the search. A timeout or
// concurrent loss remains ordinary congestion evidence under RFC 4821.
func (p *tcpPLPMTU) inconclusive(now time.Time, delay time.Duration) {
	p.active = false
	p.probeMTU = 0
	if delay < tcpPLPMTUProbeMinimumInterval {
		delay = tcpPLPMTUProbeMinimumInterval
	}
	p.nextProbe = now.Add(delay)
}

// tcpPLPMTUProbeHeadway returns one RTT per packet permitted by cwnd, the
// RFC 4821 estimate of the interval between TCP-friendly congestion events.
func tcpPLPMTUProbeHeadway(window uint32, mss int, roundTrip time.Duration) time.Duration {
	if mss < 1 {
		mss = 1
	}
	if roundTrip <= 0 {
		roundTrip = tcpInitialRTO
	}
	packets := (uint64(window) + uint64(mss) - 1) / uint64(mss)
	if packets == 0 {
		packets = 1
	}
	const maximum = time.Duration(1<<63 - 1)
	if packets > uint64(maximum/roundTrip) {
		return maximum
	}
	headway := time.Duration(packets) * roundTrip
	if headway < tcpPLPMTUProbeMinimumInterval {
		return tcpPLPMTUProbeMinimumInterval
	}
	return headway
}

// tcpPLPMTUTimeoutDelay applies RFC 4821's recommended five-times backoff
// after a timeout made a probe outcome inconclusive.
func tcpPLPMTUTimeoutDelay(headway time.Duration) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	if headway > maximum/5 {
		return maximum
	}
	return 5 * headway
}

// tcpCongestionValueForMSS preserves a congestion value in bytes when MSS
// grows and preserves its packet count when MSS shrinks, as required by RFC
// 4821. A live congestion window retains a one-packet floor.
func tcpCongestionValueForMSS(value uint32, oldMSS, newMSS int, floor bool) uint32 {
	if value == 0 || oldMSS < 1 || newMSS < 1 || newMSS >= oldMSS {
		return value
	}
	value = uint32(uint64(value) * uint64(newMSS) / uint64(oldMSS))
	if floor && value < uint32(newMSS) {
		return uint32(newMSS)
	}
	return value
}

// reduce restarts future upward search from a newly confirmed lower PMTU.
func (p *tcpPLPMTU) reduce(mtu, prior, maximum int, now time.Time) {
	high := maximum
	if prior > mtu && prior-1 < high {
		high = prior - 1
	}
	p.start(mtu, high, now.Add(pathMTULifetime))
}

// tcpUndoRange tracks one sequence interval retransmitted in a recovery
// episode. RFC 3708 permits undo only after every such interval is reported
// duplicated and rejects intervals retransmitted more than once.
type tcpUndoRange struct {
	sequence   uint32
	end        uint32
	duplicated bool
}

// tcpRecoveryUndo retains the pre-recovery state needed by RFC 3522/4015
// Eifel response and the conservative RFC 3708 DSACK disambiguation.
type tcpRecoveryUndo struct {
	active              bool
	timeout             bool
	eifelChecked        bool
	dsackDisabled       bool
	retransmitTimestamp uint32
	point               uint32
	priorWindow         uint32
	priorThreshold      uint32
	priorFlight         uint32
	priorController     tcpCongestionController
	priorRTT            rttEstimator
	ranges              []tcpUndoRange
}

// tcpEifelRTOResponse retains RFC 4015 step 11 until an RTT sample from data
// that had not been sent when the spurious timeout occurred is available.
type tcpEifelRTOResponse struct {
	point          uint32
	previousSRTT   time.Duration
	previousRTTVar time.Duration
	pending        bool
}

// tcpRetransmissionRecord is one recently retransmitted wire range. Count is
// greater than one when retransmission ambiguity forbids an RFC 3708 undo.
type tcpRetransmissionRecord struct {
	sequence uint32
	end      uint32
	count    int
}

// tcpRetransmissionHistory keeps the slightly longer history required by RFC
// 3708 after ranges leave the ordinary SACK scoreboard.
type tcpRetransmissionHistory struct {
	ranges []tcpRetransmissionRecord
}

// begin snapshots congestion state before the first reduction in an episode.
func (u *tcpRecoveryUndo) begin(timeout bool, point, window, threshold, flight uint32, controller tcpCongestionController, rtt rttEstimator) {
	*u = tcpRecoveryUndo{
		active: true, timeout: timeout, point: point, priorWindow: window,
		priorThreshold: threshold, priorFlight: flight, priorController: controller, priorRTT: rtt,
	}
}

// recordRetransmission adds one exact wire range and the first retransmission
// timestamp. Repeating a retransmission makes DSACK undo ambiguous.
func (u *tcpRecoveryUndo) recordRetransmission(sequence, end, timestamp uint32, repeated bool) {
	if !u.active {
		return
	}
	if repeated {
		u.dsackDisabled = true
	}
	if u.retransmitTimestamp == 0 {
		u.retransmitTimestamp = timestamp
	}
	for index := range u.ranges {
		candidate := &u.ranges[index]
		if candidate.sequence == sequence && candidate.end == end {
			return
		}
	}
	u.ranges = append(u.ranges, tcpUndoRange{sequence: sequence, end: end})
}

// detectEifel applies RFC 3522's conservative timestamp test to the first
// acceptable ACK after recovery starts. A current DSACK is left to RFC 3708.
func (u *tcpRecoveryUndo) detectEifel(timestampEcho uint32, currentDSACK, priorDSACK bool, acknowledgement uint32) bool {
	if !u.active || u.eifelChecked || u.retransmitTimestamp == 0 || timestampEcho == 0 {
		return false
	}
	u.eifelChecked = true
	if !tcpSequenceLess(timestampEcho, u.retransmitTimestamp) || currentDSACK {
		return false
	}
	return priorDSACK || tcpSequenceLess(acknowledgement, u.point)
}

// observeDSACK marks retransmitted ranges and reports when RFC 3708 has
// accounted every retransmission in the recovery window as duplicated.
func (u *tcpRecoveryUndo) observeDSACK(block tcpSACKBlock, acknowledgement, sendUnacknowledged uint32, scoreboardEmpty bool) bool {
	if !u.active || u.dsackDisabled {
		return false
	}
	if scoreboardEmpty && block.left == sendUnacknowledged {
		// RFC 3708 A.1 treats loss of an entire ACK window as reverse-path
		// congestion, so this recovery episode must not be undone.
		u.dsackDisabled = true
		return false
	}
	matched := false
	for index := range u.ranges {
		candidate := &u.ranges[index]
		if tcpSequenceLessEqual(block.left, candidate.sequence) && tcpSequenceGreaterEqual(block.right, candidate.end) {
			candidate.duplicated = true
			matched = true
		}
	}
	if !matched {
		// RFC 3708 treats a DSACK for data that this sender did not retransmit
		// as evidence of network duplication and disables DSACK-based undo.
		u.dsackDisabled = true
		return false
	}
	if len(u.ranges) == 0 {
		return false
	}
	for _, candidate := range u.ranges {
		if !candidate.duplicated || tcpSequenceLess(acknowledgement, candidate.end) {
			return false
		}
	}
	return true
}

// restore computes RFC 4015's bounded post-undo cwnd and restores the
// pre-recovery controller model and safe threshold. The acknowledged-byte
// burst is capped by the initial window.
func (u *tcpRecoveryUndo) restore(flight, acknowledged uint32, mss int) (uint32, uint32, tcpCongestionController) {
	credit := acknowledged
	if initial := initialTCPWindow(mss); credit > initial {
		credit = initial
	}
	window := growCongestionWindow(flight, credit)
	if window < uint32(mss) {
		window = uint32(mss)
	}
	threshold := u.priorFlight
	if threshold < u.priorThreshold {
		threshold = u.priorThreshold
	}
	controller := u.priorController
	u.active = false
	return window, threshold, controller
}

// eifelRTOResponse constructs the delayed RFC 4015 timer response for a
// timeout recovery. Fast-retransmit undo does not alter the RTT estimator.
func (u *tcpRecoveryUndo) eifelRTOResponse() tcpEifelRTOResponse {
	if !u.timeout {
		return tcpEifelRTOResponse{}
	}
	return tcpEifelRTOResponse{
		point: u.point, previousSRTT: u.priorRTT.srtt + 2*tcpEifelClockGranularity,
		previousRTTVar: u.priorRTT.variation, pending: true,
	}
}

// observe applies RFC 4015 step 11 to the first valid RTT sample covering
// data beyond the recovery point.
func (e *tcpEifelRTOResponse) observe(acknowledgement uint32, sample time.Duration, rtt *rttEstimator) bool {
	if !e.pending || sample <= 0 || !tcpSequenceGreater(acknowledgement, e.point) {
		return false
	}
	sample = normalizedRTTSample(sample)
	rtt.srtt = e.previousSRTT
	if rtt.srtt < sample {
		rtt.srtt = sample
	}
	rtt.variation = e.previousRTTVar
	if half := sample / 2; rtt.variation < half {
		rtt.variation = half
	}
	rtt.initialized = true
	rtt.updateRTO()
	e.pending = false
	return true
}

// record retains one retransmitted range and counts repeated retransmissions.
func (h *tcpRetransmissionHistory) record(sequence, end uint32) {
	for index := len(h.ranges) - 1; index >= 0; index-- {
		rangeState := &h.ranges[index]
		if rangeState.sequence == sequence && rangeState.end == end {
			rangeState.count++
			return
		}
	}
	repeated := false
	for index := range h.ranges {
		rangeState := &h.ranges[index]
		if tcpSequenceLess(sequence, rangeState.end) && tcpSequenceLess(rangeState.sequence, end) {
			repeated = true
			if rangeState.count < 2 {
				rangeState.count = 2
			}
		}
	}
	if len(h.ranges) == tcpRetransmissionHistoryLimit {
		copy(h.ranges, h.ranges[1:])
		h.ranges = h.ranges[:len(h.ranges)-1]
	}
	count := 1
	if repeated {
		count = 2
	}
	h.ranges = append(h.ranges, tcpRetransmissionRecord{sequence: sequence, end: end, count: count})
}

// match reports whether a DSACK covers a known retransmission and whether
// that range was retransmitted more than once.
func (h *tcpRetransmissionHistory) match(block tcpSACKBlock) (bool, bool) {
	matched, repeated := false, false
	for _, rangeState := range h.ranges {
		if tcpSequenceLessEqual(block.left, rangeState.sequence) && tcpSequenceGreaterEqual(block.right, rangeState.end) {
			matched = true
			repeated = repeated || rangeState.count > 1
		}
	}
	return matched, repeated
}

// tcpRACKSample identifies the newest transmission known to have been
// delivered. RFC 8985 orders equal transmit timestamps by sequence number.
type tcpRACKSample struct {
	sentAt        time.Time
	end           uint32
	rtt           time.Duration
	timestamp     uint32
	retransmitted bool
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

	inbound           tcpSegmentQueue
	networkError      chan error
	pathMTUUpdate     chan struct{}
	sendNotify        chan struct{}
	windowUpdate      chan struct{}
	abortCh           chan struct{}
	done              chan struct{}
	connected         chan error
	lingerDone        chan struct{}
	infoRequest       chan chan TCPInfo
	abortOnce         sync.Once
	closeOnce         sync.Once
	lingerOnce        sync.Once
	readCallMu        sync.Mutex
	writeCallMu       sync.Mutex
	icmpSequence      atomic.Uint64
	applicationReads  atomic.Uint64
	outOfOrderUnread  atomic.Int64
	retransmissions   atomic.Uint64
	inboundQueueDrops atomic.Uint64
	lastInfo          atomic.Pointer[TCPInfo]
	sendCapacityHint  atomic.Int64

	abortMu  sync.Mutex
	abortErr error
	abortRST bool

	mu                 sync.Mutex
	readBuffer         []byte
	readErr            error
	terminalErr        error
	userClosed         bool
	readClosed         bool
	writeClosed        bool
	readDeadline       time.Time
	writeDeadline      time.Time
	readChanged        chan struct{}
	writeChanged       chan struct{}
	readNotify         chan struct{}
	sendChanged        chan struct{}
	sendBuffer         []byte
	optionsChanged     chan struct{}
	receiveCapacity    int
	sendCapacity       int
	receiveMaximum     int
	sendMaximum        int
	receiveAutoTune    bool
	sendAutoTune       bool
	keepAlive          bool
	keepAliveConfig    KeepAliveConfig
	idleTimeout        time.Duration
	userTimeout        time.Duration
	noDelay            bool
	congestion         CongestionControl
	congestionUser     bool
	receiveWindowScale uint8
	trafficClass       atomic.Uint32
	linger             int

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
	handshakeRTT      time.Duration
	handshakeTimeout  bool
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
// registry. Stack.mu protects endpoint registries; cookieMu protects the
// cookie key and recent-issuance period.
type tcpPassiveState struct {
	exclusive           map[tcpListenKey]*TCPListener
	reuse               tcpReuseEndpoints
	cookieMu            sync.Mutex
	cookieKey           [16]byte
	cookieSet           bool
	cookieEpoch         time.Time
	cookiePeriod        uint64
	cookieActive        bool
	cookieScaleSet      bool
	cookieScalePeriod   uint64
	cookieWindowScale   uint8
	previousScaleSet    bool
	previousScalePeriod uint64
	previousWindowScale uint8
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

	accept  chan *TCPConn
	closed  chan struct{}
	once    sync.Once
	backlog int

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
	target := net.TCPAddrFromAddrPort(local)
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
		stack: s, key: key, local: local, dual: dual, net: network, accept: make(chan *TCPConn, state.tcpDefaults.AcceptQueue), backlog: state.tcpDefaults.SYNBacklog,
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

// portListened implements the passive-endpoint query without exposing the
// listener registry to dial-only builds.
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
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			select {
			case <-changed:
				continue
			default:
				return nil, l.operationError("accept", os.ErrDeadlineExceeded)
			}
		}
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
	if len(l.pending) >= l.backlog {
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
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	select {
	case l.accept <- connection:
		return true
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
	target := net.TCPAddrFromAddrPort(remote)
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
	initialSequence := s.tcpInitialSequence(key, time.Now())
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
	defaults, _ := normalizeTCPSocketDefaults(TCPSocketDefaults{})
	if stack != nil {
		state := stack.network.Load()
		defaults = state.tcpDefaults
	}
	connection := &TCPConn{
		stack: stack, net: network, key: key, mtu: mtu,
		inbound: newTCPSegmentQueue(), networkError: make(chan error, 8), pathMTUUpdate: make(chan struct{}, 1),
		sendNotify: make(chan struct{}, 1), windowUpdate: make(chan struct{}, 1),
		abortCh: make(chan struct{}), done: make(chan struct{}), connected: make(chan error, 1), lingerDone: make(chan struct{}),
		infoRequest: make(chan chan TCPInfo),
		readChanged: make(chan struct{}), writeChanged: make(chan struct{}), readNotify: make(chan struct{}), sendChanged: make(chan struct{}),
		optionsChanged: make(chan struct{}, 1), noDelay: !defaults.DisableNoDelay, linger: -1,
		receiveCapacity: defaults.ReceiveBuffer, sendCapacity: defaults.SendBuffer,
		receiveMaximum: defaults.MaximumReceiveBuffer, sendMaximum: defaults.MaximumSendBuffer,
		receiveAutoTune: defaults.MaximumReceiveBuffer > defaults.ReceiveBuffer,
		sendAutoTune:    defaults.MaximumSendBuffer > defaults.SendBuffer,
		keepAlive:       defaults.KeepAlive, keepAliveConfig: defaults.KeepAliveConfig,
		idleTimeout: defaults.IdleTimeout, userTimeout: defaults.UserTimeout, congestion: defaults.CongestionControl,
		receiveWindowScale: tcpReceiveWindowScaleFor(defaults.MaximumReceiveBuffer),
	}
	connection.trafficClass.Store(uint32(defaults.TrafficClass))
	connection.sendCapacityHint.Store(int64(defaults.SendBuffer))
	return connection
}

// tcpTimestamp returns a wrapping millisecond clock suitable for TSval.
func (s *Stack) tcpTimestamp() uint32 {
	return s.tcpTimestampAt(time.Now())
}

// tcpTimestampAt converts one internal monotonic event time to a wire TSval.
func (s *Stack) tcpTimestampAt(now time.Time) uint32 {
	return uint32(now.Sub(s.timestampEpoch)/time.Millisecond) + 1
}

// tcpInitialSequence implements RFC 6528's M+F(connection-id, secret)
// construction. M advances every four microseconds and wraps in sequence
// space; SipHash supplies the keyed pseudorandom per-four-tuple offset.
func (s *Stack) tcpInitialSequence(key tcpKey, now time.Time) uint32 {
	var connectionID [37]byte
	if key.local.Addr().Is6() {
		connectionID[0] = 6
	} else {
		connectionID[0] = 4
	}
	local := key.local.Addr().As16()
	remote := key.remote.Addr().As16()
	copy(connectionID[1:17], local[:])
	copy(connectionID[17:33], remote[:])
	binary.BigEndian.PutUint16(connectionID[33:35], key.local.Port())
	binary.BigEndian.PutUint16(connectionID[35:37], key.remote.Port())
	elapsed := now.Sub(s.timestampEpoch)
	var timer uint32
	if elapsed > 0 {
		timer = uint32(elapsed / (4 * time.Microsecond))
	}
	return timer + uint32(sipHash24(s.tcpISNSecret, connectionID[:]))
}

// handleTCP validates a segment, dispatches it by four-tuple, or emits RST for
// an unbound destination.
func (s *Stack) handleTCP(packet ipPacket, receivedAt time.Time) error {
	tcp := packet.payload
	if len(tcp) < tcpHeaderSize || transportChecksum(packet.source, packet.target, protocolTCP, tcp) != 0 {
		s.stats.inboundDroppedPackets.Add(1)
		s.stats.tcpInvalidSegments.Add(1)
		return nil
	}
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(tcp) {
		s.stats.inboundDroppedPackets.Add(1)
		s.stats.tcpInvalidSegments.Add(1)
		return nil
	}
	sourcePort := binary.BigEndian.Uint16(tcp[0:2])
	targetPort := binary.BigEndian.Uint16(tcp[2:4])
	raw := append([]byte(nil), tcp[tcpHeaderSize:]...)
	optionSize := headerSize - tcpHeaderSize
	segment := tcpSegment{
		sequence: binary.BigEndian.Uint32(tcp[4:8]), acknowledgement: binary.BigEndian.Uint32(tcp[8:12]),
		flags: tcp[13], window: binary.BigEndian.Uint16(tcp[14:16]), ecn: packet.ecn,
		options: raw[:optionSize], payload: raw[optionSize:], receivedAt: receivedAt,
	}
	key := tcpKey{local: netip.AddrPortFrom(packet.target, targetPort), remote: netip.AddrPortFrom(packet.source, sourcePort)}
	s.mu.RLock()
	connection := s.tcp[key]
	s.mu.RUnlock()
	if connection != nil {
		if !connection.enqueueInbound(segment) {
			s.stats.inboundDroppedPackets.Add(1)
			s.stats.tcpInboundQueueDrops.Add(1)
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
	return s.writeTCP(packet.target, packet.source, targetPort, sourcePort, sequence, acknowledgement, flags, 0, nil, nil, s.mtuFor(packet.source), 0, 0)
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
	stack.mu.Lock()
	if connection := stack.tcp[key]; connection != nil {
		stack.mu.Unlock()
		if !connection.enqueueInbound(segment) {
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
		initialSequence := stack.tcpInitialSequence(key, tcpSegmentEventTime(segment, time.Now(), time.Time{}))
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
	return true, state.sendSYNCookie(stack, key, segment, tcpSegmentEventTime(segment, time.Now(), time.Time{}))
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
	initialSequence, options, valid := state.validateSYNCookie(key, segment, tcpSegmentEventTime(segment, time.Now(), time.Time{}))
	if !valid {
		return false, nil
	}
	stack.mu.Lock()
	if connection := stack.tcp[key]; connection != nil {
		stack.mu.Unlock()
		if !connection.enqueueInbound(segment) {
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
	connection.receiveWindowScale = options.localWindowScale
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

// buildTCPPacket constructs one non-fragmented TCP segment using explicit path
// and IP-header policy.
func buildTCPPacket(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, trafficClass, ecn byte) ([]byte, error) {
	headerSize := tcpHeaderSize + (len(options)+3)&^3
	if len(options) > 40 || headerSize > 60 {
		return nil, errors.New("mipstack: invalid TCP options")
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
	// RFC 6864 makes Identification meaningless on this DF atomic datagram;
	// Linux likewise emits zero instead of consuming the fragmentation ID
	// sequence used by datagrams that routers may actually fragment.
	packet := buildIPPacketWithOptions(source, target, protocolTCP, tcp, 0, true, ipPacketOptions{trafficClass: trafficClass&0xfc | ecn&3})
	if len(packet) == 0 || len(packet) > mtu {
		return nil, syscall.EMSGSIZE
	}
	return packet, nil
}

// writeTCP emits a stack-owned control segment. Connection actors use their
// cancellation-aware writer below so a stalled embedding link cannot retain a
// terminated connection indefinitely.
func (s *Stack) writeTCP(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, trafficClass, ecn byte) error {
	packet, err := buildTCPPacket(source, target, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn)
	if err != nil {
		return err
	}
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

// enqueueInbound hands one validated segment to the byte-bounded actor queue.
func (c *TCPConn) enqueueInbound(segment tcpSegment) bool {
	if c.inbound.enqueue(segment) {
		return true
	}
	c.inboundQueueDrops.Add(1)
	return false
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
			c.applicationReads.Add(uint64(n))
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
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			select {
			case <-changed:
				continue
			default:
				return 0, os.ErrDeadlineExceeded
			}
		}
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
		if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
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
	startedAt := time.Now()
	closedNow := false
	linger := -1
	abortive := false
	c.closeOnce.Do(func() {
		closedNow = true
		c.mu.Lock()
		if !c.writeClosed {
			c.writeClosed = true
		}
		linger = c.linger
		abortive = linger == 0 || len(c.readBuffer) != 0 || c.outOfOrderUnread.Load() != 0
		c.userClosed = true
		c.readErr = net.ErrClosed
		c.readBuffer = nil
		if abortive {
			c.sendBuffer = nil
			c.notifySendChangedLocked()
		}
		c.notifyReadLocked()
		c.mu.Unlock()
	})
	if !closedNow {
		return c.operationError("close", net.ErrClosed)
	}
	if abortive {
		c.abort(net.ErrClosed)
		return nil
	}
	// Also wake an actor whose FIN was already acknowledged after CloseWrite;
	// a later full Close makes that FIN_WAIT_2 state eligible for cleanup.
	c.notifySend()
	if linger > 0 {
		timer, timeout := deadlineTimer(startedAt.Add(tcpLingerDuration(linger)))
		select {
		case <-c.lingerDone:
			stopTimer(timer)
		case <-c.done:
			stopTimer(timer)
		case <-timeout:
			c.abort(net.ErrClosed)
		}
	}
	return nil
}

// LocalAddr returns the managed local TCP endpoint.
func (c *TCPConn) LocalAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.local) }

// RemoteAddr returns the connected remote TCP endpoint.
func (c *TCPConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.remote) }

// Info returns a consistent diagnostic snapshot. The connection actor
// supplies live protocol state; after termination, the final snapshot remains
// available for post-mortem inspection.
func (c *TCPConn) Info() TCPInfo {
	response := make(chan TCPInfo, 1)
	select {
	case c.infoRequest <- response:
		select {
		case info := <-response:
			return info
		case <-c.done:
		}
	case <-c.done:
	}
	if info := c.lastInfo.Load(); info != nil {
		return *info
	}
	return c.tcpInfoBase(TCPStateClosed)
}

// tcpInfoBase snapshots application-facing state protected by c.mu.
func (c *TCPConn) tcpInfoBase(state TCPState) TCPInfo {
	c.mu.Lock()
	info := c.tcpInfoBaseLocked(state)
	c.mu.Unlock()
	return info
}

// tcpInfoBaseLocked snapshots application-facing state while c.mu is held.
func (c *TCPConn) tcpInfoBaseLocked(state TCPState) TCPInfo {
	info := TCPInfo{
		LocalAddress: c.key.local, RemoteAddress: c.key.remote, State: state,
		CongestionControl: c.congestion,
		SendBufferSize:    len(c.sendBuffer), SendBufferCapacity: c.sendCapacity, MaximumSendBuffer: c.sendMaximum,
		ReceiveBufferSize: len(c.readBuffer) + int(c.outOfOrderUnread.Load()), ReceiveBufferCapacity: c.receiveCapacity, MaximumReceiveBuffer: c.receiveMaximum,
		Retransmissions: c.retransmissions.Load(), InboundQueueDrops: c.inboundQueueDrops.Load(),
		InboundQueueBytes: c.inbound.retainedBytes(), InboundQueuePeak: c.inbound.peakBytes(), InboundQueueCapacity: tcpInboundByteCapacity,
		WindowScaling:   c.peerWindowScaling,
		PeerWindowScale: c.peerWindowScale, ReceiveWindowScale: c.receiveWindowScale,
		SACK: c.peerSACK, Timestamps: c.peerTimestamp, ECN: c.peerECN,
		KeepAlive: c.keepAlive, KeepAliveConfig: c.keepAliveConfig, IdleTimeout: c.idleTimeout, UserTimeout: c.userTimeout, NoDelay: c.noDelay,
		TrafficClass: uint8(c.trafficClass.Load()),
		LastError:    c.terminalErr,
	}
	return info
}

// respondTCPInfo retains the newest snapshot before returning it to a caller.
func (c *TCPConn) respondTCPInfo(response chan TCPInfo, info TCPInfo) {
	c.lastInfo.Store(&info)
	response <- info
}

// noteRetransmission updates stack-wide and connection-local diagnostics.
func (c *TCPConn) noteRetransmission() {
	c.stack.stats.tcpRetransmissions.Add(1)
	c.retransmissions.Add(1)
}

// handshakeTCPInfo builds the subset available before congestion and data
// transfer state has been initialized.
func (c *TCPConn) handshakeTCPInfo(state TCPState, mss int, rto time.Duration) TCPInfo {
	info := c.tcpInfoBase(state)
	info.MaximumSegmentSize = mss
	info.PathMTU = c.mtu
	info.RetransmissionTimeout = rto
	info.PeerWindow = c.peerWindow
	info.ReceiveWindow = uint32(c.receiveAvailable(0))
	return info
}

// MultipathTCP reports whether this connection uses MPTCP. Mipstack currently
// implements ordinary TCP only, so the result is always false.
func (c *TCPConn) MultipathTCP() (bool, error) { return false, nil }

// operationError wraps a TCP socket failure in the same public shape used by
// the standard net package.
func (c *TCPConn) operationError(operation string, err error) error {
	return socketOperationError(operation, c.net, c.LocalAddr(), c.RemoteAddr(), err)
}

// setOperationError wraps a deadline-setting failure using the local-address
// metadata shape of the standard net package.
func (c *TCPConn) setOperationError(err error) error {
	return socketOperationError("set", c.net, nil, c.LocalAddr(), err)
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

// SetUserTimeout bounds how long transmitted data may remain unacknowledged,
// or buffered data may remain unsent behind a zero window. Zero disables the
// custom bound while retaining the normal TCP retry limits. Like Linux
// TCP_USER_TIMEOUT, this is a local policy and does not negotiate the RFC
// 5482 UTO option.
func (c *TCPConn) SetUserTimeout(timeout time.Duration) error {
	if timeout < 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.userTimeout = timeout })
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

// SetCongestionControl changes the algorithm for this connection and prevents
// later stack-default updates from overriding the explicit choice.
func (c *TCPConn) SetCongestionControl(algorithm CongestionControl) error {
	if !algorithm.valid() {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() {
		c.congestion = algorithm
		c.congestionUser = true
	})
}

// SetTrafficClass sets IPv4 TOS or IPv6 Traffic Class DSCP bits. TCP owns and
// replaces the two ECN bits on each packet.
func (c *TCPConn) SetTrafficClass(value int) error {
	if value < 0 || value > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.trafficClass.Store(uint32(uint8(value) & 0xfc))
	c.mu.Unlock()
	return nil
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
	c.receiveAutoTune = false
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
	c.sendAutoTune = false
	c.sendCapacityHint.Store(int64(bytes))
	c.notifySendChangedLocked()
	c.mu.Unlock()
	return nil
}

// growReceiveCapacity applies automatic receive tuning without overriding a
// SetReadBuffer choice. One observation can at most double the current bound,
// which prevents a scheduler pause or counter burst from causing abrupt
// per-connection memory growth.
func (c *TCPConn) growReceiveCapacity(target int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.receiveAutoTune || target <= c.receiveCapacity {
		return false
	}
	if maximum := c.receiveCapacity * 2; target > maximum {
		target = maximum
	}
	maximum := c.receiveMaximum
	if maximum <= 0 {
		maximum = tcpMaximumReceiveCapacity
	}
	if target > maximum {
		target = maximum
	}
	if target <= c.receiveCapacity {
		return false
	}
	c.receiveCapacity = target
	return true
}

// growSendCapacity applies a delivery-rate-derived automatic target without
// overriding SetWriteBuffer. One observation can at most double the current
// capacity, preventing a scheduler pause from reserving the maximum at once.
func (c *TCPConn) growSendCapacity(target int) bool {
	if target <= int(c.sendCapacityHint.Load()) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sendAutoTune || target <= c.sendCapacity {
		return false
	}
	if maximum := c.sendCapacity * 2; target > maximum {
		target = maximum
	}
	maximum := c.sendMaximum
	if maximum <= 0 {
		maximum = tcpMaximumSendCapacity
	}
	if target > maximum {
		target = maximum
	}
	if target <= c.sendCapacity {
		return false
	}
	c.sendCapacity = target
	c.sendCapacityHint.Store(int64(target))
	c.notifySendChangedLocked()
	return true
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
		idleTimeout: c.idleTimeout, userTimeout: c.userTimeout, noDelay: c.noDelay,
		congestion: c.congestion,
	}
}

// updateDefaultCongestionControl preserves Config.UpdateConfig's established-
// connection behavior unless the application selected a per-socket override.
func (c *TCPConn) updateDefaultCongestionControl(algorithm CongestionControl) {
	c.mu.Lock()
	if c.congestionUser || c.userClosed || c.terminalErr != nil || c.congestion == algorithm {
		c.mu.Unlock()
		return
	}
	c.congestion = algorithm
	c.mu.Unlock()
	select {
	case c.optionsChanged <- struct{}{}:
	default:
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

// applicationReceiveClosed reports whether Close, rather than the explicit
// read half-close, made newly received application data undeliverable.
func (c *TCPConn) applicationReceiveClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.userClosed
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

// receiveAvailable returns storage not occupied by delivered or out-of-order
// data. CloseRead discards delivered bytes while preserving sequence state.
func (c *TCPConn) receiveAvailable(outOfOrderBytes int) int {
	available, _ := c.receiveSpace(outOfOrderBytes)
	return available
}

// receiveSpace returns both current free storage and the configured bound so
// the established actor can apply receiver-side silly-window avoidance.
func (c *TCPConn) receiveSpace(outOfOrderBytes int) (available, capacity int) {
	c.mu.Lock()
	capacity = c.receiveCapacity
	available = capacity - len(c.readBuffer) - outOfOrderBytes
	if c.userClosed || c.readClosed {
		available = capacity - outOfOrderBytes
	}
	c.mu.Unlock()
	return
}

// receiveWindow returns a wire window without prior advertisement state. It
// is used during handshakes, before the established actor owns the right edge.
func (c *TCPConn) receiveWindow(outOfOrderBytes int, scaled bool) uint16 {
	available := c.receiveAvailable(outOfOrderBytes)
	if available <= 0 {
		return 0
	}
	if scaled {
		available >>= c.receiveWindowScale
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
	// Close the actor queue before publishing its terminal snapshot. The
	// connection remains visible in Stack.tcp until run's deferred removal, so
	// a concurrent packet lookup can otherwise enqueue work after the sole
	// consumer has exited.
	c.inbound.close()
	base := c.tcpInfoBase(TCPStateClosed)
	if previous := c.lastInfo.Load(); previous != nil {
		info := *previous
		info.State = TCPStateClosed
		info.SendBufferSize, info.SendBufferCapacity, info.MaximumSendBuffer = base.SendBufferSize, base.SendBufferCapacity, base.MaximumSendBuffer
		info.ReceiveBufferSize, info.ReceiveBufferCapacity, info.MaximumReceiveBuffer = base.ReceiveBufferSize, base.ReceiveBufferCapacity, base.MaximumReceiveBuffer
		info.Retransmissions = base.Retransmissions
		info.InboundQueueDrops, info.InboundQueueBytes = base.InboundQueueDrops, base.InboundQueueBytes
		info.InboundQueuePeak, info.InboundQueueCapacity = base.InboundQueuePeak, base.InboundQueueCapacity
		info.KeepAlive, info.KeepAliveConfig, info.IdleTimeout, info.UserTimeout, info.NoDelay = base.KeepAlive, base.KeepAliveConfig, base.IdleTimeout, base.UserTimeout, base.NoDelay
		info.TrafficClass = base.TrafficClass
		info.LastError = err
		c.lastInfo.Store(&info)
	} else {
		base.LastError = err
		c.lastInfo.Store(&base)
	}
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
			_ = c.sendAbortReset(initialSequence+1, c.receiveNext, c.receiveWindow(0, false))
		}
		c.finish(err)
		return
	}
	if !listener.enqueue(c) {
		_ = c.sendAbortReset(initialSequence+1, c.receiveNext, c.receiveWindow(0, false))
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
	transmissions := 0
	timeoutAttempts := 0
	timer := newOwnedTimer()
	defer timer.close()
	var timeout <-chan time.Time
	var timeoutDeadline time.Time
	var synSentAt time.Time
	send := func(rearm bool) error {
		options := tcpPassiveSYNOptions(localMSS, sack, windowScaling, timestamp, c.receiveWindowScale, c.stack.tcpTimestamp(), c.recentTimestamp)
		flags := byte(tcpFlagSYN | tcpFlagACK)
		if c.peerECN {
			flags |= tcpFlagECE
		}
		hostQueue, err := c.writeTCPControlWithMTU(initialSequence, c.receiveNext, flags, c.receiveWindow(0, false), options, nil, c.mtu)
		if err != nil {
			return err
		}
		synSentAt = hostQueue.queuedAt
		if transmissions != 0 {
			c.noteRetransmission()
		}
		transmissions++
		if rearm {
			timeoutDeadline = synSentAt.Add(rto)
			delay := timeoutDeadline.Sub(time.Now())
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		return nil
	}
	if err := send(true); err != nil {
		return err
	}
	eventTime := tcpSegmentEventTime(syn, synSentAt, time.Time{})
	var timerBacklog tcpTimerBacklog
	for {
		activeTimeout := timeout
		inboundNotify := c.inbound.notify
		drainBacklog, forceTimeout := timerBacklog.order(c.inbound.len(), timeoutDeadline, time.Now())
		if drainBacklog {
			// Process the finite receive snapshot that was already waiting when
			// this handshake timeout expired.
			activeTimeout = nil
		} else if forceTimeout {
			inboundNotify = nil
		}
		select {
		case <-inboundNotify:
			segment, ok := c.inbound.dequeue()
			if !ok {
				continue
			}
			timerBacklog.consumed()
			receivedAt := tcpSegmentEventTime(segment, time.Now(), eventTime)
			eventTime = receivedAt
			segmentLength := uint32(len(segment.payload))
			if segment.flags&tcpFlagSYN != 0 {
				segmentLength++
			}
			if segment.flags&tcpFlagFIN != 0 {
				segmentLength++
			}
			receiveWindow := uint32(c.receiveWindow(0, false))
			if segment.flags&tcpFlagRST != 0 {
				if segment.sequence == c.receiveNext {
					return syscall.ECONNRESET
				}
				if tcpSegmentAcceptable(segment.sequence, segmentLength, c.receiveNext, receiveWindow) && c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					if err := c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagACK, c.receiveWindow(0, false), nil); err != nil {
						return err
					}
				}
				continue
			}
			if !c.passive && segment.flags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN|tcpFlagACK && segment.acknowledgement == initialSequence+1 && segment.sequence+1 == c.receiveNext {
				// During simultaneous open both endpoints send SYN-ACK. Its
				// SYN repeats the already accepted IRS while its ACK completes
				// our active half of the handshake.
				if c.peerTimestamp {
					value, _, present := parseTCPTimestamp(segment.options)
					if !present || tcpSequenceLess(value, c.recentTimestamp) {
						continue
					}
					c.recentTimestamp = value
				}
				c.peerWindow = uint32(segment.window)
				c.peerWindowSeq = segment.sequence
				c.peerWindowACK = segment.acknowledgement
				if transmissions == 1 {
					c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
				}
				timer.stop()
				return c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagACK, c.receiveWindow(0, c.peerWindowScaling), nil)
			}
			if segment.flags&tcpFlagSYN != 0 && segment.flags&tcpFlagACK == 0 && segment.sequence+1 == c.receiveNext {
				// RFC 3168 section 6.1.1.1 permits an initiator to clear ECE
				// and CWR after an ECN setup SYN times out. The retransmitted
				// SYN must downgrade the stateful passive open as well as the
				// SYN-ACK sent in response, or an ECN-intolerant path can never
				// complete the fallback handshake.
				if segment.flags&(tcpFlagECE|tcpFlagCWR) != tcpFlagECE|tcpFlagCWR {
					c.peerECN = false
				}
				if c.peerTimestamp {
					value, _, present := parseTCPTimestamp(segment.options)
					if present && !tcpSequenceLess(value, c.recentTimestamp) {
						c.recentTimestamp = value
					}
				}
				if err := send(false); err != nil {
					return err
				}
				continue
			}
			if !tcpSegmentAcceptable(segment.sequence, segmentLength, c.receiveNext, receiveWindow) {
				if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					if err := c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagACK, c.receiveWindow(0, false), nil); err != nil {
						return err
					}
				}
				continue
			}
			if segment.flags&tcpFlagACK != 0 && segment.acknowledgement != initialSequence+1 {
				if _, err := c.writeTCPControlWithMTU(segment.acknowledgement, 0, tcpFlagRST, 0, nil, nil, c.mtu); err != nil {
					return err
				}
				continue
			}
			if segment.flags&tcpFlagSYN != 0 {
				if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					if err := c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagACK, c.receiveWindow(0, false), nil); err != nil {
						return err
					}
				}
				continue
			}
			if segment.flags&tcpFlagACK == 0 || segment.acknowledgement != initialSequence+1 {
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
			if transmissions == 1 {
				c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
			}
			timer.stop()
			if len(segment.payload) != 0 || segment.flags&tcpFlagFIN != 0 {
				if !c.inbound.prepend(segment) {
					c.inboundQueueDrops.Add(1)
					c.stack.stats.inboundDroppedPackets.Add(1)
					c.stack.stats.tcpInboundQueueDrops.Add(1)
				}
			}
			return nil
		case <-c.pathMTUUpdate:
			c.mtu = c.stack.mtuFor(c.key.remote.Addr())
			localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
			if localMSS < 1 {
				return errors.New("mipstack: MTU is too small for TCP")
			}
			if err := send(false); err != nil {
				return err
			}
		case <-c.networkError:
			// Network errors during passive open are soft; the peer's retry and
			// the bounded SYN-ACK timeout decide whether the flow survives.
		case <-activeTimeout:
			timer.consumed()
			if timeoutAttempts >= tcpPassiveSYNMaximumAttempts-1 {
				return os.ErrDeadlineExceeded
			}
			timeoutAttempts++
			c.handshakeTimeout = true
			rto *= 2
			if rto > tcpMaximumRTO {
				rto = tcpMaximumRTO
			}
			if err := send(true); err != nil {
				return err
			}
		case response := <-c.infoRequest:
			c.respondTCPInfo(response, c.handshakeTCPInfo(TCPStateSYNReceived, localMSS, rto))
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
	transmissions := 0
	timeoutAttempts := 0
	ecnFallback := false
	timer := newOwnedTimer()
	defer timer.close()
	var timeout <-chan time.Time
	var timeoutDeadline time.Time
	var lastSoftError error
	var synSentAt time.Time
	send := func(rearm bool) error {
		options := tcpSYNOptions(localMSS, c.receiveWindowScale, c.stack.tcpTimestamp())
		flags := byte(tcpFlagSYN)
		if !ecnFallback {
			flags |= tcpFlagECE | tcpFlagCWR
		}
		hostQueue, err := c.writeTCPControlWithMTU(initialSequence, 0, flags, c.receiveWindow(0, false), options, nil, c.mtu)
		if err != nil {
			return err
		}
		synSentAt = hostQueue.queuedAt
		if transmissions != 0 {
			c.noteRetransmission()
		}
		transmissions++
		if rearm {
			timeoutDeadline = synSentAt.Add(rto)
			delay := timeoutDeadline.Sub(time.Now())
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		return nil
	}
	if err := send(true); err != nil {
		return err
	}
	eventTime := synSentAt
	var timerBacklog tcpTimerBacklog
	for {
		activeTimeout := timeout
		inboundNotify := c.inbound.notify
		drainBacklog, forceTimeout := timerBacklog.order(c.inbound.len(), timeoutDeadline, time.Now())
		if drainBacklog {
			activeTimeout = nil
		} else if forceTimeout {
			inboundNotify = nil
		}
		select {
		case <-inboundNotify:
			segment, ok := c.inbound.dequeue()
			if !ok {
				continue
			}
			timerBacklog.consumed()
			receivedAt := tcpSegmentEventTime(segment, time.Now(), eventTime)
			eventTime = receivedAt
			if segment.flags&tcpFlagACK != 0 && segment.acknowledgement != initialSequence+1 {
				// RFC 9293 SYN-SENT processing: an unacceptable ACK elicits
				// RST unless the incoming segment was itself a reset.
				if segment.flags&tcpFlagRST == 0 {
					_, _ = c.writeTCPControlWithMTU(segment.acknowledgement, 0, tcpFlagRST, 0, nil, nil, c.mtu)
				}
				continue
			}
			if segment.flags&tcpFlagRST != 0 {
				if segment.flags&tcpFlagACK != 0 && segment.acknowledgement == initialSequence+1 {
					return syscall.ECONNREFUSED
				}
				continue
			}
			if segment.flags&tcpFlagSYN != 0 && segment.flags&tcpFlagACK == 0 {
				// Crossed SYNs are a simultaneous open. Reuse SYN-RECEIVED
				// processing with our existing ISS and wait for the peer's
				// final ACK of the SYN-ACK.
				timer.stop()
				return c.passiveHandshake(segment, initialSequence)
			}
			if segment.flags&(tcpFlagSYN|tcpFlagACK) != tcpFlagSYN|tcpFlagACK || segment.acknowledgement != initialSequence+1 {
				continue
			}
			mss, scale, windowScaling, sack, timestamp, timestampValue := parseTCPOptions(segment.options, defaultTCPPeerMSS(c.key.remote.Addr()), 65535)
			c.peerMSS, c.peerWindowScale, c.peerSACK = mss, scale, sack
			c.peerWindowScaling = windowScaling
			c.peerTimestamp, c.recentTimestamp = timestamp, timestampValue
			// Once an ECN setup SYN has timed out, RFC 3168 requires the
			// legacy SYN retransmission to disable ECN for this connection.
			// A delayed setup SYN-ACK cannot re-enable the negotiation after
			// that fallback has started.
			c.peerECN = !ecnFallback && segment.flags&tcpFlagECE != 0 && segment.flags&tcpFlagCWR == 0
			c.receiveNext = segment.sequence + 1
			// The window in SYN and SYN-ACK is never scaled. The negotiated
			// shift applies only to later segments.
			c.peerWindow = uint32(segment.window)
			c.peerWindowSeq = segment.sequence
			c.peerWindowACK = segment.acknowledgement
			if transmissions == 1 {
				c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
			}
			timer.stop()
			return c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagACK, c.receiveWindow(0, c.peerWindowScaling), nil)
		case <-c.pathMTUUpdate:
			c.mtu = c.stack.mtuFor(c.key.remote.Addr())
			localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
			if localMSS < 1 {
				return errors.New("mipstack: MTU is too small for TCP")
			}
			if err := send(false); err != nil {
				return err
			}
		case err := <-c.networkError:
			// RFC 1122 treats asynchronous network failures during an active
			// open as soft errors except for an authenticated protocol or port
			// unreachable. A later SYN retry may still establish the connection
			// after a routing hint, while an explicit rejection ends this open.
			if tcpActiveOpenHardError(err) {
				return err
			}
			lastSoftError = err
		case <-activeTimeout:
			timer.consumed()
			if timeoutAttempts >= tcpActiveSYNMaximumAttempts-1 {
				return tcpTimeoutError(lastSoftError)
			}
			timeoutAttempts++
			c.handshakeTimeout = true
			ecnFallback = true
			rto *= 2
			if rto > tcpMaximumRTO {
				rto = tcpMaximumRTO
			}
			if err := send(true); err != nil {
				return err
			}
		case response := <-c.infoRequest:
			c.respondTCPInfo(response, c.handshakeTCPInfo(TCPStateSYNSent, localMSS, rto))
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
	pathMSS := localMaximum
	receiveMSS := pathMSS
	var (
		sendUnacknowledged  = sendNext
		peerScale           = c.peerWindowScale
		peerSACK            = c.peerSACK
		peerWindow          = c.peerWindow
		peerWindowSequence  = c.peerWindowSeq
		peerWindowACK       = c.peerWindowACK
		maximumPeerWindow   = c.peerWindow
		bytesAcknowledged   uint64
		bytesSent           uint64
		bytesReceived       uint64
		spuriousUndos       uint64
		pathMTUProbes       uint64
		pathMTUSuccesses    uint64
		pathMTUFailures     uint64
		receiveNext         = c.receiveNext
		congestionWindow    = initialTCPWindow(peerMSS)
		slowStartThreshold  = ^uint32(0) >> 1
		outstanding         []sentTCPSegment
		outOfOrder          []tcpReceivedPiece
		outOfOrderBytes     int
		recentDSACK         tcpSACKBlock
		haveRecentDSACK     bool
		localFINSent        bool
		localFINAcked       bool
		remoteFINReceived   bool
		timeWaitRequired    bool
		finWaitArmed        bool
		timeWaitArmed       bool
		duplicateACKs       int
		fastRecovery        bool
		recoveryPoint       uint32
		prrPriorFlight      uint32
		prrDelivered        uint64
		prrOut              uint64
		recentSACK          uint32
		lastACKSent         = c.receiveNext
		tailProbeActive     bool
		tailProbeEnd        uint32
		tailProbeRetransmit bool
		tailProbeRTTSamples uint64
		rtoAttempts         int
		rtoRecovery         bool
		rtoRecoveryPoint    uint32
		blackHoleRTOs       int
		lastSoftError       error
		lastTimestampUpdate = time.Now()
		ecnRecoveryPoint    uint32
		ecnRecoveryActive   bool
		controller          = newTCPCongestionController(c.socketOptions().congestion)
		rackLatestDelivered tcpRACKSample
		rackForwardACK      uint32
		rackForwardACKSet   bool
		rackReorderingSeen  bool
		rackReorderingScale = uint32(1)
		rackDSACKRound      uint32
		rackDSACKRoundSet   bool
		rackReorderPersist  int
		blackHoleMTU        int
		blackHoleExpiry     time.Time
		lastDataSent        time.Time
		ecnHoldUntil        time.Time
		receiveAutoTune     tcpBufferAutoTune
		sendAutoTune        tcpBufferAutoTune
		hyStart             tcpHyStart
		undo                tcpRecoveryUndo
		eifelRTO            tcpEifelRTOResponse
		retransmitHistory   tcpRetransmissionHistory
		seenDSACK           bool
		dsackUndoDisabled   bool
		plpmtu              tcpPLPMTU
		zeroWindowSince     time.Time
		sackedRanges        int
		sackedBytes         uint32
		haveRACKLoss        bool
	)
	c.publishICMPSequenceRange(sendUnacknowledged, sendNext)
	rtt := rttEstimator{rto: tcpInitialRTO}
	if c.handshakeTimeout {
		// RFC 6298 section 5.7 requires a three-second data RTO after a
		// SYN retransmission timer expires. A duplicate SYN or a path-MTU
		// update may resend a handshake packet without triggering this rule.
		rtt.rto = 3 * time.Second
	} else {
		rtt.observe(c.handshakeRTT)
	}
	tailProbeRTTSamples = 0
	retransmissionTimer := newOwnedTimer()
	persistTimer := newOwnedTimer()
	delayedACKTimer := newOwnedTimer()
	livenessTimer := newOwnedTimer()
	pathMTUTimer := newOwnedTimer()
	var pacingTimer *ownedTimer
	defer retransmissionTimer.close()
	defer persistTimer.close()
	defer delayedACKTimer.close()
	defer livenessTimer.close()
	defer pathMTUTimer.close()
	defer func() {
		if pacingTimer != nil {
			pacingTimer.close()
		}
	}()
	var retransmit, persist, delayedACK <-chan time.Time
	var liveness <-chan time.Time
	var pathMTUProbe, pacing <-chan time.Time
	var retransmissionDeadline, persistDeadline, delayedACKDeadline time.Time
	var livenessDeadline, pathMTUDeadline, pacingDeadline time.Time
	var retransmissionProbe, retransmissionRACK, retransmissionClose bool
	persistRTO := time.Second
	persistAttempts := 0
	ackPending := false
	ackSegments := 0
	initialWindowScaled := c.peerWindowScaling && !c.passive
	lastAdvertisedWindow := c.receiveWindow(0, initialWindowScaled)
	receiveWindowState := newTCPReceiveWindow(receiveNext, lastAdvertisedWindow, c.peerWindowScaling, initialWindowScaled, c.receiveWindowScale)
	ordinaryFlight := func() uint32 {
		flight := sendNext - sendUnacknowledged
		if sackedBytes > flight {
			// Preserve bounded behavior if malformed feedback ever violates the
			// scoreboard invariant instead of wrapping a congestion allowance.
			return 0
		}
		return flight - sackedBytes
	}
	congestionFlight := func() uint32 {
		if peerSACK && fastRecovery {
			return sackRecoveryPipe(outstanding, peerMSS)
		}
		return ordinaryFlight()
	}
	recountSACK := func() {
		sackedRanges, sackedBytes = tcpSACKedState(outstanding)
	}
	connectionState := func() TCPState {
		switch {
		case timeWaitArmed:
			return TCPStateTimeWait
		case !localFINSent && remoteFINReceived:
			return TCPStateCloseWait
		case !localFINSent:
			return TCPStateEstablished
		case !localFINAcked && !timeWaitRequired:
			return TCPStateLastACK
		case !localFINAcked && remoteFINReceived:
			return TCPStateClosing
		case !localFINAcked:
			return TCPStateFINWait1
		case !remoteFINReceived:
			return TCPStateFINWait2
		default:
			return TCPStateClosed
		}
	}
	tcpInfo := func() TCPInfo {
		c.mu.Lock()
		info := c.tcpInfoBaseLocked(connectionState())
		info.CongestionControl = controller.algorithm
		info.RTT, info.MinimumRTT, info.RTTVariation, info.RetransmissionTimeout = rtt.srtt, rtt.minimum, rtt.variation, rtt.rto
		info.CongestionWindow, info.SlowStartThreshold = congestionWindow, slowStartThreshold
		info.BytesInFlight = congestionFlight()
		info.PeerWindow, info.ReceiveWindow = peerWindow, receiveWindowState.size(receiveNext)
		info.MaximumSegmentSize, info.PathMTU = peerMSS, c.mtu
		dataAcknowledged := bytesAcknowledged
		if dataAcknowledged > bytesSent {
			dataAcknowledged = bytesSent
		}
		info.BytesSent, info.BytesAcknowledged, info.BytesReceived = bytesSent, dataAcknowledged, bytesReceived
		info.FastRecovery, info.RetransmissionRecovery, info.HyStartCSS = fastRecovery, rtoRecovery, hyStart.css
		info.PathMTUDiscovery, info.PathMTUProbe = plpmtu.searching, plpmtu.probeMTU
		info.SpuriousRecoveryUndos, info.PathMTUProbes = spuriousUndos, pathMTUProbes
		info.PathMTUProbeSuccesses, info.PathMTUProbeFailures = pathMTUSuccesses, pathMTUFailures
		c.mu.Unlock()
		return info
	}
	defer func() {
		info := tcpInfo()
		c.lastInfo.Store(&info)
	}()
	receiveAutoTune.updated = time.Now()
	receiveAutoTune.bytes = c.applicationReads.Load()
	sendAutoTune.updated = time.Now()
	sendAutoTune.bytes = bytesAcknowledged
	hyStart.start(sendNext)
	advertisedReceiveWindow := func() uint16 {
		available, capacity := c.receiveSpace(outOfOrderBytes)
		return receiveWindowState.advertise(receiveNext, available, tcpReceiveWindowIncrease(capacity, receiveMSS))
	}
	abortResetSent := false
	defer func() {
		if abortResetSent || !c.resetAfterAbort() {
			return
		}
		select {
		case <-c.abortCh:
			sequence := tcpAcceptableSendSequence(sendUnacknowledged, sendNext, peerWindow, peerScale)
			_ = c.sendAbortReset(sequence, receiveNext, advertisedReceiveWindow())
		default:
		}
	}()
	lastActivity := time.Now()
	eventTime := lastActivity
	lastKeepAlive := time.Time{}
	keepAliveProbes := 0
	effectivePathMTU := func() int {
		mtu := c.stack.mtuFor(c.key.remote.Addr())
		if blackHoleMTU > 0 && blackHoleMTU < mtu {
			mtu = blackHoleMTU
		}
		return mtu
	}
	armPathMTUProbe := func() {
		pathMTUTimer.stop()
		pathMTUProbe = nil
		pathMTUDeadline = time.Time{}
		if plpmtu.searching {
			if !plpmtu.active && time.Now().Before(plpmtu.nextProbe) {
				pathMTUProbe = pathMTUTimer.reset(time.Until(plpmtu.nextProbe))
				pathMTUDeadline = plpmtu.nextProbe
			}
			return
		}
		expiry, exists := c.stack.pathMTUExpiry(c.key.remote.Addr())
		if !blackHoleExpiry.IsZero() && (!exists || blackHoleExpiry.Before(expiry)) {
			expiry, exists = blackHoleExpiry, true
		}
		if !exists {
			return
		}
		delay := time.Until(expiry)
		if delay < 0 {
			delay = 0
		}
		pathMTUProbe = pathMTUTimer.reset(delay)
		pathMTUDeadline = expiry
	}
	armPacing := func(delay time.Duration) {
		if delay <= 0 {
			return
		}
		if pacingTimer == nil {
			pacingTimer = newOwnedTimer()
			pacing = pacingTimer.reset(delay)
			pacingDeadline = time.Now().Add(delay)
			return
		}
		pacing = pacingTimer.reset(delay)
		pacingDeadline = time.Now().Add(delay)
	}
	keepAliveEligible := func() bool {
		if len(outstanding) != 0 {
			return false
		}
		offset := int(sendNext - sendUnacknowledged)
		_, total, writeClosed := c.sendSnapshot(offset, 0)
		return offset >= total && (!writeClosed || localFINSent)
	}
	bbrApplicationLimited := func() bool {
		if controller.algorithm != CongestionControlBBR {
			return false
		}
		flight := sendNext - sendUnacknowledged
		if flight >= peerWindow {
			return true
		}
		_, total, _ := c.sendSnapshot(int(flight), 0)
		return int(flight) >= total
	}
	userTimeoutDeadline := func(now time.Time, timeout time.Duration) time.Time {
		if timeout <= 0 {
			zeroWindowSince = time.Time{}
			return time.Time{}
		}
		var oldest time.Time
		if len(outstanding) != 0 {
			index := 0
			if sackedRanges != 0 {
				index = firstUnsackedSegment(outstanding)
			}
			segment := outstanding[index]
			oldest = segment.firstSentAt
			if oldest.IsZero() {
				oldest = segment.sentAt
			}
		}
		offset := int(sendNext - sendUnacknowledged)
		_, total, writeClosed := c.sendSnapshot(offset, 0)
		zeroWindowBlocked := peerWindow == 0 && (offset < total || writeClosed && !localFINSent)
		if zeroWindowBlocked {
			if zeroWindowSince.IsZero() {
				zeroWindowSince = now
			}
			if oldest.IsZero() || zeroWindowSince.Before(oldest) {
				oldest = zeroWindowSince
			}
		} else {
			zeroWindowSince = time.Time{}
		}
		if oldest.IsZero() {
			return time.Time{}
		}
		return oldest.Add(timeout)
	}
	armLiveness := func() {
		livenessTimer.stop()
		liveness = nil
		livenessDeadline = time.Time{}
		if localFINAcked && remoteFINReceived {
			return
		}
		options := c.socketOptions()
		var deadline time.Time
		if options.idleTimeout > 0 {
			deadline = lastActivity.Add(options.idleTimeout)
		}
		if userDeadline := userTimeoutDeadline(time.Now(), options.userTimeout); !userDeadline.IsZero() && (deadline.IsZero() || userDeadline.Before(deadline)) {
			deadline = userDeadline
		}
		if options.userTimeout > 0 && keepAliveProbes != 0 {
			keepAliveUserDeadline := lastActivity.Add(options.userTimeout)
			if deadline.IsZero() || keepAliveUserDeadline.Before(deadline) {
				deadline = keepAliveUserDeadline
			}
		}
		if options.keepAlive && keepAliveEligible() {
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
			liveness = livenessTimer.reset(delay)
			livenessDeadline = deadline
		}
	}
	ageRACKReordering := func() {
		if rackReorderPersist <= 0 {
			return
		}
		rackReorderPersist--
		if rackReorderPersist == 0 {
			rackReorderingScale = 1
		}
	}
	observeRACKReordering := func(end uint32, retransmitted bool) {
		if rackAdvanceForwardACK(&rackForwardACK, &rackForwardACKSet, end, retransmitted) {
			rackReorderingSeen = true
		}
	}
	rackDeadline := func(now time.Time, haveSACKed bool) (time.Time, bool) {
		if !peerSACK || len(outstanding) == 0 {
			return time.Time{}, false
		}
		// In sequence-order transmission, a cumulatively ACKed original
		// segment cannot have been sent after any remaining higher sequence.
		// RACK has a candidate only after selective delivery or delivery of a
		// retransmission has made transmit order differ from sequence order.
		if !haveSACKed && !rackLatestDelivered.retransmitted {
			return time.Time{}, false
		}
		reorderingWindow := rackReorderingWindow(rtt.minimum, rtt.srtt, rackReorderingScale)
		if !rackReorderingSeen && (fastRecovery || rtoRecovery || sackedRanges >= tcpDuplicateACKThreshold) {
			reorderingWindow = 0
		}
		delay, exists := rackLossDelay(outstanding, rackLatestDelivered, now, reorderingWindow)
		if !exists {
			return time.Time{}, false
		}
		return now.Add(delay), true
	}

	armRetransmission := func() {
		retransmissionTimer.stop()
		retransmit = nil
		retransmissionDeadline = time.Time{}
		retransmissionProbe = false
		retransmissionRACK = false
		retransmissionClose = false
		if len(outstanding) != 0 {
			now := time.Now()
			index := 0
			if sackedRanges != 0 {
				index = firstUnsackedSegment(outstanding)
			}
			deadline := outstanding[index].sentAt.Add(rtt.rto)
			haveSACKed := peerSACK && sackedRanges != 0
			if peerSACK && peerWindow != 0 && ecnHoldUntil.IsZero() && !tailProbeActive && rtt.samples > tailProbeRTTSamples && !fastRecovery && !haveSACKed {
				probeIndex := len(outstanding) - 1
				probeDeadline := outstanding[probeIndex].sentAt.Add(tailLossProbeDelay(rtt.srtt, rtt.rto, len(outstanding) == 1))
				if probeDeadline.Before(deadline) {
					deadline = probeDeadline
					retransmissionProbe = true
				}
			}
			if candidate, exists := rackDeadline(now, haveSACKed); exists && !candidate.After(deadline) {
				deadline = candidate
				retransmissionProbe = false
				retransmissionRACK = true
			}
			delay := deadline.Sub(now)
			if delay < 0 {
				delay = 0
			}
			retransmit = retransmissionTimer.reset(delay)
			retransmissionDeadline = deadline
		}
	}
	armRetransmissionAfterACK := func(acknowledgedAt time.Time) {
		retransmissionTimer.stop()
		retransmit = nil
		retransmissionDeadline = time.Time{}
		retransmissionProbe = false
		retransmissionRACK = false
		retransmissionClose = false
		if len(outstanding) == 0 {
			return
		}
		// RFC 6298 section 5.3 restarts the timer when TCP processes an ACK
		// that cumulatively acknowledges new data. Packet arrival time remains
		// the RTT/RACK sample clock, but host delay before the actor updates its
		// scoreboard must not consume the newly installed RTO or tail-probe
		// interval and manufacture an immediate retransmission.
		now := time.Now()
		deadline := now.Add(rtt.rto)
		haveSACKed := peerSACK && sackedRanges != 0
		if peerSACK && peerWindow != 0 && ecnHoldUntil.IsZero() && !tailProbeActive && rtt.samples > tailProbeRTTSamples && !fastRecovery && !haveSACKed {
			probeDeadline := now.Add(tailLossProbeDelay(rtt.srtt, rtt.rto, len(outstanding) == 1))
			if probeDeadline.Before(deadline) {
				deadline = probeDeadline
				retransmissionProbe = true
			}
		}
		if candidate, exists := rackDeadline(acknowledgedAt, haveSACKed); exists {
			if !candidate.After(deadline) {
				deadline = candidate
				retransmissionProbe = false
				retransmissionRACK = true
			}
		}
		delay := deadline.Sub(now)
		if delay < 0 {
			delay = 0
		}
		retransmit = retransmissionTimer.reset(delay)
		retransmissionDeadline = deadline
	}
	armClose := func(startedAt time.Time, duration time.Duration) {
		now := time.Now()
		retransmissionDeadline = now.Add(duration)
		if !startedAt.IsZero() {
			retransmissionDeadline = startedAt.Add(duration)
		}
		delay := retransmissionDeadline.Sub(now)
		if delay < 0 {
			delay = 0
		}
		retransmit = retransmissionTimer.reset(delay)
		retransmissionProbe = false
		retransmissionRACK = false
		retransmissionClose = true
	}
	armPersist := func(sentAt time.Time) {
		offset := int(sendNext - sendUnacknowledged)
		_, total, writeClosed := c.sendSnapshot(offset, 0)
		// Linux keeps packets_out under the normal retransmission timer.
		// Persist is needed only when no transmitted sequence is outstanding
		// and a closed receive window prevents new data or FIN from being sent.
		pending := len(outstanding) == 0 && (offset < total || writeClosed && !localFINSent)
		if pending && peerWindow == 0 && persist == nil {
			if persistRTO < rtt.rto {
				persistRTO = rtt.rto
			}
			persistDeadline = time.Now().Add(persistRTO)
			if !sentAt.IsZero() {
				persistDeadline = sentAt.Add(persistRTO)
			}
			delay := time.Until(persistDeadline)
			if delay < 0 {
				delay = 0
			}
			persist = persistTimer.reset(delay)
		} else if peerWindow != 0 || !pending {
			persistTimer.stop()
			persist = nil
			persistDeadline = time.Time{}
			persistRTO = time.Second
			persistAttempts = 0
		}
	}
	clearDelayedACK := func() {
		delayedACKTimer.stop()
		delayedACK = nil
		delayedACKDeadline = time.Time{}
		ackPending = false
		ackSegments = 0
	}
	sackOptions := func(reservePayload int) ([]byte, bool) {
		if !peerSACK {
			return nil, false
		}
		maximumBlocks := tcpSACKBlockLimit(c.mtu, c.key.local.Addr(), c.peerTimestamp, reservePayload)
		options := tcpSACKOptions(outOfOrder, recentSACK, maximumBlocks, recentDSACK, haveRecentDSACK)
		return options, haveRecentDSACK && len(options) >= 10
	}
	sendACKAt := func(sequence uint32) error {
		options, dsackSent := sackOptions(0)
		window := advertisedReceiveWindow()
		if err := c.sendSegmentWithOptions(sequence, receiveNext, tcpFlagACK, window, options, nil); err != nil {
			return err
		}
		lastACKSent = receiveNext
		lastAdvertisedWindow = window
		if dsackSent {
			haveRecentDSACK = false
		}
		clearDelayedACK()
		return nil
	}
	sendACK := func() error {
		sequence := tcpAcceptableSendSequence(sendUnacknowledged, sendNext, peerWindow, peerScale)
		return sendACKAt(sequence)
	}
	sendChallengeACK := func() error {
		if !c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
			return nil
		}
		return sendACK()
	}
	sendChallengeACKAt := func(sequence uint32) error {
		if !c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
			return nil
		}
		return sendACKAt(sequence)
	}
	scheduleACK := func(immediate, data bool, receivedAt time.Time) error {
		ackPending = true
		if data {
			ackSegments++
		}
		if immediate || ackSegments >= 2 {
			return sendACK()
		}
		if delayedACK == nil {
			delayedACKDeadline = receivedAt.Add(tcpDelayedACKTimeout)
			delay := delayedACKDeadline.Sub(time.Now())
			if delay < 0 {
				delay = 0
			}
			delayedACK = delayedACKTimer.reset(delay)
		}
		return nil
	}
	var sendNextData func(uint32, bool) (bool, error)
	sendNextData = func(congestionAllowance uint32, limitedTransmit bool) (bool, error) {
		windowFlight := sendNext - sendUnacknowledged
		congestionFlight := congestionFlight()
		now := time.Now()
		if !ecnHoldUntil.IsZero() {
			if now.Before(ecnHoldUntil) {
				armPacing(ecnHoldUntil.Sub(now))
				return false, nil
			}
			ecnHoldUntil = time.Time{}
		}
		if congestionFlight == 0 && !lastDataSent.IsZero() && now.Sub(lastDataSent) > rtt.rto {
			congestionWindow = tcpRestartWindow(congestionWindow, peerMSS)
			hyStart.restartRound(sendNext)
		}
		congestionLimit := growCongestionWindow(congestionWindow, congestionAllowance)
		if localFINSent || windowFlight >= peerWindow || congestionFlight >= congestionLimit {
			return false, nil
		}
		offset := int(sendNext - sendUnacknowledged)
		options, dsackSent := sackOptions(1)
		optionSize := (len(options) + 3) &^ 3
		if optionSize >= pathMSS {
			// Preserve one data byte when an exceptionally small path cannot fit
			// the optional SACK feedback in addition to negotiated timestamps.
			options = nil
			dsackSent = false
			optionSize = 0
		}
		segmentMSS := tcpSegmentPayloadLimit(peerMSS, pathMSS, optionSize)
		size := segmentMSS
		transmitMTU := c.mtu
		probe := false
		probePayload := 0
		canProbePath := plpmtu.searching && !fastRecovery && !rtoRecovery && sackedRanges == 0
		if canProbePath {
			candidateMTU, ok := plpmtu.candidate(now)
			if ok {
				candidateMSS := tcpMSSForMTU(candidateMTU, c.key.local.Addr())
				if c.peerTimestamp {
					candidateMSS -= 12
				}
				candidateMSS = tcpSegmentPayloadLimit(c.peerMSS, candidateMSS, optionSize)
				_, total, _ := c.sendSnapshot(offset, 0)
				if candidateMSS > segmentMSS && total-offset >= candidateMSS+(tcpDuplicateACKThreshold+1)*segmentMSS {
					size = candidateMSS
					probePayload = candidateMSS
					transmitMTU = candidateMTU
					probe = true
				}
			}
		}
		if available := int(peerWindow - windowFlight); size > available {
			size = available
		}
		if available := int(congestionLimit - congestionFlight); size > available {
			size = available
		}
		if probe && size != probePayload {
			probe = false
			transmitMTU = c.mtu
			if size > segmentMSS {
				size = segmentMSS
			}
		}
		if size <= 0 {
			return false, nil
		}
		payload, total, writeClosed := c.sendSnapshot(offset, size)
		if len(payload) == 0 {
			return false, nil
		}
		if delay := controller.pacingDelay(now, congestionWindow, congestionFlight, peerMSS, rtt.srtt, slowStartThreshold); delay > 0 {
			armPacing(delay)
			return false, nil
		}
		if congestionAllowance == 0 {
			if !c.socketOptions().noDelay && len(outstanding) != 0 && len(payload) < segmentMSS && !writeClosed {
				return false, nil
			}
		}
		flags := tcpFlagACK
		if offset+len(payload) == total {
			flags |= tcpFlagPSH
		}
		next := sendNext + uint32(len(payload))
		carriesCWR := c.peerECN && c.sendCWR
		c.publishICMPSequenceRange(sendUnacknowledged, next)
		window := advertisedReceiveWindow()
		timestamp, hostQueue, err := c.sendSegmentForMTU(sendNext, receiveNext, flags, window, options, payload, true, transmitMTU)
		if err != nil {
			return false, err
		}
		sentAt := hostQueue.queuedAt
		lastACKSent = receiveNext
		lastAdvertisedWindow = window
		if dsackSent {
			haveRecentDSACK = false
		}
		if ackPending {
			clearDelayedACK()
		}
		controller.onDataSend(len(payload), peerMSS, sentAt, congestionWindow, congestionFlight, rtt.srtt, slowStartThreshold)
		outstanding = append(outstanding, sentTCPSegment{sequence: sendNext, end: next, flags: flags, payload: payload, sentAt: sentAt, timestamp: timestamp, firstSentAt: sentAt, transmissions: 1, limited: limitedTransmit, cwr: carriesCWR, mtuProbe: probe, probeMTU: transmitMTU, hostQueue: hostQueue})
		bytesSent += uint64(len(payload))
		if probe {
			plpmtu.sent(transmitMTU, sendNext, next)
			pathMTUProbes++
			c.stack.stats.pathMTUProbes.Add(1)
		}
		if fastRecovery && peerSACK {
			prrOut += uint64(len(payload))
		}
		sendNext = next
		lastDataSent = sentAt
		return true, nil
	}
	fillWindow := func() error {
		defer armLiveness()
		if localFINSent {
			armPersist(time.Time{})
			return nil
		}
		for {
			sent, err := sendNextData(0, false)
			if err != nil {
				return err
			}
			if !sent {
				break
			}
		}
		if !ecnHoldUntil.IsZero() && time.Now().Before(ecnHoldUntil) {
			return nil
		}
		windowFlight := sendNext - sendUnacknowledged
		congestionFlight := congestionFlight()
		offset := int(sendNext - sendUnacknowledged)
		_, total, writeClosed := c.sendSnapshot(offset, 0)
		if writeClosed && offset >= total && windowFlight < peerWindow && congestionFlight < congestionWindow {
			c.publishICMPSequenceRange(sendUnacknowledged, sendNext+1)
			options, dsackSent := sackOptions(0)
			window := advertisedReceiveWindow()
			timestamp, hostQueue, err := c.sendSegmentForMTU(sendNext, receiveNext, tcpFlagACK|tcpFlagFIN, window, options, nil, false, c.mtu)
			if err != nil {
				return err
			}
			sentAt := hostQueue.queuedAt
			lastACKSent = receiveNext
			lastAdvertisedWindow = window
			if dsackSent {
				haveRecentDSACK = false
			}
			outstanding = append(outstanding, sentTCPSegment{sequence: sendNext, end: sendNext + 1, flags: tcpFlagACK | tcpFlagFIN, sentAt: sentAt, timestamp: timestamp, firstSentAt: sentAt, transmissions: 1, hostQueue: hostQueue})
			sendNext++
			// Only the endpoint that closes first, or closes simultaneously,
			// enters TIME-WAIT. A FIN sent after the peer's FIN is LAST-ACK.
			timeWaitRequired = !remoteFINReceived
			localFINSent = true
			if ackPending {
				clearDelayedACK()
			}
		}
		if len(outstanding) != 0 {
			armRetransmission()
		} else if !localFINAcked {
			armRetransmission()
		}
		armPersist(time.Time{})
		return nil
	}
	retransmitSegment := func(index int, timeout bool) error {
		if len(outstanding) == 0 {
			return nil
		}
		if index < 0 || index >= len(outstanding) {
			index = firstUnsackedSegment(outstanding)
		}
		if index < 0 || index >= len(outstanding) {
			return nil
		}
		if plpmtu.active {
			retransmitSequence := outstanding[index].sequence
			delay := tcpPLPMTUProbeHeadway(congestionWindow, peerMSS, rtt.srtt)
			if timeout {
				delay = tcpPLPMTUTimeoutDelay(delay)
			}
			plpmtu.inconclusive(time.Now(), delay)
			for segmentIndex := range outstanding {
				outstanding[segmentIndex].mtuProbe = false
				outstanding[segmentIndex].probeMTU = 0
			}
			outstanding = splitTCPSegments(outstanding, peerMSS)
			if sackedRanges != 0 {
				recountSACK()
			}
			index = -1
			for segmentIndex := range outstanding {
				if outstanding[segmentIndex].sequence == retransmitSequence {
					index = segmentIndex
					break
				}
			}
			if index < 0 {
				index = firstUnsackedSegment(outstanding)
			}
			armPathMTUProbe()
		}
		if index < 0 || index >= len(outstanding) {
			return nil
		}
		oldest := &outstanding[index]
		sentSize := oldest.end - oldest.sequence
		rackRetransmission := oldest.rackLost
		lostRetransmission := rackRetransmission && oldest.transmissions > 1
		lostCWR := oldest.cwr
		beginUndo := timeout && !rtoRecovery || !timeout && (!fastRecovery || lostRetransmission)
		if beginUndo {
			flight := ordinaryFlight()
			if !timeout && controller.algorithm != CongestionControlBBR {
				flight = lossRecoveryFlightSize(outstanding)
			}
			undo.begin(timeout, sendNext, congestionWindow, slowStartThreshold, flight, controller, rtt)
		}
		window := advertisedReceiveWindow()
		repeated := oldest.transmissions > 1
		retransmitTimestamp, hostQueue, err := c.sendSegmentTimestamp(oldest.sequence, receiveNext, oldest.flags, window, oldest.payload)
		if err != nil {
			return err
		}
		retransmitHistory.record(oldest.sequence, oldest.end)
		undo.recordRetransmission(oldest.sequence, oldest.end, retransmitTimestamp, repeated)
		sentAt := hostQueue.queuedAt
		lastACKSent = receiveNext
		lastAdvertisedWindow = window
		oldest.sentAt = sentAt
		oldest.timestamp = retransmitTimestamp
		oldest.hostQueue = hostQueue
		oldest.transmissions++
		oldest.sackRetried = !timeout
		oldest.rackLost = false
		if rackRetransmission {
			haveRACKLoss = hasRACKLoss(outstanding)
		}
		oldest.cwr = false
		c.noteRetransmission()
		if !timeout && peerSACK {
			c.stack.stats.tcpSACKRetransmissions.Add(1)
			if rackRetransmission {
				c.stack.stats.tcpRACKRetransmissions.Add(1)
			}
		}
		if timeout {
			tailProbeActive = false
			tailProbeRetransmit = false
			flight := ordinaryFlight()
			// RFC 5681 updates ssthresh only on the first timeout for one
			// outstanding sequence range. Recomputing it after cwnd has already
			// fallen to one SMSS would collapse CUBIC's retained threshold on
			// every exponential-backoff retry.
			if !rtoRecovery {
				hyStart.disable()
				slowStartThreshold = controller.onTimeout(congestionWindow, flight, peerMSS)
				rtoRecovery = true
				rtoRecoveryPoint = sendNext
				if c.peerECN {
					c.sendCWR = true
				}
			}
			congestionWindow = uint32(peerMSS)
			fastRecovery = false
			prrPriorFlight = 0
			prrDelivered = 0
			prrOut = 0
			ecnRecoveryPoint = sendNext
			ecnRecoveryActive = true
			for index := range outstanding {
				outstanding[index].sacked = false
				outstanding[index].sackRetried = false
				outstanding[index].rackLost = false
			}
			sackedRanges, sackedBytes = 0, 0
			haveRACKLoss = false
			rtt.backoff()
		} else {
			tailProbeActive = false
			tailProbeRetransmit = false
			if !fastRecovery || lostRetransmission {
				hyStart.disable()
				flight := lossRecoveryFlightSize(outstanding)
				// RFC 3042 excludes Limited Transmit data only from the
				// FlightSize calculation that enters this recovery episode. Any
				// still-unacknowledged range is ordinary flight in later episodes.
				for index := range outstanding {
					outstanding[index].limited = false
				}
				if controller.algorithm == CongestionControlBBR {
					flight = ordinaryFlight()
				}
				// RFC 3168 permits only one congestion-window reduction for
				// dropped and/or CE-marked packets from one transmitted window.
				// A lost retransmission is the RFC 8985 exception: it is a new
				// congestion indication even while the original recovery is active.
				if lostRetransmission || lostCWR || tcpECNStartsRecovery(ecnRecoveryActive, sendUnacknowledged, ecnRecoveryPoint) {
					slowStartThreshold = controller.onCongestion(congestionWindow, flight, peerMSS)
					ecnRecoveryPoint = sendNext
					ecnRecoveryActive = true
					if c.peerECN {
						c.sendCWR = true
					}
				}
				if controller.algorithm == CongestionControlBBR {
					congestionWindow = flight
					if minimum := uint32(bbrMinimumCongestionMSS * peerMSS); congestionWindow < minimum {
						congestionWindow = minimum
					}
				} else if peerSACK {
					// RFC 6675 uses the SACK scoreboard's pipe estimate rather
					// than NewReno duplicate-ACK window inflation.
					congestionWindow = slowStartThreshold
				} else {
					congestionWindow = slowStartThreshold + uint32(3*peerMSS)
				}
				fastRecovery = true
				recoveryPoint = sendNext
				if peerSACK {
					prrPriorFlight = flight
					prrDelivered = 0
					prrOut = uint64(sentSize)
					// Linux PRR admits exactly the forced recovery-entry
					// retransmission before delivery feedback grants more.
					congestionWindow = sackRecoveryPipe(outstanding, peerMSS)
				}
			} else if peerSACK {
				prrOut += uint64(sentSize)
			}
		}
		if len(outstanding) != 0 {
			armRetransmission()
		}
		controller.onRetransmit(len(oldest.payload), peerMSS, oldest.sentAt, congestionWindow, congestionFlight(), rtt.srtt, slowStartThreshold)
		return nil
	}
	retransmitRTORecovery := func(index int) error {
		if len(outstanding) == 0 {
			return nil
		}
		if index < 0 || index >= len(outstanding) {
			return nil
		}
		segment := &outstanding[index]
		window := advertisedReceiveWindow()
		retransmitTimestamp, hostQueue, err := c.sendSegmentTimestamp(segment.sequence, receiveNext, segment.flags, window, segment.payload)
		if err != nil {
			return err
		}
		retransmitHistory.record(segment.sequence, segment.end)
		undo.recordRetransmission(segment.sequence, segment.end, retransmitTimestamp, segment.transmissions > 1)
		sentAt := hostQueue.queuedAt
		lastACKSent = receiveNext
		lastAdvertisedWindow = window
		if segment.cwr && c.peerECN {
			c.sendCWR = true
		}
		segment.cwr = false
		segment.sentAt = sentAt
		segment.timestamp = retransmitTimestamp
		segment.hostQueue = hostQueue
		segment.transmissions++
		segment.sackRetried = false
		rackLost := segment.rackLost
		segment.rackLost = false
		if rackLost {
			haveRACKLoss = hasRACKLoss(outstanding)
		}
		tailProbeActive = false
		tailProbeRetransmit = false
		c.noteRetransmission()
		controller.onRetransmit(len(segment.payload), peerMSS, segment.sentAt, congestionWindow, ordinaryFlight(), rtt.srtt, slowStartThreshold)
		armRetransmission()
		return nil
	}
	failPLPMTUProbe := func() error {
		if !plpmtu.active {
			return nil
		}
		plpmtu.failed(time.Now(), tcpPLPMTUProbeHeadway(congestionWindow, peerMSS, rtt.srtt))
		if !plpmtu.searching {
			// Convergence reconfirms the working lower bound so an expired
			// destination-cache entry cannot immediately restart probing.
			c.stack.confirmPathMTU(c.key.remote.Addr(), c.mtu, c)
		}
		for index := range outstanding {
			outstanding[index].mtuProbe = false
			outstanding[index].probeMTU = 0
		}
		outstanding = splitTCPSegments(outstanding, peerMSS)
		if sackedRanges != 0 {
			recountSACK()
		}
		index := firstUnsackedSegment(outstanding)
		if index < 0 || index >= len(outstanding) {
			armPathMTUProbe()
			return nil
		}
		segment := &outstanding[index]
		window := advertisedReceiveWindow()
		timestamp, hostQueue, err := c.sendSegmentForMTU(segment.sequence, receiveNext, segment.flags, window, nil, segment.payload, false, c.mtu)
		if err != nil {
			return err
		}
		retransmitHistory.record(segment.sequence, segment.end)
		segment.sentAt = hostQueue.queuedAt
		segment.timestamp = timestamp
		segment.hostQueue = hostQueue
		segment.transmissions++
		segment.sackRetried = true
		lastACKSent = receiveNext
		lastAdvertisedWindow = window
		c.noteRetransmission()
		pathMTUFailures++
		c.stack.stats.pathMTUProbeFailures.Add(1)
		controller.onRetransmit(len(segment.payload), peerMSS, segment.sentAt, congestionWindow, congestionFlight(), rtt.srtt, slowStartThreshold)
		armRetransmission()
		armPathMTUProbe()
		return nil
	}
	recoverSACKHoles := func(highest uint32, allowSpeculative bool) error {
		for {
			index := firstUnretriedLoss(outstanding, peerMSS)
			if index < 0 && allowSpeculative {
				index = firstUnretriedSACKHole(outstanding, highest)
			}
			if index < 0 {
				return nil
			}
			size := outstanding[index].end - outstanding[index].sequence
			pipe := sackRecoveryPipe(outstanding, peerMSS)
			// RFC 6675 permits the recovery-entry retransmission before
			// SetPipe, but every later transmission requires cwnd-Pipe space.
			if !sackRecoveryCanSend(fastRecovery, pipe, size, congestionWindow) {
				return nil
			}
			if fastRecovery {
				now := time.Now()
				if delay := controller.pacingDelay(now, congestionWindow, pipe, peerMSS, rtt.srtt, slowStartThreshold); delay > 0 {
					armPacing(delay)
					return nil
				}
			}
			if err := retransmitSegment(index, false); err != nil {
				return err
			}
		}
	}
	applyPathMTU := func(mtu int, retransmit bool) error {
		configured := c.socketOptions().congestion
		if configured != controller.algorithm {
			controller = newTCPCongestionController(configured)
			hyStart.disable()
			if pacingTimer != nil {
				pacingTimer.stop()
			}
			pacing = nil
			pacingDeadline = time.Time{}
		}
		priorMTU := c.mtu
		c.mtu = mtu
		if mtu < priorMTU {
			for index := range outstanding {
				outstanding[index].mtuProbe = false
				outstanding[index].probeMTU = 0
			}
			plpmtu.reduce(mtu, priorMTU, c.stack.network.Load().mtu, time.Now())
		}
		pathMSS = tcpMSSForMTU(mtu, c.key.local.Addr())
		if c.peerTimestamp {
			pathMSS -= 12
		}
		receiveMSS = pathMSS
		armPathMTUProbe()
		newMSS := clampMSS(c.peerMSS, pathMSS)
		if newMSS == peerMSS {
			return nil
		}
		if newMSS > peerMSS {
			peerMSS = newMSS
			controller.onMTUChange()
			return nil
		}
		oldMSS := peerMSS
		peerMSS = newMSS
		congestionWindow = tcpCongestionValueForMSS(congestionWindow, oldMSS, newMSS, true)
		if slowStartThreshold != ^uint32(0)>>1 {
			slowStartThreshold = tcpCongestionValueForMSS(slowStartThreshold, oldMSS, newMSS, false)
		}
		controller.onMTUChange()
		outstanding = splitTCPSegments(outstanding, peerMSS)
		if sackedRanges != 0 {
			recountSACK()
		}
		if retransmit && len(outstanding) != 0 {
			index := firstUnsackedSegment(outstanding)
			segment := &outstanding[index]
			window := advertisedReceiveWindow()
			timestamp, hostQueue, err := c.sendSegmentForMTU(segment.sequence, receiveNext, segment.flags, window, nil, segment.payload, false, c.mtu)
			if err != nil {
				return err
			}
			retransmitHistory.record(segment.sequence, segment.end)
			sentAt := hostQueue.queuedAt
			lastACKSent = receiveNext
			lastAdvertisedWindow = window
			if segment.cwr && c.peerECN {
				c.sendCWR = true
			}
			segment.cwr = false
			segment.sentAt = sentAt
			segment.timestamp = timestamp
			segment.hostQueue = hostQueue
			segment.transmissions++
			c.noteRetransmission()
			controller.onRetransmit(len(segment.payload), peerMSS, segment.sentAt, congestionWindow, congestionFlight(), rtt.srtt, slowStartThreshold)
			armRetransmission()
		}
		return nil
	}
	armPathMTUProbe()
	armLiveness()
	var timerBacklog tcpTimerBacklog
	for {
		activeRetransmit, activePersist, activeDelayedACK := retransmit, persist, delayedACK
		activeLiveness, activePathMTUProbe, activePacing := liveness, pathMTUProbe, pacing
		inboundNotify := c.inbound.notify
		var earliestTimer time.Time
		for _, timer := range [...]struct {
			active   <-chan time.Time
			deadline time.Time
		}{
			{activeRetransmit, retransmissionDeadline}, {activePersist, persistDeadline},
			{activeDelayedACK, delayedACKDeadline}, {activeLiveness, livenessDeadline},
			{activePathMTUProbe, pathMTUDeadline}, {activePacing, pacingDeadline},
		} {
			if timer.active != nil && !timer.deadline.IsZero() && (earliestTimer.IsZero() || timer.deadline.Before(earliestTimer)) {
				earliestTimer = timer.deadline
			}
		}
		if !earliestTimer.IsZero() {
			// A select entered before several deadlines may resume after all of
			// them. Expose only the earliest one so runtime scheduling cannot
			// reorder protocol timers.
			if retransmissionDeadline.After(earliestTimer) {
				activeRetransmit = nil
			}
			if persistDeadline.After(earliestTimer) {
				activePersist = nil
			}
			if delayedACKDeadline.After(earliestTimer) {
				activeDelayedACK = nil
			}
			if livenessDeadline.After(earliestTimer) {
				activeLiveness = nil
			}
			if pathMTUDeadline.After(earliestTimer) {
				activePathMTUProbe = nil
			}
			if pacingDeadline.After(earliestTimer) {
				activePacing = nil
			}
		}
		drainBacklog, forceTimer := timerBacklog.order(c.inbound.len(), earliestTimer, time.Now())
		if drainBacklog {
			activeRetransmit, activePersist, activeDelayedACK = nil, nil, nil
			activeLiveness, activePathMTUProbe, activePacing = nil, nil, nil
		} else if forceTimer {
			inboundNotify = nil
		}
		select {
		case <-inboundNotify:
			segment, ok := c.inbound.dequeue()
			if !ok {
				continue
			}
			timerBacklog.consumed()
			processedAt := time.Now()
			receivedAt := tcpSegmentEventTime(segment, processedAt, eventTime)
			// Device receive functions may call Stack.Write concurrently. Keep
			// the actor's protocol clock monotonic even if lock acquisition puts
			// two batches into its FIFO in the opposite timestamp order.
			eventTime = receivedAt
			segmentLength := uint32(len(segment.payload))
			if segment.flags&tcpFlagSYN != 0 {
				segmentLength++
			}
			if segment.flags&tcpFlagFIN != 0 {
				segmentLength++
			}
			receiveWindow := receiveWindowState.size(receiveNext)
			retransmittedTimeWaitFIN := timeWaitArmed && segment.flags&(tcpFlagRST|tcpFlagSYN|tcpFlagACK|tcpFlagFIN) == tcpFlagACK|tcpFlagFIN &&
				segment.sequence+uint32(len(segment.payload))+1 == receiveNext
			if !tcpSegmentAcceptable(segment.sequence, segmentLength, receiveNext, receiveWindow) {
				if retransmittedTimeWaitFIN {
					if err := sendACK(); err != nil {
						return err
					}
					armClose(time.Now(), tcpTimeWaitDuration)
					continue
				}
				if segment.flags&tcpFlagRST == 0 {
					var err error
					if tcpKeepAliveOrWindowProbe(segment, segmentLength, receiveNext, receiveWindow) {
						err = sendACK()
					} else {
						sequence := tcpChallengeACKSequence(segment, sendUnacknowledged, sendNext, peerWindow, peerScale)
						err = sendChallengeACKAt(sequence)
					}
					if err != nil {
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
				if receivedAt.Sub(lastTimestampUpdate) < 24*24*time.Hour && tcpSequenceLess(timestampValue, c.recentTimestamp) {
					if err := sendChallengeACK(); err != nil {
						return err
					}
					continue
				}
				if tcpSequenceLessEqual(segment.sequence, lastACKSent) {
					c.recentTimestamp = timestampValue
					lastTimestampUpdate = receivedAt
				}
			}
			lastActivity = receivedAt
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
			ack := segment.acknowledgement
			if tcpSequenceGreater(ack, sendNext) {
				if err := sendChallengeACK(); err != nil {
					return err
				}
				continue
			}
			if tcpSequenceLess(ack, sendUnacknowledged) {
				oldestAcceptable := maximumPeerWindow
				if uint64(oldestAcceptable) > bytesAcknowledged {
					oldestAcceptable = uint32(bytesAcknowledged)
				}
				// RFC 5961 section 5.2 and Linux reject an ACK older than both
				// the largest observed send window and all bytes ever acknowledged.
				// A merely reordered ACK may still carry valid receive data below.
				if tcpSequenceLess(ack, sendUnacknowledged-oldestAcceptable) {
					if err := sendChallengeACK(); err != nil {
						return err
					}
					continue
				}
			} else {
				previousSendUnacknowledged := sendUnacknowledged
				sackScoreboardEmpty := sackedRanges == 0
				previousWindow := peerWindow
				if tcpWindowUpdateAllowed(segment.sequence, ack, peerWindowSequence, peerWindowACK) {
					peerWindow = uint32(segment.window) << peerScale
					if peerWindow > maximumPeerWindow {
						maximumPeerWindow = peerWindow
					}
					peerWindowSequence = segment.sequence
					peerWindowACK = ack
				}
				ackAdvanced := tcpSequenceGreater(ack, sendUnacknowledged)
				recoveryAtACK := fastRecovery
				newlyDelivered := uint32(0)
				acknowledgedForUndo := uint32(0)
				rttSample := time.Duration(0)
				rtoPartialACK := false
				ecnCongestion := false
				if c.peerECN && segment.flags&tcpFlagECE != 0 && len(outstanding) != 0 && tcpECNStartsRecovery(ecnRecoveryActive, ack, ecnRecoveryPoint) {
					hyStart.disable()
					undo.active = false
					minimumWindow := congestionWindow <= uint32(peerMSS)
					flight := congestionFlight()
					slowStartThreshold = controller.onECN(congestionWindow, flight, peerMSS)
					congestionWindow = slowStartThreshold
					ecnRecoveryPoint = sendNext
					ecnRecoveryActive = true
					ecnCongestion = true
					c.sendCWR = true
					if minimumWindow {
						// RFC 3168 section 6.1.2 uses the retransmission interval
						// to reduce an already one-segment sending rate further.
						ecnHoldUntil = receivedAt.Add(rtt.rto)
						armPacing(ecnHoldUntil.Sub(time.Now()))
					}
				}
				if tcpSequenceGreater(ack, sendUnacknowledged) {
					acknowledged := ack - sendUnacknowledged
					acknowledgedForUndo = acknowledged
					probeSucceeded := plpmtu.active && tcpSequenceGreaterEqual(ack, plpmtu.probeEnd)
					newlyDelivered = tcpNewlyAcknowledgedBytes(outstanding, ack)
					bytesAcknowledged += uint64(acknowledged)
					flightBeforeACK := congestionFlight()
					c.acknowledgeSend(int(acknowledged))
					sendUnacknowledged = ack
					c.publishICMPSequenceRange(sendUnacknowledged, sendNext)
					duplicateACKs = 0
					rtoAttempts = 0
					if rtoRecovery {
						if tcpSequenceGreaterEqual(ack, rtoRecoveryPoint) {
							rtoRecovery = false
							rtoRecoveryPoint = 0
							ageRACKReordering()
						} else {
							rtoPartialACK = true
						}
					}
					blackHoleRTOs = 0
					lastSoftError = nil
					sampledRTT := false
					if c.peerTimestamp && timestampEcho != 0 {
						delta := c.stack.tcpTimestampAt(receivedAt) - timestampEcho
						if delta != 0 && time.Duration(delta)*time.Millisecond <= tcpMaximumRTO {
							rttSample = time.Duration(delta) * time.Millisecond
							rtt.observeAt(rttSample, receivedAt)
							sampledRTT = true
						}
					}
					// A negotiated timestamp only removes Karn ambiguity when this
					// ACK actually produced a valid timestamp sample. If it did not,
					// the sent-time fallback must still reject a cumulative ACK that
					// covers any retransmitted range.
					ambiguousRTT := tcpACKRTTAmbiguous(outstanding, ack)
					for len(outstanding) != 0 && tcpSequenceGreaterEqual(ack, outstanding[0].end) {
						oldest := outstanding[0]
						if oldest.sacked {
							sackedRanges--
							sackedBytes -= oldest.end - oldest.sequence
						} else {
							observeRACKReordering(oldest.end, oldest.transmissions > 1)
						}
						candidate := tcpRACKSample{sentAt: oldest.sentAt, end: oldest.end, rtt: elapsedRTTSampleAt(oldest.sentAt, receivedAt), timestamp: oldest.timestamp, retransmitted: oldest.transmissions > 1}
						rackLatestDelivered = newerRACKSample(rackLatestDelivered, validRACKSample(candidate, rtt.minimum, timestampEcho))
						if !sampledRTT && !ambiguousRTT && oldest.transmissions == 1 {
							rttSample = elapsedRTTSampleAt(oldest.sentAt, receivedAt)
							rtt.observeAt(rttSample, receivedAt)
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
						sackedRanges, sackedBytes = 0, 0
					}
					if len(outstanding) != 0 && tcpSequenceGreater(ack, outstanding[0].sequence) {
						if outstanding[0].sacked {
							sackedBytes -= ack - outstanding[0].sequence
						} else {
							observeRACKReordering(ack, outstanding[0].transmissions > 1)
						}
						candidate := tcpRACKSample{sentAt: outstanding[0].sentAt, end: ack, rtt: elapsedRTTSampleAt(outstanding[0].sentAt, receivedAt), timestamp: outstanding[0].timestamp, retransmitted: outstanding[0].transmissions > 1}
						rackLatestDelivered = newerRACKSample(rackLatestDelivered, validRACKSample(candidate, rtt.minimum, timestampEcho))
						trimAcknowledgedTCPSegment(&outstanding[0], ack)
					}
					if probeSucceeded {
						mtu := plpmtu.success(receivedAt)
						c.stack.confirmPathMTU(c.key.remote.Addr(), mtu, c)
						pathMTUSuccesses++
						c.stack.stats.pathMTUProbeSuccesses.Add(1)
						if err := applyPathMTU(mtu, false); err != nil {
							return err
						}
					}
					// RFC 3042 excludes Limited Transmit data only when the
					// duplicate-ACK episode that sent it enters recovery. Once a
					// cumulative ACK advances without doing so, every remaining
					// range is ordinary flight for any later loss episode.
					if !fastRecovery {
						for index := range outstanding {
							outstanding[index].limited = false
						}
					}
					if tailProbeActive && tcpSequenceGreaterEqual(ack, tailProbeEnd) {
						if !tailProbeRetransmit {
							tailProbeActive = false
						} else if tcpSequenceGreater(ack, tailProbeEnd) {
							if !fastRecovery {
								if tcpECNStartsRecovery(ecnRecoveryActive, sendUnacknowledged, ecnRecoveryPoint) {
									hyStart.disable()
									slowStartThreshold = controller.onCongestion(congestionWindow, flightBeforeACK, peerMSS)
									congestionWindow = slowStartThreshold
									ecnRecoveryPoint = sendNext
									ecnRecoveryActive = true
									if c.peerECN {
										c.sendCWR = true
									}
								}
							}
							tailProbeActive = false
							tailProbeRetransmit = false
						}
					}
					now := receivedAt
					if fastRecovery {
						// BBR continues delivery-rate and min-RTT sampling during
						// recovery, but PRR/NewReno retains ownership of cwnd.
						controller.observeRecoveryACK(congestionWindow, acknowledged, peerMSS, now, rtt.srtt, normalizedRTTSample(rttSample), flightBeforeACK, bbrApplicationLimited())
						if tcpSequenceGreaterEqual(ack, recoveryPoint) {
							ageRACKReordering()
							fastRecovery = false
							prrPriorFlight = 0
							prrDelivered = 0
							prrOut = 0
							congestionWindow = slowStartThreshold
						} else if !peerSACK {
							// RFC 6582 NewReno: a partial ACK confirms one loss
							// but not the recovery point. Deflate by newly ACKed
							// data, add one SMSS, and retransmit the next hole.
							congestionWindow = newRenoPartialACKWindow(congestionWindow, acknowledged, peerMSS)
							if err := retransmitSegment(firstUnsackedSegment(outstanding), false); err != nil {
								return err
							}
						}
					} else if !ecnCongestion {
						growth := acknowledged
						sample := normalizedRTTSample(rttSample)
						if controller.algorithm != CongestionControlBBR && congestionWindow < slowStartThreshold {
							var completed bool
							growth, completed = hyStart.onACK(ack, sendNext, acknowledged, sample)
							if completed {
								slowStartThreshold = congestionWindow
							}
						}
						congestionWindow = controller.onACKWithThreshold(congestionWindow, growth, peerMSS, now, rtt.srtt, sample, flightBeforeACK, slowStartThreshold, bbrApplicationLimited())
					}
					if target := sendAutoTune.target(receivedAt, rtt.srtt, bytesAcknowledged, tcpMaximumSendCapacity); target > 0 {
						c.growSendCapacity(target)
					}
					armRetransmissionAfterACK(receivedAt)
				}
				history := uint32(bytesAcknowledged)
				if bytesAcknowledged > uint64(tcpMaximumScaledWindow) {
					history = tcpMaximumScaledWindow
				}
				dsack, hasDSACK := tcpSACKBlock{}, false
				if peerSACK {
					dsack, hasDSACK = parseTCPDSACKOption(segment.options, ack, sendNext, history)
				}
				priorDSACK := seenDSACK
				spuriousRecovery := ackAdvanced && undo.detectEifel(timestampEcho, hasDSACK, priorDSACK, ack)
				if hasDSACK {
					if !dsackUndoDisabled {
						matched, repeated := retransmitHistory.match(dsack)
						switch {
						case !matched:
							// RFC 3708 A.4 disables DSACK undo for the rest of
							// this connection after evidence of network duplication.
							dsackUndoDisabled = true
							undo.dsackDisabled = true
						case repeated:
							undo.dsackDisabled = true
						case undo.observeDSACK(dsack, ack, previousSendUnacknowledged, sackScoreboardEmpty):
							spuriousRecovery = true
						}
					}
					seenDSACK = true
					rackReorderingSeen = true
					rackReorderPersist = 16
					if !rackDSACKRoundSet || tcpSequenceGreater(ack, rackDSACKRound) {
						if rackReorderingScale != ^uint32(0) {
							rackReorderingScale++
						}
						rackDSACKRound = sendNext
						rackDSACKRoundSet = true
					}
					if tailProbeActive && tailProbeRetransmit && tcpSequenceLess(dsack.left, tailProbeEnd) && tcpSequenceGreaterEqual(dsack.right, tailProbeEnd) {
						tailProbeActive = false
						tailProbeRetransmit = false
					}
				}
				if spuriousRecovery && segment.flags&tcpFlagECE != 0 {
					undo.active = false
				} else if spuriousRecovery {
					flight := ordinaryFlight()
					response := undo.eifelRTOResponse()
					congestionWindow, slowStartThreshold, controller = undo.restore(flight, acknowledgedForUndo, peerMSS)
					if response.pending {
						eifelRTO = response
					}
					fastRecovery = false
					rtoRecovery = false
					rtoRecoveryPoint = 0
					prrPriorFlight = 0
					prrDelivered = 0
					prrOut = 0
					ecnRecoveryActive = false
					spuriousUndos++
					c.stack.stats.tcpSpuriousRecoveryUndos.Add(1)
					armRetransmissionAfterACK(receivedAt)
				}
				if eifelRTO.observe(ack, rttSample, &rtt) {
					armRetransmissionAfterACK(receivedAt)
				}
				var highestSACK uint32
				hasSACK := false
				newSACKInfo := false
				trackPRRLoss := recoveryAtACK && fastRecovery && peerSACK
				lostBefore := 0
				if trackPRRLoss {
					lostBefore = sackLostRangeCount(outstanding, peerMSS)
				}
				if peerSACK && len(outstanding) != 0 {
					blocks := parseTCPSACKOptions(segment.options, sendUnacknowledged, sendNext)
					var latestSACK tcpRACKSample
					var newlySACKed []sentTCPSegment
					outstanding, highestSACK, hasSACK, newSACKInfo, latestSACK, newlySACKed = applyTCPSACK(outstanding, blocks)
					if hasSACK {
						recountSACK()
					}
					for _, candidate := range newlySACKed {
						newlyDelivered = growCongestionWindow(newlyDelivered, candidate.end-candidate.sequence)
						observeRACKReordering(candidate.end, candidate.transmissions > 1)
					}
					latestSACK.rtt = elapsedRTTSampleAt(latestSACK.sentAt, receivedAt)
					rackLatestDelivered = newerRACKSample(rackLatestDelivered, validRACKSample(latestSACK, rtt.minimum, timestampEcho))
					reorderingWindow := rackReorderingWindow(rtt.minimum, rtt.srtt, rackReorderingScale)
					if !rackReorderingSeen && (fastRecovery || rtoRecovery || sackedRanges >= tcpDuplicateACKThreshold) {
						reorderingWindow = 0
					}
					if rackLatestDelivered.retransmitted || sackedRanges != 0 {
						haveRACKLoss = markRACKLoss(outstanding, rackLatestDelivered, receivedAt, reorderingWindow)
					}
				}
				newlyLost := trackPRRLoss && sackLostRangeCount(outstanding, peerMSS) > lostBefore
				if recoveryAtACK && fastRecovery && peerSACK && newlyDelivered != 0 {
					prrDelivered += uint64(newlyDelivered)
					pipe := sackRecoveryPipe(outstanding, peerMSS)
					congestionWindow = prrCongestionWindow(pipe, slowStartThreshold, prrPriorFlight, prrDelivered, prrOut, newlyDelivered, ackAdvanced, newlyLost, peerMSS)
				}
				probeFailed := false
				if plpmtu.active && hasSACK && sendUnacknowledged == plpmtu.probeStart && isolatedPLPMTUProbeLoss(outstanding, plpmtu.probeStart, highestSACK, peerMSS) {
					if err := failPLPMTUProbe(); err != nil {
						return err
					}
					probeFailed = true
				}
				if tailProbeActive && tailProbeRetransmit && !ackAdvanced && ack == tailProbeEnd && previousWindow == peerWindow && !hasSACK && len(segment.payload) == 0 && segment.flags&tcpFlagFIN == 0 {
					tailProbeActive = false
					tailProbeRetransmit = false
				}
				if rtoPartialACK {
					index := firstUnsackedSegment(outstanding)
					if peerSACK {
						// RFC 8985 avoids the traditional go-back-N behavior after
						// an RTO. A recent higher transmission is retried only after
						// the ACK of the RTO packet supplies time-based loss proof.
						index = firstRACKLoss(outstanding)
					}
					if err := retransmitRTORecovery(index); err != nil {
						return err
					}
				}
				if !rtoRecovery && haveRACKLoss {
					if err := recoverSACKHoles(highestSACK, false); err != nil {
						return err
					}
					haveRACKLoss = hasRACKLoss(outstanding)
				}
				duplicateEvidence := tcpDuplicateACKEvidence(segment, peerSACK, newSACKInfo, ackAdvanced, sendUnacknowledged, previousWindow, peerWindow)
				// RFC 6675 DupAcks and Limited Transmit apply before recovery.
				// Once SACK recovery is active, each ACK carrying new scoreboard
				// information drives SetPipe/NextSeg below without re-entering it.
				countDuplicate := duplicateEvidence && (!peerSACK || !fastRecovery)
				if !probeFailed && !rtoRecovery && len(outstanding) != 0 && countDuplicate {
					duplicateACKs++
					if duplicateACKs < tcpDuplicateACKThreshold && !fastRecovery {
						// RFC 3042 Limited Transmit permits one new segment for each
						// of the first two duplicate ACKs without inflating cwnd.
						// sendNextData still enforces the receive window and the
						// cumulative cwnd+2*SMSS allowance.
						if _, err := sendNextData(uint32(duplicateACKs*peerMSS), true); err != nil {
							return err
						}
					} else if duplicateACKs == tcpDuplicateACKThreshold {
						if peerSACK {
							// RFC 6675 enters recovery after DupThresh ACKs carrying
							// new SACK information even if IsLost remains false.
							if err := retransmitSegment(firstUnsackedSegment(outstanding), false); err != nil {
								return err
							}
							if err := recoverSACKHoles(highestSACK, false); err != nil {
								return err
							}
						} else if err := retransmitSegment(firstUnsackedSegment(outstanding), false); err != nil {
							return err
						}
					} else if duplicateACKs > tcpDuplicateACKThreshold && !peerSACK {
						congestionWindow = growCongestionWindow(congestionWindow, uint32(peerMSS))
					}
				}
				if fastRecovery && hasSACK {
					if ackAdvanced || newSACKInfo {
						if err := recoverSACKHoles(highestSACK, true); err != nil {
							return err
						}
					}
				}
			}

			fin := segment.flags&tcpFlagFIN != 0
			if len(segment.payload) != 0 || fin {
				previousReceiveNext := receiveNext
				newApplicationData := len(segment.payload) != 0 && tcpSequenceGreater(segment.sequence+uint32(len(segment.payload)), previousReceiveNext)
				hadOutOfOrder := len(outOfOrder) != 0
				recentSACK = segment.sequence
				if peerSACK {
					if block, duplicate := tcpDuplicateSACKBlock(segment.sequence, len(segment.payload), fin, receiveNext, outOfOrder); duplicate {
						recentDSACK, haveRecentDSACK = block, true
					}
				}
				if !remoteFINReceived {
					_, closed := c.receiveTCPData(segment.sequence, segment.payload, fin, receiveWindow, &receiveNext, &outOfOrder, &outOfOrderBytes)
					advanced := receiveNext - previousReceiveNext
					if closed && advanced != 0 {
						advanced--
					}
					bytesReceived += uint64(advanced)
					if closed {
						remoteFINReceived = true
						c.setReadEOF()
					}
				}
				if newApplicationData && c.applicationReceiveClosed() {
					sequence := tcpAcceptableSendSequence(sendUnacknowledged, sendNext, peerWindow, peerScale)
					_ = c.sendSegment(sequence, receiveNext, tcpFlagRST|tcpFlagACK, advertisedReceiveWindow(), nil)
					return net.ErrClosed
				}
				immediateACK := fin || segment.sequence != previousReceiveNext || hadOutOfOrder || len(outOfOrder) != 0
				if err := scheduleACK(immediateACK, len(segment.payload) != 0, receivedAt); err != nil {
					return err
				}
			}
			if localFINAcked && remoteFINReceived {
				if !timeWaitRequired {
					return nil
				}
				// RFC 9293 restarts 2MSL for a retransmitted FIN, not for
				// every acceptable ACK received while the tuple is retained.
				if !timeWaitArmed || fin {
					startedAt := receivedAt
					if fin {
						// TIME-WAIT starts after acknowledging the peer's FIN.
						startedAt = time.Now()
					}
					armClose(startedAt, tcpTimeWaitDuration)
					timeWaitArmed = true
				}
			} else if localFINAcked && !finWaitArmed && c.applicationReceiveClosed() {
				armClose(receivedAt, tcpFINWaitDuration)
				finWaitArmed = true
			}
			armLiveness()
			if err := fillWindow(); err != nil {
				return err
			}

		case <-c.sendNotify:
			if err := fillWindow(); err != nil {
				return err
			}
			if localFINAcked && !remoteFINReceived && !finWaitArmed && c.applicationReceiveClosed() {
				armClose(time.Now(), tcpFINWaitDuration)
				finWaitArmed = true
			}

		case <-c.windowUpdate:
			now := time.Now()
			if target := receiveAutoTune.target(now, rtt.srtt, c.applicationReads.Load(), tcpMaximumReceiveCapacity); target > 0 {
				c.growReceiveCapacity(target)
			}
			if c.discardingReads() {
				outOfOrder = nil
				outOfOrderBytes = 0
				c.outOfOrderUnread.Store(0)
			} else if len(outOfOrder) != 0 {
				previousReceiveNext := receiveNext
				_, closed := c.promoteTCPReceived(&receiveNext, &outOfOrder, &outOfOrderBytes)
				advanced := receiveNext - previousReceiveNext
				if closed && advanced != 0 {
					advanced--
				}
				bytesReceived += uint64(advanced)
				if closed {
					remoteFINReceived = true
					c.setReadEOF()
				}
				if receiveNext != previousReceiveNext {
					if err := scheduleACK(true, false, time.Now()); err != nil {
						return err
					}
				}
			}
			available, capacity := c.receiveSpace(outOfOrderBytes)
			window, _ := receiveWindowState.next(receiveNext, available, tcpReceiveWindowIncrease(capacity, receiveMSS))
			if window > lastAdvertisedWindow {
				if err := scheduleACK(lastAdvertisedWindow == 0, false, time.Now()); err != nil {
					return err
				}
			}
			if err := fillWindow(); err != nil {
				return err
			}

		case <-activeRetransmit:
			retransmissionTimer.consumed()
			retransmit = nil
			retransmissionDeadline = time.Time{}
			if retransmissionClose {
				return net.ErrClosed
			}
			pendingIndex := firstUnsackedSegment(outstanding)
			if retransmissionProbe {
				pendingIndex = lastUnsackedSegment(outstanding)
			}
			if pendingIndex >= 0 && pendingIndex < len(outstanding) && outstanding[pendingIndex].hostQueue.pending() {
				// Linux refuses every retransmission while the original skb is
				// still owned by qdisc or the driver. Preserve the timer kind and
				// original xmit time, then retry after local queue progress has had
				// a chance to occur.
				retransmit = retransmissionTimer.reset(tcpHostQueueRetryInterval)
				retransmissionDeadline = time.Now().Add(tcpHostQueueRetryInterval)
				continue
			}
			if retransmissionRACK {
				reorderingWindow := rackReorderingWindow(rtt.minimum, rtt.srtt, rackReorderingScale)
				if !rackReorderingSeen && (fastRecovery || rtoRecovery || sackedRanges >= tcpDuplicateACKThreshold) {
					reorderingWindow = 0
				}
				haveRACKLoss = markRACKLoss(outstanding, rackLatestDelivered, time.Now(), reorderingWindow)
				if haveRACKLoss {
					if err := recoverSACKHoles(0, false); err != nil {
						return err
					}
					haveRACKLoss = hasRACKLoss(outstanding)
				}
				armRetransmission()
				continue
			}
			if retransmissionProbe {
				sent, err := sendNextData(uint32(peerMSS), false)
				if err != nil {
					return err
				}
				probeSentAt := time.Time{}
				if sent {
					probeSentAt = outstanding[len(outstanding)-1].sentAt
				}
				tailProbeRetransmit = !sent
				if !sent {
					index := lastUnsackedSegment(outstanding)
					segment := &outstanding[index]
					window := advertisedReceiveWindow()
					timestamp, hostQueue, err := c.sendSegmentForMTU(segment.sequence, receiveNext, segment.flags, window, nil, segment.payload, false, c.mtu)
					if err != nil {
						return err
					}
					retransmitHistory.record(segment.sequence, segment.end)
					sentAt := hostQueue.queuedAt
					lastACKSent = receiveNext
					lastAdvertisedWindow = window
					segment.sentAt = sentAt
					segment.timestamp = timestamp
					segment.hostQueue = hostQueue
					probeSentAt = sentAt
					segment.transmissions++
					c.noteRetransmission()
					controller.onRetransmit(len(segment.payload), peerMSS, segment.sentAt, congestionWindow, congestionFlight(), rtt.srtt, slowStartThreshold)
				}
				tailProbeActive = true
				tailProbeEnd = sendNext
				tailProbeRTTSamples = rtt.samples
				c.stack.stats.tcpTailLossProbes.Add(1)
				// RFC 8985 requires a full RTO from the probe transmission;
				// retaining the oldest segment's prior deadline can otherwise
				// turn a useful new-data probe into an immediate timeout.
				armRetransmissionAfterACK(probeSentAt)
				continue
			}
			rtoAttempts++
			if rtoAttempts > tcpMaximumRTOs {
				return tcpTimeoutError(lastSoftError)
			}
			blackHoleRTOs++
			if blackHoleRTOs >= tcpBlackHoleTimeouts {
				if len(outstanding) != 0 {
					segment := outstanding[firstUnsackedSegment(outstanding)]
					mtu := nextBlackHoleProbeMTU(c.mtu, c.key.remote.Addr().Is6(), len(segment.payload), c.peerTimestamp)
					if mtu < c.mtu {
						c.stack.stats.pathMTUBlackHoleReductions.Add(1)
						blackHoleMTU = mtu
						blackHoleExpiry = time.Now().Add(pathMTULifetime)
						if err := applyPathMTU(effectivePathMTU(), false); err != nil {
							return err
						}
					}
				}
			}
			if err := retransmitSegment(firstUnsackedSegment(outstanding), true); err != nil {
				return err
			}

		case <-activePersist:
			persistTimer.consumed()
			persist = nil
			persistDeadline = time.Time{}
			if c.applicationReceiveClosed() {
				persistAttempts++
				if persistAttempts > tcpMaximumRTOs {
					return os.ErrDeadlineExceeded
				}
			}
			// Like Linux and gVisor, probe with an already acknowledged byte.
			// Consuming new sequence space here would move pure ACKs beyond the
			// peer's zero window and can deadlock a full-duplex connection.
			sequence, flags := sendUnacknowledged-1, byte(tcpFlagACK)
			payload := tcpZeroWindowProbe[:]
			window := advertisedReceiveWindow()
			_, hostQueue, err := c.sendSegmentTimestamp(sequence, receiveNext, flags, window, payload)
			if err != nil {
				return err
			}
			probeSentAt := hostQueue.queuedAt
			lastACKSent = receiveNext
			lastAdvertisedWindow = window
			c.stack.stats.tcpZeroWindowProbes.Add(1)
			persistRTO *= 2
			if persistRTO > tcpMaximumRTO {
				persistRTO = tcpMaximumRTO
			}
			armPersist(probeSentAt)

		case <-activeDelayedACK:
			delayedACKTimer.consumed()
			delayedACK = nil
			delayedACKDeadline = time.Time{}
			if err := sendACK(); err != nil {
				return err
			}

		case <-c.pathMTUUpdate:
			if err := applyPathMTU(effectivePathMTU(), true); err != nil {
				return err
			}
		case <-activePathMTUProbe:
			pathMTUTimer.consumed()
			pathMTUProbe = nil
			pathMTUDeadline = time.Time{}
			now := time.Now()
			if plpmtu.searching {
				plpmtu.nextProbe = now
				if err := fillWindow(); err != nil {
					return err
				}
				continue
			}
			if !blackHoleExpiry.IsZero() && !time.Now().Before(blackHoleExpiry) {
				blackHoleMTU = 0
				blackHoleExpiry = time.Time{}
			}
			plpmtu.start(c.mtu, c.stack.network.Load().mtu, now)
			if !plpmtu.searching {
				// A sub-threshold remaining gain is not worth a probe, but the
				// working PMTU still needs the RFC 4821 re-probe interval.
				c.stack.confirmPathMTU(c.key.remote.Addr(), c.mtu, c)
				armPathMTUProbe()
			}
			if err := fillWindow(); err != nil {
				return err
			}
		case <-activePacing:
			pacingTimer.consumed()
			pacing = nil
			pacingDeadline = time.Time{}
			if fastRecovery && peerSACK && len(outstanding) != 0 {
				if err := recoverSACKHoles(highestSACKedSequence(outstanding), true); err != nil {
					return err
				}
			}
			if err := fillWindow(); err != nil {
				return err
			}
		case <-c.optionsChanged:
			configured := c.socketOptions().congestion
			if configured != controller.algorithm {
				controller = newTCPCongestionController(configured)
				// Linux reinitializes only congestion-controller private state.
				// The established connection's cwnd and ssthresh remain transport
				// state across a TCP_CONGESTION change.
				hyStart.disable()
				if pacingTimer != nil {
					pacingTimer.stop()
				}
				pacing = nil
				pacingDeadline = time.Time{}
			}
			keepAliveProbes = 0
			lastKeepAlive = time.Time{}
			armLiveness()
			if err := fillWindow(); err != nil {
				return err
			}
		case response := <-c.infoRequest:
			c.respondTCPInfo(response, tcpInfo())
		case <-activeLiveness:
			livenessTimer.consumed()
			liveness = nil
			livenessDeadline = time.Time{}
			options := c.socketOptions()
			now := time.Now()
			if options.idleTimeout > 0 && !now.Before(lastActivity.Add(options.idleTimeout)) {
				return os.ErrDeadlineExceeded
			}
			if deadline := userTimeoutDeadline(now, options.userTimeout); !deadline.IsZero() && !now.Before(deadline) {
				return syscall.ETIMEDOUT
			}
			if options.userTimeout > 0 && keepAliveProbes != 0 && !now.Before(lastActivity.Add(options.userTimeout)) {
				return syscall.ETIMEDOUT
			}
			if options.keepAlive && keepAliveEligible() {
				deadline := lastActivity.Add(options.keepAliveConfig.Idle)
				if keepAliveProbes != 0 {
					deadline = lastKeepAlive.Add(options.keepAliveConfig.Interval)
				}
				if !now.Before(deadline) {
					if options.userTimeout == 0 && keepAliveProbes >= options.keepAliveConfig.Count {
						return syscall.ETIMEDOUT
					}
					probeSequence := sendNext - 1
					if probeSequence-sendUnacknowledged > sendNext-sendUnacknowledged {
						c.publishICMPSequenceRange(probeSequence, sendNext)
					}
					window := advertisedReceiveWindow()
					_, hostQueue, err := c.sendSegmentTimestamp(probeSequence, receiveNext, tcpFlagACK, window, nil)
					if err != nil {
						return err
					}
					lastACKSent = receiveNext
					lastAdvertisedWindow = window
					keepAliveProbes++
					lastKeepAlive = hostQueue.queuedAt
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
				sequence := tcpAcceptableSendSequence(sendUnacknowledged, sendNext, peerWindow, peerScale)
				abortResetSent = true
				_ = c.sendAbortReset(sequence, receiveNext, advertisedReceiveWindow())
			}
			return err
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

// sendSegment emits a segment with the supplied advertised window.
func (c *TCPConn) sendSegment(sequence, acknowledgement uint32, flags byte, window uint16, payload []byte) error {
	return c.sendSegmentWithOptions(sequence, acknowledgement, flags, window, nil, payload)
}

// sendAbortReset makes one nonblocking attempt to publish the final RST from
// an actor whose normal packet writes have already been canceled.
func (c *TCPConn) sendAbortReset(sequence, acknowledgement uint32, window uint16) error {
	flags := byte(tcpFlagRST | tcpFlagACK)
	var options []byte
	if c.peerTimestamp {
		options = tcpTimestampOptions(c.stack.tcpTimestamp(), c.recentTimestamp)
	}
	if c.echoCongestion {
		flags |= tcpFlagECE
	}
	packet, err := buildTCPPacket(
		c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(),
		sequence, acknowledgement, flags, window, options, nil, c.mtu, uint8(c.trafficClass.Load()), 0,
	)
	if err != nil {
		return err
	}
	return c.stack.tryWritePacket(packet)
}

// writeTCPControlWithMTU applies the socket DSCP policy to handshake and
// reset packets that precede established's timestamp and ECN state.
func (c *TCPConn) writeTCPControlWithMTU(sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int) (packetQueueTicket, error) {
	return c.writeTCP(
		sequence, acknowledgement, flags, window, options, payload, mtu, uint8(c.trafficClass.Load()), 0,
	)
}

// sendSegmentTimestamp is sendSegment plus the exact TSval placed on the
// wire. A zero timestamp is returned when timestamps were not negotiated.
func (c *TCPConn) sendSegmentTimestamp(sequence, acknowledgement uint32, flags byte, window uint16, payload []byte) (uint32, packetQueueTicket, error) {
	return c.sendSegmentForMTU(sequence, acknowledgement, flags, window, nil, payload, false, c.mtu)
}

// sendSegmentWithOptions emits a segment with TCP options and the actor's
// current advertised window.
func (c *TCPConn) sendSegmentWithOptions(sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte) error {
	_, _, err := c.sendSegmentForMTU(sequence, acknowledgement, flags, window, options, payload, false, c.mtu)
	return err
}

// sendSegmentForMTU emits a segment against an explicit path ceiling. It
// returns the serialized TSval so Eifel does not need a second clock read.
func (c *TCPConn) sendSegmentForMTU(sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, ecnCapable bool, mtu int) (uint32, packetQueueTicket, error) {
	timestamp := uint32(0)
	if c.peerTimestamp {
		timestamp = c.stack.tcpTimestamp()
		combined := make([]byte, 0, 12+len(options))
		combined = append(combined, tcpTimestampOptions(timestamp, c.recentTimestamp)...)
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
	trafficClass := uint8(c.trafficClass.Load())
	hostQueue, err := c.writeTCP(sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn)
	if err == nil && includeCWR {
		c.sendCWR = false
	}
	return timestamp, hostQueue, err
}

// writeTCP emits one connection-owned segment and remains interruptible while
// the embedding packet queue is full.
func (c *TCPConn) writeTCP(sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, trafficClass, ecn byte) (packetQueueTicket, error) {
	packet, err := buildTCPPacket(
		c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(),
		sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn,
	)
	if err != nil {
		return packetQueueTicket{}, err
	}
	hostQueue, err := c.stack.writePacketUntilTicket(packet, c.packetWriteState)
	if errors.Is(err, net.ErrClosed) {
		select {
		case <-c.abortCh:
			return packetQueueTicket{}, c.abortedError()
		default:
		}
	}
	return hostQueue, err
}

// packetWriteState exposes actor cancellation to a blocked packet-queue write.
// A graceful Close deliberately leaves it open so already accepted bytes and
// FIN can still be transmitted.
func (c *TCPConn) packetWriteState() (time.Time, <-chan struct{}, bool) {
	select {
	case <-c.abortCh:
		return time.Time{}, c.abortCh, true
	default:
		return time.Time{}, c.abortCh, false
	}
}

// rttEstimator implements the RFC 6298 smoothed RTT and variance calculation.
type rttEstimator struct {
	initialized bool
	samples     uint64
	minimum     time.Duration
	minimums    tcpMinimumRTTFilter
	srtt        time.Duration
	variation   time.Duration
	rto         time.Duration
}

// tcpMinimumRTTSample is one candidate in Linux's constant-space running-min
// filter.
type tcpMinimumRTTSample struct {
	at    time.Time
	value time.Duration
}

// tcpMinimumRTTFilter retains the best three time-separated RTT samples. This
// is Kathleen Nichols' running-min algorithm used by Linux for tcp_min_rtt.
type tcpMinimumRTTFilter struct {
	samples     [3]tcpMinimumRTTSample
	initialized bool
}

// observe incorporates one RTT sample and returns the current windowed
// minimum.
func (f *tcpMinimumRTTFilter) observe(now time.Time, value time.Duration) time.Duration {
	candidate := tcpMinimumRTTSample{at: now, value: value}
	if !f.initialized || value <= f.samples[0].value || now.Sub(f.samples[2].at) > tcpMinimumRTTWindow {
		f.samples[0], f.samples[1], f.samples[2] = candidate, candidate, candidate
		f.initialized = true
		return value
	}
	if value <= f.samples[1].value {
		f.samples[1], f.samples[2] = candidate, candidate
	} else if value <= f.samples[2].value {
		f.samples[2] = candidate
	}
	delta := now.Sub(f.samples[0].at)
	if delta > tcpMinimumRTTWindow {
		f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], candidate
		if now.Sub(f.samples[0].at) > tcpMinimumRTTWindow {
			f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], candidate
		}
	} else if f.samples[1].at.Equal(f.samples[0].at) && delta > tcpMinimumRTTWindow/4 {
		f.samples[1], f.samples[2] = candidate, candidate
	} else if f.samples[2].at.Equal(f.samples[1].at) && delta > tcpMinimumRTTWindow/2 {
		f.samples[2] = candidate
	}
	return f.samples[0].value
}

// observe incorporates one non-retransmitted acknowledgement sample.
func (r *rttEstimator) observe(sample time.Duration) {
	r.observeAt(sample, time.Now())
}

// observeAt incorporates a sample at its packet-arrival time so actor
// scheduling delay cannot age the running minimum.
func (r *rttEstimator) observeAt(sample time.Duration, receivedAt time.Time) {
	if sample <= 0 {
		return
	}
	r.samples++
	sample = normalizedRTTSample(sample)
	r.minimum = r.minimums.observe(receivedAt, sample)
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
	r.updateRTO()
}

// updateRTO derives and bounds the RFC 6298 retransmission timeout from the
// current smoothed RTT and variation.
func (r *rttEstimator) updateRTO() {
	r.rto = r.srtt + 4*r.variation
	if r.rto < tcpMinimumRTO {
		r.rto = tcpMinimumRTO
	} else if r.rto > tcpMaximumRTO {
		r.rto = tcpMaximumRTO
	}
}

// normalizedRTTSample keeps estimator arithmetic and model-based pacing
// bounded after a process suspension or other multi-minute scheduling gap.
func normalizedRTTSample(sample time.Duration) time.Duration {
	if sample > tcpMaximumRTO {
		return tcpMaximumRTO
	}
	return sample
}

// elapsedRTTSampleAt measures delivery at packet arrival rather than when a
// connection actor was eventually scheduled to process the acknowledgement.
func elapsedRTTSampleAt(sentAt, receivedAt time.Time) time.Duration {
	if sentAt.IsZero() {
		return 0
	}
	sample := receivedAt.Sub(sentAt)
	if sample < time.Microsecond {
		return time.Microsecond
	}
	return sample
}

// tcpSegmentEventTime returns the stack-arrival time attached by handleTCP,
// bounded by the actor's prior event time and its current processing time.
// Concurrent device receive loops can otherwise enqueue timestamped batches
// in the opposite order and move protocol timers backwards.
func tcpSegmentEventTime(segment tcpSegment, now, previous time.Time) time.Time {
	result := segment.receivedAt
	if result.IsZero() || result.After(now) {
		result = now
	}
	if result.Before(previous) {
		result = previous
	}
	return result
}

// backoff doubles RTO after a retransmission timeout.
func (r *rttEstimator) backoff() {
	r.rto *= 2
	if r.rto > tcpMaximumRTO {
		r.rto = tcpMaximumRTO
	}
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
	for _, candidate := range [...]int{1500, 1280, 1006, 576, 508, 296, 68} {
		if candidate < current {
			return candidate
		}
	}
	return current
}

// nextBlackHoleProbeMTU skips nominal plateaus that would emit the same wire
// payload. A black-hole probe must make the retransmission smaller to provide
// new path information; repeatedly recording a larger MTU that already fits
// the current segment cannot recover the connection.
func nextBlackHoleProbeMTU(current int, ipv6 bool, payloadSize int, timestamp bool) int {
	address := netip.IPv4Unspecified()
	if ipv6 {
		address = netip.IPv6Unspecified()
	}
	probe := current
	for {
		next := nextBlackHoleMTU(probe, ipv6)
		if next >= probe {
			return current
		}
		maximumPayload := tcpMSSForMTU(next, address)
		if timestamp {
			maximumPayload -= 12
		}
		if payloadSize > maximumPayload {
			return next
		}
		probe = next
	}
}

// tcpTimeoutError preserves the last validated asynchronous network failure
// when TCP ultimately cannot recover it through retransmission.
func tcpTimeoutError(softError error) error {
	if softError != nil {
		return softError
	}
	return os.ErrDeadlineExceeded
}

// tcpActiveOpenHardError applies RFC 1122's protocol/port-unreachable split.
// IPv6 has no protocol-unreachable destination code, but its port-unreachable
// code carries the same definitive active-open meaning.
func tcpActiveOpenHardError(err error) bool {
	var networkError ICMPError
	if !errors.As(err, &networkError) {
		return false
	}
	if networkError.QuotedSource.Is6() {
		return networkError.Type == 1 && networkError.Code == 4
	}
	return networkError.Type == 3 && (networkError.Code == 2 || networkError.Code == 3)
}

// tcpSYNOptions advertises MSS, SACK, receive window scaling, and timestamps.
func tcpSYNOptions(mss int, windowScale uint8, timestamp uint32) []byte {
	return tcpPassiveSYNOptions(mss, true, true, true, windowScale, timestamp, 0)
}

// tcpPassiveSYNOptions advertises only extensions offered by the initiating
// peer, while MSS is always present.
func tcpPassiveSYNOptions(mss int, sack, windowScaling, timestamp bool, windowScale uint8, timestampValue, timestampEcho uint32) []byte {
	options := []byte{2, 4, byte(mss >> 8), byte(mss)}
	if sack {
		options = append(options, 4, 2)
	}
	if windowScaling {
		options = append(options, 1, 3, 3, windowScale)
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

// tcpSACKBlockLimit returns the largest SACK option fitting both TCP's
// 40-byte option space and the current PMTU. reservePayload keeps room for a
// data byte when the option is piggybacked instead of sent on a pure ACK.
func tcpSACKBlockLimit(mtu int, address netip.Addr, timestamp bool, reservePayload int) int {
	ipHeader := 40
	if address.Is4() {
		ipHeader = 20
	}
	budget := mtu - ipHeader - tcpHeaderSize - reservePayload
	if budget > 40 {
		budget = 40
	}
	if budget < 0 {
		return 0
	}
	timestampSize := 0
	maximum := 4
	if timestamp {
		timestampSize = 12
		maximum = 3
	}
	for blocks := maximum; blocks > 0; blocks-- {
		optionSize := timestampSize + 2 + 8*blocks
		optionSize = (optionSize + 3) &^ 3
		if optionSize <= budget {
			return blocks
		}
	}
	return 0
}

// tcpSACKOptions reports retained out-of-order ranges and an optional RFC 2883
// duplicate range. DSACK occupies the first block; otherwise the range
// containing the segment that triggered the ACK is first as required by RFC
// 2018.
func tcpSACKOptions(pieces []tcpReceivedPiece, recent uint32, maximumBlocks int, dsack tcpSACKBlock, haveDSACK bool) []byte {
	blocks := make([]tcpSACKBlock, 0, len(pieces))
	for _, piece := range pieces {
		right := piece.sequence + uint32(len(piece.payload))
		if piece.fin {
			right++
		}
		if right == piece.sequence {
			continue
		}
		if len(blocks) != 0 && !tcpSequenceGreater(piece.sequence, blocks[len(blocks)-1].right) {
			if tcpSequenceGreater(right, blocks[len(blocks)-1].right) {
				blocks[len(blocks)-1].right = right
			}
		} else {
			blocks = append(blocks, tcpSACKBlock{left: piece.sequence, right: right})
		}
	}
	if len(blocks) == 0 && !haveDSACK {
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
	if haveDSACK {
		ordered = append(ordered, dsack)
	}
	if recentIndex >= 0 {
		if len(ordered) < maximumBlocks {
			ordered = append(ordered, blocks[recentIndex])
		}
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

// tcpDuplicateSACKBlock finds the first duplicate sequence range in an
// incoming segment. Ranges below RCV.NXT and overlaps with retained
// out-of-order data use the two DSACK forms defined by RFC 2883.
func tcpDuplicateSACKBlock(sequence uint32, payloadLength int, fin bool, receiveNext uint32, pieces []tcpReceivedPiece) (tcpSACKBlock, bool) {
	length := uint32(payloadLength)
	if fin {
		length++
	}
	if length == 0 {
		return tcpSACKBlock{}, false
	}
	end := sequence + length
	if tcpSequenceLess(sequence, receiveNext) {
		right := end
		if tcpSequenceGreater(right, receiveNext) {
			right = receiveNext
		}
		if tcpSequenceGreater(right, sequence) {
			return tcpSACKBlock{left: sequence, right: right}, true
		}
		sequence = receiveNext
	}
	incomingStart := sequence - receiveNext
	incomingEnd := end - receiveNext
	if incomingStart >= incomingEnd {
		return tcpSACKBlock{}, false
	}
	for _, piece := range pieces {
		pieceStart := piece.sequence - receiveNext
		pieceEnd := pieceStart + uint32(len(piece.payload))
		if piece.fin {
			pieceEnd++
		}
		left := incomingStart
		if pieceStart > left {
			left = pieceStart
		}
		right := incomingEnd
		if pieceEnd < right {
			right = pieceEnd
		}
		if left < right {
			return tcpSACKBlock{left: receiveNext + left, right: receiveNext + right}, true
		}
	}
	return tcpSACKBlock{}, false
}

// parseTCPDSACKOption returns RFC 2883's distinguished first SACK block when
// it describes already cumulatively acknowledged data or is contained in the
// following ordinary SACK block. history bounds below-ACK reports to sequence
// space this connection actually acknowledged recently.
func parseTCPDSACKOption(options []byte, acknowledged, sendNext, history uint32) (tcpSACKBlock, bool) {
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
			left := binary.BigEndian.Uint32(options[offset+2 : offset+6])
			right := binary.BigEndian.Uint32(options[offset+6 : offset+10])
			block := tcpSACKBlock{left: left, right: right}
			if tcpSequenceLess(left, right) && tcpSequenceLessEqual(right, acknowledged) && acknowledged-left <= history {
				return block, true
			}
			if length >= 18 {
				secondLeft := binary.BigEndian.Uint32(options[offset+10 : offset+14])
				secondRight := binary.BigEndian.Uint32(options[offset+14 : offset+18])
				secondLength := secondRight - secondLeft
				if secondLength != 0 && secondLength <= sendNext-acknowledged &&
					left-secondLeft < secondLength && right-secondLeft <= secondLength && left != right {
					return block, true
				}
			}
			return tcpSACKBlock{}, false
		}
		offset += length
	}
	return tcpSACKBlock{}, false
}

// parseTCPSACKOptions validates and merges ordinary SACK ranges within the
// current send window. The distinguished DSACK block is handled separately.
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

// applyTCPSACK splits transmissions at SACK boundaries, marks exact covered
// ranges, and returns the newest delivery information used by RACK.
func applyTCPSACK(outstanding []sentTCPSegment, blocks []tcpSACKBlock) ([]sentTCPSegment, uint32, bool, bool, tcpRACKSample, []sentTCPSegment) {
	var highest uint32
	var newInformation bool
	var latest tcpRACKSample
	var newlySACKed []sentTCPSegment
	for blockIndex, block := range blocks {
		if blockIndex == 0 || tcpSequenceGreater(block.right, highest) {
			highest = block.right
		}
		outstanding = splitTCPSegmentAt(outstanding, block.left)
		outstanding = splitTCPSegmentAt(outstanding, block.right)
		for index := range outstanding {
			segment := &outstanding[index]
			if tcpSequenceGreaterEqual(segment.sequence, block.left) && tcpSequenceGreaterEqual(block.right, segment.end) {
				if !segment.sacked {
					newInformation = true
					newlySACKed = append(newlySACKed, *segment)
					latest = newerRACKSample(latest, tcpRACKSample{sentAt: segment.sentAt, end: segment.end, timestamp: segment.timestamp, retransmitted: segment.transmissions > 1})
				}
				segment.sacked = true
			}
		}
	}
	return outstanding, highest, len(blocks) != 0, newInformation, latest, newlySACKed
}

// splitTCPSegmentAt makes the SACK scoreboard byte-accurate when a peer's
// block edge falls inside one transmitted segment.
func splitTCPSegmentAt(outstanding []sentTCPSegment, boundary uint32) []sentTCPSegment {
	splitRanges := 0
	for index := range outstanding {
		if outstanding[index].sackSplit {
			splitRanges++
		}
	}
	for index := range outstanding {
		segment := outstanding[index]
		if !tcpSequenceGreater(boundary, segment.sequence) || !tcpSequenceLess(boundary, segment.end) {
			continue
		}
		increase := 1
		if !segment.sackSplit {
			increase = 2
		}
		if splitRanges+increase > tcpMaximumSACKSplitRanges {
			return outstanding
		}
		left, right := segment, segment
		left.sackSplit, right.sackSplit = true, true
		left.end = boundary
		left.flags &^= tcpFlagPSH | tcpFlagFIN
		right.sequence = boundary
		payloadOffset := int(boundary - segment.sequence)
		if payloadOffset > len(segment.payload) {
			payloadOffset = len(segment.payload)
		}
		left.payload = segment.payload[:payloadOffset]
		right.payload = segment.payload[payloadOffset:]
		outstanding = append(outstanding, sentTCPSegment{})
		copy(outstanding[index+2:], outstanding[index+1:])
		outstanding[index], outstanding[index+1] = left, right
		return outstanding
	}
	return outstanding
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
func tailLossProbeDelay(smoothedRTT, rto time.Duration, singleSegment bool) time.Duration {
	delay := 2 * smoothedRTT
	if smoothedRTT == 0 {
		delay = rto
	} else if singleSegment {
		delay += tcpDelayedACKTimeout
	}
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	if delay > rto {
		delay = rto
	}
	return delay
}

// tcpSACKedState rebuilds the actor's aggregate scoreboard after an operation
// that splits transmission ranges. The ordinary send and ACK paths update the
// same aggregates incrementally and therefore remain constant-time.
func tcpSACKedState(outstanding []sentTCPSegment) (ranges int, bytes uint32) {
	for _, segment := range outstanding {
		if segment.sacked {
			ranges++
			bytes += segment.end - segment.sequence
		}
	}
	return ranges, bytes
}

// highestSACKedSequence returns HighSACK for RFC 6675 NextSeg processing.
func highestSACKedSequence(outstanding []sentTCPSegment) uint32 {
	var highest uint32
	var found bool
	for _, segment := range outstanding {
		if segment.sacked && (!found || tcpSequenceGreater(segment.end, highest)) {
			highest = segment.end
			found = true
		}
	}
	return highest
}

// firstUnretriedLoss returns the first range satisfying RACK or RFC 6675's
// IsLost test and not already retransmitted in this recovery round.
func firstUnretriedLoss(outstanding []sentTCPSegment, mss int) int {
	index := -1
	var sackedRanges, sackedBytes int
	for next := len(outstanding) - 1; next >= 0; next-- {
		segment := outstanding[next]
		if segment.sacked {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		lost := segment.rackLost || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss
		if !segment.sackRetried && lost {
			index = next
		}
	}
	return index
}

// firstUnretriedSACKHole implements RFC 6675 NextSeg rule 3 after all ranges
// with sufficient loss evidence have been retransmitted.
func firstUnretriedSACKHole(outstanding []sentTCPSegment, highest uint32) int {
	for index := range outstanding {
		segment := &outstanding[index]
		if !segment.sacked && !segment.sackRetried && tcpSequenceLess(segment.sequence, highest) {
			return index
		}
	}
	return -1
}

// sackLostRangeCount counts ranges satisfying RFC 6675 IsLost, including
// RACK declarations, for PRR's newly-lost suppression of slow-start reduction.
func sackLostRangeCount(outstanding []sentTCPSegment, mss int) int {
	count := 0
	var sackedRanges, sackedBytes int
	for index := len(outstanding) - 1; index >= 0; index-- {
		segment := outstanding[index]
		if segment.sacked {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		if segment.rackLost || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss {
			count++
		}
	}
	return count
}

// sackSegmentLost implements RFC 6675 IsLost: either DupThresh transmitted
// ranges or more than (DupThresh-1)*SMSS bytes have been SACKed above it.
func sackSegmentLost(outstanding []sentTCPSegment, index, mss int) bool {
	if index < 0 || index >= len(outstanding) || outstanding[index].sacked {
		return false
	}
	if outstanding[index].rackLost {
		return true
	}
	var ranges, bytes int
	for next := index + 1; next < len(outstanding); next++ {
		segment := outstanding[next]
		if !segment.sacked {
			continue
		}
		ranges++
		bytes += int(segment.end - segment.sequence)
		if ranges >= tcpDuplicateACKThreshold || mss > 0 && bytes > (tcpDuplicateACKThreshold-1)*mss {
			return true
		}
	}
	return false
}

// isolatedPLPMTUProbeLoss requires ordinary RFC 6675/RACK loss evidence for
// the probe and rejects any second hole below HighSACK. Only that isolated
// case may suppress congestion response under RFC 4821.
func isolatedPLPMTUProbeLoss(outstanding []sentTCPSegment, probeStart, highestSACK uint32, mss int) bool {
	probeIndex := -1
	for index, segment := range outstanding {
		if segment.sequence == probeStart {
			probeIndex = index
			break
		}
	}
	if !sackSegmentLost(outstanding, probeIndex, mss) {
		return false
	}
	for index, segment := range outstanding {
		if index != probeIndex && !segment.sacked && tcpSequenceLess(segment.sequence, highestSACK) {
			return false
		}
	}
	return true
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

// lossRecoveryFlightSize applies RFC 3042's exception: data sent by Limited
// Transmit is not included when DupThresh establishes the new ssthresh.
func lossRecoveryFlightSize(outstanding []sentTCPSegment) uint32 {
	var bytes uint32
	for _, segment := range outstanding {
		if !segment.sacked && !segment.limited {
			bytes += segment.end - segment.sequence
		}
	}
	return bytes
}

// tcpACKRTTAmbiguous implements Karn's algorithm for one cumulative ACK. If
// any newly acknowledged sequence range was retransmitted, the ACK cannot
// identify which transmission produced it, including untouched later ranges
// covered by the same cumulative acknowledgement.
func tcpACKRTTAmbiguous(outstanding []sentTCPSegment, acknowledgement uint32) bool {
	for _, segment := range outstanding {
		if !tcpSequenceLess(segment.sequence, acknowledgement) {
			break
		}
		if segment.transmissions > 1 {
			return true
		}
	}
	return false
}

// sackRecoveryPipe implements RFC 6675 SetPipe. An unSACKed range not yet
// considered lost counts its original transmission, while every retransmitted
// range counts its replacement as well. A speculative retransmission can
// therefore count twice, exactly as required by SetPipe.
func sackRecoveryPipe(outstanding []sentTCPSegment, mss int) uint32 {
	var bytes uint32
	var sackedRanges, sackedBytes int
	for index := len(outstanding) - 1; index >= 0; index-- {
		segment := outstanding[index]
		if segment.sacked {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		size := segment.end - segment.sequence
		lost := segment.rackLost || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss
		if !lost {
			bytes = growCongestionWindow(bytes, size)
		}
		if segment.sackRetried {
			bytes = growCongestionWindow(bytes, size)
		}
	}
	return bytes
}

// sackRecoveryCanSend applies RFC 6675's cwnd-Pipe gate. The one
// retransmission that enters recovery precedes SetPipe and is exempt.
func sackRecoveryCanSend(recovery bool, pipe, size, window uint32) bool {
	return !recovery || uint64(pipe)+uint64(size) <= uint64(window)
}

// tcpNewlyAcknowledgedBytes counts cumulative delivery not previously
// reported by SACK, avoiding double accounting in RFC 6937 PRR.
func tcpNewlyAcknowledgedBytes(outstanding []sentTCPSegment, acknowledgement uint32) uint32 {
	var delivered uint32
	for _, segment := range outstanding {
		if !tcpSequenceGreater(acknowledgement, segment.sequence) {
			break
		}
		if segment.sacked {
			continue
		}
		end := segment.end
		if tcpSequenceLess(acknowledgement, end) {
			end = acknowledgement
		}
		delivered = growCongestionWindow(delivered, end-segment.sequence)
	}
	return delivered
}

// prrCongestionWindow implements Linux's byte-scaled RFC 6937 send-count
// calculation. Returning Pipe+sndcnt lets the existing RFC 6675 sender apply
// the allowance to retransmissions and new data with one common gate.
func prrCongestionWindow(pipe, threshold, priorFlight uint32, delivered, sent uint64, newlyDelivered uint32, cumulativeACK, newlyLost bool, mss int) uint32 {
	if newlyDelivered == 0 || priorFlight == 0 || mss < 1 {
		return pipe
	}
	var allowance uint64
	if pipe > threshold {
		target := (uint64(threshold)*delivered + uint64(priorFlight) - 1) / uint64(priorFlight)
		if target > sent {
			allowance = target - sent
		}
	} else {
		if delivered > sent {
			allowance = delivered - sent
		}
		if allowance < uint64(newlyDelivered) {
			allowance = uint64(newlyDelivered)
		}
		if cumulativeACK && !newlyLost {
			allowance += uint64(mss)
		}
		if available := uint64(threshold - pipe); allowance > available {
			allowance = available
		}
	}
	if allowance > uint64(tcpMaximumScaledWindow) {
		allowance = uint64(tcpMaximumScaledWindow)
	}
	return growCongestionWindow(pipe, uint32(allowance))
}

// tcpCongestionFlight selects RFC 6675 SetPipe while SACK recovery is active.
// Outside recovery, one copy of each unSACKed range is ordinary flight.
func tcpCongestionFlight(outstanding []sentTCPSegment, sack, recovery bool, mss int) uint32 {
	if sack && recovery {
		return sackRecoveryPipe(outstanding, mss)
	}
	return outstandingBytes(outstanding, false)
}

// rackReorderingWindow returns RFC 8985's initial min_RTT/4 settling
// allowance, bounded by SRTT as required for every adapted RACK window.
func rackReorderingWindow(minimumRTT, smoothedRTT time.Duration, scale uint32) time.Duration {
	if minimumRTT <= 0 || smoothedRTT <= 0 {
		return 0
	}
	if scale == 0 {
		scale = 1
	}
	window := minimumRTT / 4
	if window <= 0 {
		return 0
	}
	if scale > uint32(smoothedRTT/window) {
		return smoothedRTT
	}
	window *= time.Duration(scale)
	if window > smoothedRTT {
		window = smoothedRTT
	}
	return window
}

// newerRACKSample returns the later transmission under RFC 8985's transmit
// time ordering. Sequence order disambiguates timestamps with equal clock
// granularity.
func newerRACKSample(current, candidate tcpRACKSample) tcpRACKSample {
	if candidate.sentAt.IsZero() {
		return current
	}
	if candidate.sentAt.After(current.sentAt) || candidate.sentAt.Equal(current.sentAt) && tcpSequenceGreater(candidate.end, current.end) {
		return candidate
	}
	return current
}

// validRACKSample applies RFC 8985's fallback ambiguity check for a
// retransmitted segment. Without proof from a timestamp echo, an RTT below
// min_RTT can belong to the original transmission and must not advance RACK.
func validRACKSample(sample tcpRACKSample, minimumRTT time.Duration, timestampEcho uint32) tcpRACKSample {
	if sample.retransmitted {
		// RFC 8985 rejects a delivery sample when TSecr identifies an older
		// copy than the latest retransmission. The min-RTT check remains
		// necessary when timestamps are absent or coarser than the path RTT.
		if sample.timestamp != 0 && timestampEcho != 0 && tcpSequenceLess(timestampEcho, sample.timestamp) {
			return tcpRACKSample{}
		}
		if minimumRTT > 0 && sample.rtt < minimumRTT {
			return tcpRACKSample{}
		}
	}
	return sample
}

// rackDeliveredAfter reports whether delivered was transmitted after segment.
// A later ACK alone is insufficient: RACK compares transmit order so reordered
// acknowledgements cannot declare a newer transmission lost.
func rackDeliveredAfter(delivered tcpRACKSample, segment sentTCPSegment) bool {
	return delivered.sentAt.After(segment.sentAt) || delivered.sentAt.Equal(segment.sentAt) && tcpSequenceGreater(delivered.end, segment.end)
}

// rackAdvanceForwardACK updates RFC 8985's highest newly delivered sequence
// and reports original data delivered out of order below that edge.
func rackAdvanceForwardACK(forward *uint32, set *bool, end uint32, retransmitted bool) bool {
	if !*set || tcpSequenceGreater(end, *forward) {
		*forward, *set = end, true
		return false
	}
	return tcpSequenceLess(end, *forward) && !retransmitted
}

// rackLossDelay returns RFC 8985's maximum remaining reordering wait across
// eligible transmissions. Linux measures each threshold as the latest
// delivered transmission's RTT plus reo_wnd minus the candidate's current age.
func rackLossDelay(outstanding []sentTCPSegment, delivered tcpRACKSample, now time.Time, reorderingWindow time.Duration) (time.Duration, bool) {
	var maximum time.Duration
	found := false
	for _, segment := range outstanding {
		// A range already declared lost waits for cwnd-Pipe space or the
		// ordinary RTO. Re-arming its expired reordering deadline would spin
		// the actor while recovery is congestion-window limited.
		if segment.sacked || segment.rackLost || !rackDeliveredAfter(delivered, segment) {
			continue
		}
		remaining := segment.sentAt.Add(delivered.rtt + reorderingWindow).Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		if !found || remaining > maximum {
			maximum, found = remaining, true
		}
	}
	return maximum, found
}

// markRACKLoss records eligible transmissions whose reordering wait expired.
// A retransmission can itself be lost; clearing sackRetried makes that range
// eligible for another recovery transmission instead of deferring it to RTO.
// The result reports whether any timed loss remains eligible.
func markRACKLoss(outstanding []sentTCPSegment, delivered tcpRACKSample, now time.Time, reorderingWindow time.Duration) bool {
	lost := false
	for index := range outstanding {
		segment := &outstanding[index]
		if !segment.sacked && rackDeliveredAfter(delivered, *segment) && !now.Before(segment.sentAt.Add(delivered.rtt+reorderingWindow)) {
			segment.rackLost = true
			segment.sackRetried = false
		}
		lost = lost || segment.rackLost && !segment.sackRetried
	}
	return lost
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

// firstRACKLoss returns the oldest range with time-based loss evidence.
func firstRACKLoss(outstanding []sentTCPSegment) int {
	for index := range outstanding {
		if outstanding[index].rackLost && !outstanding[index].sacked {
			return index
		}
	}
	return -1
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
			part.cwr = offset == 0 && segment.cwr
			if end != len(segment.payload) {
				part.flags &^= tcpFlagPSH | tcpFlagFIN
			} else if part.flags&tcpFlagFIN != 0 {
				part.end++
			}
			result = append(result, part)
		}
	}
	return result
}

// trimAcknowledgedTCPSegment removes a cumulatively acknowledged prefix from
// a partially acknowledged range. A data-plus-FIN segment can be acknowledged
// exactly through its data, leaving a FIN-only range in sequence space.
func trimAcknowledgedTCPSegment(segment *sentTCPSegment, acknowledgement uint32) {
	if segment == nil || !tcpSequenceGreater(acknowledgement, segment.sequence) || !tcpSequenceLess(acknowledgement, segment.end) {
		return
	}
	skip := acknowledgement - segment.sequence
	if skip < uint32(len(segment.payload)) {
		segment.payload = segment.payload[skip:]
	} else {
		segment.payload = nil
		segment.flags &^= tcpFlagPSH
	}
	segment.sequence = acknowledgement
	// Any ACK inside this transmitted packet proves that its CWR header was
	// delivered even if a control flag remains outstanding.
	segment.cwr = false
}

// clampMSS applies local packet-size bounds to a peer MSS.
func clampMSS(value, maximum int) int {
	if value < tcpMinimumPeerMSS {
		value = tcpMinimumPeerMSS
	}
	if value > maximum {
		value = maximum
	}
	return value
}

// tcpSegmentPayloadLimit applies peer MSS to data only, while charging extra
// TCP options exclusively to the current path's header budget.
func tcpSegmentPayloadLimit(peerMSS, pathMSS, optionSize int) int {
	pathLimit := pathMSS - optionSize
	if pathLimit < peerMSS {
		return pathLimit
	}
	return peerMSS
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

// tcpRestartWindow applies RFC 5681's restart window after an idle interval
// longer than the current RTO.
func tcpRestartWindow(window uint32, mss int) uint32 {
	restart := initialTCPWindow(mss)
	if window < restart {
		return window
	}
	return restart
}

// growCongestionWindow adds delta without wrapping beyond TCP's maximum
// representable scaled receive window.
func growCongestionWindow(window, delta uint32) uint32 {
	if window >= tcpMaximumScaledWindow || delta >= tcpMaximumScaledWindow-window {
		return tcpMaximumScaledWindow
	}
	return window + delta
}

// newRenoPartialACKWindow applies RFC 6582 partial-window deflation. One
// SMSS is restored only when at least one complete SMSS left the network, and
// the result retains TCP's one-segment congestion-window floor.
func newRenoPartialACKWindow(window, acknowledged uint32, mss int) uint32 {
	if acknowledged >= window {
		window = 0
	} else {
		window -= acknowledged
	}
	minimum := uint32(mss)
	if acknowledged >= minimum {
		window = growCongestionWindow(window, minimum)
	}
	if window < minimum {
		window = minimum
	}
	return window
}

// receiveTCPData inserts one range and exposes all newly contiguous bytes.
func (c *TCPConn) receiveTCPData(sequence uint32, payload []byte, fin bool, receiveWindow uint32, receiveNext *uint32, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) (bool, bool) {
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
	if sequence == *receiveNext && len(*outOfOrder) == 0 {
		// The overwhelmingly common in-order path does not need an
		// allocation, sort, or a second payload copy through the
		// out-of-order scoreboard.
		originalPayloadSize := len(payload)
		if uint64(len(payload)) > uint64(receiveWindow) {
			payload = payload[:receiveWindow]
		}
		accepted := c.appendReadBuffer(payload, 0)
		*receiveNext += uint32(accepted)
		closed := fin && accepted == originalPayloadSize && uint64(originalPayloadSize) < uint64(receiveWindow)
		if closed {
			*receiveNext++
		}
		c.outOfOrderUnread.Store(0)
		return accepted != 0 || closed, closed
	}
	if !c.storeTCPOutOfOrder(*receiveNext, receiveWindow, sequence, payload, fin, outOfOrder, outOfOrderBytes) && tcpSequenceGreater(sequence, *receiveNext) {
		return false, false
	}
	return c.promoteTCPReceived(receiveNext, outOfOrder, outOfOrderBytes)
}

// promoteTCPReceived exposes queued bytes that became deliverable after either
// a segment filled a sequence gap or the application reopened its window.
func (c *TCPConn) promoteTCPReceived(receiveNext *uint32, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) (bool, bool) {
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
	c.outOfOrderUnread.Store(int64(*outOfOrderBytes))
	return delivered || remoteClosed, remoteClosed
}

// tcpDataFragment is an uncovered portion of a newly received segment.
type tcpDataFragment struct {
	offset  uint32
	payload []byte
}

// storeTCPOutOfOrder retains only uncovered bytes within the receive window.
func (c *TCPConn) storeTCPOutOfOrder(receiveNext, receiveWindow, sequence uint32, payload []byte, fin bool, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) bool {
	distance := sequence - receiveNext
	available := c.receiveAvailable(*outOfOrderBytes)
	if available < 0 {
		available = 0
	}
	if distance >= receiveWindow && !(distance == 0 && len(payload) == 0 && fin) {
		return false
	}
	originalPayloadSize := len(payload)
	if maximumPayload := int(receiveWindow - distance); len(payload) > maximumPayload {
		payload = payload[:maximumPayload]
	}
	fin = fin && (distance == 0 && len(payload) == 0 || uint64(distance)+uint64(originalPayloadSize) < uint64(receiveWindow))
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
		// An earlier FIN terminates the stream before a previously queued FIN.
		// Retain it and let normalization discard all later sequence space.
		fin = fin && !tcpSequenceGreater(incomingFINSequence, existingFINSequence)
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
		start, end := distance, distance+uint32(len(payload))
		cursor := start
		for _, existing := range *outOfOrder {
			existingStart := existing.sequence - receiveNext
			existingEnd := existingStart + uint32(len(existing.payload))
			if existingEnd <= cursor {
				continue
			}
			if existingStart >= end {
				break
			}
			if cursor < existingStart {
				fragmentEnd := existingStart
				if fragmentEnd > end {
					fragmentEnd = end
				}
				fragments = append(fragments, tcpDataFragment{
					offset:  cursor,
					payload: payload[cursor-start : fragmentEnd-start],
				})
			}
			if existingEnd > cursor {
				cursor = existingEnd
			}
			if cursor >= end {
				break
			}
		}
		if cursor < end {
			fragments = append(fragments, tcpDataFragment{offset: cursor, payload: payload[cursor-start:]})
		}
	}
	candidate := append([]tcpReceivedPiece(nil), (*outOfOrder)...)
	for _, fragment := range fragments {
		candidate = append(candidate, tcpReceivedPiece{sequence: receiveNext + fragment.offset, payload: append([]byte(nil), fragment.payload...)})
	}
	if fin {
		candidate = append(candidate, tcpReceivedPiece{sequence: incomingFINSequence, fin: true})
	}
	candidate = normalizeTCPReceivedPieces(receiveNext, candidate)
	bytes := 0
	for _, piece := range candidate {
		bytes += len(piece.payload)
	}
	if bytes > *outOfOrderBytes+available || len(candidate) > tcpMaximumOutOfOrder {
		return false
	}
	*outOfOrder, *outOfOrderBytes = candidate, bytes
	c.outOfOrderUnread.Store(int64(bytes))
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
		if tcpSequenceGreater(previousEnd, piece.sequence) {
			skip := previousEnd - piece.sequence
			if skip < uint32(len(piece.payload)) {
				piece.sequence += skip
				piece.payload = piece.payload[skip:]
				result = append(result, piece)
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

// tcpAcceptableSendSequence follows Linux's tcp_acceptable_seq rule for an
// empty ACK or active reset after the peer shrinks its receive window. SND.NXT
// is normally correct, but a sequence beyond the shrunken right edge would be
// rejected before its ACK field can be processed.
func tcpAcceptableSendSequence(sendUnacknowledged, sendNext, sendWindow uint32, sendWindowScale uint8) uint32 {
	// A zero window has no scaling ambiguity: RFC 9293 accepts only an empty
	// segment exactly at RCV.NXT. Applying the scale quantum here can create an
	// ACK loop when a small amount of data remains unacknowledged.
	if sendWindow == 0 {
		return sendUnacknowledged
	}
	windowEnd := sendUnacknowledged + sendWindow
	if !tcpSequenceLess(windowEnd, sendNext) || sendNext-windowEnd < uint32(1)<<sendWindowScale {
		return sendNext
	}
	return windowEnd
}

// tcpChallengeACKSequence selects a response that a legitimate peer can
// accept after sending an out-of-window pure ACK during a window shrink. The
// segment is still dropped without changing the TCB; only an ACK already
// within the current send range may inform the response sequence.
func tcpChallengeACKSequence(segment tcpSegment, sendUnacknowledged, sendNext, currentSendWindow uint32, sendWindowScale uint8) uint32 {
	fallback := tcpAcceptableSendSequence(sendUnacknowledged, sendNext, currentSendWindow, sendWindowScale)
	if segment.flags != tcpFlagACK || len(segment.payload) != 0 || segment.acknowledgement-sendUnacknowledged > sendNext-sendUnacknowledged {
		return fallback
	}
	sendWindow := uint32(segment.window) << sendWindowScale
	return tcpAcceptableSendSequence(segment.acknowledgement, sendNext, sendWindow, sendWindowScale)
}

// tcpECNStartsRecovery permits one congestion response per transmitted window.
// Equality still belongs to the current recovery epoch; only an ACK beyond the
// saved boundary proves that later data encountered another CE mark.
func tcpECNStartsRecovery(active bool, acknowledgement, recoveryPoint uint32) bool {
	return !active || tcpSequenceGreater(acknowledgement, recoveryPoint)
}

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

// tcpKeepAliveOrWindowProbe recognizes the two RFC 9293 probe forms that use
// RCV.NXT-1 deliberately. They require an ordinary ACK and must not consume
// the RFC 5961 challenge-ACK rate limit.
func tcpKeepAliveOrWindowProbe(segment tcpSegment, length, receiveNext, receiveWindow uint32) bool {
	if segment.flags&(tcpFlagRST|tcpFlagSYN|tcpFlagFIN) != 0 || segment.flags&tcpFlagACK == 0 || segment.sequence != receiveNext-1 {
		return false
	}
	// RFC 1122 permits a keepalive to contain either no payload or one
	// garbage octet. The latter remains a keepalive when the receive window
	// is open; its sequence is deliberately just below the left edge.
	return length <= 1
}

// tcpWindowUpdateAllowed implements the RFC 9293 SND.WL1/SND.WL2 ordering
// rule so reordered ACKs cannot restore a stale advertised send window.
func tcpWindowUpdateAllowed(sequence, acknowledgement, lastSequence, lastAcknowledgement uint32) bool {
	return tcpSequenceGreater(sequence, lastSequence) ||
		sequence == lastSequence && tcpSequenceGreaterEqual(acknowledgement, lastAcknowledgement)
}

// tcpDuplicateACKEvidence applies the deliberately different RFC 5681 and RFC
// 6675 duplicate-ACK definitions. A SACK sender counts newly reported
// scoreboard data even when the segment also advances ACK, updates the window,
// or carries data. Without SACK, only a repeated pure ACK with an unchanged
// advertised window provides classic fast-retransmit evidence.
func tcpDuplicateACKEvidence(segment tcpSegment, peerSACK, newSACKInfo, ackAdvanced bool, sendUnacknowledged, previousWindow, peerWindow uint32) bool {
	if peerSACK {
		return newSACKInfo
	}
	return !ackAdvanced && segment.acknowledgement == sendUnacknowledged && previousWindow == peerWindow &&
		len(segment.payload) == 0 && segment.flags&(tcpFlagSYN|tcpFlagFIN) == 0
}

// Verify that TCPConn implements net.Conn.
var _ net.Conn = (*TCPConn)(nil)

// Verify the additional standard TCPConn interfaces.
var _ io.ReaderFrom = (*TCPConn)(nil)
var _ io.WriterTo = (*TCPConn)(nil)
