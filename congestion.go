package mipstack

import (
	"math"
	"time"
)

// CongestionControl identifies a TCP congestion-control algorithm.
type CongestionControl string

const (
	// CongestionControlCUBIC selects RFC 9438 CUBIC with Reno-friendly growth.
	CongestionControlCUBIC CongestionControl = "cubic"
	// CongestionControlReno selects RFC 5681 Reno congestion avoidance.
	CongestionControlReno CongestionControl = "reno"
	// CongestionControlBBR selects model-based BBR congestion control.
	CongestionControlBBR CongestionControl = "bbr"
)

const (
	// bbrBandwidthWindow is the number of packet-timed rounds retained by the
	// bottleneck-bandwidth max filter.
	bbrBandwidthWindow = 10
	// bbrFullBandwidthRounds is the number of stagnant rounds that end Startup.
	bbrFullBandwidthRounds = 3
	// bbrMinRTTWindow is the lifetime of a propagation-delay sample.
	bbrMinRTTWindow = 10 * time.Second
	// bbrProbeRTTDuration is the minimum time spent with a reduced flight size.
	bbrProbeRTTDuration = 200 * time.Millisecond
	// bbrStartupPacingGain rapidly fills an initially unknown path.
	bbrStartupPacingGain = 2.885
	// bbrDrainPacingGain removes the Startup queue at the reciprocal gain.
	bbrDrainPacingGain = 1 / bbrStartupPacingGain
	// bbrCongestionWindowGain retains two estimated bandwidth-delay products.
	bbrCongestionWindowGain = 2.0
	// bbrFullBandwidthGrowth is the minimum meaningful round-to-round growth.
	bbrFullBandwidthGrowth = 1.25
	// bbrMinimumCongestionMSS is the ProbeRTT and model-target window floor.
	bbrMinimumCongestionMSS = 4
	// tcpPacingInitialBurst matches Linux fq's unpaced first ten segments.
	tcpPacingInitialBurst = 10
	// tcpUserspacePacingQuantum amortizes connection-actor timer wakes and
	// avoids treating sub-quantum clock jitter as host scheduling delay.
	tcpUserspacePacingQuantum = 500 * time.Microsecond
	// bbrPacingLowRateThreshold is Linux BBR's 1.2 Mbit/s boundary between a
	// one-MSS and two-MSS minimum send quantum.
	bbrPacingLowRateThreshold = 1_200_000 / 8
	// bbrMaximumSendQuantum matches Linux's maximum GSO/send quantum. The
	// stack does not create a GSO packet, but may release this many paced bytes
	// from one connection actor before waiting again.
	bbrMaximumSendQuantum = 65535
)

// bbrProbeBandwidthGains cycles above, below, and at the estimated bottleneck
// rate to discover more capacity without retaining a standing queue.
var bbrProbeBandwidthGains = [...]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

// valid reports whether c names a supported algorithm.
func (c CongestionControl) valid() bool {
	switch c {
	case CongestionControlCUBIC, CongestionControlReno, CongestionControlBBR:
		return true
	default:
		return false
	}
}

// tcpCongestionController keeps algorithm state inside one connection actor.
type tcpCongestionController struct {
	algorithm      CongestionControl
	renoCredit     float64
	pacingNext     time.Time
	pacingSegments uint64
	cubic          cubicCongestionControl
	bbr            bbrCongestionControl
}

// newTCPCongestionController constructs one per-connection controller.
func newTCPCongestionController(algorithm CongestionControl) tcpCongestionController {
	return tcpCongestionController{algorithm: algorithm}
}

// onCongestion computes the slow-start threshold after packet loss.
func (c *tcpCongestionController) onCongestion(window, flight uint32, mss int) uint32 {
	c.renoCredit = 0
	switch c.algorithm {
	case CongestionControlReno:
		// RFC 5681 defines Reno's threshold from FlightSize, not cwnd. They
		// differ when the sender is application- or receive-window-limited.
		return congestionThreshold(flight, mss, 1, 2)
	case CongestionControlBBR:
		// Linux BBR preserves ssthresh and manages recovery with packet
		// conservation; it does not apply CUBIC's beta decrease.
		return window
	default:
		return c.cubic.onCongestion(window, mss)
	}
}

// onECN computes the slow-start threshold for an ECN congestion event. RFC
// 3168 and RFC 9438 permit an ECN response to reduce cwnd to one SMSS, while
// loss recovery retains RFC 5681's two-SMSS threshold floor.
func (c *tcpCongestionController) onECN(window, flight uint32, mss int) uint32 {
	c.renoCredit = 0
	switch c.algorithm {
	case CongestionControlReno:
		return congestionThresholdWithFloor(flight, mss, 1, 2, 1)
	case CongestionControlBBR:
		return window
	default:
		return c.cubic.onECN(window, mss)
	}
}

// onTimeout applies the algorithm's retransmission-timeout response. CUBIC
// starts its next congestion-avoidance epoch at K=0 as required by RFC 9438;
// fast loss and ECN continue through onCongestion and onECN respectively.
func (c *tcpCongestionController) onTimeout(window, flight uint32, mss int) uint32 {
	c.renoCredit = 0
	switch c.algorithm {
	case CongestionControlReno:
		return congestionThreshold(flight, mss, 1, 2)
	case CongestionControlBBR:
		return window
	default:
		return c.cubic.onTimeout(window, mss)
	}
}

// onACK advances slow start or the selected congestion-avoidance model.
func (c *tcpCongestionController) onACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight uint32, slowStart bool) uint32 {
	threshold := window
	if slowStart {
		threshold = ^uint32(0)
	}
	return c.onACKWithThreshold(window, acknowledged, mss, now, smoothedRTT, sampleRTT, flight, threshold)
}

// onACKWithThreshold splits one cumulative ACK at the slow-start boundary,
// matching Linux tcp_slow_start's returned congestion-avoidance credit.
func (c *tcpCongestionController) onACKWithThreshold(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight, slowStartThreshold uint32) uint32 {
	if window == 0 || acknowledged == 0 || mss < 1 {
		return window
	}
	switch c.algorithm {
	case CongestionControlReno:
		if !congestionWindowLimited(window, flight, mss) {
			return window
		}
		if window < slowStartThreshold {
			growth := acknowledged
			if available := slowStartThreshold - window; growth > available {
				growth = available
			}
			window = growCongestionWindow(window, growth)
			acknowledged -= growth
			if acknowledged == 0 {
				return window
			}
		}
		return applyCongestionIncrease(window, &c.renoCredit, additiveIncrease(window, acknowledged, mss))
	case CongestionControlBBR:
		return c.bbr.onACK(window, acknowledged, mss, now, smoothedRTT, sampleRTT, flight, !congestionWindowLimited(window, flight, mss))
	default:
		if !congestionWindowLimited(window, flight, mss) {
			c.cubic.onApplicationLimited(now)
			return window
		}
		if window < slowStartThreshold {
			growth := acknowledged
			if available := slowStartThreshold - window; growth > available {
				growth = available
			}
			window = growCongestionWindow(window, growth)
			acknowledged -= growth
			if acknowledged == 0 {
				return window
			}
		}
		return c.cubic.onACK(window, acknowledged, mss, now, smoothedRTT)
	}
}

// observeRecoveryACK keeps BBR's delivery and propagation models current
// while PRR or packet conservation owns the recovery congestion window. Linux
// likewise runs BBR's model update for recovery ACKs before applying the
// recovery-specific cwnd bound. Reno and CUBIC have no model-only work here.
func (c *tcpCongestionController) observeRecoveryACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight uint32) {
	if c.algorithm != CongestionControlBBR || window == 0 || acknowledged == 0 || mss < 1 {
		return
	}
	_ = c.bbr.onACK(window, acknowledged, mss, now, smoothedRTT, sampleRTT, flight, !congestionWindowLimited(window, flight, mss))
}

// congestionWindowLimited mirrors Linux's packet-granularity allowance: a
// sender that is less than one MSS below cwnd is still congestion-limited.
func congestionWindowLimited(window, flight uint32, mss int) bool {
	if flight >= window {
		return true
	}
	return window-flight <= uint32(mss)
}

// pacingDelay returns the remaining userspace pacing interval. BBR supplies
// its model rate; Reno and CUBIC use Linux's cwnd/SRTT pacing formula.
func (c *tcpCongestionController) pacingDelay(now time.Time, window, flight uint32, mss int, smoothedRTT time.Duration, slowStartThreshold uint32) time.Duration {
	if c.algorithm == CongestionControlBBR {
		return c.bbr.pacingDelay(now, mss)
	}
	if c.pacingSegments < tcpPacingInitialBurst || smoothedRTT <= 0 || c.pacingNext.IsZero() || !now.Before(c.pacingNext) {
		return 0
	}
	return pacingTimerDelay(c.pacingNext.Sub(now), tcpUserspacePacingQuantum)
}

// onDataSend advances algorithm and pacing state after a first transmission.
func (c *tcpCongestionController) onDataSend(bytes, mss int, now time.Time, window, flight uint32, smoothedRTT time.Duration, slowStartThreshold uint32) {
	switch c.algorithm {
	case CongestionControlCUBIC:
		c.cubic.onSend(now, flight)
	case CongestionControlBBR:
		c.bbr.onSend(bytes, mss, now, flight)
		return
	}
	c.advanceWindowPacing(bytes, mss, now, window, flight, smoothedRTT, slowStartThreshold, true)
}

// onRetransmit advances only the pacing clock. Loss recovery must not treat a
// retransmission as new application data or a new CUBIC transmission epoch.
func (c *tcpCongestionController) onRetransmit(bytes, mss int, now time.Time, window, flight uint32, smoothedRTT time.Duration, slowStartThreshold uint32) {
	if c.algorithm == CongestionControlBBR {
		c.bbr.advanceRetransmissionPacing(bytes, mss, now)
		return
	}
	c.advanceWindowPacing(bytes, mss, now, window, flight, smoothedRTT, slowStartThreshold, false)
}

// advanceWindowPacing applies Linux tcp_update_pacing_rate semantics. Linux
// uses 200% of max(cwnd, packets_out)/SRTT in early slow start and 120% while
// approaching ssthresh or in congestion avoidance.
func (c *tcpCongestionController) advanceWindowPacing(bytes, mss int, now time.Time, window, flight uint32, smoothedRTT time.Duration, slowStartThreshold uint32, catchUp bool) {
	if bytes <= 0 {
		return
	}
	c.pacingSegments++
	if c.pacingSegments < tcpPacingInitialBurst || smoothedRTT <= 0 {
		return
	}
	rate := windowPacingRate(window, flight, smoothedRTT, slowStartThreshold)
	if rate <= 0 || math.IsInf(rate, 0) || math.IsNaN(rate) {
		return
	}
	delay := time.Duration(float64(time.Second) * float64(bytes) / rate)
	if delay < time.Microsecond {
		delay = time.Microsecond
	}
	maximumDebt := delay
	const maximumDuration = time.Duration(1<<63 - 1)
	if delay <= maximumDuration/tcpPacingInitialBurst {
		maximumDebt *= tcpPacingInitialBurst
	} else {
		maximumDebt = maximumDuration
	}
	base, _ := pacingScheduleBase(c.pacingNext, now, maximumDebt, catchUp && flight != 0)
	c.pacingNext = base.Add(delay)
}

// windowPacingRate applies Linux tcp_update_pacing_rate semantics. Linux uses
// 200% of max(cwnd, packets_out)/SRTT in early slow start and 120% while
// approaching ssthresh or in congestion avoidance.
func windowPacingRate(window, flight uint32, smoothedRTT time.Duration, slowStartThreshold uint32) float64 {
	if smoothedRTT <= 0 {
		return 0
	}
	rateWindow := window
	if flight > rateWindow {
		rateWindow = flight
	}
	ratio := 1.2
	if window < slowStartThreshold/2 {
		ratio = 2
	}
	return float64(rateWindow) * ratio / smoothedRTT.Seconds()
}

// bbrSendQuantum follows Linux BBR's send-quantum policy: one MSS below
// 1.2 Mbit/s, two MSS above it, at least 1/1024 second of the pacing rate, and
// never more than 65535 bytes. It amortizes userspace timer wakes without an
// operating-system-specific timer allowance.
func bbrSendQuantum(rate float64, mss int) int {
	if rate <= 0 || mss < 1 || math.IsInf(rate, 0) || math.IsNaN(rate) {
		return 0
	}
	quantum := mss
	if rate >= bbrPacingLowRateThreshold {
		quantum = 2 * mss
	}
	if rate >= float64(bbrMaximumSendQuantum*1024) {
		return bbrMaximumSendQuantum
	}
	if rateQuantum := int(rate / 1024); rateQuantum > quantum {
		quantum = rateQuantum
	}
	if quantum > bbrMaximumSendQuantum {
		quantum = bbrMaximumSendQuantum
	}
	return quantum
}

// bbrSendQuantumDuration converts the byte quantum to its interval at rate.
func bbrSendQuantumDuration(rate float64, mss int) time.Duration {
	quantum := bbrSendQuantum(rate, mss)
	if quantum == 0 {
		return 0
	}
	durationValue := float64(time.Second) * float64(quantum) / rate
	const maximumDuration = time.Duration(1<<63 - 1)
	if durationValue >= float64(maximumDuration) {
		return maximumDuration
	}
	duration := time.Duration(durationValue)
	if duration < time.Microsecond {
		duration = time.Microsecond
	}
	return duration
}

// bbrTimerQuantumDuration adds a small userspace timer floor to Linux's byte
// quantum. Kernel fq can schedule a 64 KiB quantum at sub-millisecond
// precision; waking a Go connection actor more often than this floor adds CPU
// cost without improving the long-term pacing rate.
func bbrTimerQuantumDuration(rate float64, mss int) time.Duration {
	duration := bbrSendQuantumDuration(rate, mss)
	if duration < tcpUserspacePacingQuantum {
		return tcpUserspacePacingQuantum
	}
	return duration
}

// pacingTimerDelay retains a bounded send quantum to amortize timers while
// preserving the long-term pacing rate, like Linux's fq/TSQ batching.
func pacingTimerDelay(delay, quantum time.Duration) time.Duration {
	if delay <= quantum {
		return 0
	}
	return delay - quantum
}

// pacingScheduleBase retains at most one send quantum of pacing debt after a
// late userspace wake. late reports material host scheduling delay;
// retransmissions pass catchUp=false so an RTO cannot release stale debt.
func pacingScheduleBase(next, now time.Time, maximumDebt time.Duration, catchUp bool) (base time.Time, late bool) {
	if next.IsZero() {
		return now, false
	}
	if !next.Before(now) {
		return next, false
	}
	if !catchUp {
		return now, false
	}
	late = now.Sub(next) > tcpUserspacePacingQuantum
	earliest := now.Add(-maximumDebt)
	if next.Before(earliest) {
		next = earliest
	}
	return next, late
}

// onMTUChange resets packet-size-dependent epochs without discarding BBR's
// path bandwidth and RTT model.
func (c *tcpCongestionController) onMTUChange() {
	c.renoCredit = 0
	c.pacingNext = time.Time{}
	c.cubic = cubicCongestionControl{}
	c.bbr.nextSend = time.Time{}
	c.bbr.schedulerLimited = false
}

// congestionThreshold applies one multiplicative decrease with the RFC 5681
// two-segment floor.
func congestionThreshold(window uint32, mss, numerator, denominator int) uint32 {
	return congestionThresholdWithFloor(window, mss, numerator, denominator, 2)
}

// congestionThresholdWithFloor applies one multiplicative decrease and a
// caller-selected segment floor.
func congestionThresholdWithFloor(window uint32, mss, numerator, denominator, minimumSegments int) uint32 {
	threshold := uint32(uint64(window) * uint64(numerator) / uint64(denominator))
	if minimum := uint32(minimumSegments * mss); threshold < minimum {
		threshold = minimum
	}
	return threshold
}

// additiveIncrease computes the fractional byte-counted Reno increment. The
// caller retains sub-byte credit so a large window cannot grow once per ACK
// merely because integer arithmetic rounded every increment up to one.
func additiveIncrease(window, acknowledged uint32, mss int) float64 {
	return float64(acknowledged) * float64(mss) / float64(window)
}

// applyCongestionIncrease commits all whole bytes from a fractional growth
// credit while preserving the remainder for later ACKs.
func applyCongestionIncrease(window uint32, credit *float64, increment float64) uint32 {
	if increment <= 0 || math.IsNaN(increment) {
		return window
	}
	*credit += increment
	whole := uint64(*credit)
	if whole == 0 {
		return window
	}
	*credit -= float64(whole)
	if whole > uint64(tcpMaximumScaledWindow) {
		whole = uint64(tcpMaximumScaledWindow)
	}
	return growCongestionWindow(window, uint32(whole))
}

// cubicCongestionControl retains the CUBIC epoch and previous maximum window.
// Windows are stored in bytes; floating-point arithmetic is confined to the
// actor goroutine and only evaluates the RFC 9438 growth curve.
type cubicCongestionControl struct {
	epochStart         time.Time
	lastSend           time.Time
	applicationLimited time.Time
	lastMaximum        float64
	previousMaximum    float64
	priorWindow        float64
	estimate           float64
	origin             float64
	k                  float64
	credit             float64
	afterTimeout       bool
}

// onSend freezes CUBIC's epoch across application-idle periods, matching
// Linux's CA_EVENT_TX_START handling. Otherwise wall-clock idle time would
// move the resumed flow far ahead on the cubic growth curve.
func (c *cubicCongestionControl) onSend(now time.Time, flight uint32) {
	if !c.applicationLimited.IsZero() {
		if !c.epochStart.IsZero() && now.After(c.applicationLimited) {
			c.epochStart = c.epochStart.Add(now.Sub(c.applicationLimited))
		}
		c.applicationLimited = time.Time{}
	} else if flight == 0 && !c.epochStart.IsZero() && !c.lastSend.IsZero() && now.After(c.lastSend) {
		c.epochStart = c.epochStart.Add(now.Sub(c.lastSend))
	}
	c.lastSend = now
}

// onApplicationLimited records when ACK processing first observes that the
// sender is below cwnd. The next new-data send removes this interval from the
// CUBIC epoch, including receive-window-limited periods.
func (c *cubicCongestionControl) onApplicationLimited(now time.Time) {
	if c.applicationLimited.IsZero() {
		c.applicationLimited = now
	}
}

// onCongestion applies CUBIC's beta=0.7 decrease and resets the growth epoch.
func (c *cubicCongestionControl) onCongestion(window uint32, mss int) uint32 {
	return c.reduce(window, mss, 2)
}

// onECN applies CUBIC's multiplicative decrease with the one-SMSS ECN floor.
func (c *cubicCongestionControl) onECN(window uint32, mss int) uint32 {
	return c.reduce(window, mss, 1)
}

// reduce updates CUBIC state for one congestion event.
func (c *cubicCongestionControl) reduce(window uint32, mss, minimumSegments int) uint32 {
	current := float64(window) / float64(mss)
	if c.previousMaximum != 0 && current < c.previousMaximum {
		c.lastMaximum = current * 0.85
	} else {
		c.lastMaximum = current
	}
	c.previousMaximum = current
	c.epochStart = time.Time{}
	c.applicationLimited = time.Time{}
	c.priorWindow = current
	c.estimate = 0
	c.credit = 0
	c.afterTimeout = false
	return congestionThresholdWithFloor(window, mss, 7, 10, minimumSegments)
}

// onTimeout records the RFC 9438 timeout rule. Slow start runs first; the
// window at the beginning of the following congestion-avoidance stage becomes
// both W_max and W_est with K=0.
func (c *cubicCongestionControl) onTimeout(window uint32, mss int) uint32 {
	c.epochStart = time.Time{}
	c.lastSend = time.Time{}
	c.applicationLimited = time.Time{}
	c.lastMaximum = 0
	c.previousMaximum = 0
	// cwnd_prior is the window at the most recent ssthresh update, even
	// though W_max for the next epoch is reset at the later CA entry point.
	// Keeping the two values distinct prevents W_est from switching to
	// alpha=1 before it has recovered the pre-timeout window (RFC 9438 4.3).
	c.priorWindow = float64(window) / float64(mss)
	c.estimate = 0
	c.origin = 0
	c.k = 0
	c.credit = 0
	c.afterTimeout = true
	return congestionThreshold(window, mss, 7, 10)
}

// onACK advances the CUBIC curve while retaining Reno-compatible additive
// growth as a lower bound in low-window and high-RTT regimes.
func (c *cubicCongestionControl) onACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT time.Duration) uint32 {
	if window == 0 || acknowledged == 0 || mss < 1 {
		return window
	}
	current := float64(window) / float64(mss)
	if c.epochStart.IsZero() {
		c.epochStart = now
		c.estimate = current
		if c.afterTimeout {
			c.lastMaximum = current
			c.previousMaximum = current
			c.origin = current
			c.k = 0
			c.afterTimeout = false
		} else if c.lastMaximum > current {
			c.origin = c.lastMaximum
			c.k = math.Cbrt((c.lastMaximum - current) / 0.4)
		} else {
			c.origin = current
			c.k = 0
		}
	}
	alpha := float64(9) / 17
	if c.priorWindow > 0 && c.estimate >= c.priorWindow {
		alpha = 1
	}
	c.estimate += alpha * float64(acknowledged) / float64(window)
	elapsed := now.Sub(c.epochStart).Seconds()
	curve := 0.4*math.Pow(elapsed-c.k, 3) + c.origin
	target := 0.4*math.Pow(elapsed+smoothedRTT.Seconds()-c.k, 3) + c.origin
	if target < current {
		target = current
	} else if maximum := 1.5 * current; target > maximum {
		target = maximum
	}
	// RFC 9438 section 4.3 uses alpha=3*(1-beta)/(1+beta). For
	// beta=0.7 this is 9/17, not Reno's full one-SMSS-per-RTT growth.
	increment := float64(0)
	if curve < c.estimate {
		increment = (c.estimate - current) * float64(mss)
	} else if target > current {
		increment = float64(acknowledged) * (target - current) / current
	}
	return applyCongestionIncrease(window, &c.credit, increment)
}

// bbrMode is one phase of the BBR state machine.
type bbrMode uint8

const (
	// bbrStartup exponentially discovers available bottleneck bandwidth.
	bbrStartup bbrMode = iota
	// bbrDrain removes the queue accumulated during Startup.
	bbrDrain
	// bbrProbeBandwidth cycles pacing gains around the estimated bandwidth.
	bbrProbeBandwidth
	// bbrProbeRTT briefly reduces flight size to refresh propagation delay.
	bbrProbeRTT
)

// bbrCongestionControl estimates bottleneck bandwidth and propagation RTT,
// then derives a congestion window and pacing rate from that path model.
type bbrCongestionControl struct {
	mode bbrMode

	bandwidthSamples [bbrBandwidthWindow]float64
	bandwidthIndex   int
	bandwidthCount   int
	bandwidth        float64
	roundBandwidth   float64
	sampleStart      time.Time
	sampleBytes      uint64

	minimumRTT      time.Duration
	minimumRTTStamp time.Time
	roundBytes      uint32
	roundTarget     uint32
	roundLimited    bool
	fullBandwidth   float64
	fullRounds      int

	cycleIndex  int
	cycleStamp  time.Time
	probeDone   time.Time
	probeRound  bool
	priorWindow uint32
	nextSend    time.Time
	idleRestart bool
	// schedulerLimited marks a packet-timed round whose sender was delayed by
	// the host rather than by the modeled network path.
	schedulerLimited bool
}

// onACK updates BBR's delivery model, state machine, and congestion window.
func (b *bbrCongestionControl) onACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight uint32, applicationLimited bool) uint32 {
	idleRestart := b.idleRestart
	b.idleRestart = false
	minimumExpired := b.minimumRTT != 0 && now.Sub(b.minimumRTTStamp) >= bbrMinRTTWindow
	if sampleRTT > 0 && (b.minimumRTT == 0 || sampleRTT < b.minimumRTT || minimumExpired) {
		b.minimumRTT, b.minimumRTTStamp = sampleRTT, now
	}
	limited := applicationLimited || b.schedulerLimited
	b.observeBandwidth(acknowledged, now, smoothedRTT, flight, limited)
	roundStart := b.advanceRound(window, acknowledged, limited)
	if roundStart {
		b.schedulerLimited = false
	}
	if b.mode != bbrProbeRTT && minimumExpired && !idleRestart {
		b.mode = bbrProbeRTT
		b.probeDone = time.Time{}
		b.probeRound = false
		b.priorWindow = window
		b.nextSend = time.Time{}
		// Start packet-timed accounting at ProbeRTT entry. Reusing a target
		// derived from the former large cwnd can keep a drained flow in
		// ProbeRTT for hundreds of low-flight rounds.
		remaining := flight
		if acknowledged >= remaining {
			remaining = uint32(mss)
		} else {
			remaining -= acknowledged
		}
		b.roundBytes = 0
		b.roundTarget = remaining
		b.roundLimited = false
		b.schedulerLimited = false
		roundStart = false
	}
	bdp := b.bandwidthDelayProduct()
	switch b.mode {
	case bbrStartup:
		if b.fullRounds >= bbrFullBandwidthRounds {
			b.mode = bbrDrain
		}
	case bbrDrain:
		drainTarget := b.quantizedWindow(bdp, mss, 1)
		if bdp > 0 && uint64(flight) <= drainTarget {
			b.mode = bbrProbeBandwidth
			b.cycleIndex = bbrInitialCycle(now)
			b.cycleStamp = now
		}
	case bbrProbeBandwidth:
		if b.minimumRTT > 0 && now.Sub(b.cycleStamp) >= b.minimumRTT {
			b.cycleIndex = (b.cycleIndex + 1) % len(bbrProbeBandwidthGains)
			b.cycleStamp = now
		}
	case bbrProbeRTT:
		minimumFlight := uint32(bbrMinimumCongestionMSS * mss)
		if b.probeDone.IsZero() && flight <= minimumFlight {
			b.probeDone = now.Add(bbrProbeRTTDuration)
			b.probeRound = false
		} else if !b.probeDone.IsZero() && roundStart {
			b.probeRound = true
		}
		if !b.probeDone.IsZero() && b.probeRound && !now.Before(b.probeDone) {
			b.minimumRTTStamp = now
			b.mode = bbrProbeBandwidth
			b.cycleIndex = bbrInitialCycle(now)
			b.cycleStamp = now
			if window < b.priorWindow {
				window = b.priorWindow
			}
		}
	}
	minimum := uint32(bbrMinimumCongestionMSS * mss)
	if b.mode == bbrProbeRTT {
		return minimum
	}
	target := minimum
	if bdp > 0 {
		gain := bbrCongestionWindowGain
		if b.mode == bbrStartup || b.mode == bbrDrain {
			gain = bbrStartupPacingGain
		}
		modelTarget := b.quantizedWindow(bdp, mss, gain)
		if modelTarget > uint64(tcpMaximumScaledWindow) {
			modelTarget = uint64(tcpMaximumScaledWindow)
		}
		if uint32(modelTarget) > target {
			target = uint32(modelTarget)
		}
	}
	if initial := initialTCPWindow(mss); b.mode == bbrStartup && target < initial {
		target = initial
	}
	if window < target {
		window = growCongestionWindow(window, acknowledged)
		if window > target {
			window = target
		}
	} else if b.mode != bbrStartup && window > target {
		window = target
	}
	return window
}

// observeBandwidth accumulates the largest ACK-rate sample in the current
// packet-timed round. advanceRound installs it in the ten-round max filter.
func (b *bbrCongestionControl) observeBandwidth(acknowledged uint32, now time.Time, rtt time.Duration, flight uint32, applicationLimited bool) {
	sample := float64(0)
	if b.sampleStart.IsZero() {
		if rtt <= 0 {
			return
		}
		// Bootstrap pacing from the initial flight. Using only the first ACK's
		// bytes underestimates paths with delayed ACKs, then makes this simplified
		// sampler permanently self-limit at that low rate during startup.
		if flight > 0 {
			sample = float64(flight) / rtt.Seconds()
		} else {
			sample = float64(acknowledged) / rtt.Seconds()
		}
		b.sampleStart = now
	} else if now.After(b.sampleStart) {
		b.sampleBytes += uint64(acknowledged)
		interval := now.Sub(b.sampleStart)
		minimumInterval := b.minimumRTT / 4
		if minimumInterval < 2*time.Millisecond {
			minimumInterval = 2 * time.Millisecond
		} else if minimumInterval > 50*time.Millisecond {
			minimumInterval = 50 * time.Millisecond
		}
		if interval >= minimumInterval {
			sample = float64(b.sampleBytes) / interval.Seconds()
			b.sampleStart = now
			b.sampleBytes = 0
			// ACK compression cannot create sustainable delivery above the
			// sender's current exploratory pacing rate. Keep enough headroom
			// for Startup and ProbeBW to discover additional bandwidth.
			if b.bandwidth > 0 {
				gain := b.pacingGain()
				if gain < 1.25 {
					gain = 1.25
				}
				upper := b.bandwidth * gain * 1.25
				if sample > upper {
					sample = upper
				}
			}
		}
	}
	// Linux BBR does not let a low application-limited delivery sample drag
	// down the path model. Such a sample is useful only when it establishes a
	// rate at least as high as the current filtered estimate.
	if applicationLimited && sample < b.bandwidth {
		return
	}
	if sample > b.roundBandwidth {
		b.roundBandwidth = sample
	}
	if sample > b.bandwidth {
		b.bandwidth = sample
	}
}

// advanceRound detects BBR bandwidth plateaus once per congestion-window's
// worth of acknowledged data.
func (b *bbrCongestionControl) advanceRound(window, acknowledged uint32, applicationLimited bool) bool {
	if b.roundTarget == 0 {
		b.roundTarget = window
	}
	b.roundLimited = b.roundLimited || applicationLimited
	b.roundBytes += acknowledged
	if b.roundBytes < b.roundTarget {
		return false
	}
	b.roundBytes = 0
	b.roundTarget = window
	roundLimited := b.roundLimited
	b.roundLimited = false
	if b.roundBandwidth > 0 {
		b.bandwidthSamples[b.bandwidthIndex] = b.roundBandwidth
		b.bandwidthIndex = (b.bandwidthIndex + 1) % len(b.bandwidthSamples)
		if b.bandwidthCount < len(b.bandwidthSamples) {
			b.bandwidthCount++
		}
		b.roundBandwidth = 0
		b.bandwidth = 0
		for index := 0; index < b.bandwidthCount; index++ {
			if b.bandwidthSamples[index] > b.bandwidth {
				b.bandwidth = b.bandwidthSamples[index]
			}
		}
		// A packet-timed round without a delivery-rate sample says nothing about
		// bandwidth growth. Counting it as a plateau can end Startup before the
		// sampler's minimum interval has elapsed, especially on low-RTT paths.
		if b.bandwidth >= b.fullBandwidth*bbrFullBandwidthGrowth {
			b.fullBandwidth = b.bandwidth
			b.fullRounds = 0
		} else if !roundLimited {
			b.fullRounds++
		}
	}
	return true
}

// quantizedWindow applies BBR's end-system allowance in addition to the path
// BDP. At low rates one segment stands in for each TSO/GRO scheduling slot.
func (b *bbrCongestionControl) quantizedWindow(bdp uint64, mss int, gain float64) uint64 {
	target := uint64(float64(bdp)*gain) + uint64(3*mss)
	minimum := uint64(bbrMinimumCongestionMSS * mss)
	if target < minimum {
		target = minimum
	}
	return target
}

// bbrInitialCycle spreads concurrent flows over Linux's non-probing cycle
// phases instead of synchronizing every connection on the 1.25 gain phase.
func bbrInitialCycle(now time.Time) int {
	return 1 + int(uint64(now.UnixNano())%uint64(len(bbrProbeBandwidthGains)-1))
}

// bandwidthDelayProduct returns the estimated bytes in flight at one minimum
// RTT, or zero until both model inputs are known.
func (b *bbrCongestionControl) bandwidthDelayProduct() uint64 {
	if b.bandwidth <= 0 || b.minimumRTT <= 0 {
		return 0
	}
	value := b.bandwidth * b.minimumRTT.Seconds()
	if value >= float64(tcpMaximumScaledWindow) {
		return uint64(tcpMaximumScaledWindow)
	}
	return uint64(value)
}

// pacingGain returns the gain for BBR's current phase.
func (b *bbrCongestionControl) pacingGain() float64 {
	if b.idleRestart && b.mode == bbrProbeBandwidth {
		return 1
	}
	switch b.mode {
	case bbrStartup:
		return bbrStartupPacingGain
	case bbrDrain:
		return bbrDrainPacingGain
	case bbrProbeBandwidth:
		return bbrProbeBandwidthGains[b.cycleIndex]
	default:
		return 1
	}
}

// pacingDelay reports how long the sender should wait before another new
// data segment. BBR permits the initial window as a burst before it has a
// delivery-rate sample.
func (b *bbrCongestionControl) pacingDelay(now time.Time, mss int) time.Duration {
	if b.bandwidth <= 0 || b.nextSend.IsZero() || !now.Before(b.nextSend) {
		return 0
	}
	rate := b.bandwidth * b.pacingGain()
	return pacingTimerDelay(b.nextSend.Sub(now), bbrTimerQuantumDuration(rate, mss))
}

// onSend advances BBR's packet pacing clock.
func (b *bbrCongestionControl) onSend(bytes, mss int, now time.Time, flight uint32) {
	if flight == 0 {
		// Do not fold application idle time into the next delivery sample.
		b.sampleStart = time.Time{}
		b.sampleBytes = 0
		b.nextSend = time.Time{}
		b.idleRestart = true
		b.schedulerLimited = false
	}
	b.advancePacing(bytes, mss, now)
}

// advancePacing moves BBR's new-data transmission clock and retains bounded
// debt after a late userspace wake.
func (b *bbrCongestionControl) advancePacing(bytes, mss int, now time.Time) {
	b.advancePacingAt(bytes, mss, now, true)
}

// advanceRetransmissionPacing discards expired pacing debt. A retransmission
// caused by network loss or an RTO is not evidence of a late pacer wake and
// must not trigger a catch-up burst.
func (b *bbrCongestionControl) advanceRetransmissionPacing(bytes, mss int, now time.Time) {
	b.advancePacingAt(bytes, mss, now, false)
}

// advancePacingAt advances the BBR clock with optional late-wake catch-up.
func (b *bbrCongestionControl) advancePacingAt(bytes, mss int, now time.Time, catchUp bool) {
	rate := b.bandwidth * b.pacingGain()
	if bytes <= 0 || rate <= 0 {
		return
	}
	delayValue := float64(time.Second) * float64(bytes) / rate
	const maximumDuration = time.Duration(1<<63 - 1)
	delay := maximumDuration
	if delayValue < float64(maximumDuration) {
		delay = time.Duration(delayValue)
	}
	if delay < time.Microsecond {
		delay = time.Microsecond
	}
	maximumDebt := bbrSendQuantumDuration(rate, mss)
	base, late := pacingScheduleBase(b.nextSend, now, maximumDebt, catchUp)
	if late {
		b.schedulerLimited = true
	}
	b.nextSend = base.Add(delay)
}
