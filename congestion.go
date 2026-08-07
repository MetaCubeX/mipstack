package mipstack

import (
	"crypto/rand"
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
	// RFC 9406 HyStart++ delay-increase and Conservative Slow Start values.
	hyStartMinimumRTTThreshold = 4 * time.Millisecond
	hyStartMaximumRTTThreshold = 16 * time.Millisecond
	hyStartRTTDivisor          = 8
	hyStartMinimumRTTSamples   = 8
	hyStartCSSGrowthDivisor    = 4
	hyStartCSSRounds           = 5

	// bbrBandwidthWindow is the number of packet-timed rounds retained by the
	// bottleneck-bandwidth max filter.
	bbrBandwidthWindow = 10
	// bbrFullBandwidthRounds is the number of stagnant rounds that end Startup.
	bbrFullBandwidthRounds = 3
	// bbrMinRTTWindow is the lifetime of a propagation-delay sample.
	bbrMinRTTWindow = 10 * time.Second
	// bbrProbeRTTDuration is the minimum time spent with a reduced flight size.
	bbrProbeRTTDuration = 200 * time.Millisecond
	// bbrStartupPacingGain rapidly fills an initially unknown path. Linux's
	// fixed-point BBR_UNIT representation evaluates to 739/256.
	bbrStartupPacingGain = 739.0 / 256
	// bbrDrainPacingGain removes the Startup queue using Linux's 88/256 value.
	bbrDrainPacingGain = 88.0 / 256
	// bbrCongestionWindowGain retains two estimated bandwidth-delay products.
	bbrCongestionWindowGain = 2.0
	// bbrFullBandwidthGrowth is the minimum meaningful round-to-round growth.
	bbrFullBandwidthGrowth = 1.25
	// bbrMinimumCongestionMSS is the ProbeRTT and model-target window floor.
	bbrMinimumCongestionMSS = 4
	// bbrInitialCongestionMSS is Linux TCP_INIT_CWND, used when BBR has no
	// valid propagation-delay sample.
	bbrInitialCongestionMSS = 10
	// bbrPacingMargin keeps the average pacing rate one percent below the
	// estimated bottleneck bandwidth, matching Linux BBRv1.
	bbrPacingMargin = 0.99
	// bbrLongTermMinimumRounds is the minimum policer sampling interval.
	bbrLongTermMinimumRounds = 4
	// bbrLongTermMaximumRounds bounds one policer sampling interval.
	bbrLongTermMaximumRounds = 4 * bbrLongTermMinimumRounds
	// bbrLongTermUseRounds periodically leaves policer mode to probe again.
	bbrLongTermUseRounds = 48
	// bbrLongTermLossRatio is Linux BBRv1's fixed-point loss threshold. Its
	// documented 20 percent value is represented as 50/256 in the kernel.
	bbrLongTermLossRatio = 50.0 / 256
	// bbrLongTermBandwidthRatio accepts estimates within one eighth.
	bbrLongTermBandwidthRatio = 1.0 / 8
	// bbrLongTermBandwidthDifference is the absolute 4 Kbit/s allowance after
	// Linux's one-percent rate margin is applied.
	bbrLongTermBandwidthDifference = (4000.0 / 8) / bbrPacingMargin
	// bbrExtraACKedWindow rotates its two aggregation maxima every five rounds.
	bbrExtraACKedWindow = 5
	// bbrExtraACKedMaximumInterval caps aggregation allowance at 100 ms of bw.
	bbrExtraACKedMaximumInterval = 100 * time.Millisecond
	// tcpPacingInitialBurst matches Linux fq's unpaced first ten segments.
	tcpPacingInitialBurst = 10
	// tcpUserspaceSchedulingTolerance avoids classifying ordinary timer and
	// actor jitter as a host-scheduler limitation.
	tcpUserspaceSchedulingTolerance = 25 * time.Microsecond
	// tcpUserspacePacingBatch amortizes per-segment timer wakes for Reno and
	// CUBIC while preserving their long-term window-derived pacing rate.
	tcpUserspacePacingBatch = 500 * time.Microsecond
	// bbrPacingLowRateThreshold is Linux BBR's 1.2 Mbit/s boundary between a
	// one-MSS and two-MSS minimum send quantum.
	bbrPacingLowRateThreshold = 1_200_000 / 8
	// bbrSendQuantumByteTarget is the Linux-style byte target applied before
	// dividing by MSS. The minimum segment goal can exceed it for unusual MSS
	// values, just as bbr_tso_segs_goal permits in Linux.
	bbrSendQuantumByteTarget = 65535
	// bbrMaximumSendSegments is Linux's per-GSO segment-count cap.
	bbrMaximumSendSegments = 127
	// bbrMaximumUserspaceQuanta bounds one actor pacing group. Linux fq can
	// revisit a single active flow after each quantum without a goroutine hop;
	// mipstack groups at most four such quanta to amortize that userspace cost.
	bbrMaximumUserspaceQuanta = 4
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
	algorithm         CongestionControl
	renoCredit        float64
	pacingNext        time.Time
	pacingSegments    uint64
	pacingRate        float64
	maximumPacingRate uint64
	cubic             cubicCongestionControl
	bbr               bbrCongestionControl
}

// setMaximumPacingRate updates the socket policy without discarding the
// congestion controller's unconstrained model rate. It reports a change so
// the connection actor can cancel a timer based on the former policy.
func (c *tcpCongestionController) setMaximumPacingRate(rate uint64) bool {
	if c.maximumPacingRate == rate {
		return false
	}
	c.pacingNext = time.Time{}
	c.bbr.nextSend = time.Time{}
	c.bbr.pacingWakeDeadline = time.Time{}
	c.bbr.pacingBurstRemaining = 0
	c.maximumPacingRate = rate
	c.bbr.maximumPacingRate = rate
	return true
}

// limitPacingRate applies the socket's sk_max_pacing_rate-style policy.
func (c *tcpCongestionController) limitPacingRate(rate float64) float64 {
	if c.maximumPacingRate != 0 && rate > float64(c.maximumPacingRate) {
		return float64(c.maximumPacingRate)
	}
	return rate
}

// tcpHyStart implements RFC 9406 round tracking and Conservative Slow Start.
// It is used only for the initial Reno/CUBIC slow start; BBR owns its Startup
// transition and post-loss slow starts use ordinary RFC 5681 behavior.
type tcpHyStart struct {
	windowEnd       uint32
	lastRoundMinRTT time.Duration
	currentMinRTT   time.Duration
	samples         int
	css             bool
	cssBaselineRTT  time.Duration
	cssRounds       int
	cssCredit       uint32
	done            bool
}

// start initializes sequence-number round measurement at SND.NXT.
func (h *tcpHyStart) start(sendNext uint32) {
	*h = tcpHyStart{windowEnd: sendNext}
}

// restartRound discards measurements that span an application-idle restart.
func (h *tcpHyStart) restartRound(sendNext uint32) {
	if h.done {
		return
	}
	h.windowEnd = sendNext
	h.lastRoundMinRTT = 0
	h.currentMinRTT = 0
	h.samples = 0
	h.css = false
	h.cssBaselineRTT = 0
	h.cssRounds = 0
	h.cssCredit = 0
}

// disable prevents HyStart++ from restarting after loss, ECN, or completion.
func (h *tcpHyStart) disable() {
	h.done = true
	h.css = false
	h.cssCredit = 0
}

// onACK returns the byte credit that slow start may apply and whether CSS has
// completed. The caller sets ssthresh to the current cwnd on completion.
func (h *tcpHyStart) onACK(acknowledgement, sendNext, acknowledged uint32, sampleRTT time.Duration) (uint32, bool) {
	if h.done || acknowledged == 0 {
		return acknowledged, false
	}
	if tcpSequenceGreaterEqual(acknowledgement, h.windowEnd) {
		if h.css {
			if h.cssRounds >= hyStartCSSRounds {
				h.disable()
				return acknowledged, true
			}
			h.cssRounds++
		}
		h.lastRoundMinRTT = h.currentMinRTT
		h.currentMinRTT = 0
		h.samples = 0
		h.windowEnd = sendNext
	}
	if sampleRTT > 0 {
		if h.currentMinRTT == 0 || sampleRTT < h.currentMinRTT {
			h.currentMinRTT = sampleRTT
		}
		h.samples++
	}
	if h.samples >= hyStartMinimumRTTSamples {
		if h.css {
			if h.currentMinRTT < h.cssBaselineRTT {
				h.css = false
				h.cssBaselineRTT = 0
				h.cssRounds = 0
				h.cssCredit = 0
			}
		} else if h.lastRoundMinRTT > 0 && h.currentMinRTT > 0 {
			threshold := h.lastRoundMinRTT / hyStartRTTDivisor
			if threshold < hyStartMinimumRTTThreshold {
				threshold = hyStartMinimumRTTThreshold
			} else if threshold > hyStartMaximumRTTThreshold {
				threshold = hyStartMaximumRTTThreshold
			}
			if h.currentMinRTT >= h.lastRoundMinRTT+threshold {
				h.css = true
				h.cssBaselineRTT = h.currentMinRTT
				h.cssRounds = 1 // A partial transition round counts per RFC 9406.
			}
		}
	}
	if !h.css {
		return acknowledged, false
	}
	credit := uint64(h.cssCredit) + uint64(acknowledged)
	growth := uint32(credit / hyStartCSSGrowthDivisor)
	h.cssCredit = uint32(credit % hyStartCSSGrowthDivisor)
	return growth, false
}

// newTCPCongestionController constructs one per-connection controller.
func newTCPCongestionController(algorithm CongestionControl) tcpCongestionController {
	controller := tcpCongestionController{algorithm: algorithm}
	if algorithm == CongestionControlBBR {
		// Linux starts with a bubble in the pipe so early samples cannot lower
		// an established bandwidth model. A high sample is still accepted.
		controller.bbr.applicationLimitedUntil = 1
	}
	return controller
}

// onCongestion computes the slow-start threshold after packet loss.
func (c *tcpCongestionController) onCongestion(window, flight, slowStartThreshold uint32, mss int) uint32 {
	c.renoCredit = 0
	switch c.algorithm {
	case CongestionControlReno:
		// RFC 5681 defines Reno's threshold from FlightSize, not cwnd. They
		// differ when the sender is application- or receive-window-limited.
		return congestionThreshold(flight, mss, 1, 2)
	case CongestionControlBBR:
		// Linux BBR preserves ssthresh and manages recovery with packet
		// conservation; it does not apply CUBIC's beta decrease.
		c.bbr.saveWindow(window)
		return slowStartThreshold
	default:
		return c.cubic.onCongestion(window, mss)
	}
}

// onECN computes both transport values changed by an ECN congestion event.
// Reno and CUBIC reduce cwnd to their new threshold; Linux BBR leaves its
// model-controlled cwnd and infinite threshold intact while entering CWR.
func (c *tcpCongestionController) onECN(window, flight, slowStartThreshold uint32, mss int) (threshold, congestionWindow uint32) {
	c.renoCredit = 0
	switch c.algorithm {
	case CongestionControlReno:
		threshold = congestionThresholdWithFloor(flight, mss, 1, 2, 1)
		return threshold, threshold
	case CongestionControlBBR:
		c.bbr.saveWindow(window)
		return slowStartThreshold, window
	default:
		threshold = c.cubic.onECN(window, mss)
		return threshold, threshold
	}
}

// onTimeout applies the algorithm's retransmission-timeout response. CUBIC
// starts its next congestion-avoidance epoch at K=0 as required by RFC 9438;
// fast loss and ECN continue through onCongestion and onECN respectively.
func (c *tcpCongestionController) onTimeout(window, flight, slowStartThreshold uint32, mss int, now time.Time) uint32 {
	c.renoCredit = 0
	switch c.algorithm {
	case CongestionControlReno:
		return congestionThreshold(flight, mss, 1, 2)
	case CongestionControlBBR:
		c.bbr.saveWindow(window)
		// Linux records TCP_CA_Loss separately from ordinary fast recovery. The
		// window is restored only after the RTO recovery point is acknowledged.
		c.bbr.recovery = false
		c.bbr.lossRecovery = true
		c.bbr.packetConservation = false
		c.bbr.fullBandwidth = 0
		c.bbr.roundStart = true
		c.bbr.updateLongTermBandwidth(bbrRateSample{losses: 1, ackTime: now})
		c.bbr.sampledLost = c.bbr.totalLost
		return slowStartThreshold
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
	return c.onACKWithThreshold(window, acknowledged, mss, now, smoothedRTT, sampleRTT, flight, threshold, !congestionWindowLimited(window, flight, mss))
}

// onACKWithThreshold splits one cumulative ACK at the slow-start boundary,
// matching Linux tcp_slow_start's returned congestion-avoidance credit.
func (c *tcpCongestionController) onACKWithThreshold(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight, slowStartThreshold uint32, applicationLimited bool) uint32 {
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
		return c.bbr.onACK(window, acknowledged, mss, now, smoothedRTT, sampleRTT, flight, applicationLimited)
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

// finishBBRRateSample converts delivery snapshots selected during cumulative
// ACK and SACK processing into one Linux-style rate sample.
func (c *tcpCongestionController) finishBBRRateSample(sample *bbrRateSample, acknowledged uint32, priorInFlight, inFlight uint32, now time.Time, nowStamp monotonicStamp, minimumRTT, smoothedRTT, sampleRTT time.Duration) {
	if c.algorithm != CongestionControlBBR {
		return
	}
	c.bbr.finishRateSample(sample, acknowledged, priorInFlight, inFlight, now, nowStamp, minimumRTT, smoothedRTT, sampleRTT)
}

// onBBRRateSample applies one completed delivery sample to cwnd and pacing.
// A nonzero threshold is Linux's one-time Startup-to-Drain ssthresh update.
func (c *tcpCongestionController) onBBRRateSample(window uint32, mss int, sample bbrRateSample) (uint32, uint32) {
	if c.algorithm != CongestionControlBBR {
		return window, 0
	}
	return c.bbr.onRateSample(window, mss, sample)
}

// markApplicationLimited records a sender bubble for future BBR snapshots.
func (c *tcpCongestionController) markApplicationLimited(flight uint32) {
	if c.algorithm == CongestionControlBBR {
		c.bbr.markApplicationLimited(flight)
	}
}

// noteLoss records newly declared lost bytes. duringACK retains them for the
// rate sample being assembled; timer-driven recovery has already consumed the
// event and must not report it again on the next ACK.
func (c *tcpCongestionController) noteLoss(bytes uint32, duringACK bool) {
	if c.algorithm == CongestionControlBBR {
		c.bbr.noteLoss(bytes)
		if !duringACK {
			c.bbr.sampledLost = c.bbr.totalLost
		}
	}
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
func (c *tcpCongestionController) pacingDelay(now time.Time, bytes int, window, flight uint32, mss int, smoothedRTT time.Duration, slowStartThreshold uint32) time.Duration {
	if c.algorithm == CongestionControlBBR {
		if c.pacingSegments < tcpPacingInitialBurst {
			return 0
		}
		return c.bbr.pacingDelay(now, bytes, mss, flight)
	}
	if c.pacingSegments < tcpPacingInitialBurst || smoothedRTT <= 0 || c.pacingNext.IsZero() || !now.Before(c.pacingNext) {
		return 0
	}
	return pacingTimerDelay(c.pacingNext.Sub(now), tcpUserspacePacingBatch)
}

// onPacingWake accounts an actual actor timer wake even when another socket
// limit prevents the following send attempt from reaching pacingDelay.
func (c *tcpCongestionController) onPacingWake(now time.Time, flight uint32) {
	if c.algorithm == CongestionControlBBR {
		c.bbr.consumePacingWake(now, flight)
	}
}

// cancelPacingWake discards a BBR pacing request when the actor repurposes its
// logical pacing timer for a different transport policy such as an ECN hold.
func (c *tcpCongestionController) cancelPacingWake() {
	if c.algorithm == CongestionControlBBR {
		c.bbr.pacingWakeDeadline = time.Time{}
	}
}

// onDataSend advances Reno/CUBIC pacing state after a first transmission.
func (c *tcpCongestionController) onDataSend(bytes, mss int, now time.Time, window, flight uint32, smoothedRTT time.Duration, slowStartThreshold uint32) {
	switch c.algorithm {
	case CongestionControlCUBIC:
		c.cubic.onSend(now, flight)
	}
	c.advanceWindowPacing(bytes, mss, now, window, flight, smoothedRTT, slowStartThreshold, true)
}

// onBBRDataSend snapshots Linux delivery metadata, advances BBR pacing, and
// returns any ProbeRTT window restoration caused by an idle restart.
func (c *tcpCongestionController) onBBRDataSend(bytes, mss int, now time.Time, stamp monotonicStamp, packetsOut, window uint32) (bbrRateSnapshot, uint32) {
	c.pacingSegments++
	return c.bbr.onSend(bytes, mss, now, stamp, packetsOut, window)
}

// onRetransmit advances only the pacing clock. Loss recovery must not treat a
// retransmission as new application data or a new CUBIC transmission epoch.
func (c *tcpCongestionController) onRetransmit(bytes, mss int, now time.Time, stamp monotonicStamp, window, flight, packetsOut uint32, smoothedRTT time.Duration, slowStartThreshold uint32) bbrRateSnapshot {
	if c.algorithm == CongestionControlBBR {
		snapshot := c.bbr.snapshotSend(stamp, packetsOut)
		c.bbr.advanceRetransmissionPacing(bytes, mss, now)
		return snapshot
	}
	c.advanceWindowPacing(bytes, mss, now, window, flight, smoothedRTT, slowStartThreshold, false)
	return bbrRateSnapshot{}
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
	modelRate := windowPacingRate(window, flight, smoothedRTT, slowStartThreshold)
	if modelRate <= 0 || math.IsInf(modelRate, 0) || math.IsNaN(modelRate) {
		return
	}
	c.pacingRate = modelRate
	rate := c.limitPacingRate(modelRate)
	delay := pacingDuration(bytes, rate)
	maximumDebt := delay
	const maximumDuration = time.Duration(1<<63 - 1)
	if delay <= maximumDuration/tcpPacingInitialBurst {
		maximumDebt *= tcpPacingInitialBurst
	} else {
		maximumDebt = maximumDuration
	}
	base := pacingScheduleBase(c.pacingNext, now, maximumDebt, catchUp && flight != 0)
	c.pacingNext = base.Add(delay)
}

// pacingTimerDelay permits one bounded userspace batch ahead of the pacing
// clock while preserving the long-term rate in the accumulated deadline.
func pacingTimerDelay(delay, batch time.Duration) time.Duration {
	if delay <= batch {
		return 0
	}
	return delay - batch
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
// 1.2 Mbit/s, two MSS above it, and otherwise the whole-MSS portion of 1/1024
// second of the pacing rate. The byte target is capped before applying the
// one/two-segment minimum, and the final result is capped at 127 segments. It
// amortizes userspace timer wakes without an operating-system-specific timer
// allowance.
func bbrSendQuantum(rate float64, mss int) int {
	if rate <= 0 || mss < 1 || math.IsInf(rate, 0) || math.IsNaN(rate) {
		return 0
	}
	minimumSegments := 1
	if rate >= bbrPacingLowRateThreshold {
		minimumSegments = 2
	}
	targetBytes := rate / 1024
	if targetBytes > bbrSendQuantumByteTarget {
		targetBytes = bbrSendQuantumByteTarget
	}
	segments := int(targetBytes / float64(mss))
	if segments < minimumSegments {
		segments = minimumSegments
	}
	if segments > bbrMaximumSendSegments {
		segments = bbrMaximumSendSegments
	}
	return segments * mss
}

// bbrSendQuantumDuration converts the byte quantum to its interval at rate.
func bbrSendQuantumDuration(rate float64, mss int) time.Duration {
	quantum := bbrSendQuantum(rate, mss)
	return pacingDuration(quantum, rate)
}

// pacingDuration converts a byte count and rate to a positive, saturated
// scheduling interval.
func pacingDuration(bytes int, rate float64) time.Duration {
	if bytes <= 0 || rate <= 0 || math.IsNaN(rate) {
		return 0
	}
	durationValue := float64(time.Second) * float64(bytes) / rate
	const maximumDuration = time.Duration(1<<63 - 1)
	if durationValue >= float64(maximumDuration) {
		return maximumDuration
	}
	duration := time.Duration(durationValue)
	if duration < time.Nanosecond {
		duration = time.Nanosecond
	}
	return duration
}

// bbrUserspacePacingBudget groups whole Linux send quanta only when one
// quantum is shorter than the userspace timer batching interval.
func bbrUserspacePacingBudget(rate float64, mss int) int {
	quantum := bbrSendQuantum(rate, mss)
	if quantum == 0 {
		return 0
	}
	targetValue := math.Ceil(rate * tcpUserspacePacingBatch.Seconds())
	if targetValue <= float64(quantum) {
		return quantum
	}
	maximum := quantum * bbrMaximumUserspaceQuanta
	if targetValue >= float64(maximum) {
		return maximum
	}
	target := int(targetValue)
	quanta := (target + quantum - 1) / quantum
	return quanta * quantum
}

// pacingScheduleBase retains bounded pacing debt after a late userspace wake.
// Retransmissions pass catchUp=false so an RTO cannot release stale debt.
func pacingScheduleBase(next, now time.Time, maximumDebt time.Duration, catchUp bool) time.Time {
	if next.IsZero() {
		return now
	}
	if !next.Before(now) {
		return next
	}
	if !catchUp {
		return now
	}
	earliest := now.Add(-maximumDebt)
	if next.Before(earliest) {
		next = earliest
	}
	return next
}

// onMTUChange resets packet-size-dependent epochs without discarding BBR's
// path bandwidth and RTT model.
func (c *tcpCongestionController) onMTUChange() {
	c.renoCredit = 0
	c.pacingNext = time.Time{}
	c.cubic = cubicCongestionControl{}
	c.bbr.nextSend = time.Time{}
	c.bbr.pacingWakeDeadline = time.Time{}
	c.bbr.pacingBurstRemaining = 0
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
	if c.lastMaximum != 0 && current < c.lastMaximum {
		c.lastMaximum = current * 0.85
	} else {
		c.lastMaximum = current
	}
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

// bbrStamp is a wrapping microsecond timestamp. Every sampled interval is
// bounded by current flight or an idle restart, so modulo subtraction remains
// valid across its approximately 71-minute wrap interval.
type bbrStamp uint32

// bbrStampAt compacts a stack-relative nanosecond stamp.
func bbrStampAt(stamp monotonicStamp) bbrStamp {
	if stamp == 0 {
		return 0
	}
	value := bbrStamp((uint64(stamp)-1)/uint64(time.Microsecond)) + 1
	if value == 0 {
		return 1
	}
	return value
}

// bbrStampDuration returns a modulo-safe microsecond interval.
func bbrStampDuration(later, earlier bbrStamp) time.Duration {
	if later == 0 || earlier == 0 {
		return 0
	}
	delta := uint32(later - earlier)
	if delta == 0 {
		return 0
	}
	return time.Duration(delta) * time.Microsecond
}

const (
	bbrRateApplicationLimited = uint32(1) << 31
	bbrRateDeliveredMask      = bbrRateApplicationLimited - 1
)

// bbrRateSnapshot is Linux tcp_rate_skb_sent's per-transmission delivery
// snapshot. Compact stamps and a packed flag keep it at 12 bytes.
type bbrRateSnapshot struct {
	firstSent      bbrStamp
	deliveredStamp bbrStamp
	deliveredFlags uint32
}

// delivered returns the byte counter without its packed flag.
func (s bbrRateSnapshot) delivered() uint32 { return s.deliveredFlags & bbrRateDeliveredMask }

// applicationLimited reports the packed Linux app-limited snapshot bit.
func (s bbrRateSnapshot) applicationLimited() bool {
	return s.deliveredFlags&bbrRateApplicationLimited != 0
}

// bbrDeliveredAfterEqual compares the 31-bit delivery counter while its
// unambiguous half-range remains at least the maximum TCP flight size.
func bbrDeliveredAfterEqual(value, reference uint32) bool {
	delta := (value - reference) & bbrRateDeliveredMask
	return delta == 0 || delta < bbrRateApplicationLimited/2
}

// bbrRateSample is one ACK's Linux-style delivery-rate observation. Rates use
// bytes rather than packets because mipstack's SACK scoreboard is byte exact.
type bbrRateSample struct {
	priorDelivered     uint32
	delivered          uint32
	acked              uint32
	losses             uint64
	priorInFlight      uint32
	inFlight           uint32
	interval           time.Duration
	rtt                time.Duration
	smoothedRTT        time.Duration
	ackTime            time.Time
	lastSent           monotonicStamp
	lastEnd            uint32
	applicationLimited bool
	schedulerLimited   bool
	retransmitted      bool
	recovery           bool
	fastRecovery       bool
	ackDelayed         bool
	valid              bool
	firstSent          bbrStamp
	priorStamp         bbrStamp
}

// observe retains delivery metadata from the most recently transmitted range
// newly acknowledged by the cumulative ACK or SACK scoreboard.
func (s *bbrRateSample) observe(segment sentTCPSegment) {
	snapshot := segment.rate
	if snapshot.deliveredStamp == 0 {
		return
	}
	sent := segment.hostQueue.queuedAt
	if s.priorStamp != 0 && (sent < s.lastSent || sent == s.lastSent && !tcpSequenceGreater(segment.end, s.lastEnd)) {
		return
	}
	s.priorDelivered = snapshot.delivered()
	s.priorStamp = snapshot.deliveredStamp
	s.firstSent = snapshot.firstSent
	s.lastSent = sent
	s.lastEnd = segment.end
	s.applicationLimited = snapshot.applicationLimited()
	s.schedulerLimited = segment.rateSchedulerLimited
	s.retransmitted = segment.transmissions > 1
}

// bbrMode is one phase of the Linux BBRv1 state machine.
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

// String returns the conventional Linux BBR state name.
func (m bbrMode) String() string {
	switch m {
	case bbrStartup:
		return "STARTUP"
	case bbrDrain:
		return "DRAIN"
	case bbrProbeBandwidth:
		return "PROBE_BW"
	case bbrProbeRTT:
		return "PROBE_RTT"
	default:
		return ""
	}
}

// bbrRateValue converts an internal byte rate to its diagnostic representation.
func bbrRateValue(rate float64) uint64 {
	if rate <= 0 || math.IsNaN(rate) {
		return 0
	}
	if rate >= float64(^uint64(0)) || math.IsInf(rate, 1) {
		return ^uint64(0)
	}
	return uint64(rate)
}

// bbrBandwidthSample is one candidate in Linux's constant-space windowed
// maximum filter. Round subtraction intentionally uses uint32 wrap semantics.
type bbrBandwidthSample struct {
	rate  float64
	round uint32
}

// bbrBandwidthFilter tracks the best three well-spaced samples from the last
// bbrBandwidthWindow packet-timed rounds, matching Linux win_minmax.
type bbrBandwidthFilter struct {
	samples [3]bbrBandwidthSample
}

// reset replaces every candidate with one newly accepted measurement.
func (f *bbrBandwidthFilter) reset(round uint32, rate float64) float64 {
	sample := bbrBandwidthSample{rate: rate, round: round}
	f.samples[0], f.samples[1], f.samples[2] = sample, sample, sample
	return rate
}

// update applies Linux minmax_running_max and returns the current maximum.
func (f *bbrBandwidthFilter) update(window, round uint32, rate float64) float64 {
	sample := bbrBandwidthSample{rate: rate, round: round}
	if sample.rate >= f.samples[0].rate || sample.round-f.samples[2].round > window {
		return f.reset(round, rate)
	}
	if sample.rate >= f.samples[1].rate {
		f.samples[1], f.samples[2] = sample, sample
	} else if sample.rate >= f.samples[2].rate {
		f.samples[2] = sample
	}
	delta := sample.round - f.samples[0].round
	if delta > window {
		f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], sample
		if sample.round-f.samples[0].round > window {
			f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], sample
		}
	} else if f.samples[1].round == f.samples[0].round && delta > window/4 {
		f.samples[1], f.samples[2] = sample, sample
	} else if f.samples[2].round == f.samples[1].round && delta > window/2 {
		f.samples[2] = sample
	}
	return f.samples[0].rate
}

// bbrCongestionControl is a byte-scaled implementation of Linux BBRv1. It
// retains Linux's delivery sampler, packet-timed rounds, max filters, ACK
// aggregation compensation, policer detection, gain cycle, and ProbeRTT.
type bbrCongestionControl struct {
	mode bbrMode

	bandwidthFilter      bbrBandwidthFilter
	bandwidth            float64
	roundCount           uint32
	nextRoundDelivered   uint32
	roundStart           bool
	fullBandwidth        float64
	fullRounds           int
	fullBandwidthReached bool

	minimumRTT      time.Duration
	minimumRTTStamp time.Time
	cycleIndex      int
	cycleStamp      bbrStamp
	probeDone       time.Time
	probeRound      bool
	priorWindow     uint32

	delivered               uint64
	deliveredStamp          bbrStamp
	firstSent               bbrStamp
	applicationLimitedUntil uint64
	schedulerLimitedUntil   uint64
	schedulerLimitedEvents  uint64
	totalLost               uint64
	sampledLost             uint64

	ackEpochStamp    time.Time
	ackEpochBytes    uint64
	extraACKed       [2]uint32
	extraACKedIndex  int
	extraACKedRounds int

	longTermSampling      bool
	longTermUseBandwidth  bool
	longTermBandwidth     float64
	longTermLastDelivered uint64
	longTermLastLost      uint64
	longTermLastStamp     time.Time
	longTermRounds        int

	pacingRate           float64
	maximumPacingRate    uint64
	nextSend             time.Time
	pacingWakeDeadline   time.Time
	pacingBurstRemaining int
	idleRestart          bool
	hasSeenRTT           bool

	recovery           bool
	lossRecovery       bool
	packetConservation bool
}

// onACK is retained for controller-level tests and callers without packet
// metadata. Established TCP uses finishRateSample and onRateSample instead.
func (b *bbrCongestionControl) onACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight uint32, applicationLimited bool) uint32 {
	sample := bbrRateSample{
		priorDelivered: uint32(b.delivered) & bbrRateDeliveredMask, delivered: acknowledged, acked: acknowledged,
		priorInFlight: flight, inFlight: flight, interval: smoothedRTT, rtt: sampleRTT,
		smoothedRTT: smoothedRTT, ackTime: now, applicationLimited: applicationLimited, valid: smoothedRTT > 0,
	}
	if acknowledged < sample.inFlight {
		sample.inFlight -= acknowledged
	} else {
		sample.inFlight = 0
	}
	b.delivered += uint64(acknowledged)
	if acknowledged != 0 {
		b.deliveredStamp = bbrStampAt(monotonicStamp(now.UnixNano()) + 1)
	}
	window, _ = b.onRateSample(window, mss, sample)
	return window
}

// finishRateSample advances delivery accounting and validates the sample using
// the longer of its send and ACK phases, as Linux tcp_rate_gen does.
func (b *bbrCongestionControl) finishRateSample(sample *bbrRateSample, acknowledged uint32, priorInFlight, inFlight uint32, now time.Time, nowStamp monotonicStamp, minimumRTT, smoothedRTT, sampleRTT time.Duration) {
	sample.acked = acknowledged
	sample.priorInFlight = priorInFlight
	sample.inFlight = inFlight
	sample.ackTime = now
	sample.rtt = sampleRTT
	sample.smoothedRTT = smoothedRTT
	sample.losses = b.totalLost - b.sampledLost
	b.sampledLost = b.totalLost
	if acknowledged != 0 {
		b.delivered += uint64(acknowledged)
		b.deliveredStamp = bbrStampAt(nowStamp)
	}
	if b.applicationLimitedUntil != 0 && b.delivered > b.applicationLimitedUntil {
		b.applicationLimitedUntil = 0
	}
	if b.schedulerLimitedUntil != 0 && b.delivered > b.schedulerLimitedUntil {
		b.schedulerLimitedUntil = 0
	}
	if sample.priorStamp == 0 {
		return
	}
	// tcp_rate_skb_delivered advances first_tx_mstamp to the transmit time of
	// the newest range selected for this ACK. Future packets snapshot this new
	// boundary so their send phase does not grow from the connection's first
	// flight forever.
	compactNow := bbrStampAt(nowStamp)
	compactSent := bbrStampAt(sample.lastSent)
	b.firstSent = compactSent
	if !sample.retransmitted {
		if selectedRTT := bbrStampDuration(compactNow, compactSent); selectedRTT > 0 {
			sample.rtt = selectedRTT
		}
	}
	sample.delivered = (uint32(b.delivered) - sample.priorDelivered) & bbrRateDeliveredMask
	sendInterval := bbrStampDuration(compactSent, sample.firstSent)
	ackInterval := bbrStampDuration(compactNow, sample.priorStamp)
	if ackInterval > sendInterval {
		sendInterval = ackInterval
	}
	if sendInterval <= 0 || minimumRTT > 0 && sendInterval < minimumRTT {
		return
	}
	sample.interval = sendInterval
	sample.valid = true
}

// onRateSample updates BBR's path model, pacing rate, and congestion window.
func (b *bbrCongestionControl) onRateSample(window uint32, mss int, sample bbrRateSample) (uint32, uint32) {
	b.updateBandwidth(sample)
	b.updateACKAggregation(sample, window, mss)
	b.updateCycle(sample, mss)
	b.checkFullBandwidth(sample)
	threshold := b.checkDrain(sample, mss)
	window = b.updateMinimumRTT(window, sample, mss)
	// Linux clears idle_restart at the end of bbr_update_min_rtt, before
	// updating gains and the pacing rate. The saved ProbeBW gain still governs
	// cycle advancement above; only the actual rate was neutralized on restart.
	if sample.delivered != 0 {
		b.idleRestart = false
	}
	b.setPacingRate(window, sample.smoothedRTT)
	window = b.setCongestionWindow(window, sample, mss)
	return window, threshold
}

// updateBandwidth advances packet-timed rounds and the ten-round max filter.
func (b *bbrCongestionControl) updateBandwidth(sample bbrRateSample) {
	b.roundStart = false
	if !sample.valid {
		return
	}
	if bbrDeliveredAfterEqual(sample.priorDelivered, b.nextRoundDelivered) {
		b.nextRoundDelivered = uint32(b.delivered) & bbrRateDeliveredMask
		b.roundCount++
		b.roundStart = true
		b.packetConservation = false
	}
	b.updateLongTermBandwidth(sample)
	rate := float64(sample.delivered) / sample.interval.Seconds()
	if sample.locallyLimited() && rate < b.bandwidth {
		return
	}
	b.bandwidth = b.bandwidthFilter.update(bbrBandwidthWindow, b.roundCount, rate)
}

// updateACKAggregation tracks excess ACKed bytes over the expected delivery
// rate in an approximate five-to-ten-round window.
func (b *bbrCongestionControl) updateACKAggregation(sample bbrRateSample, window uint32, mss int) {
	if !sample.valid || sample.acked == 0 || mss < 1 {
		return
	}
	if b.roundStart {
		b.extraACKedRounds++
		if b.extraACKedRounds >= bbrExtraACKedWindow {
			b.extraACKedRounds = 0
			b.extraACKedIndex ^= 1
			b.extraACKed[b.extraACKedIndex] = 0
		}
	}
	if sample.schedulerLimited {
		// A delayed userspace sender can release overdue pacing groups close
		// together. Their returning ACKs are not path aggregation evidence, but
		// packet-timed rounds must still age the existing maximum filter.
		b.ackEpochStamp = sample.ackTime
		b.ackEpochBytes = 0
		return
	}
	if b.ackEpochStamp.IsZero() {
		b.ackEpochStamp = sample.ackTime
	}
	elapsed := sample.ackTime.Sub(b.ackEpochStamp)
	if elapsed < 0 {
		elapsed = 0
	}
	expected := uint64(b.effectiveBandwidth() * elapsed.Seconds())
	maximumEpochBytes := uint64(1<<20) * uint64(mss)
	if b.ackEpochBytes <= expected || b.ackEpochBytes+uint64(sample.acked) >= maximumEpochBytes {
		b.ackEpochBytes = 0
		b.ackEpochStamp = sample.ackTime
		expected = 0
	}
	b.ackEpochBytes += uint64(sample.acked)
	if b.ackEpochBytes >= maximumEpochBytes {
		// Linux stores ack_epoch_acked in a saturated 20-bit field. This
		// byte-scaled equivalent keeps the same reset threshold.
		b.ackEpochBytes = maximumEpochBytes - 1
	}
	extra := b.ackEpochBytes - expected
	if extra > uint64(window) {
		extra = uint64(window)
	}
	if extra > uint64(^uint32(0)) {
		extra = uint64(^uint32(0))
	}
	if uint32(extra) > b.extraACKed[b.extraACKedIndex] {
		b.extraACKed[b.extraACKedIndex] = uint32(extra)
	}
}

// checkFullBandwidth applies Linux's 25-percent growth test for three
// consecutive packet-timed rounds not limited by the application or host
// scheduler.
func (b *bbrCongestionControl) checkFullBandwidth(sample bbrRateSample) {
	if b.fullBandwidthReached || !b.roundStart || sample.locallyLimited() {
		return
	}
	if b.bandwidth >= b.fullBandwidth*bbrFullBandwidthGrowth {
		b.fullBandwidth = b.bandwidth
		b.fullRounds = 0
		return
	}
	b.fullRounds++
	b.fullBandwidthReached = b.fullRounds >= bbrFullBandwidthRounds
}

// checkDrain enters Drain after Startup and ProbeBW after the excess queue is
// estimated to have left the network.
func (b *bbrCongestionControl) checkDrain(sample bbrRateSample, mss int) uint32 {
	gain := b.pacingGain()
	inflight := b.packetsInNetwork(sample.inFlight, sample.ackTime, mss, gain)
	var threshold uint32
	if b.mode == bbrStartup && b.fullBandwidthReached {
		threshold = uint32(b.quantizeWindowAt(b.modelWindowForBandwidth(b.bandwidth, 1, mss), mss, false))
		b.mode = bbrDrain
	}
	// Linux drains against bbr_max_bw, even if its long-term policer estimate
	// currently controls pacing and the normal model window.
	drainTarget := b.quantizeWindowAt(b.modelWindowForBandwidth(b.bandwidth, 1, mss), mss, false)
	if b.mode == bbrDrain && uint64(inflight) <= drainTarget {
		b.resetProbeBandwidth(sample.ackTime)
	}
	return threshold
}

// updateCycle applies Linux BBRv1's time, inflight, and loss conditions for
// each ProbeBW pacing-gain phase.
func (b *bbrCongestionControl) updateCycle(sample bbrRateSample, mss int) {
	if b.mode != bbrProbeBandwidth || b.minimumRTT <= 0 || b.cycleStamp == 0 || b.deliveredStamp == 0 {
		return
	}
	fullLength := bbrStampDuration(b.deliveredStamp, b.cycleStamp) > b.minimumRTT
	gain := b.pacingGain()
	advance := fullLength
	inflight := uint64(b.packetsInNetwork(sample.priorInFlight, sample.ackTime, mss, gain))
	switch {
	case gain > 1:
		advance = fullLength && (sample.losses != 0 || inflight >= b.inflightTarget(gain, mss))
	case gain < 1:
		advance = fullLength || inflight <= b.inflightTarget(1, mss)
	}
	if advance {
		b.cycleIndex = (b.cycleIndex + 1) % len(bbrProbeBandwidthGains)
		b.cycleStamp = b.deliveredStamp
	}
}

// updateMinimumRTT maintains the ten-second propagation filter and ProbeRTT.
func (b *bbrCongestionControl) updateMinimumRTT(window uint32, sample bbrRateSample, mss int) uint32 {
	expired := b.minimumRTT != 0 && sample.ackTime.Sub(b.minimumRTTStamp) > bbrMinRTTWindow
	if sample.rtt > 0 && (b.minimumRTT == 0 || sample.rtt < b.minimumRTT || expired && !sample.ackDelayed) {
		b.minimumRTT = sample.rtt
		b.minimumRTTStamp = sample.ackTime
	}
	if expired && !b.idleRestart && b.mode != bbrProbeRTT {
		b.mode = bbrProbeRTT
		if sample.recovery {
			if window > b.priorWindow {
				b.priorWindow = window
			}
		} else {
			b.priorWindow = window
		}
		b.probeDone = time.Time{}
		b.probeRound = false
		b.nextSend = time.Time{}
		b.pacingWakeDeadline = time.Time{}
	}
	if b.mode != bbrProbeRTT {
		return window
	}
	b.markApplicationLimited(sample.inFlight)
	minimumFlight := uint32(bbrMinimumCongestionMSS * mss)
	if b.probeDone.IsZero() && sample.inFlight <= minimumFlight {
		b.probeDone = sample.ackTime.Add(bbrProbeRTTDuration)
		b.probeRound = false
		b.nextRoundDelivered = uint32(b.delivered) & bbrRateDeliveredMask
	} else if !b.probeDone.IsZero() && b.roundStart {
		b.probeRound = true
	}
	if !b.probeDone.IsZero() && b.probeRound && !sample.ackTime.Before(b.probeDone) {
		b.minimumRTTStamp = sample.ackTime
		if window < b.priorWindow {
			window = b.priorWindow
		}
		b.resetMode(sample.ackTime)
	}
	return window
}

// setCongestionWindow follows Linux BBR's recovery, growth, and target-capping
// rules. SACK/RACK still decides which ranges are retransmitted; BBR owns only
// the congestion window used by that common recovery machinery.
func (b *bbrCongestionControl) setCongestionWindow(window uint32, sample bbrRateSample, mss int) uint32 {
	minimum := uint32(bbrMinimumCongestionMSS * mss)
	if sample.acked == 0 {
		// Linux skips recovery and growth without a newly (S)ACKed packet, but
		// still applies the ProbeRTT cap after updating the path model.
		if b.mode == bbrProbeRTT && window > minimum {
			return minimum
		}
		return window
	}
	if sample.losses != 0 {
		losses := sample.losses
		if losses >= uint64(window) {
			window = uint32(mss)
		} else {
			window -= uint32(losses)
		}
	}
	if b.lossRecovery && !sample.recovery {
		b.lossRecovery = false
		if window < b.priorWindow {
			window = b.priorWindow
		}
	}
	switch {
	case sample.fastRecovery && !b.recovery:
		// Linux starts the first packet-timed recovery round by releasing one
		// packet for each newly delivered packet.
		b.recovery = true
		b.packetConservation = true
		b.nextRoundDelivered = uint32(b.delivered) & bbrRateDeliveredMask
		window = growCongestionWindow(sample.inFlight, sample.acked)
	case !sample.fastRecovery && b.recovery:
		b.recovery = false
		b.packetConservation = false
		if window < b.priorWindow {
			window = b.priorWindow
		}
	}
	if b.packetConservation {
		conserved := growCongestionWindow(sample.inFlight, sample.acked)
		if window < conserved {
			window = conserved
		}
		if window < minimum {
			window = minimum
		}
		if b.mode == bbrProbeRTT && window > minimum {
			window = minimum
		}
		return window
	}
	if b.mode == bbrProbeRTT {
		if window > minimum {
			return minimum
		}
		return window
	}
	target := b.modelWindow(b.congestionWindowGain(), mss)
	if b.fullBandwidthReached {
		extra := uint64(b.extraACKed[0])
		if uint64(b.extraACKed[1]) > extra {
			extra = uint64(b.extraACKed[1])
		}
		maximumExtra := uint64(b.effectiveBandwidth() * bbrExtraACKedMaximumInterval.Seconds())
		if extra > maximumExtra {
			extra = maximumExtra
		}
		target += extra
	}
	target = b.quantizeWindow(target, mss)
	if b.fullBandwidthReached {
		grown := growCongestionWindow(window, sample.acked)
		if uint64(grown) > target {
			window = uint32(target)
		} else {
			window = grown
		}
	} else if uint64(window) < target || b.delivered < uint64(bbrInitialCongestionMSS*mss) {
		window = growCongestionWindow(window, sample.acked)
	}
	if window < minimum {
		window = minimum
	}
	return window
}

// modelWindow applies a gain to the effective bandwidth-delay product.
func (b *bbrCongestionControl) modelWindow(gain float64, mss int) uint64 {
	return b.modelWindowForBandwidth(b.effectiveBandwidth(), gain, mss)
}

// modelWindowForBandwidth matches Linux bbr_bdp, including its conservative
// ten-segment fallback when no valid RTT sample exists.
func (b *bbrCongestionControl) modelWindowForBandwidth(bandwidth, gain float64, mss int) uint64 {
	if mss < 1 {
		return 0
	}
	if b.minimumRTT <= 0 {
		return uint64(bbrInitialCongestionMSS * mss)
	}
	if bandwidth <= 0 || gain <= 0 {
		return 0
	}
	value := math.Ceil(bandwidth * b.minimumRTT.Seconds() * gain)
	if value >= float64(tcpMaximumScaledWindow) {
		return uint64(tcpMaximumScaledWindow)
	}
	return uint64(value)
}

// quantizeWindow applies Linux BBR's end-system and delayed-ACK allowances.
func (b *bbrCongestionControl) quantizeWindow(target uint64, mss int) uint64 {
	probeHigh := b.mode == bbrProbeBandwidth && b.cycleIndex == 0
	return b.quantizeWindowAt(target, mss, probeHigh)
}

// quantizeWindowAt applies the common end-system allowances with an explicit
// ProbeBW high-gain flag so Startup's drain threshold remains phase-neutral.
func (b *bbrCongestionControl) quantizeWindowAt(target uint64, mss int, probeHigh bool) uint64 {
	if mss < 1 {
		return 0
	}
	quantum := bbrSendQuantum(b.effectivePacingRate(), mss)
	if quantum < mss {
		quantum = mss
	}
	target += uint64(3 * quantum)
	segments := (target + uint64(mss) - 1) / uint64(mss)
	if segments&1 != 0 {
		segments++
	}
	target = segments * uint64(mss)
	if probeHigh {
		target += uint64(2 * mss)
	}
	minimum := uint64(bbrMinimumCongestionMSS * mss)
	if target < minimum {
		target = minimum
	}
	if target > uint64(tcpMaximumScaledWindow) {
		return uint64(tcpMaximumScaledWindow)
	}
	return target
}

// inflightTarget derives a quantized byte window from BDP and a gain.
func (b *bbrCongestionControl) inflightTarget(gain float64, mss int) uint64 {
	return b.quantizeWindow(b.modelWindow(gain, mss), mss)
}

// packetsInNetwork discounts bytes scheduled for future paced transmission.
// gain is captured before a state transition because Linux updates its stored
// gain only after finishing the model update for the ACK.
func (b *bbrCongestionControl) packetsInNetwork(inflight uint32, now time.Time, mss int, gain float64) uint32 {
	value := uint64(inflight)
	if gain > 1 {
		value += uint64(bbrSendQuantum(b.effectivePacingRate(), mss))
	}
	if now.Before(b.nextSend) && b.effectiveBandwidth() > 0 {
		delivered := uint64(b.effectiveBandwidth() * b.nextSend.Sub(now).Seconds())
		if delivered >= value {
			return 0
		}
		value -= delivered
	}
	if value > uint64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}

// effectiveBandwidth selects the policer estimate while long-term mode is active.
func (b *bbrCongestionControl) effectiveBandwidth() float64 {
	if b.longTermUseBandwidth {
		return b.longTermBandwidth
	}
	return b.bandwidth
}

// updateLongTermBandwidth implements Linux BBRv1's token-bucket policer model.
func (b *bbrCongestionControl) updateLongTermBandwidth(sample bbrRateSample) {
	if b.longTermUseBandwidth {
		if b.mode == bbrProbeBandwidth && b.roundStart {
			b.longTermRounds++
			if b.longTermRounds >= bbrLongTermUseRounds {
				b.resetLongTermBandwidth(sample.ackTime)
				b.resetProbeBandwidth(sample.ackTime)
			}
		}
		return
	}
	if !b.longTermSampling {
		if sample.losses == 0 {
			return
		}
		b.resetLongTermInterval(sample.ackTime)
		b.longTermSampling = true
	}
	if sample.locallyLimited() {
		b.resetLongTermBandwidth(sample.ackTime)
		return
	}
	if b.roundStart {
		b.longTermRounds++
	}
	if b.longTermRounds < bbrLongTermMinimumRounds {
		return
	}
	if b.longTermRounds > bbrLongTermMaximumRounds {
		b.resetLongTermBandwidth(sample.ackTime)
		return
	}
	if sample.losses == 0 {
		return
	}
	delivered := b.delivered - b.longTermLastDelivered
	lost := b.totalLost - b.longTermLastLost
	if delivered == 0 || float64(lost)/float64(delivered) < bbrLongTermLossRatio {
		return
	}
	interval := sample.ackTime.Sub(b.longTermLastStamp)
	if interval < time.Millisecond {
		return
	}
	rate := float64(delivered) / interval.Seconds()
	if b.longTermBandwidth != 0 {
		difference := math.Abs(rate - b.longTermBandwidth)
		if difference <= b.longTermBandwidth*bbrLongTermBandwidthRatio || difference <= bbrLongTermBandwidthDifference {
			b.longTermBandwidth = (b.longTermBandwidth + rate) / 2
			b.longTermUseBandwidth = true
			b.longTermRounds = 0
			return
		}
	}
	b.longTermBandwidth = rate
	b.resetLongTermInterval(sample.ackTime)
}

// resetLongTermInterval starts one policer measurement interval.
func (b *bbrCongestionControl) resetLongTermInterval(now time.Time) {
	b.longTermLastStamp = now
	b.longTermLastDelivered = b.delivered
	b.longTermLastLost = b.totalLost
	b.longTermRounds = 0
}

// resetLongTermBandwidth leaves policer mode and clears its samples.
func (b *bbrCongestionControl) resetLongTermBandwidth(now time.Time) {
	b.longTermBandwidth = 0
	b.longTermUseBandwidth = false
	b.longTermSampling = false
	b.resetLongTermInterval(now)
}

// undoRecovery applies Linux bbr_undo_cwnd without rewinding delivery
// accounting that newer per-transmission rate snapshots already reference.
func (b *bbrCongestionControl) undoRecovery(now time.Time) {
	b.fullBandwidth = 0
	b.fullRounds = 0
	b.recovery = false
	b.lossRecovery = false
	b.packetConservation = false
	b.resetLongTermBandwidth(now)
}

// noteLoss records bytes newly declared lost for the next rate sample.
func (b *bbrCongestionControl) noteLoss(bytes uint32) {
	b.totalLost += uint64(bytes)
}

// saveWindow remembers a usable cwnd before recovery or ProbeRTT reduction.
func (b *bbrCongestionControl) saveWindow(window uint32) {
	if !b.recovery && !b.lossRecovery && b.mode != bbrProbeRTT {
		b.priorWindow = window
		return
	}
	if window > b.priorWindow {
		b.priorWindow = window
	}
}

// markApplicationLimited records the delivery boundary that drains a sender bubble.
func (b *bbrCongestionControl) markApplicationLimited(flight uint32) {
	limit := b.delivered + uint64(flight)
	if limit == 0 {
		limit = 1
	}
	b.applicationLimitedUntil = limit
}

// markSchedulerLimited records a delivery boundary whose samples include a
// material userspace scheduling delay rather than a path limitation.
func (b *bbrCongestionControl) markSchedulerLimited(flight uint32) {
	limit := b.delivered + uint64(flight)
	if limit == 0 {
		limit = 1
	}
	if limit > b.schedulerLimitedUntil {
		b.schedulerLimitedUntil = limit
	}
	b.schedulerLimitedEvents++
}

// schedulerLimited reports whether new transmissions still belong to a
// scheduler-limited delivery interval.
func (b *bbrCongestionControl) schedulerLimited() bool {
	return b.schedulerLimitedUntil != 0
}

// snapshotSend captures delivery state for one original or retransmitted range.
func (b *bbrCongestionControl) snapshotSend(stamp monotonicStamp, packetsOut uint32) bbrRateSnapshot {
	compactStamp := bbrStampAt(stamp)
	if packetsOut == 0 {
		b.firstSent = compactStamp
		b.deliveredStamp = compactStamp
		b.nextSend = time.Time{}
		b.pacingWakeDeadline = time.Time{}
		b.pacingBurstRemaining = 0
		if b.applicationLimitedUntil != 0 {
			b.idleRestart = true
			if b.mode == bbrProbeBandwidth && b.bandwidth > 0 {
				b.pacingRate = b.effectiveBandwidth() * bbrPacingMargin
			}
		}
	}
	deliveredFlags := uint32(b.delivered) & bbrRateDeliveredMask
	if b.applicationLimitedUntil != 0 {
		deliveredFlags |= bbrRateApplicationLimited
	}
	return bbrRateSnapshot{firstSent: b.firstSent, deliveredStamp: b.deliveredStamp, deliveredFlags: deliveredFlags}
}

// onSend snapshots delivery state, handles Linux's idle ProbeRTT exit, and
// advances BBR's packet pacing clock.
func (b *bbrCongestionControl) onSend(bytes, mss int, now time.Time, stamp monotonicStamp, packetsOut, window uint32) (bbrRateSnapshot, uint32) {
	snapshot := b.snapshotSend(stamp, packetsOut)
	if packetsOut == 0 && b.idleRestart {
		// Mirror Linux CA_EVENT_TX_START. The first returning ACK may rotate this
		// epoch under the normal below-expected-rate rule.
		b.ackEpochStamp = now
		b.ackEpochBytes = 0
	}
	if packetsOut == 0 && b.idleRestart && b.mode == bbrProbeRTT && !b.probeDone.IsZero() && !now.Before(b.probeDone) {
		b.minimumRTTStamp = now
		if window < b.priorWindow {
			window = b.priorWindow
		}
		b.resetMode(now)
	}
	b.consumePacingBurst(bytes)
	b.advancePacing(bytes, mss, now)
	return snapshot, window
}

// locallyLimited reports samples that cannot safely lower the path model.
func (s bbrRateSample) locallyLimited() bool {
	return s.applicationLimited || s.schedulerLimited
}

// resetMode returns from ProbeRTT according to whether Startup filled the pipe.
func (b *bbrCongestionControl) resetMode(now time.Time) {
	if b.fullBandwidthReached {
		b.resetProbeBandwidth(now)
	} else {
		b.mode = bbrStartup
	}
}

// resetProbeBandwidth starts Linux's randomized steady-state gain cycle.
func (b *bbrCongestionControl) resetProbeBandwidth(now time.Time) {
	b.mode = bbrProbeBandwidth
	b.cycleIndex = bbrInitialCycle(now)
	b.cycleStamp = b.deliveredStamp
}

// bbrInitialCycle mirrors Linux's randomized initial ProbeBW phase.
func bbrInitialCycle(now time.Time) int {
	const choices = byte(len(bbrProbeBandwidthGains) - 1)
	var value [1]byte
	for {
		if _, err := rand.Read(value[:]); err != nil {
			value[0] = byte(uint64(now.UnixNano()) % uint64(choices))
			break
		}
		// Discard the incomplete final interval to keep all seven Linux phases
		// equally likely.
		if value[0] < ^byte(0)-(^byte(0)%choices) {
			value[0] %= choices
			break
		}
	}
	return (len(bbrProbeBandwidthGains) - int(value[0])) % len(bbrProbeBandwidthGains)
}

// pacingGain returns the gain for BBR's current phase.
func (b *bbrCongestionControl) pacingGain() float64 {
	switch b.mode {
	case bbrStartup:
		return bbrStartupPacingGain
	case bbrDrain:
		return bbrDrainPacingGain
	case bbrProbeBandwidth:
		if b.longTermUseBandwidth {
			return 1
		}
		return bbrProbeBandwidthGains[b.cycleIndex]
	default:
		return 1
	}
}

// congestionWindowGain returns Linux BBRv1's mode-specific cwnd gain.
func (b *bbrCongestionControl) congestionWindowGain() float64 {
	if b.mode == bbrStartup || b.mode == bbrDrain {
		return bbrStartupPacingGain
	}
	if b.mode == bbrProbeRTT {
		return 1
	}
	return bbrCongestionWindowGain
}

// initializePacingRate applies Linux's high-gain initial-window estimate. A
// connection without an RTT sample uses the kernel's nominal one millisecond
// RTT but remains eligible for reinitialization from its first real sample.
func (b *bbrCongestionControl) initializePacingRate(window uint32, smoothedRTT time.Duration) {
	roundTrip := smoothedRTT
	if roundTrip <= 0 {
		roundTrip = time.Millisecond
	} else {
		b.hasSeenRTT = true
	}
	b.pacingRate = float64(window) / roundTrip.Seconds() * bbrStartupPacingGain * bbrPacingMargin
}

// setPacingRate applies the mode gain and Linux's one-percent pacing margin.
// Before Startup fills the pipe, BBR never lowers an established pacing rate.
func (b *bbrCongestionControl) setPacingRate(window uint32, smoothedRTT time.Duration) {
	if !b.hasSeenRTT && smoothedRTT > 0 {
		b.initializePacingRate(window, smoothedRTT)
	}
	bw := b.effectiveBandwidth()
	if bw <= 0 {
		return
	}
	rate := bw * b.pacingGain() * bbrPacingMargin
	if b.pacingRate == 0 || b.fullBandwidthReached || rate > b.pacingRate {
		b.pacingRate = rate
	}
}

// pacingDelay reports how long the sender should wait before new data.
func (b *bbrCongestionControl) pacingDelay(now time.Time, bytes, mss int, flight uint32) time.Duration {
	rate := b.effectivePacingRate()
	if bytes <= 0 || rate <= 0 {
		return 0
	}
	b.consumePacingWake(now, flight)
	if b.pacingBurstRemaining >= bytes {
		return 0
	}
	budget := bbrUserspacePacingBudget(rate, mss)
	if !b.nextSend.IsZero() && now.Before(b.nextSend) {
		allowance := pacingDuration(budget, rate)
		deadline := b.nextSend.Add(-allowance)
		if now.Before(deadline) {
			b.pacingWakeDeadline = deadline
			return deadline.Sub(now)
		}
	}
	if b.nextSend.IsZero() {
		b.nextSend = now
	}
	// Linux fq releases one BBR send quantum at an EDT. A late actor retains at
	// most one send quantum of debt in advancePacingAt. Already overdue groups
	// may follow without an artificial actor yield; future transmission can
	// never be released more than one bounded userspace group early.
	b.pacingBurstRemaining = budget
	return 0
}

// consumePacingWake clears one requested wake and records material local
// lateness. The actor also calls it when a peer or congestion window prevents
// pacingDelay from being reached after the timer fires.
func (b *bbrCongestionControl) consumePacingWake(now time.Time, flight uint32) {
	if b.pacingWakeDeadline.IsZero() {
		return
	}
	deadline := b.pacingWakeDeadline
	b.pacingWakeDeadline = time.Time{}
	if flight != 0 && now.Sub(deadline) > tcpUserspaceSchedulingTolerance {
		b.markSchedulerLimited(flight)
	}
}

// effectivePacingRate applies the socket pacing ceiling while preserving the
// unconstrained BBR model in pacingRate.
func (b *bbrCongestionControl) effectivePacingRate() float64 {
	rate := b.pacingRate
	if b.maximumPacingRate != 0 && rate > float64(b.maximumPacingRate) {
		return float64(b.maximumPacingRate)
	}
	return rate
}

// consumePacingBurst accounts bytes released by the current actor wake.
func (b *bbrCongestionControl) consumePacingBurst(bytes int) {
	if bytes <= 0 || b.pacingBurstRemaining <= 0 {
		return
	}
	b.pacingBurstRemaining -= bytes
	if b.pacingBurstRemaining < 0 {
		b.pacingBurstRemaining = 0
	}
}

// advancePacing moves BBR's new-data transmission clock with bounded debt.
func (b *bbrCongestionControl) advancePacing(bytes, mss int, now time.Time) {
	b.advancePacingAt(bytes, mss, now, true)
}

// advanceRetransmissionPacing discards stale debt after loss or an RTO.
func (b *bbrCongestionControl) advanceRetransmissionPacing(bytes, mss int, now time.Time) {
	b.pacingWakeDeadline = time.Time{}
	b.consumePacingBurst(bytes)
	b.advancePacingAt(bytes, mss, now, false)
}

// advancePacingAt advances the userspace pacing clock.
func (b *bbrCongestionControl) advancePacingAt(bytes, mss int, now time.Time, catchUp bool) {
	rate := b.effectivePacingRate()
	if bytes <= 0 || rate <= 0 {
		return
	}
	delay := pacingDuration(bytes, rate)
	maximumDebt := bbrSendQuantumDuration(rate, mss)
	base := pacingScheduleBase(b.nextSend, now, maximumDebt, catchUp)
	b.nextSend = base.Add(delay)
}
