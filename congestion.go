package mipstack

import (
	"math"
	"time"
)

const (
	// hyStartMinimumRTTThreshold is the RFC 9406 lower delay threshold.
	hyStartMinimumRTTThreshold = 4 * time.Millisecond
	// hyStartMaximumRTTThreshold is the RFC 9406 upper delay threshold.
	hyStartMaximumRTTThreshold = 16 * time.Millisecond
	// hyStartRTTDivisor scales the measured minimum RTT into a delay threshold.
	hyStartRTTDivisor = 8
	// hyStartMinimumRTTSamples is the sample floor for a round decision.
	hyStartMinimumRTTSamples = 8
	// hyStartCSSGrowthDivisor reduces growth during Conservative Slow Start.
	hyStartCSSGrowthDivisor = 4
	// hyStartCSSRounds bounds consecutive Conservative Slow Start rounds.
	hyStartCSSRounds = 5
	// tcpPacingInitialBurst matches Linux fq's unpaced first ten segments.
	tcpPacingInitialBurst = 10
	// tcpUserspaceSchedulingTolerance avoids classifying ordinary timer and
	// actor jitter as a host-scheduler limitation.
	tcpUserspaceSchedulingTolerance = 25 * time.Microsecond
	// tcpUserspacePacingBatch amortizes per-segment timer wakes for Reno and
	// CUBIC while preserving their long-term window-derived pacing rate.
	tcpUserspacePacingBatch = 500 * time.Microsecond
)

// tcpCongestionController adapts the selected implementation to TCP's common
// pacing, recovery, and delivery-sampling machinery.
type tcpCongestionController struct {
	factory            *CongestionControlFactory
	algorithm          CongestionController
	features           CongestionControlFeatures
	sendBufferMultiple uint32
	initialized        bool
	delivery           tcpDeliveryRateEstimator
	state              CongestionState
	event              CongestionEvent
	pacingNext         time.Time
	pacingSegments     uint64
	pacingRate         float64
	maximumPacingRate  uint64
	packetState        uint64
}

// setMaximumPacingRate updates the socket policy without discarding the
// congestion controller's unconstrained model rate. It reports a change so
// the connection actor can cancel a timer based on the former policy.
func (c *tcpCongestionController) setMaximumPacingRate(rate uint64) bool {
	if c.maximumPacingRate == rate {
		return false
	}
	c.pacingNext = time.Time{}
	c.maximumPacingRate = rate
	c.state.MaximumPacingRate = rate
	if c.customPacing() && c.initialized {
		event := c.prepareEvent(CongestionEventPacing, time.Now())
		event.Pacing = CongestionPacing{Operation: CongestionPacingPolicyChanged}
		c.handleEvent()
	}
	return true
}

// limitPacingRate applies the socket's sk_max_pacing_rate-style policy.
func (c *tcpCongestionController) limitPacingRate(rate float64) float64 {
	if c.maximumPacingRate != 0 && rate > float64(c.maximumPacingRate) {
		return float64(c.maximumPacingRate)
	}
	return rate
}

// congestionRateValue converts an internal byte rate to its diagnostic value.
func congestionRateValue(rate float64) uint64 {
	if rate <= 0 || math.IsNaN(rate) {
		return 0
	}
	if rate >= float64(^uint64(0)) || math.IsInf(rate, 1) {
		return ^uint64(0)
	}
	return uint64(rate)
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

// newTCPCongestionController constructs one per-connection controller from the
// immutable registered factory. Invalid internal input retains CUBIC's
// historical fallback; public configuration is validated before this point.
func newTCPCongestionController(algorithm CongestionControl) tcpCongestionController {
	factory, exists := registeredCongestionControlFactory(algorithm)
	if !exists {
		factory, _ = registeredCongestionControlFactory(CongestionControlCUBIC)
	}
	return newTCPCongestionControllerFromFactory(factory, CongestionControlContext{})
}

// newTCPCongestionControllerFromDefinition constructs an adapter from a
// definition. Tests use it without mutating the registry.
func newTCPCongestionControllerFromDefinition(definition CongestionControlDefinition) tcpCongestionController {
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		panic(err)
	}
	return newTCPCongestionControllerFromFactory(factory, CongestionControlContext{})
}

// newTCPCongestionControllerFromFactory constructs an adapter and one
// connection-private implementation from an immutable factory.
func newTCPCongestionControllerFromFactory(factory *CongestionControlFactory, context CongestionControlContext) tcpCongestionController {
	if factory == nil {
		factory, _ = registeredCongestionControlFactory(CongestionControlCUBIC)
	}
	implementation := factory.definition.New(context)
	if implementation == nil {
		panic("mipstack: congestion control factory returned nil")
	}
	controller := tcpCongestionController{
		factory:            factory,
		algorithm:          implementation,
		features:           factory.definition.Features,
		sendBufferMultiple: factory.definition.SendBufferMultiplier,
	}
	if controller.usesDeliveryRate() {
		// Match Linux's initial app-limited bubble: the first rate sample may
		// raise an established model but cannot lower it.
		controller.delivery.applicationLimitedUntil = 1
	}
	return controller
}

// release delivers the final serialized callback before this controller is
// replaced or its owning connection actor exits.
func (c *tcpCongestionController) release(now time.Time, window, threshold, flight uint32, mss int, smoothedRTT, minimumRTT time.Duration) {
	if c.algorithm == nil || !c.initialized {
		return
	}
	c.syncTransportState(window, threshold, flight, mss, smoothedRTT)
	c.state.MinimumRTT = minimumRTT
	c.prepareEvent(CongestionEventRelease, now)
	c.handleEvent()
	c.initialized = false
}

// prepareEvent attaches the latest common state without clearing unrelated
// payloads. Callers replace the complete payload associated with eventType.
func (c *tcpCongestionController) prepareEvent(eventType CongestionEventType, now time.Time) *CongestionEvent {
	c.event.Type = eventType
	c.event.Time = now
	c.event.State = &c.state
	c.event.RateSample = nil
	c.event.MarkApplicationLimited = false
	c.event.PacketState = 0
	c.event.Pacing.MarkSchedulerLimited = false
	return &c.event
}

// handleEvent dispatches one event. Event storage is invalid as soon as this
// method returns; mutations through State already target persistent storage.
func (c *tcpCongestionController) handleEvent() {
	eventType := c.event.Type
	pacingOperation := c.event.Pacing.Operation
	c.algorithm.HandleCongestionEvent(&c.event)
	markApplicationLimited := c.event.MarkApplicationLimited
	markSchedulerLimited := c.event.Pacing.MarkSchedulerLimited
	c.event.State = nil
	c.event.RateSample = nil
	deliveryStateChanged := false
	if markApplicationLimited && eventType == CongestionEventACK && c.usesDeliveryRate() {
		c.delivery.markApplicationLimited(c.state.BytesInFlight)
		deliveryStateChanged = true
	}
	if markSchedulerLimited && eventType == CongestionEventPacing &&
		(pacingOperation == CongestionPacingQuery || pacingOperation == CongestionPacingWake) && c.usesDeliveryRate() {
		c.delivery.markSchedulerLimited(c.state.BytesInFlight)
		deliveryStateChanged = true
	}
	if deliveryStateChanged {
		c.syncDeliveryState()
	}
}

// syncTransportState updates the common snapshot before an event.
func (c *tcpCongestionController) syncTransportState(window, slowStartThreshold, flight uint32, mss int, smoothedRTT time.Duration) {
	c.state.CongestionWindow = window
	c.state.SlowStartThreshold = slowStartThreshold
	c.state.BytesInFlight = flight
	c.state.MaximumSegmentSize = mss
	c.state.SmoothedRTT = smoothedRTT
	c.state.MaximumPacingRate = c.maximumPacingRate
}

// syncDeliveryState publishes transport-owned rate-accounting state.
func (c *tcpCongestionController) syncDeliveryState() {
	if !c.usesDeliveryRate() && !c.usesLossEvents() {
		return
	}
	c.state.DeliveredBytes = c.delivery.delivered
	c.state.LostBytes = c.delivery.totalLost
	c.state.ApplicationLimited = c.delivery.applicationLimitedUntil != 0
	c.state.SchedulerLimited = c.delivery.schedulerLimited()
	c.state.SchedulerLimitedEvents = c.delivery.schedulerLimitedEvents
}

// setCongestionPhase publishes one slow-path phase transition. Initialization
// seeds Open directly so it remains the first controller callback.
func (c *tcpCongestionController) setCongestionPhase(phase CongestionPhase, now time.Time) {
	if c.state.Phase == phase {
		return
	}
	previous := c.state.Phase
	c.state.Phase = phase
	if !c.initialized {
		return
	}
	event := c.prepareEvent(CongestionEventStateChanged, now)
	event.PreviousPhase = previous
	c.handleEvent()
}

// onCongestion applies one loss congestion signal.
func (c *tcpCongestionController) onCongestion(window, flight, slowStartThreshold uint32, mss int, now time.Time) (threshold, congestionWindow uint32) {
	c.syncTransportState(window, slowStartThreshold, flight, mss, c.state.SmoothedRTT)
	c.setCongestionPhase(CongestionPhaseRecovery, now)
	c.prepareEvent(CongestionEventLoss, now)
	c.handleEvent()
	return c.state.SlowStartThreshold, c.state.CongestionWindow
}

// onECN computes both transport values changed by an ECN congestion event.
// Reno and CUBIC reduce cwnd to their new threshold; Linux BBR leaves its
// model-controlled cwnd and infinite threshold intact while entering CWR.
func (c *tcpCongestionController) onECN(window, flight, slowStartThreshold uint32, mss int, now time.Time) (threshold, congestionWindow uint32) {
	c.syncTransportState(window, slowStartThreshold, flight, mss, c.state.SmoothedRTT)
	c.setCongestionPhase(CongestionPhaseCWR, now)
	c.prepareEvent(CongestionEventECN, now)
	c.handleEvent()
	return c.state.SlowStartThreshold, c.state.CongestionWindow
}

// onTimeout applies the algorithm's retransmission-timeout response. CUBIC
// starts its next congestion-avoidance epoch at K=0 as required by RFC 9438;
// fast loss and ECN continue through onCongestion and onECN respectively.
func (c *tcpCongestionController) onTimeout(window, flight, slowStartThreshold uint32, mss int, now time.Time) uint32 {
	c.syncTransportState(window, slowStartThreshold, flight, mss, c.state.SmoothedRTT)
	c.setCongestionPhase(CongestionPhaseLoss, now)
	c.prepareEvent(CongestionEventTimeout, now)
	c.handleEvent()
	return c.state.SlowStartThreshold
}

// onACK advances slow start or the selected congestion-avoidance model.
func (c *tcpCongestionController) onACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight uint32, slowStart bool) uint32 {
	threshold := window
	if slowStart {
		threshold = ^uint32(0)
	}
	if c.usesDeliveryRate() {
		priorDeliveredTotal := c.delivery.delivered
		priorDelivered := uint32(priorDeliveredTotal) & tcpDeliveryDeliveredMask
		c.delivery.delivered += uint64(acknowledged)
		if acknowledged != 0 {
			c.delivery.deliveredStamp = tcpDeliveryTimestampAt(monotonicStamp(now.UnixNano()) + 1)
		}
		c.syncDeliveryState()
		c.state.SlowStartThreshold = threshold
		c.state.ApplicationLimited = !congestionWindowLimited(window, flight, mss)
		sample := tcpDeliveryRateSample{
			priorDelivered:      priorDelivered,
			priorDeliveredTotal: priorDeliveredTotal,
			delivered:           acknowledged,
			acked:               acknowledged,
			priorInFlight:       flight,
			inFlight:            flight,
			interval:            smoothedRTT,
			rtt:                 sampleRTT,
			smoothedRTT:         smoothedRTT,
			ackTime:             now,
			ackStamp:            c.delivery.deliveredStamp,
			applicationLimited:  c.state.ApplicationLimited,
			valid:               smoothedRTT > 0,
		}
		if acknowledged < sample.inFlight {
			sample.inFlight -= acknowledged
		} else {
			sample.inFlight = 0
		}
		window, updatedThreshold := c.onDeliveryRateSample(window, threshold, mss, 0, &sample)
		if updatedThreshold != 0 {
			c.state.SlowStartThreshold = updatedThreshold
		}
		return window
	}
	window, _ = c.onACKWithThreshold(window, acknowledged, 0, mss, now, smoothedRTT, c.state.MinimumRTT, sampleRTT, flight, threshold, !congestionWindowLimited(window, flight, mss))
	return window
}

// onACKWithThreshold splits one cumulative ACK at the slow-start boundary,
// matching Linux tcp_slow_start's returned congestion-avoidance credit.
func (c *tcpCongestionController) onACKWithThreshold(window, acknowledged, acknowledgementNumber uint32, mss int, now time.Time, smoothedRTT, minimumRTT, sampleRTT time.Duration, flight, slowStartThreshold uint32, applicationLimited bool) (uint32, uint32) {
	if window == 0 || acknowledged == 0 || mss < 1 {
		return window, slowStartThreshold
	}
	c.syncTransportState(window, slowStartThreshold, flight, mss, smoothedRTT)
	c.state.MinimumRTT = minimumRTT
	c.state.ApplicationLimited = applicationLimited
	event := c.prepareEvent(CongestionEventACK, now)
	event.Acknowledged = acknowledged
	event.AcknowledgementNumber = acknowledgementNumber
	event.SampleRTT = sampleRTT
	event.RateSample = nil
	c.handleEvent()
	return c.state.CongestionWindow, c.state.SlowStartThreshold
}

// finishDeliveryRateSample converts delivery snapshots selected during cumulative
// ACK and SACK processing into one Linux-style rate sample.
func (c *tcpCongestionController) finishDeliveryRateSample(sample *tcpDeliveryRateSample, acknowledged uint32, priorInFlight, inFlight uint32, now time.Time, nowStamp monotonicStamp, minimumRTT, smoothedRTT, sampleRTT time.Duration) {
	if !c.usesDeliveryRate() {
		return
	}
	c.delivery.finishRateSample(sample, acknowledged, priorInFlight, inFlight, now, nowStamp, minimumRTT, smoothedRTT, sampleRTT)
	c.state.MinimumRTT = minimumRTT
	c.state.SmoothedRTT = smoothedRTT
	c.syncDeliveryState()
}

// onDeliveryRateSample applies one completed delivery sample to controller
// state. A nonzero threshold replaces TCP's current ssthresh.
func (c *tcpCongestionController) onDeliveryRateSample(window, slowStartThreshold uint32, mss int, acknowledgementNumber uint32, sample *tcpDeliveryRateSample) (uint32, uint32) {
	if !c.usesDeliveryRate() {
		return window, 0
	}
	c.syncTransportState(window, slowStartThreshold, sample.inFlight, mss, sample.smoothedRTT)
	event := c.prepareEvent(CongestionEventACK, sample.ackTime)
	event.Acknowledged = sample.acked
	event.AcknowledgementNumber = acknowledgementNumber
	event.SampleRTT = sample.rtt
	event.RateSample = sample
	c.handleEvent()
	threshold := c.state.SlowStartThreshold
	if threshold == slowStartThreshold {
		threshold = 0
	}
	return c.state.CongestionWindow, threshold
}

// markApplicationLimited records a sender bubble for future delivery snapshots.
func (c *tcpCongestionController) markApplicationLimited(flight uint32) {
	if c.usesDeliveryRate() {
		c.delivery.markApplicationLimited(flight)
		c.syncDeliveryState()
	}
}

// noteLoss records newly declared lost bytes. duringACK retains them for the
// rate sample being assembled; timer-driven recovery has already consumed the
// event and must not report it again on the next ACK.
func (c *tcpCongestionController) noteLoss(bytes uint32, duringACK bool) {
	if c.usesDeliveryRate() || c.usesLossEvents() {
		c.delivery.recordLoss(bytes, duringACK)
		c.syncDeliveryState()
	}
}

// notePacketLoss records one newly proven transmission generation and, when
// requested, returns the controller-owned state captured for that generation.
// The event follows delivery accounting so State.LostBytes includes this loss.
func (c *tcpCongestionController) notePacketLoss(segment *sentTCPSegment, bytes uint32, duringACK bool, now time.Time, window, slowStartThreshold, flight uint32, mss int, smoothedRTT time.Duration) {
	if bytes == 0 {
		return
	}
	c.noteLoss(bytes, duringACK)
	if !c.usesLossEvents() {
		return
	}
	c.syncTransportState(window, slowStartThreshold, flight, mss, smoothedRTT)
	event := c.prepareEvent(CongestionEventPacketLost, now)
	event.PacketBytes = int(bytes)
	if segment != nil {
		event.PacketState = segment.congestionPacketState
	}
	c.handleEvent()
}

// onTailLossProbeRecovered reports Linux CA_EVENT_TLP_RECOVERY after a
// retransmitted tail probe is proven to have repaired data loss.
func (c *tcpCongestionController) onTailLossProbeRecovered(now time.Time, packetBytes int, packetState uint64, window, slowStartThreshold, flight uint32, mss int, smoothedRTT time.Duration) {
	if !c.usesLossEvents() {
		return
	}
	c.syncTransportState(window, slowStartThreshold, flight, mss, smoothedRTT)
	event := c.prepareEvent(CongestionEventTailLossProbeRecovered, now)
	event.PacketBytes = packetBytes
	event.PacketState = packetState
	c.handleEvent()
}

// congestionWindowLimited mirrors Linux's packet-granularity allowance: a
// sender that is less than one MSS below cwnd is still congestion-limited.
func congestionWindowLimited(window, flight uint32, mss int) bool {
	if flight >= window {
		return true
	}
	return window-flight <= uint32(mss)
}

// pacingDelay returns the remaining userspace pacing interval. Delivery-rate
// controllers may own their rate; window controllers use Linux's cwnd/SRTT
// pacing formula.
func (c *tcpCongestionController) pacingDelay(now time.Time, bytes int, window, flight uint32, mss int, smoothedRTT time.Duration, slowStartThreshold uint32) time.Duration {
	if c.customPacing() {
		c.state.CongestionWindow = window
		c.state.BytesInFlight = flight
		event := c.prepareEvent(CongestionEventPacing, now)
		event.Pacing = CongestionPacing{Operation: CongestionPacingQuery, Bytes: bytes, TransmittedSegments: c.pacingSegments}
		c.handleEvent()
		return event.Pacing.Delay
	}
	if c.pacingSegments < tcpPacingInitialBurst || smoothedRTT <= 0 || c.pacingNext.IsZero() || !now.Before(c.pacingNext) {
		return 0
	}
	return pacingTimerDelay(c.pacingNext.Sub(now), tcpUserspacePacingBatch)
}

// onPacingWake accounts an actual actor timer wake even when another socket
// limit prevents the following send attempt from reaching pacingDelay.
func (c *tcpCongestionController) onPacingWake(now time.Time, flight uint32) {
	if c.customPacing() {
		c.state.BytesInFlight = flight
		event := c.prepareEvent(CongestionEventPacing, now)
		event.Pacing = CongestionPacing{Operation: CongestionPacingWake}
		c.handleEvent()
	}
}

// cancelPacingWake discards a controller pacing request when the actor
// repurposes its logical pacing timer for another policy such as an ECN hold.
func (c *tcpCongestionController) cancelPacingWake() {
	if c.customPacing() {
		event := c.prepareEvent(CongestionEventPacing, time.Now())
		event.Pacing = CongestionPacing{Operation: CongestionPacingCancel}
		c.handleEvent()
	}
}

// onDataSend advances the selected controller after a first transmission.
// Delivery-rate implementations also return the per-range snapshot retained
// by TCP until cumulative ACK or SACK processing selects it.
func (c *tcpCongestionController) onDataSend(bytes, mss int, now time.Time, stamp monotonicStamp, packetsOut, window, flight uint32, smoothedRTT time.Duration, slowStartThreshold uint32) (tcpDeliverySnapshot, uint32) {
	snapshot := tcpDeliverySnapshot{}
	c.packetState = 0
	if c.usesDeliveryRate() {
		snapshot, window = c.delivery.onDeliveryDataSent(bytes, mss, now, stamp, packetsOut, window)
	}
	if c.usesTransmissionEvents() {
		c.state.CongestionWindow = window
		c.state.BytesInFlight = flight
		event := c.prepareEvent(CongestionEventPacketSent, now)
		event.PacketBytes = bytes
		event.OutstandingBytes = packetsOut
		c.handleEvent()
		c.packetState = event.PacketState
		window = c.state.CongestionWindow
	}
	if c.customPacing() {
		c.pacingSegments++
		return snapshot, window
	}
	c.advanceWindowPacing(bytes, mss, now, window, flight, smoothedRTT, slowStartThreshold, true)
	return snapshot, window
}

// onRetransmit advances only the pacing clock and delivery snapshot. Loss
// recovery must not treat a retransmission as new application data or a new
// congestion-avoidance epoch.
func (c *tcpCongestionController) onRetransmit(bytes, mss int, now time.Time, stamp monotonicStamp, window, flight, packetsOut uint32, smoothedRTT time.Duration, slowStartThreshold uint32) tcpDeliverySnapshot {
	snapshot := tcpDeliverySnapshot{}
	c.packetState = 0
	if c.usesDeliveryRate() {
		snapshot = c.delivery.onDeliveryRetransmit(bytes, mss, now, stamp, packetsOut)
	}
	if c.usesTransmissionEvents() {
		c.state.CongestionWindow = window
		c.state.BytesInFlight = flight
		event := c.prepareEvent(CongestionEventPacketRetransmitted, now)
		event.PacketBytes = bytes
		event.OutstandingBytes = packetsOut
		c.handleEvent()
		c.packetState = event.PacketState
	}
	if c.customPacing() {
		return snapshot
	}
	c.advanceWindowPacing(bytes, mss, now, window, flight, smoothedRTT, slowStartThreshold, false)
	return snapshot
}

// transmissionState returns the opaque state produced by the immediately
// preceding original-transmission or retransmission callback.
func (c *tcpCongestionController) transmissionState() uint64 { return c.packetState }

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
	if c.state.UsePacingRate {
		modelRate = float64(c.state.PacingRate)
	}
	if modelRate <= 0 || math.IsInf(modelRate, 0) || math.IsNaN(modelRate) {
		return
	}
	c.pacingRate = modelRate
	if !c.state.UsePacingRate {
		c.state.PacingRate = congestionRateValue(modelRate)
	}
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

// onMTUChange resets packet-size-dependent epochs without discarding an
// algorithm's packet-size-independent path model.
func (c *tcpCongestionController) onMTUChange(window, slowStartThreshold uint32, mss int) {
	c.pacingNext = time.Time{}
	previousMSS := c.state.MaximumSegmentSize
	c.syncTransportState(window, slowStartThreshold, c.state.BytesInFlight, mss, c.state.SmoothedRTT)
	event := c.prepareEvent(CongestionEventMTUChanged, time.Now())
	event.PreviousMaximumSegmentSize = previousMSS
	c.handleEvent()
}

// algorithmName reports the selected public algorithm identifier.
func (c *tcpCongestionController) algorithmName() CongestionControl {
	return c.factory.Name()
}

// usesDeliveryRate reports whether per-transmission delivery sampling is active.
func (c *tcpCongestionController) usesDeliveryRate() bool {
	return c.features&CongestionControlFeatureDeliveryRate != 0
}

// customPacing reports whether the algorithm replaces the common window pacer.
func (c *tcpCongestionController) customPacing() bool {
	return c.features&CongestionControlFeatureCustomPacing != 0
}

// usesTransmissionEvents reports whether the controller observes sends.
func (c *tcpCongestionController) usesTransmissionEvents() bool {
	return c.features&CongestionControlFeatureTransmissionEvents != 0
}

// usesLossEvents reports whether per-generation losses must be dispatched.
func (c *tcpCongestionController) usesLossEvents() bool {
	return c.features&CongestionControlFeatureLossEvents != 0
}

// customRecovery reports whether the controller overrides RFC recovery windows.
func (c *tcpCongestionController) customRecovery() bool {
	return c.features&CongestionControlFeatureCustomRecovery != 0
}

// initialize seeds optional delivery and pacing models from the connection's
// handshake observations.
func (c *tcpCongestionController) initialize(now time.Time, minimumRTT, smoothedRTT time.Duration, window, slowStartThreshold uint32, mss int, stamp monotonicStamp) (uint32, uint32) {
	if c.usesDeliveryRate() {
		c.delivery.initializeDelivery(now, minimumRTT, stamp)
	}
	c.state.CongestionWindow = window
	c.state.SlowStartThreshold = slowStartThreshold
	c.state.MaximumSegmentSize = mss
	c.state.MinimumRTT = minimumRTT
	c.state.SmoothedRTT = smoothedRTT
	c.state.MaximumPacingRate = c.maximumPacingRate
	c.state.Phase = CongestionPhaseOpen
	c.syncDeliveryState()
	c.prepareEvent(CongestionEventInitialize, now)
	c.handleEvent()
	c.initialized = true
	return c.state.CongestionWindow, c.state.SlowStartThreshold
}

// snapshotSend captures current delivery state for a retransmitted range.
func (c *tcpCongestionController) snapshotSend(stamp monotonicStamp, packetsOut uint32) tcpDeliverySnapshot {
	if !c.usesDeliveryRate() {
		return tcpDeliverySnapshot{}
	}
	return c.delivery.snapshotSend(stamp, packetsOut)
}

// schedulerLimited reports whether new delivery snapshots include host delay.
func (c *tcpCongestionController) schedulerLimited() bool {
	return c.usesDeliveryRate() && c.delivery.schedulerLimited()
}

// sendBufferMultiplier reports an algorithm-requested multiple of cwnd used
// for automatic send-buffer expansion. Zero leaves ordinary tuning in charge.
func (c *tcpCongestionController) sendBufferMultiplier() uint32 {
	return c.sendBufferMultiple
}

// checkpointRecovery asks the algorithm to retain any private state required
// to undo the following recoverable congestion episode.
func (c *tcpCongestionController) checkpointRecovery(now time.Time, window, threshold, flight uint32, mss int) {
	c.syncTransportState(window, threshold, flight, mss, c.state.SmoothedRTT)
	event := c.prepareEvent(CongestionEventRecovery, now)
	event.Recovery.Stage = CongestionRecoveryCheckpoint
	c.handleEvent()
}

// undoRecovery reports a congestion episode proven spurious after synchronizing
// the transport state that will be restored.
func (c *tcpCongestionController) undoRecovery(now time.Time, window, threshold, flight uint32, mss int) {
	c.syncTransportState(window, threshold, flight, mss, c.state.SmoothedRTT)
	event := c.prepareEvent(CongestionEventRecovery, now)
	event.Recovery.Stage = CongestionRecoveryUndo
	c.handleEvent()
	c.setCongestionPhase(CongestionPhaseOpen, now)
}

// recoveryFlight selects the flight estimate used to enter recovery.
func (c *tcpCongestionController) recoveryFlight(now time.Time, ordinary, lossBased uint32) uint32 {
	if !c.customRecovery() {
		return lossBased
	}
	c.state.BytesInFlight = ordinary
	event := c.prepareEvent(CongestionEventRecovery, now)
	event.Recovery = CongestionRecovery{
		Stage:          CongestionRecoverySelectFlight,
		OrdinaryFlight: ordinary,
		LossFlight:     lossBased,
		Flight:         lossBased,
	}
	c.handleEvent()
	return event.Recovery.Flight
}

// recoveryWindow selects the initial fast-recovery congestion window.
func (c *tcpCongestionController) recoveryWindow(now time.Time, current, flight, threshold uint32, mss int, sack bool) uint32 {
	window := threshold
	if !sack {
		window = growCongestionWindow(threshold, uint32(3*mss))
	}
	c.syncTransportState(window, threshold, flight, mss, c.state.SmoothedRTT)
	c.setCongestionPhase(CongestionPhaseRecovery, now)
	if !c.customRecovery() {
		return window
	}
	event := c.prepareEvent(CongestionEventRecovery, now)
	event.Recovery = CongestionRecovery{Stage: CongestionRecoveryEnter, SACK: sack, Flight: flight, PreviousWindow: current, ProposedWindow: window}
	c.handleEvent()
	return c.state.CongestionWindow
}

// applyPRRWindow applies or declines TCP's proposed PRR window.
func (c *tcpCongestionController) applyPRRWindow(now time.Time, current, proposed, flight uint32) uint32 {
	if !c.customRecovery() {
		return proposed
	}
	c.state.CongestionWindow = proposed
	c.state.BytesInFlight = flight
	event := c.prepareEvent(CongestionEventRecovery, now)
	event.Recovery = CongestionRecovery{Stage: CongestionRecoveryPRR, SACK: true, Flight: flight, PreviousWindow: current, ProposedWindow: proposed}
	c.handleEvent()
	return c.state.CongestionWindow
}

// exitRecoveryWindow selects cwnd after the recovery point is acknowledged.
func (c *tcpCongestionController) exitRecoveryWindow(now time.Time, current, threshold, flight uint32, sack bool) uint32 {
	c.state.CongestionWindow = threshold
	c.state.SlowStartThreshold = threshold
	c.state.BytesInFlight = flight
	if !c.customRecovery() {
		c.setCongestionPhase(CongestionPhaseOpen, now)
		return threshold
	}
	event := c.prepareEvent(CongestionEventRecovery, now)
	event.Recovery = CongestionRecovery{Stage: CongestionRecoveryExit, SACK: sack, Flight: flight, PreviousWindow: current, ProposedWindow: threshold}
	c.handleEvent()
	window := c.state.CongestionWindow
	c.setCongestionPhase(CongestionPhaseOpen, event.Time)
	return window
}

// partialACKWindow handles a NewReno partial ACK during fast recovery.
func (c *tcpCongestionController) partialACKWindow(now time.Time, current, acknowledged, flight uint32, mss int) uint32 {
	window := newRenoPartialACKWindow(current, acknowledged, mss)
	if !c.customRecovery() {
		return window
	}
	c.state.CongestionWindow = window
	c.state.BytesInFlight = flight
	c.state.MaximumSegmentSize = mss
	event := c.prepareEvent(CongestionEventRecovery, now)
	event.Recovery = CongestionRecovery{Stage: CongestionRecoveryPartialACK, Flight: flight, PreviousWindow: current, Acknowledged: acknowledged, ProposedWindow: window}
	c.handleEvent()
	return c.state.CongestionWindow
}

// duplicateACKWindow handles duplicate-ACK inflation without SACK.
func (c *tcpCongestionController) duplicateACKWindow(now time.Time, current, flight uint32, mss int) uint32 {
	window := growCongestionWindow(current, uint32(mss))
	if !c.customRecovery() {
		return window
	}
	c.state.CongestionWindow = window
	c.state.BytesInFlight = flight
	c.state.MaximumSegmentSize = mss
	event := c.prepareEvent(CongestionEventRecovery, now)
	event.Recovery = CongestionRecovery{Stage: CongestionRecoveryDuplicateACK, Flight: flight, PreviousWindow: current, ProposedWindow: window}
	c.handleEvent()
	return c.state.CongestionWindow
}

// diagnostics returns the controller-owned portion of TCPInfo after publishing
// the transport state from the same actor snapshot.
func (c *tcpCongestionController) diagnostics(now time.Time, window, threshold, flight uint32, mss int, smoothedRTT, minimumRTT time.Duration) CongestionDiagnostics {
	c.syncTransportState(window, threshold, flight, mss, smoothedRTT)
	c.state.MinimumRTT = minimumRTT
	c.syncDeliveryState()
	event := c.prepareEvent(CongestionEventDiagnostics, now)
	event.Diagnostics = CongestionDiagnostics{}
	c.handleEvent()
	diagnostics := event.Diagnostics
	if !c.customPacing() {
		diagnostics.PacingRate = congestionRateValue(c.limitPacingRate(c.pacingRate))
	}
	return diagnostics
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
