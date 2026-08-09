package mipstack

import (
	"math"
	"math/bits"
	"time"
)

const (
	// bbr3Scale is the fixed-point denominator used by Linux BBRv3 defaults.
	// Mipstack uses byte rather than kernel packet accounting, while retaining
	// the same ratios and packet-timed state transitions.
	bbr3Scale = 256
	// bbr3StartupPacingGain is the Linux Startup pacing gain.
	bbr3StartupPacingGain = 710.0 / bbr3Scale
	// bbr3DrainPacingGain drains Startup's excess queue.
	bbr3DrainPacingGain = 88.0 / bbr3Scale
	// bbr3ProbeDownPacingGain drains excess inflight after Probe Up.
	bbr3ProbeDownPacingGain = 232.0 / bbr3Scale
	// bbr3ProbeUpPacingGain raises inflight during a bandwidth probe.
	bbr3ProbeUpPacingGain = 1.25
	// bbr3CongestionWindowGain is the ordinary model-window gain.
	bbr3CongestionWindowGain = 2.0
	// bbr3ProbeUpWindowGain is the model-window gain during Probe Up.
	bbr3ProbeUpWindowGain = 2.25
	// bbr3ProbeRTTWindowGain reduces inflight while measuring minimum RTT.
	bbr3ProbeRTTWindowGain = 0.5
	// bbr3LossThreshold is the loss percentage that marks inflight as excessive.
	bbr3LossThreshold = 5
	// bbr3LossRetained is the fixed-point inflight retention after excessive loss.
	bbr3LossRetained = 180
	// bbr3InflightHeadroom is the fixed-point headroom below inflight_hi.
	bbr3InflightHeadroom = 38
	// bbr3FullLossEvents is the Startup loss-round exit threshold.
	bbr3FullLossEvents = 6
	// bbr3ProbeMaximumRounds bounds the upward probe slope.
	bbr3ProbeMaximumRounds = 63
	// bbr3ProbeBase is the minimum wall-clock interval between bandwidth probes.
	bbr3ProbeBase = 2 * time.Second
	// bbr3ProbeRandom is the randomized addition to the probe interval.
	bbr3ProbeRandom = time.Second
	// bbr3ProbeRTTWindow is the shortened minimum-RTT window used after ProbeRTT.
	bbr3ProbeRTTWindow = 5 * time.Second
	// bbr3PacketInflightMask extracts inflight bytes from a packet-state cookie.
	bbr3PacketInflightMask = uint32(1)<<31 - 1
	// bbr3PacketApplicationFlag marks an application-limited packet-state cookie.
	bbr3PacketApplicationFlag = uint32(1) << 31
)

// bbr3ProbePhase identifies BBRv3's four PROBE_BW pacing phases.
type bbr3ProbePhase uint8

const (
	// bbr3ProbeUp grows inflight to search for additional bandwidth.
	bbr3ProbeUp bbr3ProbePhase = iota
	// bbr3ProbeDown drains the queue created by Probe Up.
	bbr3ProbeDown
	// bbr3ProbeCruise holds inflight below the learned upper bound.
	bbr3ProbeCruise
	// bbr3ProbeRefill restores inflight before the next Probe Up.
	bbr3ProbeRefill
)

// String returns the Linux diagnostic phase name.
func (p bbr3ProbePhase) String() string {
	switch p {
	case bbr3ProbeUp:
		return "PROBE_BW_UP"
	case bbr3ProbeDown:
		return "PROBE_BW_DOWN"
	case bbr3ProbeCruise:
		return "PROBE_BW_CRUISE"
	case bbr3ProbeRefill:
		return "PROBE_BW_REFILL"
	default:
		return ""
	}
}

// bbr3ACKPhase tracks which ACKs contain feedback from a bandwidth probe.
type bbr3ACKPhase uint8

const (
	// bbr3ACKsInitial is the neutral probe-feedback state.
	bbr3ACKsInitial bbr3ACKPhase = iota
	// bbr3ACKsRefilling observes packets sent while refilling inflight.
	bbr3ACKsRefilling
	// bbr3ACKsProbeStarting waits for the first Probe Up transmission feedback.
	bbr3ACKsProbeStarting
	// bbr3ACKsProbeFeedback observes delivery from Probe Up transmissions.
	bbr3ACKsProbeFeedback
	// bbr3ACKsProbeStopping waits for pre-stop probe feedback to drain.
	bbr3ACKsProbeStopping
)

// bbr3PacketSnapshot is decoded controller-owned per-transmission state.
type bbr3PacketSnapshot struct {
	inflight           uint32
	lost               uint32
	applicationLimited bool
}

// bbr3EncodePacketState stores Linux tx.in_flight, tx.lost, and app-limited
// state in the generic 64-bit congestion packet cookie. The ACK-phase state
// machine, like Linux bw_probe_samples, identifies bandwidth-probe feedback.
func bbr3EncodePacketState(state *CongestionState, bytes int) uint64 {
	inflight := uint64(state.BytesInFlight)
	if bytes > 0 {
		inflight += uint64(bytes)
	}
	if inflight > uint64(bbr3PacketInflightMask) {
		inflight = uint64(bbr3PacketInflightMask)
	}
	flags := uint32(inflight)
	if state.ApplicationLimited {
		flags |= bbr3PacketApplicationFlag
	}
	return uint64(uint32(state.LostBytes))<<32 | uint64(flags)
}

// bbr3DecodePacketState restores per-transmission inflight and loss evidence.
func bbr3DecodePacketState(value uint64) bbr3PacketSnapshot {
	flags := uint32(value)
	return bbr3PacketSnapshot{
		inflight:           flags & bbr3PacketInflightMask,
		lost:               uint32(value >> 32),
		applicationLimited: flags&bbr3PacketApplicationFlag != 0,
	}
}

// bbr3CongestionControl is a byte-scaled implementation of Google's public
// Linux BBRv3 algorithm. TCP retains ownership of ACK validation, SACK/RACK,
// retransmission selection, and delivery-rate sampling; this type owns only
// BBRv3's path model, congestion window, and pacing policy.
type bbr3CongestionControl struct {
	mode       bbrMode
	probePhase bbr3ProbePhase
	ackPhase   bbr3ACKPhase

	bandwidthHigh   [2]float64
	bandwidthLow    float64
	inflightLow     uint32
	inflightHigh    uint32
	latestBandwidth float64
	latestInflight  uint32

	roundCount           uint32
	nextRoundDelivered   uint32
	roundStart           bool
	fullBandwidth        float64
	fullRounds           uint8
	fullBandwidthNow     bool
	fullBandwidthReached bool

	lossRoundDelivered uint32
	lossRoundStart     bool
	lossInRound        bool
	lossEventsInRound  uint8

	minimumRTT      time.Duration
	minimumRTTStamp time.Time
	probeRTTMinimum time.Duration
	probeRTTStamp   time.Time
	probeDone       time.Time
	probeRound      bool
	priorWindow     uint32

	probeStarted         time.Time
	probeWait            time.Duration
	roundsSinceProbe     uint32
	probeUpCount         uint32
	probeUpACKed         uint64
	probeUpRounds        uint8
	probeSamples         bool
	stoppedRiskyProbe    bool
	previousProbeTooHigh bool
	initialWindowMSS     uint32

	delivered              uint64
	lost                   uint64
	applicationLimited     bool
	schedulerLimited       bool
	schedulerLimitedEvents uint64
	requestAppLimited      bool

	ackEpochStamp    time.Time
	ackEpochBytes    uint64
	extraACKed       [2]uint32
	extraACKedIndex  uint8
	extraACKedRounds uint8

	pacingRate           float64
	maximumPacingRate    uint64
	nextSend             time.Time
	pacingWakeDeadline   time.Time
	pacingBurstRemaining int
	idleRestart          bool
	hasSeenRTT           bool
	probeRandom          uint64

	recovery           bool
	lossRecovery       bool
	packetConservation bool
	undoBounds         bool
	undoBandwidthLow   float64
	undoInflightLow    uint32
	undoInflightHigh   uint32
}

// newBBR3CongestionControl constructs one independent BBRv3 controller.
func newBBR3CongestionControl() *bbr3CongestionControl {
	return &bbr3CongestionControl{
		probePhase:         bbr3ProbeDown,
		ackPhase:           bbr3ACKsInitial,
		lossRoundDelivered: 1,
	}
}

// bbr3InitialWindowMSS expresses the initial window as a rounded MSS count.
func bbr3InitialWindowMSS(window uint32, mss int) uint32 {
	if mss < 1 {
		return bbrInitialCongestionMSS
	}
	segments := (uint64(window) + uint64(mss) - 1) / uint64(mss)
	if segments == 0 {
		segments = 1
	}
	// Linux stores init_cwnd in seven bits. Preserve that semantic cap rather
	// than letting a controller switch turn an established cwnd into an
	// effectively unbounded no-RTT fallback.
	if segments > 127 {
		segments = 127
	}
	return uint32(segments)
}

// HandleCongestionEvent implements CongestionController.
func (b *bbr3CongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	switch event.Type {
	case CongestionEventInitialize:
		b.syncDeliveryState(event.State)
		b.maximumPacingRate = event.State.MaximumPacingRate
		b.initialWindowMSS = bbr3InitialWindowMSS(event.State.CongestionWindow, event.State.MaximumSegmentSize)
		if event.State.MinimumRTT > 0 {
			b.minimumRTT = event.State.MinimumRTT
			b.minimumRTTStamp = event.Time
			b.probeRTTMinimum = event.State.MinimumRTT
			b.probeRTTStamp = event.Time
		}
		b.initializePacingRate(event.State.CongestionWindow, event.State.SmoothedRTT)
	case CongestionEventACK:
		b.syncDeliveryState(event.State)
		b.requestAppLimited = false
		if event.RateSample == nil {
			return
		}
		var threshold uint32
		event.State.CongestionWindow, threshold = b.onRateSample(event.State.CongestionWindow, event.State.MaximumSegmentSize, event.RateSample)
		if threshold != 0 {
			event.State.SlowStartThreshold = threshold
		}
		event.MarkApplicationLimited = b.requestAppLimited
	case CongestionEventLoss, CongestionEventECN:
		// Classic ECE still enters transport recovery, but BBRv3's low-latency
		// ECN alpha model is deliberately disabled without precise CE counters.
		b.saveWindow(event.State.CongestionWindow)
	case CongestionEventTimeout:
		b.syncDeliveryState(event.State)
		b.saveWindow(event.State.CongestionWindow)
		b.recovery = false
		b.lossRecovery = true
		b.packetConservation = false
		b.resetFullBandwidth()
	case CongestionEventPacketSent:
		event.PacketState = bbr3EncodePacketState(event.State, event.PacketBytes)
		b.applicationLimited = event.State.ApplicationLimited
		event.State.CongestionWindow = b.onDeliverySend(event.Time, event.OutstandingBytes, event.State.CongestionWindow)
		b.consumePacingBurst(event.PacketBytes)
		b.advancePacing(event.PacketBytes, event.State.MaximumSegmentSize, event.Time)
	case CongestionEventPacketRetransmitted:
		event.PacketState = bbr3EncodePacketState(event.State, event.PacketBytes)
		b.advanceRetransmissionPacing(event.PacketBytes, event.State.MaximumSegmentSize, event.Time)
	case CongestionEventPacketLost:
		b.onPacketLost(event)
	case CongestionEventTailLossProbeRecovered:
		b.onTailLossProbeRecovered(event)
	case CongestionEventRecovery:
		b.handleRecoveryEvent(event)
	case CongestionEventPacing:
		b.handlePacingEvent(event)
	case CongestionEventMTUChanged:
		b.resetPacer()
	case CongestionEventDiagnostics:
		b.syncDeliveryState(event.State)
		state := b.mode.String()
		if b.mode == bbrProbeBandwidth {
			state = b.probePhase.String()
		}
		event.Diagnostics = CongestionDiagnostics{
			DeliveryRate:           congestionRateValue(b.effectiveBandwidth()),
			PacingRate:             congestionRateValue(b.effectivePacingRate()),
			State:                  state,
			ApplicationLimited:     b.applicationLimited,
			SchedulerLimited:       b.schedulerLimited,
			SchedulerLimitedEvents: b.schedulerLimitedEvents,
		}
	}
}

// syncDeliveryState publishes controller delivery-model state for diagnostics.
func (b *bbr3CongestionControl) syncDeliveryState(state *CongestionState) {
	b.delivered = state.DeliveredBytes
	b.lost = state.LostBytes
	b.applicationLimited = state.ApplicationLimited
	b.schedulerLimited = state.SchedulerLimited
	b.schedulerLimitedEvents = state.SchedulerLimitedEvents
}

// handleRecoveryEvent checkpoints, restores, or exits controller recovery state.
func (b *bbr3CongestionControl) handleRecoveryEvent(event *CongestionEvent) {
	switch event.Recovery.Stage {
	case CongestionRecoverySelectFlight:
		event.Recovery.Flight = event.Recovery.OrdinaryFlight
	case CongestionRecoveryEnter:
		window := event.Recovery.Flight
		if minimum := uint32(bbrMinimumCongestionMSS * event.State.MaximumSegmentSize); window < minimum {
			window = minimum
		}
		event.State.CongestionWindow = window
	case CongestionRecoveryPRR, CongestionRecoveryExit, CongestionRecoveryPartialACK, CongestionRecoveryDuplicateACK:
		event.State.CongestionWindow = event.Recovery.PreviousWindow
	case CongestionRecoveryUndo:
		b.undoRecovery()
	}
}

// handlePacingEvent answers transport pacing queries and transmission notices.
func (b *bbr3CongestionControl) handlePacingEvent(event *CongestionEvent) {
	switch event.Pacing.Operation {
	case CongestionPacingQuery:
		event.Pacing.Delay, event.Pacing.MarkSchedulerLimited = b.pacingDelay(event.Time, event.Pacing.Bytes, event.State.MaximumSegmentSize, event.State.BytesInFlight)
	case CongestionPacingWake:
		event.Pacing.MarkSchedulerLimited = b.consumePacingWake(event.Time, event.State.BytesInFlight)
	case CongestionPacingCancel:
		b.pacingWakeDeadline = time.Time{}
	case CongestionPacingPolicyChanged:
		b.resetPacer()
		b.maximumPacingRate = event.State.MaximumPacingRate
	}
}

// onRateSample advances the path model and returns updated cwnd and ssthresh.
func (b *bbr3CongestionControl) onRateSample(window uint32, mss int, sample *tcpDeliveryRateSample) (uint32, uint32) {
	packet := bbr3DecodePacketState(sample.packetState)
	if packet.inflight == 0 {
		packet.inflight = sample.priorInFlight
	}
	rate := b.updateBandwidth(sample)
	b.updateLatestDeliverySignals(sample, rate)
	b.updateCongestionSignals(sample, rate, window)
	b.updateACKAggregation(sample, window, mss)
	b.checkStartupLoss(sample, packet, mss)
	b.checkFullBandwidth(sample, rate)
	threshold := b.checkDrain(sample, mss)
	b.updateProbeBandwidth(sample, packet, rate, window, mss)
	window = b.updateMinimumRTT(window, sample, mss)
	if sample.delivered != 0 {
		b.idleRestart = false
	}
	b.setPacingRate(window, sample.smoothedRTT)
	window = b.setCongestionWindow(window, sample, mss)
	b.advanceLatestDeliverySignals(sample, rate)
	return window, threshold
}

// updateBandwidth incorporates one valid delivery sample into round maxima.
func (b *bbr3CongestionControl) updateBandwidth(sample *tcpDeliveryRateSample) float64 {
	b.roundStart = false
	if !sample.valid || sample.interval <= 0 {
		return 0
	}
	if tcpDeliveryAfterEqual(sample.priorDelivered, b.nextRoundDelivered) {
		b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
		b.roundCount++
		b.roundStart = true
		b.packetConservation = false
		if b.roundsSinceProbe != ^uint32(0) {
			b.roundsSinceProbe++
		}
	}
	rate := float64(sample.delivered) / sample.interval.Seconds()
	if !sample.locallyLimited() || rate >= b.maximumBandwidth() {
		if rate > b.bandwidthHigh[1] {
			b.bandwidthHigh[1] = rate
		}
	}
	return rate
}

// maximumBandwidth returns the current two-round delivery-rate maximum.
func (b *bbr3CongestionControl) maximumBandwidth() float64 {
	if b.bandwidthHigh[0] > b.bandwidthHigh[1] {
		return b.bandwidthHigh[0]
	}
	return b.bandwidthHigh[1]
}

// updateLatestDeliverySignals accumulates delivery and loss within one packet round.
func (b *bbr3CongestionControl) updateLatestDeliverySignals(sample *tcpDeliveryRateSample, rate float64) {
	b.lossRoundStart = false
	if !sample.valid || sample.acked == 0 {
		return
	}
	if rate > b.latestBandwidth {
		b.latestBandwidth = rate
	}
	if sample.delivered > b.latestInflight {
		b.latestInflight = sample.delivered
	}
	b.lossRoundStart = tcpDeliveryAfterEqual(sample.priorDelivered, b.lossRoundDelivered)
	if b.lossRoundStart {
		b.lossRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
	}
}

// advanceLatestDeliverySignals starts a new packet round with current evidence.
func (b *bbr3CongestionControl) advanceLatestDeliverySignals(sample *tcpDeliveryRateSample, rate float64) {
	if !b.lossRoundStart {
		return
	}
	if !sample.tailLossProbeACK {
		b.latestBandwidth = rate
		b.latestInflight = sample.delivered
	}
}

// updateCongestionSignals advances lower bandwidth and inflight bounds on round starts.
func (b *bbr3CongestionControl) updateCongestionSignals(sample *tcpDeliveryRateSample, rate float64, window uint32) {
	if sample.losses != 0 {
		b.noteLossRound()
	}
	if !b.lossRoundStart {
		return
	}
	if b.lossInRound && !b.isProbingBandwidth() {
		if b.bandwidthLow == 0 {
			b.bandwidthLow = b.maximumBandwidth()
		}
		if b.inflightLow == 0 {
			b.inflightLow = window
		}
		retainedBandwidth := b.bandwidthLow * bbr3LossRetained / bbr3Scale
		if b.latestBandwidth > retainedBandwidth {
			retainedBandwidth = b.latestBandwidth
		}
		if retainedBandwidth <= 0 && rate > 0 {
			retainedBandwidth = rate
		}
		b.bandwidthLow = retainedBandwidth
		retainedInflight := uint32(uint64(b.inflightLow) * bbr3LossRetained / bbr3Scale)
		if b.latestInflight > retainedInflight {
			retainedInflight = b.latestInflight
		}
		b.inflightLow = retainedInflight
	}
	b.lossInRound = false
}

// noteLossRound counts one Startup round with excessive loss.
func (b *bbr3CongestionControl) noteLossRound() {
	if !b.lossInRound {
		b.lossRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
	}
	b.lossInRound = true
}

// checkStartupLoss exits Startup after persistent excessive-loss rounds.
func (b *bbr3CongestionControl) checkStartupLoss(sample *tcpDeliveryRateSample, packet bbr3PacketSnapshot, mss int) {
	if b.fullBandwidthReached {
		return
	}
	if sample.losses != 0 && b.lossEventsInRound < 15 {
		b.lossEventsInRound++
	}
	if b.lossRoundStart && sample.fastRecovery && b.lossEventsInRound >= bbr3FullLossEvents && b.inflightTooHigh(b.lossesSince(packet), packet.inflight) {
		b.fullBandwidthReached = true
		upper := b.quantizeWindowAt(b.modelWindowForBandwidth(b.maximumBandwidth(), 1, mss), mss, false)
		if uint64(b.latestInflight) > upper {
			upper = uint64(b.latestInflight)
		}
		b.inflightHigh = clampCongestionUint32(upper)
	}
	if b.lossRoundStart {
		b.lossEventsInRound = 0
	}
}

// checkFullBandwidth detects the end of Startup's exponential bandwidth growth.
func (b *bbr3CongestionControl) checkFullBandwidth(sample *tcpDeliveryRateSample, rate float64) {
	if b.fullBandwidthNow || sample.applicationLimited || !sample.valid {
		return
	}
	if b.fullBandwidthReached && (b.mode != bbrProbeBandwidth || b.probePhase != bbr3ProbeUp) {
		return
	}
	if sample.schedulerLimited {
		if !b.roundStart {
			return
		}
		rate = b.maximumBandwidth()
	}
	if rate >= b.fullBandwidth*bbrFullBandwidthGrowth {
		b.fullBandwidth = rate
		b.fullRounds = 0
		return
	}
	if !b.roundStart {
		return
	}
	if b.fullRounds < ^uint8(0) {
		b.fullRounds++
	}
	if b.fullRounds >= bbrFullBandwidthRounds {
		b.fullBandwidthNow = true
		b.fullBandwidthReached = true
	}
}

// resetFullBandwidth restarts Startup growth detection after an idle restart.
func (b *bbr3CongestionControl) resetFullBandwidth() {
	b.fullBandwidth = 0
	b.fullRounds = 0
	b.fullBandwidthNow = false
}

// checkDrain leaves Drain when inflight reaches the modeled path pipe.
func (b *bbr3CongestionControl) checkDrain(sample *tcpDeliveryRateSample, mss int) uint32 {
	inflight := b.packetsInNetwork(sample.inFlight, sample.ackTime, mss, b.pacingGain())
	var threshold uint32
	if b.mode == bbrStartup && b.fullBandwidthReached {
		threshold = clampCongestionUint32(b.quantizeWindowAt(b.modelWindowForBandwidth(b.maximumBandwidth(), 1, mss), mss, false))
		b.mode = bbrDrain
		b.resetCongestionSignals()
	}
	drainTarget := b.quantizeWindowAt(b.modelWindowForBandwidth(b.maximumBandwidth(), 1, mss), mss, false)
	if b.mode == bbrDrain && uint64(inflight) <= drainTarget {
		b.mode = bbrProbeBandwidth
		b.enterProbePhase(bbr3ProbeDown, sample.ackTime)
	}
	return threshold
}

// updateProbeBandwidth advances ProbeBW phases and their learned upper bounds.
func (b *bbr3CongestionControl) updateProbeBandwidth(sample *tcpDeliveryRateSample, packet bbr3PacketSnapshot, rate float64, window uint32, mss int) {
	if b.adaptUpperBounds(sample, packet, window, mss) {
		return
	}
	if b.mode != bbrProbeBandwidth || b.minimumRTT <= 0 {
		return
	}
	inflight := uint64(b.packetsInNetwork(sample.priorInFlight, sample.ackTime, mss, b.pacingGain()))
	switch b.probePhase {
	case bbr3ProbeCruise:
		if b.probeDue(sample.ackTime, window, mss) {
			b.enterProbePhase(bbr3ProbeRefill, sample.ackTime)
		}
	case bbr3ProbeRefill:
		if b.roundStart {
			b.enterProbePhase(bbr3ProbeUp, sample.ackTime)
			b.ackPhase = bbr3ACKsProbeStarting
			b.probeSamples = true
			b.resetFullBandwidth()
			b.fullBandwidth = rate
			b.raiseProbeSlope(window, mss)
		}
	case bbr3ProbeUp:
		done := false
		if b.previousProbeTooHigh && b.inflightHigh != 0 && inflight >= uint64(b.inflightHigh) {
			b.stoppedRiskyProbe = true
			done = true
		} else if b.inflightHigh != 0 && congestionWindowLimited(window, sample.priorInFlight, mss) && window >= b.inflightHigh {
			b.resetFullBandwidth()
			b.fullBandwidth = rate
		} else if b.fullBandwidthNow {
			done = true
		}
		if done {
			b.previousProbeTooHigh = false
			b.enterProbePhase(bbr3ProbeDown, sample.ackTime)
		}
	case bbr3ProbeDown:
		if b.probeDue(sample.ackTime, window, mss) {
			b.enterProbePhase(bbr3ProbeRefill, sample.ackTime)
			return
		}
		cruiseTarget := b.quantizeWindowAt(b.modelWindowForBandwidth(b.maximumBandwidth(), 1, mss), mss, false)
		if inflight <= cruiseTarget && inflight <= b.inflightWithHeadroom(mss) {
			b.enterProbePhase(bbr3ProbeCruise, sample.ackTime)
		}
	}
}

// adaptUpperBounds updates bandwidth_hi and inflight_hi from probe feedback.
func (b *bbr3CongestionControl) adaptUpperBounds(sample *tcpDeliveryRateSample, packet bbr3PacketSnapshot, window uint32, mss int) bool {
	if !b.fullBandwidthReached {
		return false
	}
	if b.ackPhase == bbr3ACKsProbeStarting && b.roundStart {
		b.ackPhase = bbr3ACKsProbeFeedback
	}
	if b.ackPhase == bbr3ACKsProbeStopping && b.roundStart {
		b.probeSamples = false
		b.ackPhase = bbr3ACKsInitial
		if b.mode == bbrProbeBandwidth && !sample.locallyLimited() && b.bandwidthHigh[1] != 0 {
			b.bandwidthHigh[0] = b.bandwidthHigh[1]
			b.bandwidthHigh[1] = 0
		}
		if b.mode == bbrProbeBandwidth && b.stoppedRiskyProbe && !b.previousProbeTooHigh {
			b.enterProbePhase(bbr3ProbeRefill, sample.ackTime)
			return true
		}
	}
	if b.inflightTooHigh(b.lossesSince(packet), packet.inflight) {
		if b.probeSamples {
			b.handleInflightTooHigh(packet.inflight, packet.applicationLimited, window, mss, sample.ackTime)
		}
		return false
	}
	if b.inflightHigh != 0 && packet.inflight > b.inflightHigh {
		b.inflightHigh = packet.inflight
	}
	if b.mode == bbrProbeBandwidth && b.probePhase == bbr3ProbeUp {
		b.probeInflightHighUpward(sample.acked, sample.priorInFlight, window, mss)
	}
	return false
}

// probeDue reports whether elapsed time or round count requires another probe.
func (b *bbr3CongestionControl) probeDue(now time.Time, window uint32, mss int) bool {
	if mss < 1 {
		return false
	}
	target := b.quantizeWindowAt(b.modelWindowForBandwidth(b.effectiveBandwidth(), 1, mss), mss, false)
	if window != 0 && target > uint64(window) {
		target = uint64(window)
	}
	rounds := uint32(target / uint64(mss))
	if rounds == 0 {
		rounds = 1
	}
	if rounds > bbr3ProbeMaximumRounds {
		rounds = bbr3ProbeMaximumRounds
	}
	return !b.probeStarted.IsZero() && now.Sub(b.probeStarted) > b.probeWait || b.roundsSinceProbe >= rounds
}

// enterProbePhase resets phase-local state and selects the next ACK phase.
func (b *bbr3CongestionControl) enterProbePhase(phase bbr3ProbePhase, now time.Time) {
	b.probePhase = phase
	switch phase {
	case bbr3ProbeDown:
		b.resetCongestionSignals()
		b.probeUpCount = ^uint32(0)
		b.pickProbeWait(now)
		b.ackPhase = bbr3ACKsProbeStopping
		b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
		b.fullBandwidthNow = false
	case bbr3ProbeCruise:
		if b.inflightLow != 0 && b.inflightHigh != 0 && b.inflightLow > b.inflightHigh {
			b.inflightLow = b.inflightHigh
		}
	case bbr3ProbeRefill:
		b.bandwidthLow = 0
		b.inflightLow = 0
		b.probeUpRounds = 0
		b.probeUpACKed = 0
		b.stoppedRiskyProbe = false
		b.ackPhase = bbr3ACKsRefilling
		b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
	case bbr3ProbeUp:
		b.probeUpACKed = 0
	}
}

// pickProbeWait selects the randomized time and round interval to Probe Up.
func (b *bbr3CongestionControl) pickProbeWait(now time.Time) {
	b.roundsSinceProbe = uint32(b.randomBelow(2, now))
	b.probeStarted = now
	b.probeWait = bbr3ProbeBase + time.Duration(b.randomBelow(uint64(bbr3ProbeRandom), now.Add(time.Nanosecond)))
}

// randomBelow returns a bounded value from the controller's private PRNG.
func (b *bbr3CongestionControl) randomBelow(limit uint64, now time.Time) uint64 {
	if limit <= 1 {
		return 0
	}
	threshold := -limit % limit
	for {
		value := b.nextRandom(now)
		result, remainder := bits.Mul64(value, limit)
		if remainder >= threshold {
			return result
		}
	}
}

// nextRandom advances the per-connection non-cryptographic PRNG.
func (b *bbr3CongestionControl) nextRandom(now time.Time) uint64 {
	if b.probeRandom == 0 {
		b.probeRandom = uint64(now.UnixNano()) ^ bbrCycleRandomSequence.Add(bbrCycleRandomIncrement)
	}
	b.probeRandom += bbrCycleRandomIncrement
	value := b.probeRandom
	value = (value ^ value>>30) * 0xbf58476d1ce4e5b9
	value = (value ^ value>>27) * 0x94d049bb133111eb
	return value ^ value>>31
}

// raiseProbeSlope increases the per-ACK inflight_hi growth slope by probe round.
func (b *bbr3CongestionControl) raiseProbeSlope(window uint32, mss int) {
	if mss < 1 {
		return
	}
	growth := uint64(1) << b.probeUpRounds
	if b.probeUpRounds < 30 {
		b.probeUpRounds++
	}
	count := uint64(window) / growth
	if count < uint64(mss) {
		count = uint64(mss)
	}
	b.probeUpCount = clampCongestionUint32(count)
}

// probeInflightHighUpward spends ACK credit to grow inflight_hi during Probe Up.
func (b *bbr3CongestionControl) probeInflightHighUpward(acked, flight, window uint32, mss int) {
	if b.inflightHigh == 0 || !congestionWindowLimited(window, flight, mss) || window < b.inflightHigh {
		return
	}
	if b.probeUpCount == 0 {
		b.raiseProbeSlope(window, mss)
	}
	b.probeUpACKed += uint64(acked)
	if b.probeUpCount != 0 && b.probeUpACKed >= uint64(b.probeUpCount) {
		groups := b.probeUpACKed / uint64(b.probeUpCount)
		b.probeUpACKed -= groups * uint64(b.probeUpCount)
		b.inflightHigh = clampCongestionUint32(uint64(b.inflightHigh) + groups*uint64(mss))
	}
	if b.roundStart {
		b.raiseProbeSlope(window, mss)
	}
}

// inflightTooHigh applies the configured loss-rate threshold to one transmission.
func (b *bbr3CongestionControl) inflightTooHigh(lost uint64, inflight uint32) bool {
	return lost != 0 && inflight != 0 && lost > uint64(inflight)*bbr3LossThreshold/bbr3Scale
}

// lossesSince reconstructs Linux rate_sample.lost from the connection total
// and the tx.lost snapshot carried by the sampled transmission generation.
func (b *bbr3CongestionControl) lossesSince(packet bbr3PacketSnapshot) uint64 {
	return uint64(uint32(b.lost) - packet.lost)
}

// onPacketLost incorporates one transmission generation proven lost.
func (b *bbr3CongestionControl) onPacketLost(event *CongestionEvent) {
	b.syncDeliveryState(event.State)
	b.noteLossRound()
	if event.PacketBytes <= 0 || !b.probeSamples {
		return
	}
	packet := bbr3DecodePacketState(event.PacketState)
	if packet.inflight == 0 {
		return
	}
	lost := uint32(event.State.LostBytes) - packet.lost
	if !b.inflightTooHigh(uint64(lost), packet.inflight) {
		return
	}
	chunk := uint32(event.PacketBytes)
	if chunk > packet.inflight {
		chunk = packet.inflight
	}
	inflightBefore := packet.inflight - chunk
	var lostBefore uint32
	if lost > uint32(event.PacketBytes) {
		lostBefore = lost - uint32(event.PacketBytes)
	}
	lossBudget := (uint64(inflightBefore)*bbr3LossThreshold + bbr3Scale - 1) / bbr3Scale
	var lostPrefix uint64
	if uint64(lostBefore) < lossBudget {
		needed := lossBudget - uint64(lostBefore)
		lostPrefix = needed * uint64(bbr3Scale) / (bbr3Scale - bbr3LossThreshold)
	}
	b.handleInflightTooHigh(clampCongestionUint32(uint64(inflightBefore)+lostPrefix), packet.applicationLimited, event.State.CongestionWindow, event.State.MaximumSegmentSize, event.Time)
}

// onTailLossProbeRecovered applies prompt loss evidence from successful TLP recovery.
func (b *bbr3CongestionControl) onTailLossProbeRecovered(event *CongestionEvent) {
	b.syncDeliveryState(event.State)
	b.noteLossRound()
	if !b.probeSamples || event.PacketBytes <= 0 {
		return
	}
	packet := bbr3DecodePacketState(event.PacketState)
	inflight := growCongestionWindow(b.latestInflight, uint32(event.PacketBytes))
	if b.inflightTooHigh(uint64(event.PacketBytes), inflight) {
		b.handleInflightTooHigh(inflight, packet.applicationLimited, event.State.CongestionWindow, event.State.MaximumSegmentSize, event.Time)
	}
}

// handleInflightTooHigh lowers model bounds after non-application-limited loss.
func (b *bbr3CongestionControl) handleInflightTooHigh(inflight uint32, applicationLimited bool, window uint32, mss int, now time.Time) {
	b.previousProbeTooHigh = true
	b.stoppedRiskyProbe = false
	b.probeSamples = false
	if !applicationLimited {
		upper := uint64(inflight)
		target := b.quantizeWindowAt(b.modelWindowForBandwidth(b.effectiveBandwidth(), 1, mss), mss, false)
		if window != 0 && target > uint64(window) {
			target = uint64(window)
		}
		retainedTarget := target * bbr3LossRetained / bbr3Scale
		if upper < retainedTarget {
			upper = retainedTarget
		}
		b.inflightHigh = clampCongestionUint32(upper)
	}
	if b.mode == bbrProbeBandwidth && b.probePhase == bbr3ProbeUp {
		b.enterProbePhase(bbr3ProbeDown, now)
	}
}

// isProbingBandwidth reports whether current ACKs can raise model upper bounds.
func (b *bbr3CongestionControl) isProbingBandwidth() bool {
	return b.mode == bbrStartup || b.mode == bbrProbeBandwidth && (b.probePhase == bbr3ProbeRefill || b.probePhase == bbr3ProbeUp)
}

// resetCongestionSignals starts a fresh lower-bound adaptation interval.
func (b *bbr3CongestionControl) resetCongestionSignals() {
	b.lossInRound = false
	b.latestBandwidth = 0
	b.latestInflight = 0
}

// updateMinimumRTT maintains the minimum-RTT filter and ProbeRTT lifecycle.
func (b *bbr3CongestionControl) updateMinimumRTT(window uint32, sample *tcpDeliveryRateSample, mss int) uint32 {
	probeExpired := b.probeRTTMinimum != 0 && sample.ackTime.Sub(b.probeRTTStamp) > bbr3ProbeRTTWindow
	minimumExpired := b.minimumRTT != 0 && sample.ackTime.Sub(b.minimumRTTStamp) > bbrMinRTTWindow
	if sample.rtt > 0 && (b.probeRTTMinimum == 0 || sample.rtt < b.probeRTTMinimum || probeExpired && !sample.ackDelayed) {
		b.probeRTTMinimum = sample.rtt
		b.probeRTTStamp = sample.ackTime
	}
	if b.probeRTTMinimum > 0 && (b.minimumRTT == 0 || b.probeRTTMinimum <= b.minimumRTT || minimumExpired) {
		b.minimumRTT = b.probeRTTMinimum
		b.minimumRTTStamp = b.probeRTTStamp
	}
	if probeExpired && !b.idleRestart && b.mode != bbrProbeRTT {
		b.mode = bbrProbeRTT
		b.saveWindow(window)
		b.probeDone = time.Time{}
		b.probeRound = false
		b.ackPhase = bbr3ACKsProbeStopping
		b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
		b.resetPacer()
	}
	if b.mode != bbrProbeRTT {
		return window
	}
	b.requestAppLimited = true
	probeTarget := clampCongestionUint32(b.modelWindowForBandwidth(b.effectiveBandwidth(), bbr3ProbeRTTWindowGain, mss))
	minimum := uint32(bbrMinimumCongestionMSS * mss)
	if probeTarget < minimum {
		probeTarget = minimum
	}
	if b.probeDone.IsZero() && sample.inFlight <= probeTarget {
		b.probeDone = sample.ackTime.Add(bbrProbeRTTDuration)
		b.probeRound = false
		b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
	} else if !b.probeDone.IsZero() && b.roundStart {
		b.probeRound = true
	}
	if !b.probeDone.IsZero() && b.probeRound && !sample.ackTime.Before(b.probeDone) {
		b.probeRTTStamp = sample.ackTime
		if window < b.priorWindow {
			window = b.priorWindow
		}
		b.bandwidthLow = 0
		b.inflightLow = 0
		b.exitProbeRTT(sample.ackTime)
	}
	return window
}

// exitProbeRTT restores Startup or ProbeBW after the measurement interval.
func (b *bbr3CongestionControl) exitProbeRTT(now time.Time) {
	if b.fullBandwidthReached {
		b.mode = bbrProbeBandwidth
		b.enterProbePhase(bbr3ProbeDown, now)
		b.enterProbePhase(bbr3ProbeCruise, now)
		return
	}
	b.mode = bbrStartup
}

// setCongestionWindow applies ACK growth, recovery conservation, and model bounds.
func (b *bbr3CongestionControl) setCongestionWindow(window uint32, sample *tcpDeliveryRateSample, mss int) uint32 {
	minimum := uint32(bbrMinimumCongestionMSS * mss)
	probeTarget := clampCongestionUint32(b.modelWindowForBandwidth(b.effectiveBandwidth(), bbr3ProbeRTTWindowGain, mss))
	if probeTarget < minimum {
		probeTarget = minimum
	}
	if sample.acked != 0 {
		if sample.losses != 0 {
			if sample.losses >= uint64(window) {
				window = uint32(mss)
			} else {
				window -= uint32(sample.losses)
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
			b.recovery = true
			b.packetConservation = true
			b.nextRoundDelivered = uint32(b.delivered) & tcpDeliveryDeliveredMask
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
		} else if b.mode != bbrProbeRTT {
			target := b.modelWindow(b.congestionWindowGain(), mss)
			target += b.ackAggregationWindow()
			target = b.quantizeWindow(target, mss)
			if b.fullBandwidthReached {
				grown := growCongestionWindow(window, sample.acked)
				if uint64(grown) > target {
					window = clampCongestionUint32(target)
				} else {
					window = grown
				}
			} else if uint64(window) < target || uint64(window) < 2*b.initialWindow(mss) {
				window = growCongestionWindow(window, sample.acked)
			}
		}
	}
	if window < minimum {
		window = minimum
	}
	window = clampCongestionUint32(b.boundWindow(uint64(window), mss))
	if b.mode == bbrProbeRTT && window > probeTarget {
		window = probeTarget
	}
	return window
}

// boundWindow applies mode-specific inflight_hi, inflight_lo, and ProbeRTT limits.
func (b *bbr3CongestionControl) boundWindow(window uint64, mss int) uint64 {
	cap := uint64(tcpMaximumScaledWindow)
	if b.mode == bbrProbeBandwidth && b.probePhase != bbr3ProbeCruise {
		if b.inflightHigh != 0 {
			cap = uint64(b.inflightHigh)
		}
	} else if b.mode == bbrProbeRTT || b.mode == bbrProbeBandwidth && b.probePhase == bbr3ProbeCruise {
		cap = b.inflightWithHeadroom(mss)
	}
	if b.inflightLow != 0 && uint64(b.inflightLow) < cap {
		cap = uint64(b.inflightLow)
	}
	minimum := uint64(bbrMinimumCongestionMSS * mss)
	if cap < minimum {
		cap = minimum
	}
	if window > cap {
		window = cap
	}
	return window
}

// inflightWithHeadroom reserves model headroom below a finite inflight_hi.
func (b *bbr3CongestionControl) inflightWithHeadroom(mss int) uint64 {
	if b.inflightHigh == 0 {
		return uint64(tcpMaximumScaledWindow)
	}
	upper := uint64(b.inflightHigh)
	headroom := upper * bbr3InflightHeadroom / bbr3Scale
	if headroom < uint64(mss) {
		headroom = uint64(mss)
	}
	if headroom >= upper {
		upper = 0
	} else {
		upper -= headroom
	}
	minimum := uint64(bbrMinimumCongestionMSS * mss)
	if upper < minimum {
		upper = minimum
	}
	return upper
}

// ackAggregationWindow returns bounded extra cwnd for compressed ACK bursts.
func (b *bbr3CongestionControl) ackAggregationWindow() uint64 {
	extra := uint64(b.extraACKed[0])
	if uint64(b.extraACKed[1]) > extra {
		extra = uint64(b.extraACKed[1])
	}
	maximum := uint64(b.effectiveBandwidth() * bbrExtraACKedMaximumInterval.Seconds())
	if extra > maximum {
		extra = maximum
	}
	return extra
}

// clampCongestionUint32 saturates a byte count at the controller API width.
func clampCongestionUint32(value uint64) uint32 {
	if value > uint64(tcpMaximumScaledWindow) {
		return tcpMaximumScaledWindow
	}
	return uint32(value)
}

// updateACKAggregation tracks excess delivery beyond the modeled bandwidth.
func (b *bbr3CongestionControl) updateACKAggregation(sample *tcpDeliveryRateSample, window uint32, mss int) {
	if !sample.valid || sample.acked == 0 || mss < 1 {
		return
	}
	if b.roundStart {
		age := uint8(bbrExtraACKedWindow)
		if !b.fullBandwidthReached {
			age = 1
		}
		b.extraACKedRounds++
		if b.extraACKedRounds >= age {
			b.extraACKedRounds = 0
			b.extraACKedIndex ^= 1
			b.extraACKed[b.extraACKedIndex] = 0
		}
	}
	if sample.schedulerLimited {
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

// modelWindow returns a gain-scaled BDP at the effective model bandwidth.
func (b *bbr3CongestionControl) modelWindow(gain float64, mss int) uint64 {
	return b.modelWindowForBandwidth(b.effectiveBandwidth(), gain, mss)
}

// modelWindowForBandwidth returns a quantized gain-scaled BDP for bandwidth.
func (b *bbr3CongestionControl) modelWindowForBandwidth(bandwidth, gain float64, mss int) uint64 {
	if mss < 1 {
		return 0
	}
	if b.minimumRTT <= 0 {
		return b.initialWindow(mss)
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

// initialWindow reconstructs the controller's MSS-scaled initial window.
func (b *bbr3CongestionControl) initialWindow(mss int) uint64 {
	if mss < 1 {
		return 0
	}
	segments := b.initialWindowMSS
	if segments == 0 {
		segments = bbrInitialCongestionMSS
	}
	return uint64(segments) * uint64(mss)
}

// quantizeWindow adds Linux-style offload and delayed-ACK allowances.
func (b *bbr3CongestionControl) quantizeWindow(target uint64, mss int) uint64 {
	return b.quantizeWindowAt(target, mss, b.mode == bbrProbeBandwidth && b.probePhase == bbr3ProbeUp)
}

// quantizeWindowAt applies phase-specific packet quanta and the minimum window.
func (b *bbr3CongestionControl) quantizeWindowAt(target uint64, mss int, probeUp bool) uint64 {
	if mss < 1 {
		return 0
	}
	quantum := bbrSendQuantum(b.effectivePacingRate(), mss)
	if quantum < mss {
		quantum = mss
	}
	if hostBudget := uint64(3 * quantum); target < hostBudget {
		target = hostBudget
	}
	minimum := uint64(bbrMinimumCongestionMSS * mss)
	if target < minimum {
		target = minimum
	}
	if probeUp {
		target += uint64(2 * mss)
	}
	if target > uint64(tcpMaximumScaledWindow) {
		return uint64(tcpMaximumScaledWindow)
	}
	return target
}

// packetsInNetwork estimates bytes still in the network at a pacing instant.
func (b *bbr3CongestionControl) packetsInNetwork(inflight uint32, now time.Time, mss int, gain float64) uint32 {
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
	return clampCongestionUint32(value)
}

// effectiveBandwidth applies a finite lower bandwidth bound when present.
func (b *bbr3CongestionControl) effectiveBandwidth() float64 {
	bandwidth := b.maximumBandwidth()
	if b.bandwidthLow != 0 && b.bandwidthLow < bandwidth {
		return b.bandwidthLow
	}
	return bandwidth
}

// pacingGain returns the current mode and phase pacing multiplier.
func (b *bbr3CongestionControl) pacingGain() float64 {
	switch b.mode {
	case bbrStartup:
		return bbr3StartupPacingGain
	case bbrDrain:
		return bbr3DrainPacingGain
	case bbrProbeBandwidth:
		switch b.probePhase {
		case bbr3ProbeUp:
			return bbr3ProbeUpPacingGain
		case bbr3ProbeDown:
			return bbr3ProbeDownPacingGain
		}
	}
	return 1
}

// congestionWindowGain returns the current mode and phase cwnd multiplier.
func (b *bbr3CongestionControl) congestionWindowGain() float64 {
	if b.mode == bbrProbeRTT {
		return bbr3ProbeRTTWindowGain
	}
	if b.mode == bbrProbeBandwidth && b.probePhase == bbr3ProbeUp {
		return bbr3ProbeUpWindowGain
	}
	return bbr3CongestionWindowGain
}

// initializePacingRate seeds pacing from the initial window and RTT estimate.
func (b *bbr3CongestionControl) initializePacingRate(window uint32, smoothedRTT time.Duration) {
	roundTrip := smoothedRTT
	if roundTrip <= 0 {
		roundTrip = time.Millisecond
	} else {
		b.hasSeenRTT = true
	}
	b.pacingRate = float64(window) / roundTrip.Seconds() * bbr3StartupPacingGain * bbrPacingMargin
}

// setPacingRate raises or updates pacing from the current bandwidth model.
func (b *bbr3CongestionControl) setPacingRate(window uint32, smoothedRTT time.Duration) {
	if !b.hasSeenRTT && smoothedRTT > 0 {
		b.initializePacingRate(window, smoothedRTT)
	}
	bandwidth := b.effectiveBandwidth()
	if bandwidth <= 0 {
		return
	}
	rate := bandwidth * b.pacingGain() * bbrPacingMargin
	if b.pacingRate == 0 || b.fullBandwidthReached || rate > b.pacingRate {
		b.pacingRate = rate
	}
}

// effectivePacingRate applies the socket pacing ceiling to the model rate.
func (b *bbr3CongestionControl) effectivePacingRate() float64 {
	rate := b.pacingRate
	if b.maximumPacingRate != 0 && rate > float64(b.maximumPacingRate) {
		return float64(b.maximumPacingRate)
	}
	return rate
}

// pacingDelay returns the wait before bytes may be sent and whether pacing applies.
func (b *bbr3CongestionControl) pacingDelay(now time.Time, bytes, mss int, flight uint32) (time.Duration, bool) {
	rate := b.effectivePacingRate()
	if bytes <= 0 || rate <= 0 {
		return 0, false
	}
	schedulerLimited := b.consumePacingWake(now, flight)
	if b.pacingBurstRemaining >= bytes {
		return 0, schedulerLimited
	}
	budget := bbrUserspacePacingBudget(rate, mss)
	if !b.nextSend.IsZero() && now.Before(b.nextSend) {
		allowance := pacingDuration(budget, rate)
		deadline := b.nextSend.Add(-allowance)
		if now.Before(deadline) {
			b.pacingWakeDeadline = deadline
			return deadline.Sub(now), schedulerLimited
		}
	}
	if b.nextSend.IsZero() {
		b.nextSend = now
	}
	b.pacingBurstRemaining = budget
	return 0, schedulerLimited
}

// consumePacingWake validates and consumes one armed pacing wakeup.
func (b *bbr3CongestionControl) consumePacingWake(now time.Time, flight uint32) bool {
	if b.pacingWakeDeadline.IsZero() {
		return false
	}
	deadline := b.pacingWakeDeadline
	b.pacingWakeDeadline = time.Time{}
	return flight != 0 && now.Sub(deadline) > tcpUserspaceSchedulingTolerance
}

// consumePacingBurst spends initial unpaced burst credit.
func (b *bbr3CongestionControl) consumePacingBurst(bytes int) {
	if bytes <= 0 || b.pacingBurstRemaining <= 0 {
		return
	}
	b.pacingBurstRemaining -= bytes
	if b.pacingBurstRemaining < 0 {
		b.pacingBurstRemaining = 0
	}
}

// advancePacing advances the ordinary transmission pacing clock.
func (b *bbr3CongestionControl) advancePacing(bytes, mss int, now time.Time) {
	b.advancePacingAt(bytes, mss, now, true)
}

// advanceRetransmissionPacing advances pacing without consuming new-data burst credit.
func (b *bbr3CongestionControl) advanceRetransmissionPacing(bytes, mss int, now time.Time) {
	b.pacingWakeDeadline = time.Time{}
	b.consumePacingBurst(bytes)
	b.advancePacingAt(bytes, mss, now, false)
}

// advancePacingAt updates the pacing deadline with optional scheduler catch-up.
func (b *bbr3CongestionControl) advancePacingAt(bytes, mss int, now time.Time, catchUp bool) {
	rate := b.effectivePacingRate()
	if bytes <= 0 || rate <= 0 {
		return
	}
	delay := pacingDuration(bytes, rate)
	maximumDebt := bbrSendQuantumDuration(rate, mss)
	b.nextSend = pacingScheduleBase(b.nextSend, now, maximumDebt, catchUp).Add(delay)
}

// resetPacer clears pacing deadline, residual credit, and initial burst state.
func (b *bbr3CongestionControl) resetPacer() {
	b.nextSend = time.Time{}
	b.pacingWakeDeadline = time.Time{}
	b.pacingBurstRemaining = 0
}

// onDeliverySend records an idle restart and returns the packet-state inflight snapshot.
func (b *bbr3CongestionControl) onDeliverySend(now time.Time, packetsOut, window uint32) uint32 {
	if packetsOut == 0 {
		b.resetPacer()
		if b.applicationLimited {
			b.idleRestart = true
			if b.mode == bbrProbeBandwidth && b.maximumBandwidth() > 0 {
				b.pacingRate = b.effectiveBandwidth() * bbrPacingMargin
			}
		}
		b.ackEpochStamp = now
		b.ackEpochBytes = 0
	}
	if packetsOut == 0 && b.idleRestart && b.mode == bbrProbeRTT && !b.probeDone.IsZero() && !now.Before(b.probeDone) {
		b.probeRTTStamp = now
		if window < b.priorWindow {
			window = b.priorWindow
		}
		b.exitProbeRTT(now)
	}
	return window
}

// saveWindow checkpoints model and window state before recovery or ProbeRTT.
func (b *bbr3CongestionControl) saveWindow(window uint32) {
	if !b.recovery && !b.lossRecovery {
		b.undoBounds = true
		b.undoBandwidthLow = b.bandwidthLow
		b.undoInflightLow = b.inflightLow
		b.undoInflightHigh = b.inflightHigh
	}
	if !b.recovery && !b.lossRecovery && b.mode != bbrProbeRTT {
		b.priorWindow = window
	} else if window > b.priorWindow {
		b.priorWindow = window
	}
}

// undoRecovery restores model state after Eifel or DSACK proves recovery spurious.
func (b *bbr3CongestionControl) undoRecovery() {
	b.resetFullBandwidth()
	b.recovery = false
	b.lossRecovery = false
	b.packetConservation = false
	b.lossInRound = false
	b.lossEventsInRound = 0
	if b.undoBounds {
		b.bandwidthLow = bbr3WiderFloatBound(b.bandwidthLow, b.undoBandwidthLow)
		b.inflightLow = bbr3WiderBound(b.inflightLow, b.undoInflightLow)
		b.inflightHigh = bbr3WiderBound(b.inflightHigh, b.undoInflightHigh)
		b.undoBounds = false
	}
}

// bbr3WiderBound combines optional integer bounds by choosing the less restrictive.
func bbr3WiderBound(left, right uint32) uint32 {
	if left == 0 || right == 0 {
		return 0
	}
	if right > left {
		return right
	}
	return left
}

// bbr3WiderFloatBound combines optional floating bounds by choosing the larger.
func bbr3WiderFloatBound(left, right float64) float64 {
	if left == 0 || right == 0 {
		return 0
	}
	if right > left {
		return right
	}
	return left
}
