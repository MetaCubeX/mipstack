package mipstack

import "time"

// tcpDeliveryTimestamp is a wrapping microsecond timestamp. Every sampled interval is
// bounded by current flight or an idle restart, so modulo subtraction remains
// valid across its approximately 71-minute wrap interval.
type tcpDeliveryTimestamp uint32

// tcpDeliveryTimestampAt compacts a stack-relative nanosecond stamp.
func tcpDeliveryTimestampAt(stamp monotonicStamp) tcpDeliveryTimestamp {
	if stamp == 0 {
		return 0
	}
	value := tcpDeliveryTimestamp((uint64(stamp)-1)/uint64(time.Microsecond)) + 1
	if value == 0 {
		return 1
	}
	return value
}

// tcpDeliveryTimestampDuration returns a modulo-safe microsecond interval.
func tcpDeliveryTimestampDuration(later, earlier tcpDeliveryTimestamp) time.Duration {
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
	tcpDeliveryApplicationLimited = uint32(1) << 31
	tcpDeliveryDeliveredMask      = tcpDeliveryApplicationLimited - 1
)

// tcpDeliverySnapshot is Linux tcp_rate_skb_sent's per-transmission delivery
// snapshot. Compact stamps and a packed flag keep it at 12 bytes.
type tcpDeliverySnapshot struct {
	firstSent      tcpDeliveryTimestamp
	deliveredStamp tcpDeliveryTimestamp
	deliveredFlags uint32
}

// delivered returns the byte counter without its packed flag.
func (s tcpDeliverySnapshot) delivered() uint32 { return s.deliveredFlags & tcpDeliveryDeliveredMask }

// applicationLimited reports the packed Linux app-limited snapshot bit.
func (s tcpDeliverySnapshot) applicationLimited() bool {
	return s.deliveredFlags&tcpDeliveryApplicationLimited != 0
}

// tcpDeliveryAfterEqual compares the 31-bit delivery counter while its
// unambiguous half-range remains at least the maximum TCP flight size.
func tcpDeliveryAfterEqual(value, reference uint32) bool {
	delta := (value - reference) & tcpDeliveryDeliveredMask
	return delta == 0 || delta < tcpDeliveryApplicationLimited/2
}

// CongestionRateSample is one ACK's read-only delivery-rate observation.
// Its interval is the longer of the send and acknowledgement phases. Valid
// reports false when TCP could not form an unambiguous rate sample; ACK and
// loss accounting remain usable. Rates use bytes because mipstack's SACK
// scoreboard is byte exact.
//
// TCP owns this value. A controller may read it only while handling the event
// that supplied it and must not retain its pointer. Accessors deliberately
// hide transport-only sequence and timestamp selection metadata so future
// sampler changes do not alter the public congestion-control contract.
type CongestionRateSample struct {
	priorDelivered      uint32
	priorDeliveredTotal uint64
	delivered           uint32
	acked               uint32
	losses              uint64
	priorInFlight       uint32
	inFlight            uint32
	interval            time.Duration
	rtt                 time.Duration
	smoothedRTT         time.Duration
	ackTime             time.Time
	ackStamp            tcpDeliveryTimestamp
	lastSent            monotonicStamp
	lastEnd             uint32
	applicationLimited  bool
	schedulerLimited    bool
	retransmitted       bool
	recovery            bool
	fastRecovery        bool
	ackDelayed          bool
	valid               bool
	firstSent           tcpDeliveryTimestamp
	priorStamp          tcpDeliveryTimestamp
}

// tcpDeliveryRateSample is the transport's name for its public read-only view.
// The alias lets the built-in algorithms share the sample without conversion.
type tcpDeliveryRateSample = CongestionRateSample

// PriorDeliveredBytes returns the cumulative delivered-byte count captured
// when the sampled range was transmitted.
func (s *CongestionRateSample) PriorDeliveredBytes() uint64 { return s.priorDeliveredTotal }

// DeliveredBytes returns bytes delivered since the sampled transmission's
// delivery snapshot.
func (s *CongestionRateSample) DeliveredBytes() uint32 { return s.delivered }

// AcknowledgedBytes returns the cumulative ACK byte advance.
func (s *CongestionRateSample) AcknowledgedBytes() uint32 { return s.acked }

// LostBytes returns the bytes newly proven lost by this sample.
func (s *CongestionRateSample) LostBytes() uint64 { return s.losses }

// PriorBytesInFlight returns flight immediately before ACK processing.
func (s *CongestionRateSample) PriorBytesInFlight() uint32 { return s.priorInFlight }

// BytesInFlight returns flight after ACK processing and transmissions caused
// by the same ACK.
func (s *CongestionRateSample) BytesInFlight() uint32 { return s.inFlight }

// Interval returns the rate interval selected from the send and ACK phases.
func (s *CongestionRateSample) Interval() time.Duration { return s.interval }

// RTT returns the selected range's round-trip time when unambiguous.
func (s *CongestionRateSample) RTT() time.Duration { return s.rtt }

// SmoothedRTT returns the current RFC 6298 smoothed round-trip time.
func (s *CongestionRateSample) SmoothedRTT() time.Duration { return s.smoothedRTT }

// ACKTime returns packet ingress time rather than later processing time.
func (s *CongestionRateSample) ACKTime() time.Time { return s.ackTime }

// ApplicationLimited reports a sender bubble in the sampled interval.
func (s *CongestionRateSample) ApplicationLimited() bool { return s.applicationLimited }

// SchedulerLimited reports material local scheduling delay in the interval.
func (s *CongestionRateSample) SchedulerLimited() bool { return s.schedulerLimited }

// Retransmitted reports ambiguous delivery through a retransmitted range.
func (s *CongestionRateSample) Retransmitted() bool { return s.retransmitted }

// InRecovery reports fast- or timeout-recovery processing for this ACK.
func (s *CongestionRateSample) InRecovery() bool { return s.recovery }

// InFastRecovery reports fast recovery specifically.
func (s *CongestionRateSample) InFastRecovery() bool { return s.fastRecovery }

// ACKDelayed reports a lone runt sample likely delayed by the receiver.
func (s *CongestionRateSample) ACKDelayed() bool { return s.ackDelayed }

// Valid reports whether DeliveredBytes divided by Interval is a usable rate.
func (s *CongestionRateSample) Valid() bool { return s.valid }

// tcpDeliveryRateEstimator owns Linux-style connection delivery accounting.
// Model-based controllers embed it so the TCP actor can build one common rate
// sample without depending on an algorithm's private path model.
type tcpDeliveryRateEstimator struct {
	delivered               uint64
	deliveredStamp          tcpDeliveryTimestamp
	firstSent               tcpDeliveryTimestamp
	applicationLimitedUntil uint64
	schedulerLimitedUntil   uint64
	schedulerLimitedEvents  uint64
	totalLost               uint64
	sampledLost             uint64
}

// initializeDelivery seeds a new estimator at the connection's current
// monotonic timestamp.
func (d *tcpDeliveryRateEstimator) initializeDelivery(_ time.Time, _ time.Duration, stamp monotonicStamp) {
	d.restartFlight(stamp)
}

// observe retains delivery metadata from the most recently transmitted range
// newly acknowledged by the cumulative ACK or SACK scoreboard.
func (s *tcpDeliveryRateSample) observe(segment sentTCPSegment) {
	snapshot := segment.delivery
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
	s.schedulerLimited = segment.deliverySchedulerLimited
	s.retransmitted = segment.transmissions > 1
}

// finishRateSample advances delivery accounting and validates the sample using
// the longer of its send and ACK phases, as Linux tcp_rate_gen does.
func (d *tcpDeliveryRateEstimator) finishRateSample(sample *tcpDeliveryRateSample, acknowledged uint32, priorInFlight, inFlight uint32, now time.Time, nowStamp monotonicStamp, minimumRTT, smoothedRTT, sampleRTT time.Duration) {
	sample.acked = acknowledged
	sample.priorInFlight = priorInFlight
	sample.inFlight = inFlight
	sample.ackTime = now
	sample.rtt = sampleRTT
	sample.smoothedRTT = smoothedRTT
	sample.losses = d.totalLost - d.sampledLost
	d.sampledLost = d.totalLost
	if acknowledged != 0 {
		d.delivered += uint64(acknowledged)
		d.deliveredStamp = tcpDeliveryTimestampAt(nowStamp)
	}
	sample.ackStamp = d.deliveredStamp
	if d.applicationLimitedUntil != 0 && d.delivered > d.applicationLimitedUntil {
		d.applicationLimitedUntil = 0
	}
	if d.schedulerLimitedUntil != 0 && d.delivered > d.schedulerLimitedUntil {
		d.schedulerLimitedUntil = 0
	}
	if sample.priorStamp == 0 {
		return
	}
	// tcp_rate_skb_delivered advances first_tx_mstamp to the transmit time of
	// the newest range selected for this ACK. Future packets snapshot this new
	// boundary so their send phase does not grow from the connection's first
	// flight forever.
	compactNow := tcpDeliveryTimestampAt(nowStamp)
	compactSent := tcpDeliveryTimestampAt(sample.lastSent)
	d.firstSent = compactSent
	if !sample.retransmitted {
		if selectedRTT := tcpDeliveryTimestampDuration(compactNow, compactSent); selectedRTT > 0 {
			sample.rtt = selectedRTT
		}
	}
	sample.delivered = (uint32(d.delivered) - sample.priorDelivered) & tcpDeliveryDeliveredMask
	sample.priorDeliveredTotal = d.delivered - uint64(sample.delivered)
	sendInterval := tcpDeliveryTimestampDuration(compactSent, sample.firstSent)
	ackInterval := tcpDeliveryTimestampDuration(compactNow, sample.priorStamp)
	if ackInterval > sendInterval {
		sendInterval = ackInterval
	}
	if sendInterval <= 0 || minimumRTT > 0 && sendInterval < minimumRTT {
		return
	}
	sample.interval = sendInterval
	sample.valid = true
}

// noteLoss records bytes newly declared lost for the next rate sample.
func (d *tcpDeliveryRateEstimator) noteLoss(bytes uint32) {
	d.totalLost += uint64(bytes)
}

// recordLoss records one loss event and prevents timer-consumed loss from
// being repeated by the next ACK-generated sample.
func (d *tcpDeliveryRateEstimator) recordLoss(bytes uint32, duringACK bool) {
	d.noteLoss(bytes)
	if !duringACK {
		d.sampledLost = d.totalLost
	}
}

// markApplicationLimited records the delivery boundary that drains a sender bubble.
func (d *tcpDeliveryRateEstimator) markApplicationLimited(flight uint32) {
	limit := d.delivered + uint64(flight)
	if limit == 0 {
		limit = 1
	}
	d.applicationLimitedUntil = limit
}

// markSchedulerLimited records a delivery boundary whose samples include a
// material userspace scheduling delay rather than a path limitation.
func (d *tcpDeliveryRateEstimator) markSchedulerLimited(flight uint32) {
	limit := d.delivered + uint64(flight)
	if limit == 0 {
		limit = 1
	}
	if limit > d.schedulerLimitedUntil {
		d.schedulerLimitedUntil = limit
	}
	d.schedulerLimitedEvents++
}

// schedulerLimited reports whether new transmissions still belong to a
// scheduler-limited delivery interval.
func (d *tcpDeliveryRateEstimator) schedulerLimited() bool {
	return d.schedulerLimitedUntil != 0
}

// restartFlight starts delivery timestamps for a newly nonempty flight.
func (d *tcpDeliveryRateEstimator) restartFlight(stamp monotonicStamp) {
	compactStamp := tcpDeliveryTimestampAt(stamp)
	d.firstSent = compactStamp
	d.deliveredStamp = compactStamp
}

// snapshot captures the current delivery state for one transmitted range.
func (d *tcpDeliveryRateEstimator) snapshot() tcpDeliverySnapshot {
	deliveredFlags := uint32(d.delivered) & tcpDeliveryDeliveredMask
	if d.applicationLimitedUntil != 0 {
		deliveredFlags |= tcpDeliveryApplicationLimited
	}
	return tcpDeliverySnapshot{firstSent: d.firstSent, deliveredStamp: d.deliveredStamp, deliveredFlags: deliveredFlags}
}

// onDeliveryDataSent returns the common snapshot for one original
// transmission. A newly nonempty flight restarts both pipeline timestamps.
func (d *tcpDeliveryRateEstimator) onDeliveryDataSent(_, _ int, _ time.Time, stamp monotonicStamp, packetsOut, window uint32) (tcpDeliverySnapshot, uint32) {
	if packetsOut == 0 {
		d.restartFlight(stamp)
	}
	return d.snapshot(), window
}

// onDeliveryRetransmit returns the common snapshot for a retransmitted range.
func (d *tcpDeliveryRateEstimator) onDeliveryRetransmit(_, _ int, _ time.Time, stamp monotonicStamp, packetsOut uint32) tcpDeliverySnapshot {
	if packetsOut == 0 {
		d.restartFlight(stamp)
	}
	return d.snapshot()
}

// snapshotSend captures common delivery state for a range whose snapshot must
// be refreshed after ACK processing sends more data.
func (d *tcpDeliveryRateEstimator) snapshotSend(stamp monotonicStamp, packetsOut uint32) tcpDeliverySnapshot {
	if packetsOut == 0 {
		d.restartFlight(stamp)
	}
	return d.snapshot()
}
