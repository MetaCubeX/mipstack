package mipstack

// renoCongestionControl retains Reno's fractional byte-counted ACK credit.
type renoCongestionControl struct {
	credit           float64
	recoveryCredit   float64
	recoverySnapshot bool
}

// newRenoCongestionControl constructs one independent Reno controller.
func newRenoCongestionControl() *renoCongestionControl {
	return &renoCongestionControl{}
}

// HandleCongestionEvent implements CongestionController.
func (r *renoCongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	switch event.Type {
	case CongestionEventACK:
		event.State.CongestionWindow = r.increaseOnACK(
			event.State.CongestionWindow,
			event.Acknowledged,
			event.State.MaximumSegmentSize,
			event.State.BytesInFlight,
			event.State.SlowStartThreshold,
		)
	case CongestionEventLoss:
		event.State.SlowStartThreshold = r.reduceOnLoss(event.State.BytesInFlight, event.State.MaximumSegmentSize)
	case CongestionEventECN:
		threshold := r.reduceOnECN(event.State.BytesInFlight, event.State.MaximumSegmentSize)
		event.State.SlowStartThreshold = threshold
		event.State.CongestionWindow = threshold
	case CongestionEventTimeout:
		event.State.SlowStartThreshold = r.reduceOnTimeout(event.State.BytesInFlight, event.State.MaximumSegmentSize)
	case CongestionEventRecovery:
		switch event.Recovery.Stage {
		case CongestionRecoveryCheckpoint:
			r.recoveryCredit = r.credit
			r.recoverySnapshot = true
		case CongestionRecoveryUndo:
			if r.recoverySnapshot {
				r.credit = r.recoveryCredit
			}
			r.recoverySnapshot = false
		}
	case CongestionEventMTUChanged:
		r.credit = 0
		r.recoverySnapshot = false
	}
}

// reduceOnLoss returns the RFC 5681 fast-loss slow-start threshold.
func (r *renoCongestionControl) reduceOnLoss(flight uint32, mss int) uint32 {
	r.credit = 0
	// RFC 5681 defines the threshold from FlightSize, not cwnd. They differ
	// when the sender is application- or receive-window-limited.
	return congestionThreshold(flight, mss, 1, 2)
}

// reduceOnECN returns the ECN response threshold with its one-MSS floor.
func (r *renoCongestionControl) reduceOnECN(flight uint32, mss int) uint32 {
	r.credit = 0
	return congestionThresholdWithFloor(flight, mss, 1, 2, 1)
}

// reduceOnTimeout returns the RFC 5681 timeout slow-start threshold.
func (r *renoCongestionControl) reduceOnTimeout(flight uint32, mss int) uint32 {
	r.credit = 0
	return congestionThreshold(flight, mss, 1, 2)
}

// increaseOnACK applies slow start or Reno additive increase to one ACK.
func (r *renoCongestionControl) increaseOnACK(window, acknowledged uint32, mss int, flight, slowStartThreshold uint32) uint32 {
	if !congestionWindowLimited(window, flight, mss) {
		return window
	}
	window, acknowledged = applySlowStart(window, acknowledged, slowStartThreshold)
	if acknowledged == 0 {
		return window
	}
	return applyCongestionIncrease(window, &r.credit, additiveIncrease(window, acknowledged, mss))
}

// applySlowStart grows at most to ssthresh and returns ACK credit left for
// congestion avoidance, matching Linux tcp_slow_start.
func applySlowStart(window, acknowledged, slowStartThreshold uint32) (uint32, uint32) {
	if window >= slowStartThreshold {
		return window, acknowledged
	}
	growth := acknowledged
	if available := slowStartThreshold - window; growth > available {
		growth = available
	}
	return growCongestionWindow(window, growth), acknowledged - growth
}
