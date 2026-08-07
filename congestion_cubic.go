package mipstack

import (
	"math"
	"time"
)

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
	recovery           cubicRecoveryCheckpoint
}

// cubicRecoveryCheckpoint is the private CUBIC state restored after Eifel or
// DSACK proves that a congestion episode was spurious.
type cubicRecoveryCheckpoint struct {
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
	valid              bool
}

// newCUBICCongestionControl constructs one independent CUBIC controller.
func newCUBICCongestionControl() *cubicCongestionControl {
	return &cubicCongestionControl{}
}

// HandleCongestionEvent implements CongestionController.
func (c *cubicCongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	switch event.Type {
	case CongestionEventACK:
		event.State.CongestionWindow = c.increaseOnACK(
			event.State.CongestionWindow,
			event.Acknowledged,
			event.State.MaximumSegmentSize,
			event.Time,
			event.State.SmoothedRTT,
			event.State.BytesInFlight,
			event.State.SlowStartThreshold,
		)
	case CongestionEventLoss:
		event.State.SlowStartThreshold = c.onCongestion(event.State.CongestionWindow, event.State.MaximumSegmentSize)
	case CongestionEventECN:
		threshold := c.onECN(event.State.CongestionWindow, event.State.MaximumSegmentSize)
		event.State.SlowStartThreshold = threshold
		event.State.CongestionWindow = threshold
	case CongestionEventTimeout:
		event.State.SlowStartThreshold = c.onTimeout(event.State.CongestionWindow, event.State.MaximumSegmentSize)
	case CongestionEventPacketSent:
		c.onSend(event.Time, event.State.BytesInFlight)
	case CongestionEventRecovery:
		switch event.Recovery.Stage {
		case CongestionRecoveryCheckpoint:
			c.saveRecoveryCheckpoint()
		case CongestionRecoveryUndo:
			c.restoreRecoveryCheckpoint()
		}
	case CongestionEventMTUChanged:
		*c = cubicCongestionControl{}
	}
}

func (c *cubicCongestionControl) increaseOnACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT time.Duration, flight, slowStartThreshold uint32) uint32 {
	if !congestionWindowLimited(window, flight, mss) {
		c.onApplicationLimited(now)
		return window
	}
	window, acknowledged = applySlowStart(window, acknowledged, slowStartThreshold)
	if acknowledged == 0 {
		return window
	}
	return c.onACK(window, acknowledged, mss, now, smoothedRTT)
}

// saveRecoveryCheckpoint snapshots only algorithm-private state. TCP retains
// cwnd, ssthresh, RTT, and flight independently.
func (c *cubicCongestionControl) saveRecoveryCheckpoint() {
	c.recovery = cubicRecoveryCheckpoint{
		epochStart: c.epochStart, lastSend: c.lastSend, applicationLimited: c.applicationLimited,
		lastMaximum: c.lastMaximum, priorWindow: c.priorWindow, estimate: c.estimate,
		origin: c.origin, k: c.k, credit: c.credit, afterTimeout: c.afterTimeout, valid: true,
	}
}

// restoreRecoveryCheckpoint restores CUBIC's pre-recovery growth epoch.
func (c *cubicCongestionControl) restoreRecoveryCheckpoint() {
	checkpoint := c.recovery
	if !checkpoint.valid {
		return
	}
	c.epochStart = checkpoint.epochStart
	c.lastSend = checkpoint.lastSend
	c.applicationLimited = checkpoint.applicationLimited
	c.lastMaximum = checkpoint.lastMaximum
	c.priorWindow = checkpoint.priorWindow
	c.estimate = checkpoint.estimate
	c.origin = checkpoint.origin
	c.k = checkpoint.k
	c.credit = checkpoint.credit
	c.afterTimeout = checkpoint.afterTimeout
	c.recovery.valid = false
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
