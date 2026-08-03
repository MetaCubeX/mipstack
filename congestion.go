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
	algorithm CongestionControl
	cubic     cubicCongestionControl
	bbr       bbrCongestionControl
}

// newTCPCongestionController constructs one per-connection controller.
func newTCPCongestionController(algorithm CongestionControl) tcpCongestionController {
	return tcpCongestionController{algorithm: algorithm}
}

// onCongestion computes the slow-start threshold after loss or ECN feedback.
func (c *tcpCongestionController) onCongestion(window uint32, mss int) uint32 {
	switch c.algorithm {
	case CongestionControlReno:
		return congestionThreshold(window, mss, 1, 2)
	case CongestionControlBBR:
		c.bbr.nextSend = time.Time{}
		return congestionThreshold(window, mss, 7, 10)
	default:
		return c.cubic.onCongestion(window, mss)
	}
}

// onACK advances slow start or the selected congestion-avoidance model.
func (c *tcpCongestionController) onACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight uint32, slowStart bool) uint32 {
	if window == 0 || acknowledged == 0 || mss < 1 {
		return window
	}
	switch c.algorithm {
	case CongestionControlReno:
		if slowStart {
			return growCongestionWindow(window, acknowledged)
		}
		return growCongestionWindow(window, additiveIncrease(window, acknowledged, mss))
	case CongestionControlBBR:
		return c.bbr.onACK(window, acknowledged, mss, now, smoothedRTT, sampleRTT, flight)
	default:
		if slowStart {
			return growCongestionWindow(window, acknowledged)
		}
		return c.cubic.onACK(window, acknowledged, mss, now, smoothedRTT)
	}
}

// pacingDelay returns the remaining BBR pacing interval. Reno and CUBIC are
// ACK-clocked and return zero.
func (c *tcpCongestionController) pacingDelay(now time.Time) time.Duration {
	if c.algorithm != CongestionControlBBR {
		return 0
	}
	return c.bbr.pacingDelay(now)
}

// onSend advances BBR's pacing clock after a first transmission.
func (c *tcpCongestionController) onSend(bytes int, now time.Time) {
	if c.algorithm == CongestionControlBBR {
		c.bbr.onSend(bytes, now)
	}
}

// onMTUChange resets packet-size-dependent epochs without discarding BBR's
// path bandwidth and RTT model.
func (c *tcpCongestionController) onMTUChange() {
	c.cubic = cubicCongestionControl{}
	c.bbr.nextSend = time.Time{}
}

// congestionThreshold applies one multiplicative decrease with the RFC 5681
// two-segment floor.
func congestionThreshold(window uint32, mss, numerator, denominator int) uint32 {
	threshold := uint32(uint64(window) * uint64(numerator) / uint64(denominator))
	if minimum := uint32(2 * mss); threshold < minimum {
		threshold = minimum
	}
	return threshold
}

// additiveIncrease computes byte-counted Reno congestion avoidance.
func additiveIncrease(window, acknowledged uint32, mss int) uint32 {
	increment := uint32(uint64(acknowledged) * uint64(mss) / uint64(window))
	if increment == 0 {
		return 1
	}
	return increment
}

// cubicCongestionControl retains the CUBIC epoch and previous maximum window.
// Windows are stored in bytes; floating-point arithmetic is confined to the
// actor goroutine and only evaluates the RFC 9438 growth curve.
type cubicCongestionControl struct {
	epochStart  time.Time
	lastMaximum float64
	origin      float64
	k           float64
}

// onCongestion applies CUBIC's beta=0.7 decrease and resets the growth epoch.
func (c *cubicCongestionControl) onCongestion(window uint32, mss int) uint32 {
	current := float64(window) / float64(mss)
	if c.lastMaximum != 0 && current < c.lastMaximum {
		c.lastMaximum = current * 0.85
	} else {
		c.lastMaximum = current
	}
	c.epochStart = time.Time{}
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
		if c.lastMaximum > current {
			c.origin = c.lastMaximum
			c.k = math.Cbrt((c.lastMaximum - current) / 0.4)
		} else {
			c.origin = current
			c.k = 0
		}
	}
	elapsed := now.Sub(c.epochStart).Seconds() + smoothedRTT.Seconds()
	target := 0.4*math.Pow(elapsed-c.k, 3) + c.origin
	increment := additiveIncrease(window, acknowledged, mss)
	if target > current {
		candidateValue := float64(acknowledged) * (target - current) / current
		if candidateValue > float64(mss) {
			candidateValue = float64(mss)
		}
		if candidate := uint32(candidateValue); candidate > increment {
			increment = candidate
		}
	}
	return growCongestionWindow(window, increment)
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
	lastACK          time.Time

	minimumRTT      time.Duration
	minimumRTTStamp time.Time
	roundBytes      uint32
	roundTarget     uint32
	fullBandwidth   float64
	fullRounds      int

	cycleIndex int
	cycleStamp time.Time
	probeDone  time.Time
	nextSend   time.Time
}

// onACK updates BBR's delivery model, state machine, and congestion window.
func (b *bbrCongestionControl) onACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT, sampleRTT time.Duration, flight uint32) uint32 {
	if sampleRTT > 0 && (b.minimumRTT == 0 || sampleRTT < b.minimumRTT) {
		b.minimumRTT, b.minimumRTTStamp = sampleRTT, now
	}
	b.observeBandwidth(acknowledged, now, smoothedRTT, flight)
	b.advanceRound(window, acknowledged)
	if b.mode != bbrProbeRTT && b.minimumRTT != 0 && now.Sub(b.minimumRTTStamp) >= bbrMinRTTWindow {
		b.mode = bbrProbeRTT
		b.probeDone = now.Add(bbrProbeRTTDuration)
		b.nextSend = time.Time{}
	}
	bdp := b.bandwidthDelayProduct()
	switch b.mode {
	case bbrStartup:
		if b.fullRounds >= bbrFullBandwidthRounds {
			b.mode = bbrDrain
		}
	case bbrDrain:
		if bdp > 0 && flight <= uint32(bdp) {
			b.mode = bbrProbeBandwidth
			b.cycleIndex = 0
			b.cycleStamp = now
		}
	case bbrProbeBandwidth:
		if b.minimumRTT > 0 && now.Sub(b.cycleStamp) >= b.minimumRTT {
			b.cycleIndex = (b.cycleIndex + 1) % len(bbrProbeBandwidthGains)
			b.cycleStamp = now
		}
	case bbrProbeRTT:
		if !now.Before(b.probeDone) {
			b.minimumRTTStamp = now
			b.mode = bbrProbeBandwidth
			b.cycleIndex = 0
			b.cycleStamp = now
		}
	}
	minimum := uint32(bbrMinimumCongestionMSS * mss)
	if b.mode == bbrProbeRTT {
		return minimum
	}
	target := minimum
	if bdp > 0 {
		modelTarget := uint64(float64(bdp) * bbrCongestionWindowGain)
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
	} else if b.mode == bbrDrain && window > target {
		window = target
	}
	return window
}

// observeBandwidth accumulates the largest ACK-rate sample in the current
// packet-timed round. advanceRound installs it in the ten-round max filter.
func (b *bbrCongestionControl) observeBandwidth(acknowledged uint32, now time.Time, rtt time.Duration, flight uint32) {
	sample := float64(0)
	if !b.lastACK.IsZero() && now.After(b.lastACK) {
		interval := now.Sub(b.lastACK).Seconds()
		sample = float64(acknowledged) / interval
		if rtt > 0 && flight > 0 {
			upper := float64(flight) / rtt.Seconds()
			if sample > upper {
				sample = upper
			}
		}
	} else if rtt > 0 {
		sample = float64(acknowledged) / rtt.Seconds()
	}
	if sample > b.roundBandwidth {
		b.roundBandwidth = sample
	}
	if sample > b.bandwidth {
		b.bandwidth = sample
	}
	b.lastACK = now
}

// advanceRound detects BBR bandwidth plateaus once per congestion-window's
// worth of acknowledged data.
func (b *bbrCongestionControl) advanceRound(window, acknowledged uint32) {
	if b.roundTarget == 0 {
		b.roundTarget = window
	}
	b.roundBytes += acknowledged
	if b.roundBytes < b.roundTarget {
		return
	}
	b.roundBytes = 0
	b.roundTarget = window
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
	}
	if b.bandwidth >= b.fullBandwidth*bbrFullBandwidthGrowth {
		b.fullBandwidth = b.bandwidth
		b.fullRounds = 0
	} else {
		b.fullRounds++
	}
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
func (b *bbrCongestionControl) pacingDelay(now time.Time) time.Duration {
	if b.bandwidth <= 0 || b.nextSend.IsZero() || !now.Before(b.nextSend) {
		return 0
	}
	return b.nextSend.Sub(now)
}

// onSend advances BBR's packet pacing clock.
func (b *bbrCongestionControl) onSend(bytes int, now time.Time) {
	rate := b.bandwidth * b.pacingGain()
	if bytes <= 0 || rate <= 0 {
		return
	}
	base := b.nextSend
	if base.Before(now) {
		base = now
	}
	delay := time.Duration(float64(time.Second) * float64(bytes) / rate)
	if delay < time.Microsecond {
		delay = time.Microsecond
	}
	b.nextSend = base.Add(delay)
}
