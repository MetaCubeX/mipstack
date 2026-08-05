package mipstack

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestCUBICCongestionControl(t *testing.T) {
	const mss = 1200
	controller := newTCPCongestionController(CongestionControlCUBIC)
	if threshold := controller.onCongestion(12000, 9000, mss); threshold != 8400 {
		t.Fatalf("CUBIC threshold = %d, want 8400", threshold)
	}
	start := time.Unix(100, 0)
	window := uint32(8400)
	first := controller.onACK(window, mss, mss, start, 20*time.Millisecond, 20*time.Millisecond, window, false)
	if first <= window {
		t.Fatalf("CUBIC first window = %d, want > %d", first, window)
	}
	later := controller.onACK(first, 10*mss, mss, start.Add(3*time.Second), 20*time.Millisecond, 20*time.Millisecond, first, false)
	if later <= first {
		t.Fatalf("CUBIC later window = %d, want > %d", later, first)
	}
}

func TestCUBICFastConvergenceComparesAdjustedMaximum(t *testing.T) {
	const mss = 1000
	var cubic cubicCongestionControl
	cubic.onCongestion(100*mss, mss)
	if cubic.lastMaximum != 100 {
		t.Fatalf("first congestion Wmax=%v, want 100", cubic.lastMaximum)
	}
	cubic.onCongestion(80*mss, mss)
	if cubic.lastMaximum != 68 {
		t.Fatalf("second congestion Wmax=%v, want 68", cubic.lastMaximum)
	}
	cubic.onCongestion(70*mss, mss)
	if cubic.lastMaximum != 70 {
		t.Fatalf("third congestion Wmax=%v, want 70", cubic.lastMaximum)
	}
}

func TestRenoCongestionControl(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	if threshold := controller.onCongestion(12000, 9000, mss); threshold != 4500 {
		t.Fatalf("Reno threshold = %d, want 4500", threshold)
	}
	window := uint32(10000)
	if grown := controller.onACK(window, 2*mss, mss, time.Time{}, 0, 0, window, true); grown != 12000 {
		t.Fatalf("Reno slow-start window = %d, want 12000", grown)
	}
	if grown := controller.onACK(window, mss, mss, time.Time{}, 0, 0, window, false); grown != 10100 {
		t.Fatalf("Reno avoidance window = %d, want 10100", grown)
	}
}

func TestHyStartPlusPlusDelayAndCSS(t *testing.T) {
	var state tcpHyStart
	state.start(1000)
	for sample := 0; sample < hyStartMinimumRTTSamples; sample++ {
		state.onACK(900, 2000, 1000, 20*time.Millisecond)
	}
	state.onACK(1000, 2000, 1000, 25*time.Millisecond)
	for sample := 1; sample < hyStartMinimumRTTSamples; sample++ {
		growth, completed := state.onACK(1100, 2000, 1000, 25*time.Millisecond)
		if completed {
			t.Fatal("HyStart++ completed before CSS")
		}
		if sample == hyStartMinimumRTTSamples-1 && (growth != 250 || !state.css || state.cssRounds != 1) {
			t.Fatalf("CSS entry growth/state = %d/%t/%d, want 250/true/1", growth, state.css, state.cssRounds)
		}
	}
	for round := 2; round <= hyStartCSSRounds; round++ {
		state.onACK(state.windowEnd, state.windowEnd+1000, 1000, 25*time.Millisecond)
	}
	if _, completed := state.onACK(state.windowEnd, state.windowEnd+1000, 1000, 25*time.Millisecond); !completed || !state.done {
		t.Fatal("HyStart++ did not leave CSS after five rounds")
	}
}

func TestHyStartPlusPlusRejectsJitterAndUserPause(t *testing.T) {
	state := tcpHyStart{
		windowEnd: 2000, lastRoundMinRTT: 20 * time.Millisecond,
		currentMinRTT: 25 * time.Millisecond, samples: hyStartMinimumRTTSamples - 1,
	}
	state.onACK(1500, 3000, 1000, 25*time.Millisecond)
	if !state.css {
		t.Fatal("delay increase did not enter CSS")
	}
	for sample := 0; sample < hyStartMinimumRTTSamples; sample++ {
		state.onACK(1600, 3000, 1000, 19*time.Millisecond)
	}
	if state.css || state.done {
		t.Fatal("lower CSS RTT did not resume ordinary slow start")
	}
	state.restartRound(4000)
	if state.lastRoundMinRTT != 0 || state.currentMinRTT != 0 || state.samples != 0 {
		t.Fatal("idle restart retained stale HyStart++ measurements")
	}
	state.disable()
	if growth, completed := state.onACK(4000, 5000, 1000, time.Second); growth != 1000 || completed {
		t.Fatalf("disabled HyStart++ result = %d/%t", growth, completed)
	}
}

func TestWindowPacingUsesLinuxRates(t *testing.T) {
	const (
		mss    = 1000
		window = uint32(10 * mss)
	)
	start := time.Unix(100, 0)
	slowStart := newTCPCongestionController(CongestionControlReno)
	slowStart.pacingSegments = tcpPacingInitialBurst - 1
	slowStart.pacingNext = start
	slowStart.onDataSend(mss, mss, start, window, window, 100*time.Millisecond, ^uint32(0))
	slowInterval := slowStart.pacingNext.Sub(start)

	avoidance := newTCPCongestionController(CongestionControlCUBIC)
	avoidance.pacingSegments = tcpPacingInitialBurst - 1
	avoidance.pacingNext = start
	avoidance.onDataSend(mss, mss, start, window, window, 100*time.Millisecond, window)
	avoidanceInterval := avoidance.pacingNext.Sub(start)

	if slowInterval < 4999*time.Microsecond || slowInterval > 5001*time.Microsecond {
		t.Fatalf("slow-start pacing interval = %v, want 5ms", slowInterval)
	}
	if avoidanceInterval < 8332*time.Microsecond || avoidanceInterval > 8334*time.Microsecond {
		t.Fatalf("congestion-avoidance pacing interval = %v, want approximately 8.333ms", avoidanceInterval)
	}
}

func TestWindowPacingDefersAfterInitialBurst(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	start := time.Unix(100, 0)
	for segment := 0; segment < tcpPacingInitialBurst+4; segment++ {
		controller.onDataSend(mss, mss, start, 10*mss, uint32(segment*mss), 100*time.Millisecond, ^uint32(0))
	}
	if delay := controller.pacingDelay(start, 10*mss, 10*mss, mss, 100*time.Millisecond, ^uint32(0)); delay <= 0 {
		t.Fatal("window-based pacer did not defer after its initial burst")
	}
}

func TestPacingScheduleRetainsBoundedLateDebt(t *testing.T) {
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	base, late := pacingScheduleBase(start, now, 2*time.Millisecond, true)
	if !late || base != now.Add(-2*time.Millisecond) {
		t.Fatalf("late pacing base/flag = %v/%v", base, late)
	}
	base, late = pacingScheduleBase(start, now, time.Millisecond, false)
	if late || base != now {
		t.Fatalf("retransmission pacing base/flag = %v/%v, want now/false", base, late)
	}
	base, late = pacingScheduleBase(now.Add(time.Millisecond), now, time.Millisecond, true)
	if late || base != now.Add(time.Millisecond) {
		t.Fatalf("early pacing base/flag = %v/%v", base, late)
	}
}

func TestBBRSendQuantumMatchesLinuxPolicy(t *testing.T) {
	const mss = 1000
	if quantum := bbrSendQuantum(100_000, mss); quantum != mss {
		t.Fatalf("low-rate send quantum = %d, want %d", quantum, mss)
	}
	if quantum := bbrSendQuantum(200_000, mss); quantum != 2*mss {
		t.Fatalf("normal-rate send quantum = %d, want %d", quantum, 2*mss)
	}
	if quantum := bbrSendQuantum(1024*100_000, mss); quantum != bbrMaximumSendQuantum {
		t.Fatalf("high-rate send quantum = %d, want %d", quantum, bbrMaximumSendQuantum)
	}
	if duration := bbrTimerQuantumDuration(1024*1024*1024, mss); duration != tcpUserspacePacingQuantum {
		t.Fatalf("high-rate timer quantum = %v, want userspace floor %v", duration, tcpUserspacePacingQuantum)
	}
}

func TestECNCongestionWindowCanReachOneSegment(t *testing.T) {
	const mss = 1000
	for _, algorithm := range []CongestionControl{CongestionControlReno, CongestionControlCUBIC} {
		t.Run(string(algorithm), func(t *testing.T) {
			controller := newTCPCongestionController(algorithm)
			if threshold := controller.onECN(mss, mss, mss); threshold != mss {
				t.Fatalf("one-segment ECN threshold = %d, want %d", threshold, mss)
			}
			controller = newTCPCongestionController(algorithm)
			if threshold := controller.onCongestion(mss, mss, mss); threshold != 2*mss {
				t.Fatalf("one-segment loss threshold = %d, want %d", threshold, 2*mss)
			}
		})
	}
}

func TestRenoCongestionAvoidanceRetainsFractionalCredit(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	window := uint32(10 * 1024 * 1024)
	initial := window
	for acknowledged := uint32(0); acknowledged < initial; acknowledged += mss {
		window = controller.onACK(window, mss, mss, time.Time{}, 0, 0, window, false)
	}
	growth := window - initial
	if growth < 900 || growth > 1100 {
		t.Fatalf("Reno growth over one window = %d, want approximately one MSS", growth)
	}
}

func TestRenoDoesNotGrowWhenApplicationLimited(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	const window = uint32(10 * mss)
	if grown := controller.onACK(window, mss, mss, time.Time{}, 0, 0, 2*mss, false); grown != window {
		t.Fatalf("application-limited Reno window = %d, want %d", grown, window)
	}
	if grown := controller.onACK(window, mss, mss, time.Time{}, 0, 0, window-mss, false); grown <= window {
		t.Fatalf("packet-granularity cwnd-limited Reno window = %d, want > %d", grown, window)
	}
}

func TestTCPRestartWindowAfterIdle(t *testing.T) {
	const mss = 1200
	initial := initialTCPWindow(mss)
	if got := tcpRestartWindow(100*mss, mss); got != initial {
		t.Fatalf("large idle window = %d, want restart window %d", got, initial)
	}
	if got := tcpRestartWindow(2*mss, mss); got != 2*mss {
		t.Fatalf("small idle window = %d, want unchanged %d", got, 2*mss)
	}
}

func TestSlowStartReturnsExcessACKCreditToCongestionAvoidance(t *testing.T) {
	const mss = 1000
	for _, algorithm := range []CongestionControl{CongestionControlReno, CongestionControlCUBIC} {
		t.Run(string(algorithm), func(t *testing.T) {
			controller := newTCPCongestionController(algorithm)
			const window = uint32(9 * mss)
			grown := controller.onACKWithThreshold(window, 2*mss, mss, time.Unix(100, 0), 20*time.Millisecond, 0, window, 10*mss, false)
			if grown < 10*mss || grown >= 11*mss {
				t.Fatalf("boundary ACK window = %d, want [10000, 11000)", grown)
			}
		})
	}
}

func TestCUBICRenoFriendlyAlpha(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	window := uint32(100 * mss)
	initial := window
	start := time.Unix(100, 0)
	for acknowledged := uint32(0); acknowledged < initial; acknowledged += mss {
		window = controller.onACK(window, mss, mss, start, 0, 0, window, false)
	}
	growth := window - initial
	if growth < 500 || growth > 560 {
		t.Fatalf("CUBIC Reno-friendly growth = %d, want approximately 9/17 MSS", growth)
	}
}

func TestCUBICEpochExcludesApplicationIdleTime(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	controller.onDataSend(mss, mss, start, window, 0, 20*time.Millisecond, ^uint32(0))
	window = controller.onACK(window, mss, mss, start.Add(time.Millisecond), 20*time.Millisecond, 20*time.Millisecond, window, false)
	epoch := controller.cubic.epochStart
	resume := start.Add(time.Hour)
	controller.onDataSend(mss, mss, resume, window, 0, 20*time.Millisecond, ^uint32(0))
	if shift := controller.cubic.epochStart.Sub(epoch); shift != resume.Sub(start) {
		t.Fatalf("CUBIC epoch shift = %v, want idle interval %v", shift, resume.Sub(start))
	}
	before := window
	window = controller.onACK(window, mss, mss, resume.Add(time.Millisecond), 20*time.Millisecond, 20*time.Millisecond, window, false)
	if window-before >= uint32(mss) {
		t.Fatalf("CUBIC grew by %d immediately after idle, want less than one MSS", window-before)
	}
}

func TestCUBICCapsTargetAndKeepsFriendlyEstimateSeparate(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlCUBIC)
	controller.cubic = cubicCongestionControl{
		epochStart: start, lastMaximum: 10, priorWindow: 20, estimate: 1,
		origin: 10,
	}
	const window = uint32(10 * mss)
	grown := controller.onACK(window, mss, mss, start.Add(time.Minute), time.Second, 0, window, false)
	if increase := grown - window; increase > mss/2 {
		t.Fatalf("CUBIC target-cap increase = %d, want <= %d", increase, mss/2)
	}
	if controller.cubic.estimate >= float64(grown)/mss {
		t.Fatalf("friendly estimate %f was incorrectly folded into CUBIC window %d", controller.cubic.estimate, grown)
	}
}

func TestCUBICTimeoutStartsNextEpochAtKZero(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	_ = controller.onCongestion(100*mss, 100*mss, mss)
	if threshold := controller.onTimeout(70*mss, 60*mss, mss); threshold != 49*mss {
		t.Fatalf("CUBIC timeout threshold = %d, want %d", threshold, 49*mss)
	}
	start := time.Unix(100, 0)
	window := uint32(49 * mss)
	_ = controller.onACK(window, mss, mss, start, 20*time.Millisecond, 0, window, false)
	if controller.cubic.k != 0 || controller.cubic.lastMaximum != 49 || controller.cubic.origin != 49 {
		t.Fatalf("CUBIC post-timeout epoch = K %f Wmax %f origin %f", controller.cubic.k, controller.cubic.lastMaximum, controller.cubic.origin)
	}
	if controller.cubic.priorWindow != 70 {
		t.Fatalf("CUBIC post-timeout cwnd_prior = %f, want 70", controller.cubic.priorWindow)
	}
	before := controller.cubic.estimate
	_ = controller.onACK(window, mss, mss, start.Add(time.Millisecond), 20*time.Millisecond, 0, window, false)
	if increase := controller.cubic.estimate - before; increase >= 1.0/float64(window/mss) {
		t.Fatalf("CUBIC post-timeout W_est increase = %f, switched to alpha=1 before cwnd_prior", increase)
	}
}

func TestCUBICEpochExcludesNonIdleApplicationLimit(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlCUBIC)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, mss, mss, start, 20*time.Millisecond, 0, window, false)
	epoch := controller.cubic.epochStart
	limitedAt := start.Add(time.Second)
	if got := controller.onACK(window, mss, mss, limitedAt, 20*time.Millisecond, 0, 2*mss, false); got != window {
		t.Fatalf("application-limited CUBIC window = %d, want %d", got, window)
	}
	resume := start.Add(time.Hour)
	controller.onDataSend(mss, mss, resume, window, mss, 20*time.Millisecond, ^uint32(0))
	if shift := controller.cubic.epochStart.Sub(epoch); shift != resume.Sub(limitedAt) {
		t.Fatalf("application-limited epoch shift = %v, want %v", shift, resume.Sub(limitedAt))
	}
}

func TestBBRCongestionControl(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, 2*mss, mss, start, 100*time.Millisecond, 100*time.Millisecond, window, true)
	if controller.bbr.bandwidth != 100000 {
		t.Fatalf("BBR initial bandwidth = %v, want 100000", controller.bbr.bandwidth)
	}
	controller.onDataSend(mss, mss, start, window, 0, 100*time.Millisecond, ^uint32(0))
	if delay := controller.pacingDelay(start, window, 0, mss, 100*time.Millisecond, ^uint32(0)); delay >= 100*time.Millisecond {
		t.Fatalf("BBR startup pacing delay = %v, want less than 100ms", delay)
	}
	for round := 0; round < 4; round++ {
		controller.bbr.roundTarget = mss
		window = controller.onACK(window, mss, mss, start.Add(time.Duration(round+1)*100*time.Millisecond), 100*time.Millisecond, 100*time.Millisecond, window, false)
	}
	if controller.bbr.mode == bbrStartup {
		t.Fatal("BBR remained in Startup after a sustained bandwidth plateau")
	}
	controller.bbr.mode = bbrProbeBandwidth
	controller.bbr.minimumRTTStamp = start.Add(-bbrMinRTTWindow)
	window = controller.onACK(window, mss, mss, start.Add(time.Second), 100*time.Millisecond, 100*time.Millisecond, mss, false)
	if controller.bbr.mode != bbrProbeRTT || window != bbrMinimumCongestionMSS*mss {
		t.Fatalf("BBR ProbeRTT state/window = %v/%d", controller.bbr.mode, window)
	}
}

func TestBBRApplicationLimitedRoundsDoNotEndStartup(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.bandwidth = 100000
	controller.bbr.fullBandwidth = 100000
	for round := 0; round < bbrFullBandwidthRounds+2; round++ {
		controller.bbr.roundTarget = mss
		controller.bbr.roundBandwidth = 100000
		if !controller.bbr.advanceRound(10*mss, mss, true) {
			t.Fatal("application-limited BBR round did not complete")
		}
	}
	if controller.bbr.mode != bbrStartup || controller.bbr.fullRounds != 0 {
		t.Fatalf("application-limited BBR state = mode %v full rounds %d", controller.bbr.mode, controller.bbr.fullRounds)
	}
}

func TestBBRIgnoresLowApplicationLimitedBandwidthSamples(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 1_000_000}
	bbr.observeBandwidth(1000, start, 10*time.Millisecond, 1000, true)
	if bbr.roundBandwidth != 0 || bbr.bandwidth != 1_000_000 {
		t.Fatalf("low app-limited sample changed BBR model: round=%v bandwidth=%v", bbr.roundBandwidth, bbr.bandwidth)
	}
	bbr = bbrCongestionControl{bandwidth: 100_000}
	bbr.observeBandwidth(2000, start, 10*time.Millisecond, 2000, true)
	if bbr.roundBandwidth != 200_000 || bbr.bandwidth != 200_000 {
		t.Fatalf("high app-limited sample was ignored: round=%v bandwidth=%v", bbr.roundBandwidth, bbr.bandwidth)
	}
}

func TestBBRAcceptsLowSampleWhilePacingLimited(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.bandwidth = 1_000_000
	controller.bbr.minimumRTT = 10 * time.Millisecond
	controller.bbr.sampleStart = start
	controller.bbr.roundTarget = 100 * mss
	controller.onACKWithThreshold(10*mss, mss, mss, start.Add(10*time.Millisecond), 10*time.Millisecond, 10*time.Millisecond, mss, ^uint32(0), false)
	if controller.bbr.roundBandwidth == 0 {
		t.Fatal("pacing-limited BBR delivery sample was treated as application-limited")
	}
}

func TestBBRCountsACKsWithSharedBatchTimestamp(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{minimumRTT: 20 * time.Millisecond, sampleStart: start}
	bbr.observeBandwidth(1000, start, 20*time.Millisecond, 4000, false)
	bbr.observeBandwidth(1000, start, 20*time.Millisecond, 3000, false)
	bbr.observeBandwidth(1000, start.Add(5*time.Millisecond), 20*time.Millisecond, 2000, false)
	if bbr.roundBandwidth != 600_000 {
		t.Fatalf("batched ACK bandwidth = %v, want 600000", bbr.roundBandwidth)
	}
}

func TestBBRProbeRTTDoesNotRetainOldRoundTarget(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.mode = bbrProbeBandwidth
	controller.bbr.bandwidth = 10 * 1024 * 1024
	controller.bbr.minimumRTT = 10 * time.Millisecond
	controller.bbr.minimumRTTStamp = time.Unix(1, 0)
	controller.bbr.roundTarget = 1024 * 1024
	start := time.Unix(100, 0)
	window := uint32(1024 * 1024)
	window = controller.onACK(window, mss, mss, start, 10*time.Millisecond, 10*time.Millisecond, window, false)
	if controller.bbr.mode != bbrProbeRTT || controller.bbr.roundTarget >= 1024*1024 {
		t.Fatalf("ProbeRTT entry = mode %v round target %d", controller.bbr.mode, controller.bbr.roundTarget)
	}
	flight := controller.bbr.roundTarget
	now := start
	for controller.bbr.probeDone.IsZero() && flight > 0 {
		now = now.Add(time.Millisecond)
		acknowledged := uint32(mss)
		if acknowledged > flight {
			acknowledged = flight
		}
		window = controller.onACK(window, acknowledged, mss, now, 10*time.Millisecond, 10*time.Millisecond, flight, false)
		flight -= acknowledged
	}
	if controller.bbr.probeDone.IsZero() {
		t.Fatal("ProbeRTT did not begin after draining the entry flight")
	}
}

func TestBBRPacingDelaySaturates(t *testing.T) {
	controller := bbrCongestionControl{bandwidth: 1e-20}
	start := time.Unix(100, 0)
	controller.onSend(1, 1, start, 1)
	if controller.nextSend.Before(start) {
		t.Fatalf("overflowed BBR pacing deadline = %v", controller.nextSend)
	}
}

func TestBBRLateWakeCatchesUpWithoutEndingStartup(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 2, bandwidth: 1_000_000,
		minimumRTT: 100 * time.Millisecond, minimumRTTStamp: now, nextSend: start,
	}
	for segment := 0; segment < 2; segment++ {
		bbr.advancePacing(mss, mss, now)
	}
	if bbr.nextSend != now || !bbr.schedulerLimited {
		t.Fatalf("late BBR catch-up = next %v limited=%v, want now/true", bbr.nextSend, bbr.schedulerLimited)
	}
	bbr.advancePacing(mss, mss, now)
	if bbr.nextSend != now.Add(time.Millisecond) {
		t.Fatalf("post-catch-up BBR deadline = %v, want %v", bbr.nextSend, now.Add(time.Millisecond))
	}

	bbr.mode = bbrStartup
	bbr.fullBandwidth = bbr.bandwidth
	bbr.fullRounds = 0
	bbr.roundTarget = mss
	bbr.roundBandwidth = bbr.bandwidth
	_ = bbr.onACK(10*mss, mss, mss, now.Add(10*time.Millisecond), 100*time.Millisecond, 100*time.Millisecond, 10*mss, false)
	if bbr.fullRounds != 0 || bbr.schedulerLimited {
		t.Fatalf("scheduler-limited BBR round = full rounds %d limited=%v", bbr.fullRounds, bbr.schedulerLimited)
	}
}

func TestBBRRetransmissionDoesNotCatchUpPacingDebt(t *testing.T) {
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	bbr := bbrCongestionControl{mode: bbrProbeBandwidth, cycleIndex: 2, bandwidth: 1_000_000, nextSend: start}
	bbr.advanceRetransmissionPacing(1000, 1000, now)
	if bbr.nextSend != now.Add(time.Millisecond) || bbr.schedulerLimited {
		t.Fatalf("retransmission BBR pacing = next %v limited=%v", bbr.nextSend, bbr.schedulerLimited)
	}
}

func TestBBRStartupSampleCanGrowPastInitialFlight(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, 2*mss, mss, start, 100*time.Millisecond, 100*time.Millisecond, window, true)
	initialBandwidth := controller.bbr.bandwidth
	window = controller.onACK(window, 8*mss, mss, start.Add(25*time.Millisecond), 100*time.Millisecond, 0, window, true)
	if controller.bbr.bandwidth <= initialBandwidth {
		t.Fatalf("BBR bandwidth = %v, want growth above bootstrap %v", controller.bbr.bandwidth, initialBandwidth)
	}
}

func TestBBRWaitsForValidRTTBeforeSampling(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, mss, mss, start, 0, 0, window, true)
	if !controller.bbr.sampleStart.IsZero() || controller.bbr.bandwidth != 0 {
		t.Fatalf("BBR sampled without an RTT: start=%v bandwidth=%v", controller.bbr.sampleStart, controller.bbr.bandwidth)
	}
	controller.onACK(window, mss, mss, start.Add(time.Millisecond), 10*time.Millisecond, 10*time.Millisecond, window, true)
	if controller.bbr.sampleStart.IsZero() || controller.bbr.bandwidth == 0 {
		t.Fatalf("BBR did not bootstrap from the first valid RTT: start=%v bandwidth=%v", controller.bbr.sampleStart, controller.bbr.bandwidth)
	}
}

func TestBBRStartupIgnoresRoundsWithoutBandwidthSamples(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, mss, mss, start, 100*time.Millisecond, 100*time.Millisecond, window, true)
	controller.bbr.roundBandwidth = 0
	for round := 0; round < bbrFullBandwidthRounds+1; round++ {
		controller.bbr.roundTarget = mss
		window = controller.onACK(window, mss, mss, start, 100*time.Millisecond, 0, window, false)
		controller.bbr.roundBandwidth = 0
	}
	if controller.bbr.fullRounds != 0 || controller.bbr.mode != bbrStartup {
		t.Fatalf("BBR counted sampleless rounds: fullRounds=%d mode=%v", controller.bbr.fullRounds, controller.bbr.mode)
	}
}

func TestBBRDrainUsesMinimumWindowFloor(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.mode = bbrDrain
	controller.bbr.bandwidth = 1000
	controller.bbr.minimumRTT = time.Millisecond
	start := time.Unix(100, 0)
	controller.bbr.minimumRTTStamp = start
	controller.onACK(10*mss, mss, mss, start, time.Millisecond, time.Millisecond, bbrMinimumCongestionMSS*mss, false)
	if controller.bbr.mode != bbrProbeBandwidth {
		t.Fatalf("low-BDP BBR remained in Drain: mode=%v", controller.bbr.mode)
	}
}

func TestBBRExpiredMinimumRTTCanIncrease(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	controller.bbr.minimumRTT = 10 * time.Millisecond
	controller.bbr.minimumRTTStamp = start.Add(-bbrMinRTTWindow)
	controller.bbr.bandwidth = 100000
	controller.onACK(10*mss, mss, mss, start, 30*time.Millisecond, 30*time.Millisecond, 2*mss, false)
	if controller.bbr.minimumRTT != 30*time.Millisecond || controller.bbr.mode != bbrProbeRTT {
		t.Fatalf("expired min RTT/mode = %v/%v, want 30ms/ProbeRTT", controller.bbr.minimumRTT, controller.bbr.mode)
	}
	if controller.bbr.probeDone.IsZero() {
		t.Fatal("ProbeRTT did not start after flight reached its floor")
	}
}

func TestBBRIdleRestartResetsSamplingInterval(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.bandwidth = 100000
	controller.bbr.sampleStart = time.Unix(100, 0)
	controller.bbr.sampleBytes = 1000
	controller.bbr.nextSend = time.Unix(200, 0)
	now := time.Unix(150, 0)
	controller.onDataSend(1000, 1000, now, 10000, 0, 10*time.Millisecond, ^uint32(0))
	if !controller.bbr.sampleStart.IsZero() || controller.bbr.sampleBytes != 0 || controller.bbr.nextSend.Before(now) || !controller.bbr.idleRestart {
		t.Fatalf("BBR idle restart state = start %v bytes %d next %v", controller.bbr.sampleStart, controller.bbr.sampleBytes, controller.bbr.nextSend)
	}
}

func TestBBRIdleRestartUsesNeutralPacingAndSkipsProbeRTT(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	controller.bbr.mode = bbrProbeBandwidth
	controller.bbr.cycleIndex = 0
	controller.bbr.bandwidth = 100000
	controller.bbr.minimumRTT = 10 * time.Millisecond
	controller.bbr.minimumRTTStamp = start.Add(-bbrMinRTTWindow)
	controller.onDataSend(mss, mss, start, 10*mss, 0, 10*time.Millisecond, ^uint32(0))
	if gain := controller.bbr.pacingGain(); gain != 1 {
		t.Fatalf("BBR idle restart pacing gain = %v, want 1", gain)
	}
	controller.onACK(10*mss, mss, mss, start.Add(10*time.Millisecond), 10*time.Millisecond, 10*time.Millisecond, mss, false)
	if controller.bbr.mode == bbrProbeRTT || controller.bbr.idleRestart {
		t.Fatalf("BBR idle restart mode/flag = %v/%v", controller.bbr.mode, controller.bbr.idleRestart)
	}
}

func TestBBRRecoveryACKUpdatesModelWithoutApplyingModelWindow(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	controller.observeRecoveryACK(window, 2*mss, mss, start, 100*time.Millisecond, 100*time.Millisecond, window, false)
	if controller.bbr.bandwidth == 0 || controller.bbr.minimumRTT != 100*time.Millisecond {
		t.Fatalf("recovery ACK model = bandwidth %v min_rtt %v", controller.bbr.bandwidth, controller.bbr.minimumRTT)
	}
	if window != 10*mss {
		t.Fatalf("model-only recovery update changed caller window to %d", window)
	}

	reno := newTCPCongestionController(CongestionControlReno)
	reno.observeRecoveryACK(window, mss, mss, start, 100*time.Millisecond, 100*time.Millisecond, window, false)
	if reno.renoCredit != 0 {
		t.Fatalf("Reno recovery observation changed credit to %v", reno.renoCredit)
	}
}

func TestTCPSelectableCongestionControls(t *testing.T) {
	for index, algorithm := range []CongestionControl{CongestionControlCUBIC, CongestionControlReno, CongestionControlBBR} {
		t.Run(string(algorithm), func(t *testing.T) {
			local := netip.AddrFrom4([4]byte{192, 0, 2, byte(50 + index*2)})
			remote := netip.AddrFrom4([4]byte{192, 0, 2, byte(51 + index*2)})
			link, stack := newTestStack(t, local, remote)
			defer stack.Close()
			link.mu.Lock()
			link.echoTCP = true
			link.mu.Unlock()
			if err := stack.UpdateConfig(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
				TCP:            TCPSocketDefaults{CongestionControl: algorithm},
			}); err != nil {
				t.Fatal(err)
			}
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, uint16(8100+index)))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			writeAndReadTCPEcho(t, connection, make([]byte, 64*1024))
		})
	}
}

func TestTCPControllerChangePreservesCongestionState(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.58")
	remote := netip.MustParseAddr("192.0.2.59")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8150))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	writeAndReadTCPEcho(t, connection, make([]byte, 512*1024))
	tcpConnection := connection.(*TCPConn)
	before := tcpConnection.Info()
	if before.CongestionWindow <= initialTCPWindow(before.MaximumSegmentSize) {
		t.Fatalf("pre-change congestion window = %d, did not grow beyond initial window", before.CongestionWindow)
	}
	if err = tcpConnection.SetCongestionControl(CongestionControlBBR); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		return tcpConnection.Info().CongestionControl == CongestionControlBBR
	})
	after := tcpConnection.Info()
	if after.CongestionWindow != before.CongestionWindow || after.SlowStartThreshold != before.SlowStartThreshold {
		t.Fatalf("controller change altered cwnd/ssthresh = %d/%d, want %d/%d", after.CongestionWindow, after.SlowStartThreshold, before.CongestionWindow, before.SlowStartThreshold)
	}
}

func TestTCPSelectableCongestionControlsRecoverMultipleLosses(t *testing.T) {
	for index, algorithm := range []CongestionControl{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR} {
		t.Run(string(algorithm), func(t *testing.T) {
			local := netip.AddrFrom4([4]byte{192, 0, 2, byte(70 + index*2)})
			remote := netip.AddrFrom4([4]byte{192, 0, 2, byte(71 + index*2)})
			link, stack := newTestStack(t, local, remote)
			defer stack.Close()
			link.mu.Lock()
			link.echoTCP = true
			link.sackTCP = true
			link.dropTCPOrdinals = map[int]bool{1: true, 3: true}
			link.mu.Unlock()
			if err := stack.UpdateConfig(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
				TCP:            TCPSocketDefaults{CongestionControl: algorithm},
			}); err != nil {
				t.Fatal(err)
			}
			connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, uint16(8200+index)))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
			writeAndReadTCPEcho(t, connection, make([]byte, 64*1024))
			if recoveries := stack.Stats().TCPSACKRetransmissions; recoveries < 2 {
				t.Fatalf("SACK retransmissions = %d, want at least 2", recoveries)
			}
		})
	}
}
