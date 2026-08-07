package mipstack

import (
	"context"
	"math"
	"net/netip"
	"testing"
	"time"
)

func TestCUBICCongestionControl(t *testing.T) {
	const mss = 1200
	controller := newTCPCongestionController(CongestionControlCUBIC)
	if threshold := controller.onCongestion(12000, 9000, 0, mss); threshold != 8400 {
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
	if threshold := controller.onCongestion(12000, 9000, 0, mss); threshold != 4500 {
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

func TestMaximumPacingRateLimitsEveryController(t *testing.T) {
	const (
		mss   = 1000
		limit = uint64(50_000)
	)
	for _, algorithm := range []CongestionControl{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR} {
		controller := newTCPCongestionController(algorithm)
		if algorithm == CongestionControlBBR {
			controller.bbr.pacingBurstRemaining = 64 * 1024
		}
		controller.setMaximumPacingRate(limit)
		if algorithm == CongestionControlBBR {
			controller.bbr.pacingRate = 1_000_000
			if rate := controller.bbr.effectivePacingRate(); rate != float64(limit) {
				t.Fatalf("%s limited pacing rate = %v, want %d", algorithm, rate, limit)
			}
			if controller.bbr.pacingBurstRemaining != 0 {
				t.Fatal("new pacing ceiling retained credit granted at the old rate")
			}
			controller.setMaximumPacingRate(0)
			if rate := controller.bbr.effectivePacingRate(); rate != 1_000_000 {
				t.Fatalf("%s restored pacing rate = %v, want 1000000", algorithm, rate)
			}
			continue
		}
		controller.pacingSegments = tcpPacingInitialBurst - 1
		controller.onDataSend(mss, mss, time.Unix(100, 0), 10*mss, 10*mss, time.Millisecond, 10*mss)
		if effective := controller.limitPacingRate(controller.pacingRate); effective != float64(limit) || controller.pacingRate <= effective {
			t.Fatalf("%s pacing model/effective rate = %v/%v, want model above %d and effective at limit", algorithm, controller.pacingRate, effective, limit)
		}
		controller.setMaximumPacingRate(0)
		if effective := controller.limitPacingRate(controller.pacingRate); effective != controller.pacingRate || effective <= float64(limit) {
			t.Fatalf("%s pacing rate did not recover immediately: model/effective %v/%v", algorithm, controller.pacingRate, effective)
		}
	}
}

func TestMaximumPacingRateChangeInvalidatesPacingSchedule(t *testing.T) {
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.pacingNext = start.Add(time.Second)
	controller.bbr.nextSend = start.Add(2 * time.Second)
	controller.bbr.pacingWakeDeadline = start.Add(1500 * time.Millisecond)
	controller.bbr.pacingBurstRemaining = 32 * 1024
	controller.bbr.pacingRate = 1_000_000

	if !controller.setMaximumPacingRate(50_000) {
		t.Fatal("new pacing ceiling was not reported as a policy change")
	}
	if !controller.pacingNext.IsZero() || !controller.bbr.nextSend.IsZero() || !controller.bbr.pacingWakeDeadline.IsZero() || controller.bbr.pacingBurstRemaining != 0 {
		t.Fatalf("stale pacing state = window %v, BBR %v, wake %v, credit %d", controller.pacingNext, controller.bbr.nextSend, controller.bbr.pacingWakeDeadline, controller.bbr.pacingBurstRemaining)
	}
	if controller.bbr.pacingRate != 1_000_000 {
		t.Fatalf("model pacing rate = %v, want 1000000", controller.bbr.pacingRate)
	}
	if controller.setMaximumPacingRate(50_000) {
		t.Fatal("unchanged pacing ceiling was reported as a policy change")
	}
	if !controller.setMaximumPacingRate(0) || controller.bbr.effectivePacingRate() != 1_000_000 {
		t.Fatalf("removing ceiling did not immediately restore model rate: %v", controller.bbr.effectivePacingRate())
	}
}

func TestWindowPacingDefersAfterInitialBurst(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	start := time.Unix(100, 0)
	for segment := 0; segment < tcpPacingInitialBurst+4; segment++ {
		controller.onDataSend(mss, mss, start, 10*mss, uint32(segment*mss), 100*time.Millisecond, ^uint32(0))
	}
	if delay := controller.pacingDelay(start, mss, 10*mss, 10*mss, mss, 100*time.Millisecond, ^uint32(0)); delay <= 0 {
		t.Fatal("window-based pacer did not defer after its initial burst")
	}
}

func TestPacingScheduleRetainsBoundedLateDebt(t *testing.T) {
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	base := pacingScheduleBase(start, now, 2*time.Millisecond, true)
	if base != now.Add(-2*time.Millisecond) {
		t.Fatalf("late pacing base = %v", base)
	}
	base = pacingScheduleBase(start, now, time.Millisecond, false)
	if base != now {
		t.Fatalf("retransmission pacing base = %v, want now", base)
	}
	base = pacingScheduleBase(now.Add(time.Millisecond), now, time.Millisecond, true)
	if base != now.Add(time.Millisecond) {
		t.Fatalf("early pacing base = %v", base)
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
	if quantum := bbrSendQuantum(1024*100_000, mss); quantum != bbrSendQuantumByteTarget/mss*mss {
		t.Fatalf("high-rate send quantum = %d, want %d", quantum, bbrSendQuantumByteTarget/mss*mss)
	}
	if quantum := bbrSendQuantum(1024*100_000, 100); quantum != bbrMaximumSendSegments*100 {
		t.Fatalf("small-MSS send quantum = %d, want %d", quantum, bbrMaximumSendSegments*100)
	}
	if quantum := bbrSendQuantum(1024*100_000, 40_000); quantum != 80_000 {
		t.Fatalf("large-MSS send quantum = %d, want Linux's two-segment minimum", quantum)
	}
	if quantum := bbrSendQuantum(math.MaxFloat64, mss); quantum != bbrSendQuantumByteTarget/mss*mss {
		t.Fatalf("extreme-rate send quantum = %d, want %d", quantum, bbrSendQuantumByteTarget/mss*mss)
	}
	if duration := bbrSendQuantumDuration(1024*1024*1024, mss); duration < 60*time.Microsecond || duration > 61*time.Microsecond {
		t.Fatalf("high-rate send-quantum duration = %v, want approximately 60us", duration)
	}
	if budget := bbrUserspacePacingBudget(math.MaxFloat64, mss); budget != bbrMaximumUserspaceQuanta*(bbrSendQuantumByteTarget/mss*mss) {
		t.Fatalf("extreme-rate userspace budget = %d", budget)
	}
	if duration := bbrSendQuantumDuration(math.MaxFloat64, mss); duration != time.Nanosecond {
		t.Fatalf("extreme-rate quantum duration = %v, want 1ns", duration)
	}
	if duration := pacingDuration(1, math.SmallestNonzeroFloat64); duration != time.Duration(1<<63-1) {
		t.Fatalf("tiny-rate pacing duration = %v, want saturation", duration)
	}
}

func TestBBRGainsAndUnknownRTTWindowMatchLinux(t *testing.T) {
	if bbrStartupPacingGain != 739.0/256 || bbrDrainPacingGain != 88.0/256 {
		t.Fatalf("BBR fixed-point gains = %v/%v", bbrStartupPacingGain, bbrDrainPacingGain)
	}
	const mss = 1000
	bbr := bbrCongestionControl{mode: bbrStartup}
	if target := bbr.inflightTarget(bbrStartupPacingGain, mss); target != 14*mss {
		t.Fatalf("BBR target without RTT = %d, want %d", target, 14*mss)
	}
}

func TestECNCongestionWindowCanReachOneSegment(t *testing.T) {
	const mss = 1000
	for _, algorithm := range []CongestionControl{CongestionControlReno, CongestionControlCUBIC} {
		t.Run(string(algorithm), func(t *testing.T) {
			controller := newTCPCongestionController(algorithm)
			if threshold, window := controller.onECN(mss, mss, 0, mss); threshold != mss || window != mss {
				t.Fatalf("one-segment ECN threshold/window = %d/%d, want %d/%d", threshold, window, mss, mss)
			}
			controller = newTCPCongestionController(algorithm)
			if threshold := controller.onCongestion(mss, mss, 0, mss); threshold != 2*mss {
				t.Fatalf("one-segment loss threshold = %d, want %d", threshold, 2*mss)
			}
		})
	}
}

func TestBBRECNPreservesModelWindowAndThreshold(t *testing.T) {
	const (
		mss       = 1000
		window    = uint32(20 * mss)
		threshold = uint32(200 * mss)
	)
	controller := newTCPCongestionController(CongestionControlBBR)
	gotThreshold, gotWindow := controller.onECN(window, 10*mss, threshold, mss)
	if gotThreshold != threshold || gotWindow != window {
		t.Fatalf("BBR ECN threshold/window = %d/%d, want %d/%d", gotThreshold, gotWindow, threshold, window)
	}
	if controller.bbr.priorWindow != window {
		t.Fatalf("BBR ECN saved window = %d, want %d", controller.bbr.priorWindow, window)
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
	_ = controller.onCongestion(100*mss, 100*mss, 0, mss)
	if threshold := controller.onTimeout(70*mss, 60*mss, 0, mss, time.Unix(100, 0)); threshold != 49*mss {
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
	if controller.bbr.bandwidth != 20000 {
		t.Fatalf("BBR initial bandwidth = %v, want 20000", controller.bbr.bandwidth)
	}
	_, _ = controller.onBBRDataSend(mss, mss, start, 1, 0, window)
	if delay := controller.pacingDelay(start, mss, window, 0, mss, 100*time.Millisecond, ^uint32(0)); delay >= 100*time.Millisecond {
		t.Fatalf("BBR startup pacing delay = %v, want less than 100ms", delay)
	}
	for round := 0; round < 4; round++ {
		window = controller.onACK(window, mss, mss, start.Add(time.Duration(round+1)*100*time.Millisecond), 100*time.Millisecond, 100*time.Millisecond, window, false)
	}
	if controller.bbr.mode == bbrStartup {
		t.Fatal("BBR remained in Startup after a sustained bandwidth plateau")
	}
	controller.bbr.mode = bbrProbeBandwidth
	controller.bbr.minimumRTTStamp = start.Add(-bbrMinRTTWindow - time.Nanosecond)
	window = controller.onACK(window, mss, mss, start.Add(time.Second), 100*time.Millisecond, 100*time.Millisecond, mss, false)
	if controller.bbr.mode != bbrProbeRTT || window != bbrMinimumCongestionMSS*mss {
		t.Fatalf("BBR ProbeRTT state/window = %v/%d", controller.bbr.mode, window)
	}
}

func TestBBRApplicationLimitedRoundsDoNotEndStartup(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{bandwidth: 100000, fullBandwidth: 100000}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	now := time.Unix(100, 0)
	for round := 0; round < bbrFullBandwidthRounds+2; round++ {
		bbr.delivered += mss
		sample := bbrRateSample{priorDelivered: uint32(bbr.delivered - mss), delivered: mss, acked: mss, interval: 10 * time.Millisecond, ackTime: now.Add(time.Duration(round) * 10 * time.Millisecond), applicationLimited: true, valid: true}
		_, _ = bbr.onRateSample(10*mss, mss, sample)
	}
	if bbr.mode != bbrStartup || bbr.fullRounds != 0 {
		t.Fatalf("application-limited BBR state = mode %v full rounds %d", bbr.mode, bbr.fullRounds)
	}
}

func TestBBRIgnoresLowApplicationLimitedBandwidthSamples(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 1_000_000, nextRoundDelivered: 1}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.updateBandwidth(bbrRateSample{delivered: 1000, interval: 10 * time.Millisecond, ackTime: start, applicationLimited: true, valid: true})
	if bbr.bandwidth != 1_000_000 {
		t.Fatalf("low app-limited sample changed BBR model: bandwidth=%v", bbr.bandwidth)
	}
	bbr = bbrCongestionControl{bandwidth: 100_000, nextRoundDelivered: 1}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.updateBandwidth(bbrRateSample{delivered: 2000, interval: 10 * time.Millisecond, ackTime: start, applicationLimited: true, valid: true})
	if bbr.bandwidth != 200_000 {
		t.Fatalf("high app-limited sample was ignored: bandwidth=%v", bbr.bandwidth)
	}
}

func TestBBRApplicationLimitedSamplesDoNotExpireBandwidth(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 1_000_000}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	for round := 0; round < 2*bbrBandwidthWindow; round++ {
		bbr.delivered += mss
		bbr.updateBandwidth(bbrRateSample{
			priorDelivered: uint32(bbr.delivered - mss), delivered: mss,
			interval: 10 * time.Millisecond, ackTime: start.Add(time.Duration(round) * time.Millisecond),
			applicationLimited: true, valid: true,
		})
	}
	if bbr.bandwidth != 1_000_000 {
		t.Fatalf("app-limited rounds expired BBR bandwidth: %v", bbr.bandwidth)
	}
	bbr.delivered += mss
	bbr.updateBandwidth(bbrRateSample{
		priorDelivered: uint32(bbr.delivered - mss), delivered: mss,
		interval: 10 * time.Millisecond, ackTime: start.Add(time.Second), valid: true,
	})
	if bbr.bandwidth != 100_000 {
		t.Fatalf("first usable sample after stale rounds retained bandwidth: %v", bbr.bandwidth)
	}
}

func TestBBRAcceptsLowSampleWhilePacingLimited(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 1_000_000, nextRoundDelivered: 1}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.updateBandwidth(bbrRateSample{delivered: 1000, interval: 10 * time.Millisecond, ackTime: start, valid: true})
	if bbr.bandwidthFilter.samples[0].rate == 0 {
		t.Fatal("pacing-limited BBR delivery sample was treated as application-limited")
	}
}

func TestBBRRateSampleUsesLongerPipelinePhase(t *testing.T) {
	stamp := func(value time.Duration) monotonicStamp { return monotonicStamp(value) + 1 }
	bbr := bbrCongestionControl{deliveredStamp: bbrStampAt(stamp(10 * time.Millisecond)), firstSent: bbrStampAt(stamp(10 * time.Millisecond))}
	segment := sentTCPSegment{
		sequence: 1, end: 1001, transmissions: 1,
		hostQueue: packetQueueTicket{queuedAt: stamp(20 * time.Millisecond)},
		rate:      bbrRateSnapshot{firstSent: bbrStampAt(stamp(10 * time.Millisecond)), deliveredStamp: bbrStampAt(stamp(10 * time.Millisecond))},
	}
	var sample bbrRateSample
	sample.observe(segment)
	bbr.finishRateSample(&sample, 1000, 1000, 0, time.Unix(100, 0), stamp(25*time.Millisecond), time.Millisecond, time.Millisecond, time.Millisecond)
	if !sample.valid || sample.interval != 15*time.Millisecond || sample.delivered != 1000 {
		t.Fatalf("delivery sample = valid %t interval %v delivered %d", sample.valid, sample.interval, sample.delivered)
	}
	if bbr.firstSent != bbrStampAt(stamp(20*time.Millisecond)) {
		t.Fatalf("next send-phase boundary = %d, want %d", bbr.firstSent, bbrStampAt(stamp(20*time.Millisecond)))
	}
}

func TestBBRCompactStampWrapsAcrossUint32(t *testing.T) {
	earlier := bbrStamp(^uint32(0) - 5)
	later := bbrStamp(5)
	if interval := bbrStampDuration(later, earlier); interval != 11*time.Microsecond {
		t.Fatalf("wrapped BBR interval = %v, want 11us", interval)
	}
}

func TestBBRDeliveredCounterWrapsAcross31Bits(t *testing.T) {
	earlier := bbrRateDeliveredMask - 5
	later := uint32(5)
	if !bbrDeliveredAfterEqual(later, earlier) {
		t.Fatal("wrapped delivered counter was ordered before its reference")
	}
	if bbrDeliveredAfterEqual(earlier, later) {
		t.Fatal("reverse wrapped delivered counter comparison was accepted")
	}
	bbr := bbrCongestionControl{delivered: uint64(bbrRateApplicationLimited) + 5}
	sample := bbrRateSample{
		priorDelivered: earlier,
		priorStamp:     1,
		firstSent:      1,
		lastSent:       monotonicStamp(time.Microsecond) + 1,
	}
	bbr.finishRateSample(&sample, 0, 0, 0, time.Unix(100, 0), monotonicStamp(2*time.Microsecond)+1, 0, 0, 0)
	if sample.delivered != 11 || !sample.valid {
		t.Fatalf("wrapped delivered sample = %d, valid %t; want 11, true", sample.delivered, sample.valid)
	}
}

func TestBBRRateSnapshotPacksApplicationLimit(t *testing.T) {
	bbr := bbrCongestionControl{delivered: 1234, applicationLimitedUntil: 2000}
	snapshot := bbr.snapshotSend(monotonicStamp(time.Millisecond)+1, 1000)
	if snapshot.delivered() != 1234 || !snapshot.applicationLimited() {
		t.Fatalf("packed snapshot = delivered %d limited %t", snapshot.delivered(), snapshot.applicationLimited())
	}
	bbr.applicationLimitedUntil = 0
	snapshot = bbr.snapshotSend(monotonicStamp(2*time.Millisecond)+1, 1000)
	if snapshot.applicationLimited() {
		t.Fatal("unlimited BBR snapshot retained application-limited flag")
	}
}

func TestBBRACKAggregationTracksExcessDelivery(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{bandwidth: 100_000}
	bbr.updateACKAggregation(bbrRateSample{acked: 5000, delivered: 5000, interval: 10 * time.Millisecond, ackTime: start, valid: true}, 10_000, 1000)
	if bbr.extraACKed[0] != 5000 {
		t.Fatalf("extra ACKed = %d, want 5000", bbr.extraACKed[0])
	}
	bbr.updateACKAggregation(bbrRateSample{acked: 1000, delivered: 1000, interval: 10 * time.Millisecond, ackTime: start.Add(50 * time.Millisecond), valid: true}, 10_000, 1000)
	if bbr.ackEpochBytes != 1000 {
		t.Fatalf("slow ACK epoch retained %d bytes, want reset to 1000", bbr.ackEpochBytes)
	}
}

func TestBBRACKAggregationEpochSaturates(t *testing.T) {
	const mss = 48
	maximum := uint32((1 << 20) * mss)
	bbr := bbrCongestionControl{bandwidth: 1}
	bbr.updateACKAggregation(bbrRateSample{
		acked: maximum, delivered: maximum, interval: time.Second,
		ackTime: time.Unix(100, 0), valid: true,
	}, maximum, mss)
	if want := uint64(maximum) - 1; bbr.ackEpochBytes != want {
		t.Fatalf("ACK epoch bytes = %d, want %d", bbr.ackEpochBytes, want)
	}
}

func TestBBRProbeBandwidthWaitsForInflightOrLoss(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	cycleStamp := bbrStampAt(monotonicStamp(time.Millisecond) + 1)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 0, cycleStamp: cycleStamp,
		deliveredStamp: cycleStamp + bbrStamp(20*time.Millisecond/time.Microsecond),
		minimumRTT:     10 * time.Millisecond, bandwidth: 1_000_000, pacingRate: 1_000_000,
	}
	sample := bbrRateSample{ackTime: now, priorInFlight: mss, valid: true}
	bbr.updateCycle(sample, mss)
	if bbr.cycleIndex != 0 {
		t.Fatalf("underfilled probe advanced to phase %d", bbr.cycleIndex)
	}
	sample.losses = mss
	bbr.updateCycle(sample, mss)
	if bbr.cycleIndex != 1 {
		t.Fatalf("loss-limited probe phase = %d, want 1", bbr.cycleIndex)
	}
}

func TestBBRProbeBandwidthUsesDeliveryClock(t *testing.T) {
	const mss = 1000
	cycleStamp := bbrStampAt(monotonicStamp(time.Millisecond) + 1)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 2, cycleStamp: cycleStamp,
		deliveredStamp: cycleStamp + bbrStamp(5*time.Millisecond/time.Microsecond),
		minimumRTT:     10 * time.Millisecond,
	}
	bbr.updateCycle(bbrRateSample{ackTime: time.Unix(100, 0)}, mss)
	if bbr.cycleIndex != 2 {
		t.Fatalf("zero-delivery ACK advanced ProbeBW phase to %d", bbr.cycleIndex)
	}
	bbr.deliveredStamp = cycleStamp + bbrStamp(20*time.Millisecond/time.Microsecond)
	bbr.updateCycle(bbrRateSample{ackTime: time.Unix(100, 0)}, mss)
	if bbr.cycleIndex != 3 {
		t.Fatalf("delivery clock did not advance ProbeBW phase: %d", bbr.cycleIndex)
	}
}

func TestBBRLongTermPolicerDetection(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{delivered: 1000, totalLost: 300}
	bbr.updateLongTermBandwidth(bbrRateSample{losses: 300, ackTime: start})
	for interval := 1; interval <= 2; interval++ {
		bbr.longTermRounds = bbrLongTermMinimumRounds
		bbr.delivered += 10_000
		bbr.totalLost += 3000
		bbr.updateLongTermBandwidth(bbrRateSample{losses: 3000, ackTime: start.Add(time.Duration(interval) * time.Second)})
	}
	if !bbr.longTermUseBandwidth || bbr.longTermBandwidth != 10_000 {
		t.Fatalf("policer model = use %t rate %v", bbr.longTermUseBandwidth, bbr.longTermBandwidth)
	}
}

func TestBBRPolicerSamplingProcessesFirstLossRound(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{delivered: 1000, totalLost: 300, roundStart: true}
	bbr.updateLongTermBandwidth(bbrRateSample{losses: 300, ackTime: start})
	if !bbr.longTermSampling || bbr.longTermRounds != 1 {
		t.Fatalf("first-loss sampling state = active %t, rounds %d", bbr.longTermSampling, bbr.longTermRounds)
	}

	bbr = bbrCongestionControl{delivered: 1000, totalLost: 300, roundStart: true}
	bbr.updateLongTermBandwidth(bbrRateSample{losses: 300, ackTime: start, schedulerLimited: true})
	if bbr.longTermSampling || bbr.longTermRounds != 0 || bbr.longTermBandwidth != 0 {
		t.Fatalf("locally limited first-loss sample retained policer state: %+v", bbr)
	}
}

func TestBBRPolicerGainOnlyOverridesProbeBandwidth(t *testing.T) {
	bbr := bbrCongestionControl{longTermUseBandwidth: true}
	if gain := bbr.pacingGain(); gain != bbrStartupPacingGain {
		t.Fatalf("policed Startup gain = %v, want %v", gain, bbrStartupPacingGain)
	}
	bbr.mode = bbrDrain
	if gain := bbr.pacingGain(); gain != bbrDrainPacingGain {
		t.Fatalf("policed Drain gain = %v, want %v", gain, bbrDrainPacingGain)
	}
	bbr.mode = bbrProbeBandwidth
	bbr.cycleIndex = 0
	if gain := bbr.pacingGain(); gain != 1 {
		t.Fatalf("policed ProbeBW gain = %v, want 1", gain)
	}
}

func TestBBRPacingRateOnlyFallsAfterStartup(t *testing.T) {
	bbr := bbrCongestionControl{bandwidth: 1_000_000}
	bbr.setPacingRate(0, 0)
	initial := bbr.pacingRate
	bbr.bandwidth = 500_000
	bbr.setPacingRate(0, 0)
	if bbr.pacingRate != initial {
		t.Fatalf("Startup pacing rate fell from %v to %v", initial, bbr.pacingRate)
	}
	bbr.fullBandwidthReached = true
	bbr.setPacingRate(0, 0)
	if bbr.pacingRate >= initial {
		t.Fatalf("full-pipe pacing rate remained %v, initial %v", bbr.pacingRate, initial)
	}
}

func TestBBRInitialPacingUsesWindowAndSRTT(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{bandwidth: 20_000}
	bbr.setPacingRate(10*mss, time.Millisecond)
	want := float64(10*mss) / time.Millisecond.Seconds() * bbrStartupPacingGain * bbrPacingMargin
	if bbr.pacingRate != want || !bbr.hasSeenRTT {
		t.Fatalf("initial BBR pacing = %v seen %t, want %v/true", bbr.pacingRate, bbr.hasSeenRTT, want)
	}
	bbr.bandwidth = 1000
	bbr.setPacingRate(10*mss, time.Millisecond)
	if bbr.pacingRate != want {
		t.Fatalf("Startup lowered initialized pacing rate to %v", bbr.pacingRate)
	}
}

func TestBBRInitialPacingUsesNominalRTTUntilMeasured(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{}
	bbr.initializePacingRate(10*mss, 0)
	want := float64(10*mss) / time.Millisecond.Seconds() * bbrStartupPacingGain * bbrPacingMargin
	if bbr.pacingRate != want || bbr.hasSeenRTT {
		t.Fatalf("nominal BBR pacing = %v seen %t, want %v/false", bbr.pacingRate, bbr.hasSeenRTT, want)
	}
	bbr.setPacingRate(10*mss, 10*time.Millisecond)
	realWant := float64(10*mss) / (10 * time.Millisecond).Seconds() * bbrStartupPacingGain * bbrPacingMargin
	if bbr.pacingRate != realWant || !bbr.hasSeenRTT {
		t.Fatalf("measured BBR pacing = %v seen %t, want %v/true", bbr.pacingRate, bbr.hasSeenRTT, realWant)
	}
}

func TestBBRInitialPacingQuantumAllowsTenSegments(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.pacingRate = 10_000
	for segment := 0; segment < tcpPacingInitialBurst; segment++ {
		if delay := controller.pacingDelay(start, mss, 10*mss, uint32(segment*mss), mss, 100*time.Millisecond, ^uint32(0)); delay != 0 {
			t.Fatalf("initial segment %d pacing delay = %v", segment+1, delay)
		}
		_, _ = controller.onBBRDataSend(mss, mss, start, monotonicStamp(segment+1), uint32(segment*mss), 10*mss)
	}
	if delay := controller.pacingDelay(start, mss, 10*mss, 10*mss, mss, 100*time.Millisecond, ^uint32(0)); delay <= 0 {
		t.Fatalf("post-initial-quantum pacing delay = %v", delay)
	}
}

func TestBBRPacedBatchBoundsFutureCredit(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.pacingSegments = tcpPacingInitialBurst
	controller.bbr.pacingRate = 1_000_000
	controller.bbr.nextSend = start
	budget := bbrUserspacePacingBudget(controller.bbr.pacingRate, mss)
	// One due group and one group of future credit may be released at the
	// deadline, but a third group must wait for the accumulated pacing clock.
	for sent := 0; sent < 2*budget; sent += mss {
		if delay := controller.pacingDelay(start, mss, 100*mss, uint32(sent+mss), mss, time.Millisecond, 100*mss); delay != 0 {
			t.Fatalf("paced byte %d delayed by %v before credit exhaustion", sent, delay)
		}
		_, _ = controller.onBBRDataSend(mss, mss, start, monotonicStamp(sent+1), uint32(sent+mss), 100*mss)
	}
	if delay := controller.pacingDelay(start, mss, 100*mss, uint32(2*budget), mss, time.Millisecond, 100*mss); delay <= 0 {
		t.Fatalf("sender released more than one future %d-byte pacing group", budget)
	}
}

func TestBBRProbeRTTDoesNotRetainOldRoundTarget(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.mode = bbrProbeBandwidth
	controller.bbr.bandwidth = 10 * 1024 * 1024
	controller.bbr.bandwidthFilter.reset(0, controller.bbr.bandwidth)
	controller.bbr.minimumRTT = 10 * time.Millisecond
	controller.bbr.minimumRTTStamp = time.Unix(1, 0)
	start := time.Unix(100, 0)
	window := uint32(1024 * 1024)
	window = controller.onACK(window, mss, mss, start, 10*time.Millisecond, 10*time.Millisecond, window, false)
	if controller.bbr.mode != bbrProbeRTT {
		t.Fatalf("ProbeRTT entry mode = %v", controller.bbr.mode)
	}
	flight := uint32(1024 * 1024)
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
	controller := bbrCongestionControl{pacingRate: 1e-20}
	start := time.Unix(100, 0)
	_, _ = controller.onSend(1, 1, start, 1, 1, 1)
	if controller.nextSend.Before(start) {
		t.Fatalf("overflowed BBR pacing deadline = %v", controller.nextSend)
	}
}

func TestBBRLateWakeRetainsBoundedPacingDebt(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 2, bandwidth: 1_000_000, pacingRate: 1_000_000,
		minimumRTT: 100 * time.Millisecond, minimumRTTStamp: now, nextSend: start,
	}
	for segment := 0; segment < 2; segment++ {
		bbr.advancePacing(mss, mss, now)
	}
	if bbr.nextSend != now {
		t.Fatalf("late BBR catch-up = next %v, want %v", bbr.nextSend, now)
	}
	bbr.advancePacing(mss, mss, now)
	if bbr.nextSend != now.Add(time.Millisecond) {
		t.Fatalf("post-catch-up BBR deadline = %v, want %v", bbr.nextSend, now.Add(time.Millisecond))
	}
}

func TestBBRLatePacingWakeMarksDeliverySampleSchedulerLimited(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{pacingRate: 1_000_000, nextSend: start.Add(10 * time.Millisecond), delivered: 1000}
	if delay := bbr.pacingDelay(start, mss, mss, 10*mss); delay != 8*time.Millisecond {
		t.Fatalf("initial pacing delay = %v, want 8ms", delay)
	}
	if delay := bbr.pacingDelay(start.Add(10*time.Millisecond), mss, mss, 10*mss); delay != 0 {
		t.Fatalf("late-wake pacing delay = %v", delay)
	}
	snapshot, _ := bbr.onSend(mss, mss, start.Add(10*time.Millisecond), 1, 10*mss, 20*mss)
	if snapshot.applicationLimited() || !bbr.schedulerLimited() || bbr.schedulerLimitedUntil != 11_000 || bbr.schedulerLimitedEvents != 1 {
		t.Fatalf("late-wake state = app %t scheduler %t boundary %d events %d", snapshot.applicationLimited(), bbr.schedulerLimited(), bbr.schedulerLimitedUntil, bbr.schedulerLimitedEvents)
	}
	bbr.markApplicationLimited(mss)
	if bbr.applicationLimitedUntil != 2_000 {
		t.Fatalf("refreshed application-limit boundary = %d, want 2000", bbr.applicationLimitedUntil)
	}
}

func TestBBRSchedulerLimitUsesUserspaceWakeDeadline(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	nextSend := start.Add(10 * time.Millisecond)
	deadline := nextSend.Add(-2 * time.Millisecond) // 2 MSS at 1 MB/s.

	early := bbrCongestionControl{pacingRate: 1_000_000, nextSend: nextSend, delivered: 1000}
	if delay := early.pacingDelay(start, mss, mss, 10*mss); delay != 8*time.Millisecond {
		t.Fatalf("initial pacing delay = %v, want 8ms", delay)
	}
	if delay := early.pacingDelay(deadline.Add(-time.Microsecond), mss, mss, 10*mss); delay != time.Microsecond {
		t.Fatalf("pre-deadline pacing delay = %v, want 1us", delay)
	}
	if early.schedulerLimited() || early.schedulerLimitedEvents != 0 {
		t.Fatal("pre-deadline sender was marked scheduler limited")
	}

	late := bbrCongestionControl{pacingRate: 1_000_000, nextSend: nextSend, delivered: 1000}
	if delay := late.pacingDelay(start, mss, mss, 10*mss); delay != 8*time.Millisecond {
		t.Fatalf("initial pacing delay = %v, want 8ms", delay)
	}
	now := deadline.Add(tcpUserspaceSchedulingTolerance + time.Microsecond)
	if !now.Before(nextSend) {
		t.Fatal("test wake must remain earlier than the pacing clock")
	}
	if delay := late.pacingDelay(now, mss, mss, 10*mss); delay != 0 {
		t.Fatalf("late userspace wake delay = %v, want 0", delay)
	}
	if !late.schedulerLimited() || late.schedulerLimitedUntil != 11_000 || late.schedulerLimitedEvents != 1 {
		t.Fatalf("late wake state = limited %t, boundary %d, events %d", late.schedulerLimited(), late.schedulerLimitedUntil, late.schedulerLimitedEvents)
	}

	unarmed := bbrCongestionControl{pacingRate: 1_000_000, nextSend: nextSend, delivered: 1000}
	if delay := unarmed.pacingDelay(now, mss, mss, 10*mss); delay != 0 {
		t.Fatalf("unarmed pacing delay = %v, want 0", delay)
	}
	if unarmed.schedulerLimited() || unarmed.schedulerLimitedEvents != 0 {
		t.Fatal("sender without a prior pacing wait was marked scheduler limited")
	}
}

func TestBBRSchedulerLimitedSampleCannotLowerBandwidthModel(t *testing.T) {
	bbr := bbrCongestionControl{bandwidth: 1_000_000}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.updateBandwidth(bbrRateSample{
		priorDelivered: 1, delivered: 1000, interval: 2 * time.Millisecond,
		ackTime: time.Unix(100, 0), schedulerLimited: true, valid: true,
	})
	if bbr.bandwidth != 1_000_000 {
		t.Fatalf("scheduler-limited sample lowered bandwidth to %v", bbr.bandwidth)
	}
}

func TestBBRSchedulerLimitedSampleDoesNotCreateACKAggregation(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{
		bandwidth: 1_000_000, ackEpochStamp: start, ackEpochBytes: 1000,
		extraACKed: [2]uint32{200, 100},
	}
	bbr.updateACKAggregation(bbrRateSample{
		acked: 10_000, ackTime: start.Add(time.Millisecond),
		schedulerLimited: true, valid: true,
	}, 100_000, 1000)
	if bbr.ackEpochStamp != start.Add(time.Millisecond) || bbr.ackEpochBytes != 0 {
		t.Fatalf("scheduler-limited ACK epoch = %v/%d", bbr.ackEpochStamp, bbr.ackEpochBytes)
	}
	if bbr.extraACKed != [2]uint32{200, 100} {
		t.Fatalf("scheduler-limited ACK changed aggregation history: %v", bbr.extraACKed)
	}

	bbr.roundStart = true
	bbr.extraACKedRounds = bbrExtraACKedWindow - 1
	bbr.updateACKAggregation(bbrRateSample{
		acked: 10_000, ackTime: start.Add(2 * time.Millisecond),
		schedulerLimited: true, valid: true,
	}, 100_000, 1000)
	if bbr.extraACKedRounds != 0 || bbr.extraACKedIndex != 1 || bbr.extraACKed != [2]uint32{200, 0} {
		t.Fatalf("scheduler-limited round did not age aggregation history: rounds %d, index %d, values %v", bbr.extraACKedRounds, bbr.extraACKedIndex, bbr.extraACKed)
	}
}

func TestBBRPacingTimerConsumesWakeWhenSendIsBlocked(t *testing.T) {
	start := time.Unix(100, 0)
	bbr := bbrCongestionControl{pacingWakeDeadline: start, delivered: 1000}
	bbr.consumePacingWake(start.Add(tcpUserspaceSchedulingTolerance+time.Microsecond), 10_000)
	if !bbr.pacingWakeDeadline.IsZero() || !bbr.schedulerLimited() || bbr.schedulerLimitedEvents != 1 {
		t.Fatalf("consumed pacing wake = deadline %v, limited %t, events %d", bbr.pacingWakeDeadline, bbr.schedulerLimited(), bbr.schedulerLimitedEvents)
	}
	bbr.consumePacingWake(start.Add(time.Second), 10_000)
	if bbr.schedulerLimitedEvents != 1 {
		t.Fatalf("one pacing wake was counted %d times", bbr.schedulerLimitedEvents)
	}
}

func TestBBRPacingWakeCanBeRepurposedWithoutSchedulerSample(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.pacingWakeDeadline = time.Unix(100, 0)
	controller.cancelPacingWake()
	controller.onPacingWake(time.Unix(101, 0), 10_000)
	if !controller.bbr.pacingWakeDeadline.IsZero() || controller.bbr.schedulerLimited() || controller.bbr.schedulerLimitedEvents != 0 {
		t.Fatalf("cancelled pacing wake = deadline %v, limited %t, events %d", controller.bbr.pacingWakeDeadline, controller.bbr.schedulerLimited(), controller.bbr.schedulerLimitedEvents)
	}
}

func TestBBRRetransmissionDoesNotCatchUpPacingDebt(t *testing.T) {
	start := time.Unix(100, 0)
	now := start.Add(100 * time.Millisecond)
	bbr := bbrCongestionControl{mode: bbrProbeBandwidth, cycleIndex: 2, bandwidth: 1_000_000, pacingRate: 1_000_000, nextSend: start}
	bbr.advanceRetransmissionPacing(1000, 1000, now)
	if bbr.nextSend != now.Add(time.Millisecond) {
		t.Fatalf("retransmission BBR pacing = next %v", bbr.nextSend)
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
	if controller.bbr.bandwidth != 0 {
		t.Fatalf("BBR sampled without an RTT: bandwidth=%v", controller.bbr.bandwidth)
	}
	controller.onACK(window, mss, mss, start.Add(time.Millisecond), 10*time.Millisecond, 10*time.Millisecond, window, true)
	if controller.bbr.bandwidth == 0 {
		t.Fatal("BBR did not bootstrap from the first valid RTT")
	}
}

func TestBBRStartupIgnoresRoundsWithoutBandwidthSamples(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	window := uint32(10 * mss)
	window = controller.onACK(window, mss, mss, start, 0, 100*time.Millisecond, window, true)
	for round := 0; round < bbrFullBandwidthRounds+1; round++ {
		window = controller.onACK(window, mss, mss, start, 0, 0, window, false)
	}
	if controller.bbr.fullRounds != 0 || controller.bbr.mode != bbrStartup {
		t.Fatalf("BBR counted sampleless rounds: fullRounds=%d mode=%v", controller.bbr.fullRounds, controller.bbr.mode)
	}
}

func TestBBRStartupPublishesDrainThreshold(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.fullBandwidthReached = true
	controller.bbr.bandwidth = 1_000_000
	controller.bbr.minimumRTT = 10 * time.Millisecond
	controller.bbr.minimumRTTStamp = time.Unix(100, 0)
	want := uint32(controller.bbr.quantizeWindowAt(controller.bbr.modelWindowForBandwidth(controller.bbr.bandwidth, 1, mss), mss, false))
	window, threshold := controller.onBBRRateSample(100*mss, mss, bbrRateSample{
		priorInFlight: 100 * mss, inFlight: 100 * mss, ackTime: time.Unix(100, 0),
	})
	if controller.bbr.mode != bbrDrain || window != 100*mss || threshold != want {
		t.Fatalf("BBR drain publication = mode %v window %d threshold %d, want DRAIN/%d/%d", controller.bbr.mode, window, threshold, 100*mss, want)
	}
}

func TestBBRStartupProbeRTTDoesNotPublishDrainThreshold(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.minimumRTT = 10 * time.Millisecond
	controller.bbr.minimumRTTStamp = time.Unix(100, 0)
	_, threshold := controller.onBBRRateSample(10*mss, mss, bbrRateSample{
		ackTime: time.Unix(100, 0).Add(bbrMinRTTWindow + time.Second),
	})
	if controller.bbr.mode != bbrProbeRTT || threshold != 0 {
		t.Fatalf("Startup ProbeRTT = mode %v threshold %d", controller.bbr.mode, threshold)
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
	controller.bbr.minimumRTTStamp = start.Add(-bbrMinRTTWindow - time.Nanosecond)
	controller.bbr.bandwidth = 100000
	controller.onACK(10*mss, mss, mss, start, 30*time.Millisecond, 30*time.Millisecond, 2*mss, false)
	if controller.bbr.minimumRTT != 30*time.Millisecond || controller.bbr.mode != bbrProbeRTT {
		t.Fatalf("expired min RTT/mode = %v/%v, want 30ms/ProbeRTT", controller.bbr.minimumRTT, controller.bbr.mode)
	}
	if controller.bbr.probeDone.IsZero() {
		t.Fatal("ProbeRTT did not start after flight reached its floor")
	}
}

func TestBBRExpiredMinimumRTTIgnoresDelayedACK(t *testing.T) {
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, minimumRTT: 10 * time.Millisecond,
		minimumRTTStamp: time.Unix(100, 0), idleRestart: true,
	}
	now := bbr.minimumRTTStamp.Add(bbrMinRTTWindow + time.Nanosecond)
	window := bbr.updateMinimumRTT(10_000, bbrRateSample{ackTime: now, rtt: 30 * time.Millisecond, ackDelayed: true}, 1000)
	if bbr.minimumRTT != 10*time.Millisecond || window != 10_000 {
		t.Fatalf("delayed ACK replaced expired min RTT: min %v window %d", bbr.minimumRTT, window)
	}
	bbr.updateMinimumRTT(window, bbrRateSample{ackTime: now, rtt: 5 * time.Millisecond, ackDelayed: true}, 1000)
	if bbr.minimumRTT != 5*time.Millisecond {
		t.Fatalf("lower delayed-ACK RTT was ignored: min %v", bbr.minimumRTT)
	}
}

func TestBBRIdleRestartResetsSamplingInterval(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.bandwidth = 100000
	controller.bbr.pacingRate = 100000
	controller.bbr.firstSent = 10
	controller.bbr.deliveredStamp = 10
	controller.bbr.nextSend = time.Unix(200, 0)
	now := time.Unix(150, 0)
	stamp := monotonicStamp(20*time.Microsecond) + 1
	snapshot, _ := controller.onBBRDataSend(1000, 1000, now, stamp, 0, 10_000)
	if snapshot.firstSent != bbrStampAt(stamp) || snapshot.deliveredStamp != bbrStampAt(stamp) || controller.bbr.nextSend.Before(now) || !controller.bbr.idleRestart {
		t.Fatalf("BBR idle restart state = first %d delivered %d next %v", snapshot.firstSent, snapshot.deliveredStamp, controller.bbr.nextSend)
	}
	if controller.bbr.ackEpochStamp != now || controller.bbr.ackEpochBytes != 0 {
		t.Fatalf("BBR idle ACK epoch = %v/%d, want %v/0", controller.bbr.ackEpochStamp, controller.bbr.ackEpochBytes, now)
	}
}

func TestBBRIdleRestartUsesNeutralPacingAndSkipsProbeRTT(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	start := time.Unix(100, 0)
	controller.bbr.mode = bbrProbeBandwidth
	controller.bbr.cycleIndex = 0
	controller.bbr.bandwidth = 100000
	controller.bbr.pacingRate = 100000
	controller.bbr.minimumRTT = 10 * time.Millisecond
	controller.bbr.minimumRTTStamp = start.Add(-bbrMinRTTWindow)
	_, _ = controller.onBBRDataSend(mss, mss, start, 1, 0, 10*mss)
	if gain := controller.bbr.pacingGain(); gain != bbrProbeBandwidthGains[0] {
		t.Fatalf("BBR idle restart saved pacing gain = %v, want %v", gain, bbrProbeBandwidthGains[0])
	}
	if controller.bbr.pacingRate != controller.bbr.bandwidth*bbrPacingMargin {
		t.Fatalf("BBR idle restart pacing rate = %v, want %v", controller.bbr.pacingRate, controller.bbr.bandwidth*bbrPacingMargin)
	}
	controller.onACK(10*mss, mss, mss, start.Add(10*time.Millisecond), 10*time.Millisecond, 10*time.Millisecond, mss, false)
	if controller.bbr.mode == bbrProbeRTT || controller.bbr.idleRestart {
		t.Fatalf("BBR idle restart mode/flag = %v/%v", controller.bbr.mode, controller.bbr.idleRestart)
	}
}

func TestBBRIdleRestartRetainsProbeBandwidthPhase(t *testing.T) {
	const mss = 1000
	start := time.Unix(100, 0)
	cycleStamp := bbrStampAt(monotonicStamp(time.Millisecond) + 1)
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, cycleIndex: 0, cycleStamp: cycleStamp,
		deliveredStamp: cycleStamp + bbrStamp(20*time.Millisecond/time.Microsecond),
		minimumRTT:     10 * time.Millisecond, minimumRTTStamp: start,
		bandwidth: 1_000_000, pacingRate: 1_000_000, idleRestart: true,
	}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	sample := bbrRateSample{
		priorDelivered: 1, delivered: mss, acked: mss,
		priorInFlight: mss, inFlight: 0, interval: 10 * time.Millisecond,
		rtt: 10 * time.Millisecond, smoothedRTT: 10 * time.Millisecond,
		ackTime: start, applicationLimited: true, valid: true,
	}
	bbr.delivered = mss + 1
	_, _ = bbr.onRateSample(10*mss, mss, sample)
	if bbr.cycleIndex != 0 {
		t.Fatalf("idle restart advanced underfilled high-gain phase to %d", bbr.cycleIndex)
	}
	if bbr.idleRestart {
		t.Fatal("delivery ACK retained idle-restart state")
	}
}

func TestBBRIdleRestartCompletesProbeRTT(t *testing.T) {
	const mss = 1000
	now := time.Unix(100, 0)
	bbr := bbrCongestionControl{
		mode: bbrProbeRTT, fullBandwidthReached: true, priorWindow: 20 * mss,
		probeDone: now.Add(-time.Millisecond), applicationLimitedUntil: 1,
		bandwidth: 1_000_000, pacingRate: 1_000_000,
	}
	_, window := bbr.onSend(mss, mss, now, 1, 0, bbrMinimumCongestionMSS*mss)
	if bbr.mode != bbrProbeBandwidth || window != 20*mss || bbr.minimumRTTStamp != now {
		t.Fatalf("idle ProbeRTT exit = mode %v window %d stamp %v", bbr.mode, window, bbr.minimumRTTStamp)
	}
}

func TestBBRPacketConservationEndsAfterOneRound(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{
		mode: bbrProbeBandwidth, bandwidth: 1_000_000, minimumRTT: 10 * time.Millisecond,
		minimumRTTStamp: time.Unix(100, 0), fullBandwidthReached: true, priorWindow: 20 * mss,
	}
	bbr.bandwidthFilter.reset(0, bbr.bandwidth)
	bbr.delivered = 2 * mss
	start := time.Unix(100, 0)
	sample := bbrRateSample{
		priorDelivered: 0, delivered: 2 * mss, acked: 2 * mss,
		priorInFlight: 10 * mss, inFlight: 8 * mss, interval: 10 * time.Millisecond,
		rtt: 10 * time.Millisecond, ackTime: start, fastRecovery: true, recovery: true, valid: true,
	}
	window, _ := bbr.onRateSample(20*mss, mss, sample)
	if !bbr.recovery || !bbr.packetConservation || window != 10*mss {
		t.Fatalf("BBR recovery entry = recovery %t conservation %t window %d", bbr.recovery, bbr.packetConservation, window)
	}
	bbr.delivered += 2 * mss
	sample.priorDelivered = uint32(bbr.delivered - 2*mss)
	sample.inFlight = 6 * mss
	sample.ackTime = start.Add(10 * time.Millisecond)
	window, _ = bbr.onRateSample(window, mss, sample)
	if bbr.packetConservation {
		t.Fatal("BBR retained packet conservation after a packet-timed round")
	}
	sample.fastRecovery = false
	sample.recovery = false
	sample.acked = mss
	sample.delivered = mss
	sample.inFlight = 5 * mss
	sample.ackTime = start.Add(20 * time.Millisecond)
	window, _ = bbr.onRateSample(window, mss, sample)
	if bbr.recovery || window != 21*mss {
		t.Fatalf("BBR recovery exit = recovery %t window %d, want false/%d", bbr.recovery, window, 21*mss)
	}
}

func TestBBRZeroDeliveryLossSampleDefersPacketConservation(t *testing.T) {
	const mss = 1000
	bbr := bbrCongestionControl{priorWindow: 20 * mss}
	window, _ := bbr.onRateSample(20*mss, mss, bbrRateSample{
		losses: mss, priorInFlight: 10 * mss, inFlight: 9 * mss,
		ackTime: time.Unix(100, 0), recovery: true, fastRecovery: true,
	})
	if bbr.recovery || bbr.packetConservation || window != 20*mss {
		t.Fatalf("zero-delivery loss sample recovery = %t/%t window %d", bbr.recovery, bbr.packetConservation, window)
	}
}

func TestBBRLossSamplingSeparatesACKAndTimerEvents(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.noteLoss(1000, false)
	var sample bbrRateSample
	controller.finishBBRRateSample(&sample, 0, 0, 0, time.Unix(100, 0), 1, 0, 0, 0)
	if sample.losses != 0 {
		t.Fatalf("timer loss repeated on ACK as %d bytes", sample.losses)
	}
	controller.noteLoss(500, true)
	controller.finishBBRRateSample(&sample, 0, 0, 0, time.Unix(101, 0), 2, 0, 0, 0)
	if sample.losses != 500 {
		t.Fatalf("ACK loss sample = %d, want 500", sample.losses)
	}
}

func TestBBRTimeoutRestoresWindowOnlyAfterLossRecovery(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlBBR)
	controller.bbr.recovery = true
	controller.bbr.packetConservation = true
	controller.bbr.fullBandwidth = 1_000_000
	controller.bbr.fullRounds = 2
	now := time.Unix(100, 0)
	const slowStartThreshold = 15 * mss
	if threshold := controller.onTimeout(20*mss, 10*mss, slowStartThreshold, mss, now); threshold != slowStartThreshold {
		t.Fatalf("BBR timeout threshold = %d, want %d", threshold, slowStartThreshold)
	}
	if controller.bbr.recovery || !controller.bbr.lossRecovery || controller.bbr.packetConservation || controller.bbr.fullBandwidth != 0 || !controller.bbr.roundStart || !controller.bbr.longTermSampling {
		t.Fatalf("BBR timeout state = recovery %t loss %t conservation %t full_bw %v round %t policer %t", controller.bbr.recovery, controller.bbr.lossRecovery, controller.bbr.packetConservation, controller.bbr.fullBandwidth, controller.bbr.roundStart, controller.bbr.longTermSampling)
	}
	sample := bbrRateSample{acked: mss, delivered: mss, recovery: true, ackTime: now.Add(time.Millisecond)}
	if window := controller.bbr.setCongestionWindow(mss, sample, mss); window != bbrMinimumCongestionMSS*mss || !controller.bbr.lossRecovery {
		t.Fatalf("BBR active loss window/state = %d/%t", window, controller.bbr.lossRecovery)
	}
	sample.recovery = false
	if window := controller.bbr.setCongestionWindow(mss, sample, mss); window != 21*mss || controller.bbr.lossRecovery {
		t.Fatalf("BBR completed loss window/state = %d/%t, want %d/false", window, controller.bbr.lossRecovery, 21*mss)
	}
}

func TestBBRSpuriousRecoveryUndoRetainsDeliveryAccounting(t *testing.T) {
	prior := newTCPCongestionController(CongestionControlBBR)
	prior.bbr.delivered = 1000
	var undo tcpRecoveryUndo
	undo.begin(false, 2000, 20_000, 20_000, 10_000, prior, rttEstimator{})
	current := prior
	current.bbr.delivered = 5000
	current.bbr.bandwidth = 1_000_000
	current.bbr.fullBandwidth = 1_000_000
	current.bbr.fullRounds = 2
	current.bbr.longTermSampling = true
	current.bbr.recovery = true
	current.bbr.packetConservation = true
	_, _, restored := undo.restore(10_000, 1000, 1000, current, time.Unix(100, 0))
	if restored.bbr.delivered != current.bbr.delivered || restored.bbr.bandwidth != current.bbr.bandwidth {
		t.Fatalf("BBR undo rewound delivery model: delivered %d bandwidth %v", restored.bbr.delivered, restored.bbr.bandwidth)
	}
	if restored.bbr.fullBandwidth != 0 || restored.bbr.fullRounds != 0 || restored.bbr.longTermSampling || restored.bbr.recovery || restored.bbr.lossRecovery || restored.bbr.packetConservation {
		t.Fatalf("BBR undo state = full %v/%d policer %t recovery %t/%t/%t", restored.bbr.fullBandwidth, restored.bbr.fullRounds, restored.bbr.longTermSampling, restored.bbr.recovery, restored.bbr.lossRecovery, restored.bbr.packetConservation)
	}
}

func TestBBRSaveWindowReplacesStaleOpenState(t *testing.T) {
	bbr := bbrCongestionControl{priorWindow: 20_000}
	bbr.saveWindow(10_000)
	if bbr.priorWindow != 10_000 {
		t.Fatalf("open-state prior window = %d, want 10000", bbr.priorWindow)
	}
	bbr.recovery = true
	bbr.saveWindow(8_000)
	bbr.saveWindow(12_000)
	if bbr.priorWindow != 12_000 {
		t.Fatalf("recovery prior window = %d, want 12000", bbr.priorWindow)
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

func TestTCPBBRPartialCumulativeACKProducesRateSample(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.88")
	remote := netip.MustParseAddr("192.0.2.89")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.partialTCPACK = 500
	link.delayTCPACK = 5 * time.Millisecond
	link.mu.Unlock()
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlBBR},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8288))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool {
		info := tcpConnection.Info()
		return info.BytesAcknowledged == 500 && info.DeliveryRate != 0
	})
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
