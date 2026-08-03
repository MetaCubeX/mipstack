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
	if threshold := controller.onCongestion(12000, mss); threshold != 8400 {
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

func TestRenoCongestionControl(t *testing.T) {
	const mss = 1000
	controller := newTCPCongestionController(CongestionControlReno)
	if threshold := controller.onCongestion(12000, mss); threshold != 6000 {
		t.Fatalf("Reno threshold = %d, want 6000", threshold)
	}
	window := uint32(10000)
	if grown := controller.onACK(window, 2*mss, mss, time.Time{}, 0, 0, window, true); grown != 12000 {
		t.Fatalf("Reno slow-start window = %d, want 12000", grown)
	}
	if grown := controller.onACK(window, mss, mss, time.Time{}, 0, 0, window, false); grown != 10100 {
		t.Fatalf("Reno avoidance window = %d, want 10100", grown)
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
	controller.onSend(mss, start)
	if delay := controller.pacingDelay(start); delay <= 0 || delay >= 100*time.Millisecond {
		t.Fatalf("BBR startup pacing delay = %v, want (0, 100ms)", delay)
	}
	for round := 0; round < 4; round++ {
		controller.bbr.roundTarget = mss
		window = controller.onACK(window, mss, mss, start.Add(time.Duration(round+1)*100*time.Millisecond), 100*time.Millisecond, 100*time.Millisecond, 2*mss, false)
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
				LocalAddresses:    []netip.Prefix{netip.PrefixFrom(local, 32)},
				CongestionControl: algorithm,
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
