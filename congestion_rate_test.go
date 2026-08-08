package mipstack

import (
	"testing"
	"time"
)

func TestTCPDeliveryRateSampleUsesLongerPipelinePhase(t *testing.T) {
	stamp := func(value time.Duration) monotonicStamp { return monotonicStamp(value) + 1 }
	estimator := tcpDeliveryRateEstimator{
		deliveredStamp: tcpDeliveryTimestampAt(stamp(10 * time.Millisecond)),
		firstSent:      tcpDeliveryTimestampAt(stamp(10 * time.Millisecond)),
	}
	segment := sentTCPSegment{
		sequence: 1, end: 1001, state: sentTCPSegmentTransmitted,
		hostQueue: packetQueueTicket{queuedAt: stamp(20 * time.Millisecond)},
		delivery:  tcpDeliverySnapshot{firstSent: tcpDeliveryTimestampAt(stamp(10 * time.Millisecond)), deliveredStamp: tcpDeliveryTimestampAt(stamp(10 * time.Millisecond))},
	}
	var sample tcpDeliveryRateSample
	sample.observe(segment)
	estimator.finishRateSample(&sample, 1000, 1000, 0, time.Unix(100, 0), stamp(25*time.Millisecond), time.Millisecond, time.Millisecond, time.Millisecond)
	if !sample.valid || sample.interval != 15*time.Millisecond || sample.delivered != 1000 {
		t.Fatalf("delivery sample = valid %t interval %v delivered %d", sample.valid, sample.interval, sample.delivered)
	}
	if estimator.firstSent != tcpDeliveryTimestampAt(stamp(20*time.Millisecond)) {
		t.Fatalf("next send-phase boundary = %d, want %d", estimator.firstSent, tcpDeliveryTimestampAt(stamp(20*time.Millisecond)))
	}
}

func TestTCPDeliveryTimestampWrapsAcrossUint32(t *testing.T) {
	earlier := tcpDeliveryTimestamp(^uint32(0) - 5)
	later := tcpDeliveryTimestamp(5)
	if interval := tcpDeliveryTimestampDuration(later, earlier); interval != 11*time.Microsecond {
		t.Fatalf("wrapped delivery interval = %v, want 11us", interval)
	}
}

func TestTCPDeliveryCounterWrapsAcross31Bits(t *testing.T) {
	earlier := tcpDeliveryDeliveredMask - 5
	later := uint32(5)
	if !tcpDeliveryAfterEqual(later, earlier) {
		t.Fatal("wrapped delivered counter was ordered before its reference")
	}
	if tcpDeliveryAfterEqual(earlier, later) {
		t.Fatal("reverse wrapped delivered counter comparison was accepted")
	}
	estimator := tcpDeliveryRateEstimator{delivered: uint64(tcpDeliveryApplicationLimited) + 5}
	sample := tcpDeliveryRateSample{
		priorDelivered: earlier,
		priorStamp:     1,
		firstSent:      1,
		lastSent:       monotonicStamp(time.Microsecond) + 1,
	}
	estimator.finishRateSample(&sample, 0, 0, 0, time.Unix(100, 0), monotonicStamp(2*time.Microsecond)+1, 0, 0, 0)
	if sample.delivered != 11 || !sample.valid {
		t.Fatalf("wrapped delivered sample = %d, valid %t; want 11, true", sample.delivered, sample.valid)
	}
	if prior := sample.PriorDeliveredBytes(); prior != uint64(tcpDeliveryApplicationLimited)-6 {
		t.Fatalf("public prior delivered bytes = %d, want %d", prior, uint64(tcpDeliveryApplicationLimited)-6)
	}
}

func TestTCPDeliverySnapshotPacksApplicationLimit(t *testing.T) {
	estimator := tcpDeliveryRateEstimator{delivered: 1234, applicationLimitedUntil: 2000}
	snapshot := estimator.snapshot()
	if snapshot.delivered() != 1234 || !snapshot.applicationLimited() {
		t.Fatalf("packed snapshot = delivered %d limited %t", snapshot.delivered(), snapshot.applicationLimited())
	}
	estimator.applicationLimitedUntil = 0
	snapshot = estimator.snapshot()
	if snapshot.applicationLimited() {
		t.Fatal("unlimited snapshot retained application-limited flag")
	}
}
