package mipstack_test

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mipstack"
)

var externalCongestionName atomic.Uint64

type externalCongestionController struct{}

func (*externalCongestionController) HandleCongestionEvent(event *mipstack.CongestionEvent) {
	if event.Type == mipstack.CongestionEventInitialize {
		event.State.CongestionWindow = 16 * uint32(event.State.MaximumSegmentSize)
	}
}

func TestPublicCongestionControllerAPI(t *testing.T) {
	sample := new(mipstack.CongestionRateSample)
	_, _, _, _, _ = sample.PriorDeliveredBytes(), sample.DeliveredBytes(), sample.AcknowledgedBytes(), sample.LostBytes(), sample.PriorBytesInFlight()
	_, _, _, _, _ = sample.BytesInFlight(), sample.Interval(), sample.RTT(), sample.SmoothedRTT(), sample.ACKTime()
	_, _, _, _, _, _, _ = sample.ApplicationLimited(), sample.SchedulerLimited(), sample.Retransmitted(), sample.InRecovery(), sample.InFastRecovery(), sample.ACKDelayed(), sample.Valid()
	_, _ = sample.PacketState(), sample.TailLossProbeACK()

	name := mipstack.CongestionControl(fmt.Sprintf("external-test-%d", externalCongestionName.Add(1)))
	if err := mipstack.RegisterCongestionControl(name, mipstack.CongestionControlDefinition{
		New:      func() mipstack.CongestionController { return &externalCongestionController{} },
		Features: mipstack.CongestionControlFeatureDeliveryRate,
	}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, available := range mipstack.AvailableCongestionControls() {
		if available == name {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("registered controller %q is not discoverable", name)
	}
}
