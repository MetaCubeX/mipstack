package mipstack

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	// CongestionControlCUBIC selects RFC 9438 CUBIC with Reno-friendly growth.
	CongestionControlCUBIC = "cubic"
	// CongestionControlReno selects RFC 5681 Reno congestion avoidance.
	CongestionControlReno = "reno"
	// CongestionControlBBR selects model-based BBR congestion control.
	CongestionControlBBR = "bbr"
	// CongestionControlBBR3 selects Google's loss-bounded BBRv3 model.
	CongestionControlBBR3 = "bbr3"
)

// CongestionControlContext identifies the TCP connection for which a
// controller is being created. It is an immutable, by-value snapshot; dynamic
// transport state is supplied by CongestionEventInitialize and later events.
type CongestionControlContext struct {
	// LocalAddress is the connection's local TCP endpoint.
	LocalAddress netip.AddrPort
	// RemoteAddress is the connection's peer TCP endpoint.
	RemoteAddress netip.AddrPort
	// Passive reports whether the connection was accepted rather than dialed.
	Passive bool
	// Forwarded reports whether a TCP forwarder accepted the connection for an
	// intercepted destination. Every forwarded connection is also passive.
	Forwarded bool
}

// CongestionController is one connection's congestion-control policy.
// HandleCongestionEvent is called serially by the connection actor. It must
// return promptly, must not retain event or references reachable from it, and
// must ignore event types it does not recognize. The event storage is reused
// as soon as HandleCongestionEvent returns. The first call for each controller
// is CongestionEventInitialize and the final call is CongestionEventRelease.
// An implementation must not start work that outlives the release callback.
// Different connections own different controller instances and may invoke
// them concurrently; package-level state therefore requires synchronization.
//
// A controller owns congestion policy and its private model. TCP continues to
// own acknowledgement validation, loss detection, retransmission selection,
// SACK/RACK/TLP, PRR accounting, and delivery-rate measurement.
type CongestionController interface {
	// HandleCongestionEvent applies one serialized transport event.
	HandleCongestionEvent(event *CongestionEvent)
}

// CongestionControlFeatures declares transport work required by a controller.
// Unknown bits are rejected when the controller is registered.
type CongestionControlFeatures uint32

const (
	// CongestionControlFeatureDeliveryRate asks TCP to retain per-transmission
	// metadata and include a delivery-rate sample in ACK events.
	CongestionControlFeatureDeliveryRate CongestionControlFeatures = 1 << iota
	// CongestionControlFeatureCustomPacing asks TCP to send pacing query, wake,
	// cancellation, and policy-change events instead of using its window pacer.
	CongestionControlFeatureCustomPacing
	// CongestionControlFeatureTransmissionEvents asks TCP to report original
	// transmissions and retransmissions. Custom pacers require this feature so
	// they can advance their clock only after an actual transmission.
	CongestionControlFeatureTransmissionEvents
	// CongestionControlFeatureCustomRecovery asks TCP to expose recovery-window
	// selection, PRR, partial-ACK, duplicate-ACK, and exit decisions. TCP applies
	// its RFC defaults when this feature is absent.
	CongestionControlFeatureCustomRecovery
	// CongestionControlFeatureLossEvents asks TCP to retain the opaque packet
	// state returned by transmission events and report each transmission
	// generation that is proven lost. It also enables tail-loss-probe recovery
	// notifications. Transmission events are required so a controller can seed
	// the state associated with each generation.
	CongestionControlFeatureLossEvents
)

// congestionControlKnownFeatures is the complete transport-supported feature mask.
const congestionControlKnownFeatures = CongestionControlFeatureDeliveryRate |
	CongestionControlFeatureCustomPacing |
	CongestionControlFeatureTransmissionEvents |
	CongestionControlFeatureCustomRecovery |
	CongestionControlFeatureLossEvents

// CongestionControlDefinition describes a congestion-control implementation
// before it is validated and frozen into a CongestionControlFactory. New may
// be called concurrently for different connections, must return promptly, and
// must return a non-nil, independent controller on every call. It must not
// retain references to mutable connection state; the context is an immutable
// value. SendBufferMultiplier requests automatic send-buffer growth to this
// multiple of cwnd; zero retains the ordinary socket auto-tuning policy.
type CongestionControlDefinition struct {
	// Name is the diagnostic name and, when registered, the process-registry key.
	Name string
	// New creates one independent controller for the supplied connection.
	New func(CongestionControlContext) CongestionController
	// Features requests optional transport work for the controller.
	Features CongestionControlFeatures
	// SendBufferMultiplier requests a send buffer sized as a multiple of cwnd.
	SendBufferMultiplier uint32
}

// CongestionControlFactory is an immutable, reusable per-connection controller
// factory. It may be shared by stacks, listeners, and connections; every use
// invokes its definition's New function to create an independent controller.
// Factory pointer identity determines whether a live connection's selected
// implementation changed.
type CongestionControlFactory struct {
	definition CongestionControlDefinition
}

// NewCongestionControlFactory validates definition and returns a local factory
// without registering it process-wide. Definition.Name is used for diagnostics
// and need not be globally unique. Reuse the returned pointer when successive
// configurations should identify the same implementation.
func NewCongestionControlFactory(definition CongestionControlDefinition) (*CongestionControlFactory, error) {
	if err := validateCongestionControlDefinition(definition); err != nil {
		return nil, err
	}
	return &CongestionControlFactory{definition: definition}, nil
}

// Name returns the diagnostic name reported by TCPConnInfo. A nil factory has an
// empty name and is not a valid connection policy.
func (f *CongestionControlFactory) Name() string {
	if f == nil {
		return ""
	}
	return f.definition.Name
}

// valid reports whether f could have been returned by the public constructor.
func (f *CongestionControlFactory) valid() bool {
	return f != nil && validateCongestionControlDefinition(f.definition) == nil
}

// validateCongestionControlDefinition checks one factory description.
func validateCongestionControlDefinition(definition CongestionControlDefinition) error {
	if definition.Name == "" {
		return fmt.Errorf("mipstack: congestion control name is empty")
	}
	if definition.New == nil {
		return fmt.Errorf("mipstack: congestion control %q has no factory", definition.Name)
	}
	if unknown := definition.Features &^ congestionControlKnownFeatures; unknown != 0 {
		return fmt.Errorf("mipstack: congestion control %q has unknown features %#x", definition.Name, uint32(unknown))
	}
	if definition.Features&CongestionControlFeatureCustomPacing != 0 && definition.Features&CongestionControlFeatureTransmissionEvents == 0 {
		return fmt.Errorf("mipstack: congestion control %q custom pacing requires transmission events", definition.Name)
	}
	if definition.Features&CongestionControlFeatureLossEvents != 0 && definition.Features&CongestionControlFeatureTransmissionEvents == 0 {
		return fmt.Errorf("mipstack: congestion control %q loss events require transmission events", definition.Name)
	}
	return nil
}

// congestionControlRegistry holds built-in and application-registered factories.
var congestionControlRegistry = struct {
	sync.RWMutex
	factories map[string]*CongestionControlFactory
}{factories: map[string]*CongestionControlFactory{
	CongestionControlCUBIC: mustCongestionControlFactory(CongestionControlDefinition{
		Name:     CongestionControlCUBIC,
		New:      func(CongestionControlContext) CongestionController { return newCUBICCongestionControl() },
		Features: CongestionControlFeatureTransmissionEvents,
	}),
	CongestionControlReno: mustCongestionControlFactory(CongestionControlDefinition{
		Name: CongestionControlReno,
		New:  func(CongestionControlContext) CongestionController { return newRenoCongestionControl() },
	}),
	CongestionControlBBR: mustCongestionControlFactory(CongestionControlDefinition{
		Name: CongestionControlBBR,
		New:  func(CongestionControlContext) CongestionController { return newBBRCongestionControl() },
		Features: CongestionControlFeatureDeliveryRate |
			CongestionControlFeatureCustomPacing |
			CongestionControlFeatureTransmissionEvents |
			CongestionControlFeatureCustomRecovery,
		SendBufferMultiplier: 3,
	}),
	CongestionControlBBR3: mustCongestionControlFactory(CongestionControlDefinition{
		Name: CongestionControlBBR3,
		New:  func(CongestionControlContext) CongestionController { return newBBR3CongestionControl() },
		Features: CongestionControlFeatureDeliveryRate |
			CongestionControlFeatureCustomPacing |
			CongestionControlFeatureTransmissionEvents |
			CongestionControlFeatureCustomRecovery |
			CongestionControlFeatureLossEvents,
		SendBufferMultiplier: 3,
	}),
}}

// mustCongestionControlFactory constructs one statically defined built-in.
func mustCongestionControlFactory(definition CongestionControlDefinition) *CongestionControlFactory {
	factory, err := NewCongestionControlFactory(definition)
	if err != nil {
		panic(err)
	}
	return factory
}

// RegisterCongestionControl makes factory available by name to future stack
// configurations and connections. Registration is concurrency-safe and
// permanent for the process lifetime, so active connections can keep using
// the factory without an unregister race. A name cannot be replaced. Factory
// remains valid for direct local use if registration fails.
func RegisterCongestionControl(factory *CongestionControlFactory) error {
	if !factory.valid() {
		return fmt.Errorf("mipstack: invalid congestion control factory")
	}
	congestionControlRegistry.Lock()
	defer congestionControlRegistry.Unlock()
	name := factory.definition.Name
	if _, exists := congestionControlRegistry.factories[name]; exists {
		return fmt.Errorf("mipstack: congestion control %q is already registered", name)
	}
	congestionControlRegistry.factories[name] = factory
	return nil
}

// AvailableCongestionControls returns the registered algorithm names in
// lexical order. The returned slice is independent of the registry.
func AvailableCongestionControls() []string {
	congestionControlRegistry.RLock()
	controls := make([]string, 0, len(congestionControlRegistry.factories))
	for name := range congestionControlRegistry.factories {
		controls = append(controls, name)
	}
	congestionControlRegistry.RUnlock()
	sort.Slice(controls, func(i, j int) bool { return controls[i] < controls[j] })
	return controls
}

// registeredCongestionControlFactory returns one stable registry entry.
func registeredCongestionControlFactory(name string) (*CongestionControlFactory, bool) {
	congestionControlRegistry.RLock()
	factory, exists := congestionControlRegistry.factories[name]
	congestionControlRegistry.RUnlock()
	return factory, exists
}

// CongestionEventType identifies why a controller is being called. New event
// types may be added without changing CongestionController; implementations
// must ignore values they do not recognize.
type CongestionEventType uint8

const (
	// CongestionEventUnknown is never sent by TCP.
	CongestionEventUnknown CongestionEventType = iota
	// CongestionEventInitialize seeds a newly established controller and
	// permits updates to its initial cwnd, ssthresh, and pacing-rate policy.
	CongestionEventInitialize
	// CongestionEventACK reports newly delivered data and permits updates to
	// cwnd, ssthresh, and the common pacing-rate policy.
	CongestionEventACK
	// CongestionEventLoss reports entry into loss-based congestion recovery and
	// permits updates to cwnd, ssthresh, and common pacing policy.
	CongestionEventLoss
	// CongestionEventECN reports a new ECN congestion indication and permits
	// updates to cwnd, ssthresh, and common pacing policy.
	CongestionEventECN
	// CongestionEventTimeout reports the first RTO in a recovery episode. TCP
	// accepts updated ssthresh and common pacing policy, then applies the RFC
	// one-MSS timeout window.
	CongestionEventTimeout
	// CongestionEventPacketSent reports an original data transmission to a
	// controller that requested transmission events. It follows delivery-rate
	// snapshot capture and precedes advancement of the common pacer. A custom
	// controller may update cwnd and common pacing policy, for example when
	// leaving a reduced probe state.
	CongestionEventPacketSent
	// CongestionEventPacketRetransmitted reports a retransmission to a controller
	// that requested transmission events, after delivery-rate snapshot capture.
	// It permits updates to common pacing policy.
	CongestionEventPacketRetransmitted
	// CongestionEventRecovery reports a TCP recovery-window transition and
	// permits the outputs documented by CongestionRecovery plus common pacing
	// policy updates.
	CongestionEventRecovery
	// CongestionEventStateChanged reports a congestion-phase transition. State
	// is observational except for persistent pacing policy.
	CongestionEventStateChanged
	// CongestionEventPacing reports custom-pacer work. State is observational.
	CongestionEventPacing
	// CongestionEventMTUChanged reports a new path maximum segment size. State is
	// observational except for persistent pacing policy.
	CongestionEventMTUChanged
	// CongestionEventDiagnostics asks the controller for current diagnostics
	// without changing transport state.
	CongestionEventDiagnostics
	// CongestionEventPacketLost reports one transmission generation newly
	// proven lost by SACK, RACK, or an RTO. PacketBytes and PacketState describe
	// that generation. State is observational.
	CongestionEventPacketLost
	// CongestionEventTailLossProbeRecovered corresponds to Linux
	// CA_EVENT_TLP_RECOVERY: a retransmitted tail-loss probe repaired genuine
	// tail loss rather than merely recovering a lost ACK. PacketBytes describes
	// the repaired range and PacketState is its pre-probe transmission state.
	// State is observational.
	CongestionEventTailLossProbeRecovered
	// CongestionEventRelease is the final callback before TCP drops or replaces
	// a controller. State is observational. Implementations must release any
	// controller-owned resources and must not retain event or references from it.
	CongestionEventRelease
)

// CongestionPhase is TCP's high-level congestion state, corresponding to the
// state exposed to Linux congestion-control modules.
type CongestionPhase uint8

const (
	// CongestionPhaseUnknown is used before controller initialization.
	CongestionPhaseUnknown CongestionPhase = iota
	// CongestionPhaseOpen has no active congestion response.
	CongestionPhaseOpen
	// CongestionPhaseDisorder has duplicate or selective ACK evidence but no
	// proven loss. TCP may add finer-grained disorder notifications later.
	CongestionPhaseDisorder
	// CongestionPhaseCWR is responding to ECN congestion.
	CongestionPhaseCWR
	// CongestionPhaseRecovery is fast loss recovery.
	CongestionPhaseRecovery
	// CongestionPhaseLoss is retransmission-timeout recovery.
	CongestionPhaseLoss
)

// CongestionState is the transport snapshot visible to a controller. TCP
// applies changes to CongestionWindow, SlowStartThreshold, UsePacingRate, and
// PacingRate only for event types that explicitly permit them; the remaining
// fields are read-only. Pacing policy persists between callbacks. When
// UsePacingRate is false, TCP derives pacing from cwnd and SRTT. Setting it true
// makes the common pacer use PacingRate bytes per second. A zero duration or
// counter means that the value is not yet known.
type CongestionState struct {
	// CongestionWindow is cwnd in bytes.
	CongestionWindow uint32
	// SlowStartThreshold is ssthresh in bytes.
	SlowStartThreshold uint32
	// BytesInFlight is the transport's current congestion flight in bytes.
	BytesInFlight uint32
	// MaximumSegmentSize is the current sender MSS in bytes.
	MaximumSegmentSize int
	// SmoothedRTT is the current RFC 6298 smoothed round-trip time.
	SmoothedRTT time.Duration
	// MinimumRTT is the current transport minimum-RTT estimate.
	MinimumRTT time.Duration
	// UsePacingRate selects PacingRate instead of TCP's window-derived rate.
	UsePacingRate bool
	// PacingRate is the requested or current model rate in bytes per second.
	PacingRate uint64
	// MaximumPacingRate is the socket pacing ceiling in bytes per second.
	MaximumPacingRate uint64
	// DeliveredBytes is the cumulative delivery-rate sampler byte count.
	DeliveredBytes uint64
	// LostBytes is the cumulative transport-proven lost byte count.
	LostBytes uint64
	// ApplicationLimited reports an active application-limited interval.
	ApplicationLimited bool
	// SchedulerLimited reports an active local-scheduler-limited interval.
	SchedulerLimited bool
	// SchedulerLimitedEvents counts material local pacing wake delays.
	SchedulerLimitedEvents uint64
	// Phase is TCP's current congestion-control phase.
	Phase CongestionPhase
}

// CongestionRecoveryStage identifies one transport-owned recovery step.
type CongestionRecoveryStage uint8

const (
	// CongestionRecoveryUnknown is never sent by TCP.
	CongestionRecoveryUnknown CongestionRecoveryStage = iota
	// CongestionRecoveryCheckpoint precedes a recoverable congestion signal.
	CongestionRecoveryCheckpoint
	// CongestionRecoverySelectFlight selects the flight used to enter recovery.
	CongestionRecoverySelectFlight
	// CongestionRecoveryEnter applies the initial fast-recovery window.
	CongestionRecoveryEnter
	// CongestionRecoveryPRR applies a PRR-proposed window.
	CongestionRecoveryPRR
	// CongestionRecoveryExit leaves fast recovery.
	CongestionRecoveryExit
	// CongestionRecoveryPartialACK handles a NewReno partial ACK.
	CongestionRecoveryPartialACK
	// CongestionRecoveryDuplicateACK applies non-SACK duplicate-ACK inflation.
	CongestionRecoveryDuplicateACK
	// CongestionRecoveryUndo reports that recovery was proven spurious.
	CongestionRecoveryUndo
)

// CongestionRecovery describes a transport-owned recovery transition. TCP
// places its RFC-default result in State.CongestionWindow before dispatch;
// controllers with CongestionControlFeatureCustomRecovery may replace it.
// Flight is initialized to the transport default during
// CongestionRecoverySelectFlight and is the only mutable field of that stage.
type CongestionRecovery struct {
	// Stage identifies the current recovery interaction.
	Stage CongestionRecoveryStage
	// SACK reports whether selective acknowledgement recovery is active.
	SACK bool
	// OrdinaryFlight is TCP's ordinary bytes-in-flight estimate.
	OrdinaryFlight uint32
	// LossFlight is the RFC loss-recovery flight estimate.
	LossFlight uint32
	// Flight is the mutable result of CongestionRecoverySelectFlight and the
	// selected or current recovery flight during later stages.
	Flight uint32
	// PreviousWindow is cwnd before TCP installs ProposedWindow.
	PreviousWindow uint32
	// Acknowledged is the byte advance for a partial ACK.
	Acknowledged uint32
	// ProposedWindow is TCP's RFC-default cwnd for this stage.
	ProposedWindow uint32
}

// CongestionPacingOperation identifies a custom-pacing interaction.
type CongestionPacingOperation uint8

const (
	// CongestionPacingUnknown is never sent by TCP.
	CongestionPacingUnknown CongestionPacingOperation = iota
	// CongestionPacingQuery asks how long the next transmission must wait.
	CongestionPacingQuery
	// CongestionPacingWake reports an actor wake requested by the controller.
	CongestionPacingWake
	// CongestionPacingCancel invalidates a pending pacing wake.
	CongestionPacingCancel
	// CongestionPacingPolicyChanged reports a new maximum pacing rate.
	CongestionPacingPolicyChanged
)

// CongestionPacing carries one custom-pacer request and response. Query
// handlers place the required delay in Delay. Query and wake handlers may set
// MarkSchedulerLimited when local scheduling, rather than the path, delayed
// the current flight.
type CongestionPacing struct {
	// Operation identifies the custom-pacer interaction.
	Operation CongestionPacingOperation
	// Bytes is the pending transmission size for CongestionPacingQuery.
	Bytes int
	// TransmittedSegments counts original data segments sent by this controller.
	TransmittedSegments uint64
	// Delay is the query result before another transmission may be attempted.
	Delay time.Duration
	// MarkSchedulerLimited asks TCP to mark the current delivery interval.
	MarkSchedulerLimited bool
}

// CongestionDiagnostics is the controller-owned portion of TCPConnInfo.
type CongestionDiagnostics struct {
	// DeliveryRate is the current delivery model in bytes per second.
	DeliveryRate uint64
	// PacingRate is the effective paced-data rate in bytes per second.
	PacingRate uint64
	// State is an algorithm-defined short state name.
	State string
	// ApplicationLimited reports the controller's current local limitation.
	ApplicationLimited bool
	// SchedulerLimited reports a material userspace scheduling limitation.
	SchedulerLimited bool
	// SchedulerLimitedEvents counts material userspace pacing wake delays.
	SchedulerLimitedEvents uint64
}

// CongestionEvent is the reusable event passed to CongestionController.
// Fields not associated with Type are unspecified and must not be read.
// State points at the connection's persistent state; controllers may update
// fields only when the event and payload documentation permit it, and must not
// replace or retain the pointer. During recovery, only Flight in the selection
// stage and State.CongestionWindow in custom window stages are outputs. During
// pacing, only Delay and MarkSchedulerLimited are outputs. Diagnostics is an
// output only during diagnostic events. RateSample, when non-nil, is a
// callback-lifetime read-only view and must not be retained. PacketState is an
// opaque controller output during original-transmission and retransmission
// events; TCP returns the value unchanged if that generation is selected for a
// delivery-rate sample, later reported lost, or repaired by a tail-loss probe.
// A delivery-rate controller may set MarkApplicationLimited during an ACK
// event to ask TCP to mark the current flight as locally application limited.
type CongestionEvent struct {
	// Type identifies the valid event payload and permitted outputs.
	Type CongestionEventType
	// Time is ingress time for ACKs and the observation time for other events.
	Time time.Time
	// State is the connection state shared for the callback lifetime.
	State *CongestionState
	// Acknowledged is newly cumulatively acknowledged data in bytes.
	Acknowledged uint32
	// AcknowledgementNumber is the cumulative TCP ACK sequence number.
	AcknowledgementNumber uint32
	// SampleRTT is the current ACK's RTT sample when unambiguous.
	SampleRTT time.Duration
	// RateSample is non-nil on ACK events when delivery-rate sampling is enabled.
	RateSample *CongestionRateSample
	// PacketBytes is the transmission size for packet events.
	PacketBytes int
	// PacketState is controller-owned per-generation state. It is writable only
	// during packet transmission events and read-only during packet-loss and
	// tail-loss-probe events.
	PacketState uint64
	// OutstandingBytes is sequence-space still outstanding before a packet event.
	OutstandingBytes uint32
	// PreviousMaximumSegmentSize is the sender MSS before an MTU event.
	PreviousMaximumSegmentSize int
	// PreviousPhase is the phase before CongestionEventStateChanged.
	PreviousPhase CongestionPhase
	// MarkApplicationLimited asks TCP to mark the current delivery interval.
	MarkApplicationLimited bool
	// Recovery is valid for CongestionEventRecovery.
	Recovery CongestionRecovery
	// Pacing is valid for CongestionEventPacing.
	Pacing CongestionPacing
	// Diagnostics is the output of CongestionEventDiagnostics.
	Diagnostics CongestionDiagnostics
}
