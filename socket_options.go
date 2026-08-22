package mipstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// SocketOption is one strongly typed socket policy. Concrete option types are
// private; use SocketOptions to construct values understood by this package.
// Each constructor documents the creation operations that accept its value.
// Using an explicit setting outside that scope reports syscall.ENOPROTOOPT
// before an endpoint is created. Unset markers are accepted by every creation
// operation and have no effect where their corresponding setting is
// inapplicable.
type SocketOption interface {
	apply(socketOptionSet, socketOptionUse) (socketOptionSet, error)
}

// SocketOptionFactory constructs socket options used when creating sockets.
// Its value carries no state; use SocketOptions rather than constructing one.
type SocketOptionFactory uint8

// SocketOptions constructs creation-time socket policies. See the methods on
// [SocketOptionFactory] for each constructor's detailed contract. The
// constructors have the following operation scopes:
//
//   - ReadBuffer, TrafficClass, and FlowLabel are valid for every creation
//     method on ListenConfig and Dialer, TCPForwarderRequest.Accept, and
//     UDPForwarderRequest.Accept or UDPForwarderRequest.Listen.
//   - WriteBuffer, KeepAlive, KeepAliveConfig, NoDelay, IdleTimeout,
//     UserTimeout, CongestionControl, CongestionControlFactory, and
//     MaximumPacingRate are valid for ListenConfig.ListenTCP, Dialer.DialTCP,
//     and TCPForwarderRequest.Accept.
//   - AcceptQueue and SYNBacklog are valid only for ListenConfig.ListenTCP.
//   - ReceiveErrors, PathMTUDiscovery, HopLimit, Broadcast, MulticastHopLimit,
//     and MulticastLoopback are valid for the UDP and IP creation methods on
//     ListenConfig and Dialer, UDPForwarderRequest.Accept, and
//     UDPForwarderRequest.Listen.
//   - ReuseAddress and ReusePort are valid only for ListenConfig.ListenTCP and
//     ListenConfig.ListenUDP.
//   - IPHeaderIncludedOnWrite, IPHeaderIncludedOnRead, ICMPv4Filter,
//     ICMPv6Filter, and IPv6Checksum are valid only for
//     ListenConfig.ListenIP and Dialer.DialIP. The latter three are also
//     validated against the resolved address family and IP protocol.
//
// Every Unset constructor is valid for every socket creation operation. It
// removes an applicable earlier override of the same kind and otherwise has no
// effect. Using an explicit setting outside its scope reports
// syscall.ENOPROTOOPT before an endpoint is created.
const SocketOptions SocketOptionFactory = 0

// socketOptionBoolOverride records whether a boolean policy is inherited or
// explicitly disabled or enabled.
type socketOptionBoolOverride uint8

const (
	// socketOptionBoolOverrideUnset restores the operation-specific default.
	socketOptionBoolOverrideUnset socketOptionBoolOverride = iota
	// socketOptionBoolOverrideDisabled explicitly disables a policy.
	socketOptionBoolOverrideDisabled
	// socketOptionBoolOverrideEnabled explicitly enables a policy.
	socketOptionBoolOverrideEnabled
)

// newSocketOptionBoolOverride converts an explicit boolean policy to its
// internal override.
func newSocketOptionBoolOverride(enabled bool) socketOptionBoolOverride {
	if enabled {
		return socketOptionBoolOverrideEnabled
	}
	return socketOptionBoolOverrideDisabled
}

// valid reports whether override is a recognized tri-state boolean value.
func (override socketOptionBoolOverride) valid() bool {
	return override <= socketOptionBoolOverrideEnabled
}

// socketOptionOverride distinguishes an inherited policy from an explicit
// value, including an explicit zero value.
type socketOptionOverride[T any] struct {
	value T
	set   bool
}

// reuseAddressSocketOption stores one SO_REUSEADDR policy.
type reuseAddressSocketOption socketOptionBoolOverride

// reusePortSocketOption stores one SO_REUSEPORT policy.
type reusePortSocketOption socketOptionBoolOverride

// ipHeaderIncludedOnWriteSocketOption stores one IP_HDRINCL/IPV6_HDRINCL
// write policy.
type ipHeaderIncludedOnWriteSocketOption socketOptionBoolOverride

// ipHeaderIncludedOnReadSocketOption stores one complete-packet read policy.
type ipHeaderIncludedOnReadSocketOption socketOptionBoolOverride

// icmpV4FilterSocketOption stores one Linux-compatible ICMP_FILTER snapshot.
type icmpV4FilterSocketOption socketOptionOverride[ICMPv4Filter]

// icmpV6FilterSocketOption stores one RFC 3542 ICMP6_FILTER snapshot.
type icmpV6FilterSocketOption socketOptionOverride[ICMPv6Filter]

// ipv6ChecksumPolicy stores one IPV6_CHECKSUM enablement and field offset.
type ipv6ChecksumPolicy struct {
	enabled bool
	offset  int
}

// ipv6ChecksumSocketOption stores one raw IPv6 upper-layer checksum policy.
type ipv6ChecksumSocketOption socketOptionOverride[ipv6ChecksumPolicy]

// readBufferSocketOption stores one receive-buffer capacity override.
type readBufferSocketOption socketOptionOverride[int]

// trafficClassSocketOption stores one IPv4 TOS or IPv6 Traffic Class override.
type trafficClassSocketOption socketOptionOverride[int]

// flowLabelSocketOption stores one IPv6 Flow Label override.
type flowLabelSocketOption socketOptionOverride[uint32]

// writeBufferSocketOption stores one TCP send-buffer capacity override.
type writeBufferSocketOption socketOptionOverride[int]

// keepAliveSocketOption stores one TCP keepalive enablement override.
type keepAliveSocketOption socketOptionBoolOverride

// keepAliveConfigSocketOption stores one TCP keepalive timing override.
type keepAliveConfigSocketOption socketOptionOverride[KeepAliveConfig]

// noDelaySocketOption stores one TCP Nagle-policy override.
type noDelaySocketOption socketOptionBoolOverride

// idleTimeoutSocketOption stores one TCP receive-idle timeout override.
type idleTimeoutSocketOption socketOptionOverride[time.Duration]

// userTimeoutSocketOption stores one TCP unacknowledged-data timeout override.
type userTimeoutSocketOption socketOptionOverride[time.Duration]

// congestionControlSocketOption stores one registered TCP congestion-control
// name. It shares its destination slot with congestionControlFactorySocketOption.
type congestionControlSocketOption struct {
	name CongestionControl
	set  bool
}

// congestionControlFactorySocketOption stores one local TCP
// congestion-control factory override.
type congestionControlFactorySocketOption socketOptionOverride[*CongestionControlFactory]

// maximumPacingRateSocketOption stores one TCP pacing-rate cap override.
type maximumPacingRateSocketOption socketOptionOverride[uint64]

// acceptQueueSocketOption stores one completed TCP handshake queue limit.
type acceptQueueSocketOption socketOptionOverride[int]

// synBacklogSocketOption stores one stateful TCP handshake limit.
type synBacklogSocketOption socketOptionOverride[int]

// receiveErrorsSocketOption stores one UDP or IP asynchronous-error policy.
type receiveErrorsSocketOption socketOptionBoolOverride

// pathMTUDiscoverySocketOption stores one UDP or IP PMTU-discovery policy.
type pathMTUDiscoverySocketOption socketOptionOverride[PathMTUDiscovery]

// hopLimitSocketOption stores one UDP or IP unicast hop-limit override.
type hopLimitSocketOption socketOptionOverride[int]

// broadcastSocketOption stores one UDP or IP broadcast-output policy.
type broadcastSocketOption socketOptionBoolOverride

// multicastHopLimitSocketOption stores one UDP or IP multicast hop limit.
type multicastHopLimitSocketOption socketOptionOverride[int]

// multicastLoopbackSocketOption stores one UDP or IP multicast-loopback policy.
type multicastLoopbackSocketOption socketOptionBoolOverride

// ReadBuffer fixes the receive-buffer capacity of a newly created TCP, UDP,
// or IP socket. On TCP it disables receive auto-tuning for that connection.
// The value must be positive; UDP and IP raise values below one message's
// metadata cost to that protocol's minimum usable capacity.
//
// It is valid for every creation method on ListenConfig and Dialer, for
// TCPForwarderRequest.Accept, and for UDPForwarderRequest.Accept and
// UDPForwarderRequest.Listen.
func (SocketOptionFactory) ReadBuffer(bytes int) SocketOption {
	return readBufferSocketOption{value: bytes, set: true}
}

// UnsetReadBuffer restores inheritance from the current Stack configuration,
// overriding an earlier ReadBuffer option in the same list. The unset marker
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetReadBuffer() SocketOption {
	return readBufferSocketOption{}
}

// apply validates and applies one receive-buffer override.
func (option readBufferSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if value.set && value.value <= 0 {
		return set, syscall.EINVAL
	}
	if use.isTCP() {
		set.tcp.readBuffer = value
	} else if use.isDatagram() {
		set.datagram.readBuffer = value
	} else {
		return set, syscall.ENOPROTOOPT
	}
	return set, nil
}

// TrafficClass sets the IPv4 TOS or IPv6 Traffic Class byte inherited by a
// newly created TCP, UDP, or IP socket. TCP masks the two ECN bits because its
// transport state controls them independently. Value must be in [0, 255].
//
// It is valid for every creation method on ListenConfig and Dialer, for
// TCPForwarderRequest.Accept, and for UDPForwarderRequest.Accept and
// UDPForwarderRequest.Listen.
func (SocketOptionFactory) TrafficClass(value int) SocketOption {
	return trafficClassSocketOption{value: value, set: true}
}

// UnsetTrafficClass restores inheritance from the current Stack
// configuration, overriding an earlier TrafficClass option in the same list.
// The unset marker is valid for every socket creation operation.
func (SocketOptionFactory) UnsetTrafficClass() SocketOption {
	return trafficClassSocketOption{}
}

// apply validates and applies one traffic-class override.
func (option trafficClassSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if value.set && (value.value < 0 || value.value > 255) {
		return set, syscall.EINVAL
	}
	if use.isTCP() {
		set.tcp.trafficClass = value
	} else if use.isDatagram() {
		set.datagram.trafficClass = value
	} else {
		return set, syscall.ENOPROTOOPT
	}
	return set, nil
}

// FlowLabel fixes the IPv6 Flow Label inherited by a newly created TCP, UDP,
// or IP socket. Zero explicitly disables automatic labeling. An IPv4-only
// endpoint reports EAFNOSUPPORT when the socket is created. Label must fit in
// 20 bits.
//
// It is valid for every creation method on ListenConfig and Dialer, for
// TCPForwarderRequest.Accept, and for UDPForwarderRequest.Accept and
// UDPForwarderRequest.Listen.
func (SocketOptionFactory) FlowLabel(label uint32) SocketOption {
	return flowLabelSocketOption{value: label, set: true}
}

// UnsetFlowLabel restores inheritance, including automatic flow-label
// selection when the Stack default is zero. The unset marker is valid for
// every socket creation operation.
func (SocketOptionFactory) UnsetFlowLabel() SocketOption {
	return flowLabelSocketOption{}
}

// apply validates and applies one flow-label override.
func (option flowLabelSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[uint32](option)
	if value.set && value.value > ipv6MaximumFlowLabel {
		return set, syscall.EINVAL
	}
	if use.isTCP() {
		set.tcp.flowLabel = value
	} else if use.isDatagram() {
		set.datagram.flowLabel = value
	} else {
		return set, syscall.ENOPROTOOPT
	}
	return set, nil
}

// WriteBuffer fixes the send-buffer capacity of a newly created TCP
// connection and disables send auto-tuning for that connection. It is not a
// UDP or IP option because those protocols synchronously hand writes to the
// stack output queue and retain no per-socket send buffer.
//
// It is valid for ListenConfig.ListenTCP, Dialer.DialTCP, and
// TCPForwarderRequest.Accept.
func (SocketOptionFactory) WriteBuffer(bytes int) SocketOption {
	return writeBufferSocketOption{value: bytes, set: true}
}

// UnsetWriteBuffer restores TCP send-buffer inheritance and auto-tuning. It
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetWriteBuffer() SocketOption {
	return writeBufferSocketOption{}
}

// apply validates and applies one TCP send-buffer override.
func (option writeBufferSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.tcp.writeBuffer = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value <= 0 {
		return set, syscall.EINVAL
	}
	set.tcp.writeBuffer = value
	return set, nil
}

// KeepAlive controls keepalive probing on newly created TCP connections. It is
// valid for ListenConfig.ListenTCP, Dialer.DialTCP, and
// TCPForwarderRequest.Accept.
func (SocketOptionFactory) KeepAlive(enabled bool) SocketOption {
	return keepAliveSocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetKeepAlive restores the current Stack TCP keepalive default. It is valid
// for every socket creation operation.
func (SocketOptionFactory) UnsetKeepAlive() SocketOption {
	return keepAliveSocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one TCP keepalive enablement override.
func (option keepAliveSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.tcp.keepAlive = override
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	set.tcp.keepAlive = override
	return set, nil
}

// KeepAliveConfig sets the keepalive idle interval, probe interval, and probe
// count inherited by newly created TCP connections. Every field must be
// positive. It is valid for ListenConfig.ListenTCP, Dialer.DialTCP, and
// TCPForwarderRequest.Accept.
func (SocketOptionFactory) KeepAliveConfig(config KeepAliveConfig) SocketOption {
	return keepAliveConfigSocketOption{value: config, set: true}
}

// UnsetKeepAliveConfig restores the current Stack keepalive timing policy. It
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetKeepAliveConfig() SocketOption {
	return keepAliveConfigSocketOption{}
}

// apply validates and applies one TCP keepalive timing override.
func (option keepAliveConfigSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[KeepAliveConfig](option)
	if !value.set {
		set.tcp.keepAliveConfig = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value.Idle <= 0 || value.value.Interval <= 0 || value.value.Count <= 0 {
		return set, syscall.EINVAL
	}
	set.tcp.keepAliveConfig = value
	return set, nil
}

// NoDelay controls Nagle coalescing on newly created TCP connections. True is
// the package and net.TCPConn-compatible default. It is valid for
// ListenConfig.ListenTCP, Dialer.DialTCP, and TCPForwarderRequest.Accept.
func (SocketOptionFactory) NoDelay(enabled bool) SocketOption {
	return noDelaySocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetNoDelay restores the current Stack TCP Nagle policy. It is valid for
// every socket creation operation.
func (SocketOptionFactory) UnsetNoDelay() SocketOption {
	return noDelaySocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one TCP Nagle-policy override.
func (option noDelaySocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.tcp.noDelay = override
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	set.tcp.noDelay = override
	return set, nil
}

// IdleTimeout closes newly created TCP connections after this duration
// without an acceptable inbound segment. Zero explicitly disables the policy.
// It is valid for ListenConfig.ListenTCP, Dialer.DialTCP, and
// TCPForwarderRequest.Accept.
func (SocketOptionFactory) IdleTimeout(timeout time.Duration) SocketOption {
	return idleTimeoutSocketOption{value: timeout, set: true}
}

// UnsetIdleTimeout restores the current Stack receive-idle policy. It is valid
// for every socket creation operation.
func (SocketOptionFactory) UnsetIdleTimeout() SocketOption {
	return idleTimeoutSocketOption{}
}

// apply validates and applies one TCP receive-idle timeout override.
func (option idleTimeoutSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[time.Duration](option)
	if !value.set {
		set.tcp.idleTimeout = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 {
		return set, syscall.EINVAL
	}
	set.tcp.idleTimeout = value
	return set, nil
}

// UserTimeout bounds how long data on a newly created TCP connection may
// remain unacknowledged or unsent behind a zero window. Zero explicitly
// disables this custom bound. It is valid for ListenConfig.ListenTCP,
// Dialer.DialTCP, and TCPForwarderRequest.Accept.
func (SocketOptionFactory) UserTimeout(timeout time.Duration) SocketOption {
	return userTimeoutSocketOption{value: timeout, set: true}
}

// UnsetUserTimeout restores the current Stack TCP user-timeout policy. It is
// valid for every socket creation operation.
func (SocketOptionFactory) UnsetUserTimeout() SocketOption {
	return userTimeoutSocketOption{}
}

// apply validates and applies one TCP user-timeout override.
func (option userTimeoutSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[time.Duration](option)
	if !value.set {
		set.tcp.userTimeout = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 {
		return set, syscall.EINVAL
	}
	set.tcp.userTimeout = value
	return set, nil
}

// CongestionControl selects one registered algorithm for newly created TCP
// connections. It overrides CongestionControlFactory when it appears later in
// the same option list. It is valid for ListenConfig.ListenTCP,
// Dialer.DialTCP, and TCPForwarderRequest.Accept.
func (SocketOptionFactory) CongestionControl(algorithm CongestionControl) SocketOption {
	return congestionControlSocketOption{name: algorithm, set: true}
}

// UnsetCongestionControl restores the current Stack congestion-control
// policy, overriding either congestion-control option form used earlier. The
// unset marker is valid for every socket creation operation.
func (SocketOptionFactory) UnsetCongestionControl() SocketOption {
	return congestionControlSocketOption{}
}

// apply resolves and applies one registered congestion-control override.
func (option congestionControlSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	if !option.set {
		set.tcp.congestionControl = socketOptionOverride[*CongestionControlFactory]{}
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	factory, exists := registeredCongestionControlFactory(option.name)
	if !exists {
		return set, syscall.EINVAL
	}
	set.tcp.congestionControl = socketOptionOverride[*CongestionControlFactory]{value: factory, set: true}
	return set, nil
}

// CongestionControlFactory selects an immutable local factory for newly
// created TCP connections. It overrides CongestionControl when it appears
// later in the same option list. It is valid for ListenConfig.ListenTCP,
// Dialer.DialTCP, and TCPForwarderRequest.Accept.
func (SocketOptionFactory) CongestionControlFactory(factory *CongestionControlFactory) SocketOption {
	return congestionControlFactorySocketOption{value: factory, set: true}
}

// apply validates and applies one local congestion-control factory override.
func (option congestionControlFactorySocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[*CongestionControlFactory](option)
	if !value.set {
		set.tcp.congestionControl = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if !value.value.valid() {
		return set, syscall.EINVAL
	}
	set.tcp.congestionControl = value
	return set, nil
}

// MaximumPacingRate caps newly created TCP connections to bytesPerSecond.
// Zero explicitly removes the cap. It is valid for ListenConfig.ListenTCP,
// Dialer.DialTCP, and TCPForwarderRequest.Accept.
func (SocketOptionFactory) MaximumPacingRate(bytesPerSecond uint64) SocketOption {
	return maximumPacingRateSocketOption{value: bytesPerSecond, set: true}
}

// UnsetMaximumPacingRate restores the current Stack pacing-rate policy. It is
// valid for every socket creation operation.
func (SocketOptionFactory) UnsetMaximumPacingRate() SocketOption {
	return maximumPacingRateSocketOption{}
}

// apply validates and applies one TCP pacing-rate override.
func (option maximumPacingRateSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[uint64](option)
	if !value.set {
		set.tcp.maximumPacingRate = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	set.tcp.maximumPacingRate = value
	return set, nil
}

// AcceptQueue sets the number of completed TCP handshakes that may wait for
// Accept. Zero creates an unbuffered accept handoff; the value cannot be
// negative. The policy belongs to the listener and is not inherited by a
// connection. It is valid only for ListenConfig.ListenTCP.
func (SocketOptionFactory) AcceptQueue(capacity int) SocketOption {
	return acceptQueueSocketOption{value: capacity, set: true}
}

// UnsetAcceptQueue restores the current Stack completed-handshake limit. It is
// valid for every socket creation operation.
func (SocketOptionFactory) UnsetAcceptQueue() SocketOption {
	return acceptQueueSocketOption{}
}

// apply validates and applies one TCP accept-queue override.
func (option acceptQueueSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.tcp.acceptQueue = value
		return set, nil
	}
	if use != socketOptionTCPListen {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 {
		return set, syscall.EINVAL
	}
	set.tcp.acceptQueue = value
	return set, nil
}

// SYNBacklog sets the number of stateful TCP handshakes owned by a listener
// before it falls back to SYN cookies. Zero selects cookies immediately; the
// value cannot be negative. It is valid only for ListenConfig.ListenTCP.
func (SocketOptionFactory) SYNBacklog(capacity int) SocketOption {
	return synBacklogSocketOption{value: capacity, set: true}
}

// UnsetSYNBacklog restores the current Stack stateful-handshake limit. It is
// valid for every socket creation operation.
func (SocketOptionFactory) UnsetSYNBacklog() SocketOption {
	return synBacklogSocketOption{}
}

// apply validates and applies one TCP SYN-backlog override.
func (option synBacklogSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.tcp.synBacklog = value
		return set, nil
	}
	if use != socketOptionTCPListen {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 {
		return set, syscall.EINVAL
	}
	set.tcp.synBacklog = value
	return set, nil
}

// ReceiveErrors controls whether newly created UDP and IP sockets reserve
// asynchronous errors for ReadError instead of returning them from ordinary
// reads after queued payloads. It is valid for the UDP and IP creation methods
// on ListenConfig and Dialer, and for UDPForwarderRequest.Accept and
// UDPForwarderRequest.Listen.
func (SocketOptionFactory) ReceiveErrors(enabled bool) SocketOption {
	return receiveErrorsSocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetReceiveErrors restores the current Stack asynchronous-error policy. It
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetReceiveErrors() SocketOption {
	return receiveErrorsSocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one UDP or IP asynchronous-error override.
func (option receiveErrorsSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.datagram.receiveErrors = override
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	set.datagram.receiveErrors = override
	return set, nil
}

// PathMTUDiscovery sets the Linux-compatible IP_MTU_DISCOVER policy inherited
// by newly created UDP and IP sockets. It is valid for the UDP and IP creation
// methods on ListenConfig and Dialer, and for UDPForwarderRequest.Accept and
// UDPForwarderRequest.Listen.
func (SocketOptionFactory) PathMTUDiscovery(mode PathMTUDiscovery) SocketOption {
	return pathMTUDiscoverySocketOption{value: mode, set: true}
}

// UnsetPathMTUDiscovery restores the current Stack PMTU-discovery policy. It
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetPathMTUDiscovery() SocketOption {
	return pathMTUDiscoverySocketOption{}
}

// apply validates and applies one UDP or IP PMTU-discovery override.
func (option pathMTUDiscoverySocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[PathMTUDiscovery](option)
	if !value.set {
		set.datagram.pathMTUDiscovery = value
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	if !value.value.valid() {
		return set, syscall.EINVAL
	}
	set.datagram.pathMTUDiscovery = value
	return set, nil
}

// HopLimit sets the default unicast IPv4 TTL or IPv6 Hop Limit inherited by
// newly created UDP and IP sockets. Value must be in [0, 255]. Zero is valid
// only for an IPv6-only endpoint; IPv4 and dual-stack creation report EINVAL.
// It is valid for the UDP and IP creation methods on ListenConfig and Dialer,
// and for UDPForwarderRequest.Accept and UDPForwarderRequest.Listen.
func (SocketOptionFactory) HopLimit(hopLimit int) SocketOption {
	return hopLimitSocketOption{value: hopLimit, set: true}
}

// UnsetHopLimit restores the current Stack unicast hop-limit policy. It is
// valid for every socket creation operation.
func (SocketOptionFactory) UnsetHopLimit() SocketOption {
	return hopLimitSocketOption{}
}

// apply validates and applies one UDP or IP unicast hop-limit override.
func (option hopLimitSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.datagram.hopLimit = value
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 || value.value > 255 {
		return set, syscall.EINVAL
	}
	set.datagram.hopLimit = value
	return set, nil
}

// Broadcast controls the SO_BROADCAST-equivalent output permission inherited
// by newly created UDP and IP sockets. It is valid for the UDP and IP creation
// methods on ListenConfig and Dialer, and for UDPForwarderRequest.Accept and
// UDPForwarderRequest.Listen.
func (SocketOptionFactory) Broadcast(enabled bool) SocketOption {
	return broadcastSocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetBroadcast restores the current Stack broadcast-output policy. It is
// valid for every socket creation operation.
func (SocketOptionFactory) UnsetBroadcast() SocketOption {
	return broadcastSocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one UDP or IP broadcast-output override.
func (option broadcastSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.datagram.broadcast = override
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	set.datagram.broadcast = override
	return set, nil
}

// MulticastHopLimit sets the IPv4 multicast TTL or IPv6 multicast Hop Limit
// inherited by newly created UDP and IP sockets. Value must be in [0, 255];
// zero confines output to this host. It is valid for the UDP and IP creation
// methods on ListenConfig and Dialer, and for UDPForwarderRequest.Accept and
// UDPForwarderRequest.Listen.
func (SocketOptionFactory) MulticastHopLimit(hopLimit int) SocketOption {
	return multicastHopLimitSocketOption{value: hopLimit, set: true}
}

// UnsetMulticastHopLimit restores the current Stack multicast hop limit. It
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetMulticastHopLimit() SocketOption {
	return multicastHopLimitSocketOption{}
}

// apply validates and applies one UDP or IP multicast hop-limit override.
func (option multicastHopLimitSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.datagram.multicastHopLimit = value
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 || value.value > 255 {
		return set, syscall.EINVAL
	}
	set.datagram.multicastHopLimit = value
	return set, nil
}

// MulticastLoopback controls delivery of transmitted multicast packets to
// matching local memberships for newly created UDP and IP sockets. It is valid
// for the UDP and IP creation methods on ListenConfig and Dialer, and for
// UDPForwarderRequest.Accept and UDPForwarderRequest.Listen.
func (SocketOptionFactory) MulticastLoopback(enabled bool) SocketOption {
	return multicastLoopbackSocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetMulticastLoopback restores the current Stack multicast-loopback policy.
// It is valid for every socket creation operation.
func (SocketOptionFactory) UnsetMulticastLoopback() SocketOption {
	return multicastLoopbackSocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one UDP or IP multicast-loopback override.
func (option multicastLoopbackSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.datagram.multicastLoopback = override
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	set.datagram.multicastLoopback = override
	return set, nil
}

// ReuseAddress controls Linux SO_REUSEADDR-style address reuse during bind.
// TCP listeners enable it by default, matching Go's standard listener setup;
// an explicit false value disables that behavior. UDP listeners default to an
// exclusive binding and require every overlapping endpoint to opt in. It is
// valid only for ListenConfig.ListenTCP and ListenConfig.ListenUDP.
func (SocketOptionFactory) ReuseAddress(enabled bool) SocketOption {
	return reuseAddressSocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetReuseAddress restores the operation-specific SO_REUSEADDR default,
// overriding earlier ReuseAddress options in the same list. The unset marker
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetReuseAddress() SocketOption {
	return reuseAddressSocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one SO_REUSEADDR policy.
func (option reuseAddressSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.reuseAddress = use == socketOptionTCPListen
		return set, nil
	}
	if use != socketOptionTCPListen && use != socketOptionUDPListen {
		return set, syscall.ENOPROTOOPT
	}
	set.reuseAddress = override == socketOptionBoolOverrideEnabled
	return set, nil
}

// ReusePort controls Linux SO_REUSEPORT-style flow distribution for TCP and
// UDP listeners. Every endpoint in an overlapping group must enable it. It is
// valid only for ListenConfig.ListenTCP and ListenConfig.ListenUDP.
func (SocketOptionFactory) ReusePort(enabled bool) SocketOption {
	return reusePortSocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetReusePort restores the default disabled SO_REUSEPORT policy,
// overriding earlier ReusePort options in the same list. The unset marker is
// valid for every socket creation operation.
func (SocketOptionFactory) UnsetReusePort() SocketOption {
	return reusePortSocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one SO_REUSEPORT policy.
func (option reusePortSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.reusePort = false
		return set, nil
	}
	if use != socketOptionTCPListen && use != socketOptionUDPListen {
		return set, syscall.ENOPROTOOPT
	}
	set.reusePort = override == socketOptionBoolOverrideEnabled
	return set, nil
}

// IPHeaderIncludedOnWrite controls whether IPConn writes contain a complete
// IPv4 or IPv6 packet instead of a protocol payload. It corresponds to
// IP_HDRINCL and IPV6_HDRINCL. Use IPConn.SetIPHeaderIncludedOnWrite to change
// the representation of an existing socket. It is valid only for
// ListenConfig.ListenIP and Dialer.DialIP.
func (SocketOptionFactory) IPHeaderIncludedOnWrite(enabled bool) SocketOption {
	return ipHeaderIncludedOnWriteSocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetIPHeaderIncludedOnWrite restores protocol-payload writes, overriding
// earlier IPHeaderIncludedOnWrite options in the same list. The unset marker
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetIPHeaderIncludedOnWrite() SocketOption {
	return ipHeaderIncludedOnWriteSocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one complete-packet write policy.
func (option ipHeaderIncludedOnWriteSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.ip.headerIncludedOnWrite = false
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	set.ip.headerIncludedOnWrite = override == socketOptionBoolOverrideEnabled
	return set, nil
}

// IPHeaderIncludedOnRead controls whether IPConn reads return the complete,
// reassembled IP packet instead of only its protocol payload. It is a
// creation-time option because changing the interpretation of queued messages
// would make concurrent reads ambiguous. It is valid only for
// ListenConfig.ListenIP and Dialer.DialIP.
func (SocketOptionFactory) IPHeaderIncludedOnRead(enabled bool) SocketOption {
	return ipHeaderIncludedOnReadSocketOption(newSocketOptionBoolOverride(enabled))
}

// UnsetIPHeaderIncludedOnRead restores protocol-payload reads, overriding
// earlier IPHeaderIncludedOnRead options in the same list. The unset marker is
// valid for every socket creation operation.
func (SocketOptionFactory) UnsetIPHeaderIncludedOnRead() SocketOption {
	return ipHeaderIncludedOnReadSocketOption(socketOptionBoolOverrideUnset)
}

// apply validates and applies one complete-packet read policy.
func (option ipHeaderIncludedOnReadSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.ip.headerIncludedOnRead = false
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	set.ip.headerIncludedOnRead = override == socketOptionBoolOverrideEnabled
	return set, nil
}

// ICMPv4Filter installs a receive-type filter on a newly created IPv4 ICMP
// protocol socket. A generic dual-stack ip:icmp socket applies it only to its
// IPv4 branch. Other protocols report syscall.ENOPROTOOPT and IPv6-only
// sockets report syscall.EAFNOSUPPORT before the endpoint is created.
func (SocketOptionFactory) ICMPv4Filter(filter ICMPv4Filter) SocketOption {
	return icmpV4FilterSocketOption{value: filter, set: true}
}

// UnsetICMPv4Filter restores the all-accepting default, overriding an earlier
// ICMPv4Filter option in the same list. The unset marker is valid for every
// socket creation operation.
func (SocketOptionFactory) UnsetICMPv4Filter() SocketOption {
	return icmpV4FilterSocketOption{}
}

// apply records one IPv4 ICMP receive filter for late protocol validation.
func (option icmpV4FilterSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[ICMPv4Filter](option)
	if !value.set {
		set.ip.icmpV4Filter = value
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	set.ip.icmpV4Filter = value
	return set, nil
}

// ICMPv6Filter installs a receive-type filter on a newly created ICMPv6
// protocol socket. A generic dual-stack ip:ipv6-icmp socket applies it only to
// its IPv6 branch. Other protocols report syscall.ENOPROTOOPT and IPv4-only
// sockets report syscall.EAFNOSUPPORT before the endpoint is created.
func (SocketOptionFactory) ICMPv6Filter(filter ICMPv6Filter) SocketOption {
	return icmpV6FilterSocketOption{value: filter, set: true}
}

// UnsetICMPv6Filter restores the all-accepting default, overriding an earlier
// ICMPv6Filter option in the same list. The unset marker is valid for every
// socket creation operation.
func (SocketOptionFactory) UnsetICMPv6Filter() SocketOption {
	return icmpV6FilterSocketOption{}
}

// apply records one ICMPv6 receive filter for late protocol validation.
func (option icmpV6FilterSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[ICMPv6Filter](option)
	if !value.set {
		set.ip.icmpV6Filter = value
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	set.ip.icmpV6Filter = value
	return set, nil
}

// IPv6Checksum controls RFC 3542 IPV6_CHECKSUM processing for a newly created
// non-ICMPv6 protocol socket. When enabled, offset is the even, non-negative
// byte offset of the 16-bit checksum field in the upper-layer payload. When
// disabled, offset is ignored. IPv4-only sockets report syscall.EAFNOSUPPORT;
// ICMPv6 sockets report syscall.EINVAL because their checksum at offset 2 is
// mandatory and cannot be configured.
func (SocketOptionFactory) IPv6Checksum(enabled bool, offset int) SocketOption {
	return ipv6ChecksumSocketOption{
		value: ipv6ChecksumPolicy{enabled: enabled, offset: offset},
		set:   true,
	}
}

// UnsetIPv6Checksum restores the protocol default, overriding an earlier
// IPv6Checksum option in the same list. ICMPv6 restores mandatory processing
// at offset 2; other protocols restore disabled processing. The unset marker
// is valid for every socket creation operation.
func (SocketOptionFactory) UnsetIPv6Checksum() SocketOption {
	return ipv6ChecksumSocketOption{}
}

// apply validates one checksum offset and records it for late protocol and
// address-family validation.
func (option ipv6ChecksumSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[ipv6ChecksumPolicy](option)
	if !value.set {
		set.ip.ipv6Checksum = value
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	if value.value.enabled && (value.value.offset < 0 || value.value.offset&1 != 0) {
		return set, syscall.EINVAL
	}
	set.ip.ipv6Checksum = value
	return set, nil
}

// tcpSocketOptionSet is the compact set of TCP policies that may remain on a
// listener and be applied to future accepted connections.
type tcpSocketOptionSet struct {
	readBuffer        socketOptionOverride[int]
	writeBuffer       socketOptionOverride[int]
	keepAlive         socketOptionBoolOverride
	keepAliveConfig   socketOptionOverride[KeepAliveConfig]
	noDelay           socketOptionBoolOverride
	idleTimeout       socketOptionOverride[time.Duration]
	userTimeout       socketOptionOverride[time.Duration]
	congestionControl socketOptionOverride[*CongestionControlFactory]
	maximumPacingRate socketOptionOverride[uint64]
	trafficClass      socketOptionOverride[int]
	flowLabel         socketOptionOverride[uint32]
	acceptQueue       socketOptionOverride[int]
	synBacklog        socketOptionOverride[int]
}

// datagramSocketOptionSet is the shared UDP and raw-IP creation-policy set.
type datagramSocketOptionSet struct {
	readBuffer        socketOptionOverride[int]
	receiveErrors     socketOptionBoolOverride
	pathMTUDiscovery  socketOptionOverride[PathMTUDiscovery]
	hopLimit          socketOptionOverride[int]
	broadcast         socketOptionBoolOverride
	multicastHopLimit socketOptionOverride[int]
	multicastLoopback socketOptionBoolOverride
	trafficClass      socketOptionOverride[int]
	flowLabel         socketOptionOverride[uint32]
}

// ipSocketOptionSet contains policies meaningful only to raw IP sockets.
type ipSocketOptionSet struct {
	headerIncludedOnWrite bool
	headerIncludedOnRead  bool
	icmpV4Filter          socketOptionOverride[ICMPv4Filter]
	icmpV6Filter          socketOptionOverride[ICMPv6Filter]
	ipv6Checksum          socketOptionOverride[ipv6ChecksumPolicy]
}

// socketOptionSet is the validated creation-time option snapshot.
type socketOptionSet struct {
	tcp          tcpSocketOptionSet
	datagram     datagramSocketOptionSet
	ip           ipSocketOptionSet
	reuseAddress bool
	reusePort    bool
}

// socketOptionUse identifies the protocol and creation operation against
// which an option list is validated.
type socketOptionUse uint8

const (
	// socketOptionTCPListen validates options for a passive TCP endpoint.
	socketOptionTCPListen socketOptionUse = iota
	// socketOptionUDPListen validates options for an unconnected UDP endpoint.
	socketOptionUDPListen
	// socketOptionIPListen validates options for an unconnected IP endpoint.
	socketOptionIPListen
	// socketOptionTCPDial validates options for an active TCP endpoint.
	socketOptionTCPDial
	// socketOptionUDPDial validates options for a connected UDP endpoint.
	socketOptionUDPDial
	// socketOptionIPDial validates options for a connected IP endpoint.
	socketOptionIPDial
)

// isTCP reports whether use creates a TCP endpoint or listener.
func (use socketOptionUse) isTCP() bool {
	return use == socketOptionTCPListen || use == socketOptionTCPDial
}

// isDatagram reports whether use creates a UDP or raw-IP message endpoint.
func (use socketOptionUse) isDatagram() bool {
	return use == socketOptionUDPListen || use == socketOptionUDPDial || use == socketOptionIPListen || use == socketOptionIPDial
}

// validateFamily applies policies whose validity depends on the endpoint's
// resolved address family. Dual-stack endpoints are represented as IPv6 and
// may use IPv6 flow labels, but cannot use a zero hop limit because they can
// also emit IPv4 packets.
func (set socketOptionSet) validateFamily(use socketOptionUse, ipv6, dual bool) error {
	flowLabel := set.datagram.flowLabel
	if use.isTCP() {
		flowLabel = set.tcp.flowLabel
	}
	if flowLabel.set && !ipv6 && !dual {
		return syscall.EAFNOSUPPORT
	}
	if use.isDatagram() && set.datagram.hopLimit.set && set.datagram.hopLimit.value == 0 && (!ipv6 || dual) {
		return syscall.EINVAL
	}
	return nil
}

// validateIPSocket applies raw options whose validity depends on the parsed
// upper-layer protocol and the endpoint's resolved family capabilities.
func (set socketOptionSet) validateIPSocket(protocol byte, ipv6, dual bool) error {
	hasIPv4 := !ipv6 || dual
	if set.ip.icmpV4Filter.set {
		if !hasIPv4 {
			return syscall.EAFNOSUPPORT
		}
		if protocol != ProtocolICMPv4 {
			return syscall.ENOPROTOOPT
		}
	}
	if set.ip.icmpV6Filter.set {
		if !ipv6 {
			return syscall.EAFNOSUPPORT
		}
		if protocol != ProtocolICMPv6 {
			return syscall.ENOPROTOOPT
		}
	}
	if set.ip.ipv6Checksum.set {
		if !ipv6 {
			return syscall.EAFNOSUPPORT
		}
		if protocol == ProtocolICMPv6 {
			return syscall.EINVAL
		}
	}
	return nil
}

// applyDatagramSocketOptions overlays explicit creation policies on normalized
// UDP or raw-IP defaults. minimumReceiveBuffer accounts for the protocol's
// queue metadata when a caller requests a smaller positive capacity.
func applyDatagramSocketOptions(defaults DatagramSocketDefaults, options datagramSocketOptionSet, minimumReceiveBuffer int) DatagramSocketDefaults {
	if options.readBuffer.set {
		defaults.ReceiveBuffer = options.readBuffer.value
		if defaults.ReceiveBuffer < minimumReceiveBuffer {
			defaults.ReceiveBuffer = minimumReceiveBuffer
		}
	}
	if options.receiveErrors != socketOptionBoolOverrideUnset {
		defaults.ReceiveErrors = options.receiveErrors == socketOptionBoolOverrideEnabled
	}
	if options.pathMTUDiscovery.set {
		defaults.PathMTUDiscovery = options.pathMTUDiscovery.value
	}
	if options.hopLimit.set {
		defaults.HopLimit = options.hopLimit.value
	}
	if options.broadcast != socketOptionBoolOverrideUnset {
		defaults.DisableBroadcast = options.broadcast == socketOptionBoolOverrideDisabled
	}
	if options.multicastHopLimit.set {
		defaults.MulticastHopLimit = options.multicastHopLimit.value
	}
	if options.multicastLoopback != socketOptionBoolOverrideUnset {
		defaults.DisableMulticastLoopback = options.multicastLoopback == socketOptionBoolOverrideDisabled
	}
	if options.trafficClass.set {
		defaults.TrafficClass = uint8(options.trafficClass.value)
	}
	if options.flowLabel.set {
		defaults.FlowLabel = options.flowLabel.value
	}
	return defaults
}

// parseSocketOptions applies options in order; a repeated option uses its last
// explicit value or unset marker.
func parseSocketOptions(options []SocketOption, use socketOptionUse) (socketOptionSet, error) {
	set := socketOptionSet{reuseAddress: use == socketOptionTCPListen}
	for _, option := range options {
		if option == nil {
			return socketOptionSet{}, syscall.ENOPROTOOPT
		}
		var err error
		set, err = option.apply(set, use)
		if err != nil {
			return socketOptionSet{}, err
		}
	}
	return set, nil
}

// ListenConfig contains options applied before a socket is bound. The zero
// value is ready for use.
type ListenConfig struct {
	// Options contains creation policies applied before binding. The call reads
	// but does not retain the slice. Repeated option kinds use the last value.
	Options []SocketOption
}

// ListenTCP binds a TCP listener on stack. The returned net.Listener has
// dynamic type *TCPListener.
func (config *ListenConfig) ListenTCP(ctx context.Context, stack *Stack, network string, local netip.AddrPort) (net.Listener, error) {
	if stack == nil {
		return nil, socketOperationError("listen", network, nil, net.TCPAddrFromAddrPort(local), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(listenConfigOptions(config), socketOptionTCPListen)
	if err != nil {
		return nil, socketOperationError("listen", network, nil, net.TCPAddrFromAddrPort(local), err)
	}
	var binding tcpListenerBinding = exclusiveTCPListenerBinding{reuseAddress: options.reuseAddress}
	if options.reusePort {
		binding = reuseTCPListenerBinding{reuseAddress: options.reuseAddress}
	}
	return stack.listenTCP(ctx, network, local, binding, options.tcp)
}

// ListenUDP binds an unconnected UDP packet socket on stack. The returned
// net.PacketConn has dynamic type *UDPConn.
func (config *ListenConfig) ListenUDP(ctx context.Context, stack *Stack, network string, local netip.AddrPort) (net.PacketConn, error) {
	if stack == nil {
		return nil, socketOperationError("listen", network, nil, net.UDPAddrFromAddrPort(local), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(listenConfigOptions(config), socketOptionUDPListen)
	if err != nil {
		return nil, socketOperationError("listen", network, nil, net.UDPAddrFromAddrPort(local), err)
	}
	var binding udpSocketBinding = exclusiveUDPSocketBinding{}
	if options.reusePort {
		binding = reuseUDPSocketBinding{reuseAddress: options.reuseAddress}
	} else if options.reuseAddress {
		binding = reuseAddressUDPSocketBinding{}
	}
	return stack.listenUDP(ctx, network, local, binding, options.datagram)
}

// ListenIP binds an unconnected IP protocol socket on stack. The returned
// net.PacketConn has dynamic type *IPConn.
func (config *ListenConfig) ListenIP(ctx context.Context, stack *Stack, network string, local netip.Addr) (net.PacketConn, error) {
	if stack == nil {
		return nil, socketOperationError("listen", network, nil, ipNetAddr(local), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(listenConfigOptions(config), socketOptionIPListen)
	if err != nil {
		return nil, socketOperationError("listen", network, nil, ipNetAddr(local), err)
	}
	return stack.listenIP(ctx, network, local, options)
}

// listenConfigOptions treats a nil *ListenConfig like its useful zero value.
func listenConfigOptions(config *ListenConfig) []SocketOption {
	if config == nil {
		return nil
	}
	return config.Options
}

// Dialer contains options applied before a socket is connected. The zero value
// is ready for use.
type Dialer struct {
	// Options contains creation policies applied before connecting. The call
	// reads but does not retain the slice. Repeated option kinds use the last
	// value.
	Options []SocketOption
}

// DialTCP establishes a TCP connection through stack.
func (dialer *Dialer) DialTCP(ctx context.Context, stack *Stack, network string, source, remote netip.AddrPort) (net.Conn, error) {
	if stack == nil {
		return nil, socketOperationError("dial", network, net.TCPAddrFromAddrPort(source), net.TCPAddrFromAddrPort(remote), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(dialerOptions(dialer), socketOptionTCPDial)
	if err != nil {
		return nil, socketOperationError("dial", network, net.TCPAddrFromAddrPort(source), net.TCPAddrFromAddrPort(remote), err)
	}
	return stack.dialTCP(ctx, network, source, remote, options.tcp)
}

// DialUDP creates a connected UDP socket through stack.
func (dialer *Dialer) DialUDP(ctx context.Context, stack *Stack, network string, source, remote netip.AddrPort) (net.Conn, error) {
	if stack == nil {
		return nil, socketOperationError("dial", network, net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(remote), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(dialerOptions(dialer), socketOptionUDPDial)
	if err != nil {
		return nil, socketOperationError("dial", network, net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(remote), err)
	}
	return stack.dialUDP(ctx, network, source, remote, options.datagram)
}

// DialIP creates a connected IP protocol socket through stack.
func (dialer *Dialer) DialIP(ctx context.Context, stack *Stack, network string, source, remote netip.Addr) (net.Conn, error) {
	if stack == nil {
		return nil, socketOperationError("dial", network, ipNetAddr(source), ipNetAddr(remote), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(dialerOptions(dialer), socketOptionIPDial)
	if err != nil {
		return nil, socketOperationError("dial", network, ipNetAddr(source), ipNetAddr(remote), err)
	}
	return stack.dialIP(ctx, network, source, remote, options)
}

// dialerOptions treats a nil *Dialer like its useful zero value.
func dialerOptions(dialer *Dialer) []SocketOption {
	if dialer == nil {
		return nil
	}
	return dialer.Options
}
