package mipstack

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// multicastDefaultRobustness is the RFC 9776/RFC 3810 default.
	multicastDefaultRobustness = 2
	// multicastDefaultQueryInterval is the default Querier's Query Interval.
	multicastDefaultQueryInterval = 125 * time.Second
	// multicastDefaultResponseInterval is the default Query Response Interval.
	multicastDefaultResponseInterval = 10 * time.Second
	// multicastUnsolicitedReportInterval bounds state-change retransmission
	// jitter in both IGMPv3 and MLDv2.
	multicastUnsolicitedReportInterval = time.Second
	// multicastMaximumQuerySources bounds state retained from untrusted
	// Group-and-Source-Specific Queries. It exceeds RFC 9776's mandatory
	// service-API minimum while keeping one hostile query memory-bounded.
	multicastMaximumQuerySources = 4096
)

const (
	// igmpMembershipQuery is the IGMP Membership Query message type.
	igmpMembershipQuery = 0x11
	// igmpV1MembershipReport is the IGMPv1 Membership Report message type.
	igmpV1MembershipReport = 0x12
	// igmpV2MembershipReport is the IGMPv2 Membership Report message type.
	igmpV2MembershipReport = 0x16
	// igmpV2LeaveGroup is the IGMPv2 Leave Group message type.
	igmpV2LeaveGroup = 0x17
	// igmpV3MembershipReport is the IGMPv3 Membership Report message type.
	igmpV3MembershipReport = 0x22
	// mldMembershipQuery is the MLD Multicast Listener Query message type.
	mldMembershipQuery = 130
	// mldV1MembershipReport is the MLDv1 Multicast Listener Report type.
	mldV1MembershipReport = 131
	// mldV1ListenerDone is the MLDv1 Multicast Listener Done message type.
	mldV1ListenerDone = 132
	// mldV2MembershipReport is the MLDv2 Multicast Listener Report type.
	mldV2MembershipReport = 143

	// multicastRecordModeIsInclude reports the current INCLUDE source state.
	multicastRecordModeIsInclude = 1
	// multicastRecordModeIsExclude reports the current EXCLUDE source state.
	multicastRecordModeIsExclude = 2
	// multicastRecordChangeToIncludeMode announces a transition to INCLUDE.
	multicastRecordChangeToIncludeMode = 3
	// multicastRecordChangeToExcludeMode announces a transition to EXCLUDE.
	multicastRecordChangeToExcludeMode = 4
	// multicastRecordAllowNewSources adds sources accepted by the interface.
	multicastRecordAllowNewSources = 5
	// multicastRecordBlockOldSources removes sources accepted by the interface.
	multicastRecordBlockOldSources = 6
)

// MulticastSourceFilterMode identifies an RFC 3678 full-state source policy.
type MulticastSourceFilterMode uint8

const (
	// MulticastSourceFilterExclude receives packets from every source except
	// those listed. An empty EXCLUDE list is an any-source membership. Its
	// value matches Linux and RFC 3678's MCAST_EXCLUDE.
	MulticastSourceFilterExclude MulticastSourceFilterMode = iota
	// MulticastSourceFilterInclude receives packets only from listed sources.
	// An empty INCLUDE list is equivalent to leaving the group. Its value
	// matches Linux and RFC 3678's MCAST_INCLUDE.
	MulticastSourceFilterInclude
)

// MulticastSourceFilter is the complete per-socket RFC 3678 filter state for
// one group. SetMulticastSourceFilter copies Sources before returning, and
// MulticastSourceFilter returns an independent, address-sorted snapshot.
type MulticastSourceFilter struct {
	// Mode selects an INCLUDE or EXCLUDE source set.
	Mode MulticastSourceFilterMode
	// Sources is copied by SetMulticastSourceFilter and may be reused by the
	// caller as soon as that method returns.
	Sources []netip.Addr
}

// multicastFilterMode is the RFC 9776/RFC 3810 internal source-filter mode.
// It is deliberately independent of the Linux-compatible public constants,
// so zero-initialized protocol state remains INCLUDE as required by the
// interface-state merge rules.
type multicastFilterMode uint8

const (
	// multicastFilterInclude accepts only sources present in the filter.
	multicastFilterInclude multicastFilterMode = iota
	// multicastFilterExclude accepts every source absent from the filter.
	multicastFilterExclude
)

// multicastMembershipOperation identifies one RFC 3678 delta operation.
type multicastMembershipOperation uint8

const (
	// multicastJoinAnySource creates an EXCLUDE {} membership.
	multicastJoinAnySource multicastMembershipOperation = iota
	// multicastLeaveGroup removes every membership for the group.
	multicastLeaveGroup
	// multicastJoinSource adds one source to an INCLUDE membership.
	multicastJoinSource
	// multicastLeaveSource removes one source from an INCLUDE membership.
	multicastLeaveSource
	// multicastExcludeSource adds one source to an EXCLUDE membership.
	multicastExcludeSource
	// multicastIncludeSource removes one source from an EXCLUDE membership.
	multicastIncludeSource
)

// multicastFilter is one socket's source policy. Published filters and their
// source maps are immutable; delta operations replace them copy-on-write so
// lock-free dispatch snapshots can share the maps safely.
type multicastFilter struct {
	mode    multicastFilterMode
	sources map[netip.Addr]struct{}
}

// multicastEndpoint is implemented only by datagram sockets that can own an
// IP multicast membership. The marker keeps membership storage type-safe.
type multicastEndpoint interface {
	// multicastEndpoint marks a UDP or raw IP socket as a membership owner.
	multicastEndpoint()
}

// multicastEndpoints is the optional multicast dispatcher retained by Stack.
// Its concrete state is reachable only when an application joins a group.
type multicastEndpoints interface {
	// acceptsDestination reports whether the interface has an active
	// membership for a destination group.
	acceptsDestination(netip.Addr) bool
	// acceptsSource applies the aggregate interface filter for a group.
	acceptsSource(netip.Addr, netip.Addr) bool
	// deliverUDP fans one multicast datagram out to matching UDP memberships.
	deliverUDP(ipPacket, uint16, uint16)
	// deliverIP fans one multicast payload out to matching raw IP memberships.
	deliverIP(ipPacket) bool
	// deliverImplicitIP applies explicit filters while preserving the implicit
	// all-hosts delivery inherited by raw IP sockets.
	deliverImplicitIP(ipPacket, ipEndpoints) bool
	// handleControl processes one validated IGMP or MLD control packet.
	handleControl(ipPacket, time.Time)
	// removeEndpoint drops every membership owned by a closing socket.
	removeEndpoint(multicastEndpoint)
	// updateConfig reconciles memberships with a new interface configuration.
	updateConfig(*networkState)
	// close stops background work and releases retained membership state.
	close()
}

// multicastGroupState owns the socket filters and their RFC-derived aggregate
// interface state for one IP group.
type multicastGroupState struct {
	members   map[multicastEndpoint]*multicastFilter
	aggregate multicastFilter
	dispatch  atomic.Pointer[multicastDispatchGroup]
	query     multicastPendingQuery
	// lastReporter is used only by IGMPv1/v2 and MLDv1 suppression and leave
	// behavior. Version 3/2 reports are deliberately never suppressed.
	lastReporter bool
}

// multicastDispatchSnapshot is an immutable address index. Each indexed group
// publishes its own immutable dispatch entry independently.
type multicastDispatchSnapshot struct {
	groups map[netip.Addr]*multicastGroupState
}

// multicastDispatchGroup separates endpoint types so packet delivery does
// not allocate or perform interface assertions.
type multicastDispatchGroup struct {
	filter multicastFilter
	udp    []multicastUDPDispatch
	ip     []multicastIPDispatch
}

// multicastUDPDispatch is one immutable UDP membership entry.
type multicastUDPDispatch struct {
	connection *UDPConn
	filter     multicastFilter
}

// multicastIPDispatch is one immutable raw-IP membership entry.
type multicastIPDispatch struct {
	connection *IPConn
	filter     multicastFilter
}

// multicastPendingQuery is one group-specific delayed response. sourceQuery
// distinguishes an empty source intersection from a Group-Specific Query.
type multicastPendingQuery struct {
	deadline    time.Time
	sources     map[netip.Addr]struct{}
	sourceQuery bool
}

// multicastQuery carries both the current-version and legacy linear response
// delay interpretations needed when a newer wire Query arrives while the
// interface remains in an older host compatibility mode.
type multicastQuery struct {
	v6            bool
	version       uint8
	group         netip.Addr
	sources       []netip.Addr
	maximum       time.Duration
	legacyMaximum time.Duration
	robustness    uint8
	queryInterval time.Duration
}

// multicastRetransmission holds the RFC 9776 section 5.1 merge state for one
// interface group. Source counters survive successive changes until the
// configured robustness number of reports has carried each transition.
type multicastRetransmission struct {
	filter        multicastFilter
	exists        bool
	lastReporter  bool
	modeRemaining uint8
	allow         map[netip.Addr]uint8
	block         map[netip.Addr]uint8
	due           time.Time
}

// multicastReportRecord is one IGMPv3 or MLDv2 group record snapshot.
type multicastReportRecord struct {
	recordType byte
	group      netip.Addr
	sources    []netip.Addr
}

// multicastReportBatch is produced under the state lock and emitted without
// it, so bounded device-queue work never stalls membership or query handling.
type multicastReportBatch struct {
	v6           bool
	legacy       uint8
	group        netip.Addr
	exists       bool
	lastReporter bool
	records      []multicastReportRecord
	cancel       <-chan struct{}
}

// multicastQuerierState is the interface-wide querier state shared by the
// lightweight pre-membership seed and the complete membership dispatcher.
// Keeping it independent prevents an inbound Query by itself from retaining
// the report worker and serializers in binaries that never use multicast.
type multicastQuerierState struct {
	robustness       [2]uint8
	queryInterval    [2]time.Duration
	responseInterval [2]time.Duration
	compatibility    [2]uint8
	igmpV1Until      time.Time
	igmpV2Until      time.Time
	mldV1Until       time.Time
}

// multicastQuerierSeed retains Queries received before the first membership.
// Stack.mu protects it; it has no goroutine, timer, or membership state.
type multicastQuerierSeed struct {
	multicastQuerierState
}

// multicastState owns memberships for mipstack's single embedding interface.
// Stack.mu protects publication; mu protects the state after publication.
type multicastState struct {
	stack *Stack

	multicastQuerierState
	mu              sync.Mutex
	groups          map[netip.Addr]*multicastGroupState
	retransmissions map[netip.Addr]*multicastRetransmission
	familyGroups    [2]int
	generalQuery    [2]time.Time
	random          uint64
	wake            chan struct{}
	done            chan struct{}
	closeOnce       sync.Once
	closed          bool
	dispatch        atomic.Pointer[multicastDispatchSnapshot]
	reportCancel    [2]chan struct{}
}

// defaultMulticastQuerierState returns the RFC default host variables.
func defaultMulticastQuerierState() multicastQuerierState {
	return multicastQuerierState{
		robustness:       [2]uint8{multicastDefaultRobustness, multicastDefaultRobustness},
		queryInterval:    [2]time.Duration{multicastDefaultQueryInterval, multicastDefaultQueryInterval},
		responseInterval: [2]time.Duration{multicastDefaultResponseInterval, multicastDefaultResponseInterval},
		compatibility:    [2]uint8{3, 2},
	}
}

// newMulticastState constructs the lazily published membership dispatcher.
// The caller holds stack.mu, which also protects migration of multicastSeed.
func newMulticastState(stack *Stack) *multicastState {
	querier := defaultMulticastQuerierState()
	if stack.multicastSeed != nil {
		querier = stack.multicastSeed.multicastQuerierState
		querier.refresh(time.Now())
		stack.multicastSeed = nil
	}
	state := &multicastState{
		stack: stack, groups: make(map[netip.Addr]*multicastGroupState), retransmissions: make(map[netip.Addr]*multicastRetransmission),
		multicastQuerierState: querier,
		random:                uint64(time.Now().UnixNano()) ^ sipHash24(stack.flowLabelSecret, []byte("multicast-report")),
		wake:                  make(chan struct{}, 1), done: make(chan struct{}),
		reportCancel: [2]chan struct{}{make(chan struct{}), make(chan struct{})},
	}
	state.dispatch.Store(&multicastDispatchSnapshot{groups: make(map[netip.Addr]*multicastGroupState)})
	go state.run()
	return state
}

// ListenMulticastUDP creates a reusable UDP socket, disables multicast
// loopback like net.ListenMulticastUDP, and joins group. Mipstack has one
// embedding interface, so no interface selector is required. Source-specific
// groups return EINVAL; use ListenConfig with SocketOptions.ReuseAddress and
// JoinSourceSpecificGroup.
func (s *Stack) ListenMulticastUDP(ctx context.Context, network string, group netip.AddrPort) (*UDPConn, error) {
	group = netip.AddrPortFrom(group.Addr().Unmap(), group.Port())
	target := net.UDPAddrFromAddrPort(group)
	wrap := func(err error) (*UDPConn, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	if !group.IsValid() || !validMulticastGroup(group.Addr()) {
		return wrap(syscall.EINVAL)
	}
	if err := validateListenNetwork(network, "udp", group.Addr()); err != nil {
		return wrap(err)
	}
	localAddress := netip.IPv4Unspecified()
	listenNetwork := network
	if group.Addr().Is6() {
		localAddress = netip.IPv6Unspecified()
		if network == "udp" {
			listenNetwork = "udp6"
		}
	} else if network == "udp" {
		listenNetwork = "udp4"
	}
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReuseAddress(true)}}
	packetConnection, err := listenConfig.ListenUDP(ctx, s, listenNetwork, netip.AddrPortFrom(localAddress, group.Port()))
	if err != nil {
		return nil, err
	}
	connection := packetConnection.(*UDPConn)
	if err = connection.SetMulticastLoopback(false); err == nil {
		err = connection.JoinGroup(group.Addr())
	}
	if err != nil {
		_ = connection.Close()
		return wrap(err)
	}
	return connection, nil
}

// JoinGroup joins an any-source multicast group. It is the single-interface
// equivalent of MCAST_JOIN_GROUP and x/net's JoinGroup. RFC 4604 SSM groups
// return EINVAL and require JoinSourceSpecificGroup.
func (c *UDPConn) JoinGroup(group netip.Addr) error {
	return c.changeMulticastMembership(multicastJoinAnySource, group, netip.Addr{})
}

// LeaveGroup leaves a multicast group regardless of its source-filter mode.
func (c *UDPConn) LeaveGroup(group netip.Addr) error {
	return c.changeMulticastMembership(multicastLeaveGroup, group, netip.Addr{})
}

// JoinSourceSpecificGroup adds source to an INCLUDE-mode membership, creating
// the membership when this is its first source.
func (c *UDPConn) JoinSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastJoinSource, group, source)
}

// LeaveSourceSpecificGroup removes source from an INCLUDE-mode membership. It
// leaves the group when source was its final entry.
func (c *UDPConn) LeaveSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastLeaveSource, group, source)
}

// ExcludeSourceSpecificGroup blocks source on an existing any-source
// membership. It returns EINVAL for an SSM group.
func (c *UDPConn) ExcludeSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastExcludeSource, group, source)
}

// IncludeSourceSpecificGroup removes a source block from an existing
// any-source membership. It returns EINVAL for an SSM group.
func (c *UDPConn) IncludeSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastIncludeSource, group, source)
}

// SetBroadcast changes the SO_BROADCAST-equivalent output permission.
func (c *UDPConn) SetBroadcast(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.broadcast = enabled
		return nil
	}
}

// Broadcast reports the SO_BROADCAST-equivalent output permission.
func (c *UDPConn) Broadcast() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.broadcast, nil
	}
}

// SetMulticastHopLimit changes the IPv4 multicast TTL or IPv6 multicast Hop
// Limit. Zero confines output to this host.
func (c *UDPConn) SetMulticastHopLimit(hopLimit int) error {
	if hopLimit < 0 || hopLimit > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.multicastHopLimit = byte(hopLimit)
		return nil
	}
}

// MulticastHopLimit returns the IPv4 multicast TTL or IPv6 multicast Hop
// Limit used by subsequent writes.
func (c *UDPConn) MulticastHopLimit() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return 0, c.setOperationError(net.ErrClosed)
	default:
		return int(c.multicastHopLimit), nil
	}
}

// SetMulticastLoopback controls delivery of transmitted multicast packets to
// matching local memberships.
func (c *UDPConn) SetMulticastLoopback(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.multicastLoopback = enabled
		return nil
	}
}

// MulticastLoopback reports whether transmitted multicast packets are copied
// to matching local memberships.
func (c *UDPConn) MulticastLoopback() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.multicastLoopback, nil
	}
}

// SetMulticastSourceFilter atomically replaces the complete INCLUDE/EXCLUDE
// source policy for a previously joined group. An empty INCLUDE filter leaves
// that membership, matching Linux MCAST_MSFILTER behavior. EXCLUDE returns
// EINVAL for an RFC 4604 SSM group.
func (c *UDPConn) SetMulticastSourceFilter(group netip.Addr, filter MulticastSourceFilter) error {
	if c == nil || c.stack == nil {
		return net.ErrClosed
	}
	if err := c.stack.setMulticastSourceFilter(c, group, filter); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

// MulticastSourceFilter returns the complete source policy for group.
func (c *UDPConn) MulticastSourceFilter(group netip.Addr) (MulticastSourceFilter, error) {
	if c == nil || c.stack == nil {
		return MulticastSourceFilter{}, net.ErrClosed
	}
	filter, err := c.stack.multicastSourceFilter(c, group)
	if err != nil {
		return MulticastSourceFilter{}, c.setOperationError(err)
	}
	return filter, nil
}

// JoinGroup joins an any-source multicast group for a raw protocol socket.
// RFC 4604 SSM groups return EINVAL and require JoinSourceSpecificGroup.
func (c *IPConn) JoinGroup(group netip.Addr) error {
	return c.changeMulticastMembership(multicastJoinAnySource, group, netip.Addr{})
}

// LeaveGroup leaves a raw protocol socket's multicast group.
func (c *IPConn) LeaveGroup(group netip.Addr) error {
	return c.changeMulticastMembership(multicastLeaveGroup, group, netip.Addr{})
}

// JoinSourceSpecificGroup adds source to an INCLUDE-mode raw membership,
// creating the membership when this is its first source.
func (c *IPConn) JoinSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastJoinSource, group, source)
}

// LeaveSourceSpecificGroup removes source from an INCLUDE-mode raw membership.
// It leaves the group when source was its final entry.
func (c *IPConn) LeaveSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastLeaveSource, group, source)
}

// ExcludeSourceSpecificGroup blocks source on an existing any-source raw
// membership. It returns EINVAL for an SSM group.
func (c *IPConn) ExcludeSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastExcludeSource, group, source)
}

// IncludeSourceSpecificGroup removes a source block from an existing
// any-source raw membership. It returns EINVAL for an SSM group.
func (c *IPConn) IncludeSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastIncludeSource, group, source)
}

// SetBroadcast changes the raw socket's SO_BROADCAST-equivalent permission.
func (c *IPConn) SetBroadcast(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.broadcast = enabled
		return nil
	}
}

// Broadcast reports the raw socket's SO_BROADCAST-equivalent permission.
func (c *IPConn) Broadcast() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.broadcast, nil
	}
}

// SetMulticastHopLimit changes the raw socket's multicast TTL or Hop Limit.
func (c *IPConn) SetMulticastHopLimit(hopLimit int) error {
	if hopLimit < 0 || hopLimit > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.multicastHopLimit = byte(hopLimit)
		return nil
	}
}

// MulticastHopLimit returns the raw socket's multicast TTL or Hop Limit.
func (c *IPConn) MulticastHopLimit() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return 0, c.setOperationError(net.ErrClosed)
	default:
		return int(c.multicastHopLimit), nil
	}
}

// SetMulticastLoopback controls raw multicast delivery to local memberships.
func (c *IPConn) SetMulticastLoopback(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.multicastLoopback = enabled
		return nil
	}
}

// MulticastLoopback reports whether raw multicast output is delivered locally.
func (c *IPConn) MulticastLoopback() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.multicastLoopback, nil
	}
}

// SetMulticastSourceFilter atomically replaces a raw socket's complete
// INCLUDE/EXCLUDE source policy for a previously joined group. An empty
// INCLUDE filter leaves that membership. EXCLUDE returns EINVAL for an RFC
// 4604 SSM group.
func (c *IPConn) SetMulticastSourceFilter(group netip.Addr, filter MulticastSourceFilter) error {
	if c == nil || c.stack == nil {
		return net.ErrClosed
	}
	if err := c.stack.setMulticastSourceFilter(c, group, filter); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

// MulticastSourceFilter returns a raw socket's complete source policy.
func (c *IPConn) MulticastSourceFilter(group netip.Addr) (MulticastSourceFilter, error) {
	if c == nil || c.stack == nil {
		return MulticastSourceFilter{}, net.ErrClosed
	}
	filter, err := c.stack.multicastSourceFilter(c, group)
	if err != nil {
		return MulticastSourceFilter{}, c.setOperationError(err)
	}
	return filter, nil
}

// multicastEndpoint marks UDPConn as a membership owner.
func (*UDPConn) multicastEndpoint() {}

// multicastEndpoint marks IPConn as a membership owner.
func (*IPConn) multicastEndpoint() {}

// changeMulticastMembership applies one UDP membership operation.
func (c *UDPConn) changeMulticastMembership(operation multicastMembershipOperation, group, source netip.Addr) error {
	if c == nil || c.stack == nil {
		return net.ErrClosed
	}
	if err := c.stack.changeMulticastMembership(c, operation, group, source); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

// changeMulticastMembership applies one raw IP membership operation.
func (c *IPConn) changeMulticastMembership(operation multicastMembershipOperation, group, source netip.Addr) error {
	if c == nil || c.stack == nil {
		return net.ErrClosed
	}
	if err := c.stack.changeMulticastMembership(c, operation, group, source); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

// changeMulticastMembership validates endpoint ownership and serializes a
// membership update with socket removal.
func (s *Stack) changeMulticastMembership(endpoint multicastEndpoint, operation multicastMembershipOperation, group, source netip.Addr) error {
	group, source = group.Unmap(), source.Unmap()
	if !validMulticastGroup(group) {
		return syscall.EINVAL
	}
	if isSourceSpecificMulticast(group) &&
		(operation == multicastJoinAnySource || operation == multicastExcludeSource || operation == multicastIncludeSource) {
		return syscall.EINVAL
	}
	if source.IsValid() && !validMulticastSourceSyntax(source, group.Is6()) {
		return syscall.EINVAL
	}
	if operation >= multicastJoinSource && !source.IsValid() {
		return syscall.EINVAL
	}
	s.mu.Lock()
	if s.closed || !s.multicastEndpointRegisteredLocked(endpoint) {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if !multicastEndpointSupportsGroup(endpoint, group) {
		s.mu.Unlock()
		return syscall.EAFNOSUPPORT
	}
	if source.IsValid() && !validMulticastSourceAddress(s.network.Load(), source, group.Is6()) {
		s.mu.Unlock()
		return syscall.EINVAL
	}
	state, ok := s.multicast.(*multicastState)
	if !ok {
		switch operation {
		case multicastJoinAnySource, multicastJoinSource:
		case multicastLeaveGroup:
			s.mu.Unlock()
			return syscall.EADDRNOTAVAIL
		default:
			s.mu.Unlock()
			return syscall.EINVAL
		}
		state = newMulticastState(s)
		s.multicast = state
	}
	err := state.change(endpoint, operation, group, source)
	s.mu.Unlock()
	if err == nil {
		s.pruneFragments(s.network.Load())
	}
	return err
}

// setMulticastSourceFilter validates and installs one complete socket state.
func (s *Stack) setMulticastSourceFilter(endpoint multicastEndpoint, group netip.Addr, filter MulticastSourceFilter) error {
	group = group.Unmap()
	if !validMulticastGroup(group) ||
		filter.Mode != MulticastSourceFilterInclude && filter.Mode != MulticastSourceFilterExclude {
		return syscall.EINVAL
	}
	if filter.Mode == MulticastSourceFilterExclude && isSourceSpecificMulticast(group) {
		return syscall.EINVAL
	}
	sources := make(map[netip.Addr]struct{}, len(filter.Sources))
	for _, source := range filter.Sources {
		source = source.Unmap()
		if !validMulticastSourceSyntax(source, group.Is6()) {
			return syscall.EINVAL
		}
		sources[source] = struct{}{}
	}
	mode := multicastFilterInclude
	if filter.Mode == MulticastSourceFilterExclude {
		mode = multicastFilterExclude
	}
	s.mu.Lock()
	if s.closed || !s.multicastEndpointRegisteredLocked(endpoint) {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if !multicastEndpointSupportsGroup(endpoint, group) {
		s.mu.Unlock()
		return syscall.EAFNOSUPPORT
	}
	network := s.network.Load()
	for source := range sources {
		if !validMulticastSourceAddress(network, source, group.Is6()) {
			s.mu.Unlock()
			return syscall.EINVAL
		}
	}
	state, ok := s.multicast.(*multicastState)
	if !ok {
		s.mu.Unlock()
		if mode == multicastFilterInclude && len(sources) == 0 {
			return syscall.EADDRNOTAVAIL
		}
		return syscall.EINVAL
	}
	err := state.set(endpoint, group, mode, sources)
	s.mu.Unlock()
	if err == nil {
		s.pruneFragments(s.network.Load())
	}
	return err
}

// validMulticastSourceAddress recognizes an RFC 3678 unicast source in the
// requested family, including the IPv4 broadcast exclusions known to this
// single interface.
func validMulticastSourceAddress(network *networkState, source netip.Addr, v6 bool) bool {
	if !validMulticastSourceSyntax(source, v6) {
		return false
	}
	source = source.Unmap()
	if source.Is4() && network.broadcastDestination(source) {
		return false
	}
	return true
}

// validMulticastSourceSyntax recognizes an unzoned unicast address in one
// address family without consulting configuration-dependent broadcast state.
func validMulticastSourceSyntax(source netip.Addr, v6 bool) bool {
	source = source.Unmap()
	return source.IsValid() && !source.IsUnspecified() && !source.IsMulticast() && source.Zone() == "" && source.Is6() == v6
}

// isSourceSpecificMulticast recognizes the IANA SSM ranges from RFC 4607:
// IPv4 232/8 and every valid IPv6 FF3x::/32 scope.
func isSourceSpecificMulticast(group netip.Addr) bool {
	group = group.Unmap()
	if !group.IsMulticast() {
		return false
	}
	if group.Is4() {
		return group.As4()[0] == 232
	}
	raw := group.As16()
	return raw[1]>>4 == 3 && raw[2] == 0 && raw[3] == 0
}

// multicastSourceFilter snapshots one socket's current group state.
func (s *Stack) multicastSourceFilter(endpoint multicastEndpoint, group netip.Addr) (MulticastSourceFilter, error) {
	group = group.Unmap()
	if !validMulticastGroup(group) {
		return MulticastSourceFilter{}, syscall.EINVAL
	}
	s.mu.RLock()
	if s.closed || !s.multicastEndpointRegisteredLocked(endpoint) {
		s.mu.RUnlock()
		return MulticastSourceFilter{}, net.ErrClosed
	}
	state, ok := s.multicast.(*multicastState)
	if !ok {
		s.mu.RUnlock()
		return MulticastSourceFilter{}, syscall.EADDRNOTAVAIL
	}
	state.mu.Lock()
	s.mu.RUnlock()
	groupState := state.groups[group]
	var current *multicastFilter
	if groupState != nil {
		current = groupState.members[endpoint]
	}
	if current == nil {
		state.mu.Unlock()
		return MulticastSourceFilter{}, syscall.EADDRNOTAVAIL
	}
	mode := MulticastSourceFilterInclude
	if current.mode == multicastFilterExclude {
		mode = MulticastSourceFilterExclude
	}
	result := MulticastSourceFilter{Mode: mode, Sources: make([]netip.Addr, 0, len(current.sources))}
	for source := range current.sources {
		result.Sources = append(result.Sources, source)
	}
	state.mu.Unlock()
	sort.Slice(result.Sources, func(left, right int) bool { return result.Sources[left].Compare(result.Sources[right]) < 0 })
	return result, nil
}

// multicastEndpointRegisteredLocked reports whether endpoint is still owned
// by this stack while Stack.mu is held.
func (s *Stack) multicastEndpointRegisteredLocked(endpoint multicastEndpoint) bool {
	switch connection := endpoint.(type) {
	case *UDPConn:
		key := udpKey{address: connection.local, port: connection.port}
		if s.udp[key] == connection {
			return true
		}
		flow := udpFlowKey{local: netip.AddrPortFrom(connection.local, connection.port), remote: connection.remote}
		if s.udpForwarded[flow] == connection {
			return true
		}
		return s.udpReuse != nil && s.udpReuse.contains(connection)
	case *IPConn:
		state, ok := s.ip.(*ipEndpointState)
		return ok && state.contains(connection)
	}
	return false
}

// multicastEndpointSupportsGroup checks the immutable socket family policy.
func multicastEndpointSupportsGroup(endpoint multicastEndpoint, group netip.Addr) bool {
	switch connection := endpoint.(type) {
	case *UDPConn:
		return connection.dual || connection.v6 == group.Is6()
	case *IPConn:
		return connection.dual || connection.v6 == group.Is6()
	default:
		return false
	}
}

// change applies one membership delta and recomputes the RFC interface filter.
func (s *multicastState) change(endpoint multicastEndpoint, operation multicastMembershipOperation, group, source netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	groupState := s.groups[group]
	old, oldExists := multicastInterfaceFilter(groupState)
	oldLastReporter := groupState != nil && groupState.lastReporter
	filter := (*multicastFilter)(nil)
	if groupState != nil {
		filter = groupState.members[endpoint]
	}
	existingFilter := filter != nil
	switch operation {
	case multicastJoinAnySource:
		if filter != nil {
			return syscall.EADDRINUSE
		}
		filter = &multicastFilter{mode: multicastFilterExclude, sources: make(map[netip.Addr]struct{})}
	case multicastLeaveGroup:
		if filter == nil {
			return syscall.EADDRNOTAVAIL
		}
	case multicastJoinSource:
		if filter == nil {
			filter = &multicastFilter{mode: multicastFilterInclude, sources: make(map[netip.Addr]struct{})}
		} else if filter.mode != multicastFilterInclude {
			return syscall.EINVAL
		}
		if _, exists := filter.sources[source]; exists {
			return syscall.EADDRINUSE
		}
	case multicastLeaveSource:
		if filter == nil || filter.mode != multicastFilterInclude {
			return syscall.EINVAL
		}
		if _, exists := filter.sources[source]; !exists {
			return syscall.EADDRNOTAVAIL
		}
	case multicastExcludeSource:
		if filter == nil || filter.mode != multicastFilterExclude {
			return syscall.EINVAL
		}
		if _, exists := filter.sources[source]; exists {
			return syscall.EADDRINUSE
		}
	case multicastIncludeSource:
		if filter == nil || filter.mode != multicastFilterExclude {
			return syscall.EINVAL
		}
		if _, exists := filter.sources[source]; !exists {
			return syscall.EADDRNOTAVAIL
		}
	default:
		return syscall.EINVAL
	}
	if existingFilter && operation != multicastLeaveGroup {
		copied := cloneMulticastFilter(*filter)
		if copied.sources == nil {
			copied.sources = make(map[netip.Addr]struct{})
		}
		filter = &copied
	}
	if groupState == nil {
		groupState = &multicastGroupState{members: make(map[multicastEndpoint]*multicastFilter)}
		s.groups[group] = groupState
		if multicastGroupNeedsReport(group) {
			s.familyGroups[multicastFamilyIndex(group)]++
		}
	}
	switch operation {
	case multicastLeaveGroup:
		delete(groupState.members, endpoint)
	case multicastJoinSource, multicastExcludeSource:
		filter.sources[source] = struct{}{}
		groupState.members[endpoint] = filter
	case multicastLeaveSource:
		delete(filter.sources, source)
		if len(filter.sources) == 0 {
			delete(groupState.members, endpoint)
		} else {
			groupState.members[endpoint] = filter
		}
	case multicastIncludeSource:
		delete(filter.sources, source)
		groupState.members[endpoint] = filter
	default:
		groupState.members[endpoint] = filter
	}
	if len(groupState.members) == 0 {
		s.removeGroupLocked(group)
	} else {
		groupState.aggregate = aggregateMulticastFilter(groupState.members)
	}
	s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
	s.rebuildGroupDispatchLocked(group)
	return nil
}

// set replaces one endpoint's complete filter and recomputes interface state.
func (s *multicastState) set(endpoint multicastEndpoint, group netip.Addr, mode multicastFilterMode, sources map[netip.Addr]struct{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	groupState := s.groups[group]
	if groupState == nil || groupState.members[endpoint] == nil {
		if mode == multicastFilterInclude && len(sources) == 0 {
			return syscall.EADDRNOTAVAIL
		}
		// Linux's full-state source-filter API requires a prior ASM or SSM
		// join before either filter mode can be installed.
		return syscall.EINVAL
	}
	old, oldExists := multicastInterfaceFilter(groupState)
	oldLastReporter := groupState.lastReporter
	if mode == multicastFilterInclude && len(sources) == 0 {
		delete(groupState.members, endpoint)
		if len(groupState.members) == 0 {
			s.removeGroupLocked(group)
		} else {
			groupState.aggregate = aggregateMulticastFilter(groupState.members)
		}
		s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
		s.rebuildGroupDispatchLocked(group)
		return nil
	}
	groupState.members[endpoint] = &multicastFilter{mode: mode, sources: sources}
	groupState.aggregate = aggregateMulticastFilter(groupState.members)
	s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
	s.rebuildGroupDispatchLocked(group)
	return nil
}

// removeEndpoint drops every membership owned by one closing socket.
func (s *multicastState) removeEndpoint(endpoint multicastEndpoint) {
	s.mu.Lock()
	indexChanged := false
	for group, groupState := range s.groups {
		if _, exists := groupState.members[endpoint]; !exists {
			continue
		}
		old, oldExists := multicastInterfaceFilter(groupState)
		oldLastReporter := groupState.lastReporter
		delete(groupState.members, endpoint)
		removed := len(groupState.members) == 0
		if removed {
			s.removeGroupLocked(group)
			indexChanged = true
		} else {
			groupState.aggregate = aggregateMulticastFilter(groupState.members)
		}
		s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
		if !removed {
			s.rebuildGroupDispatchLocked(group)
		}
	}
	if indexChanged {
		s.rebuildDispatchIndexLocked()
	}
	s.mu.Unlock()
}

// removeGroupLocked removes one empty group and its family count.
func (s *multicastState) removeGroupLocked(group netip.Addr) {
	if state := s.groups[group]; state != nil {
		state.dispatch.Store(nil)
	}
	delete(s.groups, group)
	if multicastGroupNeedsReport(group) {
		s.familyGroups[multicastFamilyIndex(group)]--
	}
}

// aggregateMulticastFilter applies RFC 9776 section 3.2's per-interface merge.
func aggregateMulticastFilter(members map[multicastEndpoint]*multicastFilter) multicastFilter {
	if len(members) == 1 {
		for _, filter := range members {
			// Published socket filters are immutable and every delta replaces
			// its source map copy-on-write, so the identical one-member
			// interface policy can share that map with dispatch snapshots.
			return *filter
		}
	}
	result := multicastFilter{mode: multicastFilterInclude}
	firstExclude := true
	var include map[netip.Addr]struct{}
	for _, filter := range members {
		if filter.mode == multicastFilterInclude {
			for source := range filter.sources {
				if include == nil {
					include = make(map[netip.Addr]struct{})
				}
				include[source] = struct{}{}
			}
			continue
		}
		result.mode = multicastFilterExclude
		if firstExclude {
			if len(filter.sources) != 0 {
				result.sources = make(map[netip.Addr]struct{}, len(filter.sources))
				for source := range filter.sources {
					result.sources[source] = struct{}{}
				}
			}
			firstExclude = false
			continue
		}
		for source := range result.sources {
			if _, exists := filter.sources[source]; !exists {
				delete(result.sources, source)
			}
		}
	}
	if result.mode == multicastFilterInclude {
		result.sources = include
		return result
	}
	for source := range include {
		delete(result.sources, source)
	}
	return result
}

// multicastInterfaceFilter returns an immutable aggregate snapshot.
func multicastInterfaceFilter(state *multicastGroupState) (multicastFilter, bool) {
	if state == nil || len(state.members) == 0 {
		return multicastFilter{mode: multicastFilterInclude}, false
	}
	return state.aggregate, true
}

// cloneMulticastFilter detaches source state from later socket mutations.
func cloneMulticastFilter(filter multicastFilter) multicastFilter {
	if len(filter.sources) == 0 {
		return multicastFilter{mode: filter.mode}
	}
	result := multicastFilter{mode: filter.mode, sources: make(map[netip.Addr]struct{}, len(filter.sources))}
	for source := range filter.sources {
		result.sources[source] = struct{}{}
	}
	return result
}

// multicastFiltersEqual compares the unordered source policies.
func multicastFiltersEqual(left multicastFilter, leftExists bool, right multicastFilter, rightExists bool) bool {
	if leftExists != rightExists || left.mode != right.mode || len(left.sources) != len(right.sources) {
		return false
	}
	for source := range left.sources {
		if _, exists := right.sources[source]; !exists {
			return false
		}
	}
	return true
}

// interfaceStateChangedLocked merges one aggregate transition into the RFC
// retransmission state. The caller holds s.mu.
func (s *multicastState) interfaceStateChangedLocked(group netip.Addr, old multicastFilter, oldExists, oldLastReporter bool) {
	groupState := s.groups[group]
	current, currentExists := multicastInterfaceFilter(groupState)
	if multicastFiltersEqual(old, oldExists, current, currentExists) || !multicastGroupNeedsReport(group) {
		return
	}
	now := time.Now()
	s.refreshCompatibilityLocked(now)
	index := multicastFamilyIndex(group)
	latest := uint8(3)
	if group.Is6() {
		latest = 2
	}
	if s.compatibility[index] < latest && oldExists == currentExists {
		// IGMPv1/v2 and MLDv1 can express only group presence. Preserve any
		// pending join retransmission, but do not create redundant reports for
		// source-filter changes while the group remains joined.
		return
	}
	robustness := s.robustness[index]
	if robustness == 0 {
		robustness = multicastDefaultRobustness
	}
	pending := s.retransmissions[group]
	if pending == nil {
		pending = &multicastRetransmission{}
		s.retransmissions[group] = pending
	}
	pending.filter, pending.exists = current, currentExists
	if currentExists {
		pending.lastReporter = groupState.lastReporter
	} else {
		pending.lastReporter = oldLastReporter
	}
	if old.mode != current.mode {
		pending.modeRemaining = robustness
		pending.allow, pending.block = nil, nil
	} else {
		var allow, block map[netip.Addr]struct{}
		if current.mode == multicastFilterInclude {
			allow = multicastSourceDifference(current.sources, old.sources)
			block = multicastSourceDifference(old.sources, current.sources)
		} else {
			allow = multicastSourceDifference(old.sources, current.sources)
			block = multicastSourceDifference(current.sources, old.sources)
		}
		for source := range allow {
			if pending.allow == nil {
				pending.allow = make(map[netip.Addr]uint8)
			}
			pending.allow[source] = robustness
			delete(pending.block, source)
		}
		for source := range block {
			if pending.block == nil {
				pending.block = make(map[netip.Addr]uint8)
			}
			pending.block[source] = robustness
			delete(pending.allow, source)
		}
	}
	pending.due = now
	s.wakeLocked()
}

// multicastSourceDifference returns left minus right.
func multicastSourceDifference(left, right map[netip.Addr]struct{}) map[netip.Addr]struct{} {
	var result map[netip.Addr]struct{}
	for source := range left {
		if _, exists := right[source]; !exists {
			if result == nil {
				result = make(map[netip.Addr]struct{})
			}
			result[source] = struct{}{}
		}
	}
	return result
}

// wakeLocked interrupts the worker after a timer-relevant state change.
func (s *multicastState) wakeLocked() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// multicastFamilyIndex maps IPv4 and IPv6 to compact per-interface state.
func multicastFamilyIndex(address netip.Addr) int {
	if address.Is6() {
		return 1
	}
	return 0
}

// isAllHostsGroup identifies groups whose membership is implicit and must
// never be announced by IGMP or MLD.
func isAllHostsGroup(group netip.Addr) bool {
	if group.Is4() {
		return group == netip.AddrFrom4([4]byte{224, 0, 0, 1})
	}
	value := group.As16()
	return value[0] == 0xff && (value[1] == 1 || value[1] == 2) &&
		value[2] == 0 && value[3] == 0 && value[4] == 0 && value[5] == 0 && value[6] == 0 && value[7] == 0 &&
		value[8] == 0 && value[9] == 0 && value[10] == 0 && value[11] == 0 && value[12] == 0 && value[13] == 0 && value[14] == 0 && value[15] == 1
}

// multicastGroupNeedsReport identifies memberships visible to multicast
// routers on the embedding link. IPv4's all-hosts group and IPv6's all-nodes
// groups are implicit; every IPv6 interface-local group remains entirely
// inside the host and therefore must not generate MLD traffic.
func multicastGroupNeedsReport(group netip.Addr) bool {
	group = group.Unmap()
	if !validMulticastGroup(group) {
		return false
	}
	if group.Is4() {
		return group != netip.AddrFrom4([4]byte{224, 0, 0, 1})
	}
	value := group.As16()
	return value[1]&0x0f > 1 && !isAllHostsGroup(group)
}

// rebuildGroupDispatchLocked publishes one immutable data-plane entry. Source
// maps remain immutable after publication, and unrelated groups are untouched.
func (s *multicastState) rebuildGroupDispatchLocked(address netip.Addr) {
	state := s.groups[address]
	if state == nil {
		s.rebuildDispatchIndexLocked()
		return
	}
	group := &multicastDispatchGroup{filter: state.aggregate}
	for endpoint, filter := range state.members {
		switch connection := endpoint.(type) {
		case *UDPConn:
			group.udp = append(group.udp, multicastUDPDispatch{connection: connection, filter: *filter})
		case *IPConn:
			group.ip = append(group.ip, multicastIPDispatch{connection: connection, filter: *filter})
		}
	}
	state.dispatch.Store(group)
	snapshot := s.dispatch.Load()
	if snapshot == nil || snapshot.groups[address] != state {
		s.rebuildDispatchIndexLocked()
	}
}

// rebuildDispatchIndexLocked publishes the active address-to-group index only
// when a group is added or removed.
func (s *multicastState) rebuildDispatchIndexLocked() {
	snapshot := &multicastDispatchSnapshot{groups: make(map[netip.Addr]*multicastGroupState, len(s.groups))}
	for address, state := range s.groups {
		snapshot.groups[address] = state
	}
	s.dispatch.Store(snapshot)
}

// loadDispatchGroup returns one immutable entry without taking the membership
// state lock.
func (s *multicastState) loadDispatchGroup(address netip.Addr) *multicastDispatchGroup {
	snapshot := s.dispatch.Load()
	if snapshot == nil {
		return nil
	}
	state := snapshot.groups[address]
	if state == nil {
		return nil
	}
	return state.dispatch.Load()
}

// acceptsSource applies the RFC 9776/RFC 3810 aggregate interface filter
// before built-in protocols process ordinary multicast traffic. IGMP and MLD
// control messages bypass this check at the caller, as required by the RFCs.
func (s *multicastState) acceptsSource(group, source netip.Addr) bool {
	group, source = group.Unmap(), source.Unmap()
	if isAllHostsGroup(group) {
		return true
	}
	state := s.loadDispatchGroup(group)
	return state != nil && state.filter.accepts(source)
}

// acceptsDestination reports group membership or an all-hosts control target.
func (s *multicastState) acceptsDestination(group netip.Addr) bool {
	group = group.Unmap()
	if !networkStateHasFamily(s.stack.network.Load(), group.Is6()) {
		return false
	}
	state := s.loadDispatchGroup(group)
	return state != nil && (len(state.udp) != 0 || len(state.ip) != 0)
}

// deliverUDP fans a multicast datagram out to every matching socket filter.
func (s *multicastState) deliverUDP(packet ipPacket, sourcePort, targetPort uint16) {
	group := s.loadDispatchGroup(packet.target)
	if group == nil {
		return
	}
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	remote := netip.AddrPortFrom(packet.source, sourcePort)
	for _, endpoint := range group.udp {
		connection := endpoint.connection
		if !connection.local.IsUnspecified() || connection.port != targetPort || connection.remote.IsValid() && connection.remote != remote || !endpoint.filter.accepts(packet.source) {
			continue
		}
		connection.enqueue(packet.payload[udpHeaderSize:], remote, packet.target, options)
	}
}

// deliverIP fans a multicast payload out to matching raw protocol sockets.
func (s *multicastState) deliverIP(packet ipPacket) bool {
	group := s.loadDispatchGroup(packet.target)
	if group == nil {
		return false
	}
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	delivered := false
	for _, endpoint := range group.ip {
		connection := endpoint.connection
		if !connection.local.IsUnspecified() || connection.protocol != packet.protocol || connection.remote.IsValid() && connection.remote != packet.source || !endpoint.filter.accepts(packet.source) {
			continue
		}
		connection.enqueuePacket(packet, options)
		delivered = true
	}
	return delivered
}

// deliverImplicitIP preserves the all-hosts delivery inherited by raw sockets
// while applying an explicit membership's per-socket source filter when one
// exists. Linux applies the explicit filter before its multicast-all fallback
// in the same way.
func (s *multicastState) deliverImplicitIP(packet ipPacket, endpoints ipEndpoints) bool {
	state, ok := endpoints.(*ipEndpointState)
	if !ok {
		return false
	}
	var explicit []multicastIPDispatch
	if group := s.loadDispatchGroup(packet.target); group != nil {
		explicit = group.ip
	}
	s.stack.mu.RLock()
	if s.stack.ip != state {
		s.stack.mu.RUnlock()
		return false
	}
	connections := state.connectionsForLocked(packet.target, packet.protocol)
	s.stack.mu.RUnlock()
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	delivered := false
	for _, connection := range connections {
		if connection.remote.IsValid() && connection.remote != packet.source {
			continue
		}
		allowed := true
		for _, membership := range explicit {
			if membership.connection == connection {
				allowed = membership.filter.accepts(packet.source)
				break
			}
		}
		if !allowed {
			continue
		}
		delivered = true
		connection.enqueuePacket(packet, options)
	}
	return delivered
}

// accepts reports whether source passes one socket's INCLUDE/EXCLUDE filter.
func (f *multicastFilter) accepts(source netip.Addr) bool {
	_, listed := f.sources[source.Unmap()]
	if f.mode == multicastFilterInclude {
		return listed
	}
	return !listed
}

// nonUnicastOutputPolicy snapshots the socket options that differ from
// ordinary unicast output. The returned packet options carry an explicit
// multicast hop limit, including the meaningful zero-hop value.
func nonUnicastOutputPolicy(target netip.Addr, multicastHopLimit byte, multicastLoopback, broadcast bool, options ipPacketOptions) (ipPacketOptions, bool, bool, error) {
	if target.IsMulticast() {
		if !options.hopLimitSet {
			options.hopLimit = multicastHopLimit
			options.hopLimitSet = true
		}
		external := options.hopLimit != 0
		if target.Is6() && target.As16()[1]&0x0f <= 1 {
			external = false
		}
		return options, external, multicastLoopback, nil
	}
	if !broadcast {
		return ipPacketOptions{}, false, false, syscall.EACCES
	}
	return options, true, true, nil
}

// writeNonUnicastDatagram emits broadcast or multicast output against the
// interface MTU. It deliberately bypasses destination PMTU state and ICMP
// correlation, neither of which identifies one non-unicast receiver.
func (c *UDPConn) writeNonUnicastDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, dontWait bool) error {
	udpSize := udpHeaderSize + len(payload)
	if udpSize > 65535 || target.Is4() && udpSize > 65515 {
		return syscall.EMSGSIZE
	}
	c.mu.Lock()
	options, external, loopback, err := nonUnicastOutputPolicy(target, c.multicastHopLimit, c.multicastLoopback, c.broadcast, options)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	fragmentation := sourceFragmentationForMode(pathMTUDiscovery)
	if !loopback {
		if !external {
			return nil
		}
		return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, fragmentation, c.stack.network.Load().mtu, dontWait)
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = c.stack.automaticTransportFlowLabel(source, target, ProtocolUDP, sourcePort, targetPort)
		options.flowLabelSet = true
	}
	mtu := c.stack.network.Load().mtu
	ipSize := ipHeaderSize(source, target, udpSize)
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed, dontWait: dontWait}
	if ipSize+udpSize <= mtu {
		identification := uint16(0)
		if source.Is4() && fragmentation.requiresIPv4ID() {
			identification = uint16(c.stack.ipv4ID.Add(1))
		}
		return c.stack.writeNonUnicastPacketUntil(ipSize+udpSize, external, loopback, state, func(packet []byte) bool {
			if !marshalIPHeader(packet, source, target, ProtocolUDP, identification, fragmentation.dontFragment, options) {
				return false
			}
			marshalUDPDatagram(packet[ipSize:], source, target, sourcePort, targetPort, payload)
			return true
		})
	}
	if !fragmentation.allow {
		return syscall.EMSGSIZE
	}
	datagram := make([]byte, udpSize)
	marshalUDPDatagram(datagram, source, target, sourcePort, targetPort, payload)
	packets, err := c.stack.ipPayloadPacketsForMTU(source, target, ProtocolUDP, datagram, fragmentation, options, mtu)
	if err != nil {
		return err
	}
	return c.stack.writeNonUnicastPacketsUntil(packets, external, loopback, state)
}

// writeNonUnicastPayload is the raw-protocol counterpart of UDP multicast and
// broadcast output.
func (c *IPConn) writeNonUnicastPayload(source, target netip.Addr, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery, dontWait bool) error {
	ipSize := ipHeaderSize(source, target, len(payload))
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	c.mu.Lock()
	options, external, loopback, err := nonUnicastOutputPolicy(target, c.multicastHopLimit, c.multicastLoopback, c.broadcast, options)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	fragmentation := sourceFragmentationForMode(pathMTUDiscovery)
	if !loopback {
		if !external {
			return nil
		}
		state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed, dontWait: dontWait}
		return c.stack.writeIPPayloadUntilOptionsForMTU(source, target, c.protocol, payload, fragmentation, options, c.stack.network.Load().mtu, state)
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = c.stack.automaticFlowLabel(source, target, c.protocol, payload)
		options.flowLabelSet = true
	}
	mtu := c.stack.network.Load().mtu
	state := socketWriteState{deadline: &c.writeDeadline, closed: c.closed, dontWait: dontWait}
	if ipSize+len(payload) <= mtu {
		identification := uint16(0)
		if source.Is4() && fragmentation.requiresIPv4ID() {
			identification = uint16(c.stack.ipv4ID.Add(1))
		}
		return c.stack.writeNonUnicastPacketUntil(ipSize+len(payload), external, loopback, state, func(packet []byte) bool {
			if !marshalIPHeader(packet, source, target, c.protocol, identification, fragmentation.dontFragment, options) {
				return false
			}
			copy(packet[ipSize:], payload)
			return true
		})
	}
	if !fragmentation.allow {
		return syscall.EMSGSIZE
	}
	packets, err := c.stack.ipPayloadPacketsForMTU(source, target, c.protocol, payload, fragmentation, options, mtu)
	if err != nil {
		return err
	}
	return c.stack.writeNonUnicastPacketsUntil(packets, external, loopback, state)
}

// writeNonUnicastPacketUntil serializes one unfragmented packet directly
// into queue-owned storage. Link output observes socket backpressure; the
// optional local copy remains best effort and uses independent storage.
func (s *Stack) writeNonUnicastPacketUntil(size int, external, loopback bool, state socketWriteState, marshal func([]byte) bool) error {
	if !external && !loopback {
		return nil
	}
	if err := state.err(); err != nil {
		return err
	}
	if !external {
		slot, reserved := s.loopback.tryReserve()
		if !reserved {
			return nil
		}
		packet, reusable := s.loopback.acquireBuffer(size)
		if !marshal(packet) {
			s.loopback.releaseBuffer(packet, reusable)
			s.loopback.releaseReserved(slot)
			return syscall.EMSGSIZE
		}
		if !s.loopback.enqueueReservedPacket(slot, packet, reusable) {
			return ErrClosed
		}
		s.recordOutput(true)
		return nil
	}
	slot, err := s.reservePacketUntil(&s.outbound, false, state)
	if err != nil {
		return err
	}
	packet, reusable := s.outbound.acquireBuffer(size)
	if !marshal(packet) {
		s.outbound.releaseBuffer(packet, reusable)
		s.outbound.releaseReserved(slot)
		return syscall.EMSGSIZE
	}
	var localPacket []byte
	var localSlot uint16
	var localReusable, localReserved bool
	if loopback {
		localSlot, localReserved = s.loopback.tryReserve()
		if localReserved {
			localPacket, localReusable = s.loopback.acquireBuffer(size)
			copy(localPacket, packet)
		}
	}
	if !s.outbound.enqueueReservedPacket(slot, packet, reusable) {
		if localReserved {
			s.loopback.releaseReserved(localSlot)
		}
		return ErrClosed
	}
	s.recordOutput(false)
	if localReserved {
		if s.loopback.enqueueReservedPacket(localSlot, localPacket, localReusable) {
			s.recordOutput(true)
		}
	}
	return nil
}

// writeNonUnicastPacketsUntil streams a source-fragmented datagram through the
// bounded link queue with the same deadline behavior as unicast output. Local
// copies are best effort, as with kernel receive queues: a full local queue
// must not make an otherwise successful send fail.
func (s *Stack) writeNonUnicastPacketsUntil(packets [][]byte, external, loopback bool, state socketWriteState) error {
	if len(packets) == 0 || !external && !loopback {
		return nil
	}
	if err := state.err(); err != nil {
		return err
	}
	if state.dontWait {
		if external {
			if err := s.tryWritePacketsTo(packets, &s.outbound, false); err != nil {
				if errors.Is(err, ErrResourceLimit) {
					return syscall.EAGAIN
				}
				return err
			}
		}
		if loopback {
			// Local delivery remains best effort, but reassembly must never see
			// only the prefix of a datagram because its queue filled mid-send.
			_ = s.tryWritePacketsTo(packets, &s.loopback, true)
		}
		return nil
	}
	for _, packet := range packets {
		var slot uint16
		if external {
			var err error
			slot, err = s.reservePacketUntil(&s.outbound, false, state)
			if err != nil {
				return err
			}
		}
		if external {
			if !s.outbound.enqueueReservedPacket(slot, packet, false) {
				return ErrClosed
			}
			s.recordOutput(false)
		}
		// Fragment builders return immutable, independently owned packets.
		// Both queues may therefore retain the same slice without the extra
		// full-fragment copy required by reusable queue-owned buffers.
		if loopback {
			if s.loopback.tryEnqueue(packet) {
				s.recordOutput(true)
			} else if !external {
				select {
				case <-s.closeCh:
					return ErrClosed
				default:
				}
			}
		}
	}
	return nil
}

// isMulticastControlPacket identifies IGMP and MLD messages, which RFC 9776
// and RFC 3810 exempt from multicast source filtering.
func isMulticastControlPacket(packet ipPacket) bool {
	if packet.protocol == ProtocolIGMP && packet.source.Is4() {
		return true
	}
	if packet.protocol == ProtocolICMPv6 && len(packet.payload) != 0 {
		switch packet.payload[0] {
		case mldMembershipQuery, mldV1MembershipReport, mldV1ListenerDone, mldV2MembershipReport:
			return true
		}
	}
	return false
}

// multicastStateForQuery records interface protocol variables when a Query
// arrives before the first socket joins a group. It deliberately retains only
// a lightweight seed; the first membership promotes it to multicastState.
func (s *Stack) multicastStateForQuery(packet ipPacket, current multicastEndpoints, receivedAt time.Time) multicastEndpoints {
	if current != nil || len(packet.payload) == 0 {
		return current
	}
	var query multicastQuery
	var expected netip.Addr
	var valid bool
	network := s.network.Load()
	switch packet.protocol {
	case ProtocolIGMP:
		if packet.payload[0] != igmpMembershipQuery {
			return nil
		}
		query, expected, valid = parseIGMPQuery(packet, network)
	case ProtocolICMPv6:
		if packet.payload[0] != mldMembershipQuery {
			return nil
		}
		query, expected, valid = parseMLDQuery(packet, network)
	default:
		return nil
	}
	if !valid || !s.acceptsMulticastControlDestination(packet.target, expected, nil) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.multicast != nil {
		// A concurrent Join published the full state after the caller took its
		// snapshot. Let handleControl process the Query exactly once there.
		return s.multicast
	}
	if s.multicastSeed == nil {
		s.multicastSeed = &multicastQuerierSeed{multicastQuerierState: defaultMulticastQuerierState()}
	}
	s.multicastSeed.noteQuery(query, receivedAt)
	return nil
}

// handleControl consumes IGMP and MLD host-side control messages. Raw sockets
// receive their copy before this method runs, matching the kernel IP path.
func (s *multicastState) handleControl(packet ipPacket, receivedAt time.Time) {
	if packet.protocol == ProtocolIGMP {
		s.handleIGMP(packet, receivedAt)
	} else {
		s.handleMLD(packet, receivedAt)
	}
}

// handleIGMP validates one host-relevant IGMP message before changing timers.
func (s *multicastState) handleIGMP(packet ipPacket, receivedAt time.Time) {
	payload := packet.payload
	if len(payload) != 0 && payload[0] == igmpMembershipQuery {
		query, expected, valid := parseIGMPQuery(packet, s.stack.network.Load())
		if valid && s.acceptsControlDestination(packet.target, expected) {
			s.scheduleQuery(query, receivedAt)
		}
		return
	}
	if len(payload) < 8 || packet.hopLimit != 1 || checksum(payload) != 0 {
		return
	}
	switch payload[0] {
	case igmpV1MembershipReport, igmpV2MembershipReport:
		if len(payload) < 8 || payload[0] == igmpV2MembershipReport && !packet.hasRouterAlert() {
			return
		}
		group := netip.AddrFrom4([4]byte(payload[4:8]))
		if group.IsMulticast() && s.acceptsControlDestination(packet.target, group) {
			s.heardLegacyReport(group)
		}
	}
}

// handleMLD validates the RFC 3810 link-local envelope and query/report body.
func (s *multicastState) handleMLD(packet ipPacket, receivedAt time.Time) {
	payload := packet.payload
	if len(payload) != 0 && payload[0] == mldMembershipQuery {
		query, expected, valid := parseMLDQuery(packet, s.stack.network.Load())
		if valid && s.acceptsControlDestination(packet.target, expected) {
			s.scheduleQuery(query, receivedAt)
		}
		return
	}
	if len(payload) < 8 || payload[1] != 0 || packet.hopLimit != 1 || !packet.hasRouterAlert() ||
		!packet.source.IsLinkLocalUnicast() ||
		transportChecksum(packet.source, packet.target, ProtocolICMPv6, payload) != 0 {
		return
	}
	switch payload[0] {
	case mldV1MembershipReport:
		if len(payload) >= 24 {
			group := netip.AddrFrom16([16]byte(payload[8:24]))
			if group.IsMulticast() && s.acceptsControlDestination(packet.target, group) {
				s.heardLegacyReport(group)
			}
		}
	}
}

// parseIGMPQuery validates one complete IGMP Query and returns its scheduling
// data plus the destination assigned to its group form.
func parseIGMPQuery(packet ipPacket, network *networkState) (multicastQuery, netip.Addr, bool) {
	payload := packet.payload
	if len(payload) < 8 || payload[0] != igmpMembershipQuery || packet.hopLimit != 1 || checksum(payload) != 0 {
		return multicastQuery{}, netip.Addr{}, false
	}
	query := multicastQuery{version: 3, maximum: decodeIGMPTime(payload[1])}
	if len(payload) == 8 {
		if payload[1] == 0 {
			query.version, query.maximum = 1, multicastDefaultResponseInterval
		} else {
			query.version = 2
			query.maximum = decodeIGMPv2Time(payload[1])
		}
	} else {
		if len(payload) < 12 {
			return multicastQuery{}, netip.Addr{}, false
		}
		query.robustness = payload[8] & 7
		query.queryInterval = decodeIGMPQueryInterval(payload[9])
		count := int(binary.BigEndian.Uint16(payload[10:12]))
		if count > multicastMaximumQuerySources || len(payload)-12 < count*4 {
			return multicastQuery{}, netip.Addr{}, false
		}
		query.sources = make([]netip.Addr, 0, count)
		for offset := 12; len(query.sources) < count; offset += 4 {
			source := netip.AddrFrom4([4]byte(payload[offset : offset+4]))
			if !validMulticastSourceAddress(network, source, false) {
				return multicastQuery{}, netip.Addr{}, false
			}
			query.sources = append(query.sources, source)
		}
	}
	if query.version >= 2 && !packet.hasRouterAlert() {
		return multicastQuery{}, netip.Addr{}, false
	}
	query.group = netip.AddrFrom4([4]byte(payload[4:8]))
	if query.version == 1 && !query.group.IsUnspecified() ||
		!query.group.IsUnspecified() && !validMulticastGroup(query.group) ||
		len(query.sources) != 0 && query.group.IsUnspecified() {
		return multicastQuery{}, netip.Addr{}, false
	}
	query.legacyMaximum = query.maximum
	expected := query.group
	if expected.IsUnspecified() {
		expected = netip.AddrFrom4([4]byte{224, 0, 0, 1})
	}
	return query, expected, true
}

// parseMLDQuery validates one complete MLD Query and returns its scheduling
// data plus the destination assigned to its group form.
func parseMLDQuery(packet ipPacket, network *networkState) (multicastQuery, netip.Addr, bool) {
	payload := packet.payload
	if len(payload) < 24 || payload[0] != mldMembershipQuery || payload[1] != 0 || packet.hopLimit != 1 ||
		!packet.hasRouterAlert() || !packet.source.IsLinkLocalUnicast() ||
		transportChecksum(packet.source, packet.target, ProtocolICMPv6, payload) != 0 {
		return multicastQuery{}, netip.Addr{}, false
	}
	legacyResponse := time.Duration(binary.BigEndian.Uint16(payload[4:6])) * time.Millisecond
	query := multicastQuery{v6: true, version: 1, maximum: legacyResponse, legacyMaximum: legacyResponse}
	if len(payload) != 24 {
		if len(payload) < 28 {
			return multicastQuery{}, netip.Addr{}, false
		}
		query.version = 2
		query.maximum = decodeMLDTime(binary.BigEndian.Uint16(payload[4:6]))
		query.robustness = payload[24] & 7
		query.queryInterval = decodeIGMPQueryInterval(payload[25])
		count := int(binary.BigEndian.Uint16(payload[26:28]))
		if count > multicastMaximumQuerySources || len(payload)-28 < count*16 {
			return multicastQuery{}, netip.Addr{}, false
		}
		query.sources = make([]netip.Addr, 0, count)
		for offset := 28; len(query.sources) < count; offset += 16 {
			source := netip.AddrFrom16([16]byte(payload[offset : offset+16]))
			if !validMulticastSourceAddress(network, source, true) {
				return multicastQuery{}, netip.Addr{}, false
			}
			query.sources = append(query.sources, source)
		}
	}
	query.group = netip.AddrFrom16([16]byte(payload[8:24]))
	if !query.group.IsUnspecified() && !validMulticastGroup(query.group) ||
		len(query.sources) != 0 && query.group.IsUnspecified() {
		return multicastQuery{}, netip.Addr{}, false
	}
	expected := query.group
	if expected.IsUnspecified() {
		expected = netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	}
	return query, expected, true
}

// acceptsControlDestination implements the assigned-address exceptions in
// RFC 9776 sections 4.1.12 and 4.2.15 and RFC 3810 sections 5.1.15 and
// 5.2.14. Queries and legacy Reports must be accepted when sent to any
// unicast or multicast address assigned to the interface.
func (s *multicastState) acceptsControlDestination(target, expected netip.Addr) bool {
	return s.stack.acceptsMulticastControlDestination(target, expected, s)
}

// acceptsMulticastControlDestination applies the multicast-control assigned-
// address exceptions without requiring a complete membership dispatcher.
func (s *Stack) acceptsMulticastControlDestination(target, expected netip.Addr, memberships multicastEndpoints) bool {
	target = target.Unmap()
	network := s.network.Load()
	if target == expected || networkStateHasLocal(network, target) {
		return true
	}
	if isAllHostsGroup(target) && networkStateHasFamily(network, target.Is6()) {
		return true
	}
	return target.IsMulticast() && memberships != nil && memberships.acceptsDestination(target)
}

// decodeIGMPv2Time decodes the version 2 field linearly over all eight bits.
func decodeIGMPv2Time(code byte) time.Duration {
	return time.Duration(code) * 100 * time.Millisecond
}

// decodeIGMPTime decodes the RFC 9776 floating Max Resp Code in 100ms units.
func decodeIGMPTime(code byte) time.Duration {
	value := uint32(code)
	if code >= 128 {
		value = uint32(code&0x0f|0x10) << ((code >> 4 & 7) + 3)
	}
	return time.Duration(value) * 100 * time.Millisecond
}

// decodeIGMPQueryInterval decodes the shared 8-bit floating QQIC in seconds.
func decodeIGMPQueryInterval(code byte) time.Duration {
	value := uint32(code)
	if code >= 128 {
		value = uint32(code&0x0f|0x10) << ((code >> 4 & 7) + 3)
	}
	return time.Duration(value) * time.Second
}

// decodeMLDTime decodes the RFC 3810 16-bit floating Max Resp Code.
func decodeMLDTime(code uint16) time.Duration {
	value := uint32(code)
	if code >= 0x8000 {
		value = uint32(code&0x0fff|0x1000) << ((code >> 12 & 7) + 3)
	}
	return time.Duration(value) * time.Millisecond
}

// scheduleQuery merges a validated query with the RFC per-interface and
// per-group pending response state.
func (s *multicastState) scheduleQuery(query multicastQuery, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	index := 0
	latest := uint8(3)
	if query.v6 {
		index, latest = 1, 2
	}
	s.refreshCompatibilityLocked(now)
	if query.version == latest && s.compatibility[index] < latest {
		// RFC 9776 section 7.2.1 and RFC 3810 section 8.2.1 require a
		// host in an older compatibility mode to use only that version's
		// listener behavior. Linux consequently ignores newer source lists;
		// IGMPv1 also treats an IGMPv3 Query as a General Query.
		query.sources = nil
		if query.v6 {
			query.maximum = query.legacyMaximum
		} else if s.compatibility[index] == 1 {
			query.group = netip.IPv4Unspecified()
			query.maximum = multicastDefaultResponseInterval
		}
		// In IGMPv2 mode, retain the v3 Max Resp decoding. A v3-format
		// Query from a v2 querier is internally inconsistent; Linux treats
		// its code as v3 because that is the sender's actual wire format.
	} else {
		s.noteQueryVersionLocked(index, query.version, query.group.IsUnspecified(), query.robustness, query.queryInterval, query.maximum, now)
	}
	if query.maximum <= 0 {
		// RFC 9776 section 5.2 and RFC 3810 section 6.2 require a
		// randomized, non-immediate response. Linux likewise clamps a zero
		// Max Resp value to one timer tick; one nanosecond is the smallest
		// scheduler-independent duration representable by Go.
		query.maximum = time.Nanosecond
	}
	legacy := s.compatibility[index] < latest
	if query.group.IsUnspecified() {
		if legacy {
			for address, state := range s.groups {
				if address.Is6() != query.v6 || !multicastGroupNeedsReport(address) {
					continue
				}
				deadline := now.Add(s.randomDelayLocked(query.maximum))
				if state.query.deadline.IsZero() || deadline.Before(state.query.deadline) {
					state.query = multicastPendingQuery{deadline: deadline}
				}
			}
		} else if s.familyGroups[index] != 0 {
			deadline := now.Add(s.randomDelayLocked(query.maximum))
			if s.generalQuery[index].IsZero() || deadline.Before(s.generalQuery[index]) {
				s.generalQuery[index] = deadline
			}
		}
		s.wakeLocked()
		return
	}
	state := s.groups[query.group]
	if state == nil || !multicastGroupNeedsReport(query.group) {
		return
	}
	deadline := now.Add(s.randomDelayLocked(query.maximum))
	if !s.generalQuery[index].IsZero() && !deadline.Before(s.generalQuery[index]) {
		return
	}
	pending := &state.query
	if pending.deadline.IsZero() {
		pending.deadline = deadline
		pending.sourceQuery = len(query.sources) != 0
		if pending.sourceQuery {
			pending.sources = multicastAddressSet(query.sources)
		}
	} else if len(query.sources) == 0 || !pending.sourceQuery {
		pending.sourceQuery, pending.sources = false, nil
		if deadline.Before(pending.deadline) {
			pending.deadline = deadline
		}
	} else {
		if pending.sources == nil {
			pending.sources = make(map[netip.Addr]struct{})
		}
		for _, source := range query.sources {
			if len(pending.sources) >= multicastMaximumQuerySources {
				break
			}
			pending.sources[source] = struct{}{}
		}
		if deadline.Before(pending.deadline) {
			pending.deadline = deadline
		}
	}
	s.wakeLocked()
}

// noteQuery applies a pre-membership Query without retaining its group or
// source list. Those fields can schedule responses only after a group exists.
func (s *multicastQuerierSeed) noteQuery(query multicastQuery, now time.Time) {
	s.refresh(now)
	index, latest := 0, uint8(3)
	if query.v6 {
		index, latest = 1, 2
	}
	if query.version == latest && s.compatibility[index] < latest {
		return
	}
	s.noteQueryVersion(index, query.version, query.group.IsUnspecified(), query.robustness, query.queryInterval, query.maximum, now)
	s.refresh(now)
}

// noteQueryVersion updates querier variables and older-version deadlines. The
// caller refreshes compatibility immediately before and after this operation.
func (s *multicastQuerierState) noteQueryVersion(index int, version uint8, general bool, robustness uint8, queryInterval, responseInterval time.Duration, now time.Time) {
	latest := uint8(3)
	if index == 1 {
		latest = 2
	}
	if version == latest {
		if robustness == 0 {
			robustness = multicastDefaultRobustness
		}
		if queryInterval == 0 {
			queryInterval = multicastDefaultQueryInterval
		}
		s.robustness[index] = robustness
		s.queryInterval[index] = queryInterval
		// Unlike QRV and QQIC, a zero Max Resp Code means a real zero
		// Query Response Interval. It is not a request for the default.
		s.responseInterval[index] = responseInterval
	}
	timeout := time.Duration(s.robustness[index])*s.queryInterval[index] + s.responseInterval[index]
	if index == 0 {
		// RFC 9776 section 8.12 incorporates Erratum 4375: IGMP uses ten
		// times the Max Response Time from the older Query. MLD deliberately
		// retains RFC 3810 section 9.12's RV*QI+QRI formula above.
		timeout = time.Duration(s.robustness[index])*s.queryInterval[index] + 10*responseInterval
	}
	if index == 0 {
		if version == 1 {
			s.igmpV1Until = now.Add(timeout)
		} else if version == 2 && general {
			s.igmpV2Until = now.Add(timeout)
		}
	} else if version == 1 {
		s.mldV1Until = now.Add(timeout)
	}
}

// noteQueryVersionLocked updates querier variables and older-version timers.
func (s *multicastState) noteQueryVersionLocked(index int, version uint8, general bool, robustness uint8, queryInterval, responseInterval time.Duration, now time.Time) {
	s.refreshCompatibilityLocked(now)
	s.multicastQuerierState.noteQueryVersion(index, version, general, robustness, queryInterval, responseInterval, now)
	s.refreshCompatibilityLocked(now)
}

// refresh expires older-querier deadlines and returns the families whose
// effective host compatibility mode changed.
func (s *multicastQuerierState) refresh(now time.Time) (changed [2]bool) {
	if !s.igmpV1Until.IsZero() && !now.Before(s.igmpV1Until) {
		s.igmpV1Until = time.Time{}
	}
	if !s.igmpV2Until.IsZero() && !now.Before(s.igmpV2Until) {
		s.igmpV2Until = time.Time{}
	}
	if !s.mldV1Until.IsZero() && !now.Before(s.mldV1Until) {
		s.mldV1Until = time.Time{}
	}
	mode4 := uint8(3)
	if !s.igmpV2Until.IsZero() {
		mode4 = 2
	}
	if !s.igmpV1Until.IsZero() {
		mode4 = 1
	}
	mode6 := uint8(2)
	if !s.mldV1Until.IsZero() {
		mode6 = 1
	}
	for index, mode := range [2]uint8{mode4, mode6} {
		changed[index] = s.compatibility[index] != mode
		s.compatibility[index] = mode
	}
	return changed
}

// refreshCompatibilityLocked applies older-querier timer expiry and the RFC
// requirement to cancel pending response/retransmission state on each mode
// transition. The caller holds s.mu.
func (s *multicastState) refreshCompatibilityLocked(now time.Time) {
	if s.closed {
		return
	}
	for index, changed := range s.multicastQuerierState.refresh(now) {
		if !changed {
			continue
		}
		close(s.reportCancel[index])
		s.reportCancel[index] = make(chan struct{})
		s.cancelPendingFamilyLocked(index)
	}
}

// cancelPendingFamilyLocked clears timers invalidated by a compatibility mode
// transition while preserving socket membership itself.
func (s *multicastState) cancelPendingFamilyLocked(index int) {
	s.generalQuery[index] = time.Time{}
	v6 := index == 1
	for group, state := range s.groups {
		if group.Is6() == v6 {
			state.query = multicastPendingQuery{}
		}
	}
	for group := range s.retransmissions {
		if group.Is6() == v6 {
			delete(s.retransmissions, group)
		}
	}
}

// heardLegacyReport applies IGMPv1/v2 and MLDv1 host suppression.
func (s *multicastState) heardLegacyReport(group netip.Addr) {
	if isSourceSpecificMulticast(group) {
		// RFC 4604 forbids an older-version Report from suppressing an
		// SSM-aware host's source-specific state.
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.refreshCompatibilityLocked(time.Now())
	index, latest := multicastFamilyIndex(group), uint8(3)
	if group.Is6() {
		latest = 2
	}
	if s.compatibility[index] == latest {
		s.mu.Unlock()
		return
	}
	if state := s.groups[group]; state != nil {
		state.query = multicastPendingQuery{}
		state.lastReporter = false
		if pending := s.retransmissions[group]; pending != nil && pending.exists {
			delete(s.retransmissions, group)
		}
	}
	s.wakeLocked()
	s.mu.Unlock()
}

// multicastAddressSet copies one untrusted query source vector.
func multicastAddressSet(addresses []netip.Addr) map[netip.Addr]struct{} {
	result := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		result[address] = struct{}{}
	}
	return result
}

// randomDelayLocked returns a nonzero uniform delay when maximum is positive.
func (s *multicastState) randomDelayLocked(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	s.random += 0x9e3779b97f4a7c15
	value := s.random
	value = (value ^ value>>30) * 0xbf58476d1ce4e5b9
	value = (value ^ value>>27) * 0x94d049bb133111eb
	value ^= value >> 31
	return time.Duration(value%uint64(maximum)) + time.Nanosecond
}

// run owns the single reusable timer for reports and query responses.
func (s *multicastState) run() {
	timer := newOwnedTimer()
	defer timer.close()
	for {
		now := time.Now()
		batches, next, haveNext := s.collectReports(now)
		for _, batch := range batches {
			s.sendReport(batch)
		}
		timer.stop()
		var timeout <-chan time.Time
		if haveNext {
			delay := time.Until(next)
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		select {
		case <-timeout:
			timer.consumed()
		case <-s.wake:
		case <-s.done:
			return
		}
	}
}

// collectReports advances due state under the lock and returns immutable wire
// work plus the earliest remaining deadline.
func (s *multicastState) collectReports(now time.Time) ([]multicastReportBatch, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, time.Time{}, false
	}
	s.refreshCompatibilityLocked(now)
	var batches []multicastReportBatch
	for group, pending := range s.retransmissions {
		if pending.due.After(now) {
			continue
		}
		records, remains := s.advanceRetransmissionLocked(pending)
		legacy := s.legacyVersionLocked(group.Is6())
		for index := range records {
			records[index].group = group
		}
		family := multicastFamilyIndex(group)
		batch := multicastReportBatch{v6: group.Is6(), legacy: legacy, group: group, exists: pending.exists, lastReporter: pending.lastReporter, records: records, cancel: s.reportCancel[family]}
		if legacy != 0 && pending.exists {
			if state := s.groups[group]; state != nil {
				state.lastReporter = true
			}
		}
		if legacy != 0 || len(records) != 0 {
			batches = append(batches, batch)
		}
		if legacy != 0 && !pending.exists {
			remains = false
		}
		if remains {
			interval := multicastUnsolicitedReportInterval
			if legacy != 0 {
				interval = 10 * time.Second
			}
			pending.due = now.Add(s.randomDelayLocked(interval))
		} else {
			delete(s.retransmissions, group)
		}
	}
	for index, deadline := range s.generalQuery {
		if deadline.IsZero() || deadline.After(now) {
			continue
		}
		v6 := index == 1
		legacy := s.legacyVersionLocked(v6)
		records := make([]multicastReportRecord, 0, s.familyGroups[index])
		for group, state := range s.groups {
			if group.Is6() != v6 || !multicastGroupNeedsReport(group) {
				continue
			}
			if legacy != 0 {
				state.lastReporter = true
				batches = append(batches, multicastReportBatch{v6: v6, legacy: legacy, group: group, exists: true, cancel: s.reportCancel[index]})
			} else {
				records = append(records, multicastCurrentStateRecord(group, state.aggregate, false, nil))
			}
			// RFC 9776 section 5.2 and RFC 3810 section 6.2 clear
			// recorded source lists for every group covered by a General
			// Report. A later Group Timer remains armed, but now requests
			// the complete group state rather than the stale intersection.
			if !state.query.deadline.IsZero() {
				state.query.sourceQuery = false
				state.query.sources = nil
			}
		}
		if legacy == 0 && len(records) != 0 {
			batches = append(batches, multicastReportBatch{v6: v6, records: records, cancel: s.reportCancel[index]})
		}
		s.generalQuery[index] = time.Time{}
	}
	for group, state := range s.groups {
		if state.query.deadline.IsZero() || state.query.deadline.After(now) {
			continue
		}
		query := state.query
		state.query = multicastPendingQuery{}
		legacy := s.legacyVersionLocked(group.Is6())
		if legacy != 0 {
			state.lastReporter = true
			batches = append(batches, multicastReportBatch{v6: group.Is6(), legacy: legacy, group: group, exists: true, cancel: s.reportCancel[multicastFamilyIndex(group)]})
			continue
		}
		record := multicastCurrentStateRecord(group, state.aggregate, query.sourceQuery, query.sources)
		if !query.sourceQuery || len(record.sources) != 0 {
			batches = append(batches, multicastReportBatch{v6: group.Is6(), records: []multicastReportRecord{record}, cancel: s.reportCancel[multicastFamilyIndex(group)]})
		}
	}
	var next time.Time
	setNext := func(candidate time.Time) {
		if !candidate.IsZero() && (next.IsZero() || candidate.Before(next)) {
			next = candidate
		}
	}
	for _, pending := range s.retransmissions {
		setNext(pending.due)
	}
	for _, deadline := range s.generalQuery {
		setNext(deadline)
	}
	for _, state := range s.groups {
		setNext(state.query.deadline)
	}
	setNext(s.igmpV1Until)
	setNext(s.igmpV2Until)
	setNext(s.mldV1Until)
	return batches, next, !next.IsZero()
}

// sendReport serializes one immutable report batch without holding state.mu.
func (s *multicastState) sendReport(batch multicastReportBatch) {
	if batch.legacy != 0 {
		if batch.v6 {
			s.sendMLDv1Report(batch.group, batch.exists, batch.lastReporter, batch.cancel)
		} else {
			s.sendIGMPLegacyReport(batch.group, batch.legacy, batch.exists, batch.lastReporter, batch.cancel)
		}
		return
	}
	if batch.v6 {
		s.sendMLDv2Records(batch.records, batch.cancel)
	} else {
		s.sendIGMPv3Records(batch.records, batch.cancel)
	}
}

// sendIGMPLegacyReport emits an IGMPv1/v2 report or a last-reporter v2 leave.
func (s *multicastState) sendIGMPLegacyReport(group netip.Addr, version uint8, exists, lastReporter bool, cancel <-chan struct{}) {
	if !group.Is4() || !group.IsMulticast() {
		return
	}
	messageType := byte(igmpV1MembershipReport)
	target, routerAlert := group, true
	if version >= 2 {
		messageType = igmpV2MembershipReport
	}
	if !exists {
		if version < 2 || !lastReporter {
			return
		}
		messageType = igmpV2LeaveGroup
		target = netip.AddrFrom4([4]byte{224, 0, 0, 2})
	}
	payload := make([]byte, 8)
	payload[0] = messageType
	groupBytes := group.As4()
	copy(payload[4:8], groupBytes[:])
	binary.BigEndian.PutUint16(payload[2:4], checksum(payload))
	s.sendIGMPPacket(target, payload, routerAlert, cancel)
}

// sendMLDv1Report emits an MLDv1 report or last-listener Done message.
func (s *multicastState) sendMLDv1Report(group netip.Addr, exists, lastReporter bool, cancel <-chan struct{}) {
	if !group.Is6() || !group.IsMulticast() || !exists && !lastReporter {
		return
	}
	messageType := byte(mldV1MembershipReport)
	target := group
	if !exists {
		messageType = mldV1ListenerDone
		target = netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	}
	payload := make([]byte, 24)
	payload[0] = messageType
	groupBytes := group.As16()
	copy(payload[8:24], groupBytes[:])
	s.sendMLDPacket(target, payload, cancel)
}

// sendIGMPv3Records packs current or state-change records to the interface
// MTU according to RFC 9776 section 4.2.17.
func (s *multicastState) sendIGMPv3Records(records []multicastReportRecord, cancel <-chan struct{}) {
	maximum := s.stack.network.Load().mtu - 24
	for _, report := range packMulticastRecords(records, maximum, 8, 8, 4) {
		payloadSize := 8
		for _, record := range report {
			payloadSize += 8 + 4*len(record.sources)
		}
		payload := make([]byte, payloadSize)
		payload[0] = igmpV3MembershipReport
		binary.BigEndian.PutUint16(payload[6:8], uint16(len(report)))
		offset := 8
		for _, record := range report {
			payload[offset] = record.recordType
			binary.BigEndian.PutUint16(payload[offset+2:offset+4], uint16(len(record.sources)))
			group := record.group.As4()
			copy(payload[offset+4:offset+8], group[:])
			offset += 8
			for _, source := range record.sources {
				value := source.As4()
				copy(payload[offset:offset+4], value[:])
				offset += 4
			}
		}
		binary.BigEndian.PutUint16(payload[2:4], checksum(payload))
		s.sendIGMPPacket(netip.AddrFrom4([4]byte{224, 0, 0, 22}), payload, true, cancel)
	}
}

// sendMLDv2Records is the IPv6 form of sendIGMPv3Records.
func (s *multicastState) sendMLDv2Records(records []multicastReportRecord, cancel <-chan struct{}) {
	maximum := s.stack.network.Load().mtu - 48
	for _, report := range packMulticastRecords(records, maximum, 8, 20, 16) {
		payloadSize := 8
		for _, record := range report {
			payloadSize += 20 + 16*len(record.sources)
		}
		payload := make([]byte, payloadSize)
		payload[0] = mldV2MembershipReport
		binary.BigEndian.PutUint16(payload[6:8], uint16(len(report)))
		offset := 8
		for _, record := range report {
			payload[offset] = record.recordType
			binary.BigEndian.PutUint16(payload[offset+2:offset+4], uint16(len(record.sources)))
			group := record.group.As16()
			copy(payload[offset+4:offset+20], group[:])
			offset += 20
			for _, source := range record.sources {
				value := source.As16()
				copy(payload[offset:offset+16], value[:])
				offset += 16
			}
		}
		s.sendMLDPacket(netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16}), payload, cancel)
	}
}

// packMulticastRecords creates MTU-sized reports. INCLUDE, ALLOW, and BLOCK
// records may be split; EXCLUDE records are stably truncated as the RFC
// requires because splitting their set-intersection semantics is unsafe.
func packMulticastRecords(records []multicastReportRecord, maximum, reportHeader, recordHeader, addressSize int) [][]multicastReportRecord {
	if maximum < reportHeader+recordHeader {
		return nil
	}
	maximumSources := (maximum - reportHeader - recordHeader) / addressSize
	var reports [][]multicastReportRecord
	var current []multicastReportRecord
	currentSize := reportHeader
	flush := func() {
		if len(current) != 0 {
			reports = append(reports, current)
			current, currentSize = nil, reportHeader
		}
	}
	for _, record := range records {
		if len(record.sources) > maximumSources {
			flush()
			if record.recordType == multicastRecordModeIsExclude || record.recordType == multicastRecordChangeToExcludeMode {
				record.sources = record.sources[:maximumSources]
				reports = append(reports, []multicastReportRecord{record})
				continue
			}
			if maximumSources == 0 {
				continue
			}
			for start := 0; start < len(record.sources); start += maximumSources {
				end := start + maximumSources
				if end > len(record.sources) {
					end = len(record.sources)
				}
				part := record
				part.sources = record.sources[start:end]
				reports = append(reports, []multicastReportRecord{part})
			}
			continue
		}
		size := recordHeader + addressSize*len(record.sources)
		if currentSize+size > maximum {
			flush()
		}
		current = append(current, record)
		currentSize += size
	}
	flush()
	return reports
}

// sendIGMPPacket adds the IPv4 Router Alert option when required and queues
// one link-local, nonfragmented control message best effort.
func (s *multicastState) sendIGMPPacket(target netip.Addr, payload []byte, routerAlert bool, cancel <-chan struct{}) {
	source, ok := s.reportSource(false)
	if !ok {
		return
	}
	headerSize := 20
	packetValue := IPPacket{
		Source: source, Destination: target, Protocol: ProtocolIGMP,
		HopLimit: 1, TrafficClass: 0xc0, Identification: uint16(s.stack.ipv4ID.Add(1)),
		DontFragment: true, Payload: payload,
	}
	var routerAlertOption [4]byte
	if routerAlert {
		headerSize = 24
		routerAlertOption = [4]byte{IPv4HeaderOptionRouterAlert, 4, 0, 0}
		packetValue.IPv4Options = routerAlertOption[:]
	}
	packet := make([]byte, headerSize+len(payload))
	marshalPublicIPPacket(packet, packetValue, headerSize)
	_ = s.stack.writePacketUntil(packet, socketWriteState{closed: cancel})
}

// sendMLDPacket adds the IPv6 Router Alert Hop-by-Hop header and repairs the
// ICMPv6 checksum before best-effort link output.
func (s *multicastState) sendMLDPacket(target netip.Addr, payload []byte, cancel <-chan struct{}) {
	source, ok := s.reportSource(true)
	if !ok || len(payload) < 4 {
		return
	}
	packet := make([]byte, 48+len(payload))
	marshalPublicIPv6BaseHeader(packet, IPPacket{Source: source, Destination: target, HopLimit: 1}, IPv6ExtensionHeaderHopByHop, 8+len(payload))
	copy(packet[40:48], []byte{ProtocolICMPv6, 0, IPv6ExtensionOptionRouterAlert, 2, 0, 0, IPv6ExtensionOptionPadN, 0})
	marshalPublicICMPMessage(packet[48:], ICMPMessage{
		Source: source, Destination: target, Type: payload[0], Code: payload[1], Body: payload[4:],
	})
	_ = s.stack.writePacketUntil(packet, socketWriteState{closed: cancel})
}

// reportSource selects the address required by IGMP or MLD. RFC 3590 permits
// the IPv6 unspecified source when no link-local address is configured.
func (s *multicastState) reportSource(v6 bool) (netip.Addr, bool) {
	network := s.stack.network.Load()
	if !v6 {
		for _, source := range network.sources {
			if source.Is4() && !source.IsLoopback() {
				return source, true
			}
		}
		return netip.Addr{}, false
	}
	for _, source := range network.sources {
		if source.Is6() && source.IsLinkLocalUnicast() {
			return source, true
		}
	}
	if networkStateHasFamily(network, true) {
		return netip.IPv6Unspecified(), true
	}
	return netip.Addr{}, false
}

// advanceRetransmissionLocked creates one RFC state-change report and
// decrements every source carried in it.
func (s *multicastState) advanceRetransmissionLocked(pending *multicastRetransmission) ([]multicastReportRecord, bool) {
	if pending.modeRemaining != 0 {
		recordType := byte(multicastRecordChangeToIncludeMode)
		if pending.filter.mode == multicastFilterExclude {
			recordType = multicastRecordChangeToExcludeMode
		}
		pending.modeRemaining--
		record := multicastReportRecord{recordType: recordType, sources: sortedMulticastSources(pending.filter.sources)}
		return []multicastReportRecord{record}, pending.modeRemaining != 0 || len(pending.allow) != 0 || len(pending.block) != 0
	}
	var records []multicastReportRecord
	if len(pending.allow) != 0 {
		records = append(records, multicastReportRecord{recordType: multicastRecordAllowNewSources, sources: advanceMulticastSourceCounters(pending.allow)})
	}
	if len(pending.block) != 0 {
		records = append(records, multicastReportRecord{recordType: multicastRecordBlockOldSources, sources: advanceMulticastSourceCounters(pending.block)})
	}
	return records, len(pending.allow) != 0 || len(pending.block) != 0
}

// advanceMulticastSourceCounters snapshots and decrements retransmission state.
func advanceMulticastSourceCounters(counters map[netip.Addr]uint8) []netip.Addr {
	result := make([]netip.Addr, 0, len(counters))
	for source, remaining := range counters {
		result = append(result, source)
		if remaining <= 1 {
			delete(counters, source)
		} else {
			counters[source] = remaining - 1
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Compare(result[right]) < 0 })
	return result
}

// multicastCurrentStateRecord implements the RFC source-query intersection.
func multicastCurrentStateRecord(group netip.Addr, filter multicastFilter, sourceQuery bool, queried map[netip.Addr]struct{}) multicastReportRecord {
	recordType := byte(multicastRecordModeIsInclude)
	if !sourceQuery && filter.mode == multicastFilterExclude {
		recordType = multicastRecordModeIsExclude
	}
	var sources []netip.Addr
	if sourceQuery {
		for source := range queried {
			_, listed := filter.sources[source]
			if filter.mode == multicastFilterInclude && listed || filter.mode == multicastFilterExclude && !listed {
				sources = append(sources, source)
			}
		}
		sort.Slice(sources, func(left, right int) bool { return sources[left].Compare(sources[right]) < 0 })
	} else {
		sources = sortedMulticastSources(filter.sources)
	}
	return multicastReportRecord{recordType: recordType, group: group, sources: sources}
}

// sortedMulticastSources makes report truncation stable across retransmits.
func sortedMulticastSources(sources map[netip.Addr]struct{}) []netip.Addr {
	result := make([]netip.Addr, 0, len(sources))
	for source := range sources {
		result = append(result, source)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Compare(result[right]) < 0 })
	return result
}

// legacyVersionLocked returns zero for IGMPv3/MLDv2 or the active older host
// compatibility version. The caller holds s.mu.
func (s *multicastState) legacyVersionLocked(v6 bool) uint8 {
	index, latest := 0, uint8(3)
	if v6 {
		index, latest = 1, 2
	}
	if s.compatibility[index] == latest {
		return 0
	}
	return s.compatibility[index]
}

// updateConfig schedules a fresh current-state report after address changes.
func (s *multicastState) updateConfig(network *networkState) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.removeInvalidSourcesLocked(network)
	now := time.Now()
	for index := range s.generalQuery {
		if s.familyGroups[index] != 0 && networkStateHasFamily(network, index == 1) {
			s.generalQuery[index] = now
		}
	}
	s.wakeLocked()
	s.mu.Unlock()
}

// removeInvalidSourcesLocked drops source entries that became IPv4 directed
// broadcast addresses after a prefix change. Published filters are replaced
// copy-on-write before the interface state and dispatch snapshots are rebuilt.
func (s *multicastState) removeInvalidSourcesLocked(network *networkState) {
	indexChanged := false
	for group, groupState := range s.groups {
		old, oldExists := multicastInterfaceFilter(groupState)
		oldLastReporter := groupState.lastReporter
		changed := false
		for endpoint, filter := range groupState.members {
			var updated *multicastFilter
			for source := range filter.sources {
				if validMulticastSourceAddress(network, source, group.Is6()) {
					continue
				}
				if updated == nil {
					copied := cloneMulticastFilter(*filter)
					updated = &copied
				}
				delete(updated.sources, source)
			}
			if updated == nil {
				continue
			}
			changed = true
			if updated.mode == multicastFilterInclude && len(updated.sources) == 0 {
				delete(groupState.members, endpoint)
			} else {
				groupState.members[endpoint] = updated
			}
		}
		if !changed {
			continue
		}
		removed := len(groupState.members) == 0
		if removed {
			s.removeGroupLocked(group)
			indexChanged = true
		} else {
			groupState.aggregate = aggregateMulticastFilter(groupState.members)
		}
		s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
		if !removed {
			s.rebuildGroupDispatchLocked(group)
		}
	}
	if indexChanged {
		s.rebuildDispatchIndexLocked()
	}
}

// close stops multicast background work and releases endpoint references.
func (s *multicastState) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		s.closed = true
		for index, cancel := range s.reportCancel {
			if cancel != nil {
				close(cancel)
				s.reportCancel[index] = nil
			}
		}
		for _, group := range s.groups {
			group.dispatch.Store(nil)
		}
		s.groups = nil
		s.retransmissions = nil
		s.dispatch.Store(nil)
		s.familyGroups = [2]int{}
		s.generalQuery = [2]time.Time{}
		s.mu.Unlock()
	})
}

// contains reports raw endpoint registration while Stack.mu is held.
func (state *ipEndpointState) contains(connection *IPConn) bool {
	for candidate := range state.bindings[ipKey{address: connection.local, protocol: connection.protocol}] {
		if candidate == connection {
			return true
		}
	}
	return false
}
