package mipstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
)

// AddressProperties supplies RFC 6724 source-selection state that cannot be
// represented by a netip.Prefix alone.
type AddressProperties struct {
	// Deprecated marks an address past its preferred lifetime. Automatic source
	// selection avoids it when an otherwise usable preferred address exists.
	Deprecated bool
	// Temporary marks an IPv6 privacy address. PreferTemporaryAddresses selects
	// whether automatic source selection favors it over a stable address.
	Temporary bool
}

// Route admits one unicast destination prefix. Source optionally pins the
// preferred local source address; Metric breaks ties between equal prefixes.
// The embedding link remains responsible for next-hop selection.
type Route struct {
	// Destination is the admitted unicast prefix.
	Destination netip.Prefix
	// Source pins the preferred local source address when valid.
	Source netip.Addr
	// Metric breaks ties between routes with equal prefix length.
	Metric uint32
}

// networkState is an immutable address, route, and MTU snapshot.
type networkState struct {
	mtu               int
	maxTCPConnections int
	promiscuous       bool
	tcpDefaults       TCPSocketDefaults
	udpDefaults       DatagramSocketDefaults
	ipDefaults        DatagramSocketDefaults
	local             map[netip.Addr]struct{}
	broadcast         map[netip.Addr]struct{}
	sources           []netip.Addr
	sourcePrefixBits  []int
	localPrefixes     []netip.Prefix
	routes            []Route
	addressProperties map[netip.Addr]AddressProperties
	preferTemporary   bool
}

// samePathConfiguration reports whether cached destination PMTU information
// remains valid across a configuration update. Address order participates in
// source selection, while prefix and route order can change admission and
// equal-priority route selection.
func (state *networkState) samePathConfiguration(other *networkState) bool {
	if state == nil || other == nil || state.mtu != other.mtu ||
		len(state.sources) != len(other.sources) || len(state.localPrefixes) != len(other.localPrefixes) || len(state.routes) != len(other.routes) ||
		!state.sameSourceProperties(other) {
		return false
	}
	for index := range state.sources {
		if state.sources[index] != other.sources[index] {
			return false
		}
	}
	for index := range state.localPrefixes {
		if state.localPrefixes[index] != other.localPrefixes[index] {
			return false
		}
	}
	for index := range state.routes {
		if state.routes[index] != other.routes[index] {
			return false
		}
	}
	return true
}

// sameMulticastConfiguration reports whether family availability, report
// source selection, and IPv4 directed-broadcast classification are unchanged.
func (state *networkState) sameMulticastConfiguration(other *networkState) bool {
	if state == nil || other == nil || len(state.sources) != len(other.sources) || len(state.localPrefixes) != len(other.localPrefixes) ||
		!state.sameSourceProperties(other) {
		return false
	}
	for index := range state.sources {
		if state.sources[index] != other.sources[index] {
			return false
		}
	}
	for index := range state.localPrefixes {
		if state.localPrefixes[index] != other.localPrefixes[index] {
			return false
		}
	}
	return true
}

// sameSourceProperties reports whether RFC 6724 address preference state is
// unchanged between immutable network snapshots.
func (state *networkState) sameSourceProperties(other *networkState) bool {
	if state.preferTemporary != other.preferTemporary || len(state.addressProperties) != len(other.addressProperties) {
		return false
	}
	for address, properties := range state.addressProperties {
		otherProperties, exists := other.addressProperties[address]
		if !exists || otherProperties != properties {
			return false
		}
	}
	return true
}

// buildNetworkState validates and normalizes one public configuration.
func buildNetworkState(config Config) (*networkState, error) {
	mtu := int(config.MTU)
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 68 || mtu > 65535 {
		return nil, errors.New("mipstack: MTU must be between 68 and 65535")
	}
	if config.MaxTCPConnections < 0 {
		return nil, errors.New("mipstack: maximum TCP connections cannot be negative")
	}
	tcpDefaults, err := normalizeTCPSocketDefaults(config.TCP)
	if err != nil {
		return nil, err
	}
	udpDefaults, err := normalizeDatagramSocketDefaults(config.UDP, udpDefaultReceiveCapacity, udpDatagramMetadataSize)
	if err != nil {
		return nil, errors.New("mipstack: invalid UDP socket defaults: " + err.Error())
	}
	ipDefaults, err := normalizeDatagramSocketDefaults(config.IP, ipDefaultReceiveCapacity, ipDatagramMetadataSize)
	if err != nil {
		return nil, errors.New("mipstack: invalid IP socket defaults: " + err.Error())
	}
	state := &networkState{
		mtu: mtu, maxTCPConnections: config.MaxTCPConnections, promiscuous: config.Promiscuous,
		tcpDefaults: tcpDefaults, udpDefaults: udpDefaults, ipDefaults: ipDefaults,
		local: make(map[netip.Addr]struct{}, len(config.LocalAddresses)), sources: make([]netip.Addr, 0, len(config.LocalAddresses)),
		preferTemporary: config.PreferTemporaryAddresses,
	}
	for _, prefix := range config.LocalAddresses {
		address := prefix.Addr().Unmap()
		if !prefix.IsValid() || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return nil, errors.New("mipstack: invalid local address")
		}
		bits := prefix.Bits()
		if prefix.Addr().Is6() && address.Is4() {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return nil, errors.New("mipstack: invalid local prefix")
		}
		if address.Is4() && isIPv4Broadcast(prefix, address, bits) {
			return nil, errors.New("mipstack: IPv4 broadcast address cannot be local")
		}
		if _, exists := state.local[address]; !exists {
			state.local[address] = struct{}{}
			state.sources = append(state.sources, address)
			state.sourcePrefixBits = append(state.sourcePrefixBits, bits)
		}
		masked := netip.PrefixFrom(address, bits).Masked()
		state.localPrefixes = append(state.localPrefixes, masked)
		if broadcast, ok := ipv4BroadcastAddress(masked); ok {
			if state.broadcast == nil {
				state.broadcast = make(map[netip.Addr]struct{}, len(config.LocalAddresses))
			}
			state.broadcast[broadcast] = struct{}{}
		}
	}
	for address := range state.local {
		if _, broadcast := state.broadcast[address]; broadcast {
			return nil, errors.New("mipstack: IPv4 broadcast address cannot be local")
		}
	}
	if len(config.AddressProperties) != 0 {
		state.addressProperties = make(map[netip.Addr]AddressProperties, len(config.AddressProperties))
		for address, properties := range config.AddressProperties {
			normalized := address.Unmap()
			if !address.IsValid() || address.Zone() != "" || !normalized.IsValid() || normalized.IsUnspecified() || normalized.IsMulticast() {
				return nil, errors.New("mipstack: invalid address-properties key")
			}
			if _, local := state.local[normalized]; !local {
				return nil, errors.New("mipstack: address properties refer to a nonlocal address")
			}
			if properties.Temporary && normalized.Is4() {
				return nil, errors.New("mipstack: temporary source property requires IPv6")
			}
			if existing, duplicate := state.addressProperties[normalized]; duplicate && existing != properties {
				return nil, errors.New("mipstack: conflicting address properties")
			}
			state.addressProperties[normalized] = properties
		}
	}
	if len(state.local) == 0 {
		return nil, errors.New("mipstack: at least one local address is required")
	}
	if mtu < ipv6MinimumMTU {
		for _, source := range state.sources {
			if source.Is6() {
				return nil, errors.New("mipstack: IPv6 requires an MTU of at least 1280")
			}
		}
	}
	state.routes = make([]Route, 0, len(config.Routes)+2)
	for _, route := range config.Routes {
		destination, err := normalizeRoutePrefix(route.Destination)
		if err != nil {
			return nil, err
		}
		source := route.Source.Unmap()
		if route.Source.IsValid() {
			if !source.IsValid() || source.IsUnspecified() || source.IsMulticast() || source.Zone() != "" || source.Is6() != destination.Addr().Is6() {
				return nil, errors.New("mipstack: invalid route source")
			}
			if _, exists := state.local[source]; !exists {
				return nil, errors.New("mipstack: route source is not local")
			}
		} else {
			source = netip.Addr{}
		}
		state.routes = append(state.routes, Route{Destination: destination, Source: source, Metric: route.Metric})
	}
	for _, route := range state.routes {
		familyAvailable := false
		for _, source := range state.sources {
			if source.Is6() == route.Destination.Addr().Is6() {
				familyAvailable = true
				break
			}
		}
		if !familyAvailable {
			return nil, errors.New("mipstack: route has no local address in its family")
		}
	}
	if config.Routes == nil {
		var have4, have6 bool
		for _, source := range state.sources {
			if source.Is4() {
				have4 = true
			} else {
				have6 = true
			}
		}
		if have4 {
			state.routes = append(state.routes, Route{Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0)})
		}
		if have6 {
			state.routes = append(state.routes, Route{Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0)})
		}
	}
	return state, nil
}

// acceptsInboundDestination reports whether one unicast destination may enter
// transport dispatch. Promiscuous admission deliberately remains separate
// from local ownership, source selection, and loopback routing.
func (state *networkState) acceptsInboundDestination(address netip.Addr) bool {
	address = address.Unmap()
	if _, local := state.local[address]; local {
		return true
	}
	return state.acceptsNonlocalDestination(address)
}

// acceptsNonlocalDestination applies only the promiscuous branch after the
// caller has already established that address is not locally owned.
func (state *networkState) acceptsNonlocalDestination(address netip.Addr) bool {
	address = address.Unmap()
	if !state.promiscuous || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return false
	}
	return !state.broadcastDestination(address)
}

// normalizeTCPSocketDefaults validates optional limits and fills the policy
// used by new sockets without changing Config's useful zero value.
func normalizeTCPSocketDefaults(value TCPSocketDefaults) (TCPSocketDefaults, error) {
	if value.CongestionControlFactory != nil {
		if value.CongestionControl != "" {
			return TCPSocketDefaults{}, errors.New("mipstack: TCP congestion control name and factory are mutually exclusive")
		}
		if !value.CongestionControlFactory.valid() {
			return TCPSocketDefaults{}, errors.New("mipstack: invalid TCP congestion control factory")
		}
	} else {
		if value.CongestionControl == "" {
			value.CongestionControl = CongestionControlCUBIC
		}
		factory, exists := registeredCongestionControlFactory(value.CongestionControl)
		if !exists {
			return TCPSocketDefaults{}, errors.New("mipstack: unsupported congestion control")
		}
		value.CongestionControl = ""
		value.CongestionControlFactory = factory
	}
	if value.ReceiveBuffer < 0 || value.MaximumReceiveBuffer < 0 || value.SendBuffer < 0 || value.MaximumSendBuffer < 0 ||
		value.AcceptQueue < 0 || value.SYNBacklog < 0 || value.IdleTimeout < 0 || value.UserTimeout < 0 {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP socket defaults cannot be negative")
	}
	if value.FlowLabel > ipv6MaximumFlowLabel {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP flow label exceeds 20 bits")
	}
	if value.ReceiveBuffer == 0 {
		value.ReceiveBuffer = tcpReceiveCapacity
	}
	if value.MaximumReceiveBuffer == 0 {
		value.MaximumReceiveBuffer = tcpMaximumReceiveCapacity
	}
	if value.SendBuffer == 0 {
		value.SendBuffer = tcpSendCapacity
	}
	if value.MaximumSendBuffer == 0 {
		value.MaximumSendBuffer = tcpMaximumSendCapacity
	}
	if value.MaximumReceiveBuffer < value.ReceiveBuffer || value.MaximumSendBuffer < value.SendBuffer {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP automatic buffer maximum is below its initial size")
	}
	if uint64(value.MaximumReceiveBuffer) > uint64(tcpMaximumScaledWindow) {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP receive buffer maximum exceeds the RFC 7323 window limit")
	}
	if value.AcceptQueue == 0 {
		value.AcceptQueue = tcpAcceptQueue
	}
	if value.SYNBacklog == 0 {
		value.SYNBacklog = tcpSYNBacklog
	}
	if value.KeepAliveConfig.Idle == 0 {
		value.KeepAliveConfig.Idle = tcpDefaultKeepAliveIdle
	}
	if value.KeepAliveConfig.Interval == 0 {
		value.KeepAliveConfig.Interval = tcpDefaultKeepAliveInterval
	}
	if value.KeepAliveConfig.Count == 0 {
		value.KeepAliveConfig.Count = tcpDefaultKeepAliveCount
	}
	if value.KeepAliveConfig.Idle < 0 || value.KeepAliveConfig.Interval < 0 || value.KeepAliveConfig.Count < 0 {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP keepalive defaults cannot be negative")
	}
	value.TrafficClass &= 0xfc
	return value, nil
}

// normalizeDatagramSocketDefaults validates one UDP or IP default policy.
func normalizeDatagramSocketDefaults(value DatagramSocketDefaults, defaultReceiveBuffer, minimumReceiveBuffer int) (DatagramSocketDefaults, error) {
	if value.ReceiveBuffer < 0 || value.HopLimit < 0 || value.HopLimit > 255 || value.MulticastHopLimit < 0 || value.MulticastHopLimit > 255 {
		return DatagramSocketDefaults{}, errors.New("receive buffer and hop limit must be valid")
	}
	if !value.PathMTUDiscovery.valid() {
		return DatagramSocketDefaults{}, errors.New("unsupported path MTU discovery mode")
	}
	if value.FlowLabel > ipv6MaximumFlowLabel {
		return DatagramSocketDefaults{}, errors.New("flow label exceeds 20 bits")
	}
	if value.ReceiveBuffer == 0 {
		value.ReceiveBuffer = defaultReceiveBuffer
	} else if value.ReceiveBuffer < minimumReceiveBuffer {
		value.ReceiveBuffer = minimumReceiveBuffer
	}
	if value.HopLimit == 0 {
		value.HopLimit = 64
	}
	if value.MulticastHopLimit == 0 {
		value.MulticastHopLimit = 1
	}
	return value, nil
}

// invalidInboundSource reports source addresses that RFC 1122 forbids on an
// incoming datagram. Generic multicast, unspecified, and limited-broadcast
// checks are performed by the caller; this method recognizes a directed
// broadcast on one of the stack's configured IPv4 subnets.
func (state *networkState) invalidInboundSource(address netip.Addr) bool {
	_, broadcast := state.broadcast[address.Unmap()]
	return broadcast
}

// broadcastDestination reports limited broadcast and directed broadcast for
// one of the configured IPv4 prefixes.
func (state *networkState) broadcastDestination(address netip.Addr) bool {
	address = address.Unmap()
	if !address.Is4() {
		return false
	}
	if address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	_, broadcast := state.broadcast[address]
	return broadcast
}

// ipv4BroadcastAddress returns the directed broadcast for prefixes that have
// a host field. RFC 3021 /31 and host /32 prefixes have no broadcast address;
// RFC 1122 loopback space must never select the embedding link.
func ipv4BroadcastAddress(prefix netip.Prefix) (netip.Addr, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() || prefix.Bits() >= 31 {
		return netip.Addr{}, false
	}
	networkBytes := prefix.Masked().Addr().As4()
	network := binary.BigEndian.Uint32(networkBytes[:])
	hostMask := uint32((uint64(1) << (32 - prefix.Bits())) - 1)
	var address [4]byte
	binary.BigEndian.PutUint32(address[:], network|hostMask)
	return netip.AddrFrom4(address), true
}

// isIPv4Broadcast reports limited broadcast and subnet broadcast addresses.
// Prefixes /31 and /32 do not reserve a subnet broadcast address.
func isIPv4Broadcast(prefix netip.Prefix, address netip.Addr, bits int) bool {
	addressBytes := address.As4()
	value := binary.BigEndian.Uint32(addressBytes[:])
	if value == ^uint32(0) {
		return true
	}
	if bits >= 31 {
		return false
	}
	networkBytes := prefix.Masked().Addr().Unmap().As4()
	network := binary.BigEndian.Uint32(networkBytes[:])
	hostMask := uint32((uint64(1) << (32 - bits)) - 1)
	return value == network|hostMask
}

// normalizeRoutePrefix converts mapped IPv4 prefixes and rejects malformed
// or zone-bearing route keys.
func normalizeRoutePrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, errors.New("mipstack: invalid route destination")
	}
	address := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if prefix.Addr().Is6() && address.Is4() {
		bits -= 96
	}
	if bits < 0 || bits > address.BitLen() {
		return netip.Prefix{}, errors.New("mipstack: invalid route destination")
	}
	return netip.PrefixFrom(address, bits).Masked(), nil
}

// routeFor returns the longest-prefix, lowest-metric route for destination.
func (state *networkState) routeFor(destination netip.Addr) (Route, bool) {
	destination = destination.Unmap()
	if _, local := state.local[destination]; local {
		return Route{Destination: netip.PrefixFrom(destination, destination.BitLen()), Source: destination}, true
	}
	var selected Route
	selectedIndex := -1
	for index, route := range state.routes {
		if route.Destination.Addr().Is6() != destination.Is6() || !route.Destination.Contains(destination) {
			continue
		}
		if selectedIndex < 0 || route.Destination.Bits() > selected.Destination.Bits() ||
			route.Destination.Bits() == selected.Destination.Bits() && route.Metric < selected.Metric {
			selected, selectedIndex = route, index
		}
	}
	return selected, selectedIndex >= 0
}

// sourceForUnicast selects a route-admitted local address using the applicable
// RFC 6724 rules for a single interface. The caller has already excluded
// multicast and broadcast.
func (state *networkState) sourceForUnicast(destination, requested netip.Addr) (netip.Addr, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || destination.IsUnspecified() || destination.IsMulticast() || destination.Zone() != "" {
		return netip.Addr{}, syscall.EINVAL
	}
	route, exists := state.routeFor(destination)
	if !exists {
		return netip.Addr{}, syscall.ENETUNREACH
	}
	if destination.IsLoopback() {
		if _, local := state.local[destination]; !local {
			return netip.Addr{}, syscall.ENETUNREACH
		}
	}
	requested = requested.Unmap()
	if requested.IsValid() && !requested.IsUnspecified() {
		if requested.Is6() != destination.Is6() {
			return netip.Addr{}, syscall.EAFNOSUPPORT
		}
		if _, local := state.local[requested]; !local {
			return netip.Addr{}, syscall.EADDRNOTAVAIL
		}
		return requested, nil
	}
	if route.Source.IsValid() {
		return route.Source, nil
	}
	var selected netip.Addr
	selectedPrefixBits := 0
	for index, candidate := range state.sources {
		if candidate.Is6() != destination.Is6() {
			continue
		}
		candidatePrefixBits := state.sourcePrefixBits[index]
		if !selected.IsValid() || state.preferSource(candidate, candidatePrefixBits, selected, selectedPrefixBits, destination) {
			selected = candidate
			selectedPrefixBits = candidatePrefixBits
		}
	}
	if !selected.IsValid() {
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	return selected, nil
}

// sourceForNonUnicast selects the source of output constrained to mipstack's
// single embedding interface. Broadcast and multicast do not use the unicast
// route table: Linux represents their selected output interface separately,
// while mipstack has exactly one such interface.
func (state *networkState) sourceForNonUnicast(destination, requested netip.Addr) (netip.Addr, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || destination.IsUnspecified() || destination.Zone() != "" ||
		!destination.IsMulticast() && !state.broadcastDestination(destination) {
		return netip.Addr{}, syscall.EINVAL
	}
	if destination.IsMulticast() && !validMulticastGroup(destination) {
		return netip.Addr{}, syscall.EINVAL
	}
	requested = requested.Unmap()
	if requested.IsValid() && !requested.IsUnspecified() {
		if requested.Zone() != "" || requested.IsMulticast() || requested.Is6() != destination.Is6() {
			return netip.Addr{}, syscall.EAFNOSUPPORT
		}
		if _, local := state.local[requested]; !local {
			return netip.Addr{}, syscall.EADDRNOTAVAIL
		}
		if state.broadcastDestination(destination) && requested.IsLoopback() {
			return netip.Addr{}, syscall.ENETUNREACH
		}
		if destination.IsMulticast() && !sourceScopeUsable(requested, destination) {
			return netip.Addr{}, syscall.ENETUNREACH
		}
		return requested, nil
	}
	if state.broadcastDestination(destination) {
		// Prefer an address from the directed-broadcast subnet. Limited
		// broadcast falls through to the first configured IPv4 address.
		if destination != netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			for _, prefix := range state.localPrefixes {
				if !prefix.Addr().Is4() || !isIPv4Broadcast(prefix, destination, prefix.Bits()) {
					continue
				}
				for _, candidate := range state.sources {
					if candidate.Is4() && !candidate.IsLoopback() && prefix.Contains(candidate) {
						return candidate, nil
					}
				}
			}
		}
		for _, candidate := range state.sources {
			if candidate.Is4() && !candidate.IsLoopback() {
				return candidate, nil
			}
		}
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	if destination.Is4() {
		// Without IP_MULTICAST_IF, Linux uses the selected interface's
		// primary IPv4 address. Configuration order defines that primary
		// address for mipstack's single interface.
		for _, candidate := range state.sources {
			if candidate.Is4() && !candidate.IsLoopback() {
				return candidate, nil
			}
		}
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	var selected netip.Addr
	selectedPrefixBits := 0
	for index, candidate := range state.sources {
		if candidate.Is6() != destination.Is6() {
			continue
		}
		candidatePrefixBits := state.sourcePrefixBits[index]
		if !selected.IsValid() || state.preferSource(candidate, candidatePrefixBits, selected, selectedPrefixBits, destination) {
			selected = candidate
			selectedPrefixBits = candidatePrefixBits
		}
	}
	if !selected.IsValid() {
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	return selected, nil
}

// hasOutputPath reports whether an established connectionless socket can
// still select this stack's only output interface after a configuration
// change. Non-unicast interface selection is independent of unicast routes.
func (state *networkState) hasOutputPath(destination netip.Addr) bool {
	destination = destination.Unmap()
	if destination.IsMulticast() || state.broadcastDestination(destination) {
		return networkStateHasFamily(state, destination.Is6())
	}
	_, routed := state.routeFor(destination)
	return routed
}

// preferSource applies the relevant RFC 6724 rules in order. Home-address and
// outgoing-interface rules are ties because one Stack represents one
// interface and exposes no mobile home-address state. Stable configuration
// order resolves complete ties.
func (state *networkState) preferSource(candidate netip.Addr, candidatePrefixBits int, current netip.Addr, currentPrefixBits int, destination netip.Addr) bool {
	if candidate == destination || current == destination {
		return candidate == destination
	}
	candidateScope, currentScope, destinationScope := addressScope(candidate), addressScope(current), addressScope(destination)
	if candidateScope != currentScope {
		candidateAppropriate := candidateScope >= destinationScope
		currentAppropriate := currentScope >= destinationScope
		if candidateAppropriate != currentAppropriate {
			return candidateAppropriate
		}
		if candidateAppropriate {
			return candidateScope < currentScope
		}
		return candidateScope > currentScope
	}
	candidateProperties, currentProperties := state.addressProperties[candidate], state.addressProperties[current]
	if candidateProperties.Deprecated != currentProperties.Deprecated {
		return !candidateProperties.Deprecated
	}
	if (addressLabel(candidate) == addressLabel(destination)) != (addressLabel(current) == addressLabel(destination)) {
		return addressLabel(candidate) == addressLabel(destination)
	}
	if candidateProperties.Temporary != currentProperties.Temporary {
		return candidateProperties.Temporary == state.preferTemporary
	}
	return commonPrefixBits(candidate, destination, candidatePrefixBits) > commonPrefixBits(current, destination, currentPrefixBits)
}

// sourceScopeUsable reports whether an explicitly selected source has enough
// scope for a non-unicast destination. Automatic RFC 6724 selection does not
// discard insufficient candidates because one must still win when every
// configured address has insufficient scope.
func sourceScopeUsable(source, destination netip.Addr) bool {
	return addressScope(source) >= addressScope(destination) || destination.IsLoopback()
}

// validMulticastGroup rejects malformed group addresses that netip still
// classifies by prefix. It applies RFC 4291/RFC 7346 reserved flag and scope
// rules plus the RFC 3306/RFC 3956 dependencies between R, P, and T. Embedded
// fields are deliberately not validated here because RFC 3956 requires
// receivers to ignore some sender-reserved values.
func validMulticastGroup(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsMulticast() || address.Zone() != "" {
		return false
	}
	if address.Is4() {
		return true
	}
	raw := address.As16()
	flags, scope := raw[1]>>4, raw[1]&0x0f
	if scope == 0 || scope == 0x0f || flags&8 != 0 {
		return false
	}
	transient, prefixBased, embeddedRP := flags&1 != 0, flags&2 != 0, flags&4 != 0
	if prefixBased && !transient || embeddedRP && !prefixBased {
		return false
	}
	return true
}

// isInterfaceLocalMulticast identifies IPv6 scope one, which may traverse
// mipstack's internal loopback path but must never arrive from or leave via
// the embedding link.
func isInterfaceLocalMulticast(address netip.Addr) bool {
	address = address.Unmap()
	return address.Is6() && address.IsMulticast() && address.As16()[1]&0x0f == 1
}

// addressScope returns the RFC 6724 scope used to compare unicast and
// multicast candidates. The values match IPv6 multicast's scope field.
func addressScope(address netip.Addr) uint8 {
	address = address.Unmap()
	if address.IsLoopback() {
		return 2
	}
	if address.IsMulticast() {
		if address.Is4() {
			value := address.As4()
			if value[0] == 224 && value[1] == 0 && value[2] == 0 {
				return 2
			}
			if value[0] == 239 && value[1] == 255 {
				return 3
			}
			if value[0] == 239 && value[1]&0xfc == 192 {
				return 8
			}
			return 14
		}
		return address.As16()[1] & 0x0f
	}
	if address.IsLinkLocalUnicast() {
		return 2
	}
	if address.Is6() {
		value := address.As16()
		if value[0] == 0xfe && value[1]&0xc0 == 0xc0 {
			return 5
		}
	}
	return 14
}

// addressLabel returns the relevant RFC 6724 default-policy label.
func addressLabel(address netip.Addr) uint8 {
	address = address.Unmap()
	if address.Is4() {
		return 4
	}
	if address.IsLoopback() {
		return 0
	}
	value := address.As16()
	if value[0] == 0x20 && value[1] == 0x02 {
		return 2
	}
	if value[0] == 0x20 && value[1] == 0x01 && value[2] == 0 && value[3] == 0 {
		return 5
	}
	if value[0]&0xfe == 0xfc {
		return 13
	}
	if value[0] == 0xfe && value[1]&0xc0 == 0xc0 {
		return 11
	}
	if value[0] == 0x3f && value[1] == 0xfe {
		return 12
	}
	if binary.BigEndian.Uint64(value[:8]) == 0 && binary.BigEndian.Uint32(value[8:12]) == 0 {
		return 3
	}
	return 1
}

// commonPrefixBits counts equal high-order address bits up to the source
// address's configured prefix length, as required by RFC 6724 rule 8.
func commonPrefixBits(left, right netip.Addr, limit int) int {
	left, right = left.Unmap(), right.Unmap()
	if !left.IsValid() || !right.IsValid() || left.Is4() != right.Is4() || limit <= 0 {
		return 0
	}
	leftValue, rightValue := left.As16(), right.As16()
	start := 0
	if left.Is4() {
		start = 12
	}
	leftBytes, rightBytes := leftValue[start:], rightValue[start:]
	result := 0
	for index := range leftBytes {
		difference := leftBytes[index] ^ rightBytes[index]
		if difference == 0 {
			result += 8
			continue
		}
		for mask := byte(0x80); difference&mask == 0; mask >>= 1 {
			result++
		}
		break
	}
	if result > limit {
		return limit
	}
	return result
}
