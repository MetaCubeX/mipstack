package mipstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
)

// Route admits one unicast destination prefix. Source optionally pins the
// preferred local source address; Metric breaks ties between equal prefixes.
// The embedding link remains responsible for next-hop selection.
type Route struct {
	Destination netip.Prefix
	Source      netip.Addr
	Metric      uint32
}

// networkState is an immutable address, route, and MTU snapshot.
type networkState struct {
	mtu               int
	maxTCPConnections int
	congestionControl CongestionControl
	local             map[netip.Addr]struct{}
	sources           []netip.Addr
	routes            []Route
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
	congestionControl := config.CongestionControl
	if congestionControl == "" {
		congestionControl = CongestionControlCUBIC
	}
	if !congestionControl.valid() {
		return nil, errors.New("mipstack: congestion control must be cubic, reno, or bbr")
	}
	state := &networkState{
		mtu: mtu, maxTCPConnections: config.MaxTCPConnections, congestionControl: congestionControl,
		local:   make(map[netip.Addr]struct{}, len(config.LocalAddresses)),
		sources: make([]netip.Addr, 0, len(config.LocalAddresses)),
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

// isIPv4Broadcast reports limited broadcast and subnet broadcast addresses.
// Prefixes /31 and /32 do not reserve a subnet broadcast address.
func isIPv4Broadcast(prefix netip.Prefix, address netip.Addr, bits int) bool {
	value := binary.BigEndian.Uint32(address.AsSlice())
	if value == ^uint32(0) {
		return true
	}
	if bits >= 31 {
		return false
	}
	network := binary.BigEndian.Uint32(prefix.Masked().Addr().Unmap().AsSlice())
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

// sourceFor selects a route-admitted local address using the applicable RFC
// 6724 rules for a single interface with preferred, non-temporary addresses.
func (state *networkState) sourceFor(destination, requested netip.Addr) (netip.Addr, error) {
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
	for _, candidate := range state.sources {
		if candidate.Is6() != destination.Is6() || !sourceScopeUsable(candidate, destination) {
			continue
		}
		if !selected.IsValid() || preferSource(candidate, selected, destination) {
			selected = candidate
		}
	}
	if !selected.IsValid() {
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	return selected, nil
}

// preferSource applies same-address, matching-scope, matching-label, and
// longest-prefix rules. Stable configuration order resolves complete ties.
func preferSource(candidate, current, destination netip.Addr) bool {
	if candidate == destination || current == destination {
		return candidate == destination
	}
	candidateScope, currentScope, destinationScope := addressScope(candidate), addressScope(current), addressScope(destination)
	if (candidateScope == destinationScope) != (currentScope == destinationScope) {
		return candidateScope == destinationScope
	}
	if (addressLabel(candidate) == addressLabel(destination)) != (addressLabel(current) == addressLabel(destination)) {
		return addressLabel(candidate) == addressLabel(destination)
	}
	return commonPrefixBits(candidate, destination) > commonPrefixBits(current, destination)
}

// sourceScopeUsable rejects a source whose scope cannot reach destination.
func sourceScopeUsable(source, destination netip.Addr) bool {
	return addressScope(source) >= addressScope(destination) || destination.IsLoopback()
}

// addressScope returns an ordered subset of the RFC 6724 scope classes.
func addressScope(address netip.Addr) uint8 {
	address = address.Unmap()
	if address.IsLoopback() {
		return 0
	}
	if address.IsLinkLocalUnicast() {
		return 1
	}
	return 2
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

// commonPrefixBits counts equal high-order address bits.
func commonPrefixBits(left, right netip.Addr) int {
	left, right = left.Unmap(), right.Unmap()
	if left.Is4() != right.Is4() {
		return 0
	}
	leftBytes, rightBytes := left.AsSlice(), right.AsSlice()
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
	return result
}
