package mipstack

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
)

// reuseTCPListenerBinding permits a port to be shared only with other
// REUSEPORT listeners.
type reuseTCPListenerBinding struct {
	reuseAddress bool
}

// tcpReuseRegistry owns flow-distributed TCP listener groups. Stack.mu
// protects its maps and group slices. Its unpredictable SipHash key prevents
// a remote peer that controls flow tuples from targeting one listener.
type tcpReuseRegistry struct {
	key    [16]byte
	groups map[tcpListenKey][]*TCPListener
}

// udpReuseRegistry owns SO_REUSEADDR and flow-distributed SO_REUSEPORT UDP
// groups. Stack.mu protects its maps and group slices. Its unpredictable
// SipHash key prevents a remote peer that controls flow tuples from targeting
// one SO_REUSEPORT socket.
type udpReuseRegistry struct {
	key    [16]byte
	groups map[udpKey][]*UDPConn
	all    []*UDPConn
}

// available rejects overlap with an ordinary listener. Other REUSEPORT
// groups may overlap; exact bindings take precedence during dispatch.
func (reuseTCPListenerBinding) available(state *tcpPassiveState, address netip.Addr, port uint16, dual bool) bool {
	for key, listener := range state.exclusive {
		if key.port == port && listenAddressesOverlap(key.address, listener.dual, address, dual) {
			return false
		}
	}
	if registry, ok := state.reuse.(*tcpReuseRegistry); ok {
		group := registry.groups[tcpListenKey{address: address, port: port}]
		if len(group) != 0 && group[0].dual != dual {
			return false
		}
	}
	return true
}

// register adds one TCP listener to its REUSEPORT group.
func (binding reuseTCPListenerBinding) register(state *tcpPassiveState, listener *TCPListener) error {
	registry, ok := state.reuse.(*tcpReuseRegistry)
	if !ok {
		registry = &tcpReuseRegistry{groups: make(map[tcpListenKey][]*TCPListener)}
		if _, err := rand.Read(registry.key[:]); err != nil {
			return err
		}
		state.reuse = registry
	}
	listener.reuseAddress = binding.reuseAddress
	listener.reusePort = true
	registry.add(listener)
	return nil
}

// connectionReusable implements tcpListenerBinding. Linux permits an active
// tuple to coexist when both sockets share either SO_REUSEADDR or
// SO_REUSEPORT; the two options remain independent.
func (binding reuseTCPListenerBinding) connectionReusable(connection *TCPConn) bool {
	return binding.reuseAddress && connection.reuseAddress || connection.reusePort
}

// empty reports whether no TCP REUSEPORT groups remain.
func (registry *tcpReuseRegistry) empty() bool { return len(registry.groups) == 0 }

// listeners returns all TCP REUSEPORT listeners while Stack.mu is held.
func (registry *tcpReuseRegistry) listeners() []*TCPListener {
	var listeners []*TCPListener
	for _, group := range registry.groups {
		listeners = append(listeners, group...)
	}
	return listeners
}

// overlaps reports whether a TCP REUSEPORT binding covers an endpoint.
func (registry *tcpReuseRegistry) overlaps(address netip.Addr, port uint16, dual bool) bool {
	for key, group := range registry.groups {
		if key.port == port && len(group) != 0 && listenAddressesOverlap(key.address, group[0].dual, address, dual) {
			return true
		}
	}
	return false
}

// listener selects one member of an exact TCP REUSEPORT group.
func (registry *tcpReuseRegistry) listener(binding, local, remote netip.AddrPort) *TCPListener {
	group := registry.groups[tcpListenKey{address: binding.Addr(), port: binding.Port()}]
	if len(group) == 0 {
		return nil
	}
	return group[reuseFlowIndex(registry.key, local, remote, len(group))]
}

// add appends one TCP listener to its group.
func (registry *tcpReuseRegistry) add(listener *TCPListener) {
	registry.groups[listener.key] = append(registry.groups[listener.key], listener)
}

// remove deletes one TCP listener without disturbing unrelated groups.
func (registry *tcpReuseRegistry) remove(listener *TCPListener) bool {
	group := registry.groups[listener.key]
	for index, candidate := range group {
		if candidate != listener {
			continue
		}
		last := len(group) - 1
		group[index] = group[last]
		group[last] = nil
		if last == 0 {
			delete(registry.groups, listener.key)
		} else {
			registry.groups[listener.key] = group[:last]
		}
		return true
	}
	return false
}

// reuseUDPSocketBinding requests SO_REUSEPORT and retains whether the same
// bind also requested SO_REUSEADDR for pairwise Linux compatibility checks.
type reuseUDPSocketBinding struct {
	reuseAddress bool
}

// available accepts overlap with existing REUSEPORT sockets. The shared
// listen core separately rejects every overlapping ordinary UDP socket.
func (binding reuseUDPSocketBinding) available(stack *Stack, address netip.Addr, port uint16, dual bool) bool {
	return reusableUDPBindingAvailable(stack, address, port, dual, binding.reuseAddress, true)
}

// register adds one UDP socket to its REUSEPORT group.
func (binding reuseUDPSocketBinding) register(stack *Stack, connection *UDPConn) error {
	connection.reuseAddress = binding.reuseAddress
	connection.reusePort = true
	return registerReusableUDP(stack, connection)
}

// registerReusableUDP initializes the shared registry and adds one endpoint.
func registerReusableUDP(stack *Stack, connection *UDPConn) error {
	registry, ok := stack.udpReuse.(*udpReuseRegistry)
	if !ok {
		registry = &udpReuseRegistry{groups: make(map[udpKey][]*UDPConn)}
		if _, err := rand.Read(registry.key[:]); err != nil {
			return err
		}
		stack.udpReuse = registry
	}
	registry.add(connection)
	return nil
}

// reusableUDPBindingAvailable applies Linux's pairwise bind rule to every
// overlapping reusable socket. Two endpoints may coexist when both selected
// SO_REUSEADDR or both selected SO_REUSEPORT; an endpoint selecting both can
// therefore join either kind of group. Identical IPv6 wildcard bindings must
// still agree about whether they also accept IPv4 traffic.
func reusableUDPBindingAvailable(stack *Stack, address netip.Addr, port uint16, dual, reuseAddress, reusePort bool) bool {
	registry, ok := stack.udpReuse.(*udpReuseRegistry)
	if !ok {
		return true
	}
	for _, connection := range registry.all {
		if connection.port != port || !listenAddressesOverlap(connection.local, connection.dual, address, dual) {
			continue
		}
		if connection.local == address && connection.dual != dual {
			return false
		}
		if !(reuseAddress && connection.reuseAddress || reusePort && connection.reusePort) {
			return false
		}
	}
	return true
}

// empty reports whether no UDP REUSEPORT groups remain.
func (registry *udpReuseRegistry) empty() bool { return len(registry.groups) == 0 }

// connections returns the registry-owned flat socket list. The caller holds
// Stack.mu and must not retain or modify the returned slice.
func (registry *udpReuseRegistry) connections() []*UDPConn { return registry.all }

// contains reports whether connection is still registered in its exact
// REUSEPORT group. The caller holds Stack.mu.
func (registry *udpReuseRegistry) contains(connection *UDPConn) bool {
	key := udpKey{address: connection.local, port: connection.port}
	for _, candidate := range registry.groups[key] {
		if candidate == connection {
			return true
		}
	}
	return false
}

// overlaps reports whether a UDP REUSEPORT binding covers an endpoint.
func (registry *udpReuseRegistry) overlaps(address netip.Addr, port uint16, dual bool) bool {
	for key, group := range registry.groups {
		if key.port == port && len(group) != 0 && listenAddressesOverlap(key.address, group[0].dual, address, dual) {
			return true
		}
	}
	return false
}

// connection selects one member of an exact UDP REUSEPORT group.
func (registry *udpReuseRegistry) connection(binding, local, remote netip.AddrPort) *UDPConn {
	group := registry.groups[udpKey{address: binding.Addr(), port: binding.Port()}]
	if len(group) == 0 {
		return nil
	}
	for _, connection := range group {
		if !connection.reusePort {
			return group[len(group)-1]
		}
	}
	return group[reuseFlowIndex(registry.key, local, remote, len(group))]
}

// add appends one UDP socket to its group.
func (registry *udpReuseRegistry) add(connection *UDPConn) {
	key := udpKey{address: connection.local, port: connection.port}
	registry.groups[key] = append(registry.groups[key], connection)
	registry.all = append(registry.all, connection)
}

// remove deletes one UDP socket without disturbing unrelated groups.
func (registry *udpReuseRegistry) remove(connection *UDPConn) bool {
	key := udpKey{address: connection.local, port: connection.port}
	group := registry.groups[key]
	for index, candidate := range group {
		if candidate != connection {
			continue
		}
		last := len(group) - 1
		copy(group[index:], group[index+1:])
		group[last] = nil
		if last == 0 {
			delete(registry.groups, key)
		} else {
			registry.groups[key] = group[:last]
		}
		for flatIndex, flatConnection := range registry.all {
			if flatConnection != connection {
				continue
			}
			flatLast := len(registry.all) - 1
			registry.all[flatIndex] = registry.all[flatLast]
			registry.all[flatLast] = nil
			registry.all = registry.all[:flatLast]
			break
		}
		return true
	}
	return false
}

// reuseFlowIndex hashes both endpoints with a per-registry random seed. The
// binding lookup key may be a wildcard, so local is always the actual packet
// destination rather than the registered wildcard address.
func reuseFlowIndex(key [16]byte, local, remote netip.AddrPort, count int) int {
	var input [38]byte
	encodeReuseAddress(input[0:17], local.Addr())
	encodeReuseAddress(input[17:34], remote.Addr())
	binary.BigEndian.PutUint16(input[34:36], local.Port())
	binary.BigEndian.PutUint16(input[36:38], remote.Port())
	return int(sipHash24(key, input[:]) % uint64(count))
}

// encodeReuseAddress adds an unambiguous address family and bytes to a flow
// hash.
func encodeReuseAddress(output []byte, address netip.Addr) {
	if !address.IsValid() {
		return
	}
	if address.Is4() {
		value := address.As4()
		output[0] = 4
		copy(output[1:5], value[:])
		return
	}
	value := address.As16()
	output[0] = 6
	copy(output[1:17], value[:])
}
