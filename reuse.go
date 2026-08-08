package mipstack

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
)

// reuseTCPListenerBinding permits a port to be shared only with other
// REUSEPORT listeners.
type reuseTCPListenerBinding struct{}

// tcpReuseRegistry owns flow-distributed TCP listener groups. Stack.mu
// protects its maps and group slices. Its unpredictable SipHash key prevents
// a remote peer that controls flow tuples from targeting one listener.
type tcpReuseRegistry struct {
	key    [16]byte
	groups map[tcpListenKey][]*TCPListener
}

// udpReuseRegistry owns flow-distributed UDP socket groups. Stack.mu protects
// its maps and group slices. Its unpredictable SipHash key prevents a remote
// peer that controls flow tuples from targeting one socket.
type udpReuseRegistry struct {
	key    [16]byte
	groups map[udpKey][]*UDPConn
}

// ListenTCPReusePort creates a passive TCP endpoint that may share its
// address and port with other ListenTCPReusePort listeners. Incoming flows
// are assigned consistently from their local and remote tuples.
func (s *Stack) ListenTCPReusePort(ctx context.Context, network string, local netip.AddrPort) (*TCPListener, error) {
	return s.listenTCP(ctx, network, local, reuseTCPListenerBinding{})
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
func (reuseTCPListenerBinding) register(state *tcpPassiveState, listener *TCPListener) error {
	registry, ok := state.reuse.(*tcpReuseRegistry)
	if !ok {
		registry = &tcpReuseRegistry{groups: make(map[tcpListenKey][]*TCPListener)}
		if _, err := rand.Read(registry.key[:]); err != nil {
			return err
		}
		state.reuse = registry
	}
	registry.add(listener)
	return nil
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

// reuseUDPSocketBinding permits a port to be shared only with other
// REUSEPORT packet sockets.
type reuseUDPSocketBinding struct{}

// ListenUDPReusePort creates an unconnected UDP packet socket that may share
// its address and port with other ListenUDPReusePort sockets. Incoming flows
// are assigned consistently from their local and remote tuples.
func (s *Stack) ListenUDPReusePort(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error) {
	return s.listenUDP(ctx, network, local, reuseUDPSocketBinding{})
}

// available accepts overlap with existing REUSEPORT sockets. The shared
// listen core separately rejects every overlapping ordinary UDP socket.
func (reuseUDPSocketBinding) available(stack *Stack, address netip.Addr, port uint16, dual bool) bool {
	if registry, ok := stack.udpReuse.(*udpReuseRegistry); ok {
		group := registry.groups[udpKey{address: address, port: port}]
		return len(group) == 0 || group[0].dual == dual
	}
	return true
}

// register adds one UDP socket to its REUSEPORT group.
func (reuseUDPSocketBinding) register(stack *Stack, connection *UDPConn) error {
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

// empty reports whether no UDP REUSEPORT groups remain.
func (registry *udpReuseRegistry) empty() bool { return len(registry.groups) == 0 }

// connections returns all UDP REUSEPORT sockets while Stack.mu is held.
func (registry *udpReuseRegistry) connections() []*UDPConn {
	var connections []*UDPConn
	for _, group := range registry.groups {
		connections = append(connections, group...)
	}
	return connections
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
	return group[reuseFlowIndex(registry.key, local, remote, len(group))]
}

// add appends one UDP socket to its group.
func (registry *udpReuseRegistry) add(connection *UDPConn) {
	key := udpKey{address: connection.local, port: connection.port}
	registry.groups[key] = append(registry.groups[key], connection)
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
		group[index] = group[last]
		group[last] = nil
		if last == 0 {
			delete(registry.groups, key)
		} else {
			registry.groups[key] = group[:last]
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
