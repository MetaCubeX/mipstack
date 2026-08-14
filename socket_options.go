package mipstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// SocketOption is one strongly typed socket policy. Concrete option types are
// private; use SocketOptions to construct values understood by this package.
type SocketOption interface {
	apply(socketOptionSet, socketOptionUse) (socketOptionSet, error)
}

// socketOptionsNamespace groups socket-option constructors without adding one
// exported package identifier per option. Its numeric value has no meaning.
type socketOptionsNamespace uint8

// SocketOptions constructs socket options accepted by ListenConfig and Dialer.
const SocketOptions socketOptionsNamespace = 0

// socketOptionState records whether a boolean option is absent or explicitly
// disabled or enabled.
type socketOptionState uint8

const (
	// socketOptionStateUnset restores the operation-specific default.
	socketOptionStateUnset socketOptionState = iota
	// socketOptionStateDisabled explicitly disables an option.
	socketOptionStateDisabled
	// socketOptionStateEnabled explicitly enables an option.
	socketOptionStateEnabled
)

// newSocketOptionState converts an explicit boolean option value to its
// internal state.
func newSocketOptionState(enabled bool) socketOptionState {
	if enabled {
		return socketOptionStateEnabled
	}
	return socketOptionStateDisabled
}

// resolve returns the explicit value or defaultValue for an unset state.
func (state socketOptionState) resolve(defaultValue bool) (bool, error) {
	switch state {
	case socketOptionStateUnset:
		return defaultValue, nil
	case socketOptionStateDisabled:
		return false, nil
	case socketOptionStateEnabled:
		return true, nil
	default:
		return false, syscall.EINVAL
	}
}

// reuseAddressSocketOption stores one SO_REUSEADDR policy.
type reuseAddressSocketOption socketOptionState

// reusePortSocketOption stores one SO_REUSEPORT policy.
type reusePortSocketOption socketOptionState

// ipHeaderIncludedOnWriteSocketOption stores one IP_HDRINCL/IPV6_HDRINCL
// write policy.
type ipHeaderIncludedOnWriteSocketOption socketOptionState

// ipHeaderIncludedOnReadSocketOption stores one complete-packet read policy.
type ipHeaderIncludedOnReadSocketOption socketOptionState

// ReuseAddress controls Linux SO_REUSEADDR-style address reuse during bind.
// TCP listeners enable it by default, matching Go's standard listener setup;
// an explicit false value disables that behavior. UDP listeners default to an
// exclusive binding and require every overlapping endpoint to opt in.
func (socketOptionsNamespace) ReuseAddress(enabled bool) SocketOption {
	return reuseAddressSocketOption(newSocketOptionState(enabled))
}

// UnsetReuseAddress restores the operation-specific SO_REUSEADDR default,
// overriding earlier ReuseAddress options in the same list.
func (socketOptionsNamespace) UnsetReuseAddress() SocketOption {
	return reuseAddressSocketOption(socketOptionStateUnset)
}

// apply validates and applies one SO_REUSEADDR policy.
func (option reuseAddressSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	if use != socketOptionTCPListen && use != socketOptionUDPListen {
		return set, syscall.ENOPROTOOPT
	}
	resolved, err := socketOptionState(option).resolve(use == socketOptionTCPListen)
	if err != nil {
		return set, err
	}
	set.reuseAddress = resolved
	return set, nil
}

// ReusePort controls Linux SO_REUSEPORT-style flow distribution for TCP and
// UDP listeners. Every endpoint in an overlapping group must enable it.
func (socketOptionsNamespace) ReusePort(enabled bool) SocketOption {
	return reusePortSocketOption(newSocketOptionState(enabled))
}

// UnsetReusePort restores the default disabled SO_REUSEPORT policy,
// overriding earlier ReusePort options in the same list.
func (socketOptionsNamespace) UnsetReusePort() SocketOption {
	return reusePortSocketOption(socketOptionStateUnset)
}

// apply validates and applies one SO_REUSEPORT policy.
func (option reusePortSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	if use != socketOptionTCPListen && use != socketOptionUDPListen {
		return set, syscall.ENOPROTOOPT
	}
	resolved, err := socketOptionState(option).resolve(false)
	if err != nil {
		return set, err
	}
	set.reusePort = resolved
	return set, nil
}

// IPHeaderIncludedOnWrite controls whether IPConn writes contain a complete
// IPv4 or IPv6 packet instead of a protocol payload. It corresponds to
// IP_HDRINCL and IPV6_HDRINCL. Use IPConn.SetIPHeaderIncludedOnWrite to change
// the representation of an existing socket.
func (socketOptionsNamespace) IPHeaderIncludedOnWrite(enabled bool) SocketOption {
	return ipHeaderIncludedOnWriteSocketOption(newSocketOptionState(enabled))
}

// UnsetIPHeaderIncludedOnWrite restores protocol-payload writes, overriding
// earlier IPHeaderIncludedOnWrite options in the same list.
func (socketOptionsNamespace) UnsetIPHeaderIncludedOnWrite() SocketOption {
	return ipHeaderIncludedOnWriteSocketOption(socketOptionStateUnset)
}

// apply validates and applies one complete-packet write policy.
func (option ipHeaderIncludedOnWriteSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	resolved, err := socketOptionState(option).resolve(false)
	if err != nil {
		return set, err
	}
	set.ipHeaderIncludedOnWrite = resolved
	return set, nil
}

// IPHeaderIncludedOnRead controls whether IPConn reads return the complete,
// reassembled IP packet instead of only its protocol payload. It is a
// creation-time option because changing the interpretation of queued messages
// would make concurrent reads ambiguous.
func (socketOptionsNamespace) IPHeaderIncludedOnRead(enabled bool) SocketOption {
	return ipHeaderIncludedOnReadSocketOption(newSocketOptionState(enabled))
}

// UnsetIPHeaderIncludedOnRead restores protocol-payload reads, overriding
// earlier IPHeaderIncludedOnRead options in the same list.
func (socketOptionsNamespace) UnsetIPHeaderIncludedOnRead() SocketOption {
	return ipHeaderIncludedOnReadSocketOption(socketOptionStateUnset)
}

// apply validates and applies one complete-packet read policy.
func (option ipHeaderIncludedOnReadSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	resolved, err := socketOptionState(option).resolve(false)
	if err != nil {
		return set, err
	}
	set.ipHeaderIncludedOnRead = resolved
	return set, nil
}

// socketOptionSet is the validated creation-time option snapshot.
type socketOptionSet struct {
	reuseAddress            bool
	reusePort               bool
	ipHeaderIncludedOnWrite bool
	ipHeaderIncludedOnRead  bool
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

// ListenTCP binds a TCP listener on stack.
func (config *ListenConfig) ListenTCP(ctx context.Context, stack *Stack, network string, local netip.AddrPort) (*TCPListener, error) {
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
	return stack.listenTCP(ctx, network, local, binding)
}

// ListenUDP binds an unconnected UDP packet socket on stack.
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
	return stack.listenUDP(ctx, network, local, binding)
}

// ListenIP binds an unconnected IP protocol socket on stack.
func (config *ListenConfig) ListenIP(ctx context.Context, stack *Stack, network string, local netip.Addr) (*IPConn, error) {
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
	_, err := parseSocketOptions(dialerOptions(dialer), socketOptionTCPDial)
	if err != nil {
		return nil, socketOperationError("dial", network, net.TCPAddrFromAddrPort(source), net.TCPAddrFromAddrPort(remote), err)
	}
	return stack.DialTCP(ctx, network, source, remote)
}

// DialUDP creates a connected UDP socket through stack.
func (dialer *Dialer) DialUDP(ctx context.Context, stack *Stack, network string, source, remote netip.AddrPort) (net.Conn, error) {
	if stack == nil {
		return nil, socketOperationError("dial", network, net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(remote), errors.New("mipstack: nil Stack"))
	}
	_, err := parseSocketOptions(dialerOptions(dialer), socketOptionUDPDial)
	if err != nil {
		return nil, socketOperationError("dial", network, net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(remote), err)
	}
	return stack.DialUDP(ctx, network, source, remote)
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
