package mipstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestTCPReusePortFlowSelectionAndRebind(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.31")
	serverAddress := netip.MustParseAddr("192.0.2.32")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, client, server)
	local := netip.AddrPortFrom(serverAddress, 47000)
	first, err := server.ListenTCPReusePort(context.Background(), "tcp4", local)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := server.ListenTCPReusePort(context.Background(), "tcp4", local)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = server.ListenTCP(context.Background(), "tcp4", local); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ordinary listener over REUSEPORT group error = %v, want EADDRINUSE", err)
	}

	server.mu.RLock()
	state := server.tcpPassive.(*tcpPassiveState)
	registry := state.reuse.(*tcpReuseRegistry)
	ports := make(map[*TCPListener]uint16)
	for port := uint16(40000); port < 41000 && len(ports) != 2; port++ {
		remote := netip.AddrPortFrom(clientAddress, port)
		ports[registry.listener(local, local, remote)] = port
	}
	server.mu.RUnlock()
	if len(ports) != 2 {
		t.Fatal("could not find stable flows for both TCP REUSEPORT listeners")
	}

	var clients []net.Conn
	var accepted []*TCPConn
	for listener, port := range ports {
		connection, dialErr := client.DialTCP(context.Background(), "tcp4", netip.AddrPortFrom(clientAddress, port), local)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		clients = append(clients, connection)
		if deadlineErr := listener.SetDeadline(time.Now().Add(time.Second)); deadlineErr != nil {
			t.Fatal(deadlineErr)
		}
		serverConnection, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		accepted = append(accepted, serverConnection)
		if serverConnection.RemoteAddr().(*net.TCPAddr).AddrPort().Port() != port {
			t.Fatalf("REUSEPORT listener accepted source %v, want port %d", serverConnection.RemoteAddr(), port)
		}
	}
	defer func() {
		for _, connection := range clients {
			_ = connection.Close()
		}
		for _, connection := range accepted {
			_ = connection.Close()
		}
	}()

	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = server.ListenTCP(context.Background(), "tcp4", local); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("bind while one REUSEPORT listener remains = %v, want EADDRINUSE", err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	rebound, err := server.ListenTCP(context.Background(), "tcp4", local)
	if err != nil {
		t.Fatalf("rebind with accepted connections still active: %v", err)
	}
	_ = rebound.Close()
}

func TestUDPReusePortFlowSelectionAndPrecedence(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.41")
	remote := netip.MustParseAddr("198.51.100.41")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	binding := netip.AddrPortFrom(netip.IPv4Unspecified(), 47001)
	firstPacket, err := stack.ListenUDPReusePort(context.Background(), "udp4", binding)
	if err != nil {
		t.Fatal(err)
	}
	first := firstPacket.(*UDPConn)
	defer first.Close()
	secondPacket, err := stack.ListenUDPReusePort(context.Background(), "udp4", binding)
	if err != nil {
		t.Fatal(err)
	}
	second := secondPacket.(*UDPConn)
	defer second.Close()
	if _, err = stack.ListenUDP(context.Background(), "udp4", binding); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ordinary UDP bind over REUSEPORT group error = %v, want EADDRINUSE", err)
	}

	actualLocal := netip.AddrPortFrom(local, binding.Port())
	stack.mu.RLock()
	registry := stack.udpReuse.(*udpReuseRegistry)
	ports := make(map[*UDPConn]uint16)
	for port := uint16(41000); port < 42000 && len(ports) != 2; port++ {
		peer := netip.AddrPortFrom(remote, port)
		ports[registry.connection(binding, actualLocal, peer)] = port
	}
	stack.mu.RUnlock()
	if len(ports) != 2 {
		t.Fatal("could not find stable flows for both UDP REUSEPORT sockets")
	}
	for connection, port := range ports {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, port, binding.Port(), []byte{byte(port)})); err != nil {
			t.Fatal(err)
		}
		if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		n, source, readErr := connection.ReadFrom(buffer)
		if readErr != nil || n != 1 || source.(*net.UDPAddr).Port != int(port) {
			t.Fatalf("UDP REUSEPORT read = %d byte from %v, %v, want port %d", n, source, readErr, port)
		}
	}

	exactPacket, err := stack.ListenUDPReusePort(context.Background(), "udp4", netip.AddrPortFrom(local, binding.Port()))
	if err != nil {
		t.Fatal(err)
	}
	exact := exactPacket.(*UDPConn)
	defer exact.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 43000, binding.Port(), []byte("exact"))); err != nil {
		t.Fatal(err)
	}
	if err = exact.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	n, _, err := exact.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "exact" {
		t.Fatalf("exact REUSEPORT binding precedence = %q, %v", buffer[:n], err)
	}
}

func TestReusePortRejectsMixedDualStackGroups(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.71")
	local6 := netip.MustParseAddr("2001:db8::71")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32), netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	wildcard := netip.AddrPortFrom(netip.IPv6Unspecified(), 47003)
	tcp, err := stack.ListenTCPReusePort(context.Background(), "tcp", wildcard)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if _, err = stack.ListenTCPReusePort(context.Background(), "tcp6", wildcard); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("mixed dual/IPv6-only TCP group error = %v, want EADDRINUSE", err)
	}
	udp, err := stack.ListenUDPReusePort(context.Background(), "udp", netip.AddrPortFrom(netip.IPv6Unspecified(), 47004))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if _, err = stack.ListenUDPReusePort(context.Background(), "udp6", netip.AddrPortFrom(netip.IPv6Unspecified(), 47004)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("mixed dual/IPv6-only UDP group error = %v, want EADDRINUSE", err)
	}
}

// TestReusePortConfigInvalidationClosesGroups verifies that UpdateConfig
// enumerates and closes every member bound to a removed local address.
func TestReusePortConfigInvalidationClosesGroups(t *testing.T) {
	removed := netip.MustParseAddr("192.0.2.81")
	retained := netip.MustParseAddr("192.0.2.82")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(removed, 32), netip.PrefixFrom(retained, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	tcpLocal := netip.AddrPortFrom(removed, 47005)
	tcpFirst, err := stack.ListenTCPReusePort(context.Background(), "tcp4", tcpLocal)
	if err != nil {
		t.Fatal(err)
	}
	tcpSecond, err := stack.ListenTCPReusePort(context.Background(), "tcp4", tcpLocal)
	if err != nil {
		t.Fatal(err)
	}
	udpLocal := netip.AddrPortFrom(removed, 47006)
	udpFirstPacket, err := stack.ListenUDPReusePort(context.Background(), "udp4", udpLocal)
	if err != nil {
		t.Fatal(err)
	}
	udpSecondPacket, err := stack.ListenUDPReusePort(context.Background(), "udp4", udpLocal)
	if err != nil {
		t.Fatal(err)
	}
	udpFirst, udpSecond := udpFirstPacket.(*UDPConn), udpSecondPacket.(*UDPConn)
	if stats := stack.Stats(); stats.ActiveTCPListeners != 2 || stats.ActiveUDPSockets != 2 {
		t.Fatalf("active REUSEPORT endpoints before update = %+v", stats)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(retained, 32)}}); err != nil {
		t.Fatal(err)
	}
	for index, listener := range []*TCPListener{tcpFirst, tcpSecond} {
		if !listener.Info().Closed {
			t.Fatalf("TCP REUSEPORT listener %d remained open", index)
		}
		if _, acceptErr := listener.Accept(); !errors.Is(acceptErr, net.ErrClosed) {
			t.Fatalf("TCP REUSEPORT listener %d Accept = %v, want net.ErrClosed", index, acceptErr)
		}
	}
	for index, connection := range []*UDPConn{udpFirst, udpSecond} {
		if !connection.Info().Closed {
			t.Fatalf("UDP REUSEPORT socket %d remained open", index)
		}
		if _, _, readErr := connection.ReadFrom(make([]byte, 1)); !errors.Is(readErr, net.ErrClosed) {
			t.Fatalf("UDP REUSEPORT socket %d ReadFrom = %v, want net.ErrClosed", index, readErr)
		}
	}
	if stats := stack.Stats(); stats.ActiveTCPListeners != 0 || stats.ActiveUDPSockets != 0 {
		t.Fatalf("active REUSEPORT endpoints after update = %+v", stats)
	}
	stack.mu.RLock()
	defer stack.mu.RUnlock()
	if stack.tcpPassive != nil || stack.udpReuse != nil {
		t.Fatalf("empty REUSEPORT registries retained: tcp=%T udp=%T", stack.tcpPassive, stack.udpReuse)
	}
}
