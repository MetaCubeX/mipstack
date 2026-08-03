package mipstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

var _ func(*Stack, context.Context, string, netip.AddrPort, netip.AddrPort) (net.Conn, error) = (*Stack).DialTCP
var _ func(*Stack, context.Context, string, netip.AddrPort, netip.AddrPort) (net.Conn, error) = (*Stack).DialUDP
var _ func(*Stack, context.Context, string, netip.Addr, netip.Addr) (net.Conn, error) = (*Stack).DialIP
var _ func(*Stack, context.Context, string, netip.AddrPort) (*TCPListener, error) = (*Stack).ListenTCP
var _ func(*Stack, context.Context, string, netip.AddrPort) (net.PacketConn, error) = (*Stack).ListenUDP
var _ func(*Stack, context.Context, string, netip.AddrPort) (*TCPListener, error) = (*Stack).ListenTCPReusePort
var _ func(*Stack, context.Context, string, netip.AddrPort) (net.PacketConn, error) = (*Stack).ListenUDPReusePort

func TestListenValidationPrecedesLifecycle(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if _, err = stack.ListenTCP(context.Background(), "udp", netip.AddrPort{}); err == nil {
		t.Fatal("ListenTCP accepted an invalid network before Start")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("invalid network error = %v, want net.UnknownNetworkError", err)
		}
	}
	if _, err = stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv6Unspecified(), 0)); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("mismatched listen family error = %v, want EAFNOSUPPORT", err)
	}
	if _, err = stack.ListenTCP(context.Background(), "tcp", netip.AddrPort{}); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("valid listen before Start error = %v, want ErrNotStarted", err)
	}
}

func TestListenNetworkWildcardNormalization(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.10")
	local6 := netip.MustParseAddr("2001:db8::10")
	remote4 := netip.MustParseAddr("198.51.100.10")
	remote6 := netip.MustParseAddr("2001:db8:1::10")
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
	state := stack.network.Load()
	for _, test := range []struct {
		name    string
		network string
		address netip.Addr
		want    netip.Addr
		dual    bool
	}{
		{name: "generic empty", network: "tcp", want: netip.IPv6Unspecified(), dual: true},
		{name: "generic IPv4 unspecified", network: "tcp", address: netip.IPv4Unspecified(), want: netip.IPv6Unspecified(), dual: true},
		{name: "generic IPv6 unspecified", network: "tcp", address: netip.IPv6Unspecified(), want: netip.IPv6Unspecified(), dual: true},
		{name: "IPv4 empty", network: "tcp4", want: netip.IPv4Unspecified()},
		{name: "IPv6 empty", network: "tcp6", want: netip.IPv6Unspecified()},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, dual, listenErr := listenAddress(state, test.network, "tcp", test.address)
			if listenErr != nil || address != test.want || dual != test.dual {
				t.Fatalf("listenAddress(%q, %v) = %v, %v, %v; want %v, %v, nil", test.network, test.address, address, dual, listenErr, test.want, test.dual)
			}
		})
	}

	tcpListener, err := stack.ListenTCP(context.Background(), "tcp", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	tcpLocal := tcpListener.Addr().(*net.TCPAddr).AddrPort()
	if !tcpLocal.Addr().Is6() || !tcpLocal.Addr().IsUnspecified() || !tcpListener.dual {
		t.Fatalf("generic TCP wildcard = %v, dual = %v", tcpLocal, tcpListener.dual)
	}
	stack.mu.RLock()
	passive := stack.tcpPassive.(*tcpPassiveState)
	lookup4 := passive.listener(netip.AddrPortFrom(local4, tcpLocal.Port()), netip.AddrPort{})
	lookup6 := passive.listener(netip.AddrPortFrom(local6, tcpLocal.Port()), netip.AddrPort{})
	stack.mu.RUnlock()
	if lookup4 != tcpListener || lookup6 != tcpListener {
		t.Fatalf("dual TCP lookup = %p/%p, want %p", lookup4, lookup6, tcpListener)
	}

	udpConnection, err := stack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(netip.Addr{}, 46000))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	udpLocal := udpConnection.LocalAddr().(*net.UDPAddr).AddrPort()
	if udpLocal != netip.AddrPortFrom(netip.IPv6Unspecified(), 46000) || !udpConnection.(*UDPConn).dual {
		t.Fatalf("generic UDP wildcard = %v, dual = %v", udpLocal, udpConnection.(*UDPConn).dual)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote4, local4, 50000, 46000, []byte("v4"))); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote6, local6, 50001, 46000, []byte("v6"))); err != nil {
		t.Fatal(err)
	}
	if err = udpConnection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	for _, expected := range []string{"v4", "v6"} {
		n, _, readErr := udpConnection.ReadFrom(buffer)
		if readErr != nil || string(buffer[:n]) != expected {
			t.Fatalf("dual UDP read = %q, %v, want %q", buffer[:n], readErr, expected)
		}
	}

	tcp6, err := stack.ListenTCP(context.Background(), "tcp6", netip.AddrPortFrom(netip.Addr{}, 46001))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp6.Close()
	if tcp6.dual || tcp6.Addr().(*net.TCPAddr).AddrPort() != netip.AddrPortFrom(netip.IPv6Unspecified(), 46001) {
		t.Fatalf("tcp6 wildcard = %v, dual = %v", tcp6.Addr(), tcp6.dual)
	}
	udp4, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.Addr{}, 46002))
	if err != nil {
		t.Fatal(err)
	}
	defer udp4.Close()
	if got := udp4.LocalAddr().(*net.UDPAddr).AddrPort(); got != netip.AddrPortFrom(netip.IPv4Unspecified(), 46002) {
		t.Fatalf("udp4 empty-address wildcard = %v", got)
	}
	udp6, err := stack.ListenUDP(context.Background(), "udp6", netip.AddrPortFrom(netip.Addr{}, 46003))
	if err != nil {
		t.Fatal(err)
	}
	defer udp6.Close()
	if got := udp6.LocalAddr().(*net.UDPAddr).AddrPort(); got != netip.AddrPortFrom(netip.IPv6Unspecified(), 46003) {
		t.Fatalf("udp6 empty-address wildcard = %v", got)
	}
	if _, err = stack.ListenUDP(context.Background(), "tcp", netip.AddrPort{}); err == nil {
		t.Fatal("ListenUDP accepted a TCP network")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("unknown listen network error = %v", err)
		}
	}
}

// TestDialCrossFamilyUnspecifiedSource follows the net.Dialer distinction:
// generic networks treat either unspecified family as automatic source
// selection, while family-specific networks reject the mismatch.
func TestDialCrossFamilyUnspecifiedSource(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("198.51.100.11"))
	defer stack.Close()
	link.echoTCP = true
	source := netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	remoteTCP := netip.AddrPortFrom(link.remote, 8080)
	connection, err := stack.DialTCP(context.Background(), "tcp", source, remoteTCP)
	if err != nil {
		t.Fatalf("generic DialTCP: %v", err)
	}
	connection.Close()
	if _, err = stack.DialTCP(context.Background(), "tcp4", source, remoteTCP); err == nil {
		t.Fatal("tcp4 accepted an IPv6 unspecified source")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) {
			t.Fatalf("tcp4 source-family error = %T %v", err, err)
		}
	}
	remoteUDP := netip.AddrPortFrom(link.remote, 5353)
	udpConnection, err := stack.DialUDP(context.Background(), "udp", source, remoteUDP)
	if err != nil {
		t.Fatalf("generic DialUDP: %v", err)
	}
	udpConnection.Close()
	if _, err = stack.DialUDP(context.Background(), "udp4", source, remoteUDP); err == nil {
		t.Fatal("udp4 accepted an IPv6 unspecified source")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) {
			t.Fatalf("udp4 source-family error = %T %v", err, err)
		}
	}
	ipConnection, err := stack.DialIP(context.Background(), "ip:99", netip.IPv6Unspecified(), link.remote)
	if err != nil {
		t.Fatalf("generic DialIP: %v", err)
	}
	ipConnection.Close()
	if _, err = stack.DialIP(context.Background(), "ip4:99", netip.IPv6Unspecified(), link.remote); err == nil {
		t.Fatal("ip4 accepted an IPv6 unspecified source")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) {
			t.Fatalf("ip4 source-family error = %T %v", err, err)
		}
	}
}

// TestFullLoopbackQueueDoesNotBlock verifies the bounded overload path used
// to avoid a sole loopback consumer waiting on its own full queue.
func TestFullLoopbackQueueDoesNotBlock(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.12")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	for len(stack.loopback) < cap(stack.loopback) {
		stack.loopback <- []byte{0}
	}
	packet := buildIPPacket(local, local, protocolUDP, make([]byte, udpHeaderSize), 1, false)
	if err = stack.writePacket(packet); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("writePacket to full loopback queue = %v, want ErrResourceLimit", err)
	}
	if err = stack.writePacketUntil(packet, func() (time.Time, <-chan struct{}, bool) {
		return time.Time{}, make(chan struct{}), false
	}); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("writePacketUntil to full loopback queue = %v, want ErrResourceLimit", err)
	}
}

// TestSocketReadDeadlineErrors verifies that TCP and UDP expose net.OpError
// while preserving the standard deadline sentinel through errors.Is.
func TestSocketReadDeadlineErrors(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	tcpConnection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConnection.Close()
	if err = tcpConnection.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = tcpConnection.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("TCP Read error = %v, want os.ErrDeadlineExceeded", err)
	} else {
		checkNetOpError(t, err, "read", "tcp")
	}
	udpConnection, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(link.remote))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	if err = udpConnection.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = udpConnection.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("UDP ReadFrom error = %v, want os.ErrDeadlineExceeded", err)
	} else {
		checkNetOpError(t, err, "read", "udp")
	}
}

func TestAutomaticPortRangeFallback(t *testing.T) {
	cursor := automaticPortCursor{}
	port, err := allocateAutomaticPort(&cursor, func(uint16) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if port != dynamicPortFirst {
		t.Fatalf("first automatic port = %d, want IANA dynamic port %d", port, dynamicPortFirst)
	}

	cursor = automaticPortCursor{}
	port, err = allocateAutomaticPort(&cursor, func(port uint16) bool {
		return port < dynamicPortFirst
	})
	if err != nil {
		t.Fatal(err)
	}
	if port != fallbackPortFirst {
		t.Fatalf("fallback automatic port = %d, want %d", port, fallbackPortFirst)
	}
	if port < 1024 {
		t.Fatalf("automatic allocation selected privileged port %d", port)
	}

	probes := 0
	if _, err = allocateAutomaticPort(&cursor, func(uint16) bool {
		probes++
		return false
	}); !errors.Is(err, ErrNoPorts) {
		t.Fatalf("exhausted automatic range = %v, want ErrNoPorts", err)
	}
	if want := dynamicPortCount + fallbackPortCount; probes != want {
		t.Fatalf("automatic allocation probed %d ports, want %d", probes, want)
	}
}
