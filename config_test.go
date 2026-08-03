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

func TestMTUAndRouteFamilyValidation(t *testing.T) {
	ipv4 := netip.MustParsePrefix("192.0.2.15/32")
	if _, err := New(Config{LocalAddresses: []netip.Prefix{ipv4}, MTU: 68}); err != nil {
		t.Fatalf("minimum IPv4 MTU was rejected: %v", err)
	}
	if _, err := New(Config{LocalAddresses: []netip.Prefix{ipv4}, MTU: 67}); err == nil {
		t.Fatal("IPv4 MTU below 68 was accepted")
	}
	if _, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::15/128")}, MTU: 1279}); err == nil {
		t.Fatal("IPv6 MTU below 1280 was accepted")
	}
	if _, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.255/24")}}); err == nil {
		t.Fatal("IPv4 subnet broadcast address was accepted as local")
	}
	if _, err := New(Config{
		LocalAddresses: []netip.Prefix{ipv4},
		Routes:         []Route{{Destination: netip.MustParsePrefix("2001:db8::/32")}},
	}); err == nil {
		t.Fatal("route without a same-family local address was accepted")
	}
	withoutRoutes, err := New(Config{LocalAddresses: []netip.Prefix{ipv4}, Routes: []Route{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = withoutRoutes.RouteFor(netip.MustParseAddr("198.51.100.1")); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("explicit empty route table = %v, want ENETUNREACH", err)
	}
}

func TestTCPConnectionLimitConfiguration(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.12")
	if _, err := New(Config{
		LocalAddresses:    []netip.Prefix{netip.PrefixFrom(local, 32)},
		MaxTCPConnections: -1,
	}); err == nil {
		t.Fatal("negative MaxTCPConnections was accepted")
	}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	stack.mu.Lock()
	for index := 0; index < 16385; index++ {
		key := tcpKey{
			local:  netip.AddrPortFrom(local, uint16(1024+index)),
			remote: netip.AddrPortFrom(netip.MustParseAddr("198.51.100.12"), uint16(index+1)),
		}
		stack.tcp[key] = nil
	}
	available := stack.tcpConnectionAvailableLocked()
	stack.mu.Unlock()
	if !available {
		t.Fatal("zero MaxTCPConnections imposed an implicit limit")
	}
}

func TestCongestionControlConfiguration(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.13/32")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}})
	if err != nil {
		t.Fatal(err)
	}
	if got := stack.network.Load().congestionControl; got != CongestionControlCUBIC {
		t.Fatalf("default congestion control = %q, want %q", got, CongestionControlCUBIC)
	}
	for _, algorithm := range []CongestionControl{CongestionControlCUBIC, CongestionControlReno, CongestionControlBBR} {
		if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{local}, CongestionControl: algorithm}); err != nil {
			t.Fatalf("UpdateConfig(%q): %v", algorithm, err)
		}
		if got := stack.network.Load().congestionControl; got != algorithm {
			t.Fatalf("configured congestion control = %q, want %q", got, algorithm)
		}
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{local}, CongestionControl: "invalid"}); err == nil {
		t.Fatal("invalid congestion control was accepted")
	}
}

func TestExpiredPathMTURemainsActionable(t *testing.T) {
	local := netip.MustParsePrefix("192.0.2.14/32")
	remote := netip.MustParseAddr("198.51.100.14")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{local}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	stack.pathMTU[remote] = pathMTUEntry{mtu: 1000, updated: time.Now().Add(-pathMTULifetime - time.Second)}
	if expiry, exists := stack.pathMTUExpiry(remote); !exists || !expiry.Before(time.Now()) {
		t.Fatalf("expired PMTU expiry = %v, %v", expiry, exists)
	}
	if mtu := stack.mtuFor(remote); mtu != 1500 {
		t.Fatalf("MTU after expiry = %d, want 1500", mtu)
	}
	if _, exists := stack.pathMTU[remote]; exists {
		t.Fatal("expired PMTU cache entry was not removed")
	}
}

func TestRoutesAndRFC6724SourceSelection(t *testing.T) {
	ula := netip.MustParseAddr("fd00::10")
	global := netip.MustParseAddr("2001:db8::10")
	ipv4 := netip.MustParseAddr("192.0.2.30")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{
			netip.PrefixFrom(global, 128),
			netip.PrefixFrom(ula, 128),
			netip.PrefixFrom(ipv4, 32),
		},
		Routes: []Route{
			{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Metric: 20},
			{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Source: global, Metric: 10},
			{Destination: netip.MustParsePrefix("fd00::/8")},
			{Destination: netip.MustParsePrefix("198.51.100.0/24"), Source: ipv4},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	route, err := stack.RouteFor(netip.MustParseAddr("2001:db8:1::99"))
	if err != nil {
		t.Fatal(err)
	}
	if route.Metric != 10 || route.Source != global {
		t.Fatalf("selected route = %+v", route)
	}
	if _, err = stack.RouteFor(netip.MustParseAddr("203.0.113.1")); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("route miss = %v, want ENETUNREACH", err)
	}
	if source, err := stack.sourceFor(netip.MustParseAddr("fd12::1")); err != nil || source != ula {
		t.Fatalf("ULA source = %v, %v, want %v", source, err, ula)
	}
	if source, err := stack.sourceFor(netip.MustParseAddr("2001:db8:1::99")); err != nil || source != global {
		t.Fatalf("global source = %v, %v, want %v", source, err, global)
	}
	if source, err := stack.sourceFor(netip.MustParseAddr("198.51.100.99")); err != nil || source != ipv4 {
		t.Fatalf("route-pinned IPv4 source = %v, %v, want %v", source, err, ipv4)
	}
}

func TestRFC6724AddressLabels(t *testing.T) {
	for _, test := range []struct {
		address string
		label   uint8
	}{
		{address: "192.0.2.1", label: 4},
		{address: "::1", label: 0},
		{address: "2002::1", label: 2},
		{address: "2001::1", label: 5},
		{address: "fd00::1", label: 13},
		{address: "fec0::1", label: 11},
		{address: "3ffe::1", label: 12},
		{address: "::192.0.2.1", label: 3},
		{address: "2001:db8::1", label: 1},
	} {
		if label := addressLabel(netip.MustParseAddr(test.address)); label != test.label {
			t.Errorf("addressLabel(%s) = %d, want %d", test.address, label, test.label)
		}
	}
}

func TestUpdateConfigClosesInvalidBindings(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.40")
	ipv6 := netip.MustParseAddr("2001:db8::40")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(ipv4, 32),
		netip.PrefixFrom(ipv6, 128),
	}, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	tcpListener, err := stack.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(ipv4, 0))
	if err != nil {
		t.Fatal(err)
	}
	wildcardUDP, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	if !stack.observePathMTU(netip.MustParseAddr("2001:db8::99"), 1280) {
		t.Fatal("failed to install test PMTU")
	}
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(ipv6, 128)},
		MTU:            1400,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err = tcpListener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("removed TCP binding Accept = %v, want net.ErrClosed", err)
	}
	if _, _, err = wildcardUDP.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("removed UDP family ReadFrom = %v, want net.ErrClosed", err)
	}
	if _, err = stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0)); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("ListenUDP for removed family = %v, want EADDRNOTAVAIL", err)
	}
	if _, err = stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0)); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("ListenTCP for removed family = %v, want EADDRNOTAVAIL", err)
	}
	if got := stack.mtuFor(netip.MustParseAddr("2001:db8::99")); got != 1400 {
		t.Fatalf("MTU after UpdateConfig = %d, want 1400", got)
	}
	if _, err = stack.RouteFor(netip.MustParseAddr("198.51.100.1")); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("removed IPv4 route = %v, want ENETUNREACH", err)
	}
}
