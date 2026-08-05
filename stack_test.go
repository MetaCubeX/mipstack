package mipstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
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

func TestPacketQueueWaitDoesNotSerializeWriteDeadlines(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	packet := buildIPPacket(local, remote, 99, []byte{1}, 0, true)
	for index := 0; index < outboundPacketQueue; index++ {
		if err = stack.writePacket(packet); err != nil {
			t.Fatalf("fill packet %d: %v", index, err)
		}

	}
	firstStarted := make(chan struct{})
	firstDone := make(chan error, 1)
	firstChanged := make(chan struct{})
	var firstOnce sync.Once
	go func() {
		_, writeErr := stack.writePacketUntilTicket(packet, func() (time.Time, <-chan struct{}, bool) {
			firstOnce.Do(func() { close(firstStarted) })
			return time.Time{}, firstChanged, false
		})
		firstDone <- writeErr
	}()
	<-firstStarted

	deadline := time.Now().Add(25 * time.Millisecond)
	secondChanged := make(chan struct{})
	startedAt := time.Now()
	_, err = stack.writePacketUntilTicket(packet, func() (time.Time, <-chan struct{}, bool) {
		return deadline, secondChanged, false
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("second queue write = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("second queue deadline was delayed by first writer: %v", elapsed)
	}

	buffer := make([]byte, 1500)
	if _, err = stack.Read([][]byte{buffer}, make([]int, 1), 0); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-firstDone:
		if err != nil {
			t.Fatalf("first queue write = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first queue write did not resume after dequeue")
	}
}

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
	fillTestPacketQueue(t, &stack.loopback, []byte{0})
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

func TestPacketQueueTicketTracksDeviceDequeue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.13")
	remote := netip.MustParseAddr("192.0.2.14")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	packet := buildIPPacket(local, remote, protocolUDP, make([]byte, udpHeaderSize), 1, false)
	ticket, err := stack.writePacketUntilTicket(packet, func() (time.Time, <-chan struct{}, bool) {
		return time.Time{}, nil, false
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ticket.pending() {
		t.Fatal("new packet queue ticket is not pending")
	}
	buffer := make([]byte, 1500)
	if count, readErr := stack.Read([][]byte{buffer}, []int{0}, 0); readErr != nil || count != 1 {
		t.Fatalf("device Read = %d, %v", count, readErr)
	}
	if ticket.pending() {
		t.Fatal("packet queue ticket remained pending after device Read")
	}
}

func TestPacketQueueTicketGenerationSurvivesSlotReuse(t *testing.T) {
	queue := newPacketQueue(1)
	first, queued := queue.tryEnqueue([]byte{1})
	if !queued || !first.pending() {
		t.Fatal("first queue ticket was not pending")
	}
	entry := <-queue.packets
	queue.consume(entry)
	if first.pending() {
		t.Fatal("consumed queue ticket remained pending")
	}
	second, queued := queue.tryEnqueue([]byte{2})
	if !queued || !second.pending() {
		t.Fatal("reused queue slot was not pending")
	}
	if first.pending() || first.generation == second.generation {
		t.Fatalf("slot reuse revived generation %d as %d", first.generation, second.generation)
	}
	entry = <-queue.packets
	queue.consume(entry)
	if second.pending() {
		t.Fatal("second queue ticket remained pending")
	}
}

func TestPacketQueueConcurrentWritersMakeBoundedProgress(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.15")
	remote := netip.MustParseAddr("192.0.2.16")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	packet := buildIPPacket(local, remote, protocolUDP, make([]byte, udpHeaderSize), 1, false)
	const writers = 1024
	errorsCh := make(chan error, writers)
	start := make(chan struct{})
	for index := 0; index < writers; index++ {
		go func() {
			<-start
			errorsCh <- stack.writePacket(packet)
		}()
	}
	close(start)
	buffer := make([]byte, 1500)
	for received := 0; received < writers; {
		count, readErr := stack.Read([][]byte{buffer}, []int{0}, 0)
		if readErr != nil {
			t.Fatal(readErr)
		}
		received += count
	}
	for index := 0; index < writers; index++ {
		if writeErr := <-errorsCh; writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if len(stack.outbound.packets) != 0 || len(stack.outbound.free) != cap(stack.outbound.free) {
		t.Fatalf("queue did not release every slot: packets=%d free=%d", len(stack.outbound.packets), len(stack.outbound.free))
	}
}

func TestDatagramQueueRetainsOnlySmallBacking(t *testing.T) {
	var queue datagramQueue[int]
	for value := 0; value < datagramQueueRetain; value++ {
		queue.push(value)
	}
	for value := 0; value < datagramQueueRetain; value++ {
		got, ok := queue.pop()
		if !ok || got != value {
			t.Fatalf("small queue pop = %d, %v, want %d, true", got, ok, value)
		}
	}
	if queue.len() != 0 || cap(queue.values) == 0 || cap(queue.values) > datagramQueueRetain {
		t.Fatalf("small drained queue = len %d cap %d", queue.len(), cap(queue.values))
	}
	for value := 0; value < datagramQueueRetain+1; value++ {
		queue.push(value)
	}
	for value := 0; value < datagramQueueRetain+1; value++ {
		got, ok := queue.pop()
		if !ok || got != value {
			t.Fatalf("large queue pop = %d, %v, want %d, true", got, ok, value)
		}
	}
	if queue.values != nil || queue.head != 0 {
		t.Fatalf("large drained queue retained len %d cap %d head %d", len(queue.values), cap(queue.values), queue.head)
	}
}

func TestDeadlineTimerCacheIsConcurrentAndBounded(t *testing.T) {
	var cache deadlineTimerCache
	timers := make([]*time.Timer, 2*deadlineTimerCacheLimit)
	for index := range timers {
		timer, _ := cache.timer(time.Now().Add(time.Hour))
		timers[index] = timer
	}
	var wait sync.WaitGroup
	wait.Add(len(timers))
	for _, timer := range timers {
		go func(timer *time.Timer) {
			defer wait.Done()
			cache.release(timer, false)
		}(timer)
	}
	wait.Wait()
	cache.mu.Lock()
	cached := len(cache.timers)
	cache.mu.Unlock()
	if cached != deadlineTimerCacheLimit {
		t.Fatalf("cached deadline timers = %d, want %d", cached, deadlineTimerCacheLimit)
	}
}

func TestDeadlineTimerCacheResetHasNoStaleTick(t *testing.T) {
	var cache deadlineTimerCache
	for _, consume := range []bool{false, true} {
		timer, timeout := cache.timer(time.Now().Add(time.Millisecond))
		if consume {
			<-timeout
		} else {
			time.Sleep(10 * time.Millisecond)
		}
		cache.release(timer, consume)

		reused, next := cache.timer(time.Now().Add(time.Hour))
		if reused != timer {
			t.Fatal("deadline timer cache did not reuse the released timer")
		}
		select {
		case <-next:
			t.Fatalf("deadline timer cache exposed a stale tick after consumed=%v", consume)
		default:
		}
		cache.release(reused, false)
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

func TestAutomaticPortCursorUsesKeyedFullPeriodSteps(t *testing.T) {
	first := automaticPortCursor{secret: [16]byte{1}}
	second := automaticPortCursor{secret: [16]byte{2}}
	firstPort, err := allocateAutomaticPort(&first, func(uint16) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	secondPort, err := allocateAutomaticPort(&second, func(uint16) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if firstPort != dynamicPortFirst || secondPort != dynamicPortFirst {
		t.Fatalf("initial automatic ports = %d, %d", firstPort, secondPort)
	}
	if first.dynamic == 1 || second.dynamic == 1 {
		t.Fatal("automatic port cursor retained a sequential increment")
	}
	if first.dynamic == second.dynamic {
		t.Fatal("automatic port cursors with different keys selected the same increment")
	}

	seen := make(map[uint16]struct{}, dynamicPortCount)
	cursor := automaticPortCursor{secret: [16]byte{3}}
	offsets := [2]uint32{12345, 6789}
	for index := uint32(0); index < dynamicPortCount; index++ {
		port, allocateErr := allocateAutomaticPortWithOffsets(&cursor, offsets, func(uint16) bool { return true })
		if allocateErr != nil {
			t.Fatal(allocateErr)
		}
		if _, exists := seen[port]; exists {
			t.Fatalf("automatic port %d repeated after %d allocations", port, index)
		}
		seen[port] = struct{}{}
	}
}

func TestAutomaticTCPPortOffsetsSeparateDestinations(t *testing.T) {
	secret := [16]byte{4}
	local := netip.MustParseAddr("192.0.2.1")
	first := automaticTCPPortOffsets(secret, local, netip.MustParseAddrPort("198.51.100.1:443"))
	second := automaticTCPPortOffsets(secret, local, netip.MustParseAddrPort("198.51.100.2:443"))
	if first == second {
		t.Fatal("different TCP destinations received the same automatic-port offsets")
	}
}
