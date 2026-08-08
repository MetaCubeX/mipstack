package mipstack

import (
	"context"
	"encoding/binary"
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
		writeErr := stack.writePacketUntil(packet, func() (time.Time, <-chan struct{}, bool) {
			firstOnce.Do(func() { close(firstStarted) })
			return time.Time{}, firstChanged, false
		})
		firstDone <- writeErr
	}()
	<-firstStarted

	deadline := time.Now().Add(25 * time.Millisecond)
	secondChanged := make(chan struct{})
	startedAt := time.Now()
	err = stack.writePacketUntil(packet, func() (time.Time, <-chan struct{}, bool) {
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

func TestMonotonicStampRoundTripAndClamping(t *testing.T) {
	epoch := time.Unix(100, 123)
	value := epoch.Add(250*time.Millisecond + 456*time.Nanosecond)
	stamp := monotonicStampAt(epoch, value)
	if got := stamp.time(epoch); got != value {
		t.Fatalf("monotonic timestamp round trip = %v, want %v", got, value)
	}
	if got := monotonicStampAt(epoch, epoch.Add(-time.Nanosecond)).time(epoch); got != epoch {
		t.Fatalf("pre-epoch timestamp = %v, want %v", got, epoch)
	}
	if got := monotonicStampAt(epoch, time.Time{}); got != 0 {
		t.Fatalf("zero timestamp encoding = %d, want 0", got)
	}
	if got := monotonicStamp(0).time(epoch); !got.IsZero() {
		t.Fatalf("zero timestamp decoding = %v, want zero time", got)
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
	queue, loopback := stack.outputQueue(packet)
	if loopback {
		t.Fatal("remote packet selected the loopback queue")
	}
	slot, reserved := queue.tryReserve()
	if !reserved {
		t.Fatal("packet queue slot was not available")
	}
	ticket := queue.enqueueReserved(slot, packet, false)
	stack.recordOutput(false)
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
	firstSlot, reserved := queue.tryReserve()
	if !reserved {
		t.Fatal("first queue slot was not available")
	}
	first := queue.enqueueReserved(firstSlot, []byte{1}, false)
	if !first.pending() {
		t.Fatal("first queue ticket was not pending")
	}
	entry := <-queue.packets
	queue.release(entry)
	if first.pending() {
		t.Fatal("consumed queue ticket remained pending")
	}
	secondSlot, reserved := queue.tryReserve()
	if !reserved {
		t.Fatal("reused queue slot was not available")
	}
	second := queue.enqueueReserved(secondSlot, []byte{2}, false)
	if !second.pending() {
		t.Fatal("reused queue slot was not pending")
	}
	if first.pending() || first.generation == second.generation {
		t.Fatalf("slot reuse revived generation %d as %d", first.generation, second.generation)
	}
	entry = <-queue.packets
	queue.release(entry)
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
	if stack.outbound.len() != 0 || len(stack.outbound.free) != cap(stack.outbound.free) {
		t.Fatalf("queue did not release every slot: packets=%d free=%d", stack.outbound.len(), len(stack.outbound.free))
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

func TestListenAddressesOverlap(t *testing.T) {
	any4 := netip.IPv4Unspecified()
	any6 := netip.IPv6Unspecified()
	first4 := netip.MustParseAddr("192.0.2.1")
	second4 := netip.MustParseAddr("192.0.2.2")
	first6 := netip.MustParseAddr("2001:db8::1")
	second6 := netip.MustParseAddr("2001:db8::2")
	for _, test := range []struct {
		name                string
		left, right         netip.Addr
		leftDual, rightDual bool
		want                bool
	}{
		{name: "same IPv4", left: first4, right: first4, want: true},
		{name: "different IPv4", left: first4, right: second4},
		{name: "IPv4 wildcard", left: any4, right: first4, want: true},
		{name: "IPv4 wildcard and IPv6", left: any4, right: first6},
		{name: "same IPv6", left: first6, right: first6, want: true},
		{name: "different IPv6", left: first6, right: second6},
		{name: "IPv6 wildcard", left: any6, right: first6, want: true},
		{name: "IPv6-only wildcard and IPv4", left: any6, right: first4},
		{name: "dual wildcard and IPv4", left: any6, leftDual: true, right: first4, want: true},
		{name: "dual wildcard and IPv6", left: any6, leftDual: true, right: first6, want: true},
		{name: "dual and IPv4 wildcards", left: any6, leftDual: true, right: any4, want: true},
		{name: "two dual wildcards", left: any6, leftDual: true, right: any6, rightDual: true, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if overlap := listenAddressesOverlap(test.left, test.leftDual, test.right, test.rightDual); overlap != test.want {
				t.Fatalf("listenAddressesOverlap = %t, want %t", overlap, test.want)
			}
			if overlap := listenAddressesOverlap(test.right, test.rightDual, test.left, test.leftDual); overlap != test.want {
				t.Fatalf("reversed listenAddressesOverlap = %t, want %t", overlap, test.want)
			}
		})
	}
}

func TestRecentDestinationCacheEvictionAndExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	cache := make(recentDestinationCache[int])
	cache.remember(0, now.Add(-time.Second))
	for destination := 1; destination < recentDestinationMaximum; destination++ {
		cache.remember(destination, now)
	}
	cache.remember(recentDestinationMaximum, now)
	if len(cache) != recentDestinationMaximum || cache.contains(0, now) || !cache.contains(recentDestinationMaximum, now) {
		t.Fatalf("oldest-entry eviction = size %d oldest %t newest %t", len(cache), cache.contains(0, now), cache.contains(recentDestinationMaximum, now))
	}
	cache[1] = now.Add(-recentDestinationLifetime)
	cache.remember(recentDestinationMaximum+1, now)
	if len(cache) != recentDestinationMaximum || cache.contains(1, now) || !cache.contains(recentDestinationMaximum+1, now) {
		t.Fatalf("expired-entry eviction = size %d expired %t newest %t", len(cache), cache.contains(1, now), cache.contains(recentDestinationMaximum+1, now))
	}
	cache.remember(2, now.Add(time.Second))
	if updated := cache[2]; updated != now.Add(time.Second) || len(cache) != recentDestinationMaximum {
		t.Fatalf("existing-entry update = %v, size %d", updated, len(cache))
	}
	cache[3] = now.Add(-recentDestinationLifetime)
	if cache.contains(3, now) {
		t.Fatal("expired destination remained present")
	}
	if _, exists := cache[3]; exists {
		t.Fatal("contains retained expired destination")
	}
}

func testOutputUDPPacket(source, target netip.Addr, sourcePort, targetPort uint16, size int) []byte {
	if size < udpHeaderSize {
		size = udpHeaderSize
	}
	payload := make([]byte, size)
	binary.BigEndian.PutUint16(payload[0:2], sourcePort)
	binary.BigEndian.PutUint16(payload[2:4], targetPort)
	return buildIPPacket(source, target, protocolUDP, payload, 0, true)
}

func enqueueTestOutputPacket(t *testing.T, queue *packetQueue, packet []byte) {
	t.Helper()
	slot, ok := queue.tryReserve()
	if !ok {
		t.Fatal("output queue has no free slot")
	}
	queue.enqueueReservedPacket(slot, packet, false)
}

func TestFairPacketQueueRotatesAfterInitialByteCredit(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.1")
	first := testOutputUDPPacket(source, target, 10000, 53, 80)
	second := testOutputUDPPacket(source, target, 10001, 53, 80)
	queue := newFairPacketQueueAt(16, time.Now(), len(first), [16]byte{1})
	for index := 0; index < 12; index++ {
		enqueueTestOutputPacket(t, &queue, first)
	}
	enqueueTestOutputPacket(t, &queue, second)
	for index := 0; index < 10; index++ {
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("packet %d was not schedulable", index)
		}
		if got := binary.BigEndian.Uint16(entry.packet[20:22]); got != 10000 {
			t.Fatalf("packet %d source port = %d, want first flow", index, got)
		}
		queue.release(entry)
	}
	entry, ok := queue.tryDequeue()
	if !ok {
		t.Fatal("second flow was not scheduled after the initial quantum")
	}
	if got := binary.BigEndian.Uint16(entry.packet[20:22]); got != 10001 {
		t.Fatalf("packet after initial quantum source port = %d, want second flow", got)
	}
	queue.release(entry)
}

func TestFairPacketQueueUsesByteCredit(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.2")
	target := netip.MustParseAddr("198.51.100.2")
	large := testOutputUDPPacket(source, target, 11000, 53, 1400)
	small := testOutputUDPPacket(source, target, 11001, 53, 200)
	queue := newFairPacketQueueAt(128, time.Now(), 1500, [16]byte{2})
	for index := 0; index < 64; index++ {
		enqueueTestOutputPacket(t, &queue, large)
		enqueueTestOutputPacket(t, &queue, small)
	}
	bytesByPort := map[uint16]int{}
	// Both flows receive the same initial 10-MTU byte allowance. The small
	// flow needs more packets to consume it, so compare after that allowance
	// rather than after an equal packet count.
	for index := 0; index < 75; index++ {
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("packet %d was not schedulable", index)
		}
		bytesByPort[binary.BigEndian.Uint16(entry.packet[20:22])] += len(entry.packet)
		queue.release(entry)
	}
	difference := bytesByPort[11000] - bytesByPort[11001]
	if difference < 0 {
		difference = -difference
	}
	if difference > 2*1500 {
		t.Fatalf("byte-fair service differs by %d bytes: %v", difference, bytesByPort)
	}
}

func TestOutputPacketFlowHashSeparatesTransportTuples(t *testing.T) {
	secret := [16]byte{3}
	for _, addresses := range [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("198.51.100.3")},
		{netip.MustParseAddr("2001:db8::3"), netip.MustParseAddr("2001:db8:1::3")},
	} {
		first := testOutputUDPPacket(addresses[0], addresses[1], 12000, 53, 64)
		second := testOutputUDPPacket(addresses[0], addresses[1], 12001, 53, 64)
		if firstHash, secondHash := outputPacketFlowHash(secret, first), outputPacketFlowHash(secret, second); firstHash == secondHash {
			t.Fatalf("%s flow hashes collide: %x", addresses[0], firstHash)
		}
		if got, want := outputPacketFlowHash(secret, first), outputPacketFlowHash(secret, append([]byte(nil), first...)); got != want {
			t.Fatalf("%s stable flow hash = %x, want %x", addresses[0], got, want)
		}
		longer := testOutputUDPPacket(addresses[0], addresses[1], 12000, 53, 1400)
		if got, want := outputPacketFlowHash(secret, longer), outputPacketFlowHash(secret, first); got != want {
			t.Fatalf("%s differently sized packets hash to %x and %x", addresses[0], got, want)
		}
	}
}

func TestOutputPacketFlowHashKeepsIPv6FragmentsTogether(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::4")
	target := netip.MustParseAddr("2001:db8:1::4")
	secret := [16]byte{4}
	fragments := buildIPv6FragmentsWithOptions(source, target, protocolUDP, make([]byte, 3000), 1280, 0x12345678, ipPacketOptions{})
	if len(fragments) < 2 {
		t.Fatal("test datagram was not fragmented")
	}
	want := outputPacketFlowHash(secret, fragments[0])
	for index, fragment := range fragments[1:] {
		if got := outputPacketFlowHash(secret, fragment); got != want {
			t.Fatalf("fragment %d hash = %x, want %x", index+1, got, want)
		}
	}
	other := buildIPv6FragmentsWithOptions(source, target, protocolUDP, make([]byte, 3000), 1280, 0x12345679, ipPacketOptions{})
	if got := outputPacketFlowHash(secret, other[0]); got == want {
		t.Fatalf("different fragment identifications share hash %x", got)
	}
}

func TestOutputPacketFlowHashKeepsICMPEchoSequenceTogether(t *testing.T) {
	secret := [16]byte{5}
	for _, addresses := range [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("198.51.100.5")},
		{netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("2001:db8:1::5")},
	} {
		protocol, echoType := protocolICMPv4, byte(8)
		if addresses[0].Is6() {
			protocol, echoType = protocolICMPv6, 128
		}
		makeEcho := func(identifier, sequence uint16) []byte {
			message := make([]byte, 12)
			message[0] = echoType
			binary.BigEndian.PutUint16(message[4:6], identifier)
			binary.BigEndian.PutUint16(message[6:8], sequence)
			if protocol == protocolICMPv4 {
				binary.BigEndian.PutUint16(message[2:4], checksum(message))
			} else {
				binary.BigEndian.PutUint16(message[2:4], transportChecksum(addresses[0], addresses[1], protocol, message))
			}
			return buildIPPacketWithOptions(addresses[0], addresses[1], protocol, message, 0, true, ipPacketOptions{hopLimit: 64})
		}
		first := makeEcho(0x1234, 1)
		second := makeEcho(0x1234, 2)
		if got, want := outputPacketFlowHash(secret, second), outputPacketFlowHash(secret, first); got != want {
			t.Fatalf("%s echo sequences hash to %x and %x", addresses[0], want, got)
		}
		other := makeEcho(0x1235, 1)
		if got, want := outputPacketFlowHash(secret, other), outputPacketFlowHash(secret, first); got == want {
			t.Fatalf("%s echo identifiers share hash %x", addresses[0], got)
		}
	}
}

func TestFairPacketQueueReusesBoundedFlowStorage(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.4")
	target := netip.MustParseAddr("198.51.100.4")
	queue := newFairPacketQueueAt(4, time.Now(), 1500, [16]byte{4})
	for round := 0; round < 128; round++ {
		packet := testOutputUDPPacket(source, target, uint16(13000+round), 53, 64)
		enqueueTestOutputPacket(t, &queue, packet)
		entry, ok := queue.tryDequeue()
		if !ok {
			t.Fatalf("round %d packet was not schedulable", round)
		}
		queue.release(entry)
	}
	if got := len(queue.scheduler.store); got != 4 {
		t.Fatalf("flow storage grew to %d, want 4", got)
	}
	if got := len(queue.scheduler.flows); got > 4 {
		t.Fatalf("retained flow map grew to %d, want <= 4", got)
	}
}

func TestFairPacketQueueWakesConcurrentSinglePacketReaders(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.6")
	target := netip.MustParseAddr("198.51.100.6")
	queue := newFairPacketQueueAt(4, time.Now(), 1500, [16]byte{6})
	packet := testOutputUDPPacket(source, target, 15000, 53, 64)
	closed := make(chan struct{})
	started := make(chan struct{}, 2)
	results := make(chan bool, 2)
	for index := 0; index < 2; index++ {
		go func() {
			started <- struct{}{}
			entry, ok := queue.dequeue(closed)
			if ok {
				queue.release(entry)
			}
			results <- ok
		}()
	}
	<-started
	<-started
	time.Sleep(10 * time.Millisecond)
	for index := 0; index < 2; index++ {
		enqueueTestOutputPacket(t, &queue, packet)
	}
	for index := 0; index < 2; index++ {
		select {
		case ok := <-results:
			if !ok {
				t.Fatalf("single-packet reader %d was closed", index)
			}
		case <-time.After(time.Second):
			close(closed)
			t.Fatalf("single-packet reader %d was not woken", index)
		}
	}
}

func BenchmarkPacketQueueScheduling(b *testing.B) {
	source := netip.MustParseAddr("192.0.2.5")
	target := netip.MustParseAddr("198.51.100.5")
	packet := testOutputUDPPacket(source, target, 14000, 443, 1400)
	const capacity = 256
	for _, benchmark := range []struct {
		name  string
		fair  bool
		flows int
	}{
		{name: "fifo", flows: 1},
		{name: "drr-single", fair: true, flows: 1},
		{name: "drr-64", fair: true, flows: 64},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			queue := newPacketQueue(capacity)
			if benchmark.fair {
				queue = newFairPacketQueueAt(capacity, time.Now(), 1500, [16]byte{5})
			}
			flowIDs := make([]uint64, benchmark.flows)
			for index := range flowIDs {
				flowIDs[index] = uint64(index + 1)
			}
			b.SetBytes(int64(capacity * len(packet)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				for index := 0; index < capacity; index++ {
					slot, ok := queue.tryReserve()
					if !ok {
						b.Fatal("output queue unexpectedly full")
					}
					queue.enqueueReservedTCP(slot, packet, false, flowIDs[index%len(flowIDs)])
				}
				for index := 0; index < capacity; index++ {
					entry, ok := queue.tryDequeue()
					if !ok {
						b.Fatal("output queue unexpectedly empty")
					}
					queue.release(entry)
				}
			}
		})
	}
}
