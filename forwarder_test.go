package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// newForwarderTestStack constructs and starts one stack with an optional
// promiscuous admission policy.
func newForwarderTestStack(t *testing.T, local netip.Addr, promiscuous bool) *Stack {
	t.Helper()
	bits := 32
	if local.Is6() {
		bits = 128
	}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}, Promiscuous: promiscuous, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	return stack
}

// readForwarderTestPacket consumes one packet directly from the outbound
// device queue.
func readForwarderTestPacket(t *testing.T, stack *Stack) []byte {
	t.Helper()
	select {
	case entry := <-stack.outbound.packets:
		return consumeTestPacket(&stack.outbound, entry)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwarded response")
		return nil
	}
}

func TestForwarderRegistrationAndCloseLifecycle(t *testing.T) {
	type control interface {
		Close() error
		Done() <-chan struct{}
		Info() ForwarderInfo
	}
	constructors := []struct {
		name string
		new  func(*Stack) (control, error)
	}{
		{name: "TCP", new: func(stack *Stack) (control, error) {
			return NewTCPForwarder(stack, TCPForwarderOptions{}, func(*TCPForwarderRequest) {})
		}},
		{name: "UDP", new: func(stack *Stack) (control, error) {
			return NewUDPForwarder(stack, UDPForwarderOptions{}, func(*UDPForwarderRequest) {})
		}},
		{name: "ICMP", new: func(stack *Stack) (control, error) {
			return NewICMPForwarder(stack, ICMPForwarderOptions{}, func(*ICMPForwarderRequest) {})
		}},
	}
	for _, constructor := range constructors {
		t.Run(constructor.name, func(t *testing.T) {
			if _, err := constructor.new(nil); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("constructor with nil stack = %v", err)
			}
			local := netip.MustParseAddr("192.0.2.9")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				t.Fatal(err)
			}
			first, err := constructor.new(stack)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = constructor.new(stack); !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatalf("duplicate constructor = %v", err)
			}
			if err = first.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-first.Done():
			default:
				t.Fatal("Done remained open after Close")
			}
			if info := first.Info(); !info.Closed || info.Pending != 0 {
				t.Fatalf("closed forwarder info = %+v", info)
			}
			if err = first.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("repeated Close = %v", err)
			}
			replacement, err := constructor.new(stack)
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			stackResult, forwarderResult := make(chan error, 1), make(chan error, 1)
			go func() {
				<-start
				stackResult <- stack.Close()
			}()
			go func() {
				<-start
				forwarderResult <- replacement.Close()
			}()
			close(start)
			if err = <-stackResult; err != nil {
				t.Fatalf("concurrent Stack.Close = %v", err)
			}
			if err = <-forwarderResult; err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("concurrent Forwarder.Close = %v", err)
			}
			select {
			case <-replacement.Done():
			default:
				t.Fatal("replacement Done remained open after concurrent Close")
			}
			if _, err = constructor.new(stack); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("constructor on closed stack = %v", err)
			}
		})
	}
	if _, err := NewTCPForwarder(&Stack{}, TCPForwarderOptions{}, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("TCP constructor with nil handler = %v", err)
	}
	if _, err := NewUDPForwarder(&Stack{}, UDPForwarderOptions{}, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("UDP constructor with nil handler = %v", err)
	}
	if _, err := NewICMPForwarder(&Stack{}, ICMPForwarderOptions{}, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("ICMP constructor with nil handler = %v", err)
	}
}

func TestTCPForwarderInterceptsNonlocalDestination(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.10")
	serverAddress := netip.MustParseAddr("192.0.2.20")
	intercepted := netip.MustParseAddr("198.51.100.80")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)

	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(50 * time.Millisecond))

	type acceptResult struct {
		connection *TCPConn
		err        error
	}
	accepted := make(chan acceptResult, 1)
	forwarder, err := NewTCPForwarder(server, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		flow := request.Flow()
		if flow.Source.Addr() != clientAddress || flow.Destination != netip.AddrPortFrom(intercepted, 8080) {
			t.Errorf("TCP forwarder flow = %+v", flow)
		}
		connection, acceptErr := request.Accept(context.Background())
		accepted <- acceptResult{connection: connection, err: acceptErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()

	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(intercepted, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	serverConnection := result.connection
	defer serverConnection.Close()
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if got := serverConnection.LocalAddr().(*net.TCPAddr).AddrPort(); got != netip.AddrPortFrom(intercepted, 8080) {
		t.Fatalf("forwarded TCP local address = %v", got)
	}
	if _, err = listener.AcceptTCP(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ordinary wildcard listener accepted nonlocal flow: %v", err)
	}
	localClient, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer localClient.Close()
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	localServer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer localServer.Close()
	if got := localServer.LocalAddr().(*net.TCPAddr).AddrPort().Addr(); got != serverAddress {
		t.Fatalf("ordinary listener local address = %v", got)
	}

	_ = clientConnection.SetDeadline(time.Now().Add(time.Second))
	_ = serverConnection.SetDeadline(time.Now().Add(time.Second))
	if _, err = clientConnection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, err := serverConnection.Read(buffer)
	if err != nil || string(buffer[:n]) != "request" {
		t.Fatalf("forwarded TCP request = %q, %v", buffer[:n], err)
	}
	if _, err = serverConnection.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	n, err = clientConnection.Read(buffer)
	if err != nil || string(buffer[:n]) != "response" {
		t.Fatalf("forwarded TCP response = %q, %v", buffer[:n], err)
	}
	if info := forwarder.Info(); !info.Closed || info.Requests != 1 || info.Accepted != 1 || info.Pending != 0 {
		t.Fatalf("TCP forwarder info = %+v", info)
	}
	if err = server.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = serverConnection.Read(buffer); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("forwarded TCP survived promiscuous disable: %v", err)
	}
}

func TestTCPForwarderCoalescesPendingSYNs(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.30")
	remote := netip.MustParseAddr("192.0.2.31")
	target := netip.MustParseAddr("198.51.100.30")
	stack := newForwarderTestStack(t, owned, true)
	entered := make(chan struct{})
	result := make(chan error, 1)
	var calls atomic.Uint32
	forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{MaxInFlight: 1}, func(request *TCPForwarderRequest) {
		calls.Add(1)
		close(entered)
		<-request.Done()
		_, acceptErr := request.Accept(context.Background())
		result <- acceptErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	syn := buildTestTCP(remote, target, 42000, 443, 100, 0, tcpFlagSYN, 65535, nil, nil)
	var writers sync.WaitGroup
	for index := 0; index < 32; index++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			if writeErr := writeTestPacket(stack, syn); writeErr != nil {
				t.Error(writeErr)
			}
		}()
	}
	writers.Wait()
	<-entered
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestTCP(remote, target, 42001, 443, 200, 0, tcpFlagSYN, 65535, nil, nil)); err != nil {
		t.Fatal(err)
	}
	info := forwarder.Info()
	if calls.Load() != 1 || info.Requests != 1 || info.Dropped != 1 {
		t.Fatalf("duplicate SYN created %d handlers, info %+v", calls.Load(), info)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("invalidated TCP request Accept = %v", err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 2 {
		t.Fatalf("invalidated TCP forwarder info = %+v", info)
	}
}

func TestTCPForwarderCloseSignalsCompletedRequestHandler(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.34")
	remote := netip.MustParseAddr("192.0.2.35")
	target := netip.MustParseAddr("198.51.100.34")
	stack := newForwarderTestStack(t, local, true)
	actionComplete := make(chan struct{})
	handlerComplete := make(chan struct{})
	forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		if dropErr := request.Drop(); dropErr != nil {
			t.Errorf("Drop TCP request: %v", dropErr)
			return
		}
		close(actionComplete)
		<-request.Done()
		close(handlerComplete)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestTCP(remote, target, 50003, 443, 100, 0, tcpFlagSYN, 65535, nil, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-actionComplete:
	case <-time.After(time.Second):
		t.Fatal("TCP handler did not complete its action")
	}
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handlerComplete:
	case <-time.After(time.Second):
		t.Fatal("completed TCP request did not observe forwarder closure")
	}
}

func TestForwarderAcceptFailureAllowsRetry(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.37")
		remote := netip.MustParseAddr("192.0.2.38")
		target := netip.MustParseAddr("198.51.100.37")
		stack, err := New(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true,
			Routes: []Route{}, MTU: 1400,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stack.Close() })
		results := make(chan error, 2)
		var calls atomic.Uint32
		forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
			if calls.Add(1) == 1 {
				_, acceptErr := request.Accept(context.Background())
				results <- acceptErr
				return
			}
			results <- request.Drop()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildTestTCP(remote, target, 50004, 443, 100, 0, tcpFlagSYN, 65535, nil, nil)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if err = <-results; !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("first TCP Accept = %v", err)
		}
		if err = stack.UpdateConfig(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
		}); err != nil {
			t.Fatal(err)
		}
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if err = <-results; err != nil {
			t.Fatalf("retried TCP request: %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("TCP handler calls = %d, want 2", calls.Load())
		}
	})

	t.Run("UDP", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.39")
		remote := netip.MustParseAddr("192.0.2.40")
		target := netip.MustParseAddr("198.51.100.39")
		stack, err := New(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true,
			Routes: []Route{}, MTU: 1400,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stack.Close() })
		results := make(chan error, 2)
		var calls atomic.Uint32
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			connection, acceptErr := request.Accept()
			if connection != nil {
				_ = connection.Close()
			}
			calls.Add(1)
			results <- acceptErr
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildTestUDP(remote, target, 50005, 53, []byte("query"))
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if err = <-results; !errors.Is(err, syscall.ENETUNREACH) {
			t.Fatalf("first UDP Accept = %v", err)
		}
		if err = stack.UpdateConfig(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
		}); err != nil {
			t.Fatal(err)
		}
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		if err = <-results; err != nil {
			t.Fatalf("retried UDP Accept: %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("UDP handler calls = %d, want 2", calls.Load())
		}
	})
}

func TestPromiscuousAdmissionDoesNotImplySourceSpoofing(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.35")
	remote := netip.MustParseAddr("192.0.2.36")
	target := netip.MustParseAddr("198.51.100.35")
	stack := newForwarderTestStack(t, owned, true)
	packets := [][]byte{
		buildTestTCP(remote, target, 42500, 80, 1, 0, tcpFlagSYN, 65535, nil, nil),
		buildTestUDP(remote, target, 42501, 53, []byte("query")),
	}
	icmp := make([]byte, 8)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	packets = append(packets, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true))
	for _, packet := range packets {
		if err := writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case entry := <-stack.outbound.packets:
		response := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("bare promiscuous admission emitted response %x", response)
	case <-time.After(30 * time.Millisecond):
	}
	if got := stack.Stats().PromiscuousInboundPackets; got != uint64(len(packets)) {
		t.Fatalf("promiscuous packet count = %d", got)
	}
}

func TestForwardersHandleLocalTrafficWithoutPromiscuous(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.37")
	remote := netip.MustParseAddr("192.0.2.38")
	stack := newForwarderTestStack(t, local, false)
	tcpHandled, udpHandled, icmpHandled := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	_, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		tcpHandled <- struct{}{}
		_ = request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		udpHandled <- struct{}{}
		_ = request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		icmpHandled <- struct{}{}
		_ = request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestTCP(remote, local, 42600, 80, 1, 0, tcpFlagSYN, 65535, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 42601, 53, []byte("local"))); err != nil {
		t.Fatal(err)
	}
	icmp := make([]byte, 20)
	icmp[0] = 13
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, local, protocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	for name, handled := range map[string]<-chan struct{}{"TCP": tcpHandled, "UDP": udpHandled, "ICMP": icmpHandled} {
		select {
		case <-handled:
		case <-time.After(time.Second):
			t.Fatalf("local %s traffic did not reach forwarder", name)
		}
	}
	if got := stack.Stats().PromiscuousInboundPackets; got != 0 {
		t.Fatalf("local forwarder traffic counted as promiscuous = %d", got)
	}
}

func TestUDPForwarderUsesCompleteFlowTuple(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.40")
	firstRemote := netip.MustParseAddr("192.0.2.41")
	secondRemote := netip.MustParseAddr("192.0.2.42")
	target := netip.MustParseAddr("198.51.100.40")
	stack := newForwarderTestStack(t, owned, true)

	ordinary, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 5353))
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	connections := make(chan *UDPConn, 2)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		if flow := request.Flow(); flow.Destination != netip.AddrPortFrom(target, 5353) {
			t.Errorf("UDP forwarder flow = %+v", flow)
		}
		connection, acceptErr := request.Accept()
		if acceptErr != nil {
			t.Errorf("Accept UDP: %v", acceptErr)
			return
		}
		connections <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()

	firstPacket := buildTestUDP(firstRemote, target, 51001, 5353, []byte("first"))
	if err = writeTestPacket(stack, firstPacket); err != nil {
		t.Fatal(err)
	}
	first := <-connections
	defer first.Close()
	_ = first.SetDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	n, err := first.Read(buffer)
	if err != nil || string(buffer[:n]) != "first" {
		t.Fatalf("first forwarded UDP payload = %q, %v", buffer[:n], err)
	}
	if got := first.LocalAddr().(*net.UDPAddr).AddrPort(); got != netip.AddrPortFrom(target, 5353) {
		t.Fatalf("forwarded UDP local address = %v", got)
	}

	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51001, 5353, []byte("again"))); err != nil {
		t.Fatal(err)
	}
	n, err = first.Read(buffer)
	if err != nil || string(buffer[:n]) != "again" {
		t.Fatalf("existing forwarded UDP payload = %q, %v", buffer[:n], err)
	}
	if err = writeTestPacket(stack, buildTestUDP(secondRemote, target, 51001, 5353, []byte("second"))); err != nil {
		t.Fatal(err)
	}
	second := <-connections
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(time.Second))
	n, err = second.Read(buffer)
	if err != nil || string(buffer[:n]) != "second" {
		t.Fatalf("second forwarded UDP payload = %q, %v", buffer[:n], err)
	}
	if info := forwarder.Info(); info.Requests != 2 || info.Accepted != 2 {
		t.Fatalf("UDP forwarder info = %+v", info)
	}

	_ = ordinary.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err = ordinary.ReadFrom(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ordinary wildcard received nonlocal datagram: %v", err)
	}
	_ = ordinary.SetReadDeadline(time.Now().Add(time.Second))
	if err = writeTestPacket(stack, buildTestUDP(firstRemote, owned, 51002, 5353, []byte("ordinary"))); err != nil {
		t.Fatal(err)
	}
	n, _, err = ordinary.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "ordinary" {
		t.Fatalf("ordinary local UDP payload = %q, %v", buffer[:n], err)
	}
	if info := forwarder.Info(); info.Requests != 2 {
		t.Fatalf("local UDP reached forwarder: %+v", info)
	}
	if _, err = first.Write([]byte("reply")); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.source != target || parsed.target != firstRemote || parsed.protocol != protocolUDP {
		t.Fatalf("forwarded UDP response = %x", response)
	}
	if gotSource, gotTarget := binary.BigEndian.Uint16(parsed.payload[0:2]), binary.BigEndian.Uint16(parsed.payload[2:4]); gotSource != 5353 || gotTarget != 51001 {
		t.Fatalf("forwarded UDP response ports = %d -> %d", gotSource, gotTarget)
	}
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51001, 5353, []byte("after close"))); err != nil {
		t.Fatal(err)
	}
	n, err = first.Read(buffer)
	if err != nil || string(buffer[:n]) != "after close" {
		t.Fatalf("accepted UDP after forwarder close = %q, %v", buffer[:n], err)
	}
}

func TestUDPForwarderListenUnconnected(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.44")
	firstRemote := netip.MustParseAddr("192.0.2.45")
	secondRemote := netip.MustParseAddr("192.0.2.46")
	target := netip.MustParseAddr("198.51.100.44")
	stack := newForwarderTestStack(t, owned, true)

	connections := make(chan *UDPConn, 1)
	var handlerCalls atomic.Uint32
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		handlerCalls.Add(1)
		connection, listenErr := request.Listen()
		if listenErr != nil {
			t.Errorf("Listen forwarded UDP: %v", listenErr)
			return
		}
		connections <- connection
	})
	if err != nil {
		t.Fatal(err)
	}

	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51101, 5353, []byte("first"))); err != nil {
		t.Fatal(err)
	}
	connection := <-connections
	defer connection.Close()
	if connection.RemoteAddr() != nil {
		t.Fatalf("listened UDP remote address = %v, want nil", connection.RemoteAddr())
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 32)
	n, source, err := connection.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "first" || source != netip.AddrPortFrom(firstRemote, 51101) {
		t.Fatalf("first listened UDP datagram = %q from %v, %v", buffer[:n], source, err)
	}

	if err = writeTestPacket(stack, buildTestUDP(secondRemote, target, 51102, 5353, []byte("second"))); err != nil {
		t.Fatal(err)
	}
	n, source, err = connection.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "second" || source != netip.AddrPortFrom(secondRemote, 51102) {
		t.Fatalf("second listened UDP datagram = %q from %v, %v", buffer[:n], source, err)
	}
	if got := handlerCalls.Load(); got != 1 {
		t.Fatalf("UDP listener handler calls = %d, want 1", got)
	}
	if _, err = connection.Write([]byte("missing destination")); err == nil {
		t.Fatal("Write on unconnected forwarded UDP succeeded")
	}
	if _, err = connection.WriteToUDPAddrPort([]byte("reply"), netip.AddrPortFrom(secondRemote, 51102)); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.source != target || parsed.target != secondRemote || parsed.protocol != protocolUDP {
		t.Fatalf("listened UDP response = %x", response)
	}
	if gotSource, gotTarget := binary.BigEndian.Uint16(parsed.payload[0:2]), binary.BigEndian.Uint16(parsed.payload[2:4]); gotSource != 5353 || gotTarget != 51102 {
		t.Fatalf("listened UDP response ports = %d -> %d", gotSource, gotTarget)
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Accepted != 1 || info.Pending != 0 {
		t.Fatalf("UDP listener forwarder info = %+v", info)
	}
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51101, 5353, []byte("after close"))); err != nil {
		t.Fatal(err)
	}
	n, source, err = connection.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "after close" || source != netip.AddrPortFrom(firstRemote, 51101) {
		t.Fatalf("listened UDP after forwarder close = %q from %v, %v", buffer[:n], source, err)
	}
}

func TestUDPForwarderListenOwnsLocalBinding(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.47")
	remote := netip.MustParseAddr("192.0.2.48")
	stack := newForwarderTestStack(t, local, false)
	accepted := make(chan *UDPConn, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, listenErr := request.Listen()
		if listenErr != nil {
			t.Errorf("Listen local forwarded UDP: %v", listenErr)
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	localEndpoint := netip.AddrPortFrom(local, 5354)
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 51201, localEndpoint.Port(), []byte("local"))); err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	buffer := make([]byte, 16)
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if n, source, readErr := connection.ReadFromUDPAddrPort(buffer); readErr != nil || string(buffer[:n]) != "local" || source != netip.AddrPortFrom(remote, 51201) {
		t.Fatalf("local listened UDP = %q from %v, %v", buffer[:n], source, readErr)
	}
	if _, err = stack.ListenUDP(context.Background(), "udp4", localEndpoint); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("ordinary bind over forwarded UDP listener = %v, want EADDRINUSE", err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	ordinary, err := stack.ListenUDP(context.Background(), "udp4", localEndpoint)
	if err != nil {
		t.Fatalf("ordinary bind after forwarded listener close: %v", err)
	}
	_ = ordinary.Close()
}

func TestUDPForwarderListenConflictsWithAcceptedFlow(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.49")
	firstRemote := netip.MustParseAddr("192.0.2.60")
	secondRemote := netip.MustParseAddr("192.0.2.61")
	target := netip.MustParseAddr("198.51.100.49")
	stack := newForwarderTestStack(t, owned, true)
	accepted := make(chan *UDPConn, 1)
	listenResult := make(chan error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		if request.Flow().Source.Addr() == firstRemote {
			connection, acceptErr := request.Accept()
			if acceptErr == nil {
				accepted <- connection
			}
			return
		}
		_, listenErr := request.Listen()
		listenResult <- listenErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(firstRemote, target, 51301, 5355, []byte("flow"))); err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	defer connection.Close()
	if err = writeTestPacket(stack, buildTestUDP(secondRemote, target, 51302, 5355, []byte("listen"))); err != nil {
		t.Fatal(err)
	}
	if err = <-listenResult; !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Listen over accepted UDP flow = %v, want EADDRINUSE", err)
	}
	if info := forwarder.Info(); info.Requests != 2 || info.Accepted != 1 || info.Dropped != 1 || info.Pending != 0 {
		t.Fatalf("conflicting UDP listener forwarder info = %+v", info)
	}
}

func TestUDPForwarderEndpointSurvivesInitialQueueDrop(t *testing.T) {
	actions := []struct {
		name string
		run  func(*UDPForwarderRequest) (*UDPConn, error)
	}{
		{name: "Accept", run: func(request *UDPForwarderRequest) (*UDPConn, error) { return request.Accept() }},
		{name: "Listen", run: func(request *UDPForwarderRequest) (*UDPConn, error) { return request.Listen() }},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.58")
			remote := netip.MustParseAddr("192.0.2.59")
			stack, err := New(Config{
				LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
				UDP: DatagramSocketDefaults{ReceiveBuffer: udpDatagramMetadataSize},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			accepted := make(chan *UDPConn, 1)
			forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
				connection, actionErr := action.run(request)
				if actionErr != nil {
					t.Errorf("%s after initial queue drop: %v", action.name, actionErr)
					return
				}
				accepted <- connection
			})
			if err != nil {
				t.Fatal(err)
			}
			defer forwarder.Close()
			large := bytes.Repeat([]byte{0x5a}, 32)
			if err = writeTestPacket(stack, buildTestUDP(remote, local, 51400, 5356, large)); err != nil {
				t.Fatal(err)
			}
			connection := <-accepted
			defer connection.Close()
			if info := connection.Info(); info.PacketsDropped != 1 || info.ReceiveQueuePackets != 0 {
				t.Fatalf("%s initial queue drop info = %+v", action.name, info)
			}
			if err = writeTestPacket(stack, buildTestUDP(remote, local, 51400, 5356, nil)); err != nil {
				t.Fatal(err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			buffer := make([]byte, 1)
			n, source, readErr := connection.ReadFromUDPAddrPort(buffer)
			if readErr != nil || n != 0 || source != netip.AddrPortFrom(remote, 51400) {
				t.Fatalf("%s later datagram = %d bytes from %v, %v", action.name, n, source, readErr)
			}
			if info := forwarder.Info(); info.Requests != 1 || info.Accepted != 1 || info.Dropped != 0 || info.Pending != 0 {
				t.Fatalf("%s forwarder info after queue drop = %+v", action.name, info)
			}
		})
	}
}

func TestPromiscuousUpdateClosesForwardedUDPListener(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.62")
	remote := netip.MustParseAddr("192.0.2.63")
	target := netip.MustParseAddr("198.51.100.62")
	stack := newForwarderTestStack(t, owned, true)
	accepted := make(chan *UDPConn, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, listenErr := request.Listen()
		if listenErr != nil {
			t.Errorf("Listen forwarded UDP: %v", listenErr)
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 51401, 5356, []byte("open"))); err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	buffer := make([]byte, 8)
	if _, _, err = connection.ReadFrom(buffer); err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = connection.ReadFrom(buffer); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("forwarded UDP listener survived promiscuous disable: %v", err)
	}
}

func TestPromiscuousUpdateClosesForwardedUDP(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.50")
	remote := netip.MustParseAddr("192.0.2.51")
	target := netip.MustParseAddr("198.51.100.50")
	stack := newForwarderTestStack(t, owned, true)
	accepted := make(chan *UDPConn, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, acceptErr := request.Accept()
		if acceptErr != nil {
			t.Errorf("Accept UDP: %v", acceptErr)
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 52001, 52002, []byte("open"))); err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	buffer := make([]byte, 8)
	if _, err = connection.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Read(buffer); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("forwarded UDP survived promiscuous disable: %v", err)
	}
	if stack.Stats().PromiscuousInboundPackets == 0 {
		t.Fatal("promiscuous input was not counted")
	}
}

func TestUDPForwarderPendingConfigInvalidation(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.52")
	remote := netip.MustParseAddr("192.0.2.53")
	target := netip.MustParseAddr("198.51.100.52")
	stack := newForwarderTestStack(t, owned, true)
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		close(entered)
		<-release
		_, acceptErr := request.Accept()
		result <- acceptErr
	})
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeTestPacket(stack, buildTestUDP(remote, target, 52201, 52202, []byte("pending")))
	}()
	<-entered
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err = <-result; !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("invalidated UDP request Accept = %v", err)
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("invalidated UDP forwarder info = %+v", info)
	}
}

func TestUDPForwarderReceivesReassembledNonlocalDatagram(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.55")
	remote := netip.MustParseAddr("192.0.2.56")
	target := netip.MustParseAddr("198.51.100.55")
	stack := newForwarderTestStack(t, owned, true)
	accepted := make(chan *UDPConn, 1)
	_, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, acceptErr := request.Accept()
		if acceptErr != nil {
			t.Errorf("Accept fragmented UDP: %v", acceptErr)
			return
		}
		accepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1800)
	complete, ok := parseIPPacket(buildTestUDP(remote, target, 52501, 52502, payload))
	if !ok {
		t.Fatal("failed to parse complete UDP test packet")
	}
	fragments := buildIPv4Fragments(remote, target, protocolUDP, complete.payload, 600, 77)
	for _, fragment := range fragments {
		if err = writeTestPacket(stack, fragment); err != nil {
			t.Fatal(err)
		}
	}
	connection := <-accepted
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	received := make([]byte, len(payload))
	n, err := connection.Read(received)
	if err != nil || n != len(payload) || !bytes.Equal(received, payload) {
		t.Fatalf("reassembled forwarded UDP = %d bytes, %v", n, err)
	}
}

func TestICMPForwarderRepliesFromOriginalDestination(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.60")
	remote := netip.MustParseAddr("192.0.2.61")
	target := netip.MustParseAddr("198.51.100.60")
	stack := newForwarderTestStack(t, owned, true)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		message := request.Message()
		if message.Source != remote || message.Destination != target || message.Type != 8 || message.Code != 0 || !message.IsEchoRequest() {
			t.Errorf("ICMP forwarder message = %+v", message)
			_ = request.Drop()
			return
		}
		if replyErr := request.ReplyEcho(); replyErr != nil {
			t.Errorf("ReplyEcho ICMP: %v", replyErr)
		}
		if replyErr := request.ReplyEcho(); replyErr != nil {
			t.Errorf("second ReplyEcho ICMP: %v", replyErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 12)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
	binary.BigEndian.PutUint16(icmp[6:8], 0x5678)
	copy(icmp[8:], "ping")
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.source != target || parsed.target != remote || parsed.protocol != protocolICMPv4 || parsed.payload[0] != 0 || !bytes.Equal(parsed.payload[4:], icmp[4:]) || checksum(parsed.payload) != 0 {
		t.Fatalf("forwarded ICMP response = %x", response)
	}
	response = readForwarderTestPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.payload[0] != 0 || checksum(parsed.payload) != 0 {
		t.Fatalf("second forwarded ICMP response = %x", response)
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Replies != 2 {
		t.Fatalf("ICMP forwarder info = %+v", info)
	}
}

func TestICMPForwarderCloseInvalidatesRunningRequest(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.65")
	remote := netip.MustParseAddr("192.0.2.66")
	target := netip.MustParseAddr("198.51.100.65")
	stack := newForwarderTestStack(t, owned, true)
	entered, release := make(chan struct{}), make(chan struct{})
	actionResult := make(chan error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		close(entered)
		<-release
		actionResult <- request.Drop()
	})
	if err != nil {
		t.Fatal(err)
	}
	icmp := make([]byte, 8)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true))
	}()
	<-entered
	if err = forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); !info.Closed || info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("closed ICMP forwarder info = %+v", info)
	}
	close(release)
	if err = <-actionResult; !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("action after ICMP forwarder Close = %v", err)
	}
	if err = <-writeResult; err != nil {
		t.Fatal(err)
	}
}

func TestForwarderRequestReplyAndRejectActions(t *testing.T) {
	t.Run("TCP reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.70")
		remote := netip.MustParseAddr("192.0.2.71")
		target := netip.MustParseAddr("198.51.100.70")
		stack := newForwarderTestStack(t, owned, true)
		repeated := make(chan error, 1)
		forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
			if rejectErr := request.Reject(); rejectErr != nil {
				t.Errorf("Reject TCP: %v", rejectErr)
			}
			_, repeatedErr := request.Accept(context.Background())
			repeated <- repeatedErr
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		if err = writeTestPacket(stack, buildTestTCP(remote, target, 53001, 443, 99, 0, tcpFlagSYN, 65535, nil, nil)); err != nil {
			t.Fatal(err)
		}
		response := readForwarderTestPacket(t, stack)
		parsed, ok := parseIPPacket(response)
		if !ok || parsed.source != target || parsed.target != remote || parsed.payload[13] != tcpFlagRST|tcpFlagACK || binary.BigEndian.Uint32(parsed.payload[8:12]) != 100 {
			t.Fatalf("forwarded TCP rejection = %x", response)
		}
		if err = <-repeated; !errors.Is(err, ErrForwarderRequestCompleted) {
			t.Fatalf("repeated TCP action = %v", err)
		}
	})

	t.Run("UDP reply", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.72")
		remote := netip.MustParseAddr("192.0.2.73")
		target := netip.MustParseAddr("198.51.100.72")
		stack := newForwarderTestStack(t, owned, true)
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			if string(request.Payload()) != "query" {
				t.Errorf("UDP request payload = %q", request.Payload())
			}
			if _, replyErr := request.Reply([]byte("answer")); replyErr != nil {
				t.Errorf("Reply UDP: %v", replyErr)
			}
			if _, replyErr := request.Reply([]byte("second answer")); replyErr != nil {
				t.Errorf("second Reply UDP: %v", replyErr)
			}
			if dropErr := request.Drop(); !errors.Is(dropErr, ErrForwarderReplyActive) {
				t.Errorf("Drop UDP request in reply mode: %v", dropErr)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		if err = writeTestPacket(stack, buildTestUDP(remote, target, 53003, 53, []byte("query"))); err != nil {
			t.Fatal(err)
		}
		response := readForwarderTestPacket(t, stack)
		parsed, ok := parseIPPacket(response)
		if !ok || parsed.source != target || parsed.target != remote || binary.BigEndian.Uint16(parsed.payload[0:2]) != 53 || binary.BigEndian.Uint16(parsed.payload[2:4]) != 53003 || string(parsed.payload[udpHeaderSize:]) != "answer" {
			t.Fatalf("forwarded UDP reply = %x", response)
		}
		response = readForwarderTestPacket(t, stack)
		parsed, ok = parseIPPacket(response)
		if !ok || string(parsed.payload[udpHeaderSize:]) != "second answer" {
			t.Fatalf("second forwarded UDP reply = %x", response)
		}
		if info := forwarder.Info(); info.Replies != 2 || info.ReplyErrors != 0 {
			t.Fatalf("multi-reply UDP forwarder info = %+v", info)
		}
	})

	t.Run("ICMP reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.74")
		remote := netip.MustParseAddr("192.0.2.75")
		target := netip.MustParseAddr("198.51.100.74")
		stack := newForwarderTestStack(t, owned, true)
		forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) { _ = request.Reject() })
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		icmp := make([]byte, 8)
		icmp[0] = 8
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)); err != nil {
			t.Fatal(err)
		}
		response := readForwarderTestPacket(t, stack)
		parsed, ok := parseIPPacket(response)
		if !ok || parsed.source != target || parsed.target != remote || parsed.payload[0] != 3 || parsed.payload[1] != 13 || checksum(parsed.payload) != 0 {
			t.Fatalf("forwarded ICMP rejection = %x", response)
		}
	})
}

func TestForwarderOutputActionsDoNotBlockOnFullQueue(t *testing.T) {
	awaitResourceLimit := func(t *testing.T, result <-chan error) {
		t.Helper()
		select {
		case err := <-result:
			if !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("full-queue action error = %v, want ErrResourceLimit", err)
			}
		case <-time.After(time.Second):
			t.Fatal("full-queue action blocked")
		}
	}

	t.Run("TCP Reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.100")
		remote := netip.MustParseAddr("192.0.2.101")
		target := netip.MustParseAddr("198.51.100.100")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewTCPForwarder(stack, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
			result <- request.Reject()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		packet := buildTestTCP(remote, target, 55001, 443, 100, 0, tcpFlagSYN, 65535, nil, nil)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		awaitResourceLimit(t, result)
		if info := forwarder.Info(); info.Pending != 0 || info.Rejected != 1 {
			t.Fatalf("full-queue TCP forwarder info = %+v", info)
		}
	})

	t.Run("UDP Reply", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.102")
		remote := netip.MustParseAddr("192.0.2.103")
		target := netip.MustParseAddr("198.51.100.102")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			_, replyErr := request.Reply([]byte("answer"))
			result <- replyErr
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		if err = writeTestPacket(stack, buildTestUDP(remote, target, 55002, 53, []byte("query"))); err != nil {
			t.Fatal(err)
		}
		awaitResourceLimit(t, result)
	})

	t.Run("UDP Reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.104")
		remote := netip.MustParseAddr("192.0.2.105")
		target := netip.MustParseAddr("198.51.100.104")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			result <- request.Reject()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		if err = writeTestPacket(stack, buildTestUDP(remote, target, 55003, 5353, []byte("reject"))); err != nil {
			t.Fatal(err)
		}
		awaitResourceLimit(t, result)
	})

	t.Run("ICMP Reply", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.106")
		remote := netip.MustParseAddr("192.0.2.107")
		target := netip.MustParseAddr("198.51.100.106")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
			reply := append([]byte(nil), request.Message().Payload...)
			reply[0] = 0
			result <- request.Reply(reply)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		icmp := make([]byte, 8)
		icmp[0] = 8
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)); err != nil {
			t.Fatal(err)
		}
		awaitResourceLimit(t, result)
	})

	t.Run("ICMP Reject", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.108")
		remote := netip.MustParseAddr("192.0.2.109")
		target := netip.MustParseAddr("198.51.100.108")
		stack := newForwarderTestStack(t, owned, true)
		fillTestPacketQueue(t, &stack.outbound, []byte{0})
		result := make(chan error, 1)
		forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
			result <- request.Reject()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer forwarder.Close()
		icmp := make([]byte, 8)
		icmp[0] = 8
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)); err != nil {
			t.Fatal(err)
		}
		awaitResourceLimit(t, result)
	})
}

func TestUDPForwarderReplyReservesAllFragments(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.110")
	remote := netip.MustParseAddr("192.0.2.111")
	target := netip.MustParseAddr("198.51.100.110")
	stack := newForwarderTestStack(t, owned, true)
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	entry := <-stack.outbound.packets
	stack.outbound.release(entry)
	before := len(stack.outbound.packets)
	result := make(chan error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr := request.Reply(bytes.Repeat([]byte{0x5a}, 1800))
		result <- replyErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55004, 5353, []byte("fragment"))); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("fragmented Reply with one slot = %v, want ErrResourceLimit", err)
	}
	if got := len(stack.outbound.packets); got != before {
		t.Fatalf("partial UDP fragments were queued: before=%d after=%d", before, got)
	}
}

func TestUDPForwarderFragmentedReply(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.114")
	serverAddress := netip.MustParseAddr("192.0.2.115")
	target := netip.MustParseAddr("198.51.100.114")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)
	payload := bytes.Repeat([]byte{0x6b}, 1800)
	replyResult := make(chan error, 1)
	forwarder, err := NewUDPForwarder(server, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr := request.Reply(payload)
		replyResult <- replyErr
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	connection, err := client.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(target, 5353))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err = connection.Write([]byte("fragmented reply")); err != nil {
		t.Fatal(err)
	}
	if err = <-replyResult; err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	n, err := connection.Read(received)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || !bytes.Equal(received[:n], payload) {
		t.Fatalf("fragmented UDP Reply length=%d want=%d", n, len(payload))
	}
}

func TestUDPForwarderReplyUsesSocketDefaults(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::108")
	remote := netip.MustParseAddr("2001:db8::109")
	target := netip.MustParseAddr("2001:db8:1::108")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, Promiscuous: true, MTU: 1400,
		UDP: DatagramSocketDefaults{HopLimit: 37, TrafficClass: 0x2e, FlowLabel: 0x54321},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		if _, replyErr := request.Reply([]byte("answer")); replyErr != nil {
			t.Errorf("Reply UDP with configured defaults: %v", replyErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 52900, 53, []byte("query"))); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.source != target || parsed.target != remote || parsed.protocol != protocolUDP {
		t.Fatalf("configured UDP forwarder response = %x", response)
	}
	if parsed.hopLimit != 37 || parsed.trafficClass != 0x2e || parsed.flowLabel != 0x54321 {
		t.Fatalf("configured UDP output fields = hop %d, class %#x, label %#x", parsed.hopLimit, parsed.trafficClass, parsed.flowLabel)
	}
}

func TestUDPForwarderReplyUsesAutomaticFlowLabel(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::110")
	remote := netip.MustParseAddr("2001:db8::111")
	target := netip.MustParseAddr("2001:db8:1::110")
	stack := newForwarderTestStack(t, local, true)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		if _, replyErr := request.Reply([]byte("answer")); replyErr != nil {
			t.Errorf("Reply UDP with automatic flow label: %v", replyErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	const sourcePort, targetPort = 52901, 53
	if err = writeTestPacket(stack, buildTestUDP(remote, target, sourcePort, targetPort, []byte("query"))); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok {
		t.Fatalf("automatic-label UDP forwarder response = %x", response)
	}
	want := stack.automaticTransportFlowLabel(target, remote, protocolUDP, targetPort, sourcePort)
	if parsed.flowLabel != want {
		t.Fatalf("automatic UDP flow label = %#x, want %#x", parsed.flowLabel, want)
	}
}

func TestUDPForwarderDetachedReply(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.116")
	remote := netip.MustParseAddr("192.0.2.117")
	target := netip.MustParseAddr("198.51.100.116")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	packet := buildTestUDP(remote, target, 55007, 53, []byte("async query"))
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	for index := range packet {
		packet[index] = 0
	}
	if got := responder.Flow(); got != (TransportFlow{Source: netip.AddrPortFrom(remote, 55007), Destination: netip.AddrPortFrom(target, 53)}) {
		t.Fatalf("detached UDP flow = %+v", got)
	}
	if got := string(responder.Payload()); got != "async query" {
		t.Fatalf("detached UDP payload = %q", got)
	}
	if info := forwarder.Info(); info.Pending != 0 {
		t.Fatalf("detached UDP forwarder info = %+v", info)
	}
	result := make(chan error, 1)
	go func() {
		_, replyErr := responder.Reply([]byte("async answer"))
		result <- replyErr
	}()
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.source != target || parsed.target != remote || string(parsed.payload[udpHeaderSize:]) != "async answer" {
		t.Fatalf("detached UDP response = %x", response)
	}
	if _, err = responder.Reply([]byte("second answer")); err != nil {
		t.Fatal(err)
	}
	response = readForwarderTestPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || string(parsed.payload[udpHeaderSize:]) != "second answer" {
		t.Fatalf("second detached UDP response = %x", response)
	}
	if err = responder.Drop(); !errors.Is(err, ErrForwarderReplyActive) {
		t.Fatalf("Drop active detached UDP responder = %v", err)
	}
	if err = responder.Reject(); !errors.Is(err, ErrForwarderReplyActive) {
		t.Fatalf("Reject active detached UDP responder = %v", err)
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = responder.Reply([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Reply closed detached UDP responder = %v", err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Replies != 2 || info.Dropped != 0 {
		t.Fatalf("completed detached UDP forwarder info = %+v", info)
	}
}

func TestICMPForwarderDetachedReply(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.118")
	remote := netip.MustParseAddr("192.0.2.119")
	target := netip.MustParseAddr("198.51.100.118")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *ICMPForwarderResponder, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach ICMP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 12)
	icmp[0] = 8
	copy(icmp[8:], "ping")
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	packet := buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	for index := range packet {
		packet[index] = 0
	}
	message := responder.Message()
	if message.Source != remote || message.Destination != target || message.Type != 8 || message.Code != 0 || string(message.Payload[8:]) != "ping" {
		t.Fatalf("detached ICMP message = %+v", message)
	}
	result := make(chan error, 1)
	go func() { result <- responder.ReplyEcho() }()
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.source != target || parsed.target != remote || parsed.payload[0] != 0 || checksum(parsed.payload) != 0 {
		t.Fatalf("detached ICMP response = %x", response)
	}
	if err = responder.ReplyEcho(); err != nil {
		t.Fatal(err)
	}
	response = readForwarderTestPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.payload[0] != 0 || checksum(parsed.payload) != 0 {
		t.Fatalf("second detached ICMP response = %x", response)
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Replies != 2 {
		t.Fatalf("completed detached ICMP forwarder info = %+v", info)
	}
}

func TestICMPForwarderDetachedTerminalActions(t *testing.T) {
	for _, action := range []string{"Drop", "Reject"} {
		t.Run(action, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.122")
			remote := netip.MustParseAddr("192.0.2.123")
			target := netip.MustParseAddr("198.51.100.122")
			stack := newForwarderTestStack(t, local, true)
			detached := make(chan *ICMPForwarderResponder, 1)
			forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
				responder, detachErr := request.Detach()
				if detachErr != nil {
					t.Errorf("Detach ICMP: %v", detachErr)
					return
				}
				detached <- responder
			})
			if err != nil {
				t.Fatal(err)
			}
			icmp := make([]byte, 8)
			icmp[0] = 13
			binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
			if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)); err != nil {
				t.Fatal(err)
			}
			responder := <-detached
			if action == "Drop" {
				err = responder.Drop()
			} else {
				err = responder.Reject()
			}
			if err != nil {
				t.Fatalf("%s detached ICMP: %v", action, err)
			}
			if err = responder.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Close after detached ICMP %s = %v", action, err)
			}
			info := forwarder.Info()
			if action == "Drop" {
				if info.Dropped != 1 || info.Rejected != 0 {
					t.Fatalf("dropped detached ICMP info = %+v", info)
				}
			} else {
				if info.Dropped != 0 || info.Rejected != 1 {
					t.Fatalf("rejected detached ICMP info = %+v", info)
				}
				response := readForwarderTestPacket(t, stack)
				parsed, ok := parseIPPacket(response)
				if !ok || parsed.payload[0] != 3 || parsed.payload[1] != 13 {
					t.Fatalf("detached ICMP rejection = %x", response)
				}
			}
			if err = forwarder.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-responder.Done():
			default:
				t.Fatal("detached ICMP responder Done remained open")
			}
		})
	}
}

func TestUDPForwarderDetachedReplyCanRetry(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.132")
	remote := netip.MustParseAddr("192.0.2.133")
	target := netip.MustParseAddr("198.51.100.132")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55302, 53, []byte("retry"))); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	if _, err = responder.Reply([]byte("answer")); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("full-queue detached UDP Reply = %v", err)
	}
	if err = responder.Drop(); !errors.Is(err, ErrForwarderReplyActive) {
		t.Fatalf("Drop active detached UDP responder = %v", err)
	}
	for len(stack.outbound.packets) != 0 {
		consumeTestPacket(&stack.outbound, <-stack.outbound.packets)
	}
	if _, err = responder.Reply([]byte("answer")); err != nil {
		t.Fatalf("retry detached UDP Reply: %v", err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || string(parsed.payload[udpHeaderSize:]) != "answer" {
		t.Fatalf("retried detached UDP response = %x", response)
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Replies != 1 || info.ReplyErrors != 1 {
		t.Fatalf("retried detached UDP forwarder info = %+v", info)
	}
}

func TestUDPForwarderRequestReplyCanRetry(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.134")
	remote := netip.MustParseAddr("192.0.2.135")
	target := netip.MustParseAddr("198.51.100.134")
	stack := newForwarderTestStack(t, owned, true)
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	results := make(chan [3]error, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, firstErr := request.Reply([]byte("answer"))
		_, acceptErr := request.Accept()
		for len(stack.outbound.packets) != 0 {
			consumeTestPacket(&stack.outbound, <-stack.outbound.packets)
		}
		_, retryErr := request.Reply([]byte("answer"))
		results <- [3]error{firstErr, acceptErr, retryErr}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55303, 53, []byte("retry"))); err != nil {
		t.Fatal(err)
	}
	result := <-results
	if !errors.Is(result[0], ErrResourceLimit) {
		t.Fatalf("full-queue request Reply = %v", result[0])
	}
	if !errors.Is(result[1], ErrForwarderReplyActive) {
		t.Fatalf("Accept request in reply mode = %v", result[1])
	}
	if result[2] != nil {
		t.Fatalf("retry request Reply = %v", result[2])
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || string(parsed.payload[udpHeaderSize:]) != "answer" {
		t.Fatalf("retried request UDP response = %x", response)
	}
	if info := forwarder.Info(); info.Replies != 1 || info.ReplyErrors != 1 || info.Dropped != 0 {
		t.Fatalf("retried request UDP forwarder info = %+v", info)
	}
}

func TestUDPForwarderDetachedResponderIsCallerOwned(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.124")
	remote := netip.MustParseAddr("192.0.2.125")
	target := netip.MustParseAddr("198.51.100.124")
	stack := newForwarderTestStack(t, owned, true)
	responders := make(chan *UDPForwarderResponder, 300)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		responders <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < cap(responders); index++ {
		packet := buildTestUDP(remote, target, uint16(55000+index), 53, []byte("query"))
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Requests != uint64(cap(responders)) || info.Dropped != 0 {
		t.Fatalf("caller-owned UDP forwarder info = %+v", info)
	}
	responder := <-responders
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
		t.Fatal(err)
	}
	if _, err = responder.Reply([]byte("late")); !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatalf("config-invalidated UDP responder action = %v", err)
	}
	if err = responder.Close(); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 0 || info.ReplyErrors != 1 {
		t.Fatalf("invalidated UDP forwarder info = %+v", info)
	}
	for len(responders) != 0 {
		if dropErr := (<-responders).Drop(); dropErr != nil {
			t.Fatal(dropErr)
		}
	}
	if info := forwarder.Info(); info.Dropped != uint64(cap(responders)-1) {
		t.Fatalf("completed caller-owned UDP forwarder info = %+v", info)
	}
}

func TestDetachedForwarderResponderRevalidatesLifecycle(t *testing.T) {
	t.Run("UDP forwarder close", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.126")
		remote := netip.MustParseAddr("192.0.2.127")
		target := netip.MustParseAddr("198.51.100.126")
		stack := newForwarderTestStack(t, owned, true)
		detached := make(chan *UDPForwarderResponder, 1)
		forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
			responder, detachErr := request.Detach()
			if detachErr != nil {
				t.Errorf("Detach UDP: %v", detachErr)
				return
			}
			detached <- responder
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = writeTestPacket(stack, buildTestUDP(remote, target, 55300, 53, []byte("close"))); err != nil {
			t.Fatal(err)
		}
		responder := <-detached
		if err = forwarder.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-forwarder.Done():
		default:
			t.Fatal("UDP forwarder Done remained open after Close")
		}
		select {
		case <-responder.Done():
		default:
			t.Fatal("UDP responder Done remained open after forwarder Close")
		}
		if _, err = responder.Reply([]byte("late")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("detached UDP Reply after Close = %v", err)
		}
		if err = responder.Close(); err != nil {
			t.Fatal(err)
		}
		if err = responder.Drop(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Drop closed detached UDP responder = %v", err)
		}
		if info := forwarder.Info(); !info.Closed || info.Pending != 0 || info.Dropped != 0 || info.ReplyErrors != 1 {
			t.Fatalf("closed detached UDP forwarder info = %+v", info)
		}
	})

	t.Run("ICMP configuration removal", func(t *testing.T) {
		owned := netip.MustParseAddr("192.0.2.128")
		remote := netip.MustParseAddr("192.0.2.129")
		target := netip.MustParseAddr("198.51.100.128")
		stack := newForwarderTestStack(t, owned, true)
		detached := make(chan *ICMPForwarderResponder, 1)
		forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
			responder, detachErr := request.Detach()
			if detachErr != nil {
				t.Errorf("Detach ICMP: %v", detachErr)
				return
			}
			detached <- responder
		})
		if err != nil {
			t.Fatal(err)
		}
		icmp := make([]byte, 8)
		icmp[0] = 8
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)); err != nil {
			t.Fatal(err)
		}
		responder := <-detached
		if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(owned, 32)}, MTU: 1400}); err != nil {
			t.Fatal(err)
		}
		if err = responder.Reply(icmp); !errors.Is(err, syscall.EADDRNOTAVAIL) {
			t.Fatalf("detached ICMP Reply after configuration removal = %v", err)
		}
		if err = responder.Close(); err != nil {
			t.Fatal(err)
		}
		if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 0 || info.ReplyErrors != 1 {
			t.Fatalf("invalidated detached ICMP forwarder info = %+v", info)
		}
	})
}

func TestDetachedForwarderResponderConcurrentAction(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.130")
	remote := netip.MustParseAddr("192.0.2.131")
	target := netip.MustParseAddr("198.51.100.130")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55301, 53, []byte("race"))); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	results := make(chan error, 32)
	for index := 0; index < cap(results); index++ {
		go func() { results <- responder.Drop() }()
	}
	succeeded := 0
	for index := 0; index < cap(results); index++ {
		actionErr := <-results
		if actionErr == nil {
			succeeded++
		} else if !errors.Is(actionErr, net.ErrClosed) {
			t.Fatalf("concurrent detached action = %v", actionErr)
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent detached actions = %d", succeeded)
	}
	if info := forwarder.Info(); info.Pending != 0 || info.Dropped != 1 {
		t.Fatalf("concurrent detached UDP forwarder info = %+v", info)
	}
}

func TestDetachedForwarderResponderConcurrentReplyAndClose(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.136")
	remote := netip.MustParseAddr("192.0.2.137")
	target := netip.MustParseAddr("198.51.100.136")
	stack := newForwarderTestStack(t, owned, true)
	detached := make(chan *UDPForwarderResponder, 1)
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		responder, detachErr := request.Detach()
		if detachErr != nil {
			t.Errorf("Detach UDP: %v", detachErr)
			return
		}
		detached <- responder
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, target, 55304, 53, []byte("race"))); err != nil {
		t.Fatal(err)
	}
	responder := <-detached
	const replies = 32
	start := make(chan struct{})
	results := make(chan error, replies)
	for index := 0; index < replies; index++ {
		go func() {
			<-start
			_, replyErr := responder.Reply([]byte("answer"))
			results <- replyErr
		}()
	}
	closed := make(chan error, 1)
	go func() {
		<-start
		closed <- responder.Close()
	}()
	close(start)
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
	succeeded := 0
	for index := 0; index < replies; index++ {
		replyErr := <-results
		if replyErr == nil {
			succeeded++
		} else if !errors.Is(replyErr, net.ErrClosed) {
			t.Fatalf("concurrent detached Reply = %v", replyErr)
		}
	}
	if _, err = responder.Reply([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Reply after concurrent Close = %v", err)
	}
	if info := forwarder.Info(); info.Replies != uint64(succeeded) {
		t.Fatalf("concurrent Reply forwarder info = %+v, succeeded=%d", info, succeeded)
	}
}

func TestAutomaticControlResponsesDoNotBlockOnFullQueue(t *testing.T) {
	for _, protocol := range []string{"TCP", "UDP"} {
		t.Run(protocol, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.112")
			remote := netip.MustParseAddr("192.0.2.113")
			stack := newForwarderTestStack(t, local, false)
			fillTestPacketQueue(t, &stack.outbound, []byte{0})
			var packet []byte
			if protocol == "TCP" {
				packet = buildTestTCP(remote, local, 55005, 443, 100, 0, tcpFlagSYN, 65535, nil, nil)
			} else {
				packet = buildTestUDP(remote, local, 55006, 5353, []byte("unhandled"))
			}
			done := make(chan error, 1)
			go func() { done <- writeTestPacket(stack, packet) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("automatic %s response returned input error: %v", protocol, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("automatic %s response blocked Stack.Write", protocol)
			}
		})
	}
}

func TestICMPv6ForwarderReply(t *testing.T) {
	owned := netip.MustParseAddr("2001:db8::80")
	remote := netip.MustParseAddr("2001:db8::81")
	target := netip.MustParseAddr("2001:db8:1::80")
	stack := newForwarderTestStack(t, owned, true)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		if !request.Message().IsEchoRequest() {
			t.Error("ICMPv6 Echo Request was not recognized")
			_ = request.Drop()
			return
		}
		if replyErr := request.ReplyEcho(); replyErr != nil {
			t.Errorf("ReplyEcho ICMPv6: %v", replyErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 12)
	icmp[0] = 128
	copy(icmp[8:], "ping")
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(remote, target, protocolICMPv6, icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv6, icmp, 0, true)); err != nil {
		t.Fatal(err)
	}
	response := readForwarderTestPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.source != target || parsed.target != remote || parsed.payload[0] != 129 || transportChecksum(target, remote, protocolICMPv6, parsed.payload) != 0 {
		t.Fatalf("forwarded ICMPv6 reply = %x", response)
	}
}

func TestICMPForwarderReplyEchoRejectsNonEcho(t *testing.T) {
	owned := netip.MustParseAddr("192.0.2.82")
	remote := netip.MustParseAddr("192.0.2.83")
	target := netip.MustParseAddr("198.51.100.82")
	stack := newForwarderTestStack(t, owned, true)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		if request.Message().IsEchoRequest() {
			t.Error("ICMP Echo Reply was recognized as a request")
		}
		if replyErr := request.ReplyEcho(); !errors.Is(replyErr, syscall.EINVAL) {
			t.Errorf("ReplyEcho non-Echo ICMP = %v", replyErr)
		}
		if dropErr := request.Drop(); dropErr != nil {
			t.Errorf("Drop after invalid ReplyEcho = %v", dropErr)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := make([]byte, 8)
	icmp[0] = 0
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	if info := forwarder.Info(); info.Requests != 1 || info.Replies != 0 || info.Dropped != 1 {
		t.Fatalf("ICMP forwarder info after invalid ReplyEcho = %+v", info)
	}
}

func TestICMPMessageIsEchoRequest(t *testing.T) {
	v4Source := netip.MustParseAddr("192.0.2.90")
	v4Target := netip.MustParseAddr("198.51.100.90")
	v6Source := netip.MustParseAddr("2001:db8::90")
	v6Target := netip.MustParseAddr("2001:db8:1::90")
	v4Echo := []byte{8, 0, 0, 0, 0, 1, 0, 2}
	v6Echo := []byte{128, 0, 0, 0, 0, 1, 0, 2}
	tests := []struct {
		name    string
		message ICMPMessage
		want    bool
	}{
		{name: "IPv4", message: ICMPMessage{Source: v4Source, Destination: v4Target, Type: 8, Payload: v4Echo}, want: true},
		{name: "IPv6", message: ICMPMessage{Source: v6Source, Destination: v6Target, Type: 128, Payload: v6Echo}, want: true},
		{name: "reply", message: ICMPMessage{Source: v4Source, Destination: v4Target, Payload: []byte{0, 0, 0, 0, 0, 1, 0, 2}}},
		{name: "nonzero code", message: ICMPMessage{Source: v4Source, Destination: v4Target, Type: 8, Code: 1, Payload: []byte{8, 1, 0, 0, 0, 1, 0, 2}}},
		{name: "truncated", message: ICMPMessage{Source: v4Source, Destination: v4Target, Type: 8, Payload: []byte{8, 0}}},
		{name: "cross family", message: ICMPMessage{Source: v4Source, Destination: v6Target, Type: 8, Payload: v4Echo}},
		{name: "metadata mismatch", message: ICMPMessage{Source: v4Source, Destination: v4Target, Type: 128, Payload: v4Echo}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.message.IsEchoRequest(); got != test.want {
				t.Fatalf("IsEchoRequest() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestICMPReplyEchoLifecycleAndSnapshotValidation(t *testing.T) {
	nonEcho := []byte{0, 0, 0, 0, 0, 1, 0, 2}
	request := &ICMPForwarderRequest{packet: ipPacket{protocol: protocolICMPv4, payload: nonEcho}}
	request.state.Store(uint32(forwarderRequestDropped))
	if err := request.ReplyEcho(); !errors.Is(err, ErrForwarderRequestCompleted) {
		t.Fatalf("ReplyEcho after request completion = %v", err)
	}
	responder := &ICMPForwarderResponder{
		message: ICMPMessage{
			Source: netip.MustParseAddr("192.0.2.91"), Destination: netip.MustParseAddr("198.51.100.91"),
			Payload: nonEcho,
		},
		packet: ipPacket{protocol: protocolICMPv4},
	}
	responder.lifecycle.state.Store(uint32(forwarderResponderClosed))
	if err := responder.ReplyEcho(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReplyEcho after responder closure = %v", err)
	}
	responder.lifecycle.state.Store(uint32(forwarderResponderPending))
	responder.message.Payload[0] = 8
	if responder.message.IsEchoRequest() {
		t.Fatal("mutated detached message has inconsistent Echo metadata")
	}
	if err := responder.ReplyEcho(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("ReplyEcho with inconsistent detached message = %v", err)
	}
}

func TestICMPForwarderRejectsShortReply(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.92")
	remote := netip.MustParseAddr("192.0.2.93")
	target := netip.MustParseAddr("198.51.100.92")
	stack := newForwarderTestStack(t, local, true)
	results := make(chan [4]error, 1)
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		var replyErrors [4]error
		for index := range replyErrors {
			replyErrors[index] = request.Reply(make([]byte, index+4))
		}
		results <- replyErrors
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	icmp := []byte{13, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	if err = writeTestPacket(stack, buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)); err != nil {
		t.Fatal(err)
	}
	for size, replyErr := range <-results {
		if !errors.Is(replyErr, syscall.EINVAL) {
			t.Fatalf("%d-byte ICMP Reply = %v", size+4, replyErr)
		}
	}
	select {
	case entry := <-stack.outbound.packets:
		stack.outbound.release(entry)
		t.Fatal("short ICMP Reply emitted a packet")
	default:
	}
	if info := forwarder.Info(); info.Replies != 0 || info.ReplyErrors != 4 {
		t.Fatalf("short ICMP Reply diagnostics = %+v", info)
	}
}

func BenchmarkUDPForwarderReply(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.200")
	remote := netip.MustParseAddr("192.0.2.201")
	target := netip.MustParseAddr("198.51.100.200")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
	})
	if err != nil {
		b.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		b.Fatal(err)
	}
	reply := []byte("benchmark answer")
	var replyErr error
	forwarder, err := NewUDPForwarder(stack, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		_, replyErr = request.Reply(reply)
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = forwarder.Close()
		_ = stack.Close()
	})
	packet := buildTestUDP(remote, target, 53000, 53, []byte("benchmark query"))
	b.ReportAllocs()
	b.SetBytes(int64(len(packet) + len(reply)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err = stack.Write([][]byte{packet}, 0); err != nil {
			b.Fatal(err)
		}
		if replyErr != nil {
			b.Fatal(replyErr)
		}
		stack.outbound.release(<-stack.outbound.packets)
	}
}

func BenchmarkICMPForwarderReplyEcho(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.202")
	remote := netip.MustParseAddr("192.0.2.203")
	target := netip.MustParseAddr("198.51.100.202")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, Promiscuous: true, MTU: 1400,
	})
	if err != nil {
		b.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		b.Fatal(err)
	}
	var replyErr error
	forwarder, err := NewICMPForwarder(stack, ICMPForwarderOptions{}, func(request *ICMPForwarderRequest) {
		replyErr = request.ReplyEcho()
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = forwarder.Close()
		_ = stack.Close()
	})
	icmp := make([]byte, 40)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 1)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	packet := buildIPPacket(remote, target, protocolICMPv4, icmp, 1, true)
	b.ReportAllocs()
	b.SetBytes(int64(len(packet) + len(icmp)))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err = stack.Write([][]byte{packet}, 0); err != nil {
			b.Fatal(err)
		}
		if replyErr != nil {
			b.Fatal(replyErr)
		}
		stack.outbound.release(<-stack.outbound.packets)
	}
}

func TestIPv6TransportForwarders(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::90")
	serverAddress := netip.MustParseAddr("2001:db8::91")
	target := netip.MustParseAddr("2001:db8:1::90")
	client := newForwarderTestStack(t, clientAddress, false)
	server := newForwarderTestStack(t, serverAddress, true)
	newStackBridge(t, client, server)

	tcpAccepted := make(chan *TCPConn, 1)
	_, err := NewTCPForwarder(server, TCPForwarderOptions{}, func(request *TCPForwarderRequest) {
		connection, acceptErr := request.Accept(context.Background())
		if acceptErr != nil {
			t.Errorf("Accept IPv6 TCP: %v", acceptErr)
			return
		}
		tcpAccepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	clientTCP, err := client.DialTCP(context.Background(), "tcp6", netip.AddrPort{}, netip.AddrPortFrom(target, 8443))
	if err != nil {
		t.Fatal(err)
	}
	defer clientTCP.Close()
	serverTCP := <-tcpAccepted
	defer serverTCP.Close()
	_ = clientTCP.SetDeadline(time.Now().Add(time.Second))
	_ = serverTCP.SetDeadline(time.Now().Add(time.Second))
	if _, err = clientTCP.Write([]byte("tcp6")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, err := serverTCP.Read(buffer)
	if err != nil || string(buffer[:n]) != "tcp6" {
		t.Fatalf("IPv6 forwarded TCP = %q, %v", buffer[:n], err)
	}

	udpAccepted := make(chan *UDPConn, 1)
	_, err = NewUDPForwarder(server, UDPForwarderOptions{}, func(request *UDPForwarderRequest) {
		connection, acceptErr := request.Accept()
		if acceptErr != nil {
			t.Errorf("Accept IPv6 UDP: %v", acceptErr)
			return
		}
		udpAccepted <- connection
	})
	if err != nil {
		t.Fatal(err)
	}
	clientUDP, err := client.DialUDP(context.Background(), "udp6", netip.AddrPort{}, netip.AddrPortFrom(target, 5353))
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	_ = clientUDP.SetDeadline(time.Now().Add(time.Second))
	if _, err = clientUDP.Write([]byte("udp6")); err != nil {
		t.Fatal(err)
	}
	serverUDP := <-udpAccepted
	defer serverUDP.Close()
	_ = serverUDP.SetDeadline(time.Now().Add(time.Second))
	n, err = serverUDP.Read(buffer)
	if err != nil || string(buffer[:n]) != "udp6" {
		t.Fatalf("IPv6 forwarded UDP = %q, %v", buffer[:n], err)
	}
	if _, err = serverUDP.Write([]byte("reply6")); err != nil {
		t.Fatal(err)
	}
	n, err = clientUDP.Read(buffer)
	if err != nil || string(buffer[:n]) != "reply6" {
		t.Fatalf("IPv6 forwarded UDP reply = %q, %v", buffer[:n], err)
	}
}
