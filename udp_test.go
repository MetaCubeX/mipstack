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
	"syscall"
	"testing"
	"time"
)

type testUDPStringAddress string

func (a testUDPStringAddress) Network() string { return "udp" }
func (a testUDPStringAddress) String() string  { return string(a) }

// TestUDPConcurrentDemultiplexing verifies family and port based dispatch.
func TestUDPConcurrentDemultiplexing(t *testing.T) {
	for _, test := range []struct {
		name   string
		local  netip.Addr
		remote netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.1"), remote: netip.MustParseAddr("192.0.2.2")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::1"), remote: netip.MustParseAddr("2001:db8::2")},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			defer stack.Close()
			first, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(test.remote))
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(test.remote))
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if first.LocalAddr().String() == second.LocalAddr().String() {
				t.Fatal("UDP sockets received the same ephemeral port")
			}
			link.echoUDP = true
			target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(test.remote, 5353))
			connections := []net.PacketConn{first, second}
			var wait sync.WaitGroup
			for index, connection := range connections {
				index, connection := index, connection
				wait.Add(1)
				go func() {
					defer wait.Done()
					payload := []byte{byte(index), 2, 3, 4}
					if _, writeErr := connection.WriteTo(payload, target); writeErr != nil {
						t.Error(writeErr)
						return
					}
					if deadlineErr := connection.SetReadDeadline(time.Now().Add(time.Second)); deadlineErr != nil {
						t.Error(deadlineErr)
						return
					}
					buffer := make([]byte, 32)
					n, source, readErr := connection.ReadFrom(buffer)
					if readErr != nil {
						t.Error(readErr)
						return
					}
					if !bytes.Equal(buffer[:n], payload) || source.String() != target.String() {
						t.Errorf("UDP reply = %x from %v, want %x from %v", buffer[:n], source, payload, target)
					}
				}()
			}
			wait.Wait()
		})
	}
}

func TestUDPDestinationPortZeroUsesProtocolPath(t *testing.T) {
	for _, test := range []struct {
		name           string
		network        string
		client, server netip.Addr
	}{
		{name: "IPv4", network: "udp4", client: netip.MustParseAddr("192.0.2.230"), server: netip.MustParseAddr("192.0.2.231")},
		{name: "IPv6", network: "udp6", client: netip.MustParseAddr("2001:db8::230"), server: netip.MustParseAddr("2001:db8::231")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newStackPair(t, test.client, test.server, 1400)
			newStackBridge(t, client, server)
			connection, err := client.DialUDP(context.Background(), test.network, netip.AddrPort{}, netip.AddrPortFrom(test.server, 0))
			if err != nil {
				t.Fatalf("DialUDP to port zero: %v", err)
			}
			defer connection.Close()
			if n, writeErr := connection.Write([]byte("zero")); writeErr != nil || n != len("zero") {
				t.Fatalf("Write to port zero = %d, %v", n, writeErr)
			}
			if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, readErr := connection.Read(make([]byte, 1)); readErr == nil {
				t.Fatal("port-zero datagram did not receive an ICMP error")
			} else {
				var networkError ICMPError
				if !errors.As(readErr, &networkError) || networkError.QuotedTargetPort != 0 {
					t.Fatalf("port-zero read error = %#v", readErr)
				}
			}
		})
	}
}

func TestUDPPacketizationLayerPathMTUDiscovery(t *testing.T) {
	for _, test := range []struct {
		name       string
		local      netip.Addr
		remote     netip.Addr
		baseMTU    uint32
		payloadLen int
		connected  bool
	}{
		{name: "IPv4 connected", local: netip.MustParseAddr("192.0.2.231"), remote: netip.MustParseAddr("198.51.100.231"), baseMTU: 1000, payloadLen: 1200, connected: true},
		{name: "IPv6 unconnected", local: netip.MustParseAddr("2001:db8::231"), remote: netip.MustParseAddr("2001:db8:1::231"), baseMTU: 1280, payloadLen: 1400},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 32
			if test.local.Is6() {
				bits = 128
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1500})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			if !stack.observePathMTU(test.remote, test.baseMTU) {
				t.Fatal("failed to install base PMTU")
			}
			target := netip.AddrPortFrom(test.remote, 5353)
			var connection *UDPConn
			if test.connected {
				var netConnection net.Conn
				netConnection, err = stack.DialUDP(context.Background(), "udp", netip.AddrPort{}, target)
				if err == nil {
					connection = netConnection.(*UDPConn)
				}
			} else {
				var packetConnection net.PacketConn
				packetConnection, err = stack.ListenUDP(context.Background(), "udp", netip.AddrPort{})
				if err == nil {
					connection = packetConnection.(*UDPConn)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, test.payloadLen)
			if test.connected {
				if _, err = connection.Write(payload); err != nil {
					t.Fatal(err)
				}
			} else if _, err = connection.WriteToUDPAddrPort(payload, target); err != nil {
				t.Fatal(err)
			}
			readPacket := func() []byte {
				buffer := make([]byte, 1600)
				sizes := []int{0}
				if _, readErr := stack.Read([][]byte{buffer}, sizes, 0); readErr != nil {
					t.Fatal(readErr)
				}
				return append([]byte(nil), buffer[:sizes[0]]...)
			}
			for fragment := 0; fragment < 2; fragment++ {
				if packet := readPacket(); len(packet) > int(test.baseMTU) {
					t.Fatalf("ordinary UDP fragment size = %d, want <= %d", len(packet), test.baseMTU)
				}
			}
			if test.connected {
				if _, err = connection.WritePathMTUProbe(payload); err != nil {
					t.Fatal(err)
				}
			} else if _, err = connection.WritePathMTUProbeTo(payload, target); err != nil {
				t.Fatal(err)
			}
			probe := readPacket()
			wantProbeSize := test.payloadLen + udpHeaderSize + 20
			if test.remote.Is6() {
				wantProbeSize = test.payloadLen + udpHeaderSize + 40
			}
			if len(probe) != wantProbeSize {
				t.Fatalf("UDP path probe size = %d, want %d", len(probe), wantProbeSize)
			}
			if test.connected {
				err = connection.ConfirmPathMTU(wantProbeSize)
			} else {
				err = connection.ConfirmPathMTUFor(test.remote, wantProbeSize)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mtu, pathErr := stack.PathMTU(test.remote); pathErr != nil || mtu != wantProbeSize {
				t.Fatalf("confirmed UDP PMTU = %d, %v, want %d", mtu, pathErr, wantProbeSize)
			}
		})
	}
}

func TestUDPPathMTUConfirmationCanRaiseExpiredBaseline(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.150")
	remote := netip.MustParseAddr("192.0.2.151")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if !stack.observePathMTU(remote, 1000) {
		t.Fatal("initial path MTU was not recorded")
	}
	stack.pathMTUMu.Lock()
	entry := stack.pathMTU[remote]
	entry.updated = time.Now().Add(-pathMTULifetime)
	stack.pathMTU[remote] = entry
	stack.pathMTUMu.Unlock()
	if err = stack.ConfirmPathMTU(remote, 1200); err != nil {
		t.Fatalf("confirming above expired baseline: %v", err)
	}
	if mtu, pathErr := stack.PathMTU(remote); pathErr != nil || mtu != 1200 {
		t.Fatalf("confirmed path MTU = %d, %v, want 1200", mtu, pathErr)
	}
}

func TestMarshalUDPDatagramOverwritesReusedBuffer(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.243")
	target := netip.MustParseAddr("198.51.100.243")
	payload := []byte("reused UDP datagram")
	want := make([]byte, udpHeaderSize+len(payload))
	marshalUDPDatagram(want, source, target, 49152, 5353, payload)
	dirty := make([]byte, len(want))
	for index := range dirty {
		dirty[index] = 0xff
	}
	marshalUDPDatagram(dirty, source, target, 49152, 5353, payload)
	if !bytes.Equal(dirty, want) {
		t.Fatalf("reused UDP datagram differs:\n got %x\nwant %x", dirty, want)
	}
}

func BenchmarkUDPDatagramRoundTrip(b *testing.B) {
	link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.241"), netip.MustParseAddr("198.51.100.241"))
	link.mu.Lock()
	link.echoUDP = true
	link.mu.Unlock()
	connection, err := stack.DialUDP(context.Background(), "udp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 5353))
	if err != nil {
		b.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	response := make([]byte, len(payload))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err = connection.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err = connection.Read(response); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPFragmentedDatagramOutput(b *testing.B) {
	for _, test := range []struct {
		name           string
		source, target netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.245"), netip.MustParseAddr("198.51.100.245")},
		{"IPv6", netip.MustParseAddr("2001:db8::245"), netip.MustParseAddr("2001:db8:1::245")},
	} {
		b.Run(test.name, func(b *testing.B) {
			bits := 32
			if test.source.Is6() {
				bits = 128
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.source, bits)}, MTU: 1280})
			if err != nil {
				b.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				b.Fatal(err)
			}
			defer stack.Close()
			connection := newUDPConn(stack, "udp", 49152, test.source.Is6(), test.source, netip.AddrPort{})
			payload := bytes.Repeat([]byte{0x6d}, 60*1024)
			maximum := (1280 - 20) &^ 7
			if test.source.Is6() {
				maximum = (1280 - 48) &^ 7
			}
			fragments := (udpHeaderSize + len(payload) + maximum - 1) / maximum
			drain := func() {
				for index := 0; index < fragments; index++ {
					entry, ok := waitTestPacketEntry(&stack.outbound, time.Second)
					if !ok {
						b.Fatal("timed out waiting for UDP fragment")
					}
					stack.outbound.release(entry)
				}
			}
			if err = connection.writeDatagramForMTU(test.source, test.target, 49152, 5353, payload, ipPacketOptions{}, true, 1280); err != nil {
				b.Fatal(err)
			}
			drain()
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err = connection.writeDatagramForMTU(test.source, test.target, 49152, 5353, payload, ipPacketOptions{}, true, 1280); err != nil {
					b.Fatal(err)
				}
				drain()
			}
		})
	}
}

func TestUDPConcurrentReadersReuseBoundedTimers(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.242")
	remote := netip.MustParseAddrPort("198.51.100.242:5353")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote)
	defer connection.closeFromStack()
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	const readers = 8
	start := make(chan struct{})
	results := make(chan byte, readers)
	for index := 0; index < readers; index++ {
		go func() {
			<-start
			buffer := make([]byte, 1)
			n, readErr := connection.Read(buffer)
			if readErr != nil || n != 1 {
				results <- 0xff
				return
			}
			results <- buffer[0]
		}()
	}
	close(start)
	for value := byte(0); value < readers; value++ {
		connection.enqueue([]byte{value}, remote, local, ipPacketOptions{})
	}
	seen := make(map[byte]struct{}, readers)
	for index := 0; index < readers; index++ {
		select {
		case value := <-results:
			if value == 0xff {
				t.Fatal("concurrent UDP read failed")
			}
			seen[value] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent UDP readers did not make progress")
		}
	}
	if len(seen) != readers {
		t.Fatalf("concurrent UDP reads received %d distinct datagrams", len(seen))
	}
}

func TestUDPDialNetworkValidation(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.121")
	remote := netip.MustParseAddrPort("198.51.100.121:53")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if _, err = stack.DialUDP(context.Background(), "tcp", netip.AddrPort{}, remote); err == nil {
		t.Fatal("DialUDP with TCP network succeeded")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("DialUDP unknown network error = %v", err)
		}
	}
	if _, err = stack.DialUDP(context.Background(), "udp6", netip.AddrPort{}, remote); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("DialUDP family mismatch = %v, want EAFNOSUPPORT", err)
	}
}

// TestConnectedUDP exchanges datagrams through net.Conn and verifies that a
// connected socket rejects WriteTo and filters packets from another tuple.
func TestConnectedUDP(t *testing.T) {
	for _, test := range []struct {
		name         string
		client, peer netip.Addr
	}{
		{name: "IPv4", client: netip.MustParseAddr("192.0.2.1"), peer: netip.MustParseAddr("192.0.2.2")},
		{name: "IPv6", client: netip.MustParseAddr("2001:db8::1"), peer: netip.MustParseAddr("2001:db8::2")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, peer := newStackPair(t, test.client, test.peer, 1400)
			_ = newStackBridge(t, client, peer)
			receiver, err := peer.ListenUDP(context.Background(), `udp`, wildcardUDP(test.client))
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			remote := netip.AddrPortFrom(test.peer, uint16(receiver.LocalAddr().(*net.UDPAddr).Port))
			connection, err := client.DialUDP(context.Background(), "udp", netip.AddrPort{}, remote)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if connection.LocalAddr().(*net.UDPAddr).AddrPort().Addr() != test.client || connection.RemoteAddr().(*net.UDPAddr).AddrPort() != remote {
				t.Fatalf("connected addresses = %v -> %v", connection.LocalAddr(), connection.RemoteAddr())
			}
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			payload := []byte("connected UDP")
			if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
				t.Fatalf("Write = %d, %v", n, writeErr)
			}
			buffer := make([]byte, 64)
			n, source, err := receiver.ReadFrom(buffer)
			if err != nil || !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("ReadFrom = %q, %v", buffer[:n], err)
			}
			if _, err = receiver.WriteTo([]byte("reply"), source); err != nil {
				t.Fatal(err)
			}
			n, err = connection.Read(buffer)
			if err != nil || string(buffer[:n]) != "reply" {
				t.Fatalf("Read = %q, %v", buffer[:n], err)
			}
			udpConnection := connection.(*UDPConn)
			if _, err = udpConnection.WriteTo(payload, net.UDPAddrFromAddrPort(remote)); err == nil {
				t.Fatal("WriteTo on connected UDP succeeded")
			} else {
				checkNetOpError(t, err, "write", udpConnection.net)
			}

			spoof, err := peer.ListenUDP(context.Background(), `udp`, wildcardUDP(test.client))
			if err != nil {
				t.Fatal(err)
			}
			defer spoof.Close()
			clientEndpoint := connection.LocalAddr().(*net.UDPAddr).AddrPort()
			if _, err = spoof.WriteTo([]byte("spoof"), net.UDPAddrFromAddrPort(clientEndpoint)); err != nil {
				t.Fatal(err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			if _, err = connection.Read(buffer); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("spoof-filter Read error = %v", err)
			}
		})
	}
}

// TestUDPWriteDeadlineInterruptsFullQueue verifies that changing a deadline
// wakes a WriteTo already blocked on the packet-device queue.
func TestUDPWriteDeadlineInterruptsFullQueue(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(netip.MustParseAddr("192.0.2.2")))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	fillTestPacketQueue(t, &stack.outbound, []byte{0})
	if err = connection.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddrPort("192.0.2.2:53")
	done := make(chan error, 1)
	go func() {
		_, writeErr := connection.WriteTo([]byte("query"), net.UDPAddrFromAddrPort(target))
		done <- writeErr
	}()
	time.Sleep(20 * time.Millisecond)
	if err = connection.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("WriteTo error = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WriteTo did not observe changed deadline")
	}
	if connection.(*UDPConn).acceptsError(target) {
		t.Fatal("failed UDP write retained an ICMP correlation target")
	}
}

func TestUDPBindingAndExplicitSource(t *testing.T) {
	firstAddress := netip.MustParseAddr("192.0.2.10")
	secondAddress := netip.MustParseAddr("192.0.2.11")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(firstAddress, 32),
		netip.PrefixFrom(secondAddress, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	const sharedPort = 45000
	first, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(firstAddress, sharedPort))
	if err != nil {
		t.Fatal(err)
	}
	second, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(secondAddress, sharedPort))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(netip.IPv4Unspecified(), sharedPort)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("wildcard overlapping exact UDP bindings = %v, want EADDRINUSE", err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}

	source := netip.AddrPortFrom(secondAddress, 45001)
	remote := netip.MustParseAddrPort("198.51.100.20:53")
	connected, err := stack.DialUDP(context.Background(), "udp", source, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	if got := connected.LocalAddr().(*net.UDPAddr).AddrPort(); got != source {
		t.Fatalf("DialUDP local endpoint = %v, want %v", got, source)
	}
	if _, err = stack.DialUDP(context.Background(), "udp", source, remote); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("duplicate explicit UDP source = %v, want EADDRINUSE", err)
	}
}

func TestUDPReadAfterCloseDiscardsQueuedDatagram(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.91")
	remote := netip.MustParseAddr("198.51.100.91")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50002))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50003, 50002, []byte("queued"))); err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = connection.ReadFrom(make([]byte, 16)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close = %v, want net.ErrClosed", err)
	}
}

func TestUDPReceiveBufferCapacity(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.92")
	remote := netip.MustParseAddr("198.51.100.92")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50002))
	if err != nil {
		t.Fatal(err)
	}
	udpConnection := connection.(*UDPConn)
	if err = udpConnection.SetReadBuffer(2 * (udpDatagramMetadataSize + 1)); err != nil {
		t.Fatal(err)
	}
	if err = udpConnection.SetReadBuffer(0); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SetReadBuffer(0) = %v, want EINVAL", err)
	}
	for index := 0; index < 3; index++ {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, uint16(50003+index), 50002, []byte{byte(index)})); err != nil {
			t.Fatal(err)
		}
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("receive-capacity drops = %d, want 1", dropped)
	}
	for index := 0; index < 2; index++ {
		buffer := make([]byte, 1)
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || n != 1 || buffer[0] != byte(index) {
			t.Fatalf("ReadFrom %d = %x, %v", index, buffer[:n], readErr)
		}
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = udpConnection.SetReadBuffer(1024); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetReadBuffer after Close = %v, want net.ErrClosed", err)
	}
}

func TestUDPReceiveBufferHasNoPacketCountLimit(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.94")
	remote := netip.MustParseAddr("198.51.100.94")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50004))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	const datagrams = 300
	for index := 0; index < datagrams; index++ {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, 50005, 50004, []byte{byte(index)})); err != nil {
			t.Fatal(err)
		}
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 0 {
		t.Fatalf("small-datagram drops = %d, want 0", dropped)
	}
	for index := 0; index < datagrams; index++ {
		buffer := make([]byte, 1)
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || n != 1 || buffer[0] != byte(index) {
			t.Fatalf("ReadFrom %d = %x, %v", index, buffer[:n], readErr)
		}
	}
}

func TestUDPConcurrentReaders(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.95")
	remote := netip.MustParseAddr("198.51.100.95")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50006))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const readers = 64
	results := make(chan int, readers)
	for index := 0; index < readers; index++ {
		go func() {
			buffer := make([]byte, 1)
			n, _, readErr := connection.ReadFrom(buffer)
			if readErr != nil || n != 1 {
				results <- -1
				return
			}
			results <- int(buffer[0])
		}()
	}
	for index := 0; index < readers; index++ {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, 50007, 50006, []byte{byte(index)})); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[int]bool, readers)
	for index := 0; index < readers; index++ {
		value := <-results
		if value < 0 || seen[value] {
			t.Fatalf("concurrent ReadFrom result %d = %d, already seen = %v", index, value, seen[value])
		}
		seen[value] = true
	}
}

func TestUDPTypedMethods(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.96")
	remote := netip.MustParseAddr("198.51.100.96")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50008))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()

	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50009, 50008, []byte("udpaddr"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, source, err := connection.ReadFromUDP(buffer)
	if err != nil || string(buffer[:n]) != "udpaddr" || source.AddrPort() != netip.AddrPortFrom(remote, 50009) {
		t.Fatalf("ReadFromUDP = %q from %v, %v", buffer[:n], source, err)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50010, 50008, []byte("addrport"))); err != nil {
		t.Fatal(err)
	}
	n, sourcePort, err := connection.ReadFromUDPAddrPort(buffer)
	if err != nil || string(buffer[:n]) != "addrport" || sourcePort != netip.AddrPortFrom(remote, 50010) {
		t.Fatalf("ReadFromUDPAddrPort = %q from %v, %v", buffer[:n], sourcePort, err)
	}
	if _, err = connection.WriteToUDP([]byte("typed"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 50011))); err != nil {
		t.Fatal(err)
	}
	if packet, ok := parseIPPacket(readOutboundPacket(t, stack)); !ok || packet.source != local || string(packet.payload[udpHeaderSize:]) != "typed" {
		t.Fatalf("WriteToUDP packet = source %v payload %q, parsed = %v", packet.source, packet.payload, ok)
	}
	if _, err = connection.WriteToUDPAddrPort([]byte("typed-port"), netip.AddrPortFrom(remote, 50012)); err != nil {
		t.Fatal(err)
	}
	if packet, ok := parseIPPacket(readOutboundPacket(t, stack)); !ok || packet.source != local || string(packet.payload[udpHeaderSize:]) != "typed-port" {
		t.Fatalf("WriteToUDPAddrPort packet = source %v payload %q, parsed = %v", packet.source, packet.payload, ok)
	}
}

func TestUDPMessagePacketInfoRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name          string
		first, second netip.Addr
		remote        netip.Addr
		controlSize   int
	}{
		{name: "IPv4", first: netip.MustParseAddr("192.0.2.97"), second: netip.MustParseAddr("192.0.2.98"), remote: netip.MustParseAddr("198.51.100.97"), controlSize: 80},
		{name: "IPv6", first: netip.MustParseAddr("2001:db8::97"), second: netip.MustParseAddr("2001:db8::98"), remote: netip.MustParseAddr("2001:db8:1::97"), controlSize: 88},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := test.first.BitLen()
			stack, err := New(Config{LocalAddresses: []netip.Prefix{
				netip.PrefixFrom(test.first, bits), netip.PrefixFrom(test.second, bits),
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			packetConnection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(wildcardUDP(test.first).Addr(), 50013))
			if err != nil {
				t.Fatal(err)
			}
			connection := packetConnection.(*UDPConn)
			defer connection.Close()
			if err = writeTestPacket(stack, buildTestUDP(test.remote, test.second, 50014, 50013, []byte("request"))); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 3)
			oob := make([]byte, 128)
			n, oobn, flags, source, err := connection.ReadMsgUDPAddrPort(buffer, oob)
			if err != nil || n != 3 || string(buffer) != "req" || source != netip.AddrPortFrom(test.remote, 50014) {
				t.Fatalf("ReadMsgUDPAddrPort = %q, %d oob, flags %#x, source %v, %v", buffer[:n], oobn, flags, source, err)
			}
			if oobn != test.controlSize || flags != linuxMessageTruncated {
				t.Fatalf("packet info size/flags = %d/%#x, want %d/%#x", oobn, flags, test.controlSize, linuxMessageTruncated)
			}
			if test.first.Is4() {
				var message IPv4ControlMessage
				if parseErr := message.Parse(oob[:oobn]); parseErr != nil || message.Dst != test.second {
					t.Fatalf("IPv4 packet info = %+v, %v, want destination %v", message, parseErr, test.second)
				}
			} else {
				var message IPv6ControlMessage
				if parseErr := message.Parse(oob[:oobn]); parseErr != nil || message.Dst != test.second {
					t.Fatalf("IPv6 packet info = %+v, %v, want destination %v", message, parseErr, test.second)
				}
			}
			n, oobWritten, err := connection.WriteMsgUDPAddrPort([]byte("reply"), oob[:oobn], netip.AddrPortFrom(test.remote, 50014))
			if err != nil || n != 5 || oobWritten != oobn {
				t.Fatalf("WriteMsgUDPAddrPort = %d/%d, %v", n, oobWritten, err)
			}
			packet, ok := parseIPPacket(readOutboundPacket(t, stack))
			if !ok || packet.source != test.second || packet.target != test.remote || string(packet.payload[udpHeaderSize:]) != "reply" {
				t.Fatalf("message packet = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
			}
		})
	}
}

func TestUDPMessageControlValidationAndWriteBuffer(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.99")
	remote := netip.MustParseAddr("198.51.100.99")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50015))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	if err = connection.SetWriteBuffer(64 * 1024); err != nil {
		t.Fatalf("SetWriteBuffer no-op = %v", err)
	}
	if err = connection.SetWriteBuffer(0); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SetWriteBuffer(0) = %v, want EINVAL", err)
	}
	control := appendLinuxPacketInfoControl(nil, local)
	binary.LittleEndian.PutUint32(control[16:20], 1)
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("bad"), control, netip.AddrPortFrom(remote, 50016)); err == nil {
		t.Fatal("WriteMsgUDPAddrPort accepted a nonzero interface index")
	}
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("bad"), control[:10], netip.AddrPortFrom(remote, 50016)); err == nil {
		t.Fatal("WriteMsgUDPAddrPort accepted a truncated control message")
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50016, 50015, []byte("control"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	oob := make([]byte, 8)
	_, oobn, flags, _, err := connection.ReadMsgUDPAddrPort(buffer, oob)
	if err != nil || oobn != len(oob) || flags != linuxMessageControlTruncated {
		t.Fatalf("control truncation = oob %d flags %#x, %v", oobn, flags, err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetWriteBuffer(1024); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetWriteBuffer after Close = %v, want net.ErrClosed", err)
	}
}

func TestUDPIPv6FlowLabelPolicy(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::190")
	remote := netip.MustParseAddr("2001:db8::191")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp6", netip.AddrPortFrom(netip.IPv6Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()
	target := netip.AddrPortFrom(remote, 5353)
	writeAndLabel := func(oob []byte) uint32 {
		t.Helper()
		if oob == nil {
			_, err = connection.WriteToUDPAddrPort([]byte("flow"), target)
		} else {
			_, _, err = connection.WriteMsgUDPAddrPort([]byte("flow"), oob, target)
		}
		if err != nil {
			t.Fatal(err)
		}
		packet, ok := parseIPPacket(readOutboundPacket(t, stack))
		if !ok {
			t.Fatal("failed to parse IPv6 UDP output")
		}
		return packet.flowLabel
	}
	automatic := writeAndLabel(nil)
	second := writeAndLabel(nil)
	if automatic == 0 || second != automatic {
		t.Fatalf("automatic UDP flow labels = %#x then %#x", automatic, second)
	}
	if err = connection.SetFlowLabel(0x12345); err != nil {
		t.Fatal(err)
	}
	if label := writeAndLabel(nil); label != 0x12345 {
		t.Fatalf("socket UDP flow label = %#x, want 0x12345", label)
	}
	oob, err := (&IPv6ControlMessage{FlowLabel: 0x54321}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if label := writeAndLabel(oob); label != 0x54321 {
		t.Fatalf("per-packet UDP flow label = %#x, want 0x54321", label)
	}
	if err = connection.SetFlowLabel(0); err != nil {
		t.Fatal(err)
	}
	if label := writeAndLabel(nil); label != 0 {
		t.Fatalf("explicit zero UDP flow label = %#x", label)
	}
	if info := connection.Info(); info.FlowLabel != 0 {
		t.Fatalf("UDP flow-label diagnostics = %+v", info)
	}
}

func TestUDPMessageIPv6ZeroHopLimit(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::99")
	remote := netip.MustParseAddr("2001:db8:1::99")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp6", netip.AddrPortFrom(local, 50017))
	if err != nil {
		t.Fatal(err)
	}
	connection := packetConnection.(*UDPConn)
	defer connection.Close()
	if err = connection.SetHopLimit(0); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.WriteToUDPAddrPort([]byte("default-zero"), netip.AddrPortFrom(remote, 50018)); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.hopLimit != 0 || packet.target != remote {
		t.Fatalf("IPv6 default zero hop-limit packet = target %v hop %d, parsed = %v", packet.target, packet.hopLimit, ok)
	}
	control := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6HopLimit, 0)
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("zero"), control, netip.AddrPortFrom(remote, 50018)); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.hopLimit != 0 || packet.target != remote {
		t.Fatalf("IPv6 zero hop-limit packet = target %v hop %d, parsed = %v", packet.target, packet.hopLimit, ok)
	}
}

func TestUDPZeroHopLimitFamilyValidation(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.MustParsePrefix("192.0.2.99/32"), netip.MustParsePrefix("2001:db8::99/128"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	for _, test := range []struct {
		name, network string
		local         netip.AddrPort
	}{
		{name: "IPv4", network: "udp4", local: netip.MustParseAddrPort("192.0.2.99:50019")},
		{name: "dual stack", network: "udp", local: netip.AddrPort{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			packetConnection, listenErr := stack.ListenUDP(context.Background(), test.network, test.local)
			if listenErr != nil {
				t.Fatal(listenErr)
			}
			defer packetConnection.Close()
			if setErr := packetConnection.(*UDPConn).SetHopLimit(0); setErr == nil {
				t.Fatal("SetHopLimit(0) succeeded")
			}
		})
	}
}

func TestUDPConnectedMessageMethods(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.100")
	remote := netip.MustParseAddr("198.51.100.100")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	netConnection, err := stack.DialUDP(context.Background(), "udp", netip.AddrPort{}, netip.AddrPortFrom(remote, 50017))
	if err != nil {
		t.Fatal(err)
	}
	connection := netConnection.(*UDPConn)
	defer connection.Close()
	n, oobn, err := connection.WriteMsgUDP([]byte("connected"), nil, nil)
	if err != nil || n != 9 || oobn != 0 {
		t.Fatalf("connected WriteMsgUDP = %d/%d, %v", n, oobn, err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.source != local || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "connected" {
		t.Fatalf("connected message packet = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
	if _, _, err = connection.WriteMsgUDP([]byte("bad"), nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(remote, 50017))); err == nil {
		t.Fatal("connected WriteMsgUDP accepted an explicit destination")
	}
	if n, oobn, writeErr := connection.WriteMsgUDPAddrPort([]byte("netip"), nil, netip.AddrPort{}); writeErr != nil || n != 5 || oobn != 0 {
		t.Fatalf("connected WriteMsgUDPAddrPort = %d/%d, %v", n, oobn, writeErr)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.source != local || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "netip" {
		t.Fatalf("connected netip message packet = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
	if _, _, err = connection.WriteMsgUDPAddrPort([]byte("bad"), nil, netip.AddrPortFrom(remote, 50017)); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected WriteMsgUDPAddrPort with destination = %v, want net.ErrWriteToConnected", err)
	}
	localPort := connection.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50017, localPort, []byte("reply"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	oob := make([]byte, 96)
	n, oobn, flags, source, err := connection.ReadMsgUDP(buffer, oob)
	if err != nil || n != 5 || string(buffer[:n]) != "reply" || oobn != 80 || flags != 0 || source.AddrPort() != netip.AddrPortFrom(remote, 50017) {
		t.Fatalf("connected ReadMsgUDP = %q/%d flags %#x from %v, %v", buffer[:n], oobn, flags, source, err)
	}
}

func TestUDPUnconnectedMessageRequiresDestination(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.101")
	remote := netip.MustParseAddr("198.51.100.101")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, _, err = connection.(*UDPConn).WriteMsgUDPAddrPort([]byte("missing"), nil, netip.AddrPort{}); err == nil {
		t.Fatal("unconnected WriteMsgUDPAddrPort accepted an invalid destination")
	} else {
		checkNetOpError(t, err, "write", "udp4")
	}
	if _, err = connection.WriteTo([]byte("invalid"), testUDPStringAddress("not-an-address")); err == nil {
		t.Fatal("unconnected WriteTo accepted an invalid generic destination")
	} else {
		checkNetOpError(t, err, "write", "udp4")
	}
	address := testUDPStringAddress(netip.AddrPortFrom(remote, 50018).String())
	if n, writeErr := connection.WriteTo([]byte("generic"), address); writeErr != nil || n != 7 {
		t.Fatalf("WriteTo generic UDP address = %d, %v", n, writeErr)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.source != local || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "generic" {
		t.Fatalf("generic UDP packet = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
}

func TestUDPOversizedWriteReturnsMessageTooLong(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.93")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.DialUDP(context.Background(), "udp", netip.AddrPort{}, netip.MustParseAddrPort("198.51.100.93:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if n, writeErr := connection.Write(make([]byte, 65535-20-udpHeaderSize)); writeErr != nil || n != 65535-20-udpHeaderSize {
		t.Fatalf("maximum IPv4 UDP Write = %d, %v", n, writeErr)
	}
	if _, err = connection.Write(make([]byte, 65536-20-udpHeaderSize)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("IPv4 UDP Write above 65507 bytes = %v, want EMSGSIZE", err)
	}
	if _, err = connection.Write(make([]byte, 65536-udpHeaderSize)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversized UDP Write = %v, want EMSGSIZE", err)
	}
}

// TestUnconnectedUDPReadAndConnectedWriteToError matches the standard
// UDPConn behavior for its net.Conn and destination-specific methods.
func TestUnconnectedUDPReadAndConnectedWriteToError(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.94")
	remote := netip.MustParseAddr("198.51.100.94")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(local, 54000))
	if err != nil {
		t.Fatal(err)
	}
	listener := packetConnection.(*UDPConn)
	defer listener.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 54001, 54000, []byte("read"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if n, readErr := listener.Read(buffer); readErr != nil || n != 4 || string(buffer) != "read" {
		t.Fatalf("unconnected UDP Read = %q, %v", buffer[:n], readErr)
	}
	connected, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 54002))
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	if _, err = connected.(*UDPConn).WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(remote, 54003)); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected UDP WriteTo = %v, want net.ErrWriteToConnected", err)
	}
}

// TestUDPIPv4MappedNetAddrWrites verifies the common net.ParseIP address
// representation across the generic PacketConn and message APIs.
func TestUDPIPv4MappedNetAddrWrites(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.96")
	remote := netip.MustParseAddr("198.51.100.96")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packetConnection, err := stack.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer packetConnection.Close()
	target := &net.UDPAddr{IP: net.ParseIP(remote.String()), Port: 56000}
	if _, err = packetConnection.WriteTo([]byte("packet"), target); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "packet" {
		t.Fatalf("mapped PacketConn write = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
	if _, _, err = packetConnection.(*UDPConn).WriteMsgUDP([]byte("message"), nil, target); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.target != remote || string(packet.payload[udpHeaderSize:]) != "message" {
		t.Fatalf("mapped WriteMsgUDP = %v -> %v payload %q, parsed = %v", packet.source, packet.target, packet.payload, ok)
	}
}

func TestUDPDefaultsAndDiagnostics(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.134")
	remote := netip.MustParseAddr("192.0.2.135")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400,
		UDP: DatagramSocketDefaults{ReceiveBuffer: 2048, HopLimit: 31, TrafficClass: 0xb8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 5353))
	if err != nil {
		t.Fatal(err)
	}
	udp := connection.(*UDPConn)
	if err = udp.SetHopLimit(37); err != nil {
		t.Fatal(err)
	}
	if err = udp.SetTrafficClass(0x2e); err != nil {
		t.Fatal(err)
	}
	if _, err = udp.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.hopLimit != 37 || packet.trafficClass != 0x2e {
		t.Fatalf("UDP output options = hop %d class %#x", packet.hopLimit, packet.trafficClass)
	}
	zeroClass := appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTypeOfService, 0)
	if _, _, err = udp.WriteMsgUDP([]byte("zero"), zeroClass, nil); err != nil {
		t.Fatal(err)
	}
	packet, ok = parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.hopLimit != 37 || packet.trafficClass != 0 {
		t.Fatalf("UDP explicit zero traffic class = hop %d class %#x", packet.hopLimit, packet.trafficClass)
	}
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 5353, udp.port, []byte("answer"))); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if n, readErr := udp.Read(buffer); readErr != nil || string(buffer[:n]) != "answer" {
		t.Fatalf("UDP Read = %q, %v", buffer[:n], readErr)
	}
	if err = udp.SetReadBuffer(udpDatagramMetadataSize); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if err = writeTestPacket(stack, buildTestUDP(remote, local, 5353, udp.port, nil)); err != nil {
			t.Fatal(err)
		}
	}
	info := udp.Info()
	if info.PacketsSent != 2 || info.BytesSent != 9 || info.PacketsReceived != 2 || info.BytesReceived != 6 ||
		info.PacketsDropped != 1 || info.ReceiveQueuePackets != 1 || info.ReceiveQueueBytes != udpDatagramMetadataSize ||
		info.ReceiveQueueCapacity != udpDatagramMetadataSize || info.PathMTU != 1400 || info.HopLimit != 37 || info.TrafficClass != 0x2e {
		t.Fatalf("UDP Info = %+v", info)
	}
}

func BenchmarkUDPReceiveQueue(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.243")
	remote := netip.MustParseAddrPort("198.51.100.243:5353")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		b.Fatal(err)
	}
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote)
	b.Cleanup(connection.closeFromStack)
	payload := bytes.Repeat([]byte{0x5a}, 1200)
	buffer := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		connection.enqueue(payload, remote, local, ipPacketOptions{})
		if n, _, _, _, _, readErr := connection.readDatagram(buffer); readErr != nil || n != len(payload) {
			b.Fatalf("readDatagram = %d, %v", n, readErr)
		}
	}
}

func TestUDPReceivePayloadSpareIsBoundedAndReleased(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.247")
	remote := netip.MustParseAddrPort("198.51.100.247:5353")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newUDPConn(stack, "udp4", 5300, false, local, remote)
	read := func(payload []byte) {
		connection.enqueue(payload, remote, local, ipPacketOptions{})
		buffer := make([]byte, len(payload))
		if n, _, _, _, _, readErr := connection.readDatagram(buffer); readErr != nil || n != len(payload) || !bytes.Equal(buffer, payload) {
			t.Fatalf("readDatagram = %d bytes, %v", n, readErr)
		}
	}
	read(make([]byte, 1200))
	connection.mu.Lock()
	spareCapacity := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if spareCapacity < 1200 || spareCapacity > datagramReusablePayloadLimit {
		t.Fatalf("receive spare capacity = %d", spareCapacity)
	}
	read(make([]byte, datagramReusablePayloadLimit+1))
	connection.mu.Lock()
	retainedAfterJumbo := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if retainedAfterJumbo != spareCapacity {
		t.Fatalf("jumbo read changed receive spare capacity from %d to %d", spareCapacity, retainedAfterJumbo)
	}
	connection.closeFromStack()
	connection.mu.Lock()
	retainedAfterClose := cap(connection.receiveSpare)
	connection.mu.Unlock()
	if retainedAfterClose != 0 {
		t.Fatalf("closed socket retained receive spare capacity %d", retainedAfterClose)
	}
}

// TestUDPImpairedLinkLatencyAndLoss verifies propagation delay, jitter-driven
// reordering, and deterministic independent loss at the packet-device boundary.
func TestUDPImpairedLinkLatencyAndLoss(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.211")
	serverAddress := netip.MustParseAddr("192.0.2.212")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	link := newTestImpairedLink(t, client, server, testLinkConditions{
		Seed:         7123,
		ClientToPeer: testLinkCondition{Latency: 30 * time.Millisecond, Jitter: 5 * time.Millisecond, LossRate: 0.2},
	})
	serverSocket, err := server.ListenUDP(context.Background(), "udp4", netip.AddrPortFrom(serverAddress, 46000))
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocket.Close()
	clientSocket, err := client.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 46000))
	if err != nil {
		t.Fatal(err)
	}
	defer clientSocket.Close()
	started := time.Now()
	for sequence := uint32(0); sequence < 64; sequence++ {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, sequence)
		if _, err = clientSocket.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, time.Second, func() bool { return link.Stats(0).Packets == 64 })
	scheduled := link.Stats(0)
	wantReceived := int(scheduled.Packets - scheduled.RandomDrops - scheduled.QueueDrops)
	_ = serverSocket.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4)
	received := 0
	firstDelivery := time.Duration(0)
	lastSequence := uint32(0)
	reordered := false
	for received < wantReceived {
		_, _, err = serverSocket.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if received == 0 {
			firstDelivery = time.Since(started)
		}
		sequence := binary.BigEndian.Uint32(buffer)
		if received != 0 && sequence < lastSequence {
			reordered = true
		}
		lastSequence = sequence
		received++
	}
	stats := link.Stats(0)
	if stats.RandomDrops == 0 || received == 0 || received >= 64 || stats.Delivered != uint64(received) {
		t.Fatalf("UDP impairment = received %d, stats %+v", received, stats)
	}
	if firstDelivery < 20*time.Millisecond {
		t.Fatalf("first UDP delivery after %v, want propagation delay", firstDelivery)
	}
	if !reordered {
		t.Fatal("UDP jitter did not exercise packet reordering")
	}
}
