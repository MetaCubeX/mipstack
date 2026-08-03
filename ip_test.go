package mipstack

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestIPConnFanoutAndLinuxControl(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		controlSize   int
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.110"), remote: netip.MustParseAddr("198.51.100.110"), controlSize: 80},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::110"), remote: netip.MustParseAddr("2001:db8:1::110"), controlSize: 88},
	} {
		t.Run(test.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, test.local.BitLen())}})
			if err != nil {
				t.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			network := "ip4:99"
			if test.local.Is6() {
				network = "ip6:99"
			}
			exact, err := stack.ListenIP(context.Background(), network, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer exact.Close()
			wildcard := netip.IPv4Unspecified()
			if test.local.Is6() {
				wildcard = netip.IPv6Unspecified()
			}
			all, err := stack.ListenIP(context.Background(), network, wildcard)
			if err != nil {
				t.Fatal(err)
			}
			defer all.Close()
			options := ipPacketOptions{hopLimit: 37, trafficClass: 0xb9}
			packet := buildIPPacketWithOptions(test.remote, test.local, 99, []byte("raw-payload"), 7, true, options)
			if err = writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 32)
			n, source, err := exact.ReadFromIP(buffer)
			if err != nil || string(buffer[:n]) != "raw-payload" || !source.IP.Equal(net.IP(test.remote.AsSlice())) {
				t.Fatalf("ReadFromIP = %q from %v, %v", buffer[:n], source, err)
			}
			short := make([]byte, 3)
			oob := make([]byte, 96)
			n, oobn, flags, source, err := all.ReadMsgIP(short, oob)
			if err != nil || n != len(short) || string(short) != "raw" || flags != linuxMessageTruncated || oobn != test.controlSize {
				t.Fatalf("ReadMsgIP = %q/%d flags %#x from %v, %v", short[:n], oobn, flags, source, err)
			}
			if test.local.Is4() {
				var message IPv4ControlMessage
				if controlErr := message.Parse(oob[:oobn]); controlErr != nil || message != (IPv4ControlMessage{TTL: 37, TOS: 0xb9, Dst: test.local}) {
					t.Fatalf("IPv4 control = %+v, %v", message, controlErr)
				}
			} else {
				var message IPv6ControlMessage
				if controlErr := message.Parse(oob[:oobn]); controlErr != nil || message != (IPv6ControlMessage{HopLimit: 37, TrafficClass: 0xb9, Dst: test.local}) {
					t.Fatalf("IPv6 control = %+v, %v", message, controlErr)
				}
			}
			if stats := stack.Stats(); stats.ActiveIPSockets != 2 {
				t.Fatalf("active IP sockets = %d, want 2", stats.ActiveIPSockets)
			}
			if len(stack.outbound) != 0 {
				t.Fatal("raw-consumed protocol generated Protocol Unreachable")
			}
		})
	}
}

func TestIPNetworkAPI(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.122")
	local6 := netip.MustParseAddr("2001:db8::122")
	remote4 := netip.MustParseAddr("198.51.100.122")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(local4, 32),
		netip.PrefixFrom(local6, 128),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	listener, err := stack.ListenIP(context.Background(), "ip4:UDP", local4)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := stack.DialIP(context.Background(), "ip:99", netip.Addr{}, remote4)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := connection.(*IPConn); !ok {
		t.Fatalf("DialIP connection type = %T", connection)
	}
	_ = connection.Close()
	if _, err = stack.ListenIP(context.Background(), "ip6:udp", local4); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("ListenIP family mismatch = %v, want EAFNOSUPPORT", err)
	}
	if _, err = stack.DialIP(context.Background(), "ip4", netip.Addr{}, remote4); err == nil {
		t.Fatal("DialIP without protocol succeeded")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("DialIP unknown network error = %v", err)
		}
	}
	if _, err = stack.DialIP(context.Background(), "ip4:not-a-protocol", netip.Addr{}, remote4); err == nil {
		t.Fatal("DialIP with unknown protocol succeeded")
	} else {
		var addressError *net.AddrError
		if !errors.As(err, &addressError) {
			t.Fatalf("DialIP unknown protocol error = %v", err)
		}
	}
}

// TestListenIPEmptyAddressDualStack verifies net.ListenIP-compatible wildcard
// normalization and delivery for both managed address families.
func TestListenIPEmptyAddressDualStack(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.123")
	local6 := netip.MustParseAddr("2001:db8::123")
	remote4 := netip.MustParseAddr("198.51.100.123")
	remote6 := netip.MustParseAddr("2001:db8:1::123")
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
	connection, err := stack.ListenIP(context.Background(), "ip:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if !connection.dual || connection.local != netip.IPv6Unspecified() {
		t.Fatalf("generic IP wildcard = %v, dual = %v", connection.local, connection.dual)
	}
	for _, packet := range [][]byte{
		buildIPPacket(remote4, local4, 99, []byte("v4"), 1, true),
		buildIPPacket(remote6, local6, 99, []byte("v6"), 2, true),
	} {
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2)
	for _, want := range []string{"v4", "v6"} {
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || string(buffer[:n]) != want {
			t.Fatalf("dual IP read = %q, %v, want %q", buffer[:n], readErr, want)
		}
	}

	ipv4Only, err := stack.ListenIP(context.Background(), "ip4:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer ipv4Only.Close()
	if ipv4Only.dual || ipv4Only.local != netip.IPv4Unspecified() {
		t.Fatalf("IPv4 IP wildcard = %v, dual = %v", ipv4Only.local, ipv4Only.dual)
	}
}

func TestIPConnObservesUDPWithoutConsumingIt(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.111")
	remote := netip.MustParseAddr("198.51.100.111")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	raw, err := stack.ListenIP(context.Background(), "ip4:udp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	packetSocket, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(local, 50100))
	if err != nil {
		t.Fatal(err)
	}
	defer packetSocket.Close()
	if err = writeTestPacket(stack, buildTestUDP(remote, local, 50101, 50100, []byte("both"))); err != nil {
		t.Fatal(err)
	}
	rawBuffer := make([]byte, 64)
	n, source, err := raw.ReadFromIP(rawBuffer)
	if err != nil || source.String() != remote.String() || n < udpHeaderSize || string(rawBuffer[udpHeaderSize:n]) != "both" {
		t.Fatalf("raw UDP copy = %x from %v, %v", rawBuffer[:n], source, err)
	}
	udpBuffer := make([]byte, 16)
	n, sourceAddr, err := packetSocket.ReadFrom(udpBuffer)
	if err != nil || string(udpBuffer[:n]) != "both" || sourceAddr.String() != netip.AddrPortFrom(remote, 50101).String() {
		t.Fatalf("UDP delivery = %q from %v, %v", udpBuffer[:n], sourceAddr, err)
	}
}

func TestIPConnWriteMsgSourceAndHeaderOptions(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.112")
	second := netip.MustParseAddr("192.0.2.113")
	remote := netip.MustParseAddr("198.51.100.112")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(first, 32), netip.PrefixFrom(second, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	options := ipPacketOptions{hopLimit: 31, trafficClass: 0xb8}
	oob, err := (&IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: second}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	n, oobn, err := connection.WriteMsgIP([]byte("raw-output"), oob, ipNetAddr(remote))
	if err != nil || n != 10 || oobn != len(oob) {
		t.Fatalf("WriteMsgIP = %d/%d, %v", n, oobn, err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.source != second || packet.target != remote || packet.protocol != 99 || packet.hopLimit != options.hopLimit || packet.trafficClass != options.trafficClass || string(packet.payload) != "raw-output" {
		t.Fatalf("raw output = %+v, parsed = %v", packet, ok)
	}
	if err = connection.SetWriteBuffer(64 * 1024); err != nil {
		t.Fatalf("SetWriteBuffer no-op = %v", err)
	}
	if err = connection.SetWriteBuffer(0); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SetWriteBuffer(0) = %v, want EINVAL", err)
	}
}

func TestIPConnTypedWritesAndDeadlines(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.123")
	remote := netip.MustParseAddr("198.51.100.123")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if connection.RemoteAddr() != nil {
		t.Fatalf("unconnected remote address = %v", connection.RemoteAddr())
	}
	if err = connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, writeErr := connection.WriteToIP([]byte("typed"), ipNetAddr(remote)); writeErr != nil || n != len("typed") {
		t.Fatalf("WriteToIP = %d, %v", n, writeErr)
	}
	if packet, ok := parseIPPacket(readOutboundPacket(t, stack)); !ok || string(packet.payload) != "typed" || packet.target != remote {
		t.Fatalf("typed output = %+v, parsed = %v", packet, ok)
	}
	if n, writeErr := connection.WriteTo([]byte("generic"), ipNetAddr(remote)); writeErr != nil || n != len("generic") {
		t.Fatalf("WriteTo = %d, %v", n, writeErr)
	}
	if packet, ok := parseIPPacket(readOutboundPacket(t, stack)); !ok || string(packet.payload) != "generic" || packet.target != remote {
		t.Fatalf("generic output = %+v, parsed = %v", packet, ok)
	}
	if err = connection.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.WriteToIP([]byte("late"), ipNetAddr(remote)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired WriteToIP = %v, want deadline", err)
	}
}

func TestConnectedIPConnAndICMPv6Checksum(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::114")
	remote := netip.MustParseAddr("2001:db8:1::114")
	other := netip.MustParseAddr("2001:db8:1::115")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.DialIP(context.Background(), "ip6:ipv6-icmp", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	payload := []byte{128, 0, 0, 0, 0, 1, 0, 1}
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("connected IP Write = %d, %v", n, writeErr)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || transportChecksum(local, remote, protocolICMPv6, packet.payload) != 0 {
		t.Fatalf("ICMPv6 raw checksum is invalid: %x", packet.payload)
	}
	wrong := buildIPPacket(other, local, protocolICMPv6, []byte{129, 0, 0, 0, 0, 1, 0, 1}, 0, true)
	binaryPayload := wrong[40:]
	binaryPayload[2], binaryPayload[3] = 0, 0
	checksumValue := transportChecksum(other, local, protocolICMPv6, binaryPayload)
	binaryPayload[2], binaryPayload[3] = byte(checksumValue>>8), byte(checksumValue)
	if err = writeTestPacket(stack, wrong); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err = connection.Read(make([]byte, 16)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connected remote filter error = %v, want deadline", err)
	}
	_ = connection.SetReadDeadline(time.Time{})
	reply := buildIPPacket(remote, local, protocolICMPv6, []byte{129, 0, 0, 0, 0, 1, 0, 1}, 0, true)
	replyPayload := reply[40:]
	replyPayload[2], replyPayload[3] = 0, 0
	checksumValue = transportChecksum(remote, local, protocolICMPv6, replyPayload)
	replyPayload[2], replyPayload[3] = byte(checksumValue>>8), byte(checksumValue)
	if err = writeTestPacket(stack, reply); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 16)
	n, err := connection.Read(buffer)
	if err != nil || n != len(replyPayload) || !bytes.Equal(buffer[:n], replyPayload) {
		t.Fatalf("connected IP Read = %x, %v", buffer[:n], err)
	}
}

func TestIPConnFragmentReassembly(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		mtu           uint32
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.116"), remote: netip.MustParseAddr("192.0.2.117"), mtu: 600},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::116"), remote: netip.MustParseAddr("2001:db8::117"), mtu: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newStackPair(t, test.local, test.remote, test.mtu)
			bridge := newStackBridge(t, client, server)
			network := "ip4:99"
			if test.remote.Is6() {
				network = "ip6:99"
			}
			listener, err := server.ListenIP(context.Background(), network, test.remote)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			netConnection, err := client.DialIP(context.Background(), network, netip.Addr{}, test.remote)
			if err != nil {
				t.Fatal(err)
			}
			connection := netConnection.(*IPConn)
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			var oob []byte
			if test.local.Is4() {
				oob, err = (&IPv4ControlMessage{TTL: 29, TOS: 0x2e, Src: test.local}).Marshal()
			} else {
				oob, err = (&IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, Src: test.local}).Marshal()
			}
			if err != nil {
				t.Fatal(err)
			}
			if n, _, writeErr := connection.WriteMsgIP(payload, oob, nil); writeErr != nil || n != len(payload) {
				t.Fatalf("fragmented WriteMsgIP = %d, %v", n, writeErr)
			}
			buffer := make([]byte, len(payload))
			control := make([]byte, 96)
			n, oobn, flags, source, readErr := listener.ReadMsgIP(buffer, control)
			if readErr != nil || n != len(payload) || flags != 0 || !bytes.Equal(buffer, payload) || source.String() != test.local.String() {
				t.Fatalf("reassembled ReadMsgIP = %d flags %#x from %v, %v", n, flags, source, readErr)
			}
			if test.local.Is4() {
				var message IPv4ControlMessage
				if controlErr := message.Parse(control[:oobn]); controlErr != nil || message != (IPv4ControlMessage{TTL: 29, TOS: 0x2e, Dst: test.remote}) {
					t.Fatalf("reassembled IPv4 control = %+v, %v", message, controlErr)
				}
			} else {
				var message IPv6ControlMessage
				if controlErr := message.Parse(control[:oobn]); controlErr != nil || message != (IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, Dst: test.remote}) {
					t.Fatalf("reassembled IPv6 control = %+v, %v", message, controlErr)
				}
			}
			bridge.mu.Lock()
			writes := bridge.clientWrites
			bridge.mu.Unlock()
			if writes < 2 {
				t.Fatalf("fragmented packet writes = %d, want at least 2", writes)
			}
		})
	}
}

func TestIPConnConfigurationLifecycle(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.118")
	second := netip.MustParseAddr("192.0.2.119")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(first, 32), netip.PrefixFrom(second, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	exact, err := stack.ListenIP(context.Background(), "ip4:99", second)
	if err != nil {
		t.Fatal(err)
	}
	wildcard, err := stack.ListenIP(context.Background(), "ip4:99", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(first, 32)}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = exact.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("removed binding ReadFrom = %v, want net.ErrClosed", err)
	}
	if stats := stack.Stats(); stats.ActiveIPSockets != 1 {
		t.Fatalf("active IP sockets after address removal = %d, want 1", stats.ActiveIPSockets)
	}
	v6 := netip.MustParseAddr("2001:db8::118")
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(v6, 128)}, MTU: 1280}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = wildcard.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("removed family ReadFrom = %v, want net.ErrClosed", err)
	}
	if stats := stack.Stats(); stats.ActiveIPSockets != 0 {
		t.Fatalf("active IP sockets after family removal = %d, want 0", stats.ActiveIPSockets)
	}
}

func TestIPConnReceiveCapacity(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.120")
	remote := netip.MustParseAddr("198.51.100.120")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetReadBuffer(2 * (ipDatagramMetadataSize + 1)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		packet := buildIPPacket(remote, local, 99, []byte{byte(index)}, uint16(index), true)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("raw receive-capacity drops = %d, want 1", dropped)
	}
	for index := 0; index < 2; index++ {
		buffer := make([]byte, 1)
		n, _, readErr := connection.ReadFrom(buffer)
		if readErr != nil || n != 1 || buffer[0] != byte(index) {
			t.Fatalf("raw ReadFrom %d = %x, %v", index, buffer[:n], readErr)
		}
	}
}

// TestUnconnectedIPReadAndConnectedWriteToError matches the standard IPConn
// behavior for payload reads and destination-specific writes.
func TestUnconnectedIPReadAndConnectedWriteToError(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.124")
	remote := netip.MustParseAddr("198.51.100.124")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	listener, err := stack.ListenIP(context.Background(), "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, []byte("read"), 1, true)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if n, readErr := listener.Read(buffer); readErr != nil || n != 4 || string(buffer) != "read" {
		t.Fatalf("unconnected IP Read = %q, %v", buffer[:n], readErr)
	}
	netConnection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	connected := netConnection.(*IPConn)
	defer connected.Close()
	if _, err = connected.WriteToIP([]byte("x"), &net.IPAddr{IP: net.IP(remote.AsSlice())}); !errors.Is(err, net.ErrWriteToConnected) {
		t.Fatalf("connected IP WriteTo = %v, want net.ErrWriteToConnected", err)
	}
}
