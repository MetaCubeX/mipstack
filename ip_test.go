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
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::110"), remote: netip.MustParseAddr("2001:db8:1::110"), controlSize: 112},
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
			oob := make([]byte, 128)
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
			if stack.outbound.len() != 0 {
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

func TestIPPathMTUProbing(t *testing.T) {
	for _, test := range []struct {
		name      string
		local     netip.Addr
		remote    netip.Addr
		baseMTU   uint32
		connected bool
	}{
		{name: "IPv4 connected", local: netip.MustParseAddr("192.0.2.170"), remote: netip.MustParseAddr("192.0.2.171"), baseMTU: 1000, connected: true},
		{name: "IPv4 unconnected", local: netip.MustParseAddr("192.0.2.172"), remote: netip.MustParseAddr("192.0.2.173"), baseMTU: 1000},
		{name: "IPv6 connected", local: netip.MustParseAddr("2001:db8::170"), remote: netip.MustParseAddr("2001:db8::171"), baseMTU: 1280, connected: true},
		{name: "IPv6 unconnected", local: netip.MustParseAddr("2001:db8::172"), remote: netip.MustParseAddr("2001:db8::173"), baseMTU: 1280},
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
			var connection *IPConn
			if test.connected {
				var netConnection net.Conn
				netConnection, err = stack.DialIP(context.Background(), "ip:99", netip.Addr{}, test.remote)
				if err == nil {
					connection = netConnection.(*IPConn)
				}
			} else {
				connection, err = stack.ListenIP(context.Background(), "ip:99", netip.Addr{})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 1300)
			if test.connected {
				_, err = connection.Write(payload)
			} else {
				_, err = connection.WriteToIP(payload, ipNetAddr(test.remote))
			}
			if err != nil {
				t.Fatal(err)
			}
			for fragment := 0; fragment < 2; fragment++ {
				if packet := readOutboundPacket(t, stack); len(packet) > int(test.baseMTU) {
					t.Fatalf("ordinary IP fragment size = %d, want <= %d", len(packet), test.baseMTU)
				}
			}
			if test.connected {
				_, err = connection.WritePathMTUProbe(payload)
			} else {
				_, err = connection.WritePathMTUProbeTo(payload, test.remote)
			}
			if err != nil {
				t.Fatal(err)
			}
			probe := readOutboundPacket(t, stack)
			wantSize := len(payload) + 20
			if test.remote.Is6() {
				wantSize = len(payload) + 40
			}
			if len(probe) != wantSize {
				t.Fatalf("IP path probe size = %d, want %d", len(probe), wantSize)
			}
			if test.connected {
				err = connection.ConfirmPathMTU(wantSize)
			} else {
				err = connection.ConfirmPathMTUFor(test.remote, wantSize)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mtu, pathErr := stack.PathMTU(test.remote); pathErr != nil || mtu != wantSize {
				t.Fatalf("confirmed IP PMTU = %d, %v, want %d", mtu, pathErr, wantSize)
			}
		})
	}
}

func TestIPIPv6FlowLabelPolicy(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::192")
	remote := netip.MustParseAddr("2001:db8::193")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := stack.ListenIP(context.Background(), "ip6:99", netip.IPv6Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	writeAndLabel := func() uint32 {
		t.Helper()
		if _, writeErr := connection.WriteToIP([]byte("flow"), ipNetAddr(remote)); writeErr != nil {
			t.Fatal(writeErr)
		}
		packet, ok := parseIPPacket(readOutboundPacket(t, stack))
		if !ok {
			t.Fatal("failed to parse IPv6 IP output")
		}
		return packet.flowLabel
	}
	first := writeAndLabel()
	if first == 0 || writeAndLabel() != first {
		t.Fatalf("unstable automatic IP flow label %#x", first)
	}
	if info := connection.Info(); info.FlowLabel != 0 {
		t.Fatalf("automatic IP flow-label diagnostics = %+v", info)
	}
	if err = connection.SetFlowLabel(0x34567); err != nil {
		t.Fatal(err)
	}
	if label := writeAndLabel(); label != 0x34567 {
		t.Fatalf("IP socket flow label = %#x, want 0x34567", label)
	}
	if info := connection.Info(); info.FlowLabel != 0x34567 {
		t.Fatalf("fixed IP flow-label diagnostics = %+v", info)
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
			control := make([]byte, 128)
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
				if controlErr := message.Parse(control[:oobn]); controlErr != nil || message.HopLimit != 29 || message.TrafficClass != 0x2e || message.FlowLabel == 0 || message.Dst != test.remote {
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

func TestIPConcurrentReadersShareDeadline(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.121")
	remote := netip.MustParseAddr("198.51.100.121")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newIPConn(stack, "ip4:99", 99, local, remote)
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
				t.Fatal("concurrent IP read failed")
			}
			seen[value] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent IP readers did not make progress")
		}
	}
	if len(seen) != readers {
		t.Fatalf("concurrent IP reads received %d distinct datagrams", len(seen))
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

func TestIPDefaultsAndDiagnostics(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::136")
	remote := netip.MustParseAddr("2001:db8::137")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1400,
		IP: DatagramSocketDefaults{ReceiveBuffer: 2048, HopLimit: 29, TrafficClass: 0x28},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	connection, err := stack.DialIP(context.Background(), "ip6:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	ip := connection.(*IPConn)
	if err = ip.SetHopLimit(41); err != nil {
		t.Fatal(err)
	}
	if err = ip.SetTrafficClass(0x2e); err != nil {
		t.Fatal(err)
	}
	if _, err = ip.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.hopLimit != 41 || packet.trafficClass != 0x2e || packet.protocol != 99 {
		t.Fatalf("IP output options = protocol %d hop %d class %#x", packet.protocol, packet.hopLimit, packet.trafficClass)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, []byte("answer"), 1, true)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if n, readErr := ip.Read(buffer); readErr != nil || string(buffer[:n]) != "answer" {
		t.Fatalf("IP Read = %q, %v", buffer[:n], readErr)
	}
	if err = ip.SetReadBuffer(ipDatagramMetadataSize); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if err = writeTestPacket(stack, buildIPPacket(remote, local, 99, nil, uint16(index+2), true)); err != nil {
			t.Fatal(err)
		}
	}
	info := ip.Info()
	if info.Protocol != 99 || info.PacketsSent != 1 || info.BytesSent != 5 || info.PacketsReceived != 2 || info.BytesReceived != 6 ||
		info.PacketsDropped != 1 || info.ReceiveQueuePackets != 1 || info.ReceiveQueueBytes != ipDatagramMetadataSize ||
		info.ReceiveQueueCapacity != ipDatagramMetadataSize || info.PathMTU != 1400 || info.HopLimit != 41 || info.TrafficClass != 0x2e {
		t.Fatalf("IP Info = %+v", info)
	}
}

func TestIPZeroHopLimitFamilyValidation(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.136")
	remote4 := netip.MustParseAddr("198.51.100.136")
	local6 := netip.MustParseAddr("2001:db8::136")
	remote6 := netip.MustParseAddr("2001:db8:1::136")
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
	connection6, err := stack.DialIP(context.Background(), "ip6:99", netip.Addr{}, remote6)
	if err != nil {
		t.Fatal(err)
	}
	ip6 := connection6.(*IPConn)
	defer ip6.Close()
	if err = ip6.SetHopLimit(0); err != nil {
		t.Fatal(err)
	}
	if _, err = ip6.Write([]byte("zero")); err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || packet.hopLimit != 0 || packet.target != remote6 {
		t.Fatalf("IPv6 default zero hop-limit packet = target %v hop %d, parsed = %v", packet.target, packet.hopLimit, ok)
	}
	connection4, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote4)
	if err != nil {
		t.Fatal(err)
	}
	ip4 := connection4.(*IPConn)
	defer ip4.Close()
	if err = ip4.SetHopLimit(0); err == nil {
		t.Fatal("IPv4 SetHopLimit(0) succeeded")
	}
}

func BenchmarkIPReceiveQueue(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.244")
	remote := netip.MustParseAddr("198.51.100.244")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		b.Fatal(err)
	}
	connection := newIPConn(stack, "ip4:99", 99, local, remote)
	b.Cleanup(connection.closeFromStack)
	payload := bytes.Repeat([]byte{0x6b}, 1200)
	buffer := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		connection.enqueue(payload, remote, local, ipPacketOptions{})
		if n, _, _, readErr := connection.readDatagram(buffer); readErr != nil || n != len(payload) {
			b.Fatalf("readDatagram = %d, %v", n, readErr)
		}
	}
}

func TestIPReceivePayloadSpareIsBoundedAndReleased(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.248")
	remote := netip.MustParseAddr("198.51.100.248")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newIPConn(stack, "ip4:99", 99, local, remote)
	read := func(payload []byte) {
		connection.enqueue(payload, remote, local, ipPacketOptions{})
		buffer := make([]byte, len(payload))
		if n, _, _, readErr := connection.readDatagram(buffer); readErr != nil || n != len(payload) || !bytes.Equal(buffer, payload) {
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

func BenchmarkIPPacketWrite(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.246")
	remote := netip.MustParseAddr("198.51.100.246")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		b.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		b.Fatal(err)
	}
	connection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = connection.Close()
		_ = stack.Close()
	})
	payload := bytes.Repeat([]byte{0x7c}, 1200)
	buffers := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err = connection.Write(payload); err != nil {
			b.Fatal(err)
		}
		if count, readErr := stack.Read(buffers, sizes, 0); readErr != nil || count != 1 {
			b.Fatalf("Stack.Read = %d, %v", count, readErr)
		}
	}
}
