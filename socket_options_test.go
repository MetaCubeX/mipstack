package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

func TestSocketOptionValidationDoesNotCreateEndpoints(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.221")
	remote := netip.MustParseAddr("198.51.100.221")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	tests := []struct {
		name string
		call func() error
	}{
		{name: "TCP listen header included", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
			return callErr
		}},
		{name: "UDP listen receive IP header", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnRead(true)}}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
			return callErr
		}},
		{name: "IP listen reuse port", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.ReusePort(true)}}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
			return callErr
		}},
		{name: "nil option", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{nil}}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
			return callErr
		}},
		{name: "TCP dial header included", call: func() error {
			_, callErr := (&Dialer{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).DialTCP(context.Background(), stack, "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 80))
			return callErr
		}},
		{name: "UDP dial reuse address", call: func() error {
			_, callErr := (&Dialer{Options: []SocketOption{SocketOptions.ReuseAddress(true)}}).DialUDP(context.Background(), stack, "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 53))
			return callErr
		}},
		{name: "IP dial reuse port", call: func() error {
			_, callErr := (&Dialer{Options: []SocketOption{SocketOptions.ReusePort(true)}}).DialIP(context.Background(), stack, "ip4:99", netip.Addr{}, remote)
			return callErr
		}},
		{name: "IP listen unset reuse address", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.UnsetReuseAddress()}}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
			return callErr
		}},
		{name: "UDP listen unset IP header", call: func() error {
			_, callErr := (&ListenConfig{Options: []SocketOption{SocketOptions.UnsetIPHeaderIncludedOnRead()}}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
			return callErr
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if callErr := test.call(); !errors.Is(callErr, syscall.ENOPROTOOPT) {
				t.Fatalf("option error = %v, want ENOPROTOOPT", callErr)
			}
			if stats := stack.Stats(); stats.ActiveTCPConnections != 0 || stats.ActiveTCPListeners != 0 || stats.ActiveUDPSockets != 0 || stats.ActiveIPSockets != 0 {
				t.Fatalf("invalid option retained endpoint state: %+v", stats)
			}
		})
	}
}

func TestSocketOptionApplicabilityMatrix(t *testing.T) {
	uses := []struct {
		name string
		use  socketOptionUse
	}{
		{name: "TCP listen", use: socketOptionTCPListen},
		{name: "UDP listen", use: socketOptionUDPListen},
		{name: "IP listen", use: socketOptionIPListen},
		{name: "TCP dial", use: socketOptionTCPDial},
		{name: "UDP dial", use: socketOptionUDPDial},
		{name: "IP dial", use: socketOptionIPDial},
	}
	options := []struct {
		name                     string
		enabled, disabled, unset SocketOption
		valid                    func(socketOptionUse) bool
		setExpected              func(*socketOptionSet, bool)
	}{
		{
			name:        "ReuseAddress",
			enabled:     SocketOptions.ReuseAddress(true),
			disabled:    SocketOptions.ReuseAddress(false),
			unset:       SocketOptions.UnsetReuseAddress(),
			valid:       func(use socketOptionUse) bool { return use == socketOptionTCPListen || use == socketOptionUDPListen },
			setExpected: func(set *socketOptionSet, enabled bool) { set.reuseAddress = enabled },
		},
		{
			name:        "ReusePort",
			enabled:     SocketOptions.ReusePort(true),
			disabled:    SocketOptions.ReusePort(false),
			unset:       SocketOptions.UnsetReusePort(),
			valid:       func(use socketOptionUse) bool { return use == socketOptionTCPListen || use == socketOptionUDPListen },
			setExpected: func(set *socketOptionSet, enabled bool) { set.reusePort = enabled },
		},
		{
			name:        "IPHeaderIncludedOnWrite",
			enabled:     SocketOptions.IPHeaderIncludedOnWrite(true),
			disabled:    SocketOptions.IPHeaderIncludedOnWrite(false),
			unset:       SocketOptions.UnsetIPHeaderIncludedOnWrite(),
			valid:       func(use socketOptionUse) bool { return use == socketOptionIPListen || use == socketOptionIPDial },
			setExpected: func(set *socketOptionSet, enabled bool) { set.ipHeaderIncludedOnWrite = enabled },
		},
		{
			name:        "IPHeaderIncludedOnRead",
			enabled:     SocketOptions.IPHeaderIncludedOnRead(true),
			disabled:    SocketOptions.IPHeaderIncludedOnRead(false),
			unset:       SocketOptions.UnsetIPHeaderIncludedOnRead(),
			valid:       func(use socketOptionUse) bool { return use == socketOptionIPListen || use == socketOptionIPDial },
			setExpected: func(set *socketOptionSet, enabled bool) { set.ipHeaderIncludedOnRead = enabled },
		},
	}
	for _, option := range options {
		for _, use := range uses {
			variants := []struct {
				name     string
				value    SocketOption
				explicit bool
				enabled  bool
			}{
				{name: "enabled", value: option.enabled, explicit: true, enabled: true},
				{name: "disabled", value: option.disabled, explicit: true},
				{name: "unset", value: option.unset},
			}
			for _, variant := range variants {
				t.Run(option.name+"/"+use.name+"/"+variant.name, func(t *testing.T) {
					got, err := parseSocketOptions([]SocketOption{variant.value}, use.use)
					if !option.valid(use.use) {
						if !errors.Is(err, syscall.ENOPROTOOPT) || got != (socketOptionSet{}) {
							t.Fatalf("invalid option result = %+v, %v", got, err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					want := socketOptionSet{reuseAddress: use.use == socketOptionTCPListen}
					if variant.explicit {
						option.setExpected(&want, variant.enabled)
					}
					if got != want {
						t.Fatalf("option result = %+v, want %+v", got, want)
					}
				})
			}
		}
	}
}

func TestSocketOptionUnsetRestoresOperationDefaults(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.220")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	tcpListener, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.ReuseAddress(false), SocketOptions.UnsetReuseAddress(),
		SocketOptions.ReusePort(true), SocketOptions.UnsetReusePort(),
	}}).ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if !tcpListener.reuseAddress || tcpListener.reusePort {
		t.Fatalf("unset TCP reuse policy = address:%v port:%v", tcpListener.reuseAddress, tcpListener.reusePort)
	}
	_ = tcpListener.Close()

	udpPacket, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.ReuseAddress(true), SocketOptions.UnsetReuseAddress(),
		SocketOptions.ReusePort(true), SocketOptions.UnsetReusePort(),
	}}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	udpConnection := udpPacket.(*UDPConn)
	if udpConnection.reuseAddress || udpConnection.reusePort {
		t.Fatalf("unset UDP reuse policy = address:%v port:%v", udpConnection.reuseAddress, udpConnection.reusePort)
	}
	_ = udpConnection.Close()

	ipConnection, err := (&ListenConfig{Options: []SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(true), SocketOptions.UnsetIPHeaderIncludedOnWrite(),
		SocketOptions.IPHeaderIncludedOnRead(true), SocketOptions.UnsetIPHeaderIncludedOnRead(),
	}}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer ipConnection.Close()
	if info := ipConnection.Info(); info.IPHeaderIncludedOnWrite || info.IPHeaderIncludedOnRead {
		t.Fatalf("unset IP representation policy = %+v", info)
	}
}

func TestSocketOptionDefaultsOrderAndSnapshot(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.222")
	remote := netip.MustParseAddr("198.51.100.222")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	defaultTCP, err := (*ListenConfig)(nil).ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if !defaultTCP.reuseAddress || defaultTCP.reusePort {
		t.Fatalf("default TCP reuse policy = address:%v port:%v", defaultTCP.reuseAddress, defaultTCP.reusePort)
	}
	_ = defaultTCP.Close()

	tcpOptions := []SocketOption{SocketOptions.ReuseAddress(true), SocketOptions.ReuseAddress(false)}
	tcpListener, err := (&ListenConfig{Options: tcpOptions}).ListenTCP(context.Background(), stack, "tcp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	if tcpListener.reuseAddress {
		t.Fatal("last TCP ReuseAddress option did not win")
	}
	tcpOptions[1] = SocketOptions.ReuseAddress(true)
	if tcpListener.reuseAddress {
		t.Fatal("TCP listener retained the caller's option slice")
	}
	_ = tcpListener.Close()

	defaultUDP, err := (*ListenConfig)(nil).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defaultUDPConn := defaultUDP.(*UDPConn)
	if defaultUDPConn.reuseAddress || defaultUDPConn.reusePort {
		t.Fatalf("default UDP reuse policy = address:%v port:%v", defaultUDPConn.reuseAddress, defaultUDPConn.reusePort)
	}
	_ = defaultUDP.Close()

	udpOptions := []SocketOption{SocketOptions.ReuseAddress(false), SocketOptions.ReuseAddress(true)}
	udpPacket, err := (&ListenConfig{Options: udpOptions}).ListenUDP(context.Background(), stack, "udp4", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	udpConnection := udpPacket.(*UDPConn)
	if !udpConnection.reuseAddress || udpConnection.reusePort {
		t.Fatalf("ordered UDP reuse policy = address:%v port:%v", udpConnection.reuseAddress, udpConnection.reusePort)
	}
	udpOptions[1] = SocketOptions.ReuseAddress(false)
	if !udpConnection.reuseAddress {
		t.Fatal("UDP socket retained the caller's option slice")
	}
	_ = udpConnection.Close()

	ipOptions := []SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(false), SocketOptions.IPHeaderIncludedOnWrite(true),
		SocketOptions.IPHeaderIncludedOnRead(true), SocketOptions.IPHeaderIncludedOnRead(false),
	}
	ipConnection, err := (&ListenConfig{Options: ipOptions}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer ipConnection.Close()
	if info := ipConnection.Info(); !info.IPHeaderIncludedOnWrite || info.IPHeaderIncludedOnRead {
		t.Fatalf("ordered IP representation policy = %+v", info)
	}
	ipOptions[1] = SocketOptions.IPHeaderIncludedOnWrite(false)
	if !ipConnection.Info().IPHeaderIncludedOnWrite {
		t.Fatal("IP socket retained the caller's option slice")
	}
	if err = ipConnection.SetIPHeaderIncludedOnWrite(false); err != nil || ipConnection.Info().IPHeaderIncludedOnWrite {
		t.Fatalf("runtime IPHeaderIncludedOnWrite(false) = %+v, %v", ipConnection.Info(), err)
	}

	dialedNet, err := (&Dialer{Options: []SocketOption{
		SocketOptions.IPHeaderIncludedOnWrite(true), SocketOptions.IPHeaderIncludedOnRead(true),
	}}).DialIP(context.Background(), stack, "ip4:99", netip.Addr{}, remote)
	if err != nil {
		t.Fatal(err)
	}
	dialed := dialedNet.(*IPConn)
	defer dialed.Close()
	if info := dialed.Info(); !info.IPHeaderIncludedOnWrite || !info.IPHeaderIncludedOnRead {
		t.Fatalf("dialed IP representation policy = %+v", info)
	}
	if _, ok := interface{}(dialed).(net.Conn); !ok {
		t.Fatal("Dialer.DialIP result does not implement net.Conn")
	}
}

func TestIPHeaderIncludedOnWriteSelectsErrorQueueRepresentationAtDelivery(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.229")
	remote := netip.MustParseAddr("198.51.100.229")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).ListenIP(context.Background(), stack, "ip4:99", local)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}

	packet := buildIPPacket(local, remote, 99, []byte("quoted-payload"), 7, true)
	parsed, ok := parseIPPacket(packet)
	if !ok {
		t.Fatal("failed to parse quoted packet")
	}
	networkError := ICMPError{
		Reporter: netip.MustParseAddr("198.51.100.1"), Type: 3, Code: 1,
		QuotedSource: local, QuotedTarget: remote, QuotedProtocol: 99,
		QuotedPacket: packet, QuotedPayload: parsed.payload,
	}

	connection.deliverError(remote, networkError)
	if err = connection.SetIPHeaderIncludedOnWrite(false); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(remote, networkError)
	for index, want := range [][]byte{packet, parsed.payload} {
		buffer := make([]byte, len(packet))
		messages := []Message{{Buffers: [][]byte{buffer}, OOB: make([]byte, 128)}}
		if count, readErr := connection.ReadBatch(messages, MessageErrorQueue); readErr != nil || count != 1 || !bytes.Equal(buffer[:messages[0].N], want) {
			t.Fatalf("error queue representation %d = count %d payload %x, %v; want %x", index, count, buffer[:messages[0].N], readErr, want)
		}
	}
}

func TestIPHeaderIncludedOnWriteLinuxRepresentation(t *testing.T) {
	t.Run("IPv4 repairs kernel-owned fields and routes by destination argument", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.223")
		routeTarget := netip.MustParseAddr("198.51.100.223")
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).ListenIP(context.Background(), stack, "ip4:99", netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()

		payload := []byte("header-included-ipv4")
		packet := make([]byte, 24+len(payload))
		packet[0], packet[1], packet[8], packet[9] = 0x46, 0x2e, 37, 99
		binary.BigEndian.PutUint16(packet[2:4], 1)
		binary.BigEndian.PutUint16(packet[10:12], 0xbeef)
		destination := local.As4()
		copy(packet[16:20], destination[:])
		copy(packet[20:24], []byte{1, 1, 0, 0})
		copy(packet[24:], payload)
		original := append([]byte(nil), packet...)
		if n, writeErr := connection.WriteToIP(packet, ipNetAddr(routeTarget)); writeErr != nil || n != len(packet) {
			t.Fatalf("header-included IPv4 write = %d, %v", n, writeErr)
		}
		if !bytes.Equal(packet, original) {
			t.Fatal("header-included IPv4 write mutated caller storage")
		}
		output := readOutboundPacket(t, stack)
		if len(output) != len(packet) || output[0] != 0x46 || output[1] != 0x2e || output[8] != 37 || output[9] != 99 ||
			binary.BigEndian.Uint16(output[2:4]) != uint16(len(output)) || binary.BigEndian.Uint16(output[4:6]) == 0 || checksum(output[:24]) != 0 ||
			!bytes.Equal(output[12:16], local.AsSlice()) || !bytes.Equal(output[16:20], local.AsSlice()) ||
			!bytes.Equal(output[20:24], []byte{1, 1, 0, 0}) || !bytes.Equal(output[24:], payload) {
			t.Fatalf("repaired header-included IPv4 packet = %x", output)
		}
		if stack.loopback.len() != 0 {
			t.Fatal("header destination selected loopback instead of the explicit route target")
		}
	})

	t.Run("IPv6 remains byte exact and routes by destination argument", func(t *testing.T) {
		local := netip.MustParseAddr("2001:db8::223")
		routeTarget := netip.MustParseAddr("2001:db8:1::223")
		packetSource := netip.MustParseAddr("2001:db8:ffff::223")
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1280})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnWrite(true)}}).ListenIP(context.Background(), stack, "ip6:99", netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()

		payload := []byte("header-included-ipv6")
		packet := make([]byte, 40+len(payload))
		packet[0], packet[1], packet[2], packet[3] = 0x6b, 0xa5, 0x43, 0x21
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
		packet[6], packet[7] = 99, 29
		copy(packet[8:24], packetSource.AsSlice())
		copy(packet[24:40], local.AsSlice())
		copy(packet[40:], payload)
		original := append([]byte(nil), packet...)
		if n, writeErr := connection.WriteToIP(packet, ipNetAddr(routeTarget)); writeErr != nil || n != len(packet) {
			t.Fatalf("header-included IPv6 write = %d, %v", n, writeErr)
		}
		if !bytes.Equal(packet, original) {
			t.Fatal("header-included IPv6 write mutated caller storage")
		}
		if output := readOutboundPacket(t, stack); !bytes.Equal(output, packet) {
			t.Fatalf("header-included IPv6 output changed:\n got %x\nwant %x", output, packet)
		}
		if stack.loopback.len() != 0 {
			t.Fatal("IPv6 header destination selected loopback instead of the explicit route target")
		}
	})
}

func TestIPReceiveHeaderPreservesCompleteReassembledPacket(t *testing.T) {
	t.Run("IPv4 options", func(t *testing.T) {
		local := netip.MustParseAddr("192.0.2.224")
		remote := netip.MustParseAddr("198.51.100.224")
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnRead(true)}}).ListenIP(context.Background(), stack, "ip4:99", local)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		packet := buildTestIPv4Options(remote, local, []byte{1, 1, 0, 0})
		packet[9], packet[10], packet[11] = 99, 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:24]))
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 256)
		n, source, readErr := connection.ReadFromIP(buffer)
		if readErr != nil || source.String() != remote.String() || !bytes.Equal(buffer[:n], packet) {
			t.Fatalf("complete IPv4 options read = %d from %v, %v", n, source, readErr)
		}
	})

	t.Run("IPv6 extension header", func(t *testing.T) {
		local := netip.MustParseAddr("2001:db8::224")
		remote := netip.MustParseAddr("2001:db8:1::224")
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1280})
		if err != nil {
			t.Fatal(err)
		}
		if err = stack.Start(); err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnRead(true)}}).ListenIP(context.Background(), stack, "ip6:99", local)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		payload := []byte("extension")
		packet := make([]byte, 48+len(payload))
		packet[0], packet[6], packet[7] = 0x60, 60, 43
		binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
		copy(packet[8:24], remote.AsSlice())
		copy(packet[24:40], local.AsSlice())
		copy(packet[40:48], []byte{99, 0, 1, 0, 0, 0, 0, 0})
		copy(packet[48:], payload)
		if err = writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 256)
		n, _, readErr := connection.ReadFromIP(buffer)
		if readErr != nil || !bytes.Equal(buffer[:n], packet) {
			t.Fatalf("complete IPv6 extension read = %d, %v", n, readErr)
		}
	})

	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		mtu           int
	}{
		{name: "IPv4 fragments", local: netip.MustParseAddr("192.0.2.225"), remote: netip.MustParseAddr("198.51.100.225"), mtu: 600},
		{name: "IPv6 fragments", local: netip.MustParseAddr("2001:db8::225"), remote: netip.MustParseAddr("2001:db8:1::225"), mtu: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := test.local.BitLen()
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: uint32(test.mtu)})
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
			connection, err := (&ListenConfig{Options: []SocketOption{SocketOptions.IPHeaderIncludedOnRead(true)}}).ListenIP(context.Background(), stack, network, test.local)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, 99, payload, test.mtu, 0x1234)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, 99, payload, test.mtu, 0x12345678, ipPacketOptions{})
			}
			for _, fragment := range fragments {
				if err = writeTestPacket(stack, fragment); err != nil {
					t.Fatal(err)
				}
			}
			buffer := make([]byte, 65535)
			n, _, readErr := connection.ReadFromIP(buffer)
			packet, ok := parseIPPacket(buffer[:n])
			if readErr != nil || !ok || packet.source != test.remote || packet.target != test.local || packet.protocol != 99 || !bytes.Equal(packet.payload, payload) {
				t.Fatalf("complete reassembled packet = %d bytes, %+v, parsed=%v, error=%v", n, packet, ok, readErr)
			}
		})
	}
}
