package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestIPv6AtomicFragmentReservedBits verifies RFC 8200's requirement to
// ignore reserved fragment-header bits on reception.
func TestIPv6AtomicFragmentReservedBits(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2001:db8::1")
	fragment := make([]byte, 8+udpHeaderSize)
	fragment[0] = ProtocolUDP
	fragment[1] = 0xff
	binary.BigEndian.PutUint16(fragment[2:4], 0x0002)
	binary.BigEndian.PutUint32(fragment[4:8], 1)
	packet := buildIPPacket(source, target, 44, fragment, 0, false)
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.protocol != ProtocolUDP || len(parsed.payload) != udpHeaderSize {
		t.Fatalf("IPv6 atomic fragment with reserved bits = %+v, parsed = %v", parsed, ok)
	}
}

func TestIPv6FragmentReservedBitsAreIgnored(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	fragments := buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, make([]byte, 24), 56, 7, ipPacketOptions{})
	for index, fragment := range fragments {
		fragment[41] = 0xff
		field := binary.BigEndian.Uint16(fragment[42:44]) | 0x0006
		binary.BigEndian.PutUint16(fragment[42:44], field)
		packet := stack.reassemblePacket(fragment, time.Now())
		if index != len(fragments)-1 && packet != nil {
			t.Fatal("reserved bits completed IPv6 reassembly early")
		}
		if index == len(fragments)-1 {
			parsed, ok := parseIPPacket(packet)
			if !ok || parsed.protocol != ProtocolUDP || len(parsed.payload) != 24 {
				t.Fatalf("reserved-bit IPv6 reassembly = %+v, parsed = %v", parsed, ok)
			}
		}
	}
}

// TestPathMTUDiscoveryOutputPolicy verifies both MTU selection and the wire
// effects of every Linux IP_MTU_DISCOVER mode. The three packet sizes cover
// output below the confirmed PMTU, between that PMTU and the interface MTU,
// and above the interface MTU.
func TestPathMTUDiscoveryOutputPolicy(t *testing.T) {
	type expectation struct {
		error        bool
		fragmented   bool
		dontFragment bool
		identifiable bool
		ceiling      int
	}
	for _, family := range []struct {
		name           string
		source, target netip.Addr
		headerSize     int
		pathMTU        int
	}{
		{name: "IPv4", source: netip.MustParseAddr("192.0.2.201"), target: netip.MustParseAddr("198.51.100.201"), headerSize: 20, pathMTU: 1000},
		{name: "IPv6", source: netip.MustParseAddr("2001:db8::201"), target: netip.MustParseAddr("2001:db8:1::201"), headerSize: 40, pathMTU: 1280},
	} {
		t.Run(family.name, func(t *testing.T) {
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(family.source, family.source.BitLen())}, MTU: 1500})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if !stack.observePathMTU(family.target, uint32(family.pathMTU)) {
				t.Fatal("failed to install confirmed PMTU")
			}

			tests := []struct {
				name       string
				mode       PathMTUDiscovery
				packetSize int
				want       expectation
			}{
				{name: "dont-small", mode: PathMTUDiscoveryDont, packetSize: 900, want: expectation{identifiable: true, ceiling: family.pathMTU}},
				{name: "want-small", mode: PathMTUDiscoveryWant, packetSize: 900, want: expectation{dontFragment: true, identifiable: true, ceiling: family.pathMTU}},
				{name: "do-small", mode: PathMTUDiscoveryDo, packetSize: 900, want: expectation{dontFragment: true, ceiling: family.pathMTU}},
				{name: "probe-small", mode: PathMTUDiscoveryProbe, packetSize: 900, want: expectation{dontFragment: true, ceiling: 1500}},
				{name: "interface-small", mode: PathMTUDiscoveryInterface, packetSize: 900, want: expectation{identifiable: true, ceiling: 1500}},
				{name: "omit-small", mode: PathMTUDiscoveryOmit, packetSize: 900, want: expectation{identifiable: true, ceiling: 1500}},
				{name: "dont-path-exceeded", mode: PathMTUDiscoveryDont, packetSize: family.pathMTU + 200, want: expectation{fragmented: true, ceiling: family.pathMTU}},
				{name: "want-path-exceeded", mode: PathMTUDiscoveryWant, packetSize: family.pathMTU + 200, want: expectation{fragmented: true, ceiling: family.pathMTU}},
				{name: "do-path-exceeded", mode: PathMTUDiscoveryDo, packetSize: family.pathMTU + 200, want: expectation{error: true, ceiling: family.pathMTU}},
				{name: "probe-ignores-path", mode: PathMTUDiscoveryProbe, packetSize: family.pathMTU + 200, want: expectation{dontFragment: true, ceiling: 1500}},
				{name: "interface-ignores-path", mode: PathMTUDiscoveryInterface, packetSize: family.pathMTU + 200, want: expectation{identifiable: true, ceiling: 1500}},
				{name: "omit-ignores-path", mode: PathMTUDiscoveryOmit, packetSize: family.pathMTU + 200, want: expectation{identifiable: true, ceiling: 1500}},
				{name: "dont-interface-exceeded", mode: PathMTUDiscoveryDont, packetSize: 1600, want: expectation{fragmented: true, ceiling: family.pathMTU}},
				{name: "want-interface-exceeded", mode: PathMTUDiscoveryWant, packetSize: 1600, want: expectation{fragmented: true, ceiling: family.pathMTU}},
				{name: "do-interface-exceeded", mode: PathMTUDiscoveryDo, packetSize: 1600, want: expectation{error: true, ceiling: family.pathMTU}},
				{name: "probe-interface-exceeded", mode: PathMTUDiscoveryProbe, packetSize: 1600, want: expectation{error: true, ceiling: 1500}},
				{name: "interface-interface-exceeded", mode: PathMTUDiscoveryInterface, packetSize: 1600, want: expectation{error: true, ceiling: 1500}},
				{name: "omit-interface-exceeded", mode: PathMTUDiscoveryOmit, packetSize: 1600, want: expectation{fragmented: true, ceiling: 1500}},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					stack.ipv4ID.Store(100)
					mtu, fragmentation := stack.pathMTUOutputPolicy(family.target, test.mode)
					if mtu != test.want.ceiling {
						t.Fatalf("selected MTU = %d, want %d", mtu, test.want.ceiling)
					}
					payload := make([]byte, test.packetSize-family.headerSize)
					packets, outputErr := stack.ipPayloadPacketsForMTU(family.source, family.target, 99, payload, fragmentation, ipPacketOptions{}, mtu)
					if test.want.error {
						if !errors.Is(outputErr, syscall.EMSGSIZE) || len(packets) != 0 {
							t.Fatalf("output = %d packets, %v; want EMSGSIZE", len(packets), outputErr)
						}
						return
					}
					if outputErr != nil {
						t.Fatal(outputErr)
					}
					if fragmented := len(packets) > 1; fragmented != test.want.fragmented {
						t.Fatalf("fragmented = %v (%d packets), want %v", fragmented, len(packets), test.want.fragmented)
					}
					for _, packet := range packets {
						if len(packet) > test.want.ceiling {
							t.Fatalf("packet length = %d, ceiling %d", len(packet), test.want.ceiling)
						}
						if family.source.Is4() {
							df := binary.BigEndian.Uint16(packet[6:8])&0x4000 != 0
							if df != test.want.dontFragment {
								t.Fatalf("IPv4 DF = %v, want %v", df, test.want.dontFragment)
							}
							identification := binary.BigEndian.Uint16(packet[4:6])
							wantIdentification := test.want.identifiable || test.want.fragmented
							if (identification != 0) != wantIdentification {
								t.Fatalf("IPv4 identification = %d, identifiable want %v", identification, wantIdentification)
							}
						} else if test.want.fragmented && packet[6] != 44 {
							t.Fatalf("IPv6 next header = %d, want Fragment", packet[6])
						}
					}
				})
			}
		})
	}
}

func TestIPv6FragmentAfterRepeatedExtensionHeaders(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")
	payload := make([]byte, 0, 6*8)
	payload = append(payload, 43, 0, 0, 0, 0, 0, 0, 0)
	payload = append(payload, 60, 0, 99, 0, 0, 0, 0, 0)
	payload = append(payload, 43, 0, 0, 0, 0, 0, 0, 0)
	payload = append(payload, 60, 0, 99, 0, 0, 0, 0, 0)
	payload = append(payload, 44, 0, 0, 0, 0, 0, 0, 0)
	payload = append(payload, 99, 0, 0, 1, 0, 0, 0, 7)
	payload = append(payload, 1, 2, 3, 4, 5, 6, 7, 8)
	fragment, ok := parseFragment(buildIPPacket(remote, local, 60, payload, 0, false))
	if !ok || !fragment.key.v6 || fragment.protocol != 99 || fragment.offset != 0 || !fragment.more || len(fragment.header) != 80 {
		t.Fatalf("fragment after repeated extension headers = %+v, parsed = %t", fragment, ok)
	}
}

func TestIPv6UnfragmentableHeaderErrors(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::31")
	remote := netip.MustParseAddr("2001:db8::32")
	for _, test := range []struct {
		name     string
		first    byte
		headers  []byte
		wantCode byte
		wantAt   uint32
	}{
		{
			name: "misplaced Hop-by-Hop", first: 60,
			headers:  append([]byte{0, 0, 0, 0, 0, 0, 0, 0}, 44, 0, 0, 0, 0, 0, 0, 0),
			wantCode: 1, wantAt: 40,
		},
		{
			name: "unsupported option", first: 60,
			headers:  []byte{44, 0, 0x80, 0, 0, 0, 0, 0},
			wantCode: 2, wantAt: 42,
		},
		{
			name: "active routing header", first: 43,
			headers:  []byte{44, 0, 99, 1, 0, 0, 0, 0},
			wantCode: 0, wantAt: 42,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fragmentHeader := []byte{99, 0, 0, 1, 0, 0, 0, 7}
			packet := buildIPPacket(remote, local, test.first, append(append([]byte(nil), test.headers...), fragmentHeader...), 0, false)
			fragment, ok := parseFragment(packet)
			if !ok || !fragment.parameter || fragment.parameterCode != test.wantCode || fragment.parameterAt != test.wantAt {
				t.Fatalf("unfragmentable-header parse = %+v, parsed=%t", fragment, ok)
			}
			link, stack := newTestStack(t, local, remote)
			if err := writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			var response []byte
			select {
			case response = <-link.outbound:
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for unfragmentable-header Parameter Problem")
			}
			parsed, ok := parseIPPacket(response)
			if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != test.wantCode || binary.BigEndian.Uint32(parsed.payload[4:8]) != test.wantAt {
				t.Fatalf("unfragmentable-header response = %x", response)
			}
		})
	}
}

func TestIPv6FirstFragmentRequiresCompleteHeaderChain(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	fragment := make([]byte, 16)
	fragment[0] = ProtocolTCP
	binary.BigEndian.PutUint16(fragment[2:4], 1)
	binary.BigEndian.PutUint32(fragment[4:8], 7)
	packet := buildIPPacket(remote, local, 44, fragment, 0, false)
	if err := writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RFC 7112 Parameter Problem")
	}
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 3 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 0 {
		t.Fatalf("incomplete first-fragment response = %x", response)
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("incomplete first fragment retained: sets=%d bytes=%d", sets, retained)
	}
}

func TestIPv6FirstFragmentHeaderCompleteness(t *testing.T) {
	extension := func(next byte, length byte, tail []byte) []byte {
		header := []byte{next, length, 0, 0, 0, 0, 0, 0}
		return append(header, tail...)
	}
	udp := make([]byte, udpHeaderSize)
	authentication := append(extension(ProtocolUDP, 2, make([]byte, 8)), udp...)
	tcp := make([]byte, tcpHeaderSize)
	tcp[12] = 5 << 4
	invalidTCPSize := append([]byte(nil), tcp...)
	invalidTCPSize[12] = 4 << 4
	for _, test := range []struct {
		name    string
		next    byte
		payload []byte
		want    bool
	}{
		{name: "hop by hop to UDP", next: 0, payload: extension(ProtocolUDP, 0, udp), want: true},
		{name: "routing to UDP", next: 43, payload: extension(ProtocolUDP, 0, udp), want: true},
		{name: "destination to UDP", next: 60, payload: extension(ProtocolUDP, 0, udp), want: true},
		{name: "mobility to UDP", next: 135, payload: extension(ProtocolUDP, 0, udp), want: true},
		{name: "truncated extension", next: 60, payload: extension(ProtocolUDP, 1, nil)},
		{name: "AH to UDP", next: IPv6ExtensionHeaderAuthentication, payload: authentication, want: true},
		{name: "short AH", next: IPv6ExtensionHeaderAuthentication, payload: extension(ProtocolUDP, 0, udp)},
		{name: "misaligned AH", next: IPv6ExtensionHeaderAuthentication, payload: extension(ProtocolUDP, 1, append(make([]byte, 4), udp...))},
		{name: "truncated AH", next: IPv6ExtensionHeaderAuthentication, payload: []byte{ProtocolUDP}},
		{name: "nested fragment", next: 44, payload: make([]byte, 8)},
		{name: "TCP", next: ProtocolTCP, payload: tcp, want: true},
		{name: "TCP short", next: ProtocolTCP, payload: tcp[:tcpHeaderSize-1]},
		{name: "TCP invalid data offset is complete", next: ProtocolTCP, payload: invalidTCPSize, want: true},
		{name: "UDP", next: ProtocolUDP, payload: udp, want: true},
		{name: "UDP short", next: ProtocolUDP, payload: udp[:udpHeaderSize-1]},
		{name: "ESP", next: 50, payload: make([]byte, 8), want: true},
		{name: "ESP short", next: 50, payload: make([]byte, 7)},
		{name: "DCCP", next: 33, payload: make([]byte, 12), want: true},
		{name: "DCCP short", next: 33, payload: make([]byte, 11)},
		{name: "SCTP", next: 132, payload: make([]byte, 12), want: true},
		{name: "SCTP short", next: 132, payload: make([]byte, 11)},
		{name: "no next header", next: 59, want: true},
		{name: "unknown raw protocol", next: 99, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if complete := ipv6FirstFragmentHeaderComplete(test.next, test.payload); complete != test.want {
				t.Fatalf("header complete = %t, want %t", complete, test.want)
			}
		})
	}
}

func TestIPv6NonFinalFragmentRequiresEightBytePayload(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::21")
	remote := netip.MustParseAddr("2001:db8::22")
	link, stack := newTestStack(t, local, remote)
	fragment := make([]byte, 8+9)
	fragment[0] = 99
	binary.BigEndian.PutUint16(fragment[2:4], 1)
	binary.BigEndian.PutUint32(fragment[4:8], 9)
	if err := writeTestPacket(stack, buildIPPacket(remote, local, 44, fragment, 0, false)); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-link.outbound:
		parsed, ok := parseIPPacket(response)
		if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 0 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 4 {
			t.Fatalf("misaligned IPv6 fragment response = %x", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for IPv6 fragment Parameter Problem")
	}
	stack.fragmentMu.Lock()
	sets := len(stack.fragments)
	stack.fragmentMu.Unlock()
	if sets != 0 {
		t.Fatalf("misaligned IPv6 fragment retained %d sets", sets)
	}
}

func TestIPv4NonFinalFragmentTrimsPartialOffsetUnit(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.87")
	remote := netip.MustParseAddr("198.51.100.87")
	_, stack := newTestStack(t, local, remote)
	firstPayload := append(bytes.Repeat([]byte{0x41}, 8), 0xff)
	first := buildIPPacket(remote, local, ProtocolUDP, firstPayload, 89, false)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], checksum(first[:20]))
	second := buildIPPacket(remote, local, ProtocolUDP, bytes.Repeat([]byte{0x42}, 8), 89, false)
	binary.BigEndian.PutUint16(second[6:8], 1)
	second[10], second[11] = 0, 0
	binary.BigEndian.PutUint16(second[10:12], checksum(second[:20]))
	if packet := stack.reassemblePacket(first, time.Now()); packet != nil {
		t.Fatal("trimmed first fragment completed datagram early")
	}
	packet := stack.reassemblePacket(second, time.Now())
	parsed, ok := parseIPPacket(packet)
	if !ok || len(parsed.payload) != 16 || !bytes.Equal(parsed.payload[:8], firstPayload[:8]) || !bytes.Equal(parsed.payload[8:], second[20:]) {
		t.Fatalf("Linux-compatible trimmed IPv4 reassembly = %x parsed=%+v ok=%t", packet, parsed, ok)
	}
}

func TestIPv6FragmentReassemblyLengthOverflow(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::85")
	remote := netip.MustParseAddr("2001:db8::86")
	link, stack := newTestStack(t, local, remote)
	fragments := buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, make([]byte, 16), 56, 88, ipPacketOptions{})
	overflow := append([]byte(nil), fragments[0]...)
	binary.BigEndian.PutUint16(overflow[42:44], 0xfff9)
	fragment, valid := parseFragment(overflow)
	if !valid || !fragment.parameter || fragment.parameterAt != 42 {
		t.Fatalf("overflow fragment parse = %+v, valid=%t", fragment, valid)
	}
	if err := writeTestPacket(stack, overflow); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for oversized-fragment Parameter Problem")
	}
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 0 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 oversized-reassembly response = %x", response)
	}
}

func TestIPv6IncompleteFirstFragmentDiscardsPriorTail(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::11")
	remote := netip.MustParseAddr("2001:db8::12")
	link, stack := newTestStack(t, local, remote)
	fragments := buildIPv6FragmentsWithOptions(remote, local, ProtocolTCP, make([]byte, 24), 56, 17, ipPacketOptions{})
	if len(fragments) != 3 {
		t.Fatalf("fragment count = %d, want 3", len(fragments))
	}
	if err := writeTestPacket(stack, fragments[1]); err != nil {
		t.Fatal(err)
	}
	stack.fragmentMu.Lock()
	retainedBefore := len(stack.fragments)
	stack.fragmentMu.Unlock()
	if retainedBefore != 1 {
		t.Fatalf("retained tails = %d, want 1", retainedBefore)
	}
	if err := writeTestPacket(stack, fragments[0]); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-link.outbound:
		parsed, ok := parseIPPacket(response)
		if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 3 {
			t.Fatalf("incomplete first-fragment response = %x", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for RFC 7112 Parameter Problem")
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("prior fragment tail retained: sets=%d bytes=%d", sets, retained)
	}
}

// TestUDPFragmentationAndReassembly exchanges an oversized datagram between
// two stacks.
func TestUDPFragmentationAndReassembly(t *testing.T) {
	for _, test := range []struct {
		name         string
		client, peer netip.Addr
	}{
		{name: "IPv4", client: netip.MustParseAddr("192.0.2.1"), peer: netip.MustParseAddr("192.0.2.2")},
		{name: "IPv6", client: netip.MustParseAddr("2001:db8::1"), peer: netip.MustParseAddr("2001:db8::2")},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 128
			if test.client.Is4() {
				bits = 32
			}
			client, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.client, bits)}, MTU: 1280})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err = client.Start(); err != nil {
				t.Fatal(err)
			}
			peer, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.peer, bits)}, MTU: 1280})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err = peer.Start(); err != nil {
				t.Fatal(err)
			}
			bridge := newStackBridge(t, client, peer)
			sender, err := client.ListenUDP(context.Background(), `udp`, wildcardUDP(test.peer))
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			receiver, err := peer.ListenUDP(context.Background(), `udp`, wildcardUDP(test.client))
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			receiverPort := receiver.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			destination := net.UDPAddrFromAddrPort(netip.AddrPortFrom(test.peer, receiverPort))
			if _, err = sender.WriteTo(payload, destination); err != nil {
				t.Fatal(err)
			}
			if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, len(payload))
			n, _, err := receiver.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("reassembled UDP payload size = %d", n)
			}
			bridge.mu.Lock()
			fragments := bridge.clientWrites
			bridge.mu.Unlock()
			if fragments < 3 {
				t.Fatalf("fragment writes = %d, want at least 3", fragments)
			}
		})
	}
}

func TestFragmentIdentificationSequences(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.41")
	remote4 := netip.MustParseAddr("192.0.2.42")
	stack4, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32)}, MTU: 68})
	if err != nil {
		t.Fatal(err)
	}
	stack4.ipv4ID.Store(100)
	first, err := stack4.ipPayloadPackets(local4, remote4, ProtocolUDP, make([]byte, 96), true)
	if err != nil || len(first) < 2 {
		t.Fatalf("first IPv4 fragments = %d, %v", len(first), err)
	}
	second, err := stack4.ipPayloadPackets(local4, remote4, ProtocolUDP, make([]byte, 96), true)
	if err != nil || len(second) < 2 {
		t.Fatalf("second IPv4 fragments = %d, %v", len(second), err)
	}
	for index, packet := range first {
		if id := binary.BigEndian.Uint16(packet[4:6]); id != 101 {
			t.Fatalf("first IPv4 fragment %d ID = %d, want 101", index, id)
		}
	}
	for index, packet := range second {
		if id := binary.BigEndian.Uint16(packet[4:6]); id != 102 {
			t.Fatalf("second IPv4 fragment %d ID = %d, want 102", index, id)
		}
	}
	atomic4, err := stack4.ipPayloadPackets(local4, remote4, ProtocolICMPv4, make([]byte, 8), false)
	if err != nil || len(atomic4) != 1 {
		t.Fatalf("atomic IPv4 packets = %d, %v", len(atomic4), err)
	}
	if id := binary.BigEndian.Uint16(atomic4[0][4:6]); id != 0 || binary.BigEndian.Uint16(atomic4[0][6:8])&0x4000 == 0 {
		t.Fatalf("atomic IPv4 ID/flags = %d/%#x, want 0/DF", id, binary.BigEndian.Uint16(atomic4[0][6:8]))
	}
	if got := stack4.ipv4ID.Load(); got != 102 {
		t.Fatalf("DF IPv4 consumed Identification: %d", got)
	}

	local6 := netip.MustParseAddr("2001:db8::41")
	remote6 := netip.MustParseAddr("2001:db8::42")
	stack6, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local6, 128)}, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	stack6.ipv6FragmentID.Store(1000)
	if _, err = stack6.ipPayloadPackets(local6, remote6, ProtocolUDP, make([]byte, 8), true); err != nil {
		t.Fatal(err)
	}
	if got := stack6.ipv6FragmentID.Load(); got != 1000 {
		t.Fatalf("unfragmented IPv6 consumed Fragment ID: %d", got)
	}
	fragments6, err := stack6.ipPayloadPackets(local6, remote6, ProtocolUDP, make([]byte, 1300), true)
	if err != nil || len(fragments6) < 2 {
		t.Fatalf("IPv6 fragments = %d, %v", len(fragments6), err)
	}
	for index, packet := range fragments6 {
		if id := binary.BigEndian.Uint32(packet[44:48]); id != 1001 {
			t.Fatalf("IPv6 fragment %d ID = %d, want 1001", index, id)
		}
	}
}

func TestDirectIPv6FragmentOutputOverwritesReusableHeader(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::43")
	remote := netip.MustParseAddr("2001:db8:1::43")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	dirty := bytes.Repeat([]byte{0xff}, 1280)
	stack.outbound.buffers <- dirty[:0]
	if err = stack.writeIPPayload(local, remote, ProtocolUDP, make([]byte, 1300), true); err != nil {
		t.Fatal(err)
	}
	entry, ok := stack.outbound.tryDequeue()
	if !ok {
		t.Fatal("missing first IPv6 fragment")
	}
	if len(entry.packet) != 1280 || entry.packet[40] != ProtocolUDP || entry.packet[41] != 0 {
		t.Fatalf("reused IPv6 fragment header = %x", entry.packet[40:48])
	}
	stack.outbound.release(entry)
	entry, ok = stack.outbound.tryDequeue()
	if !ok {
		t.Fatal("missing second IPv6 fragment")
	}
	stack.outbound.release(entry)
}

func TestDirectFragmentOutputPreservesPartialDeadlineEmission(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.44")
	remote := netip.MustParseAddr("198.51.100.44")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 68})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	dummy := buildIPPacket(local, remote, 99, []byte{1}, 0, true)
	for index := 0; index < cap(stack.outbound.free)-1; index++ {
		if !stack.outbound.tryEnqueue(dummy) {
			t.Fatalf("dummy packet %d was not queued", index)
		}
	}
	stack.ipv4ID.Store(100)
	var deadline socketDeadline
	deadline.set(time.Now().Add(20 * time.Millisecond))
	state := socketWriteState{deadline: &deadline, closed: make(chan struct{})}
	err = stack.writeIPPayloadUntilOptionsForMTU(local, remote, ProtocolUDP, make([]byte, 96), sourceFragmentation{allow: true}, ipPacketOptions{}, 68, state)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("fragmented write error = %v, want deadline exceeded", err)
	}
	fragments := 0
	for {
		entry, ok := stack.outbound.tryDequeue()
		if !ok {
			break
		}
		if len(entry.packet) >= 20 && entry.packet[9] == ProtocolUDP && binary.BigEndian.Uint16(entry.packet[6:8])&0x2000 != 0 {
			fragments++
			if identification := binary.BigEndian.Uint16(entry.packet[4:6]); identification != 101 {
				t.Fatalf("partial fragment ID = %d, want 101", identification)
			}
		}
		stack.outbound.release(entry)
	}
	if fragments != 1 {
		t.Fatalf("published fragments = %d, want 1", fragments)
	}
}

func TestMinimumSizeFragmentsReassembleRequiredPacket(t *testing.T) {
	for _, test := range []struct {
		name           string
		local, remote  netip.Addr
		payloadSize    int
		fragmentPacket int
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.45"), remote: netip.MustParseAddr("198.51.100.45"), payloadSize: 1480, fragmentPacket: 28},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::45"), remote: netip.MustParseAddr("2001:db8:1::45"), payloadSize: 1460, fragmentPacket: 56},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, stack := newTestStack(t, test.local, test.remote)
			payload := make([]byte, test.payloadSize)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, ProtocolUDP, payload, test.fragmentPacket, 45)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, ProtocolUDP, payload, test.fragmentPacket, 45, ipPacketOptions{})
			}
			if len(fragments) <= 128 || len(fragments) > fragmentMaximumPieces {
				t.Fatalf("fragment count = %d, want 129..%d", len(fragments), fragmentMaximumPieces)
			}
			var packet []byte
			for _, fragment := range fragments {
				packet = stack.reassemblePacket(fragment, time.Now())
			}
			parsed, ok := parseIPPacket(packet)
			if !ok || len(packet) != 1500 || !bytes.Equal(parsed.payload, payload) {
				t.Fatalf("minimum-fragment reassembly = packet %d payload %d parsed %v", len(packet), len(parsed.payload), ok)
			}
		})
	}
}

// TestFragmentOverlapDropsDatagram verifies the RFC 5722 overlap policy.
func TestFragmentOverlapDropsDatagram(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	payload := bytes.Repeat([]byte{0x44}, 3000)
	fragments := buildIPv4Fragments(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), ProtocolUDP, payload, 1280, 7)
	if len(fragments) < 2 {
		t.Fatal("test datagram was not fragmented")
	}
	if err := writeTestPacket(stack, fragments[0]); err != nil {
		t.Fatal(err)
	}
	overlap := append([]byte(nil), fragments[1]...)
	binary.BigEndian.PutUint16(overlap[6:8], 1|0x2000)
	overlap[10], overlap[11] = 0, 0
	binary.BigEndian.PutUint16(overlap[10:12], checksum(overlap[:20]))
	if err := writeTestPacket(stack, overlap); err != nil {
		t.Fatal(err)
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("overlapping fragments retained: sets=%d bytes=%d", sets, retained)
	}
}

func TestDuplicateFragmentPreservesReassembly(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.71"), remote: netip.MustParseAddr("192.0.2.72")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::71"), remote: netip.MustParseAddr("2001:db8::72")},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, stack := newTestStack(t, test.local, test.remote)
			payload := bytes.Repeat([]byte{0x71}, 3000)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, ProtocolUDP, payload, 1280, 71)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, ProtocolUDP, payload, 1280, 71, ipPacketOptions{})
			}
			if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
				t.Fatal("first fragment completed a datagram")
			}
			if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
				t.Fatal("duplicate fragment completed a datagram")
			}
			var packet []byte
			for _, fragment := range fragments[1:] {
				packet = stack.reassemblePacket(fragment, time.Now())
			}
			parsed, ok := parseIPPacket(packet)
			if !ok || !bytes.Equal(parsed.payload, payload) {
				t.Fatalf("duplicate-preserving reassembly = parsed %v payload %d", ok, len(parsed.payload))
			}
		})
	}
}

func TestFragmentReassemblySeparatesLoopbackAndDeviceInput(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.70")
	remote := netip.MustParseAddr("192.0.2.71")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 24)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	first := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 32), 36, 0x7071)[0]
	if packet, pending := stack.reassemblePacketStatus(first, time.Now(), false); packet != nil || !pending {
		t.Fatalf("device fragment = packet %v pending %v", packet != nil, pending)
	}
	if packet, pending := stack.reassemblePacketStatus(first, time.Now(), true); packet != nil || !pending {
		t.Fatalf("loopback fragment = packet %v pending %v", packet != nil, pending)
	}
	stack.fragmentMu.Lock()
	sets := len(stack.fragments)
	_, device := stack.fragments[fragmentKey{source: remote, target: local, identification: 0x7071, protocol: ProtocolUDP}]
	_, loopback := stack.fragments[fragmentKey{source: remote, target: local, identification: 0x7071, protocol: ProtocolUDP, loopback: true}]
	stack.fragmentMu.Unlock()
	if sets != 2 || !device || !loopback {
		t.Fatalf("fragment ingress domains = sets %d device %t loopback %t", sets, device, loopback)
	}
}

func TestDuplicateFragmentAtPieceLimitPreservesQueue(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.73"), netip.MustParseAddr("192.0.2.74"))
	key := fragmentKey{
		source: netip.MustParseAddr("192.0.2.74"), target: netip.MustParseAddr("192.0.2.73"),
		identification: 73, protocol: ProtocolUDP,
	}
	pieces := make([]fragmentPiece, fragmentMaximumPieces)
	for index := range pieces {
		pieces[index] = fragmentPiece{offset: index * 8, data: make([]byte, 8)}
	}
	stack.fragmentMu.Lock()
	stack.fragments[key] = &fragmentSet{
		pieces: pieces, total: -1, bytes: fragmentMaximumPieces * 8,
		created: time.Now(), updated: time.Now(), protocol: ProtocolUDP,
		source: key.source, target: key.target, identifier: key.identification,
		ecnMask: 1, maximum: fragmentMaximumDatagram - 20,
	}
	stack.fragmentBytes = fragmentMaximumPieces * 8
	stack.fragmentMu.Unlock()
	duplicate := buildIPv4Fragments(key.source, key.target, key.protocol, make([]byte, 16), 28, uint16(key.identification))[0]
	if packet, pending := stack.reassemblePacketStatus(duplicate, time.Now(), false); packet != nil || !pending {
		t.Fatalf("duplicate at piece limit = packet %v pending %v", packet != nil, pending)
	}
	stack.fragmentMu.Lock()
	retained := stack.fragments[key] != nil
	stack.fragmentMu.Unlock()
	if !retained {
		t.Fatal("duplicate fragment removed a full metadata queue")
	}
}

// TestIPv6FragmentUsesFirstNextHeader verifies that RFC 8200 permits Next
// Header differences and selects the value carried by the offset-zero
// fragment, including when a differing final fragment arrives first.
func TestIPv6FragmentUsesFirstNextHeader(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::1")
	remote := netip.MustParseAddr("2001:db8::2")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	payload := make([]byte, 24)
	fragments := buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, payload, 56, 7, ipPacketOptions{})
	if len(fragments) != 3 {
		t.Fatalf("fragment count = %d, want 3", len(fragments))
	}
	fragments[2][40] = ProtocolTCP
	if packet := stack.reassemblePacket(fragments[2], time.Now()); packet != nil {
		t.Fatal("final fragment completed a datagram")
	}
	if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
		t.Fatal("first fragment completed an incomplete datagram")
	}
	packet := stack.reassemblePacket(fragments[1], time.Now())
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.protocol != ProtocolUDP || !bytes.Equal(parsed.payload, payload) {
		t.Fatalf("reassembled packet uses wrong first-fragment metadata: protocol=%d payload=%x", parsed.protocol, parsed.payload)
	}
}

func TestIPv4ReassemblyPreservesHeaderOptions(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.81")
	remote := netip.MustParseAddr("192.0.2.82")
	_, stack := newTestStack(t, local, remote)
	fragments := buildIPv4Fragments(remote, local, 99, bytes.Repeat([]byte{0x5a}, 16), 28, 42)
	first := make([]byte, len(fragments[0])+4)
	copy(first[:20], fragments[0][:20])
	copy(first[20:24], []byte{1, 0, 0, 0})
	copy(first[24:], fragments[0][20:])
	first[0] = 0x46
	binary.BigEndian.PutUint16(first[2:4], uint16(len(first)))
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], checksum(first[:24]))
	if packet := stack.reassemblePacket(fragments[1], time.Now()); packet != nil {
		t.Fatal("tail fragment completed IPv4 datagram")
	}
	packet := stack.reassemblePacket(first, time.Now())
	if len(packet) != 40 || packet[0]&0x0f != 6 || !bytes.Equal(packet[20:24], []byte{1, 0, 0, 0}) || checksum(packet[:24]) != 0 {
		t.Fatalf("option-preserving IPv4 reassembly = %x", packet)
	}
}

func TestIPv6ReassemblyPreservesUnfragmentableHeaders(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::81")
	remote := netip.MustParseAddr("2001:db8::82")
	_, stack := newTestStack(t, local, remote)
	payload := bytes.Repeat([]byte{0x6b}, 16)
	fragments := make([][]byte, 2)
	for index := range fragments {
		fragmentPayload := make([]byte, 24)
		fragmentPayload[0] = 44 // Hop-by-Hop -> Fragment.
		fragmentPayload[8] = 99
		field := uint16(index * 8)
		if index == 0 {
			field |= 1
		}
		binary.BigEndian.PutUint16(fragmentPayload[10:12], field)
		binary.BigEndian.PutUint32(fragmentPayload[12:16], 77)
		copy(fragmentPayload[16:], payload[index*8:(index+1)*8])
		fragments[index] = buildIPPacket(remote, local, 0, fragmentPayload, 0, false)
	}
	if packet := stack.reassemblePacket(fragments[1], time.Now()); packet != nil {
		t.Fatal("tail fragment completed IPv6 datagram")
	}
	packet := stack.reassemblePacket(fragments[0], time.Now())
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.protocol != 99 || !bytes.Equal(parsed.payload, payload) || len(packet) != 64 || packet[6] != 0 || packet[40] != 99 {
		t.Fatalf("extension-preserving IPv6 reassembly = %x parsed=%+v ok=%v", packet, parsed, ok)
	}
}

// TestFragmentFinalLengthRejectsPriorTail verifies that a final fragment whose
// declared end precedes an already retained range invalidates the datagram.
func TestFragmentFinalLengthRejectsPriorTail(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::11")
	remote := netip.MustParseAddr("2001:db8::12")
	_, stack := newTestStack(t, local, remote)
	defer stack.Close()
	fragments := buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, make([]byte, 24), 56, 8, ipPacketOptions{})
	if len(fragments) != 3 {
		t.Fatalf("fragment count = %d, want 3", len(fragments))
	}
	high := append([]byte(nil), fragments[2]...)
	field := binary.BigEndian.Uint16(high[42:44]) | 1
	binary.BigEndian.PutUint16(high[42:44], field)
	if packet := stack.reassemblePacket(high, time.Now()); packet != nil {
		t.Fatal("high non-final fragment completed a datagram")
	}
	shortFinal := append([]byte(nil), fragments[1]...)
	field = binary.BigEndian.Uint16(shortFinal[42:44]) &^ 1
	binary.BigEndian.PutUint16(shortFinal[42:44], field)
	if packet := stack.reassemblePacket(shortFinal, time.Now()); packet != nil {
		t.Fatal("short final fragment completed a datagram")
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("invalid final length retained: sets=%d bytes=%d", sets, retained)
	}
}

// TestFragmentSetCapacityEvictsOldest verifies that incomplete traffic stays
// within its global set bound without preventing newer reassembly attempts.
func TestFragmentSetCapacityEvictsOldest(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.31")
	remote := netip.MustParseAddr("198.51.100.31")
	_, stack := newTestStack(t, local, remote)
	now := time.Now()
	for identifier := 1; identifier <= fragmentMaximumSets+1; identifier++ {
		fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 2000), 1280, uint16(identifier))
		if len(fragments) < 2 {
			t.Fatal("test payload was not fragmented")
		}
		if packet := stack.reassemblePacket(fragments[0], now.Add(time.Duration(identifier)*time.Millisecond)); packet != nil {
			t.Fatal("incomplete fragment produced a packet")
		}
	}
	stack.fragmentMu.Lock()
	sets := len(stack.fragments)
	_, oldestPresent := stack.fragments[fragmentKey{source: remote, target: local, identification: 1, protocol: ProtocolUDP}]
	stack.fragmentMu.Unlock()
	if sets != fragmentMaximumSets || oldestPresent {
		t.Fatalf("fragment sets = %d, oldest present = %v", sets, oldestPresent)
	}
	if evictions := stack.Stats().FragmentEvictions; evictions != 1 {
		t.Fatalf("fragment evictions = %d, want 1", evictions)
	}
}

func TestFragmentByteCapacityEvictsOldest(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.84")
	remote := netip.MustParseAddr("198.51.100.84")
	_, stack := newTestStack(t, local, remote)
	now := time.Now()
	oldKey := fragmentKey{source: remote, target: local, identification: 1, protocol: ProtocolUDP}
	old := &fragmentSet{
		total: -1, bytes: fragmentMaximumBytes - 1, created: now, updated: now.Add(-time.Second),
		source: remote, target: local, identifier: 1, maximum: fragmentMaximumDatagram - 20,
	}
	stack.fragmentMu.Lock()
	stack.fragments[oldKey] = old
	stack.fragmentBytes = old.bytes
	stack.fragmentMu.Unlock()
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 16), 28, 2)
	if packet := stack.reassemblePacket(fragments[0], now); packet != nil {
		t.Fatal("incomplete replacement fragment unexpectedly reassembled")
	}
	newKey := fragmentKey{source: remote, target: local, identification: 2, protocol: ProtocolUDP}
	stack.fragmentMu.Lock()
	_, oldPresent := stack.fragments[oldKey]
	newSet := stack.fragments[newKey]
	retained := stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if oldPresent || newSet == nil {
		t.Fatalf("byte-pressure sets: old present=%t new present=%t", oldPresent, newSet != nil)
	}
	if retained != len(fragments[0]) {
		t.Fatalf("retained bytes after byte-pressure eviction = %d, want %d", retained, len(fragments[0]))
	}
	if stack.Stats().FragmentEvictions == 0 {
		t.Fatal("byte-pressure eviction was not counted")
	}
}

func TestFragmentArrivalDoesNotExtendLifetime(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.41")
	remote := netip.MustParseAddr("198.51.100.41")
	_, stack := newTestStack(t, local, remote)
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 3000), 1280, 81)
	if len(fragments) < 3 {
		t.Fatal("test payload did not produce three fragments")
	}
	start := time.Now()
	if packet := stack.reassemblePacket(fragments[0], start); packet != nil {
		t.Fatal("first fragment completed a datagram")
	}
	if packet := stack.reassemblePacket(fragments[1], start.Add(fragmentIPv4Lifetime-time.Second)); packet != nil {
		t.Fatal("second fragment completed a datagram")
	}
	stack.fragmentMu.Lock()
	_ = stack.cleanFragmentsLocked(start.Add(fragmentIPv4Lifetime + time.Second))
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("late fragments extended lifetime: sets=%d bytes=%d", sets, retained)
	}
}

func TestFragmentTimesDoNotFollowLockAcquisitionOrder(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 24), 28, 97)
	if len(fragments) < 3 {
		t.Fatalf("fragment count = %d, want at least 3", len(fragments))
	}
	base := time.Unix(100, 0)
	if packet, pending := stack.reassemblePacketStatus(fragments[1], base.Add(time.Second), false); packet != nil || !pending {
		t.Fatalf("later fragment = packet %x pending %t", packet, pending)
	}
	if packet, pending := stack.reassemblePacketStatus(fragments[2], base, false); packet != nil || !pending {
		t.Fatalf("earlier fragment = packet %x pending %t", packet, pending)
	}
	parsed, ok := parseFragment(fragments[1])
	if !ok {
		t.Fatal("test fragment did not parse")
	}
	stack.fragmentMu.Lock()
	set := stack.fragments[parsed.key]
	stack.fragmentMu.Unlock()
	if set == nil {
		t.Fatal("incomplete fragment set was not retained")
	}
	if set.created != base {
		t.Fatalf("fragment creation time = %v, want %v", set.created, base)
	}
	if set.updated != base.Add(time.Second) {
		t.Fatalf("fragment update time = %v, want %v", set.updated, base.Add(time.Second))
	}
}

func TestNextFragmentExpiryUsesFirstArrivalAndAddressFamily(t *testing.T) {
	start := time.Unix(100, 0)
	stack := &Stack{fragments: map[fragmentKey]*fragmentSet{
		{identification: 1}:           {created: start.Add(time.Second)},
		{identification: 2, v6: true}: {created: start.Add(-20 * time.Second), v6: true},
	}}
	stack.fragmentMu.Lock()
	next, ok := stack.nextFragmentExpiryLocked()
	stack.fragmentMu.Unlock()
	// IPv4 expires at start+31s; IPv6 expires at start+40s.
	if !ok || next != start.Add(31*time.Second) {
		t.Fatalf("next fragment expiry = %v, %v; want %v, true", next, ok, start.Add(31*time.Second))
	}
}

func TestFragmentReassemblyTimeoutResponse(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		protocol      byte
		messageType   byte
		lifetime      time.Duration
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.43"), remote: netip.MustParseAddr("198.51.100.43"), protocol: ProtocolICMPv4, messageType: 11, lifetime: fragmentIPv4Lifetime},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::43"), remote: netip.MustParseAddr("2001:db8:1::43"), protocol: ProtocolICMPv6, messageType: 3, lifetime: fragmentIPv6Lifetime},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			payload := make([]byte, 2000)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, ProtocolUDP, payload, 1280, 42)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, ProtocolUDP, payload, 1280, 42, ipPacketOptions{})
			}
			start := time.Now()
			if packet := stack.reassemblePacket(fragments[0], start); packet != nil {
				t.Fatal("first fragment completed a datagram")
			}
			stack.expireFragments(start.Add(test.lifetime + time.Second))
			select {
			case response := <-link.outbound:
				parsed, ok := parseIPPacket(response)
				if !ok || parsed.protocol != test.protocol || len(parsed.payload) < 8 || parsed.payload[0] != test.messageType || parsed.payload[1] != 1 {
					t.Fatalf("fragment timeout response = %x", response)
				}
				if test.local.Is6() && len(response) > ipv6MinimumMTU {
					t.Fatalf("IPv6 timeout response size = %d, want <= %d", len(response), ipv6MinimumMTU)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for fragment reassembly error")
			}
			if timeouts := stack.Stats().FragmentTimeouts; timeouts != 1 {
				t.Fatalf("fragment timeouts = %d, want 1", timeouts)
			}
		})
	}
}

func TestFragmentReassemblyTimeoutSuppressesICMPError(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		protocol      byte
		messageType   byte
		lifetime      time.Duration
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.44"), remote: netip.MustParseAddr("198.51.100.44"), protocol: ProtocolICMPv4, messageType: 3, lifetime: fragmentIPv4Lifetime},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::44"), remote: netip.MustParseAddr("2001:db8:1::44"), protocol: ProtocolICMPv6, messageType: 1, lifetime: fragmentIPv6Lifetime},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			payload := make([]byte, 2000)
			payload[0] = test.messageType
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, test.protocol, payload, 1280, 43)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, test.protocol, payload, 1280, 43, ipPacketOptions{})
			}
			start := time.Now()
			_ = stack.reassemblePacket(fragments[0], start)
			stack.expireFragments(start.Add(test.lifetime + time.Second))
			select {
			case response := <-link.outbound:
				t.Fatalf("ICMP error fragment produced timeout response: %x", response)
			case <-time.After(25 * time.Millisecond):
			}
		})
	}
}

// FuzzFragmentParsing verifies that the direction-independent fragment parser
// rejects arbitrary envelopes without panicking.
func FuzzFragmentParsing(f *testing.F) {
	local := netip.MustParseAddr("192.0.2.32")
	remote := netip.MustParseAddr("198.51.100.32")
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, make([]byte, 2000), 1280, 1)
	local6 := netip.MustParseAddr("2001:db8::32")
	remote6 := netip.MustParseAddr("2001:db8:1::32")
	fragments6 := buildIPv6FragmentsWithOptions(remote6, local6, ProtocolUDP, make([]byte, 2000), 1280, 1, ipPacketOptions{})
	f.Add([]byte(nil))
	f.Add(fragments[0])
	f.Add(fragments6[0])
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65575 {
			packet = packet[:65575]
		}
		before := append([]byte(nil), packet...)
		fragment, ok := parseFragment(packet)
		if !bytes.Equal(packet, before) {
			t.Fatal("parseFragment modified its input")
		}
		if !ok {
			return
		}
		if len(fragment.original) == 0 || len(fragment.original) > len(packet) || !bytes.Equal(fragment.original, packet[:len(fragment.original)]) {
			t.Fatalf("fragment original length %d is not an input prefix of %d bytes", len(fragment.original), len(packet))
		}
		if !fragment.key.source.IsValid() || !fragment.key.target.IsValid() || fragment.key.source.Is4() != fragment.key.target.Is4() {
			t.Fatalf("fragment address families are invalid: %v -> %v", fragment.key.source, fragment.key.target)
		}
		if fragment.parameter {
			if fragment.parameterAt >= uint32(len(fragment.original)) {
				t.Fatalf("fragment parameter pointer %d is outside %d-byte packet", fragment.parameterAt, len(fragment.original))
			}
			return
		}
		if fragment.offset < 0 || fragment.offset&7 != 0 || fragment.maximum < 0 || len(fragment.payload) > fragment.maximum {
			t.Fatalf("invalid fragment bounds: offset %d payload %d maximum %d", fragment.offset, len(fragment.payload), fragment.maximum)
		}
		if len(fragment.header) == 0 || len(fragment.header) > len(fragment.original) || !bytes.Equal(fragment.header, fragment.original[:len(fragment.header)]) {
			t.Fatalf("fragment header length %d is not an original-packet prefix", len(fragment.header))
		}
		if fragment.nextHeader < 0 || fragment.nextHeader >= len(fragment.header) {
			t.Fatalf("next-header offset %d is outside %d-byte header", fragment.nextHeader, len(fragment.header))
		}
		if len(fragment.payload) > len(fragment.original) || !bytes.Equal(fragment.payload, fragment.original[len(fragment.original)-len(fragment.payload):]) {
			t.Fatalf("fragment payload length %d is not an original-packet suffix", len(fragment.payload))
		}
	})
}

// checkFragmentFuzzResources verifies bounded reassembly storage and exact
// retained-byte accounting after each fuzzed fragment.
func checkFragmentFuzzResources(t testing.TB, stack *Stack) {
	t.Helper()
	stack.fragmentMu.Lock()
	defer stack.fragmentMu.Unlock()
	if len(stack.fragments) > fragmentMaximumSets || stack.fragmentBytes < 0 || stack.fragmentBytes > fragmentMaximumBytes {
		t.Fatalf("fragment resources = %d sets, %d bytes", len(stack.fragments), stack.fragmentBytes)
	}
	retainedBytes := 0
	for _, set := range stack.fragments {
		if len(set.pieces) > fragmentMaximumPieces || set.bytes < 0 {
			t.Fatalf("fragment set resources = %d pieces, %d bytes", len(set.pieces), set.bytes)
		}
		payloadBytes := 0
		previousEnd := 0
		for index, piece := range set.pieces {
			if len(piece.data) == 0 || piece.offset < 0 || index != 0 && piece.offset < previousEnd {
				t.Fatalf("invalid retained fragment piece at %d: offset %d length %d after %d", index, piece.offset, len(piece.data), previousEnd)
			}
			previousEnd = piece.offset + len(piece.data)
			payloadBytes += len(piece.data)
		}
		if payloadBytes > set.bytes {
			t.Fatalf("fragment set retained %d payload bytes but accounts for %d", payloadBytes, set.bytes)
		}
		retainedBytes += set.bytes
	}
	if retainedBytes != stack.fragmentBytes {
		t.Fatalf("fragment byte accounting = %d, want %d", stack.fragmentBytes, retainedBytes)
	}
}

// FuzzFragmentReassemblyOrder exercises duplicate, missing, and reordered
// fragments while requiring every completed datagram to remain parseable.
func FuzzFragmentReassemblyOrder(f *testing.F) {
	f.Add([]byte{0, 1, 2}, false)
	f.Add([]byte{2, 1, 0}, false)
	f.Add([]byte{0, 0, 2, 1}, true)
	f.Fuzz(func(t *testing.T, order []byte, ipv6 bool) {
		if len(order) > 64 {
			order = order[:64]
		}
		local := netip.MustParseAddr("192.0.2.33")
		remote := netip.MustParseAddr("198.51.100.33")
		bits := 32
		if ipv6 {
			local = netip.MustParseAddr("2001:db8::33")
			remote = netip.MustParseAddr("2001:db8:1::33")
			bits = 128
		}
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}, MTU: 1280})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		payload := make([]byte, 3000)
		for index := range payload {
			payload[index] = byte(index*31 + 7)
		}
		var fragments [][]byte
		if ipv6 {
			fragments = buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, payload, 1280, 77, ipPacketOptions{})
		} else {
			fragments = buildIPv4Fragments(remote, local, ProtocolUDP, payload, 1280, 77)
		}
		now := time.Unix(100, 0)
		for _, selected := range order {
			packet := stack.reassemblePacket(fragments[int(selected)%len(fragments)], now)
			checkFragmentFuzzResources(t, stack)
			if packet == nil {
				continue
			}
			parsed, ok := parseIPPacket(packet)
			if !ok || parsed.protocol != ProtocolUDP || !bytes.Equal(parsed.payload, payload) {
				t.Fatalf("reassembled fuzz datagram = protocol %d payload %d parsed %t", parsed.protocol, len(parsed.payload), ok)
			}
		}
	})
}

// FuzzFragmentReassemblyOverlap varies offsets and payload bytes to exercise
// duplicate acceptance, RFC 5722 overlap rejection, and resource accounting.
func FuzzFragmentReassemblyOverlap(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0, 1, 1, 1, 1}, false)
	f.Add([]byte{1, 0, 1, 7, 0, 1, 1, 9}, true)
	f.Add([]byte{
		0, 0, 1, 0,
		1, 1, 1, 0,
		2, 2, 1, 0,
		3, 3, 1, 0,
		4, 4, 1, 0,
		5, 5, 1, 0,
		0, 6, 0, 0,
	}, false)
	f.Fuzz(func(t *testing.T, events []byte, ipv6 bool) {
		if len(events) > 160 {
			events = events[:160]
		}
		local := netip.MustParseAddr("192.0.2.34")
		remote := netip.MustParseAddr("198.51.100.34")
		bits := 32
		payload := make([]byte, 48)
		for index := range payload {
			payload[index] = byte(index*17 + 5)
		}
		var fragments [][]byte
		if ipv6 {
			local = netip.MustParseAddr("2001:db8::34")
			remote = netip.MustParseAddr("2001:db8:1::34")
			bits = 128
			fragments = buildIPv6FragmentsWithOptions(remote, local, ProtocolUDP, payload, 56, 78, ipPacketOptions{})
		} else {
			fragments = buildIPv4Fragments(remote, local, ProtocolUDP, payload, 28, 78)
		}
		stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}, MTU: 1280})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		now := time.Unix(200, 0)
		maximumEnd := 0
		for offset := 0; offset+4 <= len(events); offset += 4 {
			packet := append([]byte(nil), fragments[int(events[offset])%len(fragments)]...)
			fragment, ok := parseFragment(packet)
			if !ok || len(fragment.payload) == 0 {
				t.Fatal("generated base fragment is not parseable")
			}
			payloadOffset := len(fragment.original) - len(fragment.payload)
			packet[payloadOffset] ^= events[offset+3]
			fragmentOffset := int(events[offset+1]&7) * 8
			if end := fragmentOffset + len(fragment.payload); end > maximumEnd {
				maximumEnd = end
			}
			more := events[offset+2]&1 != 0
			if events[offset+2]&2 != 0 {
				more = false
			}
			if ipv6 {
				field := uint16(fragmentOffset &^ 7)
				if more {
					field |= 1
				}
				binary.BigEndian.PutUint16(packet[42:44], field)
			} else {
				field := uint16(fragmentOffset / 8)
				if more {
					field |= 0x2000
				}
				binary.BigEndian.PutUint16(packet[6:8], field)
				packet[10], packet[11] = 0, 0
				binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
			}
			reassembled := stack.reassemblePacket(packet, now)
			checkFragmentFuzzResources(t, stack)
			if reassembled == nil {
				continue
			}
			parsed, valid := parseIPPacket(reassembled)
			if !valid || parsed.protocol != ProtocolUDP || len(parsed.payload) > maximumEnd {
				t.Fatalf("overlap reassembly produced invalid packet: parsed=%t protocol=%d payload=%d", valid, parsed.protocol, len(parsed.payload))
			}
		}
	})
}

// FuzzIPPayloadFragmentationRoundTrip verifies that source fragmentation and
// inbound reassembly are inverse operations across packet-size boundaries.
func FuzzIPPayloadFragmentationRoundTrip(f *testing.F) {
	f.Add([]byte("short"), false, uint16(1500), byte(ProtocolUDP), byte(64), byte(0), uint32(0), false)
	f.Add(make([]byte, 1500), false, uint16(68), byte(ProtocolTCP), byte(1), byte(0xff), uint32(0), true)
	f.Add(make([]byte, 3000), true, uint16(1280), byte(99), byte(255), byte(0x2e), uint32(0xabcde), true)
	f.Fuzz(func(t *testing.T, payload []byte, ipv6 bool, mtuSeed uint16, protocol, hopLimit, trafficClass byte, flowLabel uint32, reverse bool) {
		if len(payload) > 4096 {
			payload = payload[:4096]
		}
		original := append([]byte(nil), payload...)
		source := netip.MustParseAddr("198.51.100.35")
		target := netip.MustParseAddr("192.0.2.35")
		mtu := 68 + int(mtuSeed)%1433
		if ipv6 {
			source = netip.MustParseAddr("2001:db8:1::35")
			target = netip.MustParseAddr("2001:db8::35")
			mtu = ipv6MinimumMTU + int(mtuSeed)%(1501-ipv6MinimumMTU)
			protocols := [...]byte{ProtocolTCP, ProtocolUDP, ProtocolICMPv6, 253, 254}
			protocol = protocols[int(protocol)%len(protocols)]
		} else {
			protocols := [...]byte{ProtocolTCP, ProtocolUDP, ProtocolICMPv4, 253, 254}
			protocol = protocols[int(protocol)%len(protocols)]
		}
		stack, err := New(Config{
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(target, target.BitLen())},
			MTU:            1500,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer stack.Close()
		if hopLimit == 0 {
			hopLimit = 1
		}
		options := ipPacketOptions{
			hopLimit: hopLimit, trafficClass: trafficClass, flowLabel: flowLabel & ipv6MaximumFlowLabel,
			hopLimitSet: true, trafficClassSet: true, flowLabelSet: true,
		}
		packets, err := stack.ipPayloadPacketsForMTU(
			source, target, protocol, payload, sourceFragmentation{allow: true}, options, mtu,
		)
		if err != nil {
			t.Fatalf("fragmentation of %d-byte payload at MTU %d: %v", len(payload), mtu, err)
		}
		if len(packets) == 0 {
			t.Fatal("fragmentation returned no packets")
		}
		if !bytes.Equal(payload, original) {
			t.Fatal("fragmentation modified caller payload")
		}
		for index, packet := range packets {
			if len(packet) > mtu {
				t.Fatalf("fragment %d has %d bytes, want at most MTU %d", index, len(packet), mtu)
			}
			if len(packets) > 1 {
				if _, ok := parseFragment(packet); !ok {
					t.Fatalf("generated fragment %d is not parseable", index)
				}
			}
		}

		var completed []byte
		if len(packets) == 1 {
			completed = packets[0]
		} else {
			now := time.Unix(300, 0)
			for step := range packets {
				index := step
				if reverse {
					index = len(packets) - 1 - step
				}
				packet := stack.reassemblePacket(packets[index], now)
				if step != len(packets)-1 && packet != nil {
					t.Fatalf("reassembly completed after %d of %d fragments", step+1, len(packets))
				}
				if packet != nil {
					completed = packet
				}
			}
			checkFragmentFuzzResources(t, stack)
		}
		parsed, ok := parseIPPacket(completed)
		if !ok || parsed.parameterError {
			t.Fatalf("fragmentation round trip produced an invalid packet: parsed=%t metadata=%+v", ok, parsed)
		}
		if parsed.source != source || parsed.target != target || parsed.protocol != protocol || !bytes.Equal(parsed.payload, payload) {
			t.Fatalf("fragmentation round trip = %s -> %s protocol %d payload %d", parsed.source, parsed.target, parsed.protocol, len(parsed.payload))
		}
		if parsed.hopLimit != hopLimit || parsed.trafficClass != trafficClass {
			t.Fatalf("fragmentation changed hop limit/traffic class to %d/%#x, want %d/%#x", parsed.hopLimit, parsed.trafficClass, hopLimit, trafficClass)
		}
		if ipv6 && parsed.flowLabel != options.flowLabel {
			t.Fatalf("fragmentation changed flow label to %#x, want %#x", parsed.flowLabel, options.flowLabel)
		}
	})
}

// TestFragmentECNReassembly verifies CE preservation and rejection of invalid
// Not-ECT/ECT combinations across an IPv4 fragment set.
func TestFragmentECNReassembly(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	fragments := buildIPv4Fragments(link.remote, link.local, ProtocolUDP, make([]byte, 2000), 1280, 91)
	if len(fragments) != 2 {
		t.Fatalf("fragment count = %d, want 2", len(fragments))
	}
	setPacketECN(fragments[0], 2)
	setPacketECN(fragments[1], 3)
	if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
		t.Fatal("first fragment completed a datagram")
	}
	packet := stack.reassemblePacket(fragments[1], time.Now())
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.ecn != 3 {
		t.Fatalf("reassembled ECN = %d, valid = %v, want CE", parsed.ecn, ok)
	}

	fragments = buildIPv4Fragments(link.remote, link.local, ProtocolUDP, make([]byte, 2000), 1280, 92)
	setPacketECN(fragments[0], 0)
	setPacketECN(fragments[1], 2)
	_ = stack.reassemblePacket(fragments[0], time.Now())
	if packet = stack.reassemblePacket(fragments[1], time.Now()); packet != nil {
		t.Fatal("mixed Not-ECT/ECT fragment set was accepted")
	}

	fragments = buildIPv4Fragments(link.remote, link.local, ProtocolUDP, make([]byte, 3000), 1280, 93)
	setPacketECN(fragments[0], 1)
	setPacketECN(fragments[1], 2)
	setPacketECN(fragments[2], 3)
	_ = stack.reassemblePacket(fragments[0], time.Now())
	_ = stack.reassemblePacket(fragments[1], time.Now())
	packet = stack.reassemblePacket(fragments[2], time.Now())
	parsed, ok = parseIPPacket(packet)
	if !ok || parsed.ecn != 3 {
		t.Fatalf("mixed ECT(0)/ECT(1)/CE reassembly = %d, valid = %v, want CE", parsed.ecn, ok)
	}

	if ecn, valid := fragmentECN(1<<1 | 1<<2); valid {
		t.Fatalf("mixed ECT(0)/ECT(1) result = %d, valid = true, want invalid", ecn)
	}
}

func TestIncompleteFragmentIsNotCountedAsDropped(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.90")
	remote := netip.MustParseAddr("198.51.100.90")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	udp := make([]byte, udpHeaderSize+16)
	binary.BigEndian.PutUint16(udp[0:2], 50000)
	binary.BigEndian.PutUint16(udp[2:4], 50001)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:8], transportChecksum(remote, local, ProtocolUDP, udp))
	fragments := buildIPv4Fragments(remote, local, ProtocolUDP, udp, 28, 1)
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	if err = writeTestPacket(stack, fragments[0]); err != nil {
		t.Fatal(err)
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 0 {
		t.Fatalf("incomplete valid fragment counted as dropped: %d", dropped)
	}
}

func TestIPv4FragmentsWithDontFragmentAreAccepted(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.94")
	target := netip.MustParseAddr("192.0.2.94")
	payload := make([]byte, 24)
	fragments := buildIPv4Fragments(source, target, ProtocolUDP, payload, 28, 1)
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	stack := &Stack{fragments: make(map[fragmentKey]*fragmentSet), fragmentWake: make(chan struct{}, 1)}
	stack.network.Store(&networkState{local: map[netip.Addr]struct{}{target: {}}})
	var packet []byte
	for index := range fragments {
		field := binary.BigEndian.Uint16(fragments[index][6:8]) | 0x4000
		binary.BigEndian.PutUint16(fragments[index][6:8], field)
		fragments[index][10], fragments[index][11] = 0, 0
		binary.BigEndian.PutUint16(fragments[index][10:12], checksum(fragments[index][:20]))
		packet = stack.reassemblePacket(fragments[index], time.Now())
		if index == 0 && stack.fragmentBytes != len(fragments[index]) {
			t.Fatalf("retained first-fragment bytes = %d, want allocation size %d", stack.fragmentBytes, len(fragments[index]))
		}
	}
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.protocol != ProtocolUDP || !bytes.Equal(parsed.payload, payload) {
		t.Fatalf("DF fragment reassembly = %+v, parsed = %v", parsed, ok)
	}
	if field := binary.BigEndian.Uint16(packet[6:8]); field&0x4000 == 0 {
		t.Fatalf("reassembled IPv4 flags = %#x, want DF", field)
	}
}

// TestIPv4FragmentWithReservedFlagIsRejected verifies that the reserved flag
// cannot create reassembly state.
func TestIPv4FragmentWithReservedFlagIsRejected(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.95")
	target := netip.MustParseAddr("192.0.2.95")
	fragments := buildIPv4Fragments(source, target, ProtocolUDP, make([]byte, 24), 28, 2)
	field := binary.BigEndian.Uint16(fragments[0][6:8]) | 0x8000
	binary.BigEndian.PutUint16(fragments[0][6:8], field)
	fragments[0][10], fragments[0][11] = 0, 0
	binary.BigEndian.PutUint16(fragments[0][10:12], checksum(fragments[0][:20]))
	if _, ok := parseFragment(fragments[0]); ok {
		t.Fatal("fragment with reserved flag was accepted")
	}
}

// TestIPv4FragmentOptionsLimit verifies that reassembly never constructs an
// original datagram larger than the 16-bit IPv4 total length. The last
// fragment is tested both before and after the option-bearing first fragment.
func TestIPv4FragmentOptionsLimit(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.96")
	target := netip.MustParseAddr("192.0.2.96")
	first := buildTestIPv4Options(source, target, []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(first[4:6], 3)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], checksum(first[:24]))
	last := buildIPPacket(source, target, ProtocolUDP, make([]byte, 8), 3, false)
	binary.BigEndian.PutUint16(last[6:8], 8188)
	last[10], last[11] = 0, 0
	binary.BigEndian.PutUint16(last[10:12], checksum(last[:20]))

	for _, order := range []struct {
		name    string
		packets [][]byte
	}{
		{name: "first fragment first", packets: [][]byte{first, last}},
		{name: "last fragment first", packets: [][]byte{last, first}},
	} {
		t.Run(order.name, func(t *testing.T) {
			_, stack := newTestStack(t, target, source)
			defer stack.Close()
			for _, packet := range order.packets {
				if reassembled := stack.reassemblePacket(packet, time.Now()); reassembled != nil {
					t.Fatal("oversized option-bearing datagram was reassembled")
				}
			}
			stack.fragmentMu.Lock()
			sets, retained := len(stack.fragments), stack.fragmentBytes
			stack.fragmentMu.Unlock()
			if sets != 0 || retained != 0 {
				t.Fatalf("oversized fragment set retained: sets=%d bytes=%d", sets, retained)
			}
		})
	}
}

func BenchmarkFragmentReassembly(b *testing.B) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.240"), remote: netip.MustParseAddr("198.51.100.240")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::240"), remote: netip.MustParseAddr("2001:db8:1::240")},
	} {
		b.Run(test.name, func(b *testing.B) {
			_, stack := newTestStack(b, test.local, test.remote)
			payload := bytes.Repeat([]byte{0x5a}, 60*1024)
			var fragments [][]byte
			if test.local.Is4() {
				fragments = buildIPv4Fragments(test.remote, test.local, ProtocolUDP, payload, 1280, 240)
			} else {
				fragments = buildIPv6FragmentsWithOptions(test.remote, test.local, ProtocolUDP, payload, 1280, 240, ipPacketOptions{})
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var packet []byte
				for _, fragment := range fragments {
					packet = stack.reassemblePacket(fragment, time.Now())
				}
				if len(packet) == 0 {
					b.Fatal("fragment sequence did not reassemble")
				}
			}
		})
	}
}

func BenchmarkIPv6FragmentBuild(b *testing.B) {
	source := netip.MustParseAddr("2001:db8::241")
	target := netip.MustParseAddr("2001:db8:1::241")
	payload := bytes.Repeat([]byte{0x6b}, 60*1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for iteration := 0; iteration < b.N; iteration++ {
		fragments := buildIPv6FragmentsWithOptions(source, target, ProtocolUDP, payload, 1280, uint32(iteration), ipPacketOptions{})
		if len(fragments) == 0 {
			b.Fatal("payload was not fragmented")
		}
	}
}

func BenchmarkFragmentRangeCovered(b *testing.B) {
	pieces := make([]fragmentPiece, fragmentMaximumPieces)
	for index := range pieces {
		pieces[index] = fragmentPiece{offset: index * 8, data: make([]byte, 8)}
	}
	end := len(pieces) * 8
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if !fragmentRangeCovered(pieces, 0, end) {
			b.Fatal("contiguous range was not covered")
		}
	}
}
