package mipstack

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// FuzzHandlePacket verifies that arbitrary L3 input cannot panic the stack.
func FuzzHandlePacket(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x45, 0, 0, 20})
	f.Add(buildIPPacket(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), protocolUDP, make([]byte, 8), 1, false))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
		defer stack.Close()
		_ = writeTestPacket(stack, packet)
	})
}

func TestStrictIPOptionsAndUnsupportedProtocols(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.50")
	remote4 := netip.MustParseAddr("198.51.100.50")
	validIPv4 := buildTestIPv4Options(remote4, local4, []byte{1, 0, 0, 0})
	if _, ok := parseIPPacket(validIPv4); !ok {
		t.Fatal("valid IPv4 options were rejected")
	}
	for _, options := range [][]byte{{7, 1, 0, 0}, {0, 1, 0, 0}} {
		parsed, ok := parseIPPacket(buildTestIPv4Options(remote4, local4, options))
		if !ok || !parsed.parameterError || parsed.parameterCode != 0 {
			t.Fatalf("malformed IPv4 options = %+v, %v for %x", parsed, ok, options)
		}
	}
	for _, test := range []struct {
		options []byte
		pointer uint32
	}{
		{[]byte{7, 2, 0, 0}, 21},
		{[]byte{7, 3, 3, 0}, 22},
		{[]byte{68, 4, 4, 0}, 22},
		{[]byte{68, 4, 5, 0xf0}, 23},
		{[]byte{148, 3, 0, 0}, 21},
		{[]byte{131, 2, 0, 0}, 21},
	} {
		parsed, ok := parseIPPacket(buildTestIPv4Options(remote4, local4, test.options))
		if !ok || !parsed.parameterError || parsed.parameterAt != test.pointer {
			t.Fatalf("IPv4 option %x = %+v, %v; want pointer %d", test.options, parsed, ok, test.pointer)
		}
	}
	// Linux accepts reserved timestamp flags on received packets even though
	// RFC 791 defines only 0, 1, and 3; strict validation is limited to locally
	// generated options without CAP_NET_RAW.
	reservedTimestampFlag := buildTestIPv4Options(remote4, local4, []byte{68, 4, 5, 2})
	if parsed, ok := parseIPPacket(reservedTimestampFlag); !ok || parsed.parameterError {
		t.Fatalf("Linux-compatible reserved timestamp flag = %+v, parsed=%t", parsed, ok)
	}
	duplicateRoute := buildTestIPv4Options(remote4, local4, []byte{7, 3, 4, 7, 3, 4, 0, 0})
	parsedRoute, ok := parseIPPacket(duplicateRoute)
	if !ok || !parsedRoute.parameterError || parsedRoute.parameterAt != 23 {
		t.Fatalf("duplicate IPv4 record route = %+v, %v", parsedRoute, ok)
	}
	if _, ok := parseIPPacket(buildTestIPv4Options(remote4, local4, []byte{131, 3, 4, 0})); ok {
		t.Fatal("unsupported IPv4 source route was accepted")
	}

	local6 := netip.MustParseAddr("2001:db8::50")
	remote6 := netip.MustParseAddr("2001:db8::51")
	if _, ok := parseIPPacket(buildTestIPv6Extension(remote6, local6, 60, []byte{protocolUDP, 0, 0x40, 0, 0, 0, 0, 0})); ok {
		t.Fatal("IPv6 discard-action option was accepted")
	}
	routingError, ok := parseIPPacket(buildTestIPv6Extension(remote6, local6, 43, []byte{protocolUDP, 0, 99, 1, 0, 0, 0, 0}))
	if !ok || !routingError.parameterError || routingError.parameterCode != 0 || routingError.parameterAt != 42 {
		t.Fatalf("active IPv6 routing header = %+v, parsed = %v", routingError, ok)
	}
	misplacedHopPayload := append([]byte{0, 0, 0, 0, 0, 0, 0, 0}, protocolUDP, 0, 0, 0, 0, 0, 0, 0)
	misplacedHop := buildIPPacket(remote6, local6, 60, misplacedHopPayload, 0, false)
	misplacedHopError, ok := parseIPPacket(misplacedHop)
	if !ok || !misplacedHopError.parameterError || misplacedHopError.parameterCode != 1 || misplacedHopError.parameterAt != 40 {
		t.Fatalf("misplaced IPv6 Hop-by-Hop header = %+v, parsed = %v", misplacedHopError, ok)
	}
	jumbogram := buildIPPacket(remote6, local6, protocolUDP, []byte{1}, 0, true)
	jumbogram[4], jumbogram[5] = 0, 0
	if _, ok := parseIPPacket(jumbogram); ok {
		t.Fatal("unsupported IPv6 jumbogram was accepted as an empty packet")
	}

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
	t.Cleanup(func() { _ = stack.Close() })
	unsupportedOption := buildTestIPv6Extension(remote6, local6, 60, []byte{protocolUDP, 0, 0x80, 0, 0, 0, 0, 0})
	if err = writeTestPacket(stack, unsupportedOption); err != nil {
		t.Fatal(err)
	}
	response := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != protocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 2 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 unsupported-option response = %x", response)
	}
	malformedIPv4 := buildTestIPv4Options(remote4, local4, []byte{7, 1, 0, 0})
	if err = writeTestPacket(stack, malformedIPv4); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != protocolICMPv4 || len(parsed.payload) < 8 || parsed.payload[0] != 12 || parsed.payload[1] != 0 || parsed.payload[4] != 20 {
		t.Fatalf("IPv4 malformed-option response = %x", response)
	}
	nonInitial := append([]byte(nil), malformedIPv4...)
	binary.BigEndian.PutUint16(nonInitial[6:8], 1)
	nonInitial[10], nonInitial[11] = 0, 0
	headerSize := int(nonInitial[0]&0x0f) * 4
	binary.BigEndian.PutUint16(nonInitial[10:12], checksum(nonInitial[:headerSize]))
	if err = writeTestPacket(stack, nonInitial); err != nil {
		t.Fatal(err)
	}
	select {
	case response = <-stack.outbound:
		t.Fatalf("non-initial malformed fragment produced Parameter Problem: %x", response)
	case <-time.After(25 * time.Millisecond):
	}
	activeRouting := buildTestIPv6Extension(remote6, local6, 43, []byte{protocolUDP, 0, 99, 1, 0, 0, 0, 0})
	if err = writeTestPacket(stack, activeRouting); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != protocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 0 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 routing-header response = %x", response)
	}
	if err = writeTestPacket(stack, misplacedHop); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != protocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 40 {
		t.Fatalf("misplaced IPv6 Hop-by-Hop response = %x", response)
	}
	icmpErrorWithUnknownOption := buildTestIPv6Extension(remote6, local6, 60, []byte{protocolICMPv6, 0, 0x80, 0, 0, 0, 0, 0})
	icmpErrorWithUnknownOption = append(icmpErrorWithUnknownOption, 1, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(icmpErrorWithUnknownOption[4:6], uint16(len(icmpErrorWithUnknownOption)-40))
	if err = writeTestPacket(stack, icmpErrorWithUnknownOption); err != nil {
		t.Fatal(err)
	}
	select {
	case response = <-stack.outbound:
		t.Fatalf("ICMPv6 error produced recursive Parameter Problem: %x", response)
	case <-time.After(25 * time.Millisecond):
	}
	if err = writeTestPacket(stack, buildIPPacket(remote4, local4, 99, []byte{1, 2, 3, 4}, 1, true)); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != protocolICMPv4 || len(parsed.payload) < 8 || parsed.payload[0] != 3 || parsed.payload[1] != 2 {
		t.Fatalf("IPv4 unsupported-protocol response = %x", response)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote6, local6, 100, []byte{1, 2, 3, 4}, 0, true)); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != protocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 6 {
		t.Fatalf("IPv6 unsupported-protocol response = %x", response)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote6, local6, 59, nil, 0, true)); err != nil {
		t.Fatal(err)
	}
	select {
	case response = <-stack.outbound:
		t.Fatalf("IPv6 No Next Header produced a response: %x", response)
	default:
	}
}

// TestIPv6ExtensionHeadersFollowReceiverRules verifies RFC 8200's distinction
// between the recommended source ordering and mandatory receiver behavior.
// Repeated Destination, Routing-with-zero-Segments-Left, and atomic Fragment
// headers remain safely traversable within the packet's bounded payload.
func TestIPv6ExtensionHeadersFollowReceiverRules(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::60")
	remote := netip.MustParseAddr("2001:db8::61")
	payload := make([]byte, 0, 7*8)
	payload = append(payload, 43, 0, 0, 0, 0, 0, 0, 0)  // Destination -> Routing.
	payload = append(payload, 60, 0, 99, 0, 0, 0, 0, 0) // Routing -> Destination.
	payload = append(payload, 43, 0, 0, 0, 0, 0, 0, 0)  // Destination -> Routing.
	payload = append(payload, 60, 0, 99, 0, 0, 0, 0, 0) // Routing -> Destination.
	payload = append(payload, 44, 0, 0, 0, 0, 0, 0, 0)  // Destination -> Fragment.
	payload = append(payload, 44, 0, 0, 0, 0, 0, 0, 1)  // Atomic Fragment -> Fragment.
	payload = append(payload, protocolUDP, 0, 0, 0, 0, 0, 0, 2)
	payload = append(payload, 1, 2, 3, 4, 5, 6, 7, 8)
	parsed, ok := parseIPPacket(buildIPPacket(remote, local, 60, payload, 0, false))
	if !ok || parsed.protocol != protocolUDP || len(parsed.payload) != 8 {
		t.Fatalf("repeated IPv6 extension headers = %+v, parsed = %t", parsed, ok)
	}
}

func TestForeignLoopbackSourceIsDropped(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, source netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.60"), source: netip.MustParseAddr("127.0.0.2")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::60"), source: netip.IPv6Loopback()},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.source)
			request := buildTestUDP(test.source, test.local, 55000, 55001, []byte("drop"))
			if err := writeTestPacket(stack, request); err != nil {
				t.Fatal(err)
			}
			select {
			case response := <-link.outbound:
				t.Fatalf("foreign loopback source produced a response: %x", response)
			case <-time.After(25 * time.Millisecond):
			}
			if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
				t.Fatalf("foreign loopback drops = %d, want 1", dropped)
			}
		})
	}
}

func TestIPv4MappedIPv6WireSourceIsDropped(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::62")
	remote := netip.MustParseAddr("2001:db8::63")
	_, stack := newTestStack(t, local, remote)
	packet := buildIPPacket(remote, local, 99, []byte{1}, 0, true)
	mapped := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	copy(packet[8:24], mapped[:])
	before := stack.Stats().InboundDroppedPackets
	if err := writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if after := stack.Stats().InboundDroppedPackets; after != before+1 {
		t.Fatalf("mapped IPv6 source drop count = %d, want %d", after, before+1)
	}
	select {
	case response := <-stack.outbound:
		t.Fatalf("mapped IPv6 source produced response: %x", response)
	default:
	}
}

func TestIPv4DirectedBroadcastSourceIsDropped(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.60")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.60/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packet := buildTestUDP(netip.MustParseAddr("192.0.2.255"), local, 55000, 55001, []byte("drop"))
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-stack.outbound:
		t.Fatalf("directed-broadcast source produced a response: %x", response)
	case <-time.After(25 * time.Millisecond):
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("directed-broadcast source drops = %d, want 1", dropped)
	}
}

func TestICMPProtocolMustMatchIPFamily(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::70")
	remote := netip.MustParseAddr("2001:db8::71")
	link, stack := newTestStack(t, local, remote)
	echo := make([]byte, 8)
	echo[0] = 8
	binary.BigEndian.PutUint16(echo[2:4], checksum(echo))
	if err := writeTestPacket(stack, buildIPPacket(remote, local, protocolICMPv4, echo, 0, true)); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cross-family protocol error")
	}
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != protocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 {
		t.Fatalf("cross-family ICMP response = %x", response)
	}
}

func BenchmarkParseIPPacket(b *testing.B) {
	for _, test := range []struct {
		name   string
		packet []byte
	}{
		{name: "IPv4", packet: buildTestUDP(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("192.0.2.1"), 50000, 443, make([]byte, 1200))},
		{name: "IPv6", packet: buildTestUDP(netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8::1"), 50000, 443, make([]byte, 1200))},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.packet)))
			for index := 0; index < b.N; index++ {
				if _, ok := parseIPPacket(test.packet); !ok {
					b.Fatal("valid packet was rejected")
				}
			}
		})
	}
}
