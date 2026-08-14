package mipstack

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func referenceChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(data[0])<<8 | uint32(data[1])
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestChecksumMatchesReference(t *testing.T) {
	data := make([]byte, 65535)
	for index := range data {
		data[index] = byte(index*37 + 11)
	}
	for _, size := range []int{0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 1500, 65534, 65535} {
		if got, want := checksum(data[:size]), referenceChecksum(data[:size]); got != want {
			t.Fatalf("checksum at length %d = %#x, want %#x", size, got, want)
		}
	}
}

func TestTransportChecksumMatchesReference(t *testing.T) {
	payload := make([]byte, 65535)
	for index := range payload {
		payload[index] = byte(index*53 + 17)
	}
	for _, test := range []struct {
		name           string
		source, target netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("192.0.2.129"), netip.MustParseAddr("198.51.100.231")},
		{"IPv6", netip.MustParseAddr("2001:db8:ffff:1::abcd"), netip.MustParseAddr("fdff:ffff:ffff:ffff::1234")},
	} {
		for _, size := range []int{0, 1, 7, 8, 15, 16, 17, 1500, 65535} {
			pseudoHeader := make([]byte, 0, 40+size)
			pseudoHeader = append(pseudoHeader, test.source.AsSlice()...)
			pseudoHeader = append(pseudoHeader, test.target.AsSlice()...)
			if test.source.Is4() {
				pseudoHeader = append(pseudoHeader, 0, protocolTCP, byte(size>>8), byte(size))
			} else {
				pseudoHeader = append(pseudoHeader, byte(size>>24), byte(size>>16), byte(size>>8), byte(size), 0, 0, 0, protocolTCP)
			}
			pseudoHeader = append(pseudoHeader, payload[:size]...)
			if got, want := transportChecksum(test.source, test.target, protocolTCP, payload[:size]), referenceChecksum(pseudoHeader); got != want {
				t.Fatalf("%s transport checksum at length %d = %#x, want %#x", test.name, size, got, want)
			}
		}
	}
}

func TestTransportChecksumPartsMatchesContiguousPayload(t *testing.T) {
	payload := make([]byte, 257)
	for index := range payload {
		payload[index] = byte(index*29 + 7)
	}
	for _, addresses := range [][2]netip.Addr{
		{netip.MustParseAddr("192.0.2.17"), netip.MustParseAddr("198.51.100.17")},
		{netip.MustParseAddr("2001:db8::17"), netip.MustParseAddr("2001:db8:1::17")},
	} {
		want := transportChecksum(addresses[0], addresses[1], protocolUDP, payload)
		for split := 0; split <= len(payload); split++ {
			if got := transportChecksumParts(addresses[0], addresses[1], protocolUDP, len(payload), payload[:split], payload[split:]); got != want {
				t.Fatalf("%s split %d checksum = %#x, want %#x", addresses[0], split, got, want)
			}
		}
	}
}

// FuzzChecksumParts verifies the Internet checksum and both pseudo-header
// variants across every odd or even split between adjacent payload regions.
func FuzzChecksumParts(f *testing.F) {
	f.Add([]byte(nil), uint16(0), false, byte(protocolUDP))
	f.Add([]byte{1}, uint16(1), false, byte(protocolTCP))
	f.Add([]byte{1, 2, 3, 4, 5}, uint16(3), true, byte(protocolICMPv6))
	f.Fuzz(func(t *testing.T, payload []byte, splitAt uint16, ipv6 bool, protocol byte) {
		if len(payload) > 65535 {
			payload = payload[:65535]
		}
		if got, want := checksum(payload), referenceChecksum(payload); got != want {
			t.Fatalf("checksum(%d bytes) = %#x, want %#x", len(payload), got, want)
		}

		source := netip.MustParseAddr("192.0.2.129")
		target := netip.MustParseAddr("198.51.100.231")
		if ipv6 {
			source = netip.MustParseAddr("2001:db8:ffff:1::abcd")
			target = netip.MustParseAddr("fdff:ffff:ffff:ffff::1234")
		}
		pseudoHeader := make([]byte, 0, 40+len(payload))
		pseudoHeader = append(pseudoHeader, source.AsSlice()...)
		pseudoHeader = append(pseudoHeader, target.AsSlice()...)
		if ipv6 {
			length := uint32(len(payload))
			pseudoHeader = append(pseudoHeader, byte(length>>24), byte(length>>16), byte(length>>8), byte(length), 0, 0, 0, protocol)
		} else {
			pseudoHeader = append(pseudoHeader, 0, protocol, byte(len(payload)>>8), byte(len(payload)))
		}
		pseudoHeader = append(pseudoHeader, payload...)
		split := int(splitAt) % (len(payload) + 1)
		if got, want := transportChecksumParts(source, target, protocol, len(payload), payload[:split], payload[split:]), referenceChecksum(pseudoHeader); got != want {
			t.Fatalf("transport checksum at split %d/%d = %#x, want %#x", split, len(payload), got, want)
		}
	})
}

func TestIPv6RouterAlertValidation(t *testing.T) {
	valid := []byte{protocolICMPv6, 0, 5, 2, 0, 0, 1, 0}
	if !ipv6RouterAlert(valid) {
		t.Fatal("valid IPv6 Router Alert was rejected")
	}
	malformed := []byte{protocolICMPv6, 0, 5, 1, 0, 1, 1, 0}
	if ipv6RouterAlert(malformed) {
		t.Fatal("malformed IPv6 Router Alert was accepted")
	}
	duplicate := []byte{protocolICMPv6, 1, 5, 2, 0, 0, 5, 2, 0, 0, 1, 4, 0, 0, 0, 0}
	if ipv6RouterAlert(duplicate) {
		t.Fatal("duplicate IPv6 Router Alert was accepted")
	}
}

func TestIPv4RouterAlertValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		options []byte
		valid   bool
	}{
		{name: "exact", options: []byte{148, 4, 0, 0}, valid: true},
		{name: "with-eol-padding", options: []byte{148, 4, 0, 0, 0, 0, 0, 0}, valid: true},
		{name: "after-nops", options: []byte{1, 1, 1, 1, 148, 4, 0, 0}, valid: true},
		{name: "missing", options: []byte{1, 1, 1, 0}},
		{name: "nonzero-value", options: []byte{148, 4, 0, 1}},
		{name: "duplicate", options: []byte{148, 4, 0, 0, 148, 4, 0, 0}},
		{name: "nonzero-eol-padding", options: []byte{148, 4, 0, 0, 0, 1, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ipv4RouterAlert(test.options); got != test.valid {
				t.Fatalf("ipv4RouterAlert() = %t, want %t", got, test.valid)
			}
		})
	}
}

func BenchmarkChecksum(b *testing.B) {
	data := make([]byte, 1500)
	for index := range data {
		data[index] = byte(index*37 + 11)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	var result uint16
	for index := 0; index < b.N; index++ {
		result = checksum(data)
	}
	if result == 0 {
		b.Fatal("unexpected zero checksum")
	}
}

// FuzzInboundPacket verifies that arbitrary L3 input cannot panic the stack.
func FuzzInboundPacket(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x45, 0, 0, 20})
	f.Add(buildIPPacket(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), protocolUDP, make([]byte, 8), 1, false))
	f.Add(buildMulticastTestIGMPQuery(
		netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("224.0.0.1"), netip.IPv4Unspecified(), 3, nil, true,
	))
	f.Add(buildMulticastTestMLDQuery(
		netip.MustParseAddr("fe80::2"), netip.MustParseAddr("ff02::1"), netip.IPv6Unspecified(), 2, nil,
	))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
		defer stack.Close()
		_ = writeTestPacket(stack, packet)
	})
}

// FuzzInboundChecksummedTransportPackets keeps transport validation past the
// checksum gate for UDP, TCP, and ICMP packets with valid pseudo-headers.
func FuzzInboundChecksummedTransportPackets(f *testing.F) {
	f.Add([]byte("udp"), false, byte(0), uint16(49152), uint16(53), byte(0))
	f.Add([]byte("tcp"), false, byte(1), uint16(49153), uint16(80), byte(tcpFlagSYN))
	f.Add([]byte("icmp"), true, byte(2), uint16(1), uint16(2), byte(0))
	f.Fuzz(func(t *testing.T, payload []byte, ipv6 bool, protocolSelector byte, sourcePort, targetPort uint16, flags byte) {
		if len(payload) > 256 {
			payload = payload[:256]
		}
		local := netip.MustParseAddr("192.0.2.1")
		remote := netip.MustParseAddr("198.51.100.1")
		if ipv6 {
			local = netip.MustParseAddr("2001:db8::1")
			remote = netip.MustParseAddr("2001:db8:1::1")
		}
		_, stack := newTestStack(t, local, remote)
		defer stack.Close()

		var packet []byte
		switch protocolSelector % 3 {
		case 0:
			packet = buildTestUDP(remote, local, sourcePort, targetPort, payload)
		case 1:
			if flags == 0 {
				flags = tcpFlagACK
			}
			options := []byte(nil)
			if flags&tcpFlagSYN != 0 {
				options = []byte{2, 4, 0x05, 0xb4, 4, 2}
			}
			packet = buildTestTCP(remote, local, sourcePort, targetPort, 1000, 2000, flags, 65535, options, payload)
		default:
			message := make([]byte, 8+len(payload))
			if ipv6 {
				message[0] = 128
			} else {
				message[0] = 8
			}
			binary.BigEndian.PutUint16(message[4:6], sourcePort)
			binary.BigEndian.PutUint16(message[6:8], targetPort)
			copy(message[8:], payload)
			if ipv6 {
				binary.BigEndian.PutUint16(message[2:4], transportChecksum(remote, local, protocolICMPv6, message))
				packet = buildIPPacket(remote, local, protocolICMPv6, message, 1, true)
			} else {
				binary.BigEndian.PutUint16(message[2:4], checksum(message))
				packet = buildIPPacket(remote, local, protocolICMPv4, message, 1, true)
			}
		}
		if err := writeTestPacket(stack, packet); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzIPPacketParsing verifies deterministic parsing, input ownership, and
// slice bounds for arbitrary IPv4 and IPv6 envelopes.
func FuzzIPPacketParsing(f *testing.F) {
	local4 := netip.MustParseAddr("192.0.2.1")
	remote4 := netip.MustParseAddr("198.51.100.1")
	local6 := netip.MustParseAddr("2001:db8::1")
	remote6 := netip.MustParseAddr("2001:db8:1::1")
	f.Add([]byte(nil))
	f.Add(buildIPPacket(remote4, local4, protocolUDP, make([]byte, udpHeaderSize), 1, false))
	f.Add(buildTestIPv4Options(remote4, local4, []byte{1, 1, 0, 0}))
	f.Add(buildIPPacket(remote6, local6, protocolTCP, make([]byte, tcpHeaderSize), 0, true))
	f.Add(buildTestIPv6Extension(remote6, local6, 60, []byte{protocolUDP, 0, 1, 0, 0, 0, 0, 0}))
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65575 {
			packet = packet[:65575]
		}
		before := append([]byte(nil), packet...)
		parsed, ok := parseIPPacket(packet)
		if !bytes.Equal(packet, before) {
			t.Fatal("parseIPPacket modified its input")
		}
		repeated, repeatedOK := parseIPPacket(packet)
		if repeatedOK != ok {
			t.Fatal("parseIPPacket returned a nondeterministic validity result")
		}
		if !ok {
			return
		}
		if parsed.source != repeated.source || parsed.target != repeated.target || parsed.protocol != repeated.protocol ||
			parsed.protocolOffset != repeated.protocolOffset || parsed.parameterError != repeated.parameterError ||
			parsed.parameterCode != repeated.parameterCode || parsed.parameterAt != repeated.parameterAt ||
			parsed.ecn != repeated.ecn || parsed.hopLimit != repeated.hopLimit || parsed.trafficClass != repeated.trafficClass ||
			parsed.flowLabel != repeated.flowLabel || !bytes.Equal(parsed.payload, repeated.payload) || !bytes.Equal(parsed.original, repeated.original) {
			t.Fatal("parseIPPacket returned nondeterministic packet metadata")
		}
		if len(parsed.original) == 0 || len(parsed.original) > len(packet) || !bytes.Equal(parsed.original, packet[:len(parsed.original)]) {
			t.Fatalf("parsed original length %d is not an input prefix of %d bytes", len(parsed.original), len(packet))
		}
		if !parsed.source.IsValid() || !parsed.target.IsValid() || parsed.source.Is4() != parsed.target.Is4() {
			t.Fatalf("parsed address families are invalid: %v -> %v", parsed.source, parsed.target)
		}
		if parsed.parameterError {
			if parsed.parameterAt >= uint32(len(parsed.original)) {
				t.Fatalf("parameter pointer %d is outside %d-byte packet", parsed.parameterAt, len(parsed.original))
			}
			return
		}
		if parsed.protocolOffset < 0 || parsed.protocolOffset >= len(parsed.original) {
			t.Fatalf("protocol offset %d is outside %d-byte packet", parsed.protocolOffset, len(parsed.original))
		}
		if len(parsed.payload) > len(parsed.original) || !bytes.Equal(parsed.payload, parsed.original[len(parsed.original)-len(parsed.payload):]) {
			t.Fatalf("parsed payload length %d is not an original-packet suffix", len(parsed.payload))
		}
	})
}

// FuzzIPv4OptionParsing builds checksum-valid IPv4 packets with arbitrary
// padded options so malformedIPv4Option and validateIPv4Options are exercised
// behind the normal header checksum gate.
func FuzzIPv4OptionParsing(f *testing.F) {
	local := netip.MustParseAddr("192.0.2.171")
	remote := netip.MustParseAddr("198.51.100.171")
	f.Add([]byte(nil))
	f.Add([]byte{1, 1, 0, 0})
	f.Add([]byte{148, 4, 0, 0})
	f.Add([]byte{148, 3, 0, 0})
	f.Add([]byte{131, 3, 4, 0})
	f.Add([]byte{7, 3, 3, 0})
	f.Add([]byte{68, 4, 5, 0xf0})
	f.Fuzz(func(t *testing.T, input []byte) {
		options := paddedIPv4FuzzOptions(input)
		packet := buildTestIPv4Options(remote, local, options)
		before := append([]byte(nil), packet...)
		parsed, ok := parseIPPacket(packet)
		if !bytes.Equal(packet, before) {
			t.Fatal("parseIPPacket modified an IPv4 option packet")
		}
		repeated, repeatedOK := parseIPPacket(packet)
		if repeatedOK != ok || parsed.parameterError != repeated.parameterError || parsed.parameterAt != repeated.parameterAt ||
			parsed.parameterCode != repeated.parameterCode || parsed.protocol != repeated.protocol || !bytes.Equal(parsed.payload, repeated.payload) {
			t.Fatal("IPv4 option parsing was nondeterministic")
		}

		optionAt, malformed := malformedIPv4Option(options)
		if malformed {
			if optionAt < 0 || optionAt >= len(options) {
				t.Fatalf("malformed IPv4 option pointer %d outside %d-byte option area", optionAt, len(options))
			}
			if !ok || !parsed.parameterError || parsed.parameterCode != 0 || parsed.parameterAt != uint32(20+optionAt) {
				t.Fatalf("malformed IPv4 options %x parsed as %+v, ok=%t", options, parsed, ok)
			}
			return
		}
		if !validateIPv4Options(options) {
			if ok {
				t.Fatalf("policy-rejected IPv4 options %x were accepted as %+v", options, parsed)
			}
			return
		}
		if !ok || parsed.parameterError || parsed.protocol != protocolUDP || len(parsed.payload) != udpHeaderSize || parsed.hasRouterAlert() != ipv4RouterAlert(options) {
			t.Fatalf("valid IPv4 options %x parsed as %+v, ok=%t", options, parsed, ok)
		}
	})
}

// paddedIPv4FuzzOptions bounds arbitrary input to IPv4's 40-byte option area
// and pads it to the header's four-byte unit.
func paddedIPv4FuzzOptions(input []byte) []byte {
	if len(input) > 40 {
		input = input[:40]
	}
	size := (len(input) + 3) &^ 3
	options := make([]byte, size)
	copy(options, input)
	return options
}

// FuzzIPv6OptionParsing frames arbitrary bytes as Hop-by-Hop or Destination
// options so inspectIPv6Options is checked through complete IPv6 packets.
func FuzzIPv6OptionParsing(f *testing.F) {
	local := netip.MustParseAddr("2001:db8::171")
	remote := netip.MustParseAddr("2001:db8:1::171")
	multicast := netip.MustParseAddr("ff02::1")
	f.Add([]byte(nil), true, false)
	f.Add([]byte{5, 2, 0, 0}, true, false)
	f.Add([]byte{0x40, 0}, true, false)
	f.Add([]byte{0x80, 0}, false, false)
	f.Add([]byte{0xc0, 0}, true, true)
	f.Fuzz(func(t *testing.T, input []byte, hopByHop bool, multicastTarget bool) {
		options := paddedIPv6FuzzOptions(input)
		header := make([]byte, 8+len(options))
		header[0] = protocolUDP
		header[1] = byte(len(header)/8 - 1)
		copy(header[2:], options)
		extensionType := byte(60)
		if hopByHop {
			extensionType = 0
		}
		target := local
		if multicastTarget {
			target = multicast
		}
		packet := buildTestIPv6Extension(remote, target, extensionType, header)
		before := append([]byte(nil), packet...)
		parsed, ok := parseIPPacket(packet)
		if !bytes.Equal(packet, before) {
			t.Fatal("parseIPPacket modified an IPv6 option packet")
		}
		repeated, repeatedOK := parseIPPacket(packet)
		if repeatedOK != ok || parsed.parameterError != repeated.parameterError || parsed.parameterAt != repeated.parameterAt ||
			parsed.parameterCode != repeated.parameterCode || parsed.protocol != repeated.protocol || !bytes.Equal(parsed.payload, repeated.payload) {
			t.Fatal("IPv6 option parsing was nondeterministic")
		}

		valid, action, optionAt := inspectIPv6Options(header)
		if !valid {
			if optionAt < 0 || optionAt >= len(header) {
				t.Fatalf("invalid IPv6 option pointer %d outside %d-byte header", optionAt, len(header))
			}
			if action >= 2 && (action == 2 || !target.IsMulticast()) {
				if !ok || !parsed.parameterError || parsed.parameterCode != 2 || parsed.parameterAt != uint32(40+optionAt) {
					t.Fatalf("invalid IPv6 options %x parsed as %+v, ok=%t", header, parsed, ok)
				}
			} else if ok {
				t.Fatalf("silently discarded IPv6 options %x were accepted as %+v", header, parsed)
			}
			return
		}
		if !ok || parsed.parameterError || parsed.protocol != protocolUDP || len(parsed.payload) != 0 {
			t.Fatalf("valid IPv6 options %x parsed as %+v, ok=%t", header, parsed, ok)
		}
		if hopByHop && parsed.hasRouterAlert() != ipv6RouterAlert(header) {
			t.Fatalf("IPv6 Router Alert mismatch for %x", header)
		}
	})
}

// paddedIPv6FuzzOptions bounds arbitrary option bytes and pads them to the
// eight-byte extension-header unit used by the enclosing fuzz packet.
func paddedIPv6FuzzOptions(input []byte) []byte {
	if len(input) > 62 {
		input = input[:62]
	}
	size := (len(input) + 7) &^ 7
	options := make([]byte, size)
	copy(options, input)
	return options
}

func TestIPv6FlowLabelEncodingAndFragmentation(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::10")
	target := netip.MustParseAddr("2001:db8::20")
	const label = uint32(0xabcde)
	packet := buildIPPacketWithOptions(source, target, protocolUDP, make([]byte, udpHeaderSize), 0, true, ipPacketOptions{
		trafficClass: 0x2e, flowLabel: label, flowLabelSet: true,
	})
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.trafficClass != 0x2e || parsed.flowLabel != label {
		t.Fatalf("IPv6 flow header = class %#x label %#x, parsed=%v", parsed.trafficClass, parsed.flowLabel, ok)
	}
	setPacketECN(packet, 3)
	parsed, ok = parseIPPacket(packet)
	if !ok || parsed.ecn != 3 || parsed.flowLabel != label {
		t.Fatalf("IPv6 ECN update changed flow label: ECN %d label %#x", parsed.ecn, parsed.flowLabel)
	}

	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(source, 128)}, MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	fragments, err := stack.ipPayloadPackets(source, target, protocolUDP, make([]byte, 2000), true)
	if err != nil || len(fragments) < 2 {
		t.Fatalf("IPv6 flow fragmentation = %d packets, %v", len(fragments), err)
	}
	var automatic uint32
	for index, fragment := range fragments {
		current := uint32(fragment[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(fragment[2:4]))
		if current == 0 || index != 0 && current != automatic {
			t.Fatalf("IPv6 fragment %d flow label = %#x, first %#x", index, current, automatic)
		}
		automatic = current
	}
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
	if entry, ok := waitTestPacketEntry(&stack.outbound, 25*time.Millisecond); ok {
		response = consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("non-initial malformed fragment produced Parameter Problem: %x", response)
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
	if entry, ok := waitTestPacketEntry(&stack.outbound, 25*time.Millisecond); ok {
		response = consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("ICMPv6 error produced recursive Parameter Problem: %x", response)
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
	if entry, ok := stack.outbound.tryDequeue(); ok {
		response = consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("IPv6 No Next Header produced a response: %x", response)
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
	if entry, ok := stack.outbound.tryDequeue(); ok {
		response := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("mapped IPv6 source produced response: %x", response)
	}
}

func TestIPv4MappedIPv6WireDestinationIsDropped(t *testing.T) {
	local4 := netip.MustParseAddr("192.0.2.62")
	remote6 := netip.MustParseAddr("2001:db8::63")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local4, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packet := buildIPPacket(remote6, netip.MustParseAddr("::ffff:192.0.2.62"), 99, []byte{1}, 0, true)
	before := stack.Stats().InboundDroppedPackets
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if after := stack.Stats().InboundDroppedPackets; after != before+1 {
		t.Fatalf("mapped IPv6 destination drop count = %d, want %d", after, before+1)
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
	if entry, ok := waitTestPacketEntry(&stack.outbound, 25*time.Millisecond); ok {
		response := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("directed-broadcast source produced a response: %x", response)
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
