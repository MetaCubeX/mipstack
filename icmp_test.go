package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// TestLegacyIPv4PathMTU verifies RFC 1191 plateau inference for routers that
// leave the next-hop MTU field zero.
func TestLegacyIPv4PathMTU(t *testing.T) {
	packet := buildIPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), ProtocolTCP, make([]byte, 1400), 1, true)
	if mtu := legacyIPv4PathMTU(packet); mtu != 1006 {
		t.Fatalf("legacy PMTU = %d, want 1006", mtu)
	}
	if mtu := legacyIPv4PathMTU([]byte{0x45}); mtu != 0 {
		t.Fatalf("truncated legacy PMTU = %d, want 0", mtu)
	}
	malformed := make([]byte, 20)
	malformed[0] = 0x45
	if mtu := legacyIPv4PathMTU(malformed); mtu != 0 {
		t.Fatalf("malformed legacy PMTU = %d, want 0", mtu)
	}
}

// TestICMPErrorCodeValidation verifies the assigned error-code ranges used by
// IPv4 and IPv6 before an error can reach transport state.
func TestICMPErrorCodeValidation(t *testing.T) {
	for _, test := range []struct {
		protocol, messageType, code byte
		valid                       bool
	}{
		{ProtocolICMPv4, 3, 15, true},
		{ProtocolICMPv4, 3, 16, false},
		{ProtocolICMPv4, 11, 1, true},
		{ProtocolICMPv4, 11, 2, false},
		{ProtocolICMPv4, 12, 2, true},
		{ProtocolICMPv4, 12, 3, false},
		{ProtocolICMPv6, 1, ICMPv6DestinationUnreachableCodeSourceRoutingHeader, true},
		{ProtocolICMPv6, 1, ICMPv6DestinationUnreachableCodeHeadersTooLong, true},
		{ProtocolICMPv6, 1, ICMPv6DestinationUnreachableCodePRoute, true},
		{ProtocolICMPv6, 1, 10, false},
		{ProtocolICMPv6, 2, 0, true},
		{ProtocolICMPv6, 2, 1, false},
		{ProtocolICMPv6, 3, 1, true},
		{ProtocolICMPv6, 3, 2, false},
		{ProtocolICMPv6, 4, ICMPv6ParameterProblemCodeIncompleteFirstFragment, true},
		{ProtocolICMPv6, 4, ICMPv6ParameterProblemCodeSRUpperLayerHeader, true},
		{ProtocolICMPv6, 4, ICMPv6ParameterProblemCodeUnrecognizedNextHeaderAtIntermediateNode, true},
		{ProtocolICMPv6, 4, ICMPv6ParameterProblemCodeOptionTooBig, true},
		{ProtocolICMPv6, 4, 11, false},
		{ProtocolICMPv4, 8, 0, false},
	} {
		if got := validICMPErrorCode(test.protocol, test.messageType, test.code); got != test.valid {
			t.Errorf("validICMPErrorCode(%d, %d, %d) = %v, want %v", test.protocol, test.messageType, test.code, got, test.valid)
		}
	}
}

// TestTruncatedICMPv6ErrorIsRejected verifies that the standalone parser does
// not rely on handleICMP's outer length check.
func TestTruncatedICMPv6ErrorIsRejected(t *testing.T) {
	if _, ok := parseICMPError(ipPacket{protocol: ProtocolICMPv6, payload: []byte{1}}); ok {
		t.Fatal("truncated ICMPv6 error was accepted")
	}
}

func TestICMPErrorRejectsCrossFamilyQuote(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol byte
		typeCode [2]byte
		quoted   []byte
	}{
		{
			name: "ICMPv4 quoting IPv6", protocol: ProtocolICMPv4, typeCode: [2]byte{3, 1},
			quoted: buildIPPacket(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"), ProtocolUDP, make([]byte, 8), 0, true),
		},
		{
			name: "ICMPv6 quoting IPv4", protocol: ProtocolICMPv6, typeCode: [2]byte{1, 0},
			quoted: buildIPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), ProtocolUDP, make([]byte, 8), 1, true),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := make([]byte, 8+len(test.quoted))
			message[0], message[1] = test.typeCode[0], test.typeCode[1]
			copy(message[8:], test.quoted)
			if _, ok := parseICMPError(ipPacket{protocol: test.protocol, payload: message}); ok {
				t.Fatal("cross-family quoted packet was accepted")
			}
		})
	}
}

func TestQuotedIPv6FirstFragmentIgnoresReservedBits(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::1")
	target := netip.MustParseAddr("2001:db8::2")
	fragment := make([]byte, 8+udpHeaderSize)
	fragment[0], fragment[1] = ProtocolUDP, 0xff
	binary.BigEndian.PutUint16(fragment[2:4], 0x0007) // Reserved bits and M.
	packet := buildIPPacket(source, target, 44, fragment, 0, false)
	quotedSource, quotedTarget, protocol, payload, ok := quotedIPPayload(packet)
	if !ok || quotedSource != source || quotedTarget != target || protocol != ProtocolUDP || len(payload) != udpHeaderSize {
		t.Fatalf("quoted reserved-bit first fragment = %v %v %d %d, parsed = %v", quotedSource, quotedTarget, protocol, len(payload), ok)
	}
}

// FuzzICMPErrorQuotes verifies truncated quoted-packet parsing, family
// validation, suffix ownership, and independent queued-error cloning.
func FuzzICMPErrorQuotes(f *testing.F) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8:1::1")
	quoted4 := buildIPPacket(source4, target4, ProtocolUDP, make([]byte, udpHeaderSize), 1, true)
	quoted6 := buildIPPacket(source6, target6, ProtocolTCP, make([]byte, tcpHeaderSize), 0, true)
	fragment := make([]byte, 8+udpHeaderSize)
	fragment[0] = ProtocolUDP
	binary.BigEndian.PutUint16(fragment[2:4], 1)
	quotedFragment6 := buildIPPacket(source6, target6, 44, fragment, 0, false)
	authentication := make([]byte, 16+udpHeaderSize)
	authentication[0], authentication[1] = ProtocolUDP, 2
	quotedAuthentication6 := buildIPPacket(source6, target6, IPv6ExtensionHeaderAuthentication, authentication, 0, false)
	f.Add([]byte(nil), false, byte(3), byte(1))
	f.Add(quoted4, false, byte(3), byte(4))
	f.Add(quoted6, true, byte(1), byte(0))
	f.Add(quotedFragment6, true, byte(2), byte(0))
	f.Add(quotedAuthentication6, true, byte(4), byte(1))
	f.Add(buildTestIPv6Extension(source6, target6, 60, []byte{ProtocolUDP, 4, 0, 0, 0, 0, 0, 0}), true, byte(3), byte(0))
	f.Fuzz(func(t *testing.T, quote []byte, ipv6 bool, messageType, code byte) {
		if len(quote) > 65575 {
			quote = quote[:65575]
		}
		before := append([]byte(nil), quote...)
		_, _, _, _, _ = quotedIPPayload(quote)
		_ = legacyIPv4PathMTU(quote)
		_ = packetInvokesICMPError(quote)
		message := make([]byte, 8+len(quote))
		message[0], message[1] = messageType, code
		copy(message[8:], quote)
		protocol := byte(ProtocolICMPv4)
		reporter := netip.MustParseAddr("203.0.113.1")
		if ipv6 {
			protocol = ProtocolICMPv6
			reporter = netip.MustParseAddr("2001:db8:ffff::1")
		}
		networkError, ok := parseICMPError(ipPacket{source: reporter, protocol: protocol, payload: message})
		destination := target4
		if ipv6 {
			destination = target6
		}
		publicMessage := ICMPMessage{
			Source: reporter, Destination: destination,
			Type: messageType, Code: code, Body: message[4:],
		}
		publicError, publicErr := publicMessage.ICMPError()
		if !bytes.Equal(quote, before) {
			t.Fatal("ICMP quote parsing modified its input")
		}
		if !ok {
			if publicErr == nil {
				t.Fatalf("public parser accepted an error rejected by the stack parser: %+v", publicError)
			}
			return
		}
		if publicErr != nil {
			t.Fatalf("public parser rejected an error accepted by the stack parser: %v", publicErr)
		}
		if !reflect.DeepEqual(publicError, networkError) {
			t.Fatalf("public and stack ICMP parsers disagree:\n public: %+v\n  stack: %+v", publicError, networkError)
		}
		if !validICMPErrorCode(protocol, messageType, code) {
			t.Fatalf("accepted invalid ICMP type/code %d/%d for protocol %d", messageType, code, protocol)
		}
		if networkError.Reporter != reporter || networkError.QuotedSource.Is6() != ipv6 || networkError.QuotedTarget.Is6() != ipv6 ||
			!networkError.QuotedSource.IsValid() || !networkError.QuotedTarget.IsValid() {
			t.Fatalf("invalid parsed ICMP endpoints: reporter %v, quote %v -> %v", networkError.Reporter, networkError.QuotedSource, networkError.QuotedTarget)
		}
		if !bytes.Equal(networkError.QuotedPacket, quote) {
			t.Fatal("parsed ICMP quote differs from its input")
		}
		if len(networkError.QuotedPayload) > len(networkError.QuotedPacket) ||
			!bytes.Equal(networkError.QuotedPayload, networkError.QuotedPacket[len(networkError.QuotedPacket)-len(networkError.QuotedPayload):]) {
			t.Fatal("parsed ICMP payload is not a quoted-packet suffix")
		}
		if len(networkError.QuotedPacket) <= 65535-8 {
			constructed, constructErr := publicError.ICMPMessage(destination)
			if constructErr != nil {
				t.Fatalf("construct parsed ICMP error: %v", constructErr)
			}
			reparsed, parseErr := constructed.ICMPError()
			if parseErr != nil {
				t.Fatalf("parse reconstructed ICMP error: %v", parseErr)
			}
			if !reflect.DeepEqual(reparsed, publicError) {
				t.Fatalf("ICMP error reconstruction changed semantics:\n original: %+v\n  rebuilt: %+v", publicError, reparsed)
			}
		}
		cloned := cloneICMPError(networkError)
		clonedPacket := append([]byte(nil), cloned.QuotedPacket...)
		clonedPayload := append([]byte(nil), cloned.QuotedPayload...)
		if len(cloned.QuotedPayload) != 0 {
			offset := len(cloned.QuotedPacket) - len(cloned.QuotedPayload)
			if &cloned.QuotedPayload[0] != &cloned.QuotedPacket[offset] {
				t.Fatal("cloned ICMP payload does not retain its packet-suffix relationship")
			}
		}
		if len(networkError.QuotedPacket) != 0 {
			networkError.QuotedPacket[0] ^= 0xff
		}
		if len(networkError.QuotedPayload) != 0 {
			networkError.QuotedPayload[0] ^= 0xff
		}
		if !bytes.Equal(cloned.QuotedPacket, clonedPacket) || !bytes.Equal(cloned.QuotedPayload, clonedPayload) {
			t.Fatal("cloned ICMP error retained caller-owned storage")
		}
	})
}

// FuzzICMPExtensionObjects verifies that the public object view and setter
// agree on every accepted RFC 4884 framing without modifying caller input.
func FuzzICMPExtensionObjects(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0, 8, ICMPExtensionClassExtendedInformation, ICMPExtensionExtendedInformationTypePointer, 0, 0, 0, 17})
	f.Add([]byte{0, 4, 0xfe, 0x7d, 0, 8, 1, 2, 1, 2, 3, 4})
	f.Add([]byte{0, 7, 1, 1, 1, 2, 3})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 65535 {
			encoded = encoded[:65535]
		}
		before := append([]byte(nil), encoded...)
		networkError := ICMPError{Extensions: encoded}
		objects, err := networkError.ExtensionObjects()
		if !bytes.Equal(encoded, before) {
			t.Fatal("ExtensionObjects modified its input")
		}
		hasPointer, valid := validateICMPExtensionObjects(encoded)
		if len(encoded) == 0 {
			if err != nil || objects != nil || valid || hasPointer {
				t.Fatalf("empty extension result = %+v, %v, %t/%t", objects, err, hasPointer, valid)
			}
			return
		}
		if err != nil {
			if valid {
				t.Fatal("public parser rejected an internally valid object sequence")
			}
			return
		}
		if !valid || len(objects) == 0 {
			t.Fatal("public parser accepted an internally invalid object sequence")
		}
		var rebuilt ICMPError
		if err = rebuilt.SetExtensionObjects(objects); err != nil || !bytes.Equal(rebuilt.Extensions, encoded) {
			t.Fatalf("object round trip = %x, %v; want %x", rebuilt.Extensions, err, encoded)
		}
		foundPointer := false
		for _, object := range objects {
			_, pointer := object.Pointer()
			foundPointer = foundPointer || pointer
		}
		if foundPointer != hasPointer {
			t.Fatalf("Pointer classification = %t, want %t", foundPointer, hasPointer)
		}
	})
}

// FuzzICMPExtensionMessages exercises Length, padding, Extension Header, and
// object framing through the shared public and stack parser.
func FuzzICMPExtensionMessages(f *testing.F) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8::2")
	quote4 := buildIPPacket(source4, target4, ProtocolUDP, make([]byte, udpHeaderSize), 21, true)
	quote6 := buildIPPacket(source6, target6, ProtocolUDP, make([]byte, udpHeaderSize), 0, true)
	for _, seed := range []struct {
		ipv6        bool
		messageType uint8
		code        uint8
		quote       []byte
	}{
		{messageType: ICMPv4TypeTimeExceeded, code: ICMPv4TimeExceededCodeTTLInTransit, quote: quote4},
		{ipv6: true, messageType: ICMPv6TypeDestinationUnreachable, code: ICMPv6DestinationUnreachableCodeHeadersTooLong, quote: quote6},
	} {
		reporter, destination := netip.MustParseAddr("203.0.113.1"), source4
		objects := []ICMPExtensionObject{{Class: 0xfe, Type: 1, Data: []byte{1, 2, 3, 4}}}
		if seed.ipv6 {
			reporter, destination = netip.MustParseAddr("2001:db8:ffff::1"), source6
			var pointer ICMPExtensionObject
			pointer.SetPointer(2048)
			objects = append(objects, pointer)
		}
		networkError := ICMPError{Reporter: reporter, Type: seed.messageType, Code: seed.code, QuotedPacket: seed.quote}
		if err := networkError.SetExtensionObjects(objects); err != nil {
			f.Fatal(err)
		}
		message, err := networkError.ICMPMessage(destination)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(append([]byte(nil), message.Body...), seed.ipv6, seed.messageType, seed.code)
	}
	f.Add([]byte(nil), false, byte(3), byte(1))
	f.Add(make([]byte, 4), true, byte(1), byte(8))
	f.Fuzz(func(t *testing.T, body []byte, ipv6 bool, messageType, code byte) {
		if len(body) > 65531 {
			body = body[:65531]
		}
		before := append([]byte(nil), body...)
		reporter, destination := netip.MustParseAddr("203.0.113.1"), source4
		protocol := byte(ProtocolICMPv4)
		if ipv6 {
			reporter, destination = netip.MustParseAddr("2001:db8:ffff::1"), source6
			protocol = ProtocolICMPv6
		}
		message := ICMPMessage{Source: reporter, Destination: destination, Type: messageType, Code: code, Body: body}
		publicError, err := message.ICMPError()
		stackError, ok := parseICMPErrorFields(reporter, protocol, messageType, code, body)
		if !bytes.Equal(body, before) {
			t.Fatal("extended ICMP parser modified its input")
		}
		if (err == nil) != ok || ok && !reflect.DeepEqual(publicError, stackError) {
			t.Fatalf("public/stack parse disagreement: public=%+v/%v stack=%+v/%t", publicError, err, stackError, ok)
		}
		if err != nil {
			return
		}
		rebuilt, rebuildErr := publicError.ICMPMessage(destination)
		if rebuildErr != nil {
			t.Fatalf("rebuild parsed extended error: %v", rebuildErr)
		}
		reparsed, reparseErr := rebuilt.ICMPError()
		if reparseErr != nil || !reflect.DeepEqual(reparsed, publicError) {
			t.Fatalf("extended semantic round trip: got %+v/%v, want %+v", reparsed, reparseErr, publicError)
		}
	})
}

// TestTCPICMPSequenceCorrelation verifies inclusive transmitted ranges,
// rejection of stale quotations, and modulo-2^32 sequence arithmetic.
func TestTCPICMPSequenceCorrelation(t *testing.T) {
	connection := &TCPConn{}
	quoted := make([]byte, 8)
	check := func(sequence uint32, want bool) {
		binary.BigEndian.PutUint32(quoted[4:8], sequence)
		if got := connection.acceptsICMPQuote(quoted); got != want {
			t.Errorf("sequence %#x accepted = %v, want %v", sequence, got, want)
		}
	}
	connection.publishICMPSequenceRange(100, 120)
	check(99, false)
	check(100, true)
	check(110, true)
	check(120, true)
	check(121, false)
	connection.publishICMPSequenceRange(0xfffffff0, 0x10)
	check(0xffffffef, false)
	check(0xfffffff0, true)
	check(0, true)
	check(0x10, true)
	check(0x11, false)
	if connection.acceptsICMPQuote(quoted[:7]) {
		t.Fatal("truncated TCP quotation was accepted")
	}
}

func TestPublicICMPMessageCodec(t *testing.T) {
	tests := []ICMPMessage{
		{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Type: 8, Body: []byte{0x12, 0x34, 0, 7, 'v', '4'}},
		{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Type: 128, Body: []byte{0x56, 0x78, 0, 9, 'v', '6'}},
	}
	for _, test := range tests {
		name := "IPv4"
		protocol := ProtocolICMPv4
		if test.Source.Is6() {
			name, protocol = "IPv6", ProtocolICMPv6
		}
		t.Run(name, func(t *testing.T) {
			wire, err := test.AppendBinary([]byte{0xaa})
			if err != nil {
				t.Fatalf("append ICMP: %v", err)
			}
			if wire[0] != 0xaa {
				t.Fatal("ICMP AppendBinary changed prefix")
			}
			wire = wire[1:]
			valid := checksum(wire) == 0
			if test.Source.Is6() {
				valid = transportChecksum(test.Source, test.Destination, ProtocolICMPv6, wire) == 0
			}
			if !valid {
				t.Fatal("encoded ICMP checksum is invalid")
			}
			packet := IPPacket{Source: test.Source, Destination: test.Destination, Protocol: protocol, HopLimit: 64, Payload: wire}
			parsed, err := packet.ICMPMessage()
			if err != nil {
				t.Fatalf("parse ICMP: %v", err)
			}
			if parsed.Source != test.Source || parsed.Destination != test.Destination || parsed.Type != test.Type || parsed.Code != test.Code || !bytes.Equal(parsed.Body, test.Body) || !parsed.IsEchoRequest() {
				t.Fatalf("parsed ICMP = %+v, want %+v", parsed, test)
			}
			roundTrip, err := parsed.MarshalBinary()
			if err != nil || !bytes.Equal(roundTrip, wire) {
				t.Fatalf("ICMP round trip: error=%v\n got %x\nwant %x", err, roundTrip, wire)
			}
		})
	}
}

func TestPublicICMPMessageEchoFieldsAndConstruction(t *testing.T) {
	for _, test := range []struct {
		name                   string
		source, destination    netip.Addr
		protocol               int
		requestType, replyType uint8
	}{
		{
			name: "IPv4 mapped", source: netip.MustParseAddr("::ffff:192.0.2.1"),
			destination: netip.MustParseAddr("::ffff:198.51.100.1"), protocol: ProtocolICMPv4,
			requestType: ICMPv4TypeEchoRequest, replyType: ICMPv4TypeEchoReply,
		},
		{
			name: "IPv6", source: netip.MustParseAddr("2001:db8::1"),
			destination: netip.MustParseAddr("2001:db8::2"), protocol: ProtocolICMPv6,
			requestType: ICMPv6TypeEchoRequest, replyType: ICMPv6TypeEchoReply,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("echo-payload")
			message := ICMPMessage{
				Source: test.source, Destination: test.destination,
				Type: 0xff, Code: 0xff, Body: []byte("replaced"),
			}
			if err := message.SetEchoRequest(0x1234, 0x5678, payload); err != nil {
				t.Fatalf("SetEchoRequest: %v", err)
			}
			if message.Source != test.source || message.Destination != test.destination {
				t.Fatalf("SetEchoRequest changed address context: %s -> %s", message.Source, message.Destination)
			}
			payload[0] ^= 0xff
			identifier, sequence, data, ok := message.Echo()
			if !ok || identifier != 0x1234 || sequence != 0x5678 || !bytes.Equal(data, []byte("echo-payload")) {
				t.Fatalf("Echo = %#x/%#x/%q/%t", identifier, sequence, data, ok)
			}
			if message.Type != test.requestType || message.Code != ICMPCodeNone || !message.IsEchoRequest() || message.IsEchoReply() {
				t.Fatalf("constructed Echo Request = %+v", message)
			}
			if &data[0] != &message.Body[4] {
				t.Fatal("Echo copied its payload")
			}

			wire, err := message.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode constructed Echo Request: %v", err)
			}
			parsed, err := (IPPacket{
				Source: message.Source, Destination: message.Destination,
				Protocol: test.protocol, HopLimit: 64, Payload: wire,
			}).ICMPMessage()
			if err != nil {
				t.Fatalf("parse constructed Echo Request: %v", err)
			}
			identifier, sequence, data, ok = parsed.Echo()
			if !ok || identifier != 0x1234 || sequence != 0x5678 || !bytes.Equal(data, []byte("echo-payload")) {
				t.Fatalf("parsed Echo = %#x/%#x/%q/%t", identifier, sequence, data, ok)
			}

			overlapping := message.Body[1:]
			wantReplyPayload := append([]byte(nil), overlapping...)
			if err = message.SetEchoReply(0xabcd, 9, overlapping); err != nil {
				t.Fatalf("SetEchoReply with overlapping payload: %v", err)
			}
			identifier, sequence, data, ok = message.Echo()
			if !ok || identifier != 0xabcd || sequence != 9 || !bytes.Equal(data, wantReplyPayload) ||
				message.Type != test.replyType || message.Code != ICMPCodeNone || message.IsEchoRequest() || !message.IsEchoReply() {
				t.Fatalf("constructed Echo Reply = %+v, fields %#x/%#x/%q/%t", message, identifier, sequence, data, ok)
			}
		})
	}
}

func TestPublicICMPMessageEchoValidation(t *testing.T) {
	v4 := ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"),
		Type: ICMPv4TypeEchoRequest, Code: ICMPCodeNone, Body: []byte{0, 1, 0, 2},
	}
	invalidMessages := []ICMPMessage{
		{Source: v4.Source, Destination: v4.Destination, Type: ICMPv4TypeEchoRequest, Code: 1, Body: v4.Body},
		{Source: v4.Source, Destination: v4.Destination, Type: ICMPv4TypeDestinationUnreachable, Body: v4.Body},
		{Source: v4.Source, Destination: v4.Destination, Type: ICMPv4TypeEchoRequest, Body: v4.Body[:3]},
		{Source: v4.Source, Destination: netip.MustParseAddr("2001:db8::1"), Type: ICMPv4TypeEchoRequest, Body: v4.Body},
		{Source: netip.MustParseAddr("fe80::1").WithZone("zone"), Destination: netip.MustParseAddr("2001:db8::1"), Type: ICMPv6TypeEchoRequest, Body: v4.Body},
	}
	for index, message := range invalidMessages {
		if identifier, sequence, payload, ok := message.Echo(); ok || identifier != 0 || sequence != 0 || payload != nil ||
			message.IsEchoRequest() || message.IsEchoReply() {
			t.Fatalf("invalid Echo %d was accepted", index)
		}
	}

	for _, test := range []struct {
		name    string
		message ICMPMessage
		payload []byte
		want    error
	}{
		{name: "invalid source", message: ICMPMessage{Destination: v4.Destination}, want: syscall.EINVAL},
		{name: "invalid destination", message: ICMPMessage{Source: v4.Source}, want: syscall.EINVAL},
		{name: "cross family", message: ICMPMessage{Source: v4.Source, Destination: netip.MustParseAddr("2001:db8::1")}, want: syscall.EINVAL},
		{name: "zoned", message: ICMPMessage{Source: netip.MustParseAddr("2001:db8::1").WithZone("zone"), Destination: netip.MustParseAddr("2001:db8::2")}, want: syscall.EINVAL},
		{name: "oversized", message: v4, payload: make([]byte, 65535-8+1), want: syscall.EMSGSIZE},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := test.message
			message.Type, message.Code, message.Body = 0xfe, 0xfd, []byte("unchanged")
			before := message
			before.Body = append([]byte(nil), message.Body...)
			if err := message.SetEchoRequest(1, 2, test.payload); !errors.Is(err, test.want) {
				t.Fatalf("SetEchoRequest error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(message, before) {
				t.Fatalf("failed SetEchoRequest changed receiver: got %+v, want %+v", message, before)
			}
		})
	}
	var nilMessage *ICMPMessage
	if err := nilMessage.SetEchoRequest(1, 2, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil SetEchoRequest error = %v", err)
	}
	if err := nilMessage.SetEchoReply(1, 2, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil SetEchoReply error = %v", err)
	}
}

func TestPublicICMPError(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	udp := make([]byte, udpHeaderSize)
	binary.BigEndian.PutUint16(udp[0:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	quoted4 := buildIPPacket(source4, target4, ProtocolUDP, udp, 7, true)
	body4 := make([]byte, 4+len(quoted4))
	binary.BigEndian.PutUint16(body4[2:4], 1280)
	copy(body4[4:], quoted4)
	message4 := ICMPMessage{
		Source: netip.MustParseAddr("198.51.100.254"), Destination: source4,
		Type: 3, Code: 4, Body: body4,
	}
	if !message4.IsError() {
		t.Fatal("IPv4 Fragmentation Needed was not classified as an error")
	}
	error4, err := message4.ICMPError()
	if err != nil {
		t.Fatalf("parse IPv4 ICMP error: %v", err)
	}
	if error4.Reporter != message4.Source || error4.Type != message4.Type || error4.Code != message4.Code || error4.MTU != 1280 ||
		error4.QuotedSource != source4 || error4.QuotedTarget != target4 || error4.QuotedProtocol != ProtocolUDP ||
		error4.QuotedSourcePort != 42000 || error4.QuotedTargetPort != 53 || !bytes.Equal(error4.QuotedPacket, quoted4) ||
		!bytes.Equal(error4.QuotedPayload, udp) {
		t.Fatalf("IPv4 ICMP error = %+v", error4)
	}
	if &error4.QuotedPacket[0] != &message4.Body[4] || &error4.QuotedPayload[0] != &message4.Body[4+20] {
		t.Fatal("public ICMP error parser copied its quoted packet")
	}

	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8:1::1")
	tcp := make([]byte, tcpHeaderSize)
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 51000)
	quoted6 := buildIPPacket(source6, target6, ProtocolTCP, tcp, 0, true)
	body6 := make([]byte, 4+len(quoted6))
	binary.BigEndian.PutUint32(body6[:4], 17)
	copy(body6[4:], quoted6)
	message6 := ICMPMessage{
		Source: netip.MustParseAddr("2001:db8:ffff::1"), Destination: source6,
		Type: 4, Code: 0, Body: body6,
	}
	error6, err := message6.ICMPError()
	if err != nil {
		t.Fatalf("parse IPv6 ICMP error: %v", err)
	}
	if !message6.IsError() || error6.Pointer != 17 || error6.QuotedSourcePort != 443 || error6.QuotedTargetPort != 51000 ||
		error6.QuotedSource != source6 || error6.QuotedTarget != target6 || error6.QuotedProtocol != ProtocolTCP {
		t.Fatalf("IPv6 ICMP error = %+v", error6)
	}

	quotedNoNext := buildIPPacket(source6, target6, ProtocolNoNextHeader, []byte{1, 2, 3, 4}, 0, true)
	noNext := ICMPMessage{
		Source: message6.Source, Destination: source6, Type: 1, Code: 0,
		Body: append(make([]byte, 4), quotedNoNext...),
	}
	noNextError, err := noNext.ICMPError()
	if err != nil || noNextError.QuotedProtocol != ProtocolNoNextHeader || noNextError.QuotedPayload != nil ||
		!bytes.Equal(noNextError.QuotedPacket, quotedNoNext) {
		t.Fatalf("IPv6 No Next Header quote = %+v, %v", noNextError, err)
	}
}

func TestPublicICMPErrorConstruction(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	reporter4 := netip.MustParseAddr("198.51.100.254")
	udp := make([]byte, udpHeaderSize+16)
	binary.BigEndian.PutUint16(udp[:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	quote4 := buildIPPacket(source4, target4, ProtocolUDP, udp, 7, true)[:20+udpHeaderSize]

	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8:1::1")
	reporter6 := netip.MustParseAddr("2001:db8:ffff::1")
	tcp := make([]byte, tcpHeaderSize)
	binary.BigEndian.PutUint16(tcp[:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	quote6 := buildIPPacket(source6, target6, ProtocolTCP, tcp, 0, true)

	for _, test := range []struct {
		name                  string
		reporter, destination netip.Addr
		messageType, code     uint8
		mtu, pointer          uint32
		quote                 []byte
		protocol              int
	}{
		{name: "IPv4 fragmentation needed", reporter: reporter4, destination: source4, messageType: ICMPv4TypeDestinationUnreachable, code: ICMPv4DestinationUnreachableCodeFragmentationNeeded, mtu: 1280, quote: quote4, protocol: ProtocolICMPv4},
		{name: "IPv4 parameter problem", reporter: reporter4, destination: source4, messageType: ICMPv4TypeParameterProblem, code: ICMPv4ParameterProblemCodePointer, pointer: 17, quote: quote4, protocol: ProtocolICMPv4},
		{name: "IPv4 host unreachable", reporter: reporter4, destination: source4, messageType: ICMPv4TypeDestinationUnreachable, code: ICMPv4DestinationUnreachableCodeHost, quote: quote4, protocol: ProtocolICMPv4},
		{name: "IPv6 packet too big", reporter: reporter6, destination: source6, messageType: ICMPv6TypePacketTooBig, code: ICMPCodeNone, mtu: 1280, quote: quote6, protocol: ProtocolICMPv6},
		{name: "IPv6 parameter problem", reporter: reporter6, destination: source6, messageType: ICMPv6TypeParameterProblem, code: ICMPv6ParameterProblemCodeUnrecognizedNextHeader, pointer: 41, quote: quote6, protocol: ProtocolICMPv6},
		{name: "IPv6 processing-limit parameter problem", reporter: reporter6, destination: source6, messageType: ICMPv6TypeParameterProblem, code: ICMPv6ParameterProblemCodeOptionTooBig, pointer: 48, quote: quote6, protocol: ProtocolICMPv6},
		{name: "IPv6 P-Route error", reporter: reporter6, destination: source6, messageType: ICMPv6TypeDestinationUnreachable, code: ICMPv6DestinationUnreachableCodePRoute, quote: quote6, protocol: ProtocolICMPv6},
		{name: "IPv6 time exceeded", reporter: reporter6, destination: source6, messageType: ICMPv6TypeTimeExceeded, code: ICMPv6TimeExceededCodeHopLimitInTransit, quote: quote6, protocol: ProtocolICMPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			quote := append([]byte(nil), test.quote...)
			wantQuote := append([]byte(nil), quote...)
			networkError := ICMPError{
				Reporter: test.reporter, Type: test.messageType, Code: test.code,
				MTU: test.mtu, Pointer: test.pointer, QuotedPacket: quote,
				QuotedSource: netip.IPv6Loopback(), QuotedTarget: netip.IPv6Loopback(),
				QuotedProtocol: 0xff, QuotedPayload: []byte("ignored"),
				QuotedSourcePort: 1, QuotedTargetPort: 2,
			}
			message, err := networkError.ICMPMessage(test.destination)
			if err != nil {
				t.Fatalf("construct ICMP error: %v", err)
			}
			if message.Source != test.reporter || message.Destination != test.destination || message.Type != test.messageType ||
				message.Code != test.code || !bytes.Equal(message.Body[4:], wantQuote) {
				t.Fatalf("constructed ICMP error = %+v", message)
			}
			if &message.Body[4] == &quote[0] {
				t.Fatal("ICMP error construction retained QuotedPacket")
			}
			quote[0] ^= 0xff
			if !bytes.Equal(message.Body[4:], wantQuote) {
				t.Fatal("mutating QuotedPacket changed constructed ICMP error")
			}

			wire, err := message.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode constructed ICMP error: %v", err)
			}
			parsedMessage, err := (IPPacket{
				Source: message.Source, Destination: message.Destination,
				Protocol: test.protocol, HopLimit: 64, Payload: wire,
			}).ICMPMessage()
			if err != nil {
				t.Fatalf("parse constructed ICMP error: %v", err)
			}
			parsedError, err := parsedMessage.ICMPError()
			if err != nil {
				t.Fatalf("decode constructed ICMP error: %v", err)
			}
			if parsedError.Reporter != test.reporter || parsedError.Type != test.messageType || parsedError.Code != test.code ||
				parsedError.MTU != test.mtu || parsedError.Pointer != test.pointer || !bytes.Equal(parsedError.QuotedPacket, wantQuote) {
				t.Fatalf("decoded constructed ICMP error = %+v", parsedError)
			}
		})
	}
}

func TestPublicICMPExtensionObjects(t *testing.T) {
	unknownData := []byte{1, 2, 3, 4}
	pointer := ICMPExtensionObject{}
	pointer.SetPointer(0x10203040)
	pointerData := pointer.Data
	objects := []ICMPExtensionObject{
		{Class: 0xfe, Type: 0x7d, Data: unknownData},
		pointer,
		{Class: ICMPExtensionClassExtendedInformation, Type: ICMPExtensionExtendedInformationTypePointer, Data: []byte{5, 6, 7, 8}},
	}
	var networkError ICMPError
	if err := networkError.SetExtensionObjects(objects); err != nil {
		t.Fatalf("SetExtensionObjects: %v", err)
	}
	wantEncoding := []byte{
		0, 8, 0xfe, 0x7d, 1, 2, 3, 4,
		0, 8, ICMPExtensionClassExtendedInformation, ICMPExtensionExtendedInformationTypePointer, 0x10, 0x20, 0x30, 0x40,
		0, 8, ICMPExtensionClassExtendedInformation, ICMPExtensionExtendedInformationTypePointer, 5, 6, 7, 8,
	}
	if !bytes.Equal(networkError.Extensions, wantEncoding) {
		t.Fatalf("extension encoding = %x, want %x", networkError.Extensions, wantEncoding)
	}
	unknownData[0] ^= 0xff
	pointerData[0] ^= 0xff
	if !bytes.Equal(networkError.Extensions, wantEncoding) {
		t.Fatal("SetExtensionObjects retained caller storage")
	}

	parsed, err := networkError.ExtensionObjects()
	if err != nil || len(parsed) != len(objects) {
		t.Fatalf("ExtensionObjects = %+v, %v", parsed, err)
	}
	if &parsed[0].Data[0] != &networkError.Extensions[icmpExtensionObjectHeaderSize] {
		t.Fatal("ExtensionObjects copied object data")
	}
	if value, ok := parsed[1].Pointer(); !ok || value != 0x10203040 {
		t.Fatalf("Pointer = %#x, %t", value, ok)
	}
	if value, ok := parsed[0].Pointer(); ok || value != 0 {
		t.Fatalf("unknown object Pointer = %#x, %t", value, ok)
	}

	before := append([]byte(nil), networkError.Extensions...)
	large := make([]byte, 40000)
	for _, test := range []struct {
		name    string
		objects []ICMPExtensionObject
		want    error
	}{
		{name: "unaligned data", objects: []ICMPExtensionObject{{Data: []byte{1}}}, want: syscall.EINVAL},
		{name: "object too large", objects: []ICMPExtensionObject{{Data: make([]byte, 65532)}}, want: syscall.EMSGSIZE},
		{name: "sequence too large", objects: []ICMPExtensionObject{{Data: large}, {Data: large}}, want: syscall.EMSGSIZE},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := networkError.SetExtensionObjects(test.objects); !errors.Is(err, test.want) {
				t.Fatalf("SetExtensionObjects error = %v, want %v", err, test.want)
			}
			if !bytes.Equal(networkError.Extensions, before) {
				t.Fatal("failed SetExtensionObjects changed receiver")
			}
		})
	}

	for _, encoded := range [][]byte{
		{0, 3, 1, 1},
		{0, 6, 1, 1, 0, 0},
		{0, 8, 1, 1},
		{0, 4, 1, 1, 0},
	} {
		if objects, err := (ICMPError{Extensions: encoded}).ExtensionObjects(); !errors.Is(err, syscall.EINVAL) || objects != nil {
			t.Fatalf("malformed ExtensionObjects(%x) = %+v, %v", encoded, objects, err)
		}
	}
	var nilError *ICMPError
	if err := nilError.SetExtensionObjects(objects); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("nil SetExtensionObjects error = %v", err)
	}
	if err := networkError.SetExtensionObjects([]ICMPExtensionObject{}); err != nil || networkError.Extensions != nil {
		t.Fatalf("clear ExtensionObjects = %x, %v", networkError.Extensions, err)
	}
	if objects, err := networkError.ExtensionObjects(); err != nil || objects != nil {
		t.Fatalf("empty ExtensionObjects = %+v, %v", objects, err)
	}
	ordinary := cloneICMPError(ICMPError{QuotedPacket: []byte{1, 2, 3, 4}})
	if ordinary.Extensions != nil {
		t.Fatalf("ordinary clone has non-nil empty Extensions: %x", ordinary.Extensions)
	}
}

func TestPublicICMPExtensionRoundTrip(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	reporter4 := netip.MustParseAddr("198.51.100.254")
	udp := make([]byte, udpHeaderSize+5)
	binary.BigEndian.PutUint16(udp[:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	quote4 := buildIPPacket(source4, target4, ProtocolUDP, udp, 9, true)

	source6 := netip.MustParseAddr("2001:db8::1")
	target6 := netip.MustParseAddr("2001:db8:1::1")
	reporter6 := netip.MustParseAddr("2001:db8:ffff::1")
	tcp := make([]byte, tcpHeaderSize+1)
	binary.BigEndian.PutUint16(tcp[:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	quote6 := buildIPPacket(source6, target6, ProtocolTCP, tcp, 0, true)

	for _, test := range []struct {
		name                  string
		reporter, destination netip.Addr
		messageType, code     uint8
		mtu, pointer          uint32
		quote                 []byte
		lengthOffset, unit    int
	}{
		{name: "IPv4 destination unreachable", reporter: reporter4, destination: source4, messageType: ICMPv4TypeDestinationUnreachable, code: ICMPv4DestinationUnreachableCodeFragmentationNeeded, mtu: 1280, quote: quote4, lengthOffset: 1, unit: 4},
		{name: "IPv4 time exceeded", reporter: reporter4, destination: source4, messageType: ICMPv4TypeTimeExceeded, code: ICMPv4TimeExceededCodeTTLInTransit, quote: quote4, lengthOffset: 1, unit: 4},
		{name: "IPv4 parameter problem", reporter: reporter4, destination: source4, messageType: ICMPv4TypeParameterProblem, code: ICMPv4ParameterProblemCodePointer, pointer: 17, quote: quote4, lengthOffset: 1, unit: 4},
		{name: "IPv6 destination unreachable", reporter: reporter6, destination: source6, messageType: ICMPv6TypeDestinationUnreachable, code: ICMPv6DestinationUnreachableCodeNoRoute, quote: quote6, lengthOffset: 0, unit: 8},
		{name: "IPv6 time exceeded", reporter: reporter6, destination: source6, messageType: ICMPv6TypeTimeExceeded, code: ICMPv6TimeExceededCodeHopLimitInTransit, quote: quote6, lengthOffset: 0, unit: 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			quote := append([]byte(nil), test.quote...)
			networkError := ICMPError{
				Reporter: test.reporter, Type: test.messageType, Code: test.code,
				MTU: test.mtu, Pointer: test.pointer, QuotedPacket: quote,
			}
			objects := []ICMPExtensionObject{{Class: 0xee, Type: 7, Data: []byte{1, 2, 3, 4}}}
			if err := networkError.SetExtensionObjects(objects); err != nil {
				t.Fatal(err)
			}
			wantExtensions := append([]byte(nil), networkError.Extensions...)
			message, err := networkError.ICMPMessage(test.destination)
			if err != nil {
				t.Fatalf("construct extended ICMP error: %v", err)
			}
			paddedLength := int(message.Body[test.lengthOffset]) * test.unit
			if paddedLength < icmpExtensionMinimumQuoteSize || paddedLength%test.unit != 0 || len(message.Body) != 4+paddedLength+icmpExtensionHeaderSize+len(wantExtensions) {
				t.Fatalf("extended body layout = length field %d, body %d", paddedLength, len(message.Body))
			}
			structure := message.Body[4+paddedLength:]
			if structure[0] != icmpExtensionVersion<<4 || structure[1] != 0 || checksum(structure) != 0 ||
				!bytes.Equal(structure[icmpExtensionHeaderSize:], wantExtensions) {
				t.Fatalf("extension structure = %x", structure)
			}
			quote[0] ^= 0xff
			networkError.Extensions[0] ^= 0xff
			if !bytes.Equal(message.Body[4:4+len(test.quote)], test.quote) ||
				!bytes.Equal(structure[icmpExtensionHeaderSize:], wantExtensions) {
				t.Fatal("ICMPMessage retained constructor storage")
			}

			parsed, err := message.ICMPError()
			if err != nil {
				t.Fatalf("parse extended ICMP error: %v", err)
			}
			if parsed.Reporter != test.reporter || parsed.Type != test.messageType || parsed.Code != test.code ||
				parsed.MTU != test.mtu || parsed.Pointer != test.pointer || !bytes.Equal(parsed.QuotedPacket, test.quote) ||
				!bytes.Equal(parsed.Extensions, wantExtensions) {
				t.Fatalf("parsed extended ICMP error = %+v", parsed)
			}
			parsedObjects, err := parsed.ExtensionObjects()
			if err != nil || len(parsedObjects) != 1 || parsedObjects[0].Class != 0xee || parsedObjects[0].Type != 7 ||
				!bytes.Equal(parsedObjects[0].Data, []byte{1, 2, 3, 4}) {
				t.Fatalf("parsed extension objects = %+v, %v", parsedObjects, err)
			}
			cloned := cloneICMPError(parsed)
			wantPacket := append([]byte(nil), cloned.QuotedPacket...)
			wantClonedExtensions := append([]byte(nil), cloned.Extensions...)
			parsed.QuotedPacket[0] ^= 0xff
			parsed.Extensions[0] ^= 0xff
			if !bytes.Equal(cloned.QuotedPacket, wantPacket) || !bytes.Equal(cloned.Extensions, wantClonedExtensions) {
				t.Fatal("cloneICMPError retained extended message storage")
			}
			if got, want := socketErrorSize(cloned), socketErrorMetadataSize+len(cloned.QuotedPacket)+len(cloned.Extensions); got != want {
				t.Fatalf("extended socket error size = %d, want %d", got, want)
			}
		})
	}
}

func TestPublicICMPv6HeadersTooLong(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::1")
	target := netip.MustParseAddr("2001:db8:1::1")
	reporter := netip.MustParseAddr("2001:db8:ffff::1")
	udp := make([]byte, udpHeaderSize)
	binary.BigEndian.PutUint16(udp[:2], 42000)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	quote := buildIPPacket(source, target, ProtocolUDP, udp, 0, true)
	pointer := ICMPExtensionObject{}
	pointer.SetPointer(4096)
	networkError := ICMPError{
		Reporter: reporter, Type: ICMPv6TypeDestinationUnreachable,
		Code: ICMPv6DestinationUnreachableCodeHeadersTooLong, QuotedPacket: quote,
	}
	if err := networkError.SetExtensionObjects([]ICMPExtensionObject{
		{Class: 0xfc, Type: 3}, pointer, pointer,
	}); err != nil {
		t.Fatal(err)
	}
	message, err := networkError.ICMPMessage(source)
	if err != nil || !message.IsError() {
		t.Fatalf("construct Headers Too Long = %+v, %v", message, err)
	}
	wire, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsedMessage, err := (IPPacket{
		Source: reporter, Destination: source, Protocol: ProtocolICMPv6, HopLimit: 64, Payload: wire,
	}).ICMPMessage()
	if err != nil {
		t.Fatalf("parse Headers Too Long wire message: %v", err)
	}
	parsed, err := parsedMessage.ICMPError()
	if err != nil || parsed.Pointer != 0 || parsed.MTU != 0 {
		t.Fatalf("parse Headers Too Long = %+v, %v", parsed, err)
	}
	objects, err := parsed.ExtensionObjects()
	if err != nil || len(objects) != 3 {
		t.Fatalf("Headers Too Long objects = %+v, %v", objects, err)
	}
	for _, index := range []int{1, 2} {
		if value, ok := objects[index].Pointer(); !ok || value != 4096 {
			t.Fatalf("Headers Too Long Pointer %d = %d, %t", index, value, ok)
		}
	}
	control, err := socketErrorControlForRead(parsed)
	if err != nil {
		t.Fatal(err)
	}
	var controlMessage SocketErrorControlMessage
	err = controlMessage.Parse(control)
	if err != nil || controlMessage.Info != 0 || controlMessage.Errno != 71 {
		t.Fatalf("Headers Too Long error control = %+v, %v", controlMessage, err)
	}

	missing := networkError
	missing.Extensions = nil
	if _, err = missing.ICMPMessage(source); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Headers Too Long without extensions error = %v", err)
	}
	if err = missing.SetExtensionObjects([]ICMPExtensionObject{{Class: 0xfc, Type: 3}}); err != nil {
		t.Fatal(err)
	}
	if _, err = missing.ICMPMessage(source); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Headers Too Long without Pointer error = %v", err)
	}
	plain := ICMPMessage{
		Source: reporter, Destination: source, Type: ICMPv6TypeDestinationUnreachable,
		Code: ICMPv6DestinationUnreachableCodeHeadersTooLong, Body: append(make([]byte, 4), quote...),
	}
	if !plain.IsError() {
		t.Fatal("Headers Too Long was not classified as an ICMP error")
	}
	if _, err = plain.ICMPError(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Headers Too Long without wire Pointer error = %v", err)
	}
}

func TestPublicICMPExtensionValidation(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.1")
	reporter := netip.MustParseAddr("198.51.100.254")
	quote := buildIPPacket(source, target, ProtocolUDP, make([]byte, udpHeaderSize+5), 11, true)
	networkError := ICMPError{
		Reporter: reporter, Type: ICMPv4TypeDestinationUnreachable,
		Code: ICMPv4DestinationUnreachableCodeHost, QuotedPacket: quote,
	}
	if err := networkError.SetExtensionObjects([]ICMPExtensionObject{{Class: 7, Type: 9, Data: []byte{1, 2, 3, 4}}}); err != nil {
		t.Fatal(err)
	}
	message, err := networkError.ICMPMessage(source)
	if err != nil {
		t.Fatal(err)
	}
	base := append([]byte(nil), message.Body...)
	paddedLength := int(base[1]) * 4
	structureOffset := 4 + paddedLength
	parse := func(body []byte) error {
		candidate := message
		candidate.Body = body
		_, parseErr := candidate.ICMPError()
		return parseErr
	}
	check := func(name string, mutate func([]byte) []byte, wantError bool) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			body := mutate(append([]byte(nil), base...))
			err := parse(body)
			if (err != nil) != wantError {
				t.Fatalf("ICMPError error = %v, wantError %t; body=%x", err, wantError, body)
			}
		})
	}
	check("checksum omitted", func(body []byte) []byte {
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, false)
	check("nonzero reserved", func(body []byte) []byte {
		body[structureOffset] |= 0x0f
		body[structureOffset+1] = 0xff
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, false)
	check("bad checksum", func(body []byte) []byte {
		body[len(body)-1] ^= 0x80
		return body
	}, true)
	check("unknown version", func(body []byte) []byte {
		body[structureOffset] = 3 << 4
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, true)
	check("quote shorter than minimum", func(body []byte) []byte {
		body[1] = 31
		return body
	}, true)
	check("no objects", func(body []byte) []byte {
		return body[:structureOffset+icmpExtensionHeaderSize]
	}, true)
	check("object shorter than header", func(body []byte) []byte {
		binary.BigEndian.PutUint16(body[structureOffset+4:structureOffset+6], 3)
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, true)
	check("object not aligned", func(body []byte) []byte {
		binary.BigEndian.PutUint16(body[structureOffset+4:structureOffset+6], 6)
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, true)
	check("object overrun", func(body []byte) []byte {
		binary.BigEndian.PutUint16(body[structureOffset+4:structureOffset+6], 12)
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return body
	}, true)
	check("trailing partial object", func(body []byte) []byte {
		body[structureOffset+2], body[structureOffset+3] = 0, 0
		return append(body, 0)
	}, true)
	check("nonzero quote padding", func(body []byte) []byte {
		body[4+len(quote)] = 1
		return body
	}, true)

	lengthZero := append([]byte(nil), base...)
	lengthZero[1] = 0
	withoutExtensions := message
	withoutExtensions.Body = lengthZero
	parsed, err := withoutExtensions.ICMPError()
	if err != nil || len(parsed.Extensions) != 0 || len(parsed.QuotedPacket) != len(lengthZero)-4 {
		t.Fatalf("zero Length extension handling = %+v, %v", parsed, err)
	}

	quote6 := buildIPPacket(
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		ProtocolUDP, make([]byte, udpHeaderSize), 0, true,
	)
	for _, test := range []ICMPError{
		{Reporter: netip.MustParseAddr("2001:db8::ff"), Type: ICMPv6TypePacketTooBig, Code: 0, MTU: 1280, QuotedPacket: quote6, Extensions: networkError.Extensions},
		{Reporter: netip.MustParseAddr("2001:db8::ff"), Type: ICMPv6TypeParameterProblem, Code: 0, QuotedPacket: quote6, Extensions: networkError.Extensions},
	} {
		if _, err := test.ICMPMessage(netip.MustParseAddr("2001:db8::1")); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("extensions on unsupported type %d error = %v", test.Type, err)
		}
	}

	longQuote := buildIPPacket(source, target, ProtocolUDP, make([]byte, 180), 12, true)
	truncated := networkError
	truncated.QuotedPacket = longQuote[:100]
	if _, err := truncated.ICMPMessage(source); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short truncated extension quote error = %v", err)
	}
	truncated.QuotedPacket = longQuote[:130]
	truncatedMessage, err := truncated.ICMPMessage(source)
	if err != nil {
		t.Fatalf("128-byte truncated extension quote: %v", err)
	}
	truncatedParsed, err := truncatedMessage.ICMPError()
	if err != nil || len(truncatedParsed.QuotedPacket) != 132 {
		t.Fatalf("aligned truncated quote = %d bytes, %v", len(truncatedParsed.QuotedPacket), err)
	}
	oversized := networkError
	oversized.QuotedPacket = buildIPPacket(source, target, ProtocolUDP, make([]byte, 1001), 13, true)
	if _, err := oversized.ICMPMessage(source); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("unrepresentable IPv4 quote error = %v", err)
	}
}

func TestPublicICMPErrorConstructionFailures(t *testing.T) {
	source4 := netip.MustParseAddr("192.0.2.1")
	target4 := netip.MustParseAddr("198.51.100.1")
	quote4 := buildIPPacket(source4, target4, ProtocolUDP, make([]byte, udpHeaderSize), 1, true)
	quote6 := buildIPPacket(
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		ProtocolUDP, make([]byte, udpHeaderSize), 0, true,
	)
	base := ICMPError{
		Reporter: netip.MustParseAddr("198.51.100.254"),
		Type:     ICMPv4TypeDestinationUnreachable, Code: ICMPv4DestinationUnreachableCodeHost,
		QuotedPacket: quote4,
	}
	for _, test := range []struct {
		name         string
		networkError ICMPError
		destination  netip.Addr
		want         error
	}{
		{name: "invalid reporter", networkError: func() ICMPError { value := base; value.Reporter = netip.Addr{}; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "invalid destination", networkError: base, destination: netip.Addr{}, want: syscall.EINVAL},
		{name: "zoned reporter", networkError: ICMPError{Reporter: netip.MustParseAddr("fe80::1").WithZone("zone"), Type: ICMPv6TypeDestinationUnreachable, Code: ICMPv6DestinationUnreachableCodeNoRoute, QuotedPacket: quote6}, destination: netip.MustParseAddr("2001:db8::1"), want: syscall.EINVAL},
		{name: "cross-family destination", networkError: base, destination: netip.MustParseAddr("2001:db8::1"), want: syscall.EINVAL},
		{name: "invalid code", networkError: func() ICMPError { value := base; value.Code = 16; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "missing quote", networkError: func() ICMPError { value := base; value.QuotedPacket = nil; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "cross-family quote", networkError: func() ICMPError { value := base; value.QuotedPacket = quote6; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "unrelated MTU", networkError: func() ICMPError { value := base; value.MTU = 1; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "unrelated pointer", networkError: func() ICMPError { value := base; value.Pointer = 1; return value }(), destination: source4, want: syscall.EINVAL},
		{name: "IPv4 MTU overflow", networkError: func() ICMPError {
			value := base
			value.Code = ICMPv4DestinationUnreachableCodeFragmentationNeeded
			value.MTU = 1 << 16
			return value
		}(), destination: source4, want: syscall.EINVAL},
		{name: "IPv4 pointer overflow", networkError: func() ICMPError {
			value := base
			value.Type = ICMPv4TypeParameterProblem
			value.Code = ICMPv4ParameterProblemCodePointer
			value.Pointer = 1 << 8
			return value
		}(), destination: source4, want: syscall.EINVAL},
		{name: "oversized quote", networkError: func() ICMPError {
			value := base
			value.QuotedPacket = append(append([]byte(nil), quote4...), make([]byte, 65535-8-len(quote4)+1)...)
			return value
		}(), destination: source4, want: syscall.EMSGSIZE},
		{name: "oversized malformed quote", networkError: func() ICMPError {
			value := base
			value.QuotedPacket = make([]byte, 65535-8+1)
			return value
		}(), destination: source4, want: syscall.EMSGSIZE},
	} {
		t.Run(test.name, func(t *testing.T) {
			message, err := test.networkError.ICMPMessage(test.destination)
			if !errors.Is(err, test.want) || !reflect.ValueOf(message).IsZero() {
				t.Fatalf("ICMPMessage = %+v, %v; want zero value and %v", message, err, test.want)
			}
		})
	}
}

func TestPublicICMPErrorFailures(t *testing.T) {
	v4 := ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.254"), Destination: netip.MustParseAddr("192.0.2.1"),
		Type: 3, Code: 1, Body: make([]byte, 4),
	}
	v6Quote := buildIPPacket(
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
		ProtocolUDP, make([]byte, udpHeaderSize), 0, true,
	)
	mappedQuote := append([]byte(nil), v6Quote...)
	mappedSource := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	copy(mappedQuote[8:24], mappedSource[:])
	crossFamily := v4
	crossFamily.Body = append(make([]byte, 4), v6Quote...)
	mapped := ICMPMessage{
		Source: netip.MustParseAddr("2001:db8::ff"), Destination: netip.MustParseAddr("2001:db8::1"),
		Type: 1, Code: 0, Body: append(make([]byte, 4), mappedQuote...),
	}
	invalidCode := v4
	invalidCode.Code = 16
	shortBody := v4
	shortBody.Body = make([]byte, 3)
	for _, test := range []struct {
		name       string
		message    ICMPMessage
		classified bool
	}{
		{name: "missing quote", message: v4, classified: true},
		{name: "cross-family quote", message: crossFamily, classified: true},
		{name: "mapped IPv6 quote", message: mapped, classified: true},
		{name: "invalid code", message: invalidCode},
		{name: "short body", message: shortBody, classified: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.message.IsError() != test.classified {
				t.Fatalf("IsError classification for %s is inconsistent", test.name)
			}
			if result, err := test.message.ICMPError(); !errors.Is(err, syscall.EINVAL) || !reflect.ValueOf(result).IsZero() {
				t.Fatalf("ICMPError = %+v, %v; want zero value and EINVAL", result, err)
			}
		})
	}
}

func TestPublicICMPMessageEchoReply(t *testing.T) {
	tests := []struct {
		name      string
		request   ICMPMessage
		source    netip.Addr
		protocol  int
		replyType uint8
	}{
		{
			name: "IPv4 mapped",
			request: ICMPMessage{
				Source: netip.MustParseAddr("::ffff:192.0.2.1"), Destination: netip.MustParseAddr("::ffff:198.51.100.1"),
				Type: 8, Body: []byte{0x12, 0x34, 0, 7, 'v', '4'},
			},
			source: netip.MustParseAddr("::ffff:198.51.100.2"), protocol: ProtocolICMPv4, replyType: 0,
		},
		{
			name: "IPv6 multicast request",
			request: ICMPMessage{
				Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("ff02::1"),
				Type: 128, Body: []byte{0x56, 0x78, 0, 9, 'v', '6'},
			},
			source: netip.MustParseAddr("2001:db8:1::1"), protocol: ProtocolICMPv6, replyType: 129,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestWire, err := test.request.AppendBinary(nil)
			if err != nil {
				t.Fatalf("append Echo Request: %v", err)
			}
			request, err := (IPPacket{
				Source: test.request.Source.Unmap(), Destination: test.request.Destination.Unmap(),
				Protocol: test.protocol, HopLimit: 64, Payload: requestWire,
			}).ICMPMessage()
			if err != nil {
				t.Fatalf("parse Echo Request: %v", err)
			}
			reply, err := request.EchoReply(test.source)
			if err != nil {
				t.Fatalf("EchoReply: %v", err)
			}
			if reply.Source != test.source.Unmap() || reply.Destination != test.request.Source.Unmap() ||
				reply.Type != test.replyType || reply.Code != 0 || !bytes.Equal(reply.Body, test.request.Body) {
				t.Fatalf("EchoReply = %+v", reply)
			}
			if &reply.Body[0] != &request.Body[0] {
				t.Fatal("EchoReply copied Body")
			}
			if reply.IsEchoRequest() {
				t.Fatal("Echo Reply classified as a request")
			}

			backing := &requestWire[0]
			wire, err := reply.AppendBinary(requestWire[:0])
			if err != nil {
				t.Fatalf("append Echo Reply: %v", err)
			}
			if &wire[0] != backing {
				t.Fatal("in-place Echo Reply encoding replaced wire backing")
			}
			parsed, err := (IPPacket{
				Source: reply.Source, Destination: reply.Destination,
				Protocol: test.protocol, HopLimit: 64, Payload: wire,
			}).ICMPMessage()
			if err != nil {
				t.Fatalf("parse Echo Reply: %v", err)
			}
			if parsed.Type != test.replyType || parsed.Code != 0 || !bytes.Equal(parsed.Body, test.request.Body) {
				t.Fatalf("parsed Echo Reply = %+v", parsed)
			}
		})
	}
}

func TestPublicICMPMessageEchoReplyErrors(t *testing.T) {
	v4 := ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
		Type: 8, Body: []byte{0, 1, 0, 2},
	}
	v6 := ICMPMessage{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Type: 128, Body: []byte{0, 1, 0, 2},
	}
	nonEcho := v4
	nonEcho.Type = 0
	nonzeroCode := v4
	nonzeroCode.Code = 1
	shortBody := v4
	shortBody.Body = make([]byte, 3)
	zonedRequest := v6
	zonedRequest.Source = zonedRequest.Source.WithZone("test")
	oversizedBody := v4
	oversizedBody.Body = make([]byte, 65532)
	tests := []struct {
		name    string
		request ICMPMessage
		source  netip.Addr
		want    error
	}{
		{name: "non-Echo", request: nonEcho, source: v4.Destination, want: syscall.EINVAL},
		{name: "nonzero code", request: nonzeroCode, source: v4.Destination, want: syscall.EINVAL},
		{name: "short body", request: shortBody, source: v4.Destination, want: syscall.EINVAL},
		{name: "invalid source", request: v4, source: netip.Addr{}, want: syscall.EINVAL},
		{name: "cross-family source", request: v4, source: v6.Destination, want: syscall.EINVAL},
		{name: "zoned source", request: v6, source: v6.Destination.WithZone("test"), want: syscall.EINVAL},
		{name: "zoned request", request: zonedRequest, source: v6.Destination, want: syscall.EINVAL},
		{name: "oversized body", request: oversizedBody, source: v4.Destination, want: syscall.EMSGSIZE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reply, err := test.request.EchoReply(test.source)
			if !errors.Is(err, test.want) {
				t.Fatalf("EchoReply error = %v, want %v", err, test.want)
			}
			if reply.Source.IsValid() || reply.Destination.IsValid() || reply.Body != nil {
				t.Fatalf("failed EchoReply returned %+v", reply)
			}
		})
	}
}

func TestPublicICMPMessageCodecErrorsDoNotModifyDestination(t *testing.T) {
	message := ICMPMessage{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Type: 8, Body: make([]byte, 4)}
	message.Destination = netip.MustParseAddr("2001:db8::1")
	prefix := []byte{4, 5, 6}
	want := append([]byte(nil), prefix...)
	if got, err := message.AppendBinary(prefix); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(got, want) || !bytes.Equal(prefix, want) {
		t.Fatalf("invalid ICMP AppendBinary: got=%x error=%v", got, err)
	}
	message.Destination = netip.MustParseAddr("192.0.2.2")
	message.Body = nil
	if _, err := message.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short ICMP body error = %v", err)
	}
	shortMessage := []byte{200, 0, 0, 0}
	binary.BigEndian.PutUint16(shortMessage[2:4], checksum(shortMessage))
	packet := IPPacket{Source: message.Source, Destination: message.Destination, Protocol: ProtocolICMPv4, Payload: shortMessage}
	if _, err := packet.ICMPMessage(); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("short ICMP parse error = %v", err)
	}
	message.Body = make([]byte, 4)
	message.Source = netip.MustParseAddr("2001:db8::1").WithZone("test")
	message.Destination = netip.MustParseAddr("2001:db8::2")
	if _, err := message.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zoned ICMP message error = %v", err)
	}
}

func FuzzPublicICMPMessageCodec(f *testing.F) {
	seed := ICMPMessage{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Type: 128, Body: []byte{0, 1, 0, 2, 3}}
	wire, err := seed.AppendBinary(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Fuzz(func(t *testing.T, wire []byte) {
		packet := IPPacket{Source: seed.Source, Destination: seed.Destination, Protocol: ProtocolICMPv6, HopLimit: 64, Payload: wire}
		message, err := packet.ICMPMessage()
		if err != nil {
			return
		}
		encoded, err := message.AppendBinary(nil)
		if err != nil {
			t.Fatalf("parsed ICMP could not be encoded: %v", err)
		}
		packet.Payload = encoded
		reparsed, err := packet.ICMPMessage()
		if err != nil {
			t.Fatalf("encoded ICMP could not be parsed: %v", err)
		}
		canonical := append([]byte(nil), encoded...)
		inPlace, err := reparsed.AppendBinary(encoded[:0])
		if err != nil || !bytes.Equal(inPlace, canonical) {
			t.Fatalf("in-place ICMP append: error=%v\n got %x\nwant %x", err, inPlace, canonical)
		}
	})
}

func FuzzPublicICMPEchoConstruction(f *testing.F) {
	f.Add(false, false, uint16(0x1234), uint16(7), []byte("IPv4 Echo"))
	f.Add(true, true, uint16(0xabcd), uint16(9), []byte("IPv6 Echo"))
	f.Fuzz(func(t *testing.T, ipv6, reply bool, identifier, sequence uint16, payload []byte) {
		if len(payload) > 65535-8 {
			payload = payload[:65535-8]
		}
		wantPayload := append([]byte(nil), payload...)
		message := ICMPMessage{
			Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"),
		}
		protocol := ProtocolICMPv4
		if ipv6 {
			message.Source = netip.MustParseAddr("2001:db8::1")
			message.Destination = netip.MustParseAddr("2001:db8::2")
			protocol = ProtocolICMPv6
		}
		var err error
		if reply {
			err = message.SetEchoReply(identifier, sequence, payload)
		} else {
			err = message.SetEchoRequest(identifier, sequence, payload)
		}
		if err != nil {
			t.Fatalf("construct Echo: %v", err)
		}
		for index := range payload {
			payload[index] ^= 0xff
		}
		gotIdentifier, gotSequence, gotPayload, ok := message.Echo()
		if !ok || gotIdentifier != identifier || gotSequence != sequence || !bytes.Equal(gotPayload, wantPayload) ||
			message.IsEchoReply() != reply || message.IsEchoRequest() == reply {
			t.Fatalf("constructed Echo = %+v, fields %#x/%#x/%x/%t", message, gotIdentifier, gotSequence, gotPayload, ok)
		}
		wire, err := message.AppendBinary(nil)
		if err != nil {
			t.Fatalf("encode Echo: %v", err)
		}
		parsed, err := (IPPacket{
			Source: message.Source, Destination: message.Destination,
			Protocol: protocol, HopLimit: 64, Payload: wire,
		}).ICMPMessage()
		if err != nil {
			t.Fatalf("parse Echo: %v", err)
		}
		gotIdentifier, gotSequence, gotPayload, ok = parsed.Echo()
		if !ok || gotIdentifier != identifier || gotSequence != sequence || !bytes.Equal(gotPayload, wantPayload) {
			t.Fatalf("parsed Echo fields = %#x/%#x/%x/%t", gotIdentifier, gotSequence, gotPayload, ok)
		}
	})
}

// TestICMPEchoReply verifies IPv4 and IPv6 remote ping handling.
func TestICMPEchoReply(t *testing.T) {
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
			icmp := make([]byte, 12)
			protocol := byte(ProtocolICMPv4)
			icmp[0] = 8
			if test.local.Is6() {
				protocol = ProtocolICMPv6
				icmp[0] = 128
			}
			binary.BigEndian.PutUint16(icmp[4:6], 0x1234)
			copy(icmp[8:], []byte("ping"))
			if test.local.Is4() {
				binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
			} else {
				binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(test.remote, test.local, protocol, icmp))
			}
			request := buildIPPacket(test.remote, test.local, protocol, icmp, 1, true)
			if err := writeTestPacket(stack, request); err != nil {
				t.Fatal(err)
			}
			select {
			case response := <-link.outbound:
				parsed, ok := parseIPPacket(response)
				if !ok || parsed.source != test.local || parsed.target != test.remote || len(parsed.payload) != len(icmp) {
					t.Fatalf("invalid ICMP response: %x", response)
				}
				expectedType := byte(0)
				if test.local.Is6() {
					expectedType = 129
				}
				if parsed.payload[0] != expectedType || !bytes.Equal(parsed.payload[4:], icmp[4:]) {
					t.Fatalf("ICMP response payload = %x", parsed.payload)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for ICMP reply")
			}
		})
	}
}

// TestUDPPortUnreachable verifies the endpoint response and quoted tuple for
// a valid datagram sent to an unbound local port.
func TestUDPPortUnreachable(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		typeCode      [2]byte
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.41"), remote: netip.MustParseAddr("198.51.100.41"), typeCode: [2]byte{3, 3}},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::41"), remote: netip.MustParseAddr("2001:db8:1::41"), typeCode: [2]byte{1, 4}},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, stack := newTestStack(t, test.local, test.remote)
			packet := buildTestUDP(test.remote, test.local, 41001, 41002, []byte("unbound"))
			if err := writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			select {
			case response := <-link.outbound:
				parsed, ok := parseIPPacket(response)
				if !ok || len(parsed.payload) < 8 || parsed.payload[0] != test.typeCode[0] || parsed.payload[1] != test.typeCode[1] {
					t.Fatalf("port-unreachable response = %x, parsed = %v", response, ok)
				}
				remoteError, ok := parseICMPError(parsed)
				if !ok || remoteError.QuotedSource != test.remote || remoteError.QuotedTarget != test.local || remoteError.QuotedProtocol != ProtocolUDP || len(remoteError.QuotedPayload) < 4 || binary.BigEndian.Uint16(remoteError.QuotedPayload[0:2]) != 41001 || binary.BigEndian.Uint16(remoteError.QuotedPayload[2:4]) != 41002 {
					t.Fatalf("quoted UDP tuple = %+v, parsed = %v", remoteError, ok)
				}
				if text := remoteError.Error(); text == "" {
					t.Fatal("ICMP error formatted as an empty string")
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for port-unreachable response")
			}
		})
	}
}

// TestUDPPathMTUAndICMPCorrelation verifies that only an error quoting an
// actual WriteTo target updates PMTU and reaches the socket.
func TestUDPPathMTUAndICMPCorrelation(t *testing.T) {
	for _, test := range []struct {
		name                   string
		local, remote, unknown netip.Addr
		mtu                    uint32
		payloadSize            int
	}{
		{
			name: "IPv4", local: netip.MustParseAddr("192.0.2.1"), remote: netip.MustParseAddr("192.0.2.2"),
			unknown: netip.MustParseAddr("192.0.2.3"), mtu: 1200, payloadSize: 1250,
		},
		{
			name: "IPv6", local: netip.MustParseAddr("2001:db8::1"), remote: netip.MustParseAddr("2001:db8::2"),
			unknown: netip.MustParseAddr("2001:db8::3"), mtu: 1280, payloadSize: 1300,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 128
			if test.local.Is4() {
				bits = 32
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1400})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			destination := netip.AddrPortFrom(test.remote, 5353)
			connection, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(test.remote))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, test.payloadSize)
			if _, err = connection.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil {
				t.Fatal(err)
			}
			original := readOutboundPacket(t, stack)
			if len(original) > 1400 {
				t.Fatalf("initial packet size = %d", len(original))
			}
			localPort := connection.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			unknownQuote := buildTestUDP(test.local, test.unknown, localPort, destination.Port(), payload)
			if err = writeTestPacket(stack, buildTestPacketTooBig(test.unknown, test.local, unknownQuote, test.mtu)); err != nil {
				t.Fatal(err)
			}
			errorPacket := buildTestPacketTooBig(test.remote, test.local, original, test.mtu)
			if err = writeTestPacket(stack, errorPacket); err != nil {
				t.Fatal(err)
			}
			for index := range errorPacket {
				errorPacket[index] = 0
			}
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			_, _, err = connection.ReadFrom(make([]byte, 1))
			var operationError *net.OpError
			if !errors.As(err, &operationError) {
				t.Fatalf("ReadFrom error = %#v, want UDP error for %s", err, destination)
			}
			errorAddress, ok := operationError.Addr.(*net.UDPAddr)
			if !ok || errorAddress.AddrPort() != destination {
				t.Fatalf("ReadFrom error address = %#v, want %s", operationError.Addr, destination)
			}
			var icmpError ICMPError
			if !errors.As(err, &icmpError) || icmpError.MTU != test.mtu {
				t.Fatalf("ReadFrom error does not expose ICMP Packet Too Big: %#v", err)
			}
			if icmpError.QuotedSourcePort != localPort || icmpError.QuotedTargetPort != destination.Port() || len(icmpError.QuotedPayload) < udpHeaderSize {
				t.Fatalf("retained ICMP quote = %+v payload %x", icmpError, icmpError.QuotedPayload)
			}
			if learned := stack.mtuFor(test.remote); learned != int(test.mtu) {
				t.Fatalf("learned PMTU = %d, want %d", learned, test.mtu)
			}
			if unknown := stack.mtuFor(test.unknown); unknown != 1400 {
				t.Fatalf("unmatched target PMTU = %d, want 1400", unknown)
			}
			if _, err = connection.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil {
				t.Fatal(err)
			}
			for index := 0; index < 2; index++ {
				packet := readOutboundPacket(t, stack)
				if len(packet) > int(test.mtu) {
					t.Fatalf("PMTU fragment %d size = %d, want <= %d", index, len(packet), test.mtu)
				}
			}
		})
	}
}

func TestUDPExtendedICMPErrorCorrelation(t *testing.T) {
	for _, test := range []struct {
		name          string
		local, remote netip.Addr
		messageType   uint8
		code          uint8
	}{
		{
			name: "IPv4", local: netip.MustParseAddr("192.0.2.210"), remote: netip.MustParseAddr("192.0.2.211"),
			messageType: ICMPv4TypeTimeExceeded, code: ICMPv4TimeExceededCodeTTLInTransit,
		},
		{
			name: "IPv6", local: netip.MustParseAddr("2001:db8::210"), remote: netip.MustParseAddr("2001:db8::211"),
			messageType: ICMPv6TypeDestinationUnreachable, code: ICMPv6DestinationUnreachableCodeHeadersTooLong,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits, protocol := 32, ProtocolICMPv4
			if test.local.Is6() {
				bits, protocol = 128, ProtocolICMPv6
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1400})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			connection, err := stack.ListenUDP(context.Background(), "udp", wildcardUDP(test.remote))
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			target := netip.AddrPortFrom(test.remote, 5353)
			payload := []byte("extended-error-correlation")
			if _, err = connection.WriteTo(payload, net.UDPAddrFromAddrPort(target)); err != nil {
				t.Fatal(err)
			}
			original := readOutboundPacket(t, stack)
			networkError := ICMPError{
				Reporter: test.remote, Type: test.messageType, Code: test.code,
				QuotedPacket: original,
			}
			objects := []ICMPExtensionObject{{Class: 0xfe, Type: 7, Data: []byte{1, 2, 3, 4}}}
			if test.local.Is6() {
				var pointer ICMPExtensionObject
				pointer.SetPointer(uint32(len(original) + 4096))
				objects = []ICMPExtensionObject{pointer}
			}
			if err = networkError.SetExtensionObjects(objects); err != nil {
				t.Fatal(err)
			}
			message, err := networkError.ICMPMessage(test.local)
			if err != nil {
				t.Fatal(err)
			}
			icmpWire, err := message.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			errorPacket, err := (IPPacket{
				Source: test.remote, Destination: test.local,
				Protocol: protocol, HopLimit: 64, Payload: icmpWire,
			}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if err = writeTestPacket(stack, errorPacket); err != nil {
				t.Fatal(err)
			}
			for index := range errorPacket {
				errorPacket[index] = 0
			}
			for index := range networkError.Extensions {
				networkError.Extensions[index] = 0
			}
			if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			_, _, readErr := connection.ReadFrom(make([]byte, 1))
			var operationError *net.OpError
			if !errors.As(readErr, &operationError) {
				t.Fatalf("ReadFrom error = %#v, want extended network error", readErr)
			}
			address, ok := operationError.Addr.(*net.UDPAddr)
			if !ok || address.AddrPort() != target {
				t.Fatalf("extended error address = %#v, want %s", operationError.Addr, target)
			}
			var received ICMPError
			if !errors.As(readErr, &received) || received.Type != test.messageType || received.Code != test.code ||
				!bytes.Equal(received.QuotedPacket, original) || len(received.QuotedPayload) != udpHeaderSize+len(payload) {
				t.Fatalf("retained extended ICMP error = %+v, payload %x", received, received.QuotedPayload)
			}
			receivedObjects, err := received.ExtensionObjects()
			if err != nil || len(receivedObjects) != 1 {
				t.Fatalf("retained extension objects = %+v, %v", receivedObjects, err)
			}
			if test.local.Is6() {
				if pointer, ok := receivedObjects[0].Pointer(); !ok || pointer != uint32(len(original)+4096) {
					t.Fatalf("retained Headers Too Long Pointer = %d, %t", pointer, ok)
				}
			} else if !bytes.Equal(receivedObjects[0].Data, []byte{1, 2, 3, 4}) {
				t.Fatalf("retained unknown extension = %+v", receivedObjects[0])
			}
		})
	}
}

func TestIPConnPathMTUAndICMPCorrelation(t *testing.T) {
	for _, test := range []struct {
		name                   string
		local, remote, unknown netip.Addr
		mtu                    uint32
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.180"), remote: netip.MustParseAddr("192.0.2.181"), unknown: netip.MustParseAddr("192.0.2.182"), mtu: 1200},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::180"), remote: netip.MustParseAddr("2001:db8::181"), unknown: netip.MustParseAddr("2001:db8::182"), mtu: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 32
			if test.local.Is6() {
				bits = 128
			}
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.local, bits)}, MTU: 1400})
			if err != nil {
				t.Fatal(err)
			}
			defer stack.Close()
			if err = stack.Start(); err != nil {
				t.Fatal(err)
			}
			connection, err := stack.ListenIP(context.Background(), "ip:99", netip.Addr{})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			payload := bytes.Repeat([]byte{0x5a}, 256)
			if _, err = connection.WriteTo(payload, ipNetAddr(test.remote)); err != nil {
				t.Fatal(err)
			}
			original := readOutboundPacket(t, stack)
			unknownQuote := buildIPPacket(test.local, test.unknown, 99, payload, 1, true)
			if err = writeTestPacket(stack, buildTestPacketTooBig(test.unknown, test.local, unknownQuote, test.mtu)); err != nil {
				t.Fatal(err)
			}
			if err = writeTestPacket(stack, buildTestPacketTooBig(test.remote, test.local, original, test.mtu)); err != nil {
				t.Fatal(err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			_, _, err = connection.ReadFrom(make([]byte, 1))
			var operationError *net.OpError
			if !errors.As(err, &operationError) {
				t.Fatalf("ReadFrom error = %#v, want IP socket network error", err)
			}
			errorAddress, ok := operationError.Addr.(*net.IPAddr)
			if !ok || errorAddress.String() != test.remote.String() {
				t.Fatalf("ReadFrom error address = %#v, want %s", operationError.Addr, test.remote)
			}
			var icmpError ICMPError
			if !errors.As(err, &icmpError) || icmpError.MTU != test.mtu || icmpError.QuotedProtocol != 99 {
				t.Fatalf("ReadFrom error does not expose matching ICMP error: %#v", err)
			}
			if learned := stack.mtuFor(test.remote); learned != int(test.mtu) {
				t.Fatalf("learned PMTU = %d, want %d", learned, test.mtu)
			}
			if unknown := stack.mtuFor(test.unknown); unknown != 1400 {
				t.Fatalf("unmatched target PMTU = %d, want 1400", unknown)
			}
			info := connection.(*IPConn).Info()
			if info.ICMPErrors != 1 || info.LastError == nil || info.PathMTU != 0 {
				t.Fatalf("IP socket diagnostics = %+v", info)
			}
		})
	}
}

func TestDatagramPathMTUDiscoverySocketPolicy(t *testing.T) {
	type pathMTUSocket interface {
		net.Conn
		SetPathMTUDiscovery(PathMTUDiscovery) error
		PathMTUDiscovery() (PathMTUDiscovery, error)
	}
	protocols := []struct {
		name string
		open func(*Stack, netip.Addr) (pathMTUSocket, error)
	}{
		{name: "UDP", open: func(stack *Stack, remote netip.Addr) (pathMTUSocket, error) {
			connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 5353))
			if err != nil {
				return nil, err
			}
			return connection.(*UDPConn), nil
		}},
		{name: "IP", open: func(stack *Stack, remote netip.Addr) (pathMTUSocket, error) {
			connection, err := stack.DialIP(context.Background(), "ip4:99", netip.Addr{}, remote)
			if err != nil {
				return nil, err
			}
			return connection.(*IPConn), nil
		}},
	}
	modes := []struct {
		name    string
		mode    PathMTUDiscovery
		updates bool
	}{
		{name: "dont", mode: PathMTUDiscoveryDont, updates: true},
		{name: "want", mode: PathMTUDiscoveryWant, updates: true},
		{name: "do", mode: PathMTUDiscoveryDo, updates: true},
		{name: "probe", mode: PathMTUDiscoveryProbe, updates: true},
		{name: "interface", mode: PathMTUDiscoveryInterface},
		{name: "omit", mode: PathMTUDiscoveryOmit},
	}
	for _, protocol := range protocols {
		for _, mode := range modes {
			t.Run(protocol.name+"/"+mode.name, func(t *testing.T) {
				local := netip.MustParseAddr("192.0.2.190")
				remote := netip.MustParseAddr("198.51.100.190")
				stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
				if err != nil {
					t.Fatal(err)
				}
				defer stack.Close()
				if err = stack.Start(); err != nil {
					t.Fatal(err)
				}
				connection, err := protocol.open(stack, remote)
				if err != nil {
					t.Fatal(err)
				}
				if initial, getErr := connection.PathMTUDiscovery(); getErr != nil || initial != PathMTUDiscoveryDont {
					t.Fatalf("initial PathMTUDiscovery = %v, %v", initial, getErr)
				}
				if err = connection.SetPathMTUDiscovery(mode.mode); err != nil {
					t.Fatal(err)
				}
				if selected, getErr := connection.PathMTUDiscovery(); getErr != nil || selected != mode.mode {
					t.Fatalf("PathMTUDiscovery = %v, %v, want %v", selected, getErr, mode.mode)
				}
				if err = connection.SetPathMTUDiscovery(PathMTUDiscovery(99)); !errors.Is(err, syscall.EINVAL) {
					t.Fatalf("invalid SetPathMTUDiscovery = %v", err)
				}
				if selected, getErr := connection.PathMTUDiscovery(); getErr != nil || selected != mode.mode {
					t.Fatalf("invalid option changed mode to %v, %v", selected, getErr)
				}
				if _, err = connection.Write([]byte("probe")); err != nil {
					t.Fatal(err)
				}
				quoted := readOutboundPacket(t, stack)
				if err = writeTestPacket(stack, buildTestPacketTooBig(remote, local, quoted, 1200)); err != nil {
					t.Fatal(err)
				}
				wantMTU := 1400
				if mode.updates {
					wantMTU = 1200
				}
				if mtu := stack.mtuFor(remote); mtu != wantMTU {
					t.Fatalf("PMTU after Packet Too Big = %d, want %d", mtu, wantMTU)
				}
				if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err = connection.Read(make([]byte, 1)); err == nil {
					t.Fatal("Packet Too Big was not delivered to socket")
				} else {
					var networkError ICMPError
					if !errors.As(err, &networkError) || networkError.MTU != 1200 {
						t.Fatalf("socket error = %#v, want Packet Too Big", err)
					}
				}
				if err = connection.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err = connection.PathMTUDiscovery(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("PathMTUDiscovery after Close = %v", err)
				}
				if err = connection.SetPathMTUDiscovery(mode.mode); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("SetPathMTUDiscovery after Close = %v", err)
				}
			})
		}
	}
}

func TestIPConnICMPErrorDoesNotRequireTransportHeader(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.183")
	remote := netip.MustParseAddr("192.0.2.184")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.ListenIP(context.Background(), "ip4:17", netip.IPv4Unspecified())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.WriteTo([]byte{1, 2, 3, 4}, ipNetAddr(remote)); err != nil {
		t.Fatal(err)
	}
	original := readOutboundPacket(t, stack)
	if err = writeTestPacket(stack, buildTestPacketTooBig(remote, local, original, 1200)); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err = connection.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("raw UDP-protocol socket did not receive the correlated ICMP error")
	} else {
		var icmpError ICMPError
		if !errors.As(err, &icmpError) || icmpError.QuotedProtocol != ProtocolUDP || len(icmpError.QuotedPayload) != 4 {
			t.Fatalf("short quoted transport error = %#v", err)
		}
	}
}

// TestControlResponseRateLimitAndStats verifies independent token accounting
// and the public read-only statistics snapshot.
func TestControlResponseRateLimitAndStats(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	stack.controlMu.Lock()
	stack.controlLimiters[controlResponseTCPReset] = tokenBucket{tokens: 1, updated: time.Now()}
	stack.controlLimiters[controlResponseTCPChallengeACK] = tokenBucket{tokens: 1, updated: time.Now()}
	stack.controlMu.Unlock()
	if !stack.allowControlResponse(controlResponseTCPReset) {
		t.Fatal("first control response was unexpectedly limited")
	}
	if stack.allowControlResponse(controlResponseTCPReset) {
		t.Fatal("second control response exceeded the token bucket")
	}
	if !stack.allowControlResponse(controlResponseTCPChallengeACK) || stack.allowControlResponse(controlResponseTCPChallengeACK) {
		t.Fatal("TCP challenge ACK did not use its independent token bucket")
	}
	stats := stack.Stats()
	if stats.RateLimitedControlResponses != 2 {
		t.Fatalf("rate-limited responses = %d, want 2", stats.RateLimitedControlResponses)
	}
}

// TestICMPv6ErrorSizeLimit verifies the RFC 4443 requirement that an ICMPv6
// error, including its IPv6 header, never exceeds the 1280-byte minimum MTU.
func TestICMPv6ErrorSizeLimit(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("2001:db8::95"), netip.MustParseAddr("2001:db8:1::95"))
	defer stack.Close()
	request := buildTestUDP(link.remote, link.local, 55000, 55001, bytes.Repeat([]byte{0x5a}, 1400))
	if err := writeTestPacket(stack, request); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ICMPv6 error")
	}
	if len(response) != ipv6MinimumMTU {
		t.Fatalf("ICMPv6 error size = %d, want %d", len(response), ipv6MinimumMTU)
	}
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) != ipv6MinimumMTU-40 || parsed.payload[0] != 1 || parsed.payload[1] != 4 {
		t.Fatalf("ICMPv6 error = %x, parsed = %v", response[:48], ok)
	}
}

// TestLimitedBroadcastSourceIsDropped prevents replies to a non-unicast IPv4
// source that could otherwise amplify traffic toward the local broadcast.
func TestLimitedBroadcastSourceIsDropped(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.95"), netip.MustParseAddr("198.51.100.95"))
	defer stack.Close()
	request := buildTestUDP(netip.MustParseAddr("255.255.255.255"), link.local, 55002, 55003, []byte("drop"))
	if err := writeTestPacket(stack, request); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-link.outbound:
		t.Fatalf("limited-broadcast source produced a response: %x", response)
	case <-time.After(25 * time.Millisecond):
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("limited-broadcast drops = %d, want 1", dropped)
	}
}

func BenchmarkPublicICMPErrorCodec(b *testing.B) {
	source := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.1")
	reporter := netip.MustParseAddr("198.51.100.254")
	quote := buildIPPacket(source, target, ProtocolUDP, make([]byte, udpHeaderSize+64), 31, true)
	plainError := ICMPError{
		Reporter: reporter, Type: ICMPv4TypeTimeExceeded,
		Code: ICMPv4TimeExceededCodeTTLInTransit, QuotedPacket: quote,
	}
	extendedError := plainError
	if err := extendedError.SetExtensionObjects([]ICMPExtensionObject{
		{Class: 0xfe, Type: 1, Data: []byte{1, 2, 3, 4}},
	}); err != nil {
		b.Fatal(err)
	}
	plainMessage, err := plainError.ICMPMessage(source)
	if err != nil {
		b.Fatal(err)
	}
	extendedMessage, err := extendedError.ICMPMessage(source)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("ParsePlain", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(plainMessage.Body)))
		var parsed ICMPError
		var parseErr error
		for i := 0; i < b.N; i++ {
			parsed, parseErr = plainMessage.ICMPError()
		}
		if parseErr != nil || parsed.Reporter != reporter {
			b.Fatal(parseErr)
		}
	})
	b.Run("ParseExtended", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(extendedMessage.Body)))
		var parsed ICMPError
		var parseErr error
		for i := 0; i < b.N; i++ {
			parsed, parseErr = extendedMessage.ICMPError()
		}
		if parseErr != nil || len(parsed.Extensions) == 0 {
			b.Fatal(parseErr)
		}
	})
	b.Run("ExtensionObjects", func(b *testing.B) {
		b.ReportAllocs()
		var objects []ICMPExtensionObject
		var parseErr error
		for i := 0; i < b.N; i++ {
			objects, parseErr = extendedError.ExtensionObjects()
		}
		if parseErr != nil || len(objects) != 1 {
			b.Fatal(parseErr)
		}
	})
	b.Run("ConstructPlain", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(plainMessage.Body)))
		var message ICMPMessage
		var constructErr error
		for i := 0; i < b.N; i++ {
			message, constructErr = plainError.ICMPMessage(source)
		}
		if constructErr != nil || len(message.Body) == 0 {
			b.Fatal(constructErr)
		}
	})
	b.Run("ConstructExtended", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(extendedMessage.Body)))
		var message ICMPMessage
		var constructErr error
		for i := 0; i < b.N; i++ {
			message, constructErr = extendedError.ICMPMessage(source)
		}
		if constructErr != nil || len(message.Body) == 0 {
			b.Fatal(constructErr)
		}
	})
}
