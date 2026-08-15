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
		{ProtocolICMPv6, 1, 7, true},
		{ProtocolICMPv6, 1, 8, false},
		{ProtocolICMPv6, 2, 0, true},
		{ProtocolICMPv6, 2, 1, false},
		{ProtocolICMPv6, 3, 1, true},
		{ProtocolICMPv6, 3, 2, false},
		{ProtocolICMPv6, 4, 3, true},
		{ProtocolICMPv6, 4, 4, true},
		{ProtocolICMPv6, 4, 5, false},
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
	authentication := make([]byte, 12+udpHeaderSize)
	authentication[0], authentication[1] = ProtocolUDP, 1
	quotedAuthentication6 := buildIPPacket(source6, target6, 51, authentication, 0, false)
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
		if !bytes.Equal(quote, before) {
			t.Fatal("ICMP quote parsing modified its input")
		}
		if !ok {
			return
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
			if _, err = connection.WriteToIP(payload, ipNetAddr(test.remote)); err != nil {
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
			info := connection.Info()
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
	if _, err = connection.WriteToIP([]byte{1, 2, 3, 4}, ipNetAddr(remote)); err != nil {
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
