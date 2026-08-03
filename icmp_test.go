package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestLegacyIPv4PathMTU verifies RFC 1191 plateau inference for routers that
// leave the next-hop MTU field zero.
func TestLegacyIPv4PathMTU(t *testing.T) {
	packet := buildIPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), protocolTCP, make([]byte, 1400), 1, true)
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
		{protocolICMPv4, 3, 15, true},
		{protocolICMPv4, 3, 16, false},
		{protocolICMPv4, 11, 1, true},
		{protocolICMPv4, 11, 2, false},
		{protocolICMPv4, 12, 2, true},
		{protocolICMPv4, 12, 3, false},
		{protocolICMPv6, 1, 7, true},
		{protocolICMPv6, 1, 8, false},
		{protocolICMPv6, 2, 0, true},
		{protocolICMPv6, 2, 1, false},
		{protocolICMPv6, 3, 1, true},
		{protocolICMPv6, 3, 2, false},
		{protocolICMPv6, 4, 2, true},
		{protocolICMPv6, 4, 3, false},
		{protocolICMPv4, 8, 0, false},
	} {
		if got := validICMPErrorCode(test.protocol, test.messageType, test.code); got != test.valid {
			t.Errorf("validICMPErrorCode(%d, %d, %d) = %v, want %v", test.protocol, test.messageType, test.code, got, test.valid)
		}
	}
}

// TestTruncatedICMPv6ErrorIsRejected verifies that the standalone parser does
// not rely on handleICMP's outer length check.
func TestTruncatedICMPv6ErrorIsRejected(t *testing.T) {
	if _, ok := parseICMPError(ipPacket{protocol: protocolICMPv6, payload: []byte{1}}); ok {
		t.Fatal("truncated ICMPv6 error was accepted")
	}
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
			protocol := protocolICMPv4
			icmp[0] = 8
			if test.local.Is6() {
				protocol = protocolICMPv6
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
				if !ok || remoteError.QuotedSource != test.remote || remoteError.QuotedTarget != test.local || remoteError.QuotedProtocol != protocolUDP || len(remoteError.QuotedPayload) < 4 || binary.BigEndian.Uint16(remoteError.QuotedPayload[0:2]) != 41001 || binary.BigEndian.Uint16(remoteError.QuotedPayload[2:4]) != 41002 {
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
	if !ok || parsed.protocol != protocolICMPv6 || len(parsed.payload) != ipv6MinimumMTU-40 || parsed.payload[0] != 1 || parsed.payload[1] != 4 {
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
