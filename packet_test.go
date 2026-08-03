package mipstack

import (
	"encoding/binary"
	"net/netip"
	"testing"
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
	for _, options := range [][]byte{{7, 1, 0, 0}, {131, 3, 4, 0}, {0, 1, 0, 0}} {
		if _, ok := parseIPPacket(buildTestIPv4Options(remote4, local4, options)); ok {
			t.Fatalf("invalid IPv4 options accepted: %x", options)
		}
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
	activeRouting := buildTestIPv6Extension(remote6, local6, 43, []byte{protocolUDP, 0, 99, 1, 0, 0, 0, 0})
	if err = writeTestPacket(stack, activeRouting); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != protocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 0 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 routing-header response = %x", response)
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
