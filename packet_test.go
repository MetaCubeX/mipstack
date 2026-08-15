package mipstack

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

type binaryAppender interface {
	AppendBinary([]byte) ([]byte, error)
}

var (
	_ encoding.BinaryMarshaler = IPPacket{}
	_ encoding.BinaryMarshaler = TCPSegment{}
	_ encoding.BinaryMarshaler = UDPDatagram{}
	_ encoding.BinaryMarshaler = ICMPMessage{}
	_ binaryAppender           = IPPacket{}
	_ binaryAppender           = TCPSegment{}
	_ binaryAppender           = UDPDatagram{}
	_ binaryAppender           = ICMPMessage{}
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
				pseudoHeader = append(pseudoHeader, 0, ProtocolTCP, byte(size>>8), byte(size))
			} else {
				pseudoHeader = append(pseudoHeader, byte(size>>24), byte(size>>16), byte(size>>8), byte(size), 0, 0, 0, ProtocolTCP)
			}
			pseudoHeader = append(pseudoHeader, payload[:size]...)
			if got, want := transportChecksum(test.source, test.target, ProtocolTCP, payload[:size]), referenceChecksum(pseudoHeader); got != want {
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
		want := transportChecksum(addresses[0], addresses[1], ProtocolUDP, payload)
		for split := 0; split <= len(payload); split++ {
			if got := transportChecksumParts(addresses[0], addresses[1], ProtocolUDP, len(payload), payload[:split], payload[split:]); got != want {
				t.Fatalf("%s split %d checksum = %#x, want %#x", addresses[0], split, got, want)
			}
		}
	}
}

func TestPublicIPPacketCodec(t *testing.T) {
	tests := []IPPacket{
		{
			Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
			Protocol: 99, HopLimit: 0, TrafficClass: 0xab, Identification: 0x1234, DontFragment: true,
			IPv4Options: []byte{1, 148, 4, 0, 0}, Payload: []byte("ipv4-codec-payload"),
		},
		{
			Source: netip.MustParseAddr("2001:db8::10"), Destination: netip.MustParseAddr("2001:db8::20"),
			Protocol: 60, HopLimit: 0, TrafficClass: 0xab, FlowLabel: 0xabcde,
			Payload: append([]byte{99, 0, 0x80, 0, 0, 0, 0, 0}, []byte("ipv6-upper-layer")...),
		},
	}
	for _, test := range tests {
		name := "IPv4"
		if test.Source.Is6() {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			prefix := []byte{0xaa, 0xbb, 0xcc}
			wire, err := test.AppendBinary(append([]byte(nil), prefix...))
			if err != nil {
				t.Fatalf("append packet: %v", err)
			}
			if !bytes.Equal(wire[:len(prefix)], prefix) {
				t.Fatal("AppendBinary changed the destination prefix")
			}
			wire = wire[len(prefix):]
			parsed, err := ParseIPPacket(wire)
			if err != nil {
				t.Fatalf("parse packet: %v", err)
			}
			if parsed.Source != test.Source || parsed.Destination != test.Destination || parsed.Protocol != test.Protocol || parsed.HopLimit != 0 || parsed.TrafficClass != test.TrafficClass || parsed.FlowLabel != test.FlowLabel || parsed.Identification != test.Identification || parsed.DontFragment != test.DontFragment {
				t.Fatalf("parsed packet metadata = %+v, want %+v", parsed, test)
			}
			protocol, upper, err := parsed.UpperLayer()
			if err != nil {
				t.Fatalf("locate upper layer: %v", err)
			}
			wantProtocol, wantUpper := test.Protocol, test.Payload
			if test.Source.Is6() {
				wantProtocol, wantUpper = 99, test.Payload[8:]
			}
			if protocol != wantProtocol || !bytes.Equal(upper, wantUpper) {
				t.Fatalf("upper layer = protocol %d payload %x, want %d %x", protocol, upper, wantProtocol, wantUpper)
			}
			roundTrip, err := parsed.MarshalBinary()
			if err != nil || !bytes.Equal(roundTrip, wire) {
				t.Fatalf("packet round trip: error=%v\n got %x\nwant %x", err, roundTrip, wire)
			}
			inPlace := append([]byte(nil), wire...)
			inPlacePacket, err := ParseIPPacket(inPlace)
			if err != nil {
				t.Fatal(err)
			}
			inPlaceResult, appendErr := inPlacePacket.AppendBinary(inPlace[:0])
			if appendErr != nil || len(inPlaceResult) == 0 || &inPlaceResult[0] != &inPlace[0] || !bytes.Equal(inPlaceResult, wire) {
				t.Fatalf("in-place packet round trip: error=%v\n got %x\nwant %x", appendErr, inPlaceResult, wire)
			}
		})
	}
}

func TestPublicIPv4HeaderOptions(t *testing.T) {
	data := []byte{0xaa, 0xbb}
	options := []IPv4HeaderOption{
		{Type: IPv4HeaderOptionNOP},
		{Type: IPv4HeaderOptionRouterAlert, Data: []byte{0, 0}},
		{Type: 30, Data: data},
		{Type: 30, Data: []byte{0xcc}},
		{Type: IPv4HeaderOptionEnd},
	}
	packet := IPPacket{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
		Protocol: 99, HopLimit: 64, Payload: []byte("structured-ipv4-options"),
	}
	if err := packet.SetIPv4HeaderOptions(options); err != nil {
		t.Fatalf("SetIPv4HeaderOptions: %v", err)
	}
	wantOptions := append([]byte(nil), packet.IPv4Options...)
	data[0] ^= 0xff
	if !bytes.Equal(packet.IPv4Options, wantOptions) {
		t.Fatal("SetIPv4HeaderOptions retained caller storage")
	}
	parsed, err := packet.IPv4HeaderOptions()
	if err != nil {
		t.Fatalf("IPv4HeaderOptions: %v", err)
	}
	if len(parsed) != len(options) || parsed[0].Type != IPv4HeaderOptionNOP ||
		parsed[1].Type != IPv4HeaderOptionRouterAlert || !bytes.Equal(parsed[1].Data, []byte{0, 0}) ||
		parsed[2].Type != 30 || parsed[3].Type != 30 || parsed[4].Type != IPv4HeaderOptionEnd {
		t.Fatalf("parsed IPv4 options = %+v", parsed)
	}
	sourceRoute := IPv4HeaderOption{Type: IPv4HeaderOptionLooseSourceRoute}
	if !sourceRoute.Copied() || sourceRoute.Class() != 0 || sourceRoute.Number() != 3 {
		t.Fatalf("source-route type fields = copied %t class %d number %d", sourceRoute.Copied(), sourceRoute.Class(), sourceRoute.Number())
	}

	copyPacket := packet
	if err = copyPacket.SetIPv4HeaderOptions(parsed); err != nil {
		t.Fatalf("copy parsed IPv4 options: %v", err)
	}
	parsed[2].Data[0] ^= 0xff
	if packet.IPv4Options[7] != 0x55 {
		t.Fatal("IPv4HeaderOptions Data did not borrow IPv4Options")
	}
	if !bytes.Equal(copyPacket.IPv4Options, wantOptions) {
		t.Fatal("SetIPv4HeaderOptions did not copy parsed Data")
	}
	wire, err := copyPacket.AppendBinary(nil)
	if err != nil {
		t.Fatalf("encode IPv4 options: %v", err)
	}
	decoded, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("decode IPv4 options: %v", err)
	}
	decodedOptions, err := decoded.IPv4HeaderOptions()
	if err != nil || len(decodedOptions) != len(options) {
		t.Fatalf("decoded IPv4 options = %+v, %v", decodedOptions, err)
	}
}

func TestPublicIPv4HeaderOptionErrors(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
		IPv4Options: []byte{IPv4HeaderOptionNOP},
	}
	want := append([]byte(nil), packet.IPv4Options...)
	tests := []struct {
		name    string
		options []IPv4HeaderOption
		wantErr error
	}{
		{name: "End data", options: []IPv4HeaderOption{{Type: IPv4HeaderOptionEnd, Data: []byte{1}}}, wantErr: syscall.EINVAL},
		{name: "NOP data", options: []IPv4HeaderOption{{Type: IPv4HeaderOptionNOP, Data: []byte{1}}}, wantErr: syscall.EINVAL},
		{name: "after End", options: []IPv4HeaderOption{{Type: IPv4HeaderOptionEnd}, {Type: IPv4HeaderOptionNOP}}, wantErr: syscall.EINVAL},
		{name: "oversized", options: []IPv4HeaderOption{{Type: 30, Data: make([]byte, 39)}}, wantErr: syscall.EMSGSIZE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := packet.SetIPv4HeaderOptions(test.options); !errors.Is(err, test.wantErr) {
				t.Fatalf("SetIPv4HeaderOptions error = %v, want %v", err, test.wantErr)
			}
			if !bytes.Equal(packet.IPv4Options, want) {
				t.Fatal("failed SetIPv4HeaderOptions changed the receiver")
			}
		})
	}
	for _, raw := range [][]byte{{30}, {30, 1}, make([]byte, 41)} {
		packet.IPv4Options = raw
		if _, err := packet.IPv4HeaderOptions(); err == nil {
			t.Fatalf("IPv4HeaderOptions accepted %x", raw)
		}
	}
	v6 := IPPacket{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2")}
	if _, err := v6.IPv4HeaderOptions(); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv6 IPv4HeaderOptions error = %v", err)
	}
	if err := v6.SetIPv4HeaderOptions(nil); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv6 SetIPv4HeaderOptions error = %v", err)
	}
}

func TestPublicIPv4HeaderOptionsNormalizeEOLPadding(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
		Protocol: ProtocolUDP, HopLimit: 64,
		IPv4Options: []byte{IPv4HeaderOptionEnd, 0xaa, 0xbb, 0xcc}, Payload: make([]byte, udpHeaderSize),
	}
	wire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[20:24], []byte{0, 0, 0, 0}) {
		t.Fatalf("generated IPv4 EOL padding = %x, want zeros", wire[20:24])
	}

	raw := append([]byte(nil), wire...)
	copy(raw[21:24], []byte{0xaa, 0xbb, 0xcc})
	raw[10], raw[11] = 0, 0
	binary.BigEndian.PutUint16(raw[10:12], checksum(raw[:24]))
	parsed, err := ParseIPPacket(raw)
	if err != nil {
		t.Fatalf("parse nonzero IPv4 EOL padding: %v", err)
	}
	if !bytes.Equal(parsed.IPv4Options, raw[20:24]) {
		t.Fatalf("parsed IPv4 EOL padding = %x, want %x", parsed.IPv4Options, raw[20:24])
	}
	options, err := parsed.IPv4HeaderOptions()
	if err != nil || len(options) != 1 || options[0].Type != IPv4HeaderOptionEnd {
		t.Fatalf("structured IPv4 EOL = %+v, error=%v", options, err)
	}
	reencoded, err := parsed.AppendBinary(nil)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatalf("normalized IPv4 packet: error=%v\n got %x\nwant %x", err, reencoded, wire)
	}
	internal, ok := parseIPPacket(raw)
	if !ok || internal.parameterError {
		t.Fatalf("runtime parser rejected Linux-compatible EOL padding: %+v, ok=%t", internal, ok)
	}
}

func TestPublicIPv6ExtensionHeaders(t *testing.T) {
	unknownData := []byte{1, 2, 3}
	hop := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := hop.SetOptions([]IPv6ExtensionOption{
		{Type: IPv6ExtensionOptionRouterAlert, Data: []byte{0, 0}},
		{Type: 0xe3, Data: unknownData},
		{Type: IPv6ExtensionOptionPad1},
	}); err != nil {
		t.Fatalf("set Hop-by-Hop options: %v", err)
	}
	wantHop := append([]byte(nil), hop.Data...)
	unknownData[0] ^= 0xff
	if !bytes.Equal(hop.Data, wantHop) {
		t.Fatal("SetOptions retained caller storage")
	}
	options, err := hop.Options()
	if err != nil {
		t.Fatalf("parse Hop-by-Hop options: %v", err)
	}
	if len(options) < 3 || options[0].Type != IPv6ExtensionOptionRouterAlert || options[1].Type != 0xe3 ||
		options[1].Action() != 3 || !options[1].MayChangeInTransit() || !bytes.Equal(options[1].Data, []byte{1, 2, 3}) {
		t.Fatalf("parsed IPv6 options = %+v", options)
	}
	hopCopy := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err = hopCopy.SetOptions(options); err != nil {
		t.Fatalf("copy parsed IPv6 options: %v", err)
	}
	options[1].Data[0] ^= 0xff
	if !bytes.Equal(hopCopy.Data, wantHop) {
		t.Fatal("SetOptions did not copy parsed Data")
	}

	destination := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderDestination}
	if err = destination.SetOptions(nil); err != nil {
		t.Fatal(err)
	}
	routing := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderRouting, Data: []byte{0, 0, 0, 0, 0, 0, 0}}
	fragment := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderFragment, Data: []byte{0, 0, 0, 0x12, 0x34, 0x56, 0x78}}
	authentication := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderAuthentication, Data: make([]byte, 15)}
	authentication.Data[0] = 2
	mobility := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderMobility, Data: []byte{0, 0, 0, 0, 0, 0, 0}}
	headers := []IPv6ExtensionHeader{hopCopy, routing, fragment, authentication, destination, mobility}
	payload := []byte("extension-payload")
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), HopLimit: 64,
	}
	if err = packet.SetIPv6ExtensionHeaders(headers, 99, payload); err != nil {
		t.Fatalf("SetIPv6ExtensionHeaders: %v", err)
	}
	wantPayload := append([]byte(nil), packet.Payload...)
	headers[1].Data[1] ^= 0xff
	payload[0] ^= 0xff
	if !bytes.Equal(packet.Payload, wantPayload) {
		t.Fatal("SetIPv6ExtensionHeaders retained caller storage")
	}
	parsedHeaders, protocol, upper, err := packet.IPv6ExtensionHeaders()
	if err != nil || protocol != 99 || !bytes.Equal(upper, []byte("extension-payload")) || len(parsedHeaders) != len(headers) {
		t.Fatalf("IPv6ExtensionHeaders = %d headers, protocol %d, payload %x, %v", len(parsedHeaders), protocol, upper, err)
	}
	for index := range headers {
		if parsedHeaders[index].Type != headers[index].Type {
			t.Fatalf("header %d type = %d, want %d", index, parsedHeaders[index].Type, headers[index].Type)
		}
	}
	if gotProtocol, gotPayload, upperErr := packet.UpperLayer(); upperErr != nil || gotProtocol != 99 || !bytes.Equal(gotPayload, upper) {
		t.Fatalf("UpperLayer = %d/%x, %v", gotProtocol, gotPayload, upperErr)
	}
	wire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatalf("encode extension chain: %v", err)
	}
	decoded, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("decode extension chain: %v", err)
	}
	decodedHeaders, protocol, upper, err := decoded.IPv6ExtensionHeaders()
	if err != nil || protocol != 99 || !bytes.Equal(upper, []byte("extension-payload")) || len(decodedHeaders) != len(headers) {
		t.Fatalf("decoded extension chain = %d/%d/%x, %v", len(decodedHeaders), protocol, upper, err)
	}
	noNext := packet
	trailing := []byte{1, 2, 3}
	if err = noNext.SetIPv6ExtensionHeaders(nil, ProtocolNoNextHeader, trailing); err != nil {
		t.Fatal(err)
	}
	noHeaders, noProtocol, noPayload, err := noNext.IPv6ExtensionHeaders()
	if err != nil || len(noHeaders) != 0 || noProtocol != ProtocolNoNextHeader || !bytes.Equal(noPayload, trailing) {
		t.Fatalf("No Next Header structural result = %+v/%d/%x, %v", noHeaders, noProtocol, noPayload, err)
	}
	if _, ignored, err := noNext.UpperLayer(); err != nil || ignored != nil {
		t.Fatalf("No Next Header upper payload = %x, %v", ignored, err)
	}
}

func TestPublicIPv6ExtensionHeaderErrors(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 99, Payload: []byte{1, 2, 3},
	}
	wantProtocol, wantPayload := packet.Protocol, append([]byte(nil), packet.Payload...)
	fragment := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderFragment, Data: []byte{0, 0, 1, 0, 0, 0, 1}}
	jumbo := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderHopByHop}
	if err := jumbo.SetOptions([]IPv6ExtensionOption{{Type: IPv6ExtensionOptionJumboPayload, Data: []byte{0, 1, 0, 0}}}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		headers  []IPv6ExtensionHeader
		protocol int
		payload  []byte
		wantErr  error
	}{
		{name: "extension terminal", protocol: IPv6ExtensionHeaderDestination, wantErr: syscall.EINVAL},
		{name: "unknown header", headers: []IPv6ExtensionHeader{{Type: 99}}, protocol: ProtocolUDP, wantErr: syscall.EPROTONOSUPPORT},
		{name: "late Hop-by-Hop", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderDestination, Data: make([]byte, 7)}, {Type: IPv6ExtensionHeaderHopByHop, Data: make([]byte, 7)}}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "malformed Routing", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderRouting, Data: make([]byte, 6)}}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "short Authentication", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderAuthentication, Data: make([]byte, 7)}}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "misaligned Authentication", headers: []IPv6ExtensionHeader{{Type: IPv6ExtensionHeaderAuthentication, Data: append([]byte{1}, make([]byte, 10)...)}}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "non-atomic Fragment", headers: []IPv6ExtensionHeader{fragment}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "Jumbo Payload", headers: []IPv6ExtensionHeader{jumbo}, protocol: ProtocolUDP, wantErr: syscall.EINVAL},
		{name: "oversized", protocol: ProtocolUDP, payload: make([]byte, 65536), wantErr: syscall.EMSGSIZE},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := packet.SetIPv6ExtensionHeaders(test.headers, test.protocol, test.payload); !errors.Is(err, test.wantErr) {
				t.Fatalf("SetIPv6ExtensionHeaders error = %v, want %v", err, test.wantErr)
			}
			if packet.Protocol != wantProtocol || !bytes.Equal(packet.Payload, wantPayload) {
				t.Fatal("failed SetIPv6ExtensionHeaders changed the receiver")
			}
		})
	}
	v4 := IPPacket{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1")}
	if _, _, _, err := v4.IPv6ExtensionHeaders(); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv4 IPv6ExtensionHeaders error = %v", err)
	}
	if err := v4.SetIPv6ExtensionHeaders(nil, ProtocolUDP, nil); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("IPv4 SetIPv6ExtensionHeaders error = %v", err)
	}
	if _, err := (IPv6ExtensionHeader{Type: IPv6ExtensionHeaderRouting, Data: make([]byte, 7)}).Options(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("Routing Options error = %v", err)
	}
	header := IPv6ExtensionHeader{Type: IPv6ExtensionHeaderDestination, Data: []byte{0, 1, 2}}
	wantData := append([]byte(nil), header.Data...)
	if err := header.SetOptions([]IPv6ExtensionOption{{Type: IPv6ExtensionOptionPad1, Data: []byte{1}}}); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(header.Data, wantData) {
		t.Fatalf("invalid Pad1 SetOptions = %x, %v", header.Data, err)
	}
	if err := header.SetOptions([]IPv6ExtensionOption{{Type: 30, Data: make([]byte, 256)}}); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(header.Data, wantData) {
		t.Fatalf("oversized option SetOptions = %x, %v", header.Data, err)
	}
}

// TestPublicCodecAppendBinaryOverlappingOptions covers a caller reusing a parsed
// wire buffer after selecting an option subslice that the shifted payload will
// overwrite. AppendBinary must read all semantic fields before changing dst.
func TestPublicCodecAppendBinaryOverlappingOptions(t *testing.T) {
	ip := IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: 99, HopLimit: 64, IPv4Options: []byte{1, 1, 1, 1, 148, 4, 0, 0}, Payload: []byte("overlapping-ip-options"),
	}
	ipWire, err := ip.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedIP, err := ParseIPPacket(ipWire)
	if err != nil {
		t.Fatal(err)
	}
	parsedIP.IPv4Options = parsedIP.IPv4Options[4:8]
	wantIP := parsedIP
	wantIP.IPv4Options = append([]byte(nil), parsedIP.IPv4Options...)
	wantIP.Payload = append([]byte(nil), parsedIP.Payload...)
	wantIPWire, err := wantIP.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	encodedIP, err := parsedIP.AppendBinary(ipWire[:0])
	if err != nil || len(encodedIP) == 0 || &encodedIP[0] != &ipWire[0] || !bytes.Equal(encodedIP, wantIPWire) {
		t.Fatalf("overlapping IPv4 options: error=%v\n got %x\nwant %x", err, encodedIP, wantIPWire)
	}

	segment := TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("198.51.100.20:443"),
		Flags: TCPFlagACK, Options: []byte{1, 1, 1, 1, 2, 4, 5, 180}, Payload: []byte("overlapping-tcp-options"),
	}
	tcpWire, err := segment.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedSegment, err := (IPPacket{
		Source: segment.Source.Addr(), Destination: segment.Destination.Addr(), Protocol: ProtocolTCP, Payload: tcpWire,
	}).TCPSegment()
	if err != nil {
		t.Fatal(err)
	}
	parsedSegment.Options = parsedSegment.Options[4:8]
	wantSegment := parsedSegment
	wantSegment.Options = append([]byte(nil), parsedSegment.Options...)
	wantSegment.Payload = append([]byte(nil), parsedSegment.Payload...)
	wantTCPWire, err := wantSegment.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	encodedTCP, err := parsedSegment.AppendBinary(tcpWire[:0])
	if err != nil || len(encodedTCP) == 0 || &encodedTCP[0] != &tcpWire[0] || !bytes.Equal(encodedTCP, wantTCPWire) {
		t.Fatalf("overlapping TCP options: error=%v\n got %x\nwant %x", err, encodedTCP, wantTCPWire)
	}
}

// TestPublicCodecAppendBinaryOverlappingInput verifies the natural zero-copy
// round-trip pattern where a parsed value still borrows the destination's
// backing array and AppendBinary reuses that array from length zero.
func TestPublicCodecAppendBinaryOverlappingInput(t *testing.T) {
	type appendTest struct {
		name   string
		wire   []byte
		append func([]byte) ([]byte, error)
	}
	tests := []appendTest{}

	ipWire, err := (IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: 99, HopLimit: 64, IPv4Options: []byte{1, 148, 4, 0, 0}, Payload: []byte("overlapping-ip-payload"),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedIP, err := ParseIPPacket(ipWire)
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, appendTest{"IP", ipWire, parsedIP.AppendBinary})

	tcpWire, err := (TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("198.51.100.20:443"),
		Flags: TCPFlagACK, Options: []byte{2, 4, 5, 180, 1}, Payload: []byte("overlapping-tcp-payload"),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedTCP, err := (IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: ProtocolTCP, Payload: tcpWire,
	}).TCPSegment()
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, appendTest{"TCP", tcpWire, parsedTCP.AppendBinary})

	udpWire, err := (UDPDatagram{
		Source: netip.MustParseAddrPort("192.0.2.10:1234"), Destination: netip.MustParseAddrPort("198.51.100.20:53"),
		Payload: []byte("overlapping-udp-payload"),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedUDP, err := (IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: ProtocolUDP, Payload: udpWire,
	}).UDPDatagram()
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, appendTest{"UDP", udpWire, parsedUDP.AppendBinary})

	icmpWire, err := (ICMPMessage{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Type: 8, Body: []byte{0x12, 0x34, 0, 1, 'e', 'c', 'h', 'o'},
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedICMP, err := (IPPacket{
		Source: netip.MustParseAddr("192.0.2.10"), Destination: netip.MustParseAddr("198.51.100.20"),
		Protocol: ProtocolICMPv4, Payload: icmpWire,
	}).ICMPMessage()
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, appendTest{"ICMP", icmpWire, parsedICMP.AppendBinary})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := append([]byte(nil), test.wire...)
			got, appendErr := test.append(test.wire[:0])
			if appendErr != nil || !bytes.Equal(got, want) {
				t.Fatalf("overlapping AppendBinary: error=%v\n got %x\nwant %x", appendErr, got, want)
			}
		})
	}
}

func TestPublicIPPacketCodecPolicyBoundary(t *testing.T) {
	// A codec may preserve source routing while transport decoding refuses to
	// use the base destination in a pseudo-header checksum.
	ipv4 := IPPacket{
		Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Protocol: ProtocolTCP,
		HopLimit: 64, IPv4Options: []byte{131, 7, 4, 203, 0, 113, 1}, Payload: make([]byte, tcpHeaderSize),
	}
	wire, err := ipv4.AppendBinary(nil)
	if err != nil {
		t.Fatalf("marshal source-routed IPv4: %v", err)
	}
	parsed, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse source-routed IPv4: %v", err)
	}
	if _, err = parsed.TCPSegment(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("source-routed TCP error = %v, want EPROTONOSUPPORT", err)
	}
	icmpPayload, err := (ICMPMessage{
		Source: ipv4.Source, Destination: ipv4.Destination, Type: 8, Body: []byte{0, 1, 0, 2},
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoutedICMP := ipv4
	sourceRoutedICMP.Protocol, sourceRoutedICMP.Payload = ProtocolICMPv4, icmpPayload
	if _, err = sourceRoutedICMP.ICMPMessage(); err != nil {
		t.Fatalf("decode source-routed ICMPv4 without a pseudo-header: %v", err)
	}
	uncheckedUDPPayload, err := (UDPDatagram{
		Source: netip.AddrPortFrom(ipv4.Source, 1234), Destination: netip.AddrPortFrom(ipv4.Destination, 53),
		ChecksumDisabled: true,
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoutedUDP := ipv4
	sourceRoutedUDP.Protocol, sourceRoutedUDP.Payload = ProtocolUDP, uncheckedUDPPayload
	if _, err = sourceRoutedUDP.UDPDatagram(); err != nil {
		t.Fatalf("decode source-routed IPv4 UDP without a pseudo-header checksum: %v", err)
	}
	checkedUDPPayload, err := (UDPDatagram{
		Source: netip.AddrPortFrom(ipv4.Source, 1234), Destination: netip.AddrPortFrom(ipv4.Destination, 53),
	}).AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	sourceRoutedUDP.Payload = checkedUDPPayload
	if _, err = sourceRoutedUDP.UDPDatagram(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("source-routed checksummed UDP error = %v, want EPROTONOSUPPORT", err)
	}
	exhaustedSegment := TCPSegment{
		Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("192.0.2.2:443"),
		Flags: TCPFlagACK,
	}
	exhaustedPayload, err := exhaustedSegment.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	exhausted := ipv4
	exhausted.IPv4Options = []byte{131, 7, 8, 203, 0, 113, 1}
	exhausted.Payload = exhaustedPayload
	wire, err = exhausted.AppendBinary(nil)
	if err != nil {
		t.Fatalf("marshal exhausted source route: %v", err)
	}
	parsed, err = ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse exhausted source route: %v", err)
	}
	if _, err = parsed.TCPSegment(); err != nil {
		t.Fatalf("decode TCP after exhausted source route: %v", err)
	}

	ipv6 := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Protocol: 43, HopLimit: 64,
		Payload: append([]byte{ProtocolTCP, 0, 0, 1, 0, 0, 0, 0}, make([]byte, tcpHeaderSize)...),
	}
	wire, err = ipv6.AppendBinary(nil)
	if err != nil {
		t.Fatalf("marshal actively routed IPv6: %v", err)
	}
	parsed, err = ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse actively routed IPv6: %v", err)
	}
	if protocol, _, upperErr := parsed.UpperLayer(); upperErr != nil || protocol != ProtocolTCP {
		t.Fatalf("routed upper layer = %d, %v", protocol, upperErr)
	}
	if _, err = parsed.TCPSegment(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("routed TCP error = %v, want EPROTONOSUPPORT", err)
	}

	homeAddressOptions := make([]byte, 24)
	homeAddressOptions[0], homeAddressOptions[1] = ProtocolTCP, 2
	homeAddressOptions[2], homeAddressOptions[3] = 201, 16
	copy(homeAddressOptions[4:20], netip.MustParseAddr("2001:db8::10").AsSlice())
	homeAddressOptions[20], homeAddressOptions[21] = 1, 1
	homeAddressPacket := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 60, HopLimit: 64, Payload: append(homeAddressOptions, make([]byte, tcpHeaderSize)...),
	}
	wire, err = homeAddressPacket.AppendBinary(nil)
	if err != nil {
		t.Fatalf("marshal Home Address packet: %v", err)
	}
	parsed, err = ParseIPPacket(wire)
	if err != nil {
		t.Fatalf("parse Home Address packet: %v", err)
	}
	if _, err = parsed.TCPSegment(); !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Fatalf("Home Address TCP error = %v, want EPROTONOSUPPORT", err)
	}
}

func TestPublicIPv6NoNextHeaderAndLinkPadding(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 59, HopLimit: 64, Payload: []byte{1, 2, 3, 4},
	}
	wire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseIPPacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	protocol, upper, err := parsed.UpperLayer()
	if err != nil || protocol != 59 || len(upper) != 0 || !bytes.Equal(parsed.Payload, packet.Payload) {
		t.Fatalf("No Next Header upper layer = %d, %x, %v; packet payload=%x", protocol, upper, err, parsed.Payload)
	}

	empty := packet
	empty.Payload = nil
	wire, err = empty.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	padded := append(append([]byte(nil), wire...), 1, 2, 3, 4, 5, 6)
	parsed, err = ParseIPPacket(padded)
	if err != nil || len(parsed.Payload) != 0 {
		t.Fatalf("parse padded zero-payload IPv6: packet=%+v error=%v", parsed, err)
	}
	internal, ok := parseIPPacket(padded)
	if !ok || len(internal.payload) != 0 || len(internal.original) != len(wire) {
		t.Fatalf("internal padded zero-payload IPv6 = %+v, %v", internal, ok)
	}
}

func TestPublicIPv6JumboPayloadOptionRejected(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 0, HopLimit: 64,
		Payload: []byte{59, 0, 194, 4, 0, 1, 0, 0},
	}
	if _, err := packet.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("constructing a Jumbo Payload option returned %v, want EINVAL", err)
	}

	// Build the illegal nonzero Payload Length combination directly so parsing
	// cannot reuse the public constructor under test.
	wire := make([]byte, 48)
	wire[0], wire[6], wire[7] = 0x60, 0, 64
	binary.BigEndian.PutUint16(wire[4:6], 8)
	source, destination := packet.Source.As16(), packet.Destination.As16()
	copy(wire[8:24], source[:])
	copy(wire[24:40], destination[:])
	copy(wire[40:], packet.Payload)
	if _, err := ParseIPPacket(wire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("parsing a Jumbo Payload option returned %v, want EINVAL", err)
	}
	binary.BigEndian.PutUint16(wire[4:6], 0)
	if _, err := ParseIPPacket(wire); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("parsing a Payload Length zero jumbogram returned %v, want EINVAL", err)
	}
}

func TestPublicIPv6ExtensionIntegrityFieldsRemainOpaque(t *testing.T) {
	packet := IPPacket{
		Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"),
		Protocol: 0, HopLimit: 64,
		Payload: []byte{
			51, 0, 1, 4, 0xaa, 0xbb, 0xcc, 0xdd, // Hop-by-Hop with nonzero PadN data.
			135, 2, 0xaa, 0xbb, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, // AH with nonzero Reserved.
			44, 0, 5, 0xcc, 0, 0, 0, 0, // Mobility with nonzero Reserved.
			99, 0xff, 0, 6, 0x12, 0x34, 0x56, 0x78, // Atomic Fragment with nonzero reserved fields.
			1, 2, 3, 4,
		},
	}
	wire, err := packet.AppendBinary(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[44:48], []byte{0, 0, 0, 0}) || wire[73] != 0 || binary.BigEndian.Uint16(wire[74:76]) != 0 {
		t.Fatalf("generated padding and Fragment reserved fields were not cleared: %x", wire[40:80])
	}
	if binary.BigEndian.Uint16(wire[50:52]) != 0xaabb || wire[67] != 0xcc {
		t.Fatalf("integrity-protected extension fields were changed: %x", wire[40:80])
	}

	// Parsing remains receiver-tolerant and exposes the original wire bytes.
	raw := append([]byte(nil), wire...)
	copy(raw[44:48], []byte{0xaa, 0xbb, 0xcc, 0xdd})
	binary.BigEndian.PutUint16(raw[50:52], 0xddee)
	raw[67] = 0xee
	raw[73] = 0xff
	binary.BigEndian.PutUint16(raw[74:76], 6)
	parsed, err := ParseIPPacket(raw)
	if err != nil {
		t.Fatalf("parse nonzero reserved fields: %v", err)
	}
	if !bytes.Equal(parsed.Payload, raw[40:]) {
		t.Fatal("ParseIPPacket did not preserve received extension bytes")
	}
	headers, protocol, payload, err := parsed.IPv6ExtensionHeaders()
	if err != nil || len(headers) != 4 || protocol != 99 || !bytes.Equal(payload, []byte{1, 2, 3, 4}) ||
		!bytes.Equal(headers[0].Data[3:], []byte{0xaa, 0xbb, 0xcc, 0xdd}) ||
		binary.BigEndian.Uint16(headers[1].Data[1:3]) != 0xddee || headers[2].Data[2] != 0xee ||
		headers[3].Data[0] != 0xff || binary.BigEndian.Uint16(headers[3].Data[1:3]) != 6 {
		t.Fatalf("structured extension fields did not preserve received bytes: headers=%+v protocol=%d payload=%x error=%v", headers, protocol, payload, err)
	}
	want := append([]byte(nil), raw...)
	copy(want[44:48], []byte{0, 0, 0, 0})
	want[73] = 0
	binary.BigEndian.PutUint16(want[74:76], 0)
	reencoded, err := parsed.AppendBinary(nil)
	if err != nil || !bytes.Equal(reencoded, want) {
		t.Fatalf("normalized IPv6 packet: error=%v\n got %x\nwant %x", err, reencoded, want)
	}
}

// TestIPv6MappedAddressesAreRejected verifies the RFC 6890 on-wire boundary
// and prevents a parsed IPv6 packet from being re-encoded as IPv4.
func TestIPv6MappedAddressesAreRejected(t *testing.T) {
	packet := make([]byte, 40)
	packet[0], packet[6], packet[7] = 0x60, 59, 64
	source := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	destination := netip.MustParseAddr("2001:db8::1").As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	if _, err := ParseIPPacket(packet); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("mapped IPv6 ParseIPPacket error = %v", err)
	}
	if _, ok := parseIPPacket(packet); ok {
		t.Fatal("internal parser accepted a mapped IPv6 source")
	}
}

func TestPublicIPPacketCodecErrorsDoNotModifyDestination(t *testing.T) {
	valid := IPPacket{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Protocol: 99, HopLimit: 64, Payload: []byte{1}}
	invalid := valid
	invalid.HopLimit = 256
	destination := []byte{1, 2, 3}
	want := append([]byte(nil), destination...)
	if got, err := invalid.AppendBinary(destination); !errors.Is(err, syscall.EINVAL) || !bytes.Equal(got, want) || !bytes.Equal(destination, want) {
		t.Fatalf("invalid AppendBinary: got=%x error=%v", got, err)
	}
	if _, err := ParseIPPacket([]byte{0x40}); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("truncated ParseIPPacket error = %v", err)
	}
	invalid = valid
	invalid.Source = netip.MustParseAddr("2001:db8::1").WithZone("test")
	invalid.Destination = netip.MustParseAddr("2001:db8::2")
	if _, err := invalid.AppendBinary(nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zoned IP packet error = %v", err)
	}
}

func TestPublicChecksumAPI(t *testing.T) {
	payload := []byte("public-checksum")
	if got, want := InternetChecksum(payload), checksum(payload); got != want {
		t.Fatalf("InternetChecksum = %#x, want %#x", got, want)
	}
	source, destination := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	got, err := IPTransportChecksum(source, destination, ProtocolUDP, payload)
	if err != nil || got != transportChecksum(source, destination, ProtocolUDP, payload) {
		t.Fatalf("IPTransportChecksum = %#x, %v", got, err)
	}
	if _, err = IPTransportChecksum(source, netip.MustParseAddr("192.0.2.1"), ProtocolUDP, payload); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("cross-family checksum error = %v", err)
	}
	mappedSource := netip.MustParseAddr("::ffff:192.0.2.1")
	mappedDestination := netip.MustParseAddr("::ffff:198.51.100.1")
	mapped, err := IPTransportChecksum(mappedSource, mappedDestination, ProtocolUDP, payload)
	if want := transportChecksum(mappedSource.Unmap(), mappedDestination.Unmap(), ProtocolUDP, payload); err != nil || mapped != want {
		t.Fatalf("mapped IPv4 checksum = %#x, %v; want %#x", mapped, err, want)
	}
	for _, protocol := range []int{-1, 256} {
		if _, err = IPTransportChecksum(source, destination, protocol, payload); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("protocol %d checksum error = %v", protocol, err)
		}
	}
	if _, err = IPTransportChecksum(source.WithZone("test"), destination, ProtocolUDP, payload); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("zoned checksum error = %v", err)
	}
	if _, err = IPTransportChecksum(source, destination, ProtocolUDP, make([]byte, 65536)); !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("oversized checksum error = %v", err)
	}
}

func FuzzPublicIPPacketCodec(f *testing.F) {
	seeds := []IPPacket{
		{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.2"), Protocol: 99, HopLimit: 64, Payload: []byte("v4")},
		{Source: netip.MustParseAddr("2001:db8::1"), Destination: netip.MustParseAddr("2001:db8::2"), Protocol: 99, HopLimit: 64, Payload: []byte("v6")},
	}
	for _, seed := range seeds {
		wire, err := seed.AppendBinary(nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		original := append([]byte(nil), wire...)
		packet, err := ParseIPPacket(wire)
		if !bytes.Equal(wire, original) {
			t.Fatal("ParseIPPacket modified its input")
		}
		if err != nil {
			return
		}
		structured := packet
		if packet.Source.Is4() {
			options, optionsErr := packet.IPv4HeaderOptions()
			if optionsErr != nil {
				t.Fatalf("parsed IPv4 options could not be inspected: %v", optionsErr)
			}
			if optionsErr = structured.SetIPv4HeaderOptions(options); optionsErr != nil {
				t.Fatalf("parsed IPv4 options could not be rebuilt: %v", optionsErr)
			}
		} else {
			headers, protocol, payload, headersErr := packet.IPv6ExtensionHeaders()
			if headersErr != nil {
				t.Fatalf("parsed IPv6 headers could not be inspected: %v", headersErr)
			}
			if headersErr = structured.SetIPv6ExtensionHeaders(headers, protocol, payload); headersErr != nil {
				t.Fatalf("parsed IPv6 headers could not be rebuilt: %v", headersErr)
			}
		}
		if _, err = structured.AppendBinary(nil); err != nil {
			t.Fatalf("structured packet could not be encoded: %v", err)
		}
		encoded, err := packet.AppendBinary(nil)
		if err != nil {
			t.Fatalf("parsed packet could not be encoded: %v", err)
		}
		if _, err = ParseIPPacket(encoded); err != nil {
			t.Fatalf("encoded packet could not be parsed: %v", err)
		}
		canonical := append([]byte(nil), encoded...)
		reparsed, err := ParseIPPacket(encoded)
		if err != nil {
			t.Fatal(err)
		}
		inPlace, err := reparsed.AppendBinary(encoded[:0])
		if err != nil || !bytes.Equal(inPlace, canonical) {
			t.Fatalf("in-place packet append: error=%v\n got %x\nwant %x", err, inPlace, canonical)
		}
	})
}

func FuzzPublicIPv4HeaderOptions(f *testing.F) {
	f.Add([]byte{IPv4HeaderOptionNOP, IPv4HeaderOptionRouterAlert, 4, 0, 0, IPv4HeaderOptionEnd, 0, 0})
	f.Add([]byte{30, 4, 1, 2})
	f.Fuzz(func(t *testing.T, wire []byte) {
		packet := IPPacket{
			Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"),
			IPv4Options: wire,
		}
		before := append([]byte(nil), wire...)
		options, err := packet.IPv4HeaderOptions()
		if !bytes.Equal(wire, before) {
			t.Fatal("IPv4HeaderOptions modified its input")
		}
		if err != nil {
			return
		}
		var rebuilt = packet
		rebuilt.IPv4Options = nil
		if err = rebuilt.SetIPv4HeaderOptions(options); err != nil {
			t.Fatalf("parsed IPv4 options could not be rebuilt: %v", err)
		}
		canonical := append([]byte(nil), rebuilt.IPv4Options...)
		for index := range wire {
			wire[index] ^= 0xff
		}
		if !bytes.Equal(rebuilt.IPv4Options, canonical) {
			t.Fatal("SetIPv4HeaderOptions retained parsed input")
		}
		if _, err = rebuilt.IPv4HeaderOptions(); err != nil {
			t.Fatalf("rebuilt IPv4 options could not be parsed: %v", err)
		}
	})
}

func FuzzPublicIPv6ExtensionOptions(f *testing.F) {
	f.Add(true, []byte{0, IPv6ExtensionOptionRouterAlert, 2, 0, 0, IPv6ExtensionOptionPadN, 0})
	f.Add(false, []byte{0, 0xe3, 3, 1, 2, 3, IPv6ExtensionOptionPad1})
	f.Fuzz(func(t *testing.T, hopByHop bool, data []byte) {
		headerType := uint8(IPv6ExtensionHeaderDestination)
		if hopByHop {
			headerType = IPv6ExtensionHeaderHopByHop
		}
		header := IPv6ExtensionHeader{Type: headerType, Data: data}
		before := append([]byte(nil), data...)
		options, err := header.Options()
		if !bytes.Equal(data, before) {
			t.Fatal("IPv6 Options modified its input")
		}
		if err != nil {
			return
		}
		for _, option := range options {
			_ = option.Action()
			_ = option.MayChangeInTransit()
		}
		rebuilt := IPv6ExtensionHeader{Type: headerType}
		if err = rebuilt.SetOptions(options); err != nil {
			t.Fatalf("parsed IPv6 options could not be rebuilt: %v", err)
		}
		canonical := append([]byte(nil), rebuilt.Data...)
		for index := range data {
			data[index] ^= 0xff
		}
		if !bytes.Equal(rebuilt.Data, canonical) {
			t.Fatal("SetOptions retained parsed input")
		}
		if _, err = rebuilt.Options(); err != nil {
			t.Fatalf("rebuilt IPv6 options could not be parsed: %v", err)
		}
	})
}

// FuzzChecksumParts verifies the Internet checksum and both pseudo-header
// variants across every odd or even split between adjacent payload regions.
func FuzzChecksumParts(f *testing.F) {
	f.Add([]byte(nil), uint16(0), false, byte(ProtocolUDP))
	f.Add([]byte{1}, uint16(1), false, byte(ProtocolTCP))
	f.Add([]byte{1, 2, 3, 4, 5}, uint16(3), true, byte(ProtocolICMPv6))
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
	valid := []byte{ProtocolICMPv6, 0, 5, 2, 0, 0, 1, 0}
	if !ipv6RouterAlert(valid) {
		t.Fatal("valid IPv6 Router Alert was rejected")
	}
	malformed := []byte{ProtocolICMPv6, 0, 5, 1, 0, 1, 1, 0}
	if ipv6RouterAlert(malformed) {
		t.Fatal("malformed IPv6 Router Alert was accepted")
	}
	duplicate := []byte{ProtocolICMPv6, 1, 5, 2, 0, 0, 5, 2, 0, 0, 1, 4, 0, 0, 0, 0}
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
		{name: "nonzero-eol-padding", options: []byte{148, 4, 0, 0, 0, 1, 0, 0}, valid: true},
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
	f.Add(buildIPPacket(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), ProtocolUDP, make([]byte, 8), 1, false))
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
	f.Add([]byte("tcp"), false, byte(1), uint16(49153), uint16(80), byte(TCPFlagSYN))
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
				flags = TCPFlagACK
			}
			options := []byte(nil)
			if flags&TCPFlagSYN != 0 {
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
				binary.BigEndian.PutUint16(message[2:4], transportChecksum(remote, local, ProtocolICMPv6, message))
				packet = buildIPPacket(remote, local, ProtocolICMPv6, message, 1, true)
			} else {
				binary.BigEndian.PutUint16(message[2:4], checksum(message))
				packet = buildIPPacket(remote, local, ProtocolICMPv4, message, 1, true)
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
	f.Add(buildIPPacket(remote4, local4, ProtocolUDP, make([]byte, udpHeaderSize), 1, false))
	f.Add(buildTestIPv4Options(remote4, local4, []byte{1, 1, 0, 0}))
	f.Add(buildIPPacket(remote6, local6, ProtocolTCP, make([]byte, tcpHeaderSize), 0, true))
	f.Add(buildTestIPv6Extension(remote6, local6, 60, []byte{ProtocolUDP, 0, 1, 0, 0, 0, 0, 0}))
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
	f.Add([]byte{0, 1, 2, 3})
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
		if !ok || parsed.parameterError || parsed.protocol != ProtocolUDP || len(parsed.payload) != udpHeaderSize || parsed.hasRouterAlert() != ipv4RouterAlert(options) {
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
		header[0] = ProtocolUDP
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
		if !ok || parsed.parameterError || parsed.protocol != ProtocolUDP || len(parsed.payload) != 0 {
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
	packet := buildIPPacketWithOptions(source, target, ProtocolUDP, make([]byte, udpHeaderSize), 0, true, ipPacketOptions{
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
	fragments, err := stack.ipPayloadPackets(source, target, ProtocolUDP, make([]byte, 2000), true)
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
	for _, options := range [][]byte{{7, 1, 0, 0}, {30, 1, 0, 0}} {
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
	if _, ok := parseIPPacket(buildTestIPv6Extension(remote6, local6, 60, []byte{ProtocolUDP, 0, 0x40, 0, 0, 0, 0, 0})); ok {
		t.Fatal("IPv6 discard-action option was accepted")
	}
	routingError, ok := parseIPPacket(buildTestIPv6Extension(remote6, local6, 43, []byte{ProtocolUDP, 0, 99, 1, 0, 0, 0, 0}))
	if !ok || !routingError.parameterError || routingError.parameterCode != 0 || routingError.parameterAt != 42 {
		t.Fatalf("active IPv6 routing header = %+v, parsed = %v", routingError, ok)
	}
	misplacedHopPayload := append([]byte{0, 0, 0, 0, 0, 0, 0, 0}, ProtocolUDP, 0, 0, 0, 0, 0, 0, 0)
	misplacedHop := buildIPPacket(remote6, local6, 60, misplacedHopPayload, 0, false)
	misplacedHopError, ok := parseIPPacket(misplacedHop)
	if !ok || !misplacedHopError.parameterError || misplacedHopError.parameterCode != 1 || misplacedHopError.parameterAt != 40 {
		t.Fatalf("misplaced IPv6 Hop-by-Hop header = %+v, parsed = %v", misplacedHopError, ok)
	}
	paddedEmptyPacket := buildIPPacket(remote6, local6, ProtocolUDP, []byte{1}, 0, true)
	paddedEmptyPacket[4], paddedEmptyPacket[5] = 0, 0
	parsedEmptyPacket, ok := parseIPPacket(paddedEmptyPacket)
	if !ok || len(parsedEmptyPacket.payload) != 0 || len(parsedEmptyPacket.original) != 40 {
		t.Fatalf("zero-length IPv6 payload with link padding = %+v, parsed=%t", parsedEmptyPacket, ok)
	}
	// A real jumbogram starts with a Hop-by-Hop Jumbo Payload option. The
	// declared zero length cannot expose that unsupported header to this stack.
	jumbogram := buildIPPacket(remote6, local6, 0, []byte{ProtocolUDP, 0, 0xc2, 4, 0, 1, 0, 0}, 0, true)
	jumbogram[4], jumbogram[5] = 0, 0
	if _, ok = parseIPPacket(jumbogram); ok {
		t.Fatal("unsupported IPv6 jumbogram was accepted")
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
	unsupportedOption := buildTestIPv6Extension(remote6, local6, 60, []byte{ProtocolUDP, 0, 0x80, 0, 0, 0, 0, 0})
	if err = writeTestPacket(stack, unsupportedOption); err != nil {
		t.Fatal(err)
	}
	response := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 2 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 unsupported-option response = %x", response)
	}
	malformedIPv4 := buildTestIPv4Options(remote4, local4, []byte{7, 1, 0, 0})
	if err = writeTestPacket(stack, malformedIPv4); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv4 || len(parsed.payload) < 8 || parsed.payload[0] != 12 || parsed.payload[1] != 0 || parsed.payload[4] != 20 {
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
	activeRouting := buildTestIPv6Extension(remote6, local6, 43, []byte{ProtocolUDP, 0, 99, 1, 0, 0, 0, 0})
	if err = writeTestPacket(stack, activeRouting); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 0 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 42 {
		t.Fatalf("IPv6 routing-header response = %x", response)
	}
	if err = writeTestPacket(stack, misplacedHop); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 40 {
		t.Fatalf("misplaced IPv6 Hop-by-Hop response = %x", response)
	}
	icmpErrorWithUnknownOption := buildTestIPv6Extension(remote6, local6, 60, []byte{ProtocolICMPv6, 0, 0x80, 0, 0, 0, 0, 0})
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
	if !ok || parsed.protocol != ProtocolICMPv4 || len(parsed.payload) < 8 || parsed.payload[0] != 3 || parsed.payload[1] != 2 {
		t.Fatalf("IPv4 unsupported-protocol response = %x", response)
	}
	if err = writeTestPacket(stack, buildIPPacket(remote6, local6, 100, []byte{1, 2, 3, 4}, 0, true)); err != nil {
		t.Fatal(err)
	}
	response = readOutboundPacket(t, stack)
	parsed, ok = parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 || binary.BigEndian.Uint32(parsed.payload[4:8]) != 6 {
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
	payload = append(payload, ProtocolUDP, 0, 0, 0, 0, 0, 0, 2)
	payload = append(payload, 1, 2, 3, 4, 5, 6, 7, 8)
	parsed, ok := parseIPPacket(buildIPPacket(remote, local, 60, payload, 0, false))
	if !ok || parsed.protocol != ProtocolUDP || len(parsed.payload) != 8 {
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
	if err := writeTestPacket(stack, buildIPPacket(remote, local, ProtocolICMPv4, echo, 0, true)); err != nil {
		t.Fatal(err)
	}
	var response []byte
	select {
	case response = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cross-family protocol error")
	}
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolICMPv6 || len(parsed.payload) < 8 || parsed.payload[0] != 4 || parsed.payload[1] != 1 {
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
				if _, err := ParseIPPacket(test.packet); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkStackPacketParsing(b *testing.B) {
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
