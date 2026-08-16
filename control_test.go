package mipstack

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
)

var _ encoding.BinaryMarshaler = SocketErrorControlMessage{}

func TestSocketErrorControlMessageMarshalBinary(t *testing.T) {
	tests := []struct {
		name      string
		message   SocketErrorControlMessage
		wantSize  int
		wantLevel uint32
		wantKind  uint32
	}{
		{
			name: "IPv4",
			message: SocketErrorControlMessage{
				Errno: 111, Origin: SocketErrorOriginICMP, Type: 3, Code: 3,
				Info: 0x10203040, Data: 0x50607080, Offender: netip.MustParseAddr("198.51.100.1"),
			},
			wantSize: 48, wantLevel: linuxLevelIP, wantKind: linuxIPReceiveError,
		},
		{
			name: "IPv4-mapped",
			message: SocketErrorControlMessage{
				Origin: 255, Type: 254, Code: 253, Offender: netip.MustParseAddr("::ffff:192.0.2.1"),
			},
			wantSize: 64, wantLevel: linuxLevelIPv6, wantKind: linuxIPv6ReceiveError,
		},
		{
			name: "IPv6",
			message: SocketErrorControlMessage{
				Errno: 90, Origin: SocketErrorOriginICMP6, Type: 2, Code: 1,
				Info: 1280, Data: 0xfedcba98, Offender: netip.MustParseAddr("2001:db8::1"),
			},
			wantSize: 64, wantLevel: linuxLevelIPv6, wantKind: linuxIPv6ReceiveError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control, err := test.message.MarshalBinary()
			if err != nil || len(control) != test.wantSize {
				t.Fatalf("MarshalBinary = %d bytes, %v, want %d", len(control), err, test.wantSize)
			}
			appended, err := test.message.AppendBinary([]byte{0xaa, 0xbb, 0xcc})
			if err != nil || !bytes.Equal(appended[:3], []byte{0xaa, 0xbb, 0xcc}) || !bytes.Equal(appended[3:], control) {
				t.Fatalf("AppendBinary = %x, %v, want prefix and %x", appended, err, control)
			}
			length := int(binary.LittleEndian.Uint64(control[:8]))
			if binary.LittleEndian.Uint32(control[8:12]) != test.wantLevel || binary.LittleEndian.Uint32(control[12:16]) != test.wantKind {
				t.Fatalf("control header = length %d level %d kind %d", length, binary.LittleEndian.Uint32(control[8:12]), binary.LittleEndian.Uint32(control[12:16]))
			}
			wantLength := 48
			if test.wantLevel == linuxLevelIPv6 {
				wantLength = 60
			}
			if length != wantLength {
				t.Fatalf("control length = %d, want %d", length, wantLength)
			}
			data := control[linuxControlHeaderSize:length]
			if binary.LittleEndian.Uint32(data[:4]) != test.message.Errno || data[4] != byte(test.message.Origin) ||
				data[5] != test.message.Type || data[6] != test.message.Code || data[7] != 0 ||
				binary.LittleEndian.Uint32(data[8:12]) != test.message.Info || binary.LittleEndian.Uint32(data[12:16]) != test.message.Data {
				t.Fatalf("sock_extended_err = %x", data[:16])
			}
			if test.wantLevel == linuxLevelIP {
				if binary.LittleEndian.Uint16(data[16:18]) != 2 || !bytes.Equal(data[18:20], []byte{0, 0}) ||
					netip.AddrFrom4([4]byte(data[20:24])) != test.message.Offender || !bytes.Equal(data[24:32], make([]byte, 8)) {
					t.Fatalf("IPv4 offender sockaddr = %x", data[16:])
				}
			} else if binary.LittleEndian.Uint16(data[16:18]) != 10 || !bytes.Equal(data[18:24], make([]byte, 6)) ||
				netip.AddrFrom16([16]byte(data[24:40])) != test.message.Offender || !bytes.Equal(data[40:44], make([]byte, 4)) ||
				!bytes.Equal(control[length:], make([]byte, test.wantSize-length)) {
				t.Fatalf("IPv6 offender sockaddr or alignment = %x / %x", data[16:], control[length:])
			}
			var parsed SocketErrorControlMessage
			if err = parsed.Parse(control); err != nil || parsed != test.message {
				t.Fatalf("Parse(MarshalBinary) = %+v, %v, want %+v", parsed, err, test.message)
			}
			compound := appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTimeToLive, 64)
			compound, err = test.message.AppendBinary(compound)
			if err != nil {
				t.Fatal(err)
			}
			if err = parsed.Parse(compound); err != nil || parsed != test.message {
				t.Fatalf("Parse(compound AppendBinary) = %+v, %v, want %+v", parsed, err, test.message)
			}
		})
	}

	invalid := []SocketErrorControlMessage{
		{},
		{Offender: netip.MustParseAddr("fe80::1%ethernet")},
	}
	for _, message := range invalid {
		storage := bytes.Repeat([]byte{0xa5}, 128)
		dst := storage[:3]
		before := append([]byte(nil), storage...)
		got, err := message.AppendBinary(dst)
		if err == nil || len(got) != len(dst) || &got[0] != &dst[0] || !bytes.Equal(storage, before) {
			t.Fatalf("invalid AppendBinary = %x, %v; storage changed=%v", got, err, !bytes.Equal(storage, before))
		}
	}
}

func TestSocketErrorControlMessageLinuxFixtures(t *testing.T) {
	tests := []struct {
		name    string
		wire    string
		message SocketErrorControlMessage
	}{
		{
			name: "IPv4 port unreachable",
			wire: "3000000000000000000000000b000000" +
				"6f000000020303000000000000000000" +
				"020000007f0000010000000000000000",
			message: SocketErrorControlMessage{
				Errno: 111, Origin: SocketErrorOriginICMP, Type: 3, Code: 3,
				Offender: netip.MustParseAddr("127.0.0.1"),
			},
		},
		{
			name: "IPv6 port unreachable",
			wire: "3c000000000000002900000019000000" +
				"6f000000030104000000000000000000" +
				"0a000000000000000000000000000000000000000000000100000000" +
				"00000000",
			message: SocketErrorControlMessage{
				Errno: 111, Origin: SocketErrorOriginICMP6, Type: 1, Code: 4,
				Offender: netip.MustParseAddr("::1"),
			},
		},
		{
			name: "IPv4-mapped port unreachable on IPv6 socket",
			wire: "3c000000000000002900000019000000" +
				"6f000000020303000000000000000000" +
				"0a0000000000000000000000000000000000ffff7f00000100000000" +
				"00000000",
			message: SocketErrorControlMessage{
				Errno: 111, Origin: SocketErrorOriginICMP, Type: 3, Code: 3,
				Offender: netip.MustParseAddr("::ffff:127.0.0.1"),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire, err := hex.DecodeString(test.wire)
			if err != nil {
				t.Fatal(err)
			}
			var message SocketErrorControlMessage
			if err = message.Parse(wire); err != nil || message != test.message {
				t.Fatalf("Parse(Linux fixture) = %+v, %v, want %+v", message, err, test.message)
			}
			encoded, err := test.message.MarshalBinary()
			if err != nil || !bytes.Equal(encoded, wire) {
				t.Fatalf("MarshalBinary = %x, %v, want Linux fixture %x", encoded, err, wire)
			}
		})
	}

	unknownOffender, err := hex.DecodeString(
		"3000000000000000000000000b000000" +
			"5a000000010000000005000000000000" +
			"00000000000000000000000000000000",
	)
	if err != nil {
		t.Fatal(err)
	}
	initial := SocketErrorControlMessage{Errno: 1, Offender: netip.MustParseAddr("192.0.2.1")}
	message := initial
	if err = message.Parse(unknownOffender); err == nil || message != initial {
		t.Fatalf("Parse(AF_UNSPEC Linux fixture) = %+v, %v; want unchanged receiver and error", message, err)
	}
}

func TestSocketErrorControlMessageForRead(t *testing.T) {
	tests := []struct {
		name    string
		input   ICMPError
		want    SocketErrorControlMessage
		control int
	}{
		{
			name:  "IPv4 network administratively prohibited",
			input: ICMPError{Reporter: netip.MustParseAddr("198.51.100.1"), Type: 3, Code: 9},
			want: SocketErrorControlMessage{
				Errno: 101, Origin: SocketErrorOriginICMP, Type: 3, Code: 9,
				Offender: netip.MustParseAddr("198.51.100.1"),
			},
			control: 48,
		},
		{
			name:  "IPv6 packet too big",
			input: ICMPError{Reporter: netip.MustParseAddr("2001:db8::1"), Type: 2, MTU: 1280},
			want: SocketErrorControlMessage{
				Errno: 90, Origin: SocketErrorOriginICMP6, Type: 2, Info: 1280,
				Offender: netip.MustParseAddr("2001:db8::1"),
			},
			control: 64,
		},
		{
			name:  "IPv6 parameter problem",
			input: ICMPError{Reporter: netip.MustParseAddr("2001:db8::2"), Type: 4, Code: 1, Pointer: 48},
			want: SocketErrorControlMessage{
				Errno: 71, Origin: SocketErrorOriginICMP6, Type: 4, Code: 1, Info: 48,
				Offender: netip.MustParseAddr("2001:db8::2"),
			},
			control: 64,
		},
		{
			name:  "IPv4-mapped network administratively prohibited",
			input: ICMPError{Reporter: netip.MustParseAddr("::ffff:198.51.100.1"), Type: 3, Code: 9},
			want: SocketErrorControlMessage{
				Errno: 101, Origin: SocketErrorOriginICMP, Type: 3, Code: 9,
				Offender: netip.MustParseAddr("::ffff:198.51.100.1"),
			},
			control: 64,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control, err := socketErrorControlForRead(test.input)
			if err != nil || len(control) != test.control {
				t.Fatalf("socket error control = %d bytes, %v, want %d", len(control), err, test.control)
			}
			var message SocketErrorControlMessage
			if err = message.Parse(control); err != nil || message != test.want {
				t.Fatalf("parsed socket error = %+v, %v, want %+v", message, err, test.want)
			}
			packetInfo := appendLinuxPacketInfoControl(nil, test.input.Reporter)
			packetInfo = append(packetInfo, control...)
			if err = message.Parse(packetInfo); err != nil || message != test.want {
				t.Fatalf("socket error with packet info = %+v, %v", message, err)
			}
			if err = message.Parse(append(control, control...)); err == nil {
				t.Fatal("duplicate socket error control message parsed successfully")
			}
			if err = message.Parse(control[:len(control)-1]); err == nil {
				t.Fatal("truncated socket error control message parsed successfully")
			}
		})
	}
	var message *SocketErrorControlMessage
	if err := message.Parse(nil); err == nil {
		t.Fatal("nil socket error control receiver parsed successfully")
	}
	if _, err := socketErrorControlForRead(ICMPError{Type: 3, Code: 3}); err == nil {
		t.Fatal("socket error without reporter marshaled successfully")
	}
}

func TestIPv4ControlMessageMarshalAndParse(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.123")
	outgoing := &IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: source}
	control, err := outgoing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsedSource, options, err := parseControlMessageForWrite(control, false)
	if err != nil || parsedSource != source || options != (ipPacketOptions{hopLimit: 31, trafficClass: 0xb8, hopLimitSet: true, trafficClassSet: true}) {
		t.Fatalf("marshaled IPv4 control = source %v options %+v, %v", parsedSource, options, err)
	}
	var incoming IPv4ControlMessage
	receivedControl, err := controlMessageForRead(source, options)
	if err != nil {
		t.Fatal(err)
	}
	if err = incoming.Parse(receivedControl); err != nil {
		t.Fatal(err)
	}
	if incoming != (IPv4ControlMessage{TTL: 31, TOS: 0xb8, Dst: source}) {
		t.Fatalf("parsed IPv4 control = %+v", incoming)
	}
	if control, err = (*IPv4ControlMessage)(nil).Marshal(); err != nil || control != nil {
		t.Fatalf("nil IPv4 control marshal = %x, %v", control, err)
	}
}

func TestIPv6ControlMessageMarshalAndParse(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::123")
	outgoing := &IPv6ControlMessage{TrafficClass: 0x2e, HopLimit: 29, FlowLabel: 0xabcde, Src: source}
	control, err := outgoing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsedSource, options, err := parseControlMessageForWrite(control, true)
	if err != nil || parsedSource != source || options != (ipPacketOptions{hopLimit: 29, trafficClass: 0x2e, flowLabel: 0xabcde, hopLimitSet: true, trafficClassSet: true, flowLabelSet: true}) {
		t.Fatalf("marshaled IPv6 control = source %v options %+v, %v", parsedSource, options, err)
	}
	var incoming IPv6ControlMessage
	receivedControl, err := controlMessageForRead(source, options)
	if err != nil {
		t.Fatal(err)
	}
	if err = incoming.Parse(receivedControl); err != nil {
		t.Fatal(err)
	}
	if incoming != (IPv6ControlMessage{TrafficClass: 0x2e, HopLimit: 29, FlowLabel: 0xabcde, Dst: source}) {
		t.Fatalf("parsed IPv6 control = %+v", incoming)
	}
	if control, err = (*IPv6ControlMessage)(nil).Marshal(); err != nil || control != nil {
		t.Fatalf("nil IPv6 control marshal = %x, %v", control, err)
	}
}

func TestIPv6ZeroFlowInfoIsOmittedOnRead(t *testing.T) {
	control, err := (&IPv6ControlMessage{HopLimit: 64, Dst: netip.MustParseAddr("2001:db8::124")}).marshalForRead()
	if err != nil {
		t.Fatal(err)
	}
	for remaining := control; len(remaining) != 0; {
		length := int(binary.LittleEndian.Uint64(remaining[:8]))
		if binary.LittleEndian.Uint32(remaining[8:12]) == linuxLevelIPv6 &&
			binary.LittleEndian.Uint32(remaining[12:16]) == linuxIPv6FlowInfo {
			t.Fatal("zero IPv6 flow info was emitted on receive")
		}
		aligned := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
		remaining = remaining[aligned:]
	}
}

func TestControlMessageValidation(t *testing.T) {
	invalid := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{name: "IPv4 interface", marshal: func() ([]byte, error) { return (&IPv4ControlMessage{IfIndex: 1}).Marshal() }},
		{name: "IPv4 source", marshal: func() ([]byte, error) { return (&IPv4ControlMessage{Src: netip.IPv6Unspecified()}).Marshal() }},
		{name: "IPv4 TTL", marshal: func() ([]byte, error) { return (&IPv4ControlMessage{TTL: 256}).Marshal() }},
		{name: "IPv4 TOS", marshal: func() ([]byte, error) { return (&IPv4ControlMessage{TOS: -1}).Marshal() }},
		{name: "IPv6 interface", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{IfIndex: 1}).Marshal() }},
		{name: "IPv6 source", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{Src: netip.IPv4Unspecified()}).Marshal() }},
		{name: "IPv6 hop limit", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{HopLimit: 256}).Marshal() }},
		{name: "IPv6 traffic class", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{TrafficClass: -1}).Marshal() }},
		{name: "IPv6 flow label", marshal: func() ([]byte, error) { return (&IPv6ControlMessage{FlowLabel: ipv6MaximumFlowLabel + 1}).Marshal() }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.marshal(); err == nil {
				t.Fatal("invalid control message marshaled successfully")
			}
		})
	}
	var ipv4 *IPv4ControlMessage
	if err := ipv4.Parse(nil); err == nil {
		t.Fatal("nil IPv4 control receiver parsed successfully")
	}
	var ipv6 *IPv6ControlMessage
	if err := ipv6.Parse(nil); err == nil {
		t.Fatal("nil IPv6 control receiver parsed successfully")
	}
	for _, address := range []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	} {
		control, err := controlMessageForRead(address, ipPacketOptions{})
		if err != nil {
			t.Fatalf("controlMessageForRead(%v): %v", address, err)
		}
		parsedAddress, options, err := parseLinuxIPControlValues(control, address.Is6(), true)
		if err != nil || parsedAddress != address || options.hopLimit != 0 {
			t.Fatalf("zero-hop control for %v = %v, %+v, %v", address, parsedAddress, options, err)
		}
	}
	zeroHopLimit := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6HopLimit, 0)
	_, options, err := parseLinuxIPControlValues(zeroHopLimit, true, false)
	if err != nil || options.hopLimit != 0 || !options.hopLimitSet {
		t.Fatalf("IPv6 zero hop-limit control = %+v, %v", options, err)
	}
	zeroTTL := appendLinuxControlInt32(nil, linuxLevelIP, linuxIPTimeToLive, 0)
	if _, _, err = parseLinuxIPControlValues(zeroTTL, false, false); err == nil {
		t.Fatal("IPv4 zero TTL control message parsed successfully")
	}
	var zeroFlowInfo [4]byte
	zeroFlowControl := appendLinuxControl(nil, linuxLevelIPv6, linuxIPv6FlowInfo, zeroFlowInfo[:])
	_, options, err = parseLinuxIPControlValues(zeroFlowControl, true, false)
	if err != nil || options.flowLabel != 0 || !options.flowLabelSet {
		t.Fatalf("IPv6 explicit zero flow label = %+v, %v", options, err)
	}
	conflicting := appendLinuxControlInt32(nil, linuxLevelIPv6, linuxIPv6TrafficClass, 1)
	flowInfo := [4]byte{0x02, 0, 0, 1}
	conflicting = appendLinuxControl(conflicting, linuxLevelIPv6, linuxIPv6FlowInfo, flowInfo[:])
	if _, _, err = parseLinuxIPControlValues(conflicting, true, false); err == nil {
		t.Fatal("conflicting IPv6 flow-info traffic class parsed successfully")
	}
}

// FuzzControlMessageParsing keeps the public read semantics and internal write
// semantics on the same panic-free ancillary decoder.
func FuzzControlMessageParsing(f *testing.F) {
	control4, _ := (&IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: netip.MustParseAddr("192.0.2.1")}).Marshal()
	control6, _ := (&IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, FlowLabel: 0x12345, Src: netip.MustParseAddr("2001:db8::1")}).Marshal()
	error4, _ := socketErrorControlForRead(ICMPError{Reporter: netip.MustParseAddr("198.51.100.1"), Type: 3, Code: 1})
	error6, _ := socketErrorControlForRead(ICMPError{Reporter: netip.MustParseAddr("2001:db8::2"), Type: 2, MTU: 1280})
	f.Add([]byte(nil))
	f.Add(control4)
	f.Add(control6)
	f.Add(error4)
	f.Add(error6)
	f.Fuzz(func(t *testing.T, control []byte) {
		if len(control) > 4096 {
			control = control[:4096]
		}
		before := append([]byte(nil), control...)
		initial4 := IPv4ControlMessage{TTL: -1, TOS: 256, Src: netip.MustParseAddr("192.0.2.200"), Dst: netip.MustParseAddr("192.0.2.201"), IfIndex: 7}
		ipv4 := initial4
		if err := ipv4.Parse(control); err != nil {
			if ipv4 != initial4 {
				t.Fatal("failed IPv4 control parse modified its receiver")
			}
		} else {
			encoded, marshalErr := ipv4.marshalForRead()
			var repeated IPv4ControlMessage
			if marshalErr != nil || repeated.Parse(encoded) != nil || repeated != ipv4 {
				t.Fatalf("IPv4 control round trip = %+v, %v, want %+v", repeated, marshalErr, ipv4)
			}
		}
		_, _, _ = parseControlMessageForWrite(control, false)

		initial6 := IPv6ControlMessage{
			TrafficClass: -1, HopLimit: 256, FlowLabel: ipv6MaximumFlowLabel + 1,
			Src: netip.MustParseAddr("2001:db8::200"), Dst: netip.MustParseAddr("2001:db8::201"), IfIndex: 7,
		}
		ipv6 := initial6
		if err := ipv6.Parse(control); err != nil {
			if ipv6 != initial6 {
				t.Fatal("failed IPv6 control parse modified its receiver")
			}
		} else {
			encoded, marshalErr := ipv6.marshalForRead()
			var repeated IPv6ControlMessage
			if marshalErr != nil || repeated.Parse(encoded) != nil || repeated != ipv6 {
				t.Fatalf("IPv6 control round trip = %+v, %v, want %+v", repeated, marshalErr, ipv6)
			}
		}
		_, _, _ = parseControlMessageForWrite(control, true)

		initialError := SocketErrorControlMessage{
			Errno: 1, Origin: SocketErrorOriginLocal, Type: 2, Code: 3, Info: 4, Data: 5,
			Offender: netip.MustParseAddr("192.0.2.202"),
		}
		socketError := initialError
		if err := socketError.Parse(control); err != nil {
			if socketError != initialError {
				t.Fatal("failed socket-error control parse modified its receiver")
			}
		} else {
			if !socketError.Offender.Is4() && !socketError.Offender.Is6() {
				t.Fatalf("parsed invalid socket-error offender %v", socketError.Offender)
			}
			encoded, marshalErr := socketError.AppendBinary(nil)
			var repeated SocketErrorControlMessage
			if marshalErr != nil || repeated.Parse(encoded) != nil || repeated != socketError {
				t.Fatalf("socket-error control round trip = %+v, %v, want %+v", repeated, marshalErr, socketError)
			}
		}
		if !bytes.Equal(control, before) {
			t.Fatal("control-message parsing modified its input")
		}
	})
}

// FuzzSocketErrorControlMessageMarshalBinary verifies that every field value
// has a stable canonical record and that address-family selection preserves
// the offender address representation.
func FuzzSocketErrorControlMessageMarshalBinary(f *testing.F) {
	f.Add(false, []byte{192, 0, 2, 1}, uint32(111), uint8(SocketErrorOriginICMP), uint8(3), uint8(3), uint32(0), uint32(1))
	f.Add(true, netip.MustParseAddr("2001:db8::1").AsSlice(), uint32(90), uint8(SocketErrorOriginICMP6), uint8(2), uint8(0), uint32(1280), uint32(2))
	f.Fuzz(func(t *testing.T, v6 bool, address []byte, errno uint32, origin, messageType, code uint8, info, data uint32) {
		var offender netip.Addr
		if v6 {
			var value [16]byte
			copy(value[:], address)
			offender = netip.AddrFrom16(value)
		} else {
			var value [4]byte
			copy(value[:], address)
			offender = netip.AddrFrom4(value)
		}
		message := SocketErrorControlMessage{
			Errno: errno, Origin: SocketErrorOrigin(origin), Type: messageType,
			Code: code, Info: info, Data: data, Offender: offender,
		}
		prefix := []byte{0xaa, 0xbb}
		encoded, err := message.AppendBinary(prefix)
		if err != nil || !bytes.Equal(encoded[:len(prefix)], prefix) {
			t.Fatalf("AppendBinary = %x, %v", encoded, err)
		}
		marshaled, err := message.MarshalBinary()
		if err != nil || !bytes.Equal(encoded[len(prefix):], marshaled) {
			t.Fatalf("MarshalBinary = %x, %v, want %x", marshaled, err, encoded[len(prefix):])
		}
		var parsed SocketErrorControlMessage
		if err = parsed.Parse(marshaled); err != nil {
			t.Fatal(err)
		}
		if parsed != message {
			t.Fatalf("round trip = %+v, want %+v", parsed, message)
		}
	})
}

func BenchmarkControlMessageMarshal(b *testing.B) {
	address4 := netip.MustParseAddr("192.0.2.245")
	address6 := netip.MustParseAddr("2001:db8::245")
	socketError4 := SocketErrorControlMessage{
		Errno: 111, Origin: SocketErrorOriginICMP, Type: 3, Code: 3, Data: 1, Offender: address4,
	}
	socketError6 := SocketErrorControlMessage{
		Errno: 90, Origin: SocketErrorOriginICMP6, Type: 2, Info: 1280, Data: 1, Offender: address6,
	}
	reusedSocketErrorControl := make([]byte, 0, 64)
	benchmarks := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{name: "IPv4Send", marshal: (&IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: address4}).Marshal},
		{name: "IPv4Receive", marshal: func() ([]byte, error) {
			return controlMessageForRead(address4, ipPacketOptions{hopLimit: 31, trafficClass: 0xb8})
		}},
		{name: "IPv6Send", marshal: (&IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, FlowLabel: 0x12345, Src: address6}).Marshal},
		{name: "IPv6Receive", marshal: func() ([]byte, error) {
			return controlMessageForRead(address6, ipPacketOptions{hopLimit: 29, trafficClass: 0x2e, flowLabel: 0x12345})
		}},
		{name: "SocketErrorIPv4", marshal: socketError4.MarshalBinary},
		{name: "SocketErrorIPv6", marshal: socketError6.MarshalBinary},
		{name: "SocketErrorIPv6AppendReuse", marshal: func() ([]byte, error) {
			return socketError6.AppendBinary(reusedSocketErrorControl[:0])
		}},
		{name: "SocketErrorForRead", marshal: func() ([]byte, error) {
			return socketErrorControlForRead(ICMPError{Reporter: address6, Type: ICMPv6TypePacketTooBig, MTU: 1280})
		}},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for iteration := 0; iteration < b.N; iteration++ {
				control, err := benchmark.marshal()
				if err != nil || len(control) == 0 {
					b.Fatalf("Marshal = %d bytes, %v", len(control), err)
				}
			}
		})
	}
}
