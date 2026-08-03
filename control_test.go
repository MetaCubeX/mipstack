package mipstack

import (
	"net/netip"
	"testing"
)

func TestIPv4ControlMessageMarshalAndParse(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.123")
	outgoing := &IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: source}
	control, err := outgoing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsedSource, options, err := parseControlMessageForWrite(control, false)
	if err != nil || parsedSource != source || options != (ipPacketOptions{hopLimit: 31, trafficClass: 0xb8}) {
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
	outgoing := &IPv6ControlMessage{TrafficClass: 0x2e, HopLimit: 29, Src: source}
	control, err := outgoing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsedSource, options, err := parseControlMessageForWrite(control, true)
	if err != nil || parsedSource != source || options != (ipPacketOptions{hopLimit: 29, trafficClass: 0x2e}) {
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
	if incoming != (IPv6ControlMessage{TrafficClass: 0x2e, HopLimit: 29, Dst: source}) {
		t.Fatalf("parsed IPv6 control = %+v", incoming)
	}
	if control, err = (*IPv6ControlMessage)(nil).Marshal(); err != nil || control != nil {
		t.Fatalf("nil IPv6 control marshal = %x, %v", control, err)
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
}

// FuzzControlMessageParsing keeps the public read semantics and internal write
// semantics on the same panic-free ancillary decoder.
func FuzzControlMessageParsing(f *testing.F) {
	control4, _ := (&IPv4ControlMessage{TTL: 31, TOS: 0xb8, Src: netip.MustParseAddr("192.0.2.1")}).Marshal()
	control6, _ := (&IPv6ControlMessage{HopLimit: 29, TrafficClass: 0x2e, Src: netip.MustParseAddr("2001:db8::1")}).Marshal()
	f.Add([]byte(nil))
	f.Add(control4)
	f.Add(control6)
	f.Fuzz(func(t *testing.T, control []byte) {
		var ipv4 IPv4ControlMessage
		_ = ipv4.Parse(control)
		_, _, _ = parseControlMessageForWrite(control, false)
		var ipv6 IPv6ControlMessage
		_ = ipv6.Parse(control)
		_, _, _ = parseControlMessageForWrite(control, true)
	})
}
