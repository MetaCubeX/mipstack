package mipstack

import (
	"encoding/binary"
	"net/netip"
	"syscall"
)

const (
	// ProtocolICMPv4 is the IPv4 Internet Control Message Protocol number.
	ProtocolICMPv4 = 1
	// ProtocolIGMP is the Internet Group Management Protocol number.
	ProtocolIGMP = 2
	// ProtocolTCP is the Transmission Control Protocol number.
	ProtocolTCP = 6
	// ProtocolUDP is the User Datagram Protocol number.
	ProtocolUDP = 17
	// ProtocolESP is the Encapsulating Security Payload protocol number.
	ProtocolESP = 50
	// ProtocolICMPv6 is the IPv6 Internet Control Message Protocol number.
	ProtocolICMPv6 = 58
	// ProtocolNoNextHeader is the IPv6 No Next Header value.
	ProtocolNoNextHeader = 59

	// IPv4HeaderOptionEnd terminates the IPv4 option list.
	IPv4HeaderOptionEnd = 0
	// IPv4HeaderOptionNOP is the one-byte IPv4 No Operation option.
	IPv4HeaderOptionNOP = 1
	// IPv4HeaderOptionRecordRoute records routers traversed by a datagram.
	IPv4HeaderOptionRecordRoute = 7
	// IPv4HeaderOptionTimestamp records router timestamps and optional addresses.
	IPv4HeaderOptionTimestamp = 68
	// IPv4HeaderOptionLooseSourceRoute carries a loose source route.
	IPv4HeaderOptionLooseSourceRoute = 131
	// IPv4HeaderOptionStrictSourceRoute carries a strict source route.
	IPv4HeaderOptionStrictSourceRoute = 137
	// IPv4HeaderOptionRouterAlert requests examination by transit routers.
	IPv4HeaderOptionRouterAlert = 148

	// IPv6ExtensionHeaderHopByHop identifies a Hop-by-Hop Options header.
	IPv6ExtensionHeaderHopByHop = 0
	// IPv6ExtensionHeaderRouting identifies a Routing header.
	IPv6ExtensionHeaderRouting = 43
	// IPv6ExtensionHeaderFragment identifies a Fragment header.
	IPv6ExtensionHeaderFragment = 44
	// IPv6ExtensionHeaderAuthentication identifies an Authentication header.
	IPv6ExtensionHeaderAuthentication = 51
	// IPv6ExtensionHeaderDestination identifies a Destination Options header.
	IPv6ExtensionHeaderDestination = 60
	// IPv6ExtensionHeaderMobility identifies a Mobility header.
	IPv6ExtensionHeaderMobility = 135

	// IPv6ExtensionOptionPad1 is the one-byte IPv6 padding option.
	IPv6ExtensionOptionPad1 = 0
	// IPv6ExtensionOptionPadN is variable-length IPv6 padding.
	IPv6ExtensionOptionPadN = 1
	// IPv6ExtensionOptionRouterAlert requests examination by transit routers.
	IPv6ExtensionOptionRouterAlert = 5
	// IPv6ExtensionOptionJumboPayload carries an IPv6 jumbogram length.
	IPv6ExtensionOptionJumboPayload = 194
	// IPv6ExtensionOptionHomeAddress carries a Mobile IPv6 home address.
	IPv6ExtensionOptionHomeAddress = 201

	// ipv6MaximumFlowLabel is the 20-bit RFC 8200 Flow Label ceiling.
	ipv6MaximumFlowLabel = 1<<20 - 1
)

// IPPacket is the semantic representation of one complete, unfragmented IPv4
// or IPv6 packet. For IPv6, Protocol is the base header's immediate Next
// Header value and Payload includes any extension headers. ParseIPPacket
// borrows IPv4Options and Payload from its input; callers must replace or copy
// those slices before modifying data they do not own. Construction normalizes
// IPv4-mapped IPv6 addresses to IPv4.
type IPPacket struct {
	// Source is the packet's source address.
	Source netip.Addr
	// Destination is the packet's destination address.
	Destination netip.Addr
	// Protocol is the IPv4 Protocol or IPv6 base-header Next Header value.
	Protocol int
	// HopLimit is the IPv4 TTL or IPv6 Hop Limit, including an explicit zero.
	HopLimit int
	// TrafficClass is the complete IPv4 TOS or IPv6 Traffic Class byte.
	TrafficClass int
	// FlowLabel is the IPv6 Flow Label and must be zero for IPv4.
	FlowLabel uint32
	// Identification is the IPv4 Identification field and must be zero for IPv6.
	Identification uint16
	// DontFragment is the IPv4 Don't Fragment flag and must be false for IPv6.
	DontFragment bool
	// IPv4Options contains the exact IPv4 option area, including received padding.
	// Construction also accepts an unpadded option sequence; encoding adds final
	// alignment and normalizes every byte after End to zero.
	IPv4Options []byte
	// Payload is the complete IP payload. It includes IPv6 extension headers.
	Payload []byte
}

// IPv4HeaderOption is one IPv4 header option in semantic wire order. Data
// excludes the Type and Length bytes. End and NOP require empty Data; every
// other type is encoded with a Length byte. IPv4HeaderOptions returns Data
// slices that borrow IPPacket.IPv4Options, while SetIPv4HeaderOptions copies
// every Data slice.
type IPv4HeaderOption struct {
	// Type is the complete eight-bit IPv4 option type.
	Type uint8
	// Data is the option value following Type and Length.
	Data []byte
}

// IPv6ExtensionHeader is one structurally traversable IPv6 extension header.
// Type is the value naming the header in the preceding Next Header field. Data
// excludes this header's own Next Header byte but includes every remaining raw
// field, including its length byte when present. IPv6ExtensionHeaders returns
// Data slices that borrow IPPacket.Payload. Parsing preserves received PadN
// data and sender-reserved fields; IPPacket.MarshalBinary and
// IPPacket.AppendBinary clear PadN data and the reserved Fragment fields.
// Authentication and Mobility data remains opaque because changing it would
// invalidate the header's ICV or checksum.
type IPv6ExtensionHeader struct {
	// Type identifies the extension-header wire format.
	Type uint8
	// Data contains the raw header bytes following Next Header.
	Data []byte
}

// IPv6ExtensionOption is one option in a Hop-by-Hop or Destination Options
// header. Data excludes Option Type and Opt Data Len. Options returns Data
// slices that borrow IPv6ExtensionHeader.Data, while SetOptions copies them.
type IPv6ExtensionOption struct {
	// Type is the complete eight-bit IPv6 option type.
	Type uint8
	// Data is the option value following Type and Opt Data Len.
	Data []byte
}

// IPv4HeaderOptions parses the exact IPv4 option sequence. The returned slice
// owns its descriptors, but each Data field borrows IPv4Options. End is
// returned as the final descriptor; its following received padding is omitted.
func (p IPPacket) IPv4HeaderOptions() ([]IPv4HeaderOption, error) {
	if !p.Source.Unmap().Is4() || !p.Destination.Unmap().Is4() {
		return nil, syscall.EAFNOSUPPORT
	}
	if len(p.IPv4Options) > 40 {
		return nil, syscall.EMSGSIZE
	}
	var result []IPv4HeaderOption
	for offset := 0; offset < len(p.IPv4Options); {
		optionType := p.IPv4Options[offset]
		switch optionType {
		case IPv4HeaderOptionEnd:
			return append(result, IPv4HeaderOption{Type: optionType}), nil
		case IPv4HeaderOptionNOP:
			result = append(result, IPv4HeaderOption{Type: optionType})
			offset++
			continue
		}
		if len(p.IPv4Options)-offset < 2 {
			return nil, syscall.EINVAL
		}
		length := int(p.IPv4Options[offset+1])
		if length < 2 || length > len(p.IPv4Options)-offset {
			return nil, syscall.EINVAL
		}
		result = append(result, IPv4HeaderOption{Type: optionType, Data: p.IPv4Options[offset+2 : offset+length]})
		offset += length
	}
	return result, nil
}

// SetIPv4HeaderOptions replaces IPv4Options with the encoded option sequence.
// It preserves unknown types, duplicates, and order, copies every input Data
// slice, and leaves p unchanged on failure. End must be last. MarshalBinary or
// AppendBinary adds any final four-byte header alignment.
func (p *IPPacket) SetIPv4HeaderOptions(options []IPv4HeaderOption) error {
	if p == nil {
		return syscall.EINVAL
	}
	if !p.Source.Unmap().Is4() || !p.Destination.Unmap().Is4() {
		return syscall.EAFNOSUPPORT
	}
	size := 0
	ended := false
	for _, option := range options {
		if ended {
			return syscall.EINVAL
		}
		switch option.Type {
		case IPv4HeaderOptionEnd, IPv4HeaderOptionNOP:
			if len(option.Data) != 0 {
				return syscall.EINVAL
			}
			size++
			ended = option.Type == IPv4HeaderOptionEnd
		default:
			if len(option.Data) > 253 {
				return syscall.EINVAL
			}
			size += 2 + len(option.Data)
		}
		if size > 40 {
			return syscall.EMSGSIZE
		}
	}
	var encoded []byte
	if size != 0 {
		encoded = make([]byte, 0, size)
	}
	for _, option := range options {
		encoded = append(encoded, option.Type)
		if option.Type == IPv4HeaderOptionEnd || option.Type == IPv4HeaderOptionNOP {
			continue
		}
		encoded = append(encoded, byte(2+len(option.Data)))
		encoded = append(encoded, option.Data...)
	}
	p.IPv4Options = encoded
	return nil
}

// Copied reports the IPv4 option's copied flag, which requests copying into
// every fragment.
func (o IPv4HeaderOption) Copied() bool { return o.Type&0x80 != 0 }

// Class returns the IPv4 option's two-bit class field.
func (o IPv4HeaderOption) Class() uint8 { return o.Type >> 5 & 0x03 }

// Number returns the IPv4 option's five-bit option number.
func (o IPv4HeaderOption) Number() uint8 { return o.Type & 0x1f }

// RouterAlert returns the complete two-byte Router Alert value when o is a
// well-formed RFC 2113 option. The standalone codec preserves unassigned
// values; Stack protocol handling currently recognizes only value zero.
func (o IPv4HeaderOption) RouterAlert() (uint16, bool) {
	if o.Type != IPv4HeaderOptionRouterAlert || len(o.Data) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(o.Data), true
}

// SetRouterAlert replaces o with a Router Alert option containing value.
func (o *IPv4HeaderOption) SetRouterAlert(value uint16) {
	o.Type = IPv4HeaderOptionRouterAlert
	o.Data = make([]byte, 2)
	binary.BigEndian.PutUint16(o.Data, value)
}

// IPv6ExtensionHeaders returns the structurally traversable extension-header
// chain, the final Next Header value, and the remaining payload. The returned
// descriptor slice is caller-owned; header Data and payload borrow p.Payload.
// ESP, No Next Header, and unknown values terminate traversal. Bytes following
// No Next Header are returned as payload for lossless structural reconstruction
// even though UpperLayer intentionally ignores them.
func (p IPPacket) IPv6ExtensionHeaders() (headers []IPv6ExtensionHeader, protocol int, payload []byte, err error) {
	if !p.Source.Is6() || p.Source.Is4In6() || !p.Destination.Is6() || p.Destination.Is4In6() {
		return nil, 0, nil, syscall.EAFNOSUPPORT
	}
	if p.Protocol < 0 || p.Protocol > 255 || len(p.IPv4Options) != 0 {
		return nil, 0, nil, syscall.EINVAL
	}
	next, offset := byte(p.Protocol), 0
	seenHop := false
	for offset <= len(p.Payload) {
		if !isTraversableIPv6ExtensionHeader(next) {
			return headers, int(next), p.Payload[offset:], nil
		}
		if next == IPv6ExtensionHeaderHopByHop && (offset != 0 || seenHop) {
			return nil, 0, nil, syscall.EINVAL
		}
		length, valid := ipv6ExtensionHeaderLength(next, p.Payload[offset:])
		if !valid {
			return nil, 0, nil, syscall.EINVAL
		}
		header := p.Payload[offset : offset+length]
		if next == IPv6ExtensionHeaderHopByHop || next == IPv6ExtensionHeaderDestination {
			validOptions, _, jumboPayload := inspectIPv6OptionsForCodec(header)
			if !validOptions || jumboPayload {
				return nil, 0, nil, syscall.EINVAL
			}
		}
		if next == IPv6ExtensionHeaderFragment && binary.BigEndian.Uint16(header[2:4])&0xfff9 != 0 {
			return nil, 0, nil, syscall.EINVAL
		}
		headers = append(headers, IPv6ExtensionHeader{Type: next, Data: header[1:]})
		if next == IPv6ExtensionHeaderHopByHop {
			seenHop = true
		}
		next, offset = header[0], offset+length
	}
	return nil, 0, nil, syscall.EINVAL
}

// SetIPv6ExtensionHeaders replaces Protocol and Payload with one complete
// extension chain and final upper-layer payload. It generates every Next
// Header link, copies all caller storage, and leaves p unchanged on failure.
// Each header Data excludes its Next Header byte and must otherwise contain a
// complete header-specific wire representation.
func (p *IPPacket) SetIPv6ExtensionHeaders(headers []IPv6ExtensionHeader, protocol int, payload []byte) error {
	if p == nil {
		return syscall.EINVAL
	}
	if !p.Source.Is6() || p.Source.Is4In6() || !p.Destination.Is6() || p.Destination.Is4In6() {
		return syscall.EAFNOSUPPORT
	}
	if protocol < 0 || protocol > 255 || isTraversableIPv6ExtensionHeader(byte(protocol)) {
		return syscall.EINVAL
	}
	if len(payload) > 65535 {
		return syscall.EMSGSIZE
	}
	total := len(payload)
	seenHop := false
	for index, header := range headers {
		if !isTraversableIPv6ExtensionHeader(header.Type) {
			return syscall.EPROTONOSUPPORT
		}
		if header.Type == IPv6ExtensionHeaderHopByHop {
			if index != 0 || seenHop {
				return syscall.EINVAL
			}
			seenHop = true
		}
		length, valid := ipv6ExtensionHeaderDataLength(header.Type, header.Data)
		if !valid || length != 1+len(header.Data) {
			return syscall.EINVAL
		}
		if header.Type == IPv6ExtensionHeaderHopByHop || header.Type == IPv6ExtensionHeaderDestination {
			validOptions, _, jumboPayload := inspectIPv6OptionBytesForCodec(header.Data[1:])
			if !validOptions || jumboPayload {
				return syscall.EINVAL
			}
		}
		if header.Type == IPv6ExtensionHeaderFragment && binary.BigEndian.Uint16(header.Data[1:3])&0xfff9 != 0 {
			return syscall.EINVAL
		}
		total += length
		if total > 65535 {
			return syscall.EMSGSIZE
		}
	}
	encoded := make([]byte, 0, total)
	for index, header := range headers {
		next := byte(protocol)
		if index+1 < len(headers) {
			next = headers[index+1].Type
		}
		encoded = append(encoded, next)
		encoded = append(encoded, header.Data...)
	}
	encoded = append(encoded, payload...)
	if len(headers) == 0 {
		p.Protocol = protocol
	} else {
		p.Protocol = int(headers[0].Type)
	}
	p.Payload = encoded
	return nil
}

// Options parses a Hop-by-Hop or Destination Options header. The returned
// slice owns its descriptors, but every Data field borrows h.Data. Unknown
// option types, action bits, duplicates, and padding remain in wire order.
func (h IPv6ExtensionHeader) Options() ([]IPv6ExtensionOption, error) {
	if h.Type != IPv6ExtensionHeaderHopByHop && h.Type != IPv6ExtensionHeaderDestination {
		return nil, syscall.EPROTONOSUPPORT
	}
	length, valid := ipv6ExtensionHeaderDataLength(h.Type, h.Data)
	if !valid || length != 1+len(h.Data) {
		return nil, syscall.EINVAL
	}
	return parseIPv6ExtensionOptions(h.Data[1:])
}

// SetOptions replaces Data in a Hop-by-Hop or Destination Options header. It
// preserves unknown types, duplicates, and order, copies every input Data
// slice, and adds canonical trailing Pad1 or PadN alignment. It leaves h
// unchanged on failure.
func (h *IPv6ExtensionHeader) SetOptions(options []IPv6ExtensionOption) error {
	if h == nil {
		return syscall.EINVAL
	}
	if h.Type != IPv6ExtensionHeaderHopByHop && h.Type != IPv6ExtensionHeaderDestination {
		return syscall.EPROTONOSUPPORT
	}
	optionSize := 0
	for _, option := range options {
		if option.Type == IPv6ExtensionOptionPad1 {
			if len(option.Data) != 0 {
				return syscall.EINVAL
			}
			optionSize++
		} else {
			if len(option.Data) > 255 {
				return syscall.EINVAL
			}
			optionSize += 2 + len(option.Data)
		}
		if optionSize > 2046 {
			return syscall.EMSGSIZE
		}
	}
	total := 2 + optionSize
	padding := -total & 7
	total += padding
	if total > 2048 {
		return syscall.EMSGSIZE
	}
	data := make([]byte, total-1)
	data[0] = byte(total/8 - 1)
	offset := 1
	for _, option := range options {
		data[offset] = option.Type
		offset++
		if option.Type == IPv6ExtensionOptionPad1 {
			continue
		}
		data[offset] = byte(len(option.Data))
		offset++
		copy(data[offset:], option.Data)
		offset += len(option.Data)
	}
	if padding == 1 {
		data[offset] = IPv6ExtensionOptionPad1
	} else if padding > 1 {
		data[offset], data[offset+1] = IPv6ExtensionOptionPadN, byte(padding-2)
	}
	h.Data = data
	return nil
}

// Action returns the option's two-bit RFC 8200 action on an unrecognized type.
func (o IPv6ExtensionOption) Action() uint8 { return o.Type >> 6 }

// MayChangeInTransit reports the RFC 8200 mutable-data flag.
func (o IPv6ExtensionOption) MayChangeInTransit() bool { return o.Type&0x20 != 0 }

// RouterAlert returns the complete two-byte Router Alert value when o is a
// well-formed RFC 2711 option. The standalone codec preserves unassigned
// values; Stack protocol handling currently recognizes only value zero.
func (o IPv6ExtensionOption) RouterAlert() (uint16, bool) {
	if o.Type != IPv6ExtensionOptionRouterAlert || len(o.Data) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(o.Data), true
}

// SetRouterAlert replaces o with a Router Alert option containing value.
func (o *IPv6ExtensionOption) SetRouterAlert(value uint16) {
	o.Type = IPv6ExtensionOptionRouterAlert
	o.Data = make([]byte, 2)
	binary.BigEndian.PutUint16(o.Data, value)
}

// ParseIPPacket validates packet and returns a zero-copy semantic value. It
// validates declared lengths, the IPv4 header checksum, option framing, IPv6
// extension framing, and extension placement. Stateful fragment reassembly is
// outside this codec, so non-atomic fragments are rejected. Bytes beyond the
// declared IP length are ignored as link-layer padding.
func ParseIPPacket(packet []byte) (IPPacket, error) {
	if len(packet) == 0 {
		return IPPacket{}, syscall.EINVAL
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return IPPacket{}, syscall.EINVAL
		}
		headerSize := int(packet[0]&0x0f) * 4
		totalSize := int(binary.BigEndian.Uint16(packet[2:4]))
		fragment := binary.BigEndian.Uint16(packet[6:8])
		if headerSize < 20 || totalSize < headerSize || totalSize > len(packet) || fragment&0x8000 != 0 || fragment&0x3fff != 0 || checksum(packet[:headerSize]) != 0 {
			return IPPacket{}, syscall.EINVAL
		}
		options := packet[20:headerSize]
		if !validIPv4OptionsForCodec(options) {
			return IPPacket{}, syscall.EINVAL
		}
		return IPPacket{
			Source: netip.AddrFrom4([4]byte(packet[12:16])), Destination: netip.AddrFrom4([4]byte(packet[16:20])),
			Protocol: int(packet[9]), HopLimit: int(packet[8]), TrafficClass: int(packet[1]),
			Identification: binary.BigEndian.Uint16(packet[4:6]), DontFragment: fragment&0x4000 != 0,
			IPv4Options: options, Payload: packet[headerSize:totalSize],
		}, nil
	case 6:
		if len(packet) < 40 {
			return IPPacket{}, syscall.EINVAL
		}
		payloadSize := int(binary.BigEndian.Uint16(packet[4:6]))
		end := 40 + payloadSize
		if end > len(packet) {
			return IPPacket{}, syscall.EINVAL
		}
		source, destination := netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40]))
		if source.Is4In6() || destination.Is4In6() {
			return IPPacket{}, syscall.EINVAL
		}
		result := IPPacket{
			Source: source, Destination: destination,
			Protocol: int(packet[6]), HopLimit: int(packet[7]),
			TrafficClass: int(packet[0]&0x0f)<<4 | int(packet[1]>>4),
			FlowLabel:    uint32(packet[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(packet[2:4])),
			Payload:      packet[40:end],
		}
		if _, _, _, err := result.upperLayer(); err != nil {
			return IPPacket{}, err
		}
		return result, nil
	default:
		return IPPacket{}, syscall.EINVAL
	}
}

// UpperLayer returns the final IPv4 protocol or IPv6 Next Header value and
// the corresponding upper-layer bytes. The returned slice aliases Payload.
// For IPv6 it walks supported extension headers without applying Stack routing
// or option-admission policy.
func (p IPPacket) UpperLayer() (protocol int, payload []byte, err error) {
	protocol, payload, _, err = p.upperLayer()
	return
}

// upperLayer locates the final protocol and reports whether the base source
// and destination are safe to use as a transport pseudo-header. Active IPv4
// source routes and IPv6 routing headers remain inspectable through
// UpperLayer, but protocol decoders reject them rather than validate a
// checksum against an address that an IPv4 source route, IPv6 routing header,
// or Mobile IPv6 Home Address option replaces for upper-layer processing.
func (p IPPacket) upperLayer() (protocol int, payload []byte, pseudoHeaderSafe bool, err error) {
	source, destination := p.Source.Unmap(), p.Destination.Unmap()
	if !source.IsValid() || !destination.IsValid() || p.Source.Zone() != "" || p.Destination.Zone() != "" ||
		source.Is4() != destination.Is4() || p.Protocol < 0 || p.Protocol > 255 {
		return 0, nil, false, syscall.EINVAL
	}
	if source.Is4() {
		if len(p.IPv4Options) > 40 || !validIPv4OptionsForCodec(p.IPv4Options) {
			return 0, nil, false, syscall.EINVAL
		}
		return p.Protocol, p.Payload, !hasActiveIPv4SourceRoute(p.IPv4Options), nil
	}
	if len(p.IPv4Options) != 0 {
		return 0, nil, false, syscall.EINVAL
	}
	next, upper, pseudoHeaderUnsafe, ok := walkIPv6UpperLayer(byte(p.Protocol), p.Payload)
	if !ok {
		return 0, nil, false, syscall.EINVAL
	}
	return int(next), upper, !pseudoHeaderUnsafe, nil
}

// upperLayerForProtocol returns one expected upper-layer payload and reports
// whether the base IP addresses are safe to use in a checksum pseudo-header.
func (p IPPacket) upperLayerForProtocol(protocol byte) ([]byte, bool, error) {
	actual, payload, pseudoHeaderSafe, err := p.upperLayer()
	if err != nil {
		return nil, false, err
	}
	if actual != int(protocol) {
		return nil, false, syscall.EPROTONOSUPPORT
	}
	return payload, pseudoHeaderSafe, nil
}

// MarshalBinary returns the complete packet wire encoding. It is semantically
// identical to AppendBinary(nil).
func (p IPPacket) MarshalBinary() ([]byte, error) { return p.AppendBinary(nil) }

// AppendBinary appends the complete packet wire encoding to dst. It validates
// every field and the extension chain before changing dst and does not retain
// any input slice. The destination may share backing storage with IPv4Options
// or Payload. It calculates the IPv4 header checksum but never calculates an
// upper-layer checksum; callers must encode any TCP, UDP, or ICMP value before
// assigning it to Payload. On validation failure it returns the original dst
// unchanged.
func (p IPPacket) AppendBinary(dst []byte) ([]byte, error) {
	normalized, headerSize, totalSize, err := p.wireLayout()
	if err != nil {
		return dst, err
	}
	start := len(dst)
	dst = extendForAppend(dst, totalSize)
	marshalPublicIPPacket(dst[start:], normalized, headerSize)
	return dst, nil
}

// extendForAppend exposes reusable capacity without clearing bytes that a
// zero-copy parsed value may still borrow from the same backing array.
func extendForAppend(dst []byte, size int) []byte {
	if size <= cap(dst)-len(dst) {
		return dst[:len(dst)+size]
	}
	return append(dst, make([]byte, size)...)
}

// wireLayout validates p, normalizes IPv4-mapped addresses, and returns its
// exact base-header and packet lengths.
func (p IPPacket) wireLayout() (IPPacket, int, int, error) {
	if p.Source.Zone() != "" || p.Destination.Zone() != "" {
		return IPPacket{}, 0, 0, syscall.EINVAL
	}
	p.Source, p.Destination = p.Source.Unmap(), p.Destination.Unmap()
	if !p.Source.IsValid() || !p.Destination.IsValid() || p.Source.Is4() != p.Destination.Is4() ||
		p.Protocol < 0 || p.Protocol > 255 || p.HopLimit < 0 || p.HopLimit > 255 ||
		p.TrafficClass < 0 || p.TrafficClass > 255 {
		return IPPacket{}, 0, 0, syscall.EINVAL
	}
	if p.Source.Is4() {
		if p.FlowLabel != 0 || len(p.IPv4Options) > 40 || !validIPv4OptionsForCodec(p.IPv4Options) {
			return IPPacket{}, 0, 0, syscall.EINVAL
		}
		headerSize := 20 + (len(p.IPv4Options)+3)&^3
		if len(p.Payload) > 65535-headerSize {
			return IPPacket{}, 0, 0, syscall.EMSGSIZE
		}
		return p, headerSize, headerSize + len(p.Payload), nil
	}
	if p.FlowLabel > ipv6MaximumFlowLabel || p.Identification != 0 || p.DontFragment || len(p.IPv4Options) != 0 {
		return IPPacket{}, 0, 0, syscall.EINVAL
	}
	if len(p.Payload) > 65535 {
		return IPPacket{}, 0, 0, syscall.EMSGSIZE
	}
	if _, _, _, err := p.upperLayer(); err != nil {
		return IPPacket{}, 0, 0, err
	}
	return p, 40, 40 + len(p.Payload), nil
}

// marshalPublicIPPacket writes one already validated public packet. Payload is
// copied before its header so an in-place AppendBinary can reuse a payload
// suffix.
func marshalPublicIPPacket(dst []byte, p IPPacket, headerSize int) {
	if p.Source.Is4() {
		var options [40]byte
		contentSize, _ := ipv4OptionsContentLength(p.IPv4Options)
		copy(options[:], p.IPv4Options[:contentSize])
		copy(dst[headerSize:], p.Payload)
		copy(dst[20:headerSize], options[:len(p.IPv4Options)])
		for index := 20 + len(p.IPv4Options); index < headerSize; index++ {
			dst[index] = 0
		}
		dst[0], dst[1], dst[8], dst[9] = 0x40|byte(headerSize/4), byte(p.TrafficClass), byte(p.HopLimit), byte(p.Protocol)
		binary.BigEndian.PutUint16(dst[2:4], uint16(len(dst)))
		binary.BigEndian.PutUint16(dst[4:6], p.Identification)
		fragment := uint16(0)
		if p.DontFragment {
			fragment = 0x4000
		}
		binary.BigEndian.PutUint16(dst[6:8], fragment)
		source, destination := p.Source.As4(), p.Destination.As4()
		copy(dst[12:16], source[:])
		copy(dst[16:20], destination[:])
		binary.BigEndian.PutUint16(dst[10:12], 0)
		binary.BigEndian.PutUint16(dst[10:12], checksum(dst[:headerSize]))
		return
	}
	copy(dst[headerSize:], p.Payload)
	normalizeIPv6ExtensionFields(byte(p.Protocol), dst[headerSize:])
	dst[0] = 0x60 | byte(p.TrafficClass)>>4
	dst[1] = byte(p.TrafficClass)<<4 | byte(p.FlowLabel>>16)
	binary.BigEndian.PutUint16(dst[2:4], uint16(p.FlowLabel))
	binary.BigEndian.PutUint16(dst[4:6], uint16(len(dst)-40))
	dst[6], dst[7] = byte(p.Protocol), byte(p.HopLimit)
	source, destination := p.Source.As16(), p.Destination.As16()
	copy(dst[8:24], source[:])
	copy(dst[24:40], destination[:])
}

// normalizeIPv6ExtensionFields applies sender requirements that cannot
// invalidate an opaque integrity value. Authentication and Mobility headers
// are deliberately left untouched: their ICV or checksum covers reserved
// fields, and this structural codec lacks the state required to recompute it.
func normalizeIPv6ExtensionFields(first byte, payload []byte) {
	next, offset := first, 0
	for offset <= len(payload) {
		switch next {
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination:
			length := (int(payload[offset+1]) + 1) * 8
			for optionOffset := offset + 2; optionOffset < offset+length; {
				kind := payload[optionOffset]
				if kind == IPv6ExtensionOptionPad1 {
					optionOffset++
					continue
				}
				optionLength := int(payload[optionOffset+1])
				if kind == IPv6ExtensionOptionPadN {
					for index := optionOffset + 2; index < optionOffset+2+optionLength; index++ {
						payload[index] = 0
					}
				}
				optionOffset += optionLength + 2
			}
			next, offset = payload[offset], offset+length
		case IPv6ExtensionHeaderRouting:
			length := (int(payload[offset+1]) + 1) * 8
			next, offset = payload[offset], offset+length
		case IPv6ExtensionHeaderAuthentication:
			length := (int(payload[offset+1]) + 2) * 4
			next, offset = payload[offset], offset+length
		case IPv6ExtensionHeaderMobility:
			length := (int(payload[offset+1]) + 1) * 8
			next, offset = payload[offset], offset+length
		case IPv6ExtensionHeaderFragment:
			next = payload[offset]
			payload[offset+1] = 0
			field := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
			binary.BigEndian.PutUint16(payload[offset+2:offset+4], field&^0x0006)
			offset += 8
		default:
			return
		}
	}
}

// InternetChecksum computes the RFC 1071 one's-complement checksum of data.
// A caller generating a checksummed header must clear its checksum field
// first; computing over a complete valid checksummed region returns zero.
func InternetChecksum(data []byte) uint16 { return checksum(data) }

// IPTransportChecksum computes an IPv4 or IPv6 pseudo-header checksum over
// payload. Protocol must be between 0 and 255, payload must not exceed 65535
// bytes, and both addresses must be valid, unzoned members of the same family.
// IPv4-mapped IPv6 addresses are normalized to IPv4. A caller generating a
// transport header must clear its checksum field first and apply any
// protocol-specific wire rule; in particular, RFC 768 represents a computed
// UDP checksum of zero as 0xffff. Computing over a complete valid checksummed
// payload returns zero.
func IPTransportChecksum(source, destination netip.Addr, protocol int, payload []byte) (uint16, error) {
	if source.Zone() != "" || destination.Zone() != "" {
		return 0, syscall.EINVAL
	}
	source, destination = source.Unmap(), destination.Unmap()
	if !source.IsValid() || !destination.IsValid() || source.Is4() != destination.Is4() || protocol < 0 || protocol > 255 {
		return 0, syscall.EINVAL
	}
	if len(payload) > 65535 {
		return 0, syscall.EMSGSIZE
	}
	return transportChecksum(source, destination, byte(protocol), payload), nil
}

// ipPacket is a validated, complete IP packet and its upper-layer payload.
type ipPacket struct {
	source, target netip.Addr
	protocol       byte
	protocolOffset int
	parameterError bool
	parameterCode  byte
	parameterAt    uint32
	ecn            byte
	hopLimit       byte
	trafficClass   byte
	flowLabel      uint32
	payload        []byte
	original       []byte
}

// ipPacketOptions controls fields shared by raw IPv4 and IPv6 output. A zero
// hop limit selects the stack default.
type ipPacketOptions struct {
	hopLimit        byte
	trafficClass    byte
	flowLabel       uint32
	hopLimitSet     bool
	trafficClassSet bool
	flowLabelSet    bool
}

// withDefaults fills output fields omitted by per-packet control data.
func (o ipPacketOptions) withDefaults(defaults ipPacketOptions) ipPacketOptions {
	if !o.hopLimitSet && o.hopLimit == 0 {
		o.hopLimit, o.hopLimitSet = defaults.hopLimit, defaults.hopLimitSet
	}
	if !o.trafficClassSet && o.trafficClass == 0 {
		o.trafficClass, o.trafficClassSet = defaults.trafficClass, defaults.trafficClassSet
	}
	if !o.flowLabelSet {
		o.flowLabel, o.flowLabelSet = defaults.flowLabel, defaults.flowLabelSet
	}
	return o
}

// normalized applies endpoint defaults to optional output fields.
func (o ipPacketOptions) normalized() ipPacketOptions {
	if !o.hopLimitSet && o.hopLimit == 0 {
		o.hopLimit = 64
	}
	o.flowLabel &= ipv6MaximumFlowLabel
	return o
}

// checksum computes the Internet checksum over data.
func checksum(data []byte) uint16 {
	sum := checksumSum(data)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// checksumSum accumulates one contiguous Internet-checksum region. Grouping
// adjacent 16-bit words into 32-bit halves is valid because 2^16 is congruent
// to one modulo 2^16-1. A uint64 holds every half in a maximum IP packet, and
// folding it to uint32 keeps separately accumulated pseudo-header regions
// associative for the caller's final 16-bit fold.
func checksumSum(data []byte) uint32 {
	var sum uint64
	for len(data) >= 16 {
		first := binary.BigEndian.Uint64(data[:8])
		second := binary.BigEndian.Uint64(data[8:16])
		sum += first>>32 + first&0xffffffff + second>>32 + second&0xffffffff
		data = data[16:]
	}
	for len(data) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint64(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint32(sum)
}

// transportChecksum computes an IPv4 or IPv6 pseudo-header checksum.
func transportChecksum(source, target netip.Addr, protocol byte, payload []byte) uint16 {
	return transportChecksumParts(source, target, protocol, len(payload), payload, nil)
}

// transportChecksumParts computes one transport checksum without gathering two
// adjacent payload regions. It also handles an odd first-region boundary so
// callers are not required to align their virtual headers.
func transportChecksumParts(source, target netip.Addr, protocol byte, payloadLength int, first, second []byte) uint16 {
	source, target = source.Unmap(), target.Unmap()
	var sum uint32
	if source.Is4() && target.Is4() {
		sourceBytes, targetBytes := source.As4(), target.As4()
		sum += checksumSum(sourceBytes[:])
		sum += checksumSum(targetBytes[:])
		sum += uint32(protocol)
		sum += uint32(payloadLength)
	} else if source.Is6() && target.Is6() {
		sourceBytes, targetBytes := source.As16(), target.As16()
		sum += checksumSum(sourceBytes[:])
		sum += checksumSum(targetBytes[:])
		sum += uint32(payloadLength >> 16)
		sum += uint32(payloadLength & 0xffff)
		sum += uint32(protocol)
	} else {
		return 0
	}
	sum += checksumSum(first)
	if len(first)&1 != 0 && len(second) != 0 {
		last := uint32(first[len(first)-1]) << 8
		sum -= last
		sum += last | uint32(second[0])
		second = second[1:]
	}
	sum += checksumSum(second)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// packetDestination extracts the destination without requiring transport or
// fragment validation. It is used only to choose local versus link delivery.
func packetDestination(packet []byte) (netip.Addr, bool) {
	if len(packet) < 1 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(packet[16:20])), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(packet[24:40])), true
	default:
		return netip.Addr{}, false
	}
}

// parseIPPacket validates one unfragmented packet and locates its transport
// payload through supported IPv6 extension headers.
func parseIPPacket(packet []byte) (ipPacket, bool) {
	if len(packet) == 0 {
		return ipPacket{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return ipPacket{}, false
		}
		headerSize := int(packet[0]&0x0f) * 4
		totalSize := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerSize < 20 || totalSize < headerSize || totalSize > len(packet) || checksum(packet[:headerSize]) != 0 || binary.BigEndian.Uint16(packet[6:8])&0x8000 != 0 {
			return ipPacket{}, false
		}
		// Fragmented packets are handled by the reassembly layer added before
		// production selection; never expose a partial transport header.
		if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return ipPacket{}, false
		}
		source := netip.AddrFrom4([4]byte(packet[12:16]))
		target := netip.AddrFrom4([4]byte(packet[16:20]))
		if headerSize > 20 {
			options := packet[20:headerSize]
			if optionAt, malformed := malformedIPv4Option(options); malformed {
				return ipPacket{
					source: source, target: target, original: packet[:totalSize],
					parameterError: true, parameterCode: 0, parameterAt: uint32(20 + optionAt),
				}, true
			}
			if !validateIPv4Options(options) {
				return ipPacket{}, false
			}
		}
		return ipPacket{
			source: source, target: target,
			protocol: packet[9], protocolOffset: 9, ecn: packet[1] & 3, hopLimit: packet[8], trafficClass: packet[1],
			payload: packet[headerSize:totalSize], original: packet[:totalSize],
		}, true
	case 6:
		if len(packet) < 40 {
			return ipPacket{}, false
		}
		payloadSize := int(binary.BigEndian.Uint16(packet[4:6]))
		end := 40 + payloadSize
		if end > len(packet) {
			return ipPacket{}, false
		}
		source := netip.AddrFrom16([16]byte(packet[8:24]))
		target := netip.AddrFrom16([16]byte(packet[24:40]))
		if source.Is4In6() || target.Is4In6() {
			return ipPacket{}, false
		}
		flowLabel := uint32(packet[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(packet[2:4]))
		next, nextOffset, offset := packet[6], 6, 40
		seenHop := false
		for offset <= end {
			switch next {
			case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination:
				if next == IPv6ExtensionHeaderHopByHop && (offset != 40 || seenHop) {
					// RFC 8200 permits Hop-by-Hop only immediately after the
					// IPv6 header. A later value zero is therefore an
					// unrecognized Next Header, not another extension header.
					return ipPacket{
						source: source, target: target, original: packet[:end], ecn: packet[1] >> 4 & 3,
						hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
						parameterError: true, parameterCode: 1, parameterAt: uint32(nextOffset),
					}, true
				}
				if end-offset < 8 {
					return ipPacket{}, false
				}
				length := (int(packet[offset+1]) + 1) * 8
				if length > end-offset {
					return ipPacket{}, false
				}
				valid, action, optionOffset := inspectIPv6Options(packet[offset : offset+length])
				if !valid {
					if action >= 2 && (action == 2 || !target.IsMulticast()) {
						return ipPacket{
							source: source, target: target, original: packet[:end], ecn: packet[1] >> 4 & 3,
							hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
							parameterError: true, parameterCode: 2, parameterAt: uint32(offset + optionOffset),
						}, true
					}
					return ipPacket{}, false
				}
				if next == IPv6ExtensionHeaderHopByHop {
					seenHop = true
				}
				next, nextOffset, offset = packet[offset], offset, offset+length
			case IPv6ExtensionHeaderRouting:
				if end-offset < 8 {
					return ipPacket{}, false
				}
				length := (int(packet[offset+1]) + 1) * 8
				if length > end-offset {
					return ipPacket{}, false
				}
				if packet[offset+3] != 0 {
					return ipPacket{
						source: source, target: target, original: packet[:end], ecn: packet[1] >> 4 & 3,
						hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
						parameterError: true, parameterCode: 0, parameterAt: uint32(offset + 2),
					}, true
				}
				next, nextOffset, offset = packet[offset], offset, offset+length
			case IPv6ExtensionHeaderFragment:
				// Non-atomic fragments require bounded reassembly. Atomic
				// fragments can safely continue as an ordinary packet. RFC
				// 8200 requires receivers to ignore both reserved fields.
				if end-offset < 8 || binary.BigEndian.Uint16(packet[offset+2:offset+4])&0xfff9 != 0 {
					return ipPacket{}, false
				}
				next, nextOffset, offset = packet[offset], offset, offset+8
			default:
				return ipPacket{
					source: source, target: target, protocol: next, protocolOffset: nextOffset,
					ecn: packet[1] >> 4 & 3, hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4, flowLabel: flowLabel,
					payload: packet[offset:end], original: packet[:end],
				}, true
			}
		}
	}
	return ipPacket{}, false
}

// hasRouterAlert reports the zero-valued Router Alert required by IGMP and
// MLD. Keeping this uncommon policy check out of parseIPPacket avoids adding
// work to every ordinary IPv4 and IPv6 packet.
func (p ipPacket) hasRouterAlert() bool {
	if p.source.Is4() {
		if len(p.original) < 20 {
			return false
		}
		headerSize := int(p.original[0]&0x0f) * 4
		return headerSize >= 20 && headerSize <= len(p.original) && ipv4RouterAlert(p.original[20:headerSize])
	}
	if !p.source.Is6() || len(p.original) < 48 || p.original[6] != IPv6ExtensionHeaderHopByHop {
		return false
	}
	length := (int(p.original[41]) + 1) * 8
	return length <= len(p.original)-40 && ipv6RouterAlert(p.original[40:40+length])
}

// walkIPv6UpperLayer validates supported extension-header framing and returns
// the final upper-layer view. Unknown option action bits are codec data, not
// host admission policy, and therefore do not make the public packet invalid.
func walkIPv6UpperLayer(first byte, payload []byte) (protocol byte, upper []byte, pseudoHeaderUnsafe, ok bool) {
	next, offset := first, 0
	seenHop := false
	for offset <= len(payload) {
		if next == ProtocolNoNextHeader {
			// RFC 8200 requires receivers to ignore bytes following No Next
			// Header. IPPacket.Payload still preserves them for round trips.
			return next, nil, pseudoHeaderUnsafe, true
		}
		if !isTraversableIPv6ExtensionHeader(next) {
			return next, payload[offset:], pseudoHeaderUnsafe, true
		}
		if next == IPv6ExtensionHeaderHopByHop && (offset != 0 || seenHop) {
			return 0, nil, false, false
		}
		length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
		if !valid {
			return 0, nil, false, false
		}
		header := payload[offset : offset+length]
		switch next {
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination:
			validOptions, homeAddress, jumboPayload := inspectIPv6OptionsForCodec(header)
			if !validOptions || jumboPayload {
				return 0, nil, false, false
			}
			pseudoHeaderUnsafe = pseudoHeaderUnsafe || homeAddress
		case IPv6ExtensionHeaderRouting:
			pseudoHeaderUnsafe = pseudoHeaderUnsafe || header[3] != 0
		case IPv6ExtensionHeaderFragment:
			// Only atomic fragments contain a complete upper-layer unit. The
			// two reserved fields are ignored as RFC 8200 requires.
			if binary.BigEndian.Uint16(header[2:4])&0xfff9 != 0 {
				return 0, nil, false, false
			}
		}
		if next == IPv6ExtensionHeaderHopByHop {
			seenHop = true
		}
		next, offset = header[0], offset+length
	}
	return 0, nil, false, false
}

// isTraversableIPv6ExtensionHeader reports headers whose length and following
// Next Header can be determined without security or transport state. ESP is
// intentionally terminal because its encrypted trailer identifies the next
// protocol only after decryption.
func isTraversableIPv6ExtensionHeader(headerType byte) bool {
	switch headerType {
	case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
		IPv6ExtensionHeaderFragment, IPv6ExtensionHeaderAuthentication,
		IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderMobility:
		return true
	default:
		return false
	}
}

// ipv6ExtensionHeaderLength validates one header prefix within a remaining
// packet and returns its complete length, including Next Header.
func ipv6ExtensionHeaderLength(headerType byte, header []byte) (int, bool) {
	if len(header) < 2 {
		return 0, false
	}
	length, valid := ipv6ExtensionHeaderDataLength(headerType, header[1:])
	return length, valid && length <= len(header)
}

// ipv6ExtensionHeaderDataLength validates the length field available after a
// header's Next Header byte and returns the complete header length.
func ipv6ExtensionHeaderDataLength(headerType byte, data []byte) (int, bool) {
	switch headerType {
	case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
		IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderMobility:
		if len(data) < 1 {
			return 0, false
		}
		return (int(data[0]) + 1) * 8, true
	case IPv6ExtensionHeaderFragment:
		return 8, len(data) >= 7
	case IPv6ExtensionHeaderAuthentication:
		if len(data) < 1 {
			return 0, false
		}
		length := (int(data[0]) + 2) * 4
		// RFC 4302 requires the fixed fields through Sequence Number and,
		// for IPv6, pads the complete AH to an eight-octet boundary.
		return length, length >= 16 && length%8 == 0
	default:
		return 0, false
	}
}

// parseIPv6ExtensionOptions parses the option bytes following the common
// Next Header and Hdr Ext Len fields.
func parseIPv6ExtensionOptions(options []byte) ([]IPv6ExtensionOption, error) {
	var result []IPv6ExtensionOption
	for offset := 0; offset < len(options); {
		optionType := options[offset]
		if optionType == IPv6ExtensionOptionPad1 {
			result = append(result, IPv6ExtensionOption{Type: optionType})
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return nil, syscall.EINVAL
		}
		length := int(options[offset+1])
		if length > len(options)-offset-2 {
			return nil, syscall.EINVAL
		}
		result = append(result, IPv6ExtensionOption{Type: optionType, Data: options[offset+2 : offset+2+length]})
		offset += 2 + length
	}
	return result, nil
}

// ipv4OptionsContentLength validates IPv4 option framing and returns the bytes
// through End. Like Linux, receivers ignore later padding bytes; encoders use
// the returned length to write canonical zero padding.
func ipv4OptionsContentLength(options []byte) (int, bool) {
	for offset := 0; offset < len(options); {
		switch options[offset] {
		case IPv4HeaderOptionEnd:
			return offset + 1, true
		case IPv4HeaderOptionNOP:
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return 0, false
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return 0, false
		}
		offset += length
	}
	return len(options), true
}

// validIPv4OptionsForCodec validates only the wire framing of IPv4 options.
// Host policy such as source-route rejection remains in validateIPv4Options.
func validIPv4OptionsForCodec(options []byte) bool {
	_, valid := ipv4OptionsContentLength(options)
	return valid
}

// hasActiveIPv4SourceRoute reports a loose or strict source route whose next
// address has not yet been consumed. Malformed source-route metadata is also
// unsafe because the base destination cannot be trusted for a pseudo-header.
func hasActiveIPv4SourceRoute(options []byte) bool {
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == IPv4HeaderOptionEnd {
			return false
		}
		if kind == IPv4HeaderOptionNOP {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return false
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return false
		}
		if kind == IPv4HeaderOptionLooseSourceRoute || kind == IPv4HeaderOptionStrictSourceRoute {
			if length < 3 {
				return true
			}
			pointer := int(options[offset+2])
			if pointer < 4 || pointer <= length {
				return true
			}
		}
		offset += length
	}
	return false
}

// inspectIPv6OptionsForCodec validates one complete Hop-by-Hop or Destination
// Options header and reports options that require state outside the standalone
// codec. RFC 6275 substitutes a Home Address into upper-layer pseudo-headers.
// RFC 2675's Jumbo Payload option changes IPv6 length and transport-checksum
// semantics, and mipstack intentionally does not support jumbograms.
func inspectIPv6OptionsForCodec(header []byte) (valid, homeAddress, jumboPayload bool) {
	if len(header) < 8 || len(header)%8 != 0 {
		return false, false, false
	}
	return inspectIPv6OptionBytesForCodec(header[2:])
}

// inspectIPv6OptionBytesForCodec validates a complete IPv6 option area and
// reports options that need state unavailable to the standalone codec.
func inspectIPv6OptionBytesForCodec(options []byte) (valid, homeAddress, jumboPayload bool) {
	for offset := 0; offset < len(options); {
		if options[offset] == IPv6ExtensionOptionPad1 {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return false, false, false
		}
		length := int(options[offset+1]) + 2
		if length > len(options)-offset {
			return false, false, false
		}
		homeAddress = homeAddress || options[offset] == IPv6ExtensionOptionHomeAddress
		jumboPayload = jumboPayload || options[offset] == IPv6ExtensionOptionJumboPayload
		offset += length
	}
	return true, homeAddress, jumboPayload
}

// ipv4RouterAlert reports a well-formed, zero-valued RFC 2113 option.
func ipv4RouterAlert(options []byte) bool {
	found := false
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == IPv4HeaderOptionEnd {
			return found
		}
		if kind == IPv4HeaderOptionNOP {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return false
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return false
		}
		if kind == IPv4HeaderOptionRouterAlert {
			if found || length != 4 || options[offset+2] != 0 || options[offset+3] != 0 {
				return false
			}
			found = true
		}
		offset += length
	}
	return found
}

// ipv6RouterAlert reports a zero-valued RFC 2711 option in one validated
// Hop-by-Hop header.
func ipv6RouterAlert(header []byte) bool {
	found := false
	for offset := 2; offset < len(header); {
		kind := header[offset]
		if kind == IPv6ExtensionOptionPad1 {
			offset++
			continue
		}
		if len(header)-offset < 2 {
			return false
		}
		length := int(header[offset+1]) + 2
		if length > len(header)-offset {
			return false
		}
		if kind == IPv6ExtensionOptionRouterAlert {
			if found || length != 4 || header[offset+2] != 0 || header[offset+3] != 0 {
				return false
			}
			found = true
		}
		offset += length
	}
	return found
}

// malformedIPv4Option returns the byte that Linux reports in an ICMP
// Parameter Problem for malformed option framing or fields. Policy rejection
// of a well-formed option, such as source routing, is left to
// validateIPv4Options and is not misreported as a syntax error.
func malformedIPv4Option(options []byte) (int, bool) {
	var sourceRoute, recordRoute, timestamp, routerAlert bool
	for offset := 0; offset < len(options); {
		kind := options[offset]
		switch kind {
		case IPv4HeaderOptionEnd:
			return 0, false
		case IPv4HeaderOptionNOP:
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return offset, true
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return offset, true
		}
		switch kind {
		case IPv4HeaderOptionLooseSourceRoute, IPv4HeaderOptionStrictSourceRoute:
			if length < 3 {
				return offset + 1, true
			}
			if options[offset+2] < 4 {
				return offset + 2, true
			}
			if sourceRoute {
				return offset, true
			}
			sourceRoute = true
		case IPv4HeaderOptionRecordRoute:
			if recordRoute {
				return offset, true
			}
			recordRoute = true
			if length < 3 {
				return offset + 1, true
			}
			pointer := int(options[offset+2])
			if pointer < 4 {
				return offset + 2, true
			}
			if pointer <= length && pointer+3 > length {
				return offset + 2, true
			}
		case IPv4HeaderOptionTimestamp:
			if timestamp {
				return offset, true
			}
			timestamp = true
			if length < 4 {
				return offset + 1, true
			}
			pointer := int(options[offset+2])
			if pointer < 5 {
				return offset + 2, true
			}
			flag := options[offset+3] & 0x0f
			if pointer <= length {
				required := 4
				if flag == 1 || flag == 3 {
					required = 8
				}
				if pointer+required-1 > length {
					return offset + 2, true
				}
			} else if flag != 3 && options[offset+3]>>4 == 15 {
				return offset + 3, true
			}
		case IPv4HeaderOptionRouterAlert:
			if length != 4 {
				return offset + 1, true
			}
			if routerAlert {
				return offset, true
			}
			routerAlert = true
		}
		offset += length
	}
	return 0, false
}

// validateIPv4Options checks complete TLV boundaries. Source-routing options
// are rejected because silently ignoring their destination semantics is unsafe.
func validateIPv4Options(options []byte) bool {
	for offset := 0; offset < len(options); {
		kind := options[offset]
		switch kind {
		case IPv4HeaderOptionEnd:
			return true
		case IPv4HeaderOptionNOP:
			offset++
			continue
		case IPv4HeaderOptionLooseSourceRoute, IPv4HeaderOptionStrictSourceRoute:
			return false
		}
		if len(options)-offset < 2 {
			return false
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return false
		}
		offset += length
	}
	return true
}

// inspectIPv6Options checks TLV boundaries. It returns the action bits and
// type-byte offset for an unsupported option that requires discarding.
func inspectIPv6Options(header []byte) (bool, byte, int) {
	if len(header) < 8 {
		return false, 0, 0
	}
	for offset := 2; offset < len(header); {
		kind := header[offset]
		if kind == IPv6ExtensionOptionPad1 {
			offset++
			continue
		}
		if len(header)-offset < 2 {
			return false, 0, offset
		}
		length := int(header[offset+1]) + 2
		if length > len(header)-offset {
			return false, 0, offset
		}
		if action := kind >> 6; action != 0 {
			return false, action, offset
		}
		offset += length
	}
	return true, 0, 0
}

// setPacketECN updates the two ECN bits and repairs the IPv4 header checksum.
func setPacketECN(packet []byte, ecn byte) {
	if len(packet) < 1 {
		return
	}
	if packet[0]>>4 == 4 && len(packet) >= 20 {
		headerSize := int(packet[0]&0x0f) * 4
		if headerSize < 20 || headerSize > len(packet) {
			return
		}
		packet[1] = packet[1]&^3 | ecn&3
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerSize]))
	} else if packet[0]>>4 == 6 && len(packet) >= 40 {
		packet[1] = packet[1]&0xcf | (ecn&3)<<4
	}
}

// ipHeaderSize validates an address pair and payload length and returns the
// fixed header size for the selected IP version.
func ipHeaderSize(source, target netip.Addr, payloadSize int) int {
	source, target = source.Unmap(), target.Unmap()
	if !source.IsValid() || !target.IsValid() || source.Is4() != target.Is4() {
		return 0
	}
	if source.Is4() {
		if payloadSize < 0 || payloadSize > 65515 {
			return 0
		}
		return 20
	}
	if payloadSize < 0 || payloadSize > 65535 {
		return 0
	}
	return 40
}

// marshalIPHeader writes an IPv4 or IPv6 header into a complete, already
// sized packet. Callers can fill the transport payload in the remaining
// bytes without an intermediate allocation.
func marshalIPHeader(packet []byte, source, target netip.Addr, protocol byte, identification uint16, dontFragment bool, options ipPacketOptions) bool {
	source, target = source.Unmap(), target.Unmap()
	headerSize := 20
	if source.Is6() {
		headerSize = 40
	}
	if len(packet) < headerSize || ipHeaderSize(source, target, len(packet)-headerSize) != headerSize {
		return false
	}
	options = options.normalized()
	if source.Is4() {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:6], identification)
		binary.BigEndian.PutUint16(packet[6:8], 0)
		if dontFragment {
			binary.BigEndian.PutUint16(packet[6:8], 0x4000)
		}
		packet[1], packet[8], packet[9] = options.trafficClass, options.hopLimit, protocol
		sourceBytes, targetBytes := source.As4(), target.As4()
		copy(packet[12:16], sourceBytes[:])
		copy(packet[16:20], targetBytes[:])
		binary.BigEndian.PutUint16(packet[10:12], 0)
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		return true
	}
	packet[0] = 0x60 | options.trafficClass>>4
	packet[1] = options.trafficClass<<4 | byte(options.flowLabel>>16)
	binary.BigEndian.PutUint16(packet[2:4], uint16(options.flowLabel))
	packet[6], packet[7] = protocol, options.hopLimit
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	sourceBytes, targetBytes := source.As16(), target.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], targetBytes[:])
	return true
}

// buildIPPacketWithOptions wraps payload and applies raw IP output fields.
func buildIPPacketWithOptions(source, target netip.Addr, protocol byte, payload []byte, identification uint16, dontFragment bool, options ipPacketOptions) []byte {
	headerSize := ipHeaderSize(source, target, len(payload))
	if headerSize == 0 {
		return nil
	}
	packet := make([]byte, headerSize+len(payload))
	if !marshalIPHeader(packet, source, target, protocol, identification, dontFragment, options) {
		return nil
	}
	copy(packet[headerSize:], payload)
	return packet
}
