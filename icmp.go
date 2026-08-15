package mipstack

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
)

const (
	// ICMPCodeNone is the zero code used by message types without subcodes.
	ICMPCodeNone = 0

	// ICMPv4TypeEchoReply is the ICMPv4 Echo Reply type.
	ICMPv4TypeEchoReply = 0
	// ICMPv4TypeDestinationUnreachable is the ICMPv4 Destination Unreachable type.
	ICMPv4TypeDestinationUnreachable = 3
	// ICMPv4TypeEchoRequest is the ICMPv4 Echo Request type.
	ICMPv4TypeEchoRequest = 8
	// ICMPv4TypeTimeExceeded is the ICMPv4 Time Exceeded type.
	ICMPv4TypeTimeExceeded = 11
	// ICMPv4TypeParameterProblem is the ICMPv4 Parameter Problem type.
	ICMPv4TypeParameterProblem = 12

	// ICMPv6TypeDestinationUnreachable is the ICMPv6 Destination Unreachable type.
	ICMPv6TypeDestinationUnreachable = 1
	// ICMPv6TypePacketTooBig is the ICMPv6 Packet Too Big type.
	ICMPv6TypePacketTooBig = 2
	// ICMPv6TypeTimeExceeded is the ICMPv6 Time Exceeded type.
	ICMPv6TypeTimeExceeded = 3
	// ICMPv6TypeParameterProblem is the ICMPv6 Parameter Problem type.
	ICMPv6TypeParameterProblem = 4
	// ICMPv6TypeEchoRequest is the ICMPv6 Echo Request type.
	ICMPv6TypeEchoRequest = 128
	// ICMPv6TypeEchoReply is the ICMPv6 Echo Reply type.
	ICMPv6TypeEchoReply = 129

	// ICMPv4DestinationUnreachableCodeNetwork reports an unreachable destination network.
	ICMPv4DestinationUnreachableCodeNetwork = 0
	// ICMPv4DestinationUnreachableCodeHost reports an unreachable destination host.
	ICMPv4DestinationUnreachableCodeHost = 1
	// ICMPv4DestinationUnreachableCodeProtocol reports an unsupported destination protocol.
	ICMPv4DestinationUnreachableCodeProtocol = 2
	// ICMPv4DestinationUnreachableCodePort reports an unreachable destination port.
	ICMPv4DestinationUnreachableCodePort = 3
	// ICMPv4DestinationUnreachableCodeFragmentationNeeded reports a packet that requires fragmentation with DF set.
	ICMPv4DestinationUnreachableCodeFragmentationNeeded = 4
	// ICMPv4DestinationUnreachableCodeSourceRouteFailed reports a failed source route.
	ICMPv4DestinationUnreachableCodeSourceRouteFailed = 5
	// ICMPv4DestinationUnreachableCodeNetworkUnknown reports an unknown destination network.
	ICMPv4DestinationUnreachableCodeNetworkUnknown = 6
	// ICMPv4DestinationUnreachableCodeHostUnknown reports an unknown destination host.
	ICMPv4DestinationUnreachableCodeHostUnknown = 7
	// ICMPv4DestinationUnreachableCodeSourceHostIsolated reports an isolated source host.
	ICMPv4DestinationUnreachableCodeSourceHostIsolated = 8
	// ICMPv4DestinationUnreachableCodeNetworkAdministrativelyProhibited reports a prohibited destination network.
	ICMPv4DestinationUnreachableCodeNetworkAdministrativelyProhibited = 9
	// ICMPv4DestinationUnreachableCodeHostAdministrativelyProhibited reports a prohibited destination host.
	ICMPv4DestinationUnreachableCodeHostAdministrativelyProhibited = 10
	// ICMPv4DestinationUnreachableCodeNetworkUnreachableForTOS reports a network unreachable for the requested TOS.
	ICMPv4DestinationUnreachableCodeNetworkUnreachableForTOS = 11
	// ICMPv4DestinationUnreachableCodeHostUnreachableForTOS reports a host unreachable for the requested TOS.
	ICMPv4DestinationUnreachableCodeHostUnreachableForTOS = 12
	// ICMPv4DestinationUnreachableCodeCommunicationAdministrativelyProhibited reports prohibited communication.
	ICMPv4DestinationUnreachableCodeCommunicationAdministrativelyProhibited = 13
	// ICMPv4DestinationUnreachableCodeHostPrecedenceViolation reports a host-precedence violation.
	ICMPv4DestinationUnreachableCodeHostPrecedenceViolation = 14
	// ICMPv4DestinationUnreachableCodePrecedenceCutoff reports a precedence cutoff.
	ICMPv4DestinationUnreachableCodePrecedenceCutoff = 15

	// ICMPv4TimeExceededCodeTTLInTransit reports an expired IPv4 TTL in transit.
	ICMPv4TimeExceededCodeTTLInTransit = 0
	// ICMPv4TimeExceededCodeFragmentReassembly reports an expired fragment reassembly.
	ICMPv4TimeExceededCodeFragmentReassembly = 1
	// ICMPv4ParameterProblemCodePointer reports an error at the supplied pointer.
	ICMPv4ParameterProblemCodePointer = 0
	// ICMPv4ParameterProblemCodeMissingOption reports a missing required option.
	ICMPv4ParameterProblemCodeMissingOption = 1
	// ICMPv4ParameterProblemCodeBadLength reports an invalid packet length.
	ICMPv4ParameterProblemCodeBadLength = 2

	// ICMPv6DestinationUnreachableCodeNoRoute reports that no route exists.
	ICMPv6DestinationUnreachableCodeNoRoute = 0
	// ICMPv6DestinationUnreachableCodeAdministrativelyProhibited reports prohibited communication.
	ICMPv6DestinationUnreachableCodeAdministrativelyProhibited = 1
	// ICMPv6DestinationUnreachableCodeBeyondSourceScope reports a destination beyond the source address scope.
	ICMPv6DestinationUnreachableCodeBeyondSourceScope = 2
	// ICMPv6DestinationUnreachableCodeAddress reports an unreachable destination address.
	ICMPv6DestinationUnreachableCodeAddress = 3
	// ICMPv6DestinationUnreachableCodePort reports an unreachable destination port.
	ICMPv6DestinationUnreachableCodePort = 4
	// ICMPv6DestinationUnreachableCodeSourceAddressPolicy reports a source-address policy failure.
	ICMPv6DestinationUnreachableCodeSourceAddressPolicy = 5
	// ICMPv6DestinationUnreachableCodeRejectRoute reports a rejected destination route.
	ICMPv6DestinationUnreachableCodeRejectRoute = 6
	// ICMPv6DestinationUnreachableCodeSourceRoutingHeader reports an error in a Source Routing Header.
	ICMPv6DestinationUnreachableCodeSourceRoutingHeader = 7
	// ICMPv6DestinationUnreachableCodePRoute reports an error in an RPL P-Route.
	ICMPv6DestinationUnreachableCodePRoute = 9

	// ICMPv6TimeExceededCodeHopLimitInTransit reports an expired IPv6 Hop Limit in transit.
	ICMPv6TimeExceededCodeHopLimitInTransit = 0
	// ICMPv6TimeExceededCodeFragmentReassembly reports an expired fragment reassembly.
	ICMPv6TimeExceededCodeFragmentReassembly = 1
	// ICMPv6ParameterProblemCodeErroneousHeaderField reports an erroneous header field.
	ICMPv6ParameterProblemCodeErroneousHeaderField = 0
	// ICMPv6ParameterProblemCodeUnrecognizedNextHeader reports an unrecognized Next Header value.
	ICMPv6ParameterProblemCodeUnrecognizedNextHeader = 1
	// ICMPv6ParameterProblemCodeUnrecognizedOption reports an unrecognized IPv6 option.
	ICMPv6ParameterProblemCodeUnrecognizedOption = 2
	// ICMPv6ParameterProblemCodeIncompleteFirstFragment reports an incomplete first-fragment header chain.
	ICMPv6ParameterProblemCodeIncompleteFirstFragment = 3
	// ICMPv6ParameterProblemCodeSRUpperLayerHeader reports an SR upper-layer header error.
	ICMPv6ParameterProblemCodeSRUpperLayerHeader = 4
	// ICMPv6ParameterProblemCodeUnrecognizedNextHeaderAtIntermediateNode reports an unrecognized Next Header at an intermediate node.
	ICMPv6ParameterProblemCodeUnrecognizedNextHeaderAtIntermediateNode = 5
	// ICMPv6ParameterProblemCodeExtensionHeaderTooBig reports an extension header that exceeds a processing limit.
	ICMPv6ParameterProblemCodeExtensionHeaderTooBig = 6
	// ICMPv6ParameterProblemCodeExtensionHeaderChainTooLong reports an extension-header chain that exceeds a size limit.
	ICMPv6ParameterProblemCodeExtensionHeaderChainTooLong = 7
	// ICMPv6ParameterProblemCodeTooManyExtensionHeaders reports an extension-header count that exceeds a processing limit.
	ICMPv6ParameterProblemCodeTooManyExtensionHeaders = 8
	// ICMPv6ParameterProblemCodeTooManyOptionsInExtensionHeader reports an option count that exceeds a processing limit.
	ICMPv6ParameterProblemCodeTooManyOptionsInExtensionHeader = 9
	// ICMPv6ParameterProblemCodeOptionTooBig reports an option that exceeds a processing limit.
	ICMPv6ParameterProblemCodeOptionTooBig = 10
)

// ICMPMessage is the semantic representation of one ICMPv4 or ICMPv6
// message. Source and Destination select the address family and, for ICMPv6,
// provide the checksum pseudo-header. IPPacket.ICMPMessage borrows Body from
// the packet; callers must replace or copy it before modifying unowned input.
// Validation and wire encoding treat IPv4-mapped IPv6 addresses as IPv4
// without changing the receiver's address fields.
type ICMPMessage struct {
	// Source is the source IP address.
	Source netip.Addr
	// Destination is the destination IP address.
	Destination netip.Addr
	// Type is the ICMP message type.
	Type uint8
	// Code is the subtype within Type.
	Code uint8
	// Body contains every byte after Type, Code, and Checksum. It must include
	// the message type's four-byte minimum body.
	Body []byte
}

// ICMPMessage validates and decodes the packet's family-appropriate ICMP
// upper layer.
func (p IPPacket) ICMPMessage() (ICMPMessage, error) {
	protocol := byte(ProtocolICMPv4)
	if p.Source.Unmap().Is6() {
		protocol = ProtocolICMPv6
	}
	icmp, pseudoHeaderSafe, err := p.upperLayerForProtocol(protocol)
	if err != nil {
		return ICMPMessage{}, err
	}
	if protocol == ProtocolICMPv6 && !pseudoHeaderSafe {
		return ICMPMessage{}, syscall.EPROTONOSUPPORT
	}
	if len(icmp) < 8 {
		return ICMPMessage{}, syscall.EINVAL
	}
	valid := checksum(icmp) == 0
	if protocol == ProtocolICMPv6 {
		valid = transportChecksum(p.Source, p.Destination, ProtocolICMPv6, icmp) == 0
	}
	if !valid {
		return ICMPMessage{}, syscall.EINVAL
	}
	return ICMPMessage{Source: p.Source.Unmap(), Destination: p.Destination.Unmap(), Type: icmp[0], Code: icmp[1], Body: icmp[4:]}, nil
}

// IsEchoRequest reports whether m is a complete family-appropriate Echo
// Request. The four leading Body bytes hold the echo identifier and sequence.
func (m ICMPMessage) IsEchoRequest() bool {
	request, ok := m.echoKind()
	return ok && request
}

// IsEchoReply reports whether m is a complete family-appropriate Echo Reply.
// The four leading Body bytes hold the echo identifier and sequence.
func (m ICMPMessage) IsEchoReply() bool {
	request, ok := m.echoKind()
	return ok && !request
}

// Echo returns the identifier, sequence, and data of a complete family-
// appropriate Echo Request or Echo Reply. Payload aliases Body.
func (m ICMPMessage) Echo() (identifier, sequence uint16, payload []byte, ok bool) {
	if _, ok = m.echoKind(); !ok {
		return 0, 0, nil, false
	}
	return binary.BigEndian.Uint16(m.Body[:2]), binary.BigEndian.Uint16(m.Body[2:4]), m.Body[4:], true
}

// SetEchoRequest replaces Type, Code, and Body with an Echo Request containing
// identifier, sequence, and a copy of payload. Source and Destination must
// already select one valid address family. It leaves m unchanged on failure.
func (m *ICMPMessage) SetEchoRequest(identifier, sequence uint16, payload []byte) error {
	return m.setEcho(true, identifier, sequence, payload)
}

// SetEchoReply replaces Type, Code, and Body with an Echo Reply containing
// identifier, sequence, and a copy of payload. Source and Destination must
// already select one valid address family. It leaves m unchanged on failure.
func (m *ICMPMessage) SetEchoReply(identifier, sequence uint16, payload []byte) error {
	return m.setEcho(false, identifier, sequence, payload)
}

// echoKind validates the common Echo envelope and reports whether it is a
// request. A false request with ok set is an Echo Reply.
func (m ICMPMessage) echoKind() (request, ok bool) {
	_, _, protocol, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid || len(m.Body) < 4 || m.Code != ICMPCodeNone {
		return false, false
	}
	if protocol == ProtocolICMPv4 {
		switch m.Type {
		case ICMPv4TypeEchoRequest:
			return true, true
		case ICMPv4TypeEchoReply:
			return false, true
		}
	} else {
		switch m.Type {
		case ICMPv6TypeEchoRequest:
			return true, true
		case ICMPv6TypeEchoReply:
			return false, true
		}
	}
	return false, false
}

// setEcho implements the two ownership-identical Echo construction methods.
func (m *ICMPMessage) setEcho(request bool, identifier, sequence uint16, payload []byte) error {
	if m == nil {
		return syscall.EINVAL
	}
	_, _, protocol, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid {
		return syscall.EINVAL
	}
	if len(payload) > 65535-8 {
		return syscall.EMSGSIZE
	}
	body := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(body[:2], identifier)
	binary.BigEndian.PutUint16(body[2:4], sequence)
	copy(body[4:], payload)
	messageType := uint8(ICMPv4TypeEchoReply)
	if request {
		messageType = ICMPv4TypeEchoRequest
	}
	if protocol == ProtocolICMPv6 {
		messageType = ICMPv6TypeEchoReply
		if request {
			messageType = ICMPv6TypeEchoRequest
		}
	}
	m.Type, m.Code, m.Body = messageType, ICMPCodeNone, body
	return nil
}

// EchoReply returns the semantic Echo Reply corresponding to m, using source
// as the reply source address. An explicit source is required because a request
// destination may be multicast, broadcast, or anycast and source selection
// requires IP routing state. The source argument must be an unzoned address in
// m's address family, but its ownership and address classification are not
// checked. Body aliases m.Body; MarshalBinary or AppendBinary calculates the
// reply checksum.
func (m ICMPMessage) EchoReply(source netip.Addr) (ICMPMessage, error) {
	normalized, _, err := m.wireLayout()
	if err != nil {
		return ICMPMessage{}, err
	}
	if !normalized.IsEchoRequest() || source.Zone() != "" {
		return ICMPMessage{}, syscall.EINVAL
	}
	source = source.Unmap()
	if !source.IsValid() || source.Is4() != normalized.Source.Is4() {
		return ICMPMessage{}, syscall.EINVAL
	}
	normalized.Destination = normalized.Source
	normalized.Source = source
	normalized.Type = ICMPv4TypeEchoReply
	if source.Is6() {
		normalized.Type = ICMPv6TypeEchoReply
	}
	return normalized, nil
}

// IsError reports whether m has a supported, family-appropriate ICMP error
// type and code. It classifies the message without parsing its quoted packet;
// ICMPError performs complete quote validation.
func (m ICMPMessage) IsError() bool {
	_, _, protocol, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid {
		return false
	}
	return validICMPErrorCode(protocol, m.Type, m.Code)
}

// ICMPError validates and decodes m as a supported ICMP error. QuotedPacket
// and QuotedPayload borrow m.Body, and available TCP or UDP ports are populated
// immediately. The parser accepts the intentionally truncated quotations that
// RFC 792 and RFC 4443 permit and does not apply socket-correlation policy.
func (m ICMPMessage) ICMPError() (ICMPError, error) {
	normalized, _, err := m.wireLayout()
	if err != nil {
		return ICMPError{}, err
	}
	protocol := byte(ProtocolICMPv4)
	if normalized.Source.Is6() {
		protocol = ProtocolICMPv6
	}
	result, valid := parseICMPErrorFields(normalized.Source, protocol, normalized.Type, normalized.Code, normalized.Body)
	if !valid {
		return ICMPError{}, syscall.EINVAL
	}
	return result, nil
}

// MarshalBinary returns the complete ICMP message wire encoding. Source and
// Destination select the family and contribute to the ICMPv6 pseudo-header
// checksum but are not themselves encoded. MarshalBinary is semantically
// identical to AppendBinary(nil).
func (m ICMPMessage) MarshalBinary() ([]byte, error) { return m.AppendBinary(nil) }

// AppendBinary appends the complete ICMP message wire encoding to dst. Source
// and Destination select the family and contribute to the ICMPv6 pseudo-header
// checksum but are not themselves encoded. It validates every field before
// changing dst, does not retain any input slice, and permits the destination
// to share backing storage with Body. On validation failure it returns the
// original dst unchanged.
func (m ICMPMessage) AppendBinary(dst []byte) ([]byte, error) {
	normalized, totalSize, err := m.wireLayout()
	if err != nil {
		return dst, err
	}
	start := len(dst)
	dst = extendForAppend(dst, totalSize)
	marshalPublicICMPMessage(dst[start:], normalized)
	return dst, nil
}

// wireLayout validates m, normalizes its addresses, and returns its exact
// message length.
func (m ICMPMessage) wireLayout() (ICMPMessage, int, error) {
	source, destination, _, valid := normalizeICMPAddresses(m.Source, m.Destination)
	if !valid {
		return ICMPMessage{}, 0, syscall.EINVAL
	}
	m.Source, m.Destination = source, destination
	if len(m.Body) < 4 {
		return ICMPMessage{}, 0, syscall.EINVAL
	}
	if len(m.Body) > 65535-4 {
		return ICMPMessage{}, 0, syscall.EMSGSIZE
	}
	return m, 4 + len(m.Body), nil
}

// marshalPublicICMPMessage writes one already validated semantic message.
func marshalPublicICMPMessage(dst []byte, m ICMPMessage) {
	copy(dst[4:], m.Body)
	dst[0], dst[1], dst[2], dst[3] = m.Type, m.Code, 0, 0
	value := checksum(dst)
	if m.Source.Is6() {
		value = transportChecksum(m.Source, m.Destination, ProtocolICMPv6, dst)
	}
	binary.BigEndian.PutUint16(dst[2:4], value)
}

// ICMPError describes a validated remote network error.
type ICMPError struct {
	// Reporter is the router or destination that generated the error.
	Reporter netip.Addr
	// Type is the wire ICMP error type.
	Type byte
	// Code retains the wire subtype within Type.
	Code byte
	// MTU is present for fragmentation-needed and packet-too-big errors. It is
	// also consumed by ICMPError.ICMPMessage when the error type defines that
	// field.
	MTU uint32
	// Pointer is present for IPv4 or IPv6 Parameter Problem errors. It is also
	// consumed by ICMPError.ICMPMessage when the error type defines that field.
	Pointer uint32
	// QuotedSource is the source of the failed original packet. It is derived
	// from QuotedPacket and ignored by ICMPError.ICMPMessage.
	QuotedSource netip.Addr
	// QuotedTarget is the destination of the failed original packet. It is
	// derived from QuotedPacket and ignored by ICMPError.ICMPMessage.
	QuotedTarget netip.Addr
	// QuotedProtocol is the final protocol identified in the available quote.
	// It is derived from QuotedPacket and ignored by ICMPError.ICMPMessage.
	QuotedProtocol byte
	// QuotedPacket contains the available original IP packet, including its IP
	// header. ICMPError.ICMPMessage copies it into the constructed error.
	// QuotedPayload aliases its upper-layer suffix when both are present.
	QuotedPacket []byte
	// QuotedPayload contains the available original transport header bytes. It
	// is derived from QuotedPacket and ignored by ICMPError.ICMPMessage.
	QuotedPayload []byte
	// QuotedSourcePort is the original TCP or UDP source port when present. It is
	// derived from QuotedPacket and ignored by ICMPError.ICMPMessage.
	QuotedSourcePort uint16
	// QuotedTargetPort is the original TCP or UDP destination port when present.
	// It is derived from QuotedPacket and ignored by ICMPError.ICMPMessage.
	QuotedTargetPort uint16
}

// ICMPMessage constructs the semantic ICMP error represented by e for
// destination. Reporter and destination select the address family; Type, Code,
// MTU, Pointer, and QuotedPacket provide the wire fields. It validates the
// possibly truncated quote, copies QuotedPacket, and ignores the fields derived
// from that quote. Routing, source ownership, rate limits, quote truncation,
// and recursive-error suppression remain Stack transmission policy.
func (e ICMPError) ICMPMessage(destination netip.Addr) (ICMPMessage, error) {
	reporter, destination, protocol, valid := normalizeICMPAddresses(e.Reporter, destination)
	if !valid || !validICMPErrorCode(protocol, e.Type, e.Code) {
		return ICMPMessage{}, syscall.EINVAL
	}
	if len(e.QuotedPacket) > 65535-8 {
		return ICMPMessage{}, syscall.EMSGSIZE
	}
	quotedSource, quotedTarget, _, _, quoted := quotedIPPayload(e.QuotedPacket)
	if !quoted || protocol == ProtocolICMPv4 && (!quotedSource.Is4() || !quotedTarget.Is4()) ||
		protocol == ProtocolICMPv6 && (!quotedSource.Is6() || !quotedTarget.Is6()) {
		return ICMPMessage{}, syscall.EINVAL
	}
	mtuField := protocol == ProtocolICMPv4 && e.Type == ICMPv4TypeDestinationUnreachable && e.Code == ICMPv4DestinationUnreachableCodeFragmentationNeeded ||
		protocol == ProtocolICMPv6 && e.Type == ICMPv6TypePacketTooBig
	pointerField := protocol == ProtocolICMPv4 && e.Type == ICMPv4TypeParameterProblem ||
		protocol == ProtocolICMPv6 && e.Type == ICMPv6TypeParameterProblem
	if !mtuField && e.MTU != 0 || !pointerField && e.Pointer != 0 ||
		protocol == ProtocolICMPv4 && mtuField && e.MTU > 1<<16-1 ||
		protocol == ProtocolICMPv4 && pointerField && e.Pointer > 1<<8-1 {
		return ICMPMessage{}, syscall.EINVAL
	}
	body := make([]byte, 4+len(e.QuotedPacket))
	if mtuField {
		if protocol == ProtocolICMPv4 {
			binary.BigEndian.PutUint16(body[2:4], uint16(e.MTU))
		} else {
			binary.BigEndian.PutUint32(body, e.MTU)
		}
	} else if pointerField {
		if protocol == ProtocolICMPv4 {
			body[0] = byte(e.Pointer)
		} else {
			binary.BigEndian.PutUint32(body, e.Pointer)
		}
	}
	copy(body[4:], e.QuotedPacket)
	return ICMPMessage{Source: reporter, Destination: destination, Type: e.Type, Code: e.Code, Body: body}, nil
}

// normalizeICMPAddresses validates and normalizes the address-family context
// shared by the public ICMP codecs.
func normalizeICMPAddresses(source, destination netip.Addr) (netip.Addr, netip.Addr, byte, bool) {
	if source.Zone() != "" || destination.Zone() != "" {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	source, destination = source.Unmap(), destination.Unmap()
	if !source.IsValid() || !destination.IsValid() || source.Is4() != destination.Is4() {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	if source.Is4() {
		return source, destination, ProtocolICMPv4, true
	}
	return source, destination, ProtocolICMPv6, true
}

// icmpForwarderIPPacket is one caller-owned, normalized header-included ICMP
// reply. parsed and ipv6Fragment describe slices within packet.
type icmpForwarderIPPacket struct {
	packet       []byte
	parsed       ipPacket
	ipv4DF       bool
	ipv6Fragment ipv6ForwarderFragmentPoint
}

// validateICMPForwarderReplyPayload applies the ICMP message and address-family
// size limits. RFC 4443 requires an ICMPv6 error to fit the 1280-byte minimum
// IPv6 MTU even when informational messages may use source fragmentation.
func validateICMPForwarderReplyPayload(ipv6 bool, payload []byte) error {
	if len(payload) < 8 {
		return syscall.EINVAL
	}
	maximum := 65535
	if !ipv6 {
		maximum -= 20
	}
	if len(payload) > maximum {
		return syscall.EMSGSIZE
	}
	if ipv6 && payload[0] < 128 && len(payload) > ipv6MinimumMTU-40 {
		return syscall.EMSGSIZE
	}
	return nil
}

// prepareICMPForwarderIPPacket validates and normalizes a restricted raw ICMP
// reply without consulting mutable stack state. The input is copied before any
// field is changed.
func prepareICMPForwarderIPPacket(input []byte, destination netip.Addr) (icmpForwarderIPPacket, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || len(input) == 0 {
		return icmpForwarderIPPacket{}, syscall.EINVAL
	}
	switch input[0] >> 4 {
	case 4:
		if len(input) > 65535 {
			return icmpForwarderIPPacket{}, syscall.EMSGSIZE
		}
	case 6:
		if len(input)-40 > 65535 {
			return icmpForwarderIPPacket{}, syscall.EMSGSIZE
		}
	default:
		return icmpForwarderIPPacket{}, syscall.EINVAL
	}
	packet := append([]byte(nil), input...)
	result := icmpForwarderIPPacket{packet: packet}
	switch packet[0] >> 4 {
	case 4:
		if destination.Is6() || len(packet) < 28 || len(packet) > 65535 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		headerSize := int(packet[0]&0x0f) * 4
		field := binary.BigEndian.Uint16(packet[6:8])
		if headerSize < 20 || headerSize > len(packet)-8 || field&0xbfff != 0 || packet[9] != ProtocolICMPv4 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		contentSize, validOptions := ipv4OptionsContentLength(packet[20:headerSize])
		if !validOptions {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		for index := 20 + contentSize; index < headerSize; index++ {
			packet[index] = 0
		}
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerSize]))
		result.ipv4DF = field&0x4000 != 0
	case 6:
		if destination.Is4() || len(packet) < 48 || len(packet)-40 > 65535 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		point, ok := inspectIPv6ForwarderFragmentPoint(packet)
		if !ok {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		result.ipv6Fragment = point
		if point.atomicOffset >= 0 {
			// Reserved bits are ignored by receivers but must be zero in output.
			packet[point.atomicOffset+1] = 0
			binary.BigEndian.PutUint16(packet[point.atomicOffset+2:point.atomicOffset+4], 0)
		}
	default:
		return icmpForwarderIPPacket{}, syscall.EINVAL
	}
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.parameterError || len(parsed.payload) < 8 || parsed.target != destination {
		return icmpForwarderIPPacket{}, syscall.EINVAL
	}
	if parsed.source.Is4() {
		if parsed.protocol != ProtocolICMPv4 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		parsed.payload[2], parsed.payload[3] = 0, 0
		binary.BigEndian.PutUint16(parsed.payload[2:4], checksum(parsed.payload))
	} else {
		if parsed.protocol != ProtocolICMPv6 {
			return icmpForwarderIPPacket{}, syscall.EINVAL
		}
		// RFC 4443 requires every ICMPv6 error to fit the 1280-byte minimum
		// IPv6 MTU. Informational messages may still use source fragmentation.
		if parsed.payload[0] < 128 && len(packet) > ipv6MinimumMTU {
			return icmpForwarderIPPacket{}, syscall.EMSGSIZE
		}
		parsed.payload[2], parsed.payload[3] = 0, 0
		binary.BigEndian.PutUint16(parsed.payload[2:4], transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload))
	}
	result.parsed = parsed
	return result, nil
}

// writeICMPForwarderIPPacket revalidates interception and return routing,
// applies current PMTU state, and atomically enqueues the normalized
// header-included packet or all of its fragments.
func (s *Stack) writeICMPForwarderIPPacket(request ipPacket, reply icmpForwarderIPPacket) error {
	state := s.network.Load()
	if !state.acceptsInboundDestination(request.target) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(reply.parsed.target); !routed {
		return syscall.ENETUNREACH
	}
	packets, err := s.icmpForwarderIPPackets(reply, s.mtuFor(reply.parsed.target))
	if err != nil {
		return err
	}
	return s.tryWritePackets(packets)
}

// Error formats the remote ICMP failure.
func (e ICMPError) Error() string {
	if e.MTU != 0 {
		return fmt.Sprintf("ICMP error from %s: type=%d code=%d mtu=%d", e.Reporter, e.Type, e.Code, e.MTU)
	}
	return fmt.Sprintf("ICMP error from %s: type=%d code=%d", e.Reporter, e.Type, e.Code)
}

// isICMPEchoRequest reports whether payload is one complete Echo Request for
// the supplied ICMP address family.
func isICMPEchoRequest(protocol byte, payload []byte) bool {
	if len(payload) < 8 || payload[1] != ICMPCodeNone {
		return false
	}
	switch protocol {
	case ProtocolICMPv4:
		return payload[0] == ICMPv4TypeEchoRequest
	case ProtocolICMPv6:
		return payload[0] == ICMPv6TypeEchoRequest
	default:
		return false
	}
}

// makeICMPEchoReply copies one Echo Request into an Echo Reply with a cleared
// checksum. The caller owns the returned payload and must calculate the
// address-family checksum before transmission.
func makeICMPEchoReply(protocol byte, request []byte) ([]byte, bool) {
	if !isICMPEchoRequest(protocol, request) {
		return nil, false
	}
	replyType := byte(ICMPv4TypeEchoReply)
	if protocol == ProtocolICMPv6 {
		replyType = ICMPv6TypeEchoReply
	}
	reply := append([]byte(nil), request...)
	reply[0], reply[2], reply[3] = replyType, 0, 0
	return reply, true
}

// handleICMP replies to owned-address echo requests, dispatches validated
// asynchronous errors, and offers otherwise unhandled messages to the ICMP
// forwarder.
func (s *Stack) handleICMP(packet ipPacket, localDestination bool) error {
	icmp := packet.payload
	if len(icmp) < 8 {
		return nil
	}
	if packet.protocol == ProtocolICMPv4 {
		if checksum(icmp) != 0 {
			return nil
		}
		if localDestination {
			if reply, echoRequest := makeICMPEchoReply(packet.protocol, icmp); echoRequest {
				if !s.allowControlResponse(controlResponseEchoReply) {
					return nil
				}
				binary.BigEndian.PutUint16(reply[2:4], checksum(reply))
				_ = s.writeIPPayload(packet.target, packet.source, ProtocolICMPv4, reply, true)
				return nil
			}
		}
	} else {
		if localDestination {
			if reply, echoRequest := makeICMPEchoReply(packet.protocol, icmp); echoRequest {
				if !s.allowControlResponse(controlResponseEchoReply) {
					return nil
				}
				binary.BigEndian.PutUint16(reply[2:4], transportChecksum(packet.target, packet.source, ProtocolICMPv6, reply))
				_ = s.writeIPPayload(packet.target, packet.source, ProtocolICMPv6, reply, true)
				return nil
			}
		}
	}
	remoteError, ok := parseICMPError(packet)
	if ok && s.deliverICMPError(remoteError) {
		return nil
	}
	s.mu.RLock()
	forwarder := s.icmpForwarder
	s.mu.RUnlock()
	if forwarder != nil && forwarder.handlePacket(packet) {
		return nil
	}
	return nil
}

// handleMulticastICMPv6 implements RFC 4443's Echo exception. The reply uses
// a unicast interface address rather than the request's multicast target.
func (s *Stack) handleMulticastICMPv6(packet ipPacket) error {
	icmp := packet.payload
	if len(icmp) < 8 {
		return nil
	}
	reply, echoRequest := makeICMPEchoReply(ProtocolICMPv6, icmp)
	if !echoRequest || !s.allowControlResponse(controlResponseEchoReply) {
		return nil
	}
	source, err := s.sourceForRequested(packet.source, netip.Addr{})
	if err != nil {
		return nil
	}
	binary.BigEndian.PutUint16(reply[2:4], transportChecksum(source, packet.source, ProtocolICMPv6, reply))
	_ = s.writeIPPayload(source, packet.source, ProtocolICMPv6, reply, true)
	return nil
}

// deliverICMPError correlates one validated network error with an ordinary or
// forwarded socket. It reports whether a transport or raw endpoint accepted
// the error.
func (s *Stack) deliverICMPError(remoteError ICMPError) bool {
	accepted := false
	switch remoteError.QuotedProtocol {
	case ProtocolUDP:
		if len(remoteError.QuotedPayload) >= udpHeaderSize {
			sourcePort := remoteError.QuotedSourcePort
			targetPort := remoteError.QuotedTargetPort
			local := netip.AddrPortFrom(remoteError.QuotedSource, sourcePort)
			target := netip.AddrPortFrom(remoteError.QuotedTarget, targetPort)
			s.mu.RLock()
			var connection *UDPConn
			if s.isLocal(remoteError.QuotedSource) {
				connection = s.udpConnectionLocked(local, target)
			} else {
				connection = s.udpForwardedConnectionLocked(local, target)
			}
			s.mu.RUnlock()
			if connection != nil && connection.acceptsLocal(remoteError.QuotedSource) && connection.acceptsError(target) {
				if remoteError.MTU != 0 && connection.acceptsPathMTU() {
					if s.observePathMTU(remoteError.QuotedTarget, remoteError.MTU) {
						s.notifyTCPPathMTU(remoteError.QuotedTarget, nil)
					}
				}
				connection.deliverError(target, cloneICMPError(remoteError))
				accepted = true
			}
		}
	case ProtocolTCP:
		if len(remoteError.QuotedPayload) >= 8 {
			sourcePort := remoteError.QuotedSourcePort
			targetPort := remoteError.QuotedTargetPort
			key := tcpKey{
				local:  netip.AddrPortFrom(remoteError.QuotedSource, sourcePort),
				remote: netip.AddrPortFrom(remoteError.QuotedTarget, targetPort),
			}
			s.mu.RLock()
			connection := s.tcp[key]
			s.mu.RUnlock()
			if connection != nil && connection.acceptsICMPQuote(remoteError.QuotedPayload) {
				if remoteError.MTU != 0 {
					if s.observePathMTU(remoteError.QuotedTarget, remoteError.MTU) {
						s.notifyTCPPathMTU(remoteError.QuotedTarget, nil)
					}
				}
				connection.deliverError(cloneICMPError(remoteError))
				accepted = true
			}
		}
	}
	if s.isLocal(remoteError.QuotedSource) {
		s.mu.RLock()
		raw := s.ip
		s.mu.RUnlock()
		if raw != nil && raw.deliverError(s, remoteError) {
			accepted = true
		}
	}
	return accepted
}

// writeICMPReply emits a handler-supplied complete ICMP message in the reverse
// direction after repairing its checksum.
func (s *Stack) writeICMPReply(packet ipPacket, payload []byte) error {
	if len(payload) < 8 {
		return syscall.EINVAL
	}
	return s.writeOwnedICMPReply(packet, append([]byte(nil), payload...))
}

// writeOwnedICMPReply repairs and emits a caller-owned payload that may be
// modified in place. It avoids copying replies constructed inside the stack.
func (s *Stack) writeOwnedICMPReply(packet ipPacket, reply []byte) error {
	if err := validateICMPForwarderReplyPayload(packet.source.Is6(), reply); err != nil {
		return err
	}
	state := s.network.Load()
	if _, routed := state.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	if !state.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	reply[2], reply[3] = 0, 0
	if packet.source.Is4() {
		binary.BigEndian.PutUint16(reply[2:4], checksum(reply))
		return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv4, reply, true)
	}
	binary.BigEndian.PutUint16(reply[2:4], transportChecksum(packet.target, packet.source, ProtocolICMPv6, reply))
	return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv6, reply, true)
}

// sendAdministrativeUnreachable rejects a handler-supplied ICMP request when
// RFC 792 or RFC 4443 permits an error response.
func (s *Stack) sendAdministrativeUnreachable(packet ipPacket) error {
	state := s.network.Load()
	if !state.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	if packetInvokesICMPError(packet.original) {
		return nil
	}
	if _, routed := state.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	if !s.allowControlResponse(controlResponsePortUnreachable) {
		return nil
	}
	quoteLength := len(packet.original)
	if packet.source.Is4() {
		header := int(packet.original[0]&0x0f) * 4
		if quoteLength > header+8 {
			quoteLength = header + 8
		}
		icmp := make([]byte, 8+quoteLength)
		icmp[0], icmp[1] = ICMPv4TypeDestinationUnreachable, ICMPv4DestinationUnreachableCodeCommunicationAdministrativelyProhibited
		copy(icmp[8:], packet.original[:quoteLength])
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv4, icmp, false)
	}
	maximumQuote := ipv6MinimumMTU - 48
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	icmp := make([]byte, 8+quoteLength)
	icmp[0], icmp[1] = ICMPv6TypeDestinationUnreachable, ICMPv6DestinationUnreachableCodeAdministrativelyProhibited
	copy(icmp[8:], packet.original[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(packet.target, packet.source, ProtocolICMPv6, icmp))
	return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv6, icmp, false)
}

// sendFragmentReassemblyTimeout reports an expired datagram when its first
// fragment was available. RFC 792 and RFC 4443 prohibit recursively reporting
// another ICMP error, while RFC 4443 also caps the complete IPv6 error at the
// minimum IPv6 MTU.
func (s *Stack) sendFragmentReassemblyTimeout(set *fragmentSet) error {
	if !s.isLocal(set.target) {
		return nil
	}
	fragment, ok := parseFragment(set.firstPacket)
	if !ok || fragment.offset != 0 || packetInvokesICMPError(set.firstPacket) || !s.allowControlResponse(controlResponseFragmentTimeout) {
		return nil
	}
	quoteLength := len(set.firstPacket)
	if !set.v6 {
		headerSize := int(set.firstPacket[0]&0x0f) * 4
		if quoteLength > headerSize+8 {
			quoteLength = headerSize + 8
		}
		icmp := make([]byte, 8+quoteLength)
		icmp[0], icmp[1] = ICMPv4TypeTimeExceeded, ICMPv4TimeExceededCodeFragmentReassembly
		copy(icmp[8:], set.firstPacket[:quoteLength])
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(set.target, set.source, ProtocolICMPv4, icmp, false)
	}
	maximumQuote := ipv6MinimumMTU - 48
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	icmp := make([]byte, 8+quoteLength)
	icmp[0], icmp[1] = ICMPv6TypeTimeExceeded, ICMPv6TimeExceededCodeFragmentReassembly
	copy(icmp[8:], set.firstPacket[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(set.target, set.source, ProtocolICMPv6, icmp))
	return s.writeIPPayload(set.target, set.source, ProtocolICMPv6, icmp, false)
}

// packetInvokesICMPError follows a complete or first-fragment header chain
// and applies the RFC 792/RFC 4443 recursive-error suppression rule.
func packetInvokesICMPError(packet []byte) bool {
	_, _, protocol, payload, ok := quotedIPPayload(packet)
	if !ok || len(payload) == 0 {
		return false
	}
	if protocol == ProtocolICMPv6 {
		return payload[0] < 128
	}
	if protocol == ProtocolICMPv4 {
		switch payload[0] {
		case ICMPv4TypeDestinationUnreachable, 4, 5, ICMPv4TypeTimeExceeded, ICMPv4TypeParameterProblem:
			return true
		}
	}
	return false
}

// parseICMPError extracts the quoted original packet from an ICMP error.
func parseICMPError(packet ipPacket) (ICMPError, bool) {
	icmp := packet.payload
	if len(icmp) < 8 {
		return ICMPError{}, false
	}
	return parseICMPErrorFields(packet.source, packet.protocol, icmp[0], icmp[1], icmp[4:])
}

// parseICMPErrorFields extracts a transport-relevant quoted packet from the
// semantic fields shared by the public codec and the stack receive path.
func parseICMPErrorFields(reporter netip.Addr, protocol, messageType, code byte, body []byte) (ICMPError, bool) {
	if len(body) < 4 || !validICMPErrorCode(protocol, messageType, code) {
		return ICMPError{}, false
	}
	quote := body[4:]
	source, target, quotedProtocol, payload, ok := quotedIPPayload(quote)
	if !ok || protocol == ProtocolICMPv4 && (!source.Is4() || !target.Is4()) ||
		protocol == ProtocolICMPv6 && (!source.Is6() || !target.Is6()) {
		return ICMPError{}, false
	}
	if protocol != ProtocolICMPv4 && protocol != ProtocolICMPv6 {
		return ICMPError{}, false
	}
	result := ICMPError{
		Reporter: reporter, Type: messageType, Code: code,
		QuotedSource: source, QuotedTarget: target, QuotedProtocol: quotedProtocol,
		QuotedPacket: quote, QuotedPayload: payload,
	}
	if (quotedProtocol == ProtocolTCP || quotedProtocol == ProtocolUDP) && len(payload) >= 4 {
		result.QuotedSourcePort = binary.BigEndian.Uint16(payload[:2])
		result.QuotedTargetPort = binary.BigEndian.Uint16(payload[2:4])
	}
	if protocol == ProtocolICMPv4 {
		if messageType == ICMPv4TypeDestinationUnreachable && code == ICMPv4DestinationUnreachableCodeFragmentationNeeded {
			result.MTU = uint32(binary.BigEndian.Uint16(body[2:4]))
			if result.MTU == 0 {
				result.MTU = legacyIPv4PathMTU(quote)
			}
		}
		if messageType == ICMPv4TypeParameterProblem {
			result.Pointer = uint32(body[0])
		}
	} else {
		if messageType == ICMPv6TypePacketTooBig {
			result.MTU = binary.BigEndian.Uint32(body[:4])
		}
		if messageType == ICMPv6TypeParameterProblem {
			result.Pointer = binary.BigEndian.Uint32(body[:4])
		}
	}
	return result, true
}

// cloneICMPError gives one queued consumer independent ownership while keeping
// QuotedPayload as a suffix of QuotedPacket whenever the parsed error did so.
func cloneICMPError(networkError ICMPError) ICMPError {
	if len(networkError.QuotedPacket) != 0 && len(networkError.QuotedPayload) == 0 {
		networkError.QuotedPacket = append([]byte(nil), networkError.QuotedPacket...)
		return networkError
	}
	if len(networkError.QuotedPacket) != 0 && len(networkError.QuotedPayload) <= len(networkError.QuotedPacket) {
		payloadOffset := len(networkError.QuotedPacket) - len(networkError.QuotedPayload)
		if &networkError.QuotedPayload[0] == &networkError.QuotedPacket[payloadOffset] {
			networkError.QuotedPacket = append([]byte(nil), networkError.QuotedPacket...)
			networkError.QuotedPayload = networkError.QuotedPacket[payloadOffset:]
			return networkError
		}
	}
	networkError.QuotedPacket = append([]byte(nil), networkError.QuotedPacket...)
	networkError.QuotedPayload = append([]byte(nil), networkError.QuotedPayload...)
	return networkError
}

// validICMPErrorCode rejects unsupported or unassigned type/code combinations
// before they can affect a socket or the path-MTU cache.
func validICMPErrorCode(protocol, messageType, code byte) bool {
	switch protocol {
	case ProtocolICMPv4:
		switch messageType {
		case ICMPv4TypeDestinationUnreachable:
			return code <= ICMPv4DestinationUnreachableCodePrecedenceCutoff
		case ICMPv4TypeTimeExceeded:
			return code <= ICMPv4TimeExceededCodeFragmentReassembly
		case ICMPv4TypeParameterProblem:
			return code <= ICMPv4ParameterProblemCodeBadLength
		}
	case ProtocolICMPv6:
		switch messageType {
		case ICMPv6TypeDestinationUnreachable:
			// RFC 8883 code 8 requires an RFC 4884 extension object that
			// ICMPError does not yet model. RFC 9914 code 9 retains the
			// ordinary Destination Unreachable body and is fully representable.
			return code <= ICMPv6DestinationUnreachableCodeSourceRoutingHeader || code == ICMPv6DestinationUnreachableCodePRoute
		case ICMPv6TypePacketTooBig:
			return code == ICMPCodeNone
		case ICMPv6TypeTimeExceeded:
			return code <= ICMPv6TimeExceededCodeFragmentReassembly
		case ICMPv6TypeParameterProblem:
			// RFC 7112 assigns code 3, RFC 8754 assigns code 4, and RFC
			// 8883 assigns the processing-limit errors from code 5 through 10.
			return code <= ICMPv6ParameterProblemCodeOptionTooBig
		}
	}
	return false
}

// legacyIPv4PathMTU infers the next RFC 1191 plateau when an old router emits
// Fragmentation Needed without the next-hop MTU field.
func legacyIPv4PathMTU(quoted []byte) uint32 {
	if len(quoted) < 20 || quoted[0]>>4 != 4 {
		return 0
	}
	total := uint32(binary.BigEndian.Uint16(quoted[2:4]))
	headerSize := uint32(quoted[0]&0x0f) * 4
	if headerSize < 20 || total < headerSize {
		return 0
	}
	for _, plateau := range [...]uint32{65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68} {
		if plateau < total {
			return plateau
		}
	}
	return 68
}

// quotedIPPayload parses a possibly truncated packet embedded in an ICMP
// error without requiring its original total length.
func quotedIPPayload(packet []byte) (netip.Addr, netip.Addr, byte, []byte, bool) {
	if len(packet) < 1 {
		return netip.Addr{}, netip.Addr{}, 0, nil, false
	}
	if packet[0]>>4 == 4 {
		if len(packet) < 20 {
			return netip.Addr{}, netip.Addr{}, 0, nil, false
		}
		headerSize := int(packet[0]&0x0f) * 4
		if headerSize < 20 || headerSize > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 {
			return netip.Addr{}, netip.Addr{}, 0, nil, false
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), packet[9], packet[headerSize:], true
	}
	if packet[0]>>4 == 6 && len(packet) >= 40 {
		source := netip.AddrFrom16([16]byte(packet[8:24]))
		target := netip.AddrFrom16([16]byte(packet[24:40]))
		if source.Is4In6() || target.Is4In6() {
			return netip.Addr{}, netip.Addr{}, 0, nil, false
		}
		next, offset := packet[6], 40
		for offset <= len(packet) {
			if next == ProtocolNoNextHeader {
				return source, target, next, nil, true
			}
			switch next {
			case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
				IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderAuthentication,
				IPv6ExtensionHeaderMobility:
				length, valid := ipv6ExtensionHeaderLength(next, packet[offset:])
				if !valid {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				next, offset = packet[offset], offset+length
			case IPv6ExtensionHeaderFragment:
				if len(packet)-offset < 8 {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				// A quoted first fragment is useful even when M is set. Only a
				// nonzero offset prevents transport correlation; RFC 8200's
				// reserved bits are ignored on reception.
				if binary.BigEndian.Uint16(packet[offset+2:offset+4])&0xfff8 != 0 {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				next, offset = packet[offset], offset+8
			default:
				return source, target, next, packet[offset:], true
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, 0, nil, false
}

// sendPortUnreachable rejects a valid UDP datagram with no local socket.
func (s *Stack) sendPortUnreachable(packet ipPacket) error {
	state := s.network.Load()
	if !state.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	if !s.allowControlResponse(controlResponsePortUnreachable) {
		return nil
	}
	quoteLength := len(packet.original)
	if packet.source.Is4() {
		header := int(packet.original[0]&0x0f) * 4
		if quoteLength > header+8 {
			quoteLength = header + 8
		}
		quote := packet.original[:quoteLength]
		icmp := make([]byte, 8+len(quote))
		icmp[0], icmp[1] = ICMPv4TypeDestinationUnreachable, ICMPv4DestinationUnreachableCodePort
		copy(icmp[8:], quote)
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv4, icmp, false)
	}
	maximumQuote := ipv6MinimumMTU - 48
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	quote := packet.original[:quoteLength]
	icmp := make([]byte, 8+len(quote))
	icmp[0], icmp[1] = ICMPv6TypeDestinationUnreachable, ICMPv6DestinationUnreachableCodePort
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(packet.target, packet.source, ProtocolICMPv6, icmp))
	return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv6, icmp, false)
}

// sendProtocolUnreachable rejects a valid packet whose upper-layer protocol
// has no endpoint handler. IPv6 identifies the unrecognized Next Header field.
func (s *Stack) sendProtocolUnreachable(packet ipPacket) error {
	state := s.network.Load()
	if !state.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	if !s.allowControlResponse(controlResponseParameterProblem) {
		return nil
	}
	if packet.source.Is4() {
		header := int(packet.original[0]&0x0f) * 4
		quoteLength := len(packet.original)
		if quoteLength > header+8 {
			quoteLength = header + 8
		}
		icmp := make([]byte, 8+quoteLength)
		icmp[0], icmp[1] = ICMPv4TypeDestinationUnreachable, ICMPv4DestinationUnreachableCodeProtocol
		copy(icmp[8:], packet.original[:quoteLength])
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv4, icmp, false)
	}
	maximumQuote := ipv6MinimumMTU - 48
	quoteLength := len(packet.original)
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	icmp := make([]byte, 8+quoteLength)
	icmp[0], icmp[1] = ICMPv6TypeParameterProblem, ICMPv6ParameterProblemCodeUnrecognizedNextHeader
	binary.BigEndian.PutUint32(icmp[4:8], uint32(packet.protocolOffset))
	copy(icmp[8:], packet.original[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(packet.target, packet.source, ProtocolICMPv6, icmp))
	return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv6, icmp, false)
}

// sendParameterProblem reports a malformed IPv4 option or an IPv6 field whose
// action requires an ICMP error. The pointer is an absolute byte offset.
func (s *Stack) sendParameterProblem(packet ipPacket) error {
	if !packet.source.Is4() && !packet.source.Is6() {
		return nil
	}
	if packet.source.Is4() {
		if len(packet.original) < 20 || binary.BigEndian.Uint16(packet.original[6:8])&0x1fff != 0 {
			return nil
		}
		if packetInvokesICMPError(packet.original) || !s.allowControlResponse(controlResponseParameterProblem) {
			return nil
		}
		header := int(packet.original[0]&0x0f) * 4
		quoteLength := len(packet.original)
		if quoteLength > header+8 {
			quoteLength = header + 8
		}
		icmp := make([]byte, 8+quoteLength)
		icmp[0], icmp[1], icmp[4] = ICMPv4TypeParameterProblem, packet.parameterCode, byte(packet.parameterAt)
		copy(icmp[8:], packet.original[:quoteLength])
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv4, icmp, false)
	}
	if packetInvokesICMPError(packet.original) || !s.allowControlResponse(controlResponseParameterProblem) {
		return nil
	}
	maximumQuote := ipv6MinimumMTU - 48
	quoteLength := len(packet.original)
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	icmp := make([]byte, 8+quoteLength)
	icmp[0], icmp[1] = ICMPv6TypeParameterProblem, packet.parameterCode
	binary.BigEndian.PutUint32(icmp[4:8], packet.parameterAt)
	copy(icmp[8:], packet.original[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(packet.target, packet.source, ProtocolICMPv6, icmp))
	return s.writeIPPayload(packet.target, packet.source, ProtocolICMPv6, icmp, false)
}
