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
	// ICMPv6DestinationUnreachableCodeHeadersTooLong reports that processing could not continue because the IPv6 headers were too long.
	ICMPv6DestinationUnreachableCodeHeadersTooLong = 8
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

	// ICMPExtensionClassExtendedInformation identifies RFC 8883 Extended Information objects.
	ICMPExtensionClassExtendedInformation = 4
	// ICMPExtensionExtendedInformationTypePointer identifies an RFC 8883 Pointer object.
	ICMPExtensionExtendedInformationTypePointer = 1
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

// classifyICMPEcho is the family-aware Echo grammar shared by public semantic
// values, raw Stack input, and Forwarder snapshots.
func classifyICMPEcho(protocol, messageType, code byte, bodyLength int) (request, ok bool) {
	if bodyLength < 4 || code != ICMPCodeNone {
		return false, false
	}
	switch protocol {
	case ProtocolICMPv4:
		switch messageType {
		case ICMPv4TypeEchoRequest:
			return true, true
		case ICMPv4TypeEchoReply:
			return false, true
		}
	case ProtocolICMPv6:
		switch messageType {
		case ICMPv6TypeEchoRequest:
			return true, true
		case ICMPv6TypeEchoReply:
			return false, true
		}
	}
	return false, false
}

// icmpEchoMessageType returns the request or reply type for one address family.
func icmpEchoMessageType(ipv6, request bool) byte {
	if ipv6 {
		if request {
			return ICMPv6TypeEchoRequest
		}
		return ICMPv6TypeEchoReply
	}
	if request {
		return ICMPv4TypeEchoRequest
	}
	return ICMPv4TypeEchoReply
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
	if !valid {
		return false, false
	}
	return classifyICMPEcho(protocol, m.Type, m.Code, len(m.Body))
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
	messageType := icmpEchoMessageType(protocol == ProtocolICMPv6, request)
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
	normalized.Type = icmpEchoMessageType(source.Is6(), false)
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

// ICMPError validates and decodes m as a supported ICMP error. QuotedPacket,
// QuotedPayload, and Extensions borrow m.Body, and available TCP or UDP ports
// are populated immediately. The parser accepts the intentionally truncated
// quotations that RFC 792 and RFC 4443 permit and does not apply socket-
// correlation policy.
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

// ICMPExtensionObject is one RFC 4884 extension object in semantic wire order.
// Data excludes the four-byte object header. ExtensionObjects returns Data
// slices that borrow ICMPError.Extensions, while SetExtensionObjects copies
// every Data slice. Unknown classes and types, duplicates, and order are
// preserved.
type ICMPExtensionObject struct {
	// Class is the object's Class-Num.
	Class uint8
	// Type is the class-specific C-Type.
	Type uint8
	// Data is the object payload following Length, Class-Num, and C-Type.
	Data []byte
}

// Pointer returns the byte offset carried by an RFC 8883 Extended Information
// Pointer object.
func (o ICMPExtensionObject) Pointer() (uint32, bool) {
	if o.Class != ICMPExtensionClassExtendedInformation ||
		o.Type != ICMPExtensionExtendedInformationTypePointer || len(o.Data) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(o.Data), true
}

// SetPointer replaces o with an RFC 8883 Extended Information Pointer object.
func (o *ICMPExtensionObject) SetPointer(pointer uint32) {
	o.Class = ICMPExtensionClassExtendedInformation
	o.Type = ICMPExtensionExtendedInformationTypePointer
	o.Data = make([]byte, 4)
	binary.BigEndian.PutUint32(o.Data, pointer)
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
	// Extensions contains the encoded RFC 4884 extension-object sequence,
	// excluding the four-byte Extension Header. Parsed errors borrow the ICMP
	// message body. ICMPError.ICMPMessage validates and copies this storage.
	Extensions []byte
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

const (
	icmpExtensionVersion          = 2
	icmpExtensionHeaderSize       = 4
	icmpExtensionObjectHeaderSize = 4
	icmpExtensionMinimumQuoteSize = 128
	maximumICMPExtensionDataSize  = 65535 - 8 - icmpExtensionMinimumQuoteSize - icmpExtensionHeaderSize
)

// icmpExtensionObjectCursor shares object framing between the public parser
// and validation on the stack receive path without allocating descriptors.
type icmpExtensionObjectCursor struct {
	remaining []byte
}

// next returns one borrowed object. valid distinguishes the end of a valid
// sequence from malformed framing.
func (c *icmpExtensionObjectCursor) next() (object ICMPExtensionObject, ok, valid bool) {
	if len(c.remaining) == 0 {
		return ICMPExtensionObject{}, false, true
	}
	if len(c.remaining) < icmpExtensionObjectHeaderSize {
		return ICMPExtensionObject{}, false, false
	}
	length := int(binary.BigEndian.Uint16(c.remaining[:2]))
	if length < icmpExtensionObjectHeaderSize || length&3 != 0 || length > len(c.remaining) {
		return ICMPExtensionObject{}, false, false
	}
	object = ICMPExtensionObject{
		Class: c.remaining[2], Type: c.remaining[3],
		Data: c.remaining[icmpExtensionObjectHeaderSize:length],
	}
	c.remaining = c.remaining[length:]
	return object, true, true
}

// validateICMPExtensionObjects validates one nonempty object sequence and
// reports whether it contains an RFC 8883 Pointer object.
func validateICMPExtensionObjects(encoded []byte) (hasPointer, valid bool) {
	cursor := icmpExtensionObjectCursor{remaining: encoded}
	count := 0
	for {
		object, ok, framingValid := cursor.next()
		if !framingValid {
			return false, false
		}
		if !ok {
			return hasPointer, count != 0
		}
		count++
		if _, pointer := object.Pointer(); pointer {
			hasPointer = true
		}
	}
}

// ExtensionObjects parses the RFC 4884 object sequence. The returned slice
// owns its descriptors, but every Data field borrows e.Extensions. An error
// reports malformed object framing. An ICMPError with no extensions returns a
// nil slice and nil error.
func (e ICMPError) ExtensionObjects() ([]ICMPExtensionObject, error) {
	if len(e.Extensions) == 0 {
		return nil, nil
	}
	cursor := icmpExtensionObjectCursor{remaining: e.Extensions}
	objects := make([]ICMPExtensionObject, 0, 1)
	for {
		object, ok, valid := cursor.next()
		if !valid {
			return nil, syscall.EINVAL
		}
		if !ok {
			return objects, nil
		}
		objects = append(objects, object)
	}
}

// SetExtensionObjects replaces Extensions with an encoded RFC 4884 object
// sequence. Each Data length must be a multiple of four bytes. The method
// preserves unknown classes and types, duplicates, and order, copies every
// input Data slice, and leaves e unchanged on failure. An empty sequence clears
// Extensions; an encoded Extension Structure is generated only when at least
// one object is present.
func (e *ICMPError) SetExtensionObjects(objects []ICMPExtensionObject) error {
	if e == nil {
		return syscall.EINVAL
	}
	if len(objects) == 0 {
		e.Extensions = nil
		return nil
	}
	size := 0
	for _, object := range objects {
		if len(object.Data) > 1<<16-1-icmpExtensionObjectHeaderSize {
			return syscall.EMSGSIZE
		}
		if len(object.Data)&3 != 0 {
			return syscall.EINVAL
		}
		length := icmpExtensionObjectHeaderSize + len(object.Data)
		if size > maximumICMPExtensionDataSize-length {
			return syscall.EMSGSIZE
		}
		size += length
	}
	encoded := make([]byte, size)
	offset := 0
	for _, object := range objects {
		length := icmpExtensionObjectHeaderSize + len(object.Data)
		binary.BigEndian.PutUint16(encoded[offset:offset+2], uint16(length))
		encoded[offset+2], encoded[offset+3] = object.Class, object.Type
		copy(encoded[offset+icmpExtensionObjectHeaderSize:offset+length], object.Data)
		offset += length
	}
	e.Extensions = encoded
	return nil
}

// icmpErrorFieldKinds identifies the four-byte error-body fields whose wire
// layout is shared by public construction and Stack-generated control errors.
func icmpErrorFieldKinds(protocol, messageType, code byte) (mtu, pointer bool) {
	mtu = protocol == ProtocolICMPv4 && messageType == ICMPv4TypeDestinationUnreachable && code == ICMPv4DestinationUnreachableCodeFragmentationNeeded ||
		protocol == ProtocolICMPv6 && messageType == ICMPv6TypePacketTooBig
	pointer = protocol == ProtocolICMPv4 && messageType == ICMPv4TypeParameterProblem ||
		protocol == ProtocolICMPv6 && messageType == ICMPv6TypeParameterProblem
	return
}

// marshalICMPErrorBody writes the four type-specific bytes and quoted packet
// after validation by the public constructor or selection by Stack policy.
func marshalICMPErrorBody(body []byte, protocol, messageType, code byte, mtu, pointer uint32, quote []byte) {
	body[0], body[1], body[2], body[3] = 0, 0, 0, 0
	mtuField, pointerField := icmpErrorFieldKinds(protocol, messageType, code)
	if mtuField {
		if protocol == ProtocolICMPv4 {
			binary.BigEndian.PutUint16(body[2:4], uint16(mtu))
		} else {
			binary.BigEndian.PutUint32(body[:4], mtu)
		}
	} else if pointerField {
		if protocol == ProtocolICMPv4 {
			body[0] = byte(pointer)
		} else {
			binary.BigEndian.PutUint32(body[:4], pointer)
		}
	}
	copy(body[4:], quote)
}

// icmpExtensionLayout returns the RFC 4884 Length-field offset within the
// four-byte error body and its address-family unit.
func icmpExtensionLayout(protocol, messageType byte) (lengthOffset, unit int, ok bool) {
	if protocol == ProtocolICMPv4 {
		switch messageType {
		case ICMPv4TypeDestinationUnreachable, ICMPv4TypeTimeExceeded, ICMPv4TypeParameterProblem:
			return 1, 4, true
		}
	}
	if protocol == ProtocolICMPv6 {
		switch messageType {
		case ICMPv6TypeDestinationUnreachable, ICMPv6TypeTimeExceeded:
			return 0, 8, true
		}
	}
	return 0, 0, false
}

// parseICMPExtensionStructure validates the RFC 4884 header, optional
// checksum, and complete nonempty object sequence. The returned bytes exclude
// the Extension Header and borrow structure.
func parseICMPExtensionStructure(structure []byte) (objects []byte, hasPointer, ok bool) {
	if len(structure) < icmpExtensionHeaderSize+icmpExtensionObjectHeaderSize ||
		structure[0]>>4 != icmpExtensionVersion {
		return nil, false, false
	}
	if binary.BigEndian.Uint16(structure[2:4]) != 0 && checksum(structure) != 0 {
		return nil, false, false
	}
	objects = structure[icmpExtensionHeaderSize:]
	hasPointer, valid := validateICMPExtensionObjects(objects)
	if !valid {
		return nil, false, false
	}
	return objects, hasPointer, true
}

// quotedIPDeclaredLength returns the original IP length when its base header
// makes that boundary unambiguous. IPv6 Payload Length zero remains unknown
// because the quote may be a jumbogram.
func quotedIPDeclaredLength(quote []byte) (int, bool) {
	if len(quote) == 0 {
		return 0, false
	}
	switch quote[0] >> 4 {
	case 4:
		if len(quote) < 20 {
			return 0, false
		}
		headerSize := int(quote[0]&0x0f) * 4
		totalSize := int(binary.BigEndian.Uint16(quote[2:4]))
		if headerSize < 20 || totalSize < headerSize {
			return 0, false
		}
		return totalSize, true
	case 6:
		if len(quote) < 40 {
			return 0, false
		}
		payloadSize := int(binary.BigEndian.Uint16(quote[4:6]))
		if payloadSize == 0 {
			// A zero Payload Length with a Hop-by-Hop header may identify a
			// jumbogram. Every other Next Header unambiguously describes an
			// ordinary zero-payload packet.
			if quote[6] == IPv6ExtensionHeaderHopByHop {
				return 0, false
			}
			return 40, true
		}
		return 40 + payloadSize, true
	default:
		return 0, false
	}
}

// trimICMPExtensionQuote removes RFC 4884 padding only when the quoted IP
// header proves the original boundary. Nonzero bytes beyond a proven boundary
// violate the required zero padding.
func trimICMPExtensionQuote(quote []byte) ([]byte, bool) {
	declared, known := quotedIPDeclaredLength(quote)
	if !known || declared > len(quote) {
		return quote, true
	}
	for _, value := range quote[declared:] {
		if value != 0 {
			return nil, false
		}
	}
	return quote[:declared], true
}

// splitICMPErrorQuote separates a compliant RFC 4884 Extension Structure from
// its padded quote. A zero Length field always means that no extensions are
// present, as required for compatibility by RFC 4884 section 5.4.
func splitICMPErrorQuote(protocol, messageType byte, body []byte) (quote, extensions []byte, hasPointer, ok bool) {
	lengthOffset, unit, extensible := icmpExtensionLayout(protocol, messageType)
	if !extensible || body[lengthOffset] == 0 {
		return body[4:], nil, false, true
	}
	paddedLength := int(body[lengthOffset]) * unit
	if paddedLength < icmpExtensionMinimumQuoteSize || len(body) < 4+paddedLength+icmpExtensionHeaderSize+icmpExtensionObjectHeaderSize {
		return nil, nil, false, false
	}
	extensions, hasPointer, valid := parseICMPExtensionStructure(body[4+paddedLength:])
	if !valid {
		return nil, nil, false, false
	}
	quote, valid = trimICMPExtensionQuote(body[4 : 4+paddedLength])
	if !valid {
		return nil, nil, false, false
	}
	return quote, extensions, hasPointer, true
}

// icmpExtensionQuoteLength validates that zero padding cannot replace known
// quoted bytes, then returns the representable padded quote length.
func icmpExtensionQuoteLength(protocol, messageType byte, quote []byte) (int, error) {
	_, unit, ok := icmpExtensionLayout(protocol, messageType)
	if !ok {
		return 0, syscall.EINVAL
	}
	if declared, known := quotedIPDeclaredLength(quote); known {
		if declared <= len(quote) {
			for _, value := range quote[declared:] {
				if value != 0 {
					return 0, syscall.EINVAL
				}
			}
		} else if len(quote) < icmpExtensionMinimumQuoteSize {
			return 0, syscall.EINVAL
		}
	} else if len(quote) < icmpExtensionMinimumQuoteSize {
		return 0, syscall.EINVAL
	}
	paddedLength := len(quote)
	if paddedLength < icmpExtensionMinimumQuoteSize {
		paddedLength = icmpExtensionMinimumQuoteSize
	}
	paddedLength = (paddedLength + unit - 1) &^ (unit - 1)
	if paddedLength/unit > 255 {
		return 0, syscall.EMSGSIZE
	}
	return paddedLength, nil
}

// marshalICMPExtensionStructure writes one validated RFC 4884 structure.
func marshalICMPExtensionStructure(structure, objects []byte) {
	structure[0], structure[1], structure[2], structure[3] = icmpExtensionVersion<<4, 0, 0, 0
	copy(structure[icmpExtensionHeaderSize:], objects)
	binary.BigEndian.PutUint16(structure[2:4], checksum(structure))
}

// ICMPMessage constructs the semantic ICMP error represented by e for
// destination. Reporter and destination select the address family; Type, Code,
// MTU, Pointer, QuotedPacket, and Extensions provide the wire fields. It
// validates the possibly truncated quote and extension objects, copies both
// byte slices, and ignores the fields derived from the quote. Routing, source
// ownership, rate limits, quote truncation, and recursive-error suppression
// remain Stack transmission policy.
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
	mtuField, pointerField := icmpErrorFieldKinds(protocol, e.Type, e.Code)
	if !mtuField && e.MTU != 0 || !pointerField && e.Pointer != 0 ||
		protocol == ProtocolICMPv4 && mtuField && e.MTU > 1<<16-1 ||
		protocol == ProtocolICMPv4 && pointerField && e.Pointer > 1<<8-1 {
		return ICMPMessage{}, syscall.EINVAL
	}
	if len(e.Extensions) == 0 {
		if protocol == ProtocolICMPv6 && e.Type == ICMPv6TypeDestinationUnreachable &&
			e.Code == ICMPv6DestinationUnreachableCodeHeadersTooLong {
			return ICMPMessage{}, syscall.EINVAL
		}
		body := make([]byte, 4+len(e.QuotedPacket))
		marshalICMPErrorBody(body, protocol, e.Type, e.Code, e.MTU, e.Pointer, e.QuotedPacket)
		return ICMPMessage{Source: reporter, Destination: destination, Type: e.Type, Code: e.Code, Body: body}, nil
	}
	if len(e.Extensions) > maximumICMPExtensionDataSize {
		return ICMPMessage{}, syscall.EMSGSIZE
	}
	hasPointer, validExtensions := validateICMPExtensionObjects(e.Extensions)
	if !validExtensions || protocol == ProtocolICMPv6 && e.Type == ICMPv6TypeDestinationUnreachable &&
		e.Code == ICMPv6DestinationUnreachableCodeHeadersTooLong && !hasPointer {
		return ICMPMessage{}, syscall.EINVAL
	}
	paddedQuoteLength, err := icmpExtensionQuoteLength(protocol, e.Type, e.QuotedPacket)
	if err != nil {
		return ICMPMessage{}, err
	}
	bodyLength := 4 + paddedQuoteLength + icmpExtensionHeaderSize + len(e.Extensions)
	if bodyLength > 65535-4 {
		return ICMPMessage{}, syscall.EMSGSIZE
	}
	body := make([]byte, bodyLength)
	marshalICMPErrorBody(body, protocol, e.Type, e.Code, e.MTU, e.Pointer, e.QuotedPacket)
	lengthOffset, unit, _ := icmpExtensionLayout(protocol, e.Type)
	body[lengthOffset] = byte(paddedQuoteLength / unit)
	marshalICMPExtensionStructure(body[4+paddedQuoteLength:], e.Extensions)
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
	ipv6Fragment ipv6FragmentPoint
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

// makeICMPEchoReply copies one Echo Request into an Echo Reply with a cleared
// checksum. The caller owns the returned payload and must calculate the
// address-family checksum before transmission.
func makeICMPEchoReply(protocol byte, request []byte) ([]byte, bool) {
	if len(request) < 4 {
		return nil, false
	}
	isRequest, ok := classifyICMPEcho(protocol, request[0], request[1], len(request)-4)
	if !ok || !isRequest {
		return nil, false
	}
	replyType := icmpEchoMessageType(protocol == ProtocolICMPv6, false)
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

// writeICMPError encodes one Stack-selected error through the same body and
// checksum primitives as ICMPError.ICMPMessage. Routing, rate limiting,
// recursive-error suppression, and quotation policy remain with the caller.
func (s *Stack) writeICMPError(source, target netip.Addr, messageType, code byte, mtu, pointer uint32, quote []byte) error {
	protocol := byte(ProtocolICMPv4)
	if source.Is6() {
		protocol = ProtocolICMPv6
	}
	payload := make([]byte, 8+len(quote))
	body := payload[4:]
	marshalICMPErrorBody(body, protocol, messageType, code, mtu, pointer, quote)
	marshalPublicICMPMessage(payload, ICMPMessage{
		Source: source, Destination: target, Type: messageType, Code: code, Body: body,
	})
	return s.writeIPPayload(source, target, protocol, payload, false)
}

// icmpErrorQuote applies RFC 792's IPv4 header-plus-eight minimum and RFC
// 4443's IPv6 minimum-MTU ceiling to an already validated original packet.
func icmpErrorQuote(packet []byte, ipv6 bool) []byte {
	quoteLength := len(packet)
	if !ipv6 {
		headerSize := int(packet[0]&0x0f) * 4
		if quoteLength > headerSize+8 {
			quoteLength = headerSize + 8
		}
	} else if maximum := ipv6MinimumMTU - 48; quoteLength > maximum {
		quoteLength = maximum
	}
	return packet[:quoteLength]
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
	if packet.source.Is4() {
		return s.writeICMPError(packet.target, packet.source, ICMPv4TypeDestinationUnreachable,
			ICMPv4DestinationUnreachableCodeCommunicationAdministrativelyProhibited, 0, 0, icmpErrorQuote(packet.original, false))
	}
	return s.writeICMPError(packet.target, packet.source, ICMPv6TypeDestinationUnreachable,
		ICMPv6DestinationUnreachableCodeAdministrativelyProhibited, 0, 0, icmpErrorQuote(packet.original, true))
}

// sendFragmentReassemblyTimeout reports an expired datagram when its first
// fragment was available. RFC 792 and RFC 4443 prohibit recursively reporting
// another ICMP error, while RFC 4443 also caps the complete IPv6 error at the
// minimum IPv6 MTU.
func (s *Stack) sendFragmentReassemblyTimeout(entry *ipPacketReassemblyEntry) error {
	state := &entry.state
	if !s.isLocal(state.target) {
		return nil
	}
	fragment, ok := parseFragment(state.firstPacket)
	if !ok || fragment.offset != 0 || packetInvokesICMPError(state.firstPacket) || !s.allowControlResponse(controlResponseFragmentTimeout) {
		return nil
	}
	if !state.v6 {
		return s.writeICMPError(state.target, state.source, ICMPv4TypeTimeExceeded,
			ICMPv4TimeExceededCodeFragmentReassembly, 0, 0, icmpErrorQuote(state.firstPacket, false))
	}
	return s.writeICMPError(state.target, state.source, ICMPv6TypeTimeExceeded,
		ICMPv6TimeExceededCodeFragmentReassembly, 0, 0, icmpErrorQuote(state.firstPacket, true))
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
	var extensions []byte
	hasExtensionPointer := false
	if lengthOffset, _, extensible := icmpExtensionLayout(protocol, messageType); extensible && body[lengthOffset] != 0 {
		var split bool
		quote, extensions, hasExtensionPointer, split = splitICMPErrorQuote(protocol, messageType, body)
		if !split {
			return ICMPError{}, false
		}
	}
	if protocol == ProtocolICMPv6 && messageType == ICMPv6TypeDestinationUnreachable &&
		code == ICMPv6DestinationUnreachableCodeHeadersTooLong && !hasExtensionPointer {
		return ICMPError{}, false
	}
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
		Extensions:   extensions,
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
	payloadOffset := 0
	payloadAliasesPacket := false
	if len(networkError.QuotedPacket) != 0 && len(networkError.QuotedPayload) != 0 &&
		len(networkError.QuotedPayload) <= len(networkError.QuotedPacket) {
		payloadOffset = len(networkError.QuotedPacket) - len(networkError.QuotedPayload)
		payloadAliasesPacket = &networkError.QuotedPayload[0] == &networkError.QuotedPacket[payloadOffset]
	}
	packetLength := len(networkError.QuotedPacket)
	extensionLength := len(networkError.Extensions)
	if packetLength+extensionLength != 0 {
		storage := make([]byte, packetLength+extensionLength)
		copy(storage, networkError.QuotedPacket)
		copy(storage[packetLength:], networkError.Extensions)
		if packetLength != 0 {
			networkError.QuotedPacket = storage[:packetLength:packetLength]
		} else {
			networkError.QuotedPacket = nil
		}
		if extensionLength != 0 {
			networkError.Extensions = storage[packetLength:]
		} else {
			networkError.Extensions = nil
		}
	}
	if payloadAliasesPacket {
		networkError.QuotedPayload = networkError.QuotedPacket[payloadOffset:]
	} else {
		networkError.QuotedPayload = append([]byte(nil), networkError.QuotedPayload...)
	}
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
			// RFC 8883 code 8 is accepted here as a classification; complete
			// parsing separately requires its RFC 4884 Pointer object. RFC
			// 9914 code 9 retains the ordinary Destination Unreachable body.
			return code <= ICMPv6DestinationUnreachableCodePRoute
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
		payload := packet[40:]
		next, offset := packet[6], 0
		for {
			if next == ProtocolNoNextHeader {
				return source, target, next, nil, true
			}
			switch next {
			case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
				IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderAuthentication,
				IPv6ExtensionHeaderMobility:
				length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
				if !valid {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				next, offset = payload[offset], offset+length
			case IPv6ExtensionHeaderFragment:
				if len(payload)-offset < 8 {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				header := payload[offset : offset+8]
				next, offset = header[0], offset+8
				// A quoted first fragment is useful even when M is set. Only a
				// nonzero offset prevents transport correlation; RFC 8200's
				// reserved bits are ignored on reception.
				if binary.BigEndian.Uint16(header[2:4])&0xfff8 != 0 {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
			default:
				return source, target, next, payload[offset:], true
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
	if packet.source.Is4() {
		return s.writeICMPError(packet.target, packet.source, ICMPv4TypeDestinationUnreachable,
			ICMPv4DestinationUnreachableCodePort, 0, 0, icmpErrorQuote(packet.original, false))
	}
	return s.writeICMPError(packet.target, packet.source, ICMPv6TypeDestinationUnreachable,
		ICMPv6DestinationUnreachableCodePort, 0, 0, icmpErrorQuote(packet.original, true))
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
		return s.writeICMPError(packet.target, packet.source, ICMPv4TypeDestinationUnreachable,
			ICMPv4DestinationUnreachableCodeProtocol, 0, 0, icmpErrorQuote(packet.original, false))
	}
	return s.writeICMPError(packet.target, packet.source, ICMPv6TypeParameterProblem,
		ICMPv6ParameterProblemCodeUnrecognizedNextHeader, 0, uint32(packet.protocolOffset), icmpErrorQuote(packet.original, true))
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
		return s.writeICMPError(packet.target, packet.source, ICMPv4TypeParameterProblem,
			packet.parameterCode, 0, packet.parameterAt, icmpErrorQuote(packet.original, false))
	}
	if packetInvokesICMPError(packet.original) || !s.allowControlResponse(controlResponseParameterProblem) {
		return nil
	}
	return s.writeICMPError(packet.target, packet.source, ICMPv6TypeParameterProblem,
		packet.parameterCode, 0, packet.parameterAt, icmpErrorQuote(packet.original, true))
}
