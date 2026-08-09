package mipstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	// linuxControlHeaderSize is the fixed Linux 64-bit ancillary header size
	// used on every host so control data remains portable between MIPS instances.
	linuxControlHeaderSize = 16
	// linuxControlAlignment is the fixed Linux 64-bit ancillary alignment.
	linuxControlAlignment = 8
	// linuxMessageControlTruncated is Linux MSG_CTRUNC.
	linuxMessageControlTruncated = 0x08
	// linuxMessageTruncated is Linux MSG_TRUNC.
	linuxMessageTruncated = 0x20
	// linuxLevelIP is Linux IPPROTO_IP.
	linuxLevelIP = 0
	// linuxIPTypeOfService is Linux IP_TOS.
	linuxIPTypeOfService = 1
	// linuxIPTimeToLive is Linux IP_TTL.
	linuxIPTimeToLive = 2
	// linuxIPPacketInfo is Linux IP_PKTINFO.
	linuxIPPacketInfo = 8
	// linuxLevelIPv6 is Linux IPPROTO_IPV6.
	linuxLevelIPv6 = 41
	// linuxIPv6FlowInfo is Linux IPV6_FLOWINFO.
	linuxIPv6FlowInfo = 11
	// linuxIPv6PacketInfo is Linux IPV6_PKTINFO.
	linuxIPv6PacketInfo = 50
	// linuxIPv6HopLimit is Linux IPV6_HOPLIMIT.
	linuxIPv6HopLimit = 52
	// linuxIPv6TrafficClass is Linux IPV6_TCLASS.
	linuxIPv6TrafficClass = 67
)

// IPv4ControlMessage represents per-packet IPv4 metadata carried by
// UDPConn.ReadMsgUDP, UDPConn.WriteMsgUDP, IPConn.ReadMsgIP, and
// IPConn.WriteMsgIP. Src is used when sending and Dst is populated when
// parsing received control data. MIPS has one embedding link, so IfIndex is
// always zero and a nonzero value cannot be marshaled.
type IPv4ControlMessage struct {
	// TTL is the received or requested time to live. A received value may be
	// zero; zero selects the output default when marshaling.
	TTL int
	// TOS is the received or requested type-of-service byte. Zero selects the
	// output default when marshaling.
	TOS int
	// Src selects a managed source address when marshaling.
	Src netip.Addr
	// Dst is the local destination populated by Parse and is not marshaled.
	Dst netip.Addr
	// IfIndex is the embedding-link index. MIPS supports only zero.
	IfIndex int
}

// Marshal returns the fixed Linux 64-bit little-endian ancillary encoding used
// by MIPS on every host. Zero-valued fields are omitted and select stack
// defaults.
func (message *IPv4ControlMessage) Marshal() ([]byte, error) {
	if message == nil {
		return nil, nil
	}
	return message.marshal(message.Src, false)
}

// marshalForRead encodes the receive-only Dst field and required header
// values. Keeping this operation on the public type makes it share Marshal's
// validation and wire encoding while leaving Marshal's send semantics intact.
func (message *IPv4ControlMessage) marshalForRead() ([]byte, error) {
	return message.marshal(message.Dst, true)
}

// marshal encodes the selected packet-info address and header values.
func (message *IPv4ControlMessage) marshal(address netip.Addr, receiving bool) ([]byte, error) {
	if message.IfIndex != 0 {
		return nil, errors.New("mipstack: nonzero IPv4 control-message interface index is not supported")
	}
	address = address.Unmap()
	capacity := 0
	if address.IsValid() {
		if !address.Is4() || address.Zone() != "" || !receiving && address.IsMulticast() {
			field := "source"
			if receiving {
				field = "destination"
			}
			return nil, errors.New("mipstack: invalid IPv4 control-message " + field)
		}
		capacity += 32
	}
	if message.TTL < 0 || message.TTL > 255 {
		return nil, errors.New("mipstack: IPv4 control-message TTL must be between 0 and 255")
	}
	if message.TOS < 0 || message.TOS > 255 {
		return nil, errors.New("mipstack: IPv4 control-message TOS must be between 0 and 255")
	}
	if receiving || message.TTL != 0 {
		capacity += 24
	}
	if receiving || message.TOS != 0 {
		capacity += 24
	}
	control := make([]byte, 0, capacity)
	if address.IsValid() {
		control = appendLinuxPacketInfoControl(control, address)
	}
	if receiving || message.TTL != 0 {
		control = appendLinuxControlInt32(control, linuxLevelIP, linuxIPTimeToLive, int32(message.TTL))
	}
	if receiving {
		control = appendLinuxControl(control, linuxLevelIP, linuxIPTypeOfService, []byte{byte(message.TOS)})
	} else if message.TOS != 0 {
		control = appendLinuxControlInt32(control, linuxLevelIP, linuxIPTypeOfService, int32(message.TOS))
	}
	return control, nil
}

// Parse replaces message with metadata decoded from the fixed ancillary
// encoding returned by MIPS message reads.
func (message *IPv4ControlMessage) Parse(control []byte) error {
	if message == nil {
		return errors.New("mipstack: nil IPv4 control-message receiver")
	}
	address, options, err := parseLinuxIPControlValues(control, false, true)
	if err != nil {
		return err
	}
	*message = IPv4ControlMessage{
		TTL: int(options.hopLimit), TOS: int(options.trafficClass), Dst: address,
	}
	return nil
}

// parseForWrite decodes send metadata into Src and the header fields while
// retaining whether a zero-valued field was explicitly present.
func (message *IPv4ControlMessage) parseForWrite(control []byte) (ipPacketOptions, error) {
	address, options, err := parseLinuxIPControlValues(control, false, false)
	if err != nil {
		return ipPacketOptions{}, err
	}
	*message = IPv4ControlMessage{
		TTL: int(options.hopLimit), TOS: int(options.trafficClass), Src: address,
	}
	return options, nil
}

// IPv6ControlMessage represents per-packet IPv6 metadata carried by
// UDPConn.ReadMsgUDP, UDPConn.WriteMsgUDP, IPConn.ReadMsgIP, and
// IPConn.WriteMsgIP. Src is used when sending and Dst is populated when
// parsing received control data. MIPS has one embedding link, so IfIndex is
// always zero and a nonzero value cannot be marshaled.
type IPv6ControlMessage struct {
	// TrafficClass is the received or requested traffic-class byte. Zero
	// selects the output default when marshaling.
	TrafficClass int
	// HopLimit is the received or requested hop limit. A received value may be
	// zero; zero selects the output default when marshaling.
	HopLimit int
	// FlowLabel is the received or requested 20-bit IPv6 Flow Label. Zero
	// selects automatic labeling when marshaling through this structured API.
	FlowLabel uint32
	// Src selects a managed source address when marshaling.
	Src netip.Addr
	// Dst is the local destination populated by Parse and is not marshaled.
	Dst netip.Addr
	// IfIndex is the embedding-link index. MIPS supports only zero.
	IfIndex int
}

// Marshal returns the fixed Linux 64-bit little-endian ancillary encoding used
// by MIPS on every host. Zero-valued fields are omitted and select stack
// defaults.
func (message *IPv6ControlMessage) Marshal() ([]byte, error) {
	if message == nil {
		return nil, nil
	}
	return message.marshal(message.Src, false)
}

// marshalForRead encodes the receive-only Dst field and required header
// values. Keeping this operation on the public type makes it share Marshal's
// validation and wire encoding while leaving Marshal's send semantics intact.
func (message *IPv6ControlMessage) marshalForRead() ([]byte, error) {
	return message.marshal(message.Dst, true)
}

// marshal encodes the selected packet-info address and header values.
func (message *IPv6ControlMessage) marshal(address netip.Addr, receiving bool) ([]byte, error) {
	if message.IfIndex != 0 {
		return nil, errors.New("mipstack: nonzero IPv6 control-message interface index is not supported")
	}
	address = address.Unmap()
	capacity := 0
	if address.IsValid() {
		if !address.Is6() || address.Zone() != "" || !receiving && address.IsMulticast() {
			field := "source"
			if receiving {
				field = "destination"
			}
			return nil, errors.New("mipstack: invalid IPv6 control-message " + field)
		}
		capacity += 40
	}
	if message.HopLimit < 0 || message.HopLimit > 255 {
		return nil, errors.New("mipstack: IPv6 control-message hop limit must be between 0 and 255")
	}
	if message.TrafficClass < 0 || message.TrafficClass > 255 {
		return nil, errors.New("mipstack: IPv6 control-message traffic class must be between 0 and 255")
	}
	if message.FlowLabel > ipv6MaximumFlowLabel {
		return nil, errors.New("mipstack: IPv6 control-message flow label exceeds 20 bits")
	}
	if receiving || message.HopLimit != 0 {
		capacity += 24
	}
	if receiving || message.TrafficClass != 0 {
		capacity += 24
	}
	if message.FlowLabel != 0 || receiving && message.TrafficClass != 0 {
		capacity += 24
	}
	control := make([]byte, 0, capacity)
	if address.IsValid() {
		control = appendLinuxPacketInfoControl(control, address)
	}
	if receiving || message.HopLimit != 0 {
		control = appendLinuxControlInt32(control, linuxLevelIPv6, linuxIPv6HopLimit, int32(message.HopLimit))
	}
	if receiving || message.TrafficClass != 0 {
		control = appendLinuxControlInt32(control, linuxLevelIPv6, linuxIPv6TrafficClass, int32(message.TrafficClass))
	}
	// Linux emits IPV6_FLOWINFO on receive only when the combined traffic
	// class and flow label are nonzero. Structured sends omit a zero label so
	// it retains the public API's automatic-labeling meaning; raw OOB can still
	// carry an explicit all-zero flowinfo value.
	if message.FlowLabel != 0 || receiving && message.TrafficClass != 0 {
		var flowInfo [4]byte
		binary.BigEndian.PutUint32(flowInfo[:], uint32(message.TrafficClass)<<20|message.FlowLabel)
		control = appendLinuxControl(control, linuxLevelIPv6, linuxIPv6FlowInfo, flowInfo[:])
	}
	return control, nil
}

// Parse replaces message with metadata decoded from the fixed ancillary
// encoding returned by MIPS message reads.
func (message *IPv6ControlMessage) Parse(control []byte) error {
	if message == nil {
		return errors.New("mipstack: nil IPv6 control-message receiver")
	}
	address, options, err := parseLinuxIPControlValues(control, true, true)
	if err != nil {
		return err
	}
	*message = IPv6ControlMessage{
		TrafficClass: int(options.trafficClass), HopLimit: int(options.hopLimit), FlowLabel: options.flowLabel, Dst: address,
	}
	return nil
}

// parseForWrite decodes send metadata into Src and the header fields while
// retaining whether a zero-valued field was explicitly present.
func (message *IPv6ControlMessage) parseForWrite(control []byte) (ipPacketOptions, error) {
	address, options, err := parseLinuxIPControlValues(control, true, false)
	if err != nil {
		return ipPacketOptions{}, err
	}
	*message = IPv6ControlMessage{
		TrafficClass: int(options.trafficClass), HopLimit: int(options.hopLimit), FlowLabel: options.flowLabel, Src: address,
	}
	return options, nil
}

// appendLinuxPacketInfoControl encodes source-selection metadata. Interface
// index zero selects MIPS's single embedding link.
func appendLinuxPacketInfoControl(control []byte, address netip.Addr) []byte {
	address = address.Unmap()
	if address.Is4() {
		var data [12]byte
		addressBytes := address.As4()
		copy(data[4:8], addressBytes[:])
		copy(data[8:12], addressBytes[:])
		return appendLinuxControl(control, linuxLevelIP, linuxIPPacketInfo, data[:])
	}
	var data [20]byte
	addressBytes := address.As16()
	copy(data[0:16], addressBytes[:])
	return appendLinuxControl(control, linuxLevelIPv6, linuxIPv6PacketInfo, data[:])
}

// controlMessageForRead encodes receive metadata through the public control
// message types so their field semantics remain authoritative.
func controlMessageForRead(address netip.Addr, options ipPacketOptions) ([]byte, error) {
	address = address.Unmap()
	if address.Is4() {
		message := IPv4ControlMessage{TTL: int(options.hopLimit), TOS: int(options.trafficClass), Dst: address}
		return message.marshalForRead()
	}
	message := IPv6ControlMessage{TrafficClass: int(options.trafficClass), HopLimit: int(options.hopLimit), FlowLabel: options.flowLabel, Dst: address}
	return message.marshalForRead()
}

// appendLinuxControl appends one aligned cmsghdr and payload.
func appendLinuxControl(control []byte, level, kind uint32, data []byte) []byte {
	length := linuxControlHeaderSize + len(data)
	space := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
	offset := len(control)
	control = append(control, make([]byte, space)...)
	binary.LittleEndian.PutUint64(control[offset:offset+8], uint64(length))
	binary.LittleEndian.PutUint32(control[offset+8:offset+12], level)
	binary.LittleEndian.PutUint32(control[offset+12:offset+16], kind)
	copy(control[offset+linuxControlHeaderSize:offset+length], data)
	return control
}

// appendLinuxControlInt32 appends one native-int ancillary value.
func appendLinuxControlInt32(control []byte, level, kind uint32, value int32) []byte {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], uint32(value))
	return appendLinuxControl(control, level, kind, data[:])
}

// parseControlMessageForWrite decodes send metadata through the public control
// message types so Src and header-field semantics cannot diverge.
func parseControlMessageForWrite(control []byte, v6 bool) (netip.Addr, ipPacketOptions, error) {
	if v6 {
		var message IPv6ControlMessage
		options, err := message.parseForWrite(control)
		if err != nil {
			return netip.Addr{}, ipPacketOptions{}, err
		}
		return message.Src, options, nil
	}
	var message IPv4ControlMessage
	options, err := message.parseForWrite(control)
	if err != nil {
		return netip.Addr{}, ipPacketOptions{}, err
	}
	return message.Src, options, nil
}

// parseLinuxIPControlValues validates cmsghdr framing and extracts raw values.
// Empty control data selects routing and default header values. receiving
// permits the zero hop value that can be observed at a local destination.
func parseLinuxIPControlValues(oob []byte, v6, receiving bool) (netip.Addr, ipPacketOptions, error) {
	var address netip.Addr
	var options ipPacketOptions
	var haveHopLimit, haveTrafficClass, haveTrafficClassControl, haveFlowLabel bool
	for len(oob) != 0 {
		if len(oob) < linuxControlHeaderSize {
			return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: truncated Linux IP control header")
		}
		length64 := binary.LittleEndian.Uint64(oob[0:8])
		if length64 < linuxControlHeaderSize || length64 > uint64(len(oob)) {
			return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid Linux IP control length")
		}
		length := int(length64)
		level := binary.LittleEndian.Uint32(oob[8:12])
		kind := binary.LittleEndian.Uint32(oob[12:16])
		data := oob[linuxControlHeaderSize:length]
		switch {
		case level == linuxLevelIP && kind == linuxIPPacketInfo:
			if v6 || len(data) != 12 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv4 packet-info control message")
			}
			if binary.LittleEndian.Uint32(data[0:4]) != 0 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: nonzero packet-info interface index is not supported")
			}
			candidate := netip.AddrFrom4([4]byte(data[4:8]))
			if candidate.IsUnspecified() {
				candidate = netip.AddrFrom4([4]byte(data[8:12]))
			}
			if err := mergePacketInfoAddress(&address, candidate); err != nil {
				return netip.Addr{}, ipPacketOptions{}, err
			}
		case level == linuxLevelIPv6 && kind == linuxIPv6PacketInfo:
			if !v6 || len(data) != 20 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 packet-info control message")
			}
			if binary.LittleEndian.Uint32(data[16:20]) != 0 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: nonzero packet-info interface index is not supported")
			}
			if err := mergePacketInfoAddress(&address, netip.AddrFrom16([16]byte(data[0:16]))); err != nil {
				return netip.Addr{}, ipPacketOptions{}, err
			}
		case level == linuxLevelIP && kind == linuxIPTimeToLive:
			value, err := linuxControlInt32(data)
			if v6 || err != nil || value < 0 || !receiving && value == 0 || value > 255 || haveHopLimit {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv4 TTL control message")
			}
			options.hopLimit, options.hopLimitSet, haveHopLimit = byte(value), true, true
		case level == linuxLevelIP && kind == linuxIPTypeOfService:
			value, err := linuxControlByteOrInt32(data)
			if v6 || err != nil || value < 0 || value > 255 || haveTrafficClassControl {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv4 TOS control message")
			}
			options.trafficClass, options.trafficClassSet, haveTrafficClass, haveTrafficClassControl = byte(value), true, true, true
		case level == linuxLevelIPv6 && kind == linuxIPv6HopLimit:
			value, err := linuxControlInt32(data)
			if !v6 || err != nil || value < 0 || value > 255 || haveHopLimit {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 hop-limit control message")
			}
			options.hopLimit, options.hopLimitSet, haveHopLimit = byte(value), true, true
		case level == linuxLevelIPv6 && kind == linuxIPv6TrafficClass:
			value, err := linuxControlInt32(data)
			if !v6 || err != nil || value < 0 || value > 255 || haveTrafficClassControl || haveTrafficClass && options.trafficClass != byte(value) {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 traffic-class control message")
			}
			options.trafficClass, options.trafficClassSet, haveTrafficClass, haveTrafficClassControl = byte(value), true, true, true
		case level == linuxLevelIPv6 && kind == linuxIPv6FlowInfo:
			if !v6 || len(data) != 4 || haveFlowLabel {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 flow-info control message")
			}
			flowInfo := binary.BigEndian.Uint32(data)
			if flowInfo>>28 != 0 {
				return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: invalid IPv6 flow-info control message")
			}
			flowTrafficClass := byte(flowInfo >> 20)
			if flowTrafficClass != 0 {
				if haveTrafficClass && options.trafficClass != flowTrafficClass {
					return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: conflicting IPv6 flow-info traffic class")
				}
				options.trafficClass, options.trafficClassSet, haveTrafficClass = flowTrafficClass, true, true
			}
			options.flowLabel, options.flowLabelSet, haveFlowLabel = flowInfo&ipv6MaximumFlowLabel, true, true
		default:
			return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: unsupported Linux IP control message")
		}
		aligned := (length + linuxControlAlignment - 1) &^ (linuxControlAlignment - 1)
		if aligned > len(oob) {
			if length == len(oob) {
				break
			}
			return netip.Addr{}, ipPacketOptions{}, errors.New("mipstack: truncated Linux IP control padding")
		}
		oob = oob[aligned:]
	}
	return address, options, nil
}

// mergePacketInfoAddress accepts one consistent, nonzero local address.
func mergePacketInfoAddress(current *netip.Addr, candidate netip.Addr) error {
	if !candidate.IsValid() || candidate.IsUnspecified() {
		return nil
	}
	if current.IsValid() && *current != candidate {
		return errors.New("mipstack: conflicting packet-info addresses")
	}
	*current = candidate
	return nil
}

// linuxControlInt32 decodes one Linux ancillary integer.
func linuxControlInt32(data []byte) (int32, error) {
	if len(data) != 4 {
		return 0, errors.New("invalid Linux ancillary integer")
	}
	return int32(binary.LittleEndian.Uint32(data)), nil
}

// linuxControlByteOrInt32 accepts the one-byte receive and int send forms used
// by Linux IP_TOS ancillary data.
func linuxControlByteOrInt32(data []byte) (int32, error) {
	if len(data) == 1 {
		return int32(data[0]), nil
	}
	return linuxControlInt32(data)
}
