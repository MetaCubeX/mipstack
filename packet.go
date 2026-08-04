package mipstack

import (
	"encoding/binary"
	"net/netip"
)

const (
	// protocolICMPv4 is the IPv4 ICMP protocol number.
	protocolICMPv4 = byte(1)
	// protocolTCP is the TCP protocol number.
	protocolTCP = byte(6)
	// protocolUDP is the UDP protocol number.
	protocolUDP = byte(17)
	// protocolICMPv6 is the ICMPv6 next-header number.
	protocolICMPv6 = byte(58)
)

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
	payload        []byte
	original       []byte
}

// ipPacketOptions controls fields shared by raw IPv4 and IPv6 output. A zero
// hop limit selects the stack default.
type ipPacketOptions struct {
	hopLimit     byte
	trafficClass byte
}

// normalized applies endpoint defaults to optional output fields.
func (o ipPacketOptions) normalized() ipPacketOptions {
	if o.hopLimit == 0 {
		o.hopLimit = 64
	}
	return o
}

// checksum computes the Internet checksum over data.
func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
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

// transportChecksum computes an IPv4 or IPv6 pseudo-header checksum.
func transportChecksum(source, target netip.Addr, protocol byte, payload []byte) uint16 {
	source, target = source.Unmap(), target.Unmap()
	var sum uint32
	add := func(data []byte) {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) != 0 {
			sum += uint32(data[0]) << 8
		}
	}
	if source.Is4() && target.Is4() {
		add(source.AsSlice())
		add(target.AsSlice())
		sum += uint32(protocol)
		sum += uint32(len(payload))
	} else if source.Is6() && target.Is6() {
		add(source.AsSlice())
		add(target.AsSlice())
		sum += uint32(len(payload) >> 16)
		sum += uint32(len(payload) & 0xffff)
		sum += uint32(protocol)
	} else {
		return 0
	}
	add(payload)
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
		if optionAt, malformed := malformedIPv4Option(packet[20:headerSize]); malformed {
			return ipPacket{
				source: source, target: target, original: packet[:totalSize],
				parameterError: true, parameterCode: 0, parameterAt: uint32(20 + optionAt),
			}, true
		}
		if !validateIPv4Options(packet[20:headerSize]) {
			return ipPacket{}, false
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
		if payloadSize == 0 && len(packet) > 40 {
			// Jumbo Payload options are intentionally unsupported.
			return ipPacket{}, false
		}
		end := 40 + payloadSize
		if end > len(packet) {
			return ipPacket{}, false
		}
		source := netip.AddrFrom16([16]byte(packet[8:24]))
		target := netip.AddrFrom16([16]byte(packet[24:40]))
		next, nextOffset, offset := packet[6], 6, 40
		seenHop := false
		for offset <= end {
			switch next {
			case 0, 60:
				if next == 0 && (offset != 40 || seenHop) {
					// RFC 8200 permits Hop-by-Hop only immediately after the
					// IPv6 header. A later value zero is therefore an
					// unrecognized Next Header, not another extension header.
					return ipPacket{
						source: source, target: target, original: packet[:end], ecn: packet[1] >> 4 & 3,
						hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4,
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
							hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4,
							parameterError: true, parameterCode: 2, parameterAt: uint32(offset + optionOffset),
						}, true
					}
					return ipPacket{}, false
				}
				if next == 0 {
					seenHop = true
				}
				next, nextOffset, offset = packet[offset], offset, offset+length
			case 43:
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
						hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4,
						parameterError: true, parameterCode: 0, parameterAt: uint32(offset + 2),
					}, true
				}
				next, nextOffset, offset = packet[offset], offset, offset+length
			case 44:
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
					ecn: packet[1] >> 4 & 3, hopLimit: packet[7], trafficClass: packet[0]&0x0f<<4 | packet[1]>>4,
					payload: packet[offset:end], original: packet[:end],
				}, true
			}
		}
	}
	return ipPacket{}, false
}

// malformedIPv4Option returns the byte that Linux reports in an ICMP
// Parameter Problem for malformed option framing or fields. Policy rejection
// of a well-formed option, such as source routing, is left to
// validateIPv4Options and is not misreported as a syntax error.
func malformedIPv4Option(options []byte) (int, bool) {
	var sourceRoute, recordRoute, timestamp bool
	for offset := 0; offset < len(options); {
		kind := options[offset]
		switch kind {
		case 0:
			for padding := offset + 1; padding < len(options); padding++ {
				if options[padding] != 0 {
					return padding, true
				}
			}
			return 0, false
		case 1:
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
		case 131, 137: // Loose and strict source route.
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
		case 7: // Record route.
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
		case 68: // Internet timestamp.
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
		case 148: // Router Alert.
			if length < 4 {
				return offset + 1, true
			}
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
		case 0:
			for _, padding := range options[offset+1:] {
				if padding != 0 {
					return false
				}
			}
			return true
		case 1:
			offset++
			continue
		case 131, 137:
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
		if kind == 0 {
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

// buildIPPacket wraps payload in a minimal IPv4 or IPv6 header.
func buildIPPacket(source, target netip.Addr, protocol byte, payload []byte, identification uint16, dontFragment bool) []byte {
	return buildIPPacketWithOptions(source, target, protocol, payload, identification, dontFragment, ipPacketOptions{})
}

// buildIPPacketWithOptions wraps payload and applies raw IP output fields.
func buildIPPacketWithOptions(source, target netip.Addr, protocol byte, payload []byte, identification uint16, dontFragment bool, options ipPacketOptions) []byte {
	source, target = source.Unmap(), target.Unmap()
	options = options.normalized()
	if !source.IsValid() || !target.IsValid() || source.Is4() != target.Is4() {
		return nil
	}
	if source.Is4() {
		if len(payload) > 65515 {
			return nil
		}
		packet := make([]byte, 20+len(payload))
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:6], identification)
		if dontFragment {
			binary.BigEndian.PutUint16(packet[6:8], 0x4000)
		}
		packet[1], packet[8], packet[9] = options.trafficClass, options.hopLimit, protocol
		copy(packet[12:16], source.AsSlice())
		copy(packet[16:20], target.AsSlice())
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		copy(packet[20:], payload)
		return packet
	}
	if len(payload) > 65535 {
		return nil
	}
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60 | options.trafficClass>>4
	packet[1] = options.trafficClass << 4
	packet[6], packet[7] = protocol, options.hopLimit
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], target.AsSlice())
	copy(packet[40:], payload)
	return packet
}
