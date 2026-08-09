package mipstack

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
)

// ICMPError describes a validated remote network error.
type ICMPError struct {
	// Reporter is the router or destination that generated the error.
	Reporter netip.Addr
	// Type and Code retain the wire ICMP classification.
	Type byte
	// Code retains the wire subtype within Type.
	Code byte
	// MTU is present for fragmentation-needed and packet-too-big errors.
	MTU uint32
	// QuotedSource and QuotedTarget identify the failed original packet.
	QuotedSource netip.Addr
	// QuotedTarget is the destination of the failed original packet.
	QuotedTarget netip.Addr
	// QuotedProtocol and QuotedPayload locate the available original transport
	// header bytes.
	QuotedProtocol byte
	// QuotedPayload contains the available original transport header bytes.
	QuotedPayload []byte
	// QuotedSourcePort and QuotedTargetPort identify TCP or UDP endpoints when
	// the quoted transport header contains them.
	QuotedSourcePort uint16
	// QuotedTargetPort is the original TCP or UDP destination port when present.
	QuotedTargetPort uint16
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
	if len(payload) < 8 || payload[1] != 0 {
		return false
	}
	switch protocol {
	case protocolICMPv4:
		return payload[0] == 8
	case protocolICMPv6:
		return payload[0] == 128
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
	replyType := byte(0)
	if protocol == protocolICMPv6 {
		replyType = 129
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
	if packet.protocol == protocolICMPv4 {
		if checksum(icmp) != 0 {
			return nil
		}
		if localDestination {
			if reply, echoRequest := makeICMPEchoReply(packet.protocol, icmp); echoRequest {
				if !s.allowControlResponse(controlResponseEchoReply) {
					return nil
				}
				binary.BigEndian.PutUint16(reply[2:4], checksum(reply))
				_ = s.writeIPPayload(packet.target, packet.source, protocolICMPv4, reply, true)
				return nil
			}
		}
	} else {
		if transportChecksum(packet.source, packet.target, protocolICMPv6, icmp) != 0 {
			return nil
		}
		if localDestination {
			if reply, echoRequest := makeICMPEchoReply(packet.protocol, icmp); echoRequest {
				if !s.allowControlResponse(controlResponseEchoReply) {
					return nil
				}
				binary.BigEndian.PutUint16(reply[2:4], transportChecksum(packet.target, packet.source, protocolICMPv6, reply))
				_ = s.writeIPPayload(packet.target, packet.source, protocolICMPv6, reply, true)
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
	if len(icmp) < 8 || transportChecksum(packet.source, packet.target, protocolICMPv6, icmp) != 0 {
		return nil
	}
	reply, echoRequest := makeICMPEchoReply(protocolICMPv6, icmp)
	if !echoRequest || !s.allowControlResponse(controlResponseEchoReply) {
		return nil
	}
	source, err := s.sourceForRequested(packet.source, netip.Addr{})
	if err != nil {
		return nil
	}
	binary.BigEndian.PutUint16(reply[2:4], transportChecksum(source, packet.source, protocolICMPv6, reply))
	_ = s.writeIPPayload(source, packet.source, protocolICMPv6, reply, true)
	return nil
}

// deliverICMPError correlates one validated network error with an ordinary or
// forwarded socket. It reports whether a transport or raw endpoint accepted
// the error.
func (s *Stack) deliverICMPError(remoteError ICMPError) bool {
	accepted := false
	switch remoteError.QuotedProtocol {
	case protocolUDP:
		if len(remoteError.QuotedPayload) >= udpHeaderSize {
			sourcePort := binary.BigEndian.Uint16(remoteError.QuotedPayload[0:2])
			targetPort := binary.BigEndian.Uint16(remoteError.QuotedPayload[2:4])
			remoteError.QuotedSourcePort = sourcePort
			remoteError.QuotedTargetPort = targetPort
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
				if remoteError.MTU != 0 {
					if s.observePathMTU(remoteError.QuotedTarget, remoteError.MTU) {
						s.notifyTCPPathMTU(remoteError.QuotedTarget, nil)
					}
				}
				remoteError.QuotedPayload = append([]byte(nil), remoteError.QuotedPayload...)
				connection.deliverError(target, remoteError)
				accepted = true
			}
		}
	case protocolTCP:
		if len(remoteError.QuotedPayload) >= 8 {
			sourcePort := binary.BigEndian.Uint16(remoteError.QuotedPayload[0:2])
			targetPort := binary.BigEndian.Uint16(remoteError.QuotedPayload[2:4])
			remoteError.QuotedSourcePort = sourcePort
			remoteError.QuotedTargetPort = targetPort
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
				remoteError.QuotedPayload = append([]byte(nil), remoteError.QuotedPayload...)
				connection.deliverError(remoteError)
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
	if len(reply) < 8 {
		return syscall.EINVAL
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
		return s.writeIPPayload(packet.target, packet.source, protocolICMPv4, reply, true)
	}
	binary.BigEndian.PutUint16(reply[2:4], transportChecksum(packet.target, packet.source, protocolICMPv6, reply))
	return s.writeIPPayload(packet.target, packet.source, protocolICMPv6, reply, true)
}

// sendAdministrativeUnreachable rejects a handler-supplied ICMP request when
// RFC 792 or RFC 4443 permits an error response.
func (s *Stack) sendAdministrativeUnreachable(packet ipPacket) error {
	if !s.network.Load().acceptsInboundDestination(packet.target) || packetInvokesICMPError(packet.original) || !s.allowControlResponse(controlResponsePortUnreachable) {
		return nil
	}
	quoteLength := len(packet.original)
	if packet.source.Is4() {
		header := int(packet.original[0]&0x0f) * 4
		if quoteLength > header+8 {
			quoteLength = header + 8
		}
		icmp := make([]byte, 8+quoteLength)
		icmp[0], icmp[1] = 3, 13
		copy(icmp[8:], packet.original[:quoteLength])
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(packet.target, packet.source, protocolICMPv4, icmp, false)
	}
	maximumQuote := ipv6MinimumMTU - 48
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	icmp := make([]byte, 8+quoteLength)
	icmp[0], icmp[1] = 1, 1
	copy(icmp[8:], packet.original[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(packet.target, packet.source, protocolICMPv6, icmp))
	return s.writeIPPayload(packet.target, packet.source, protocolICMPv6, icmp, false)
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
		icmp[0], icmp[1] = 11, 1
		copy(icmp[8:], set.firstPacket[:quoteLength])
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(set.target, set.source, protocolICMPv4, icmp, false)
	}
	maximumQuote := ipv6MinimumMTU - 48
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	icmp := make([]byte, 8+quoteLength)
	icmp[0], icmp[1] = 3, 1
	copy(icmp[8:], set.firstPacket[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(set.target, set.source, protocolICMPv6, icmp))
	return s.writeIPPayload(set.target, set.source, protocolICMPv6, icmp, false)
}

// packetInvokesICMPError follows a complete or first-fragment header chain
// and applies the RFC 792/RFC 4443 recursive-error suppression rule.
func packetInvokesICMPError(packet []byte) bool {
	_, _, protocol, payload, ok := quotedIPPayload(packet)
	if !ok || len(payload) == 0 {
		return false
	}
	if protocol == protocolICMPv6 {
		return payload[0] < 128
	}
	if protocol == protocolICMPv4 {
		switch payload[0] {
		case 3, 4, 5, 11, 12:
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
	if packet.protocol == protocolICMPv4 {
		if !validICMPErrorCode(protocolICMPv4, icmp[0], icmp[1]) {
			return ICMPError{}, false
		}
		source, target, protocol, payload, ok := quotedIPPayload(icmp[8:])
		if !ok || !source.Is4() || !target.Is4() {
			return ICMPError{}, false
		}
		result := ICMPError{Reporter: packet.source, Type: icmp[0], Code: icmp[1], QuotedSource: source, QuotedTarget: target, QuotedProtocol: protocol, QuotedPayload: payload}
		if icmp[0] == 3 && icmp[1] == 4 {
			result.MTU = uint32(binary.BigEndian.Uint16(icmp[6:8]))
			if result.MTU == 0 {
				result.MTU = legacyIPv4PathMTU(icmp[8:])
			}
		}
		return result, true
	}
	if packet.protocol == protocolICMPv6 && validICMPErrorCode(protocolICMPv6, icmp[0], icmp[1]) {
		source, target, protocol, payload, ok := quotedIPPayload(icmp[8:])
		if !ok || !source.Is6() || !target.Is6() {
			return ICMPError{}, false
		}
		result := ICMPError{Reporter: packet.source, Type: icmp[0], Code: icmp[1], QuotedSource: source, QuotedTarget: target, QuotedProtocol: protocol, QuotedPayload: payload}
		if icmp[0] == 2 {
			result.MTU = binary.BigEndian.Uint32(icmp[4:8])
		}
		return result, true
	}
	return ICMPError{}, false
}

// validICMPErrorCode rejects unassigned type/code combinations before they
// can affect a socket or the path-MTU cache.
func validICMPErrorCode(protocol, messageType, code byte) bool {
	switch protocol {
	case protocolICMPv4:
		switch messageType {
		case 3:
			return code <= 15
		case 11:
			return code <= 1
		case 12:
			return code <= 2
		}
	case protocolICMPv6:
		switch messageType {
		case 1:
			return code <= 7
		case 2:
			return code == 0
		case 3:
			return code <= 1
		case 4:
			// RFC 7112 assigns code 3 for an incomplete first-fragment header
			// chain; RFC 8754 assigns code 4 for an SR upper-layer error.
			return code <= 4
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
		next, offset := packet[6], 40
		for offset <= len(packet) {
			switch next {
			case 0, 43, 60, 135:
				if len(packet)-offset < 8 {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				length := (int(packet[offset+1]) + 1) * 8
				if length > len(packet)-offset {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				next, offset = packet[offset], offset+length
			case 44:
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
			case 51:
				if len(packet)-offset < 8 {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				length := (int(packet[offset+1]) + 2) * 4
				if length > len(packet)-offset {
					return netip.Addr{}, netip.Addr{}, 0, nil, false
				}
				next, offset = packet[offset], offset+length
			default:
				return source, target, next, packet[offset:], true
			}
		}
	}
	return netip.Addr{}, netip.Addr{}, 0, nil, false
}

// sendPortUnreachable rejects a valid UDP datagram with no local socket.
func (s *Stack) sendPortUnreachable(packet ipPacket) error {
	if !s.network.Load().acceptsInboundDestination(packet.target) || !s.allowControlResponse(controlResponsePortUnreachable) {
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
		icmp[0], icmp[1] = 3, 3
		copy(icmp[8:], quote)
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(packet.target, packet.source, protocolICMPv4, icmp, false)
	}
	maximumQuote := ipv6MinimumMTU - 48
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	quote := packet.original[:quoteLength]
	icmp := make([]byte, 8+len(quote))
	icmp[0], icmp[1] = 1, 4
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(packet.target, packet.source, protocolICMPv6, icmp))
	return s.writeIPPayload(packet.target, packet.source, protocolICMPv6, icmp, false)
}

// sendProtocolUnreachable rejects a valid packet whose upper-layer protocol
// has no endpoint handler. IPv6 identifies the unrecognized Next Header field.
func (s *Stack) sendProtocolUnreachable(packet ipPacket) error {
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
		icmp[0], icmp[1] = 3, 2
		copy(icmp[8:], packet.original[:quoteLength])
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(packet.target, packet.source, protocolICMPv4, icmp, false)
	}
	maximumQuote := ipv6MinimumMTU - 48
	quoteLength := len(packet.original)
	if quoteLength > maximumQuote {
		quoteLength = maximumQuote
	}
	icmp := make([]byte, 8+quoteLength)
	icmp[0], icmp[1] = 4, 1
	binary.BigEndian.PutUint32(icmp[4:8], uint32(packet.protocolOffset))
	copy(icmp[8:], packet.original[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(packet.target, packet.source, protocolICMPv6, icmp))
	return s.writeIPPayload(packet.target, packet.source, protocolICMPv6, icmp, false)
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
		icmp[0], icmp[1], icmp[4] = 12, packet.parameterCode, byte(packet.parameterAt)
		copy(icmp[8:], packet.original[:quoteLength])
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
		return s.writeIPPayload(packet.target, packet.source, protocolICMPv4, icmp, false)
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
	icmp[0], icmp[1] = 4, packet.parameterCode
	binary.BigEndian.PutUint32(icmp[4:8], packet.parameterAt)
	copy(icmp[8:], packet.original[:quoteLength])
	binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(packet.target, packet.source, protocolICMPv6, icmp))
	return s.writeIPPayload(packet.target, packet.source, protocolICMPv6, icmp, false)
}
