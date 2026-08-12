package mipstack

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"time"
)

// ipv6ForwarderFragmentPoint identifies where a source Fragment header must be
// inserted and which preceding Next Header byte names the fragmentable part.
type ipv6ForwarderFragmentPoint struct {
	previous       int
	insertion      int
	next           byte
	atomicOffset   int
	atomicPrevious int
}

// inspectIPv6ForwarderFragmentPoint validates the extension chain relevant to
// source fragmentation. RFC 8200 places Hop-by-Hop and Routing headers before
// the Fragment header; a Destination Options header before Routing remains
// unfragmentable, while a final Destination Options header is fragmentable.
// Existing non-atomic fragments and multiple Fragment headers are rejected.
// One atomic Fragment header is recorded independently from the canonical
// insertion point so refragmentation can remove it even when the caller used
// a non-recommended but receiver-valid extension-header order.
func inspectIPv6ForwarderFragmentPoint(packet []byte) (ipv6ForwarderFragmentPoint, bool) {
	if len(packet) < 40 {
		return ipv6ForwarderFragmentPoint{}, false
	}
	end := len(packet)
	next, previous, offset := packet[6], 6, 40
	point := ipv6ForwarderFragmentPoint{
		previous: 6, insertion: 40, next: next,
		atomicOffset: -1, atomicPrevious: -1,
	}
	seenHop := false
	for offset <= end {
		switch next {
		case 0:
			if offset != 40 || seenHop || end-offset < 8 {
				return ipv6ForwarderFragmentPoint{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset {
				return ipv6ForwarderFragmentPoint{}, false
			}
			seenHop = true
			next, previous, offset = packet[offset], offset, offset+length
			point.previous, point.insertion, point.next = previous, offset, next
		case 43:
			if end-offset < 8 {
				return ipv6ForwarderFragmentPoint{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset || packet[offset+3] != 0 {
				return ipv6ForwarderFragmentPoint{}, false
			}
			next, previous, offset = packet[offset], offset, offset+length
			point.previous, point.insertion, point.next = previous, offset, next
		case 60:
			if end-offset < 8 {
				return ipv6ForwarderFragmentPoint{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset {
				return ipv6ForwarderFragmentPoint{}, false
			}
			next, previous, offset = packet[offset], offset, offset+length
			// A pre-routing Destination Options header belongs to the
			// unfragmentable part only if a Routing header actually follows.
			// Never move point here: a later Routing header moves it past both
			// headers, while an upper-layer header leaves this header in the
			// fragmentable part. Continuing the scan also finds a Fragment header
			// that appears after final-destination options.
		case 44:
			if end-offset < 8 || point.atomicOffset >= 0 {
				return ipv6ForwarderFragmentPoint{}, false
			}
			field := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			if field&0xfff9 != 0 {
				return ipv6ForwarderFragmentPoint{}, false
			}
			point.atomicOffset, point.atomicPrevious = offset, previous
			next, previous, offset = packet[offset], offset, offset+8
		default:
			return point, true
		}
	}
	return ipv6ForwarderFragmentPoint{}, false
}

const (
	// fragmentMaximumSets bounds concurrent incomplete datagrams.
	fragmentMaximumSets = 128
	// fragmentMaximumPieces bounds fragment metadata per datagram while still
	// permitting the RFC 8200-required 1500-byte packet to arrive as minimum
	// eight-byte fragments.
	fragmentMaximumPieces = 256
	// fragmentMaximumBytes bounds payload retained across the stack.
	fragmentMaximumBytes = 4 * 1024 * 1024
	// fragmentMaximumDatagram is the IPv6 non-jumbogram payload limit. IPv4
	// subtracts its minimum header before applying it.
	fragmentMaximumDatagram = 65535
	// fragmentIPv4Lifetime follows Linux's IP_FRAG_TIME from the first
	// fragment. Later arrivals must not extend it.
	fragmentIPv4Lifetime = 30 * time.Second
	// fragmentIPv6Lifetime is RFC 8200's reassembly deadline from the first
	// fragment.
	fragmentIPv6Lifetime = 60 * time.Second
)

// sourceFragmentation separates local source fragmentation from the IPv4 DF
// value used when one datagram fits without fragmentation. Linux WANT mode
// permits the former while requesting the latter.
type sourceFragmentation struct {
	allow        bool
	dontFragment bool
}

// requiresIPv4ID reports whether Linux gives the datagram a fragmentation
// identity. Locally fragmentable WANT traffic retains an ID even when DF is
// set, while INTERFACE traffic needs one because DF remains clear and a router
// may fragment it despite local source fragmentation being disabled.
func (policy sourceFragmentation) requiresIPv4ID() bool {
	return policy.allow || !policy.dontFragment
}

// sourceFragmentationForMode returns the Linux IP_PMTUDISC_* output policy.
func sourceFragmentationForMode(mode PathMTUDiscovery) sourceFragmentation {
	switch mode {
	case PathMTUDiscoveryWant:
		return sourceFragmentation{allow: true, dontFragment: true}
	case PathMTUDiscoveryDo, PathMTUDiscoveryProbe:
		return sourceFragmentation{dontFragment: true}
	case PathMTUDiscoveryInterface:
		return sourceFragmentation{}
	case PathMTUDiscoveryOmit, PathMTUDiscoveryDont:
		return sourceFragmentation{allow: true}
	default:
		return sourceFragmentation{allow: true}
	}
}

// pathMTUOutputPolicy selects the destination or interface MTU together with
// the socket's local fragmentation and IPv4 DF behavior.
func (s *Stack) pathMTUOutputPolicy(destination netip.Addr, mode PathMTUDiscovery) (int, sourceFragmentation) {
	mtu := s.network.Load().mtu
	if mode < PathMTUDiscoveryProbe {
		mtu = s.mtuFor(destination)
	}
	return mtu, sourceFragmentationForMode(mode)
}

// acceptsPathMTU reports whether Linux accepts ICMP PMTU updates in mode.
func (mode PathMTUDiscovery) acceptsPathMTU() bool {
	return mode != PathMTUDiscoveryInterface && mode != PathMTUDiscoveryOmit
}

// fragmentKey identifies one IPv4 or IPv6 fragmented datagram and keeps
// internal loopback separate from packets received on the embedding link.
type fragmentKey struct {
	source, target netip.Addr
	identification uint32
	protocol       byte
	v6             bool
	loopback       bool
}

// fragmentPiece is a non-overlapping byte range in a fragment set.
type fragmentPiece struct {
	offset int
	data   []byte
}

// fragmentSet retains one bounded, incomplete datagram.
type fragmentSet struct {
	pieces      []fragmentPiece
	total       int
	bytes       int
	created     time.Time
	updated     time.Time
	protocol    byte
	source      netip.Addr
	target      netip.Addr
	identifier  uint32
	v6          bool
	ecnMask     byte
	options     ipPacketOptions
	maximum     int
	maxSize     int
	maxDFSize   int
	header      []byte
	nextHeader  int
	firstPacket []byte
}

// parsedFragment is one validated fragment extracted from its IP envelope.
type parsedFragment struct {
	key           fragmentKey
	protocol      byte
	offset        int
	more          bool
	payload       []byte
	identifier    uint32
	ecn           byte
	options       ipPacketOptions
	maximum       int
	packetSize    int
	df            bool
	header        []byte
	nextHeader    int
	original      []byte
	truncated     bool
	parameter     bool
	parameterCode byte
	parameterAt   uint32
}

// runFragmentCleaner releases incomplete sets even when no later fragments
// arrive.
func (s *Stack) runFragmentCleaner() {
	timer := newOwnedTimer()
	defer timer.close()
	var timeout <-chan time.Time
	for {
		s.fragmentMu.Lock()
		now := time.Now()
		expired := s.cleanFragmentsLocked(now)
		next, haveNext := s.nextFragmentExpiryLocked()
		s.fragmentMu.Unlock()
		s.sendFragmentTimeouts(expired)
		timer.stop()
		timeout = nil
		if haveNext {
			delay := time.Until(next)
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		select {
		case <-timeout:
			timer.consumed()
		case <-s.fragmentWake:
		case <-s.closeCh:
			return
		}
	}
}

// reassemblePacketStatus distinguishes a valid fragment waiting for more data
// from malformed input. pending is true only when the fragment was retained.
func (s *Stack) reassemblePacketStatus(packet []byte, now time.Time, loopback bool) (_ []byte, pending bool) {
	fragment, ok := parseFragment(packet)
	network := s.network.Load()
	if !ok || fragment.truncated || fragment.parameter || !s.acceptsInboundDestination(network, fragment.key.target, loopback) ||
		!validInboundFragmentSource(network, fragment.key.source, fragment.key.target, fragment.protocol) {
		return nil, false
	}
	fragment.key.loopback = loopback
	s.fragmentMu.Lock()
	select {
	case <-s.closeCh:
		s.fragmentMu.Unlock()
		return nil, false
	default:
	}
	expired := s.cleanFragmentsLocked(now)
	defer func() {
		s.fragmentMu.Unlock()
		s.sendFragmentTimeouts(expired)
	}()
	set := s.fragments[fragment.key]
	if set == nil {
		for len(s.fragments) >= fragmentMaximumSets {
			s.evictOldestFragmentExceptLocked(nil)
		}
		set = &fragmentSet{
			total: -1, created: now, updated: now, protocol: fragment.protocol,
			source: fragment.key.source, target: fragment.key.target,
			identifier: fragment.identifier, v6: fragment.key.v6, ecnMask: 1 << fragment.ecn, options: fragment.options,
			maximum: fragmentMaximumDatagram,
		}
		if fragment.key.v6 || fragment.offset == 0 {
			set.maximum = fragment.maximum
		} else {
			set.maximum -= 20
		}
		s.fragments[fragment.key] = set
		select {
		case s.fragmentWake <- struct{}{}:
		default:
		}
	} else {
		// RFC 8200 permits the Next Header fields of IPv6 fragments to
		// differ and requires reassembly to use the value from offset zero.
		// IPv4 includes Protocol in the reassembly key, so a mismatch there
		// still identifies a different datagram.
		if !set.v6 && set.protocol != fragment.protocol {
			s.removeFragmentLocked(fragment.key, set)
			return nil, false
		}
	}
	if !fragment.key.v6 && fragment.more && len(fragment.payload)%8 != 0 {
		trimmed := len(fragment.payload) &^ 7
		discarded := len(fragment.payload) - trimmed
		fragment.payload = fragment.payload[:trimmed]
		fragment.original = fragment.original[:len(fragment.original)-discarded]
		fragment.packetSize -= discarded
	}
	end := fragment.offset + len(fragment.payload)
	if len(fragment.payload) == 0 || end > set.maximum || set.total > set.maximum ||
		set.total >= 0 && end > set.total {
		s.removeFragmentLocked(fragment.key, set)
		return nil, false
	}
	duplicate := fragmentRangeCovered(set.pieces, fragment.offset, end)
	for _, existing := range set.pieces {
		existingEnd := existing.offset + len(existing.data)
		if fragment.offset < existingEnd && existing.offset < end {
			if !duplicate {
				// RFC 5722 requires dropping the complete datagram on a
				// partial overlap. Linux applies the same policy to IPv4.
				s.removeFragmentLocked(fragment.key, set)
				return nil, false
			}
			break
		}
	}
	if !fragment.more {
		if set.total >= 0 && set.total != end {
			s.removeFragmentLocked(fragment.key, set)
			return nil, false
		}
		set.total = end
		for _, existing := range set.pieces {
			if existing.offset+len(existing.data) > set.total {
				s.removeFragmentLocked(fragment.key, set)
				return nil, false
			}
		}
	}
	if now.Before(set.created) {
		// Concurrent Write calls can acquire fragmentMu out of arrival order.
		// Reassembly lifetime is defined by the earliest fragment, not by the
		// goroutine that happened to win the lock.
		set.created = now
		select {
		case s.fragmentWake <- struct{}{}:
		default:
		}
	}
	if duplicate {
		// Linux's shared IPv4/IPv6 fragment queue treats a completely
		// covered range as a duplicate. Ignore its ECN and header metadata,
		// but retain a newly learned final size so a duplicate last fragment
		// can complete an otherwise contiguous queue.
		if set.total < 0 {
			return nil, true
		}
		next := 0
		for _, piece := range set.pieces {
			if piece.offset != next {
				return nil, true
			}
			next += len(piece.data)
		}
		if next != set.total {
			return nil, true
		}
		return s.finishFragmentReassembly(fragment.key, set)
	}
	if fragment.offset == 0 {
		// Reassembly metadata follows the fragment containing the original
		// upper-layer header, regardless of arrival order.
		set.protocol = fragment.protocol
		set.options = fragment.options
		set.nextHeader = fragment.nextHeader
		set.maximum = fragment.maximum
		if set.total > set.maximum {
			s.removeFragmentLocked(fragment.key, set)
			return nil, false
		}
		for _, existing := range set.pieces {
			if existing.offset+len(existing.data) > set.maximum {
				s.removeFragmentLocked(fragment.key, set)
				return nil, false
			}
		}
	}
	if len(set.pieces) >= fragmentMaximumPieces {
		s.removeFragmentLocked(fragment.key, set)
		return nil, false
	}
	candidateECN := set.ecnMask | 1<<fragment.ecn
	if candidateECN&1 != 0 && candidateECN != 1 {
		s.removeFragmentLocked(fragment.key, set)
		return nil, false
	}
	set.ecnMask = candidateECN
	retainedBytes := len(fragment.payload)
	if fragment.offset == 0 {
		// firstPacket is needed for a possible reassembly-timeout error. Keep
		// the piece as a slice of that copy instead of retaining a second copy
		// of the same payload, and charge the complete allocation to the bound.
		retainedBytes = len(fragment.original)
	}
	for retainedBytes > fragmentMaximumBytes-s.fragmentBytes && len(s.fragments) > 1 {
		if !s.evictOldestFragmentExceptLocked(set) {
			break
		}
	}
	if retainedBytes > fragmentMaximumBytes-s.fragmentBytes {
		s.removeFragmentLocked(fragment.key, set)
		return nil, false
	}
	var data []byte
	if fragment.offset == 0 {
		set.firstPacket = append([]byte(nil), fragment.original...)
		set.header = set.firstPacket[:len(fragment.header)]
		payloadOffset := len(set.firstPacket) - len(fragment.payload)
		data = set.firstPacket[payloadOffset:]
	} else {
		data = append([]byte(nil), fragment.payload...)
	}
	piece := fragmentPiece{offset: fragment.offset, data: data}
	insertAt := len(set.pieces)
	for index, existing := range set.pieces {
		if fragment.offset < existing.offset {
			insertAt = index
			break
		}
	}
	set.pieces = append(set.pieces, fragmentPiece{})
	copy(set.pieces[insertAt+1:], set.pieces[insertAt:])
	set.pieces[insertAt] = piece
	set.bytes += retainedBytes
	if now.After(set.updated) {
		set.updated = now
	}
	if fragment.packetSize > set.maxSize {
		set.maxSize = fragment.packetSize
	}
	if fragment.df && fragment.packetSize > set.maxDFSize {
		set.maxDFSize = fragment.packetSize
	}
	s.fragmentBytes += retainedBytes
	if set.total < 0 {
		return nil, true
	}
	next := 0
	for _, piece := range set.pieces {
		if piece.offset != next {
			return nil, true
		}
		next += len(piece.data)
	}
	if next != set.total {
		return nil, true
	}
	return s.finishFragmentReassembly(fragment.key, set)
}

// fragmentRangeCovered reports whether sorted, non-overlapping pieces cover
// every byte in [start,end).
func fragmentRangeCovered(pieces []fragmentPiece, start, end int) bool {
	if start >= end {
		return false
	}
	cursor := start
	for _, piece := range pieces {
		pieceEnd := piece.offset + len(piece.data)
		if pieceEnd <= cursor {
			continue
		}
		if piece.offset > cursor {
			return false
		}
		cursor = pieceEnd
		if cursor >= end {
			return true
		}
	}
	return false
}

// finishFragmentReassembly builds and removes one contiguous fragment set.
func (s *Stack) finishFragmentReassembly(key fragmentKey, set *fragmentSet) ([]byte, bool) {
	s.removeFragmentLocked(key, set)
	ecn, valid := fragmentECN(set.ecnMask)
	if !valid {
		return nil, false
	}
	set.options.trafficClass = set.options.trafficClass&^3 | ecn
	dontFragment := !set.v6 && set.maxDFSize != 0 && set.maxDFSize == set.maxSize
	packet := buildReassembledPacket(set, dontFragment)
	setPacketECN(packet, ecn)
	return packet, false
}

// buildReassembledPacket removes fragmentation state while preserving the
// complete offset-zero IPv4 header or IPv6 unfragmentable header chain.
func buildReassembledPacket(set *fragmentSet, dontFragment bool) []byte {
	if !set.v6 {
		if len(set.header) < 20 || len(set.header)+set.total > 65535 {
			return nil
		}
		packet := make([]byte, len(set.header)+set.total)
		copy(packet, set.header)
		for _, piece := range set.pieces {
			copy(packet[len(set.header)+piece.offset:], piece.data)
		}
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		field := uint16(0)
		if dontFragment {
			field = 0x4000
		}
		binary.BigEndian.PutUint16(packet[6:8], field)
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:len(set.header)]))
		return packet
	}
	if len(set.header) < 40 || set.nextHeader < 0 || set.nextHeader >= len(set.header) || len(set.header)-40+set.total > 65535 {
		return nil
	}
	packet := make([]byte, len(set.header)+set.total)
	copy(packet, set.header)
	packet[set.nextHeader] = set.protocol
	for _, piece := range set.pieces {
		copy(packet[len(set.header)+piece.offset:], piece.data)
	}
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	return packet
}

// parseFragment validates IPv4 fragmentation fields or an IPv6 fragment
// extension header.
func parseFragment(packet []byte) (parsedFragment, bool) {
	if len(packet) < 1 {
		return parsedFragment{}, false
	}
	if packet[0]>>4 == 4 {
		if len(packet) < 20 {
			return parsedFragment{}, false
		}
		headerSize := int(packet[0]&0x0f) * 4
		totalSize := int(binary.BigEndian.Uint16(packet[2:4]))
		field := binary.BigEndian.Uint16(packet[6:8])
		// Linux accepts DF on received fragments and remembers the largest DF
		// fragment for later PMTU handling. RFC 791's reserved flag still has
		// to be zero.
		if headerSize < 20 || totalSize <= headerSize || totalSize > len(packet) || checksum(packet[:headerSize]) != 0 || field&0x3fff == 0 || field&0x8000 != 0 {
			return parsedFragment{}, false
		}
		source := netip.AddrFrom4([4]byte(packet[12:16]))
		target := netip.AddrFrom4([4]byte(packet[16:20]))
		identifier := uint32(binary.BigEndian.Uint16(packet[4:6]))
		protocol := packet[9]
		key := fragmentKey{source: source, target: target, identification: identifier, protocol: protocol}
		if optionAt, malformed := malformedIPv4Option(packet[20:headerSize]); malformed {
			return parsedFragment{
				key: key, protocol: protocol, offset: int(field&0x1fff) * 8,
				identifier: identifier, original: packet[:totalSize], parameter: true, parameterAt: uint32(20 + optionAt),
			}, true
		}
		if !validateIPv4Options(packet[20:headerSize]) {
			return parsedFragment{}, false
		}
		return parsedFragment{
			key:      key,
			protocol: protocol,
			offset:   int(field&0x1fff) * 8, more: field&0x2000 != 0,
			payload: packet[headerSize:totalSize], identifier: identifier, ecn: packet[1] & 3,
			options:    ipPacketOptions{hopLimit: packet[8], trafficClass: packet[1]},
			maximum:    fragmentMaximumDatagram - headerSize,
			packetSize: totalSize, df: field&0x4000 != 0,
			header: packet[:headerSize], nextHeader: 9,
			original: packet[:totalSize],
		}, true
	}
	if packet[0]>>4 != 6 || len(packet) < 48 {
		return parsedFragment{}, false
	}
	end := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
	if end > len(packet) {
		return parsedFragment{}, false
	}
	source := netip.AddrFrom16([16]byte(packet[8:24]))
	target := netip.AddrFrom16([16]byte(packet[24:40]))
	flowLabel := uint32(packet[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(packet[2:4]))
	next, nextHeader, offset := packet[6], 6, 40
	seenHop := false
	for offset <= end {
		switch next {
		case 0, 60:
			if next == 0 && (offset != 40 || seenHop) {
				return parsedFragment{
					key: fragmentKey{source: source, target: target, v6: true}, original: packet[:end],
					parameter: true, parameterCode: 1, parameterAt: uint32(nextHeader),
				}, true
			}
			if end-offset < 8 {
				return parsedFragment{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset {
				return parsedFragment{}, false
			}
			valid, action, optionOffset := inspectIPv6Options(packet[offset : offset+length])
			if !valid {
				if action >= 2 && (action == 2 || !target.IsMulticast()) {
					return parsedFragment{
						key: fragmentKey{source: source, target: target, v6: true}, original: packet[:end],
						parameter: true, parameterCode: 2, parameterAt: uint32(offset + optionOffset),
					}, true
				}
				return parsedFragment{}, false
			}
			if next == 0 {
				seenHop = true
			}
			next, nextHeader, offset = packet[offset], offset, offset+length
		case 43:
			if end-offset < 8 {
				return parsedFragment{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset {
				return parsedFragment{}, false
			}
			if packet[offset+3] != 0 {
				return parsedFragment{
					key: fragmentKey{source: source, target: target, v6: true}, original: packet[:end],
					parameter: true, parameterCode: 0, parameterAt: uint32(offset + 2),
				}, true
			}
			next, nextHeader, offset = packet[offset], offset, offset+length
		case 44:
			if end-offset < 8 {
				return parsedFragment{}, false
			}
			field := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			// The offset and M flag distinguish a real fragment from an
			// atomic fragment. RFC 8200 says both reserved fields are ignored
			// on reception, including on non-atomic fragments.
			if field&0xfff9 == 0 {
				return parsedFragment{}, false
			}
			protocol := packet[offset]
			identifier := binary.BigEndian.Uint32(packet[offset+4 : offset+8])
			fragmentOffset := int(field & 0xfff8)
			more := field&1 != 0
			payload := packet[offset+8 : end]
			maximum := fragmentMaximumDatagram - (offset - 40)
			parameter := more && len(payload)%8 != 0
			parameterAt := uint32(4)
			if fragmentOffset > maximum-len(payload) {
				parameter = true
				parameterAt = uint32(offset + 2)
			}
			return parsedFragment{
				key:      fragmentKey{source: source, target: target, identification: identifier, v6: true},
				protocol: protocol,
				offset:   fragmentOffset, more: more,
				payload: payload, identifier: identifier, ecn: packet[1] >> 4 & 3,
				options: ipPacketOptions{hopLimit: packet[7], trafficClass: (packet[0]&0x0f)<<4 | packet[1]>>4, flowLabel: flowLabel},
				header:  packet[:offset], nextHeader: nextHeader,
				maximum:   maximum,
				original:  packet[:end],
				truncated: fragmentOffset == 0 && more && !ipv6FirstFragmentHeaderComplete(protocol, payload),
				parameter: parameter, parameterAt: parameterAt,
			}, true
		default:
			return parsedFragment{}, false
		}
	}
	return parsedFragment{}, false
}

// ipv6FirstFragmentHeaderComplete enforces RFC 7112 for known upper-layer
// protocols while allowing an unknown protocol to reach a raw IP socket. The
// input begins immediately after the Fragment header.
func ipv6FirstFragmentHeaderComplete(next byte, payload []byte) bool {
	for offset := 0; ; {
		switch next {
		case 0, 43, 60, 135:
			if len(payload)-offset < 8 {
				return false
			}
			length := (int(payload[offset+1]) + 1) * 8
			if length > len(payload)-offset {
				return false
			}
			next, offset = payload[offset], offset+length
		case 51:
			if len(payload)-offset < 8 {
				return false
			}
			length := (int(payload[offset+1]) + 2) * 4
			if length > len(payload)-offset {
				return false
			}
			next, offset = payload[offset], offset+length
		case 44:
			return false
		case protocolTCP:
			if len(payload)-offset < tcpHeaderSize {
				return false
			}
			headerSize := int(payload[offset+12]>>4) * 4
			return headerSize < tcpHeaderSize || headerSize <= len(payload)-offset
		case protocolUDP, protocolICMPv4, protocolICMPv6, 50:
			return len(payload)-offset >= 8
		case 33, 132:
			return len(payload)-offset >= 12
		case 59:
			return true
		default:
			return true
		}
	}
}

// fragmentECN applies the RFC 3168 section 5.3 table used by Linux to the OR
// mask of ECN codepoints observed in one datagram.
func fragmentECN(mask byte) (byte, bool) {
	switch mask {
	case 1 << 0:
		return 0, true
	case 1 << 1:
		return 1, true
	case 1 << 2:
		return 2, true
	case 1 << 3, 1<<3 | 1<<1, 1<<3 | 1<<2, 1<<3 | 1<<1 | 1<<2:
		return 3, true
	default:
		// Linux's ip_frag_ecn_table rejects every unlisted combination,
		// including ECT(0) mixed with ECT(1) without a CE fragment.
		return 0, false
	}
}

// cleanFragmentsLocked removes expired sets while s.fragmentMu is held and
// returns the offset-zero fragments eligible for an ICMP timeout response.
func (s *Stack) cleanFragmentsLocked(now time.Time) []*fragmentSet {
	var expired []*fragmentSet
	for key, set := range s.fragments {
		if !now.Before(fragmentExpiry(set)) {
			s.removeFragmentLocked(key, set)
			s.stats.fragmentTimeouts.Add(1)
			if len(set.firstPacket) != 0 {
				expired = append(expired, set)
			}
		}
	}
	return expired
}

// fragmentExpiry returns the fixed deadline measured from the first-arriving
// fragment in one set.
func fragmentExpiry(set *fragmentSet) time.Time {
	lifetime := fragmentIPv4Lifetime
	if set.v6 {
		lifetime = fragmentIPv6Lifetime
	}
	return set.created.Add(lifetime)
}

// nextFragmentExpiryLocked returns the earliest pending deadline while
// fragmentMu is held.
func (s *Stack) nextFragmentExpiryLocked() (time.Time, bool) {
	var next time.Time
	for _, set := range s.fragments {
		expiry := fragmentExpiry(set)
		if next.IsZero() || expiry.Before(next) {
			next = expiry
		}
	}
	return next, !next.IsZero()
}

// sendFragmentTimeouts emits best-effort diagnostics for expired datagrams.
func (s *Stack) sendFragmentTimeouts(expired []*fragmentSet) {
	for _, set := range expired {
		_ = s.sendFragmentReassemblyTimeout(set)
	}
}

// evictOldestFragmentExceptLocked makes byte-capacity room without discarding
// the datagram currently receiving a new fragment.
func (s *Stack) evictOldestFragmentExceptLocked(except *fragmentSet) bool {
	var oldestKey fragmentKey
	var oldest *fragmentSet
	for key, set := range s.fragments {
		if set == except {
			continue
		}
		if oldest == nil || set.updated.Before(oldest.updated) {
			oldestKey, oldest = key, set
		}
	}
	if oldest != nil {
		s.removeFragmentLocked(oldestKey, oldest)
		s.stats.fragmentEvictions.Add(1)
		return true
	}
	return false
}

// removeFragmentLocked deletes a set and updates global byte accounting.
func (s *Stack) removeFragmentLocked(key fragmentKey, set *fragmentSet) {
	if s.fragments[key] != set {
		return
	}
	delete(s.fragments, key)
	s.fragmentBytes -= set.bytes
}

// discardFragment removes any incomplete datagram matching key.
func (s *Stack) discardFragment(key fragmentKey) {
	s.fragmentMu.Lock()
	if set := s.fragments[key]; set != nil {
		s.removeFragmentLocked(key, set)
	}
	s.fragmentMu.Unlock()
}

// pruneFragments discards incomplete datagrams whose destination was removed
// by a configuration or multicast-membership update. They must not later emit
// timeout errors or become deliverable after their admission state changed.
func (s *Stack) pruneFragments(network *networkState) {
	s.fragmentMu.Lock()
	for key, set := range s.fragments {
		if !s.acceptsInboundDestination(network, key.target, key.loopback) {
			s.removeFragmentLocked(key, set)
		}
	}
	s.fragmentMu.Unlock()
}

// ipPayloadPackets builds one packet or a complete source-fragmented sequence
// using the current destination PMTU.
func (s *Stack) ipPayloadPackets(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool) ([][]byte, error) {
	return s.ipPayloadPacketsWithOptions(source, target, protocol, payload, allowFragment, ipPacketOptions{})
}

// ipPayloadPacketsWithOptions is the raw-output form of ipPayloadPackets.
func (s *Stack) ipPayloadPacketsWithOptions(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool, options ipPacketOptions) ([][]byte, error) {
	fragmentation := sourceFragmentation{allow: allowFragment, dontFragment: !allowFragment}
	return s.ipPayloadPacketsForMTU(source, target, protocol, payload, fragmentation, options, s.mtuFor(target))
}

// ipPayloadPacketsForMTU builds output against an explicit ceiling. Ordinary
// traffic passes the confirmed PMTU; packetization-layer probes pass the
// first-hop MTU and disable fragmentation.
func (s *Stack) ipPayloadPacketsForMTU(source, target netip.Addr, protocol byte, payload []byte, fragmentation sourceFragmentation, options ipPacketOptions, mtu int) ([][]byte, error) {
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = s.automaticFlowLabel(source, target, protocol, payload)
		options.flowLabelSet = true
	}
	var identification uint16
	if source.Is4() && fragmentation.requiresIPv4ID() {
		// A router may fragment any IPv4 datagram without DF, so reserve its
		// ID even when it currently fits the managed link MTU.
		identification = uint16(s.ipv4ID.Add(1))
	}
	headerSize := ipHeaderSize(source, target, len(payload))
	if headerSize == 0 {
		return nil, syscall.EMSGSIZE
	}
	if headerSize+len(payload) <= mtu {
		packet := buildIPPacketWithOptions(source, target, protocol, payload, identification, fragmentation.dontFragment, options)
		return [][]byte{packet}, nil
	}
	if !fragmentation.allow {
		return nil, syscall.EMSGSIZE
	}
	var fragments [][]byte
	if source.Is4() {
		fragments = buildIPv4FragmentsWithOptions(source, target, protocol, payload, mtu, identification, options)
	} else {
		fragments = buildIPv6FragmentsWithOptions(source, target, protocol, payload, mtu, s.ipv6FragmentID.Add(1), options)
	}
	if len(fragments) == 0 {
		return nil, syscall.EMSGSIZE
	}
	return fragments, nil
}

// writeIPPayloadUntilOptionsForMTU emits output against an explicit packet
// ceiling while preserving socket deadline and closure behavior.
func (s *Stack) writeIPPayloadUntilOptionsForMTU(source, target netip.Addr, protocol byte, payload []byte, fragmentation sourceFragmentation, options ipPacketOptions, mtu int, state socketWriteState) error {
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = s.automaticFlowLabel(source, target, protocol, payload)
		options.flowLabelSet = true
	}
	headerSize := ipHeaderSize(source, target, len(payload))
	if headerSize == 0 {
		return syscall.EMSGSIZE
	}
	if headerSize+len(payload) <= mtu {
		var identification uint16
		if source.Is4() && fragmentation.requiresIPv4ID() {
			identification = uint16(s.ipv4ID.Add(1))
		}
		queue, loopback := s.outputQueueFor(target)
		slot, err := s.reservePacketUntil(queue, loopback, state)
		if err != nil {
			return err
		}
		packet, reusable := queue.acquireBuffer(headerSize + len(payload))
		if !marshalIPHeader(packet, source, target, protocol, identification, fragmentation.dontFragment, options) {
			queue.releaseBuffer(packet, reusable)
			queue.releaseReserved(slot)
			return syscall.EMSGSIZE
		}
		copy(packet[headerSize:], payload)
		if !queue.enqueueReservedPacket(slot, packet, reusable) {
			return ErrClosed
		}
		s.recordOutput(loopback)
		return nil
	}
	if !fragmentation.allow {
		return syscall.EMSGSIZE
	}
	return s.writeIPFragmentsUntilOptionsForMTU(source, target, protocol, payload, nil, options, mtu, state)
}

// writeIPPayload atomically queues one best-effort protocol response or its
// complete source-fragmented sequence without waiting for device capacity.
func (s *Stack) writeIPPayload(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool) error {
	if _, routed := s.network.Load().routeFor(target); !routed {
		return syscall.ENETUNREACH
	}
	packets, err := s.ipPayloadPackets(source, target, protocol, payload, allowFragment)
	if err != nil {
		return err
	}
	return s.tryWritePackets(packets)
}

// writeIPPayloadUntilOptions emits raw IP output with mutable deadline state.
func (s *Stack) writeIPPayloadUntilOptions(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool, options ipPacketOptions, state socketWriteState) error {
	fragmentation := sourceFragmentation{allow: allowFragment, dontFragment: !allowFragment}
	return s.writeIPPayloadUntilOptionsForMTU(source, target, protocol, payload, fragmentation, options, s.mtuFor(target), state)
}

// writeIPFragmentsUntilOptionsForMTU writes fragments directly into reserved
// queue storage. first and second are adjacent logical payload regions; this
// lets UDP prepend its virtual header without gathering the complete datagram.
func (s *Stack) writeIPFragmentsUntilOptionsForMTU(source, target netip.Addr, protocol byte, first, second []byte, options ipPacketOptions, mtu int, state socketWriteState) error {
	payloadSize := len(first) + len(second)
	maximum := (mtu - 20) &^ 7
	headerSize := 20
	identification4 := uint16(0)
	identification6 := uint32(0)
	if source.Is4() {
		if maximum < 8 || payloadSize > 65515 {
			return syscall.EMSGSIZE
		}
		identification4 = uint16(s.ipv4ID.Add(1))
	} else {
		headerSize = 48
		maximum = (mtu - headerSize) &^ 7
		if maximum < 8 || payloadSize > 65535 {
			return syscall.EMSGSIZE
		}
		identification6 = s.ipv6FragmentID.Add(1)
	}
	queue, loopback := s.outputQueueFor(target)
	for offset := 0; offset < payloadSize; {
		size := payloadSize - offset
		if size > maximum {
			size = maximum
		}
		slot, err := s.reservePacketUntil(queue, loopback, state)
		if err != nil {
			return err
		}
		packet, reusable := queue.acquireBuffer(headerSize + size)
		if source.Is4() {
			if !marshalIPHeader(packet, source, target, protocol, identification4, false, options) {
				queue.releaseBuffer(packet, reusable)
				queue.releaseReserved(slot)
				return syscall.EMSGSIZE
			}
			field := uint16(offset / 8)
			if offset+size < payloadSize {
				field |= 0x2000
			}
			binary.BigEndian.PutUint16(packet[6:8], field)
			packet[10], packet[11] = 0, 0
			binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		} else {
			if !marshalIPHeader(packet, source, target, 44, 0, false, options) {
				queue.releaseBuffer(packet, reusable)
				queue.releaseReserved(slot)
				return syscall.EMSGSIZE
			}
			fragment := packet[40:48]
			fragment[0], fragment[1] = protocol, 0
			field := uint16(offset)
			if offset+size < payloadSize {
				field |= 1
			}
			binary.BigEndian.PutUint16(fragment[2:4], field)
			binary.BigEndian.PutUint32(fragment[4:8], identification6)
		}
		copyIPPayloadParts(packet[headerSize:], offset, first, second)
		if !queue.enqueueReservedPacket(slot, packet, reusable) {
			return ErrClosed
		}
		s.recordOutput(loopback)
		offset += size
	}
	return nil
}

// copyIPPayloadParts copies one logical range from adjacent payload regions.
func copyIPPayloadParts(destination []byte, offset int, first, second []byte) {
	if offset < len(first) {
		n := copy(destination, first[offset:])
		destination = destination[n:]
		offset = 0
	} else {
		offset -= len(first)
	}
	if len(destination) != 0 {
		copy(destination, second[offset:])
	}
}

// buildIPv4FragmentsWithOptions preserves raw output fields on every fragment.
func buildIPv4FragmentsWithOptions(source, target netip.Addr, protocol byte, payload []byte, mtu int, identification uint16, options ipPacketOptions) [][]byte {
	maximum := (mtu - 20) &^ 7
	if maximum < 8 || len(payload) > 65515 {
		return nil
	}
	result := make([][]byte, 0, (len(payload)+maximum-1)/maximum)
	for offset := 0; offset < len(payload); {
		size := len(payload) - offset
		if size > maximum {
			size = maximum
		}
		packet := buildIPPacketWithOptions(source, target, protocol, payload[offset:offset+size], identification, false, options)
		field := uint16(offset / 8)
		if offset+size < len(payload) {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(packet[6:8], field)
		packet[10], packet[11] = 0, 0
		binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
		result = append(result, packet)
		offset += size
	}
	return result
}

// buildIPv6FragmentsWithOptions preserves raw output fields on every fragment.
func buildIPv6FragmentsWithOptions(source, target netip.Addr, protocol byte, payload []byte, mtu int, identification uint32, options ipPacketOptions) [][]byte {
	maximum := (mtu - 48) &^ 7
	if maximum < 8 || len(payload) > 65535 {
		return nil
	}
	result := make([][]byte, 0, (len(payload)+maximum-1)/maximum)
	for offset := 0; offset < len(payload); {
		size := len(payload) - offset
		if size > maximum {
			size = maximum
		}
		packet := make([]byte, 48+size)
		if !marshalIPHeader(packet, source, target, 44, 0, false, options) {
			return nil
		}
		fragment := packet[40:]
		fragment[0] = protocol
		field := uint16(offset)
		if offset+size < len(payload) {
			field |= 1
		}
		binary.BigEndian.PutUint16(fragment[2:4], field)
		binary.BigEndian.PutUint32(fragment[4:8], identification)
		copy(fragment[8:], payload[offset:offset+size])
		result = append(result, packet)
		offset += size
	}
	return result
}

// icmpForwarderIPPackets applies header-included fragmentation while retaining
// all caller-supplied IP fields that are meaningful on emitted fragments.
func (s *Stack) icmpForwarderIPPackets(reply icmpForwarderIPPacket, mtu int) ([][]byte, error) {
	if reply.parsed.source.Is4() && binary.BigEndian.Uint16(reply.packet[4:6]) == 0 {
		// Linux IP_HDRINCL fills an omitted IPv4 ID even when this host does
		// not need to fragment the packet. A later router may still fragment
		// a packet without DF, and matching this for DF packets keeps raw
		// output independent of the currently observed path MTU.
		binary.BigEndian.PutUint16(reply.packet[4:6], uint16(s.ipv4ID.Add(1)))
		headerSize := int(reply.packet[0]&0x0f) * 4
		reply.packet[10], reply.packet[11] = 0, 0
		binary.BigEndian.PutUint16(reply.packet[10:12], checksum(reply.packet[:headerSize]))
	}
	if len(reply.packet) <= mtu {
		return [][]byte{reply.packet}, nil
	}
	if reply.parsed.source.Is4() {
		if reply.ipv4DF {
			return nil, syscall.EMSGSIZE
		}
		identification := binary.BigEndian.Uint16(reply.packet[4:6])
		packets := fragmentICMPForwarderIPv4(reply.packet, mtu, identification)
		if len(packets) == 0 {
			return nil, syscall.EMSGSIZE
		}
		return packets, nil
	}
	identification := s.ipv6FragmentID.Add(1)
	packet := reply.packet
	point := reply.ipv6Fragment
	transportOffset := len(packet) - len(reply.parsed.payload)
	if point.atomicOffset >= 0 {
		// Unlike IPv4 IP_HDRINCL's zero ID convention, every 32-bit IPv6
		// Fragment Identification value is caller-selected, including zero.
		identification = binary.BigEndian.Uint32(packet[point.atomicOffset+4 : point.atomicOffset+8])
		// Refragmentation replaces the caller's atomic Fragment header rather
		// than nesting another one. Rewire its preceding Next Header field,
		// remove the eight bytes, and then rediscover the canonical insertion
		// point because the old header may have used a non-recommended order.
		packet[point.atomicPrevious] = packet[point.atomicOffset]
		copy(packet[point.atomicOffset:], packet[point.atomicOffset+8:])
		packet = packet[:len(packet)-8]
		transportOffset -= 8
		var ok bool
		point, ok = inspectIPv6ForwarderFragmentPoint(packet)
		if !ok || point.atomicOffset >= 0 {
			return nil, syscall.EINVAL
		}
	}
	packets := fragmentICMPForwarderIPv6(packet, point, transportOffset, mtu, identification)
	if len(packets) == 0 {
		return nil, syscall.EMSGSIZE
	}
	return packets, nil
}

// laterIPv4FragmentOptions follows Linux ip_options_fragment: it preserves the
// original option alignment and replaces each non-copied option with NOP bytes.
// RFC 791 copied options therefore remain at the same offsets in every fragment.
func laterIPv4FragmentOptions(options []byte) []byte {
	if len(options) == 0 {
		return nil
	}
	result := append([]byte(nil), options...)
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == 0 {
			break
		}
		if kind == 1 {
			offset++
			continue
		}
		length := int(options[offset+1])
		if kind&0x80 == 0 {
			for index := offset; index < offset+length; index++ {
				result[index] = 1
			}
		}
		offset += length
	}
	return result
}

// fragmentICMPForwarderIPv4 preserves the complete option set on the first
// fragment and only copied options on later fragments, as required by RFC 791.
func fragmentICMPForwarderIPv4(packet []byte, mtu int, identification uint16) [][]byte {
	originalHeaderSize := int(packet[0]&0x0f) * 4
	payload := packet[originalHeaderSize:]
	copiedOptions := laterIPv4FragmentOptions(packet[20:originalHeaderSize])
	fragments := make([][]byte, 0, (len(packet)+mtu-1)/mtu)
	for offset := 0; offset < len(payload); {
		options := copiedOptions
		if offset == 0 {
			options = packet[20:originalHeaderSize]
		}
		headerSize := 20 + len(options)
		maximum := (mtu - headerSize) &^ 7
		if maximum < 8 {
			return nil
		}
		size := len(payload) - offset
		if size > maximum {
			size = maximum
		}
		fragment := make([]byte, headerSize+size)
		copy(fragment[:20], packet[:20])
		copy(fragment[20:headerSize], options)
		fragment[0] = 0x40 | byte(headerSize/4)
		binary.BigEndian.PutUint16(fragment[2:4], uint16(len(fragment)))
		binary.BigEndian.PutUint16(fragment[4:6], identification)
		field := uint16(offset / 8)
		if offset+size < len(payload) {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(fragment[6:8], field)
		fragment[10], fragment[11] = 0, 0
		binary.BigEndian.PutUint16(fragment[10:12], checksum(fragment[:headerSize]))
		copy(fragment[headerSize:], payload[offset:offset+size])
		fragments = append(fragments, fragment)
		offset += size
	}
	return fragments
}

// fragmentICMPForwarderIPv6 inserts or reuses one Fragment header after the
// RFC 8200 unfragmentable extension chain. The upper-layer bytes and checksum
// remain unchanged across the complete fragment sequence.
func fragmentICMPForwarderIPv6(packet []byte, point ipv6ForwarderFragmentPoint, transportOffset, mtu int, identification uint32) [][]byte {
	prefix := packet[:point.insertion]
	fragmentable := packet[point.insertion:]
	maximum := (mtu - len(prefix) - 8) &^ 7
	// RFC 7112 requires the first fragment to contain the complete IPv6
	// extension-header chain and the upper-layer header. ICMP's fixed header
	// is eight bytes; refuse a path that cannot carry it without splitting a
	// header, rather than emitting a sequence every conforming receiver drops.
	icmpEnd := transportOffset + 8
	if maximum < 8 || icmpEnd-point.insertion > maximum {
		return nil
	}
	fragments := make([][]byte, 0, (len(fragmentable)+maximum-1)/maximum)
	for offset := 0; offset < len(fragmentable); {
		size := len(fragmentable) - offset
		if size > maximum {
			size = maximum
		}
		fragment := make([]byte, len(prefix)+8+size)
		copy(fragment, prefix)
		fragment[point.previous] = 44
		header := fragment[len(prefix) : len(prefix)+8]
		header[0], header[1] = point.next, 0
		field := uint16(offset)
		if offset+size < len(fragmentable) {
			field |= 1
		}
		binary.BigEndian.PutUint16(header[2:4], field)
		binary.BigEndian.PutUint32(header[4:8], identification)
		copy(fragment[len(prefix)+8:], fragmentable[offset:offset+size])
		binary.BigEndian.PutUint16(fragment[4:6], uint16(len(fragment)-40))
		fragments = append(fragments, fragment)
		offset += size
	}
	return fragments
}
