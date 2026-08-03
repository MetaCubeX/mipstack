package mipstack

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"syscall"
	"time"
)

const (
	// fragmentMaximumSets bounds concurrent incomplete datagrams.
	fragmentMaximumSets = 128
	// fragmentMaximumPieces bounds fragment metadata per datagram.
	fragmentMaximumPieces = 128
	// fragmentMaximumBytes bounds payload retained across the stack.
	fragmentMaximumBytes = 4 * 1024 * 1024
	// fragmentMaximumDatagram is the IPv6 non-jumbogram payload limit. IPv4
	// subtracts its minimum header before applying it.
	fragmentMaximumDatagram = 65535
	// fragmentLifetime expires incomplete fragment sets.
	fragmentLifetime = 30 * time.Second
)

// fragmentKey identifies one IPv4 or IPv6 fragmented datagram.
type fragmentKey struct {
	source, target netip.Addr
	identification uint32
	protocol       byte
	v6             bool
}

// fragmentPiece is a non-overlapping byte range in a fragment set.
type fragmentPiece struct {
	offset int
	data   []byte
}

// fragmentSet retains one bounded, incomplete datagram.
type fragmentSet struct {
	pieces     []fragmentPiece
	total      int
	bytes      int
	updated    time.Time
	protocol   byte
	source     netip.Addr
	target     netip.Addr
	identifier uint32
	v6         bool
	ecn        byte
	options    ipPacketOptions
	maximum    int
}

// parsedFragment is one validated fragment extracted from its IP envelope.
type parsedFragment struct {
	key        fragmentKey
	offset     int
	more       bool
	payload    []byte
	identifier uint32
	ecn        byte
	options    ipPacketOptions
	maximum    int
}

// runFragmentCleaner releases incomplete sets even when no later fragments
// arrive.
func (s *Stack) runFragmentCleaner() {
	ticker := time.NewTicker(fragmentLifetime / 2)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			s.fragmentMu.Lock()
			s.cleanFragmentsLocked(now)
			s.fragmentMu.Unlock()
		case <-s.closeCh:
			return
		}
	}
}

// reassemblePacket inserts one fragment and returns a complete minimal IP
// packet when every byte is present.
func (s *Stack) reassemblePacket(packet []byte, now time.Time) []byte {
	result, _ := s.reassemblePacketStatus(packet, now)
	return result
}

// reassemblePacketStatus distinguishes a valid fragment waiting for more data
// from malformed input. pending is true only when the fragment was retained.
func (s *Stack) reassemblePacketStatus(packet []byte, now time.Time) (_ []byte, pending bool) {
	fragment, ok := parseFragment(packet)
	if !ok || !s.isLocal(fragment.key.target) || fragment.key.source.IsUnspecified() || fragment.key.source.IsMulticast() {
		return nil, false
	}
	s.fragmentMu.Lock()
	defer s.fragmentMu.Unlock()
	s.cleanFragmentsLocked(now)
	set := s.fragments[fragment.key]
	if set == nil {
		for len(s.fragments) >= fragmentMaximumSets {
			s.evictOldestFragmentLocked()
		}
		set = &fragmentSet{
			total: -1, updated: now, protocol: fragment.key.protocol,
			source: fragment.key.source, target: fragment.key.target,
			identifier: fragment.identifier, v6: fragment.key.v6, ecn: fragment.ecn, options: fragment.options,
			maximum: fragmentMaximumDatagram,
		}
		if fragment.key.v6 || fragment.offset == 0 {
			set.maximum = fragment.maximum
		} else {
			set.maximum -= 20
		}
		s.fragments[fragment.key] = set
	} else {
		mergedECN, valid := mergeFragmentECN(set.ecn, fragment.ecn)
		if !valid {
			s.removeFragmentLocked(fragment.key, set)
			return nil, false
		}
		set.ecn = mergedECN
	}
	if fragment.offset == 0 {
		// Reassembly metadata follows the fragment containing the original
		// upper-layer header, regardless of arrival order.
		set.options = fragment.options
		if !fragment.key.v6 {
			set.maximum = fragment.maximum
		}
	}
	end := fragment.offset + len(fragment.payload)
	if len(fragment.payload) == 0 || end > set.maximum || set.total > set.maximum || fragment.more && len(fragment.payload)%8 != 0 ||
		set.total >= 0 && end > set.total || len(set.pieces) >= fragmentMaximumPieces {
		s.removeFragmentLocked(fragment.key, set)
		return nil, false
	}
	for _, existing := range set.pieces {
		existingEnd := existing.offset + len(existing.data)
		if fragment.offset < existingEnd && existing.offset < end {
			// RFC 5722 requires dropping the complete datagram on overlap.
			s.removeFragmentLocked(fragment.key, set)
			return nil, false
		}
	}
	if !fragment.more {
		if set.total >= 0 && set.total != end {
			s.removeFragmentLocked(fragment.key, set)
			return nil, false
		}
		set.total = end
	}
	if len(fragment.payload) > fragmentMaximumBytes-s.fragmentBytes {
		s.removeFragmentLocked(fragment.key, set)
		return nil, false
	}
	data := append([]byte(nil), fragment.payload...)
	set.pieces = append(set.pieces, fragmentPiece{offset: fragment.offset, data: data})
	set.bytes += len(data)
	set.updated = now
	s.fragmentBytes += len(data)
	if set.total < 0 {
		return nil, true
	}
	sort.Slice(set.pieces, func(left, right int) bool { return set.pieces[left].offset < set.pieces[right].offset })
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
	payload := make([]byte, set.total)
	for _, piece := range set.pieces {
		copy(payload[piece.offset:], piece.data)
	}
	s.removeFragmentLocked(fragment.key, set)
	set.options.trafficClass = set.options.trafficClass&^3 | set.ecn
	packet = buildIPPacketWithOptions(set.source, set.target, set.protocol, payload, uint16(set.identifier), false, set.options)
	setPacketECN(packet, set.ecn)
	return packet, false
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
		if headerSize < 20 || totalSize <= headerSize || totalSize > len(packet) || checksum(packet[:headerSize]) != 0 || field&0x3fff == 0 || field&0xc000 != 0 {
			return parsedFragment{}, false
		}
		if !validateIPv4Options(packet[20:headerSize]) {
			return parsedFragment{}, false
		}
		source := netip.AddrFrom4([4]byte(packet[12:16]))
		target := netip.AddrFrom4([4]byte(packet[16:20]))
		identifier := uint32(binary.BigEndian.Uint16(packet[4:6]))
		protocol := packet[9]
		return parsedFragment{
			key:    fragmentKey{source: source, target: target, identification: identifier, protocol: protocol},
			offset: int(field&0x1fff) * 8, more: field&0x2000 != 0,
			payload: packet[headerSize:totalSize], identifier: identifier, ecn: packet[1] & 3,
			options: ipPacketOptions{hopLimit: packet[8], trafficClass: packet[1]},
			maximum: fragmentMaximumDatagram - headerSize,
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
	next, offset := packet[6], 40
	seenHop, seenRouting, destinationHeaders := false, false, 0
	for offset <= end {
		switch next {
		case 0, 60:
			if end-offset < 8 {
				return parsedFragment{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset || !validateIPv6Options(packet[offset:offset+length]) {
				return parsedFragment{}, false
			}
			if next == 0 {
				if offset != 40 || seenHop {
					return parsedFragment{}, false
				}
				seenHop = true
			} else {
				destinationHeaders++
				if destinationHeaders > 2 {
					return parsedFragment{}, false
				}
			}
			next, offset = packet[offset], offset+length
		case 43:
			if end-offset < 8 || seenRouting {
				return parsedFragment{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset || packet[offset+3] != 0 {
				return parsedFragment{}, false
			}
			seenRouting = true
			next, offset = packet[offset], offset+length
		case 44:
			if end-offset < 8 {
				return parsedFragment{}, false
			}
			field := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			if field&0x0006 != 0 || field == 0 {
				return parsedFragment{}, false
			}
			protocol := packet[offset]
			identifier := binary.BigEndian.Uint32(packet[offset+4 : offset+8])
			return parsedFragment{
				key:    fragmentKey{source: source, target: target, identification: identifier, protocol: protocol, v6: true},
				offset: int(field & 0xfff8), more: field&1 != 0,
				payload: packet[offset+8 : end], identifier: identifier, ecn: packet[1] >> 4 & 3,
				options: ipPacketOptions{hopLimit: packet[7], trafficClass: (packet[0]&0x0f)<<4 | packet[1]>>4},
				maximum: fragmentMaximumDatagram - (offset - 40),
			}, true
		default:
			return parsedFragment{}, false
		}
	}
	return parsedFragment{}, false
}

// mergeFragmentECN preserves RFC 3168's mandatory reassembly behavior. CE
// dominates a consistent ECT codepoint; unspecified mixed Not-ECT/ECT and
// ECT(0)/ECT(1) combinations are conservatively rejected.
func mergeFragmentECN(current, incoming byte) (byte, bool) {
	current &= 3
	incoming &= 3
	if current == incoming {
		return current, true
	}
	if current == 0 || incoming == 0 || current == 1 && incoming == 2 || current == 2 && incoming == 1 {
		return 0, false
	}
	if current == 3 || incoming == 3 {
		return 3, true
	}
	return 0, false
}

// cleanFragmentsLocked removes expired sets while s.fragmentMu is held.
func (s *Stack) cleanFragmentsLocked(now time.Time) {
	for key, set := range s.fragments {
		if now.Sub(set.updated) >= fragmentLifetime {
			s.removeFragmentLocked(key, set)
			s.stats.fragmentTimeouts.Add(1)
		}
	}
}

// evictOldestFragmentLocked makes room for a new set.
func (s *Stack) evictOldestFragmentLocked() {
	var oldestKey fragmentKey
	var oldest *fragmentSet
	for key, set := range s.fragments {
		if oldest == nil || set.updated.Before(oldest.updated) {
			oldestKey, oldest = key, set
		}
	}
	if oldest != nil {
		s.removeFragmentLocked(oldestKey, oldest)
		s.stats.fragmentEvictions.Add(1)
	}
}

// removeFragmentLocked deletes a set and updates global byte accounting.
func (s *Stack) removeFragmentLocked(key fragmentKey, set *fragmentSet) {
	if s.fragments[key] != set {
		return
	}
	delete(s.fragments, key)
	s.fragmentBytes -= set.bytes
}

// ipPayloadPackets builds one packet or a complete source-fragmented sequence
// using the current destination PMTU.
func (s *Stack) ipPayloadPackets(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool) ([][]byte, error) {
	return s.ipPayloadPacketsWithOptions(source, target, protocol, payload, allowFragment, ipPacketOptions{})
}

// ipPayloadPacketsWithOptions is the raw-output form of ipPayloadPackets.
func (s *Stack) ipPayloadPacketsWithOptions(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool, options ipPacketOptions) ([][]byte, error) {
	packet := buildIPPacketWithOptions(source, target, protocol, payload, s.nextPacketID(), !allowFragment, options)
	if len(packet) == 0 {
		return nil, syscall.EMSGSIZE
	}
	mtu := s.mtuFor(target)
	if len(packet) <= mtu {
		return [][]byte{packet}, nil
	}
	if !allowFragment {
		return nil, syscall.EMSGSIZE
	}
	var fragments [][]byte
	if source.Is4() {
		fragments = buildIPv4FragmentsWithOptions(source, target, protocol, payload, mtu, s.nextPacketID(), options)
	} else {
		fragments = buildIPv6FragmentsWithOptions(source, target, protocol, payload, mtu, s.nextFragmentID(), options)
	}
	if len(fragments) == 0 {
		return nil, syscall.EMSGSIZE
	}
	return fragments, nil
}

// writeIPPayload emits one packet or a complete source-fragmented sequence.
func (s *Stack) writeIPPayload(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool) error {
	packets, err := s.ipPayloadPackets(source, target, protocol, payload, allowFragment)
	if err != nil {
		return err
	}
	for _, packet := range packets {
		if err = s.writePacket(packet); err != nil {
			return err
		}
	}
	return nil
}

// writeIPPayloadUntilOptions emits raw IP output with mutable deadline state.
func (s *Stack) writeIPPayloadUntilOptions(source, target netip.Addr, protocol byte, payload []byte, allowFragment bool, options ipPacketOptions, state func() (time.Time, <-chan struct{}, bool)) error {
	packets, err := s.ipPayloadPacketsWithOptions(source, target, protocol, payload, allowFragment, options)
	if err != nil {
		return err
	}
	for _, packet := range packets {
		if err = s.writePacketUntil(packet, state); err != nil {
			return err
		}
	}
	return nil
}

// buildIPv4Fragments divides payload on eight-byte boundaries.
func buildIPv4Fragments(source, target netip.Addr, protocol byte, payload []byte, mtu int, identification uint16) [][]byte {
	return buildIPv4FragmentsWithOptions(source, target, protocol, payload, mtu, identification, ipPacketOptions{})
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
		fragmentPayload := make([]byte, 8+size)
		fragmentPayload[0] = protocol
		field := uint16(offset)
		if offset+size < len(payload) {
			field |= 1
		}
		binary.BigEndian.PutUint16(fragmentPayload[2:4], field)
		binary.BigEndian.PutUint32(fragmentPayload[4:8], identification)
		copy(fragmentPayload[8:], payload[offset:offset+size])
		result = append(result, buildIPPacketWithOptions(source, target, 44, fragmentPayload, 0, false, options))
		offset += size
	}
	return result
}
