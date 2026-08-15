package mipstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"syscall"
	"time"
)

// ipv6FragmentPoint identifies where a source Fragment header must be inserted
// and which preceding Next Header byte names the fragmentable part.
type ipv6FragmentPoint struct {
	previous       int
	insertion      int
	next           byte
	atomicOffset   int
	atomicPrevious int
}

// inspectIPv6ForwarderFragmentPoint validates the extension chain relevant to
// source fragmentation. RFC 8200 places Hop-by-Hop and Routing headers in the
// Per-Fragment headers; a Destination Options header before Routing remains in
// that part, while a final Destination Options header is fragmentable.
// Existing non-atomic fragments and multiple Fragment headers are rejected.
// One atomic Fragment header is recorded independently from the canonical
// insertion point so refragmentation can remove it even when the caller used
// a non-recommended but receiver-valid extension-header order.
func inspectIPv6ForwarderFragmentPoint(packet []byte) (ipv6FragmentPoint, bool) {
	return inspectIPv6FragmentPoint(packet, true)
}

// inspectIPv6FragmentPoint locates the RFC 8200 boundary between the
// Per-Fragment headers and fragmentable data. Forwarder replies additionally
// reject active Routing headers because their base addresses are not sufficient
// to construct a safe response; the standalone packet codec has no such policy.
func inspectIPv6FragmentPoint(packet []byte, rejectActiveRouting bool) (ipv6FragmentPoint, bool) {
	if len(packet) < 40 {
		return ipv6FragmentPoint{}, false
	}
	end := len(packet)
	next, previous, offset := packet[6], 6, 40
	point := ipv6FragmentPoint{
		previous: 6, insertion: 40, next: next,
		atomicOffset: -1, atomicPrevious: -1,
	}
	seenHop, fragmentableStarted := false, false
	for offset <= end {
		switch next {
		case IPv6ExtensionHeaderHopByHop:
			if offset != 40 || seenHop || end-offset < 8 {
				return ipv6FragmentPoint{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset {
				return ipv6FragmentPoint{}, false
			}
			seenHop = true
			next, previous, offset = packet[offset], offset, offset+length
			point.previous, point.insertion, point.next = previous, offset, next
		case IPv6ExtensionHeaderRouting:
			if fragmentableStarted || end-offset < 8 {
				return ipv6FragmentPoint{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset || rejectActiveRouting && packet[offset+3] != 0 {
				return ipv6FragmentPoint{}, false
			}
			next, previous, offset = packet[offset], offset, offset+length
			point.previous, point.insertion, point.next = previous, offset, next
		case IPv6ExtensionHeaderDestination:
			if end-offset < 8 {
				return ipv6FragmentPoint{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset {
				return ipv6FragmentPoint{}, false
			}
			next, previous, offset = packet[offset], offset, offset+length
			// A pre-routing Destination Options header belongs to the
			// Per-Fragment headers only if a Routing header actually follows.
			// Never move point here: a later Routing header moves it past both
			// headers, while an upper-layer header leaves this header in the
			// fragmentable part. Continuing the scan also finds a Fragment header
			// that appears after final-destination options.
		case IPv6ExtensionHeaderAuthentication, IPv6ExtensionHeaderMobility:
			length, valid := ipv6ExtensionHeaderLength(next, packet[offset:])
			if !valid {
				return ipv6FragmentPoint{}, false
			}
			fragmentableStarted = true
			next, previous, offset = packet[offset], offset, offset+length
		case IPv6ExtensionHeaderFragment:
			if end-offset < 8 || point.atomicOffset >= 0 {
				return ipv6FragmentPoint{}, false
			}
			field := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			if field&0xfff9 != 0 {
				return ipv6FragmentPoint{}, false
			}
			point.atomicOffset, point.atomicPrevious = offset, previous
			next, previous, offset = packet[offset], offset, offset+8
		default:
			return point, true
		}
	}
	return ipv6FragmentPoint{}, false
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

// IPPacketReassembly incrementally reassembles one fragmented IP packet. The
// zero value is ready for use. Add copies every retained byte, so callers may
// reuse the input packet's backing storage after Add returns.
//
// An IPPacketReassembly must not be copied after its first use. Its methods are
// not safe for concurrent use; callers processing one datagram concurrently
// must serialize Add and Reset calls.
type IPPacketReassembly struct {
	initialized bool
	pieces      []fragmentPiece
	total       int
	bytes       int
	protocol    byte
	source      netip.Addr
	target      netip.Addr
	identifier  uint32
	v6          bool
	ecnMask     byte
	maximum     int
	maxSize     int
	maxDFSize   int
	header      []byte
	nextHeader  int
	firstPacket []byte
}

// fragmentSet adds Stack-owned lifecycle and accounting to one packet
// reassembly. Timeout, eviction, admission, and ICMP policy intentionally stay
// outside IPPacketReassembly.
type fragmentSet struct {
	IPPacketReassembly
	created        time.Time
	updated        time.Time
	accountedBytes int
}

// ipPacketReassemblyFragment is the validated protocol state consumed by one
// packet reassembly, independent of Stack admission and timeout policy.
type ipPacketReassemblyFragment struct {
	source     netip.Addr
	target     netip.Addr
	protocol   byte
	offset     int
	more       bool
	payload    []byte
	identifier uint32
	v6         bool
	ecn        byte
	maximum    int
	packetSize int
	df         bool
	header     []byte
	nextHeader int
	original   []byte
	owned      bool
}

// reassemblyKey applies the protocol-specific datagram identity rules. IPv4
// includes Protocol in its key; IPv6 deliberately does not include the
// Fragment header's Next Header value.
func (f ipPacketReassemblyFragment) reassemblyKey(loopback bool) fragmentKey {
	key := fragmentKey{
		source: f.source, target: f.target, identification: f.identifier,
		v6: f.v6, loopback: loopback,
	}
	if !f.v6 {
		key.protocol = f.protocol
	}
	return key
}

// parsedFragment adds Stack-specific routing and diagnostic metadata to one
// fragment parsed directly from an inbound wire packet.
type parsedFragment struct {
	ipPacketReassemblyFragment
	truncated     bool
	parameter     bool
	parameterCode byte
	parameterAt   uint32
}

// Add adds one non-atomic IPv4 or IPv6 fragment. When complete is false and
// err is nil, the receiver remains incomplete; the input was either retained
// or recognized as a duplicate. A completed packet owns its IPv4Options and
// Payload storage, and the receiver is reset for reuse before Add returns.
//
// An unfragmented packet, an IPv6 atomic fragment, an invalid standalone
// packet, or a fragment belonging to a different packet reports
// syscall.EINVAL without changing an existing reassembly. Other standalone
// validation errors are returned without changing it. A range already fully
// covered by retained fragments is a duplicate: its payload, ECN, and header
// metadata are ignored, but a duplicate final fragment may establish the
// packet's final length. A duplicate never completes reassembly by itself.
// Once a valid fragment is associated with the current packet, a conflicting
// length, ECN value, or partial overlap invalidates and resets the entire
// in-progress reassembly.
func (r *IPPacketReassembly) Add(fragment IPPacket) (packet IPPacket, complete bool, err error) {
	parsed, err := publicReassemblyFragment(fragment)
	if err != nil {
		return IPPacket{}, false, err
	}
	wire, pending, _, err := r.addFragment(parsed, 0)
	if err != nil {
		return IPPacket{}, false, err
	}
	if pending {
		return IPPacket{}, false, nil
	}
	packet, err = ParseIPPacket(wire)
	if err != nil {
		return IPPacket{}, false, err
	}
	return packet, true, nil
}

// Reset discards an incomplete packet and releases all retained storage.
// Reset is idempotent.
func (r *IPPacketReassembly) Reset() {
	*r = IPPacketReassembly{}
}

// publicReassemblyFragment validates a semantic packet and converts it to the
// representation shared with Stack's raw-wire ingress. Only an offset-zero
// fragment needs a complete owned wire image: later fragments contribute no
// header fields to the reassembled packet.
func publicReassemblyFragment(packet IPPacket) (ipPacketReassemblyFragment, error) {
	packet, headerSize, totalSize, err := packet.wireLayout()
	if err != nil {
		return ipPacketReassemblyFragment{}, err
	}
	view, fragmented := packet.Fragment()
	if !fragmented || view.IsAtomic() {
		return ipPacketReassemblyFragment{}, syscall.EINVAL
	}
	if packet.Source.Is4() {
		fragment := ipPacketReassemblyFragment{
			source: packet.Source, target: packet.Destination,
			protocol: byte(packet.Protocol), offset: view.Offset, more: view.MoreFragments,
			payload: view.Payload, identifier: view.Identification, ecn: byte(packet.TrafficClass) & 3,
			maximum: fragmentMaximumDatagram - headerSize, packetSize: totalSize, df: packet.DontFragment,
			nextHeader: 9,
		}
		if view.Offset == 0 {
			wire := make([]byte, totalSize)
			marshalPublicIPPacket(wire, packet, headerSize)
			fragment.payload = wire[headerSize:]
			fragment.header = wire[:headerSize]
			fragment.original = wire
			fragment.owned = true
		}
		return fragment, nil
	}
	fragmentOffset, previous, valid := locateIPv6FragmentHeader(byte(packet.Protocol), packet.Payload)
	if !valid || fragmentOffset+8 > len(packet.Payload) {
		return ipPacketReassemblyFragment{}, syscall.EINVAL
	}
	if view.Offset == 0 && view.MoreFragments && !ipv6FirstFragmentHeaderComplete(byte(view.Protocol), view.Payload) {
		return ipPacketReassemblyFragment{}, syscall.EINVAL
	}
	maximum := fragmentMaximumDatagram
	if view.Offset == 0 {
		maximum -= fragmentOffset
	}
	fragment := ipPacketReassemblyFragment{
		source: packet.Source, target: packet.Destination, v6: true,
		protocol: byte(view.Protocol), offset: view.Offset, more: view.MoreFragments,
		payload: packet.Payload[fragmentOffset+8:], identifier: view.Identification,
		ecn:     byte(packet.TrafficClass) & 3,
		maximum: maximum, packetSize: totalSize,
	}
	if view.Offset == 0 {
		wire := make([]byte, totalSize)
		marshalPublicIPPacket(wire, packet, headerSize)
		wireOffset := 40 + fragmentOffset
		fragment.original = wire
		fragment.header = wire[:wireOffset]
		fragment.payload = wire[wireOffset+8:]
		fragment.nextHeader = 6
		if previous >= 0 {
			fragment.nextHeader = 40 + previous
		}
		fragment.owned = true
	}
	return fragment, nil
}

// locateIPv6FragmentHeader returns the Fragment header's payload-relative
// offset and the preceding extension header's payload-relative offset. A
// previous value of -1 identifies the base header's Next Header field.
func locateIPv6FragmentHeader(first byte, payload []byte) (fragmentOffset, previous int, ok bool) {
	next, offset, previous := first, 0, -1
	for offset <= len(payload) && isTraversableIPv6ExtensionHeader(next) {
		length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
		if !valid {
			return 0, 0, false
		}
		if next == IPv6ExtensionHeaderFragment {
			return offset, previous, true
		}
		previous = offset
		next, offset = payload[offset], offset+length
	}
	return 0, 0, false
}

// addFragment contains the single-datagram state machine shared by the public
// API and Stack. maximumPieces is a Stack table policy; zero accepts every
// fragment range representable by a non-jumbogram packet. added reports a new
// retained range rather than a duplicate.
func (r *IPPacketReassembly) addFragment(fragment ipPacketReassemblyFragment, maximumPieces int) (_ []byte, pending, added bool, err error) {
	if !r.initialized {
		*r = IPPacketReassembly{
			initialized: true, total: -1, protocol: fragment.protocol,
			source: fragment.source, target: fragment.target,
			identifier: fragment.identifier, v6: fragment.v6,
			ecnMask: 1 << fragment.ecn,
			maximum: fragmentMaximumDatagram,
		}
		if fragment.v6 || fragment.offset == 0 {
			r.maximum = fragment.maximum
		} else {
			r.maximum -= 20
		}
	} else if r.v6 != fragment.v6 || r.source != fragment.source || r.target != fragment.target ||
		r.identifier != fragment.identifier || !r.v6 && r.protocol != fragment.protocol {
		return nil, false, false, syscall.EINVAL
	}
	if !fragment.v6 && fragment.more && len(fragment.payload)%8 != 0 {
		trimmed := len(fragment.payload) &^ 7
		discarded := len(fragment.payload) - trimmed
		fragment.payload = fragment.payload[:trimmed]
		fragment.original = fragment.original[:len(fragment.original)-discarded]
		fragment.packetSize -= discarded
	}
	end := fragment.offset + len(fragment.payload)
	if len(fragment.payload) == 0 || end > r.maximum || r.total > r.maximum || r.total >= 0 && end > r.total {
		r.Reset()
		return nil, false, false, syscall.EINVAL
	}
	duplicate, overlaps := fragmentRangeState(r.pieces, fragment.offset, end)
	if overlaps && !duplicate {
		r.Reset()
		return nil, false, false, syscall.EINVAL
	}
	if !fragment.more && r.total >= 0 && r.total != end {
		r.Reset()
		return nil, false, false, syscall.EINVAL
	}
	if !fragment.more {
		r.total = end
		for _, existing := range r.pieces {
			if existing.offset+len(existing.data) > r.total {
				r.Reset()
				return nil, false, false, syscall.EINVAL
			}
		}
	}
	if duplicate {
		return nil, true, false, nil
	}
	if fragment.offset == 0 {
		r.protocol = fragment.protocol
		r.nextHeader = fragment.nextHeader
		r.maximum = fragment.maximum
		if r.total > r.maximum {
			r.Reset()
			return nil, false, false, syscall.EINVAL
		}
		for _, existing := range r.pieces {
			if existing.offset+len(existing.data) > r.maximum {
				r.Reset()
				return nil, false, false, syscall.EINVAL
			}
		}
	}
	if maximumPieces > 0 && len(r.pieces) >= maximumPieces {
		r.Reset()
		return nil, false, false, ErrResourceLimit
	}
	candidateECN := r.ecnMask | 1<<fragment.ecn
	if candidateECN&1 != 0 && candidateECN != 1 {
		r.Reset()
		return nil, false, false, syscall.EINVAL
	}
	r.ecnMask = candidateECN
	retainedBytes := len(fragment.payload)
	if fragment.offset == 0 {
		if len(fragment.original) == 0 || len(fragment.header) < 20 || len(fragment.header) > len(fragment.original) ||
			len(fragment.payload) > len(fragment.original)-len(fragment.header) {
			r.Reset()
			return nil, false, false, syscall.EINVAL
		}
		retainedBytes = len(fragment.original)
	}
	var data []byte
	if fragment.offset == 0 {
		if fragment.owned {
			r.firstPacket = fragment.original
		} else {
			r.firstPacket = append([]byte(nil), fragment.original...)
		}
		r.header = r.firstPacket[:len(fragment.header)]
		payloadOffset := len(r.firstPacket) - len(fragment.payload)
		data = r.firstPacket[payloadOffset:]
	} else {
		data = append([]byte(nil), fragment.payload...)
	}
	piece := fragmentPiece{offset: fragment.offset, data: data}
	insertAt := sort.Search(len(r.pieces), func(index int) bool {
		return r.pieces[index].offset > fragment.offset
	})
	r.pieces = append(r.pieces, fragmentPiece{})
	copy(r.pieces[insertAt+1:], r.pieces[insertAt:])
	r.pieces[insertAt] = piece
	r.bytes += retainedBytes
	if fragment.packetSize > r.maxSize {
		r.maxSize = fragment.packetSize
	}
	if fragment.df && fragment.packetSize > r.maxDFSize {
		r.maxDFSize = fragment.packetSize
	}
	if !r.complete() {
		return nil, true, true, nil
	}
	wire := r.finishWire()
	r.Reset()
	if wire == nil {
		return nil, false, true, syscall.EINVAL
	}
	return wire, false, true, nil
}

// complete uses the non-overlapping-range invariant: retained payload bytes
// can equal the final length only when they cover the complete [0,total)
// interval. bytes includes the offset-zero packet header and, for IPv6, the
// Fragment header removed during reassembly.
func (r *IPPacketReassembly) complete() bool {
	overhead := len(r.header)
	if r.v6 && overhead != 0 {
		overhead += 8
	}
	return r.total >= 0 && r.bytes-overhead == r.total
}

// finishWire constructs one complete packet without retaining caller storage.
func (r *IPPacketReassembly) finishWire() []byte {
	ecn, valid := fragmentECN(r.ecnMask)
	if !valid {
		return nil
	}
	dontFragment := !r.v6 && r.maxDFSize != 0 && r.maxDFSize == r.maxSize
	packet := buildReassembledPacket(r, dontFragment)
	setPacketECN(packet, ecn)
	return packet
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
	if !ok || fragment.truncated || fragment.parameter || !s.acceptsInboundDestination(network, fragment.target, loopback) ||
		!validInboundFragmentSource(network, fragment.source, fragment.target, fragment.protocol) {
		return nil, false
	}
	key := fragment.reassemblyKey(loopback)
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
	set := s.fragments[key]
	if set == nil {
		for len(s.fragments) >= fragmentMaximumSets {
			s.evictOldestFragmentExceptLocked(nil)
		}
		set = &fragmentSet{created: now, updated: now}
		s.fragments[key] = set
		select {
		case s.fragmentWake <- struct{}{}:
		default:
		}
	}
	packet, pending, added, err := set.addFragment(fragment.ipPacketReassemblyFragment, fragmentMaximumPieces)
	s.fragmentBytes += set.bytes - set.accountedBytes
	set.accountedBytes = set.bytes
	if err != nil {
		if !set.initialized {
			s.removeFragmentLocked(key, set)
		}
		return nil, false
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
	if added && now.After(set.updated) {
		set.updated = now
	}
	for pending && s.fragmentBytes > fragmentMaximumBytes && len(s.fragments) > 1 {
		if !s.evictOldestFragmentExceptLocked(set) {
			break
		}
	}
	if pending && s.fragmentBytes > fragmentMaximumBytes {
		s.removeFragmentLocked(key, set)
		set.Reset()
		return nil, false
	}
	if pending {
		return nil, true
	}
	s.removeFragmentLocked(key, set)
	return packet, false
}

// fragmentRangeState reports whether sorted, non-overlapping pieces completely
// cover [start,end) and whether any piece intersects that range.
func fragmentRangeState(pieces []fragmentPiece, start, end int) (covered, overlaps bool) {
	if start >= end {
		return false, false
	}
	first := sort.Search(len(pieces), func(index int) bool {
		return pieces[index].offset+len(pieces[index].data) > start
	})
	if first == len(pieces) || pieces[first].offset >= end {
		return false, false
	}
	cursor := start
	for _, piece := range pieces[first:] {
		if piece.offset >= end {
			break
		}
		if piece.offset > cursor {
			return false, true
		}
		cursor = piece.offset + len(piece.data)
		if cursor >= end {
			return true, true
		}
	}
	return false, true
}

// buildReassembledPacket removes fragmentation state while preserving the
// complete offset-zero IPv4 header or IPv6 Per-Fragment header chain.
func buildReassembledPacket(set *IPPacketReassembly, dontFragment bool) []byte {
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
		if optionAt, malformed := malformedIPv4Option(packet[20:headerSize]); malformed {
			return parsedFragment{
				ipPacketReassemblyFragment: ipPacketReassemblyFragment{
					source: source, target: target, protocol: protocol, offset: int(field&0x1fff) * 8,
					identifier: identifier, original: packet[:totalSize],
				},
				parameter: true, parameterAt: uint32(20 + optionAt),
			}, true
		}
		if !validateIPv4Options(packet[20:headerSize]) {
			return parsedFragment{}, false
		}
		return parsedFragment{
			ipPacketReassemblyFragment: ipPacketReassemblyFragment{
				source: source, target: target, protocol: protocol,
				offset: int(field&0x1fff) * 8, more: field&0x2000 != 0,
				payload: packet[headerSize:totalSize], identifier: identifier, ecn: packet[1] & 3,
				maximum: fragmentMaximumDatagram - headerSize, packetSize: totalSize, df: field&0x4000 != 0,
				header: packet[:headerSize], nextHeader: 9, original: packet[:totalSize],
			},
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
	next, nextHeader, offset := packet[6], 6, 40
	seenHop := false
	for offset <= end {
		switch next {
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderDestination:
			if next == IPv6ExtensionHeaderHopByHop && (offset != 40 || seenHop) {
				return parsedFragment{
					ipPacketReassemblyFragment: ipPacketReassemblyFragment{source: source, target: target, v6: true, original: packet[:end]},
					parameter:                  true, parameterCode: 1, parameterAt: uint32(nextHeader),
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
						ipPacketReassemblyFragment: ipPacketReassemblyFragment{source: source, target: target, v6: true, original: packet[:end]},
						parameter:                  true, parameterCode: 2, parameterAt: uint32(offset + optionOffset),
					}, true
				}
				return parsedFragment{}, false
			}
			if next == IPv6ExtensionHeaderHopByHop {
				seenHop = true
			}
			next, nextHeader, offset = packet[offset], offset, offset+length
		case IPv6ExtensionHeaderRouting:
			if end-offset < 8 {
				return parsedFragment{}, false
			}
			length := (int(packet[offset+1]) + 1) * 8
			if length > end-offset {
				return parsedFragment{}, false
			}
			if packet[offset+3] != 0 {
				return parsedFragment{
					ipPacketReassemblyFragment: ipPacketReassemblyFragment{source: source, target: target, v6: true, original: packet[:end]},
					parameter:                  true, parameterCode: 0, parameterAt: uint32(offset + 2),
				}, true
			}
			next, nextHeader, offset = packet[offset], offset, offset+length
		case IPv6ExtensionHeaderFragment:
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
			// Only the offset-zero fragment supplies the Per-Fragment headers
			// retained by reassembly. RFC 8200 permits those headers to differ
			// in later fragments, so their local length cannot narrow the
			// structurally valid fragmentable-data range.
			maximum := fragmentMaximumDatagram
			if fragmentOffset == 0 {
				maximum -= offset - 40
			}
			parameter := more && len(payload)%8 != 0
			parameterAt := uint32(4)
			if fragmentOffset > maximum-len(payload) {
				parameter = true
				parameterAt = uint32(offset + 2)
			}
			return parsedFragment{
				ipPacketReassemblyFragment: ipPacketReassemblyFragment{
					source: source, target: target, protocol: protocol,
					offset: fragmentOffset, more: more, payload: payload,
					identifier: identifier, v6: true, ecn: packet[1] >> 4 & 3,
					header: packet[:offset], nextHeader: nextHeader,
					maximum: maximum, original: packet[:end],
				},
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
		case IPv6ExtensionHeaderHopByHop, IPv6ExtensionHeaderRouting,
			IPv6ExtensionHeaderDestination, IPv6ExtensionHeaderAuthentication,
			IPv6ExtensionHeaderMobility:
			length, valid := ipv6ExtensionHeaderLength(next, payload[offset:])
			if !valid {
				return false
			}
			next, offset = payload[offset], offset+length
		case IPv6ExtensionHeaderFragment:
			return false
		default:
			_, complete := ipv6FirstFragmentUpperLayerLength(next, payload[offset:])
			return complete
		}
	}
}

// ipv6FirstFragmentUpperLayerLength returns the complete known upper-layer
// header size required by RFC 7112. Unknown protocols remain admissible because
// their header boundary cannot be inferred from a protocol number alone.
func ipv6FirstFragmentUpperLayerLength(protocol byte, payload []byte) (int, bool) {
	required := 0
	switch protocol {
	case ProtocolNoNextHeader:
		return 0, true
	case ProtocolTCP:
		if len(payload) < tcpHeaderSize {
			return 0, false
		}
		required = int(payload[12]>>4) * 4
		if required < tcpHeaderSize {
			required = tcpHeaderSize
		}
	case ProtocolIGMP, ProtocolUDP, ProtocolICMPv4, ProtocolICMPv6, ProtocolESP, 136: // UDP-Lite.
		required = 8
	case 4: // IPv4 encapsulation terminates the IPv6 header chain.
		if len(payload) < 20 {
			return 0, false
		}
		required = int(payload[0]&0x0f) * 4
		if required < 20 {
			required = 20
		}
	case 33: // DCCP Data Offset covers its type-specific header and options.
		if len(payload) < 12 {
			return 0, false
		}
		required = int(payload[4]) * 4
		minimum := 12
		if payload[8]&1 != 0 {
			minimum = 16
		}
		if required < minimum {
			required = minimum
		}
	case 41: // A nested IPv6 base header is an upper-layer header for RFC 7112.
		required = 40
	case 132: // SCTP has a twelve-byte common header.
		required = 12
	default:
		return 0, true
	}
	return required, required <= len(payload)
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
	s.fragmentBytes -= set.accountedBytes
	set.accountedBytes = 0
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
	if state.dontWait {
		payload := first
		if len(second) != 0 {
			payload = make([]byte, payloadSize)
			copy(payload, first)
			copy(payload[len(first):], second)
		}
		packets, err := s.ipPayloadPacketsForMTU(source, target, protocol, payload, sourceFragmentation{allow: true}, options, mtu)
		if err != nil {
			return err
		}
		if err = s.tryWritePackets(packets); errors.Is(err, ErrResourceLimit) {
			return syscall.EAGAIN
		}
		return err
	}
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
			if !marshalIPHeader(packet, source, target, IPv6ExtensionHeaderFragment, 0, false, options) {
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

// marshalPublicIPv4Fragments fragments or refragments one validated IPPacket.
// The original offset and M flag are part of the fragmentable range, while
// Linux-style NOP replacement retains the received option-area alignment.
func marshalPublicIPv4Fragments(packet IPPacket, mtu int) ([][]byte, error) {
	headerSize := 20 + (len(packet.IPv4Options)+3)&^3
	maximum := (mtu - headerSize) &^ 7
	if maximum < 8 || len(packet.Payload) == 0 {
		return nil, syscall.EMSGSIZE
	}
	laterOptions := laterIPv4FragmentOptions(packet.IPv4Options)
	fragments := make([][]byte, 0, (len(packet.Payload)+maximum-1)/maximum)
	for offset := 0; offset < len(packet.Payload); {
		size := len(packet.Payload) - offset
		if size > mtu-headerSize {
			size = maximum
		}
		if size <= 0 {
			return nil, syscall.EMSGSIZE
		}
		more := packet.MoreFragments || offset+size < len(packet.Payload)
		options := laterOptions
		if packet.FragmentOffset+offset == 0 {
			options = packet.IPv4Options
		}
		fragment := packet
		fragment.DontFragment = false
		fragment.MoreFragments = more
		fragment.FragmentOffset = packet.FragmentOffset + offset
		fragment.IPv4Options = options
		fragment.Payload = packet.Payload[offset : offset+size]
		fragmentHeaderSize := 20 + (len(options)+3)&^3
		wire := make([]byte, fragmentHeaderSize+size)
		marshalPublicIPPacket(wire, fragment, fragmentHeaderSize)
		fragments = append(fragments, wire)
		offset += size
	}
	return fragments, nil
}

// marshalPublicIPv6Fragments inserts one Fragment header at the RFC 8200
// boundary in a validated packet. An existing atomic header is removed before
// rediscovering that boundary so the result never nests Fragment headers.
func marshalPublicIPv6Fragments(packet IPPacket, totalSize, mtu int, identification uint32) ([][]byte, error) {
	if !isTraversableIPv6ExtensionHeader(byte(packet.Protocol)) {
		return marshalPublicIPv6PayloadFragments(packet, mtu, identification)
	}
	wire := make([]byte, totalSize)
	marshalPublicIPPacket(wire, packet, 40)
	point, valid := inspectIPv6FragmentPoint(wire, false)
	if !valid {
		return nil, syscall.EINVAL
	}
	if point.atomicOffset >= 0 {
		wire[point.atomicPrevious] = wire[point.atomicOffset]
		copy(wire[point.atomicOffset:], wire[point.atomicOffset+8:])
		wire = wire[:len(wire)-8]
		binary.BigEndian.PutUint16(wire[4:6], uint16(len(wire)-40))
		point, valid = inspectIPv6FragmentPoint(wire, false)
		if !valid || point.atomicOffset >= 0 {
			return nil, syscall.EINVAL
		}
	}
	capacity := mtu - point.insertion - 8
	maximum := capacity &^ 7
	fragmentable := wire[point.insertion:]
	if maximum < 8 || len(fragmentable) == 0 {
		return nil, syscall.EMSGSIZE
	}
	firstHeaderEnd, valid := ipv6FirstFragmentHeaderEnd(wire, point)
	if !valid || firstHeaderEnd-point.insertion > maximum {
		return nil, syscall.EMSGSIZE
	}
	fragments := make([][]byte, 0, (len(fragmentable)+maximum-1)/maximum)
	for offset := 0; offset < len(fragmentable); {
		size := len(fragmentable) - offset
		if size > capacity {
			size = maximum
		}
		if size <= 0 {
			return nil, syscall.EMSGSIZE
		}
		fragment := make([]byte, point.insertion+8+size)
		copy(fragment, wire[:point.insertion])
		fragment[point.previous] = IPv6ExtensionHeaderFragment
		header := fragment[point.insertion : point.insertion+8]
		header[0] = point.next
		field := uint16(offset)
		if offset+size < len(fragmentable) {
			field |= 1
		}
		binary.BigEndian.PutUint16(header[2:4], field)
		binary.BigEndian.PutUint32(header[4:8], identification)
		copy(fragment[point.insertion+8:], fragmentable[offset:offset+size])
		binary.BigEndian.PutUint16(fragment[4:6], uint16(len(fragment)-40))
		fragments = append(fragments, fragment)
		offset += size
	}
	return fragments, nil
}

// marshalPublicIPv6PayloadFragments avoids materializing an unfragmented copy
// when the base header points directly at an upper-layer payload.
func marshalPublicIPv6PayloadFragments(packet IPPacket, mtu int, identification uint32) ([][]byte, error) {
	capacity := mtu - 48
	maximum := capacity &^ 7
	if maximum < 8 || len(packet.Payload) == 0 {
		return nil, syscall.EMSGSIZE
	}
	required, complete := ipv6FirstFragmentUpperLayerLength(byte(packet.Protocol), packet.Payload)
	if !complete || required > maximum {
		return nil, syscall.EMSGSIZE
	}
	fragments := make([][]byte, 0, (len(packet.Payload)+maximum-1)/maximum)
	for offset := 0; offset < len(packet.Payload); {
		size := len(packet.Payload) - offset
		if size > capacity {
			size = maximum
		}
		fragment := make([]byte, 48+size)
		marshalPublicIPv6BaseHeader(fragment, packet, IPv6ExtensionHeaderFragment, 8+size)
		header := fragment[40:48]
		header[0] = byte(packet.Protocol)
		field := uint16(offset)
		if offset+size < len(packet.Payload) {
			field |= 1
		}
		binary.BigEndian.PutUint16(header[2:4], field)
		binary.BigEndian.PutUint32(header[4:8], identification)
		copy(fragment[48:], packet.Payload[offset:offset+size])
		fragments = append(fragments, fragment)
		offset += size
	}
	return fragments, nil
}

// ipv6FirstFragmentHeaderEnd returns the end of every extension header and of
// the known upper-layer header required in the first fragment by RFC 7112.
func ipv6FirstFragmentHeaderEnd(packet []byte, point ipv6FragmentPoint) (int, bool) {
	next, offset := point.next, point.insertion
	for isTraversableIPv6ExtensionHeader(next) {
		if next == IPv6ExtensionHeaderFragment {
			return 0, false
		}
		length, valid := ipv6ExtensionHeaderLength(next, packet[offset:])
		if !valid {
			return 0, false
		}
		next, offset = packet[offset], offset+length
	}
	required, complete := ipv6FirstFragmentUpperLayerLength(next, packet[offset:])
	return offset + required, complete
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
		if !marshalIPHeader(packet, source, target, IPv6ExtensionHeaderFragment, 0, false, options) {
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
		if kind == IPv4HeaderOptionEnd {
			for index := offset + 1; index < len(result); index++ {
				result[index] = 0
			}
			break
		}
		if kind == IPv4HeaderOptionNOP {
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
		if contentSize, valid := ipv4OptionsContentLength(fragment[20:headerSize]); valid {
			for index := 20 + contentSize; index < headerSize; index++ {
				fragment[index] = 0
			}
		}
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
// RFC 8200 Per-Fragment header chain. The upper-layer bytes and checksum remain
// unchanged across the complete fragment sequence.
func fragmentICMPForwarderIPv6(packet []byte, point ipv6FragmentPoint, transportOffset, mtu int, identification uint32) [][]byte {
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
		fragment[point.previous] = IPv6ExtensionHeaderFragment
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
