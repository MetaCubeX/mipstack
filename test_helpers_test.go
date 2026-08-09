package mipstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

// testPacketQueueTicketAt constructs host-queue timing evidence without a
// live packet queue.
func testPacketQueueTicketAt(epoch, value time.Time) packetQueueTicket {
	return packetQueueTicket{queuedAt: monotonicStampAt(epoch, value)}
}

func testTCPReadBufferBytes(buffer *tcpReadBuffer) []byte {
	payload := make([]byte, 0, buffer.size)
	for index := buffer.head; index < len(buffer.chunks); index++ {
		payload = append(payload, buffer.chunks[index]...)
	}
	return payload
}

// buildIPPacket constructs a packet with default output fields for tests.
func buildIPPacket(source, target netip.Addr, protocol byte, payload []byte, identification uint16, dontFragment bool) []byte {
	return buildIPPacketWithOptions(source, target, protocol, payload, identification, dontFragment, ipPacketOptions{})
}

// buildIPv4Fragments constructs default-field IPv4 fragments for tests.
func buildIPv4Fragments(source, target netip.Addr, protocol byte, payload []byte, mtu int, identification uint16) [][]byte {
	return buildIPv4FragmentsWithOptions(source, target, protocol, payload, mtu, identification, ipPacketOptions{})
}

// reassemblePacket hides pending-state bookkeeping in tests concerned only
// with completed reassembly.
func (s *Stack) reassemblePacket(packet []byte, now time.Time) []byte {
	result, _ := s.reassemblePacketStatus(packet, now, false)
	return result
}

// expireFragments advances fragment cleanup synchronously for timeout tests.
func (s *Stack) expireFragments(now time.Time) {
	s.fragmentMu.Lock()
	expired := s.cleanFragmentsLocked(now)
	s.fragmentMu.Unlock()
	s.sendFragmentTimeouts(expired)
}

// testPacketLink emulates UDP and TCP peers at the packet boundary.
type testPacketLink struct {
	local, remote         netip.Addr
	stack                 *Stack
	outbound              chan []byte
	echoUDP               bool
	echoTCP               bool
	holdTCPACKs           int
	reverseTCPResponses   bool
	dropTCPSYN            int
	dropECNSYN            bool
	dropTCPData           int
	dropTCPFIN            int
	dropTCPAbove          int
	sackTCP               bool
	disableTCPSACK        bool
	dropTCPOrdinals       map[int]bool
	timestampTCP          bool
	ecnTCP                bool
	disableTCPWindowScale bool
	useTCPWindow          bool
	advertisedTCPWindow   uint16
	markTCPCE             bool
	sendTCPECE            bool
	partialTCPACK         int
	delayTCPACK           time.Duration

	mu                     sync.Mutex
	tcp                    map[uint16]*testTCPPeer
	maximumTCPBurst        int
	clientSACKs            int
	clientDataSACKs        int
	clientACKs             int
	clientTimestamps       int
	clientECTPackets       int
	clientRetransmittedECT int
	maximumTCPData         int
	clientECEs             int
	clientCWRs             int
	legacySYNSends         int
	lastClientWindow       uint16
	sackRecovery           bool
	sackRecoveries         int
	tailRetransmission     bool
	tailRecoveryDelay      time.Duration
	tcpPathMTU             uint32
	pathMTUInjected        bool
	postPathMTUMaximum     int
	done                   chan struct{}
}

func consumeTestPacket(queue *packetQueue, entry packetQueueEntry) []byte {
	packet := append([]byte(nil), entry.packet...)
	queue.release(entry)
	return packet
}

// waitTestPacketEntry receives from either packetQueue implementation while
// retaining a deterministic timeout for tests that intentionally expect no
// output.
func waitTestPacketEntry(queue *packetQueue, timeout time.Duration) (packetQueueEntry, bool) {
	cancel := make(chan struct{})
	timer := time.AfterFunc(timeout, func() { close(cancel) })
	entry, ok := queue.dequeue(cancel)
	if timer.Stop() {
		close(cancel)
	}
	return entry, ok
}

// stackBridge connects two Stack packet devices for fragmentation tests.
type stackBridge struct {
	client, peer  *Stack
	done          chan struct{}
	mu            sync.Mutex
	clientWrites  int
	clientNext    map[uint16]uint32
	clientGaps    int
	clientRepeats int
	peerSACKs     int
	peerDSACKs    int
}

// newStackBridge starts packet pumps between client and peer.
func newStackBridge(t *testing.T, client, peer *Stack) *stackBridge {
	t.Helper()
	bridge := &stackBridge{client: client, peer: peer, done: make(chan struct{}, 2)}
	go bridge.run(client, peer, true)
	go bridge.run(peer, client, false)
	t.Cleanup(func() {
		_ = client.Close()
		_ = peer.Close()
		<-bridge.done
		<-bridge.done
	})
	return bridge
}

// run copies outbound packets from source into destination.
func (b *stackBridge) run(source, destination *Stack, countClient bool) {
	defer func() { b.done <- struct{}{} }()
	buffers := make([][]byte, source.BatchSize())
	packets := make([][]byte, len(buffers))
	mtu, _ := source.MTU()
	for index := range buffers {
		buffers[index] = make([]byte, mtu)
	}
	sizes := make([]int, len(buffers))
	for {
		count, err := source.Read(buffers, sizes, 0)
		if err != nil {
			return
		}
		if countClient {
			b.mu.Lock()
			b.clientWrites += count
			for index := 0; index < count; index++ {
				b.trackClientTCPPacket(buffers[index][:sizes[index]])
			}
			b.mu.Unlock()
		} else {
			b.mu.Lock()
			for index := 0; index < count; index++ {
				b.trackPeerTCPPacket(buffers[index][:sizes[index]])
			}
			b.mu.Unlock()
		}
		for index := 0; index < count; index++ {
			packets[index] = buffers[index][:sizes[index]]
		}
		_, _ = destination.Write(packets[:count], 0)
	}
}

// trackPeerTCPPacket separates ordinary SACK evidence from DSACK generated by
// a duplicate transmission in performance diagnostics.
func (b *stackBridge) trackPeerTCPPacket(packet []byte) {
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.protocol != protocolTCP || len(parsed.payload) < tcpHeaderSize {
		return
	}
	tcp := parsed.payload
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(tcp) {
		return
	}
	acknowledgement := binary.BigEndian.Uint32(tcp[8:12])
	if headerSize == tcpHeaderSize {
		return
	}
	options := tcp[tcpHeaderSize:headerSize]
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == 0 {
			return
		}
		if kind == 1 {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			return
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			return
		}
		if kind == 5 && length >= 10 && (length-2)%8 == 0 {
			firstLeft := binary.BigEndian.Uint32(options[offset+2 : offset+6])
			firstRight := binary.BigEndian.Uint32(options[offset+6 : offset+10])
			dsack := tcpSequenceLessEqual(firstRight, acknowledgement)
			if !dsack && length >= 18 {
				secondLeft := binary.BigEndian.Uint32(options[offset+10 : offset+14])
				secondRight := binary.BigEndian.Uint32(options[offset+14 : offset+18])
				dsack = tcpSequenceGreaterEqual(firstLeft, secondLeft) && tcpSequenceLessEqual(firstRight, secondRight)
			}
			if dsack {
				b.peerDSACKs++
			} else {
				b.peerSACKs++
			}
			return
		}
		offset += length
	}
}

// trackClientTCPPacket records actual FIFO gaps and repeats at the packet
// device boundary. It is used only by performance diagnostics.
func (b *stackBridge) trackClientTCPPacket(packet []byte) {
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.protocol != protocolTCP || len(parsed.payload) < tcpHeaderSize {
		return
	}
	tcp := parsed.payload
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(tcp) {
		return
	}
	port := binary.BigEndian.Uint16(tcp[0:2])
	sequence := binary.BigEndian.Uint32(tcp[4:8])
	length := uint32(len(tcp) - headerSize)
	if tcp[13]&tcpFlagSYN != 0 {
		length++
	}
	if tcp[13]&tcpFlagFIN != 0 {
		length++
	}
	if length == 0 {
		return
	}
	if b.clientNext == nil {
		b.clientNext = make(map[uint16]uint32)
	}
	next, exists := b.clientNext[port]
	end := sequence + length
	if !exists || sequence == next {
		b.clientNext[port] = end
		return
	}
	if tcpSequenceLess(sequence, next) {
		b.clientRepeats++
		if tcpSequenceGreater(end, next) {
			b.clientNext[port] = end
		}
		return
	}
	b.clientGaps++
	b.clientNext[port] = end
}

// testTCPPeer retains one emulated server-side TCP tuple.
type testTCPPeer struct {
	serverNext       uint32
	clientNext       uint32
	highestClientEnd uint32
	pending          [][]byte
	burst            int
	finSent          bool
	resetSeen        bool
	outOfOrder       map[uint32][]byte
	dropped          map[uint32]time.Time
	seenData         map[uint32]bool
	dataSegments     int
	timestamp        uint32
	clientTimestamp  uint32
}

// newStackPair constructs and starts two single-address stacks.
func newStackPair(t *testing.T, firstAddress, secondAddress netip.Addr, mtu uint32) (*Stack, *Stack) {
	t.Helper()
	bits := 128
	if firstAddress.Is4() {
		bits = 32
	}
	first, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(firstAddress, bits)}, MTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Start(); err != nil {
		t.Fatal(err)
	}
	second, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(secondAddress, bits)}, MTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	if err = second.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = second.Close()
	})
	return first, second
}

// checkNetOpError verifies operation metadata without hiding the underlying
// error checked by each caller.
func checkNetOpError(t *testing.T, err error, operation, network string) *net.OpError {
	t.Helper()
	var operationError *net.OpError
	if !errors.As(err, &operationError) {
		t.Fatalf("error %v is not *net.OpError", err)
	}
	if operationError.Op != operation || operationError.Net != network {
		t.Fatalf("net.OpError = op %q net %q, want %q %q", operationError.Op, operationError.Net, operation, network)
	}
	return operationError
}

// newTestStack constructs a stack and its emulated lower layer.
func newTestStack(t testing.TB, local, remote netip.Addr) (*testPacketLink, *Stack) {
	t.Helper()
	link := &testPacketLink{local: local, remote: remote, outbound: make(chan []byte, 32), tcp: make(map[uint16]*testTCPPeer), done: make(chan struct{})}
	bits := 128
	if local.Is4() {
		bits = 32
	}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, bits)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	link.stack = stack
	go link.run()
	t.Cleanup(func() {
		_ = stack.Close()
		<-link.done
	})
	return link, stack
}

// run reads packets from the stack and passes them to the emulated peer.
func (l *testPacketLink) run() {
	defer close(l.done)
	buffer := make([]byte, 65535)
	for {
		sizes := []int{0}
		if _, err := l.stack.Read([][]byte{buffer}, sizes, 0); err != nil {
			return
		}
		_ = l.handleOutboundPacket(buffer[:sizes[0]])
	}
}

// handleOutboundPacket emulates the remote peer for one stack-generated L3
// packet and records control traffic needed by the test.
func (l *testPacketLink) handleOutboundPacket(packet []byte) error {
	parsed, ok := parseIPPacket(packet)
	if !ok {
		return nil
	}
	l.mu.Lock()
	echoUDP, echoTCP := l.echoUDP, l.echoTCP
	l.mu.Unlock()
	if parsed.protocol == protocolUDP && echoUDP {
		udp := parsed.payload
		if len(udp) >= udpHeaderSize {
			response := buildTestUDP(parsed.target, parsed.source, binary.BigEndian.Uint16(udp[2:4]), binary.BigEndian.Uint16(udp[0:2]), append([]byte(nil), udp[udpHeaderSize:]...))
			return writeTestPacket(l.stack, response)
		}
	}
	if parsed.protocol == protocolTCP && echoTCP {
		return l.handleTCP(parsed)
	}
	select {
	case l.outbound <- append([]byte(nil), packet...):
	default:
	}
	return nil
}

// handleTCP applies the test peer's loss, ACK, echo, and FIN policy.
func (l *testPacketLink) handleTCP(packet ipPacket) error {
	tcp := packet.payload
	if len(tcp) < tcpHeaderSize {
		return nil
	}
	headerSize := int(tcp[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(tcp) {
		return nil
	}
	clientPort := binary.BigEndian.Uint16(tcp[0:2])
	serverPort := binary.BigEndian.Uint16(tcp[2:4])
	sequence := binary.BigEndian.Uint32(tcp[4:8])
	flags := tcp[13]
	payload := append([]byte(nil), tcp[headerSize:]...)
	l.mu.Lock()
	if len(payload) > l.maximumTCPData {
		l.maximumTCPData = len(payload)
	}
	if packet.ecn == 2 {
		l.clientECTPackets++
	}
	if flags&tcpFlagECE != 0 {
		l.clientECEs++
	}
	if flags&tcpFlagCWR != 0 {
		l.clientCWRs++
	}
	peer := l.tcp[clientPort]
	if flags&tcpFlagSYN != 0 {
		if l.dropECNSYN && flags&(tcpFlagECE|tcpFlagCWR) == tcpFlagECE|tcpFlagCWR {
			l.dropECNSYN = false
			l.mu.Unlock()
			return nil
		}
		if flags&(tcpFlagECE|tcpFlagCWR) == 0 {
			l.legacySYNSends++
		}
		if l.dropTCPSYN > 0 {
			l.dropTCPSYN--
			l.mu.Unlock()
			return nil
		}
		peer = &testTCPPeer{
			serverNext: 0x10000000 + uint32(clientPort), clientNext: sequence + 1, highestClientEnd: sequence + 1,
			outOfOrder: make(map[uint32][]byte), dropped: make(map[uint32]time.Time), seenData: make(map[uint32]bool), timestamp: 1000,
		}
		if value, _, present := parseTCPTimestamp(tcp[tcpHeaderSize:headerSize]); present {
			peer.clientTimestamp = value
			l.clientTimestamps++
		}
		l.tcp[clientPort] = peer
		serverSequence, acknowledgement := peer.serverNext, peer.clientNext
		peer.serverNext++
		l.mu.Unlock()
		options := []byte{2, 4, 0x05, 0x00, 4, 2, 1, 3, 3, 2}
		if l.disableTCPSACK {
			options = []byte{2, 4, 0x05, 0x00, 1, 3, 3, 2}
		}
		if l.disableTCPWindowScale {
			options = []byte{2, 4, 0x05, 0x00}
			if !l.disableTCPSACK {
				options = append(options, 4, 2)
			}
		}
		responseFlags := byte(tcpFlagSYN | tcpFlagACK)
		if l.ecnTCP && flags&tcpFlagECE != 0 && flags&tcpFlagCWR != 0 {
			responseFlags |= tcpFlagECE
		}
		return l.deliverTCP(serverPort, clientPort, serverSequence, acknowledgement, responseFlags, 65535, options, nil)
	}
	if peer == nil {
		l.mu.Unlock()
		return nil
	}
	if flags&tcpFlagRST != 0 {
		peer.resetSeen = true
		l.mu.Unlock()
		return nil
	}
	if hasTCPOption(tcp[tcpHeaderSize:headerSize], 5) {
		l.clientSACKs++
		if len(payload) != 0 {
			l.clientDataSACKs++
		}
	}
	if value, _, present := parseTCPTimestamp(tcp[tcpHeaderSize:headerSize]); present {
		peer.clientTimestamp = value
		l.clientTimestamps++
	}
	if flags&tcpFlagACK != 0 && len(payload) == 0 {
		l.clientACKs++
		if flags&tcpFlagSYN == 0 {
			l.lastClientWindow = binary.BigEndian.Uint16(tcp[14:16])
		}
	}
	if end := sequence + uint32(len(payload)); len(payload) != 0 && tcpSequenceGreater(end, peer.highestClientEnd) {
		peer.highestClientEnd = end
	}
	if len(payload) != 0 && l.tcpPathMTU != 0 {
		if !l.pathMTUInjected {
			l.pathMTUInjected = true
			mtu := l.tcpPathMTU
			quoted := append([]byte(nil), packet.original...)
			l.mu.Unlock()
			return writeTestPacket(l.stack, buildTestPacketTooBig(l.remote, l.local, quoted, mtu))
		}
		if len(packet.original) > l.postPathMTUMaximum {
			l.postPathMTUMaximum = len(packet.original)
		}
	}
	if len(payload) != 0 && l.dropTCPAbove != 0 && len(packet.original) > l.dropTCPAbove {
		peer.dropped[sequence] = time.Now()
		l.mu.Unlock()
		return nil
	}
	if len(payload) != 0 && !peer.seenData[sequence] {
		peer.seenData[sequence] = true
		peer.dataSegments++
		if l.dropTCPOrdinals[peer.dataSegments] {
			peer.dropped[sequence] = time.Now()
			l.mu.Unlock()
			return nil
		}
	} else if len(payload) != 0 && packet.ecn != 0 {
		l.clientRetransmittedECT++
	}
	if len(payload) != 0 && l.dropTCPData > 0 {
		l.dropTCPData--
		peer.dropped[sequence] = time.Now()
		l.mu.Unlock()
		return nil
	}
	if len(payload) != 0 && tcpSequenceGreater(sequence, peer.clientNext) {
		if _, exists := peer.outOfOrder[sequence]; !exists {
			peer.outOfOrder[sequence] = payload
		}
		acknowledgement := peer.clientNext
		serverSequence := peer.serverNext
		var options []byte
		if l.sackTCP {
			options = testSACKOptions(peer.outOfOrder)
		}
		l.mu.Unlock()
		return l.deliverTCP(serverPort, clientPort, serverSequence, acknowledgement, tcpFlagACK, 65535, options, nil)
	}
	if len(payload) != 0 && sequence == peer.clientNext {
		if droppedAt, retransmitted := peer.dropped[sequence]; retransmitted {
			delete(peer.dropped, sequence)
			if len(peer.outOfOrder) != 0 {
				l.sackRecovery = true
				l.sackRecoveries++
			} else {
				l.tailRetransmission = true
				l.tailRecoveryDelay = time.Since(droppedAt)
			}
		}
		peer.clientNext += uint32(len(payload))
		peer.pending = append(peer.pending, payload)
		peer.burst++
		for {
			part, exists := peer.outOfOrder[peer.clientNext]
			if !exists {
				break
			}
			delete(peer.outOfOrder, peer.clientNext)
			peer.clientNext += uint32(len(part))
			peer.pending = append(peer.pending, part)
			peer.burst++
		}
		if peer.burst > l.maximumTCPBurst {
			l.maximumTCPBurst = peer.burst
		}
	}
	if flags&tcpFlagFIN != 0 && sequence+uint32(len(payload)) == peer.clientNext {
		if l.dropTCPFIN > 0 {
			l.dropTCPFIN--
			l.mu.Unlock()
			return nil
		}
		peer.clientNext++
		acknowledgement := peer.clientNext
		serverSequence := peer.serverNext
		peer.finSent = true
		peer.serverNext++
		l.mu.Unlock()
		if err := l.deliverTCP(serverPort, clientPort, serverSequence, acknowledgement, tcpFlagACK, 65535, nil, nil); err != nil {
			return err
		}
		return l.deliverTCP(serverPort, clientPort, serverSequence, acknowledgement, tcpFlagACK|tcpFlagFIN, 65535, nil, nil)
	}
	threshold := l.holdTCPACKs
	flush := len(peer.pending) != 0 && (threshold <= 1 || peer.burst >= threshold || flags&tcpFlagPSH != 0)
	if !flush {
		l.mu.Unlock()
		return nil
	}
	pending := peer.pending
	peer.pending = nil
	peer.burst = 0
	acknowledgement := peer.clientNext
	serverSequence := peer.serverNext
	window := uint16(65535)
	delay := l.delayTCPACK
	if l.partialTCPACK > 0 {
		pendingBytes := 0
		for _, part := range pending {
			pendingBytes += len(part)
		}
		if l.partialTCPACK < pendingBytes {
			acknowledgement -= uint32(pendingBytes - l.partialTCPACK)
		}
		l.partialTCPACK = 0
	}
	if l.useTCPWindow {
		window = l.advertisedTCPWindow
	}
	for _, part := range pending {
		peer.serverNext += uint32(len(part))
	}
	l.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	type responsePart struct {
		sequence uint32
		payload  []byte
	}
	responses := make([]responsePart, 0, len(pending))
	for _, part := range pending {
		responses = append(responses, responsePart{sequence: serverSequence, payload: part})
		serverSequence += uint32(len(part))
	}
	if l.reverseTCPResponses {
		for left, right := 0, len(responses)-1; left < right; left, right = left+1, right-1 {
			responses[left], responses[right] = responses[right], responses[left]
		}
	}
	for _, response := range responses {
		if err := l.deliverTCP(serverPort, clientPort, response.sequence, acknowledgement, tcpFlagACK|tcpFlagPSH, window, nil, response.payload); err != nil {
			return err
		}
	}
	return nil
}

// hasTCPOption reports whether a well-formed option list contains kind.
func hasTCPOption(options []byte, kind byte) bool {
	for offset := 0; offset < len(options); {
		if options[offset] == kind {
			return true
		}
		if options[offset] == 0 {
			return false
		}
		if options[offset] == 1 {
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
		offset += length
	}
	return false
}

// testSACKOptions serializes the emulated peer's retained receive ranges.
func testSACKOptions(outOfOrder map[uint32][]byte) []byte {
	sequences := make([]uint32, 0, len(outOfOrder))
	for sequence := range outOfOrder {
		sequences = append(sequences, sequence)
	}
	sort.Slice(sequences, func(left, right int) bool { return sequences[left] < sequences[right] })
	if len(sequences) > 4 {
		sequences = sequences[len(sequences)-4:]
	}
	options := make([]byte, 2+8*len(sequences))
	options[0], options[1] = 5, byte(len(options))
	for index, sequence := range sequences {
		offset := 2 + index*8
		binary.BigEndian.PutUint32(options[offset:offset+4], sequence)
		binary.BigEndian.PutUint32(options[offset+4:offset+8], sequence+uint32(len(outOfOrder[sequence])))
	}
	return options
}

// waitFor polls a test-owned condition until it succeeds or its deadline
// expires.
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(time.Millisecond)
	}
}

// writeAndReadTCPEcho exchanges one complete payload with the emulated peer.
func writeAndReadTCPEcho(t *testing.T, connection net.Conn, payload []byte) {
	t.Helper()
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("TCP Write = %d, %v", n, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("TCP echo = %q, want %q", response, payload)
	}
}

// deliverTCP builds one peer segment and injects it into the stack.
func (l *testPacketLink) deliverTCP(sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte) error {
	l.mu.Lock()
	peer := l.tcp[targetPort]
	if l.timestampTCP && peer != nil {
		peer.timestamp++
		timestampOptions := tcpTimestampOptions(peer.timestamp, peer.clientTimestamp)
		combined := make([]byte, 0, len(timestampOptions)+len(options))
		combined = append(combined, timestampOptions...)
		combined = append(combined, options...)
		options = combined
	}
	markCE := l.markTCPCE && len(payload) != 0
	if markCE {
		l.markTCPCE = false
	}
	if l.sendTCPECE && flags&tcpFlagACK != 0 {
		flags |= tcpFlagECE
	}
	l.mu.Unlock()
	headerSize := tcpHeaderSize + (len(options)+3)&^3
	tcp := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], targetPort)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], acknowledgement)
	tcp[12], tcp[13] = byte(headerSize/4)<<4, flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	copy(tcp[tcpHeaderSize:headerSize], options)
	copy(tcp[headerSize:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(l.remote, l.local, protocolTCP, tcp))
	packet := buildIPPacket(l.remote, l.local, protocolTCP, tcp, 1, true)
	if markCE {
		setPacketECN(packet, 3)
	}
	return writeTestPacket(l.stack, packet)
}

// writeTestPacket supplies one inbound packet through the public device API.
func writeTestPacket(stack *Stack, packet []byte) error {
	_, err := stack.Write([][]byte{packet}, 0)
	return err
}

func enqueueTCPTestSegment(t testing.TB, connection *TCPConn, segment tcpSegment) {
	t.Helper()
	if !connection.enqueueInbound(segment) {
		t.Fatal("test TCP segment exceeded the inbound queue")
	}
}

// wildcardUDP returns an ephemeral wildcard endpoint in address's family.
func wildcardUDP(address netip.Addr) netip.AddrPort {
	if address.Is6() {
		return netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
}

// readOutboundPacket receives one packet directly from the test device queue.
func readOutboundPacket(t *testing.T, stack *Stack) []byte {
	t.Helper()
	if entry, ok := waitTestPacketEntry(&stack.outbound, time.Second); ok {
		return consumeTestPacket(&stack.outbound, entry)
	}
	t.Fatal("timed out waiting for outbound packet")
	return nil
}

func fillTestPacketQueue(t *testing.T, queue *packetQueue, packet []byte) {
	t.Helper()
	for queue.len() < cap(queue.free) {
		if !queue.tryEnqueue(packet) {
			t.Fatal("packet queue became full before its configured capacity")
		}
	}
}

// buildTestPacketTooBig quotes an emitted packet in an IPv4 fragmentation-
// needed or IPv6 Packet Too Big error.
func buildTestPacketTooBig(reporter, target netip.Addr, quoted []byte, mtu uint32) []byte {
	icmp := make([]byte, 8+len(quoted))
	copy(icmp[8:], quoted)
	protocol := protocolICMPv6
	if reporter.Is4() {
		protocol = protocolICMPv4
		icmp[0], icmp[1] = 3, 4
		binary.BigEndian.PutUint16(icmp[6:8], uint16(mtu))
		binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	} else {
		icmp[0] = 2
		binary.BigEndian.PutUint32(icmp[4:8], mtu)
		binary.BigEndian.PutUint16(icmp[2:4], transportChecksum(reporter, target, protocol, icmp))
	}
	return buildIPPacket(reporter, target, protocol, icmp, 1, true)
}

// buildTestUDP constructs one checksummed test datagram.
func buildTestUDP(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte) []byte {
	udp := make([]byte, udpHeaderSize+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], targetPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[udpHeaderSize:], payload)
	value := transportChecksum(source, target, protocolUDP, udp)
	if value == 0 {
		value = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], value)
	return buildIPPacket(source, target, protocolUDP, udp, 1, false)
}

// buildTestTCP constructs one checksummed test segment.
func buildTestTCP(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte) []byte {
	headerSize := tcpHeaderSize + (len(options)+3)&^3
	tcp := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], targetPort)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], acknowledgement)
	tcp[12], tcp[13] = byte(headerSize/4)<<4, flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	copy(tcp[tcpHeaderSize:headerSize], options)
	copy(tcp[headerSize:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(source, target, protocolTCP, tcp))
	return buildIPPacket(source, target, protocolTCP, tcp, 1, true)
}

func buildTestIPv4Options(source, target netip.Addr, options []byte) []byte {
	packet := make([]byte, 20+len(options)+8)
	packet[0] = 0x40 | byte((20+len(options))/4)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, protocolUDP
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], target.AsSlice())
	copy(packet[20:], options)
	binary.BigEndian.PutUint16(packet[20+len(options):22+len(options)], 1)
	binary.BigEndian.PutUint16(packet[22+len(options):24+len(options)], 1)
	binary.BigEndian.PutUint16(packet[24+len(options):26+len(options)], 8)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20+len(options)]))
	return packet
}

func buildTestIPv6Extension(source, target netip.Addr, extensionType byte, extension []byte) []byte {
	packet := make([]byte, 40+len(extension))
	packet[0], packet[6], packet[7] = 0x60, extensionType, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(extension)))
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], target.AsSlice())
	copy(packet[40:], extension)
	return packet
}
