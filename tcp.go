package mipstack

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// TCPFlagFIN closes one stream direction.
	TCPFlagFIN = 1 << iota
	// TCPFlagSYN synchronizes initial sequence numbers.
	TCPFlagSYN
	// TCPFlagRST resets a connection.
	TCPFlagRST
	// TCPFlagPSH requests prompt delivery to the peer application.
	TCPFlagPSH
	// TCPFlagACK marks AcknowledgmentNumber as valid.
	TCPFlagACK
	// TCPFlagURG marks UrgentPointer as valid.
	TCPFlagURG
	// TCPFlagECE echoes congestion or negotiates ECN on an initial SYN.
	TCPFlagECE
	// TCPFlagCWR acknowledges an ECN congestion response or negotiates ECN.
	TCPFlagCWR
	// TCPFlagNS is the historic ECN Nonce Sum bit, now reserved by RFC 9293.
	TCPFlagNS

	// TCPHeaderOptionEnd terminates the TCP option list.
	TCPHeaderOptionEnd = 0
	// TCPHeaderOptionNOP is the one-byte No-Operation TCP option.
	TCPHeaderOptionNOP = 1
	// TCPHeaderOptionMSS carries a two-byte Maximum Segment Size.
	TCPHeaderOptionMSS = 2
	// TCPHeaderOptionWindowScale carries an unmodified one-byte window scale.
	TCPHeaderOptionWindowScale = 3
	// TCPHeaderOptionSACKPermitted negotiates selective acknowledgments.
	TCPHeaderOptionSACKPermitted = 4
	// TCPHeaderOptionSACK carries one to four selective-acknowledgment blocks.
	TCPHeaderOptionSACK = 5
	// TCPHeaderOptionTimestamp carries TSval and TSecr values.
	TCPHeaderOptionTimestamp = 8

	// tcpHeaderSize is the TCP header length without options.
	tcpHeaderSize = 20
	// tcpActorWakeSend reports application send-buffer progress. Wake bits
	// coalesce state-only notifications without per-class connection channels.
	tcpActorWakeSend = uint32(1 << 0)
	// tcpActorWakeWindow reports newly available receive-window space.
	tcpActorWakeWindow = uint32(1 << 1)
	// tcpActorWakeOptions reports a mutable socket-policy change.
	tcpActorWakeOptions = uint32(1 << 2)
	// tcpActorWakePathMTU reports a changed path packet-size ceiling.
	tcpActorWakePathMTU = uint32(1 << 3)
	// tcpActorWakeNetworkError reports queued asynchronous ICMP errors.
	tcpActorWakeNetworkError = uint32(1 << 4)
	// tcpActorWakeInfo reports callers waiting for a live diagnostic snapshot.
	tcpActorWakeInfo = uint32(1 << 5)

	// tcpMaximumPendingNetworkErrors preserves the former buffered-channel
	// bound while allocating storage only for connections that receive ICMP.
	tcpMaximumPendingNetworkErrors = 8
	// tcpReceiveCapacity bounds unread and out-of-order bytes per connection.
	tcpReceiveCapacity = 1024 * 1024
	// tcpSendCapacity bounds unacknowledged and not-yet-transmitted application
	// bytes retained by one connection.
	tcpSendCapacity = 256 * 1024
	// tcpMaximumReceiveCapacity bounds automatic receive-buffer growth.
	// Capacity is allocated only as application data arrives;
	// the limits therefore permit high-bandwidth-delay paths without charging
	// every mostly idle proxy connection up front.
	tcpMaximumReceiveCapacity = 16 * 1024 * 1024
	// tcpMaximumSendCapacity bounds automatic send-buffer growth under the same policy.
	tcpMaximumSendCapacity = 16 * 1024 * 1024
	// tcpReadChunkRetain keeps metadata for a modest receive burst after it
	// drains without retaining the payload backing or a multi-megabyte array of
	// slice headers on an idle connection.
	tcpReadChunkRetain = 64
	// tcpReusableReceivePayloadLimit keeps one common-MTU receive backing per
	// connection. Larger packets are released after Read so an occasional jumbo
	// segment cannot permanently raise the idle memory cost.
	tcpReusableReceivePayloadLimit = 2048
	// tcpSendChunkInitial bounds the unused backing retained by an idle
	// connection after a small write. Later chunks in the same live send window
	// use tcpSendChunkMinimum so packet construction remains scatter-bounded.
	tcpSendChunkInitial = 2 * 1024
	// tcpSendChunkMinimum packs later writes without moving bytes referenced by
	// retransmission metadata and keeps cross-chunk gathers uncommon on bulk
	// streams.
	tcpSendChunkMinimum = 16 * 1024
	// tcpSendChunkMaximum bounds unused tail capacity in one send chunk.
	tcpSendChunkMaximum = tcpSendCapacity
	// tcpReusableSendChunkLimit retains only a modest acknowledged send chunk.
	// Larger chunks are released so a completed bulk transfer does not pin its
	// former window.
	tcpReusableSendChunkLimit = 32 * 1024
	// tcpMetadataQueueInitial avoids charging every connection for a burst
	// before one occurs.
	tcpMetadataQueueInitial = 1
	// tcpMetadataQueueRetain keeps metadata after an observed short actor burst
	// while releasing larger arrays after they drain.
	tcpMetadataQueueRetain = 4
	// tcpMaximumOutOfOrder bounds retained receive-range metadata. The limit
	// accommodates a full default window split near IPv6's minimum MTU while
	// still bounding adversarial sparse one-byte ranges.
	tcpMaximumOutOfOrder = 4096
	// tcpInboundByteCapacity bounds the dynamically allocated actor queue. Two
	// maximum receive windows accommodate data and scheduler-delayed ACK bursts
	// after automatic window growth without charging idle connections up front.
	tcpInboundByteCapacity = 2 * tcpMaximumReceiveCapacity
	// tcpInboundSegmentMetadata accounts for one queued segment value, including
	// its inline TCP-option storage, and the payload slice backing allocation.
	tcpInboundSegmentMetadata = 128
	// tcpAcceptQueue bounds completed passive handshakes waiting for Accept.
	tcpAcceptQueue = 128
	// tcpSYNBacklog bounds half-open connections owned by one listener.
	tcpSYNBacklog = 256
	// tcpMaximumRTOs matches Linux's default tcp_retries2 budget for
	// consecutive retransmission timeouts without cumulative acknowledgement
	// progress. Fast recovery, tail probes, and PMTU resegmentation do not
	// consume it.
	tcpMaximumRTOs = 15
	// tcpActiveSYNMaximumAttempts is the initial SYN plus Linux's default six
	// active-open retransmissions.
	tcpActiveSYNMaximumAttempts = 7
	// tcpPassiveSYNMaximumAttempts is the initial SYN-ACK plus Linux's default
	// five passive-open retransmissions.
	tcpPassiveSYNMaximumAttempts = 6
	// tcpBlackHoleTimeouts enters optional black-hole probing only after the
	// default Linux tcp_retries1 budget has been exceeded. Earlier timeouts are
	// ordinary congestion evidence and must not make a busy path reduce its
	// packet size merely because ICMP Packet Too Big was absent.
	tcpBlackHoleTimeouts = 4
	// tcpInitialRTO follows the RFC 6298 initial retransmission timeout.
	tcpInitialRTO = time.Second
	// tcpMinimumRTO avoids excessive retransmission on low-latency overlays.
	tcpMinimumRTO = 200 * time.Millisecond
	// tcpMaximumRTO matches Linux's maximum retry and zero-window-probe RTO.
	// It also satisfies RFC 6298's requirement that an optional cap be at
	// least 60 seconds.
	tcpMaximumRTO = 120 * time.Second
	// tcpDelayedACKTimeout bounds acknowledgement delay for in-order data and
	// non-critical receive-window growth.
	tcpDelayedACKTimeout = 25 * time.Millisecond
	// tcpTailLossProbeACKDelay is the sender's allowance for an unknown peer's
	// delayed ACK timer when only one segment is outstanding. It matches
	// Linux's default tcp_rto_min_us() allowance in tcp_schedule_loss_probe;
	// the shorter local delayed-ACK policy says nothing about a remote stack.
	tcpTailLossProbeACKDelay = 200 * time.Millisecond
	// tcpTimeWaitDuration retains a completed tuple for twice the conventional
	// 30-second maximum segment lifetime.
	tcpTimeWaitDuration = 60 * time.Second
	// tcpFINWaitDuration bounds orphaned FIN_WAIT_2 resource retention. A
	// connection retained by an application after CloseWrite has no such
	// timeout and may continue receiving until the peer closes.
	tcpFINWaitDuration = 60 * time.Second
	// tcpInitialCongestionMSS is the RFC 6928 upper initial-window bound.
	tcpInitialCongestionMSS = 10
	// tcpInitialOutstandingCapacity covers the initial window plus Limited
	// Transmit without repeated sent-segment slice growth. It is allocated only
	// when a connection first sends application data.
	tcpInitialOutstandingCapacity = 16
	// tcpDuplicateACKThreshold is the RFC 5681 fast-retransmit threshold and
	// RFC 6675 packet-count loss threshold.
	tcpDuplicateACKThreshold = 3
	// tcpMinimumPeerMSS matches Linux's default tcp_min_snd_mss. Accepting a
	// one-byte advertised MSS lets an untrusted peer amplify ordinary buffered
	// writes into hundreds of thousands of packets and scoreboard entries.
	// A smaller path-derived MSS still wins when the managed MTU requires it.
	tcpMinimumPeerMSS = 48
	// tcpMaximumSACKSplitRanges bounds metadata created solely by adversarial
	// byte-granular SACK edges. Once reached, a partially covered transmission
	// remains unsacked and is conservatively retransmitted as a whole.
	tcpMaximumSACKSplitRanges = 1024
	// tcpDefaultKeepAliveIdle is the initial inactivity before probes.
	tcpDefaultKeepAliveIdle = 2 * time.Hour
	// tcpDefaultKeepAliveInterval spaces unanswered probes.
	tcpDefaultKeepAliveInterval = 75 * time.Second
	// tcpDefaultKeepAliveCount bounds unanswered probes.
	tcpDefaultKeepAliveCount = 9
	// tcpMaximumScaledWindow is the largest receive window representable by
	// TCP's 16-bit window and maximum negotiated scale.
	tcpMaximumScaledWindow = uint32(65535) << 14
	// tcpPLPMTUProbeThreshold matches Linux's default binary-search stopping
	// interval. Smaller packet-size gains do not justify another loss probe.
	tcpPLPMTUProbeThreshold = 8
	// tcpPLPMTUProbeMinimumInterval rate limits congestion-response suppression
	// after an isolated failed probe.
	tcpPLPMTUProbeMinimumInterval = time.Second
	// tcpAutoTuneMinimumInterval smooths short-RTT ACK and read batches across
	// normal userspace scheduling intervals.
	// It is an observation interval, not a wake-up timer; RTT normalization
	// still preserves the measured BDP on genuinely fast paths.
	tcpAutoTuneMinimumInterval = 10 * time.Millisecond
	// tcpHostQueueRetryInterval defers a loss timer while the candidate packet
	// is still waiting in mipstack's output FIFO. This mirrors Linux's local-
	// congestion retry without changing the packet's RACK transmission time.
	tcpHostQueueRetryInterval = 10 * time.Millisecond
	// tcpEifelClockGranularity is the timestamp and retransmission-timer clock
	// granularity used by the RFC 4015 response.
	tcpEifelClockGranularity = time.Millisecond
	// tcpRetransmissionHistoryLimit retains enough recent wire ranges to
	// distinguish late DSACK feedback from network duplication without making
	// a loss-heavy connection's memory use unbounded.
	tcpRetransmissionHistoryLimit = 128
	// tcpMinimumRTTWindow matches Linux's default tcp_min_rtt_wlen. RFC 8985
	// recommends a windowed minimum so RACK can adapt after migration to a
	// persistently longer path.
	tcpMinimumRTTWindow = 300 * time.Second
)

// TCPHeaderOption is one TCP option in semantic wire order. Data excludes the
// Kind and Length bytes. End and NOP require empty Data; every other kind is
// encoded with a Length byte. HeaderOptions returns Data slices that borrow
// TCPSegment.Options, while SetHeaderOptions copies every Data slice.
type TCPHeaderOption struct {
	// Kind is the TCP option kind.
	Kind uint8
	// Data is the option value following Kind and Length.
	Data []byte
}

// tcpHeaderOptionLength validates one length-bearing option prefix. Callers
// handle one-byte End and NOP. Zero reports malformed framing. Transport actor
// parsers keep equivalent checks local because a returned sentinel adds a
// measurable valid-path branch on every SYN or ACK.
func tcpHeaderOptionLength(option []byte) int {
	if len(option) < 2 {
		return 0
	}
	length := int(option[1])
	// The unsigned comparison rejects both lengths below two and overrun.
	if uint(length-2) > uint(len(option)-2) {
		return 0
	}
	return length
}

// TCPSACKBlock is one half-open sequence range carried by a TCP SACK option.
// Edges use TCP's wrapping 32-bit sequence space; interpreting their order
// requires connection context that the standalone wire codec does not have.
type TCPSACKBlock struct {
	// LeftEdge is the sequence number of the first acknowledged byte.
	LeftEdge uint32
	// RightEdge is the sequence number immediately after the acknowledged range.
	RightEdge uint32
}

// TCPSegment is the semantic representation of one checksummed TCP segment.
// Source and Destination provide both wire ports and the IP pseudo-header
// addresses. IPPacket.TCPSegment borrows Options and Payload from the packet;
// callers must replace or copy those slices before modifying unowned input.
// Construction normalizes IPv4-mapped IPv6 addresses to IPv4.
type TCPSegment struct {
	// Source is the source IP address and TCP port.
	Source netip.AddrPort
	// Destination is the destination IP address and TCP port.
	Destination netip.AddrPort
	// SequenceNumber is the first sequence number represented by the segment.
	SequenceNumber uint32
	// AcknowledgmentNumber is meaningful when TCPFlagACK is set.
	AcknowledgmentNumber uint32
	// Flags contains the eight current TCP control flags and the historic NS bit.
	Flags uint16
	// WindowSize is the unscaled advertised receive window.
	WindowSize uint16
	// UrgentPointer is meaningful when TCPFlagURG is set.
	UrgentPointer uint16
	// Options contains the exact parsed option area, including padding.
	// Construction also accepts an unpadded option sequence and adds zero padding;
	// bytes following an End of Option List are normalized to zero as RFC 9293
	// requires for generated segments.
	Options []byte
	// Payload is the segment's application data.
	Payload []byte
}

// tcpWireHeaderSize validates TCP's data offset against an already checked
// segment length. Checksum and option policy remain with each caller.
func tcpWireHeaderSize(dataOffset byte, segmentSize int) (int, bool) {
	headerSize := int(dataOffset>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > segmentSize {
		return 0, false
	}
	return headerSize, true
}

// HeaderOptions parses the exact TCP option sequence. The returned slice owns
// its option descriptors, but each Data field borrows Options. End is returned
// as the final descriptor and bytes after it are ignored as receiver padding.
// Recognized kinds with nonstandard lengths remain available as raw options;
// their typed accessors report ok=false.
func (s TCPSegment) HeaderOptions() ([]TCPHeaderOption, error) {
	if len(s.Options) > 40 {
		return nil, syscall.EMSGSIZE
	}
	var result []TCPHeaderOption
	for offset := 0; offset < len(s.Options); {
		kind := s.Options[offset]
		switch kind {
		case TCPHeaderOptionEnd:
			return append(result, TCPHeaderOption{Kind: kind}), nil
		case TCPHeaderOptionNOP:
			result = append(result, TCPHeaderOption{Kind: kind})
			offset++
			continue
		}
		length := tcpHeaderOptionLength(s.Options[offset:])
		if length == 0 {
			return nil, syscall.EINVAL
		}
		result = append(result, TCPHeaderOption{Kind: kind, Data: s.Options[offset+2 : offset+length]})
		offset += length
	}
	return result, nil
}

// SetHeaderOptions replaces Options with the encoded option sequence. It
// preserves unknown kinds, duplicates, and order, copies all input data, and
// leaves s unchanged on failure. An End option must be last. The final TCP
// header padding is added by MarshalBinary or AppendBinary.
func (s *TCPSegment) SetHeaderOptions(options []TCPHeaderOption) error {
	if s == nil {
		return syscall.EINVAL
	}
	size := 0
	ended := false
	for _, option := range options {
		if ended {
			return syscall.EINVAL
		}
		switch option.Kind {
		case TCPHeaderOptionEnd, TCPHeaderOptionNOP:
			if len(option.Data) != 0 {
				return syscall.EINVAL
			}
			size++
			ended = option.Kind == TCPHeaderOptionEnd
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
		encoded = append(encoded, option.Kind)
		if option.Kind == TCPHeaderOptionEnd || option.Kind == TCPHeaderOptionNOP {
			continue
		}
		encoded = append(encoded, byte(2+len(option.Data)))
		encoded = append(encoded, option.Data...)
	}
	s.Options = encoded
	return nil
}

// MaximumSegmentSize returns the raw MSS value when o is a well-formed MSS
// option. It does not replace zero or clamp the value to a path limit.
func (o TCPHeaderOption) MaximumSegmentSize() (uint16, bool) {
	if o.Kind != TCPHeaderOptionMSS || len(o.Data) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(o.Data), true
}

// SetMaximumSegmentSize replaces o with an MSS option containing value.
func (o *TCPHeaderOption) SetMaximumSegmentSize(value uint16) {
	o.Kind = TCPHeaderOptionMSS
	o.Data = make([]byte, 2)
	binary.BigEndian.PutUint16(o.Data, value)
}

// WindowScale returns the raw scale when o is a well-formed Window Scale
// option. Values above RFC 7323's operational maximum are not clamped.
func (o TCPHeaderOption) WindowScale() (uint8, bool) {
	if o.Kind != TCPHeaderOptionWindowScale || len(o.Data) != 1 {
		return 0, false
	}
	return o.Data[0], true
}

// SetWindowScale replaces o with a Window Scale option containing value.
func (o *TCPHeaderOption) SetWindowScale(value uint8) {
	o.Kind = TCPHeaderOptionWindowScale
	o.Data = []byte{value}
}

// IsSACKPermitted reports whether o is a well-formed SACK-Permitted option.
func (o TCPHeaderOption) IsSACKPermitted() bool {
	return o.Kind == TCPHeaderOptionSACKPermitted && len(o.Data) == 0
}

// SetSACKPermitted replaces o with a SACK-Permitted option.
func (o *TCPHeaderOption) SetSACKPermitted() {
	o.Kind = TCPHeaderOptionSACKPermitted
	o.Data = nil
}

// Timestamp returns the raw TSval and TSecr values when o is a well-formed
// Timestamp option.
func (o TCPHeaderOption) Timestamp() (value, echo uint32, ok bool) {
	if o.Kind != TCPHeaderOptionTimestamp || len(o.Data) != 8 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(o.Data[:4]), binary.BigEndian.Uint32(o.Data[4:]), true
}

// SetTimestamp replaces o with a Timestamp option containing value and echo.
func (o *TCPHeaderOption) SetTimestamp(value, echo uint32) {
	o.Kind = TCPHeaderOptionTimestamp
	o.Data = make([]byte, 8)
	binary.BigEndian.PutUint32(o.Data[:4], value)
	binary.BigEndian.PutUint32(o.Data[4:], echo)
}

// SACKBlocks returns the raw blocks when o is a well-formed SACK option. It
// does not classify DSACK, filter blocks against a send window, or merge them.
func (o TCPHeaderOption) SACKBlocks() ([]TCPSACKBlock, bool) {
	if o.Kind != TCPHeaderOptionSACK || len(o.Data) < 8 || len(o.Data) > 32 || len(o.Data)%8 != 0 {
		return nil, false
	}
	blocks := make([]TCPSACKBlock, len(o.Data)/8)
	for index := range blocks {
		offset := index * 8
		blocks[index] = TCPSACKBlock{
			LeftEdge:  binary.BigEndian.Uint32(o.Data[offset : offset+4]),
			RightEdge: binary.BigEndian.Uint32(o.Data[offset+4 : offset+8]),
		}
	}
	return blocks, true
}

// SetSACKBlocks replaces o with a SACK option containing one to four blocks.
// It copies the block values and leaves o unchanged when the count is invalid.
func (o *TCPHeaderOption) SetSACKBlocks(blocks []TCPSACKBlock) error {
	if o == nil || len(blocks) < 1 || len(blocks) > 4 {
		return syscall.EINVAL
	}
	data := make([]byte, len(blocks)*8)
	for index, block := range blocks {
		offset := index * 8
		binary.BigEndian.PutUint32(data[offset:offset+4], block.LeftEdge)
		binary.BigEndian.PutUint32(data[offset+4:offset+8], block.RightEdge)
	}
	o.Kind = TCPHeaderOptionSACK
	o.Data = data
	return nil
}

// TCPSegment validates and decodes the packet's TCP upper layer. The three
// unexposed reserved bits are accepted and intentionally omitted from the
// semantic result, as Linux does; encoding writes them as zero. The historic
// NS bit remains available through TCPFlagNS for wire compatibility.
func (p IPPacket) TCPSegment() (TCPSegment, error) {
	tcp, pseudoHeaderSafe, err := p.upperLayerForProtocol(ProtocolTCP)
	if err != nil {
		return TCPSegment{}, err
	}
	if !pseudoHeaderSafe {
		return TCPSegment{}, syscall.EPROTONOSUPPORT
	}
	if len(tcp) < tcpHeaderSize {
		return TCPSegment{}, syscall.EINVAL
	}
	headerSize, valid := tcpWireHeaderSize(tcp[12], len(tcp))
	if !valid {
		return TCPSegment{}, syscall.EINVAL
	}
	options := tcp[tcpHeaderSize:headerSize]
	if _, valid = tcpOptionsContentLength(options); !valid {
		return TCPSegment{}, syscall.EINVAL
	}
	source, destination := p.Source.Unmap(), p.Destination.Unmap()
	if transportChecksum(source, destination, ProtocolTCP, tcp) != 0 {
		return TCPSegment{}, syscall.EINVAL
	}
	return TCPSegment{
		Source:         netip.AddrPortFrom(source, binary.BigEndian.Uint16(tcp[0:2])),
		Destination:    netip.AddrPortFrom(destination, binary.BigEndian.Uint16(tcp[2:4])),
		SequenceNumber: binary.BigEndian.Uint32(tcp[4:8]), AcknowledgmentNumber: binary.BigEndian.Uint32(tcp[8:12]),
		Flags:      uint16(tcp[13]) | uint16(tcp[12]&1)<<8,
		WindowSize: binary.BigEndian.Uint16(tcp[14:16]), UrgentPointer: binary.BigEndian.Uint16(tcp[18:20]),
		Options: options, Payload: tcp[headerSize:],
	}, nil
}

// MarshalBinary returns the complete TCP segment wire encoding. Source and
// Destination contribute to its pseudo-header checksum but are not themselves
// encoded. MarshalBinary is semantically identical to AppendBinary(nil).
func (s TCPSegment) MarshalBinary() ([]byte, error) { return s.AppendBinary(nil) }

// AppendBinary appends the complete TCP segment wire encoding to dst. Source
// and Destination contribute to its pseudo-header checksum but are not
// themselves encoded. It validates every field before changing dst, does not
// retain any input slice, and permits the destination to share backing storage
// with Options or Payload. On validation failure it returns the original dst
// unchanged.
func (s TCPSegment) AppendBinary(dst []byte) ([]byte, error) {
	normalized, headerSize, totalSize, err := s.wireLayout()
	if err != nil {
		return dst, err
	}
	start := len(dst)
	dst = extendForAppend(dst, totalSize)
	marshalPublicTCPSegment(dst[start:], normalized, headerSize)
	return dst, nil
}

// wireLayout validates s, normalizes its addresses, and returns exact header
// and segment lengths.
func (s TCPSegment) wireLayout() (TCPSegment, int, int, error) {
	if s.Source.Addr().Zone() != "" || s.Destination.Addr().Zone() != "" {
		return TCPSegment{}, 0, 0, syscall.EINVAL
	}
	source, destination := s.Source.Addr().Unmap(), s.Destination.Addr().Unmap()
	if !s.Source.IsValid() || !s.Destination.IsValid() || source.Is4() != destination.Is4() ||
		s.Flags&^uint16(TCPFlagFIN|TCPFlagSYN|TCPFlagRST|TCPFlagPSH|TCPFlagACK|TCPFlagURG|TCPFlagECE|TCPFlagCWR|TCPFlagNS) != 0 || len(s.Options) > 40 {
		return TCPSegment{}, 0, 0, syscall.EINVAL
	}
	if _, valid := tcpOptionsContentLength(s.Options); !valid {
		return TCPSegment{}, 0, 0, syscall.EINVAL
	}
	s.Source, s.Destination = netip.AddrPortFrom(source, s.Source.Port()), netip.AddrPortFrom(destination, s.Destination.Port())
	headerSize := tcpHeaderSize + (len(s.Options)+3)&^3
	if len(s.Payload) > 65535-headerSize {
		return TCPSegment{}, 0, 0, syscall.EMSGSIZE
	}
	return s, headerSize, headerSize + len(s.Payload), nil
}

// marshalPublicTCPSegment writes one already validated semantic segment.
func marshalPublicTCPSegment(dst []byte, s TCPSegment, headerSize int) {
	var options [40]byte
	contentSize, _ := tcpOptionsContentLength(s.Options)
	copy(options[:], s.Options[:contentSize])
	copy(dst[headerSize:], s.Payload)
	copy(dst[tcpHeaderSize:headerSize], options[:len(s.Options)])
	for index := tcpHeaderSize + len(s.Options); index < headerSize; index++ {
		dst[index] = 0
	}
	marshalTCPHeaderFields(dst[:headerSize], s.Source.Port(), s.Destination.Port(), s.SequenceNumber, s.AcknowledgmentNumber, s.Flags, s.WindowSize, s.UrgentPointer)
	binary.BigEndian.PutUint16(dst[16:18], transportChecksum(s.Source.Addr(), s.Destination.Addr(), ProtocolTCP, dst))
}

// marshalTCPHeaderFields writes every fixed TCP field and clears the checksum.
// The caller supplies a complete, four-byte-aligned header including options.
func marshalTCPHeaderFields(header []byte, sourcePort, destinationPort uint16, sequence, acknowledgement uint32, flags uint16, window, urgent uint16) {
	binary.BigEndian.PutUint16(header[0:2], sourcePort)
	binary.BigEndian.PutUint16(header[2:4], destinationPort)
	binary.BigEndian.PutUint32(header[4:8], sequence)
	binary.BigEndian.PutUint32(header[8:12], acknowledgement)
	header[12], header[13] = byte(len(header)/4)<<4|byte(flags>>8)&1, byte(flags)
	binary.BigEndian.PutUint16(header[14:16], window)
	binary.BigEndian.PutUint16(header[16:18], 0)
	binary.BigEndian.PutUint16(header[18:20], urgent)
}

// tcpOptionsContentLength validates option TLV framing and returns the bytes
// through an End of Option List. Receivers ignore the remaining padding;
// encoders use the returned length so generated padding is always zero.
func tcpOptionsContentLength(options []byte) (int, bool) {
	for offset := 0; offset < len(options); {
		switch options[offset] {
		case TCPHeaderOptionEnd:
			return offset + 1, true
		case TCPHeaderOptionNOP:
			offset++
			continue
		}
		// This validator is inlined into public TCP parsing and encoding.
		// Calling tcpHeaderOptionLength here crosses the compiler's inline
		// budget; semantic option decoding still shares that helper.
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

// KeepAliveConfig configures TCP keepalive probing. Every field must be
// positive when supplied to SetKeepAliveConfig.
type KeepAliveConfig struct {
	// Idle is the inactivity interval before the first probe.
	Idle time.Duration
	// Interval is the delay between unanswered probes.
	Interval time.Duration
	// Count is the number of unanswered probes allowed before failure.
	Count int
}

// TCPState identifies the current RFC 9293 connection state exposed by
// TCPConn.Info.
type TCPState uint8

const (
	// TCPStateClosed indicates that no connection state remains.
	TCPStateClosed TCPState = iota
	// TCPStateSYNReceived indicates a passive handshake awaiting its final ACK.
	TCPStateSYNReceived
	// TCPStateSYNSent indicates an active handshake awaiting a SYN-ACK.
	TCPStateSYNSent
	// TCPStateEstablished indicates bidirectional data transfer state.
	TCPStateEstablished
	// TCPStateFINWait1 indicates that the local FIN is not yet acknowledged.
	TCPStateFINWait1
	// TCPStateFINWait2 indicates that the local FIN is acknowledged while the peer remains open.
	TCPStateFINWait2
	// TCPStateCloseWait indicates that the peer closed first.
	TCPStateCloseWait
	// TCPStateClosing indicates simultaneous close awaiting the local FIN ACK.
	TCPStateClosing
	// TCPStateLastACK indicates a locally sent FIN after the peer closed first.
	TCPStateLastACK
	// TCPStateTimeWait indicates retained state after an active or simultaneous close.
	TCPStateTimeWait
)

// String returns the conventional RFC 9293 state name.
func (s TCPState) String() string {
	switch s {
	case TCPStateSYNReceived:
		return "SYN-RECEIVED"
	case TCPStateSYNSent:
		return "SYN-SENT"
	case TCPStateEstablished:
		return "ESTABLISHED"
	case TCPStateFINWait1:
		return "FIN-WAIT-1"
	case TCPStateFINWait2:
		return "FIN-WAIT-2"
	case TCPStateCloseWait:
		return "CLOSE-WAIT"
	case TCPStateClosing:
		return "CLOSING"
	case TCPStateLastACK:
		return "LAST-ACK"
	case TCPStateTimeWait:
		return "TIME-WAIT"
	default:
		return "CLOSED"
	}
}

// TCPConnInfo is a consistent point-in-time diagnostic snapshot of one TCP
// connection. Window, congestion, buffer, and path sizes are measured in
// bytes; PathMTU and MaximumSegmentSize include and exclude IP/TCP headers,
// respectively.
type TCPConnInfo struct {
	// LocalAddress is the local TCP endpoint.
	LocalAddress netip.AddrPort
	// RemoteAddress is the peer TCP endpoint.
	RemoteAddress netip.AddrPort
	// State is the current RFC 9293 connection state.
	State TCPState
	// CongestionControl identifies the selected congestion controller.
	CongestionControl CongestionControl
	// RTT is the smoothed round-trip time.
	RTT time.Duration
	// MinimumRTT is the minimum recent round-trip time.
	MinimumRTT time.Duration
	// RTTVariation is the smoothed round-trip-time variation.
	RTTVariation time.Duration
	// RetransmissionTimeout is the current RFC 6298 RTO.
	RetransmissionTimeout time.Duration
	// CongestionWindow is the current congestion window in bytes.
	CongestionWindow uint32
	// SlowStartThreshold is the current slow-start threshold in bytes.
	SlowStartThreshold uint32
	// BytesInFlight is the amount of transmitted but unacknowledged data.
	BytesInFlight uint32
	// DeliveryRate is the most recent delivery-rate estimate in bytes per second.
	DeliveryRate uint64
	// PacingRate is the controller's current pacing rate in bytes per second.
	PacingRate uint64
	// MaximumPacingRate is the configured pacing-rate ceiling, or zero if unlimited.
	MaximumPacingRate uint64
	// CongestionState is the controller-specific diagnostic state name.
	CongestionState string
	// PeerWindow is the latest advertised peer receive window in bytes.
	PeerWindow uint32
	// ReceiveWindow is the currently advertised local receive window in bytes.
	ReceiveWindow uint32
	// MaximumSegmentSize is the effective outbound TCP payload ceiling.
	MaximumSegmentSize int
	// PathMTU is the effective complete-IP-packet path MTU.
	PathMTU int
	// SendBufferSize is the number of application bytes currently buffered for send.
	SendBufferSize int
	// SendBufferCapacity is the current send-buffer limit.
	SendBufferCapacity int
	// MaximumSendBuffer is the automatic send-buffer tuning ceiling.
	MaximumSendBuffer int
	// ReceiveBufferSize is the number of application bytes waiting to be read.
	ReceiveBufferSize int
	// ReceiveBufferCapacity is the current receive-buffer limit.
	ReceiveBufferCapacity int
	// MaximumReceiveBuffer is the automatic receive-buffer tuning ceiling.
	MaximumReceiveBuffer int
	// BytesSent counts original application bytes transmitted.
	BytesSent uint64
	// BytesAcknowledged counts application bytes cumulatively acknowledged.
	BytesAcknowledged uint64
	// BytesReceived counts in-order application bytes received.
	BytesReceived uint64
	// Retransmissions counts retransmitted TCP segments.
	Retransmissions uint64
	// InboundQueueDrops counts segments rejected by the bounded actor queue.
	InboundQueueDrops uint64
	// InboundQueueBytes is the packet memory retained by the actor queue.
	InboundQueueBytes int64
	// InboundQueuePeak is the lifetime peak retained actor-queue memory.
	InboundQueuePeak int64
	// InboundQueueCapacity is the actor queue's memory bound.
	InboundQueueCapacity int
	// FastRecovery reports whether loss or ECN fast recovery is active.
	FastRecovery bool
	// RetransmissionRecovery reports whether recovery was entered by an RTO.
	RetransmissionRecovery bool
	// HyStartCSS reports whether HyStart++ Conservative Slow Start is active.
	HyStartCSS bool
	// PathMTUDiscovery reports whether packetization-layer discovery is enabled.
	PathMTUDiscovery bool
	// PathMTUProbe is the complete packet size of an outstanding probe, or zero.
	PathMTUProbe int
	// WindowScaling reports whether RFC 7323 window scaling was negotiated.
	WindowScaling bool
	// PeerWindowScale is the peer's advertised receive-window shift.
	PeerWindowScale uint8
	// ReceiveWindowScale is the local advertised receive-window shift.
	ReceiveWindowScale uint8
	// SACK reports whether selective acknowledgements were negotiated.
	SACK bool
	// Timestamps reports whether RFC 7323 timestamps were negotiated.
	Timestamps bool
	// ECN reports whether explicit congestion notification was negotiated.
	ECN bool
	// KeepAlive reports whether keepalive probing is enabled.
	KeepAlive bool
	// KeepAliveConfig is the effective keepalive probe policy.
	KeepAliveConfig KeepAliveConfig
	// IdleTimeout is the configured bidirectional inactivity timeout.
	IdleTimeout time.Duration
	// UserTimeout is the configured TCP user timeout.
	UserTimeout time.Duration
	// NoDelay reports whether Nagle coalescing is disabled.
	NoDelay bool
	// TrafficClass is the IPv4 TOS or IPv6 Traffic Class byte.
	TrafficClass uint8
	// FlowLabel is the IPv6 Flow Label, or zero for IPv4.
	FlowLabel uint32
	// SpuriousRecoveryUndos counts Eifel or DSACK recovery reversals.
	SpuriousRecoveryUndos uint64
	// PathMTUProbes counts packetization-layer probes sent.
	PathMTUProbes uint64
	// PathMTUProbeSuccesses counts acknowledged path-MTU probes.
	PathMTUProbeSuccesses uint64
	// PathMTUProbeFailures counts probes inferred lost.
	PathMTUProbeFailures uint64
	// ApplicationLimited reports whether delivery sampling is application-limited.
	ApplicationLimited bool
	// SchedulerLimited reports whether local scheduling currently limits delivery.
	SchedulerLimited bool
	// SchedulerLimitedEvents counts transitions into scheduler-limited delivery.
	SchedulerLimitedEvents uint64
	// LastError is the most recently recorded socket or asynchronous network error.
	LastError error
}

// tcpSocketOptions is one lock-protected option snapshot.
type tcpSocketOptions struct {
	keepAlive         bool
	keepAliveConfig   KeepAliveConfig
	idleTimeout       time.Duration
	userTimeout       time.Duration
	noDelay           bool
	congestionFactory *CongestionControlFactory
	maximumPacingRate uint64
}

// tcpInitialReceive carries SYN text across the handshake boundary without
// increasing the persistent size of every TCPConn.
type tcpInitialReceive struct {
	payload []byte
	fin     bool
}

// tcpSegment is a validated segment delivered to one connection actor.
type tcpSegment struct {
	sequence        uint32
	acknowledgement uint32
	flags           byte
	window          uint16
	ecn             byte
	optionLength    uint8
	options         [40]byte
	payload         []byte
	retainedBytes   int64
	receivedAt      monotonicStamp
}

// setOptions copies TCP options into segment-owned inline storage.
func (s *tcpSegment) setOptions(options []byte) {
	if len(options) > len(s.options) {
		panic("mipstack: TCP options exceed header capacity")
	}
	s.optionLength = uint8(copy(s.options[:], options))
}

// optionBytes returns the populated portion of the inline option storage.
func (s *tcpSegment) optionBytes() []byte { return s.options[:s.optionLength] }

// tcpSegmentQueue is a byte-bounded FIFO with allocation proportional to
// actual traffic rather than a large channel allocation on every connection.
type tcpSegmentQueue struct {
	mu       sync.Mutex
	segments []tcpSegment
	spare    []byte
	head     int
	bytes    int64
	peak     int64
	closed   bool
	// burst remembers that a drained queue exceeded the retained metadata
	// capacity, so the next burst starts at that capacity instead of one slot.
	burst  bool
	notify chan struct{}
}

// newTCPSegmentQueue constructs an empty queue with one edge-triggered actor
// wakeup. Packet arrivals and state-only notifications share the token; queued
// packets and actorWakeFlags retain the work independently when they coalesce.
func newTCPSegmentQueue() tcpSegmentQueue {
	return tcpSegmentQueue{notify: make(chan struct{}, 1)}
}

// enqueue retains one segment if the byte bound permits it.
func (q *tcpSegmentQueue) enqueue(segment tcpSegment) bool {
	retained := int64(tcpInboundSegmentMetadata + len(segment.payload))
	q.mu.Lock()
	if q.closed || retained > tcpInboundByteCapacity || q.bytes > int64(tcpInboundByteCapacity)-retained {
		q.mu.Unlock()
		return false
	}
	q.enqueueLocked(segment, retained)
	q.mu.Unlock()
	return true
}

// enqueueCopy checks the actor byte bound before taking ownership of a packet
// payload. The established input path can therefore drop overload without an
// allocation and reuse one connection-local common-MTU backing.
func (q *tcpSegmentQueue) enqueueCopy(segment tcpSegment, payload []byte) bool {
	retained := int64(tcpInboundSegmentMetadata + len(payload))
	q.mu.Lock()
	if q.closed || retained > tcpInboundByteCapacity || q.bytes > int64(tcpInboundByteCapacity)-retained {
		q.mu.Unlock()
		return false
	}
	if len(payload) != 0 {
		var owned []byte
		if cap(q.spare) >= len(payload) {
			owned = q.spare[:len(payload)]
			q.spare = nil
		} else {
			owned = make([]byte, len(payload))
		}
		copy(owned, payload)
		segment.payload = owned[:len(owned):len(owned)]
	}
	q.enqueueLocked(segment, retained)
	q.mu.Unlock()
	return true
}

// enqueueLocked appends one owned segment while q.mu is held.
func (q *tcpSegmentQueue) enqueueLocked(segment tcpSegment, retained int64) {
	empty := q.head == len(q.segments)
	if q.head != 0 && len(q.segments) == cap(q.segments) && q.head*2 >= len(q.segments) {
		remaining := copy(q.segments, q.segments[q.head:])
		for index := remaining; index < len(q.segments); index++ {
			q.segments[index] = tcpSegment{}
		}
		q.segments = q.segments[:remaining]
		q.head = 0
	}
	if q.segments == nil {
		capacity := tcpMetadataQueueInitial
		if q.burst {
			capacity = tcpMetadataQueueRetain
		}
		q.segments = make([]tcpSegment, 0, capacity)
	} else if q.head == 0 && len(q.segments) == cap(q.segments) && cap(q.segments) == tcpMetadataQueueInitial {
		// A second simultaneously queued segment proves this is not the idle
		// singleton case. Jump directly to the retained short-burst capacity
		// instead of allocating and copying through every intermediate size.
		segments := make([]tcpSegment, len(q.segments), tcpMetadataQueueRetain)
		copy(segments, q.segments)
		q.segments = segments
	}
	segment.retainedBytes = retained
	q.segments = append(q.segments, segment)
	q.bytes += retained
	if q.bytes > q.peak {
		q.peak = q.bytes
	}
	if empty {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
}

// recyclePayload retains at most one modest backing after the application has
// synchronously consumed it. A larger available buffer replaces a smaller one
// so ordinary full-sized segments do not repeatedly allocate after short ACKs.
func (q *tcpSegmentQueue) recyclePayload(payload []byte) {
	if cap(payload) == 0 || cap(payload) > tcpReusableReceivePayloadLimit {
		return
	}
	q.mu.Lock()
	if !q.closed && cap(payload) > cap(q.spare) {
		q.spare = payload[:0]
	}
	q.mu.Unlock()
}

// prepend returns an actor-owned segment to the front when handshake state
// hands a data-bearing completion segment to the established state machine.
func (q *tcpSegmentQueue) prepend(segment tcpSegment) bool {
	retained := int64(tcpInboundSegmentMetadata + len(segment.payload))
	segment.retainedBytes = retained
	q.mu.Lock()
	if q.closed || retained > tcpInboundByteCapacity || q.bytes > int64(tcpInboundByteCapacity)-retained {
		q.mu.Unlock()
		return false
	}
	empty := q.head == len(q.segments)
	if q.head != 0 {
		q.head--
		q.segments[q.head] = segment
	} else {
		q.segments = append(q.segments, tcpSegment{})
		copy(q.segments[1:], q.segments[:len(q.segments)-1])
		q.segments[0] = segment
	}
	q.bytes += retained
	if empty {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	q.mu.Unlock()
	return true
}

// dequeue removes one segment and keeps a wakeup armed while work remains.
func (q *tcpSegmentQueue) dequeue() (tcpSegment, bool) {
	q.mu.Lock()
	if q.head == len(q.segments) {
		q.mu.Unlock()
		return tcpSegment{}, false
	}
	segment := q.segments[q.head]
	q.segments[q.head] = tcpSegment{}
	q.head++
	q.bytes -= segment.retainedBytes
	segment.retainedBytes = 0
	if q.head == len(q.segments) {
		if cap(q.segments) <= tcpMetadataQueueRetain {
			q.segments = q.segments[:0]
		} else {
			// Remember observed burst traffic after releasing its larger
			// backing. A later burst then avoids regrowing through the tiny
			// idle-connection capacities on every cycle.
			q.burst = true
			q.segments = nil
		}
		q.head = 0
	} else {
		if q.head >= 1024 && q.head*2 >= len(q.segments) {
			copy(q.segments, q.segments[q.head:])
			q.segments = q.segments[:len(q.segments)-q.head]
			q.head = 0
		}
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	q.mu.Unlock()
	return segment, true
}

// len returns the number of segments waiting for the actor.
func (q *tcpSegmentQueue) len() int {
	q.mu.Lock()
	length := len(q.segments) - q.head
	q.mu.Unlock()
	return length
}

// retainedBytes returns the approximate memory retained by queued segments.
func (q *tcpSegmentQueue) retainedBytes() int64 {
	q.mu.Lock()
	retained := q.bytes
	q.mu.Unlock()
	return retained
}

// peakBytes returns the largest approximate memory occupancy observed.
func (q *tcpSegmentQueue) peakBytes() int64 {
	q.mu.Lock()
	peak := q.peak
	q.mu.Unlock()
	return peak
}

// close releases every queued packet and rejects later delivery while
// retaining lifetime diagnostics.
func (q *tcpSegmentQueue) close() {
	q.mu.Lock()
	q.segments = nil
	q.spare = nil
	q.head = 0
	q.bytes = 0
	q.closed = true
	q.mu.Unlock()
}

// tcpTimerBacklog gives receive work that was already queued when a timer
// expired one bounded turn ahead of that timer. Packets arriving during the
// turn are not added, so a continuously refilled queue cannot starve timers.
type tcpTimerBacklog struct {
	deadline  time.Time
	remaining int
}

// order reports whether to drain the captured receive snapshot or force the
// expired timer. A changed or newly expired deadline starts a fresh snapshot.
func (b *tcpTimerBacklog) order(queueLength int, deadline, now time.Time) (drain, forceTimer bool) {
	if deadline.IsZero() || now.Before(deadline) {
		b.deadline = time.Time{}
		b.remaining = 0
		return false, false
	}
	if b.deadline.IsZero() || !b.deadline.Equal(deadline) {
		b.deadline = deadline
		b.remaining = queueLength
	}
	return b.remaining != 0, b.remaining == 0
}

// consumed advances the fixed receive snapshot without counting later input.
func (b *tcpTimerBacklog) consumed() {
	if b.remaining > 0 {
		b.remaining--
	}
}

// tcpZeroWindowProbe is an allocation-free acknowledged byte used to elicit
// a current window advertisement from a peer.
var tcpZeroWindowProbe = [...]byte{0}

// tcpReceiveWindow retains the furthest receive sequence promised to the
// peer. Buffer occupancy may reduce newly available space, but it must not
// move an already advertised right edge backwards.
type tcpReceiveWindow struct {
	right uint32
	shift uint8
}

// newTCPReceiveWindow starts with the last window sent during the handshake
// and the scale advertised by this endpoint. A SYN-ACK is unscaled, while an
// active opener's final ACK is scaled.
func newTCPReceiveWindow(receiveNext uint32, initial uint16, scaled, initialScaled bool, scale uint8) tcpReceiveWindow {
	initialBytes := uint32(initial)
	window := tcpReceiveWindow{}
	if scaled {
		window.shift = scale
	}
	if initialScaled {
		initialBytes <<= window.shift
	}
	window.right = receiveNext + initialBytes
	return window
}

// tcpReceiveWindowScaleFor selects the smallest RFC 7323 scale capable of
// advertising the configured automatic receive ceiling. Keeping the scale
// minimal preserves window precision for deliberately small socket policies.
func tcpReceiveWindowScaleFor(maximum int) uint8 {
	if maximum <= 65535 {
		return 0
	}
	var scale uint8
	for scale < 14 && uint64(65535)<<scale < uint64(maximum) {
		scale++
	}
	return scale
}

// next returns the wire window that would be advertised with the currently
// available storage, without committing that promise until a segment is sent.
func (w *tcpReceiveWindow) next(receiveNext uint32, available, minimumIncrease int) (uint16, uint32) {
	if available < 0 {
		available = 0
	}
	maximum := uint32(65535) << w.shift
	if uint64(available) > uint64(maximum) {
		available = int(maximum)
	}
	desired := receiveNext + uint32(available>>w.shift)<<w.shift
	right := w.right
	if tcpSequenceGreater(desired, right) {
		increase := desired - right
		if minimumIncrease < 0 {
			minimumIncrease = 0
		}
		if increase >= uint32(minimumIncrease) {
			right = desired
		}
	}
	if tcpSequenceLess(right, receiveNext) {
		return 0, right
	}
	return uint16((right - receiveNext) >> w.shift), right
}

// advertise commits and returns the window carried by an outgoing segment.
func (w *tcpReceiveWindow) advertise(receiveNext uint32, available, minimumIncrease int) uint16 {
	window, right := w.next(receiveNext, available, minimumIncrease)
	w.right = right
	return window
}

// size returns the receive sequence space covered by prior advertisements.
func (w *tcpReceiveWindow) size(receiveNext uint32) uint32 {
	if tcpSequenceLess(w.right, receiveNext) {
		return 0
	}
	return w.right - receiveNext
}

// tcpReceiveWindowIncrease is the RFC 1122 receiver SWS threshold:
// min(one half of the receive buffer, one expected segment).
func tcpReceiveWindowIncrease(capacity, mss int) int {
	if capacity < 1 {
		return 0
	}
	threshold := capacity/2 + capacity%2
	if mss > 0 && threshold > mss {
		threshold = mss
	}
	return threshold
}

// tcpBufferAutoTune measures useful byte progress over an RTT. Receive tuning
// supplies application-consumed bytes; send tuning supplies acknowledged
// bytes. Queue or congestion-window size alone is not evidence that a larger
// application buffer improves throughput.
type tcpBufferAutoTune struct {
	updated time.Time
	bytes   uint64
}

// target returns twice the measured per-RTT progress, leaving one BDP queued
// while the preceding BDP is consumed or acknowledged.
func (t *tcpBufferAutoTune) target(now time.Time, rtt time.Duration, total uint64, maximum int) int {
	if rtt <= 0 {
		return 0
	}
	if t.updated.IsZero() {
		t.updated, t.bytes = now, total
		return 0
	}
	elapsed := now.Sub(t.updated)
	interval := rtt
	if interval < tcpAutoTuneMinimumInterval {
		interval = tcpAutoTuneMinimumInterval
	}
	if elapsed < interval {
		return 0
	}
	delta := total - t.bytes
	t.updated, t.bytes = now, total
	if delta == 0 {
		return 0
	}
	// Normalize a delayed observation to one RTT so a suspended userspace
	// actor cannot interpret many intervals of reads as one enormous BDP.
	perRTT := delta
	if elapsed > rtt {
		perRTT = uint64(float64(delta) * float64(rtt) / float64(elapsed))
	}
	if maximum <= 0 {
		return 0
	}
	if perRTT > uint64(maximum/2) {
		perRTT = uint64(maximum / 2)
	}
	return int(perRTT * 2)
}

// sentTCPSegmentState packs independent retransmission, recovery, and delivery
// flags into the fixed-size record retained for each outstanding sequence
// range.
type sentTCPSegmentState uint16

const (
	// sentTCPSegmentSACKed marks a range that the peer selectively acknowledged.
	sentTCPSegmentSACKed sentTCPSegmentState = 1 << iota
	// sentTCPSegmentSACKRetried marks a range already sent during the current
	// SACK recovery so it is not selected again without new loss evidence.
	sentTCPSegmentSACKRetried
	// sentTCPSegmentRACKLost marks a range whose transmission time satisfies
	// RACK's loss test.
	sentTCPSegmentRACKLost
	// sentTCPSegmentLimited marks data sent by RFC 3042 Limited Transmit, which
	// is excluded from the FlightSize captured when recovery starts.
	sentTCPSegmentLimited
	// sentTCPSegmentCWR records that the transmission carried CWR state which
	// recovery may need to restore on another transmission.
	sentTCPSegmentCWR
	// sentTCPSegmentSACKSplit marks a range created at a SACK boundary so the
	// scoreboard can bound further fragmentation.
	sentTCPSegmentSACKSplit
	// sentTCPSegmentMTUProbe associates the range with the active PLPMTUD probe.
	sentTCPSegmentMTUProbe
	// sentTCPSegmentDeliveryPending defers refreshing the delivery snapshot
	// until the ACK currently being processed has updated the rate sampler.
	sentTCPSegmentDeliveryPending
	// sentTCPSegmentDeliverySchedulerLimited records that the congestion
	// controller considered this transmission scheduler-limited.
	sentTCPSegmentDeliverySchedulerLimited
	// sentTCPSegmentTransmitted makes the current transmission generation
	// eligible for proven-loss accounting.
	sentTCPSegmentTransmitted
	// sentTCPSegmentRetransmitted records that the range has been retransmitted
	// at least once; the compact state deliberately retains no exact count.
	sentTCPSegmentRetransmitted
	// sentTCPSegmentLossReported prevents reporting the current transmission
	// generation's loss to the congestion controller more than once.
	sentTCPSegmentLossReported
)

// has reports whether any requested state bit is present.
func (s sentTCPSegmentState) has(flag sentTCPSegmentState) bool { return s&flag != 0 }

// set adds or removes one or more state bits according to enabled.
func (s *sentTCPSegmentState) set(flag sentTCPSegmentState, enabled bool) {
	if enabled {
		*s |= flag
	} else {
		*s &^= flag
	}
}

// sentTCPSegmentInitialState constructs the state of a newly transmitted range.
// Every such range starts with a current transmission generation; the remaining
// arguments capture properties of that first transmission.
func sentTCPSegmentInitialState(limited, cwr, mtuProbe, deliveryPending, schedulerLimited bool) sentTCPSegmentState {
	state := sentTCPSegmentTransmitted
	if limited {
		state |= sentTCPSegmentLimited
	}
	if cwr {
		state |= sentTCPSegmentCWR
	}
	if mtuProbe {
		state |= sentTCPSegmentMTUProbe
	}
	if deliveryPending {
		state |= sentTCPSegmentDeliveryPending
	}
	if schedulerLimited {
		state |= sentTCPSegmentDeliverySchedulerLimited
	}
	return state
}

// sentTCPSegment retains retransmission state for one sequence range.
// On 64-bit targets, its layout deliberately occupies one 64-byte cache line:
//
//	 0..15  sequence range, TCP timestamp, state, flags, and alignment
//	16..39  first-send time and host-queue ticket
//	40..47  controller-owned CongestionEvent.PacketState
//	48..59  delivery-rate snapshot
//	60..63  tail padding
//
// Blank fields make both padding regions explicit; layout tests enforce the
// offsets. The packet state is opaque to TCP and belongs to the transmission
// generation that produced it. Methods use pointer receivers so hot ACK paths
// do not copy the complete cache-line-sized record.
type sentTCPSegment struct {
	sequence              uint32
	end                   uint32
	timestamp             uint32
	state                 sentTCPSegmentState
	flags                 byte
	_                     [1]byte
	firstSent             time.Duration
	hostQueue             packetQueueTicket
	congestionPacketState uint64
	delivery              tcpDeliverySnapshot
	_                     [4]byte
}

// dataSize returns the application bytes covered by this sequence range.
// FIN occupies sequence space but is not retained in the send buffer.
func (s *sentTCPSegment) dataSize() int {
	size := s.end - s.sequence
	if s.flags&TCPFlagFIN != 0 && size != 0 {
		size--
	}
	return int(size)
}

// isTransmitted reports whether the range has a current transmission generation
// that can contribute a proven-loss event.
func (s *sentTCPSegment) isTransmitted() bool {
	return s.state.has(sentTCPSegmentTransmitted)
}

// isRetransmitted reports whether the sequence range has been transmitted more
// than once, without retaining an exact transmission count.
func (s *sentTCPSegment) isRetransmitted() bool {
	return s.state.has(sentTCPSegmentRetransmitted)
}

// lossAlreadyReported reports whether loss for the current transmission
// generation has already been delivered to the congestion controller.
func (s *sentTCPSegment) lossAlreadyReported() bool {
	return s.state.has(sentTCPSegmentLossReported)
}

// advanceTransmissionGeneration records a retransmission and makes its new
// generation independently eligible for a loss event.
func (s *sentTCPSegment) advanceTransmissionGeneration() {
	s.state |= sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted
	s.state &^= sentTCPSegmentLossReported
}

// transmittedAt reconstructs the host-queue admission time used by loss
// recovery. epoch must be the stack epoch shared by the ticket's owning queue;
// retaining only the relative stamp avoids a time.Time in every range.
func (s *sentTCPSegment) transmittedAt(epoch time.Time) time.Time {
	return s.hostQueue.queuedTime(epoch)
}

// tcpPLPMTU is one RFC 4821 binary-search episode. Sizes include the IP and
// TCP headers, matching the specification's Probe_Size definition.
type tcpPLPMTU struct {
	searchLow  int
	searchHigh int
	probeMTU   int
	probeStart uint32
	probeEnd   uint32
	nextProbe  time.Time
	searching  bool
	active     bool
}

// start begins an upward search without changing the confirmed effective MTU.
func (p *tcpPLPMTU) start(base, maximum int, now time.Time) {
	if maximum-base < tcpPLPMTUProbeThreshold {
		*p = tcpPLPMTU{}
		return
	}
	*p = tcpPLPMTU{searchLow: base, searchHigh: maximum, nextProbe: now, searching: true}
}

// candidate returns the midpoint packet size when another probe is useful.
func (p *tcpPLPMTU) candidate(now time.Time) (int, bool) {
	if !p.searching || p.active || now.Before(p.nextProbe) || p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		return 0, false
	}
	return p.searchLow + (p.searchHigh-p.searchLow+1)/2, true
}

// sent records the exact sequence interval carried by a probe.
func (p *tcpPLPMTU) sent(mtu int, start, end uint32) {
	p.probeMTU, p.probeStart, p.probeEnd, p.active = mtu, start, end, true
}

// success raises the confirmed lower bound and permits the next binary probe.
func (p *tcpPLPMTU) success(now time.Time) int {
	mtu := p.probeMTU
	p.searchLow = mtu
	p.active = false
	p.probeMTU = 0
	p.nextProbe = now
	if p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		p.searching = false
	}
	return mtu
}

// failed lowers the upper search bound after an isolated probe loss and
// enforces RFC 4821's TCP-friendly suppression headway.
func (p *tcpPLPMTU) failed(now time.Time, headway time.Duration) {
	if p.probeMTU > 0 && p.probeMTU-1 < p.searchHigh {
		p.searchHigh = p.probeMTU - 1
	}
	p.active = false
	p.probeMTU = 0
	if headway < tcpPLPMTUProbeMinimumInterval {
		headway = tcpPLPMTUProbeMinimumInterval
	}
	p.nextProbe = now.Add(headway)
	if p.searchHigh-p.searchLow < tcpPLPMTUProbeThreshold {
		p.searching = false
	}
}

// inconclusive cancels one probe without narrowing the search. A timeout or
// concurrent loss remains ordinary congestion evidence under RFC 4821.
func (p *tcpPLPMTU) inconclusive(now time.Time, delay time.Duration) {
	p.active = false
	p.probeMTU = 0
	if delay < tcpPLPMTUProbeMinimumInterval {
		delay = tcpPLPMTUProbeMinimumInterval
	}
	p.nextProbe = now.Add(delay)
}

// tcpPLPMTUProbeHeadway returns one RTT per packet permitted by cwnd, the
// RFC 4821 estimate of the interval between TCP-friendly congestion events.
func tcpPLPMTUProbeHeadway(window uint32, mss int, roundTrip time.Duration) time.Duration {
	if mss < 1 {
		mss = 1
	}
	if roundTrip <= 0 {
		roundTrip = tcpInitialRTO
	}
	packets := (uint64(window) + uint64(mss) - 1) / uint64(mss)
	if packets == 0 {
		packets = 1
	}
	const maximum = time.Duration(1<<63 - 1)
	if packets > uint64(maximum/roundTrip) {
		return maximum
	}
	headway := time.Duration(packets) * roundTrip
	if headway < tcpPLPMTUProbeMinimumInterval {
		return tcpPLPMTUProbeMinimumInterval
	}
	return headway
}

// tcpPLPMTUTimeoutDelay applies RFC 4821's recommended five-times backoff
// after a timeout made a probe outcome inconclusive.
func tcpPLPMTUTimeoutDelay(headway time.Duration) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	if headway > maximum/5 {
		return maximum
	}
	return 5 * headway
}

// tcpCongestionValueForMSS preserves a congestion value in bytes when MSS
// grows and preserves its packet count when MSS shrinks, as required by RFC
// 4821. A live congestion window retains a one-packet floor.
func tcpCongestionValueForMSS(value uint32, oldMSS, newMSS int, floor bool) uint32 {
	if value == 0 || oldMSS < 1 || newMSS < 1 || newMSS >= oldMSS {
		return value
	}
	value = uint32(uint64(value) * uint64(newMSS) / uint64(oldMSS))
	if floor && value < uint32(newMSS) {
		return uint32(newMSS)
	}
	return value
}

// reduce restarts future upward search from a newly confirmed lower PMTU.
func (p *tcpPLPMTU) reduce(mtu, prior, maximum int, now time.Time) {
	high := maximum
	if prior > mtu && prior-1 < high {
		high = prior - 1
	}
	p.start(mtu, high, now.Add(pathMTULifetime))
}

// tcpUndoRange tracks one sequence interval retransmitted in a recovery
// episode. RFC 3708 permits undo only after every such interval is reported
// duplicated and rejects intervals retransmitted more than once.
type tcpUndoRange struct {
	sequence   uint32
	end        uint32
	duplicated bool
}

// tcpRecoveryUndo retains the pre-recovery state needed by RFC 3522/4015
// Eifel response and the conservative RFC 3708 DSACK disambiguation.
type tcpRecoveryUndo struct {
	active              bool
	timeout             bool
	eifelChecked        bool
	dsackDisabled       bool
	retransmitTimestamp uint32
	point               uint32
	priorWindow         uint32
	priorThreshold      uint32
	priorFlight         uint32
	// spuriousUndos is lifetime diagnostic state. begin preserves it while
	// resetting the per-recovery fields in this object.
	spuriousUndos uint64
	priorRTT      rttEstimator
	ranges        []tcpUndoRange
}

// tcpEifelRTOResponse retains RFC 4015 step 11 until an RTT sample from data
// that had not been sent when the spurious timeout occurred is available.
type tcpEifelRTOResponse struct {
	point          uint32
	previousSRTT   time.Duration
	previousRTTVar time.Duration
	pending        bool
}

// tcpRetransmissionRecord is one recently retransmitted wire range. Count is
// greater than one when retransmission ambiguity forbids an RFC 3708 undo.
type tcpRetransmissionRecord struct {
	sequence uint32
	end      uint32
	count    int
}

// tcpRetransmissionHistory keeps the slightly longer history required by RFC
// 3708 after ranges leave the ordinary SACK scoreboard.
type tcpRetransmissionHistory struct {
	ranges []tcpRetransmissionRecord
}

// begin snapshots congestion state before the first reduction in an episode.
func (u *tcpRecoveryUndo) begin(timeout bool, point, window, threshold, flight uint32, controller *tcpCongestionController, rtt rttEstimator) {
	controller.checkpointRecovery(time.Now(), window, threshold, flight, controller.state.MaximumSegmentSize)
	spuriousUndos := u.spuriousUndos
	*u = tcpRecoveryUndo{
		active: true, timeout: timeout, point: point, priorWindow: window,
		priorThreshold: threshold, priorFlight: flight, priorRTT: rtt,
		spuriousUndos: spuriousUndos,
	}
}

// recordRetransmission adds one exact wire range and the first retransmission
// timestamp. Repeating a retransmission makes DSACK undo ambiguous.
func (u *tcpRecoveryUndo) recordRetransmission(sequence, end, timestamp uint32, repeated bool) {
	if !u.active {
		return
	}
	if repeated {
		u.dsackDisabled = true
	}
	if u.retransmitTimestamp == 0 {
		u.retransmitTimestamp = timestamp
	}
	for index := range u.ranges {
		candidate := &u.ranges[index]
		if candidate.sequence == sequence && candidate.end == end {
			return
		}
	}
	u.ranges = append(u.ranges, tcpUndoRange{sequence: sequence, end: end})
}

// detectEifel applies RFC 3522's conservative timestamp test to the first
// acceptable ACK after recovery starts. A current DSACK is left to RFC 3708.
func (u *tcpRecoveryUndo) detectEifel(timestampEcho uint32, currentDSACK, priorDSACK bool, acknowledgement uint32) bool {
	if !u.active || u.eifelChecked || u.retransmitTimestamp == 0 || timestampEcho == 0 {
		return false
	}
	u.eifelChecked = true
	if !tcpSequenceLess(timestampEcho, u.retransmitTimestamp) || currentDSACK {
		return false
	}
	return priorDSACK || tcpSequenceLess(acknowledgement, u.point)
}

// observeDSACK marks retransmitted ranges and reports when RFC 3708 has
// accounted every retransmission in the recovery window as duplicated.
func (u *tcpRecoveryUndo) observeDSACK(block TCPSACKBlock, acknowledgement, sendUnacknowledged uint32, scoreboardEmpty bool) bool {
	if !u.active || u.dsackDisabled {
		return false
	}
	if scoreboardEmpty && block.LeftEdge == sendUnacknowledged {
		// RFC 3708 A.1 treats loss of an entire ACK window as reverse-path
		// congestion, so this recovery episode must not be undone.
		u.dsackDisabled = true
		return false
	}
	matched := false
	for index := range u.ranges {
		candidate := &u.ranges[index]
		if tcpSequenceLessEqual(block.LeftEdge, candidate.sequence) && tcpSequenceGreaterEqual(block.RightEdge, candidate.end) {
			candidate.duplicated = true
			matched = true
		}
	}
	if !matched {
		// RFC 3708 treats a DSACK for data that this sender did not retransmit
		// as evidence of network duplication and disables DSACK-based undo.
		u.dsackDisabled = true
		return false
	}
	if len(u.ranges) == 0 {
		return false
	}
	for _, candidate := range u.ranges {
		if !candidate.duplicated || tcpSequenceLess(acknowledgement, candidate.end) {
			return false
		}
	}
	return true
}

// restore computes RFC 4015's bounded post-undo cwnd and restores the safe
// threshold. The controller receives an undo event so loss-based algorithms
// can restore their checkpoint while model-based algorithms retain live
// delivery accounting. The acknowledged-byte burst is capped by the initial
// window.
func (u *tcpRecoveryUndo) restore(flight, acknowledged uint32, mss int, current *tcpCongestionController, now time.Time) (uint32, uint32) {
	credit := acknowledged
	if initial := initialTCPWindow(mss); credit > initial {
		credit = initial
	}
	window := growCongestionWindow(flight, credit)
	if window < uint32(mss) {
		window = uint32(mss)
	}
	threshold := u.priorFlight
	if threshold < u.priorThreshold {
		threshold = u.priorThreshold
	}
	current.undoRecovery(now, window, threshold, flight, mss)
	u.active = false
	return window, threshold
}

// eifelRTOResponse constructs the delayed RFC 4015 timer response for a
// timeout recovery. Fast-retransmit undo does not alter the RTT estimator.
func (u *tcpRecoveryUndo) eifelRTOResponse() tcpEifelRTOResponse {
	if !u.timeout {
		return tcpEifelRTOResponse{}
	}
	return tcpEifelRTOResponse{
		point: u.point, previousSRTT: u.priorRTT.srtt + 2*tcpEifelClockGranularity,
		previousRTTVar: u.priorRTT.variation, pending: true,
	}
}

// observe applies RFC 4015 step 11 to the first valid RTT sample covering
// data beyond the recovery point.
func (e *tcpEifelRTOResponse) observe(acknowledgement uint32, sample time.Duration, rtt *rttEstimator) bool {
	if !e.pending || sample <= 0 || !tcpSequenceGreater(acknowledgement, e.point) {
		return false
	}
	sample = normalizedRTTSample(sample)
	rtt.srtt = e.previousSRTT
	if rtt.srtt < sample {
		rtt.srtt = sample
	}
	rtt.variation = e.previousRTTVar
	if half := sample / 2; rtt.variation < half {
		rtt.variation = half
	}
	rtt.initialized = true
	rtt.updateRTO()
	e.pending = false
	return true
}

// record retains one retransmitted range and counts repeated retransmissions.
func (h *tcpRetransmissionHistory) record(sequence, end uint32) {
	for index := len(h.ranges) - 1; index >= 0; index-- {
		rangeState := &h.ranges[index]
		if rangeState.sequence == sequence && rangeState.end == end {
			rangeState.count++
			return
		}
	}
	repeated := false
	for index := range h.ranges {
		rangeState := &h.ranges[index]
		if tcpSequenceLess(sequence, rangeState.end) && tcpSequenceLess(rangeState.sequence, end) {
			repeated = true
			if rangeState.count < 2 {
				rangeState.count = 2
			}
		}
	}
	if len(h.ranges) == tcpRetransmissionHistoryLimit {
		copy(h.ranges, h.ranges[1:])
		h.ranges = h.ranges[:len(h.ranges)-1]
	}
	count := 1
	if repeated {
		count = 2
	}
	h.ranges = append(h.ranges, tcpRetransmissionRecord{sequence: sequence, end: end, count: count})
}

// match reports whether a DSACK covers a known retransmission and whether
// that range was retransmitted more than once.
func (h *tcpRetransmissionHistory) match(block TCPSACKBlock) (bool, bool) {
	matched, repeated := false, false
	for _, rangeState := range h.ranges {
		if tcpSequenceLessEqual(block.LeftEdge, rangeState.sequence) && tcpSequenceGreaterEqual(block.RightEdge, rangeState.end) {
			matched = true
			repeated = repeated || rangeState.count > 1
		}
	}
	return matched, repeated
}

// tcpRACKSample identifies the newest transmission known to have been
// delivered. RFC 8985 orders equal transmit timestamps by sequence number.
type tcpRACKSample struct {
	sentAt        time.Time
	end           uint32
	rtt           time.Duration
	timestamp     uint32
	retransmitted bool
}

// tcpEstablishedLivenessState holds state first needed by asynchronous
// network errors, keepalive probing, or a zero-window user timeout. Keeping it
// separate from path and recovery diagnostics avoids charging one cold event
// for every unrelated optional field.
type tcpEstablishedLivenessState struct {
	zeroWindowSince, lastKeepAlive time.Time
	lastSoftError                  error
	keepAliveProbes                int
}

// tcpEstablishedPathMTUState holds PLPMTUD search, black-hole fallback, and
// their diagnostics. A connection that never receives PMTU feedback or starts
// an upward probe does not allocate it.
type tcpEstablishedPathMTUState struct {
	discovery                   tcpPLPMTU
	blackHoleExpiry             time.Time
	probes, successes, failures uint64
	blackHoleMTU                int
}

// tcpEstablishedState contains protocol state owned by one established TCP
// actor. Keeping the long-lived state behind one pointer avoids duplicating
// captures across the event loop's local operations and lets an idle actor
// remain in the runtime's smaller goroutine stack class.
type tcpEstablishedState struct {
	// connection owns application-visible synchronization and socket policy;
	// every other field in this object is accessed only by its actor goroutine.
	connection                                    *TCPConn
	sendNext, sendUnacknowledged                  uint32
	peerMSS, pathMSS, receiveMSS                  int
	peerWindow, peerWindowSequence, peerWindowACK uint32
	maximumPeerWindow                             uint32
	bytesAcknowledged, bytesSent, bytesReceived   uint64
	receiveNext                                   uint32
	congestionWindow, slowStartThreshold          uint32
	ecnRecoveryPoint                              uint32
	// outstanding is the live suffix of outstandingBase. outstandingHead is
	// its offset in that backing and permits cheap cumulative-ACK removal until
	// compactOutstanding or rebaseOutstanding restores a zero-based slice.
	outstanding, outstandingBase        []sentTCPSegment
	outstandingHead                     int
	outOfOrder                          []tcpReceivedPiece
	outOfOrderBytes                     int
	recentDSACK                         TCPSACKBlock
	duplicateACKs                       int
	recoveryPoint, prrPriorFlight       uint32
	prrDelivered, prrOut                uint64
	recentSACK, lastACKSent             uint32
	tailProbeEnd                        uint32
	tailProbeBytes                      int
	tailProbeState, tailProbeRTTSamples uint64
	rtoAttempts                         int
	rtoRecoveryPoint                    uint32
	blackHoleRTOs                       int
	lastTimestampUpdate                 time.Time
	controller                          tcpCongestionController
	rackLatestDelivered                 tcpRACKSample
	rackForwardACK                      uint32
	rackReorderingScale, rackDSACKRound uint32
	rackReorderPersist                  int
	lastDataSent, ecnHoldUntil          time.Time
	receiveAutoTune, sendAutoTune       tcpBufferAutoTune
	hyStart                             tcpHyStart
	// Recovery helpers remain nil until their corresponding loss evidence is
	// observed. Once created they are connection-local and reused by the actor.
	undo              *tcpRecoveryUndo
	eifelRTO          *tcpEifelRTOResponse
	retransmitHistory *tcpRetransmissionHistory
	sackedRanges      int
	sackedBytes       uint32
	rtt               rttEstimator
	// actorTimerChannel is the sole physical timer. The logical timer flags and
	// deadlines below select which protocol event owns its current firing.
	actorTimerChannel                       <-chan time.Time
	actorTimerDeadline                      time.Time
	retransmissionDeadline, persistDeadline time.Time
	delayedACKDeadline                      time.Time
	livenessDeadline, pathMTUDeadline       time.Time
	pacingDeadline                          time.Time
	// deliverySample is allocated only for controllers that consume delivery
	// rate samples; loss-based controllers leave it nil.
	deliverySample               *tcpDeliveryRateSample
	deliveryACKAddedFlight       uint32
	persistRTO                   time.Duration
	persistAttempts, ackSegments int
	lastAdvertisedWindow         uint16
	receiveWindowState           tcpReceiveWindow
	lastActivity, eventTime      time.Time
	// sackWorkspace is allocated only when an ACK must encode SACK blocks.
	sackWorkspace *[34]byte
	// These independent cold states prevent one liveness or path event from
	// allocating storage for the other feature family.
	livenessState *tcpEstablishedLivenessState
	pathMTUState  *tcpEstablishedPathMTUState

	// Group single-byte state to avoid alignment holes without adding bitset
	// operations to packet-processing paths.
	peerScale                                  uint8
	peerSACK, haveRecentDSACK                  bool
	localFINSent, localFINAcked                bool
	remoteFINReceived, timeWaitRequired        bool
	finWaitArmed, timeWaitArmed, fastRecovery  bool
	tailProbeActive, tailProbeRetransmit       bool
	rtoRecovery, ecnRecoveryActive             bool
	rackForwardACKSet, rackReorderingSeen      bool
	rackDSACKRoundSet, seenDSACK               bool
	dsackUndoDisabled, haveRACKLoss            bool
	retransmit, persist, delayedACK            bool
	liveness, pathMTUProbe, pacing             bool
	retransmissionProbe, retransmissionRACK    bool
	retransmissionClose, processingDeliveryACK bool
	deliveryACKPendingSnapshots, ackPending    bool
}

// ensureLivenessState initializes infrequently used liveness state on demand.
func (s *tcpEstablishedState) ensureLivenessState() *tcpEstablishedLivenessState {
	if s.livenessState == nil {
		s.livenessState = new(tcpEstablishedLivenessState)
	}
	return s.livenessState
}

// ensurePathMTUState initializes infrequently used path diagnostics on demand.
func (s *tcpEstablishedState) ensurePathMTUState() *tcpEstablishedPathMTUState {
	if s.pathMTUState == nil {
		s.pathMTUState = new(tcpEstablishedPathMTUState)
	}
	return s.pathMTUState
}

// newTCPEstablishedState transfers handshake results into one actor-owned
// state object and initializes the data-phase timers and congestion state.
func newTCPEstablishedState(c *TCPConn, sendNext uint32) *tcpEstablishedState {
	localMaximum := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	if c.peerTimestamp {
		localMaximum -= 12
	}
	peerMSS := clampMSS(c.peerMSS, localMaximum)
	options := c.socketOptions()
	now := time.Now()
	state := &tcpEstablishedState{
		connection: c,
		sendNext:   sendNext, sendUnacknowledged: sendNext,
		peerMSS: peerMSS, pathMSS: localMaximum, receiveMSS: localMaximum,
		peerScale: c.peerWindowScale, peerSACK: c.peerSACK,
		peerWindow: c.peerWindow, peerWindowSequence: c.peerWindowSeq,
		peerWindowACK: c.peerWindowACK, maximumPeerWindow: c.peerWindow,
		receiveNext: c.receiveNext, lastACKSent: c.receiveNext,
		congestionWindow: initialTCPWindow(peerMSS), slowStartThreshold: ^uint32(0) >> 1,
		lastTimestampUpdate: now, rackReorderingScale: 1,
		persistRTO: time.Second,
		controller: newTCPCongestionControllerFromFactory(options.congestionFactory, CongestionControlContext{
			LocalAddress: c.key.local, RemoteAddress: c.key.remote,
			Passive: c.passive, Forwarded: c.forwarded,
		}),
	}
	state.controller.setMaximumPacingRate(options.maximumPacingRate)
	c.publishICMPSequenceRange(state.sendUnacknowledged, state.sendNext)
	initialDataRTO := tcpInitialRTO
	if c.handshakeTimeout {
		// RFC 6298 section 5.7 requires a three-second data RTO after a
		// SYN retransmission timer expires. A duplicate SYN or a path-MTU
		// update may resend a handshake packet without triggering this rule.
		initialDataRTO = 3 * time.Second
	}
	state.rtt = newRTTEstimator(initialDataRTO)
	if !c.handshakeTimeout {
		state.rtt.observeAt(c.handshakeRTT, monotonicStampAt(c.stack.timestampEpoch, now))
	}
	state.congestionWindow, state.slowStartThreshold = state.controller.initialize(now, state.rtt.minimum, state.rtt.srtt, state.congestionWindow, state.slowStartThreshold, state.peerMSS, monotonicStampAt(c.stack.timestampEpoch, now))
	initialWindowScaled := c.peerWindowScaling && !c.passive
	state.lastAdvertisedWindow = c.receiveWindow(0, initialWindowScaled)
	state.receiveWindowState = newTCPReceiveWindow(state.receiveNext, state.lastAdvertisedWindow, c.peerWindowScaling, initialWindowScaled, c.receiveWindowScale)
	state.receiveAutoTune.updated = now
	state.receiveAutoTune.bytes = c.applicationReads.Load()
	state.sendAutoTune.updated = now
	state.hyStart.start(state.sendNext)
	state.lastActivity = now
	state.eventTime = now
	return state
}

// finish publishes the final live diagnostic snapshot, releases controller
// resources, and makes at most one abortive-reset attempt.
func (s *tcpEstablishedState) finish() {
	defer s.controller.release(time.Now(), s.congestionWindow, s.slowStartThreshold, s.congestionFlight(), s.peerMSS, s.rtt.srtt, s.rtt.minimum)
	c := s.connection
	if c.takeAbortReset() {
		sequence := tcpAcceptableSendSequence(s.sendUnacknowledged, s.sendNext, s.peerWindow, s.peerScale)
		_ = c.sendAbortReset(sequence, s.receiveNext, s.advertisedReceiveWindow())
	}
	info := s.tcpInfo()
	c.lastInfo.Store(&info)
}

// compactOutstanding moves the live suffix to the start of its existing
// backing before an append would otherwise allocate another slice.
func (s *tcpEstablishedState) compactOutstanding() {
	if s.outstandingHead == 0 {
		return
	}
	if len(s.outstanding) == 0 {
		s.outstanding, s.outstandingBase, s.outstandingHead = nil, nil, 0
		return
	}
	storage := s.outstandingBase[:s.outstandingHead+len(s.outstanding)]
	copy(storage, s.outstanding)
	for index := len(s.outstanding); index < len(storage); index++ {
		storage[index] = sentTCPSegment{}
	}
	s.outstanding = storage[:len(s.outstanding)]
	s.outstandingHead = 0
}

// appendOutstanding adds one transmitted sequence range while retaining a
// small initial capacity for ordinary windows and control-only traffic.
func (s *tcpEstablishedState) appendOutstanding(segment sentTCPSegment) {
	if s.outstanding == nil {
		capacity := 1
		if segment.dataSize() != 0 {
			capacity = tcpInitialOutstandingCapacity
		}
		s.outstandingBase = make([]sentTCPSegment, 0, capacity)
		s.outstanding = s.outstandingBase
	}
	if len(s.outstanding) == cap(s.outstanding) && s.outstandingHead != 0 {
		s.compactOutstanding()
	}
	priorCapacity := cap(s.outstanding)
	s.outstanding = append(s.outstanding, segment)
	if cap(s.outstanding) != priorCapacity {
		s.outstandingBase = s.outstanding[:0]
		s.outstandingHead = 0
	}
}

// rebaseOutstanding normalizes the live outstanding slice after cumulative
// removal and releases an empty backing.
func (s *tcpEstablishedState) rebaseOutstanding() {
	if len(s.outstanding) == 0 {
		s.outstanding, s.outstandingBase, s.outstandingHead = nil, nil, 0
		return
	}
	s.outstandingBase = s.outstanding[:0]
	s.outstandingHead = 0
}

// ordinaryFlight returns sent but not cumulatively or selectively
// acknowledged sequence space outside SACK recovery.
func (s *tcpEstablishedState) ordinaryFlight() uint32 {
	flight := s.sendNext - s.sendUnacknowledged
	if s.sackedBytes > flight {
		return 0
	}
	return flight - s.sackedBytes
}

// congestionFlight returns the controller-visible flight estimate, using
// RFC 6675 Pipe while SACK recovery is active.
func (s *tcpEstablishedState) congestionFlight() uint32 {
	if s.peerSACK && s.fastRecovery {
		return sackRecoveryPipe(s.outstanding, s.peerMSS)
	}
	return s.ordinaryFlight()
}

// recountSACK refreshes the cached SACKed range and byte totals after the
// scoreboard has been structurally modified.
func (s *tcpEstablishedState) recountSACK() {
	s.sackedRanges, s.sackedBytes = tcpSACKedState(s.outstanding)
}

// recordRetransmission initializes history only after the first retransmission;
// loss-free connections never need the DSACK correlation storage.
func (s *tcpEstablishedState) recordRetransmission(start, end uint32) {
	if s.retransmitHistory == nil {
		s.retransmitHistory = new(tcpRetransmissionHistory)
	}
	s.retransmitHistory.record(start, end)
}

// lossObservationTime selects the ACK arrival time for a delivery sample and
// otherwise uses the current actor time for congestion loss reporting.
func (s *tcpEstablishedState) lossObservationTime() time.Time {
	if s.processingDeliveryACK && s.deliverySample != nil && !s.deliverySample.ackTime.IsZero() {
		return s.deliverySample.ackTime
	}
	return time.Now()
}

// recordProvenLosses reports newly proven loss through the event family used
// by the active congestion controller.
func (s *tcpEstablishedState) recordProvenLosses() {
	if !s.controller.usesLossEvents() {
		s.controller.noteLoss(recordProvenTCPLosses(s.outstanding, s.peerMSS), s.processingDeliveryACK)
		return
	}
	now := s.lossObservationTime()
	recordProvenTCPLossesWith(s.outstanding, s.peerMSS, func(segment *sentTCPSegment, bytes uint32) {
		s.controller.notePacketLoss(segment, bytes, s.processingDeliveryACK, now, s.congestionWindow, s.slowStartThreshold, s.congestionFlight(), s.peerMSS, s.rtt.srtt)
	})
}

// connectionState derives the public TCP state from the actor's close flags.
func (s *tcpEstablishedState) connectionState() TCPState {
	switch {
	case s.timeWaitArmed:
		return TCPStateTimeWait
	case !s.localFINSent && s.remoteFINReceived:
		return TCPStateCloseWait
	case !s.localFINSent:
		return TCPStateEstablished
	case !s.localFINAcked && !s.timeWaitRequired:
		return TCPStateLastACK
	case !s.localFINAcked && s.remoteFINReceived:
		return TCPStateClosing
	case !s.localFINAcked:
		return TCPStateFINWait1
	case !s.remoteFINReceived:
		return TCPStateFINWait2
	default:
		return TCPStateClosed
	}
}

// tcpInfo combines actor-owned protocol state with the connection's locked
// application-facing state into one consistent diagnostic snapshot.
func (s *tcpEstablishedState) tcpInfo() TCPConnInfo {
	c := s.connection
	c.mu.Lock()
	info := c.tcpConnInfoBaseLocked(s.connectionState())
	info.CongestionControl = s.controller.algorithmName()
	info.RTT, info.MinimumRTT, info.RTTVariation, info.RetransmissionTimeout = s.rtt.srtt, s.rtt.minimum, s.rtt.variation, s.rtt.rto
	info.CongestionWindow, info.SlowStartThreshold = s.congestionWindow, s.slowStartThreshold
	info.BytesInFlight = s.congestionFlight()
	diagnostics := s.controller.diagnostics(time.Now(), s.congestionWindow, s.slowStartThreshold, info.BytesInFlight, s.peerMSS, s.rtt.srtt, s.rtt.minimum)
	info.DeliveryRate, info.PacingRate = diagnostics.DeliveryRate, diagnostics.PacingRate
	info.CongestionState = diagnostics.State
	info.ApplicationLimited, info.SchedulerLimited = diagnostics.ApplicationLimited, diagnostics.SchedulerLimited
	info.SchedulerLimitedEvents = diagnostics.SchedulerLimitedEvents
	info.MaximumPacingRate = s.controller.maximumPacingRate
	info.PeerWindow, info.ReceiveWindow = s.peerWindow, s.receiveWindowState.size(s.receiveNext)
	info.MaximumSegmentSize, info.PathMTU = s.peerMSS, c.mtu
	dataAcknowledged := s.bytesAcknowledged
	if dataAcknowledged > s.bytesSent {
		dataAcknowledged = s.bytesSent
	}
	info.BytesSent, info.BytesAcknowledged, info.BytesReceived = s.bytesSent, dataAcknowledged, s.bytesReceived
	info.FastRecovery, info.RetransmissionRecovery, info.HyStartCSS = s.fastRecovery, s.rtoRecovery, s.hyStart.css
	if s.undo != nil {
		info.SpuriousRecoveryUndos = s.undo.spuriousUndos
	}
	if s.pathMTUState != nil {
		info.PathMTUDiscovery, info.PathMTUProbe = s.pathMTUState.discovery.searching, s.pathMTUState.discovery.probeMTU
		info.PathMTUProbes = s.pathMTUState.probes
		info.PathMTUProbeSuccesses, info.PathMTUProbeFailures = s.pathMTUState.successes, s.pathMTUState.failures
	}
	c.mu.Unlock()
	return info
}

// advertisedReceiveWindow advances the RFC window advertisement state from
// current contiguous and out-of-order receive occupancy.
func (s *tcpEstablishedState) advertisedReceiveWindow() uint16 {
	available, capacity := s.connection.receiveSpace(s.outOfOrderBytes)
	return s.receiveWindowState.advertise(s.receiveNext, available, tcpReceiveWindowIncrease(capacity, s.receiveMSS))
}

// effectivePathMTU returns the route MTU capped by any connection-local
// black-hole fallback.
func (s *tcpEstablishedState) effectivePathMTU() int {
	c := s.connection
	mtu := c.stack.mtuFor(c.key.remote.Addr())
	if s.pathMTUState != nil && s.pathMTUState.blackHoleMTU > 0 && s.pathMTUState.blackHoleMTU < mtu {
		mtu = s.pathMTUState.blackHoleMTU
	}
	return mtu
}

// armPacingAt schedules pacing at an absolute actor deadline.
func (s *tcpEstablishedState) armPacingAt(deadline time.Time) {
	s.pacing = true
	s.pacingDeadline = deadline
}

// keepAliveEligible reports whether all queued sequence space has been sent
// and no data remains outstanding, as required before probing an idle peer.
func (s *tcpEstablishedState) keepAliveEligible() bool {
	if len(s.outstanding) != 0 {
		return false
	}
	offset := int(s.sendNext - s.sendUnacknowledged)
	total, writeClosed := s.connection.sendState()
	return offset >= total && (!writeClosed || s.localFINSent)
}

// userTimeoutDeadline returns the oldest unacknowledged-data or zero-window
// deadline. It allocates liveness state only when zero-window timing begins.
func (s *tcpEstablishedState) userTimeoutDeadline(now time.Time, timeout time.Duration) time.Time {
	if timeout <= 0 {
		if s.livenessState != nil {
			s.livenessState.zeroWindowSince = time.Time{}
		}
		return time.Time{}
	}
	var oldest time.Time
	if len(s.outstanding) != 0 {
		index := 0
		if s.sackedRanges != 0 {
			index = firstUnsackedSegment(s.outstanding)
		}
		oldest = s.connection.stack.timestampEpoch.Add(s.outstanding[index].firstSent)
	}
	offset := int(s.sendNext - s.sendUnacknowledged)
	total, writeClosed := s.connection.sendState()
	zeroWindowBlocked := s.peerWindow == 0 && (offset < total || writeClosed && !s.localFINSent)
	if zeroWindowBlocked {
		liveness := s.ensureLivenessState()
		if liveness.zeroWindowSince.IsZero() {
			liveness.zeroWindowSince = now
		}
		if oldest.IsZero() || liveness.zeroWindowSince.Before(oldest) {
			oldest = liveness.zeroWindowSince
		}
	} else if s.livenessState != nil {
		s.livenessState.zeroWindowSince = time.Time{}
	}
	if oldest.IsZero() {
		return time.Time{}
	}
	return oldest.Add(timeout)
}

// ageRACKReordering expires one persistence round of an enlarged RACK
// reordering window.
func (s *tcpEstablishedState) ageRACKReordering() {
	if s.rackReorderPersist <= 0 {
		return
	}
	s.rackReorderPersist--
	if s.rackReorderPersist == 0 {
		s.rackReorderingScale = 1
	}
}

// observeRACKReordering records forward-ACK evidence that retransmission
// reordering has occurred.
func (s *tcpEstablishedState) observeRACKReordering(end uint32, retransmitted bool) {
	if rackAdvanceForwardACK(&s.rackForwardACK, &s.rackForwardACKSet, end, retransmitted) {
		s.rackReorderingSeen = true
	}
}

// rackDeadline returns the earliest RACK loss-detection deadline for the
// current scoreboard, if RACK has enough delivery evidence to arm one.
func (s *tcpEstablishedState) rackDeadline(now time.Time, haveSACKed bool) (time.Time, bool) {
	if !s.peerSACK || len(s.outstanding) == 0 || !haveSACKed && !s.rackLatestDelivered.retransmitted {
		return time.Time{}, false
	}
	reorderingWindow := rackReorderingWindow(s.rtt.minimum, s.rtt.srtt, s.rackReorderingScale)
	if !s.rackReorderingSeen && (s.fastRecovery || s.rtoRecovery || s.sackedRanges >= tcpDuplicateACKThreshold) {
		reorderingWindow = 0
	}
	delay, exists := rackLossDelay(s.outstanding, s.rackLatestDelivered, now, reorderingWindow, s.connection.stack.timestampEpoch)
	if !exists {
		return time.Time{}, false
	}
	return now.Add(delay), true
}

// armClose reuses the retransmission timer for a bounded close-state wait.
func (s *tcpEstablishedState) armClose(startedAt time.Time, duration time.Duration) {
	s.retransmissionDeadline = time.Now().Add(duration)
	if !startedAt.IsZero() {
		s.retransmissionDeadline = startedAt.Add(duration)
	}
	s.retransmit = true
	s.retransmissionProbe = false
	s.retransmissionRACK = false
	s.retransmissionClose = true
}

// clearDelayedACK cancels delayed acknowledgement state after an ACK is sent.
func (s *tcpEstablishedState) clearDelayedACK() {
	s.delayedACK = false
	s.delayedACKDeadline = time.Time{}
	s.ackPending = false
	s.ackSegments = 0
}

// armPathMTUProbe selects the next per-connection discovery or cached route
// expiry that requires path-MTU work.
func (s *tcpEstablishedState) armPathMTUProbe() {
	s.pathMTUProbe = false
	s.pathMTUDeadline = time.Time{}
	if s.pathMTUState != nil && s.pathMTUState.discovery.searching {
		if !s.pathMTUState.discovery.active && time.Now().Before(s.pathMTUState.discovery.nextProbe) {
			s.pathMTUProbe = true
			s.pathMTUDeadline = s.pathMTUState.discovery.nextProbe
		}
		return
	}
	c := s.connection
	expiry, exists := c.stack.pathMTUExpiry(c.key.remote.Addr())
	if s.pathMTUState != nil && !s.pathMTUState.blackHoleExpiry.IsZero() && (!exists || s.pathMTUState.blackHoleExpiry.Before(expiry)) {
		expiry, exists = s.pathMTUState.blackHoleExpiry, true
	}
	if exists {
		s.pathMTUProbe = true
		s.pathMTUDeadline = expiry
	}
}

// armLiveness selects the earliest idle, user-timeout, zero-window, or
// keepalive deadline without allocating state for inactive policies.
func (s *tcpEstablishedState) armLiveness() {
	s.liveness = false
	s.livenessDeadline = time.Time{}
	if s.localFINAcked && s.remoteFINReceived {
		return
	}
	options := s.connection.socketOptions()
	var deadline time.Time
	if options.idleTimeout > 0 {
		deadline = s.lastActivity.Add(options.idleTimeout)
	}
	if userDeadline := s.userTimeoutDeadline(time.Now(), options.userTimeout); !userDeadline.IsZero() && (deadline.IsZero() || userDeadline.Before(deadline)) {
		deadline = userDeadline
	}
	if options.userTimeout > 0 && s.livenessState != nil && s.livenessState.keepAliveProbes != 0 {
		keepAliveUserDeadline := s.lastActivity.Add(options.userTimeout)
		if deadline.IsZero() || keepAliveUserDeadline.Before(deadline) {
			deadline = keepAliveUserDeadline
		}
	}
	if options.keepAlive && s.keepAliveEligible() {
		keepAliveDeadline := s.lastActivity.Add(options.keepAliveConfig.Idle)
		if s.livenessState != nil && s.livenessState.keepAliveProbes != 0 {
			keepAliveDeadline = s.livenessState.lastKeepAlive.Add(options.keepAliveConfig.Interval)
		}
		if deadline.IsZero() || keepAliveDeadline.Before(deadline) {
			deadline = keepAliveDeadline
		}
	}
	if !deadline.IsZero() {
		s.liveness = true
		s.livenessDeadline = deadline
	}
}

// armRetransmission selects the earliest RTO, tail-loss probe, or RACK
// deadline for the current outstanding scoreboard.
func (s *tcpEstablishedState) armRetransmission() {
	s.retransmit = false
	s.retransmissionDeadline = time.Time{}
	s.retransmissionProbe = false
	s.retransmissionRACK = false
	s.retransmissionClose = false
	if len(s.outstanding) == 0 {
		return
	}
	now := time.Now()
	index := 0
	if s.sackedRanges != 0 {
		index = firstUnsackedSegment(s.outstanding)
	}
	deadline := s.outstanding[index].transmittedAt(s.connection.stack.timestampEpoch).Add(s.rtt.rto)
	haveSACKed := s.peerSACK && s.sackedRanges != 0
	if s.peerSACK && s.peerWindow != 0 && s.ecnHoldUntil.IsZero() && !s.tailProbeActive && s.rtt.samples > s.tailProbeRTTSamples && !s.fastRecovery && !s.rtoRecovery && !haveSACKed {
		probeIndex := len(s.outstanding) - 1
		probeDeadline := s.outstanding[probeIndex].transmittedAt(s.connection.stack.timestampEpoch).Add(tailLossProbeDelay(s.rtt.srtt, s.rtt.rto, len(s.outstanding) == 1))
		if probeDeadline.Before(deadline) {
			deadline = probeDeadline
			s.retransmissionProbe = true
		}
	}
	if candidate, exists := s.rackDeadline(now, haveSACKed); exists && !candidate.After(deadline) {
		deadline = candidate
		s.retransmissionProbe = false
		s.retransmissionRACK = true
	}
	s.retransmit = true
	s.retransmissionDeadline = deadline
}

// armRetransmissionAfterACK restarts RFC 6298 timing from actor processing
// time while retaining packet-arrival time for RACK loss calculations.
func (s *tcpEstablishedState) armRetransmissionAfterACK(acknowledgedAt time.Time) {
	s.retransmit = false
	s.retransmissionDeadline = time.Time{}
	s.retransmissionProbe = false
	s.retransmissionRACK = false
	s.retransmissionClose = false
	if len(s.outstanding) == 0 {
		return
	}
	// RFC 6298 section 5.3 restarts the timer when TCP processes an ACK
	// that cumulatively acknowledges new data. Packet arrival time remains
	// the RTT/RACK sample clock, but host delay before the actor updates its
	// scoreboard must not consume the newly installed RTO or tail-probe
	// interval and manufacture an immediate retransmission.
	now := time.Now()
	deadline := now.Add(s.rtt.rto)
	haveSACKed := s.peerSACK && s.sackedRanges != 0
	if s.peerSACK && s.peerWindow != 0 && s.ecnHoldUntil.IsZero() && !s.tailProbeActive && s.rtt.samples > s.tailProbeRTTSamples && !s.fastRecovery && !s.rtoRecovery && !haveSACKed {
		probeDeadline := now.Add(tailLossProbeDelay(s.rtt.srtt, s.rtt.rto, len(s.outstanding) == 1))
		if probeDeadline.Before(deadline) {
			deadline = probeDeadline
			s.retransmissionProbe = true
		}
	}
	if candidate, exists := s.rackDeadline(acknowledgedAt, haveSACKed); exists && !candidate.After(deadline) {
		deadline = candidate
		s.retransmissionProbe = false
		s.retransmissionRACK = true
	}
	s.retransmit = true
	s.retransmissionDeadline = deadline
}

// armPersist schedules zero-window probing only when unsent sequence space is
// blocked and no transmitted segment belongs under the retransmission timer.
func (s *tcpEstablishedState) armPersist(sentAt time.Time) {
	offset := int(s.sendNext - s.sendUnacknowledged)
	total, writeClosed := s.connection.sendState()
	// Linux keeps packets_out under the normal retransmission timer. Persist is
	// needed only when no transmitted sequence is outstanding and a closed
	// receive window prevents new data or FIN from being sent.
	pending := len(s.outstanding) == 0 && (offset < total || writeClosed && !s.localFINSent)
	if pending && s.peerWindow == 0 && !s.persist {
		if s.persistRTO < s.rtt.rto {
			s.persistRTO = s.rtt.rto
		}
		s.persistDeadline = time.Now().Add(s.persistRTO)
		if !sentAt.IsZero() {
			s.persistDeadline = sentAt.Add(s.persistRTO)
		}
		s.persist = true
	} else if s.peerWindow != 0 || !pending {
		s.persist = false
		s.persistDeadline = time.Time{}
		s.persistRTO = time.Second
		s.persistAttempts = 0
	}
}

// sackOptions builds bounded ACK options in the connection-local lazy
// workspace and reports whether the pending DSACK was encoded.
func (s *tcpEstablishedState) sackOptions(reservePayload int) ([]byte, bool) {
	if !s.peerSACK || len(s.outOfOrder) == 0 && !s.haveRecentDSACK {
		return nil, false
	}
	if s.sackWorkspace == nil {
		s.sackWorkspace = new([34]byte)
	}
	c := s.connection
	maximumBlocks := tcpSACKBlockLimit(c.mtu, c.key.local.Addr(), c.peerTimestamp, reservePayload)
	options := tcpSACKOptions(s.outOfOrder, s.recentSACK, maximumBlocks, s.recentDSACK, s.haveRecentDSACK, s.sackWorkspace)
	return options, s.haveRecentDSACK && len(options) >= 10
}

// sendACKAt emits an ACK from sequence and commits window, SACK, and delayed-
// ACK bookkeeping only after packet construction succeeds.
func (s *tcpEstablishedState) sendACKAt(sequence uint32) error {
	options, dsackSent := s.sackOptions(0)
	window := s.advertisedReceiveWindow()
	if err := s.connection.sendSegmentWithOptions(sequence, s.receiveNext, TCPFlagACK, window, options, nil); err != nil {
		return err
	}
	s.lastACKSent = s.receiveNext
	s.lastAdvertisedWindow = window
	if dsackSent {
		s.haveRecentDSACK = false
	}
	s.clearDelayedACK()
	return nil
}

// sendACK emits an ACK from a sequence acceptable in the current peer window.
func (s *tcpEstablishedState) sendACK() error {
	sequence := tcpAcceptableSendSequence(s.sendUnacknowledged, s.sendNext, s.peerWindow, s.peerScale)
	return s.sendACKAt(sequence)
}

// sendChallengeACK emits a rate-limited RFC 5961 challenge ACK.
func (s *tcpEstablishedState) sendChallengeACK() error {
	if !s.connection.stack.allowControlResponse(controlResponseTCPChallengeACK) {
		return nil
	}
	return s.sendACK()
}

// sendChallengeACKAt emits a rate-limited challenge ACK from an explicit
// sequence selected by the validating control path.
func (s *tcpEstablishedState) sendChallengeACKAt(sequence uint32) error {
	if !s.connection.stack.allowControlResponse(controlResponseTCPChallengeACK) {
		return nil
	}
	return s.sendACKAt(sequence)
}

// scheduleACK records received data and either sends immediately or arms the
// delayed-ACK timer at the packet's arrival time.
func (s *tcpEstablishedState) scheduleACK(immediate, data bool, receivedAt time.Time) error {
	s.ackPending = true
	if data {
		s.ackSegments++
	}
	if immediate || s.ackSegments >= 2 {
		return s.sendACK()
	}
	if !s.delayedACK {
		s.delayedACKDeadline = receivedAt.Add(tcpDelayedACKTimeout)
		s.delayedACK = true
	}
	return nil
}

// changeCongestionController replaces only controller-private state while
// retaining transport-owned cwnd, ssthresh, RTT, and outstanding data.
func (s *tcpEstablishedState) changeCongestionController(factory *CongestionControlFactory, maximumPacingRate uint64) {
	if factory == s.controller.factory {
		if s.controller.setMaximumPacingRate(maximumPacingRate) {
			s.pacing = false
			s.pacingDeadline = time.Time{}
		}
		return
	}
	now := time.Now()
	s.controller.release(now, s.congestionWindow, s.slowStartThreshold, s.congestionFlight(), s.peerMSS, s.rtt.srtt, s.rtt.minimum)
	c := s.connection
	s.controller = newTCPCongestionControllerFromFactory(factory, CongestionControlContext{
		LocalAddress: c.key.local, RemoteAddress: c.key.remote,
		Passive: c.passive, Forwarded: c.forwarded,
	})
	s.controller.setMaximumPacingRate(maximumPacingRate)
	if s.undo != nil {
		s.undo.active = false
	}
	for index := range s.outstanding {
		s.outstanding[index].delivery = tcpDeliverySnapshot{}
		s.outstanding[index].congestionPacketState = 0
	}
	s.congestionWindow, s.slowStartThreshold = s.controller.initialize(now, s.rtt.minimum, s.rtt.srtt, s.congestionWindow, s.slowStartThreshold, s.peerMSS, monotonicStampAt(c.stack.timestampEpoch, now))
	s.hyStart.disable()
	s.pacing = false
	s.pacingDeadline = time.Time{}
}

// consumeActorTimer marks the shared physical timer drained before a logical
// timer handler rearms it.
func (s *tcpEstablishedState) consumeActorTimer(actorTimer *ownedTimer) {
	actorTimer.consumed()
	s.actorTimerChannel = nil
	s.actorTimerDeadline = time.Time{}
}

// tcpReceivedPiece retains one normalized out-of-order receive range.
type tcpReceivedPiece struct {
	sequence uint32
	payload  []byte
	fin      bool
}

// tcpReadBuffer is a byte-counted deque of actor-owned receive payloads. TCP
// packets already arrive in independent backing allocations; retaining those
// chunks avoids repeatedly copying the entire unread stream as a contiguous
// buffer grows.
type tcpReadBuffer struct {
	chunks [][]byte
	head   int
	size   int
}

// append transfers one immutable payload into the deque.
func (b *tcpReadBuffer) append(payload []byte) {
	if len(payload) == 0 {
		return
	}
	if b.head != 0 && len(b.chunks) == cap(b.chunks) {
		live := copy(b.chunks, b.chunks[b.head:])
		for index := live; index < len(b.chunks); index++ {
			b.chunks[index] = nil
		}
		b.chunks = b.chunks[:live]
		b.head = 0
	}
	b.chunks = append(b.chunks, payload)
	b.size += len(payload)
}

// read copies across as many chunks as needed to fill destination, matching a
// stream Read rather than exposing packet boundaries.
func (b *tcpReadBuffer) read(destination []byte, maximum int, recycle func([]byte)) int {
	if maximum > len(destination) {
		maximum = len(destination)
	}
	if maximum > b.size {
		maximum = b.size
	}
	written := 0
	for written < maximum {
		chunk := b.chunks[b.head]
		n := copy(destination[written:maximum], chunk)
		written += n
		b.size -= n
		if n == len(chunk) {
			if recycle != nil {
				recycle(chunk)
			}
			b.chunks[b.head] = nil
			b.head++
		} else {
			b.chunks[b.head] = chunk[n:]
		}
	}
	if b.size == 0 {
		b.reset()
	}
	return written
}

// take removes one stable chunk prefix without copying. Each receive payload
// has independent backing, so later appends cannot modify the returned bytes.
func (b *tcpReadBuffer) take(maximum int) ([]byte, bool) {
	chunk := b.chunks[b.head]
	complete := len(chunk) <= maximum
	if len(chunk) > maximum {
		chunk = chunk[:maximum:maximum]
	} else {
		chunk = chunk[:len(chunk):len(chunk)]
	}
	b.size -= len(chunk)
	if len(chunk) == len(b.chunks[b.head]) {
		b.chunks[b.head] = nil
		b.head++
	} else {
		b.chunks[b.head] = b.chunks[b.head][len(chunk):]
	}
	if b.size == 0 {
		b.reset()
	}
	return chunk, complete
}

// reset releases payload references and retains only bounded deque metadata.
func (b *tcpReadBuffer) reset() {
	for index := range b.chunks {
		b.chunks[index] = nil
	}
	if cap(b.chunks) > tcpReadChunkRetain {
		b.chunks = nil
	} else {
		b.chunks = b.chunks[:0]
	}
	b.head = 0
	b.size = 0
}

// tcpSendChunk owns one immutable range while it may be referenced by a sent
// segment. start and end delimit live bytes in storage; streamStart is the
// connection-relative offset represented by start.
type tcpSendChunk struct {
	storage     []byte
	start       int
	end         int
	streamStart uint64
}

// tcpPayloadViewMaximumChunks bounds scatter metadata for one TCP segment.
const tcpPayloadViewMaximumChunks = 5

// tcpPayloadView is a stack-owned scatter view of immutable send-buffer bytes.
// A maximum-sized TCP segment can cross at most five send chunks because only
// the first live chunk may be as small as tcpSendChunkInitial and all later
// chunks are at least tcpSendChunkMinimum bytes.
type tcpPayloadView struct {
	chunks [tcpPayloadViewMaximumChunks][]byte
	count  int
	size   int
}

// setBytes initializes a one-piece view for control paths with contiguous
// payload. The caller retains ownership until packet construction completes.
func (v *tcpPayloadView) setBytes(payload []byte) {
	*v = tcpPayloadView{}
	if len(payload) != 0 {
		v.chunks[0] = payload
		v.count = 1
		v.size = len(payload)
	}
}

// copyTo serializes the view into final packet storage.
func (v *tcpPayloadView) copyTo(destination []byte) int {
	copied := 0
	for index := 0; index < v.count; index++ {
		copied += copy(destination[copied:], v.chunks[index])
	}
	return copied
}

// tcpSendBuffer is a sequence-addressed deque. It never compacts live bytes,
// so a payload slice held by retransmission metadata cannot be overwritten by
// a concurrent Write. At most one acknowledged modest chunk is retained.
type tcpSendBuffer struct {
	chunks []tcpSendChunk
	spare  []byte
	base   uint64
	end    uint64
	size   int
	// reusableState prevents one moderate write from permanently retaining its
	// backing while allowing repeated same-class traffic to reuse one chunk.
	reusableState uint8
}

// Moderate send backing moves from unseen to released on its first disposal
// and to confirmed on the next allocation. Initial small chunks bypass this
// policy and may always be retained.
const (
	// tcpSendReusableUnseen has not yet observed a released moderate chunk.
	tcpSendReusableUnseen uint8 = iota
	// tcpSendReusableReleased observed one release without retaining it.
	tcpSendReusableReleased
	// tcpSendReusableConfirmed permits one moderate backing to remain spare.
	tcpSendReusableConfirmed
)

// append copies payload into bounded chunks without moving earlier bytes.
func (b *tcpSendBuffer) append(payload []byte) {
	for len(payload) != 0 {
		if len(b.chunks) == 0 || b.chunks[len(b.chunks)-1].end == cap(b.chunks[len(b.chunks)-1].storage) {
			capacity := len(payload)
			if len(b.chunks) == 0 && capacity < tcpSendChunkMinimum {
				if capacity < tcpSendChunkInitial {
					capacity = tcpSendChunkInitial
				}
			} else if capacity < tcpSendChunkMinimum {
				capacity = tcpSendChunkMinimum
			} else if capacity > tcpSendChunkMaximum {
				capacity = tcpSendChunkMaximum
			}
			var storage []byte
			// A small retained first chunk cannot be inserted behind a live
			// chunk: doing so would violate the scatter bound used by view.
			if b.spare != nil && (len(b.chunks) == 0 || cap(b.spare) >= tcpSendChunkMinimum) {
				storage = b.spare
				b.spare = nil
			}
			if cap(storage) == 0 {
				storage = make([]byte, capacity)
				if capacity > tcpSendChunkInitial && capacity <= tcpReusableSendChunkLimit && b.reusableState == tcpSendReusableReleased {
					b.reusableState = tcpSendReusableConfirmed
				}
			} else {
				storage = storage[:cap(storage)]
			}
			b.chunks = append(b.chunks, tcpSendChunk{storage: storage, streamStart: b.end})
		}
		chunk := &b.chunks[len(b.chunks)-1]
		written := copy(chunk.storage[chunk.end:], payload)
		chunk.end += written
		b.end += uint64(written)
		b.size += written
		payload = payload[written:]
	}
}

// view fills caller-owned slice headers for up to maximum bytes at offset.
// Chunk storage remains immutable until the connection actor cumulatively
// acknowledges the corresponding sequence range.
func (b *tcpSendBuffer) view(offset, maximum int, result *tcpPayloadView) int {
	*result = tcpPayloadView{}
	total := b.size
	if offset < 0 || offset >= total || maximum <= 0 {
		return total
	}
	wanted := maximum
	if available := total - offset; wanted > available {
		wanted = available
	}
	target := b.base + uint64(offset)
	low, high := 0, len(b.chunks)
	for low < high {
		middle := int(uint(low+high) >> 1)
		chunk := &b.chunks[middle]
		if chunk.streamStart+uint64(chunk.end-chunk.start) <= target {
			low = middle + 1
		} else {
			high = middle
		}
	}
	remaining := wanted
	for index := low; index < len(b.chunks) && remaining != 0; index++ {
		chunk := &b.chunks[index]
		start := chunk.start
		if index == low {
			start += int(target - chunk.streamStart)
		}
		size := chunk.end - start
		if size > remaining {
			size = remaining
		}
		if size == 0 {
			continue
		}
		if result.count == len(result.chunks) {
			panic("mipstack: TCP payload spans too many send chunks")
		}
		result.chunks[result.count] = chunk.storage[start : start+size : start+size]
		result.count++
		result.size += size
		remaining -= size
	}
	return total
}

// acknowledge removes a cumulatively acknowledged prefix. Retransmission
// metadata stores sequence ranges rather than payload slices, so released
// storage can become reusable immediately.
func (b *tcpSendBuffer) acknowledge(size int) {
	if size > b.size {
		size = b.size
	}
	if size <= 0 {
		return
	}
	b.base += uint64(size)
	b.size -= size
	remaining := size
	for remaining != 0 && len(b.chunks) != 0 {
		chunk := &b.chunks[0]
		available := chunk.end - chunk.start
		if remaining < available {
			chunk.start += remaining
			chunk.streamStart += uint64(remaining)
			remaining = 0
			break
		}
		remaining -= available
		capacity := cap(chunk.storage)
		if capacity <= tcpSendChunkInitial || capacity <= tcpReusableSendChunkLimit && b.reusableState == tcpSendReusableConfirmed {
			if capacity > cap(b.spare) {
				b.spare = chunk.storage[:0]
			}
		} else if capacity <= tcpReusableSendChunkLimit && b.reusableState == tcpSendReusableUnseen {
			// A single moderate write must not permanently raise idle memory.
			// Remember its release without retaining the backing; allocating a
			// second moderate chunk confirms that reuse is worthwhile.
			b.reusableState = tcpSendReusableReleased
		}
		b.chunks[0] = tcpSendChunk{}
		b.chunks = b.chunks[1:]
	}
	if len(b.chunks) == 0 {
		b.chunks = nil
		b.base, b.end = 0, 0
	}
}

// clear releases application data and any retained empty storage.
func (b *tcpSendBuffer) clear() { *b = tcpSendBuffer{} }

// tcpPendingEvents groups queues that most TCP connections never need.
type tcpPendingEvents struct {
	// networkErrors is bounded by tcpMaximumPendingNetworkErrors and retains its
	// backing after first use so repeated ICMP feedback does not reallocate.
	networkErrors []error
	// infoRequests is detached as one actor batch; later callers append to a new
	// slice and publish another wake.
	infoRequests []chan TCPConnInfo
}

// TCPConn is an active userspace TCP connection.
type TCPConn struct {
	stack *Stack
	key   tcpKey
	mtu   int
	net   string

	inbound        tcpSegmentQueue
	actorWakeFlags atomic.Uint32
	abortCh        chan struct{}
	done           chan struct{}
	// lingerDone remains nil unless a positive-linger Close must block.
	lingerDone        chan struct{}
	abortOnce         sync.Once
	closeOnce         sync.Once
	readCallMu        sync.Mutex
	writeCallMu       sync.Mutex
	icmpSequence      atomic.Uint64
	applicationReads  atomic.Uint64
	outOfOrderUnread  atomic.Int64
	retransmissions   atomic.Uint64
	inboundQueueDrops atomic.Uint64
	lastInfo          atomic.Pointer[TCPConnInfo]
	sendCapacityHint  atomic.Int64

	abortMu  sync.Mutex
	abortErr error

	mu          sync.Mutex
	readBuffer  tcpReadBuffer
	readErr     error
	terminalErr error
	// pending remains nil until asynchronous errors or live Info callers need
	// actor delivery.
	pending       *tcpPendingEvents
	readDeadline  socketDeadline
	writeDeadline socketDeadline
	// readNotify and sendChanged are allocated only when an operation first
	// blocks after checking its condition while mu is held.
	readNotify        chan struct{}
	sendChanged       chan struct{}
	sendBuffer        tcpSendBuffer
	receiveCapacity   int
	sendCapacity      int
	receiveMaximum    int
	sendMaximum       int
	keepAliveConfig   KeepAliveConfig
	idleTimeout       time.Duration
	userTimeout       time.Duration
	congestionFactory *CongestionControlFactory
	maximumPacingRate uint64
	outputFlowID      uint64
	trafficClass      atomic.Uint32
	flowLabel         uint32
	linger            int

	// Handshake results are passed to established by the same actor goroutine.
	peerMSS         int
	recentTimestamp uint32
	receiveNext     uint32
	peerWindow      uint32
	peerWindowSeq   uint32
	peerWindowACK   uint32
	handshakeRTT    time.Duration

	// Group single-byte state to avoid alignment holes without adding bitset
	// operations to synchronization and packet-processing paths.
	// passive is set before registration for connections created by a
	// listener. The inherited reuseAddress and reusePort policies decide
	// whether such a connection permits rebinding after its listener closes.
	passive bool
	// reuseAddress is inherited from the listener that created a passive
	// connection. It controls whether a later listener may overlap the retained
	// established or TIME_WAIT tuple after the original listener closes.
	reuseAddress bool
	// reusePort is inherited independently so a SO_REUSEPORT-only listener may
	// be replaced while one of its accepted connections remains active.
	reusePort bool
	// forwarded authorizes this connection to retain an intercepted nonlocal
	// destination as its local endpoint while promiscuous admission remains
	// enabled.
	forwarded bool
	// abortRST is protected by abortMu and consumed by takeAbortReset.
	abortRST                                 bool
	userClosed, readClosed, writeClosed      bool
	receiveAutoTune, sendAutoTune, keepAlive bool
	noDelay, congestionUser                  bool
	receiveWindowScale, peerWindowScale      uint8
	// lingerComplete records acknowledgement even when no waiter channel was
	// needed, preventing a later Close from waiting for an event already seen.
	lingerComplete                            bool
	peerWindowScaling                         bool
	peerSACK, peerTimestamp, peerECN          bool
	echoCongestion, sendCWR, handshakeTimeout bool
}

// tcpListenKey identifies one specific or wildcard passive TCP endpoint.
type tcpListenKey struct {
	address netip.Addr
	port    uint16
}

// tcpPassiveEndpoints is the small data-plane surface retained by Stack.
// Its implementation is created only when an application uses TCP listeners,
// allowing listener-only protocol code to be removed from dial-only binaries.
type tcpPassiveEndpoints interface {
	// portListened reports whether passive dispatch owns the local port.
	portListened(local netip.Addr, port uint16) bool
	// handleSegment dispatches one segment to a listener or SYN-cookie path.
	handleSegment(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error)
	// updateConfig closes listeners invalidated by new network policy.
	updateConfig(stack *Stack, network *networkState)
	// closeAll closes every listener retained by the dispatcher.
	closeAll()
}

// tcpReuseEndpoints is implemented by the optional REUSEPORT registry. It is
// deliberately reached through an interface so ordinary listeners do not
// retain group selection and hashing code.
type tcpReuseEndpoints interface {
	// empty reports whether the registry contains no listeners.
	empty() bool
	// listeners returns a snapshot of all registered listeners.
	listeners() []*TCPListener
	// overlaps reports whether a binding conflicts with any registry entry.
	overlaps(address netip.Addr, port uint16, dual bool) bool
	// listener selects a listener for one local and remote endpoint pair.
	listener(binding, local, remote netip.AddrPort) *TCPListener
	// add registers a listener in its reuse-port group.
	add(listener *TCPListener)
	// remove unregisters a listener and reports whether it was present.
	remove(listener *TCPListener) bool
}

// tcpPassiveState owns exclusive listeners and an optional REUSEPORT
// registry. Stack.mu protects endpoint registries; cookieMu protects the
// cookie key and recent-issuance period.
type tcpPassiveState struct {
	exclusive           map[tcpListenKey]*TCPListener
	reuse               tcpReuseEndpoints
	cookieMu            sync.Mutex
	cookieKey           [16]byte
	cookieSet           bool
	cookieEpoch         time.Time
	cookiePeriod        uint64
	cookieActive        bool
	cookieScaleSet      bool
	cookieScalePeriod   uint64
	cookieWindowScale   uint8
	previousScaleSet    bool
	previousScalePeriod uint64
	previousWindowScale uint8
}

// tcpListenerBinding supplies only the registration policy that differs
// between ordinary and REUSEPORT listeners; validation and construction stay
// in one shared Listen implementation.
type tcpListenerBinding interface {
	// available reports whether the requested listener binding can be registered.
	available(state *tcpPassiveState, address netip.Addr, port uint16, dual bool) bool
	// register publishes one validated listener binding.
	register(state *tcpPassiveState, listener *TCPListener) error
	// connectionReusable reports whether this binding and an existing
	// connection share a Linux address- or port-reuse policy.
	connectionReusable(*TCPConn) bool
}

// exclusiveTCPListenerBinding is the default one-listener bind policy.
type exclusiveTCPListenerBinding struct {
	reuseAddress bool
}

// TCPListenerInfo is a point-in-time diagnostic snapshot of one passive TCP
// endpoint. Queue peaks and counters cover the listener's complete lifetime.
type TCPListenerInfo struct {
	// LocalAddress is the bound listener endpoint.
	LocalAddress netip.AddrPort
	// Closed reports whether the listener was closed when sampled.
	Closed bool
	// AcceptQueueConnections is the number of completed connections awaiting Accept.
	AcceptQueueConnections int
	// AcceptQueueCapacity is the completed-connection queue limit.
	AcceptQueueCapacity int
	// AcceptQueuePeak is the lifetime peak completed-connection queue depth.
	AcceptQueuePeak int
	// SYNBacklogConnections is the number of stateful handshakes in progress.
	SYNBacklogConnections int
	// SYNBacklogCapacity is the stateful handshake limit.
	SYNBacklogCapacity int
	// SYNBacklogPeak is the lifetime peak number of stateful handshakes.
	SYNBacklogPeak int
	// SYNsReceived counts valid initial SYN segments dispatched to the listener.
	SYNsReceived uint64
	// StatefulHandshakes counts connection states allocated for initial SYNs.
	StatefulHandshakes uint64
	// HandshakeCompletions counts passive handshakes that reached the accept queue.
	HandshakeCompletions uint64
	// HandshakeFailures counts stateful passive handshakes that did not complete.
	HandshakeFailures uint64
	// HandshakeTimeouts counts stateful passive handshakes that timed out.
	HandshakeTimeouts uint64
	// SYNCookiesSent counts stateless SYN-cookie responses.
	SYNCookiesSent uint64
	// SYNCookiesAccepted counts valid cookie acknowledgements.
	SYNCookiesAccepted uint64
	// SYNCookiesRejected counts invalid or stale cookie acknowledgements.
	SYNCookiesRejected uint64
	// AcceptQueueDrops counts completed handshakes rejected by a full accept queue.
	AcceptQueueDrops uint64
	// AcceptedConnections counts connections returned successfully by Accept.
	AcceptedConnections uint64
}

// TCPListener is a passive userspace TCP endpoint.
type TCPListener struct {
	stack        *Stack
	key          tcpListenKey
	local        netip.AddrPort
	dual         bool
	net          string
	options      tcpSocketOptionSet
	reuseAddress bool
	reusePort    bool

	accept         chan *TCPConn
	closed         chan struct{}
	once           sync.Once
	backlog        int
	acceptCapacity int

	mu          sync.Mutex
	deadline    socketDeadline
	pending     map[*TCPConn]struct{}
	handshaking map[*TCPConn]struct{}
	acceptPeak  int
	backlogPeak int

	synsReceived         atomic.Uint64
	statefulHandshakes   atomic.Uint64
	handshakeCompletions atomic.Uint64
	handshakeFailures    atomic.Uint64
	handshakeTimeouts    atomic.Uint64
	synCookiesSent       atomic.Uint64
	synCookiesAccepted   atomic.Uint64
	synCookiesRejected   atomic.Uint64
	acceptQueueDrops     atomic.Uint64
	acceptedConnections  atomic.Uint64
}

// ListenTCP creates a passive TCP endpoint. Network must be tcp, tcp4, or
// tcp6. A wildcard with tcp uses one dual-stack endpoint when both families
// are configured. Port zero selects an automatic port.
func (s *Stack) ListenTCP(ctx context.Context, network string, local netip.AddrPort) (*TCPListener, error) {
	return s.listenTCP(ctx, network, local, exclusiveTCPListenerBinding{reuseAddress: true}, tcpSocketOptionSet{})
}

// listenTCP contains validation, automatic port allocation, and listener
// construction shared by the ordinary and optional REUSEPORT entry points.
func (s *Stack) listenTCP(ctx context.Context, network string, local netip.AddrPort, binding tcpListenerBinding, options tcpSocketOptionSet) (*TCPListener, error) {
	address := local.Addr().Unmap()
	local = netip.AddrPortFrom(address, local.Port())
	target := net.TCPAddrFromAddrPort(local)
	wrap := func(err error) (*TCPListener, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	if err := validateListenNetwork(network, "tcp", address); err != nil {
		return wrap(err)
	}
	if address.IsValid() && (address.IsMulticast() || address.Zone() != "") {
		return wrap(errors.New("mipstack: invalid TCP listen address"))
	}
	if address.IsValid() && !address.IsUnspecified() && !s.isLocal(address) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	if err := ctx.Err(); err != nil {
		return wrap(err)
	}
	if err := s.ready(); err != nil {
		return wrap(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wrap(ErrClosed)
	}
	state := s.network.Load()
	address, dual, err := listenAddress(state, network, "tcp", address)
	if err != nil {
		return wrap(err)
	}
	if err = (socketOptionSet{tcp: options}).validateFamily(socketOptionTCPListen, address.Is6(), dual); err != nil {
		return wrap(err)
	}
	if !address.IsUnspecified() && !networkStateHasLocal(state, address) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	local = netip.AddrPortFrom(address, local.Port())
	passive := s.tcpPassiveStateLocked()
	defer func() {
		if passive.empty() && s.tcpPassive == passive {
			s.tcpPassive = nil
		}
	}()
	port := local.Port()
	if port == 0 {
		port, err = s.allocateTCPListenPortLocked(passive, address, dual)
		if err != nil {
			return wrap(err)
		}
	} else if !s.tcpListenEndpointAvailableLocked(passive, binding, address, port, dual) {
		return wrap(syscall.EADDRINUSE)
	}
	local = netip.AddrPortFrom(address, port)
	key := tcpListenKey{address: address, port: port}
	acceptCapacity := state.tcpDefaults.AcceptQueue
	if options.acceptQueue.set {
		acceptCapacity = options.acceptQueue.value
	}
	backlog := state.tcpDefaults.SYNBacklog
	if options.synBacklog.set {
		backlog = options.synBacklog.value
	}
	listener := &TCPListener{
		stack: s, key: key, local: local, dual: dual, net: network, options: options, accept: make(chan *TCPConn, acceptCapacity), backlog: backlog,
		acceptCapacity: acceptCapacity,
		closed:         make(chan struct{}), pending: make(map[*TCPConn]struct{}), handshaking: make(map[*TCPConn]struct{}),
	}
	if err = binding.register(passive, listener); err != nil {
		return wrap(err)
	}
	s.stats.activeTCPListeners.Add(1)
	return listener, nil
}

// tcpPassiveStateLocked returns the lazily allocated passive dispatcher while
// Stack.mu is held.
func (s *Stack) tcpPassiveStateLocked() *tcpPassiveState {
	if s.tcpPassive == nil {
		state := &tcpPassiveState{exclusive: make(map[tcpListenKey]*TCPListener)}
		s.tcpPassive = state
		return state
	}
	return s.tcpPassive.(*tcpPassiveState)
}

// allocateTCPListenPortLocked selects an unused passive endpoint while s.mu
// is held.
func (s *Stack) allocateTCPListenPortLocked(state *tcpPassiveState, address netip.Addr, dual bool) (uint16, error) {
	index := 0
	if address.Is6() {
		index = 1
	}
	return allocateAutomaticPort(&s.nextPort[index], func(port uint16) bool {
		// Like bind(2) with port zero, automatic allocation selects an unused
		// endpoint even when the eventual listener requested a reuse option.
		return s.tcpListenEndpointAvailableLocked(state, exclusiveTCPListenerBinding{}, address, port, dual)
	})
}

// tcpListenEndpointAvailableLocked reports whether binding address and port
// would conflict with a listener or active local endpoint while s.mu is held.
func (s *Stack) tcpListenEndpointAvailableLocked(state *tcpPassiveState, binding tcpListenerBinding, address netip.Addr, port uint16, dual bool) bool {
	if !binding.available(state, address, port, dual) {
		return false
	}
	for key, connection := range s.tcp {
		local := key.local
		if local.Port() == port && listenAddressesOverlap(local.Addr(), false, address, dual) {
			if !binding.connectionReusable(connection) {
				return false
			}
		}
	}
	return true
}

// available implements exclusive listener binding.
func (exclusiveTCPListenerBinding) available(state *tcpPassiveState, address netip.Addr, port uint16, dual bool) bool {
	return !state.overlaps(address, port, dual)
}

// register adds one exclusive listener while Stack.mu is held.
func (binding exclusiveTCPListenerBinding) register(state *tcpPassiveState, listener *TCPListener) error {
	listener.reuseAddress = binding.reuseAddress
	state.exclusive[listener.key] = listener
	return nil
}

// connectionReusable implements tcpListenerBinding.
func (binding exclusiveTCPListenerBinding) connectionReusable(connection *TCPConn) bool {
	return binding.reuseAddress && connection.reuseAddress
}

// empty reports whether the passive dispatcher has no listeners.
func (state *tcpPassiveState) empty() bool {
	return len(state.exclusive) == 0 && (state.reuse == nil || state.reuse.empty())
}

// listeners returns a snapshot while Stack.mu is held.
func (state *tcpPassiveState) listeners() []*TCPListener {
	listeners := make([]*TCPListener, 0, len(state.exclusive))
	for _, listener := range state.exclusive {
		listeners = append(listeners, listener)
	}
	if state.reuse != nil {
		listeners = append(listeners, state.reuse.listeners()...)
	}
	return listeners
}

// updateConfig closes listeners whose local binding no longer exists.
func (state *tcpPassiveState) updateConfig(stack *Stack, network *networkState) {
	stack.mu.RLock()
	if stack.tcpPassive != state {
		stack.mu.RUnlock()
		return
	}
	listeners := state.listeners()
	stack.mu.RUnlock()
	for _, listener := range listeners {
		address := listener.local.Addr()
		if listener.dual && !networkStateHasFamily(network, false) && !networkStateHasFamily(network, true) ||
			!listener.dual && address.IsUnspecified() && !networkStateHasFamily(network, address.Is6()) ||
			!address.IsUnspecified() && !networkStateHasLocal(network, address) {
			stack.closeTCPListener(listener)
		}
	}
}

// closeAll publishes stack closure to a detached passive dispatcher.
func (state *tcpPassiveState) closeAll() {
	for _, listener := range state.listeners() {
		listener.closeFromStack()
	}
}

// overlaps reports whether any passive binding covers an address and port.
func (state *tcpPassiveState) overlaps(address netip.Addr, port uint16, dual bool) bool {
	for key, listener := range state.exclusive {
		if key.port == port && listenAddressesOverlap(key.address, listener.dual, address, dual) {
			return true
		}
	}
	return state.reuse != nil && state.reuse.overlaps(address, port, dual)
}

// listener selects an exact binding before a family wildcard and a dual-stack
// wildcard. REUSEPORT groups apply their stable flow selection at each level.
func (state *tcpPassiveState) listener(local, remote netip.AddrPort) *TCPListener {
	if listener := state.exclusive[tcpListenKey{address: local.Addr(), port: local.Port()}]; listener != nil {
		return listener
	}
	if state.reuse != nil {
		if listener := state.reuse.listener(local, local, remote); listener != nil {
			return listener
		}
	}
	wildcard := netip.IPv4Unspecified()
	if local.Addr().Is6() {
		wildcard = netip.IPv6Unspecified()
	}
	wildcardLocal := netip.AddrPortFrom(wildcard, local.Port())
	if listener := state.exclusive[tcpListenKey{address: wildcard, port: local.Port()}]; listener != nil {
		return listener
	}
	if state.reuse != nil {
		if listener := state.reuse.listener(wildcardLocal, local, remote); listener != nil {
			return listener
		}
	}
	if local.Addr().Is4() {
		dualLocal := netip.AddrPortFrom(netip.IPv6Unspecified(), local.Port())
		if listener := state.exclusive[tcpListenKey{address: dualLocal.Addr(), port: local.Port()}]; listener != nil && listener.dual {
			return listener
		}
		if state.reuse != nil {
			if listener := state.reuse.listener(dualLocal, local, remote); listener != nil && listener.dual {
				return listener
			}
		}
	}
	return nil
}

// portListened implements the passive-endpoint query without exposing the
// listener registry to dial-only builds.
func (state *tcpPassiveState) portListened(local netip.Addr, port uint16) bool {
	return state.overlaps(local, port, false)
}

// remove unregisters a listener while Stack.mu is held.
func (state *tcpPassiveState) remove(listener *TCPListener) bool {
	if state.exclusive[listener.key] == listener {
		delete(state.exclusive, listener.key)
		return true
	}
	if state.reuse != nil && state.reuse.remove(listener) {
		if state.reuse.empty() {
			state.reuse = nil
		}
		return true
	}
	return false
}

// Accept waits for and returns the next completed passive connection.
func (l *TCPListener) Accept() (net.Conn, error) {
	connection, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	return connection, nil
}

// AcceptTCP waits for and returns the next completed passive connection.
func (l *TCPListener) AcceptTCP() (*TCPConn, error) {
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		return nil, l.operationError("accept", net.ErrClosed)
	default:
	}
	timeout := l.deadline.wait()
	select {
	case <-timeout:
		l.mu.Unlock()
		return nil, l.operationError("accept", os.ErrDeadlineExceeded)
	default:
	}
	l.mu.Unlock()
	select {
	case connection := <-l.accept:
		l.mu.Lock()
		select {
		case <-l.closed:
			l.mu.Unlock()
			return nil, l.operationError("accept", net.ErrClosed)
		default:
		}
		delete(l.pending, connection)
		l.mu.Unlock()
		l.acceptedConnections.Add(1)
		return connection, nil
	case <-timeout:
		return nil, l.operationError("accept", os.ErrDeadlineExceeded)
	case <-l.closed:
		return nil, l.operationError("accept", net.ErrClosed)
	}
}

// Close stops listening without closing connections already returned by
// Accept.
func (l *TCPListener) Close() error {
	if l.stack.closeTCPListener(l) {
		return nil
	}
	return l.operationError("close", net.ErrClosed)
}

// Addr returns the bound TCP endpoint.
func (l *TCPListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.local) }

// Info returns queue pressure, handshake outcomes, and SYN-cookie activity for
// this listener. The final snapshot remains available after Close.
func (l *TCPListener) Info() TCPListenerInfo {
	l.mu.Lock()
	info := TCPListenerInfo{
		LocalAddress:           l.local,
		AcceptQueueConnections: len(l.accept), AcceptQueueCapacity: l.acceptCapacity, AcceptQueuePeak: l.acceptPeak,
		SYNBacklogConnections: len(l.handshaking), SYNBacklogCapacity: l.backlog, SYNBacklogPeak: l.backlogPeak,
	}
	select {
	case <-l.closed:
		info.Closed = true
	default:
	}
	l.mu.Unlock()
	info.SYNsReceived = l.synsReceived.Load()
	info.StatefulHandshakes = l.statefulHandshakes.Load()
	info.HandshakeCompletions = l.handshakeCompletions.Load()
	info.HandshakeFailures = l.handshakeFailures.Load()
	info.HandshakeTimeouts = l.handshakeTimeouts.Load()
	info.SYNCookiesSent = l.synCookiesSent.Load()
	info.SYNCookiesAccepted = l.synCookiesAccepted.Load()
	info.SYNCookiesRejected = l.synCookiesRejected.Load()
	info.AcceptQueueDrops = l.acceptQueueDrops.Load()
	info.AcceptedConnections = l.acceptedConnections.Load()
	return info
}

// SetDeadline sets the deadline for subsequent Accept calls.
func (l *TCPListener) SetDeadline(deadline time.Time) error {
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		return l.operationError("set", net.ErrClosed)
	default:
	}
	l.deadline.set(deadline)
	l.mu.Unlock()
	return nil
}

// operationError wraps a listener failure in the standard net.OpError shape.
func (l *TCPListener) operationError(operation string, err error) error {
	return socketOperationError(operation, l.net, nil, l.Addr(), err)
}

// trackHandshake reserves one listener SYN-backlog entry for connection.
func (l *TCPListener) trackHandshake(connection *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	if len(l.handshaking) >= l.backlog {
		return false
	}
	l.pending[connection] = struct{}{}
	l.handshaking[connection] = struct{}{}
	if len(l.handshaking) > l.backlogPeak {
		l.backlogPeak = len(l.handshaking)
	}
	return true
}

// trackCompleted retains a completed SYN-cookie connection until Accept
// returns it. It deliberately does not consult or occupy the SYN backlog.
func (l *TCPListener) trackCompleted(connection *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
		l.pending[connection] = struct{}{}
		return true
	}
}

// removePending releases a failed handshake from the listener backlog.
func (l *TCPListener) removePending(connection *TCPConn) {
	l.mu.Lock()
	delete(l.pending, connection)
	delete(l.handshaking, connection)
	l.mu.Unlock()
}

// enqueue publishes one completed passive handshake to Accept.
func (l *TCPListener) enqueue(connection *TCPConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.handshaking, connection)
	select {
	case <-l.closed:
		return false
	default:
	}
	select {
	case l.accept <- connection:
		l.handshakeCompletions.Add(1)
		if len(l.accept) > l.acceptPeak {
			l.acceptPeak = len(l.accept)
		}
		return true
	default:
		l.acceptQueueDrops.Add(1)
		l.stack.stats.tcpAcceptQueueDrops.Add(1)
		return false
	}
}

// noteHandshakeFailure classifies a failed stateful passive open.
func (l *TCPListener) noteHandshakeFailure(err error) {
	l.handshakeFailures.Add(1)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		l.handshakeTimeouts.Add(1)
		l.stack.stats.tcpHandshakeTimeouts.Add(1)
	}
}

// closeFromStack publishes listener closure, releases accept storage, and
// aborts connections not yet returned by Accept.
func (l *TCPListener) closeFromStack() {
	l.once.Do(func() {
		l.mu.Lock()
		l.deadline.stop()
		close(l.closed)
		pending := make([]*TCPConn, 0, len(l.pending))
		for connection := range l.pending {
			pending = append(pending, connection)
		}
		l.accept = nil
		l.pending = nil
		l.handshaking = nil
		l.mu.Unlock()
		for _, connection := range pending {
			connection.abort(net.ErrClosed)
		}
	})
}

// Verify that TCPListener implements net.Listener.
var _ net.Listener = (*TCPListener)(nil)

// DialTCP establishes an active IPv4 or IPv6 TCP connection. Network must be
// tcp, tcp4, or tcp6. A zero source selects both address and port
// automatically; an unspecified source address selects only the address.
func (s *Stack) DialTCP(ctx context.Context, network string, source, remote netip.AddrPort) (net.Conn, error) {
	return s.dialTCP(ctx, network, source, remote, tcpSocketOptionSet{})
}

// dialTCP contains active connection construction shared by Stack and Dialer.
func (s *Stack) dialTCP(ctx context.Context, network string, source, remote netip.AddrPort, options tcpSocketOptionSet) (net.Conn, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	target := net.TCPAddrFromAddrPort(remote)
	wrap := func(source net.Addr, err error) (net.Conn, error) {
		return nil, socketOperationError("dial", network, source, target, err)
	}
	if err := validateTransportNetwork(network, "tcp", remote.Addr()); err != nil {
		return wrap(nil, err)
	}
	if !remote.IsValid() || remote.Addr().IsUnspecified() || remote.Addr().IsMulticast() || remote.Addr().Zone() != "" {
		return wrap(nil, errors.New("mipstack: invalid TCP destination"))
	}
	if err := (socketOptionSet{tcp: options}).validateFamily(socketOptionTCPDial, remote.Addr().Is6(), false); err != nil {
		return wrap(nil, err)
	}
	if s.network.Load().broadcastDestination(remote.Addr()) {
		return wrap(nil, syscall.EACCES)
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	if err := s.ready(); err != nil {
		return wrap(nil, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return wrap(nil, ErrClosed)
	}
	local, err := s.localEndpointFor(network, remote, source)
	if err != nil {
		s.mu.Unlock()
		return wrap(nil, err)
	}
	localAddress := local.Addr()
	localNetAddress := net.TCPAddrFromAddrPort(local)
	connectionMTU := s.mtuFor(remote.Addr())
	if !s.tcpConnectionAvailableLocked() {
		s.mu.Unlock()
		return wrap(localNetAddress, ErrResourceLimit)
	}
	port := local.Port()
	if port == 0 {
		port, err = s.allocateTCPPortLocked(localAddress, remote)
		if err != nil {
			s.mu.Unlock()
			return wrap(localNetAddress, err)
		}
	} else {
		key := tcpKey{local: netip.AddrPortFrom(localAddress, port), remote: remote}
		if s.tcpPortListenedLocked(localAddress, port) {
			s.mu.Unlock()
			return wrap(localNetAddress, syscall.EADDRINUSE)
		}
		if _, exists := s.tcp[key]; exists {
			s.mu.Unlock()
			return wrap(localNetAddress, syscall.EADDRINUSE)
		}
	}
	key := tcpKey{local: netip.AddrPortFrom(localAddress.Unmap(), port), remote: remote}
	initialSequence := s.tcpInitialSequence(key, time.Now())
	connection := newTCPConn(s, network, key, connectionMTU, options)
	connected := make(chan error, 1)
	connection.publishICMPSequenceRange(initialSequence, initialSequence+1)
	s.tcp[key] = connection
	s.stats.activeTCPConnections.Add(1)
	s.mu.Unlock()
	go connection.run(initialSequence, connected)
	select {
	case err = <-connected:
		if err != nil {
			return wrap(connection.LocalAddr(), err)
		}
		return connection, nil
	case <-ctx.Done():
		connection.abort(ctx.Err())
		return wrap(connection.LocalAddr(), ctx.Err())
	}
}

// newTCPConn allocates connection state after applying explicit creation
// policies to the latest Stack defaults.
func newTCPConn(stack *Stack, network string, key tcpKey, mtu int, options tcpSocketOptionSet) *TCPConn {
	defaults, _ := normalizeTCPSocketDefaults(TCPSocketDefaults{})
	if stack != nil {
		state := stack.network.Load()
		defaults = state.tcpDefaults
	}
	defaults = applyTCPSocketOptions(defaults, options)
	connection := &TCPConn{
		stack: stack, net: network, key: key, mtu: mtu,
		inbound: newTCPSegmentQueue(),
		abortCh: make(chan struct{}), done: make(chan struct{}),
		noDelay: !defaults.DisableNoDelay, linger: -1,
		receiveCapacity: defaults.ReceiveBuffer, sendCapacity: defaults.SendBuffer,
		receiveMaximum: defaults.MaximumReceiveBuffer, sendMaximum: defaults.MaximumSendBuffer,
		receiveAutoTune: defaults.MaximumReceiveBuffer > defaults.ReceiveBuffer,
		sendAutoTune:    defaults.MaximumSendBuffer > defaults.SendBuffer,
		keepAlive:       defaults.KeepAlive, keepAliveConfig: defaults.KeepAliveConfig,
		idleTimeout: defaults.IdleTimeout, userTimeout: defaults.UserTimeout,
		congestionFactory:  defaults.CongestionControlFactory,
		congestionUser:     options.congestionControl.set,
		maximumPacingRate:  defaults.MaximumPacingRate,
		receiveWindowScale: tcpReceiveWindowScaleFor(defaults.MaximumReceiveBuffer),
	}
	if stack != nil {
		connection.outputFlowID = stack.nextOutputFlow.Add(1)
	}
	if key.local.Addr().Is6() {
		if options.flowLabel.set {
			connection.flowLabel = options.flowLabel.value
		} else {
			connection.flowLabel = defaults.FlowLabel
		}
		if connection.flowLabel == 0 && !options.flowLabel.set && stack != nil {
			connection.flowLabel = stack.automaticTransportFlowLabel(key.local.Addr(), key.remote.Addr(), ProtocolTCP, key.local.Port(), key.remote.Port())
		}
	}
	connection.trafficClass.Store(uint32(defaults.TrafficClass))
	connection.sendCapacityHint.Store(int64(defaults.SendBuffer))
	return connection
}

// applyTCPSocketOptions overlays explicit creation policies on normalized
// Stack defaults. Buffer overrides also fix the auto-tuning maximum so the
// connection starts with the same semantics as SetReadBuffer or SetWriteBuffer.
func applyTCPSocketOptions(defaults TCPSocketDefaults, options tcpSocketOptionSet) TCPSocketDefaults {
	if options.readBuffer.set {
		defaults.ReceiveBuffer = options.readBuffer.value
		defaults.MaximumReceiveBuffer = options.readBuffer.value
	}
	if options.writeBuffer.set {
		defaults.SendBuffer = options.writeBuffer.value
		defaults.MaximumSendBuffer = options.writeBuffer.value
	}
	if options.keepAlive != socketOptionBoolOverrideUnset {
		defaults.KeepAlive = options.keepAlive == socketOptionBoolOverrideEnabled
	}
	if options.keepAliveConfig.set {
		defaults.KeepAliveConfig = options.keepAliveConfig.value
	}
	if options.noDelay != socketOptionBoolOverrideUnset {
		defaults.DisableNoDelay = options.noDelay == socketOptionBoolOverrideDisabled
	}
	if options.idleTimeout.set {
		defaults.IdleTimeout = options.idleTimeout.value
	}
	if options.userTimeout.set {
		defaults.UserTimeout = options.userTimeout.value
	}
	if options.congestionControl.set {
		defaults.CongestionControlFactory = options.congestionControl.value
	}
	if options.maximumPacingRate.set {
		defaults.MaximumPacingRate = options.maximumPacingRate.value
	}
	if options.trafficClass.set {
		defaults.TrafficClass = uint8(options.trafficClass.value) & 0xfc
	}
	if options.flowLabel.set {
		defaults.FlowLabel = options.flowLabel.value
	}
	return defaults
}

// tcpTimestamp returns a wrapping millisecond clock suitable for TSval.
func (s *Stack) tcpTimestamp() uint32 {
	return s.tcpTimestampAt(time.Now())
}

// tcpTimestampAt converts one internal monotonic event time to a wire TSval.
func (s *Stack) tcpTimestampAt(now time.Time) uint32 {
	return uint32(now.Sub(s.timestampEpoch)/time.Millisecond) + 1
}

// tcpInitialSequence implements RFC 6528's M+F(connection-id, secret)
// construction. M advances every four microseconds and wraps in sequence
// space; SipHash supplies the keyed pseudorandom per-four-tuple offset.
func (s *Stack) tcpInitialSequence(key tcpKey, now time.Time) uint32 {
	var connectionID [37]byte
	if key.local.Addr().Is6() {
		connectionID[0] = 6
	} else {
		connectionID[0] = 4
	}
	local := key.local.Addr().As16()
	remote := key.remote.Addr().As16()
	copy(connectionID[1:17], local[:])
	copy(connectionID[17:33], remote[:])
	binary.BigEndian.PutUint16(connectionID[33:35], key.local.Port())
	binary.BigEndian.PutUint16(connectionID[35:37], key.remote.Port())
	elapsed := now.Sub(s.timestampEpoch)
	var timer uint32
	if elapsed > 0 {
		timer = uint32(elapsed / (4 * time.Microsecond))
	}
	return timer + uint32(sipHash24(s.tcpISNSecret, connectionID[:]))
}

// handleTCP validates a segment, dispatches it by four-tuple, or emits RST for
// an unbound local destination. Stack packet input uses
// handleTCPForDestination after computing destination ownership once.
func (s *Stack) handleTCP(packet ipPacket, receivedAt time.Time) error {
	return s.handleTCPForDestination(packet, receivedAt, true)
}

// handleTCPForDestination preserves ordinary listener ownership while
// allowing established forwarded tuples to use nonlocal destinations.
func (s *Stack) handleTCPForDestination(packet ipPacket, receivedAt time.Time, localDestination bool) error {
	tcp := packet.payload
	if len(tcp) < tcpHeaderSize || transportChecksum(packet.source, packet.target, ProtocolTCP, tcp) != 0 {
		s.stats.inboundDroppedPackets.Add(1)
		s.stats.tcpInvalidSegments.Add(1)
		return nil
	}
	headerSize, valid := tcpWireHeaderSize(tcp[12], len(tcp))
	if !valid {
		s.stats.inboundDroppedPackets.Add(1)
		s.stats.tcpInvalidSegments.Add(1)
		return nil
	}
	sourcePort := binary.BigEndian.Uint16(tcp[0:2])
	targetPort := binary.BigEndian.Uint16(tcp[2:4])
	segment := tcpSegment{
		sequence: binary.BigEndian.Uint32(tcp[4:8]), acknowledgement: binary.BigEndian.Uint32(tcp[8:12]),
		flags: tcp[13], window: binary.BigEndian.Uint16(tcp[14:16]), ecn: packet.ecn,
		receivedAt: monotonicStampAt(s.timestampEpoch, receivedAt),
	}
	segment.setOptions(tcp[tcpHeaderSize:headerSize])
	payload := tcp[headerSize:]
	key := tcpKey{local: netip.AddrPortFrom(packet.target, targetPort), remote: netip.AddrPortFrom(packet.source, sourcePort)}
	s.mu.RLock()
	connection := s.tcp[key]
	s.mu.RUnlock()
	if connection != nil {
		if !connection.enqueueInboundCopy(segment, payload) {
			s.stats.inboundDroppedPackets.Add(1)
			s.stats.tcpInboundQueueDrops.Add(1)
		}
		return nil
	}
	s.mu.RLock()
	passive, forwarder := s.tcpPassive, s.tcpForwarder
	s.mu.RUnlock()
	if len(payload) != 0 {
		if localDestination && passive != nil || forwarder != nil {
			segment.payload = append([]byte(nil), payload...)
			segment.payload = segment.payload[:len(segment.payload):len(segment.payload)]
		} else {
			// rejectTCPSegment only inspects the payload length synchronously;
			// borrowing the caller-owned packet avoids an otherwise discarded copy.
			segment.payload = payload
		}
	}
	if localDestination && passive != nil {
		handled, err := passive.handleSegment(s, packet, segment, key)
		if handled || err != nil {
			return err
		}
	}
	if forwarder != nil && forwarder.handleSegment(segment, key) {
		return nil
	}
	if !localDestination {
		return nil
	}
	_ = s.rejectTCPSegment(key, segment)
	return nil
}

// rejectTCPSegment emits the RFC 9293 response for one otherwise unhandled
// segment. Incoming resets never elicit another reset.
func (s *Stack) rejectTCPSegment(key tcpKey, segment tcpSegment) error {
	if segment.flags&TCPFlagRST != 0 {
		return nil
	}
	state := s.network.Load()
	if !state.acceptsInboundDestination(key.local.Addr()) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(key.remote.Addr()); !routed {
		return syscall.ENETUNREACH
	}
	if !s.allowControlResponse(controlResponseTCPReset) {
		return nil
	}
	var sequence, acknowledgement uint32
	flags := byte(TCPFlagRST)
	if segment.flags&TCPFlagACK != 0 {
		sequence = segment.acknowledgement
	} else {
		acknowledgement = segment.sequence + uint32(len(segment.payload))
		if segment.flags&TCPFlagSYN != 0 {
			acknowledgement++
		}
		if segment.flags&TCPFlagFIN != 0 {
			acknowledgement++
		}
		flags |= TCPFlagACK
	}
	return s.tryWriteTCP(key.local.Addr(), key.remote.Addr(), key.local.Port(), key.remote.Port(), sequence, acknowledgement, flags, 0, nil, nil, s.mtuFor(key.remote.Addr()), 0, 0, 0, false)
}

// acceptTCP creates and starts one forwarded passive connection after the
// handler has claimed its request.
func (f *TCPForwarder) acceptTCP(request *TCPForwarderRequest, options tcpSocketOptionSet) (*TCPConn, <-chan error, error) {
	stack := f.stack
	stack.mu.Lock()
	if stack.closed {
		stack.mu.Unlock()
		return nil, nil, ErrClosed
	}
	if stack.tcpForwarder != f {
		stack.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	state := stack.network.Load()
	if !state.acceptsInboundDestination(request.key.local.Addr()) {
		stack.mu.Unlock()
		return nil, nil, syscall.EADDRNOTAVAIL
	}
	if _, routed := state.routeFor(request.key.remote.Addr()); !routed {
		stack.mu.Unlock()
		return nil, nil, syscall.ENETUNREACH
	}
	if stack.tcp[request.key] != nil || networkStateHasLocal(state, request.key.local.Addr()) && stack.tcpPortListenedLocked(request.key.local.Addr(), request.key.local.Port()) {
		stack.mu.Unlock()
		return nil, nil, syscall.EADDRINUSE
	}
	if !stack.tcpConnectionAvailableLocked() {
		stack.mu.Unlock()
		return nil, nil, ErrResourceLimit
	}
	network := "tcp4"
	if request.key.local.Addr().Is6() {
		network = "tcp6"
	}
	connection := newTCPConn(stack, network, request.key, stack.mtuFor(request.key.remote.Addr()), options)
	connection.passive = true
	connection.forwarded = true
	initialSequence := stack.tcpInitialSequence(request.key, tcpSegmentEventTime(request.segment, time.Now(), time.Time{}, stack.timestampEpoch))
	connection.publishICMPSequenceRange(initialSequence, initialSequence+1)
	stack.tcp[request.key] = connection
	stack.stats.activeTCPConnections.Add(1)
	stack.mu.Unlock()
	f.remove(request)
	result := make(chan error, 1)
	go connection.runForwardedPassive(request.segment, initialSequence, result)
	return connection, result, nil
}

// tcpConnectionAvailableLocked applies the optional embedding limit while
// s.mu is held. Zero deliberately means that allocation is memory-limited.
func (s *Stack) tcpConnectionAvailableLocked() bool {
	maximum := s.network.Load().maxTCPConnections
	return maximum == 0 || len(s.tcp) < maximum
}

// handleSegment admits a new passive open. Stack.handleTCP calls this through
// tcpPassiveEndpoints, so dial-only binaries do not retain this implementation.
func (state *tcpPassiveState) handleSegment(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error) {
	if key.remote.Port() == 0 {
		return false, nil
	}
	if segment.flags&TCPFlagSYN != 0 && segment.flags&(TCPFlagACK|TCPFlagRST) == 0 {
		return state.handleSYN(stack, packet, segment, key)
	}
	if segment.flags&TCPFlagACK != 0 && segment.flags&(TCPFlagSYN|TCPFlagRST) == 0 {
		return state.handleSYNCookieACK(stack, segment, key)
	}
	return false, nil
}

// handleSYN allocates the ordinary half-open state when capacity permits and
// falls back to a stateless SYN cookie under pressure.
func (state *tcpPassiveState) handleSYN(stack *Stack, packet ipPacket, segment tcpSegment, key tcpKey) (bool, error) {
	stack.mu.RLock()
	listener := state.listener(key.local, key.remote)
	stack.mu.RUnlock()
	if listener == nil {
		return false, nil
	}
	listener.synsReceived.Add(1)
	stack.mu.Lock()
	if connection := stack.tcp[key]; connection != nil {
		stack.mu.Unlock()
		if !connection.enqueueInbound(segment) {
			stack.stats.inboundDroppedPackets.Add(1)
		}
		return true, nil
	}
	if stack.tcpPassive != state {
		stack.mu.Unlock()
		return false, nil
	}
	listener = state.listener(key.local, key.remote)
	if listener != nil && stack.tcpConnectionAvailableLocked() {
		initialSequence := stack.tcpInitialSequence(key, tcpSegmentEventTime(segment, time.Now(), time.Time{}, stack.timestampEpoch))
		connection := newTCPConn(stack, listener.net, key, stack.mtuFor(packet.source), listener.options)
		connection.passive = true
		connection.reuseAddress, connection.reusePort = listener.reuseAddress, listener.reusePort
		connection.publishICMPSequenceRange(initialSequence, initialSequence+1)
		if listener.trackHandshake(connection) {
			listener.statefulHandshakes.Add(1)
			stack.tcp[key] = connection
			stack.stats.activeTCPConnections.Add(1)
			stack.mu.Unlock()
			go connection.runPassive(listener, segment, initialSequence)
			return true, nil
		}
	}
	stack.mu.Unlock()
	if listener == nil {
		return false, nil
	}
	err := state.sendSYNCookie(stack, listener, key, segment, tcpSegmentEventTime(segment, time.Now(), time.Time{}, stack.timestampEpoch))
	if err == nil {
		listener.synCookiesSent.Add(1)
		stack.stats.tcpSYNCookiesSent.Add(1)
	} else if errors.Is(err, ErrResourceLimit) {
		return true, nil
	}
	return true, err
}

// handleSYNCookieACK allocates connection state only after authenticating a
// final ACK produced from a stateless SYN-ACK.
func (state *tcpPassiveState) handleSYNCookieACK(stack *Stack, segment tcpSegment, key tcpKey) (bool, error) {
	stack.mu.RLock()
	listener := state.listener(key.local, key.remote)
	stack.mu.RUnlock()
	if listener == nil {
		return false, nil
	}
	initialSequence, options, valid, attempted := state.validateSYNCookieCandidate(key, segment, tcpSegmentEventTime(segment, time.Now(), time.Time{}, stack.timestampEpoch))
	if !valid {
		if attempted {
			listener.synCookiesRejected.Add(1)
			stack.stats.tcpSYNCookiesRejected.Add(1)
		}
		return false, nil
	}
	stack.mu.Lock()
	if connection := stack.tcp[key]; connection != nil {
		stack.mu.Unlock()
		if !connection.enqueueInbound(segment) {
			stack.stats.inboundDroppedPackets.Add(1)
		}
		return true, nil
	}
	if stack.tcpPassive != state {
		stack.mu.Unlock()
		return false, nil
	}
	listener = state.listener(key.local, key.remote)
	if listener == nil {
		stack.mu.Unlock()
		return false, nil
	}
	if !stack.tcpConnectionAvailableLocked() {
		stack.mu.Unlock()
		return true, nil
	}
	connection := newTCPConn(stack, listener.net, key, stack.mtuFor(key.remote.Addr()), listener.options)
	connection.passive = true
	connection.reuseAddress, connection.reusePort = listener.reuseAddress, listener.reusePort
	connection.publishICMPSequenceRange(initialSequence+1, initialSequence+1)
	connection.peerMSS = options.mss
	connection.peerWindowScale = options.windowScale
	connection.peerWindowScaling = options.windowScaling
	connection.peerSACK = options.sack
	connection.peerTimestamp = options.timestamp
	connection.recentTimestamp = options.timestampNow
	connection.peerECN = options.ecn
	connection.receiveNext = segment.sequence
	connection.peerWindow = uint32(segment.window)
	if options.windowScaling {
		connection.peerWindow <<= options.windowScale
	}
	connection.peerWindowSeq = segment.sequence
	connection.peerWindowACK = segment.acknowledgement
	connection.receiveWindowScale = options.localWindowScale
	if !listener.trackCompleted(connection) {
		stack.mu.Unlock()
		return true, nil
	}
	listener.synCookiesAccepted.Add(1)
	stack.stats.tcpSYNCookiesAccepted.Add(1)
	stack.tcp[key] = connection
	stack.stats.activeTCPConnections.Add(1)
	stack.mu.Unlock()
	go connection.runPassiveCookie(listener, segment, initialSequence)
	return true, nil
}

// buildTCPPacket constructs one non-fragmented TCP segment using explicit path
// and IP-header policy.
func buildTCPPacket(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, trafficClass, ecn byte, flowLabel uint32) ([]byte, error) {
	_, _, packetSize, err := tcpPacketLayout(source, target, options, len(payload), mtu)
	if err != nil {
		return nil, err
	}
	return buildTCPPacketInto(make([]byte, packetSize), source, target, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn, flowLabel)
}

// tcpPacketLayout validates option and path bounds and returns exact header
// and complete packet sizes.
func tcpPacketLayout(source, target netip.Addr, options []byte, payloadSize, mtu int) (ipSize, headerSize, packetSize int, err error) {
	headerSize = tcpHeaderSize + (len(options)+3)&^3
	if len(options) > 40 || headerSize > 60 {
		return 0, 0, 0, errors.New("mipstack: invalid TCP options")
	}
	ipSize = ipHeaderSize(source, target, headerSize+payloadSize)
	if ipSize == 0 || ipSize+headerSize+payloadSize > mtu {
		return 0, 0, 0, syscall.EMSGSIZE
	}
	return ipSize, headerSize, ipSize + headerSize + payloadSize, nil
}

// buildTCPPacketInto serializes one validated segment into caller-owned
// storage. The supplied buffer must have the exact layout size.
func buildTCPPacketInto(packet []byte, source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, trafficClass, ecn byte, flowLabel uint32) ([]byte, error) {
	var view tcpPayloadView
	view.setBytes(payload)
	return buildTCPPacketViewInto(packet, source, target, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, &view, mtu, trafficClass, ecn, flowLabel)
}

// buildTCPPacketViewInto serializes one scatter payload into caller-owned
// packet storage without first gathering send-buffer chunks.
func buildTCPPacketViewInto(packet []byte, source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options []byte, payload *tcpPayloadView, mtu int, trafficClass, ecn byte, flowLabel uint32) ([]byte, error) {
	ipSize, headerSize, packetSize, err := tcpPacketLayout(source, target, options, payload.size, mtu)
	if err != nil {
		return nil, err
	}
	if len(packet) != packetSize {
		return nil, errors.New("mipstack: invalid TCP packet buffer size")
	}
	// RFC 6864 makes Identification meaningless on this DF atomic datagram;
	// Linux likewise emits zero instead of consuming the ID sequence reserved
	// for datagrams that routers may actually fragment.
	if !marshalIPHeader(packet, source, target, ProtocolTCP, 0, true, ipPacketOptions{
		trafficClass: trafficClass&0xfc | ecn&3, flowLabel: flowLabel, flowLabelSet: true,
	}) {
		return nil, syscall.EMSGSIZE
	}
	tcp := packet[ipSize:]
	for index := tcpHeaderSize; index < headerSize; index++ {
		tcp[index] = 0
	}
	copy(tcp[tcpHeaderSize:headerSize], options)
	marshalTCPHeaderFields(tcp[:headerSize], sourcePort, targetPort, sequence, acknowledgement, uint16(flags), window, 0)
	if payload.copyTo(tcp[headerSize:]) != payload.size {
		return nil, errors.New("mipstack: incomplete TCP payload view")
	}
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(source, target, ProtocolTCP, tcp))
	return packet, nil
}

// tryWriteTCP emits one best-effort stack-owned control segment without
// waiting for device capacity.
func (s *Stack) tryWriteTCP(source, target netip.Addr, sourcePort, targetPort uint16, sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int, trafficClass, ecn byte, flowLabel uint32, flowLabelSet bool) error {
	if source.Is6() && !flowLabelSet {
		flowLabel = s.network.Load().tcpDefaults.FlowLabel
		if flowLabel == 0 {
			flowLabel = s.automaticTransportFlowLabel(source, target, ProtocolTCP, sourcePort, targetPort)
		}
	}
	packet, err := buildTCPPacket(source, target, sourcePort, targetPort, sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn, flowLabel)
	if err != nil {
		return err
	}
	return s.tryWritePacket(packet)
}

// deliverError queues a matching ICMP error without blocking packet input.
func (c *TCPConn) deliverError(err error) {
	var networkError ICMPError
	if errors.As(err, &networkError) && networkError.MTU != 0 {
		return
	}
	c.mu.Lock()
	if c.terminalErr != nil {
		c.mu.Unlock()
		return
	}
	queued := c.pending == nil || len(c.pending.networkErrors) < tcpMaximumPendingNetworkErrors
	if queued {
		if c.pending == nil {
			c.pending = new(tcpPendingEvents)
		}
		if c.pending.networkErrors == nil {
			c.pending.networkErrors = make([]error, 0, tcpMaximumPendingNetworkErrors)
		}
		c.pending.networkErrors = append(c.pending.networkErrors, err)
	}
	c.mu.Unlock()
	if queued {
		c.wakeActor(tcpActorWakeNetworkError)
	}
}

// takeNetworkError removes one queued asynchronous error. Its backing is
// retained only after a connection has actually received ICMP feedback.
func (c *TCPConn) takeNetworkError() (error, bool) {
	c.mu.Lock()
	if c.pending == nil || len(c.pending.networkErrors) == 0 {
		c.mu.Unlock()
		return nil, false
	}
	errors := c.pending.networkErrors
	err := errors[0]
	copy(errors, errors[1:])
	last := len(errors) - 1
	errors[last] = nil
	c.pending.networkErrors = errors[:last]
	c.mu.Unlock()
	return err, true
}

// discardNetworkErrors clears queued soft errors while retaining the bounded
// backing for later feedback on the same connection.
func (c *TCPConn) discardNetworkErrors() {
	c.mu.Lock()
	if c.pending == nil {
		c.mu.Unlock()
		return
	}
	for index := range c.pending.networkErrors {
		c.pending.networkErrors[index] = nil
	}
	c.pending.networkErrors = c.pending.networkErrors[:0]
	c.mu.Unlock()
}

// enqueueInbound hands one validated segment to the byte-bounded actor queue.
func (c *TCPConn) enqueueInbound(segment tcpSegment) bool {
	if c.inbound.enqueue(segment) {
		return true
	}
	c.inboundQueueDrops.Add(1)
	return false
}

// enqueueInboundCopy gives the established actor an independent payload while
// avoiding allocation when its byte-bounded queue is already full.
func (c *TCPConn) enqueueInboundCopy(segment tcpSegment, payload []byte) bool {
	if c.inbound.enqueueCopy(segment, payload) {
		return true
	}
	c.inboundQueueDrops.Add(1)
	return false
}

// wakeActor coalesces state-only notifications while preserving updates that
// race with the actor clearing an earlier batch. The inbound token may already
// represent a packet; the actor consumes flags before dequeueing that packet.
func (c *TCPConn) wakeActor(flags uint32) {
	for {
		previous := c.actorWakeFlags.Load()
		if c.actorWakeFlags.CompareAndSwap(previous, previous|flags) {
			if previous != 0 {
				return
			}
			break
		}
	}
	select {
	case c.inbound.notify <- struct{}{}:
	default:
	}
}

// takeActorWake consumes one coalesced notification batch.
func (c *TCPConn) takeActorWake() uint32 { return c.actorWakeFlags.Swap(0) }

// publishICMPSequenceRange atomically exposes the transmitted sequence span
// used to authenticate asynchronous ICMP errors. Pure ACKs use the inclusive
// upper endpoint.
func (c *TCPConn) publishICMPSequenceRange(unacknowledged, next uint32) {
	c.icmpSequence.Store(uint64(unacknowledged)<<32 | uint64(next))
}

// acceptsICMPQuote reports whether the quoted TCP sequence belongs to data,
// control flags, or a pure ACK emitted by this connection.
func (c *TCPConn) acceptsICMPQuote(quoted []byte) bool {
	if len(quoted) < 8 {
		return false
	}
	sequenceRange := c.icmpSequence.Load()
	unacknowledged := uint32(sequenceRange >> 32)
	next := uint32(sequenceRange)
	sequence := binary.BigEndian.Uint32(quoted[4:8])
	return sequence-unacknowledged <= next-unacknowledged
}

// Read returns contiguous application bytes or the receive terminal state.
func (c *TCPConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	c.readCallMu.Lock()
	defer c.readCallMu.Unlock()
	n, err := c.read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, c.operationError("read", err)
	}
	return n, err
}

// read returns stream data without adding the public operation wrapper. The
// caller serializes it with other stream reads.
func (c *TCPConn) read(buffer []byte) (int, error) {
	_, n, _, err := c.readChunk(buffer, len(buffer))
	return n, err
}

// readChunk consumes one receive-buffer prefix. A nil destination transfers
// one independently owned chunk to another synchronous TCP writer.
func (c *TCPConn) readChunk(destination []byte, maximum int) ([]byte, int, bool, error) {
	for {
		c.mu.Lock()
		if c.userClosed || c.readClosed {
			c.mu.Unlock()
			return nil, 0, false, net.ErrClosed
		}
		timeout := c.readDeadline.wait()
		select {
		case <-timeout:
			c.mu.Unlock()
			return nil, 0, false, os.ErrDeadlineExceeded
		default:
		}
		if c.readBuffer.size != 0 {
			var payload []byte
			recyclable := false
			n := 0
			if destination == nil {
				payload, recyclable = c.readBuffer.take(maximum)
				n = len(payload)
			} else {
				n = c.readBuffer.read(destination, maximum, c.inbound.recyclePayload)
			}
			c.mu.Unlock()
			c.applicationReads.Add(uint64(n))
			c.wakeActor(tcpActorWakeWindow)
			return payload, n, recyclable, nil
		}
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return nil, 0, false, err
		}
		if c.readNotify == nil {
			c.readNotify = make(chan struct{}, 1)
		}
		notified := c.readNotify
		c.mu.Unlock()
		select {
		case <-notified:
		case <-timeout:
			return nil, 0, false, os.ErrDeadlineExceeded
		case <-c.done:
		}
	}
}

// WriteTo copies the receive stream into writer while preserving read
// ordering with concurrent calls to Read. It implements io.WriterTo.
func (c *TCPConn) WriteTo(writer io.Writer) (int64, error) {
	c.readCallMu.Lock()
	defer c.readCallMu.Unlock()
	if target, ok := writer.(*TCPConn); ok {
		return c.writeToTCP(target)
	}
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		_, n, _, readErr := c.readChunk(buffer, len(buffer))
		if n > 0 {
			written, writeErr := writer.Write(buffer[:n])
			if written < 0 || written > n {
				return total, c.operationError("writeto", errors.New("mipstack: invalid Write count"))
			}
			total += int64(written)
			if writeErr != nil {
				return total, c.operationError("writeto", writeErr)
			}
			if written != n {
				return total, c.operationError("writeto", io.ErrShortWrite)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, c.operationError("writeto", readErr)
		}
	}
}

// writeToTCP avoids a gather allocation when both ends use this stack. Write
// synchronously copies each immutable receive chunk before it returns.
func (c *TCPConn) writeToTCP(target *TCPConn) (int64, error) {
	var total int64
	for {
		payload, _, recyclable, readErr := c.readChunk(nil, 32*1024)
		if len(payload) != 0 {
			written, writeErr := target.Write(payload)
			if recyclable {
				c.inbound.recyclePayload(payload)
			}
			total += int64(written)
			if writeErr != nil {
				return total, c.operationError("writeto", writeErr)
			}
			if written != len(payload) {
				return total, c.operationError("writeto", io.ErrShortWrite)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, c.operationError("writeto", readErr)
		}
	}
}

// Write copies payload into the bounded TCP send buffer. It waits only for
// buffer space, not peer acknowledgement, matching standard net.Conn
// semantics. Bytes reported as written remain queued after a later timeout.
func (c *TCPConn) Write(payload []byte) (int, error) {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	written, err := c.write(payload)
	if err != nil {
		return written, c.operationError("write", err)
	}
	return written, nil
}

// write copies payload into the send buffer without adding the public
// operation wrapper. The caller serializes it with other stream writes.
func (c *TCPConn) write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(payload) {
		c.mu.Lock()
		if c.userClosed || c.writeClosed || c.terminalErr != nil {
			err := c.connectionErrorLocked()
			c.mu.Unlock()
			return written, err
		}
		timeout := c.writeDeadline.wait()
		select {
		case <-timeout:
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		default:
		}
		available := c.sendCapacity - c.sendBuffer.size
		if available > len(payload)-written {
			available = len(payload) - written
		}
		if available > 0 {
			c.sendBuffer.append(payload[written : written+available])
			written += available
		}
		var sendChanged <-chan struct{}
		if written != len(payload) {
			if c.sendChanged == nil {
				c.sendChanged = make(chan struct{}, 1)
			}
			sendChanged = c.sendChanged
		}
		c.mu.Unlock()
		if available > 0 {
			c.notifySend()
		}
		if written == len(payload) {
			return written, nil
		}
		select {
		case <-sendChanged:
		case <-timeout:
			return written, os.ErrDeadlineExceeded
		case <-c.done:
			c.mu.Lock()
			err := c.connectionErrorLocked()
			c.mu.Unlock()
			return written, err
		}
	}
	return written, nil
}

// ReadFrom copies a stream into c while preserving write ordering with
// concurrent calls to Write. It implements io.ReaderFrom without recursively
// entering io.Copy's ReaderFrom fast path.
func (c *TCPConn) ReadFrom(reader io.Reader) (int64, error) {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	buffer := make([]byte, 32*1024)
	var total int64
	emptyReads := 0
	for {
		n, readErr := reader.Read(buffer)
		if n < 0 || n > len(buffer) {
			return total, c.operationError("readfrom", errors.New("mipstack: invalid Read count"))
		}
		if n > 0 {
			emptyReads = 0
			written, writeErr := c.write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, c.operationError("readfrom", writeErr)
			}
			if written != n {
				return total, c.operationError("readfrom", io.ErrShortWrite)
			}
		} else if readErr == nil {
			emptyReads++
			if emptyReads >= 100 {
				return total, c.operationError("readfrom", io.ErrNoProgress)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, c.operationError("readfrom", readErr)
		}
	}
}

// CloseWrite queues FIN after all bytes already accepted by Write.
func (c *TCPConn) CloseWrite() error {
	c.writeCallMu.Lock()
	defer c.writeCallMu.Unlock()
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		err := c.connectionErrorLocked()
		c.mu.Unlock()
		return c.operationError("close", err)
	}
	if c.writeClosed {
		c.mu.Unlock()
		return nil
	}
	c.writeClosed = true
	c.mu.Unlock()
	c.notifySend()
	return nil
}

// CloseRead closes the application receive direction without resetting TCP.
func (c *TCPConn) CloseRead() error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		err := c.connectionErrorLocked()
		c.mu.Unlock()
		return c.operationError("close", err)
	}
	if !c.readClosed {
		c.readClosed = true
		c.readBuffer.reset()
		c.readErr = net.ErrClosed
		c.notifyReadLocked()
	}
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeWindow)
	return nil
}

// Close releases application access and applies the SetLinger policy. The
// default queues FIN after accepted writes and finishes protocol processing in
// the background.
func (c *TCPConn) Close() error {
	startedAt := time.Now()
	closedNow := false
	linger := -1
	var lingerDone <-chan struct{}
	abortive := false
	c.closeOnce.Do(func() {
		closedNow = true
		c.mu.Lock()
		c.readDeadline.stop()
		c.writeDeadline.stop()
		if !c.writeClosed {
			c.writeClosed = true
		}
		linger = c.linger
		abortive = linger == 0 || c.readBuffer.size != 0 || c.outOfOrderUnread.Load() != 0
		if linger > 0 && !abortive && !c.lingerComplete {
			if c.lingerDone == nil {
				c.lingerDone = make(chan struct{})
			}
			lingerDone = c.lingerDone
		}
		c.userClosed = true
		c.readErr = net.ErrClosed
		c.readBuffer.reset()
		if abortive {
			c.sendBuffer.clear()
		}
		c.notifySendChangedLocked()
		c.notifyReadLocked()
		c.mu.Unlock()
	})
	if !closedNow {
		return c.operationError("close", net.ErrClosed)
	}
	if abortive {
		c.abort(net.ErrClosed)
		return nil
	}
	// Also wake an actor whose FIN was already acknowledged after CloseWrite;
	// a later full Close makes that FIN_WAIT_2 state eligible for cleanup.
	c.notifySend()
	if linger > 0 && lingerDone != nil {
		timer, timeout := deadlineTimer(startedAt.Add(tcpLingerDuration(linger)))
		select {
		case <-lingerDone:
			stopTimer(timer)
		case <-c.done:
			stopTimer(timer)
		case <-timeout:
			c.abort(net.ErrClosed)
		}
	}
	return nil
}

// LocalAddr returns the managed local TCP endpoint.
func (c *TCPConn) LocalAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.local) }

// RemoteAddr returns the connected remote TCP endpoint.
func (c *TCPConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.remote) }

// Info returns a consistent diagnostic snapshot. The connection actor
// supplies live protocol state; after termination, the final snapshot remains
// available for post-mortem inspection.
func (c *TCPConn) Info() TCPConnInfo {
	select {
	case <-c.done:
		if info := c.lastInfo.Load(); info != nil {
			return *info
		}
		return c.tcpConnInfoBase(TCPStateClosed)
	default:
	}
	response := make(chan TCPConnInfo, 1)
	c.mu.Lock()
	queued := c.terminalErr == nil
	if queued {
		if c.pending == nil {
			c.pending = new(tcpPendingEvents)
		}
		c.pending.infoRequests = append(c.pending.infoRequests, response)
	}
	c.mu.Unlock()
	if queued {
		c.wakeActor(tcpActorWakeInfo)
		select {
		case info := <-response:
			return info
		case <-c.done:
		}
	} else {
		<-c.done
	}
	if info := c.lastInfo.Load(); info != nil {
		return *info
	}
	return c.tcpConnInfoBase(TCPStateClosed)
}

// takeInfoRequests detaches the callers represented by the current info wake.
// Requests arriving after the detach remain queued for the next wake.
func (c *TCPConn) takeInfoRequests() []chan TCPConnInfo {
	c.mu.Lock()
	if c.pending == nil {
		c.mu.Unlock()
		return nil
	}
	requests := c.pending.infoRequests
	c.pending.infoRequests = nil
	c.mu.Unlock()
	return requests
}

// tcpConnInfoBase snapshots application-facing state protected by c.mu.
func (c *TCPConn) tcpConnInfoBase(state TCPState) TCPConnInfo {
	c.mu.Lock()
	info := c.tcpConnInfoBaseLocked(state)
	c.mu.Unlock()
	return info
}

// tcpConnInfoBaseLocked snapshots application-facing state while c.mu is held.
func (c *TCPConn) tcpConnInfoBaseLocked(state TCPState) TCPConnInfo {
	info := TCPConnInfo{
		LocalAddress: c.key.local, RemoteAddress: c.key.remote, State: state,
		CongestionControl: c.congestionFactory.Name(),
		SendBufferSize:    c.sendBuffer.size, SendBufferCapacity: c.sendCapacity, MaximumSendBuffer: c.sendMaximum,
		ReceiveBufferSize: c.readBuffer.size + int(c.outOfOrderUnread.Load()), ReceiveBufferCapacity: c.receiveCapacity, MaximumReceiveBuffer: c.receiveMaximum,
		Retransmissions: c.retransmissions.Load(), InboundQueueDrops: c.inboundQueueDrops.Load(),
		InboundQueueBytes: c.inbound.retainedBytes(), InboundQueuePeak: c.inbound.peakBytes(), InboundQueueCapacity: tcpInboundByteCapacity,
		WindowScaling:   c.peerWindowScaling,
		PeerWindowScale: c.peerWindowScale, ReceiveWindowScale: c.receiveWindowScale,
		SACK: c.peerSACK, Timestamps: c.peerTimestamp, ECN: c.peerECN,
		KeepAlive: c.keepAlive, KeepAliveConfig: c.keepAliveConfig, IdleTimeout: c.idleTimeout, UserTimeout: c.userTimeout, NoDelay: c.noDelay,
		TrafficClass: uint8(c.trafficClass.Load()), FlowLabel: c.flowLabel, MaximumPacingRate: c.maximumPacingRate,
		LastError: c.terminalErr,
	}
	return info
}

// respondTCPConnInfo retains one snapshot before returning it to every caller
// coalesced into the same actor wake.
func (c *TCPConn) respondTCPConnInfo(requests []chan TCPConnInfo, info TCPConnInfo) {
	if len(requests) == 0 {
		return
	}
	c.lastInfo.Store(&info)
	for _, response := range requests {
		response <- info
	}
}

// noteRetransmission updates stack-wide and connection-local diagnostics.
func (c *TCPConn) noteRetransmission() {
	c.stack.stats.tcpRetransmissions.Add(1)
	c.retransmissions.Add(1)
}

// handshakeTCPConnInfo builds the subset available before congestion and data
// transfer state has been initialized.
func (c *TCPConn) handshakeTCPConnInfo(state TCPState, mss int, rto time.Duration) TCPConnInfo {
	info := c.tcpConnInfoBase(state)
	info.MaximumSegmentSize = mss
	info.PathMTU = c.mtu
	info.RetransmissionTimeout = rto
	info.PeerWindow = c.peerWindow
	info.ReceiveWindow = uint32(c.receiveAvailable(0))
	return info
}

// MultipathTCP reports whether this connection uses MPTCP. Mipstack currently
// implements ordinary TCP only, so the result is always false.
func (c *TCPConn) MultipathTCP() (bool, error) { return false, nil }

// operationError wraps a TCP socket failure in the same public shape used by
// the standard net package.
func (c *TCPConn) operationError(operation string, err error) error {
	return socketOperationError(operation, c.net, c.LocalAddr(), c.RemoteAddr(), err)
}

// setOperationError wraps a deadline-setting failure using the local-address
// metadata shape of the standard net package.
func (c *TCPConn) setOperationError(err error) error {
	return socketOperationError("set", c.net, nil, c.LocalAddr(), err)
}

// SetDeadline updates both application deadlines.
func (c *TCPConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.readDeadline.set(deadline)
	c.writeDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

// SetReadDeadline updates the next Read deadline.
func (c *TCPConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.readDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline updates the next Write deadline.
func (c *TCPConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.writeDeadline.set(deadline)
	c.mu.Unlock()
	return nil
}

// SetKeepAlive enables or disables TCP keepalive probes.
func (c *TCPConn) SetKeepAlive(enabled bool) error {
	return c.updateSocketOptions(func() { c.keepAlive = enabled })
}

// SetKeepAlivePeriod sets both the idle delay and probe interval. Use
// SetKeepAliveConfig when different values or a custom probe count are needed.
func (c *TCPConn) SetKeepAlivePeriod(period time.Duration) error {
	if period <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() {
		c.keepAliveConfig.Idle = period
		c.keepAliveConfig.Interval = period
	})
}

// SetKeepAliveConfig replaces keepalive timing and probe count.
func (c *TCPConn) SetKeepAliveConfig(config KeepAliveConfig) error {
	if config.Idle <= 0 || config.Interval <= 0 || config.Count <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.keepAliveConfig = config })
}

// SetIdleTimeout closes the connection when no acceptable segment arrives for
// timeout. Zero disables the timeout.
func (c *TCPConn) SetIdleTimeout(timeout time.Duration) error {
	if timeout < 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.idleTimeout = timeout })
}

// SetUserTimeout bounds how long transmitted data may remain unacknowledged,
// or buffered data may remain unsent behind a zero window. Zero disables the
// custom bound while retaining the normal TCP retry limits. Like Linux
// TCP_USER_TIMEOUT, this is a local policy and does not negotiate the RFC
// 5482 UTO option.
func (c *TCPConn) SetUserTimeout(timeout time.Duration) error {
	if timeout < 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() { c.userTimeout = timeout })
}

// SetNoDelay controls Nagle coalescing. The default is true, matching
// net.TCPConn.
func (c *TCPConn) SetNoDelay(noDelay bool) error {
	err := c.updateSocketOptions(func() { c.noDelay = noDelay })
	if err == nil {
		c.notifySend()
	}
	return err
}

// SetCongestionControl changes the algorithm for this connection and prevents
// later stack-default updates from overriding the explicit choice.
func (c *TCPConn) SetCongestionControl(algorithm CongestionControl) error {
	factory, exists := registeredCongestionControlFactory(algorithm)
	if !exists {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() {
		c.congestionFactory = factory
		c.congestionUser = true
	})
}

// SetCongestionControlFactory changes this connection to an immutable local
// factory and prevents later stack-default updates from overriding the explicit
// choice. The factory creates a new connection-private controller on the actor
// goroutine; it may be shared with other connections safely.
func (c *TCPConn) SetCongestionControlFactory(factory *CongestionControlFactory) error {
	if !factory.valid() {
		return c.setOperationError(syscall.EINVAL)
	}
	return c.updateSocketOptions(func() {
		c.congestionFactory = factory
		c.congestionUser = true
	})
}

// SetMaximumPacingRate caps this connection's paced-data rate in bytes per
// second. Zero removes the limit. Initial and control bursts mean it is not a
// strict byte-rate shaper. The selected congestion controller still maintains
// its unconstrained path model so removing a limit takes effect without
// resetting congestion state.
func (c *TCPConn) SetMaximumPacingRate(bytesPerSecond uint64) error {
	return c.updateSocketOptions(func() { c.maximumPacingRate = bytesPerSecond })
}

// SetTrafficClass sets IPv4 TOS or IPv6 Traffic Class DSCP bits. TCP owns and
// replaces the two ECN bits on each packet.
func (c *TCPConn) SetTrafficClass(value int) error {
	if value < 0 || value > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.trafficClass.Store(uint32(uint8(value) & 0xfc))
	c.mu.Unlock()
	return nil
}

// SetLinger controls how Close handles data waiting to be sent or
// acknowledged. A negative value completes in the background, zero performs
// an abortive close, and a positive value waits up to that many seconds before
// aborting the remaining transmission.
func (c *TCPConn) SetLinger(seconds int) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.linger = seconds
	c.mu.Unlock()
	return nil
}

// tcpLingerDuration converts a positive seconds value without overflowing a
// time.Duration on 64-bit platforms.
func tcpLingerDuration(seconds int) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	if int64(seconds) > int64(maximum)/int64(time.Second) {
		return maximum
	}
	return time.Duration(seconds) * time.Second
}

// SetReadBuffer changes the bounded application receive capacity.
func (c *TCPConn) SetReadBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.receiveCapacity = bytes
	c.receiveAutoTune = false
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeWindow)
	return nil
}

// SetWriteBuffer changes the bounded application send capacity.
func (c *TCPConn) SetWriteBuffer(bytes int) error {
	if bytes <= 0 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	c.sendCapacity = bytes
	c.sendAutoTune = false
	c.sendCapacityHint.Store(int64(bytes))
	c.notifySendChangedLocked()
	c.mu.Unlock()
	return nil
}

// growReceiveCapacity applies automatic receive tuning without overriding a
// SetReadBuffer choice. One observation can at most double the current bound,
// which prevents a scheduler pause or counter burst from causing abrupt
// per-connection memory growth.
func (c *TCPConn) growReceiveCapacity(target int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.receiveAutoTune || target <= c.receiveCapacity {
		return false
	}
	if maximum := c.receiveCapacity * 2; target > maximum {
		target = maximum
	}
	maximum := c.receiveMaximum
	if maximum <= 0 {
		maximum = tcpMaximumReceiveCapacity
	}
	if target > maximum {
		target = maximum
	}
	if target <= c.receiveCapacity {
		return false
	}
	c.receiveCapacity = target
	return true
}

// growSendCapacity applies a delivery-rate-derived automatic target without
// overriding SetWriteBuffer. One observation can at most double the current
// capacity, preventing a scheduler pause from reserving the maximum at once.
func (c *TCPConn) growSendCapacity(target int) bool {
	if target <= int(c.sendCapacityHint.Load()) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sendAutoTune || target <= c.sendCapacity {
		return false
	}
	if maximum := c.sendCapacity * 2; target > maximum {
		target = maximum
	}
	maximum := c.sendMaximum
	if maximum <= 0 {
		maximum = tcpMaximumSendCapacity
	}
	if target > maximum {
		target = maximum
	}
	if target <= c.sendCapacity {
		return false
	}
	c.sendCapacity = target
	c.sendCapacityHint.Store(int64(target))
	c.notifySendChangedLocked()
	return true
}

// updateSocketOptions applies one option update and wakes the actor.
func (c *TCPConn) updateSocketOptions(update func()) error {
	c.mu.Lock()
	if c.userClosed || c.terminalErr != nil {
		c.mu.Unlock()
		return c.setOperationError(net.ErrClosed)
	}
	update()
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeOptions)
	return nil
}

// socketOptions returns one consistent option snapshot.
func (c *TCPConn) socketOptions() tcpSocketOptions {
	c.mu.Lock()
	defer c.mu.Unlock()
	return tcpSocketOptions{
		keepAlive: c.keepAlive, keepAliveConfig: c.keepAliveConfig,
		idleTimeout: c.idleTimeout, userTimeout: c.userTimeout, noDelay: c.noDelay,
		congestionFactory: c.congestionFactory,
		maximumPacingRate: c.maximumPacingRate,
	}
}

// updateDefaultCongestionControl preserves Config.UpdateConfig's established-
// connection behavior unless the application selected a per-socket override.
func (c *TCPConn) updateDefaultCongestionControl(factory *CongestionControlFactory) {
	c.mu.Lock()
	if c.congestionUser || c.userClosed || c.terminalErr != nil || c.congestionFactory == factory {
		c.mu.Unlock()
		return
	}
	c.congestionFactory = factory
	c.mu.Unlock()
	c.wakeActor(tcpActorWakeOptions)
}

// abort publishes one actor termination request and its cause.
func (c *TCPConn) abort(err error) {
	c.abortWithReset(err, true)
}

// abortWithoutReset terminates local state without emitting from a source or
// route that the current configuration has already withdrawn.
func (c *TCPConn) abortWithoutReset(err error) {
	c.abortWithReset(err, false)
}

// abortWithReset publishes one actor termination request and its wire policy.
func (c *TCPConn) abortWithReset(err error, reset bool) {
	c.abortOnce.Do(func() {
		c.abortMu.Lock()
		c.abortErr = err
		c.abortRST = reset
		c.abortMu.Unlock()
		close(c.abortCh)
	})
}

// abortedError returns the cause stored before abortCh was closed.
func (c *TCPConn) abortedError() error {
	c.abortMu.Lock()
	defer c.abortMu.Unlock()
	if c.abortErr == nil {
		return net.ErrClosed
	}
	return c.abortErr
}

// takeAbortReset consumes permission to emit the abortive RST. Established
// cleanup can race a concurrent abort publication, so the policy itself is the
// at-most-once authority rather than a separate actor-local sent flag.
func (c *TCPConn) takeAbortReset() bool {
	c.abortMu.Lock()
	reset := c.abortRST
	c.abortRST = false
	c.abortMu.Unlock()
	return reset
}

// connectionErrorLocked returns the terminal error while c.mu is held.
func (c *TCPConn) connectionErrorLocked() error {
	if c.terminalErr != nil {
		return c.terminalErr
	}
	return net.ErrClosed
}

// notifyReadLocked wakes the serialized application reader. Repeated state
// changes coalesce while it is running.
func (c *TCPConn) notifyReadLocked() {
	if c.readNotify == nil {
		return
	}
	select {
	case c.readNotify <- struct{}{}:
	default:
	}
}

// notifySend wakes the connection actor after buffered data or CloseWrite.
func (c *TCPConn) notifySend() {
	c.wakeActor(tcpActorWakeSend)
}

// notifySendChangedLocked wakes Writes waiting for send-buffer space while
// c.mu is held.
func (c *TCPConn) notifySendChangedLocked() {
	if c.sendChanged == nil {
		return
	}
	select {
	case c.sendChanged <- struct{}{}:
	default:
	}
}

// notifyLingerDone publishes that every accepted byte and the local FIN have
// been cumulatively acknowledged. The actor may remain in FIN_WAIT or
// TIME_WAIT after a positive-linger Close has returned.
func (c *TCPConn) notifyLingerDone() {
	c.mu.Lock()
	if !c.lingerComplete {
		c.lingerComplete = true
		if c.lingerDone != nil {
			close(c.lingerDone)
			c.lingerDone = nil
		}
	}
	c.mu.Unlock()
}

// sendState returns the current logical send-buffer size and close state
// without constructing a payload view.
func (c *TCPConn) sendState() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendBuffer.size, c.writeClosed
}

// sendView snapshots immutable slice headers without gathering payload bytes.
func (c *TCPConn) sendView(offset, maximum int, payload *tcpPayloadView) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := c.sendBuffer.view(offset, maximum, payload)
	return total, c.writeClosed
}

// acknowledgeSend releases cumulatively acknowledged data and wakes blocked
// writers.
func (c *TCPConn) acknowledgeSend(size int) {
	if size <= 0 {
		return
	}
	c.mu.Lock()
	if size > c.sendBuffer.size {
		size = c.sendBuffer.size
	}
	if size != 0 {
		c.sendBuffer.acknowledge(size)
		c.notifySendChangedLocked()
	}
	c.mu.Unlock()
}

// discardingReads reports whether CloseRead has disabled application delivery
// while TCP must continue acknowledging the peer's stream.
func (c *TCPConn) discardingReads() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readClosed || c.userClosed
}

// applicationReceiveClosed reports whether Close, rather than the explicit
// read half-close, made newly received application data undeliverable.
func (c *TCPConn) applicationReceiveClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.userClosed
}

// appendReadBuffer takes ownership of and retains as much contiguous data as
// the receive bound permits. owner is the complete independent allocation
// that contains payload; a trimmed range is compacted before it is retained.
func (c *TCPConn) appendReadBuffer(payload []byte, owner []byte, outOfOrderBytes int) int {
	c.mu.Lock()
	available := c.receiveCapacity - c.readBuffer.size - outOfOrderBytes
	if c.userClosed || c.readClosed {
		accepted := len(payload)
		c.mu.Unlock()
		return accepted
	}
	if available < 0 {
		available = 0
	}
	if len(payload) > available {
		payload = payload[:available]
	}
	payload = retainTCPPayload(payload, owner)
	c.readBuffer.append(payload)
	if len(payload) != 0 {
		c.notifyReadLocked()
	}
	c.mu.Unlock()
	return len(payload)
}

// retainTCPPayload adopts a complete, capacity-bounded packet payload and
// copies a subslice. A suffix-only slice can have cap==len while still pinning
// the discarded prefix, so both its start and length must match the owner.
func retainTCPPayload(payload, owner []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	if len(payload) == len(owner) && cap(owner) == len(owner) && &payload[0] == &owner[0] {
		return payload[:len(payload):len(payload)]
	}
	retained := append([]byte(nil), payload...)
	return retained[:len(retained):len(retained)]
}

// receiveAvailable returns storage not occupied by delivered or out-of-order
// data. CloseRead discards delivered bytes while preserving sequence state.
func (c *TCPConn) receiveAvailable(outOfOrderBytes int) int {
	available, _ := c.receiveSpace(outOfOrderBytes)
	return available
}

// receiveSpace returns both current free storage and the configured bound so
// the established actor can apply receiver-side silly-window avoidance.
func (c *TCPConn) receiveSpace(outOfOrderBytes int) (available, capacity int) {
	c.mu.Lock()
	capacity = c.receiveCapacity
	available = capacity - c.readBuffer.size - outOfOrderBytes
	if c.userClosed || c.readClosed {
		available = capacity - outOfOrderBytes
	}
	c.mu.Unlock()
	return
}

// receiveWindow returns a wire window without prior advertisement state. It
// is used during handshakes, before the established actor owns the right edge.
func (c *TCPConn) receiveWindow(outOfOrderBytes int, scaled bool) uint16 {
	available := c.receiveAvailable(outOfOrderBytes)
	if available <= 0 {
		return 0
	}
	if scaled {
		available >>= c.receiveWindowScale
	}
	if available > 65535 {
		available = 65535
	}
	return uint16(available)
}

// setReadEOF publishes an orderly peer FIN after buffered data.
func (c *TCPConn) setReadEOF() {
	c.mu.Lock()
	if c.readErr == nil {
		c.readErr = io.EOF
		c.notifyReadLocked()
	}
	c.mu.Unlock()
}

// finish publishes the actor terminal state, releases actor-owned buffers,
// and wakes application calls.
func (c *TCPConn) finish(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	discardReceive := false
	select {
	case <-c.stack.closeCh:
		discardReceive = true
	default:
	}
	if !discardReceive {
		select {
		case <-c.abortCh:
			discardReceive = true
		default:
		}
	}
	c.mu.Lock()
	c.terminalErr = err
	c.readDeadline.stop()
	c.writeDeadline.stop()
	if discardReceive {
		c.readBuffer = tcpReadBuffer{}
		c.outOfOrderUnread.Store(0)
		c.readErr = err
	} else if c.readErr == nil {
		c.readErr = err
	}
	c.sendBuffer.clear()

	c.pending = nil
	c.notifyReadLocked()
	c.notifySendChangedLocked()
	c.mu.Unlock()
	// Close the actor queue before publishing its terminal snapshot. The
	// connection remains visible in Stack.tcp until run's deferred removal, so
	// a concurrent packet lookup can otherwise enqueue work after the sole
	// consumer has exited.
	c.inbound.close()
	base := c.tcpConnInfoBase(TCPStateClosed)
	if previous := c.lastInfo.Load(); previous != nil {
		info := *previous
		info.State = TCPStateClosed
		info.SendBufferSize, info.SendBufferCapacity, info.MaximumSendBuffer = base.SendBufferSize, base.SendBufferCapacity, base.MaximumSendBuffer
		info.ReceiveBufferSize, info.ReceiveBufferCapacity, info.MaximumReceiveBuffer = base.ReceiveBufferSize, base.ReceiveBufferCapacity, base.MaximumReceiveBuffer
		info.Retransmissions = base.Retransmissions
		info.InboundQueueDrops, info.InboundQueueBytes = base.InboundQueueDrops, base.InboundQueueBytes
		info.InboundQueuePeak, info.InboundQueueCapacity = base.InboundQueuePeak, base.InboundQueueCapacity
		info.KeepAlive, info.KeepAliveConfig, info.IdleTimeout, info.UserTimeout, info.NoDelay = base.KeepAlive, base.KeepAliveConfig, base.IdleTimeout, base.UserTimeout, base.NoDelay
		info.MaximumPacingRate = base.MaximumPacingRate
		info.TrafficClass = base.TrafficClass
		info.LastError = err
		c.lastInfo.Store(&info)
	} else {
		base.LastError = err
		c.lastInfo.Store(&base)
	}
}

// run owns the connection protocol state from SYN through termination.
// connected is written exactly once after active-open completion and is not
// retained by TCPConn after DialTCP has observed that result.
func (c *TCPConn) run(initialSequence uint32, connected chan<- error) {
	defer c.stack.removeTCP(c)
	defer close(c.done)
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	var initialReceive tcpInitialReceive
	err := c.handshake(initialSequence, protocolTimer, &initialReceive)
	if err != nil {
		connected <- err
		c.finish(err)
		return
	}
	connected <- nil
	err = c.established(initialSequence+1, protocolTimer, initialReceive)
	c.finish(err)
}

// runPassive owns one server-side connection from SYN-ACK through
// termination.
func (c *TCPConn) runPassive(listener *TCPListener, syn tcpSegment, initialSequence uint32) {
	queued := false
	defer func() {
		if !queued {
			listener.removePending(c)
		}
	}()
	defer c.stack.removeTCP(c)
	defer close(c.done)
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	if err := c.passiveHandshake(syn, initialSequence, protocolTimer); err != nil {
		listener.noteHandshakeFailure(err)
		if errors.Is(err, net.ErrClosed) {
			_ = c.sendAbortReset(initialSequence+1, c.receiveNext, c.receiveWindow(0, false))
		}
		c.finish(err)
		return
	}
	if !listener.enqueue(c) {
		_ = c.sendAbortReset(initialSequence+1, c.receiveNext, c.receiveWindow(0, false))
		c.finish(syscall.ECONNABORTED)
		return
	}
	queued = true
	err := c.established(initialSequence+1, protocolTimer, tcpInitialReceive{payload: syn.payload, fin: syn.flags&TCPFlagFIN != 0})
	c.finish(err)
}

// runForwardedPassive completes a handler-approved passive open without an
// ordinary listener accept queue, then owns the established connection.
func (c *TCPConn) runForwardedPassive(syn tcpSegment, initialSequence uint32, result chan<- error) {
	defer c.stack.removeTCP(c)
	defer close(c.done)
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	if err := c.passiveHandshake(syn, initialSequence, protocolTimer); err != nil {
		result <- err
		c.finish(err)
		return
	}
	result <- nil
	err := c.established(initialSequence+1, protocolTimer, tcpInitialReceive{payload: syn.payload, fin: syn.flags&TCPFlagFIN != 0})
	c.finish(err)
}

// passiveHandshake replies to one valid SYN and waits for the final ACK with
// bounded retransmission.
func (c *TCPConn) passiveHandshake(syn tcpSegment, initialSequence uint32, timer *ownedTimer) error {
	localMSS := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	mss, scale, windowScaling, sack, timestamp, timestampValue := parseTCPOptions(syn.optionBytes(), defaultTCPPeerMSS(c.key.remote.Addr()), 65535)
	c.peerMSS, c.peerWindowScale, c.peerWindowScaling, c.peerSACK = mss, scale, windowScaling, sack
	c.peerTimestamp, c.recentTimestamp = timestamp, timestampValue
	c.peerECN = syn.flags&(TCPFlagECE|TCPFlagCWR) == TCPFlagECE|TCPFlagCWR
	c.receiveNext = syn.sequence + 1
	c.peerWindow = uint32(syn.window)
	c.peerWindowSeq = syn.sequence
	c.peerWindowACK = 0

	rto := tcpInitialRTO
	transmissions := 0
	timeoutAttempts := 0
	var timeout <-chan time.Time
	var timeoutDeadline time.Time
	var synSentAt time.Time
	var optionStorage [40]byte
	send := func(rearm bool) error {
		options := tcpPassiveSYNOptions(optionStorage[:0], localMSS, sack, windowScaling, timestamp, c.receiveWindowScale, c.stack.tcpTimestamp(), c.recentTimestamp)
		flags := byte(TCPFlagSYN | TCPFlagACK)
		if c.peerECN {
			flags |= TCPFlagECE
		}
		hostQueue, err := c.writeTCPControlWithMTU(initialSequence, c.receiveNext, flags, c.receiveWindow(0, false), options, nil, c.mtu)
		if err != nil {
			return err
		}
		synSentAt = hostQueue.queuedTime(c.stack.timestampEpoch)
		if transmissions != 0 {
			c.noteRetransmission()
		}
		transmissions++
		if rearm {
			timeoutDeadline = synSentAt.Add(rto)
			delay := timeoutDeadline.Sub(time.Now())
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		return nil
	}
	if err := send(true); err != nil {
		return err
	}
	eventTime := tcpSegmentEventTime(syn, synSentAt, time.Time{}, c.stack.timestampEpoch)
	var timerBacklog tcpTimerBacklog
	for {
		activeTimeout := timeout
		inboundNotify := c.inbound.notify
		drainBacklog, forceTimeout := timerBacklog.order(c.inbound.len(), timeoutDeadline, time.Now())
		if drainBacklog {
			// Process the finite receive snapshot that was already waiting when
			// this handshake timeout expired.
			activeTimeout = nil
		} else if forceTimeout && c.actorWakeFlags.Load() == 0 {
			inboundNotify = nil
		}
		select {
		case <-inboundNotify:
			wake := c.takeActorWake()
			if wake&tcpActorWakeNetworkError != 0 {
				c.discardNetworkErrors()
			}
			if wake&tcpActorWakeInfo != 0 {
				c.respondTCPConnInfo(c.takeInfoRequests(), c.handshakeTCPConnInfo(TCPStateSYNReceived, localMSS, rto))
			}
			if wake&tcpActorWakePathMTU != 0 {
				c.mtu = c.stack.mtuFor(c.key.remote.Addr())
				localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
				if localMSS < 1 {
					return errors.New("mipstack: MTU is too small for TCP")
				}
				if err := send(false); err != nil {
					return err
				}
			}
			segment, ok := c.inbound.dequeue()
			if !ok {
				continue
			}
			timerBacklog.consumed()
			receivedAt := tcpSegmentEventTime(segment, time.Now(), eventTime, c.stack.timestampEpoch)
			eventTime = receivedAt
			segmentLength := uint32(len(segment.payload))
			if segment.flags&TCPFlagSYN != 0 {
				segmentLength++
			}
			if segment.flags&TCPFlagFIN != 0 {
				segmentLength++
			}
			receiveWindow := uint32(c.receiveWindow(0, false))
			if segment.flags&TCPFlagRST != 0 {
				if segment.sequence == c.receiveNext {
					return syscall.ECONNRESET
				}
				if tcpSegmentAcceptable(segment.sequence, segmentLength, c.receiveNext, receiveWindow) && c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					if err := c.sendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false), nil); err != nil {
						return err
					}
				}
				continue
			}
			if !c.passive && segment.flags&(TCPFlagSYN|TCPFlagACK) == TCPFlagSYN|TCPFlagACK && segment.acknowledgement == initialSequence+1 && segment.sequence+1 == c.receiveNext {
				// During simultaneous open both endpoints send SYN-ACK. Its
				// SYN repeats the already accepted IRS while its ACK completes
				// our active half of the handshake.
				if c.peerTimestamp {
					value, _, present := parseTCPTimestamp(segment.optionBytes())
					if !present || tcpSequenceLess(value, c.recentTimestamp) {
						continue
					}
					c.recentTimestamp = value
				}
				c.peerWindow = uint32(segment.window)
				c.peerWindowSeq = segment.sequence
				c.peerWindowACK = segment.acknowledgement
				if transmissions == 1 {
					c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
				}
				timer.stop()
				return c.sendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, c.peerWindowScaling), nil)
			}
			if segment.flags&TCPFlagSYN != 0 && segment.flags&TCPFlagACK == 0 && segment.sequence+1 == c.receiveNext {
				// RFC 3168 section 6.1.1.1 permits an initiator to clear ECE
				// and CWR after an ECN setup SYN times out. The retransmitted
				// SYN must downgrade the stateful passive open as well as the
				// SYN-ACK sent in response, or an ECN-intolerant path can never
				// complete the fallback handshake.
				if segment.flags&(TCPFlagECE|TCPFlagCWR) != TCPFlagECE|TCPFlagCWR {
					c.peerECN = false
				}
				if c.peerTimestamp {
					value, _, present := parseTCPTimestamp(segment.optionBytes())
					if present && !tcpSequenceLess(value, c.recentTimestamp) {
						c.recentTimestamp = value
					}
				}
				if err := send(false); err != nil {
					return err
				}
				continue
			}
			if !tcpSegmentAcceptable(segment.sequence, segmentLength, c.receiveNext, receiveWindow) {
				if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					if err := c.sendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false), nil); err != nil {
						return err
					}
				}
				continue
			}
			if segment.flags&TCPFlagACK != 0 && segment.acknowledgement != initialSequence+1 {
				if _, err := c.writeTCPControlWithMTU(segment.acknowledgement, 0, TCPFlagRST, 0, nil, nil, c.mtu); err != nil {
					return err
				}
				continue
			}
			if segment.flags&TCPFlagSYN != 0 {
				if c.stack.allowControlResponse(controlResponseTCPChallengeACK) {
					if err := c.sendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, false), nil); err != nil {
						return err
					}
				}
				continue
			}
			if segment.flags&TCPFlagACK == 0 || segment.acknowledgement != initialSequence+1 {
				continue
			}
			if c.peerTimestamp {
				value, _, present := parseTCPTimestamp(segment.optionBytes())
				if !present || tcpSequenceLess(value, c.recentTimestamp) {
					continue
				}
				c.recentTimestamp = value
			}
			c.peerWindow = uint32(segment.window)
			if c.peerWindowScaling {
				c.peerWindow <<= c.peerWindowScale
			}
			c.peerWindowSeq = segment.sequence
			c.peerWindowACK = segment.acknowledgement
			if transmissions == 1 {
				c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
			}
			timer.stop()
			if len(segment.payload) != 0 || segment.flags&TCPFlagFIN != 0 {
				if !c.inbound.prepend(segment) {
					c.inboundQueueDrops.Add(1)
					c.stack.stats.inboundDroppedPackets.Add(1)
					c.stack.stats.tcpInboundQueueDrops.Add(1)
				}
			}
			return nil
		case <-activeTimeout:
			timer.consumed()
			if timeoutAttempts >= tcpPassiveSYNMaximumAttempts-1 {
				return os.ErrDeadlineExceeded
			}
			timeoutAttempts++
			c.handshakeTimeout = true
			rto *= 2
			if rto > tcpMaximumRTO {
				rto = tcpMaximumRTO
			}
			if err := send(true); err != nil {
				return err
			}
		case <-c.abortCh:
			return c.abortedError()
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

// handshake performs active open with bounded exponential SYN retransmission.
func (c *TCPConn) handshake(initialSequence uint32, timer *ownedTimer, initialReceive *tcpInitialReceive) error {
	localMSS := tcpMSSForMTU(c.mtu, c.key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	rto := tcpInitialRTO
	transmissions := 0
	timeoutAttempts := 0
	ecnFallback := false
	var timeout <-chan time.Time
	var timeoutDeadline time.Time
	var lastSoftError error
	var synSentAt time.Time
	var optionStorage [40]byte
	send := func(rearm bool) error {
		options := tcpSYNOptions(optionStorage[:0], localMSS, c.receiveWindowScale, c.stack.tcpTimestamp())
		flags := byte(TCPFlagSYN)
		if !ecnFallback {
			flags |= TCPFlagECE | TCPFlagCWR
		}
		hostQueue, err := c.writeTCPControlWithMTU(initialSequence, 0, flags, c.receiveWindow(0, false), options, nil, c.mtu)
		if err != nil {
			return err
		}
		synSentAt = hostQueue.queuedTime(c.stack.timestampEpoch)
		if transmissions != 0 {
			c.noteRetransmission()
		}
		transmissions++
		if rearm {
			timeoutDeadline = synSentAt.Add(rto)
			delay := timeoutDeadline.Sub(time.Now())
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		return nil
	}
	if err := send(true); err != nil {
		return err
	}
	eventTime := synSentAt
	var timerBacklog tcpTimerBacklog
	for {
		activeTimeout := timeout
		inboundNotify := c.inbound.notify
		drainBacklog, forceTimeout := timerBacklog.order(c.inbound.len(), timeoutDeadline, time.Now())
		if drainBacklog {
			activeTimeout = nil
		} else if forceTimeout && c.actorWakeFlags.Load() == 0 {
			inboundNotify = nil
		}
		select {
		case <-inboundNotify:
			wake := c.takeActorWake()
			if wake&tcpActorWakeNetworkError != 0 {
				for {
					err, ok := c.takeNetworkError()
					if !ok {
						break
					}
					// RFC 1122 treats asynchronous network failures during an active
					// open as soft errors except for an authenticated protocol or port
					// unreachable.
					if tcpActiveOpenHardError(err) {
						return err
					}
					lastSoftError = err
				}
			}
			if wake&tcpActorWakeInfo != 0 {
				c.respondTCPConnInfo(c.takeInfoRequests(), c.handshakeTCPConnInfo(TCPStateSYNSent, localMSS, rto))
			}
			if wake&tcpActorWakePathMTU != 0 {
				c.mtu = c.stack.mtuFor(c.key.remote.Addr())
				localMSS = tcpMSSForMTU(c.mtu, c.key.local.Addr())
				if localMSS < 1 {
					return errors.New("mipstack: MTU is too small for TCP")
				}
				if err := send(false); err != nil {
					return err
				}
			}
			segment, ok := c.inbound.dequeue()
			if !ok {
				continue
			}
			timerBacklog.consumed()
			receivedAt := tcpSegmentEventTime(segment, time.Now(), eventTime, c.stack.timestampEpoch)
			eventTime = receivedAt
			if segment.flags&TCPFlagACK != 0 && segment.acknowledgement != initialSequence+1 {
				// RFC 9293 SYN-SENT processing: an unacceptable ACK elicits
				// RST unless the incoming segment was itself a reset.
				if segment.flags&TCPFlagRST == 0 {
					_, _ = c.writeTCPControlWithMTU(segment.acknowledgement, 0, TCPFlagRST, 0, nil, nil, c.mtu)
				}
				continue
			}
			if segment.flags&TCPFlagRST != 0 {
				if segment.flags&TCPFlagACK != 0 && segment.acknowledgement == initialSequence+1 {
					return syscall.ECONNREFUSED
				}
				continue
			}
			if segment.flags&TCPFlagSYN != 0 && segment.flags&TCPFlagACK == 0 {
				// Crossed SYNs are a simultaneous open. Reuse SYN-RECEIVED
				// processing with our existing ISS and wait for the peer's
				// final ACK of the SYN-ACK.
				timer.stop()
				if initialReceive != nil {
					*initialReceive = tcpInitialReceive{payload: segment.payload, fin: segment.flags&TCPFlagFIN != 0}
				}
				return c.passiveHandshake(segment, initialSequence, timer)
			}
			if segment.flags&(TCPFlagSYN|TCPFlagACK) != TCPFlagSYN|TCPFlagACK || segment.acknowledgement != initialSequence+1 {
				continue
			}
			mss, scale, windowScaling, sack, timestamp, timestampValue := parseTCPOptions(segment.optionBytes(), defaultTCPPeerMSS(c.key.remote.Addr()), 65535)
			c.peerMSS, c.peerWindowScale, c.peerSACK = mss, scale, sack
			c.peerWindowScaling = windowScaling
			c.peerTimestamp, c.recentTimestamp = timestamp, timestampValue
			// Once an ECN setup SYN has timed out, RFC 3168 requires the
			// legacy SYN retransmission to disable ECN for this connection.
			// A delayed setup SYN-ACK cannot re-enable the negotiation after
			// that fallback has started.
			c.peerECN = !ecnFallback && segment.flags&TCPFlagECE != 0 && segment.flags&TCPFlagCWR == 0
			c.receiveNext = segment.sequence + 1
			if initialReceive != nil {
				*initialReceive = tcpInitialReceive{payload: segment.payload, fin: segment.flags&TCPFlagFIN != 0}
			}
			// The window in SYN and SYN-ACK is never scaled. The negotiated
			// shift applies only to later segments.
			c.peerWindow = uint32(segment.window)
			c.peerWindowSeq = segment.sequence
			c.peerWindowACK = segment.acknowledgement
			if transmissions == 1 {
				c.handshakeRTT = elapsedRTTSampleAt(synSentAt, receivedAt)
			}
			timer.stop()
			return c.sendSegment(initialSequence+1, c.receiveNext, TCPFlagACK, c.receiveWindow(0, c.peerWindowScaling), nil)
		case <-activeTimeout:
			timer.consumed()
			if timeoutAttempts >= tcpActiveSYNMaximumAttempts-1 {
				return tcpTimeoutError(lastSoftError)
			}
			timeoutAttempts++
			c.handshakeTimeout = true
			ecnFallback = true
			rto *= 2
			if rto > tcpMaximumRTO {
				rto = tcpMaximumRTO
			}
			if err := send(true); err != nil {
				return err
			}
		case <-c.abortCh:
			return c.abortedError()
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

// tcpEstablishedACKOperations exposes actor-local send and recovery actions to
// processAcknowledgment without recapturing the complete established frame.
// The callbacks are borrowed for one synchronous call and must not be retained
// or invoked from another goroutine.
type tcpEstablishedACKOperations struct {
	// applyPathMTU applies confirmed path feedback and optionally restarts
	// connection-local discovery.
	applyPathMTU func(int, bool) error
	// retransmitSegment retransmits one scoreboard entry.
	retransmitSegment func(int, bool) error
	// failPLPMTUProbe processes isolated loss of the active probe.
	failPLPMTUProbe func() error
	// retransmitRTORecovery sends the next range admitted by RTO recovery.
	retransmitRTORecovery func(int) error
	// recoverSACKHoles sends ranges admitted by RFC 6675 and PRR.
	recoverSACKHoles func(uint32, bool) error
	// sendNextData fills newly available peer or congestion window space.
	sendNextData func(uint32, bool) (bool, error)
}

// processAcknowledgment validates and applies one acceptable ACK to the
// actor-owned scoreboard, recovery, RTT, PMTU, and congestion state. It calls
// operations synchronously and returns the first packet-output failure.
func (state *tcpEstablishedState) processAcknowledgment(segment *tcpSegment, receivedAt time.Time, timestampEcho uint32, operations *tcpEstablishedACKOperations) error {
	c := state.connection
	ack := segment.acknowledgement
	previousSendUnacknowledged := state.sendUnacknowledged
	sackScoreboardEmpty := state.sackedRanges == 0
	previousWindow := state.peerWindow
	if tcpWindowUpdateAllowed(segment.sequence, ack, state.peerWindowSequence, state.peerWindowACK) {
		state.peerWindow = uint32(segment.window) << state.peerScale
		if state.peerWindow > state.maximumPeerWindow {
			state.maximumPeerWindow = state.peerWindow
		}
		state.peerWindowSequence = segment.sequence
		state.peerWindowACK = ack
	}
	ackAdvanced := tcpSequenceGreater(ack, state.sendUnacknowledged)
	recoveryAtACK := state.fastRecovery
	hadSACKedAtACK := state.sackedRanges != 0
	newlyDelivered := uint32(0)
	acknowledgedForUndo := uint32(0)
	rttSample := time.Duration(0)
	sampledRTT := false
	partialCumulativeACK := false
	rtoPartialACK := false
	ecnCongestion := false
	hadOutstandingAtACK := len(state.outstanding) != 0
	flightBeforeACK := state.congestionFlight()
	deliveryACK := state.controller.usesDeliveryRate()
	state.processingDeliveryACK = deliveryACK
	state.deliveryACKAddedFlight = 0
	state.deliveryACKPendingSnapshots = false
	if deliveryACK {
		if state.deliverySample == nil {
			state.deliverySample = new(tcpDeliveryRateSample)
		} else {
			*state.deliverySample = tcpDeliveryRateSample{}
		}
		state.deliverySample.ackTime = receivedAt
	}
	if state.ecnRecoveryActive && state.controller.state.Phase == CongestionPhaseCWR && tcpSequenceGreaterEqual(ack, state.ecnRecoveryPoint) {
		state.controller.setCongestionPhase(CongestionPhaseOpen, receivedAt)
	}
	if c.peerECN && segment.flags&TCPFlagECE != 0 && len(state.outstanding) != 0 && tcpECNStartsRecovery(state.ecnRecoveryActive, ack, state.ecnRecoveryPoint) {
		state.hyStart.disable()
		if state.undo != nil {
			state.undo.active = false
		}
		minimumWindow := state.congestionWindow <= uint32(state.peerMSS)
		flight := state.congestionFlight()
		state.slowStartThreshold, state.congestionWindow = state.controller.onECN(state.congestionWindow, flight, state.slowStartThreshold, state.peerMSS, receivedAt)
		state.ecnRecoveryPoint = state.sendNext
		state.ecnRecoveryActive = true
		ecnCongestion = true
		c.sendCWR = true
		if minimumWindow {
			// RFC 3168 section 6.1.2 uses the retransmission interval
			// to reduce an already one-segment sending rate further.
			state.ecnHoldUntil = receivedAt.Add(state.rtt.rto)
			state.controller.cancelPacingWake()
			state.armPacingAt(state.ecnHoldUntil)
		}
	}
	if tcpSequenceGreater(ack, state.sendUnacknowledged) {
		acknowledged := ack - state.sendUnacknowledged
		acknowledgedForUndo = acknowledged
		probeSucceeded := state.pathMTUState != nil && state.pathMTUState.discovery.active && tcpSequenceGreaterEqual(ack, state.pathMTUState.discovery.probeEnd)
		newlyDelivered = tcpNewlyAcknowledgedBytes(state.outstanding, ack)
		state.bytesAcknowledged += uint64(acknowledged)
		c.acknowledgeSend(int(acknowledged))
		state.sendUnacknowledged = ack
		c.publishICMPSequenceRange(state.sendUnacknowledged, state.sendNext)
		state.duplicateACKs = 0
		state.rtoAttempts = 0
		if state.rtoRecovery {
			if tcpSequenceGreaterEqual(ack, state.rtoRecoveryPoint) {
				state.rtoRecovery = false
				state.rtoRecoveryPoint = 0
				state.controller.setCongestionPhase(CongestionPhaseOpen, receivedAt)
				state.ageRACKReordering()
			} else {
				rtoPartialACK = true
			}
		}
		state.blackHoleRTOs = 0
		if state.livenessState != nil {
			state.livenessState.lastSoftError = nil
		}
		if c.peerTimestamp && timestampEcho != 0 {
			delta := c.stack.tcpTimestampAt(receivedAt) - timestampEcho
			if delta != 0 && time.Duration(delta)*time.Millisecond <= tcpMaximumRTO {
				rttSample = time.Duration(delta) * time.Millisecond
				state.rtt.observeAt(rttSample, monotonicStampAt(c.stack.timestampEpoch, receivedAt))
				sampledRTT = true
			}
		}
		// A negotiated timestamp only removes Karn ambiguity when this
		// ACK actually produced a valid timestamp sample. If it did not,
		// the sent-time fallback must still reject a cumulative ACK that
		// covers any retransmitted range.
		ambiguousRTT := tcpACKRTTAmbiguous(state.outstanding, ack)
		for len(state.outstanding) != 0 && tcpSequenceGreaterEqual(ack, state.outstanding[0].end) {
			oldest := state.outstanding[0]
			if deliveryACK {
				state.deliverySample.observe(oldest)
			}
			if oldest.state.has(sentTCPSegmentSACKed) {
				state.sackedRanges--
				state.sackedBytes -= oldest.end - oldest.sequence
			} else {
				state.observeRACKReordering(oldest.end, oldest.isRetransmitted())
			}
			transmittedAt := oldest.transmittedAt(c.stack.timestampEpoch)
			candidate := tcpRACKSample{sentAt: transmittedAt, end: oldest.end, rtt: elapsedRTTSampleAt(transmittedAt, receivedAt), timestamp: oldest.timestamp, retransmitted: oldest.isRetransmitted()}
			state.rackLatestDelivered = newerRACKSample(state.rackLatestDelivered, validRACKSample(candidate, state.rtt.minimum, timestampEcho))
			if !sampledRTT && !ambiguousRTT && !oldest.isRetransmitted() {
				rttSample = elapsedRTTSampleAt(transmittedAt, receivedAt)
				state.rtt.observeAt(rttSample, monotonicStampAt(c.stack.timestampEpoch, receivedAt))
				sampledRTT = true
			}
			if oldest.flags&TCPFlagFIN != 0 {
				state.localFINAcked = true
				c.notifyLingerDone()
			}
			state.outstanding[0] = sentTCPSegment{}
			state.outstanding = state.outstanding[1:]
			state.outstandingHead++
		}
		if len(state.outstanding) == 0 {
			state.outstanding, state.outstandingBase, state.outstandingHead = nil, nil, 0
			state.sackedRanges, state.sackedBytes = 0, 0
		}
		if len(state.outstanding) != 0 && tcpSequenceGreater(ack, state.outstanding[0].sequence) {
			partialCumulativeACK = true
			// Linux samples a partially acknowledged skb before trimming it,
			// but retains its delivery metadata until the remaining range is
			// cumulatively acknowledged. This lets both ACKs contribute a
			// byte-scaled rate sample without treating the prefix as a
			// separately transmitted packet.
			if deliveryACK {
				state.deliverySample.observe(state.outstanding[0])
			}
			if state.outstanding[0].state.has(sentTCPSegmentSACKed) {
				state.sackedBytes -= ack - state.outstanding[0].sequence
			} else {
				state.observeRACKReordering(ack, state.outstanding[0].isRetransmitted())
			}
			transmittedAt := state.outstanding[0].transmittedAt(c.stack.timestampEpoch)
			candidate := tcpRACKSample{sentAt: transmittedAt, end: ack, rtt: elapsedRTTSampleAt(transmittedAt, receivedAt), timestamp: state.outstanding[0].timestamp, retransmitted: state.outstanding[0].isRetransmitted()}
			state.rackLatestDelivered = newerRACKSample(state.rackLatestDelivered, validRACKSample(candidate, state.rtt.minimum, timestampEcho))
			trimAcknowledgedTCPSegment(&state.outstanding[0], ack)
		}
		if probeSucceeded {
			mtu := state.pathMTUState.discovery.success(receivedAt)
			c.stack.confirmPathMTU(c.key.remote.Addr(), mtu, c)
			state.ensurePathMTUState().successes++
			c.stack.stats.pathMTUProbeSuccesses.Add(1)
			if err := operations.applyPathMTU(mtu, false); err != nil {
				return err
			}
		}
		// RFC 3042 excludes Limited Transmit data only when the
		// duplicate-ACK episode that sent it enters recovery. Once a
		// cumulative ACK advances without doing so, every remaining
		// range is ordinary flight for any later loss episode.
		if !state.fastRecovery {
			for index := range state.outstanding {
				state.outstanding[index].state.set(sentTCPSegmentLimited, false)
			}
		}
		if state.tailProbeActive && tcpSequenceGreaterEqual(ack, state.tailProbeEnd) {
			if !state.tailProbeRetransmit {
				state.tailProbeActive = false
			} else if tcpSequenceGreater(ack, state.tailProbeEnd) {
				state.controller.onTailLossProbeRecovered(receivedAt, state.tailProbeBytes, state.tailProbeState, state.congestionWindow, state.slowStartThreshold, flightBeforeACK, state.peerMSS, state.rtt.srtt)
				if !state.fastRecovery {
					if tcpECNStartsRecovery(state.ecnRecoveryActive, state.sendUnacknowledged, state.ecnRecoveryPoint) {
						state.hyStart.disable()
						state.slowStartThreshold, state.congestionWindow = state.controller.onCongestion(state.congestionWindow, flightBeforeACK, state.slowStartThreshold, state.peerMSS, receivedAt)
						// A model-based controller may keep an effectively infinite
						// ssthresh and leave cwnd under its delivery model. The
						// controller therefore owns the post-tail-loss window.
						state.congestionWindow = state.controller.exitRecoveryWindow(receivedAt, state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), state.peerSACK)
						state.ecnRecoveryPoint = state.sendNext
						state.ecnRecoveryActive = true
						if c.peerECN {
							c.sendCWR = true
						}
					}
				}
				state.tailProbeActive = false
				state.tailProbeRetransmit = false
			}
		}
		now := receivedAt
		if state.fastRecovery {
			if tcpSequenceGreaterEqual(ack, state.recoveryPoint) {
				state.ageRACKReordering()
				state.fastRecovery = false
				state.prrPriorFlight = 0
				state.prrDelivered = 0
				state.prrOut = 0
				// Classic controllers deflate to ssthresh when recovery
				// completes. Model-based controllers may instead retain
				// the window maintained by their delivery model.
				state.congestionWindow = state.controller.exitRecoveryWindow(receivedAt, state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), state.peerSACK)
			} else if !state.peerSACK {
				// RFC 6582 NewReno: a partial ACK confirms one loss
				// but not the recovery point. Deflate by newly ACKed
				// data, add one SMSS, and retransmit the next hole.
				state.congestionWindow = state.controller.partialACKWindow(receivedAt, state.congestionWindow, acknowledged, state.congestionFlight(), state.peerMSS)
				if err := operations.retransmitSegment(firstUnsackedSegment(state.outstanding), false); err != nil {
					return err
				}
			}
		} else if !ecnCongestion && !state.controller.usesDeliveryRate() {
			growth := acknowledged
			sample := normalizedRTTSample(rttSample)
			if state.congestionWindow < state.slowStartThreshold {
				var completed bool
				growth, completed = state.hyStart.onACK(ack, state.sendNext, acknowledged, sample)
				if completed {
					state.slowStartThreshold = state.congestionWindow
				}
			}
			state.congestionWindow, state.slowStartThreshold = state.controller.onACKWithThreshold(state.congestionWindow, growth, ack, state.peerMSS, now, state.rtt.srtt, state.rtt.minimum, sample, flightBeforeACK, state.slowStartThreshold, false)
		}
		if target := state.sendAutoTune.target(receivedAt, state.rtt.srtt, state.bytesAcknowledged, c.sendMaximum); target > 0 {
			c.growSendCapacity(target)
		}
		state.armRetransmissionAfterACK(receivedAt)
	}
	history := uint32(state.bytesAcknowledged)
	if state.bytesAcknowledged > uint64(tcpMaximumScaledWindow) {
		history = tcpMaximumScaledWindow
	}
	dsack, hasDSACK := TCPSACKBlock{}, false
	if state.peerSACK {
		dsack, hasDSACK = parseTCPDSACKOption(segment.optionBytes(), ack, state.sendNext, history)
	}
	priorDSACK := state.seenDSACK
	spuriousRecovery := state.undo != nil && ackAdvanced && state.undo.detectEifel(timestampEcho, hasDSACK, priorDSACK, ack)
	if hasDSACK {
		if !state.dsackUndoDisabled {
			matched, repeated := false, false
			if state.retransmitHistory != nil {
				matched, repeated = state.retransmitHistory.match(dsack)
			}
			switch {
			case !matched:
				// RFC 3708 A.4 disables DSACK undo for the rest of
				// this connection after evidence of network duplication.
				state.dsackUndoDisabled = true
				if state.undo != nil {
					state.undo.dsackDisabled = true
				}
			case repeated:
				if state.undo != nil {
					state.undo.dsackDisabled = true
				}
			case state.undo != nil && state.undo.observeDSACK(dsack, ack, previousSendUnacknowledged, sackScoreboardEmpty):
				spuriousRecovery = true
			}
		}
		state.seenDSACK = true
		state.rackReorderingSeen = true
		state.rackReorderPersist = 16
		if !state.rackDSACKRoundSet || tcpSequenceGreater(ack, state.rackDSACKRound) {
			if state.rackReorderingScale != ^uint32(0) {
				state.rackReorderingScale++
			}
			state.rackDSACKRound = state.sendNext
			state.rackDSACKRoundSet = true
		}
		if state.tailProbeActive && state.tailProbeRetransmit && tcpSequenceLess(dsack.LeftEdge, state.tailProbeEnd) && tcpSequenceGreaterEqual(dsack.RightEdge, state.tailProbeEnd) {
			state.tailProbeActive = false
			state.tailProbeRetransmit = false
		}
	}
	if spuriousRecovery && segment.flags&TCPFlagECE != 0 {
		state.undo.active = false
	} else if spuriousRecovery {
		flight := state.ordinaryFlight()
		response := state.undo.eifelRTOResponse()
		state.congestionWindow, state.slowStartThreshold = state.undo.restore(flight, acknowledgedForUndo, state.peerMSS, &state.controller, receivedAt)
		if response.pending {
			if state.eifelRTO == nil {
				state.eifelRTO = new(tcpEifelRTOResponse)
			}
			*state.eifelRTO = response
		}
		state.fastRecovery = false
		state.rtoRecovery = false
		state.rtoRecoveryPoint = 0
		state.prrPriorFlight = 0
		state.prrDelivered = 0
		state.prrOut = 0
		state.ecnRecoveryActive = false
		state.undo.spuriousUndos++
		c.stack.stats.tcpSpuriousRecoveryUndos.Add(1)
		state.armRetransmissionAfterACK(receivedAt)
	}
	if state.eifelRTO != nil && state.eifelRTO.observe(ack, rttSample, &state.rtt) {
		state.eifelRTO = nil
		state.armRetransmissionAfterACK(receivedAt)
	}
	var highestSACK uint32
	hasSACK := false
	newSACKInfo := false
	trackPRRLoss := recoveryAtACK && state.fastRecovery && state.peerSACK
	lostBefore := 0
	if trackPRRLoss {
		lostBefore = sackLostRangeCount(state.outstanding, state.peerMSS)
	}
	if state.peerSACK && len(state.outstanding) != 0 {
		blocks := parseTCPSACKOptions(segment.optionBytes(), state.sendUnacknowledged, state.sendNext)
		var latestSACK tcpRACKSample
		var newlySACKed []sentTCPSegment
		var earliestSACK time.Time
		if len(blocks) != 0 {
			state.compactOutstanding()
			state.outstanding, highestSACK, hasSACK, newSACKInfo, latestSACK, newlySACKed = applyTCPSACK(state.outstanding, blocks, c.stack.timestampEpoch)
			state.rebaseOutstanding()
		}
		if hasSACK {
			state.recountSACK()
		}
		for _, candidate := range newlySACKed {
			newlyDelivered = growCongestionWindow(newlyDelivered, candidate.end-candidate.sequence)
			if deliveryACK {
				state.deliverySample.observe(candidate)
			}
			if !candidate.isRetransmitted() {
				sentAt := candidate.transmittedAt(c.stack.timestampEpoch)
				if earliestSACK.IsZero() || sentAt.Before(earliestSACK) {
					earliestSACK = sentAt
				}
			}
			state.observeRACKReordering(candidate.end, candidate.isRetransmitted())
		}
		if !sampledRTT && !earliestSACK.IsZero() {
			rttSample = elapsedRTTSampleAt(earliestSACK, receivedAt)
			state.rtt.observeAt(rttSample, monotonicStampAt(c.stack.timestampEpoch, receivedAt))
			sampledRTT = true
		}
		latestSACK.rtt = elapsedRTTSampleAt(latestSACK.sentAt, receivedAt)
		state.rackLatestDelivered = newerRACKSample(state.rackLatestDelivered, validRACKSample(latestSACK, state.rtt.minimum, timestampEcho))
		reorderingWindow := rackReorderingWindow(state.rtt.minimum, state.rtt.srtt, state.rackReorderingScale)
		if !state.rackReorderingSeen && (state.fastRecovery || state.rtoRecovery || state.sackedRanges >= tcpDuplicateACKThreshold) {
			reorderingWindow = 0
		}
		if state.rackLatestDelivered.retransmitted || state.sackedRanges != 0 {
			state.haveRACKLoss = markRACKLoss(state.outstanding, state.rackLatestDelivered, receivedAt, reorderingWindow, c.stack.timestampEpoch)
		}
	}
	newlyLost := trackPRRLoss && sackLostRangeCount(state.outstanding, state.peerMSS) > lostBefore
	if recoveryAtACK && state.fastRecovery && state.peerSACK && newlyDelivered != 0 {
		state.prrDelivered += uint64(newlyDelivered)
		pipe := sackRecoveryPipe(state.outstanding, state.peerMSS)
		proposed := prrCongestionWindow(pipe, state.slowStartThreshold, state.prrPriorFlight, state.prrDelivered, state.prrOut, newlyDelivered, ackAdvanced, newlyLost, state.peerMSS)
		state.congestionWindow = state.controller.applyPRRWindow(receivedAt, state.congestionWindow, proposed, pipe)
	}
	probeFailed := false
	if state.pathMTUState != nil && state.pathMTUState.discovery.active && hasSACK && state.sendUnacknowledged == state.pathMTUState.discovery.probeStart && isolatedPLPMTUProbeLoss(state.outstanding, state.pathMTUState.discovery.probeStart, highestSACK, state.peerMSS) {
		if err := operations.failPLPMTUProbe(); err != nil {
			return err
		}
		probeFailed = true
	}
	if hasSACK || state.haveRACKLoss {
		state.recordProvenLosses()
	}
	if state.tailProbeActive && state.tailProbeRetransmit && !ackAdvanced && ack == state.tailProbeEnd && previousWindow == state.peerWindow && !hasSACK && len(segment.payload) == 0 && segment.flags&TCPFlagFIN == 0 {
		state.tailProbeActive = false
		state.tailProbeRetransmit = false
	}
	if deliveryACK && state.tailProbeActive && state.tailProbeRetransmit && ack == state.tailProbeEnd {
		state.deliverySample.tailLossProbeACK = true
	}
	if rtoPartialACK {
		index := firstUnsackedSegment(state.outstanding)
		if state.peerSACK {
			// RFC 8985 avoids the traditional go-back-N behavior after
			// an RTO. A recent higher transmission is retried only after
			// the ACK of the RTO packet supplies time-based loss proof.
			index = firstRACKLoss(state.outstanding)
		}
		if err := operations.retransmitRTORecovery(index); err != nil {
			return err
		}
	}
	if !state.rtoRecovery && state.haveRACKLoss {
		if err := operations.recoverSACKHoles(highestSACK, false); err != nil {
			return err
		}
		state.haveRACKLoss = hasRACKLoss(state.outstanding)
	}
	duplicateEvidence := tcpDuplicateACKEvidence(*segment, state.peerSACK, newSACKInfo, ackAdvanced, state.sendUnacknowledged, previousWindow, state.peerWindow)
	// RFC 6675 DupAcks and Limited Transmit apply before recovery.
	// Once SACK recovery is active, each ACK carrying new scoreboard
	// information drives SetPipe/NextSeg below without re-entering it.
	countDuplicate := duplicateEvidence && (!state.peerSACK || !state.fastRecovery)
	if !probeFailed && !state.rtoRecovery && len(state.outstanding) != 0 && countDuplicate {
		state.duplicateACKs++
		if state.duplicateACKs < tcpDuplicateACKThreshold && !state.fastRecovery {
			// RFC 3042 Limited Transmit permits one new segment for each
			// of the first two duplicate ACKs without inflating cwnd.
			// sendNextData still enforces the receive window and the
			// cumulative cwnd+2*SMSS allowance.
			if _, err := operations.sendNextData(uint32(state.duplicateACKs*state.peerMSS), true); err != nil {
				return err
			}
		} else if state.duplicateACKs == tcpDuplicateACKThreshold {
			if state.peerSACK {
				// RFC 6675 enters recovery after DupThresh ACKs carrying
				// new SACK information even if IsLost remains false.
				if err := operations.retransmitSegment(firstUnsackedSegment(state.outstanding), false); err != nil {
					return err
				}
				if err := operations.recoverSACKHoles(highestSACK, false); err != nil {
					return err
				}
			} else if err := operations.retransmitSegment(firstUnsackedSegment(state.outstanding), false); err != nil {
				return err
			}
		} else if state.duplicateACKs > tcpDuplicateACKThreshold && !state.peerSACK {
			state.congestionWindow = state.controller.duplicateACKWindow(receivedAt, state.congestionWindow, state.congestionFlight(), state.peerMSS)
		}
	}
	if state.fastRecovery && hasSACK {
		if ackAdvanced || newSACKInfo {
			if err := operations.recoverSACKHoles(highestSACK, true); err != nil {
				return err
			}
		}
	}
	if deliveryACK {
		if hadOutstandingAtACK {
			inFlight := state.congestionFlight()
			if state.deliveryACKAddedFlight >= inFlight {
				inFlight = 0
			} else {
				inFlight -= state.deliveryACKAddedFlight
			}
			state.controller.finishDeliveryRateSample(state.deliverySample, newlyDelivered, flightBeforeACK, inFlight, receivedAt, monotonicStampAt(c.stack.timestampEpoch, receivedAt), state.rtt.minimum, state.rtt.srtt, normalizedRTTSample(rttSample))
			state.deliverySample.recovery = state.fastRecovery || state.rtoRecovery
			state.deliverySample.fastRecovery = state.fastRecovery
			// Linux excludes a lone runt packet's delayed ACK when an
			// expired min-RTT sample would otherwise replace the filter.
			state.deliverySample.ackDelayed = ackAdvanced && !partialCumulativeACK && !hadSACKedAtACK && !ecnCongestion && !hasDSACK && !state.deliverySample.recovery && state.deliverySample.losses == 0 && !state.deliverySample.retransmitted && state.deliverySample.acked < uint32(state.peerMSS) && state.deliverySample.delivered == state.deliverySample.acked
			var threshold uint32
			state.congestionWindow, threshold = state.controller.onDeliveryRateSample(state.congestionWindow, state.slowStartThreshold, state.peerMSS, ack, state.deliverySample)
			if threshold != 0 {
				state.slowStartThreshold = threshold
			}
		}
		if state.deliveryACKPendingSnapshots {
			packetsOut := state.sendNext - state.sendUnacknowledged
			for index := range state.outstanding {
				candidate := &state.outstanding[index]
				if !candidate.state.has(sentTCPSegmentDeliveryPending) {
					continue
				}
				candidate.delivery = state.controller.snapshotSend(candidate.hostQueue.queuedAt, packetsOut)
				candidate.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
				candidate.state.set(sentTCPSegmentDeliveryPending, false)
			}
		}
		state.processingDeliveryACK = false
	}
	if multiplier := state.controller.sendBufferMultiplier(); hadOutstandingAtACK && newlyDelivered != 0 && multiplier != 0 {
		// An algorithm may provision multiple cwnds so the application
		// queue cannot starve pacing. growSendCapacity still honors
		// explicit SetWriteBuffer choices, the configured maximum, and
		// its one-step growth bound.
		target := uint64(state.congestionWindow) * uint64(multiplier)
		if target > uint64(c.sendMaximum) {
			target = uint64(c.sendMaximum)
		}
		c.growSendCapacity(int(target))
	}
	return nil
}

// established runs the serialized data, congestion, receive, and close state
// machine. Its handshake-derived arguments belong exclusively to the
// connection actor after entry.
func (c *TCPConn) established(sendNext uint32, actorTimer *ownedTimer, initialReceive tcpInitialReceive) error {
	state := newTCPEstablishedState(c, sendNext)
	defer state.finish()
	var sendNextData func(uint32, bool) (bool, error)
	sendNextData = func(congestionAllowance uint32, limitedTransmit bool) (bool, error) {
		windowFlight := state.sendNext - state.sendUnacknowledged
		congestionFlight := state.congestionFlight()
		now := time.Now()
		if !state.ecnHoldUntil.IsZero() {
			if now.Before(state.ecnHoldUntil) {
				state.armPacingAt(state.ecnHoldUntil)
				return false, nil
			}
			state.ecnHoldUntil = time.Time{}
		}
		if congestionFlight == 0 && !state.lastDataSent.IsZero() && now.Sub(state.lastDataSent) > state.rtt.rto {
			state.congestionWindow = tcpRestartWindow(state.congestionWindow, state.peerMSS)
			state.hyStart.restartRound(state.sendNext)
		}
		congestionLimit := growCongestionWindow(state.congestionWindow, congestionAllowance)
		if state.localFINSent || windowFlight >= state.peerWindow || congestionFlight >= congestionLimit {
			return false, nil
		}
		offset := int(state.sendNext - state.sendUnacknowledged)
		options, dsackSent := state.sackOptions(1)
		optionSize := (len(options) + 3) &^ 3
		if optionSize >= state.pathMSS {
			// Preserve one data byte when an exceptionally small path cannot fit
			// the optional SACK feedback in addition to negotiated timestamps.
			options = nil
			dsackSent = false
			optionSize = 0
		}
		segmentMSS := tcpSegmentPayloadLimit(state.peerMSS, state.pathMSS, optionSize)
		size := segmentMSS
		transmitMTU := c.mtu
		probe := false
		probePayload := 0
		canProbePath := state.pathMTUState != nil && state.pathMTUState.discovery.searching && !state.fastRecovery && !state.rtoRecovery && state.sackedRanges == 0
		if canProbePath {
			candidateMTU, ok := state.pathMTUState.discovery.candidate(now)
			if ok {
				candidateMSS := tcpMSSForMTU(candidateMTU, c.key.local.Addr())
				if c.peerTimestamp {
					candidateMSS -= 12
				}
				candidateMSS = tcpSegmentPayloadLimit(c.peerMSS, candidateMSS, optionSize)
				total, _ := c.sendState()
				if candidateMSS > segmentMSS && total-offset >= candidateMSS+(tcpDuplicateACKThreshold+1)*segmentMSS {
					size = candidateMSS
					probePayload = candidateMSS
					transmitMTU = candidateMTU
					probe = true
				}
			}
		}
		if available := int(state.peerWindow - windowFlight); size > available {
			size = available
		}
		if available := int(congestionLimit - congestionFlight); size > available {
			size = available
		}
		if probe && size != probePayload {
			probe = false
			transmitMTU = c.mtu
			if size > segmentMSS {
				size = segmentMSS
			}
		}
		if size <= 0 {
			return false, nil
		}
		var payload tcpPayloadView
		total, writeClosed := c.sendView(offset, size, &payload)
		if payload.size == 0 {
			return false, nil
		}
		if delay := state.controller.pacingDelay(now, payload.size, state.congestionWindow, congestionFlight, state.peerMSS, state.rtt.srtt, state.slowStartThreshold); delay > 0 {
			state.armPacingAt(now.Add(delay))
			return false, nil
		}
		if congestionAllowance == 0 {
			if !c.socketOptions().noDelay && len(state.outstanding) != 0 && payload.size < segmentMSS && !writeClosed {
				return false, nil
			}
		}
		flags := byte(TCPFlagACK)
		if offset+payload.size == total {
			flags |= TCPFlagPSH
		}
		next := state.sendNext + uint32(payload.size)
		carriesCWR := c.peerECN && c.sendCWR
		c.publishICMPSequenceRange(state.sendUnacknowledged, next)
		window := state.advertisedReceiveWindow()
		timestamp, hostQueue, err := c.sendPayloadForMTU(state.sendNext, state.receiveNext, flags, window, options, &payload, true, transmitMTU)
		if err != nil {
			return false, err
		}
		sentAt := hostQueue.queuedTime(c.stack.timestampEpoch)
		state.lastACKSent = state.receiveNext
		state.lastAdvertisedWindow = window
		if dsackSent {
			state.haveRecentDSACK = false
		}
		if state.ackPending {
			state.clearDelayedACK()
		}
		// Delivery sampling resets its pipeline timestamps only when packets_out
		// is zero. SACKed or loss-marked data therefore remains part of the first
		// argument even when it is no longer congestion flight.
		rate, updatedWindow := state.controller.onDataSend(payload.size, state.peerMSS, sentAt, hostQueue.queuedAt, windowFlight, state.congestionWindow, congestionFlight, state.rtt.srtt, state.slowStartThreshold)
		state.congestionWindow = updatedWindow
		state.appendOutstanding(sentTCPSegment{sequence: state.sendNext, end: next, flags: flags, timestamp: timestamp, state: sentTCPSegmentInitialState(limitedTransmit, carriesCWR, probe, state.processingDeliveryACK, state.controller.schedulerLimited()), firstSent: sentAt.Sub(c.stack.timestampEpoch), hostQueue: hostQueue, congestionPacketState: state.controller.transmissionState(), delivery: rate})
		if state.processingDeliveryACK {
			state.deliveryACKAddedFlight = growCongestionWindow(state.deliveryACKAddedFlight, uint32(payload.size))
			state.deliveryACKPendingSnapshots = true
		}
		state.bytesSent += uint64(payload.size)
		if probe {
			state.pathMTUState.discovery.sent(transmitMTU, state.sendNext, next)
			state.ensurePathMTUState().probes++
			c.stack.stats.pathMTUProbes.Add(1)
		}
		if state.fastRecovery && state.peerSACK {
			state.prrOut += uint64(payload.size)
		}
		state.sendNext = next
		state.lastDataSent = sentAt
		return true, nil
	}
	fillWindow := func() error {
		defer state.armLiveness()
		if state.localFINSent {
			state.armPersist(time.Time{})
			return nil
		}
		for {
			sent, err := sendNextData(0, false)
			if err != nil {
				return err
			}
			if !sent {
				break
			}
		}
		if !state.ecnHoldUntil.IsZero() && time.Now().Before(state.ecnHoldUntil) {
			return nil
		}
		windowFlight := state.sendNext - state.sendUnacknowledged
		congestionFlight := state.congestionFlight()
		offset := int(state.sendNext - state.sendUnacknowledged)
		total, writeClosed := c.sendState()
		hostQueued := false
		if state.controller.usesDeliveryRate() && total-offset < state.peerMSS && len(state.outstanding) != 0 {
			// The output queue is FIFO. If this connection's newest range has
			// left it, every older range from the connection has left as well.
			hostQueued = state.outstanding[len(state.outstanding)-1].hostQueue.pending(c.stack)
		}
		if state.controller.usesDeliveryRate() && tcpRateApplicationLimited(total-offset, hostQueued, congestionFlight, state.congestionWindow, state.fastRecovery, state.peerSACK, state.outstanding, state.peerMSS) {
			// Match Linux tcp_rate_check_app_limited: only an application
			// bubble, rather than a congestion- or receive-window limit, marks
			// delivery samples as application limited.
			state.controller.markApplicationLimited(congestionFlight)
		}
		if writeClosed && offset >= total && windowFlight < state.peerWindow && congestionFlight < state.congestionWindow {
			c.publishICMPSequenceRange(state.sendUnacknowledged, state.sendNext+1)
			options, dsackSent := state.sackOptions(0)
			window := state.advertisedReceiveWindow()
			timestamp, hostQueue, err := c.sendSegmentForMTU(state.sendNext, state.receiveNext, TCPFlagACK|TCPFlagFIN, window, options, nil, false, c.mtu)
			if err != nil {
				return err
			}
			sentAt := hostQueue.queuedTime(c.stack.timestampEpoch)
			state.lastACKSent = state.receiveNext
			state.lastAdvertisedWindow = window
			if dsackSent {
				state.haveRecentDSACK = false
			}
			state.appendOutstanding(sentTCPSegment{sequence: state.sendNext, end: state.sendNext + 1, flags: TCPFlagACK | TCPFlagFIN, timestamp: timestamp, state: sentTCPSegmentTransmitted, firstSent: sentAt.Sub(c.stack.timestampEpoch), hostQueue: hostQueue})
			state.sendNext++
			// Only the endpoint that closes first, or closes simultaneously,
			// enters TIME-WAIT. A FIN sent after the peer's FIN is LAST-ACK.
			state.timeWaitRequired = !state.remoteFINReceived
			state.localFINSent = true
			if state.ackPending {
				state.clearDelayedACK()
			}
		}
		if len(state.outstanding) != 0 {
			state.armRetransmission()
		} else if !state.localFINAcked {
			state.armRetransmission()
		}
		state.armPersist(time.Time{})
		return nil
	}
	retransmitSegment := func(index int, timeout bool) error {
		if len(state.outstanding) == 0 {
			return nil
		}
		if index < 0 || index >= len(state.outstanding) {
			index = firstUnsackedSegment(state.outstanding)
		}
		if index < 0 || index >= len(state.outstanding) {
			return nil
		}
		if state.pathMTUState != nil && state.pathMTUState.discovery.active {
			retransmitSequence := state.outstanding[index].sequence
			delay := tcpPLPMTUProbeHeadway(state.congestionWindow, state.peerMSS, state.rtt.srtt)
			if timeout {
				delay = tcpPLPMTUTimeoutDelay(delay)
			}
			state.pathMTUState.discovery.inconclusive(time.Now(), delay)
			for segmentIndex := range state.outstanding {
				state.outstanding[segmentIndex].state.set(sentTCPSegmentMTUProbe, false)
			}
			state.outstanding = splitTCPSegments(state.outstanding, state.peerMSS)
			state.rebaseOutstanding()
			if state.sackedRanges != 0 {
				state.recountSACK()
			}
			index = -1
			for segmentIndex := range state.outstanding {
				if state.outstanding[segmentIndex].sequence == retransmitSequence {
					index = segmentIndex
					break
				}
			}
			if index < 0 {
				index = firstUnsackedSegment(state.outstanding)
			}
			state.armPathMTUProbe()
		}
		if index < 0 || index >= len(state.outstanding) {
			return nil
		}
		oldest := &state.outstanding[index]
		sentSize := oldest.end - oldest.sequence
		rackRetransmission := oldest.state.has(sentTCPSegmentRACKLost)
		lostRetransmission := rackRetransmission && oldest.isRetransmitted()
		lostCWR := oldest.state.has(sentTCPSegmentCWR)
		beginUndo := timeout && !state.rtoRecovery || !timeout && (!state.fastRecovery || lostRetransmission)
		if beginUndo {
			flight := state.ordinaryFlight()
			if !timeout {
				flight = state.controller.recoveryFlight(time.Now(), flight, lossRecoveryFlightSize(state.outstanding))
			}
			if state.undo == nil {
				state.undo = new(tcpRecoveryUndo)
			}
			state.undo.begin(timeout, state.sendNext, state.congestionWindow, state.slowStartThreshold, flight, &state.controller, state.rtt)
		}
		window := state.advertisedReceiveWindow()
		repeated := oldest.isRetransmitted()
		retransmitTimestamp, hostQueue, err := c.sendBufferedSegmentForMTU(state.sendUnacknowledged, *oldest, state.receiveNext, window, nil, false, c.mtu)
		if err != nil {
			return err
		}
		state.recordRetransmission(oldest.sequence, oldest.end)
		if state.undo != nil {
			state.undo.recordRetransmission(oldest.sequence, oldest.end, retransmitTimestamp, repeated)
		}
		state.lastACKSent = state.receiveNext
		state.lastAdvertisedWindow = window
		oldest.timestamp = retransmitTimestamp
		oldest.hostQueue = hostQueue
		lossProven := timeout || !state.peerSACK || sackSegmentLost(state.outstanding, index, state.peerMSS)
		state.controller.notePacketLoss(oldest, recordTCPSegmentLoss(oldest, lossProven), state.processingDeliveryACK, state.lossObservationTime(), state.congestionWindow, state.slowStartThreshold, state.congestionFlight(), state.peerMSS, state.rtt.srtt)
		oldest.advanceTransmissionGeneration()
		oldest.state.set(sentTCPSegmentSACKRetried, !timeout)
		oldest.state.set(sentTCPSegmentRACKLost, false)
		if rackRetransmission {
			state.haveRACKLoss = hasRACKLoss(state.outstanding)
		}
		oldest.state.set(sentTCPSegmentCWR, false)
		c.noteRetransmission()
		if !timeout && state.peerSACK {
			c.stack.stats.tcpSACKRetransmissions.Add(1)
			if rackRetransmission {
				c.stack.stats.tcpRACKRetransmissions.Add(1)
			}
		}
		if timeout {
			state.tailProbeActive = false
			state.tailProbeRetransmit = false
			flight := state.ordinaryFlight()
			// RFC 5681 updates ssthresh only on the first timeout for one
			// outstanding sequence range. Recomputing it after cwnd has already
			// fallen to one SMSS would collapse a loss-based retained threshold on
			// every exponential-backoff retry.
			if !state.rtoRecovery {
				state.hyStart.disable()
				state.slowStartThreshold = state.controller.onTimeout(state.congestionWindow, flight, state.slowStartThreshold, state.peerMSS, oldest.transmittedAt(c.stack.timestampEpoch))
				state.rtoRecovery = true
				state.rtoRecoveryPoint = state.sendNext
				if c.peerECN {
					c.sendCWR = true
				}
			}
			state.congestionWindow = uint32(state.peerMSS)
			state.fastRecovery = false
			state.prrPriorFlight = 0
			state.prrDelivered = 0
			state.prrOut = 0
			state.ecnRecoveryPoint = state.sendNext
			state.ecnRecoveryActive = true
			for index := range state.outstanding {
				state.outstanding[index].state.set(sentTCPSegmentSACKed, false)
				state.outstanding[index].state.set(sentTCPSegmentSACKRetried, false)
				state.outstanding[index].state.set(sentTCPSegmentRACKLost, false)
			}
			state.sackedRanges, state.sackedBytes = 0, 0
			state.haveRACKLoss = false
			state.rtt.backoff()
		} else {
			state.tailProbeActive = false
			state.tailProbeRetransmit = false
			if !state.fastRecovery || lostRetransmission {
				state.hyStart.disable()
				ordinary := state.ordinaryFlight()
				flight := state.controller.recoveryFlight(oldest.transmittedAt(c.stack.timestampEpoch), ordinary, lossRecoveryFlightSize(state.outstanding))
				// RFC 3042 excludes Limited Transmit data only from the
				// FlightSize calculation that enters this recovery episode. Any
				// still-unacknowledged range is ordinary flight in later episodes.
				for index := range state.outstanding {
					state.outstanding[index].state.set(sentTCPSegmentLimited, false)
				}
				// RFC 3168 permits only one congestion-window reduction for
				// dropped and/or CE-marked packets from one transmitted window.
				// A lost retransmission is the RFC 8985 exception: it is a new
				// congestion indication even while the original recovery is active.
				if lostRetransmission || lostCWR || tcpECNStartsRecovery(state.ecnRecoveryActive, state.sendUnacknowledged, state.ecnRecoveryPoint) {
					state.slowStartThreshold, state.congestionWindow = state.controller.onCongestion(state.congestionWindow, flight, state.slowStartThreshold, state.peerMSS, oldest.transmittedAt(c.stack.timestampEpoch))
					state.ecnRecoveryPoint = state.sendNext
					state.ecnRecoveryActive = true
					if c.peerECN {
						c.sendCWR = true
					}
				}
				state.congestionWindow = state.controller.recoveryWindow(oldest.transmittedAt(c.stack.timestampEpoch), state.congestionWindow, flight, state.slowStartThreshold, state.peerMSS, state.peerSACK)
				state.fastRecovery = true
				state.recoveryPoint = state.sendNext
				if state.peerSACK {
					state.prrPriorFlight = flight
					state.prrDelivered = 0
					state.prrOut = uint64(sentSize)
					// Linux PRR admits exactly the forced recovery-entry
					// retransmission before delivery feedback grants more.
					state.congestionWindow = sackRecoveryPipe(state.outstanding, state.peerMSS)
				}
			} else if state.peerSACK {
				state.prrOut += uint64(sentSize)
			}
		}
		if len(state.outstanding) != 0 {
			state.armRetransmission()
		}
		oldest.delivery = state.controller.onRetransmit(oldest.dataSize(), state.peerMSS, oldest.transmittedAt(c.stack.timestampEpoch), oldest.hostQueue.queuedAt, state.congestionWindow, state.congestionFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
		oldest.congestionPacketState = state.controller.transmissionState()
		oldest.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
		oldest.state.set(sentTCPSegmentDeliveryPending, state.processingDeliveryACK)
		if state.processingDeliveryACK && state.peerSACK && state.fastRecovery {
			state.deliveryACKAddedFlight = growCongestionWindow(state.deliveryACKAddedFlight, uint32(oldest.dataSize()))
		}
		state.deliveryACKPendingSnapshots = state.deliveryACKPendingSnapshots || state.processingDeliveryACK
		return nil
	}
	retransmitRTORecovery := func(index int) error {
		if len(state.outstanding) == 0 {
			return nil
		}
		if index < 0 || index >= len(state.outstanding) {
			return nil
		}
		segment := &state.outstanding[index]
		window := state.advertisedReceiveWindow()
		retransmitTimestamp, hostQueue, err := c.sendBufferedSegmentForMTU(state.sendUnacknowledged, *segment, state.receiveNext, window, nil, false, c.mtu)
		if err != nil {
			return err
		}
		state.recordRetransmission(segment.sequence, segment.end)
		if state.undo != nil {
			state.undo.recordRetransmission(segment.sequence, segment.end, retransmitTimestamp, segment.isRetransmitted())
		}
		state.lastACKSent = state.receiveNext
		state.lastAdvertisedWindow = window
		if segment.state.has(sentTCPSegmentCWR) && c.peerECN {
			c.sendCWR = true
		}
		segment.state.set(sentTCPSegmentCWR, false)
		segment.timestamp = retransmitTimestamp
		segment.hostQueue = hostQueue
		state.controller.notePacketLoss(segment, recordTCPSegmentLoss(segment, true), state.processingDeliveryACK, state.lossObservationTime(), state.congestionWindow, state.slowStartThreshold, state.ordinaryFlight(), state.peerMSS, state.rtt.srtt)
		segment.advanceTransmissionGeneration()
		segment.state.set(sentTCPSegmentSACKRetried, false)
		rackLost := segment.state.has(sentTCPSegmentRACKLost)
		segment.state.set(sentTCPSegmentRACKLost, false)
		if rackLost {
			state.haveRACKLoss = hasRACKLoss(state.outstanding)
		}
		state.tailProbeActive = false
		state.tailProbeRetransmit = false
		c.noteRetransmission()
		segment.delivery = state.controller.onRetransmit(segment.dataSize(), state.peerMSS, segment.transmittedAt(c.stack.timestampEpoch), segment.hostQueue.queuedAt, state.congestionWindow, state.ordinaryFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
		segment.congestionPacketState = state.controller.transmissionState()
		segment.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
		segment.state.set(sentTCPSegmentDeliveryPending, state.processingDeliveryACK)
		state.deliveryACKPendingSnapshots = state.deliveryACKPendingSnapshots || state.processingDeliveryACK
		state.armRetransmission()
		return nil
	}
	failPLPMTUProbe := func() error {
		if state.pathMTUState == nil || !state.pathMTUState.discovery.active {
			return nil
		}
		state.pathMTUState.discovery.failed(time.Now(), tcpPLPMTUProbeHeadway(state.congestionWindow, state.peerMSS, state.rtt.srtt))
		if !state.pathMTUState.discovery.searching {
			// Convergence reconfirms the working lower bound so an expired
			// destination-cache entry cannot immediately restart probing.
			c.stack.confirmPathMTU(c.key.remote.Addr(), c.mtu, c)
		}
		for index := range state.outstanding {
			segment := &state.outstanding[index]
			if segment.state.has(sentTCPSegmentMTUProbe) {
				// RFC 4821 suppresses congestion response for this isolated
				// probe generation; split pieces inherit the suppression marker.
				segment.state |= sentTCPSegmentLossReported
			}
			segment.state.set(sentTCPSegmentMTUProbe, false)
		}
		state.outstanding = splitTCPSegments(state.outstanding, state.peerMSS)
		state.rebaseOutstanding()
		if state.sackedRanges != 0 {
			state.recountSACK()
		}
		index := firstUnsackedSegment(state.outstanding)
		if index < 0 || index >= len(state.outstanding) {
			state.armPathMTUProbe()
			return nil
		}
		segment := &state.outstanding[index]
		window := state.advertisedReceiveWindow()
		timestamp, hostQueue, err := c.sendBufferedSegmentForMTU(state.sendUnacknowledged, *segment, state.receiveNext, window, nil, false, c.mtu)
		if err != nil {
			return err
		}
		state.recordRetransmission(segment.sequence, segment.end)
		segment.timestamp = timestamp
		segment.hostQueue = hostQueue
		segment.state.set(sentTCPSegmentRACKLost, false)
		segment.advanceTransmissionGeneration()
		segment.state.set(sentTCPSegmentSACKRetried, true)
		state.haveRACKLoss = hasRACKLoss(state.outstanding)
		state.lastACKSent = state.receiveNext
		state.lastAdvertisedWindow = window
		c.noteRetransmission()
		state.ensurePathMTUState().failures++
		c.stack.stats.pathMTUProbeFailures.Add(1)
		segment.delivery = state.controller.onRetransmit(segment.dataSize(), state.peerMSS, segment.transmittedAt(c.stack.timestampEpoch), segment.hostQueue.queuedAt, state.congestionWindow, state.congestionFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
		segment.congestionPacketState = state.controller.transmissionState()
		segment.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
		segment.state.set(sentTCPSegmentDeliveryPending, state.processingDeliveryACK)
		if state.processingDeliveryACK && state.peerSACK && state.fastRecovery {
			state.deliveryACKAddedFlight = growCongestionWindow(state.deliveryACKAddedFlight, uint32(segment.dataSize()))
		}
		state.deliveryACKPendingSnapshots = state.deliveryACKPendingSnapshots || state.processingDeliveryACK
		state.armRetransmission()
		state.armPathMTUProbe()
		return nil
	}
	recoverSACKHoles := func(highest uint32, allowSpeculative bool) error {
		for {
			index := firstUnretriedLoss(state.outstanding, state.peerMSS)
			if index < 0 && allowSpeculative {
				index = firstUnretriedSACKHole(state.outstanding, highest)
			}
			if index < 0 {
				return nil
			}
			size := state.outstanding[index].end - state.outstanding[index].sequence
			pipe := sackRecoveryPipe(state.outstanding, state.peerMSS)
			// RFC 6675 permits the recovery-entry retransmission before
			// SetPipe, but every later transmission requires cwnd-Pipe space.
			if !sackRecoveryCanSend(state.fastRecovery, pipe, size, state.congestionWindow) {
				return nil
			}
			if state.fastRecovery {
				now := time.Now()
				if delay := state.controller.pacingDelay(now, int(size), state.congestionWindow, pipe, state.peerMSS, state.rtt.srtt, state.slowStartThreshold); delay > 0 {
					state.armPacingAt(now.Add(delay))
					return nil
				}
			}
			if err := retransmitSegment(index, false); err != nil {
				return err
			}
		}
	}
	applyPathMTU := func(mtu int, retransmit bool) error {
		options := c.socketOptions()
		state.changeCongestionController(options.congestionFactory, options.maximumPacingRate)
		priorMTU := c.mtu
		c.mtu = mtu
		if mtu < priorMTU {
			for index := range state.outstanding {
				state.outstanding[index].state.set(sentTCPSegmentMTUProbe, false)
			}
			state.ensurePathMTUState().discovery.reduce(mtu, priorMTU, c.stack.network.Load().mtu, time.Now())
		}
		state.pathMSS = tcpMSSForMTU(mtu, c.key.local.Addr())
		if c.peerTimestamp {
			state.pathMSS -= 12
		}
		state.receiveMSS = state.pathMSS
		state.armPathMTUProbe()
		newMSS := clampMSS(c.peerMSS, state.pathMSS)
		if newMSS == state.peerMSS {
			return nil
		}
		if newMSS > state.peerMSS {
			state.peerMSS = newMSS
			state.controller.onMTUChange(state.congestionWindow, state.slowStartThreshold, state.peerMSS)
			return nil
		}
		oldMSS := state.peerMSS
		state.peerMSS = newMSS
		state.congestionWindow = tcpCongestionValueForMSS(state.congestionWindow, oldMSS, newMSS, true)
		if state.slowStartThreshold != ^uint32(0)>>1 {
			state.slowStartThreshold = tcpCongestionValueForMSS(state.slowStartThreshold, oldMSS, newMSS, false)
		}
		state.controller.onMTUChange(state.congestionWindow, state.slowStartThreshold, state.peerMSS)
		state.outstanding = splitTCPSegments(state.outstanding, state.peerMSS)
		state.rebaseOutstanding()
		if state.sackedRanges != 0 {
			state.recountSACK()
		}
		if retransmit && len(state.outstanding) != 0 {
			index := firstUnsackedSegment(state.outstanding)
			segment := &state.outstanding[index]
			window := state.advertisedReceiveWindow()
			timestamp, hostQueue, err := c.sendBufferedSegmentForMTU(state.sendUnacknowledged, *segment, state.receiveNext, window, nil, false, c.mtu)
			if err != nil {
				return err
			}
			state.recordRetransmission(segment.sequence, segment.end)
			state.lastACKSent = state.receiveNext
			state.lastAdvertisedWindow = window
			if segment.state.has(sentTCPSegmentCWR) && c.peerECN {
				c.sendCWR = true
			}
			segment.state.set(sentTCPSegmentCWR, false)
			segment.timestamp = timestamp
			segment.hostQueue = hostQueue
			segment.advanceTransmissionGeneration()
			c.noteRetransmission()
			segment.delivery = state.controller.onRetransmit(segment.dataSize(), state.peerMSS, segment.transmittedAt(c.stack.timestampEpoch), segment.hostQueue.queuedAt, state.congestionWindow, state.congestionFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
			segment.congestionPacketState = state.controller.transmissionState()
			segment.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
			segment.state.set(sentTCPSegmentDeliveryPending, state.processingDeliveryACK)
			state.deliveryACKPendingSnapshots = state.deliveryACKPendingSnapshots || state.processingDeliveryACK
			state.armRetransmission()
		}
		return nil
	}
	ackOperations := tcpEstablishedACKOperations{
		applyPathMTU:          applyPathMTU,
		retransmitSegment:     retransmitSegment,
		failPLPMTUProbe:       failPLPMTUProbe,
		retransmitRTORecovery: retransmitRTORecovery,
		recoverSACKHoles:      recoverSACKHoles,
		sendNextData:          sendNextData,
	}
	if len(initialReceive.payload) != 0 || initialReceive.fin {
		payload := initialReceive.payload
		fin := initialReceive.fin
		previousReceiveNext := state.receiveNext
		_, closed := c.receiveTCPData(state.receiveNext, payload, fin, state.receiveWindowState.size(state.receiveNext), &state.receiveNext, &state.outOfOrder, &state.outOfOrderBytes)
		advanced := state.receiveNext - previousReceiveNext
		if closed && advanced != 0 {
			advanced--
		}
		state.bytesReceived += uint64(advanced)
		if closed {
			state.remoteFINReceived = true
			c.setReadEOF()
		}
		if err := state.scheduleACK(true, len(payload) != 0, time.Now()); err != nil {
			return err
		}
	}
	state.armPathMTUProbe()
	state.armLiveness()
	var timerBacklog tcpTimerBacklog
	const (
		actorTimerNone = iota
		actorTimerRetransmission
		actorTimerPersist
		actorTimerDelayedACK
		actorTimerLiveness
		actorTimerPathMTU
		actorTimerPacing
	)
	for {
		var activeRetransmit, activePersist, activeDelayedACK <-chan time.Time
		var activeLiveness, activePathMTUProbe, activePacing <-chan time.Time
		inboundNotify := c.inbound.notify
		var earliestTimer time.Time
		nextActorTimer := actorTimerNone
		for _, timer := range [...]struct {
			active   bool
			deadline time.Time
			kind     int
		}{
			{state.retransmit, state.retransmissionDeadline, actorTimerRetransmission},
			{state.persist, state.persistDeadline, actorTimerPersist},
			{state.delayedACK, state.delayedACKDeadline, actorTimerDelayedACK},
			{state.liveness, state.livenessDeadline, actorTimerLiveness},
			{state.pathMTUProbe, state.pathMTUDeadline, actorTimerPathMTU},
			{state.pacing, state.pacingDeadline, actorTimerPacing},
		} {
			if timer.active && !timer.deadline.IsZero() && (earliestTimer.IsZero() || timer.deadline.Before(earliestTimer)) {
				earliestTimer = timer.deadline
				nextActorTimer = timer.kind
			}
		}
		if earliestTimer.IsZero() {
			if state.actorTimerChannel != nil {
				actorTimer.stop()
				state.actorTimerChannel = nil
				state.actorTimerDeadline = time.Time{}
			}
		} else if state.actorTimerChannel == nil || !state.actorTimerDeadline.Equal(earliestTimer) {
			state.actorTimerChannel = actorTimer.reset(time.Until(earliestTimer))
			state.actorTimerDeadline = earliestTimer
		}
		// Only the earliest logical timer receives the physical timer channel.
		// Equal deadlines follow this fixed protocol-priority order instead of
		// depending on select's randomized choice.
		switch nextActorTimer {
		case actorTimerRetransmission:
			activeRetransmit = state.actorTimerChannel
		case actorTimerPersist:
			activePersist = state.actorTimerChannel
		case actorTimerDelayedACK:
			activeDelayedACK = state.actorTimerChannel
		case actorTimerLiveness:
			activeLiveness = state.actorTimerChannel
		case actorTimerPathMTU:
			activePathMTUProbe = state.actorTimerChannel
		case actorTimerPacing:
			activePacing = state.actorTimerChannel
		}
		drainBacklog, forceTimer := timerBacklog.order(c.inbound.len(), earliestTimer, time.Now())
		if drainBacklog {
			activeRetransmit, activePersist, activeDelayedACK = nil, nil, nil
			activeLiveness, activePathMTUProbe, activePacing = nil, nil, nil
		} else if forceTimer && c.actorWakeFlags.Load() == 0 {
			inboundNotify = nil
		}
		select {
		case <-inboundNotify:
			wake := c.takeActorWake()
			if wake&tcpActorWakeNetworkError != 0 {
				for {
					err, ok := c.takeNetworkError()
					if !ok {
						break
					}
					// ICMP failures on an established TCP flow are soft errors. TCP
					// retransmission and its bounded timeout decide whether the stream
					// is actually unusable.
					state.ensureLivenessState().lastSoftError = err
					if tcpRevertRTOBackoff(err, state.sendUnacknowledged, state.rtoAttempts, &state.rtt) {
						state.armRetransmission()
					}
				}
			}
			fillSendWindow := wake&(tcpActorWakeSend|tcpActorWakeWindow|tcpActorWakeOptions) != 0
			if wake&tcpActorWakePathMTU != 0 {
				if err := applyPathMTU(state.effectivePathMTU(), true); err != nil {
					return err
				}
			}
			if wake&tcpActorWakeOptions != 0 {
				// Linux reinitializes only congestion-controller private state.
				// The established connection's cwnd and ssthresh remain transport
				// state across a TCP_CONGESTION change.
				options := c.socketOptions()
				state.changeCongestionController(options.congestionFactory, options.maximumPacingRate)
				if state.livenessState != nil {
					state.livenessState.keepAliveProbes = 0
					state.livenessState.lastKeepAlive = time.Time{}
				}
				state.armLiveness()
			}
			if wake&tcpActorWakeWindow != 0 {
				now := time.Now()
				if target := state.receiveAutoTune.target(now, state.rtt.srtt, c.applicationReads.Load(), c.receiveMaximum); target > 0 {
					c.growReceiveCapacity(target)
				}
				if c.discardingReads() {
					state.outOfOrder = nil
					state.outOfOrderBytes = 0
					c.outOfOrderUnread.Store(0)
				} else if len(state.outOfOrder) != 0 {
					previousReceiveNext := state.receiveNext
					_, closed := c.promoteTCPReceived(&state.receiveNext, &state.outOfOrder, &state.outOfOrderBytes)
					advanced := state.receiveNext - previousReceiveNext
					if closed && advanced != 0 {
						advanced--
					}
					state.bytesReceived += uint64(advanced)
					if closed {
						state.remoteFINReceived = true
						c.setReadEOF()
					}
					if state.receiveNext != previousReceiveNext {
						if err := state.scheduleACK(true, false, time.Now()); err != nil {
							return err
						}
					}
				}
				available, capacity := c.receiveSpace(state.outOfOrderBytes)
				window, _ := state.receiveWindowState.next(state.receiveNext, available, tcpReceiveWindowIncrease(capacity, state.receiveMSS))
				if window > state.lastAdvertisedWindow {
					if err := state.scheduleACK(state.lastAdvertisedWindow == 0, false, time.Now()); err != nil {
						return err
					}
				}
			}
			if fillSendWindow {
				if err := fillWindow(); err != nil {
					return err
				}
			}
			if wake&tcpActorWakeSend != 0 && state.localFINAcked && !state.remoteFINReceived && !state.finWaitArmed && c.applicationReceiveClosed() {
				state.armClose(time.Now(), tcpFINWaitDuration)
				state.finWaitArmed = true
			}
			if wake&tcpActorWakeInfo != 0 {
				c.respondTCPConnInfo(c.takeInfoRequests(), state.tcpInfo())
			}

			segment, ok := c.inbound.dequeue()
			if !ok {
				continue
			}
			timerBacklog.consumed()
			processedAt := time.Now()
			receivedAt := tcpSegmentEventTime(segment, processedAt, state.eventTime, c.stack.timestampEpoch)
			// Device receive functions may call Stack.Write concurrently. Keep
			// the actor's protocol clock monotonic even if lock acquisition puts
			// two batches into its FIFO in the opposite timestamp order.
			state.eventTime = receivedAt
			segmentLength := uint32(len(segment.payload))
			if segment.flags&TCPFlagSYN != 0 {
				segmentLength++
			}
			if segment.flags&TCPFlagFIN != 0 {
				segmentLength++
			}
			receiveWindow := state.receiveWindowState.size(state.receiveNext)
			retransmittedTimeWaitFIN := state.timeWaitArmed && segment.flags&(TCPFlagRST|TCPFlagSYN) == 0 &&
				segment.flags&(TCPFlagACK|TCPFlagFIN) == TCPFlagACK|TCPFlagFIN &&
				segment.sequence+uint32(len(segment.payload))+1 == state.receiveNext
			if !tcpSegmentAcceptable(segment.sequence, segmentLength, state.receiveNext, receiveWindow) {
				if retransmittedTimeWaitFIN {
					if err := state.sendACK(); err != nil {
						return err
					}
					state.armClose(time.Now(), tcpTimeWaitDuration)
					continue
				}
				if segment.flags&TCPFlagRST == 0 {
					var err error
					if tcpKeepAliveOrWindowProbe(segment, segmentLength, state.receiveNext, receiveWindow) {
						err = state.sendACK()
					} else {
						sequence := tcpChallengeACKSequence(segment, state.sendUnacknowledged, state.sendNext, state.peerWindow, state.peerScale)
						err = state.sendChallengeACKAt(sequence)
					}
					if err != nil {
						return err
					}
				}
				continue
			}
			timestampEcho := uint32(0)
			if c.peerTimestamp && segment.flags&TCPFlagRST == 0 {
				timestampValue, echo, present := parseTCPTimestamp(segment.optionBytes())
				if !present {
					continue
				}
				timestampEcho = echo
				if receivedAt.Sub(state.lastTimestampUpdate) < 24*24*time.Hour && tcpSequenceLess(timestampValue, c.recentTimestamp) {
					if err := state.sendChallengeACK(); err != nil {
						return err
					}
					continue
				}
				if tcpSequenceLessEqual(segment.sequence, state.lastACKSent) {
					c.recentTimestamp = timestampValue
					state.lastTimestampUpdate = receivedAt
				}
			}
			state.lastActivity = receivedAt
			if state.livenessState != nil {
				state.livenessState.lastKeepAlive = time.Time{}
				state.livenessState.keepAliveProbes = 0
			}
			state.armLiveness()
			if c.peerECN {
				if segment.flags&TCPFlagCWR != 0 {
					c.echoCongestion = false
				}
				if segment.ecn == 3 {
					c.echoCongestion = true
				}
			}
			if segment.flags&TCPFlagRST != 0 {
				if segment.sequence == state.receiveNext {
					return syscall.ECONNRESET
				}
				if err := state.sendChallengeACK(); err != nil {
					return err
				}
				continue
			}
			if segment.flags&TCPFlagSYN != 0 {
				if err := state.sendChallengeACK(); err != nil {
					return err
				}
				continue
			}
			if segment.flags&TCPFlagACK == 0 {
				continue
			}
			ack := segment.acknowledgement
			if tcpSequenceGreater(ack, state.sendNext) {
				if err := state.sendChallengeACK(); err != nil {
					return err
				}
				continue
			}
			if tcpSequenceLess(ack, state.sendUnacknowledged) {
				oldestAcceptable := state.maximumPeerWindow
				if uint64(oldestAcceptable) > state.bytesAcknowledged {
					oldestAcceptable = uint32(state.bytesAcknowledged)
				}
				// RFC 5961 section 5.2 and Linux reject an ACK older than both
				// the largest observed send window and all bytes ever acknowledged.
				// A merely reordered ACK may still carry valid receive data below.
				if tcpSequenceLess(ack, state.sendUnacknowledged-oldestAcceptable) {
					if err := state.sendChallengeACK(); err != nil {
						return err
					}
					continue
				}
			} else if err := state.processAcknowledgment(&segment, receivedAt, timestampEcho, &ackOperations); err != nil {
				return err
			}

			fin := segment.flags&TCPFlagFIN != 0
			if len(segment.payload) != 0 || fin {
				previousReceiveNext := state.receiveNext
				newApplicationData := len(segment.payload) != 0 && tcpSequenceGreater(segment.sequence+uint32(len(segment.payload)), previousReceiveNext)
				hadOutOfOrder := len(state.outOfOrder) != 0
				state.recentSACK = segment.sequence
				if state.peerSACK {
					if block, duplicate := tcpDuplicateSACKBlock(segment.sequence, len(segment.payload), fin, state.receiveNext, state.outOfOrder); duplicate {
						state.recentDSACK, state.haveRecentDSACK = block, true
					}
				}
				if !state.remoteFINReceived {
					_, closed := c.receiveTCPData(segment.sequence, segment.payload, fin, receiveWindow, &state.receiveNext, &state.outOfOrder, &state.outOfOrderBytes)
					advanced := state.receiveNext - previousReceiveNext
					if closed && advanced != 0 {
						advanced--
					}
					state.bytesReceived += uint64(advanced)
					if closed {
						state.remoteFINReceived = true
						c.setReadEOF()
					}
				}
				if newApplicationData && c.applicationReceiveClosed() {
					sequence := tcpAcceptableSendSequence(state.sendUnacknowledged, state.sendNext, state.peerWindow, state.peerScale)
					_ = c.sendSegment(sequence, state.receiveNext, TCPFlagRST|TCPFlagACK, state.advertisedReceiveWindow(), nil)
					return net.ErrClosed
				}
				immediateACK := fin || segment.sequence != previousReceiveNext || hadOutOfOrder || len(state.outOfOrder) != 0
				if err := state.scheduleACK(immediateACK, len(segment.payload) != 0, receivedAt); err != nil {
					return err
				}
			}
			if state.localFINAcked && state.remoteFINReceived {
				if !state.timeWaitRequired {
					return nil
				}
				// RFC 9293 restarts 2MSL for a retransmitted FIN, not for
				// every acceptable ACK received while the tuple is retained.
				if !state.timeWaitArmed || fin {
					startedAt := receivedAt
					if fin {
						// TIME-WAIT starts after acknowledging the peer's FIN.
						startedAt = time.Now()
					}
					state.armClose(startedAt, tcpTimeWaitDuration)
					state.timeWaitArmed = true
				}
			} else if state.localFINAcked && !state.finWaitArmed && c.applicationReceiveClosed() {
				state.armClose(receivedAt, tcpFINWaitDuration)
				state.finWaitArmed = true
			}
			state.armLiveness()
			if err := fillWindow(); err != nil {
				return err
			}

		case <-activeRetransmit:
			state.consumeActorTimer(actorTimer)
			state.retransmit = false
			state.retransmissionDeadline = time.Time{}
			if state.retransmissionClose {
				return net.ErrClosed
			}
			pendingIndex := firstUnsackedSegment(state.outstanding)
			if state.retransmissionProbe {
				pendingIndex = lastUnsackedSegment(state.outstanding)
			}
			if pendingIndex >= 0 && pendingIndex < len(state.outstanding) && state.outstanding[pendingIndex].hostQueue.pending(c.stack) {
				// Linux refuses every retransmission while the original skb is
				// still owned by qdisc or the driver. Preserve the timer kind and
				// original xmit time, then retry after local queue progress has had
				// a chance to occur.
				state.retransmit = true
				state.retransmissionDeadline = time.Now().Add(tcpHostQueueRetryInterval)
				continue
			}
			if state.retransmissionRACK {
				reorderingWindow := rackReorderingWindow(state.rtt.minimum, state.rtt.srtt, state.rackReorderingScale)
				if !state.rackReorderingSeen && (state.fastRecovery || state.rtoRecovery || state.sackedRanges >= tcpDuplicateACKThreshold) {
					reorderingWindow = 0
				}
				state.haveRACKLoss = markRACKLoss(state.outstanding, state.rackLatestDelivered, time.Now(), reorderingWindow, c.stack.timestampEpoch)
				if state.haveRACKLoss {
					// RACK can be the first conclusive evidence that only the
					// PLPMTU probe was lost. Apply the same RFC 4821 isolation
					// rule as the ACK path before ordinary congestion recovery.
					if state.pathMTUState != nil && state.pathMTUState.discovery.active && state.sendUnacknowledged == state.pathMTUState.discovery.probeStart && isolatedPLPMTUProbeLoss(state.outstanding, state.pathMTUState.discovery.probeStart, highestSACKedSequence(state.outstanding), state.peerMSS) {
						if err := failPLPMTUProbe(); err != nil {
							return err
						}
					}
					state.recordProvenLosses()
					if state.haveRACKLoss {
						if err := recoverSACKHoles(0, false); err != nil {
							return err
						}
					}
					state.haveRACKLoss = hasRACKLoss(state.outstanding)
				}
				state.armRetransmission()
				continue
			}
			if state.retransmissionProbe {
				sent, err := sendNextData(uint32(state.peerMSS), false)
				if err != nil {
					return err
				}
				probeSentAt := time.Time{}
				if sent {
					probeSentAt = state.outstanding[len(state.outstanding)-1].transmittedAt(c.stack.timestampEpoch)
				}
				state.tailProbeRetransmit = !sent
				state.tailProbeBytes = 0
				state.tailProbeState = 0
				if !sent {
					index := lastUnsackedSegment(state.outstanding)
					segment := &state.outstanding[index]
					originalCongestionState := segment.congestionPacketState
					window := state.advertisedReceiveWindow()
					timestamp, hostQueue, err := c.sendBufferedSegmentForMTU(state.sendUnacknowledged, *segment, state.receiveNext, window, nil, false, c.mtu)
					if err != nil {
						return err
					}
					state.recordRetransmission(segment.sequence, segment.end)
					sentAt := hostQueue.queuedTime(c.stack.timestampEpoch)
					state.lastACKSent = state.receiveNext
					state.lastAdvertisedWindow = window
					segment.timestamp = timestamp
					segment.hostQueue = hostQueue
					probeSentAt = sentAt
					segment.advanceTransmissionGeneration()
					c.noteRetransmission()
					segment.delivery = state.controller.onRetransmit(segment.dataSize(), state.peerMSS, segment.transmittedAt(c.stack.timestampEpoch), segment.hostQueue.queuedAt, state.congestionWindow, state.congestionFlight(), state.sendNext-state.sendUnacknowledged, state.rtt.srtt, state.slowStartThreshold)
					segment.congestionPacketState = state.controller.transmissionState()
					state.tailProbeBytes = segment.dataSize()
					state.tailProbeState = originalCongestionState
					segment.state.set(sentTCPSegmentDeliverySchedulerLimited, state.controller.schedulerLimited())
					segment.state.set(sentTCPSegmentDeliveryPending, state.processingDeliveryACK)
					state.deliveryACKPendingSnapshots = state.deliveryACKPendingSnapshots || state.processingDeliveryACK
				}
				state.tailProbeActive = true
				state.tailProbeEnd = state.sendNext
				state.tailProbeRTTSamples = state.rtt.samples
				c.stack.stats.tcpTailLossProbes.Add(1)
				// RFC 8985 requires a full RTO from the probe transmission;
				// retaining the oldest segment's prior deadline can otherwise
				// turn a useful new-data probe into an immediate timeout.
				state.armRetransmissionAfterACK(probeSentAt)
				continue
			}
			state.rtoAttempts++
			if state.rtoAttempts > tcpMaximumRTOs {
				var softError error
				if state.livenessState != nil {
					softError = state.livenessState.lastSoftError
				}
				return tcpTimeoutError(softError)
			}
			state.blackHoleRTOs++
			if state.blackHoleRTOs >= tcpBlackHoleTimeouts {
				if len(state.outstanding) != 0 {
					segment := state.outstanding[firstUnsackedSegment(state.outstanding)]
					mtu := nextBlackHoleProbeMTU(c.mtu, c.key.remote.Addr().Is6(), segment.dataSize(), c.peerTimestamp)
					if mtu < c.mtu {
						c.stack.stats.pathMTUBlackHoleReductions.Add(1)
						pathState := state.ensurePathMTUState()
						pathState.blackHoleMTU = mtu
						pathState.blackHoleExpiry = time.Now().Add(pathMTULifetime)
						if err := applyPathMTU(state.effectivePathMTU(), false); err != nil {
							return err
						}
					}
				}
			}
			if err := retransmitSegment(firstUnsackedSegment(state.outstanding), true); err != nil {
				return err
			}

		case <-activePersist:
			state.consumeActorTimer(actorTimer)
			state.persist = false
			state.persistDeadline = time.Time{}
			if c.applicationReceiveClosed() {
				state.persistAttempts++
				if state.persistAttempts > tcpMaximumRTOs {
					return os.ErrDeadlineExceeded
				}
			}
			// Like Linux and gVisor, probe with an already acknowledged byte.
			// Consuming new sequence space here would move pure ACKs beyond the
			// peer's zero window and can deadlock a full-duplex connection.
			sequence, flags := state.sendUnacknowledged-1, byte(TCPFlagACK)
			payload := tcpZeroWindowProbe[:]
			window := state.advertisedReceiveWindow()
			_, hostQueue, err := c.sendSegmentTimestamp(sequence, state.receiveNext, flags, window, payload)
			if err != nil {
				return err
			}
			probeSentAt := hostQueue.queuedTime(c.stack.timestampEpoch)
			state.lastACKSent = state.receiveNext
			state.lastAdvertisedWindow = window
			c.stack.stats.tcpZeroWindowProbes.Add(1)
			state.persistRTO *= 2
			if state.persistRTO > tcpMaximumRTO {
				state.persistRTO = tcpMaximumRTO
			}
			state.armPersist(probeSentAt)

		case <-activeDelayedACK:
			state.consumeActorTimer(actorTimer)
			state.delayedACK = false
			state.delayedACKDeadline = time.Time{}
			if err := state.sendACK(); err != nil {
				return err
			}

		case <-activePathMTUProbe:
			state.consumeActorTimer(actorTimer)
			state.pathMTUProbe = false
			state.pathMTUDeadline = time.Time{}
			now := time.Now()
			if state.pathMTUState != nil && state.pathMTUState.discovery.searching {
				state.pathMTUState.discovery.nextProbe = now
				if err := fillWindow(); err != nil {
					return err
				}
				continue
			}
			if state.pathMTUState != nil && !state.pathMTUState.blackHoleExpiry.IsZero() && !time.Now().Before(state.pathMTUState.blackHoleExpiry) {
				state.pathMTUState.blackHoleMTU = 0
				state.pathMTUState.blackHoleExpiry = time.Time{}
			}
			pathState := state.ensurePathMTUState()
			pathState.discovery.start(c.mtu, c.stack.network.Load().mtu, now)
			if !pathState.discovery.searching {
				// A sub-threshold remaining gain is not worth a probe, but the
				// working PMTU still needs the RFC 4821 re-probe interval.
				c.stack.confirmPathMTU(c.key.remote.Addr(), c.mtu, c)
				state.armPathMTUProbe()
			}
			if err := fillWindow(); err != nil {
				return err
			}
		case <-activePacing:
			state.consumeActorTimer(actorTimer)
			state.pacing = false
			state.pacingDeadline = time.Time{}
			state.controller.onPacingWake(time.Now(), state.congestionFlight())
			if state.fastRecovery && state.peerSACK && len(state.outstanding) != 0 {
				if err := recoverSACKHoles(highestSACKedSequence(state.outstanding), true); err != nil {
					return err
				}
			}
			if err := fillWindow(); err != nil {
				return err
			}
		case <-activeLiveness:
			state.consumeActorTimer(actorTimer)
			state.liveness = false
			state.livenessDeadline = time.Time{}
			options := c.socketOptions()
			now := time.Now()
			if options.idleTimeout > 0 && !now.Before(state.lastActivity.Add(options.idleTimeout)) {
				return os.ErrDeadlineExceeded
			}
			if deadline := state.userTimeoutDeadline(now, options.userTimeout); !deadline.IsZero() && !now.Before(deadline) {
				return syscall.ETIMEDOUT
			}
			if options.userTimeout > 0 && state.livenessState != nil && state.livenessState.keepAliveProbes != 0 && !now.Before(state.lastActivity.Add(options.userTimeout)) {
				return syscall.ETIMEDOUT
			}
			if options.keepAlive && state.keepAliveEligible() {
				deadline := state.lastActivity.Add(options.keepAliveConfig.Idle)
				if state.livenessState != nil && state.livenessState.keepAliveProbes != 0 {
					deadline = state.livenessState.lastKeepAlive.Add(options.keepAliveConfig.Interval)
				}
				if !now.Before(deadline) {
					if options.userTimeout == 0 && state.livenessState != nil && state.livenessState.keepAliveProbes >= options.keepAliveConfig.Count {
						return syscall.ETIMEDOUT
					}
					probeSequence := state.sendNext - 1
					if probeSequence-state.sendUnacknowledged > state.sendNext-state.sendUnacknowledged {
						c.publishICMPSequenceRange(probeSequence, state.sendNext)
					}
					window := state.advertisedReceiveWindow()
					_, hostQueue, err := c.sendSegmentTimestamp(probeSequence, state.receiveNext, TCPFlagACK, window, nil)
					if err != nil {
						return err
					}
					state.lastACKSent = state.receiveNext
					state.lastAdvertisedWindow = window
					liveness := state.ensureLivenessState()
					liveness.keepAliveProbes++
					liveness.lastKeepAlive = hostQueue.queuedTime(c.stack.timestampEpoch)
					c.stack.stats.tcpKeepAliveProbes.Add(1)
				}
			}
			state.armLiveness()
		case <-c.abortCh:
			err := c.abortedError()
			if c.takeAbortReset() {
				sequence := tcpAcceptableSendSequence(state.sendUnacknowledged, state.sendNext, state.peerWindow, state.peerScale)
				_ = c.sendAbortReset(sequence, state.receiveNext, state.advertisedReceiveWindow())
			}
			return err
		case <-c.stack.closeCh:
			return ErrClosed
		}
	}
}

// sendSegment emits a segment with the supplied advertised window.
func (c *TCPConn) sendSegment(sequence, acknowledgement uint32, flags byte, window uint16, payload []byte) error {
	return c.sendSegmentWithOptions(sequence, acknowledgement, flags, window, nil, payload)
}

// sendAbortReset makes one nonblocking attempt to publish the final RST from
// an actor whose normal packet writes have already been canceled.
func (c *TCPConn) sendAbortReset(sequence, acknowledgement uint32, window uint16) error {
	if c.forwarded && !c.stack.network.Load().acceptsInboundDestination(c.key.local.Addr()) {
		return syscall.EADDRNOTAVAIL
	}
	flags := byte(TCPFlagRST | TCPFlagACK)
	var options []byte
	if c.peerTimestamp {
		options = tcpTimestampOptions(c.stack.tcpTimestamp(), c.recentTimestamp)
	}
	if c.echoCongestion {
		flags |= TCPFlagECE
	}
	packet, err := buildTCPPacket(
		c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(),
		sequence, acknowledgement, flags, window, options, nil, c.mtu, uint8(c.trafficClass.Load()), 0, c.flowLabel,
	)
	if err != nil {
		return err
	}
	return c.stack.tryWritePacket(packet)
}

// writeTCPControlWithMTU applies the socket DSCP policy to handshake and
// reset packets that precede established's timestamp and ECN state.
func (c *TCPConn) writeTCPControlWithMTU(sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, mtu int) (packetQueueTicket, error) {
	var view tcpPayloadView
	view.setBytes(payload)
	return c.writeTCP(
		sequence, acknowledgement, flags, window, options, &view, mtu, uint8(c.trafficClass.Load()), 0,
	)
}

// sendSegmentTimestamp is sendSegment plus the exact TSval placed on the
// wire. A zero timestamp is returned when timestamps were not negotiated.
func (c *TCPConn) sendSegmentTimestamp(sequence, acknowledgement uint32, flags byte, window uint16, payload []byte) (uint32, packetQueueTicket, error) {
	return c.sendSegmentForMTU(sequence, acknowledgement, flags, window, nil, payload, false, c.mtu)
}

// sendSegmentWithOptions emits a segment with TCP options and the actor's
// current advertised window.
func (c *TCPConn) sendSegmentWithOptions(sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte) error {
	_, _, err := c.sendSegmentForMTU(sequence, acknowledgement, flags, window, options, payload, false, c.mtu)
	return err
}

// sendSegmentForMTU emits a segment against an explicit path ceiling. It
// returns the serialized TSval so Eifel does not need a second clock read.
func (c *TCPConn) sendSegmentForMTU(sequence, acknowledgement uint32, flags byte, window uint16, options, payload []byte, ecnCapable bool, mtu int) (uint32, packetQueueTicket, error) {
	var view tcpPayloadView
	view.setBytes(payload)
	return c.sendPayloadForMTU(sequence, acknowledgement, flags, window, options, &view, ecnCapable, mtu)
}

// sendPayloadForMTU is the scatter-payload form of sendSegmentForMTU.
func (c *TCPConn) sendPayloadForMTU(sequence, acknowledgement uint32, flags byte, window uint16, options []byte, payload *tcpPayloadView, ecnCapable bool, mtu int) (uint32, packetQueueTicket, error) {
	timestamp := uint32(0)
	var timestampOptions [40]byte
	if c.peerTimestamp {
		if len(options) > len(timestampOptions)-12 {
			return 0, packetQueueTicket{}, errors.New("mipstack: invalid TCP options")
		}
		timestamp = c.stack.tcpTimestamp()
		timestampOptions[0], timestampOptions[1], timestampOptions[2], timestampOptions[3] = 1, 1, 8, 10
		binary.BigEndian.PutUint32(timestampOptions[4:8], timestamp)
		binary.BigEndian.PutUint32(timestampOptions[8:12], c.recentTimestamp)
		copy(timestampOptions[12:], options)
		options = timestampOptions[:12+len(options)]
	}
	if c.echoCongestion {
		flags |= TCPFlagECE
	}
	includeCWR := c.sendCWR && ecnCapable && payload.size != 0
	if includeCWR {
		flags |= TCPFlagCWR
	}
	ecn := byte(0)
	if c.peerECN && ecnCapable && payload.size != 0 {
		ecn = 2
	}
	trafficClass := uint8(c.trafficClass.Load())
	hostQueue, err := c.writeTCP(sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn)
	if err == nil && includeCWR {
		c.sendCWR = false
	}
	return timestamp, hostQueue, err
}

// sendBufferedSegmentForMTU resolves a retransmission range directly from the
// immutable send buffer instead of retaining or gathering payload per segment.
func (c *TCPConn) sendBufferedSegmentForMTU(sendBase uint32, segment sentTCPSegment, acknowledgement uint32, window uint16, options []byte, ecnCapable bool, mtu int) (uint32, packetQueueTicket, error) {
	var payload tcpPayloadView
	size := segment.dataSize()
	if size != 0 {
		c.sendView(int(segment.sequence-sendBase), size, &payload)
		if payload.size != size {
			return 0, packetQueueTicket{}, errors.New("mipstack: TCP retransmission data is unavailable")
		}
	}
	return c.sendPayloadForMTU(segment.sequence, acknowledgement, segment.flags, window, options, &payload, ecnCapable, mtu)
}

// writeTCP emits one connection-owned segment and remains interruptible while
// the embedding packet queue is full.
func (c *TCPConn) writeTCP(sequence, acknowledgement uint32, flags byte, window uint16, options []byte, payload *tcpPayloadView, mtu int, trafficClass, ecn byte) (packetQueueTicket, error) {
	if c.forwarded && !c.stack.network.Load().acceptsInboundDestination(c.key.local.Addr()) {
		return packetQueueTicket{}, syscall.EADDRNOTAVAIL
	}
	_, _, packetSize, err := tcpPacketLayout(c.key.local.Addr(), c.key.remote.Addr(), options, payload.size, mtu)
	if err != nil {
		return packetQueueTicket{}, err
	}
	queue, loopback := c.stack.outputQueueFor(c.key.remote.Addr())
	// A graceful Close deliberately leaves protocol output active so already
	// accepted bytes and FIN can still be transmitted; only abort cancels it.
	state := socketWriteState{closed: c.abortCh}
	slot, err := c.stack.reservePacketUntil(queue, loopback, state)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			select {
			case <-c.abortCh:
				return packetQueueTicket{}, c.abortedError()
			default:
			}
		}
		return packetQueueTicket{}, err
	}
	packet, reusable := queue.acquireBuffer(packetSize)
	built, err := buildTCPPacketViewInto(
		packet,
		c.key.local.Addr(), c.key.remote.Addr(), c.key.local.Port(), c.key.remote.Port(),
		sequence, acknowledgement, flags, window, options, payload, mtu, trafficClass, ecn, c.flowLabel,
	)
	if err != nil {
		queue.releaseBuffer(packet, reusable)
		queue.releaseReserved(slot)
		return packetQueueTicket{}, err
	}
	hostQueue, published := queue.enqueueReservedTCP(slot, built, reusable, c.outputFlowID, loopback)
	if !published {
		return packetQueueTicket{}, ErrClosed
	}
	c.stack.recordOutput(loopback)
	return hostQueue, nil
}

// rttEstimator implements the RFC 6298 smoothed RTT and variance calculation.
type rttEstimator struct {
	initialized bool
	samples     uint64
	minimum     time.Duration
	minimums    tcpMinimumRTTFilter
	srtt        time.Duration
	variation   time.Duration
	baseRTO     time.Duration
	rto         time.Duration
	backoffs    uint8
}

// newRTTEstimator installs the RFC 6298 initial RTO. A connection whose SYN
// timer expired supplies three seconds as required by section 5.7.
func newRTTEstimator(initial time.Duration) rttEstimator {
	return rttEstimator{baseRTO: initial, rto: initial}
}

// tcpMinimumRTTSample is one candidate in Linux's constant-space running-min
// filter.
type tcpMinimumRTTSample struct {
	at    monotonicStamp
	value time.Duration
}

// tcpMinimumRTTFilter retains the best three time-separated RTT samples. This
// is Kathleen Nichols' running-min algorithm used by Linux for tcp_min_rtt.
type tcpMinimumRTTFilter struct {
	samples     [3]tcpMinimumRTTSample
	initialized bool
}

// observe incorporates one RTT sample and returns the current windowed
// minimum.
func (f *tcpMinimumRTTFilter) observe(now monotonicStamp, value time.Duration) time.Duration {
	candidate := tcpMinimumRTTSample{at: now, value: value}
	if !f.initialized || value <= f.samples[0].value || time.Duration(now-f.samples[2].at) > tcpMinimumRTTWindow {
		f.samples[0], f.samples[1], f.samples[2] = candidate, candidate, candidate
		f.initialized = true
		return value
	}
	if value <= f.samples[1].value {
		f.samples[1], f.samples[2] = candidate, candidate
	} else if value <= f.samples[2].value {
		f.samples[2] = candidate
	}
	delta := time.Duration(now - f.samples[0].at)
	if delta > tcpMinimumRTTWindow {
		f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], candidate
		if time.Duration(now-f.samples[0].at) > tcpMinimumRTTWindow {
			f.samples[0], f.samples[1], f.samples[2] = f.samples[1], f.samples[2], candidate
		}
	} else if f.samples[1].at == f.samples[0].at && delta > tcpMinimumRTTWindow/4 {
		f.samples[1], f.samples[2] = candidate, candidate
	} else if f.samples[2].at == f.samples[1].at && delta > tcpMinimumRTTWindow/2 {
		f.samples[2] = candidate
	}
	return f.samples[0].value
}

// observeAt incorporates a sample at its packet-arrival time so actor
// scheduling delay cannot age the running minimum.
func (r *rttEstimator) observeAt(sample time.Duration, receivedAt monotonicStamp) {
	if sample <= 0 {
		return
	}
	r.samples++
	sample = normalizedRTTSample(sample)
	r.minimum = r.minimums.observe(receivedAt, sample)
	if !r.initialized {
		r.srtt = sample
		r.variation = sample / 2
		r.initialized = true
	} else {
		difference := r.srtt - sample
		if difference < 0 {
			difference = -difference
		}
		r.variation = (3*r.variation + difference) / 4
		r.srtt = (7*r.srtt + sample) / 8
	}
	r.updateRTO()
}

// updateRTO derives and bounds the RFC 6298 retransmission timeout from the
// current smoothed RTT and variation.
func (r *rttEstimator) updateRTO() {
	r.baseRTO = r.srtt + 4*r.variation
	if r.baseRTO < tcpMinimumRTO {
		r.baseRTO = tcpMinimumRTO
	} else if r.baseRTO > tcpMaximumRTO {
		r.baseRTO = tcpMaximumRTO
	}
	r.rto = r.baseRTO
	r.backoffs = 0
}

// normalizedRTTSample keeps estimator arithmetic and model-based pacing
// bounded after a process suspension or other multi-minute scheduling gap.
func normalizedRTTSample(sample time.Duration) time.Duration {
	if sample > tcpMaximumRTO {
		return tcpMaximumRTO
	}
	return sample
}

// elapsedRTTSampleAt measures delivery at packet arrival rather than when a
// connection actor was eventually scheduled to process the acknowledgement.
func elapsedRTTSampleAt(sentAt, receivedAt time.Time) time.Duration {
	if sentAt.IsZero() {
		return 0
	}
	sample := receivedAt.Sub(sentAt)
	if sample < time.Microsecond {
		return time.Microsecond
	}
	return sample
}

// tcpSegmentEventTime returns the stack-arrival time attached by handleTCP,
// bounded by the actor's prior event time and its current processing time.
// Concurrent device receive loops can otherwise enqueue timestamped batches
// in the opposite order and move protocol timers backwards.
func tcpSegmentEventTime(segment tcpSegment, now, previous, epoch time.Time) time.Time {
	result := segment.receivedAt.time(epoch)
	if result.IsZero() || result.After(now) {
		result = now
	}
	if result.Before(previous) {
		result = previous
	}
	return result
}

// backoff doubles RTO after a retransmission timeout.
func (r *rttEstimator) backoff() {
	if r.baseRTO <= 0 {
		r.baseRTO = r.rto
		if r.baseRTO <= 0 {
			r.baseRTO = tcpInitialRTO
		}
	}
	if r.backoffs != ^uint8(0) {
		r.backoffs++
	}
	r.rto = backedOffRTO(r.baseRTO, r.backoffs)
}

// revertBackoff implements one RFC 6069 TCP-LD step without changing the RTT
// estimator. Linux likewise decrements backoff while retaining the current
// retransmission count.
func (r *rttEstimator) revertBackoff() bool {
	if r.backoffs == 0 {
		return false
	}
	r.backoffs--
	r.rto = backedOffRTO(r.baseRTO, r.backoffs)
	return true
}

// backedOffRTO applies a bounded exponential multiplier without overflowing a
// duration when a connection has been unreachable for many attempts.
func backedOffRTO(base time.Duration, backoffs uint8) time.Duration {
	if base <= 0 {
		base = tcpInitialRTO
	}
	result := base
	for backoff := uint8(0); backoff < backoffs; backoff++ {
		if result >= tcpMaximumRTO/2 {
			return tcpMaximumRTO
		}
		result *= 2
	}
	if result > tcpMaximumRTO {
		return tcpMaximumRTO
	}
	return result
}

// tcpMSSForMTU returns the largest transport payload fitting one IP packet.
func tcpMSSForMTU(mtu int, address netip.Addr) int {
	header := tcpHeaderSize + 40
	if address.Is4() {
		header = tcpHeaderSize + 20
	}
	maximum := mtu - header
	if maximum > 65535 {
		maximum = 65535
	}
	return maximum
}

// nextBlackHoleMTU selects the next conservative packet-size plateau after
// repeated retransmission timeouts without an ICMP Packet Too Big response.
func nextBlackHoleMTU(current int, ipv6 bool) int {
	if ipv6 {
		if current > ipv6MinimumMTU {
			return ipv6MinimumMTU
		}
		return current
	}
	for _, candidate := range [...]int{1500, 1280, 1006, 576, 508, 296, 68} {
		if candidate < current {
			return candidate
		}
	}
	return current
}

// nextBlackHoleProbeMTU skips nominal plateaus that would emit the same wire
// payload. A black-hole probe must make the retransmission smaller to provide
// new path information; repeatedly recording a larger MTU that already fits
// the current segment cannot recover the connection.
func nextBlackHoleProbeMTU(current int, ipv6 bool, payloadSize int, timestamp bool) int {
	address := netip.IPv4Unspecified()
	if ipv6 {
		address = netip.IPv6Unspecified()
	}
	probe := current
	for {
		next := nextBlackHoleMTU(probe, ipv6)
		if next >= probe {
			return current
		}
		maximumPayload := tcpMSSForMTU(next, address)
		if timestamp {
			maximumPayload -= 12
		}
		if payloadSize > maximumPayload {
			return next
		}
		probe = next
	}
}

// tcpTimeoutError preserves the last validated asynchronous network failure
// when TCP ultimately cannot recover it through retransmission.
func tcpTimeoutError(softError error) error {
	if softError != nil {
		return softError
	}
	return os.ErrDeadlineExceeded
}

// tcpActiveOpenHardError applies RFC 1122's protocol/port-unreachable split.
// IPv6 has no protocol-unreachable destination code, but its port-unreachable
// code carries the same definitive active-open meaning.
func tcpActiveOpenHardError(err error) bool {
	var networkError ICMPError
	if !errors.As(err, &networkError) {
		return false
	}
	if networkError.QuotedSource.Is6() {
		return networkError.Type == ICMPv6TypeDestinationUnreachable && networkError.Code == ICMPv6DestinationUnreachableCodePort
	}
	return networkError.Type == ICMPv4TypeDestinationUnreachable &&
		(networkError.Code == ICMPv4DestinationUnreachableCodeProtocol || networkError.Code == ICMPv4DestinationUnreachableCodePort)
}

// tcpRevertRTOBackoff implements the Linux tcp_ld_RTO_revert behavior from
// RFC 6069. A network/host-unreachable quotation for SND.UNA after an RTO
// removes one exponential-backoff level so restored connectivity is retried
// promptly; the ICMP error remains soft.
func tcpRevertRTOBackoff(err error, sendUnacknowledged uint32, retransmissions int, rtt *rttEstimator) bool {
	if retransmissions == 0 || rtt == nil {
		return false
	}
	var networkError ICMPError
	if !errors.As(err, &networkError) || len(networkError.QuotedPayload) < 8 {
		return false
	}
	revert := false
	if networkError.QuotedSource.Is6() {
		revert = networkError.Type == ICMPv6TypeDestinationUnreachable && networkError.Code == ICMPv6DestinationUnreachableCodeNoRoute
	} else {
		revert = networkError.Type == ICMPv4TypeDestinationUnreachable &&
			(networkError.Code == ICMPv4DestinationUnreachableCodeNetwork || networkError.Code == ICMPv4DestinationUnreachableCodeHost)
	}
	if !revert || binary.BigEndian.Uint32(networkError.QuotedPayload[4:8]) != sendUnacknowledged {
		return false
	}
	return rtt.revertBackoff()
}

// tcpSYNOptions writes MSS, SACK, receive window scaling, and timestamps into
// caller-owned TCP option storage.
func tcpSYNOptions(storage []byte, mss int, windowScale uint8, timestamp uint32) []byte {
	return tcpPassiveSYNOptions(storage, mss, true, true, true, windowScale, timestamp, 0)
}

// tcpPassiveSYNOptions writes only extensions offered by the initiating peer,
// while MSS is always present. Callers provide enough storage to avoid one
// allocation for every connection and handshake retransmission.
func tcpPassiveSYNOptions(storage []byte, mss int, sack, windowScaling, timestamp bool, windowScale uint8, timestampValue, timestampEcho uint32) []byte {
	options := append(storage[:0], TCPHeaderOptionMSS, 4, byte(mss>>8), byte(mss))
	if sack {
		options = append(options, TCPHeaderOptionSACKPermitted, 2)
	}
	if windowScaling {
		options = append(options, TCPHeaderOptionNOP, TCPHeaderOptionWindowScale, 3, windowScale)
	}
	if timestamp {
		offset := len(options)
		options = append(options, TCPHeaderOptionNOP, TCPHeaderOptionNOP, TCPHeaderOptionTimestamp, 10, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(options[offset+4:offset+8], timestampValue)
		binary.BigEndian.PutUint32(options[offset+8:offset+12], timestampEcho)
	}
	return options
}

// parseTCPOptions extracts SYN options while ignoring unknown options.
func parseTCPOptions(options []byte, fallback, localMaximum int) (int, uint8, bool, bool, bool, uint32) {
	mss := fallback
	var scale uint8
	var windowScaling bool
	var sack bool
	var timestamp bool
	var timestampValue uint32
	for offset := 0; offset < len(options); {
		kind := options[offset]
		switch kind {
		case TCPHeaderOptionEnd:
			return clampMSS(mss, localMaximum), scale, windowScaling, sack, timestamp, timestampValue
		case TCPHeaderOptionNOP:
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		switch kind {
		case TCPHeaderOptionMSS:
			if length == 4 {
				value := int(binary.BigEndian.Uint16(options[offset+2 : offset+4]))
				if value != 0 {
					mss = value
				}
			}
		case TCPHeaderOptionWindowScale:
			if length == 3 {
				windowScaling = true
				scale = options[offset+2]
				if scale > 14 {
					scale = 14
				}
			}
		case TCPHeaderOptionSACKPermitted:
			sack = length == 2
		case TCPHeaderOptionTimestamp:
			if length == 10 {
				timestamp = true
				timestampValue = binary.BigEndian.Uint32(options[offset+2 : offset+6])
			}
		}
		offset += length
	}
	return clampMSS(mss, localMaximum), scale, windowScaling, sack, timestamp, timestampValue
}

// parseTCPTimestamp extracts one well-formed timestamp option.
func parseTCPTimestamp(options []byte) (uint32, uint32, bool) {
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == TCPHeaderOptionEnd {
			break
		}
		if kind == TCPHeaderOptionNOP {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		if kind == TCPHeaderOptionTimestamp && length == 10 {
			return binary.BigEndian.Uint32(options[offset+2 : offset+6]), binary.BigEndian.Uint32(options[offset+6 : offset+10]), true
		}
		offset += length
	}
	return 0, 0, false
}

// tcpTimestampOptions serializes TSval and the most recent peer TSval.
func tcpTimestampOptions(value, echo uint32) []byte {
	options := make([]byte, 12)
	options[0], options[1], options[2], options[3] = TCPHeaderOptionNOP, TCPHeaderOptionNOP, TCPHeaderOptionTimestamp, 10
	binary.BigEndian.PutUint32(options[4:8], value)
	binary.BigEndian.PutUint32(options[8:12], echo)
	return options
}

// tcpSACKBlockLimit returns the largest SACK option fitting both TCP's
// 40-byte option space and the current PMTU. reservePayload keeps room for a
// data byte when the option is piggybacked instead of sent on a pure ACK.
func tcpSACKBlockLimit(mtu int, address netip.Addr, timestamp bool, reservePayload int) int {
	ipHeader := 40
	if address.Is4() {
		ipHeader = 20
	}
	budget := mtu - ipHeader - tcpHeaderSize - reservePayload
	if budget > 40 {
		budget = 40
	}
	if budget < 0 {
		return 0
	}
	timestampSize := 0
	maximum := 4
	if timestamp {
		timestampSize = 12
		maximum = 3
	}
	for blocks := maximum; blocks > 0; blocks-- {
		optionSize := timestampSize + 2 + 8*blocks
		optionSize = (optionSize + 3) &^ 3
		if optionSize <= budget {
			return blocks
		}
	}
	return 0
}

// tcpSACKOptions reports retained out-of-order ranges and an optional RFC 2883
// duplicate range. DSACK occupies the first block; otherwise the range
// containing the segment that triggered the ACK is first as required by RFC
// 2018.
func tcpSACKOptions(pieces []tcpReceivedPiece, recent uint32, maximumBlocks int, dsack TCPSACKBlock, haveDSACK bool, workspace *[34]byte) []byte {
	if maximumBlocks < 1 {
		return nil
	}
	if maximumBlocks > 4 {
		maximumBlocks = 4
	}
	var recentBlock TCPSACKBlock
	haveRecent := false
	for index := 0; index < len(pieces); {
		block, next := tcpReceivedSACKBlockForward(pieces, index)
		if tcpSequenceGreaterEqual(recent, block.LeftEdge) && tcpSequenceLess(recent, block.RightEdge) {
			recentBlock, haveRecent = block, true
			break
		}
		index = next
	}
	var ordered [4]TCPSACKBlock
	count := 0
	if haveDSACK {
		ordered[count] = dsack
		count++
	}
	if haveRecent && count < maximumBlocks {
		ordered[count] = recentBlock
		count++
	}
	for index := len(pieces) - 1; index >= 0 && count < maximumBlocks; {
		block, previous := tcpReceivedSACKBlockBackward(pieces, index)
		index = previous
		if haveRecent && block == recentBlock {
			continue
		}
		ordered[count] = block
		count++
	}
	if count == 0 {
		return nil
	}
	options := workspace[:2+8*count]
	options[0], options[1] = TCPHeaderOptionSACK, byte(len(options))
	for index, block := range ordered[:count] {
		offset := 2 + 8*index
		binary.BigEndian.PutUint32(options[offset:offset+4], block.LeftEdge)
		binary.BigEndian.PutUint32(options[offset+4:offset+8], block.RightEdge)
	}
	return options
}

// tcpReceivedSACKBlockForward merges one contiguous receive range and returns
// the first piece index after it.
func tcpReceivedSACKBlockForward(pieces []tcpReceivedPiece, index int) (TCPSACKBlock, int) {
	piece := pieces[index]
	block := TCPSACKBlock{LeftEdge: piece.sequence, RightEdge: piece.sequence + uint32(len(piece.payload))}
	if piece.fin {
		block.RightEdge++
	}
	index++
	for index < len(pieces) {
		piece = pieces[index]
		right := piece.sequence + uint32(len(piece.payload))
		if piece.fin {
			right++
		}
		if tcpSequenceGreater(piece.sequence, block.RightEdge) {
			break
		}
		if tcpSequenceGreater(right, block.RightEdge) {
			block.RightEdge = right
		}
		index++
	}
	return block, index
}

// tcpReceivedSACKBlockBackward is the reverse iterator used to prefer the most
// recently received high ranges after the RFC 2018 recent block.
func tcpReceivedSACKBlockBackward(pieces []tcpReceivedPiece, index int) (TCPSACKBlock, int) {
	piece := pieces[index]
	block := TCPSACKBlock{LeftEdge: piece.sequence, RightEdge: piece.sequence + uint32(len(piece.payload))}
	if piece.fin {
		block.RightEdge++
	}
	index--
	for index >= 0 {
		piece = pieces[index]
		right := piece.sequence + uint32(len(piece.payload))
		if piece.fin {
			right++
		}
		if tcpSequenceGreater(block.LeftEdge, right) {
			break
		}
		block.LeftEdge = piece.sequence
		if tcpSequenceGreater(right, block.RightEdge) {
			block.RightEdge = right
		}
		index--
	}
	return block, index
}

// tcpDuplicateSACKBlock finds the first duplicate sequence range in an
// incoming segment. Ranges below RCV.NXT and overlaps with retained
// out-of-order data use the two DSACK forms defined by RFC 2883.
func tcpDuplicateSACKBlock(sequence uint32, payloadLength int, fin bool, receiveNext uint32, pieces []tcpReceivedPiece) (TCPSACKBlock, bool) {
	length := uint32(payloadLength)
	if fin {
		length++
	}
	if length == 0 {
		return TCPSACKBlock{}, false
	}
	end := sequence + length
	if tcpSequenceLess(sequence, receiveNext) {
		right := end
		if tcpSequenceGreater(right, receiveNext) {
			right = receiveNext
		}
		if tcpSequenceGreater(right, sequence) {
			return TCPSACKBlock{LeftEdge: sequence, RightEdge: right}, true
		}
		sequence = receiveNext
	}
	incomingStart := sequence - receiveNext
	incomingEnd := end - receiveNext
	if incomingStart >= incomingEnd {
		return TCPSACKBlock{}, false
	}
	for _, piece := range pieces {
		pieceStart := piece.sequence - receiveNext
		pieceEnd := pieceStart + uint32(len(piece.payload))
		if piece.fin {
			pieceEnd++
		}
		left := incomingStart
		if pieceStart > left {
			left = pieceStart
		}
		right := incomingEnd
		if pieceEnd < right {
			right = pieceEnd
		}
		if left < right {
			return TCPSACKBlock{LeftEdge: receiveNext + left, RightEdge: receiveNext + right}, true
		}
	}
	return TCPSACKBlock{}, false
}

// parseTCPDSACKOption returns RFC 2883's distinguished first SACK block when
// it describes already cumulatively acknowledged data or is contained in the
// following ordinary SACK block. history bounds below-ACK reports to sequence
// space this connection actually acknowledged recently.
func parseTCPDSACKOption(options []byte, acknowledged, sendNext, history uint32) (TCPSACKBlock, bool) {
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == TCPHeaderOptionEnd {
			break
		}
		if kind == TCPHeaderOptionNOP {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		if kind == TCPHeaderOptionSACK && length >= 10 && (length-2)%8 == 0 {
			left := binary.BigEndian.Uint32(options[offset+2 : offset+6])
			right := binary.BigEndian.Uint32(options[offset+6 : offset+10])
			block := TCPSACKBlock{LeftEdge: left, RightEdge: right}
			if !tcpSequenceLess(left, right) {
				return TCPSACKBlock{}, false
			}
			if tcpSequenceLessEqual(right, acknowledged) && acknowledged-left <= history {
				return block, true
			}
			if length >= 18 {
				secondLeft := binary.BigEndian.Uint32(options[offset+10 : offset+14])
				secondRight := binary.BigEndian.Uint32(options[offset+14 : offset+18])
				secondLength := secondRight - secondLeft
				if secondLength != 0 && secondLength <= sendNext-acknowledged &&
					left-secondLeft < secondLength && right-secondLeft <= secondLength {
					return block, true
				}
			}
			return TCPSACKBlock{}, false
		}
		offset += length
	}
	return TCPSACKBlock{}, false
}

// parseTCPSACKOptions validates and merges ordinary SACK ranges within the
// current send window. The distinguished DSACK block is handled separately.
func parseTCPSACKOptions(options []byte, acknowledged, sendNext uint32) []TCPSACKBlock {
	window := sendNext - acknowledged
	var blocks []TCPSACKBlock
	for offset := 0; offset < len(options); {
		kind := options[offset]
		if kind == TCPHeaderOptionEnd {
			break
		}
		if kind == TCPHeaderOptionNOP {
			offset++
			continue
		}
		if len(options)-offset < 2 {
			break
		}
		length := int(options[offset+1])
		if length < 2 || length > len(options)-offset {
			break
		}
		if kind == TCPHeaderOptionSACK && length >= 10 && (length-2)%8 == 0 {
			for blockOffset := offset + 2; blockOffset < offset+length; blockOffset += 8 {
				left := binary.BigEndian.Uint32(options[blockOffset : blockOffset+4])
				right := binary.BigEndian.Uint32(options[blockOffset+4 : blockOffset+8])
				leftDistance, rightDistance := left-acknowledged, right-acknowledged
				if leftDistance < rightDistance && rightDistance <= window {
					blocks = append(blocks, TCPSACKBlock{LeftEdge: left, RightEdge: right})
				}
			}
		}
		offset += length
	}
	sort.Slice(blocks, func(left, right int) bool {
		return blocks[left].LeftEdge-acknowledged < blocks[right].LeftEdge-acknowledged
	})
	merged := blocks[:0]
	for _, block := range blocks {
		if len(merged) == 0 || tcpSequenceLess(merged[len(merged)-1].RightEdge, block.LeftEdge) {
			merged = append(merged, block)
			continue
		}
		if tcpSequenceGreater(block.RightEdge, merged[len(merged)-1].RightEdge) {
			merged[len(merged)-1].RightEdge = block.RightEdge
		}
	}
	return merged
}

// applyTCPSACK splits transmissions at SACK boundaries, marks exact covered
// ranges, and returns the newest delivery information used by RACK. epoch must
// be the owning stack's timestamp epoch so compact host-queue stamps reconstruct
// to the transmission times compared by RACK.
func applyTCPSACK(outstanding []sentTCPSegment, blocks []TCPSACKBlock, epoch time.Time) ([]sentTCPSegment, uint32, bool, bool, tcpRACKSample, []sentTCPSegment) {
	var highest uint32
	var newInformation bool
	var latest tcpRACKSample
	var newlySACKed []sentTCPSegment
	for blockIndex, block := range blocks {
		if blockIndex == 0 || tcpSequenceGreater(block.RightEdge, highest) {
			highest = block.RightEdge
		}
		outstanding = splitTCPSegmentAt(outstanding, block.LeftEdge)
		outstanding = splitTCPSegmentAt(outstanding, block.RightEdge)
		for index := range outstanding {
			segment := &outstanding[index]
			if tcpSequenceGreaterEqual(segment.sequence, block.LeftEdge) && tcpSequenceGreaterEqual(block.RightEdge, segment.end) {
				if !segment.state.has(sentTCPSegmentSACKed) {
					newInformation = true
					newlySACKed = append(newlySACKed, *segment)
					latest = newerRACKSample(latest, tcpRACKSample{sentAt: segment.transmittedAt(epoch), end: segment.end, timestamp: segment.timestamp, retransmitted: segment.isRetransmitted()})
					// A range contributes delivery-rate metadata only on its first
					// SACK or cumulative ACK, matching tcp_rate_skb_delivered.
					segment.delivery.deliveredStamp = 0
				}
				segment.state.set(sentTCPSegmentSACKed, true)
			}
		}
	}
	return outstanding, highest, len(blocks) != 0, newInformation, latest, newlySACKed
}

// splitTCPSegmentAt makes the SACK scoreboard byte-accurate when a peer's
// block edge falls inside one transmitted segment.
func splitTCPSegmentAt(outstanding []sentTCPSegment, boundary uint32) []sentTCPSegment {
	splitRanges := 0
	for index := range outstanding {
		if outstanding[index].state.has(sentTCPSegmentSACKSplit) {
			splitRanges++
		}
	}
	for index := range outstanding {
		segment := outstanding[index]
		if !tcpSequenceGreater(boundary, segment.sequence) || !tcpSequenceLess(boundary, segment.end) {
			continue
		}
		increase := 1
		if !segment.state.has(sentTCPSegmentSACKSplit) {
			increase = 2
		}
		if splitRanges+increase > tcpMaximumSACKSplitRanges {
			return outstanding
		}
		left, right := segment, segment
		left.state.set(sentTCPSegmentSACKSplit, true)
		right.state.set(sentTCPSegmentSACKSplit, true)
		left.end = boundary
		left.flags &^= TCPFlagPSH | TCPFlagFIN
		right.sequence = boundary
		outstanding = append(outstanding, sentTCPSegment{})
		copy(outstanding[index+2:], outstanding[index+1:])
		outstanding[index], outstanding[index+1] = left, right
		return outstanding
	}
	return outstanding
}

// firstUnsackedSegment returns the oldest known hole, falling back to the
// first segment when every segment is selectively acknowledged and the
// cumulative ACK may have been lost.
func firstUnsackedSegment(outstanding []sentTCPSegment) int {
	for index := range outstanding {
		if !outstanding[index].state.has(sentTCPSegmentSACKed) {
			return index
		}
	}
	return 0
}

// lastUnsackedSegment returns the newest segment eligible for a tail-loss
// probe, falling back to the final segment when only a cumulative ACK is
// missing.
func lastUnsackedSegment(outstanding []sentTCPSegment) int {
	for index := len(outstanding) - 1; index >= 0; index-- {
		if !outstanding[index].state.has(sentTCPSegmentSACKed) {
			return index
		}
	}
	return len(outstanding) - 1
}

// tailLossProbeDelay schedules one probe before the normal RTO after an RTT
// sample is available.
func tailLossProbeDelay(smoothedRTT, rto time.Duration, singleSegment bool) time.Duration {
	delay := 2 * smoothedRTT
	if smoothedRTT == 0 {
		delay = rto
	} else if singleSegment {
		delay += tcpTailLossProbeACKDelay
	}
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	if delay > rto {
		delay = rto
	}
	return delay
}

// tcpSACKedState rebuilds the actor's aggregate scoreboard after an operation
// that splits transmission ranges. The ordinary send and ACK paths update the
// same aggregates incrementally and therefore remain constant-time.
func tcpSACKedState(outstanding []sentTCPSegment) (ranges int, bytes uint32) {
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentSACKed) {
			ranges++
			bytes += segment.end - segment.sequence
		}
	}
	return ranges, bytes
}

// highestSACKedSequence returns HighSACK for RFC 6675 NextSeg processing.
func highestSACKedSequence(outstanding []sentTCPSegment) uint32 {
	var highest uint32
	var found bool
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentSACKed) && (!found || tcpSequenceGreater(segment.end, highest)) {
			highest = segment.end
			found = true
		}
	}
	return highest
}

// firstUnretriedLoss returns the first range satisfying RACK or RFC 6675's
// IsLost test and not already retransmitted in this recovery round.
func firstUnretriedLoss(outstanding []sentTCPSegment, mss int) int {
	index := -1
	var sackedRanges, sackedBytes int
	for next := len(outstanding) - 1; next >= 0; next-- {
		segment := outstanding[next]
		if segment.state.has(sentTCPSegmentSACKed) {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		lost := segment.state.has(sentTCPSegmentRACKLost) || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss
		if !segment.state.has(sentTCPSegmentSACKRetried) && lost {
			index = next
		}
	}
	return index
}

// tcpRateApplicationLimited mirrors Linux tcp_rate_check_app_limited. In
// particular, a SACK/RACK loss that is known but not yet retransmitted is a
// recovery limitation rather than an application bubble.
func tcpRateApplicationLimited(queued int, hostQueued bool, flight, window uint32, recovery, peerSACK bool, outstanding []sentTCPSegment, mss int) bool {
	if queued >= mss || hostQueued || flight >= window {
		return false
	}
	return !recovery || !peerSACK || firstUnretriedLoss(outstanding, mss) < 0
}

// firstUnretriedSACKHole implements RFC 6675 NextSeg rule 3 after all ranges
// with sufficient loss evidence have been retransmitted.
func firstUnretriedSACKHole(outstanding []sentTCPSegment, highest uint32) int {
	for index := range outstanding {
		segment := &outstanding[index]
		if !segment.state.has(sentTCPSegmentSACKed) && !segment.state.has(sentTCPSegmentSACKRetried) && tcpSequenceLess(segment.sequence, highest) {
			return index
		}
	}
	return -1
}

// sackLostRangeCount counts ranges satisfying RFC 6675 IsLost, including
// RACK declarations, for PRR's newly-lost suppression of slow-start reduction.
func sackLostRangeCount(outstanding []sentTCPSegment, mss int) int {
	count := 0
	var sackedRanges, sackedBytes int
	for index := len(outstanding) - 1; index >= 0; index-- {
		segment := outstanding[index]
		if segment.state.has(sentTCPSegmentSACKed) {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		if segment.state.has(sentTCPSegmentRACKLost) || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss {
			count++
		}
	}
	return count
}

// sackSegmentLost implements RFC 6675 IsLost: either DupThresh transmitted
// ranges or more than (DupThresh-1)*SMSS bytes have been SACKed above it.
func sackSegmentLost(outstanding []sentTCPSegment, index, mss int) bool {
	if index < 0 || index >= len(outstanding) || outstanding[index].state.has(sentTCPSegmentSACKed) {
		return false
	}
	if outstanding[index].state.has(sentTCPSegmentRACKLost) {
		return true
	}
	var ranges, bytes int
	for next := index + 1; next < len(outstanding); next++ {
		segment := outstanding[next]
		if !segment.state.has(sentTCPSegmentSACKed) {
			continue
		}
		ranges++
		bytes += int(segment.end - segment.sequence)
		if ranges >= tcpDuplicateACKThreshold || mss > 0 && bytes > (tcpDuplicateACKThreshold-1)*mss {
			return true
		}
	}
	return false
}

// recordTCPSegmentLoss marks a proven transmission generation as reported and
// returns its sequence-space size. A later retransmission starts a new
// generation that can independently be proven lost.
func recordTCPSegmentLoss(segment *sentTCPSegment, proven bool) uint32 {
	if !proven || segment == nil || !segment.isTransmitted() || segment.lossAlreadyReported() {
		return 0
	}
	segment.state |= sentTCPSegmentLossReported
	return segment.end - segment.sequence
}

// recordProvenTCPLosses returns bytes newly declared lost by RACK or RFC
// 6675 IsLost. A speculative SACK-hole retransmission is not loss evidence,
// and an already retransmitted range needs new RACK evidence or an RTO before
// its replacement generation can be reported.
func recordProvenTCPLosses(outstanding []sentTCPSegment, mss int) uint32 {
	return recordProvenTCPLossesWith(outstanding, mss, nil)
}

// recordProvenTCPLossesWith additionally reports every newly lost generation
// without allocating a temporary slice. report runs synchronously while the
// connection actor owns outstanding.
func recordProvenTCPLossesWith(outstanding []sentTCPSegment, mss int, report func(*sentTCPSegment, uint32)) uint32 {
	var losses uint32
	var sackedRanges, sackedBytes int
	for index := len(outstanding) - 1; index >= 0; index-- {
		segment := &outstanding[index]
		if segment.state.has(sentTCPSegmentSACKed) {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		// SACK evidence above a speculatively retransmitted range describes the
		// original transmission and cannot prove that its replacement was lost.
		// RACK compares transmit times and therefore is direct evidence for the
		// current replacement generation.
		lost := segment.state.has(sentTCPSegmentRACKLost) || !segment.state.has(sentTCPSegmentSACKRetried) && (sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss)
		if lost {
			bytes := recordTCPSegmentLoss(segment, true)
			losses = growCongestionWindow(losses, bytes)
			if bytes != 0 && report != nil {
				report(segment, bytes)
			}
		}
	}
	return losses
}

// isolatedPLPMTUProbeLoss requires ordinary RFC 6675/RACK loss evidence for
// the probe and rejects any second hole below HighSACK. Only that isolated
// case may suppress congestion response under RFC 4821.
func isolatedPLPMTUProbeLoss(outstanding []sentTCPSegment, probeStart, highestSACK uint32, mss int) bool {
	probeIndex := -1
	for index, segment := range outstanding {
		if segment.sequence == probeStart {
			probeIndex = index
			break
		}
	}
	if !sackSegmentLost(outstanding, probeIndex, mss) {
		return false
	}
	for index, segment := range outstanding {
		if index != probeIndex && !segment.state.has(sentTCPSegmentSACKed) && tcpSequenceLess(segment.sequence, highestSACK) {
			return false
		}
	}
	return true
}

// outstandingBytes returns bytes currently counted in the congestion pipe.
func outstandingBytes(outstanding []sentTCPSegment, includeSACKed bool) uint32 {
	var bytes uint32
	for _, segment := range outstanding {
		if includeSACKed || !segment.state.has(sentTCPSegmentSACKed) {
			bytes += segment.end - segment.sequence
		}
	}
	return bytes
}

// lossRecoveryFlightSize applies RFC 3042's exception: data sent by Limited
// Transmit is not included when DupThresh establishes the new ssthresh.
func lossRecoveryFlightSize(outstanding []sentTCPSegment) uint32 {
	var bytes uint32
	for _, segment := range outstanding {
		if !segment.state.has(sentTCPSegmentSACKed) && !segment.state.has(sentTCPSegmentLimited) {
			bytes += segment.end - segment.sequence
		}
	}
	return bytes
}

// tcpACKRTTAmbiguous implements Karn's algorithm for one cumulative ACK. If
// any newly acknowledged sequence range was retransmitted, the ACK cannot
// identify which transmission produced it, including untouched later ranges
// covered by the same cumulative acknowledgement.
func tcpACKRTTAmbiguous(outstanding []sentTCPSegment, acknowledgement uint32) bool {
	for _, segment := range outstanding {
		if !tcpSequenceLess(segment.sequence, acknowledgement) {
			break
		}
		if segment.isRetransmitted() {
			return true
		}
	}
	return false
}

// sackRecoveryPipe implements RFC 6675 SetPipe. An unSACKed range not yet
// considered lost counts its original transmission, while every retransmitted
// range counts its replacement as well. A speculative retransmission can
// therefore count twice, exactly as required by SetPipe.
func sackRecoveryPipe(outstanding []sentTCPSegment, mss int) uint32 {
	var bytes uint32
	var sackedRanges, sackedBytes int
	for index := len(outstanding) - 1; index >= 0; index-- {
		segment := outstanding[index]
		if segment.state.has(sentTCPSegmentSACKed) {
			sackedRanges++
			sackedBytes += int(segment.end - segment.sequence)
			continue
		}
		size := segment.end - segment.sequence
		lost := segment.state.has(sentTCPSegmentRACKLost) || sackedRanges >= tcpDuplicateACKThreshold || mss > 0 && sackedBytes > (tcpDuplicateACKThreshold-1)*mss
		if !lost {
			bytes = growCongestionWindow(bytes, size)
		}
		if segment.state.has(sentTCPSegmentSACKRetried) {
			bytes = growCongestionWindow(bytes, size)
		}
	}
	return bytes
}

// sackRecoveryCanSend applies RFC 6675's cwnd-Pipe gate. The one
// retransmission that enters recovery precedes SetPipe and is exempt.
func sackRecoveryCanSend(recovery bool, pipe, size, window uint32) bool {
	return !recovery || uint64(pipe)+uint64(size) <= uint64(window)
}

// tcpNewlyAcknowledgedBytes counts cumulative delivery not previously
// reported by SACK, avoiding double accounting in RFC 6937 PRR.
func tcpNewlyAcknowledgedBytes(outstanding []sentTCPSegment, acknowledgement uint32) uint32 {
	var delivered uint32
	for _, segment := range outstanding {
		if !tcpSequenceGreater(acknowledgement, segment.sequence) {
			break
		}
		if segment.state.has(sentTCPSegmentSACKed) {
			continue
		}
		end := segment.end
		if tcpSequenceLess(acknowledgement, end) {
			end = acknowledgement
		}
		delivered = growCongestionWindow(delivered, end-segment.sequence)
	}
	return delivered
}

// prrCongestionWindow implements Linux's byte-scaled RFC 6937 send-count
// calculation. Returning Pipe+sndcnt lets the existing RFC 6675 sender apply
// the allowance to retransmissions and new data with one common gate.
func prrCongestionWindow(pipe, threshold, priorFlight uint32, delivered, sent uint64, newlyDelivered uint32, cumulativeACK, newlyLost bool, mss int) uint32 {
	if newlyDelivered == 0 || priorFlight == 0 || mss < 1 {
		return pipe
	}
	var allowance uint64
	if pipe > threshold {
		target := (uint64(threshold)*delivered + uint64(priorFlight) - 1) / uint64(priorFlight)
		if target > sent {
			allowance = target - sent
		}
	} else {
		if delivered > sent {
			allowance = delivered - sent
		}
		if allowance < uint64(newlyDelivered) {
			allowance = uint64(newlyDelivered)
		}
		if cumulativeACK && !newlyLost {
			allowance += uint64(mss)
		}
		if available := uint64(threshold - pipe); allowance > available {
			allowance = available
		}
	}
	if allowance > uint64(tcpMaximumScaledWindow) {
		allowance = uint64(tcpMaximumScaledWindow)
	}
	return growCongestionWindow(pipe, uint32(allowance))
}

// tcpCongestionFlight selects RFC 6675 SetPipe while SACK recovery is active.
// Outside recovery, one copy of each unSACKed range is ordinary flight.
func tcpCongestionFlight(outstanding []sentTCPSegment, sack, recovery bool, mss int) uint32 {
	if sack && recovery {
		return sackRecoveryPipe(outstanding, mss)
	}
	return outstandingBytes(outstanding, false)
}

// rackReorderingWindow returns RFC 8985's initial min_RTT/4 settling
// allowance, bounded by SRTT as required for every adapted RACK window.
func rackReorderingWindow(minimumRTT, smoothedRTT time.Duration, scale uint32) time.Duration {
	if minimumRTT <= 0 || smoothedRTT <= 0 {
		return 0
	}
	if scale == 0 {
		scale = 1
	}
	window := minimumRTT / 4
	if window <= 0 {
		return 0
	}
	if scale > uint32(smoothedRTT/window) {
		return smoothedRTT
	}
	window *= time.Duration(scale)
	if window > smoothedRTT {
		window = smoothedRTT
	}
	return window
}

// newerRACKSample returns the later transmission under RFC 8985's transmit
// time ordering. Sequence order disambiguates timestamps with equal clock
// granularity.
func newerRACKSample(current, candidate tcpRACKSample) tcpRACKSample {
	if candidate.sentAt.IsZero() {
		return current
	}
	if candidate.sentAt.After(current.sentAt) || candidate.sentAt.Equal(current.sentAt) && tcpSequenceGreater(candidate.end, current.end) {
		return candidate
	}
	return current
}

// validRACKSample applies RFC 8985's fallback ambiguity check for a
// retransmitted segment. Without proof from a timestamp echo, an RTT below
// min_RTT can belong to the original transmission and must not advance RACK.
func validRACKSample(sample tcpRACKSample, minimumRTT time.Duration, timestampEcho uint32) tcpRACKSample {
	if sample.retransmitted {
		// RFC 8985 rejects a delivery sample when TSecr identifies an older
		// copy than the latest retransmission. The min-RTT check remains
		// necessary when timestamps are absent or coarser than the path RTT.
		if sample.timestamp != 0 && timestampEcho != 0 && tcpSequenceLess(timestampEcho, sample.timestamp) {
			return tcpRACKSample{}
		}
		if minimumRTT > 0 && sample.rtt < minimumRTT {
			return tcpRACKSample{}
		}
	}
	return sample
}

// rackDeliveredAfter reports whether delivered was transmitted after segment.
// A later ACK alone is insufficient: RACK compares transmit order so reordered
// acknowledgements cannot declare a newer transmission lost. epoch is the
// owning stack's timestamp epoch for the segment's compact queue stamp.
func rackDeliveredAfter(delivered tcpRACKSample, segment sentTCPSegment, epoch time.Time) bool {
	transmittedAt := segment.transmittedAt(epoch)
	return delivered.sentAt.After(transmittedAt) || delivered.sentAt.Equal(transmittedAt) && tcpSequenceGreater(delivered.end, segment.end)
}

// rackAdvanceForwardACK updates RFC 8985's highest newly delivered sequence
// and reports original data delivered out of order below that edge.
func rackAdvanceForwardACK(forward *uint32, set *bool, end uint32, retransmitted bool) bool {
	if !*set || tcpSequenceGreater(end, *forward) {
		*forward, *set = end, true
		return false
	}
	return tcpSequenceLess(end, *forward) && !retransmitted
}

// rackLossDelay returns RFC 8985's maximum remaining reordering wait across
// eligible transmissions. Linux measures each threshold as the latest
// delivered transmission's RTT plus reo_wnd minus the candidate's current age.
// epoch is the owning stack's timestamp epoch for candidate transmission times.
func rackLossDelay(outstanding []sentTCPSegment, delivered tcpRACKSample, now time.Time, reorderingWindow time.Duration, epoch time.Time) (time.Duration, bool) {
	var maximum time.Duration
	found := false
	for _, segment := range outstanding {
		// A range already declared lost waits for cwnd-Pipe space or the
		// ordinary RTO. Re-arming its expired reordering deadline would spin
		// the actor while recovery is congestion-window limited.
		if segment.state.has(sentTCPSegmentSACKed) || segment.state.has(sentTCPSegmentRACKLost) || !rackDeliveredAfter(delivered, segment, epoch) {
			continue
		}
		remaining := segment.transmittedAt(epoch).Add(delivered.rtt + reorderingWindow).Sub(now)
		if remaining < 0 {
			remaining = 0
		}
		if !found || remaining > maximum {
			maximum, found = remaining, true
		}
	}
	return maximum, found
}

// markRACKLoss records eligible transmissions whose reordering wait expired.
// A retransmission can itself be lost; clearing its SACK-recovery retry marker
// makes that range eligible for another recovery transmission instead of
// deferring it to RTO. epoch is the owning stack's timestamp epoch used to
// reconstruct candidate transmission times.
// The result reports whether any timed loss remains eligible.
func markRACKLoss(outstanding []sentTCPSegment, delivered tcpRACKSample, now time.Time, reorderingWindow time.Duration, epoch time.Time) bool {
	lost := false
	for index := range outstanding {
		segment := &outstanding[index]
		if !segment.state.has(sentTCPSegmentSACKed) && rackDeliveredAfter(delivered, *segment, epoch) && !now.Before(segment.transmittedAt(epoch).Add(delivered.rtt+reorderingWindow)) {
			segment.state.set(sentTCPSegmentRACKLost, true)
			segment.state.set(sentTCPSegmentSACKRetried, false)
		}
		lost = lost || segment.state.has(sentTCPSegmentRACKLost) && !segment.state.has(sentTCPSegmentSACKRetried)
	}
	return lost
}

// hasRACKLoss reports whether the scoreboard contains a timed loss.
func hasRACKLoss(outstanding []sentTCPSegment) bool {
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentRACKLost) && !segment.state.has(sentTCPSegmentSACKRetried) {
			return true
		}
	}
	return false
}

// firstRACKLoss returns the oldest range with time-based loss evidence.
func firstRACKLoss(outstanding []sentTCPSegment) int {
	for index := range outstanding {
		if outstanding[index].state.has(sentTCPSegmentRACKLost) && !outstanding[index].state.has(sentTCPSegmentSACKed) {
			return index
		}
	}
	return -1
}

// splitTCPSegments resegments unacknowledged payload after a PMTU reduction.
func splitTCPSegments(outstanding []sentTCPSegment, mss int) []sentTCPSegment {
	result := make([]sentTCPSegment, 0, len(outstanding))
	for _, segment := range outstanding {
		payloadSize := segment.dataSize()
		if payloadSize <= mss {
			result = append(result, segment)
			continue
		}
		for offset := 0; offset < payloadSize; offset += mss {
			end := offset + mss
			if end > payloadSize {
				end = payloadSize
			}
			part := segment
			part.sequence = segment.sequence + uint32(offset)
			part.end = segment.sequence + uint32(end)
			part.state.set(sentTCPSegmentCWR, offset == 0 && segment.state.has(sentTCPSegmentCWR))
			if end != payloadSize {
				part.flags &^= TCPFlagPSH | TCPFlagFIN
			} else if part.flags&TCPFlagFIN != 0 {
				part.end++
			}
			result = append(result, part)
		}
	}
	return result
}

// trimAcknowledgedTCPSegment removes a cumulatively acknowledged prefix from
// a partially acknowledged range. A data-plus-FIN segment can be acknowledged
// exactly through its data, leaving a FIN-only range in sequence space.
func trimAcknowledgedTCPSegment(segment *sentTCPSegment, acknowledgement uint32) {
	if segment == nil || !tcpSequenceGreater(acknowledgement, segment.sequence) || !tcpSequenceLess(acknowledgement, segment.end) {
		return
	}
	if skip := acknowledgement - segment.sequence; skip >= uint32(segment.dataSize()) {
		segment.flags &^= TCPFlagPSH
	}
	segment.sequence = acknowledgement
	// Any ACK inside this transmitted packet proves that its CWR header was
	// delivered even if a control flag remains outstanding.
	segment.state.set(sentTCPSegmentCWR, false)
}

// clampMSS applies local packet-size bounds to a peer MSS.
func clampMSS(value, maximum int) int {
	if value < tcpMinimumPeerMSS {
		value = tcpMinimumPeerMSS
	}
	if value > maximum {
		value = maximum
	}
	return value
}

// tcpSegmentPayloadLimit applies peer MSS to data only, while charging extra
// TCP options exclusively to the current path's header budget.
func tcpSegmentPayloadLimit(peerMSS, pathMSS, optionSize int) int {
	pathLimit := pathMSS - optionSize
	if pathLimit < peerMSS {
		return pathLimit
	}
	return peerMSS
}

// defaultTCPPeerMSS returns the RFC default for a SYN without an MSS option.
func defaultTCPPeerMSS(address netip.Addr) int {
	if address.Is4() {
		return 536
	}
	return 1220
}

// initialTCPWindow applies the RFC 6928 byte and segment limits.
func initialTCPWindow(mss int) uint32 {
	window := 10 * mss
	minimum := 2 * mss
	if minimum < 14600 {
		minimum = 14600
	}
	if window > minimum {
		window = minimum
	}
	return uint32(window)
}

// tcpRestartWindow applies RFC 5681's restart window after an idle interval
// longer than the current RTO.
func tcpRestartWindow(window uint32, mss int) uint32 {
	restart := initialTCPWindow(mss)
	if window < restart {
		return window
	}
	return restart
}

// growCongestionWindow adds delta without wrapping beyond TCP's maximum
// representable scaled receive window.
func growCongestionWindow(window, delta uint32) uint32 {
	if window >= tcpMaximumScaledWindow || delta >= tcpMaximumScaledWindow-window {
		return tcpMaximumScaledWindow
	}
	return window + delta
}

// newRenoPartialACKWindow applies RFC 6582 partial-window deflation. One
// SMSS is restored only when at least one complete SMSS left the network, and
// the result retains TCP's one-segment congestion-window floor.
func newRenoPartialACKWindow(window, acknowledged uint32, mss int) uint32 {
	if acknowledged >= window {
		window = 0
	} else {
		window -= acknowledged
	}
	minimum := uint32(mss)
	if acknowledged >= minimum {
		window = growCongestionWindow(window, minimum)
	}
	if window < minimum {
		window = minimum
	}
	return window
}

// receiveTCPData inserts one range and exposes all newly contiguous bytes.
func (c *TCPConn) receiveTCPData(sequence uint32, payload []byte, fin bool, receiveWindow uint32, receiveNext *uint32, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) (bool, bool) {
	owner := payload
	finSequence := sequence + uint32(len(payload))
	if tcpSequenceLess(sequence, *receiveNext) {
		skip := *receiveNext - sequence
		if skip < uint32(len(payload)) {
			payload = payload[skip:]
			sequence = *receiveNext
		} else {
			payload = nil
			sequence = *receiveNext
			fin = fin && finSequence == *receiveNext
		}
	}
	if sequence == *receiveNext && len(*outOfOrder) == 0 {
		// The overwhelmingly common in-order path does not need an
		// allocation, sort, or a second payload copy through the
		// out-of-order scoreboard.
		originalPayloadSize := len(payload)
		if uint64(len(payload)) > uint64(receiveWindow) {
			payload = payload[:receiveWindow]
		}
		accepted := c.appendReadBuffer(payload, owner, 0)
		*receiveNext += uint32(accepted)
		closed := fin && accepted == originalPayloadSize && uint64(originalPayloadSize) < uint64(receiveWindow)
		if closed {
			*receiveNext++
		}
		c.outOfOrderUnread.Store(0)
		return accepted != 0 || closed, closed
	}
	if !c.storeTCPOutOfOrder(*receiveNext, receiveWindow, sequence, payload, owner, fin, outOfOrder, outOfOrderBytes) && tcpSequenceGreater(sequence, *receiveNext) {
		return false, false
	}
	return c.promoteTCPReceived(receiveNext, outOfOrder, outOfOrderBytes)
}

// promoteTCPReceived exposes queued bytes that became deliverable after either
// a segment filled a sequence gap or the application reopened its window.
func (c *TCPConn) promoteTCPReceived(receiveNext *uint32, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) (bool, bool) {
	delivered, remoteClosed := false, false
	for len(*outOfOrder) != 0 && !remoteClosed {
		piece := (*outOfOrder)[0]
		owner := piece.payload
		if tcpSequenceGreater(piece.sequence, *receiveNext) {
			break
		}
		*outOfOrder = (*outOfOrder)[1:]
		*outOfOrderBytes -= len(piece.payload)
		pieceFINSequence := piece.sequence + uint32(len(piece.payload))
		if tcpSequenceLess(piece.sequence, *receiveNext) {
			skip := *receiveNext - piece.sequence
			if skip < uint32(len(piece.payload)) {
				piece.payload = piece.payload[skip:]
				piece.sequence = *receiveNext
			} else {
				piece.payload = nil
				piece.sequence = *receiveNext
				piece.fin = piece.fin && pieceFINSequence == *receiveNext
			}
		}
		accepted := c.appendReadBuffer(piece.payload, owner, *outOfOrderBytes)
		*receiveNext += uint32(accepted)
		delivered = delivered || accepted != 0
		if accepted != len(piece.payload) {
			remaining := retainTCPPayload(piece.payload[accepted:], owner)
			*outOfOrder = append([]tcpReceivedPiece{{sequence: *receiveNext, payload: remaining, fin: piece.fin}}, *outOfOrder...)
			*outOfOrderBytes += len(remaining)
			break
		}
		if piece.fin {
			*receiveNext++
			remoteClosed = true
		}
	}
	if remoteClosed {
		*outOfOrder = nil
		*outOfOrderBytes = 0
	}
	c.outOfOrderUnread.Store(int64(*outOfOrderBytes))
	return delivered || remoteClosed, remoteClosed
}

// tcpDataFragment is an uncovered portion of a newly received segment.
type tcpDataFragment struct {
	offset  uint32
	payload []byte
}

// storeTCPOutOfOrder retains only uncovered bytes within the receive window.
func (c *TCPConn) storeTCPOutOfOrder(receiveNext, receiveWindow, sequence uint32, payload, owner []byte, fin bool, outOfOrder *[]tcpReceivedPiece, outOfOrderBytes *int) bool {
	distance := sequence - receiveNext
	available := c.receiveAvailable(*outOfOrderBytes)
	if available < 0 {
		available = 0
	}
	if distance >= receiveWindow && !(distance == 0 && len(payload) == 0 && fin) {
		return false
	}
	originalPayloadSize := len(payload)
	if maximumPayload := int(receiveWindow - distance); len(payload) > maximumPayload {
		payload = payload[:maximumPayload]
	}
	fin = fin && (distance == 0 && len(payload) == 0 || uint64(distance)+uint64(originalPayloadSize) < uint64(receiveWindow))
	incomingFINSequence := sequence + uint32(originalPayloadSize)
	var existingFINSequence uint32
	hasExistingFIN := false
	for _, existing := range *outOfOrder {
		if existing.fin {
			existingFINSequence = existing.sequence + uint32(len(existing.payload))
			hasExistingFIN = true
			break
		}
	}
	if hasExistingFIN {
		// An earlier FIN terminates the stream before a previously queued FIN.
		// Retain it and let normalization discard all later sequence space.
		fin = fin && !tcpSequenceGreater(incomingFINSequence, existingFINSequence)
		payloadEnd := sequence + uint32(len(payload))
		if tcpSequenceGreater(payloadEnd, existingFINSequence) {
			if !tcpSequenceLess(sequence, existingFINSequence) {
				payload = nil
			} else {
				payload = payload[:existingFINSequence-sequence]
			}
		}
	}
	var fragmentWorkspace [2]tcpDataFragment
	fragments := fragmentWorkspace[:0]
	if len(payload) != 0 {
		start, end := distance, distance+uint32(len(payload))
		cursor := start
		for _, existing := range *outOfOrder {
			existingStart := existing.sequence - receiveNext
			existingEnd := existingStart + uint32(len(existing.payload))
			if existingEnd <= cursor {
				continue
			}
			if existingStart >= end {
				break
			}
			if cursor < existingStart {
				fragmentEnd := existingStart
				if fragmentEnd > end {
					fragmentEnd = end
				}
				fragments = append(fragments, tcpDataFragment{
					offset:  cursor,
					payload: payload[cursor-start : fragmentEnd-start],
				})
			}
			if existingEnd > cursor {
				cursor = existingEnd
			}
			if cursor >= end {
				break
			}
		}
		if cursor < end {
			fragments = append(fragments, tcpDataFragment{offset: cursor, payload: payload[cursor-start:]})
		}
	}
	addedBytes := 0
	for _, fragment := range fragments {
		addedBytes += len(fragment.payload)
	}
	upperCount := len(*outOfOrder) + len(fragments)
	if fin {
		upperCount++
	}
	reuseScoreboard := addedBytes <= available && upperCount <= tcpMaximumOutOfOrder && cap(*outOfOrder) >= upperCount
	var candidate []tcpReceivedPiece
	if reuseScoreboard {
		candidate = (*outOfOrder)[:len(*outOfOrder)]
	} else {
		candidate = append([]tcpReceivedPiece(nil), (*outOfOrder)...)
	}
	for _, fragment := range fragments {
		retained := retainTCPPayload(fragment.payload, owner)
		candidate = append(candidate, tcpReceivedPiece{sequence: receiveNext + fragment.offset, payload: retained})
	}
	if fin {
		candidate = append(candidate, tcpReceivedPiece{sequence: incomingFINSequence, fin: true})
	}
	candidate = normalizeTCPReceivedPieces(receiveNext, candidate)
	bytes := 0
	for _, piece := range candidate {
		bytes += len(piece.payload)
	}
	if bytes > *outOfOrderBytes+available || len(candidate) > tcpMaximumOutOfOrder {
		if !reuseScoreboard {
			return false
		}
	}
	*outOfOrder, *outOfOrderBytes = candidate, bytes
	c.outOfOrderUnread.Store(int64(bytes))
	return len(fragments) != 0 || fin
}

// normalizeTCPReceivedPieces sorts, merges, and truncates ranges at the first
// accepted FIN.
func normalizeTCPReceivedPieces(receiveNext uint32, pieces []tcpReceivedPiece) []tcpReceivedPiece {
	sort.SliceStable(pieces, func(left, right int) bool {
		leftOffset, rightOffset := pieces[left].sequence-receiveNext, pieces[right].sequence-receiveNext
		if leftOffset != rightOffset {
			return leftOffset < rightOffset
		}
		return len(pieces[left].payload) > len(pieces[right].payload)
	})
	var finOffset uint32
	hasFIN := false
	for _, piece := range pieces {
		if piece.fin {
			offset := piece.sequence - receiveNext + uint32(len(piece.payload))
			if !hasFIN || offset < finOffset {
				finOffset, hasFIN = offset, true
			}
		}
	}
	result := pieces[:0]
	for _, piece := range pieces {
		piece.fin = false
		pieceOffset := piece.sequence - receiveNext
		if hasFIN {
			if pieceOffset >= finOffset {
				continue
			}
			if pieceEnd := pieceOffset + uint32(len(piece.payload)); pieceEnd > finOffset {
				owner := piece.payload
				piece.payload = retainTCPPayload(piece.payload[:finOffset-pieceOffset], owner)
			}
		}
		if len(piece.payload) == 0 {
			continue
		}
		if len(result) == 0 {
			result = append(result, piece)
			continue
		}
		previous := &result[len(result)-1]
		previousEnd := previous.sequence + uint32(len(previous.payload))
		if tcpSequenceGreater(previousEnd, piece.sequence) {
			skip := previousEnd - piece.sequence
			if skip < uint32(len(piece.payload)) {
				owner := piece.payload
				piece.sequence += skip
				piece.payload = retainTCPPayload(piece.payload[skip:], owner)
				result = append(result, piece)
			}
		} else {
			result = append(result, piece)
		}
	}
	if hasFIN {
		finSequence := receiveNext + finOffset
		attached := false
		if len(result) != 0 {
			last := &result[len(result)-1]
			if last.sequence+uint32(len(last.payload)) == finSequence {
				last.fin = true
				attached = true
			}
		}
		if !attached {
			result = append(result, tcpReceivedPiece{sequence: finSequence, fin: true})
		}
	}
	for index := len(result); index < len(pieces); index++ {
		pieces[index] = tcpReceivedPiece{}
	}
	return result
}

// tcpSequenceLess compares sequence numbers modulo 2^32.
func tcpSequenceLess(left, right uint32) bool { return int32(left-right) < 0 }

// tcpSequenceGreater compares sequence numbers modulo 2^32.
func tcpSequenceGreater(left, right uint32) bool { return tcpSequenceLess(right, left) }

// tcpSequenceLessEqual compares sequence numbers modulo 2^32.
func tcpSequenceLessEqual(left, right uint32) bool { return !tcpSequenceGreater(left, right) }

// tcpSequenceGreaterEqual compares sequence numbers modulo 2^32.
func tcpSequenceGreaterEqual(left, right uint32) bool { return !tcpSequenceLess(left, right) }

// tcpAcceptableSendSequence follows Linux's tcp_acceptable_seq rule for an
// empty ACK or active reset after the peer shrinks its receive window. SND.NXT
// is normally correct, but a sequence beyond the shrunken right edge would be
// rejected before its ACK field can be processed.
func tcpAcceptableSendSequence(sendUnacknowledged, sendNext, sendWindow uint32, sendWindowScale uint8) uint32 {
	// A zero window has no scaling ambiguity: RFC 9293 accepts only an empty
	// segment exactly at RCV.NXT. Applying the scale quantum here can create an
	// ACK loop when a small amount of data remains unacknowledged.
	if sendWindow == 0 {
		return sendUnacknowledged
	}
	windowEnd := sendUnacknowledged + sendWindow
	if !tcpSequenceLess(windowEnd, sendNext) || sendNext-windowEnd < uint32(1)<<sendWindowScale {
		return sendNext
	}
	return windowEnd
}

// tcpChallengeACKSequence selects a response that a legitimate peer can
// accept after sending an out-of-window pure ACK during a window shrink. The
// segment is still dropped without changing the TCB; only an ACK already
// within the current send range may inform the response sequence.
func tcpChallengeACKSequence(segment tcpSegment, sendUnacknowledged, sendNext, currentSendWindow uint32, sendWindowScale uint8) uint32 {
	fallback := tcpAcceptableSendSequence(sendUnacknowledged, sendNext, currentSendWindow, sendWindowScale)
	if segment.flags != TCPFlagACK || len(segment.payload) != 0 || segment.acknowledgement-sendUnacknowledged > sendNext-sendUnacknowledged {
		return fallback
	}
	sendWindow := uint32(segment.window) << sendWindowScale
	return tcpAcceptableSendSequence(segment.acknowledgement, sendNext, sendWindow, sendWindowScale)
}

// tcpECNStartsRecovery permits one congestion response per transmitted window.
// Equality still belongs to the current recovery epoch; only an ACK beyond the
// saved boundary proves that later data encountered another CE mark.
func tcpECNStartsRecovery(active bool, acknowledgement, recoveryPoint uint32) bool {
	return !active || tcpSequenceGreater(acknowledgement, recoveryPoint)
}

// tcpSegmentAcceptable implements the RFC 9293 receive-window tests for a
// segment's first and last sequence numbers.
func tcpSegmentAcceptable(sequence, length, receiveNext, receiveWindow uint32) bool {
	if receiveWindow == 0 {
		return length == 0 && sequence == receiveNext
	}
	if sequence-receiveNext < receiveWindow {
		return true
	}
	return length != 0 && sequence+length-1-receiveNext < receiveWindow
}

// tcpKeepAliveOrWindowProbe recognizes the two RFC 9293 probe forms that use
// RCV.NXT-1 deliberately. They require an ordinary ACK and must not consume
// the RFC 5961 challenge-ACK rate limit.
func tcpKeepAliveOrWindowProbe(segment tcpSegment, length, receiveNext, receiveWindow uint32) bool {
	if segment.flags&(TCPFlagRST|TCPFlagSYN|TCPFlagFIN) != 0 || segment.flags&TCPFlagACK == 0 || segment.sequence != receiveNext-1 {
		return false
	}
	// RFC 1122 permits a keepalive to contain either no payload or one
	// garbage octet. The latter remains a keepalive when the receive window
	// is open; its sequence is deliberately just below the left edge.
	return length <= 1
}

// tcpWindowUpdateAllowed implements the RFC 9293 SND.WL1/SND.WL2 ordering
// rule so reordered ACKs cannot restore a stale advertised send window.
func tcpWindowUpdateAllowed(sequence, acknowledgement, lastSequence, lastAcknowledgement uint32) bool {
	return tcpSequenceGreater(sequence, lastSequence) ||
		sequence == lastSequence && tcpSequenceGreaterEqual(acknowledgement, lastAcknowledgement)
}

// tcpDuplicateACKEvidence applies the deliberately different RFC 5681 and RFC
// 6675 duplicate-ACK definitions. A SACK sender counts newly reported
// scoreboard data even when the segment also advances ACK, updates the window,
// or carries data. Without SACK, only a repeated pure ACK with an unchanged
// advertised window provides classic fast-retransmit evidence.
func tcpDuplicateACKEvidence(segment tcpSegment, peerSACK, newSACKInfo, ackAdvanced bool, sendUnacknowledged, previousWindow, peerWindow uint32) bool {
	if peerSACK {
		return newSACKInfo
	}
	return !ackAdvanced && segment.acknowledgement == sendUnacknowledged && previousWindow == peerWindow &&
		len(segment.payload) == 0 && segment.flags&(TCPFlagSYN|TCPFlagFIN) == 0
}

// Verify that TCPConn implements net.Conn.
var _ net.Conn = (*TCPConn)(nil)

// Verify the additional standard TCPConn interfaces.
var _ io.ReaderFrom = (*TCPConn)(nil)
var _ io.WriterTo = (*TCPConn)(nil)
