// Package mipstack implements the mihomo IP stack (MIPS), a small userspace
// IPv4/IPv6 endpoint stack for applications that exchange complete packets
// with an L3 link. It implements active and passive TCP, connected and
// unconnected UDP and IP protocol sockets, and the ICMP behavior required by
// those transports. Optional forwarders provide transparent handling of
// otherwise unbound TCP, UDP, ICMP, and other IP protocol traffic.
package mipstack

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// dynamicPortFirst is the first IANA dynamic client port.
	dynamicPortFirst = 49152
	// dynamicPortCount is the size of the IANA dynamic port range.
	dynamicPortCount = 1 << 14
	// fallbackPortFirst keeps well-known ports out of automatic allocation.
	fallbackPortFirst = 1024
	// fallbackPortCount is used only after the IANA dynamic range is exhausted.
	fallbackPortCount = dynamicPortFirst - fallbackPortFirst
	// defaultMTU matches the conventional Ethernet payload MTU.
	defaultMTU = 1500
	// ipv6MinimumMTU is both the minimum configured IPv6 link MTU and the
	// maximum complete ICMPv6 error size required by RFC 4443.
	ipv6MinimumMTU = 1280
	// outboundPacketQueue bounds packets waiting for the embedding link.
	outboundPacketQueue = 256
	// loopbackPacketQueue bounds asynchronous local delivery and prevents a
	// socket actor from recursively entering its own protocol handler.
	loopbackPacketQueue = 256
	// packetReusableBufferLimit retains common link-MTU packets while allowing
	// uncommon jumbo packets to be collected immediately after transmission.
	packetReusableBufferLimit = 2048
	// pathMTUMaximumEntries bounds destinations learned from authenticated
	// transport tuples so long-running proxy workloads cannot grow the cache
	// without limit.
	pathMTUMaximumEntries = 1024
	// pathMTULifetime eventually retries the controller-provided link MTU after
	// a transient lower-path constraint disappears.
	pathMTULifetime = 10 * time.Minute
	// controlResponseRate is the sustained number of unsolicited control
	// responses permitted per class and second.
	controlResponseRate = 100
	// controlResponseBurst permits short diagnostic bursts without allowing a
	// packet flood to monopolize the outbound queue.
	controlResponseBurst = 200
	// recentDestinationMaximum bounds ICMP correlation state for one
	// connectionless socket.
	recentDestinationMaximum = 256
	// recentDestinationLifetime accepts delayed network errors without
	// retaining every destination used by a long-running socket.
	recentDestinationLifetime = 2 * time.Minute
	// datagramQueueRetain keeps a small metadata burst allocation after a queue
	// drains without pinning an application-sized receive queue on idle sockets.
	datagramQueueRetain = 4
	// datagramReusablePayloadLimit keeps one common MTU payload backing per
	// active socket while allowing jumbo datagrams to be collected after Read.
	datagramReusablePayloadLimit = 2048
)

var (
	// ErrClosed is returned after the stack has been closed.
	ErrClosed = net.ErrClosed
	// ErrNotStarted is returned when packet or socket I/O is attempted before
	// Start.
	ErrNotStarted = errors.New("mipstack: stack is not started")
	// ErrNoPorts reports exhaustion of all automatically allocated,
	// non-privileged ports.
	ErrNoPorts = errors.New("mipstack: no automatic ports available")
	// ErrResourceLimit reports exhaustion of a bounded in-memory socket or
	// protocol resource.
	ErrResourceLimit = errors.New("mipstack: resource limit reached")
	// ErrForwarderRequestCompleted reports an action on a forwarder request that
	// was already accepted, detached, dropped, rejected, invalidated, or whose
	// callback lifetime has ended.
	ErrForwarderRequestCompleted = errors.New("mipstack: forwarder request is already completed")
)

// TCPSocketDefaults configures policies inherited by newly created TCP
// connections and listeners. Zero fields retain the package defaults.
type TCPSocketDefaults struct {
	// CongestionControl selects the algorithm used by new connections. The
	// zero value selects CUBIC. UpdateConfig also applies a changed value to
	// established connections without an explicit per-connection override. It
	// must be empty when CongestionControlFactory is set.
	CongestionControl CongestionControl
	// CongestionControlFactory selects an immutable local factory without
	// process-wide registration. It must be created by
	// NewCongestionControlFactory and is mutually exclusive with
	// CongestionControl. The factory creates an independent controller for every
	// connection and may be shared safely by multiple stacks and listeners.
	CongestionControlFactory *CongestionControlFactory
	// ReceiveBuffer is the initial application receive capacity.
	ReceiveBuffer int
	// MaximumReceiveBuffer bounds automatic receive tuning.
	MaximumReceiveBuffer int
	// SendBuffer is the initial application send capacity.
	SendBuffer int
	// MaximumSendBuffer bounds automatic send tuning.
	MaximumSendBuffer int
	// MaximumPacingRate caps the paced-data rate of new TCP connections in
	// bytes per second. Zero leaves the pacing rate unlimited. Initial and
	// control bursts mean this is not a strict byte-rate shaper.
	MaximumPacingRate uint64
	// AcceptQueue bounds completed connections waiting for Accept.
	AcceptQueue int
	// SYNBacklog bounds stateful handshakes before SYN cookies are used.
	SYNBacklog int
	// KeepAlive enables keepalive probes on new connections.
	KeepAlive bool
	// KeepAliveConfig supplies the default probe timing and retry count.
	KeepAliveConfig KeepAliveConfig
	// IdleTimeout closes a connection after receive inactivity. Zero disables it.
	IdleTimeout time.Duration
	// UserTimeout bounds how long transmitted data may remain unacknowledged,
	// or buffered data may remain unsent behind a zero window. Zero disables
	// this custom bound while retaining the normal TCP retry limits.
	UserTimeout time.Duration
	// DisableNoDelay makes new connections start with Nagle coalescing enabled.
	DisableNoDelay bool
	// TrafficClass supplies IPv4 TOS or IPv6 Traffic Class DSCP bits. TCP
	// controls the two ECN bits independently.
	TrafficClass uint8
	// FlowLabel fixes the IPv6 Flow Label on new connections. Zero selects a
	// stable RFC 6437-style label derived from the connection tuple.
	FlowLabel uint32
}

// PathMTUDiscovery is the Linux-compatible IP_MTU_DISCOVER policy used by UDP
// and IP protocol sockets. Its numeric values match IP_PMTUDISC_* so callers
// translating a Linux socket policy do not need another mapping table.
type PathMTUDiscovery int

const (
	// PathMTUDiscoveryDont permits source fragmentation and leaves IPv4 DF
	// clear. Validated destination PMTU information still selects the local
	// fragment size, matching Linux IP_PMTUDISC_DONT route-cache behavior.
	PathMTUDiscoveryDont PathMTUDiscovery = iota
	// PathMTUDiscoveryWant uses the destination PMTU, sets IPv4 DF when a
	// datagram fits, and source-fragments it when needed.
	PathMTUDiscoveryWant
	// PathMTUDiscoveryDo uses the destination PMTU, always sets IPv4 DF, and
	// reports EMSGSIZE instead of source-fragmenting an oversized datagram.
	PathMTUDiscoveryDo
	// PathMTUDiscoveryProbe ignores the destination PMTU, uses the embedding
	// interface MTU, sets IPv4 DF, and reports EMSGSIZE above that MTU.
	PathMTUDiscoveryProbe
	// PathMTUDiscoveryInterface ignores destination PMTU updates, uses the
	// embedding interface MTU, leaves IPv4 DF clear, and reports EMSGSIZE above
	// that MTU.
	PathMTUDiscoveryInterface
	// PathMTUDiscoveryOmit ignores destination PMTU updates, uses the embedding
	// interface MTU, leaves IPv4 DF clear, and permits source fragmentation.
	PathMTUDiscoveryOmit
)

// valid reports whether mode is one of Linux's IP_PMTUDISC_* values.
func (mode PathMTUDiscovery) valid() bool {
	return mode >= PathMTUDiscoveryDont && mode <= PathMTUDiscoveryOmit
}

// SocketMessage represents one scatter/gather datagram or IP protocol
// message. Its layout and field meanings match golang.org/x/net/ipv4.Message
// and golang.org/x/net/ipv6.Message without requiring either package.
type SocketMessage struct {
	// Buffers contains the contiguous payload regions read or written in order.
	// A batch operation requires their combined length to be nonzero.
	Buffers [][]byte
	// OOB contains Linux-compatible packet-info, hop-limit, traffic-class,
	// IPv6 flow-label, or asynchronous-error ancillary data.
	OOB []byte
	// Addr specifies the destination for an unconnected write and receives the
	// source address after a successful read. It must be nil for a connected
	// write.
	Addr net.Addr
	// N is the number of payload bytes read or written through Buffers.
	N int
	// NN is the number of ancillary bytes read or written through OOB.
	NN int
	// Flags contains Linux-compatible MSG_TRUNC, MSG_CTRUNC, and MSG_ERRQUEUE
	// results after a successful read.
	Flags int
}

const (
	// MessageFlagPeek is Linux MSG_PEEK. Ordinary ReadBatch calls copy the oldest
	// queued payload without consuming it. A pending socket error and a
	// MessageFlagErrorQueue result are still consumed, matching Linux recvmsg.
	MessageFlagPeek = 0x02
	// MessageFlagControlTruncated is Linux MSG_CTRUNC. ReadMsg and ReadBatch include
	// it in the result flags when the supplied OOB buffer was too small.
	MessageFlagControlTruncated = 0x08
	// MessageFlagTruncated is Linux MSG_TRUNC. ReadMsg and ReadBatch include it in
	// the result flags when the supplied payload buffers were too small.
	MessageFlagTruncated = 0x20
	// MessageFlagDontWait is Linux MSG_DONTWAIT. Reads and writes return EAGAIN
	// instead of waiting for queue state to change.
	MessageFlagDontWait = 0x40
	// MessageFlagErrorQueue is Linux MSG_ERRQUEUE. ReadBatch reads asynchronous
	// network errors instead of ordinary payloads and never blocks.
	MessageFlagErrorQueue = 0x2000
)

// DatagramSocketDefaults configures policies inherited by newly created UDP
// or IP protocol sockets. Zero fields retain the package defaults.
type DatagramSocketDefaults struct {
	// ReceiveBuffer is the approximate retained-memory receive capacity.
	ReceiveBuffer int
	// ReceiveErrors reserves asynchronous network errors for ReadError instead
	// of returning them from ordinary reads after queued payloads.
	ReceiveErrors bool
	// PathMTUDiscovery selects the Linux-compatible source-fragmentation and
	// destination-PMTU policy. The zero value is PathMTUDiscoveryDont.
	PathMTUDiscovery PathMTUDiscovery
	// HopLimit is the default IPv4 TTL or IPv6 Hop Limit. Zero selects 64.
	HopLimit int
	// MulticastHopLimit is the default IPv4 multicast TTL or IPv6 multicast
	// Hop Limit. Zero selects the socket-compatible default of one hop.
	MulticastHopLimit int
	// DisableMulticastLoopback disables delivery of transmitted multicast
	// packets to matching local memberships. Loopback is enabled by default,
	// matching IP_MULTICAST_LOOP and IPV6_MULTICAST_LOOP.
	DisableMulticastLoopback bool
	// DisableBroadcast clears the SO_BROADCAST-equivalent permission inherited
	// by new sockets. Broadcast is enabled by default, matching Go's net UDP
	// sockets on supported operating systems.
	DisableBroadcast bool
	// TrafficClass is the default IPv4 TOS or IPv6 Traffic Class byte.
	TrafficClass uint8
	// FlowLabel is the default IPv6 Flow Label. Zero selects a stable automatic
	// label for each destination flow.
	FlowLabel uint32
}

// Config configures a Stack.
type Config struct {
	// LocalAddresses lists addresses owned by ordinary sockets and available
	// for source selection and loopback delivery.
	LocalAddresses []netip.Prefix
	// AddressProperties optionally marks configured local addresses as
	// deprecated or temporary for RFC 6724 source selection. Every key must
	// identify an address in LocalAddresses.
	AddressProperties map[netip.Addr]AddressProperties
	// PreferTemporaryAddresses applies RFC 6724 rule 7 in favor of temporary
	// IPv6 privacy addresses. The zero value favors stable public addresses,
	// matching Linux unless per-interface privacy preference is enabled.
	PreferTemporaryAddresses bool
	// Promiscuous admits unicast packets addressed to otherwise nonlocal
	// destinations so protocol forwarders can intercept them. Forwarders do not
	// require Promiscuous for unhandled packets addressed to LocalAddresses.
	// Enabling Promiscuous without a matching forwarder only admits and silently
	// drops nonlocal protocol traffic. Ordinary sockets retain
	// LocalAddresses semantics, and only forwarder-created endpoints or
	// request-scoped actions may reply from intercepted addresses.
	Promiscuous bool
	// MTU bounds packets emitted by Read. Zero selects 1500.
	MTU uint32
	// Routes optionally restrict admitted unicast destinations and provide a
	// preferred source. Nil installs one default route per configured address
	// family; a non-nil empty slice installs no routes.
	Routes []Route
	// MaxTCPConnections optionally bounds active, handshaking, and TIME_WAIT
	// connections. Zero leaves the number unbounded; per-listener queues and
	// per-connection buffers remain independently bounded.
	MaxTCPConnections int
	// TCP supplies default socket and listener policies.
	TCP TCPSocketDefaults
	// UDP supplies defaults inherited by new UDP sockets.
	UDP DatagramSocketDefaults
	// IP supplies defaults inherited by new IP protocol sockets.
	IP DatagramSocketDefaults
}

// Stack converts raw IPv4/IPv6 packets to application TCP, UDP, and IP
// protocol sockets.
type Stack struct {
	network  atomic.Pointer[networkState]
	outbound packetQueue
	loopback packetQueue

	mu            sync.RWMutex
	started       bool
	closed        bool
	tcp           map[tcpKey]*TCPConn
	tcpPassive    tcpPassiveEndpoints
	tcpForwarder  tcpForwarderEndpoints
	udp           map[udpKey]*UDPConn
	udpReuse      udpReuseEndpoints
	udpForwarded  map[udpFlowKey]*UDPConn
	udpForwarder  udpForwarderEndpoints
	ip            ipEndpoints
	ipForwarder   ipForwarderEndpoints
	multicast     multicastEndpoints
	multicastSeed *multicastQuerierSeed
	icmpForwarder icmpForwarderEndpoints
	nextPort      [2]automaticPortCursor

	pathMTUMu sync.RWMutex
	pathMTU   map[netip.Addr]pathMTUEntry

	ipv4ID          atomic.Uint32
	ipv6FragmentID  atomic.Uint32
	nextOutputFlow  atomic.Uint64
	closeCh         chan struct{}
	timestampEpoch  time.Time
	tcpISNSecret    [16]byte
	flowLabelSecret [16]byte

	fragmentMu    sync.Mutex
	fragments     map[fragmentKey]*ipPacketReassemblyEntry
	fragmentBytes int
	fragmentWake  chan struct{}

	controlMu       sync.Mutex
	controlLimiters [controlResponseClassCount]tokenBucket
	stats           stackCounters
}

// inboundDestinationClass keeps local ownership, non-unicast reception, and
// transparent admission distinct throughout transport dispatch.
type inboundDestinationClass uint8

const (
	// inboundDestinationRejected identifies traffic outside every admissible
	// local, non-unicast, and transparent destination class.
	inboundDestinationRejected inboundDestinationClass = iota
	// inboundDestinationLocalUnicast identifies an address owned by the Stack.
	inboundDestinationLocalUnicast
	// inboundDestinationBroadcast identifies limited or configured-subnet IPv4
	// broadcast traffic.
	inboundDestinationBroadcast
	// inboundDestinationMulticast identifies traffic admitted by an implicit
	// all-hosts group or an explicit multicast membership.
	inboundDestinationMulticast
	// inboundDestinationPromiscuousUnicast identifies nonlocal unicast admitted
	// only for transparent forwarders.
	inboundDestinationPromiscuousUnicast
)

// StackStats is a point-in-time snapshot of stack activity. Counters are
// monotonic except ActiveTCPConnections, ActiveTCPListeners,
// ActiveUDPSockets, and ActiveIPSockets.
type StackStats struct {
	// InboundPackets counts complete packets presented to the stack.
	InboundPackets uint64
	// InboundDroppedPackets counts invalid packets and bounded-queue drops.
	InboundDroppedPackets uint64
	// InvalidIPPackets counts packets rejected by IP parsing or reassembly.
	InvalidIPPackets uint64
	// UnacceptedIPPackets counts valid packets whose source or destination is
	// not admissible for this endpoint stack.
	UnacceptedIPPackets uint64
	// NonlocalDestinationPackets is the unaccepted subset addressed elsewhere.
	NonlocalDestinationPackets uint64
	// PromiscuousInboundPackets counts valid packets admitted for a destination
	// not present in LocalAddresses.
	PromiscuousInboundPackets uint64
	// InvalidSourcePackets is the unaccepted subset with a prohibited source.
	InvalidSourcePackets uint64
	// OutboundPackets counts complete packets accepted by the device queue.
	OutboundPackets uint64
	// LoopbackPackets counts locally routed packets that bypassed the link.
	LoopbackPackets uint64
	// ActiveTCPConnections includes handshakes, established flows, and
	// TIME_WAIT actors.
	ActiveTCPConnections uint64
	// ActiveTCPListeners is the current number of passive TCP endpoints.
	ActiveTCPListeners uint64
	// ActiveUDPSockets is the current number of open packet sockets.
	ActiveUDPSockets uint64
	// ActiveIPSockets is the current number of open protocol sockets.
	ActiveIPSockets uint64
	// TCPRetransmissions counts all SYN, data, FIN, SACK, RACK, and tail-probe
	// retransmissions.
	TCPRetransmissions uint64
	// TCPInboundQueueDrops counts validated segments rejected by a connection's
	// byte-bounded actor queue.
	TCPInboundQueueDrops uint64
	// TCPInvalidSegments counts malformed headers and checksum failures.
	TCPInvalidSegments uint64
	// TCPSACKRetransmissions counts retransmissions selected by the SACK
	// scoreboard, including its RACK-confirmed subset.
	TCPSACKRetransmissions uint64
	// TCPRACKRetransmissions counts the time-based subset of SACK recovery.
	TCPRACKRetransmissions uint64
	// TCPTailLossProbes counts probes sent before the ordinary RTO.
	TCPTailLossProbes uint64
	// TCPSpuriousRecoveryUndos counts Eifel or DSACK evidence that safely
	// restored congestion state after an unnecessary retransmission.
	TCPSpuriousRecoveryUndos uint64
	// TCPZeroWindowProbes counts persist probes sent while the peer advertises
	// a closed receive window.
	TCPZeroWindowProbes uint64
	// TCPKeepAliveProbes counts probes sent after configured receive inactivity.
	TCPKeepAliveProbes uint64
	// TCPSYNCookiesSent counts stateless SYN-ACKs emitted under listener or
	// stack connection pressure.
	TCPSYNCookiesSent uint64
	// TCPSYNCookiesAccepted counts final ACKs that authenticated a recent SYN
	// cookie and entered a listener backlog.
	TCPSYNCookiesAccepted uint64
	// TCPSYNCookiesRejected counts candidate final ACKs that failed cookie
	// authentication while cookie validation was active.
	TCPSYNCookiesRejected uint64
	// TCPHandshakeTimeouts counts passive stateful handshakes that exhausted
	// their SYN-ACK retry budget.
	TCPHandshakeTimeouts uint64
	// TCPAcceptQueueDrops counts completed handshakes aborted because their
	// listener's accept queue was full.
	TCPAcceptQueueDrops uint64
	// PathMTUUpdates counts accepted destination PMTU reductions.
	PathMTUUpdates uint64
	// PathMTUProbes counts TCP packets sent above the confirmed effective MTU.
	PathMTUProbes uint64
	// PathMTUProbeSuccesses counts acknowledged upward TCP probes.
	PathMTUProbeSuccesses uint64
	// PathMTUProbeFailures counts isolated upward probes rejected by SACK
	// evidence without treating them as congestion loss.
	PathMTUProbeFailures uint64
	// PathMTUBlackHoleReductions counts PMTU reductions inferred from repeated
	// TCP timeouts rather than ICMP.
	PathMTUBlackHoleReductions uint64
	// FragmentEvictions counts incomplete datagrams removed for capacity.
	FragmentEvictions uint64
	// FragmentTimeouts counts incomplete datagrams removed for age.
	FragmentTimeouts uint64
	// RateLimitedControlResponses counts suppressed TCP RST and challenge ACK,
	// ICMP unreachable, parameter-problem, and ICMP echo replies.
	RateLimitedControlResponses uint64
}

// stackCounters stores concurrently updated statistics.
type stackCounters struct {
	inboundPackets              atomic.Uint64
	inboundDroppedPackets       atomic.Uint64
	invalidIPPackets            atomic.Uint64
	unacceptedIPPackets         atomic.Uint64
	nonlocalDestinationPackets  atomic.Uint64
	promiscuousInboundPackets   atomic.Uint64
	invalidSourcePackets        atomic.Uint64
	outboundPackets             atomic.Uint64
	loopbackPackets             atomic.Uint64
	activeTCPConnections        atomic.Uint64
	activeTCPListeners          atomic.Uint64
	activeUDPSockets            atomic.Uint64
	activeIPSockets             atomic.Uint64
	tcpRetransmissions          atomic.Uint64
	tcpInboundQueueDrops        atomic.Uint64
	tcpInvalidSegments          atomic.Uint64
	tcpSACKRetransmissions      atomic.Uint64
	tcpRACKRetransmissions      atomic.Uint64
	tcpTailLossProbes           atomic.Uint64
	tcpSpuriousRecoveryUndos    atomic.Uint64
	tcpZeroWindowProbes         atomic.Uint64
	tcpKeepAliveProbes          atomic.Uint64
	tcpSYNCookiesSent           atomic.Uint64
	tcpSYNCookiesAccepted       atomic.Uint64
	tcpSYNCookiesRejected       atomic.Uint64
	tcpHandshakeTimeouts        atomic.Uint64
	tcpAcceptQueueDrops         atomic.Uint64
	pathMTUUpdates              atomic.Uint64
	pathMTUProbes               atomic.Uint64
	pathMTUProbeSuccesses       atomic.Uint64
	pathMTUProbeFailures        atomic.Uint64
	pathMTUBlackHoleReductions  atomic.Uint64
	fragmentEvictions           atomic.Uint64
	fragmentTimeouts            atomic.Uint64
	rateLimitedControlResponses atomic.Uint64
}

// controlResponseClass separates independent control-plane token buckets.
type controlResponseClass uint8

const (
	// controlResponseTCPReset limits resets for unbound TCP tuples.
	controlResponseTCPReset controlResponseClass = iota
	// controlResponseTCPChallengeACK limits RFC 5961 acknowledgements for
	// suspicious segments on established tuples.
	controlResponseTCPChallengeACK
	// controlResponsePortUnreachable limits ICMP errors for unbound UDP ports.
	controlResponsePortUnreachable
	// controlResponseEchoReply limits ICMP echo replies.
	controlResponseEchoReply
	// controlResponseParameterProblem limits errors for unsupported IPv6
	// options and upper-layer protocols.
	controlResponseParameterProblem
	// controlResponseFragmentTimeout limits ICMP reassembly timeout errors.
	controlResponseFragmentTimeout
	// controlResponseClassCount is the number of independent token buckets.
	controlResponseClassCount
)

// tokenBucket is one lock-protected control-response limiter.
type tokenBucket struct {
	tokens  float64
	updated time.Time
}

// pathMTUEntry is one learned destination MTU and its last confirmation.
type pathMTUEntry struct {
	mtu     int
	updated time.Time
}

// recentDestinationCache retains bounded evidence that a connectionless
// socket actually sent to a destination quoted by an ICMP error. Callers own
// synchronization so the cache can share their existing socket mutex.
type recentDestinationCache[T comparable] map[T]time.Time

// remember records a successful transmission and evicts expired or oldest
// evidence when the bound is full.
func (c *recentDestinationCache[T]) remember(destination T, now time.Time) {
	if *c == nil {
		*c = make(recentDestinationCache[T])
	}
	cache := *c
	if _, exists := cache[destination]; exists {
		cache[destination] = now
		return
	}
	if len(cache) >= recentDestinationMaximum {
		var oldest T
		var oldestTime time.Time
		haveOldest := false
		for candidate, updated := range cache {
			if now.Sub(updated) >= recentDestinationLifetime {
				delete(cache, candidate)
				continue
			}
			if !haveOldest || updated.Before(oldestTime) {
				oldest, oldestTime, haveOldest = candidate, updated, true
			}
		}
		if len(cache) >= recentDestinationMaximum && haveOldest {
			delete(cache, oldest)
		}
	}
	cache[destination] = now
}

// contains reports recent transmission evidence and removes it after expiry.
func (c recentDestinationCache[T]) contains(destination T, now time.Time) bool {
	updated, exists := c[destination]
	if exists && now.Sub(updated) >= recentDestinationLifetime {
		delete(c, destination)
		return false
	}
	return exists
}

// datagramQueue is a compact FIFO whose small backing allocation survives an
// empty transition. A head index avoids moving queued payload metadata on each
// read; larger bursts are released when fully drained.
type datagramQueue[T any] struct {
	values []T
	head   int
}

const socketErrorMetadataSize = 192

// queuedSocketError retains one asynchronous network error and its
// conservative receive-buffer charge.
type queuedSocketError struct {
	err     *net.OpError
	payload []byte
	size    int
}

// socketErrorSize returns the receive-buffer charge for an asynchronous
// network error, including any retained quoted packet bytes.
func socketErrorSize(err error) int {
	size := socketErrorMetadataSize
	var networkError ICMPError
	if errors.As(err, &networkError) {
		if len(networkError.QuotedPacket) != 0 {
			size += len(networkError.QuotedPacket)
		} else {
			size += len(networkError.QuotedPayload)
		}
		size += len(networkError.Extensions)
	}
	return size
}

// messageBufferLength validates the nonempty scatter/gather payload required
// by the batch API and detects integer overflow before allocation.
func messageBufferLength(buffers [][]byte) (int, error) {
	total := 0
	maximum := int(^uint(0) >> 1)
	for _, buffer := range buffers {
		if len(buffer) > maximum-total {
			return 0, syscall.EMSGSIZE
		}
		total += len(buffer)
	}
	if total == 0 {
		return 0, syscall.EINVAL
	}
	return total, nil
}

// copyMessagePayload scatters one complete payload across buffers in order.
func copyMessagePayload(buffers [][]byte, payload []byte) int {
	written := 0
	for _, buffer := range buffers {
		if len(payload) == 0 {
			break
		}
		n := copy(buffer, payload)
		written += n
		payload = payload[n:]
	}
	return written
}

// copyMessageBuffers joins scatter/gather source regions into destination
// without allocating an intermediate payload.
func copyMessageBuffers(destination []byte, buffers [][]byte) int {
	written := 0
	for _, buffer := range buffers {
		written += copy(destination[written:], buffer)
		if written == len(destination) {
			break
		}
	}
	return written
}

// gatherMessagePayload returns the single supplied region directly and joins
// a true scatter/gather message only when the existing transmit path requires
// contiguous protocol payload bytes.
func gatherMessagePayload(buffers [][]byte, maximum int) ([]byte, error) {
	size, err := messageBufferLength(buffers)
	if err != nil {
		return nil, err
	}
	if size > maximum {
		return nil, syscall.EMSGSIZE
	}
	if len(buffers) == 1 {
		return buffers[0], nil
	}
	payload := make([]byte, size)
	offset := 0
	for _, buffer := range buffers {
		offset += copy(payload[offset:], buffer)
	}
	return payload, nil
}

// fillSocketErrorMessage copies one immutable error-queue entry into the
// public scatter/gather representation.
func fillSocketErrorMessage(message *SocketMessage, queued queuedSocketError, returnLength bool) error {
	if _, err := messageBufferLength(message.Buffers); err != nil {
		return err
	}
	control, err := socketErrorControlForRead(queued.err)
	if err != nil {
		return err
	}
	copied := copyMessagePayload(message.Buffers, queued.payload)
	n := copied
	flags := MessageFlagErrorQueue
	if copied < len(queued.payload) {
		flags |= MessageFlagTruncated
		if returnLength {
			n = len(queued.payload)
		}
	}
	oobn := copy(message.OOB, control)
	if oobn < len(control) {
		flags |= MessageFlagControlTruncated
	}
	message.N, message.NN, message.Flags, message.Addr = n, oobn, flags, queued.err.Addr
	return nil
}

// readSocketErrorMessage fills one message from the queue head and consumes it
// only after every validation and ancillary-data conversion succeeds. Linux
// MSG_ERRQUEUE ignores MSG_PEEK, so a successful read always removes the
// error. The caller must hold the owning socket mutex for the complete call.
func readSocketErrorMessage(queue *datagramQueue[queuedSocketError], message *SocketMessage, flags int) (size int, ok bool, err error) {
	queued, ok := queue.peek()
	if !ok {
		return 0, false, nil
	}
	if err := fillSocketErrorMessage(message, queued, flags&MessageFlagTruncated != 0); err != nil {
		return 0, true, err
	}
	consumed, popped := queue.pop()
	if !popped {
		panic("mipstack: socket error queue changed while locked")
	}
	return consumed.size, true, nil
}

// len returns the number of queued values.
func (q *datagramQueue[T]) len() int { return len(q.values) - q.head }

// push appends one value while compacting a full partially consumed backing.
func (q *datagramQueue[T]) push(value T) {
	if q.head != 0 && len(q.values) == cap(q.values) {
		copy(q.values, q.values[q.head:])
		remaining := len(q.values) - q.head
		var zero T
		for index := remaining; index < len(q.values); index++ {
			q.values[index] = zero
		}
		q.values = q.values[:remaining]
		q.head = 0
	}
	q.values = append(q.values, value)
}

// peek returns the oldest value without changing queue ownership.
func (q *datagramQueue[T]) peek() (T, bool) {
	var zero T
	if q.head == len(q.values) {
		return zero, false
	}
	return q.values[q.head], true
}

// pop removes the oldest value and releases oversized drained backing storage.
func (q *datagramQueue[T]) pop() (T, bool) {
	var zero T
	if q.head == len(q.values) {
		return zero, false
	}
	value := q.values[q.head]
	q.values[q.head] = zero
	q.head++
	if q.head == len(q.values) {
		if cap(q.values) <= datagramQueueRetain {
			q.values = q.values[:0]
		} else {
			q.values = nil
		}
		q.head = 0
	}
	return value, true
}

// clear releases all values and backing storage.
func (q *datagramQueue[T]) clear() {
	var zero T
	for index := range q.values {
		q.values[index] = zero
	}
	q.values = nil
	q.head = 0
}

// udpKey identifies one specific or wildcard local UDP endpoint.
type udpKey struct {
	address netip.Addr
	port    uint16
}

// udpFlowKey identifies a connected forwarded UDP four-tuple. An invalid
// remote identifies an unconnected endpoint bound only to local.
type udpFlowKey struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

// tcpKey is the four-tuple used to dispatch inbound TCP segments.
type tcpKey struct {
	local  netip.AddrPort
	remote netip.AddrPort
}

// automaticPortCursor remembers the next randomized position in the primary
// IANA range and its lower, non-privileged fallback range.
type automaticPortCursor struct {
	dynamic      uint16
	fallback     uint16
	dynamicStep  uint16
	fallbackStep uint16
	secret       [16]byte
}

const (
	// outputFlowDetached marks retained scheduler state with no ready packets.
	outputFlowDetached = iota
	// outputFlowNew marks a ready flow eligible for initial priority.
	outputFlowNew
	// outputFlowOld marks a ready flow that consumed its initial priority.
	outputFlowOld
	// outputFlowUnused marks an available fixed scheduler entry.
	outputFlowUnused
)

// outputFlowRefillDelay matches sch_fq's delay before an idle flow recovers a
// full service quantum. Retaining negative credit across short idle gaps stops
// bursty writers from repeatedly presenting themselves as new flows.
const outputFlowRefillDelay = 40 * time.Millisecond

// outputPacketNode occupies the same fixed index as its packetQueue slot, so
// fair scheduling adds no per-packet allocation.
type outputPacketNode struct {
	entry packetQueueEntry
	next  int
}

// outputFlow is one bounded scheduler flow. Ready and detached lists share the
// intrusive links because a flow belongs to exactly one list at a time.
type outputFlow struct {
	key        outputFlowKey
	head       int
	tail       int
	credit     int
	state      uint8
	previous   *outputFlow
	next       *outputFlow
	detachedAt time.Time
}

// outputFlowKey uses a TCP connection's stack-local identity when available
// and a keyed packet hash for connectionless traffic.
type outputFlowKey struct {
	tcp  uint64
	hash uint64
}

// outputFlowList is an intrusive FIFO of scheduler flows in one state.
type outputFlowList struct {
	first *outputFlow
	last  *outputFlow
}

// append adds flow to the tail of the list.
func (l *outputFlowList) append(flow *outputFlow) {
	flow.previous = l.last
	flow.next = nil
	if l.last == nil {
		l.first = flow
	} else {
		l.last.next = flow
	}
	l.last = flow
}

// remove detaches flow from the list that currently owns it.
func (l *outputFlowList) remove(flow *outputFlow) {
	if flow.previous == nil {
		l.first = flow.next
	} else {
		flow.previous.next = flow.next
	}
	if flow.next == nil {
		l.last = flow.previous
	} else {
		flow.next.previous = flow.previous
	}
	flow.previous, flow.next = nil, nil
}

// fairPacketScheduler implements the local-flow portion of Linux sch_fq: new
// and old flow lists, byte credit, an initial burst allowance, and bounded
// retention of idle flow state. TCP owns pacing; this scheduler only chooses
// among packets the transport has already made eligible.
type fairPacketScheduler struct {
	mu sync.Mutex

	ready chan struct{}
	nodes []outputPacketNode
	flows map[outputFlowKey]*outputFlow
	store []outputFlow
	free  *outputFlow

	newFlows outputFlowList
	oldFlows outputFlowList
	detached outputFlowList
	queued   int
	quantum  int
	initial  int
	secret   [16]byte
	lastFlow *outputFlow
}

// newFairPacketScheduler allocates one fixed-capacity flow scheduler.
func newFairPacketScheduler(capacity, mtu int, secret [16]byte) *fairPacketScheduler {
	if mtu < 1 {
		mtu = defaultMTU
	}
	scheduler := &fairPacketScheduler{
		ready:  make(chan struct{}, 1),
		nodes:  make([]outputPacketNode, capacity),
		flows:  make(map[outputFlowKey]*outputFlow, capacity),
		store:  make([]outputFlow, capacity),
		secret: secret,
	}
	scheduler.setMTULocked(mtu)
	for index := len(scheduler.store) - 1; index >= 0; index-- {
		flow := &scheduler.store[index]
		flow.state = outputFlowUnused
		flow.next = scheduler.free
		scheduler.free = flow
	}
	return scheduler
}

// setMTU updates byte credit from a validated or defaulted link MTU.
func (s *fairPacketScheduler) setMTU(mtu int) {
	if mtu < 1 {
		mtu = defaultMTU
	}
	s.mu.Lock()
	s.setMTULocked(mtu)
	s.mu.Unlock()
}

// setMTULocked updates byte credit while s.mu is held.
func (s *fairPacketScheduler) setMTULocked(mtu int) {
	s.quantum = 2 * mtu
	s.initial = 10 * mtu
}

// signal publishes level-triggered dequeue readiness without blocking.
func (s *fairPacketScheduler) signal() {
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

// acquireFlow obtains and initializes fixed flow state for key.
func (s *fairPacketScheduler) acquireFlow(key outputFlowKey) *outputFlow {
	if s.free == nil {
		// An empty new flow takes one pass through old_flows before detaching,
		// matching sch_fq's starvation prevention. A stream of one-packet flows
		// can consume every fixed flow object before dequeue makes that pass, so
		// allocation also retires one empty old flow when necessary.
		for flow := s.oldFlows.first; flow != nil && s.detached.first == nil; flow = flow.next {
			if flow.head < 0 {
				s.oldFlows.remove(flow)
				s.detachFlow(flow)
				break
			}
		}
		// At most one active flow exists per queued packet. If every fixed flow
		// object is in use while a reserved slot is being published, at least
		// one retained detached flow is available for eviction.
		flow := s.detached.first
		if flow == nil {
			panic("mipstack: output flow capacity invariant violated")
		}
		s.detached.remove(flow)
		delete(s.flows, flow.key)
		if s.lastFlow == flow {
			s.lastFlow = nil
		}
		flow.state = outputFlowUnused
		flow.next = s.free
		s.free = flow
	}
	flow := s.free
	s.free = flow.next
	*flow = outputFlow{key: key, head: -1, tail: -1, credit: s.initial, state: outputFlowNew}
	s.flows[key] = flow
	s.newFlows.append(flow)
	return flow
}

// reactivateFlow moves retained idle state back to the new-flow list.
func (s *fairPacketScheduler) reactivateFlow(flow *outputFlow) {
	s.detached.remove(flow)
	if time.Since(flow.detachedAt) >= outputFlowRefillDelay && flow.credit < s.quantum {
		flow.credit = s.quantum
	}
	flow.state = outputFlowNew
	flow.detachedAt = time.Time{}
	s.newFlows.append(flow)
}

// enqueue publishes entry to its scheduler flow.
func (s *fairPacketScheduler) enqueue(entry packetQueueEntry, flowID uint64) {
	key := outputFlowKey{tcp: flowID}
	if flowID == 0 {
		key.hash = outputPacketFlowHash(s.secret, entry.packet)
	}
	s.mu.Lock()
	flow := s.lastFlow
	if flow == nil || flow.key != key || flow.state == outputFlowUnused {
		flow = s.flows[key]
	}
	if flow == nil {
		flow = s.acquireFlow(key)
	} else if flow.state == outputFlowDetached {
		s.reactivateFlow(flow)
	}
	s.lastFlow = flow
	node := &s.nodes[entry.slot]
	node.entry, node.next = entry, -1
	if flow.tail < 0 {
		flow.head = int(entry.slot)
	} else {
		s.nodes[flow.tail].next = int(entry.slot)
	}
	flow.tail = int(entry.slot)
	s.queued++
	if s.queued == 1 {
		s.signal()
	}
	s.mu.Unlock()
}

// detachFlow retains empty flow credit for bounded idle reuse.
func (s *fairPacketScheduler) detachFlow(flow *outputFlow) {
	flow.state = outputFlowDetached
	flow.detachedAt = time.Now()
	s.detached.append(flow)
}

// selectList returns the highest-priority nonempty ready list.
func (s *fairPacketScheduler) selectList() (*outputFlowList, uint8) {
	if s.newFlows.first != nil {
		return &s.newFlows, outputFlowNew
	}
	if s.oldFlows.first != nil {
		return &s.oldFlows, outputFlowOld
	}
	return nil, outputFlowDetached
}

// tryDequeue removes one immediately schedulable packet.
func (s *fairPacketScheduler) tryDequeue() (packetQueueEntry, bool) {
	return s.tryDequeueAndSignal(false)
}

// tryDequeueAndSignal optionally hands readiness to another blocking reader.
// Batch drains use tryDequeue and avoid one channel operation per packet.
func (s *fairPacketScheduler) tryDequeueAndSignal(signalRemaining bool) (packetQueueEntry, bool) {
	s.mu.Lock()
	for s.queued != 0 {
		list, state := s.selectList()
		if list == nil {
			s.mu.Unlock()
			return packetQueueEntry{}, false
		}
		flow := list.first
		if flow.head < 0 {
			list.remove(flow)
			if state == outputFlowNew {
				flow.state = outputFlowOld
				s.oldFlows.append(flow)
			} else {
				s.detachFlow(flow)
			}
			continue
		}
		if flow.credit <= 0 {
			flow.credit += s.quantum
			list.remove(flow)
			flow.state = outputFlowOld
			s.oldFlows.append(flow)
			continue
		}
		slot := flow.head
		node := &s.nodes[slot]
		flow.head = node.next
		if flow.head < 0 {
			flow.tail = -1
		}
		entry := node.entry
		node.entry, node.next = packetQueueEntry{}, -1
		flow.credit -= len(entry.packet)
		s.queued--
		if flow.head < 0 {
			list.remove(flow)
			if state == outputFlowNew {
				flow.state = outputFlowOld
				s.oldFlows.append(flow)
			} else {
				s.detachFlow(flow)
			}
		} else if flow.credit <= 0 {
			flow.credit += s.quantum
			list.remove(flow)
			flow.state = outputFlowOld
			s.oldFlows.append(flow)
		}
		if signalRemaining && s.queued != 0 {
			// Keep readiness level-triggered when callers read only one packet at
			// a time. Batch readers signal only after their blocking first packet.
			s.signal()
		}
		s.mu.Unlock()
		return entry, true
	}
	s.mu.Unlock()
	return packetQueueEntry{}, false
}

// dequeue waits for one schedulable packet or closure.
func (s *fairPacketScheduler) dequeue(closeCh <-chan struct{}) (packetQueueEntry, bool) {
	for {
		if entry, ok := s.tryDequeueAndSignal(true); ok {
			return entry, true
		}
		select {
		case <-s.ready:
		case <-closeCh:
			return packetQueueEntry{}, false
		}
	}
}

// len returns the current scheduled packet count.
func (s *fairPacketScheduler) len() int {
	s.mu.Lock()
	queued := s.queued
	s.mu.Unlock()
	return queued
}

// outputHashWord applies a keyed, non-cryptographic avalanche to one flow-key
// word. Flow hashes are internal and never exposed; the random per-stack seed
// prevents an external endpoint from constructing deliberate collisions while
// avoiding a cryptographic hash in the packet hot path.
func outputHashWord(hash, value uint64) uint64 {
	hash ^= bits.RotateLeft64(value+0x9e3779b97f4a7c15, 23)
	hash *= 0xbf58476d1ce4e5b9
	hash ^= hash >> 29
	return hash
}

// outputTransportSelector extracts the stable four-byte discriminator used by
// locally generated TCP, UDP, and ICMP traffic. ICMP checksums and echo
// sequence numbers vary per message; type, code, and identifier do not.
func outputTransportSelector(protocol byte, payload []byte) uint32 {
	if protocol == ProtocolICMPv4 || protocol == ProtocolICMPv6 {
		var selector [4]byte
		if len(payload) >= 2 {
			selector[0], selector[1] = payload[0], payload[1]
		}
		if len(payload) >= 6 {
			copy(selector[2:4], payload[4:6])
		}
		return binary.BigEndian.Uint32(selector[:])
	}
	if len(payload) >= 4 {
		return binary.BigEndian.Uint32(payload[:4])
	}
	return 0
}

// outputPacketFlowHash classifies locally generated traffic without fully
// parsing or validating a packet that the stack has just constructed.
func outputPacketFlowHash(secret [16]byte, packet []byte) uint64 {
	hash := binary.LittleEndian.Uint64(secret[0:8]) ^ 0x6a09e667f3bcc909
	seed := binary.LittleEndian.Uint64(secret[8:16])
	if len(packet) == 0 {
		return outputHashWord(hash, seed)
	}
	version := packet[0] >> 4
	hash = outputHashWord(hash, uint64(version)^seed)
	switch version {
	case 4:
		if len(packet) < 20 {
			for index, value := range packet {
				hash = outputHashWord(hash, uint64(value)<<uint((index&7)*8))
			}
			return hash
		}
		addresses := binary.BigEndian.Uint64(packet[12:20])
		hash = outputHashWord(hash, addresses)
		protocol := packet[9]
		hash = outputHashWord(hash, uint64(protocol))
		headerSize := int(packet[0]&0x0f) * 4
		fragment := binary.BigEndian.Uint16(packet[6:8])
		if fragment&0x3fff != 0 {
			hash = outputHashWord(hash, uint64(binary.BigEndian.Uint16(packet[4:6])))
		} else if headerSize >= 20 && headerSize < len(packet) {
			hash = outputHashWord(hash, uint64(outputTransportSelector(protocol, packet[headerSize:])))
		}
	case 6:
		if len(packet) < 40 {
			for index, value := range packet {
				hash = outputHashWord(hash, uint64(value)<<uint((index&7)*8))
			}
			return hash
		}
		for offset := 8; offset < 40; offset += 8 {
			hash = outputHashWord(hash, binary.BigEndian.Uint64(packet[offset:offset+8]))
		}
		protocol := packet[6]
		hash = outputHashWord(hash, uint64(protocol))
		flowLabel := uint32(packet[1]&0x0f)<<16 | uint32(binary.BigEndian.Uint16(packet[2:4]))
		if flowLabel != 0 {
			hash = outputHashWord(hash, uint64(flowLabel))
		} else if protocol == IPv6ExtensionHeaderFragment && len(packet) >= 48 {
			// Locally fragmented packets carry the Fragment header directly
			// after the IPv6 header. Offset and M differ between fragments, so
			// use Next Header and Identification to keep one datagram ordered.
			hash = outputHashWord(hash, uint64(packet[40]))
			hash = outputHashWord(hash, uint64(binary.BigEndian.Uint32(packet[44:48])))
		} else if len(packet) > 40 {
			hash = outputHashWord(hash, uint64(outputTransportSelector(protocol, packet[40:])))
		}
	default:
		limit := len(packet)
		if limit > 40 {
			limit = 40
		}
		for offset := 0; offset < limit; offset++ {
			hash = outputHashWord(hash, uint64(packet[offset])<<uint((offset&7)*8))
		}
	}
	return hash
}

// packetQueueEntry couples one packet with its fixed queue slot. The entry is
// stored inline in the bounded channel and does not allocate per packet.
type packetQueueEntry struct {
	packet   []byte
	slot     uint16
	reusable bool
}

// packetQueue uses one reusable slot per queue position. The free-slot channel
// is both a capacity semaphore and a one-producer wakeup mechanism; releasing
// one consumed packet cannot wake every writer waiting on a full host queue.
// scheduler is nil for FIFO queues such as loopback and non-nil for the link's
// byte-fair flow scheduler.
type packetQueue struct {
	packets   chan packetQueueEntry
	free      chan uint16
	slots     []atomic.Uint64
	buffers   chan []byte
	epoch     time.Time
	scheduler *fairPacketScheduler
	batchMu   sync.Mutex
	closed    atomic.Bool
}

// monotonicStamp stores an exact monotonic duration relative to one stack
// epoch. Zero remains the unset value used by zero-initialized protocol state.
type monotonicStamp int64

// monotonicStampAt converts value to a compact duration relative to epoch.
// One is added so the exact epoch remains distinguishable from an unset stamp;
// values before epoch are defensively clamped to it.
func monotonicStampAt(epoch, value time.Time) monotonicStamp {
	if value.IsZero() {
		return 0
	}
	elapsed := value.Sub(epoch)
	if elapsed < 0 {
		// Internal packet timestamps are always taken after New. Clamping keeps
		// manually supplied test times and defensive callers representable.
		elapsed = 0
	}
	return monotonicStamp(elapsed) + 1
}

// time reconstructs a timestamp from the same epoch used by monotonicStampAt.
// An unset stamp reconstructs as the zero time.
func (s monotonicStamp) time(epoch time.Time) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return epoch.Add(time.Duration(s - 1))
}

// packetQueueTicket identifies one generation of a fixed queue slot. TCP uses
// it to avoid treating scheduler or embedding-link backpressure as packet
// loss, matching Linux's skb_still_in_host_queue check.
//
// token uses bits 0..15 for the slot, bit 16 for the loopback queue, and bits
// 17..63 for a 47-bit generation. An old ticket can therefore alias only after
// 2^47 reuses of the same slot.
type packetQueueTicket struct {
	token    uint64
	queuedAt monotonicStamp
}

const (
	// packetQueueTicketLoopback distinguishes stack.loopback from the ordinary
	// outbound queue without retaining a queue pointer in every TCP range.
	packetQueueTicketLoopback = uint64(1) << 16
	// packetQueueTicketGenerationShift is the first bit occupied by the reuse
	// generation after the slot and queue-identity fields.
	packetQueueTicketGenerationShift = 17
	// packetQueueTicketGenerationMask bounds the generation to its 47-bit token
	// field before a slot is published again.
	packetQueueTicketGenerationMask = uint64(1)<<47 - 1
)

// packetQueueTicketToken packs the bounded 16-bit slot, its queue identity,
// and a 47-bit reuse generation.
func packetQueueTicketToken(slot uint16, generation uint64, loopback bool) uint64 {
	token := generation<<packetQueueTicketGenerationShift | uint64(slot)
	if loopback {
		token |= packetQueueTicketLoopback
	}
	return token
}

// slot returns the fixed queue position encoded in the low 16 token bits.
func (t packetQueueTicket) slot() uint16 { return uint16(t.token) }

// generation returns the slot reuse generation encoded in the ticket.
func (t packetQueueTicket) generation() uint64 { return t.token >> packetQueueTicketGenerationShift }

// loopback reports whether the ticket belongs to stack.loopback rather than
// stack.outbound.
func (t packetQueueTicket) loopback() bool { return t.token&packetQueueTicketLoopback != 0 }

// initFIFO initializes q as a bounded FIFO queue sharing its stack's monotonic
// epoch. The caller must exclusively own an inactive q.
func (q *packetQueue) initFIFO(capacity int, epoch time.Time) {
	q.initStorage(capacity, epoch)
	q.packets = make(chan packetQueueEntry, capacity)
}

// initStorage initializes the fixed slot and buffer storage shared by FIFO and
// fair queues without allocating an unused second packet queue. The caller
// must exclusively own an inactive q.
func (q *packetQueue) initStorage(capacity int, epoch time.Time) {
	q.packets = nil
	q.free = make(chan uint16, capacity)
	q.slots = make([]atomic.Uint64, capacity)
	// A full queue may legitimately own one buffer per position. Retaining no
	// more than that avoids reallocating after a burst while the per-buffer
	// limit keeps the cache below 512 KiB for the standard queue size.
	q.buffers = make(chan []byte, capacity)
	q.epoch = epoch
	q.scheduler = nil
	q.closed.Store(false)
	for slot := range q.slots {
		q.free <- uint16(slot)
	}
}

// initFair initializes q as a bounded per-flow output queue while retaining
// the same fixed packet slots and host-queue ticket semantics as the FIFO
// implementation. The caller must exclusively own an inactive q.
func (q *packetQueue) initFair(capacity int, epoch time.Time, mtu int, secret [16]byte) {
	q.initStorage(capacity, epoch)
	q.scheduler = newFairPacketScheduler(capacity, mtu, secret)
}

// queuedTime reconstructs the queue-admission time from the owning stack's
// monotonic epoch.
func (t packetQueueTicket) queuedTime(epoch time.Time) time.Time { return t.queuedAt.time(epoch) }

// pendingIn reports whether queue still owns this exact slot generation. Read
// or local delivery clears that ownership, and later reuse of the bounded slot
// cannot revive an old ticket.
func (t packetQueueTicket) pendingIn(queue *packetQueue) bool {
	slot := t.slot()
	if queue == nil || int(slot) >= len(queue.slots) {
		return false
	}
	return queue.slots[slot].Load() == t.generation()<<1|1
}

// pending selects the ticket's encoded outbound or loopback queue and reports
// whether that queue still owns its exact slot generation.
func (t packetQueueTicket) pending(stack *Stack) bool {
	if stack == nil {
		return false
	}
	queue := &stack.outbound
	if t.loopback() {
		queue = &stack.loopback
	}
	return t.pendingIn(queue)
}

// tryReserve acquires one queue position without blocking.
func (q *packetQueue) tryReserve() (uint16, bool) {
	select {
	case slot := <-q.free:
		return slot, true
	default:
		return 0, false
	}
}

// releaseReserved returns a slot that was acquired but not published.
func (q *packetQueue) releaseReserved(slot uint16) { q.free <- slot }

// enqueueReserved publishes a packet after its caller has acquired slot.
// Since the packet channel and slot semaphore have equal capacities, a
// reserved slot always has a corresponding channel position.
func (q *packetQueue) enqueueReserved(slot uint16, packet []byte, reusable bool) packetQueueTicket {
	queuedAt := monotonicStampAt(q.epoch, time.Now())
	generation, _ := q.publishReserved(slot, packet, reusable, 0)
	return packetQueueTicket{token: packetQueueTicketToken(slot, generation, false), queuedAt: queuedAt}
}

// enqueueReservedTCP publishes a connection-owned packet without hashing its
// serialized headers to rediscover an identity TCP already has. loopback must
// be true exactly when q is stack.loopback because the returned ticket uses
// that bit to find its queue without retaining a pointer. published is false
// when queue closure wins the publication race.
func (q *packetQueue) enqueueReservedTCP(slot uint16, packet []byte, reusable bool, flowID uint64, loopback bool) (ticket packetQueueTicket, published bool) {
	queuedAt := monotonicStampAt(q.epoch, time.Now())
	generation, published := q.publishReserved(slot, packet, reusable, flowID)
	return packetQueueTicket{token: packetQueueTicketToken(slot, generation, loopback), queuedAt: queuedAt}, published
}

// enqueueReservedPacket publishes a packet that does not need TCP host-queue
// loss tracking and therefore avoids reading the clock. It reports whether
// publication completed before queue closure.
func (q *packetQueue) enqueueReservedPacket(slot uint16, packet []byte, reusable bool) bool {
	_, published := q.publishReserved(slot, packet, reusable, 0)
	return published
}

// publishReserved marks and publishes one already-reserved slot. A publisher
// that raced with close removes any late publication without making Close wait.
func (q *packetQueue) publishReserved(slot uint16, packet []byte, reusable bool, flowID uint64) (uint64, bool) {
	state := q.slots[slot].Load()
	generation := (state>>1 + 1) & packetQueueTicketGenerationMask
	if generation == 0 {
		generation = 1
	}
	q.slots[slot].Store(generation<<1 | 1)
	entry := packetQueueEntry{packet: packet, slot: slot, reusable: reusable}
	if q.scheduler == nil {
		q.packets <- entry
	} else {
		q.scheduler.enqueue(entry, flowID)
	}
	if q.closed.Load() {
		q.discard()
		return generation, false
	}
	return generation, true
}

// dequeue waits for one schedulable packet or stack closure.
func (q *packetQueue) dequeue(closeCh <-chan struct{}) (packetQueueEntry, bool) {
	if q.scheduler != nil {
		return q.scheduler.dequeue(closeCh)
	}
	select {
	case entry := <-q.packets:
		return entry, true
	case <-closeCh:
		return packetQueueEntry{}, false
	}
}

// tryDequeue returns one immediately schedulable packet without blocking.
func (q *packetQueue) tryDequeue() (packetQueueEntry, bool) {
	if q.scheduler != nil {
		return q.scheduler.tryDequeue()
	}
	select {
	case entry := <-q.packets:
		return entry, true
	default:
		return packetQueueEntry{}, false
	}
}

// len returns the number of published packets waiting for a consumer.
func (q *packetQueue) len() int {
	if q.scheduler != nil {
		return q.scheduler.len()
	}
	return len(q.packets)
}

// setMTU updates scheduler byte credit when this queue is flow-scheduled.
func (q *packetQueue) setMTU(mtu int) {
	if q.scheduler != nil {
		q.scheduler.setMTU(mtu)
	}
}

// tryEnqueue publishes one packet only when a queue slot is immediately
// available.
func (q *packetQueue) tryEnqueue(packet []byte) bool {
	slot, ok := q.tryReserve()
	if !ok {
		return false
	}
	return q.enqueueReservedPacket(slot, packet, false)
}

// acquireBuffer returns bounded queue-owned storage for one complete packet.
func (q *packetQueue) acquireBuffer(size int) ([]byte, bool) {
	if size > packetReusableBufferLimit {
		return make([]byte, size), false
	}
	select {
	case buffer := <-q.buffers:
		if cap(buffer) >= size {
			return buffer[:size], true
		}
	default:
	}
	return make([]byte, size), true
}

// releaseBuffer returns reusable storage without publishing a queue slot.
func (q *packetQueue) releaseBuffer(packet []byte, reusable bool) {
	if !reusable {
		return
	}
	select {
	case q.buffers <- packet[:0]:
	default:
		return
	}
	// close can drain the cache between the state check and the send. Removing
	// one equivalent entry prevents a late Read from recreating retained state.
	if q.closed.Load() {
		select {
		case <-q.buffers:
		default:
		}
	}
}

// release marks an entry as consumed, recycles bounded packet storage, and
// makes its slot available to exactly one waiting producer. The caller must
// finish reading packet before release because another writer may reuse it.
func (q *packetQueue) release(entry packetQueueEntry) {
	state := q.slots[entry.slot].Load()
	q.slots[entry.slot].Store(state &^ 1)
	q.releaseBuffer(entry.packet, entry.reusable)
	q.free <- entry.slot
}

// close rejects future publications and discards all currently published
// packets and reusable buffers. batchMu lets a previously admitted multi-packet
// datagram finish publication before closure; ordinary single-packet publishers
// racing closure discard themselves without making close wait.
func (q *packetQueue) close() {
	q.batchMu.Lock()
	q.closed.Store(true)
	q.discard()
	q.batchMu.Unlock()
}

// discard releases every packet and reusable buffer currently owned by q.
func (q *packetQueue) discard() {
	for {
		entry, ok := q.tryDequeue()
		if !ok {
			break
		}
		q.release(entry)
	}
	for {
		select {
		case <-q.buffers:
		default:
			return
		}
	}
}

// New constructs an inactive-socket stack.
func New(config Config) (*Stack, error) {
	state, err := buildNetworkState(config)
	if err != nil {
		return nil, err
	}
	// One OS-random read seeds independent port, fragment-ID, RFC 6528,
	// flow-label, and output-flow spaces. Per-connection ISNs are derived from
	// tcpISNSecret.
	var seed [104]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, err
	}
	ports4 := automaticPortCursor{
		dynamic:  uint16(binary.BigEndian.Uint32(seed[0:4]) % dynamicPortCount),
		fallback: uint16(binary.BigEndian.Uint32(seed[4:8]) % fallbackPortCount),
	}
	ports6 := automaticPortCursor{
		dynamic:  uint16(binary.BigEndian.Uint32(seed[8:12]) % dynamicPortCount),
		fallback: uint16(binary.BigEndian.Uint32(seed[12:16]) % fallbackPortCount),
	}
	copy(ports4.secret[:], seed[40:56])
	copy(ports6.secret[:], seed[56:72])
	ipv4ID := binary.BigEndian.Uint32(seed[16:20])
	ipv6FragmentID := binary.BigEndian.Uint32(seed[20:24])
	timestampEpoch := time.Now()
	var flowLabelSecret [16]byte
	copy(flowLabelSecret[:], seed[72:88])
	var outputFlowSecret [16]byte
	copy(outputFlowSecret[:], seed[88:104])
	stack := &Stack{
		tcp: make(map[tcpKey]*TCPConn), udp: make(map[udpKey]*UDPConn),
		nextPort: [2]automaticPortCursor{ports4, ports6}, pathMTU: make(map[netip.Addr]pathMTUEntry),
		closeCh: make(chan struct{}), timestampEpoch: timestampEpoch, fragments: make(map[fragmentKey]*ipPacketReassemblyEntry), fragmentWake: make(chan struct{}, 1),
	}
	stack.outbound.initFair(outboundPacketQueue, timestampEpoch, state.mtu, outputFlowSecret)
	stack.loopback.initFIFO(loopbackPacketQueue, timestampEpoch)
	copy(stack.tcpISNSecret[:], seed[24:40])
	stack.flowLabelSecret = flowLabelSecret
	stack.ipv4ID.Store(ipv4ID)
	stack.ipv6FragmentID.Store(ipv6FragmentID)
	stack.network.Store(state)
	return stack, nil
}

// UpdateConfig validates and atomically replaces the stack configuration. New
// sockets inherit the replacement defaults. Sockets bound to removed addresses
// or destinations without a remaining route are closed. Other TCP connections
// immediately apply a changed default congestion controller and reclamp their
// MSS; existing sockets retain the remaining inherited policies.
func (s *Stack) UpdateConfig(config Config) error {
	state, err := buildNetworkState(config)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	previous := s.network.Load()
	multicastConfigurationChanged := !previous.sameMulticastConfiguration(state)
	if !previous.samePathConfiguration(state) {
		s.pathMTUMu.Lock()
		s.network.Store(state)
		s.pathMTU = make(map[netip.Addr]pathMTUEntry)
		s.pathMTUMu.Unlock()
	} else {
		s.network.Store(state)
	}
	s.outbound.setMTU(state.mtu)
	tcpConnections := make([]*TCPConn, 0, len(s.tcp))
	for _, connection := range s.tcp {
		tcpConnections = append(tcpConnections, connection)
	}
	tcpPassive := s.tcpPassive
	tcpForwarder, udpForwarder, ipForwarder, icmpForwarder := s.tcpForwarder, s.udpForwarder, s.ipForwarder, s.icmpForwarder
	multicast := s.multicast
	udpConnections := s.udpConnectionsLocked()
	ip := s.ip
	s.mu.Unlock()
	if tcpPassive != nil {
		tcpPassive.updateConfig(s, state)
	}
	if tcpForwarder != nil {
		tcpForwarder.updateConfig(state)
	}
	if udpForwarder != nil {
		udpForwarder.updateConfig(state)
	}
	if ipForwarder != nil {
		ipForwarder.updateConfig(state)
	}
	if icmpForwarder != nil {
		icmpForwarder.updateConfig(state)
	}
	for _, connection := range tcpConnections {
		connection.updateDefaultCongestionControl(state.tcpDefaults.CongestionControlFactory)
		_, routed := state.routeFor(connection.key.remote.Addr())
		if !networkStateHasLocal(state, connection.key.local.Addr()) && !(connection.forwarded && state.acceptsInboundDestination(connection.key.local.Addr())) {
			connection.abortWithoutReset(syscall.EADDRNOTAVAIL)
			continue
		}
		if !routed {
			connection.abortWithoutReset(syscall.ENETUNREACH)
			continue
		}
		connection.wakeActor(tcpActorWakePathMTU)
	}
	for _, connection := range udpConnections {
		if connection.dual && !networkStateHasFamily(state, false) && !networkStateHasFamily(state, true) ||
			!connection.dual && connection.local.IsUnspecified() && !networkStateHasFamily(state, connection.v6) ||
			connection.local.IsValid() && !connection.local.IsUnspecified() && !networkStateHasLocal(state, connection.local) && !(connection.forwarded && state.acceptsInboundDestination(connection.local)) {
			s.closeUDP(connection)
			continue
		}
		if connection.remote.IsValid() {
			if !state.hasOutputPath(connection.remote.Addr()) {
				s.closeUDP(connection)
			}
		}
	}
	if ip != nil {
		ip.updateConfig(s, state)
	}
	if multicast != nil && multicastConfigurationChanged {
		multicast.updateConfig(state)
	}
	s.pruneFragments(state)
	return nil
}

// LocalAddresses returns an independent snapshot of all configured local
// addresses in configuration order.
func (s *Stack) LocalAddresses() []netip.Addr {
	return append([]netip.Addr(nil), s.network.Load().sources...)
}

// RouteFor returns the selected route for one unicast destination.
func (s *Stack) RouteFor(destination netip.Addr) (Route, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || destination.IsUnspecified() || destination.IsMulticast() || destination.Zone() != "" {
		return Route{}, syscall.EINVAL
	}
	state := s.network.Load()
	if state.broadcastDestination(destination) {
		return Route{}, syscall.EACCES
	}
	route, exists := state.routeFor(destination)
	if !exists {
		return Route{}, syscall.ENETUNREACH
	}
	return route, nil
}

// PathMTU returns the currently confirmed packet size for one routed unicast
// destination. The result includes the IP header.
func (s *Stack) PathMTU(destination netip.Addr) (int, error) {
	if _, err := s.RouteFor(destination); err != nil {
		return 0, err
	}
	return s.mtuFor(destination), nil
}

// ConfirmPathMTU records packetization-layer acknowledgement of an
// unfragmented probe. Connectionless protocols must call this only after their
// own acknowledgement semantics prove delivery; queueing a packet is not
// confirmation.
func (s *Stack) ConfirmPathMTU(destination netip.Addr, mtu int) error {
	if _, err := s.RouteFor(destination); err != nil {
		return err
	}
	destination = destination.Unmap()
	minimum := 68
	if destination.Is6() {
		minimum = ipv6MinimumMTU
	}
	s.pathMTUMu.Lock()
	select {
	case <-s.closeCh:
		s.pathMTUMu.Unlock()
		return ErrClosed
	default:
	}
	linkMTU := s.network.Load().mtu
	if mtu < minimum || mtu > linkMTU {
		s.pathMTUMu.Unlock()
		return syscall.EINVAL
	}
	// An expired lower cache entry is still the most recent packetization-
	// layer confirmation. Keep it as the lower bound of an application's
	// binary search instead of requiring the first successful probe to jump
	// directly to the link MTU.
	confirmed := linkMTU
	if current, exists := s.pathMTU[destination]; exists && current.mtu < confirmed {
		confirmed = current.mtu
	}
	if mtu < confirmed {
		s.pathMTUMu.Unlock()
		return syscall.EINVAL
	}
	changed := s.confirmPathMTULocked(destination, mtu, linkMTU, time.Now())
	s.pathMTUMu.Unlock()
	if changed {
		s.notifyTCPPathMTU(destination, nil)
	}
	return nil
}

// networkStateHasLocal reports membership in an immutable configuration.
func networkStateHasLocal(state *networkState, address netip.Addr) bool {
	_, exists := state.local[address.Unmap()]
	return exists
}

// networkStateHasFamily reports whether one configured source belongs to the
// requested address family.
func networkStateHasFamily(state *networkState, v6 bool) bool {
	for _, source := range state.sources {
		if source.Is6() == v6 {
			return true
		}
	}
	return false
}

// listenAddress validates a listen network and canonicalizes a generic
// wildcard to the same dual-stack IPv6 representation used by net.Listen.
func listenAddress(state *networkState, network, protocol string, address netip.Addr) (netip.Addr, bool, error) {
	if err := validateListenNetwork(network, protocol, address); err != nil {
		return netip.Addr{}, false, err
	}
	switch network {
	case protocol + "4":
		if !networkStateHasFamily(state, false) {
			return netip.Addr{}, false, syscall.EADDRNOTAVAIL
		}
		if !address.IsValid() {
			address = netip.IPv4Unspecified()
		}
		return address, false, nil
	case protocol + "6":
		if !networkStateHasFamily(state, true) {
			return netip.Addr{}, false, syscall.EADDRNOTAVAIL
		}
		if !address.IsValid() {
			address = netip.IPv6Unspecified()
		}
		return address, false, nil
	case protocol:
	}
	if address.IsValid() && !address.IsUnspecified() {
		return address, false, nil
	}
	have4 := networkStateHasFamily(state, false)
	have6 := networkStateHasFamily(state, true)
	if have6 {
		return netip.IPv6Unspecified(), have4, nil
	}
	if have4 {
		return netip.IPv4Unspecified(), false, nil
	}
	return netip.Addr{}, false, syscall.EADDRNOTAVAIL
}

// validateListenNetwork checks a listener's protocol name and an explicitly
// supplied address family before stack lifecycle or binding errors.
func validateListenNetwork(network, protocol string, address netip.Addr) error {
	switch network {
	case protocol:
		return nil
	case protocol + "4":
		if address.IsValid() && address.Is6() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	case protocol + "6":
		if address.IsValid() && address.Is4() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	default:
		return net.UnknownNetworkError(network)
	}
}

// mtuFor returns the unexpired destination PMTU, or the managed link MTU.
func (s *Stack) mtuFor(destination netip.Addr) int {
	destination = destination.Unmap()
	s.pathMTUMu.RLock()
	linkMTU := s.network.Load().mtu
	entry, exists := s.pathMTU[destination]
	s.pathMTUMu.RUnlock()
	if !exists {
		return linkMTU
	}
	now := time.Now()
	if exists && now.Sub(entry.updated) < pathMTULifetime && entry.mtu < linkMTU {
		return entry.mtu
	}
	if exists && now.Sub(entry.updated) >= pathMTULifetime {
		s.pathMTUMu.Lock()
		linkMTU = s.network.Load().mtu
		current, currentExists := s.pathMTU[destination]
		if currentExists && now.Sub(current.updated) >= pathMTULifetime {
			delete(s.pathMTU, destination)
			currentExists = false
		}
		s.pathMTUMu.Unlock()
		if currentExists && current.mtu < linkMTU {
			// Another ICMP update refreshed this entry after the stale read.
			return current.mtu
		}
	}
	return linkMTU
}

// pathMTUExpiry returns the time at which a destination PMTU should be probed
// upward. A past expiry remains actionable so a connection that raced cache
// expiry while starting is woken immediately; mtuFor then removes the entry.
func (s *Stack) pathMTUExpiry(destination netip.Addr) (time.Time, bool) {
	destination = destination.Unmap()
	s.pathMTUMu.RLock()
	linkMTU := s.network.Load().mtu
	entry, exists := s.pathMTU[destination]
	s.pathMTUMu.RUnlock()
	if !exists || entry.mtu >= linkMTU {
		return time.Time{}, false
	}
	return entry.updated.Add(pathMTULifetime), true
}

// notifyTCPPathMTU wakes all established and handshaking flows to one
// destination except an optional actor that is already applying the change.
// The PMTU lock is never held while acquiring the socket registry lock.
func (s *Stack) notifyTCPPathMTU(destination netip.Addr, except *TCPConn) {
	destination = destination.Unmap()
	s.mu.RLock()
	for key, connection := range s.tcp {
		if connection == nil || connection == except || key.remote.Addr() != destination {
			continue
		}
		connection.wakeActor(tcpActorWakePathMTU)
	}
	s.mu.RUnlock()
}

// observePathMTU records a validated ICMP next-hop MTU reduction.
func (s *Stack) observePathMTU(destination netip.Addr, mtu uint32) bool {
	destination = destination.Unmap()
	minimum := uint32(68)
	if destination.Is6() {
		minimum = 1280
	}
	if !destination.IsValid() || mtu == 0 {
		return false
	}
	if destination.Is6() && mtu < minimum {
		// RFC 8201 requires discarding a Packet Too Big value below the
		// IPv6 minimum link MTU rather than turning it into a 1280-byte hint.
		return false
	}
	if mtu < minimum {
		mtu = minimum
	}
	s.pathMTUMu.Lock()
	defer s.pathMTUMu.Unlock()
	select {
	case <-s.closeCh:
		return false
	default:
	}
	if mtu >= uint32(s.network.Load().mtu) {
		return false
	}
	now := time.Now()
	current, exists := s.pathMTU[destination]
	if exists && now.Sub(current.updated) < pathMTULifetime {
		if current.mtu < int(mtu) {
			// A Packet Too Big message can only lower the confirmed PMTU.
			// A larger value neither proves the smaller path constraint still
			// exists nor authorizes an upward change.
			return false
		}
		if current.mtu == int(mtu) {
			current.updated = now
			s.pathMTU[destination] = current
			return false
		}
	}
	s.storePathMTULocked(destination, pathMTUEntry{mtu: int(mtu), updated: now})
	s.stats.pathMTUUpdates.Add(1)
	return true
}

// storePathMTULocked installs one entry while preserving the global cache
// bound. Callers hold pathMTUMu for writing.
func (s *Stack) storePathMTULocked(destination netip.Addr, entry pathMTUEntry) {
	if _, exists := s.pathMTU[destination]; !exists && len(s.pathMTU) >= pathMTUMaximumEntries {
		var oldestAddress netip.Addr
		var oldest pathMTUEntry
		for address, candidate := range s.pathMTU {
			if !oldestAddress.IsValid() || candidate.updated.Before(oldest.updated) {
				oldestAddress, oldest = address, candidate
			}
		}
		delete(s.pathMTU, oldestAddress)
	}
	s.pathMTU[destination] = entry
}

// confirmPathMTU raises a shared destination PMTU after packetization-layer
// acknowledgement and wakes sibling TCP flows on the same single-link path.
func (s *Stack) confirmPathMTU(destination netip.Addr, mtu int, except *TCPConn) bool {
	destination = destination.Unmap()
	if !destination.IsValid() || mtu <= 0 {
		return false
	}
	s.pathMTUMu.Lock()
	select {
	case <-s.closeCh:
		s.pathMTUMu.Unlock()
		return false
	default:
	}
	linkMTU := s.network.Load().mtu
	if mtu > linkMTU {
		s.pathMTUMu.Unlock()
		return false
	}
	changed := s.confirmPathMTULocked(destination, mtu, linkMTU, time.Now())
	s.pathMTUMu.Unlock()
	if changed {
		s.notifyTCPPathMTU(destination, except)
	}
	return changed
}

// confirmPathMTULocked raises one destination PMTU against the network
// snapshot protected by pathMTUMu. UpdateConfig publishes a changed link MTU
// under the same lock, so a confirmation cannot combine an old ceiling with
// a newly reset cache.
func (s *Stack) confirmPathMTULocked(destination netip.Addr, mtu, linkMTU int, now time.Time) bool {
	current, exists := s.pathMTU[destination]
	if exists && now.Sub(current.updated) < pathMTULifetime {
		if current.mtu > mtu {
			// Delivery of a smaller probe does not reconfirm the larger packet
			// size established by another flow.
			return false
		}
		if current.mtu == mtu {
			current.updated = now
			s.pathMTU[destination] = current
			return false
		}
	}
	if mtu >= linkMTU {
		delete(s.pathMTU, destination)
	} else {
		s.storePathMTULocked(destination, pathMTUEntry{mtu: mtu, updated: now})
	}
	return true
}

// Stats returns a consistent-enough lock-free snapshot of stack counters.
// Concurrent activity may become visible across adjacent fields at slightly
// different instants.
func (s *Stack) Stats() StackStats {
	return StackStats{
		InboundPackets:              s.stats.inboundPackets.Load(),
		InboundDroppedPackets:       s.stats.inboundDroppedPackets.Load(),
		InvalidIPPackets:            s.stats.invalidIPPackets.Load(),
		UnacceptedIPPackets:         s.stats.unacceptedIPPackets.Load(),
		NonlocalDestinationPackets:  s.stats.nonlocalDestinationPackets.Load(),
		PromiscuousInboundPackets:   s.stats.promiscuousInboundPackets.Load(),
		InvalidSourcePackets:        s.stats.invalidSourcePackets.Load(),
		OutboundPackets:             s.stats.outboundPackets.Load(),
		LoopbackPackets:             s.stats.loopbackPackets.Load(),
		ActiveTCPConnections:        s.stats.activeTCPConnections.Load(),
		ActiveTCPListeners:          s.stats.activeTCPListeners.Load(),
		ActiveUDPSockets:            s.stats.activeUDPSockets.Load(),
		ActiveIPSockets:             s.stats.activeIPSockets.Load(),
		TCPRetransmissions:          s.stats.tcpRetransmissions.Load(),
		TCPInboundQueueDrops:        s.stats.tcpInboundQueueDrops.Load(),
		TCPInvalidSegments:          s.stats.tcpInvalidSegments.Load(),
		TCPSACKRetransmissions:      s.stats.tcpSACKRetransmissions.Load(),
		TCPRACKRetransmissions:      s.stats.tcpRACKRetransmissions.Load(),
		TCPTailLossProbes:           s.stats.tcpTailLossProbes.Load(),
		TCPSpuriousRecoveryUndos:    s.stats.tcpSpuriousRecoveryUndos.Load(),
		TCPZeroWindowProbes:         s.stats.tcpZeroWindowProbes.Load(),
		TCPKeepAliveProbes:          s.stats.tcpKeepAliveProbes.Load(),
		TCPSYNCookiesSent:           s.stats.tcpSYNCookiesSent.Load(),
		TCPSYNCookiesAccepted:       s.stats.tcpSYNCookiesAccepted.Load(),
		TCPSYNCookiesRejected:       s.stats.tcpSYNCookiesRejected.Load(),
		TCPHandshakeTimeouts:        s.stats.tcpHandshakeTimeouts.Load(),
		TCPAcceptQueueDrops:         s.stats.tcpAcceptQueueDrops.Load(),
		PathMTUUpdates:              s.stats.pathMTUUpdates.Load(),
		PathMTUProbes:               s.stats.pathMTUProbes.Load(),
		PathMTUProbeSuccesses:       s.stats.pathMTUProbeSuccesses.Load(),
		PathMTUProbeFailures:        s.stats.pathMTUProbeFailures.Load(),
		PathMTUBlackHoleReductions:  s.stats.pathMTUBlackHoleReductions.Load(),
		FragmentEvictions:           s.stats.fragmentEvictions.Load(),
		FragmentTimeouts:            s.stats.fragmentTimeouts.Load(),
		RateLimitedControlResponses: s.stats.rateLimitedControlResponses.Load(),
	}
}

// allowControlResponse consumes one token from a control-response class.
func (s *Stack) allowControlResponse(class controlResponseClass) bool {
	s.controlMu.Lock()
	now := time.Now()
	bucket := &s.controlLimiters[class]
	if bucket.updated.IsZero() {
		bucket.tokens = controlResponseBurst
	} else {
		bucket.tokens += now.Sub(bucket.updated).Seconds() * controlResponseRate
		if bucket.tokens > controlResponseBurst {
			bucket.tokens = controlResponseBurst
		}
	}
	bucket.updated = now
	allowed := bucket.tokens >= 1
	if allowed {
		bucket.tokens--
	}
	s.controlMu.Unlock()
	if !allowed {
		s.stats.rateLimitedControlResponses.Add(1)
	}
	return allowed
}

// Start activates packet and socket I/O and starts background maintenance.
// Repeated calls do not start additional workers.
func (s *Stack) Start() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.mu.Unlock()
	go s.runFragmentCleaner()
	go s.runLoopback()
	return nil
}

// runLoopback serializes local delivery outside the sending socket actor.
func (s *Stack) runLoopback() {
	for {
		select {
		case entry := <-s.loopback.packets:
			select {
			case <-s.closeCh:
				s.loopback.release(entry)
				return
			default:
			}
			_ = s.handleInboundPacket(entry.packet, time.Now(), true)
			s.loopback.release(entry)
		case <-s.closeCh:
			return
		}
	}
}

// ready reports whether the stack has started and has not closed.
func (s *Stack) ready() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	if !s.started {
		return ErrNotStarted
	}
	return nil
}

// sourceForOutput validates an explicit source or selects one automatically
// and returns whether output must use multicast or broadcast semantics.
func (s *Stack) sourceForOutput(destination, requested netip.Addr) (netip.Addr, bool, error) {
	state := s.network.Load()
	destination = destination.Unmap()
	if destination.IsMulticast() || state.broadcastDestination(destination) {
		source, err := state.sourceForNonUnicast(destination, requested)
		return source, true, err
	}
	source, err := state.sourceForUnicast(destination, requested)
	return source, false, err
}

// sourceForRequested is the source-selection form used when the caller does
// not need the already-computed output class.
func (s *Stack) sourceForRequested(destination, requested netip.Addr) (netip.Addr, error) {
	source, _, err := s.sourceForOutput(destination, requested)
	return source, err
}

// classifyInboundDestination applies local ownership and network policy, then
// consults the optional multicast membership state only for multicast input.
func (s *Stack) classifyInboundDestination(state *networkState, destination netip.Addr, loopback bool) inboundDestinationClass {
	if destination.Is4In6() {
		return inboundDestinationRejected
	}
	destination = destination.Unmap()
	if networkStateHasLocal(state, destination) {
		return inboundDestinationLocalUnicast
	}
	if state.broadcastDestination(destination) {
		if !networkStateHasFamily(state, false) {
			return inboundDestinationRejected
		}
		return inboundDestinationBroadcast
	}
	if destination.IsMulticast() {
		if !validMulticastGroup(destination) || isInterfaceLocalMulticast(destination) && !loopback {
			return inboundDestinationRejected
		}
		if isAllHostsGroup(destination) && networkStateHasFamily(state, destination.Is6()) {
			return inboundDestinationMulticast
		}
		s.mu.RLock()
		multicast := s.multicast
		s.mu.RUnlock()
		if multicast != nil && multicast.acceptsDestination(destination) {
			return inboundDestinationMulticast
		}
		return inboundDestinationRejected
	}
	if state.acceptsNonlocalDestination(destination) {
		return inboundDestinationPromiscuousUnicast
	}
	return inboundDestinationRejected
}

// acceptsInboundDestination is the admission predicate used before fragment
// retention. Final dispatch classifies the reassembled packet again so a
// membership removal cannot deliver stale queued fragments.
func (s *Stack) acceptsInboundDestination(state *networkState, destination netip.Addr, loopback bool) bool {
	return s.classifyInboundDestination(state, destination, loopback) != inboundDestinationRejected
}

// validInboundSource applies protocol-independent martian-source checks.
// RFC 1122 permits 0.0.0.0 only during address initialization; accepting it
// solely for limited broadcast preserves DHCP and BOOTP. Protocol-specific
// exceptions are applied only after this predicate rejects the source.
func validInboundSource(state *networkState, source, destination netip.Addr) bool {
	if source.Is4In6() {
		return false
	}
	source, destination = source.Unmap(), destination.Unmap()
	if source.Is4() {
		value := source.As4()
		if value[0] == 0 {
			return source.IsUnspecified() && destination == netip.AddrFrom4([4]byte{255, 255, 255, 255})
		}
	}
	if !source.IsValid() || source.IsUnspecified() || source.IsMulticast() ||
		source == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || state.invalidInboundSource(source) {
		return false
	}
	return !source.IsLoopback() || networkStateHasLocal(state, source)
}

// validInboundFragmentSource admits the only protocol-specific source that
// cannot be verified before reassembly. RFC 9776 allows an IGMP Membership
// Report from 0.0.0.0; the complete payload is checked again after assembly.
func validInboundFragmentSource(state *networkState, source, destination netip.Addr, protocol byte) bool {
	if validInboundSource(state, source, destination) {
		return true
	}
	source = source.Unmap()
	return protocol == ProtocolIGMP && source.Is4() && source.IsUnspecified()
}

// validInboundPacketSource applies the RFC 9776 section 4.2.14 exception for
// Membership Reports from a host that has not acquired an IPv4 address. The
// exception does not admit zero-source Queries or unrelated IGMP messages.
func validInboundPacketSource(state *networkState, packet ipPacket) bool {
	if validInboundSource(state, packet.source, packet.target) {
		return true
	}
	source := packet.source.Unmap()
	if packet.protocol != ProtocolIGMP || !source.Is4() || !source.IsUnspecified() || len(packet.payload) == 0 {
		return false
	}
	switch packet.payload[0] {
	case igmpV1MembershipReport, igmpV2MembershipReport, igmpV3MembershipReport:
		return true
	default:
		return false
	}
}

// automaticFlowLabel derives one nonzero RFC 6437-style label from a stable
// per-stack secret and the fields available to identify an IPv6 flow.
func (s *Stack) automaticFlowLabel(source, target netip.Addr, protocol byte, payload []byte) uint32 {
	var selector [4]byte
	switch protocol {
	case ProtocolTCP, ProtocolUDP:
		if len(payload) >= 4 {
			copy(selector[:], payload[:4])
		}
	case ProtocolICMPv6:
		if len(payload) >= 6 {
			selector[0], selector[1] = payload[0], payload[1]
			copy(selector[2:4], payload[4:6])
		}
	}
	return s.flowLabel(source, target, protocol, selector)
}

// automaticTransportFlowLabel is automaticFlowLabel without requiring a
// serialized TCP or UDP header.
func (s *Stack) automaticTransportFlowLabel(source, target netip.Addr, protocol byte, sourcePort, targetPort uint16) uint32 {
	var selector [4]byte
	binary.BigEndian.PutUint16(selector[0:2], sourcePort)
	binary.BigEndian.PutUint16(selector[2:4], targetPort)
	return s.flowLabel(source, target, protocol, selector)
}

// flowLabel hashes one directional flow identity into IPv6's 20-bit field.
func (s *Stack) flowLabel(source, target netip.Addr, protocol byte, selector [4]byte) uint32 {
	var input [37]byte
	sourceValue, targetValue := source.As16(), target.As16()
	copy(input[0:16], sourceValue[:])
	copy(input[16:32], targetValue[:])
	input[32] = protocol
	copy(input[33:37], selector[:])
	label := uint32(sipHash24(s.flowLabelSecret, input[:])) & ipv6MaximumFlowLabel
	if label == 0 {
		label = 1
	}
	return label
}

// allocateAutomaticPort selects an available IANA dynamic port first, then
// falls back to the lower non-privileged range only after a complete scan.
func allocateAutomaticPort(cursor *automaticPortCursor, available func(uint16) bool) (uint16, error) {
	return allocateAutomaticPortWithOffsets(cursor, [2]uint32{}, available)
}

// allocateAutomaticPortWithOffsets combines a moving full-period cursor with
// keyed per-destination offsets, following RFC 6056's hash-based selection
// model without retaining a table for every remote endpoint.
func allocateAutomaticPortWithOffsets(cursor *automaticPortCursor, offsets [2]uint32, available func(uint16) bool) (uint16, error) {
	ranges := [...]struct {
		id     byte
		first  uint32
		count  uint32
		cursor *uint16
		step   *uint16
	}{
		{0, dynamicPortFirst, dynamicPortCount, &cursor.dynamic, &cursor.dynamicStep},
		{1, fallbackPortFirst, fallbackPortCount, &cursor.fallback, &cursor.fallbackStep},
	}
	for _, portRange := range ranges {
		if *portRange.step == 0 {
			*portRange.step = automaticPortStep(cursor.secret, portRange.id, portRange.count)
		}
		base := uint32(*portRange.cursor)
		start := (base + offsets[portRange.id]%portRange.count) % portRange.count
		for probe := uint32(0); probe < portRange.count; probe++ {
			position := (start + probe*uint32(*portRange.step)) % portRange.count
			port := uint16(portRange.first + position)
			if !available(port) {
				continue
			}
			// Advance the shared cursor independently of the destination offset.
			// For one destination this visits the complete range before returning
			// to a recently closed four-tuple retained by its peer in TIME_WAIT.
			*portRange.cursor = uint16((base + (probe+1)*uint32(*portRange.step)) % portRange.count)
			return port, nil
		}
	}
	return 0, ErrNoPorts
}

// automaticPortStep derives an unpredictable full-period traversal step.
func automaticPortStep(secret [16]byte, id byte, count uint32) uint16 {
	step := uint32(1) + uint32(sipHash24(secret, []byte{id})%uint64(count-1))
	for greatestCommonDivisor(step, count) != 1 {
		step++
		if step == count {
			step = 1
		}
	}
	return uint16(step)
}

// greatestCommonDivisor supports full-period automatic-port traversal.
func greatestCommonDivisor(left, right uint32) uint32 {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

// isLocal reports whether address belongs to this stack.
func (s *Stack) isLocal(address netip.Addr) bool {
	return networkStateHasLocal(s.network.Load(), address)
}

// allocateUDPPortLocked reserves one collision-free automatic local endpoint
// while s.mu is held.
func (s *Stack) allocateUDPPortLocked(address netip.Addr, dual bool) (uint16, error) {
	index := 0
	if address.Is6() {
		index = 1
	}
	return allocateAutomaticPort(&s.nextPort[index], func(port uint16) bool {
		// Like bind(2) with port zero, automatic allocation selects an unused
		// endpoint even when the eventual socket requested a reuse option.
		return s.udpEndpointAvailableLocked(exclusiveUDPSocketBinding{}, address, port, dual)
	})
}

// udpEndpointAvailableLocked reports whether address and port can be bound
// without overlapping a wildcard or exact endpoint while s.mu is held.
func (s *Stack) udpEndpointAvailableLocked(binding udpSocketBinding, address netip.Addr, port uint16, dual bool) bool {
	if !binding.available(s, address, port, dual) {
		return false
	}
	for key, connection := range s.udp {
		if key.port == port && listenAddressesOverlap(key.address, connection.dual, address, dual) {
			return false
		}
	}
	state := s.network.Load()
	for key := range s.udpForwarded {
		if key.remote.IsValid() || key.local.Port() != port || !networkStateHasLocal(state, key.local.Addr()) {
			continue
		}
		if listenAddressesOverlap(key.local.Addr(), false, address, dual) {
			return false
		}
	}
	return true
}

// listenAddressesOverlap reports whether two single-interface bindings cover
// at least one common local address family and address.
func listenAddressesOverlap(left netip.Addr, leftDual bool, right netip.Addr, rightDual bool) bool {
	if leftDual || rightDual {
		if left.IsUnspecified() && right.IsUnspecified() {
			return true
		}
		if leftDual && right.Is4() || rightDual && left.Is4() {
			return true
		}
	}
	return left.Is6() == right.Is6() && (left.IsUnspecified() || right.IsUnspecified() || left == right)
}

// allocateTCPPortLocked selects a local port whose complete four-tuple is not
// active or in TIME_WAIT while s.mu is held.
func (s *Stack) allocateTCPPortLocked(local netip.Addr, remote netip.AddrPort) (uint16, error) {
	index := 0
	if remote.Addr().Is6() {
		index = 1
	}
	cursor := &s.nextPort[index]
	offsets := automaticTCPPortOffsets(cursor.secret, local, remote)
	return allocateAutomaticPortWithOffsets(cursor, offsets, func(port uint16) bool {
		if s.tcpPortListenedLocked(local, port) {
			return false
		}
		key := tcpKey{local: netip.AddrPortFrom(local, port), remote: remote}
		if _, exists := s.tcp[key]; exists {
			return false
		}
		return true
	})
}

// automaticTCPPortOffsets separate the ephemeral sequence observed by each
// remote endpoint using the same tuple inputs recommended by RFC 6056.
func automaticTCPPortOffsets(secret [16]byte, local netip.Addr, remote netip.AddrPort) [2]uint32 {
	var input [35]byte
	if local.Is6() {
		input[0] = 6
	} else {
		input[0] = 4
	}
	localValue, remoteValue := local.As16(), remote.Addr().As16()
	copy(input[1:17], localValue[:])
	copy(input[17:33], remoteValue[:])
	binary.BigEndian.PutUint16(input[33:35], remote.Port())
	hash := sipHash24(secret, input[:])
	return [2]uint32{uint32(hash), uint32(hash >> 32)}
}

// tcpPortListenedLocked reports whether a wildcard or exact listener owns a
// local TCP endpoint while s.mu is held.
func (s *Stack) tcpPortListenedLocked(local netip.Addr, port uint16) bool {
	return s.tcpPassive != nil && s.tcpPassive.portListened(local, port)
}

// ListenUDP binds an unconnected UDP packet socket. Network must be udp, udp4,
// or udp6. A wildcard with udp uses one dual-stack endpoint when both families
// are configured. Port zero selects an automatic port.
func (s *Stack) ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error) {
	return s.listenUDP(ctx, network, local, exclusiveUDPSocketBinding{}, datagramSocketOptionSet{})
}

// listenUDP contains validation, automatic port allocation, and socket
// construction shared by the ordinary and optional REUSEPORT entry points.
func (s *Stack) listenUDP(ctx context.Context, network string, local netip.AddrPort, binding udpSocketBinding, options datagramSocketOptionSet) (net.PacketConn, error) {
	address := local.Addr().Unmap()
	local = netip.AddrPortFrom(address, local.Port())
	target := net.UDPAddrFromAddrPort(local)
	wrap := func(err error) (net.PacketConn, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	if err := validateListenNetwork(network, "udp", address); err != nil {
		return wrap(err)
	}
	if address.IsValid() && (address.IsMulticast() || address.Zone() != "") {
		return wrap(errors.New("mipstack: invalid UDP listen address"))
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
	address, dual, err := listenAddress(state, network, "udp", address)
	if err != nil {
		return wrap(err)
	}
	if err = (socketOptionSet{datagram: options}).validateFamily(socketOptionUDPListen, address.Is6(), dual); err != nil {
		return wrap(err)
	}
	if !address.IsUnspecified() && !networkStateHasLocal(state, address) {
		return wrap(syscall.EADDRNOTAVAIL)
	}
	local = netip.AddrPortFrom(address, local.Port())
	port := local.Port()
	if port == 0 {
		port, err = s.allocateUDPPortLocked(address, dual)
		if err != nil {
			return wrap(err)
		}
	} else if !s.udpEndpointAvailableLocked(binding, address, port, dual) {
		return wrap(syscall.EADDRINUSE)
	}
	connection := newUDPConn(s, network, port, address.Is6(), address, netip.AddrPort{}, options)
	connection.dual = dual
	if err = binding.register(s, connection); err != nil {
		return wrap(err)
	}
	s.stats.activeUDPSockets.Add(1)
	return connection, nil
}

// DialUDP creates a connected UDP socket for one IPv4 or IPv6 remote endpoint.
// Network must be udp, udp4, or udp6. A zero source selects both address and
// port automatically; an unspecified source address selects only the address.
func (s *Stack) DialUDP(ctx context.Context, network string, source, remote netip.AddrPort) (net.Conn, error) {
	return s.dialUDP(ctx, network, source, remote, datagramSocketOptionSet{})
}

// dialUDP contains connected socket construction shared by Stack and Dialer.
func (s *Stack) dialUDP(ctx context.Context, network string, source, remote netip.AddrPort, options datagramSocketOptionSet) (net.Conn, error) {
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	target := net.UDPAddrFromAddrPort(remote)
	wrap := func(source net.Addr, err error) (net.Conn, error) {
		return nil, socketOperationError("dial", network, source, target, err)
	}
	if err := validateTransportNetwork(network, "udp", remote.Addr()); err != nil {
		return wrap(nil, err)
	}
	if !remote.IsValid() || remote.Addr().IsUnspecified() || remote.Addr().Zone() != "" {
		return wrap(nil, errors.New("mipstack: invalid UDP destination"))
	}
	if err := (socketOptionSet{datagram: options}).validateFamily(socketOptionUDPDial, remote.Addr().Is6(), false); err != nil {
		return wrap(nil, err)
	}
	if err := ctx.Err(); err != nil {
		return wrap(nil, err)
	}
	if err := s.ready(); err != nil {
		return wrap(nil, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return wrap(nil, ErrClosed)
	}
	local, err := s.localEndpointFor(network, remote, source)
	if err != nil {
		return wrap(nil, err)
	}
	localAddress := net.UDPAddrFromAddrPort(local)
	port := local.Port()
	if port == 0 {
		port, err = s.allocateUDPPortLocked(local.Addr(), false)
		if err != nil {
			return wrap(localAddress, err)
		}
	} else if !s.udpEndpointAvailableLocked(exclusiveUDPSocketBinding{}, local.Addr(), port, false) {
		return wrap(localAddress, syscall.EADDRINUSE)
	}
	local = netip.AddrPortFrom(local.Addr(), port)
	connection := newUDPConn(s, network, port, remote.Addr().Is6(), local.Addr(), remote, options)
	s.udp[udpKey{address: local.Addr(), port: port}] = connection
	s.stats.activeUDPSockets.Add(1)
	return connection, nil
}

// validateTransportNetwork accepts the network names used by the net package's
// netip-based DialTCP and DialUDP methods and enforces an explicit IP family.
func validateTransportNetwork(network, protocol string, remote netip.Addr) error {
	switch network {
	case protocol:
		return nil
	case protocol + "4":
		if remote.IsValid() && remote.Is6() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	case protocol + "6":
		if remote.IsValid() && remote.Is4() {
			return syscall.EAFNOSUPPORT
		}
		return nil
	default:
		return net.UnknownNetworkError(network)
	}
}

// localEndpointFor resolves and validates the local side of an active socket.
func (s *Stack) localEndpointFor(network string, remote, requested netip.AddrPort) (netip.AddrPort, error) {
	requestedAddress := requested.Addr()
	if requestedAddress.IsValid() {
		requestedAddress = requestedAddress.Unmap()
		if requestedAddress.Zone() != "" || requestedAddress.IsMulticast() {
			return netip.AddrPort{}, syscall.EINVAL
		}
		if requestedAddress.Is6() != remote.Addr().Is6() && (!requestedAddress.IsUnspecified() || network[len(network)-1] == '4' || network[len(network)-1] == '6') {
			family := "IPv6"
			if remote.Addr().Is4() {
				family = "IPv4"
			}
			return netip.AddrPort{}, &net.AddrError{Err: "non-" + family + " address", Addr: requestedAddress.String()}
		}
	}
	address, err := s.sourceForRequested(remote.Addr(), requestedAddress)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(address, requested.Port()), nil
}

// Read blocks for one complete outbound IP packet, then drains up to
// BatchSize packets into consecutive buffers at offset. On success it sets
// the corresponding packet lengths in sizes, matching tun.Device.Read.
func (s *Stack) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	if err := s.ready(); err != nil {
		if errors.Is(err, ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	if len(sizes) < len(buffers) {
		return 0, errors.New("mipstack: Read sizes shorter than buffers")
	}
	limit := len(buffers)
	if limit > deviceBatchSize {
		limit = deviceBatchSize
	}
	if limit == 0 {
		return 0, errors.New("mipstack: Read requires one buffer and size")
	}
	for index := 0; index < limit; index++ {
		if offset < 0 || offset > len(buffers[index]) {
			return 0, errors.New("mipstack: invalid Read offset")
		}
	}
	readPacket := func(index int, entry packetQueueEntry) error {
		if len(entry.packet) > len(buffers[index])-offset {
			s.outbound.release(entry)
			return io.ErrShortBuffer
		}
		sizes[index] = copy(buffers[index][offset:], entry.packet)
		s.outbound.release(entry)
		return nil
	}
	first, ok := s.outbound.dequeue(s.closeCh)
	if !ok {
		return 0, os.ErrClosed
	}
	if err := readPacket(0, first); err != nil {
		return 0, err
	}
	count := 1
	for count < limit {
		entry, available := s.outbound.tryDequeue()
		if !available {
			return count, nil
		}
		if err := readPacket(count, entry); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// Write delivers complete inbound IP packets from buffers at offset. Invalid,
// unrelated, and unsupported packets are silently discarded.
func (s *Stack) Write(buffers [][]byte, offset int) (int, error) {
	if err := s.ready(); err != nil {
		if errors.Is(err, ErrClosed) {
			return 0, os.ErrClosed
		}
		return 0, err
	}
	receivedAt := time.Now()
	count := 0
	for _, buffer := range buffers {
		if offset < 0 || offset > len(buffer) {
			return count, errors.New("mipstack: invalid Write offset")
		}
		if err := s.handleInboundPacket(buffer[offset:], receivedAt, false); err != nil {
			if errors.Is(err, ErrClosed) {
				return count, os.ErrClosed
			}
			return count, err
		}
		count++
	}
	return count, nil
}

// writePacket queues one complete outbound IP packet for Read.
func (s *Stack) writePacket(packet []byte) error {
	select {
	case <-s.closeCh:
		return ErrClosed
	default:
	}
	queue, loopback := s.outputQueue(packet)
	if loopback {
		if queue.tryEnqueue(packet) {
			s.recordOutput(true)
			return nil
		}
		select {
		case <-s.closeCh:
			return ErrClosed
		default:
			// runLoopback is the sole consumer and may itself be emitting a
			// reply. Blocking it on its own full queue would deadlock all local
			// traffic, so overload is reported to the producing socket.
			return ErrResourceLimit
		}
	}
	for {
		if queue.tryEnqueue(packet) {
			s.recordOutput(false)
			return nil
		}
		select {
		case slot := <-queue.free:
			if !queue.enqueueReservedPacket(slot, packet, false) {
				return ErrClosed
			}
			s.recordOutput(false)
			return nil
		case <-s.closeCh:
			return ErrClosed
		}
	}
}

// tryWritePacket queues one best-effort control packet without waiting for
// device space. It is used when an already aborted TCP actor emits its final
// reset and must not retain connection state behind a stalled embedding link.
func (s *Stack) tryWritePacket(packet []byte) error {
	select {
	case <-s.closeCh:
		return ErrClosed
	default:
	}
	queue, loopback := s.outputQueue(packet)
	if !queue.tryEnqueue(packet) {
		select {
		case <-s.closeCh:
			return ErrClosed
		default:
		}
		return ErrResourceLimit
	}
	s.recordOutput(loopback)
	return nil
}

// tryWritePackets atomically queues packets that all select the same output
// queue. It reserves every required slot before publishing any packet, so a
// fragmented datagram is either accepted in full or not emitted at all.
func (s *Stack) tryWritePackets(packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	if len(packets) == 1 {
		return s.tryWritePacket(packets[0])
	}
	queue, loopback := s.outputQueue(packets[0])
	return s.tryWritePacketsTo(packets, queue, loopback)
}

// tryWritePacketsTo atomically queues packets into one explicitly selected
// output queue. It underpins nonblocking non-unicast output, where external
// and local delivery are selected independently of the packet destination.
func (s *Stack) tryWritePacketsTo(packets [][]byte, queue *packetQueue, loopback bool) error {
	if len(packets) == 0 {
		return nil
	}
	select {
	case <-s.closeCh:
		return ErrClosed
	default:
	}
	if len(packets) > cap(queue.free) {
		return ErrResourceLimit
	}
	slots := make([]uint16, len(packets))
	reserved := 0
	for ; reserved < len(slots); reserved++ {
		slot, ok := queue.tryReserve()
		if !ok {
			for _, acquired := range slots[:reserved] {
				queue.releaseReserved(acquired)
			}
			return ErrResourceLimit
		}
		slots[reserved] = slot
	}
	queue.batchMu.Lock()
	defer queue.batchMu.Unlock()
	select {
	case <-s.closeCh:
		for _, slot := range slots {
			queue.releaseReserved(slot)
		}
		return ErrClosed
	default:
	}
	if queue.closed.Load() {
		for _, slot := range slots {
			queue.releaseReserved(slot)
		}
		return ErrClosed
	}
	for index, packet := range packets {
		if !queue.enqueueReservedPacket(slots[index], packet, false) {
			for _, slot := range slots[index+1:] {
				queue.releaseReserved(slot)
			}
			return ErrClosed
		}
		s.recordOutput(loopback)
	}
	return nil
}

// writePacketUntil queues a packet while observing a socket's mutable write
// deadline. The fast path allocates no timer when the packet queue has room.
func (s *Stack) writePacketUntil(packet []byte, state socketWriteState) error {
	queue, loopback := s.outputQueue(packet)
	slot, err := s.reservePacketUntil(queue, loopback, state)
	if err != nil {
		return err
	}
	if !queue.enqueueReservedPacket(slot, packet, false) {
		return ErrClosed
	}
	s.recordOutput(loopback)
	return nil
}

// writeCompletePacketUntil queues a caller-owned complete packet using an
// independently selected route destination. Header-included sockets may route
// through a send address that differs from the destination in the IP header.
func (s *Stack) writeCompletePacketUntil(packet []byte, routeTarget netip.Addr, state socketWriteState) error {
	queue, loopback := s.outputQueueFor(routeTarget)
	slot, err := s.reservePacketUntil(queue, loopback, state)
	if err != nil {
		return err
	}
	if !queue.enqueueReservedPacket(slot, packet, false) {
		return ErrClosed
	}
	s.recordOutput(loopback)
	return nil
}

// reservePacketUntil acquires one queue slot while observing a socket's
// mutable write deadline. Callers must release the slot if packet construction
// fails before enqueueReserved publishes it.
func (s *Stack) reservePacketUntil(queue *packetQueue, loopback bool, state socketWriteState) (uint16, error) {
	if err := state.err(); err != nil {
		return 0, err
	}
	if slot, reserved := queue.tryReserve(); reserved {
		return slot, nil
	}
	if state.dontWait {
		select {
		case <-s.closeCh:
			return 0, ErrClosed
		default:
			return 0, syscall.EAGAIN
		}
	}
	if loopback {
		select {
		case <-s.closeCh:
			return 0, ErrClosed
		default:
			return 0, ErrResourceLimit
		}
	}
	var timeout <-chan struct{}
	if state.deadline != nil {
		timeout = state.deadline.wait()
	}
	select {
	case slot := <-queue.free:
		if err := state.err(); err != nil {
			queue.releaseReserved(slot)
			return 0, err
		}
		return slot, nil
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	case <-state.closed:
		return 0, net.ErrClosed
	case <-s.closeCh:
		return 0, ErrClosed
	}
}

// deadlineTimer returns a disabled channel for an unset deadline.
func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	duration := time.Until(deadline)
	if duration < 0 {
		duration = 0
	}
	timer := time.NewTimer(duration)
	return timer, timer.C
}

// stopTimer stops a non-nil timer.
func stopTimer(timer *time.Timer) {
	if timer != nil && !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

// socketDeadline follows the channel-generation model used by net.Pipe. One
// timer closes the current wait channel to wake every blocked operation;
// extending or clearing a live deadline keeps that channel stable, so existing
// waiters observe the update without allocating their own timers. The zero
// value is ready for use.
type socketDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	waiter atomic.Pointer[socketDeadlineWaiter]
}

// socketDeadlineWaiter is one immutable channel generation. Publishing a new
// pointer lets the I/O fast path obtain the current channel without a lock.
type socketDeadlineWaiter struct {
	done chan struct{}
}

// set replaces the deadline. A zero time disables it, and an expired deadline
// closes the current generation immediately.
func (d *socketDeadline) set(deadline time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	waiter := d.waiter.Load()
	if waiter == nil {
		waiter = &socketDeadlineWaiter{done: make(chan struct{})}
		d.waiter.Store(waiter)
	}
	if d.timer != nil && !d.timer.Stop() {
		<-waiter.done
	}
	d.timer = nil
	closed := false
	select {
	case <-waiter.done:
		closed = true
	default:
	}
	if deadline.IsZero() {
		if closed {
			d.waiter.Store(&socketDeadlineWaiter{done: make(chan struct{})})
		}
		return
	}
	if duration := time.Until(deadline); duration > 0 {
		if closed {
			waiter = &socketDeadlineWaiter{done: make(chan struct{})}
			d.waiter.Store(waiter)
		}
		done := waiter.done
		d.timer = time.AfterFunc(duration, func() { close(done) })
		return
	}
	if !closed {
		close(waiter.done)
	}
}

// wait returns the channel closed by the current deadline generation.
func (d *socketDeadline) wait() <-chan struct{} {
	if waiter := d.waiter.Load(); waiter != nil {
		return waiter.done
	}
	d.mu.Lock()
	waiter := d.waiter.Load()
	if waiter == nil {
		waiter = &socketDeadlineWaiter{done: make(chan struct{})}
		d.waiter.Store(waiter)
	}
	d.mu.Unlock()
	return waiter.done
}

// stop releases an armed timer when its owning socket can no longer perform
// I/O. A callback that has already started may still close its private channel.
func (d *socketDeadline) stop() {
	d.mu.Lock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.mu.Unlock()
}

// socketWriteState carries the two independent events that can interrupt a
// write blocked on the stack's bounded packet queue.
type socketWriteState struct {
	deadline *socketDeadline
	closed   <-chan struct{}
	dontWait bool
}

// err reports an already-observable close before a deadline, matching socket
// methods that reject operations after Close even when a deadline also fired.
func (s socketWriteState) err() error {
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	if s.deadline != nil {
		select {
		case <-s.deadline.wait():
			return os.ErrDeadlineExceeded
		default:
		}
	}
	return nil
}

// ownedTimer is a reusable timer consumed by exactly one actor goroutine. Its
// active bit distinguishes a tick already received by select from an expired
// tick that still has to be drained before Reset under Go 1.20 timer semantics.
type ownedTimer struct {
	timer  *time.Timer
	active bool
}

// newOwnedTimer allocates one stopped timer with reusable ownership state.
func newOwnedTimer() *ownedTimer {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	return &ownedTimer{timer: timer}
}

// reset replaces the deadline and returns the stable timer channel.
func (t *ownedTimer) reset(duration time.Duration) <-chan time.Time {
	t.stop()
	if duration < 0 {
		duration = 0
	}
	t.timer.Reset(duration)
	t.active = true
	return t.timer.C
}

// consumed records that select received the current tick.
func (t *ownedTimer) consumed() { t.active = false }

// stop prevents the current generation and drains an unconsumed expired tick.
func (t *ownedTimer) stop() {
	if !t.active {
		return
	}
	t.active = false
	if !t.timer.Stop() {
		<-t.timer.C
	}
}

// close stops the timer and drains any value still owned by the caller.
func (t *ownedTimer) close() {
	t.stop()
	t.timer.Stop()
}

// outputQueue chooses local delivery when the destination belongs to this
// stack, otherwise the embedding link's packet queue.
func (s *Stack) outputQueue(packet []byte) (*packetQueue, bool) {
	if destination, ok := packetDestination(packet); ok {
		return s.outputQueueFor(destination)
	}
	return &s.outbound, false
}

// outputQueueFor chooses a queue when the packet builder already has the
// validated destination address.
func (s *Stack) outputQueueFor(destination netip.Addr) (*packetQueue, bool) {
	if s.isLocal(destination) {
		return &s.loopback, true
	}
	return &s.outbound, false
}

// recordOutput updates the appropriate queue statistic.
func (s *Stack) recordOutput(loopback bool) {
	if loopback {
		s.stats.loopbackPackets.Add(1)
	} else {
		s.stats.outboundPackets.Add(1)
	}
}

// handleInboundPacket validates and reassembles one L3 packet before
// dispatching it to ICMP, TCP, UDP, or a raw IP endpoint. receivedAt is shared
// by packets from one device batch so transport timing does not depend on
// parsing order.
func (s *Stack) handleInboundPacket(packet []byte, receivedAt time.Time, loopback bool) error {
	select {
	case <-s.closeCh:
		return ErrClosed
	default:
	}
	s.stats.inboundPackets.Add(1)
	parsed, ok := parseIPPacket(packet)
	if !ok {
		network := s.network.Load()
		fragment, validFragment := parseFragment(packet)
		if validFragment && s.acceptsInboundDestination(network, fragment.target, loopback) &&
			validInboundFragmentSource(network, fragment.source, fragment.target, fragment.protocol) {
			if fragment.truncated || fragment.parameter {
				s.discardFragment(fragment.reassemblyKey(loopback))
				s.stats.inboundDroppedPackets.Add(1)
				destination := s.classifyInboundDestination(s.network.Load(), fragment.target, loopback)
				code, at := byte(3), uint32(0)
				if fragment.parameter && !fragment.truncated {
					code, at = fragment.parameterCode, fragment.parameterAt
				}
				_ = s.sendInboundParameterProblem(ipPacket{
					source: fragment.source, target: fragment.target, original: fragment.original,
					parameterError: true, parameterCode: code, parameterAt: at,
				}, destination)
				return nil
			}
		}
		if validFragment {
			if reassembled, pending := s.reassembleParsedFragmentStatus(fragment, receivedAt, loopback); reassembled != nil {
				parsed, ok = parseIPPacket(reassembled)
			} else if pending {
				return nil
			}
		}
	}
	network := s.network.Load()
	destination := inboundDestinationRejected
	if ok {
		destination = s.classifyInboundDestination(network, parsed.target, loopback)
	}
	acceptedDestination := destination != inboundDestinationRejected
	invalidSource := ok && !validInboundPacketSource(network, parsed)
	if !ok || !acceptedDestination || invalidSource {
		s.stats.inboundDroppedPackets.Add(1)
		if !ok {
			s.stats.invalidIPPackets.Add(1)
		} else {
			s.stats.unacceptedIPPackets.Add(1)
			if !acceptedDestination {
				s.stats.nonlocalDestinationPackets.Add(1)
			} else {
				s.stats.invalidSourcePackets.Add(1)
			}
		}
		return nil
	}
	if destination == inboundDestinationPromiscuousUnicast {
		s.stats.promiscuousInboundPackets.Add(1)
	}
	s.mu.RLock()
	closed := s.closed
	ip := s.ip
	ipForwarder := s.ipForwarder
	multicast := s.multicast
	s.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if parsed.parameterError {
		s.stats.inboundDroppedPackets.Add(1)
		if destination == inboundDestinationMulticast && !isAllHostsGroup(parsed.target) &&
			(multicast == nil || !multicast.acceptsSource(parsed.target, parsed.source)) {
			return nil
		}
		_ = s.sendInboundParameterProblem(parsed, destination)
		return nil
	}
	// RFC 3542 requires the kernel to verify every received ICMPv6 checksum
	// before exposing the message to a raw socket. Raw fan-out precedes the
	// built-in ICMP handler below, so this validation belongs at the common
	// dispatch boundary rather than in the handler alone.
	if parsed.source.Is6() && parsed.protocol == ProtocolICMPv6 &&
		(len(parsed.payload) < 4 || transportChecksum(parsed.source, parsed.target, ProtocolICMPv6, parsed.payload) != 0) {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	multicastControl := isMulticastControlPacket(parsed)
	if multicastControl {
		multicast = s.multicastStateForQuery(parsed, multicast, receivedAt)
	}
	// UDP and raw sockets apply equivalent per-socket filters during fanout.
	// Built-in ICMP processing needs the aggregate interface filter here.
	if destination == inboundDestinationMulticast && (parsed.protocol == ProtocolICMPv4 || parsed.protocol == ProtocolICMPv6) &&
		!isAllHostsGroup(parsed.target) && !isMulticastControlPacket(parsed) &&
		(multicast == nil || !multicast.acceptsSource(parsed.target, parsed.source)) {
		s.stats.inboundDroppedPackets.Add(1)
		return nil
	}
	rawDelivered := false
	switch destination {
	case inboundDestinationLocalUnicast, inboundDestinationBroadcast:
		rawDelivered = ip != nil && ip.deliver(s, parsed)
	case inboundDestinationMulticast:
		if isAllHostsGroup(parsed.target) {
			if multicast != nil {
				rawDelivered = multicast.deliverImplicitIP(parsed, ip)
			} else {
				rawDelivered = ip != nil && ip.deliver(s, parsed)
			}
		} else {
			rawDelivered = multicast != nil && multicast.deliverIP(parsed)
		}
	}
	if multicastControl {
		if multicast != nil {
			multicast.handleControl(parsed, receivedAt)
		}
		return nil
	}
	switch parsed.protocol {
	case ProtocolTCP:
		if destination == inboundDestinationLocalUnicast || destination == inboundDestinationPromiscuousUnicast {
			return s.handleTCPForDestination(parsed, receivedAt, destination == inboundDestinationLocalUnicast)
		}
		return nil
	case ProtocolUDP:
		return s.handleUDP(parsed, destination)
	case ProtocolICMPv4:
		if parsed.source.Is4() && (destination == inboundDestinationLocalUnicast || destination == inboundDestinationPromiscuousUnicast) {
			return s.handleICMP(parsed, destination == inboundDestinationLocalUnicast)
		}
	case ProtocolICMPv6:
		if parsed.source.Is6() && destination == inboundDestinationMulticast {
			return s.handleMulticastICMPv6(parsed)
		}
		if parsed.source.Is6() && (destination == inboundDestinationLocalUnicast || destination == inboundDestinationPromiscuousUnicast) {
			return s.handleICMP(parsed, destination == inboundDestinationLocalUnicast)
		}
	default:
	}
	noNextHeader := parsed.source.Is6() && parsed.protocol == ProtocolNoNextHeader
	if (destination == inboundDestinationLocalUnicast || destination == inboundDestinationPromiscuousUnicast) &&
		!noNextHeader && !rawDelivered && ipForwarder != nil && ipForwarder.handlePacket(parsed) {
		return nil
	}
	if destination != inboundDestinationLocalUnicast || noNextHeader || rawDelivered {
		return nil
	}
	_ = s.sendProtocolUnreachable(parsed)
	return nil
}

// sendInboundParameterProblem applies the RFC 4443 multicast exception for
// an unrecognized IPv6 option. A multicast destination is never a valid reply
// source, so the response uses the unicast source selected for the sender.
func (s *Stack) sendInboundParameterProblem(packet ipPacket, destination inboundDestinationClass) error {
	if destination == inboundDestinationLocalUnicast {
		return s.sendParameterProblem(packet)
	}
	if destination != inboundDestinationMulticast || !packet.source.Is6() || packet.parameterCode != 2 {
		return nil
	}
	source, err := s.sourceForRequested(packet.source, netip.Addr{})
	if err != nil {
		return err
	}
	packet.target = source
	return s.sendParameterProblem(packet)
}

// Close cancels packet-device I/O, rejects later calls, and starts orderly
// socket and background-worker shutdown. It does not wait for socket actors or
// user forwarder handlers to return.
func (s *Stack) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	tcpConnections := make([]*TCPConn, 0, len(s.tcp))
	for _, connection := range s.tcp {
		tcpConnections = append(tcpConnections, connection)
	}
	tcpPassive := s.tcpPassive
	udpConnections := s.udpConnectionsLocked()
	ip := s.ip
	tcpForwarder, udpForwarder, ipForwarder, icmpForwarder := s.tcpForwarder, s.udpForwarder, s.ipForwarder, s.icmpForwarder
	multicast := s.multicast
	s.tcp = nil
	s.tcpPassive = nil
	s.tcpForwarder = nil
	s.udp = nil
	s.udpReuse = nil
	s.udpForwarded = nil
	s.udpForwarder = nil
	s.ip = nil
	s.ipForwarder = nil
	s.icmpForwarder = nil
	s.multicast = nil
	s.multicastSeed = nil
	s.stats.activeTCPConnections.Store(0)
	s.stats.activeTCPListeners.Store(0)
	s.stats.activeUDPSockets.Store(0)
	s.stats.activeIPSockets.Store(0)
	s.mu.Unlock()
	s.outbound.close()
	s.loopback.close()
	s.pathMTUMu.Lock()
	s.pathMTU = nil
	s.pathMTUMu.Unlock()
	s.fragmentMu.Lock()
	s.fragments = nil
	s.fragmentBytes = 0
	s.fragmentMu.Unlock()
	if tcpPassive != nil {
		tcpPassive.closeAll()
	}
	if tcpForwarder != nil {
		tcpForwarder.closeFromStack()
	}
	if udpForwarder != nil {
		udpForwarder.closeFromStack()
	}
	if ipForwarder != nil {
		ipForwarder.closeFromStack()
	}
	if icmpForwarder != nil {
		icmpForwarder.closeFromStack()
	}
	if multicast != nil {
		multicast.close()
	}
	for _, connection := range tcpConnections {
		connection.abortWithoutReset(ErrClosed)
	}
	for _, connection := range udpConnections {
		connection.closeFromStack()
	}
	if ip != nil {
		ip.closeAll()
	}
	return nil
}

// closeTCPListener removes listener from passive dispatch and publishes its
// closure.
func (s *Stack) closeTCPListener(listener *TCPListener) bool {
	s.mu.Lock()
	removed := false
	state, ok := s.tcpPassive.(*tcpPassiveState)
	if ok && state.remove(listener) {
		s.stats.activeTCPListeners.Add(^uint64(0))
		removed = true
		if state.empty() {
			s.tcpPassive = nil
		}
	}
	s.mu.Unlock()
	listener.closeFromStack()
	return removed
}

// closeUDP removes connection from the UDP dispatcher and releases its port.
func (s *Stack) closeUDP(connection *UDPConn) bool {
	key := udpKey{address: connection.local, port: connection.port}
	flow := udpFlowKey{local: netip.AddrPortFrom(connection.local, connection.port), remote: connection.remote}
	s.mu.Lock()
	removed := false
	if s.udp[key] == connection {
		delete(s.udp, key)
		removed = true
	} else if s.udpForwarded[flow] == connection {
		delete(s.udpForwarded, flow)
		if len(s.udpForwarded) == 0 {
			s.udpForwarded = nil
		}
		removed = true
	} else if s.udpReuse != nil && s.udpReuse.remove(connection) {
		removed = true
		if s.udpReuse.empty() {
			s.udpReuse = nil
		}
	}
	if removed {
		if s.multicast != nil {
			s.multicast.removeEndpoint(connection)
		}
		s.stats.activeUDPSockets.Add(^uint64(0))
	}
	s.mu.Unlock()
	if removed {
		s.pruneFragments(s.network.Load())
	}
	connection.closeFromStack()
	return removed
}

// udpConnectionsLocked returns every exclusive and REUSEPORT socket while
// Stack.mu is held.
func (s *Stack) udpConnectionsLocked() []*UDPConn {
	connections := make([]*UDPConn, 0, len(s.udp)+len(s.udpForwarded))
	for _, connection := range s.udp {
		connections = append(connections, connection)
	}
	if s.udpReuse != nil {
		connections = append(connections, s.udpReuse.connections()...)
	}
	for _, connection := range s.udpForwarded {
		connections = append(connections, connection)
	}
	return connections
}

// closeIP removes a protocol socket from fan-out and publishes closure.
func (s *Stack) closeIP(connection *IPConn) bool {
	s.mu.Lock()
	removed := false
	state, ok := s.ip.(*ipEndpointState)
	if ok && state.remove(connection) {
		if s.multicast != nil {
			s.multicast.removeEndpoint(connection)
		}
		s.stats.activeIPSockets.Add(^uint64(0))
		removed = true
		if state.empty() {
			s.ip = nil
		}
	}
	s.mu.Unlock()
	if removed {
		s.pruneFragments(s.network.Load())
	}
	connection.closeFromStack()
	return removed
}

// removeTCP removes a terminated connection and releases its port.
func (s *Stack) removeTCP(connection *TCPConn) {
	s.mu.Lock()
	if s.tcp[connection.key] == connection {
		delete(s.tcp, connection.key)
		s.stats.activeTCPConnections.Add(^uint64(0))
	}
	s.mu.Unlock()
}
