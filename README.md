# mihomo IP stack

The mihomo IP stack (MIPS) is the small, pure-Go userspace IP stack developed
for mihomo. It converts complete IPv4 and IPv6 packets from an arbitrary L3
link into standard Go TCP, UDP, and IP protocol socket interfaces. It requires
Go 1.20 or later, uses only the Go standard library, and does not require cgo.

The package is independent of any particular link, routing policy, or L2
neighbor implementation. An embedding application owns route admission and
packet delivery.

## Usage

```go
package main

import (
    "context"
    "net/netip"

    "github.com/metacubex/mipstack"
)

func open(ctx context.Context, local netip.Prefix, destination netip.AddrPort) error {
    stack, err := mipstack.New(mipstack.Config{
        LocalAddresses: []netip.Prefix{local},
        MTU:            1500,
        TCP: mipstack.TCPSocketDefaults{
            CongestionControl: mipstack.CongestionControlCUBIC,
        },
    })
    if err != nil {
        return err
    }
    defer stack.Close()
    if err = stack.Start(); err != nil {
        return err
    }

    connection, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, destination)
    if err != nil {
        return err
    }
    return connection.Close()
}
```

`Stack.Write` delivers complete inbound IP packets to the stack. `Stack.Read`
returns complete outbound IP packets for the embedding link:

```go
_, err := stack.Write([][]byte{inboundPacket}, 0)

buffer := make([]byte, 65535)
sizes := []int{0}
_, err = stack.Read([][]byte{buffer}, sizes, 0)
outboundPacket := buffer[:sizes[0]]
```

The packet methods intentionally match the common batched userspace-TUN shape.
`Read` blocks for one packet and then drains up to 64 currently queued packets
into the supplied buffers; `BatchSize` reports that upper bound. `Write`
accepts every packet supplied in an inbound batch. `Start` is idempotent, while
`Close` is terminal and unblocks pending packet and socket operations.
`Read` requires `sizes` to be at least as long as the buffer slice and honors
the same leading `offset` in every buffer. Both methods report the successfully
completed packet prefix before any later-buffer error, as expected by wireguard-go's
packet-device loops. They also accept a buffer slice larger than `BatchSize`
because a composite WireGuard device may use a larger Bind batch; `Read`
still returns no more than 64 packets.

For integration with userspace packet-device consumers, `Stack` also provides
`MTU`, `Name`, and `BatchSize`. `LocalAddresses` returns an independent
snapshot of every configured address in configuration order. Operating-system
file descriptors and event channels whose element type belongs to another
package are left to embedding adapters so MIPS remains standard-library-only.

## Socket API

MIPS provides:

- `DialTCP` for active IPv4 and IPv6 TCP connections;
- `ListenTCP` for specific or wildcard passive TCP endpoints;
- `ListenTCPReusePort` for flow-distributed shared TCP bindings;
- `DialUDP` for connected UDP sockets;
- `ListenUDP` for unconnected UDP packet sockets;
- `ListenUDPReusePort` for flow-distributed shared UDP bindings;
- `DialIP` and `ListenIP` for connected and unconnected IPv4 or IPv6 protocol
  payload sockets, using standard network names such as `ip4:icmp`,
  `ip6:ipv6-icmp`, and `ip:99`;
- `TCPForwarder`, `UDPForwarder`, and `ICMPForwarder` for otherwise unhandled
  inbound traffic, including transparent nonlocal destinations;
- exported `TCPConn`, `TCPListener`, `UDPConn`, and `IPConn` implementations of the
  corresponding standard `net` interfaces.

The three `DialTCP`, `DialUDP`, and `DialIP` entry points mirror the netip-based
methods available on newer `net.Dialer` versions: they accept a context,
network name, local address, and remote address, while returning `net.Conn` for
straightforward adapter use. The package remains buildable with Go 1.20.

Listen methods accept the standard `tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, and
`udp6` network names. An empty `netip.Addr` has the same wildcard meaning as a
nil IP in `net.TCPAddr` or `net.UDPAddr`; its port is retained. For the generic
network, a wildcard becomes one dual-stack `[::]` endpoint when both address
families are configured. The `4` and `6` forms select one family and reject an
explicit address from the other family.

`ListenIP` applies the same empty-address rules to `ip`, `ip4`, and `ip6`
protocol sockets. A generic `ip:*` wildcard receives both families when both
are configured. On unconnected UDP and IP sockets, `Read` reads a payload and
discards its source address, matching the corresponding standard connection
types; `ReadFrom` and message reads retain it.

Ordinary listeners have exclusive bindings. The explicit `ReusePort` methods
may share an address and port only with other `ReusePort` listeners. Exact
bindings take precedence over wildcard bindings, and a per-registry keyed hash
keeps each TCP or UDP flow on one group member. Closing a TCP listener permits
an immediate rebind while its already accepted connections remain active,
matching the `SO_REUSEADDR` behavior used by standard Go listeners.

## Transparent interception

`Config.Promiscuous` admits valid unicast IP packets whose destination is not
listed by `LocalAddresses`. This is an L3 transparent-receive policy, not an L2
interface or MAC promiscuous mode. Local ownership remains unchanged: ordinary
wildcard sockets receive only managed local destinations, source selection
uses only `LocalAddresses`, and nonlocal destinations never become loopback
routes. The forwarder name refers to delivery into an application handler;
MIPS still does not route or forward IP packets between links.

Forwarders and promiscuous admission are independent. A forwarder always sees
otherwise unhandled traffic addressed to `LocalAddresses`, without requiring
`Promiscuous`. `Promiscuous` is required only when the original destination is
not locally owned. Enabling it without a matching forwarder does not make
ordinary wildcard sockets transparent and does not generate automatic replies;
the admitted nonlocal TCP, UDP, and ICMP packet is silently dropped.

`NewTCPForwarder`, `NewUDPForwarder`, and `NewICMPForwarder` install one
protocol-specific fallback handler each. All three constructors take their own
options type so later protocol policy can evolve independently. Established
tuples and ordinary local listeners take precedence. A TCP request represents
a valid initial SYN. Its handler runs in a new goroutine and may block, but an
undecided handler occupies `TCPForwarderOptions.MaxInFlight` capacity. `Accept`
blocks until the handshake, context cancellation, or stack closure and returns
a `TCPConn` whose `LocalAddr` preserves the original destination. The handler
must wait for `Accept` itself to return, but may return immediately afterward:
the returned connection has its own lifetime and may instead be handed to
another goroutine. `Drop` consumes the SYN silently, while `Reject` sends the
RFC 9293 reset on a best-effort basis. Retransmitted SYNs do not create
duplicate handler calls.

`TCPForwarderRequest.Done` closes when its handler returns, a pending request
is invalidated by configuration, or its forwarder or stack closes. Forwarder
closure remains observable after the request has selected an action, allowing
blocking handler work to stop promptly. Each forwarder's `Done` channel closes
on direct closure or `Stack.Close`; `Close` does not wait for handlers,
accepted endpoints, or replies already in progress.

UDP requests expose the source, original destination, and triggering payload.
`Accept` creates a connected `UDPConn`, offers a copy of that first datagram to
its receive queue, and retains the complete four-tuple for subsequent dispatch.
The connection is bound to the original destination and connected to the
original source: `Read` accepts only that peer, `Write` replies to it, and
`WriteTo` reports `net.ErrWriteToConnected`. `Listen` instead creates an
unconnected `UDPConn` bound to the original destination: it receives all later
sources through `ReadFrom` and replies through `WriteTo`. Both actions offer
the first datagram to the new socket's capacity-bounded receive queue; a queue
drop does not undo endpoint registration. The handler must wait for `Accept` or
`Listen` to return, but the returned connection remains valid after the
callback. `Reply` writes one reverse datagram without retaining a flow. Its
first call selects synchronous reply mode, and it may then be repeated or
retried until the callback returns.

ICMP requests similarly expose a checksum-validated complete message and
provide a repeatable, checksum-repairing reverse `Reply`. `IsEchoRequest`
identifies an IPv4 or IPv6 Echo Request, while `ReplyEcho` constructs its reply
directly, preserving the identifier, sequence, and data. A detached ICMP
snapshot permits `Payload` modification, but its `Type` and `Code` retain the
original classification; changing the corresponding `Payload` bytes makes
`IsEchoRequest` false and causes `ReplyEcho` to report `syscall.EINVAL`.

UDP and ICMP handlers run synchronously inside `Stack.Write` or loopback packet
delivery. They may be invoked concurrently by concurrent writers and must
return promptly; waiting for traffic that depends on the same delivery call
would deadlock it. Request values and payloads returned by request methods are
borrowed and valid only during the callback. Detached responders instead own
their payload or message snapshot. Every handler must select one terminal
action or make at least one `Reply` call before returning; otherwise MIPS
applies `Drop`. After Reply mode begins, further Reply calls are allowed but
other request actions report `ErrForwarderReplyActive`. Every call must finish
before the callback returns.

`Detach` instead finishes the callback-scoped ownership transfer and returns a
responder with its own payload or message snapshot. That responder may be
retained or handed to another goroutine, while concurrent access to its mutable
snapshot remains the application's responsibility. Repeated or invalidated
terminal request actions report `ErrForwarderRequestCompleted`.

A detached UDP or ICMP responder starts pending. Its first `Reply` selects
reply mode, after which `Reply` may be called repeatedly or concurrently until
`Close`; concurrent calls have no ordering guarantee. Reply mode is selected
before output validation, so an output error does not change the legal next
operations and may be retried.

`Reject` and `Drop` are available only before the first `Reply`. `Close` before
reply mode is equivalent to `Drop`, while closing an active responder prevents
new replies and permits already started calls to finish. `Drop` or `Reject` in
reply mode reports `ErrForwarderReplyActive`; actions after closure report
`net.ErrClosed`. The forwarder does not retain the responder, create a timer,
or impose a detached-request capacity. The application owns its memory,
concurrency bound, cancellation, timeout, and eventual logical closure. Every
output call revalidates forwarder closure and the current destination policy.
`Done` lets asynchronous work observe permanent forwarder or stack closure;
configuration changes remain dynamic and are reported by individual calls.

Request-scoped `Reply` and every `Reject` action are nonblocking with respect to
the outbound packet queue. They report `ErrResourceLimit` when capacity is
unavailable; a fragmented reply reserves all required slots before publishing
any fragment. TCP resets and ICMP errors generated automatically for unhandled
local traffic follow the same best-effort policy but silently discard queue
pressure. Applications that need ordinary UDP write backpressure should use
`Accept` or `Listen`, retain the returned `UDPConn`, and set a write deadline.

`ForwarderInfo.Pending` excludes caller-owned responders and handlers that
continue running after selecting an action. `Accepted` counts created TCP/UDP
endpoints, `Replies` counts successfully queued replies, and `ReplyErrors`
counts failed attempts after reply mode was selected. Consequently reply
counters may exceed `Requests` when one request produces several packets.

Only a forwarded endpoint, request-scoped reply, or detached responder may use
an intercepted destination as an output source. Removing that destination's
admission by disabling `Promiscuous` closes affected forwarded connections,
removes pending fragments, invalidates callback-scoped requests, and makes
later responder output fail current-policy validation. Closing a forwarder
stops new fallback requests and invalidates undecided callback-scoped requests
without waiting for callbacks to return. An output action already claimed by
a request or responder may finish. Accepted TCP and UDP endpoints remain usable
until closed or invalidated by configuration.

Active sockets allocate from the IANA dynamic range (`49152..65535`) first.
Only when that range is unavailable for the requested binding or TCP tuple do
they fall back to non-privileged ports `1024..49151`. Ports below 1024 are
never selected automatically but remain available for explicit bindings.
TCP combines an RFC 6056-style SipHash offset of the local and remote
endpoints with a keyed full-period scan step. Different destinations therefore
observe separated sequences, and a collision-free sequence does not revisit a
recently closed tuple until it has traversed the complete range. The keys and
initial cursors are read from system randomness once when the Stack is created;
socket creation does not perform another system-random read.
`Config.MaxTCPConnections` may impose an application-selected resource bound;
its zero value does not impose an artificial connection limit. Listener count
is controlled only by available memory and explicit application creation.

`Config.Routes == nil` installs one default route for each configured address
family. A non-nil empty route slice deliberately admits only destinations that
are themselves local. IPv4-only stacks accept MTUs down to 68; configurations
containing IPv6 require the IPv6 minimum MTU of 1280.
`Config.TCP` defines policies inherited by newly created connections and
listeners: initial and maximum automatic receive/send buffers, completed and
half-open listener queues, congestion control, maximum pacing rate, keepalive,
receive-idle timeout, Nagle behavior, TCP user timeout, DSCP bits, and IPv6
Flow Label policy. A zero TCP Flow Label selects a stable keyed label for the
connection tuple; a nonzero value fixes the label for new connections. A zero
maximum pacing rate is unlimited; nonzero values cap paced data in bytes per
second. The initial data burst and control packets are not strictly shaped, so
this policy is not a byte-exact traffic shaper.
Congestion control accepts
`CongestionControlCUBIC`, `CongestionControlReno`, or `CongestionControlBBR`;
its zero value selects CUBIC. `UpdateConfig` applies a changed congestion
controller to established connections without an explicit per-connection
override. Existing sockets retain the other inherited policies. Receive window
scale is selected per connection from the configured receive ceiling,
so deliberate small-buffer policies retain window precision while large-BDP
connections can use their full automatic maximum. Calling `SetReadBuffer` or
`SetWriteBuffer` locks that side to the application value and disables its
automatic growth, matching the user-locked behavior of operating-system TCP
stacks. Automatic growth follows application-consumed and acknowledged bytes
per RTT rather than queue size or cwnd alone, so short-RTT scheduler batches do
not inflate buffers. `SetCongestionControl`, `SetMaximumPacingRate`, and
`SetTrafficClass` provide per-connection overrides. Passing zero to
`SetMaximumPacingRate` removes the limit without resetting the controller's
path model. BBR pacing groups whole Linux-style send quanta to amortize
userspace actor scheduling; a group never exceeds four send quanta, and only
one bounded group may be credited ahead of the pacing clock.

`Config.UDP` and `Config.IP` define the receive-buffer capacity, default
TTL/Hop Limit, default TOS/Traffic Class, and IPv6 Flow Label policy inherited
by new datagram sockets. `SetReadBuffer`, `SetHopLimit`, `SetTrafficClass`, and
`SetFlowLabel` provide per-socket overrides. A zero configured Flow Label uses
a stable keyed label for each flow; explicitly setting a socket label to zero
disables automatic labeling. Nonzero message control fields override the
socket defaults; an explicit zero TOS/Traffic Class or Flow Label encoded in
raw OOB data remains distinguishable from an omitted field.

Socket operation failures use `*net.OpError`. `errors.Is` continues to identify
`os.ErrDeadlineExceeded`, `net.ErrClosed`, and syscall errors. Orderly TCP EOF
is returned directly as `io.EOF`, and destination-specific writes on connected
UDP or IP sockets retain `net.ErrWriteToConnected`. Validated asynchronous ICMP
details are available through `errors.As` to `mipstack.ICMPError`.

`TCPConn.SetLinger` provides background graceful close, abortive close, and a
bounded wait for acknowledgement. `UDPConn.SetReadBuffer` changes the receive
queue's approximate retained-memory capacity; payload and per-datagram
metadata both count toward the bound. UDP writes are synchronous with packet
delivery to the embedding device, so `SetWriteBuffer` is a validated no-op.

`TCPConn.Info` returns a consistent live diagnostic snapshot from the
connection actor and retains the final snapshot after close. It includes RFC
9293 state, endpoints, negotiated extensions, RTT/RTO, congestion controller,
cwnd and ssthresh, peer/receive windows, bytes in flight, BBR delivery and
pacing rates and mode, path MTU and active probe state, buffer occupancy and
automatic limits, byte counters, recovery state, inherited
keepalive/Nagle/DSCP/Flow Label policies, window-scale values, and
connection-local retransmission, PMTU-probe, and spurious-recovery counters.
It distinguishes application-limited delivery from host-scheduler-limited
delivery and counts material pacing wake delays, which helps distinguish a
local runtime stall from a path-bandwidth reduction. The configured maximum
pacing rate is reported alongside the effective rate.
It also reports the current and peak byte-bounded actor queue occupancy and
queue drops, making scheduler or embedding-link backpressure distinguishable
from network loss.
`TCPListener.Info` reports current, capacity, and lifetime peak occupancy for
the accept and SYN backlogs, along with handshake, SYN-cookie, accept, timeout,
and queue-drop counters. `UDPConn.Info` and `IPConn.Info` expose endpoint
identity, queue occupancy, socket defaults, path MTU for connected sockets,
and cumulative accepted, dropped, and transmitted datagram counters. Both
retain the latest correlated ICMP error. An automatic `IPConn` Flow Label is
reported as zero because raw payload fields may select a different flow on
each write; fixed socket labels are reported directly.

UDP message methods use the Linux 64-bit little-endian control-message layout
on every host. `ReadMsgUDP` emits `IP_PKTINFO` or `IPV6_PKTINFO` for the local
destination plus TTL/Hop Limit and TOS/Traffic Class, with Linux
`MSG_TRUNC`/`MSG_CTRUNC` flags. Passing that data to `WriteMsgUDP` selects the
corresponding managed source and output header fields. IPv6 messages also
carry Linux `IPV6_FLOWINFO`. `IPConn` uses the same ancillary representation.

`IPv4ControlMessage` and `IPv6ControlMessage` make that ancillary data
structured rather than opaque. Their `Parse` methods decode OOB returned by a
message read; their `Marshal` methods encode `Src`, TTL/Hop Limit, and
TOS/Traffic Class for a message write. `IPv6ControlMessage` also exposes the
20-bit Flow Label. `Dst` is populated while parsing. `IfIndex` is always zero
because MIPS has one embedding link.

## Protocol behavior

TCP implements active and passive open, bounded accept and SYN queues,
concurrent four-tuple demultiplexing, safe local-port reuse for distinct remote
tuples, and bounded active and TIME_WAIT state. Validated inbound segments wait
in a dynamically allocated, byte-bounded FIFO, so idle connections do not pay
for a large channel while high-throughput connections are not constrained by
an arbitrary segment count. Initial sequence numbers follow RFC 6528: a
four-microsecond monotonic counter is added to a SipHash-derived per-four-tuple
offset under a 128-bit per-stack secret. Its data path includes bounded
send and receive buffers, adaptive RTO with exponential backoff, selectable
CUBIC, Reno, and paced model-based BBR congestion control, window scaling,
delayed ACKs, SACK multi-hole recovery with Proportional Rate Reduction, RACK
time-based loss detection, tail-loss probes, timestamp negotiation with PAWS,
and classic ECN feedback. Text and FIN carried in a stateful SYN or SYN-ACK are
retained through the handshake and processed only after the connection enters
ESTABLISHED. SYN-cookie mode remains stateless, so unacknowledged SYN text is
accepted only when the peer retransmits it with or after the final ACK.

Loss evidence, SACK/RACK/TLP retransmission selection, PRR inputs, and generic
delivery-rate sampling remain owned by TCP rather than an individual
congestion controller. Reno, CUBIC, and BBR are separate per-connection
implementations behind the public `CongestionController` event contract; each
owns its window policy and private model. Consequently a new controller does
not require protocol-specific branches in the TCP actor, and delivery-rate
controllers can reuse the common sampler without duplicating TCP sequence or
scoreboard logic.

Custom algorithms are registered process-wide with
`RegisterCongestionControl` and selected through the existing
`TCPSocketDefaults.CongestionControl` field. Registration is permanent and
cannot replace an existing name, so live connections never race an unloaded
factory. The factory creates one independent controller per connection. Its
first callback is `CongestionEventInitialize`; later callbacks are serialized
on that connection's actor, reuse the `CongestionEvent` storage, and must not
block or retain it. Factories and controller instances belonging to different
connections may run concurrently. Implementations must ignore unknown event
types so a newer stack can add observations without changing the one-method
controller interface.

`CongestionState` supplies the Linux-style connection view. Controllers may
change cwnd and ssthresh directly during the event types that permit those
outputs. They may also select an explicit byte-rate for the common pacer, or
declare `CongestionControlFeatureCustomPacing` when they need to own pacing
deadlines and wake accounting. Declaring
`CongestionControlFeatureDeliveryRate` enables per-transmission metadata and a
Linux-style sample on ACK events; algorithms that do not need it pay no
sampling cost. The sample is a callback-lifetime read-only view exposed through
accessors, so sampler internals can evolve without changing controller code.
`CongestionControlFeatureTransmissionEvents` opts into original send and
retransmission callbacks and is required by custom pacers.
`CongestionControlFeatureCustomRecovery` opts into PRR and recovery-window
decisions. Without it TCP applies its RFC recovery defaults without dispatching
those detailed stages; checkpoint and undo notifications remain available to
every controller for restoring private state after spurious recovery.

Validated network- and host-unreachable feedback for `SND.UNA` applies RFC
6069 TCP-LD one-step RTO backoff reversion without turning an established
connection's soft network error into a hard failure.
On a SACK-negotiated connection, only newly reported scoreboard information
counts toward RFC 6675 `DupAcks`; repeated cumulative ACKs and window-probe
responses without new SACK data cannot manufacture a loss episode.
Initial Reno and CUBIC slow start uses RFC 9406 HyStart++ and Conservative Slow
Start; BBR retains its own Startup model. Eifel timestamps and conservative
DSACK accounting detect spurious fast retransmits and timeouts, while the RFC
4015 response bounds the restored congestion window and makes the RTO more
conservative after a spurious timeout. TCP also handles overlap-aware receive
reassembly, data-bearing zero-window probes, reset validation, deadlines,
half-close, FIN states, and TIME_WAIT.

BBR is a byte-scaled implementation of Linux BBRv1. Each original or
retransmitted range carries a Linux-style delivery snapshot; ACK processing
uses the longer send and acknowledgement phase, a three-candidate ten-round
windowed maximum, and a ten-second minimum-RTT filter. Startup, Drain, ProbeBW,
and ProbeRTT use the Linux fixed-point gains, randomized ProbeBW phase, ACK
aggregation allowance, token-bucket policer detection, idle restart, and
first-round packet conservation. SACK and RACK remain responsible for proving
loss and selecting retransmissions; transmission-generation accounting keeps
merely speculative retransmissions out of BBR's loss model until a replacement
generation is independently proven lost, and excludes isolated PLPMTU probe
failures. BBR owns pacing and cwnd rather than duplicating the common recovery
machinery. Since a Go connection actor does not have kernel fq pacing, a
materially late pacing wake is marked locally limited so scheduler delay cannot
become a false low path-bandwidth sample. Complete scheduler-limited rounds
still participate in Startup plateau detection, preventing sustained host load
from trapping the connection in Startup. Pacing retains at most one send
quantum of overdue debt, groups at most four whole quanta per actor turn, and
credits at most one bounded group ahead of the pacing clock, preventing an
unbounded catch-up burst.

RTT sampling uses packet arrival time rather than actor scheduling time. Its
minimum is the Linux-style three-sample running minimum over a 300-second
window, so a route change can replace stale path history without retaining an
unbounded sample set. When receive work and a protocol timer become ready
together, the actor drains the finite receive snapshot that was already queued
before servicing the timer. Packets arriving during that turn are excluded, so
host scheduling delay cannot manufacture loss and a continuous packet stream
cannot starve retransmission, liveness, pacing, or PMTU timers. Transmission
timestamps start when packets enter the embedding device queue, and loss
timers defer while the original packet still occupies that FIFO, so link
backpressure is not misclassified as network loss.

TCP user timeout follows Linux `TCP_USER_TIMEOUT`: it applies only in
synchronized states, returns `ETIMEDOUT`, does not change retransmission or
keepalive probe timing, and bounds data that remains unacknowledged or unsent
behind a zero window. Retransmission does not restart the absolute deadline.
When keepalive is enabled, user timeout replaces the probe-count close policy.
MIPS treats it as a local socket policy and does not advertise the optional
RFC 5482 UTO option.

When the SYN backlog or configured connection capacity is exhausted, passive
open uses stateless SYN cookies instead of retaining another half-open
connection. A per-stack random key authenticates the complete tuple, client
sequence, recent time period, and negotiated options. A valid final ACK
reconstructs conservative MSS, window scaling, SACK, timestamp, and ECN state;
forged or expired cookies do not allocate a connection.

Validated ICMP Packet Too Big errors maintain a bounded, expiring destination
PMTU cache. Error type/code combinations and quoted TCP sequence spans are
checked before they can affect transport state. `Stack.PathMTU` exposes the
currently confirmed value, while `Stack.ConfirmPathMTU` records an
application-proven packetization-layer acknowledgement for protocols that
manage probing directly. TCP immediately resegments outstanding data and
implements RFC 4821 binary-search PLPMTUD when a cached reduction expires.
Upward probes carry real data; cumulative ACK confirms success, while only
isolated loss proven by SACK suppresses congestion response. Concurrent loss
and timeouts remain ordinary congestion and use TCP-friendly probe backoff.
MSS changes preserve the required byte/packet congestion units, and successful
probes update sibling flows sharing the destination path. A failed path is
also reduced by validated ICMP or by IPv4 and IPv6 PMTU black-hole inference
after repeated RTOs.

UDP uses the learned MTU for ordinary fragmentation. `WritePathMTUProbe` and
`WritePathMTUProbeTo` send an explicitly unfragmented packet above the current
confirmed PMTU but no larger than the first-hop MTU. Because UDP has no
generic acknowledgement, sending alone never raises the PMTU; an application
must use its own protected acknowledgement and then call `ConfirmPathMTU` or
`ConfirmPathMTUFor`, following RFC 8899's packetization-layer contract.
Connected UDP sockets select a stable local address and filter inbound remote
tuples; unconnected sockets can use arbitrary destinations in one IP family.
Both correlate asynchronous ICMP errors with recently used remote endpoints.

`IPConn` applies the same recent-destination correlation to protocol payload
writes. Validated errors are returned by a subsequent read and retained in
`IPInfo`; Packet Too Big also updates the shared destination PMTU. Its explicit
probe and confirmation methods follow the same application-acknowledgement
contract as UDP.

ICMP echo, unreachable, packet-too-big, IPv4 fragmentation, IPv6 source
fragmentation, and bounded IPv4 and IPv6 reassembly are handled internally.
Fragment overlap drops the complete datagram. Incomplete sets have count, byte,
piece, and lifetime limits. Unsolicited reset, port-unreachable, and echo
responses are rate limited, as are RFC 5961 challenge ACKs. ICMPv6 error
messages are capped at the IPv6 minimum MTU and active unsupported Routing
Headers receive the required Parameter Problem response.

Raw protocol sockets receive reassembled payload copies before the built-in
TCP, UDP, or ICMP handler runs. Multiple matching sockets receive independent
copies. A listener for an otherwise unknown protocol suppresses Protocol
Unreachable while its receive queue accepts or drops matching traffic.

`Stack.Stats` returns a lock-free snapshot of active socket counts, categorized
IP/TCP packet and actor-queue drops, passive handshake, SYN-cookie and accept
queue outcomes, retransmission modes, PMTU changes, fragment cleanup, and rate
limiting.

Optional surfaces are arranged for ordinary Go linker reachability rather than
build tags. A consumer that only dials TCP and listens for UDP does not retain
TCP listener/SYN-cookie code, `ReusePort` registries, raw `IPConn` support,
message-control helpers, forwarder implementations, or other unreferenced
public methods. No package-level registration table or reflection root keeps
these APIs alive.

## Scope

MIPS is an endpoint stack, not a general host network stack. `IPConn`
exchanges protocol payloads while MIPS owns the IP header; header-included
raw packets and operating-system file descriptors are deliberately absent. It
also does not implement forwarding, NAT, multicast sockets, TCP urgent data,
or next-hop routing. `LocalAddresses` controls endpoint ownership and source
selection. `Routes` provides destination admission, longest-prefix selection,
metrics, and optional preferred sources, while the lower link remains
responsible for gateways, next hops, and L2 neighbor handling. Applications
requiring those facilities should use a mature general-purpose userspace
stack.

## License

MIPS is licensed under the Mozilla Public License 2.0. See `LICENSE`.
