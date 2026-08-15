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
`Close` is terminal and unblocks pending packet and socket operations. It
returns after publishing closure and starting orderly shutdown; it does not
wait for TCP actors or user forwarder handlers to return. Stack-owned queues
and caches are discarded before it returns, while actor-owned buffers are
released as those actors observe cancellation.
`Read` requires `sizes` to be at least as long as the buffer slice and honors
the same leading `offset` in every buffer. Both methods report the successfully
completed packet prefix before any later-buffer error, as expected by wireguard-go's
packet-device loops. They also accept a buffer slice larger than `BatchSize`
because a composite WireGuard device may use a larger Bind batch; `Read`
still returns no more than 64 packets.

The outbound link queue uses byte-based deficit round robin modeled on the
local-flow scheduling in Linux `sch_fq`. New flows receive a bounded initial
allowance, active flows rotate by byte credit, and short UDP or ICMP exchanges
therefore do not sit behind an entire queue of bulk TCP packets. TCP pacing
remains connection-owned: the scheduler only chooses among packets that a TCP
actor has already made eligible. Local loopback delivery remains FIFO because
it has no serialized external-link bottleneck.

For integration with userspace packet-device consumers, `Stack` also provides
`MTU`, `Name`, and `BatchSize`. `LocalAddresses` returns an independent
snapshot of every configured address in configuration order. Operating-system
file descriptors and event channels whose element type belongs to another
package are left to embedding adapters so MIPS remains standard-library-only.

## Packet codec

`ParseIPPacket` exposes a validated, zero-copy `IPPacket` view of one complete
IPv4 or IPv6 packet. Its `TCPSegment`, `UDPDatagram`, and `ICMPMessage` methods
validate the final upper-layer protocol and checksum and return the matching
semantic value. Parsed option and payload slices borrow the input packet;
callers must copy or replace a slice before changing input they do not own.

The same four values construct wire data through `MarshalBinary` and
`AppendBinary`. They implement `encoding.BinaryMarshaler` on every supported Go
version and `encoding.BinaryAppender` when built with Go 1.24 or newer; the
`AppendBinary` method remains directly callable with Go 1.20. Both methods
validate the complete value, calculate the checksum owned by that layer, and
do not retain caller storage. `IPPacket` calculates the IPv4 header checksum
but leaves upper-layer checksums to `TCPSegment`, `UDPDatagram`, or
`ICMPMessage`; callers building another protocol can use the checksum helpers
below. `AppendBinary` preserves the existing destination prefix and supports
output that overlaps borrowed option or payload storage, including appending
to a zero-length view of the parsed wire buffer. It returns the original
destination unchanged when validation fails. `MarshalBinary` is semantically
identical to `AppendBinary(nil)`. For TCP, UDP, and ICMP, source and destination
addresses provide address-family and pseudo-header checksum context but are not
part of the returned transport wire. IPv4-mapped input addresses are normalized
to IPv4 during construction, while an IPv4-mapped address encoded in an IPv6
header is rejected, including inside a quoted packet carried by an ICMP
error. TCP encoding clears the three unexposed reserved bits and normalizes
every byte after End of Option List to RFC 9293's required zero padding while
parsing remains compatible with Linux's tolerant receive behavior. The
historic NS bit remains explicitly available. IPv6 encoding similarly clears
PadN data and Fragment reserved fields without hiding the received bytes from
a parsed `IPPacket`.

IPv4 option parsing likewise follows Linux's tolerant EOL behavior: received
bytes after End remain available in `IPPacket.IPv4Options`, while structured
option traversal stops at End and packet encoding writes canonical zero
padding.

`ICMPMessage.IsEchoRequest` and `IsEchoReply` identify complete IPv4 and IPv6
Echo messages, while `Echo` returns their identifier, sequence, and a borrowed
payload view. `SetEchoRequest` and `SetEchoReply` build either direction with
an independently owned payload. `EchoReply` creates a zero-copy semantic reply
from an existing request using a caller-selected source address; explicit
selection is required because multicast, broadcast, and anycast destinations
cannot be reused blindly as reply sources. The zero-copy reply shares `Body`
with the request, while `MarshalBinary` and `AppendBinary` encode the complete
message and calculate its address-family checksum.
`ICMPMessage.IsError` classifies supported family-specific error type/code
pairs, while `ICMPMessage.ICMPError` validates the available quoted structure
and returns its addresses, protocol, TCP or UDP ports, path MTU, and parameter
pointer. Quoted packet and payload slices borrow `ICMPMessage.Body`; socket
delivery takes an independent copy when it must retain them. For IPv6 No Next
Header, `QuotedPacket` retains ignored trailing bytes while `QuotedPayload` is
empty, matching `IPPacket.UpperLayer`. `ICMPError.ICMPMessage` performs the
reverse construction from a validated, possibly truncated quoted packet and
copies that quote; route selection, rate limiting, recursive-error suppression,
and quote truncation remain transmission policy rather than codec behavior.
The exported untyped ICMP type and code constants cover every error subtype the
stack accepts as well as Echo Request and Reply. This includes the RFC 8883
IPv6 Parameter Problem processing-limit codes and RFC 9914 P-Route errors.
RFC 8883's Destination Unreachable "Headers too long" code remains excluded
because its required RFC 4884 extension object is not represented by
`ICMPError`; accepting it as an ordinary quoted error would lose its pointer
and misidentify extension bytes as part of the quoted packet.

TCP options are available in wire order through `TCPSegment.HeaderOptions` and
`SetHeaderOptions`. `TCPHeaderOption` preserves unknown and repeated kinds and
provides typed construction and inspection for MSS, Window Scale,
SACK-Permitted, SACK blocks, and Timestamps. `TCPSACKBlock` uses the original
wrapping 32-bit sequence edges without applying connection-specific window
policy. IPv4 options use the corresponding `IPv4HeaderOptions` and
`SetIPv4HeaderOptions` methods; `IPv4HeaderOption` also exposes the copied,
class, and number fields of its complete option type. IPv4 and IPv6 option
descriptors both provide typed `RouterAlert` and `SetRouterAlert` methods; the
standalone codec preserves the complete 16-bit value, while stack IGMP and MLD
handling recognizes the protocol-defined value zero. `ProtocolIGMP` exposes
the corresponding IP protocol number alongside the existing protocol
constants.

`IPPacket.IPv6ExtensionHeaders` and `SetIPv6ExtensionHeaders` expose and build
the linked extension-header sequence without making callers write Next Header
links themselves. Hop-by-Hop and Destination Options headers additionally use
`IPv6ExtensionHeader.Options` and `SetOptions` for their option TLVs. Set
methods copy caller data and leave their receiver unchanged on failure; parse
methods return caller-owned descriptors whose data slices borrow the original
wire storage. Parsing preserves received sender-reserved fields for inspection;
serialization clears PadN data and Fragment reserved fields. Authentication and
Mobility headers remain opaque: their reserved fields are integrity-protected,
so callers constructing either header must provide canonical fields together
with a matching ICV or checksum.

`IPPacket.UpperLayer` structurally walks IPv6 Hop-by-Hop, Destination Options,
Routing, atomic Fragment, Authentication, and Mobility headers. ESP and
unknown values terminate traversal, while No Next Header returns no upper-layer
payload even if preserved trailing bytes are available through the structural
extension API. Structural AH or Mobility traversal does not authenticate or
otherwise implement those protocols; AH framing still requires its complete
fixed fields and IPv6's eight-octet alignment. Stateful fragment reassembly
belongs to `Stack`, not the standalone codec, while IPv6 jumbograms are not
supported. Non-atomic fragments and every Jumbo Payload option are therefore
rejected. A decoder that must validate an address-dependent pseudo-header
(TCP, checksummed UDP, or ICMPv6) rejects an active IPv4 source route, active
IPv6 Routing Header, or Mobile IPv6 Home Address option because it lacks the
corresponding routing state. ICMPv4 and checksum-disabled IPv4 UDP remain
decodable.

Protocol numbers, TCP flags, TCP and IP option kinds, and IPv6 extension-header
identifiers are exposed as untyped constants so callers can use them directly
with the wire-sized integer fields. This includes `ProtocolESP` and
`ProtocolNoNextHeader`. `TCPSegment.Flags` remains a `uint16`. The package also
exposes `InternetChecksum` and `IPTransportChecksum` for callers building
other upper-layer protocols. The codec intentionally stops at the 65,535-byte
non-jumbogram IP model used by the Stack.

## Socket API

MIPS provides:

- `DialTCP` for active IPv4 and IPv6 TCP connections;
- `ListenTCP` for specific or wildcard passive TCP endpoints;
- `DialUDP` for connected UDP sockets;
- `ListenUDP` for unconnected UDP packet sockets;
- `ListenMulticastUDP` for a reusable wildcard UDP binding joined to one IPv4
  or IPv6 multicast group;
- `DialIP` and `ListenIP` for connected and unconnected IPv4 or IPv6 protocol
  payload sockets, using standard network names such as `ip4:icmp`,
  `ip6:ipv6-icmp`, and `ip:99`;
- `TCPForwarder`, `UDPForwarder`, `IPForwarder`, and `ICMPForwarder` for
  otherwise unhandled inbound traffic, including transparent nonlocal
  destinations;
- exported `TCPConn`, `TCPListener`, `UDPConn`, and `IPConn` implementations of the
  corresponding standard `net` interfaces.

The zero-value `ListenConfig` and `Dialer` mirror the creation-time policy
pattern used by `net.ListenConfig` and `net.Dialer`. Their `Options` slices are
read in order and are not retained. `SocketOptions` constructs sealed,
strongly typed policies without adding a top-level exported type for every
option. The creation policies are:

| Scope | Options |
| --- | --- |
| TCP, UDP, and IP | `ReadBuffer`, `TrafficClass`, `FlowLabel` |
| TCP connections | `WriteBuffer`, `KeepAlive`, `KeepAliveConfig`, `NoDelay`, `IdleTimeout`, `UserTimeout`, `CongestionControl`, `CongestionControlFactory`, `MaximumPacingRate` |
| TCP listeners | `AcceptQueue`, `SYNBacklog`, plus the TCP connection policies inherited by accepted connections |
| UDP and IP | `ReceiveErrors`, `PathMTUDiscovery`, `HopLimit`, `Broadcast`, `MulticastHopLimit`, `MulticastLoopback` |
| TCP and UDP listeners | `ReuseAddress`, `ReusePort` |
| IP | `IPHeaderIncludedOnWrite`, `IPHeaderIncludedOnRead`, `ICMPv4Filter`, `ICMPv6Filter`, `IPv6Checksum` |

Every constructor is an explicit choice, including boolean `false` and valid
numeric zero values. Every policy has a corresponding `UnsetXxx` constructor;
the congestion-control name and factory forms share
`UnsetCongestionControl`. An unset marker removes an earlier choice of the
same kind and restores the operation-specific Stack default. Unset markers are
accepted by every socket creation operation and have no effect where the
corresponding setting is inapplicable. This supports layered option slices
without treating an explicit disable or zero as absence.

An option used with an inapplicable protocol or operation reports
`ENOPROTOOPT` before an endpoint is created. Repeated option kinds use the last
value or unset marker. `IPConn.SetIPHeaderIncludedOnWrite` may change the write
representation of an existing socket between operations; `SocketOption`
values are consumed only during socket creation. Like Linux raw sockets, an
ICMP error delivered after such a change uses the write representation in
effect when the error arrives. The direct `Stack` methods remain concise
default-policy entry points.

A TCP listener retains only its explicit connection-policy overrides. Each
accepted connection reads the current `Config.TCP` defaults at creation and
then applies those overrides, so a later `UpdateConfig` affects future accepts
without discarding listener-specific choices. Explicit TCP buffer capacities
also become their auto-tuning maxima. The listener's `AcceptQueue` and
`SYNBacklog` are fixed when it is bound, and its SYN-cookie responses use the
same receive-window, Traffic Class, and Flow Label policy as stateful
handshakes.

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

Direct TCP listeners enable `ReuseAddress` by default, matching Go's standard
listener setup; direct UDP listeners use exclusive bindings. A
`ListenConfig` can override the TCP default or opt UDP into reuse. Two
overlapping UDP bindings are compatible only when both enable `ReuseAddress`
or both enable `ReusePort`. A group in which every member enables `ReusePort`
uses a per-registry keyed flow hash; a `ReuseAddress` group otherwise delivers
unicast to its most recently bound member. TCP permits simultaneous shared
listeners only through `ReusePort`. Exact bindings take precedence over
wildcards. Port zero always allocates a distinct unused ephemeral port even
when reuse is enabled. Accepted TCP connections inherit both policies, so a
listener can be rebound over a live accepted connection only when the old and
new sockets share the applicable Linux reuse policy.

UDP and raw IP sockets expose the single-interface equivalents of Go's
`x/net/ipv4` and `x/net/ipv6` multicast controls: `JoinGroup`, `LeaveGroup`,
the source-specific join/leave and include/exclude operations, and atomic
`SetMulticastSourceFilter` snapshots for previously joined groups.
`MulticastSourceFilterExclude` and
`MulticastSourceFilterInclude` use Linux's `MCAST_EXCLUDE=0` and
`MCAST_INCLUDE=1` values. No interface argument is needed because one Stack
represents exactly one embedding interface.

Memberships belong to the socket that created them and are removed when that
socket is closed. While the Stack remains operational, removing its final
membership schedules the applicable state-change Report, Leave, or Done on a
best-effort basis. `Stack.Close` is terminal: it cancels pending reports and
packet I/O without attempting a final leave because the embedding link may no
longer be usable. `JoinSourceSpecificGroup` creates an INCLUDE membership for
its first source, and removing its final source leaves the group. The
include/exclude delta operations require an existing membership in the
corresponding mode. Closing one reusable listener does not affect memberships
owned by the other listeners on that port.

As an RFC 4604 SSM-aware host, MIPS requires source-specific INCLUDE
memberships for IPv4 232/8 and IPv6 FF3x::/32. Any-source joins, EXCLUDE
filters, and EXCLUDE delta operations in those ranges return `EINVAL`; an
older IGMPv1/v2 or MLDv1 Report cannot suppress a pending SSM report.

`SetMulticastHopLimit` and `SetMulticastLoopback` control output independently
from ordinary unicast hop limits. `ListenMulticastUDP` disables loopback on
the returned sending socket like `net.ListenMulticastUDP`; other sockets keep
the standard enabled default. IPv4 limited and configured-subnet broadcasts
are delivered to eligible wildcard UDP and raw sockets. `SetBroadcast`
controls output permission and starts enabled, matching Go's default UDP and
raw sockets on supported operating systems.

The stack maintains the RFC 9776 and RFC 3810 aggregate interface filter and
emits IGMPv1/v2/v3 or MLDv1/v2 reports according to the active querier
compatibility mode. Reports include the required Router Alert, fit the link
MTU, and preserve source-filter state across socket and address changes.
IPv6 interface-local multicast and an explicit multicast hop limit of zero
remain inside the host; multicast loopback still obeys each sending socket's
setting.

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
admitted nonlocal traffic without a matching protocol forwarder is silently
dropped.

`NewTCPForwarder`, `NewUDPForwarder`, `NewIPForwarder`, and
`NewICMPForwarder` install one protocol-specific fallback handler each. All
four constructors take their own options type so later protocol policy can
evolve independently. Established tuples and ordinary local listeners take
precedence. A TCP request represents a valid initial SYN. Its handler runs in
a new goroutine and may block, but an undecided handler occupies
`TCPForwarderOptions.MaxInFlight` capacity. `Accept` blocks until the handshake,
context cancellation, or stack closure and returns a `TCPConn` whose
`LocalAddr` preserves the original destination. The handler must wait for
`Accept` itself to return, but may return immediately afterward: the returned
connection has its own lifetime and may instead be handed to another
goroutine. `Drop` consumes the SYN silently, while `Reject` sends the RFC 9293
reset on a best-effort basis. Retransmitted SYNs do not create duplicate
handler calls. `Accept` takes the same variadic connection `SocketOption`
values as `Dialer`; option validation happens before the request is claimed,
so an invalid option does not prevent a different terminal action.

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
callback. Both creation methods accept the UDP/IP policy `SocketOption` values
used by `Dialer`; they validate options before claiming the request. Forwarded
listeners retain exclusive flow ownership and therefore reject bind-reuse
options. `Reply` writes one reverse datagram without retaining a flow and uses
`Flow().Destination` as its default source. `ReplyFrom` selects any valid
same-family source address and UDP port. Source membership in `LocalAddresses`
and unicast, multicast, or broadcast classification are not policy checks; a
zero source port is preserved. This is stateless transparent output, not
arbitrary destination selection: every reply still targets `Flow().Source`.
Replies may be repeated or retried and do not prevent a later `Accept`,
`Listen`, `Detach`, `DetachForReplies`, `Drop`, or `Reject`.
Stateless replies inherit the current `Config.UDP` output defaults.

ICMP requests similarly expose a checksum-validated complete message and
provide a repeatable, checksum-repairing reverse `Reply`. `IPPacket` exposes the
complete reassembled L3 packet: request-scoped storage is read-only and valid
only during the callback, while a detached responder owns its mutable snapshot.
In both forms `Message().Payload` aliases the ICMP region. Detached `Source`,
`Destination`, `Type`, and `Code` remain the original metadata; changing the
corresponding payload bytes makes `IsEchoRequest` false but changing IP header
bytes does not reclassify that metadata.
`ICMPForwarderMessage.ICMPMessage` validates the current wire snapshot and
returns a zero-copy semantic view whose `Body` aliases `Payload[4:]`.
`SetICMPMessage` performs the reverse conversion, recalculates the checksum,
and reuses existing `Payload` capacity when possible; validation failure leaves
the forwarder message unchanged.

`ReplyIPPacket` is a restricted header-included ICMP reply, not arbitrary raw
packet injection. Its destination must be the triggering packet's source; its
source may be any valid same-family address, without stack-membership or address
classification policy. The stack copies caller storage, normalizes IPv4 Total
Length or IPv6 Payload Length, repairs
the outer IPv4 and ICMP checksum, and preserves other supported header fields.
A fitting IPv6 atomic Fragment header is retained with reserved fields cleared.
If the packet must be fragmented, an existing atomic header is replaced rather
than nested, and the Fragment header is inserted after the RFC 8200
unfragmentable chain.
IPv4 DF reports `syscall.EMSGSIZE`; otherwise source fragmentation preserves
copied IPv4 options. ICMPv6 errors larger than the 1280-byte minimum IPv6 MTU
are rejected as required by RFC 4443, while informational messages may be
fragmented. `IsEchoRequest` identifies an IPv4 or IPv6 Echo Request, and
`ReplyEcho` constructs its reply directly, preserving identifier, sequence,
and data.

IP requests cover valid, reassembled upper-layer protocols that matched no
`IPConn` and are not TCP, UDP, ICMP, or IPv6 No Next Header. A matching raw
protocol socket always takes priority. `Message` exposes the source,
destination, protocol number, received hop limit, traffic class, IPv6 flow
label, and protocol payload. `Reply` sends the same protocol number in the
reverse direction using the current `Config.IP` output defaults, while
`Reject` emits IPv4 Protocol Unreachable or IPv6 Parameter Problem. IPv4
protocol number 59 remains an ordinary protocol; No Next Header is special
only in IPv6.

UDP, IP, and ICMP handlers run synchronously inside `Stack.Write` or loopback
packet delivery. They may be invoked concurrently by concurrent writers and
must return promptly; waiting for traffic that depends on the same delivery
call would deadlock it. Request values and payloads returned by request methods
are borrowed and valid only during the callback. `Reply`, `ReplyFrom`,
`ReplyIPPacket`, and `ReplyEcho` are repeatable output operations, not terminal
actions. A handler may make zero or more reply attempts and then select at most
one terminal action. Returning after at least one reply attempt without a
terminal action simply completes the request; returning without either applies
an implicit `Drop`. Every request method call must finish before the callback
returns.

For UDP, terminal request actions are `Accept`, `Listen`, `Detach`,
`DetachForReplies`, `Drop`, and `Reject`; for IP and ICMP they are `Detach`,
`DetachForReplies`, `Drop`, and `Reject`. Both detach methods remove the request
from the forwarder's pending set and transfer asynchronous reply ownership to a
caller-owned responder. `Detach` also copies the input snapshot and retains the
quote needed by `Reject`. `DetachForReplies` avoids those copies when the caller
already knows it needs only replies. The ownership and reference directions
are:

```text
Stack -> registered Forwarder -> pending callback-scoped Request
                                   |
                                   | Detach or DetachForReplies
                                   v
Caller -> detached Responder -> originating Forwarder state -> Stack
```

The lower chain is one-way: the responder retains access to its originating
forwarder's state and stack for output, diagnostics, and `Done`, but neither the
forwarder nor the stack retains the responder. It is therefore independent of
the callback and request lifetime, not independent of forwarder state. The
caller may retain it, hand it to another goroutine, or discard it; concurrent
access to its mutable snapshot remains the caller's responsibility. A request
reply that began before a terminal request action may finish, but a reply begun
after it reports `ErrForwarderRequestCompleted`. Repeated or invalidated
terminal request actions report the same error.

A detached UDP, IP, or ICMP responder permits repeated or concurrent reply
operations while it is active or restricted to replies. An argument,
forwarder, configuration, route, PMTU, queue, or stack error fails only that
call and may be followed by another reply or, while active, a terminal action.
Concurrent calls have no ordering guarantee.

`RestrictToReplies` irreversibly converts a responder returned by `Detach` to
the same capability set as one returned by `DetachForReplies`. It releases the
responder's references to copied input storage and does not count as `Drop` or
`Reject`. UDP retains `Flow`, `Reply`, `ReplyFrom`, and `Done`; IP retains
`Message` metadata, `Reply`, and `Done`; ICMP retains `Message` metadata,
`Reply`, `ReplyIPPacket`, and `Done`. Snapshot accessors then return nil payload
or packet storage, while `ReplyEcho`, `Drop`, and `Reject` report
`net.ErrClosed` where applicable. Repeated calls, including calls on a responder
returned by `DetachForReplies`, are idempotent no-ops; only a terminal responder
causes `RestrictToReplies` to report `net.ErrClosed`. The caller must invoke it
while no other responder method is running. Reply operations may again run
concurrently after it returns. A slice obtained before restriction remains
valid and keeps its backing storage live while the caller retains it.

`Drop` and `Reject` remain available after any number of responder replies, and
exactly one of them may terminate an active responder. They are unavailable
after restriction. A reply that began before an active responder's terminal
action may finish, while a later reply or terminal action reports
`net.ErrClosed`. The terminal action does not wait for calls already in
progress. Neither action is required for resource release because no stack-side
collection, timer, or detached-request capacity owns the responder. Discarding
it after its final reply releases the caller's reference and contributes no
terminal-action diagnostic count. The caller controls its retention,
concurrency bound, cancellation, and timeout. Every output call revalidates
forwarder closure, the current destination policy, and the return route.
Closing the originating forwarder closes the responder's `Done` channel and
makes later output fail with `net.ErrClosed`; it does not reclaim or mutate any
caller-owned snapshot. Configuration changes remain dynamic and are reported
by individual calls.

Request-scoped `Reply` and every `Reject` action are nonblocking with respect to
the outbound packet queue. They report `ErrResourceLimit` when capacity is
unavailable; a fragmented reply reserves all required slots before publishing
any fragment. TCP resets and ICMP errors generated automatically for unhandled
local traffic follow the same best-effort policy but silently discard queue
pressure. Applications that need ordinary UDP write backpressure should use
`Accept` or `Listen`, retain the returned `UDPConn`, and set a write deadline.

`ForwarderInfo.Pending` excludes caller-owned responders and handlers that
continue running after selecting an action. `Accepted` counts created TCP/UDP
endpoints, `Replies` counts successfully queued reply calls, and `ReplyErrors`
counts failed output attempts, including argument and packet validation
failures. Calls rejected because a terminal action already completed the
request or responder are lifecycle misuse rather than output attempts and do
not increment `ReplyErrors`. Reply counters may exceed `Requests` when one
request produces several replies, and a request may contribute to both reply
counters and one terminal-action counter.

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
`Config.AddressProperties` supplies the deprecated and temporary state that a
`netip.Prefix` cannot express. Automatic source selection applies the RFC 6724
same-address, scope, deprecation, label, temporary-address, and longest-prefix
rules in order. `PreferTemporaryAddresses` selects temporary IPv6 privacy
addresses after label matching; the zero value favors stable addresses. Every
property key must identify a configured local address, and `Temporary` is valid
only for IPv6.
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
`CongestionControlCUBIC`, `CongestionControlReno`, `CongestionControlBBR`, or
`CongestionControlBBR3`; its zero value selects CUBIC. A programmatic caller
may instead supply a local `CongestionControlFactory`, described below.
`UpdateConfig` applies a changed congestion controller to established
connections without an explicit per-connection override. Existing sockets
retain the other inherited policies. Receive window
scale is selected per connection from the configured receive ceiling,
so deliberate small-buffer policies retain window precision while large-BDP
connections can use their full automatic maximum. Calling `SetReadBuffer` or
`SetWriteBuffer` locks that side to the application value and disables its
automatic growth, matching the user-locked behavior of operating-system TCP
stacks. Automatic growth follows application-consumed and acknowledged bytes
per RTT rather than queue size or cwnd alone, so short-RTT scheduler batches do
not inflate buffers. `SetCongestionControl`,
`SetCongestionControlFactory`, `SetMaximumPacingRate`, and `SetTrafficClass`
provide per-connection overrides. An explicit named or local factory choice is
not replaced by later `UpdateConfig` default changes. Passing zero to
`SetMaximumPacingRate` removes the limit without resetting the controller's
path model. BBR pacing groups whole Linux-style send quanta to amortize
userspace actor scheduling; a group never exceeds four send quanta, and only
one bounded group may be credited ahead of the pacing clock.

`Config.UDP` and `Config.IP` define the receive-buffer capacity, path-MTU
policy, default TTL/Hop Limit, default TOS/Traffic Class, and IPv6 Flow Label
policy inherited by new datagram sockets. `SetReadBuffer`,
`SetPathMTUDiscovery`, `SetHopLimit`, `SetTrafficClass`, and `SetFlowLabel`
provide per-socket overrides. A zero configured Flow Label uses a stable keyed
label for each flow; explicitly setting a socket label to zero disables
automatic labeling. Nonzero message control fields override the socket
defaults; an explicit zero TOS/Traffic Class or Flow Label encoded in raw OOB
data remains distinguishable from an omitted field.

`PathMTUDiscovery` uses Linux's numeric `IP_PMTUDISC_*` values. `Dont` uses
confirmed destination PMTU, permits source fragmentation, and leaves IPv4 DF
clear. `Want` also uses destination PMTU, requests DF on a fitting IPv4 packet,
and may still fragment locally when needed. `Do` uses destination PMTU and
returns `EMSGSIZE` instead of fragmenting. `Probe` ignores destination PMTU,
uses the link MTU, requests DF, and returns `EMSGSIZE` above it. `Interface`
uses the link MTU, leaves DF clear, and rejects an oversized local packet;
`Omit` instead permits source fragmentation. `Interface` and `Omit` ignore
ICMP PMTU updates for that socket, matching Linux. The zero value is `Dont` and
preserves MIPS's fragmentable datagram default.

Socket operation failures use `*net.OpError`. `errors.Is` continues to identify
`os.ErrDeadlineExceeded`, `net.ErrClosed`, and syscall errors. Orderly TCP EOF
is returned directly as `io.EOF`, and destination-specific writes on connected
UDP or IP sockets retain `net.ErrWriteToConnected`. Validated asynchronous ICMP
details are available through `errors.As` to `mipstack.ICMPError`.

`TCPConn.SetLinger` provides background graceful close, abortive close, and a
bounded wait for acknowledgement. `UDPConn.SetReadBuffer` changes the receive
queue's approximate retained-memory capacity; payload, per-datagram metadata,
and asynchronous errors share the bound. `IPConn` applies the same policy.
`SetReceiveErrors(true)` reserves asynchronous ICMP errors for nonblocking
`ReadError`; an empty error queue returns `EAGAIN`. With the default false
setting, ordinary reads return queued errors after already queued payloads,
preserving the original socket behavior. `ReceiveErrors` reports the current
mode. UDP and IP writes are synchronous with packet delivery to the embedding
device, so `SetWriteBuffer` is a validated no-op.

UDP and IP `ReadBatch`/`WriteBatch` also accept Linux-compatible message flags.
`MessageFlagPeek` preserves an ordinary queued payload, while pending socket
errors and successful `MessageFlagErrorQueue` reads are consumed like Linux. A
`MessageFlagErrorQueue` read never blocks and returns the quoted failed payload,
the original destination in `Addr`, and a Linux `sock_extended_err` record in
`OOB`; `SocketErrorControlMessage.Parse` provides its structured form.
`MessageFlagDontWait` makes packet-queue reads and writes return `EAGAIN`
instead of waiting. `MessageFlagTruncated` requests the complete payload length
and, along with `MessageFlagControlTruncated`, also reports output truncation.
Nonblocking fragmented output reserves the complete fragment set before
publishing it, so a failed send cannot leave a partial datagram on the link or
loopback path.

An ordinary `IPConn` exchanges upper-layer protocol payloads. With
`IPHeaderIncludedOnWrite`, IPv4 writes follow Linux `IP_HDRINCL`: the stack
fills a zero source and ID, repairs Total Length and the header checksum, and
otherwise preserves the caller's header and payload. Linux IPv6
`IPV6_HDRINCL` preserves the supplied packet byte-for-byte, and MIPS does the
same. The destination argument selects routing independently from the
destination stored in either header. `IPHeaderIncludedOnRead` returns the
complete packet after validation and reassembly, retaining IPv4 options and
IPv6 extension headers while removing fragmentation state. Caller write
buffers and packets queued to different raw sockets have independent
ownership.

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
also report the PMTU-discovery mode, explicit-error mode, queued error count and
bytes, and errors dropped by the shared receive-buffer bound. They retain the
latest correlated ICMP error while open; closing the socket releases that
diagnostic state while preserving cumulative counters. An automatic `IPConn`
Flow Label is reported as zero because raw payload fields may select a different
flow on each write; fixed socket labels are reported directly.

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

`UDPConn.ReadBatch`/`WriteBatch` and `IPConn.ReadBatch`/`WriteBatch` use the
same `SocketMessage` layout as `x/net/ipv4` and `x/net/ipv6`: `Buffers` contains
the scatter/gather payload, `OOB` contains ancillary data, `Addr` carries the
peer, and `N`, `NN`, and `Flags` receive operation results. A read blocks for
its first message and then drains only the currently ready prefix;
`MessageFlagDontWait` makes the first read nonblocking.
`MessageFlagTruncated` and `MessageFlagControlTruncated` name the fixed Linux
result bits returned on every host. Batch operations follow Linux
`recvmmsg`/`sendmmsg` successful-prefix semantics: an error after one or more
completed messages is deferred until the caller retries the unprocessed
suffix, whose result fields remain unchanged.
Batch writes accept `MessageFlagDontWait`; other nonzero write flags return
`EOPNOTSUPP`.

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
CUBIC, Reno, BBRv1, and BBRv3 congestion control, window scaling,
delayed ACKs, SACK multi-hole recovery with Proportional Rate Reduction, RACK
time-based loss detection, tail-loss probes, timestamp negotiation with PAWS,
and classic ECN feedback. Text and FIN carried in a stateful SYN or SYN-ACK are
retained through the handshake and processed only after the connection enters
ESTABLISHED. SYN-cookie mode remains stateless, so unacknowledged SYN text is
accepted only when the peer retransmits it with or after the final ACK.

Loss evidence, SACK/RACK/TLP retransmission selection, PRR inputs, and generic
delivery-rate sampling remain owned by TCP rather than an individual
congestion controller. Reno, CUBIC, BBRv1, and BBRv3 are separate per-connection
implementations behind the public `CongestionController` event contract; each
owns its window policy and private model. Consequently a new controller does
not require protocol-specific branches in the TCP actor, and delivery-rate
controllers can reuse the common sampler without duplicating TCP sequence or
scoreboard logic.

Custom algorithms may be registered process-wide with
`RegisterCongestionControl` and selected by name through
`TCPSocketDefaults.CongestionControl`. Registration is permanent and cannot
replace an existing name, so live connections never race an unloaded factory.
Programmatic users may instead create an immutable local
`CongestionControlFactory` from a named `CongestionControlDefinition` with
`NewCongestionControlFactory`, install it in
`TCPSocketDefaults.CongestionControlFactory`, or select it for one live
connection with `SetCongestionControlFactory`. Local factories are not entered
in the process registry unless explicitly passed to
`RegisterCongestionControl`, may use the same diagnostic name with different
configuration, and compare by pointer identity when a live connection applies
an update. The constructor copies and privately retains the definition, so
later changes to the caller's value cannot alter the factory. The name and
factory fields in `TCPSocketDefaults` are mutually exclusive.

Every factory invocation receives a by-value `CongestionControlContext` with
the local and remote endpoints and the connection's active, passive, or
forwarded role. The context is an immutable identity snapshot rather than a
`TCPConn`, so a factory cannot reenter and deadlock the connection actor.
Dynamic MSS, RTT, window, pacing, delivery, loss, and recovery state arrives
through events. A factory may capture shared read-only configuration but must
create one independent controller per connection; factory calls and controller
instances belonging to different connections may run concurrently.

The first controller callback is `CongestionEventInitialize`; later callbacks
are serialized on that connection's actor, reuse the `CongestionEvent` storage,
and must not block or retain it. `CongestionEventRelease` is the final,
observational callback before an implementation is replaced or its connection
actor exits. It permits controller-owned cleanup but must return promptly and
must not start work that outlives it. Implementations must ignore unknown event
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
retransmission callbacks and is required by custom pacers. A controller may
attach a 64-bit `PacketState` value to each transmission generation; TCP
returns it unchanged through the selected delivery-rate sample.
`CongestionControlFeatureLossEvents` additionally retains that value until the
generation is proven lost and reports per-generation SACK, RACK, RTO, and
tail-loss-probe recovery events. `CongestionRateSample.TailLossProbeACK`
identifies the Linux-style ambiguous ACK that exactly covers a retransmitted
TLP range, allowing a model to preserve delivery signals until later ACK or
DSACK evidence resolves the loss.
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

BBR3 is an independent byte-scaled implementation of Google's public Linux
BBRv3 model. It retains STARTUP, DRAIN, PROBE_BW, and PROBE_RTT; PROBE_BW uses
the DOWN, CRUISE, REFILL, and UP phases and the corresponding ACK-feedback
state machine. Its path model includes a two-cycle `bw_hi` maximum, short-term
`bw_lo` and `inflight_lo` bounds, the robust `inflight_hi` bound, loss-prefix
reconstruction from each transmission generation, loss-based Startup exit,
Reno-coexistence and randomized wall-clock probe intervals, ACK aggregation,
and the independent five-second ProbeRTT trigger with a ten-second global
minimum-RTT window. Recovery undo restores the less restrictive pre-recovery
model bounds.

MIPS does not enable BBRv3's low-latency ECN model: classic RFC 3168 ECE does
not provide the precise homogeneous CE counts and route-level low-latency ECN
eligibility that Linux requires for that model. Classic ECN still uses TCP's
ordinary congestion-recovery path. Protective Load Balancing is also absent because
an endpoint stack with one embedding link has no kernel route rehash operation.
MIPS sends individual TCP segments rather than kernel TSO/GSO skbs, and its
connection actor supplies bounded pacing groups in place of Linux fq/EDT.
Consequently kernel offload-specific burst sizing is not reproduced, while
send-time flight/loss snapshots and all model-visible pacing deadlines remain
per connection.

RTT sampling uses packet arrival time rather than actor scheduling time. Its
minimum is the Linux-style three-sample running minimum over a 300-second
window, so a route change can replace stale path history without retaining an
unbounded sample set. When receive work and a protocol timer become ready
together, the actor drains the finite receive snapshot that was already queued
before servicing the timer. Packets arriving during that turn are excluded, so
host scheduling delay cannot manufacture loss and a continuous packet stream
cannot starve retransmission, liveness, pacing, or PMTU timers. Transmission
timestamps start when packets enter the embedding device queue, and loss
timers defer while the original packet still occupies that outbound queue, so
link backpressure is not misclassified as network loss.

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
`IPConnInfo`; Packet Too Big also updates the shared destination PMTU. Its
explicit probe and confirmation methods follow the same
application-acknowledgement contract as UDP.

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
`ICMPv4Filter` follows Linux's 32-bit `ICMP_FILTER` receive mask, while
`ICMPv6Filter` covers all 256 types defined by RFC 3542. Both may be installed
at creation or atomically replaced on an `IPConn`; packets already queued are
not reconsidered. ICMPv6 checksums are always verified and are inserted for
ordinary payload writes. Other raw IPv6 protocols may enable RFC 3542 checksum
insertion and verification at an even payload offset through `IPv6Checksum`.
Checksum processing occurs before source fragmentation and after reassembly,
and does not alter caller-owned header-included writes.

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

## gVisor interoperability

[`interop/gvisor`](interop/gvisor) is an independent Go 1.20 module that links
the current checkout directly to the metacubex gVisor fork. Its tests exchange
complete L3 packets over an IPv4 MTU matrix from 68 through 9,000 bytes and an
IPv6 matrix from 1,280 through 9,000 bytes. Coverage includes bidirectional
TCP, UDP, ICMP echo, fragmentation and impairment recovery, every built-in TCP
congestion controller, socket errors and ancillary data, transparent
Forwarders, broadcast, multicast, PMTU handling, raw IP payload sockets,
header-included complete packets, complete-packet reassembly, and Linux-style
ICMP error queues.
Keeping the tests behind a nested module preserves the root module's
standard-library-only dependency graph.

The root `go test ./...` command does not enter nested modules. Run this suite
explicitly with `cd interop/gvisor && go test ./...` when changing packet or
transport behavior.

## Scope

MIPS is an endpoint stack, not a general host network stack. `IPConn` supports
protocol-payload and complete-packet raw socket representations, but
operating-system file descriptors are deliberately absent. MIPS also does not
implement forwarding, NAT, multicast routing, TCP urgent data, or next-hop
routing. `LocalAddresses` controls endpoint ownership and source selection.
`Routes` provides destination admission, longest-prefix selection, metrics,
and optional preferred sources, while the lower link remains responsible for
gateways, next hops, and L2 neighbor handling. Applications requiring those
facilities should use a mature general-purpose userspace stack.

TCP Fast Open is also intentionally absent. A complete server implementation
must deliver SYN data before the handshake completes and integrate cookie,
SYN-cookie, retransmission, and accept ownership; merely parsing the option or
delaying the data until `Accept` would not implement RFC 7413. The current
`DialTCP` API has no early-data argument, so a partial client implementation
would not benefit existing consumers.

## License

MIPS is licensed under the Mozilla Public License 2.0. See `LICENSE`.
