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
        LocalAddresses:    []netip.Prefix{local},
        MTU:               1500,
        CongestionControl: mipstack.CongestionControlCUBIC,
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

The packet methods intentionally match the common batched userspace-TUN shape
and currently process a batch size of one. `Start` is idempotent, while `Close`
is terminal and unblocks pending packet and socket operations.

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

Active sockets allocate from the IANA dynamic range (`49152..65535`) first.
Only when that range is unavailable for the requested binding or TCP tuple do
they fall back to non-privileged ports `1024..49151`. Ports below 1024 are
never selected automatically but remain available for explicit bindings.
`Config.MaxTCPConnections` may impose an application-selected resource bound;
its zero value does not impose an artificial connection limit. Listener count
is controlled only by available memory and explicit application creation.

`Config.Routes == nil` installs one default route for each configured address
family. A non-nil empty route slice deliberately admits only destinations that
are themselves local. IPv4-only stacks accept MTUs down to 68; configurations
containing IPv6 require the IPv6 minimum MTU of 1280.
`Config.CongestionControl` selects `CongestionControlCUBIC`,
`CongestionControlReno`, or `CongestionControlBBR`; its zero value selects
CUBIC. `UpdateConfig` applies a changed selection to established connections
without closing them.

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

UDP message methods use the Linux 64-bit little-endian control-message layout
on every host. `ReadMsgUDP` emits `IP_PKTINFO` or `IPV6_PKTINFO` for the local
destination plus TTL/Hop Limit and TOS/Traffic Class, with Linux
`MSG_TRUNC`/`MSG_CTRUNC` flags. Passing that data to `WriteMsgUDP` selects the
corresponding managed source and output header fields. `IPConn` uses the same
ancillary representation.

`IPv4ControlMessage` and `IPv6ControlMessage` make that ancillary data
structured rather than opaque. Their `Parse` methods decode OOB returned by a
message read; their `Marshal` methods encode `Src`, TTL/Hop Limit, and
TOS/Traffic Class for a message write. `Dst` is populated while parsing.
`IfIndex` is always zero because MIPS has one embedding link.

## Protocol behavior

TCP implements active and passive open, bounded accept and SYN queues,
concurrent four-tuple demultiplexing, safe local-port reuse for distinct remote
tuples, and bounded active and TIME_WAIT state. Its data path includes bounded
send and receive buffers, adaptive RTO with exponential backoff, selectable
CUBIC, Reno, and paced model-based BBR congestion control, window scaling,
delayed ACKs, SACK multi-hole recovery, RACK time-based loss detection,
tail-loss probes, timestamp negotiation with PAWS, and classic ECN feedback.
It also handles overlap-aware receive reassembly, data-bearing zero-window
probes, reset validation, deadlines, half-close, FIN states, and TIME_WAIT.

When the SYN backlog or configured connection capacity is exhausted, passive
open uses stateless SYN cookies instead of retaining another half-open
connection. A per-stack random key authenticates the complete tuple, client
sequence, recent time period, and negotiated options. A valid final ACK
reconstructs conservative MSS, window scaling, SACK, timestamp, and ECN state;
forged or expired cookies do not allocate a connection.

Validated ICMP Packet Too Big errors maintain a bounded, expiring destination
PMTU cache. Error type/code combinations and quoted TCP sequence spans are
checked before they can affect transport state. TCP immediately resegments
outstanding data, raises the MSS of established connections when a cached
reduction expires, and uses later data as an upward path probe. A failed probe
is reduced again by validated ICMP or by IPv4 and IPv6 PMTU black-hole
inference after repeated RTOs. UDP uses the learned MTU for later datagrams.
Connected UDP sockets select a stable local address and filter inbound remote
tuples; unconnected sockets can use arbitrary destinations in one IP family.
Both correlate asynchronous ICMP errors with recently used remote endpoints.

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

`Stack.Stats` returns a lock-free snapshot of active socket counts, packet
drops, retransmission modes, PMTU changes, fragment cleanup, and rate limiting.

Optional surfaces are arranged for ordinary Go linker reachability rather than
build tags. A consumer that only dials TCP and listens for UDP does not retain
TCP listener/SYN-cookie code, `ReusePort` registries, raw `IPConn` support,
message-control helpers, or other unreferenced public methods. No package-level
registration table or reflection root keeps these APIs alive.

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
