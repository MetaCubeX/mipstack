# gVisor interoperability tests

This directory is a separate Go module for wire-level interoperability tests
between mipstack and the metacubex gVisor fork. The module boundary keeps
gVisor and its transitive dependencies out of mipstack's dependency-free root
module.

The tests connect the two stacks with gVisor's native channel link endpoint.
The bridge transfers complete IPv4 and IPv6 packets and does not translate
socket operations, transport state, checksums, fragmentation, or errors.

The suite covers:

- IPv4 MTUs 68, 576, 1,280, 1,420, 1,500, and 9,000, plus IPv6 MTUs 1,280,
  1,420, 1,500, and 9,000;
- IPv4 and IPv6 TCP with either stack listening, simultaneous streams,
  half-close processing, wildcard dual-stack listeners, closed-port and
  established-connection resets, keepalive probes, receive-window closure and
  reopening, and SYN, SYN-ACK, final-ACK, FIN, and data retransmission after
  deterministic loss or reordering;
- Reno, CUBIC, BBR, and BBRv3 mipstack senders recovering from loss against
  both active and passive gVisor connections;
- connected and unconnected UDP in both arrangements, connected-peer
  filtering, zero-length and maximum-size datagrams, wildcard dual-stack
  sockets, IPv4 zero-checksum acceptance, mandatory IPv6 checksums, invalid
  checksum rejection, and bidirectional ICMP Port Unreachable delivery;
- UDP fragmentation and reassembly in both directions, including reordered
  and duplicate IPv4 and IPv6 fragments;
- bidirectional UDP and raw-IP ancillary data for destination address, TTL or
  Hop Limit, TOS or Traffic Class, and emitted IPv6 Flow Label;
- ICMPv4 and ICMPv6 echo initiated by either stack, including messages that
  require source fragmentation and receive-side reassembly;
- IPv4 and IPv6 TCP, UDP, ICMP, and arbitrary-protocol Forwarders for nonlocal
  destinations, including connected, unconnected, stateless, and detached
  reply paths, plus TCP, UDP, ICMP, and arbitrary-protocol rejection observed
  by native gVisor sockets;
- IPv4 limited and directed broadcast, bidirectional IPv4/IPv6 ASM multicast,
  and mipstack SSM INCLUDE filtering plus atomic source-set replacement using
  two gVisor source addresses;
- bidirectional raw IP payload sockets using IANA protocol 99;
- IPv4 router-generated PMTU discovery at next-hop MTUs 68, 576, 1,280, and
  1,420, subsequent local EMSGSIZE behavior, and invalid IPv6 Packet Too Big
  rejection at 1,280 and 1,420;

Payload sizes are selected relative to each subtest's MTU. TCP retains 512 KiB
streams at ordinary and jumbo MTUs while bounding packet count at legacy IPv4
minimums. UDP, ICMP, Forwarder, broadcast, and multicast tests cross MTU
boundaries at every size where fragmentation is possible. Raw IP tests use the
exact largest unfragmented payload for each family and MTU.

Raw IP payloads intentionally fit within the link MTU. gVisor raw sockets
reject oversized writes instead of source-fragmenting them, and the pinned fork
does not deliver a reassembled arbitrary-protocol IPv6 payload to its raw
endpoint. UDP and ICMP exercise IPv4 and IPv6 fragmentation in both directions
without relying on that raw-socket limitation.

The pinned gVisor forwarder currently serializes zero in the MTU field of an
ICMPv6 Packet Too Big message because its internal error reason does not carry
the outgoing link MTU. This violates RFC 4443 section 3.2. The IPv6 PMTU
subtest verifies that mipstack parses but does not accept that invalid update,
then skips the valid-update assertions instead of treating zero as compatible.
The IPv4 PMTU path is tested completely. TCP ECN is not an interoperability
case because the pinned gVisor TCP implementation explicitly does not support
ECN negotiation; mipstack's own ECN tests remain in the root module.

Run the module independently from this directory:

```sh
go test ./...
go test -race ./...
```

The `go` directive remains at 1.20. `go.mod` directly requires only the local
mipstack checkout and `github.com/metacubex/gvisor`; the other listed modules
are gVisor's own transitive requirements.
