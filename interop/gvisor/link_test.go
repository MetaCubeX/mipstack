// Package gvisorinterop_test validates wire-level interoperability between the
// current mipstack checkout and the pinned metacubex gVisor fork.
package gvisorinterop_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

const (
	// interopNIC is the sole gVisor L3 link used by the packet bridge.
	interopNIC tcpip.NICID = 1
	// interopDefaultMTU is the IPv6 minimum MTU used by tests that require the
	// complete dual-stack topology but do not exercise an MTU matrix.
	interopDefaultMTU uint32 = 1280

	// interopRawIPProtocol is IANA protocol 99, whose payload is opaque to both
	// stacks and is not interpreted as an IPv6 extension header by gVisor.
	interopRawIPProtocol tcpip.TransportProtocolNumber = 99
)

// interopFamilies supplies equivalent IPv4 and IPv6 test configurations.
var interopFamilies = []interopFamily{
	{
		name:            "ipv4",
		tcpNetwork:      "tcp4",
		udpNetwork:      "udp4",
		icmpNetwork:     "ip4:icmp",
		rawNetwork:      "ip4:99",
		mipstackAddress: netip.MustParseAddr("192.0.2.1"),
		gvisorAddress:   netip.MustParseAddr("192.0.2.2"),
		forwardAddress:  netip.MustParseAddr("198.51.100.1"),
		prefixBits:      24,
		networkProtocol: ipv4.ProtocolNumber,
		icmpProtocol:    icmp.ProtocolNumber4,
	},
	{
		name:            "ipv6",
		tcpNetwork:      "tcp6",
		udpNetwork:      "udp6",
		icmpNetwork:     "ip6:ipv6-icmp",
		rawNetwork:      "ip6:99",
		mipstackAddress: netip.MustParseAddr("2001:db8::1"),
		gvisorAddress:   netip.MustParseAddr("2001:db8::2"),
		forwardAddress:  netip.MustParseAddr("2001:db8:1::1"),
		prefixBits:      64,
		networkProtocol: ipv6.ProtocolNumber,
		icmpProtocol:    icmp.ProtocolNumber6,
	},
}

// interopFamily describes one address family as understood by both public
// socket APIs.
type interopFamily struct {
	// name labels the family in subtest output.
	name string
	// tcpNetwork and udpNetwork are mipstack's standard-library network names.
	tcpNetwork string
	udpNetwork string
	// icmpNetwork and rawNetwork are mipstack's protocol socket names.
	icmpNetwork string
	rawNetwork  string
	// mipstackAddress and gvisorAddress are the two ends of the L3 link.
	mipstackAddress netip.Addr
	gvisorAddress   netip.Addr
	// forwardAddress is outside mipstack's owned prefix and exercises
	// promiscuous Forwarder admission and transparent-source replies.
	forwardAddress netip.Addr
	// prefixBits configures the shared on-link test subnet.
	prefixBits int
	// networkProtocol and icmpProtocol select the corresponding gVisor stacks.
	networkProtocol tcpip.NetworkProtocolNumber
	icmpProtocol    tcpip.TransportProtocolNumber
}

// mipstackPrefix returns the local prefix installed in mipstack.
func (f interopFamily) mipstackPrefix() netip.Prefix {
	return netip.PrefixFrom(f.mipstackAddress, f.prefixBits)
}

// gvisorProtocolAddress returns the equivalent address configuration for
// gVisor's NIC API.
func (f interopFamily) gvisorProtocolAddress() tcpip.ProtocolAddress {
	return tcpip.ProtocolAddress{
		Protocol: f.networkProtocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   gvisorAddress(f.gvisorAddress),
			PrefixLen: f.prefixBits,
		},
	}
}

// interopNetwork owns two stacks, their cancellable packet bridge, and all
// bridge goroutines created for one subtest.
type interopNetwork struct {
	// t receives bridge errors during cleanup while the test is still active.
	t *testing.T
	// mipstack and gvisor are the endpoint stacks under test.
	mipstack *mipstack.Stack
	gvisor   *stack.Stack
	// mtu is the common L3 MTU configured on both endpoints.
	mtu uint32
	// gvisorEndpoint is the raw L3 channel endpoint attached to gvisor.
	gvisorEndpoint *channel.Endpoint
	// mipstackToGVisor and gvisorToMipstack observe and optionally drop bridge
	// packets synchronously in their respective copy goroutines.
	mipstackToGVisor interopPacketHook
	gvisorToMipstack interopPacketHook
	// ctx and cancel stop the gVisor-to-mipstack bridge receive operation.
	ctx    context.Context
	cancel context.CancelFunc
	// waitGroup waits for both bridge directions during cleanup.
	waitGroup sync.WaitGroup
	// closeOnce makes cleanup safe when a test also closes explicitly.
	closeOnce sync.Once
	// bridgeError retains the first asynchronous bridge failure.
	bridgeError chan error
}

// interopPacketHook observes one borrowed complete IP packet and reports
// whether the bridge should deliver it. The packet is invalid after return.
type interopPacketHook func(packet []byte) bool

// interopNetworkOptions selects the address families, common link MTU, and
// mipstack destination-admission policy for one isolated topology.
type interopNetworkOptions struct {
	// families contains the address families installed on both endpoints. Nil
	// selects the complete dual-stack test configuration.
	families []interopFamily
	// mtu is the common L3 link MTU. Zero selects interopDefaultMTU.
	mtu uint32
	// gvisorMTU overrides only the gVisor NIC MTU. Zero uses mtu. A lower value
	// lets forwarding tests exercise router-generated PMTU errors.
	gvisorMTU uint32
	// promiscuous admits nonlocal destinations to mipstack Forwarders.
	promiscuous bool
	// tcp supplies mipstack defaults for tests that exercise a particular TCP
	// transport policy. Its zero value retains the package defaults.
	tcp mipstack.TCPSocketDefaults
	// forwarding enables gVisor unicast forwarding for every selected family.
	forwarding bool
	// mipstackToGVisor and gvisorToMipstack optionally observe or drop packets
	// in one bridge direction. Nil delivers every packet.
	mipstackToGVisor interopPacketHook
	gvisorToMipstack interopPacketHook
}

// newInteropNetwork creates, starts, and connects fresh dual-stack endpoints.
func newInteropNetwork(t *testing.T) *interopNetwork {
	t.Helper()
	return newInteropNetworkWithOptions(t, interopNetworkOptions{})
}

// newFamilyInteropNetwork creates a single-family topology at one explicit
// MTU for ordinary socket interoperability tests.
func newFamilyInteropNetwork(t *testing.T, family interopFamily, mtu uint32) *interopNetwork {
	t.Helper()
	return newInteropNetworkWithOptions(t, interopNetworkOptions{families: []interopFamily{family}, mtu: mtu})
}

// newForwarderInteropNetwork creates a single-family topology that admits
// nonlocal packet destinations at one explicit MTU.
func newForwarderInteropNetwork(t *testing.T, family interopFamily, mtu uint32) *interopNetwork {
	t.Helper()
	return newInteropNetworkWithOptions(t, interopNetworkOptions{
		families: []interopFamily{family}, mtu: mtu, promiscuous: true,
	})
}

// newInteropNetworkWithOptions constructs the common two-stack topology.
func newInteropNetworkWithOptions(t *testing.T, options interopNetworkOptions) *interopNetwork {
	t.Helper()
	families := options.families
	if len(families) == 0 {
		families = interopFamilies
	}
	mtu := options.mtu
	if mtu == 0 {
		mtu = interopDefaultMTU
	}
	gvisorMTU := options.gvisorMTU
	if gvisorMTU == 0 {
		gvisorMTU = mtu
	}
	localAddresses := make([]netip.Prefix, 0, len(families))
	for _, family := range families {
		localAddresses = append(localAddresses, family.mipstackPrefix())
	}

	mips, err := mipstack.New(mipstack.Config{
		LocalAddresses: localAddresses,
		MTU:            mtu,
		Promiscuous:    options.promiscuous,
		TCP:            options.tcp,
	})
	if err != nil {
		t.Fatalf("create mipstack: %v", err)
	}
	if err = mips.Start(); err != nil {
		_ = mips.Close()
		t.Fatalf("start mipstack: %v", err)
	}

	gvisorStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6, newRawTestProtocol},
		HandleLocal:        true,
	})
	endpoint := channel.New(1024, gvisorMTU, "")
	if tcpipErr := gvisorStack.CreateNIC(interopNIC, endpoint); tcpipErr != nil {
		_ = mips.Close()
		gvisorStack.Destroy()
		t.Fatalf("create gVisor NIC: %s", tcpipErr.String())
	}
	for _, family := range families {
		if tcpipErr := gvisorStack.AddProtocolAddress(interopNIC, family.gvisorProtocolAddress(), stack.AddressProperties{}); tcpipErr != nil {
			_ = mips.Close()
			gvisorStack.Destroy()
			t.Fatalf("add gVisor %s address: %s", family.name, tcpipErr.String())
		}
		if options.forwarding {
			if tcpipErr := gvisorStack.SetForwardingDefaultAndAllNICs(family.networkProtocol, true); tcpipErr != nil {
				_ = mips.Close()
				gvisorStack.Destroy()
				t.Fatalf("enable gVisor %s forwarding: %s", family.name, tcpipErr.String())
			}
		}
	}
	routes := make([]tcpip.Route, 0, len(families))
	for _, family := range families {
		destination := header.IPv6EmptySubnet
		if family.mipstackAddress.Is4() {
			destination = header.IPv4EmptySubnet
		}
		routes = append(routes, tcpip.Route{Destination: destination, NIC: interopNIC})
	}
	gvisorStack.SetRouteTable(routes)

	ctx, cancel := context.WithCancel(context.Background())
	network := &interopNetwork{
		t: t, mipstack: mips, gvisor: gvisorStack, mtu: mtu, gvisorEndpoint: endpoint,
		ctx: ctx, cancel: cancel, bridgeError: make(chan error, 1),
		mipstackToGVisor: options.mipstackToGVisor, gvisorToMipstack: options.gvisorToMipstack,
	}
	network.waitGroup.Add(2)
	go network.copyMipstackToGVisor()
	go network.copyGVisorToMipstack()
	t.Cleanup(network.close)
	return network
}

// close terminates packet I/O, destroys both stacks, and reports deferred
// bridge failures before test cleanup returns.
func (n *interopNetwork) close() {
	n.closeOnce.Do(func() {
		n.cancel()
		n.gvisorEndpoint.Close()
		_ = n.mipstack.Close()
		n.gvisor.Destroy()
		n.waitGroup.Wait()
		select {
		case err := <-n.bridgeError:
			n.t.Errorf("L3 bridge: %v", err)
		default:
		}
	})
}

// copyMipstackToGVisor drains mipstack's batched device output and injects each
// complete IP packet into gVisor.
func (n *interopNetwork) copyMipstackToGVisor() {
	defer n.waitGroup.Done()
	buffers := make([][]byte, n.mipstack.BatchSize())
	sizes := make([]int, len(buffers))
	for index := range buffers {
		buffers[index] = make([]byte, n.mtu)
	}
	for {
		count, err := n.mipstack.Read(buffers, sizes, 0)
		for index := 0; index < count; index++ {
			packetBytes := buffers[index][:sizes[index]]
			if n.mipstackToGVisor != nil && !n.mipstackToGVisor(packetBytes) {
				continue
			}
			if err := n.deliverToGVisor(packetBytes); err != nil {
				n.reportBridgeError(err)
				return
			}
		}
		if err != nil {
			if n.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				n.reportBridgeError(fmt.Errorf("read mipstack packets: %w", err))
			}
			return
		}
	}
}

// interopMTUsForFamily returns the standards boundary and common deployment
// MTUs applicable to one address family. IPv6 excludes values below 1280.
func interopMTUsForFamily(family interopFamily) []uint32 {
	if family.mipstackAddress.Is4() {
		return []uint32{68, 576, 1280, 1420, 1500, 9000}
	}
	return []uint32{1280, 1420, 1500, 9000}
}

// interopMTUName returns the stable subtest label for one common link MTU.
func interopMTUName(mtu uint32) string {
	return fmt.Sprintf("mtu-%d", mtu)
}

// fragmentedInteropPayloadSize returns a payload that crosses at least two
// MTU boundaries. Low IPv4 MTUs avoid an unrelated hundreds-of-fragments
// stress case; ordinary and jumbo MTUs retain the requested pressure floor.
func fragmentedInteropPayloadSize(mtu uint32, pressureFloor int) int {
	size := int(mtu)*2 + 137
	if mtu >= 1280 && size < pressureFloor {
		return pressureFloor
	}
	return size
}

// rawInteropPayloadCapacity returns the largest unfragmented upper-layer raw
// payload for the family's fixed IP header at one link MTU.
func rawInteropPayloadCapacity(family interopFamily, mtu uint32) int {
	headerSize := header.IPv6MinimumSize
	if family.mipstackAddress.Is4() {
		headerSize = header.IPv4MinimumSize
	}
	return int(mtu) - headerSize
}

// tcpInteropStreamSize keeps sustained 512 KiB streams on deployment MTUs
// while bounding packet count at IPv4's unusually small legacy MTUs.
func tcpInteropStreamSize(mtu uint32) int {
	if mtu <= 68 {
		return 32 * 1024
	}
	if mtu < 1280 {
		return 128 * 1024
	}
	return 512 * 1024
}

// copyGVisorToMipstack transfers caller-owned copies of gVisor channel packets
// into mipstack's device input.
func (n *interopNetwork) copyGVisorToMipstack() {
	defer n.waitGroup.Done()
	for {
		packet := n.gvisorEndpoint.ReadContext(n.ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		packet.DecRef()
		packetBytes := view.AsSlice()
		if n.gvisorToMipstack != nil && !n.gvisorToMipstack(packetBytes) {
			view.Release()
			continue
		}
		err := n.deliverToMipstack(packetBytes)
		view.Release()
		if err != nil {
			if n.ctx.Err() == nil {
				n.reportBridgeError(err)
			}
			return
		}
	}
}

// deliverToGVisor injects one complete borrowed IP packet into the gVisor NIC.
// Injection is synchronous, so the caller may reuse packet after return.
func (n *interopNetwork) deliverToGVisor(packetBytes []byte) error {
	protocol, ok := packetNetworkProtocol(packetBytes)
	if !ok {
		return errors.New("mipstack emitted a packet without a valid IP version")
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packetBytes)})
	n.gvisorEndpoint.InjectInbound(protocol, packet)
	packet.DecRef()
	return nil
}

// deliverToMipstack writes one complete borrowed IP packet into mipstack and
// requires the single-packet Device contract to consume it.
func (n *interopNetwork) deliverToMipstack(packetBytes []byte) error {
	count, err := n.mipstack.Write([][]byte{packetBytes}, 0)
	if count != 1 || err != nil {
		return fmt.Errorf("write gVisor packet to mipstack: count=%d, error=%v", count, err)
	}
	return nil
}

// reportBridgeError records the first asynchronous bridge failure without
// blocking a packet-copy goroutine.
func (n *interopNetwork) reportBridgeError(err error) {
	select {
	case n.bridgeError <- err:
	default:
	}
}

// packetNetworkProtocol maps an IP version nibble to gVisor's L3 protocol.
func packetNetworkProtocol(packet []byte) (tcpip.NetworkProtocolNumber, bool) {
	if len(packet) == 0 {
		return 0, false
	}
	switch packet[0] >> 4 {
	case 4:
		return header.IPv4ProtocolNumber, true
	case 6:
		return header.IPv6ProtocolNumber, true
	default:
		return 0, false
	}
}

// gvisorAddress converts a valid unzoned netip address to gVisor's value type.
func gvisorAddress(address netip.Addr) tcpip.Address {
	address = address.Unmap()
	if address.Is4() {
		return tcpip.AddrFrom4(address.As4())
	}
	return tcpip.AddrFrom16(address.As16())
}

// gvisorFullAddress constructs a gVisor endpoint address on the test NIC.
func gvisorFullAddress(address netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: interopNIC, Addr: gvisorAddress(address), Port: port}
}

// netipAddrPort constructs the corresponding standard-library endpoint value.
func netipAddrPort(address netip.Addr, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(address, port)
}

// patternedPayload creates deterministic nonzero data with no short repeating
// byte run, making truncation and offset errors visible.
func patternedPayload(size int, seed byte) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = byte((index*131+int(seed))%251 + 1)
	}
	return payload
}

// readGVisorEndpoint waits through ErrWouldBlock and returns one complete
// datagram from a native gVisor endpoint.
func readGVisorEndpoint(ctx context.Context, endpoint tcpip.Endpoint, notifications <-chan struct{}, capacity int) ([]byte, tcpip.FullAddress, error) {
	payload, result, err := readGVisorEndpointResult(ctx, endpoint, notifications, capacity)
	return payload, result.RemoteAddr, err
}

// readGVisorEndpointResult waits through ErrWouldBlock and preserves native
// gVisor control messages together with one complete datagram.
func readGVisorEndpointResult(ctx context.Context, endpoint tcpip.Endpoint, notifications <-chan struct{}, capacity int) ([]byte, tcpip.ReadResult, error) {
	for {
		storage := make([]byte, capacity)
		writer := tcpip.SliceWriter(storage)
		result, tcpipErr := endpoint.Read(&writer, tcpip.ReadOptions{NeedRemoteAddr: true})
		if tcpipErr == nil {
			return storage[:result.Count], result, nil
		}
		if _, wouldBlock := tcpipErr.(*tcpip.ErrWouldBlock); !wouldBlock {
			return nil, tcpip.ReadResult{}, errors.New(tcpipErr.String())
		}
		select {
		case <-ctx.Done():
			return nil, tcpip.ReadResult{}, ctx.Err()
		case <-notifications:
		}
	}
}

// registerReadable registers one channel-backed readable waiter.
func registerReadable(queue *waiter.Queue) (waiter.Entry, <-chan struct{}) {
	entry, notifications := waiter.NewChannelEntry(waiter.ReadableEvents)
	queue.EventRegister(&entry)
	return entry, notifications
}

// rawTestProtocol only gives gVisor's raw socket demultiplexer a registered
// opaque upper-layer protocol. It does not implement a transport endpoint or
// interpret the payload under test.
type rawTestProtocol struct {
	// stack owns the raw endpoint registry used by NewRawEndpoint.
	stack *stack.Stack
}

// newRawTestProtocol registers the opaque protocol with gVisor's dispatcher.
func newRawTestProtocol(protocolStack *stack.Stack) stack.TransportProtocol {
	return &rawTestProtocol{stack: protocolStack}
}

// Number implements stack.TransportProtocol.
func (*rawTestProtocol) Number() tcpip.TransportProtocolNumber {
	return interopRawIPProtocol
}

// NewEndpoint rejects ordinary transport sockets because the test protocol is
// intentionally raw-only.
func (*rawTestProtocol) NewEndpoint(tcpip.NetworkProtocolNumber, *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return nil, &tcpip.ErrNotSupported{}
}

// NewRawEndpoint implements stack.TransportProtocol with gVisor's native raw
// payload endpoint.
func (p *rawTestProtocol) NewRawEndpoint(networkProtocol tcpip.NetworkProtocolNumber, queue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return raw.NewEndpoint(p.stack, networkProtocol, interopRawIPProtocol, queue)
}

// MinimumPacketSize requires the one opaque byte needed for raw demultiplexing.
func (*rawTestProtocol) MinimumPacketSize() int { return 1 }

// ParsePorts reports no ports because raw payloads have no transport tuple.
func (*rawTestProtocol) ParsePorts([]byte) (uint16, uint16, tcpip.Error) {
	return 0, 0, nil
}

// HandleUnknownDestinationPacket suppresses an irrelevant unreachable after
// raw endpoints have observed the payload.
func (*rawTestProtocol) HandleUnknownDestinationPacket(stack.TransportEndpointID, *stack.PacketBuffer) stack.UnknownDestinationPacketDisposition {
	return stack.UnknownDestinationPacketHandled
}

// SetOption reports that the descriptor has no protocol-wide options.
func (*rawTestProtocol) SetOption(tcpip.SettableTransportProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

// Option reports that the descriptor has no protocol-wide options.
func (*rawTestProtocol) Option(tcpip.GettableTransportProtocolOption) tcpip.Error {
	return &tcpip.ErrUnknownProtocolOption{}
}

// Close implements the worker-free protocol lifecycle.
func (*rawTestProtocol) Close() {}

// Wait implements the worker-free protocol lifecycle.
func (*rawTestProtocol) Wait() {}

// Pause implements the worker-free protocol lifecycle.
func (*rawTestProtocol) Pause() {}

// Resume implements the worker-free protocol lifecycle.
func (*rawTestProtocol) Resume() {}

// Restore implements the worker-free protocol lifecycle.
func (*rawTestProtocol) Restore() {}

// Parse marks one byte as an opaque transport header so gVisor can run raw
// endpoint demultiplexing without interpreting application data.
func (*rawTestProtocol) Parse(packet *stack.PacketBuffer) bool {
	// gVisor requires a non-empty transport header before raw demultiplexing.
	// One opaque byte is sufficient; the raw endpoint rejoins it with the
	// remaining payload before exposing the message to the test.
	_, ok := packet.TransportHeader().Consume(1)
	return ok
}
