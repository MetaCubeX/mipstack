package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestIPv6AtomicFragmentReservedBits verifies that reserved fragment-header
// bits are rejected even when the offset and more-fragments bit are zero.
func TestIPv6AtomicFragmentReservedBits(t *testing.T) {
	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2001:db8::1")
	fragment := make([]byte, 8+udpHeaderSize)
	fragment[0] = protocolUDP
	binary.BigEndian.PutUint16(fragment[2:4], 0x0002)
	binary.BigEndian.PutUint32(fragment[4:8], 1)
	packet := buildIPPacket(source, target, 44, fragment, 0, false)
	if _, ok := parseIPPacket(packet); ok {
		t.Fatal("IPv6 atomic fragment with reserved bits was accepted")
	}
}

// TestUDPFragmentationAndReassembly exchanges an oversized datagram between
// two stacks.
func TestUDPFragmentationAndReassembly(t *testing.T) {
	for _, test := range []struct {
		name         string
		client, peer netip.Addr
	}{
		{name: "IPv4", client: netip.MustParseAddr("192.0.2.1"), peer: netip.MustParseAddr("192.0.2.2")},
		{name: "IPv6", client: netip.MustParseAddr("2001:db8::1"), peer: netip.MustParseAddr("2001:db8::2")},
	} {
		t.Run(test.name, func(t *testing.T) {
			bits := 128
			if test.client.Is4() {
				bits = 32
			}
			client, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.client, bits)}, MTU: 1280})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err = client.Start(); err != nil {
				t.Fatal(err)
			}
			peer, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(test.peer, bits)}, MTU: 1280})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err = peer.Start(); err != nil {
				t.Fatal(err)
			}
			bridge := newStackBridge(t, client, peer)
			sender, err := client.ListenUDP(context.Background(), `udp`, wildcardUDP(test.peer))
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			receiver, err := peer.ListenUDP(context.Background(), `udp`, wildcardUDP(test.client))
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			payload := bytes.Repeat([]byte{0x5a}, 3000)
			receiverPort := receiver.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			destination := net.UDPAddrFromAddrPort(netip.AddrPortFrom(test.peer, receiverPort))
			if _, err = sender.WriteTo(payload, destination); err != nil {
				t.Fatal(err)
			}
			if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, len(payload))
			n, _, err := receiver.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buffer[:n], payload) {
				t.Fatalf("reassembled UDP payload size = %d", n)
			}
			bridge.mu.Lock()
			fragments := bridge.clientWrites
			bridge.mu.Unlock()
			if fragments < 3 {
				t.Fatalf("fragment writes = %d, want at least 3", fragments)
			}
		})
	}
}

// TestFragmentOverlapDropsDatagram verifies the RFC 5722 overlap policy.
func TestFragmentOverlapDropsDatagram(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	payload := bytes.Repeat([]byte{0x44}, 3000)
	fragments := buildIPv4Fragments(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), protocolUDP, payload, 1280, 7)
	if len(fragments) < 2 {
		t.Fatal("test datagram was not fragmented")
	}
	if err := writeTestPacket(stack, fragments[0]); err != nil {
		t.Fatal(err)
	}
	overlap := append([]byte(nil), fragments[1]...)
	binary.BigEndian.PutUint16(overlap[6:8], 1|0x2000)
	overlap[10], overlap[11] = 0, 0
	binary.BigEndian.PutUint16(overlap[10:12], checksum(overlap[:20]))
	if err := writeTestPacket(stack, overlap); err != nil {
		t.Fatal(err)
	}
	stack.fragmentMu.Lock()
	sets, retained := len(stack.fragments), stack.fragmentBytes
	stack.fragmentMu.Unlock()
	if sets != 0 || retained != 0 {
		t.Fatalf("overlapping fragments retained: sets=%d bytes=%d", sets, retained)
	}
}

// TestFragmentSetCapacityEvictsOldest verifies that incomplete traffic stays
// within its global set bound without preventing newer reassembly attempts.
func TestFragmentSetCapacityEvictsOldest(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.31")
	remote := netip.MustParseAddr("198.51.100.31")
	_, stack := newTestStack(t, local, remote)
	now := time.Now()
	for identifier := 1; identifier <= fragmentMaximumSets+1; identifier++ {
		fragments := buildIPv4Fragments(remote, local, protocolUDP, make([]byte, 2000), 1280, uint16(identifier))
		if len(fragments) < 2 {
			t.Fatal("test payload was not fragmented")
		}
		if packet := stack.reassemblePacket(fragments[0], now.Add(time.Duration(identifier)*time.Millisecond)); packet != nil {
			t.Fatal("incomplete fragment produced a packet")
		}
	}
	stack.fragmentMu.Lock()
	sets := len(stack.fragments)
	_, oldestPresent := stack.fragments[fragmentKey{source: remote, target: local, identification: 1, protocol: protocolUDP}]
	stack.fragmentMu.Unlock()
	if sets != fragmentMaximumSets || oldestPresent {
		t.Fatalf("fragment sets = %d, oldest present = %v", sets, oldestPresent)
	}
	if evictions := stack.Stats().FragmentEvictions; evictions != 1 {
		t.Fatalf("fragment evictions = %d, want 1", evictions)
	}
}

// FuzzFragmentParsing verifies that the direction-independent fragment parser
// rejects arbitrary envelopes without panicking.
func FuzzFragmentParsing(f *testing.F) {
	local := netip.MustParseAddr("192.0.2.32")
	remote := netip.MustParseAddr("198.51.100.32")
	fragments := buildIPv4Fragments(remote, local, protocolUDP, make([]byte, 2000), 1280, 1)
	f.Add([]byte(nil))
	f.Add(fragments[0])
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = parseFragment(packet)
	})
}

// TestFragmentECNReassembly verifies CE preservation and rejection of invalid
// Not-ECT/ECT combinations across an IPv4 fragment set.
func TestFragmentECNReassembly(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	fragments := buildIPv4Fragments(link.remote, link.local, protocolUDP, make([]byte, 2000), 1280, 91)
	if len(fragments) != 2 {
		t.Fatalf("fragment count = %d, want 2", len(fragments))
	}
	setPacketECN(fragments[0], 2)
	setPacketECN(fragments[1], 3)
	if packet := stack.reassemblePacket(fragments[0], time.Now()); packet != nil {
		t.Fatal("first fragment completed a datagram")
	}
	packet := stack.reassemblePacket(fragments[1], time.Now())
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.ecn != 3 {
		t.Fatalf("reassembled ECN = %d, valid = %v, want CE", parsed.ecn, ok)
	}

	fragments = buildIPv4Fragments(link.remote, link.local, protocolUDP, make([]byte, 2000), 1280, 92)
	setPacketECN(fragments[0], 0)
	setPacketECN(fragments[1], 2)
	_ = stack.reassemblePacket(fragments[0], time.Now())
	if packet = stack.reassemblePacket(fragments[1], time.Now()); packet != nil {
		t.Fatal("mixed Not-ECT/ECT fragment set was accepted")
	}
}

func TestIncompleteFragmentIsNotCountedAsDropped(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.90")
	remote := netip.MustParseAddr("198.51.100.90")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	udp := make([]byte, udpHeaderSize+16)
	binary.BigEndian.PutUint16(udp[0:2], 50000)
	binary.BigEndian.PutUint16(udp[2:4], 50001)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:8], transportChecksum(remote, local, protocolUDP, udp))
	fragments := buildIPv4Fragments(remote, local, protocolUDP, udp, 28, 1)
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	if err = writeTestPacket(stack, fragments[0]); err != nil {
		t.Fatal(err)
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 0 {
		t.Fatalf("incomplete valid fragment counted as dropped: %d", dropped)
	}
}

func TestIPv4FragmentWithDontFragmentIsRejected(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.94")
	target := netip.MustParseAddr("192.0.2.94")
	fragments := buildIPv4Fragments(source, target, protocolUDP, make([]byte, 24), 28, 1)
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d", len(fragments))
	}
	field := binary.BigEndian.Uint16(fragments[0][6:8]) | 0x4000
	binary.BigEndian.PutUint16(fragments[0][6:8], field)
	fragments[0][10], fragments[0][11] = 0, 0
	binary.BigEndian.PutUint16(fragments[0][10:12], checksum(fragments[0][:20]))
	if _, ok := parseFragment(fragments[0]); ok {
		t.Fatal("fragment with DF set was accepted")
	}
}

// TestIPv4FragmentWithReservedFlagIsRejected verifies that the reserved flag
// cannot create reassembly state.
func TestIPv4FragmentWithReservedFlagIsRejected(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.95")
	target := netip.MustParseAddr("192.0.2.95")
	fragments := buildIPv4Fragments(source, target, protocolUDP, make([]byte, 24), 28, 2)
	field := binary.BigEndian.Uint16(fragments[0][6:8]) | 0x8000
	binary.BigEndian.PutUint16(fragments[0][6:8], field)
	fragments[0][10], fragments[0][11] = 0, 0
	binary.BigEndian.PutUint16(fragments[0][10:12], checksum(fragments[0][:20]))
	if _, ok := parseFragment(fragments[0]); ok {
		t.Fatal("fragment with reserved flag was accepted")
	}
}

// TestIPv4FragmentOptionsLimit verifies that reassembly never constructs an
// original datagram larger than the 16-bit IPv4 total length. The last
// fragment is tested both before and after the option-bearing first fragment.
func TestIPv4FragmentOptionsLimit(t *testing.T) {
	source := netip.MustParseAddr("198.51.100.96")
	target := netip.MustParseAddr("192.0.2.96")
	first := buildTestIPv4Options(source, target, []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(first[4:6], 3)
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], checksum(first[:24]))
	last := buildIPPacket(source, target, protocolUDP, make([]byte, 8), 3, false)
	binary.BigEndian.PutUint16(last[6:8], 8188)
	last[10], last[11] = 0, 0
	binary.BigEndian.PutUint16(last[10:12], checksum(last[:20]))

	for _, order := range []struct {
		name    string
		packets [][]byte
	}{
		{name: "first fragment first", packets: [][]byte{first, last}},
		{name: "last fragment first", packets: [][]byte{last, first}},
	} {
		t.Run(order.name, func(t *testing.T) {
			_, stack := newTestStack(t, target, source)
			defer stack.Close()
			for _, packet := range order.packets {
				if reassembled := stack.reassemblePacket(packet, time.Now()); reassembled != nil {
					t.Fatal("oversized option-bearing datagram was reassembled")
				}
			}
			stack.fragmentMu.Lock()
			sets, retained := len(stack.fragments), stack.fragmentBytes
			stack.fragmentMu.Unlock()
			if sets != 0 || retained != 0 {
				t.Fatalf("oversized fragment set retained: sets=%d bytes=%d", sets, retained)
			}
		})
	}
}
