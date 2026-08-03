package mipstack

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// TestPacketDeviceIO verifies the tun-compatible data plane and stack-local
// source selection with multiple addresses in one family.
func TestPacketDeviceIO(t *testing.T) {
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.1/8"),
			netip.MustParsePrefix("192.168.1.2/24"),
		},
		MTU: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	destination := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.168.1.99:53"))
	connection, err := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(destination.AddrPort().Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.WriteTo([]byte("query"), destination); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1508)
	sizes := []int{0}
	if count, readErr := stack.Read([][]byte{buffer}, sizes, 8); readErr != nil || count != 1 {
		t.Fatalf("Read = %d, %v", count, readErr)
	}
	packet, ok := parseIPPacket(buffer[8 : 8+sizes[0]])
	if !ok || packet.source != netip.MustParseAddr("192.168.1.2") || packet.target != destination.AddrPort().Addr() {
		t.Fatalf("unexpected outbound packet: source=%s target=%s", packet.source, packet.target)
	}

	icmp := make([]byte, 12)
	icmp[0] = 8
	copy(icmp[8:], []byte("ping"))
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	request := buildIPPacket(netip.MustParseAddr("192.168.1.99"), netip.MustParseAddr("192.168.1.2"), protocolICMPv4, icmp, 1, true)
	padded := append(make([]byte, 4), request...)
	if count, writeErr := stack.Write([][]byte{padded}, 4); writeErr != nil || count != 1 {
		t.Fatalf("Write = %d, %v", count, writeErr)
	}
	if count, readErr := stack.Read([][]byte{buffer}, sizes, 0); readErr != nil || count != 1 {
		t.Fatalf("Read echo = %d, %v", count, readErr)
	}
	reply, ok := parseIPPacket(buffer[:sizes[0]])
	if !ok || reply.payload[0] != 0 || reply.source != netip.MustParseAddr("192.168.1.2") {
		t.Fatalf("unexpected echo reply: %x", buffer[:sizes[0]])
	}
}

// TestPacketDeviceReadUnblocksOnClose verifies that a packet pump can always
// stop when its stack generation is retired.
func TestPacketDeviceReadUnblocksOnClose(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, listenErr := stack.ListenUDP(context.Background(), `udp`, wildcardUDP(netip.MustParseAddr("192.0.2.2"))); !errors.Is(listenErr, ErrNotStarted) {
		t.Fatalf("ListenUDP before Start = %v", listenErr)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatalf("repeated Start = %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, readErr := stack.Read([][]byte{make([]byte, 65535)}, []int{0}, 0)
		done <- readErr
	}()
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Start after Close = %v", err)
	}
	select {
	case err = <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Read after Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after Close")
	}
}

func TestDeviceMetadata(t *testing.T) {
	first4 := netip.MustParseAddr("192.0.2.13")
	first6 := netip.MustParseAddr("2001:db8::13")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{
			netip.PrefixFrom(first4, 32),
			netip.PrefixFrom(first6, 128),
		},
		MTU: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mtu, mtuErr := stack.MTU(); mtuErr != nil || mtu != 1400 {
		t.Fatalf("MTU = %d, %v", mtu, mtuErr)
	}
	if name, nameErr := stack.Name(); nameErr != nil || name != "mihomo IP stack" {
		t.Fatalf("Name = %q, %v", name, nameErr)
	}
	if stack.BatchSize() != 1 {
		t.Fatalf("BatchSize = %d, want 1", stack.BatchSize())
	}
	addresses := stack.LocalAddresses()
	if len(addresses) != 2 || addresses[0] != first4 || addresses[1] != first6 {
		t.Fatalf("local addresses = %v", addresses)
	}
	addresses[0] = netip.Addr{}
	if current := stack.LocalAddresses(); current[0] != first4 {
		t.Fatalf("caller mutated local-address snapshot: %v", current)
	}
	second6 := netip.MustParseAddr("2001:db8::14")
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(second6, 128)},
		MTU:            1300,
	}); err != nil {
		t.Fatal(err)
	}
	if addresses = stack.LocalAddresses(); len(addresses) != 1 || addresses[0] != second6 {
		t.Fatalf("updated local addresses = %v", addresses)
	}
	if mtu, _ := stack.MTU(); mtu != 1300 {
		t.Fatalf("updated MTU = %d, want 1300", mtu)
	}
}
