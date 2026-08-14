package gvisorinterop_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

// TestICMPEchoInterop verifies each stack's echo requester against the other
// stack's automatic responder for IPv4 and IPv6.
func TestICMPEchoInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu)+"/mipstack-sends", func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				testMipstackICMPEcho(t, network, family, mtu)
			})
			t.Run(family.name+"/"+interopMTUName(mtu)+"/gvisor-sends", func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				testGVisorICMPEcho(t, network, family, mtu)
			})
		}
	}
}

// TestPublicICMPMessageCodecInterop verifies that gVisor accepts an echo
// request constructed by the public codec and that its native reply is decoded
// by the same semantic API.
func TestPublicICMPMessageCodecInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			captured := make(chan []byte, 4)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					select {
					case captured <- append([]byte(nil), packet...):
					default:
					}
					return false
				},
			})
			messageType, protocol := uint8(8), mipstack.ProtocolICMPv4
			if family.mipstackAddress.Is6() {
				messageType, protocol = 128, mipstack.ProtocolICMPv6
			}
			body := append([]byte{0x12, 0x34, 0, 7}, []byte("public-icmp-codec")...)
			message := mipstack.ICMPMessage{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Type: messageType, Body: body,
			}
			icmpWire, err := message.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public ICMP message: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: protocol, HopLimit: 64, Payload: icmpWire,
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public ICMP packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public ICMP packet: %v", err)
			}
			select {
			case responseWire := <-captured:
				parsedPacket, parseErr := mipstack.ParseIPPacket(responseWire)
				if parseErr != nil {
					t.Fatalf("parse gVisor ICMP packet: %v", parseErr)
				}
				parsed, parseErr := parsedPacket.ICMPMessage()
				wantType := uint8(0)
				if family.mipstackAddress.Is6() {
					wantType = 129
				}
				if parseErr != nil || parsed.Source != family.gvisorAddress || parsed.Destination != family.mipstackAddress || parsed.Type != wantType || parsed.Code != 0 || !bytes.Equal(parsed.Body, body) {
					t.Fatalf("parsed gVisor ICMP = %+v, %v", parsed, parseErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for gVisor ICMP reply")
			}
		})
	}
}

// TestMipstackICMPFilterInterop verifies that native gVisor raw ICMP traffic
// observes mipstack's Linux-compatible IPv4 and RFC 3542 IPv6 type filters.
func TestMipstackICMPFilterInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, interopDefaultMTU)
			var option mipstack.SocketOption
			if family.mipstackAddress.Is4() {
				var filter mipstack.ICMPv4Filter
				filter.Block(uint8(header.ICMPv4EchoReply))
				option = mipstack.SocketOptions.ICMPv4Filter(filter)
			} else {
				var filter mipstack.ICMPv6Filter
				filter.Block(uint8(header.ICMPv6EchoReply))
				option = mipstack.SocketOptions.ICMPv6Filter(filter)
			}
			connection, err := (&mipstack.ListenConfig{Options: []mipstack.SocketOption{option}}).ListenIP(
				context.Background(), network.mipstack, family.icmpNetwork, family.mipstackAddress,
			)
			if err != nil {
				t.Fatalf("listen with mipstack ICMP filter: %v", err)
			}
			defer connection.Close()

			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw ICMP endpoint: %s", tcpipErr.String())
			}

			message := makeICMPEcho(family, true, 0x5310, 1, []byte("filtered"), family.gvisorAddress, family.mipstackAddress)
			if written, writeErr := endpoint.Write(bytes.NewReader(message), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(message)) {
				t.Fatalf("write filtered gVisor ICMP: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			if err = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if _, readErr := connection.Read(make([]byte, 64)); !errors.Is(readErr, os.ErrDeadlineExceeded) {
				t.Fatalf("blocked ICMP read = %v, want deadline", readErr)
			}
			if err = connection.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			if family.mipstackAddress.Is4() {
				err = connection.SetICMPv4Filter(mipstack.ICMPv4Filter{})
			} else {
				err = connection.SetICMPv6Filter(mipstack.ICMPv6Filter{})
			}
			if err != nil {
				t.Fatal(err)
			}
			message = makeICMPEcho(family, true, 0x5310, 2, []byte("accepted"), family.gvisorAddress, family.mipstackAddress)
			if written, writeErr := endpoint.Write(bytes.NewReader(message), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(message)) {
				t.Fatalf("write accepted gVisor ICMP: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			storage := make([]byte, 64)
			read, readErr := connection.Read(storage)
			if readErr != nil || !bytes.Equal(storage[:read], message) {
				t.Fatalf("accepted gVisor ICMP = %x, %v", storage[:read], readErr)
			}
		})
	}
}

// TestGVisorICMPv6FilterInterop verifies mipstack-generated ICMPv6 against
// gVisor's native ICMP6_FILTER implementation.
func TestGVisorICMPv6FilterInterop(t *testing.T) {
	family := interopFamilies[1]
	network := newFamilyInteropNetwork(t, family, interopDefaultMTU)
	connection, err := network.mipstack.ListenIP(context.Background(), family.icmpNetwork, family.mipstackAddress)
	if err != nil {
		t.Fatalf("listen with mipstack ICMPv6 socket: %v", err)
	}
	defer connection.Close()

	var queue waiter.Queue
	endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor raw ICMPv6 endpoint: %s", tcpipErr.String())
	}
	defer endpoint.Close()
	if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
		t.Fatalf("bind gVisor raw ICMPv6 endpoint: %s", tcpipErr.String())
	}
	if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
		t.Fatalf("connect gVisor raw ICMPv6 endpoint: %s", tcpipErr.String())
	}
	var filter tcpip.ICMPv6Filter
	filter.DenyType[uint8(header.ICMPv6EchoReply)>>5] |= uint32(1) << (uint8(header.ICMPv6EchoReply) & 31)
	if tcpipErr = endpoint.SetSockOpt(&filter); tcpipErr != nil {
		t.Fatalf("set gVisor ICMPv6 filter: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	defer queue.EventUnregister(&entry)

	message := makeICMPEcho(family, true, 0x5320, 1, []byte("filtered"), family.mipstackAddress, family.gvisorAddress)
	if written, writeErr := connection.WriteToIP(message, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())}); writeErr != nil || written != len(message) {
		t.Fatalf("write filtered mipstack ICMPv6: n=%d, error=%v", written, writeErr)
	}
	blockedContext, cancelBlocked := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if _, _, readErr := readGVisorEndpoint(blockedContext, endpoint, notifications, 64); !errors.Is(readErr, context.DeadlineExceeded) {
		cancelBlocked()
		t.Fatalf("gVisor blocked ICMPv6 read = %v, want deadline", readErr)
	}
	cancelBlocked()
	if tcpipErr = endpoint.SetSockOpt(&tcpip.ICMPv6Filter{}); tcpipErr != nil {
		t.Fatalf("clear gVisor ICMPv6 filter: %s", tcpipErr.String())
	}
	message = makeICMPEcho(family, true, 0x5320, 2, []byte("accepted"), family.mipstackAddress, family.gvisorAddress)
	if written, writeErr := connection.WriteToIP(message, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())}); writeErr != nil || written != len(message) {
		t.Fatalf("write accepted mipstack ICMPv6: n=%d, error=%v", written, writeErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	packet, _, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 64)
	if readErr != nil || !bytes.Equal(packet, message) {
		t.Fatalf("accepted mipstack ICMPv6 = %x, %v", packet, readErr)
	}
}

// testMipstackICMPEcho sends fitting and fragmented echo requests through a
// mipstack IPConn and validates gVisor's replies.
func testMipstackICMPEcho(t *testing.T, network *interopNetwork, family interopFamily, mtu uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connection, err := network.mipstack.DialIP(ctx, family.icmpNetwork, family.mipstackAddress, family.gvisorAddress)
	if err != nil {
		t.Fatalf("dial mipstack ICMP: %v", err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set mipstack ICMP deadline: %v", err)
	}

	storage := make([]byte, 65535)
	const identifier = 0x5101
	for index, size := range []int{29, fragmentedInteropPayloadSize(mtu, 4096)} {
		payload := patternedPayload(size, byte(43+index))
		request := makeICMPEcho(family, false, identifier, uint16(index+1), payload, family.mipstackAddress, family.gvisorAddress)
		written, writeErr := connection.Write(request)
		if writeErr != nil || written != len(request) {
			t.Fatalf("write mipstack ICMP echo: n=%d, error=%v", written, writeErr)
		}
		read, readErr := connection.Read(storage)
		if readErr != nil {
			t.Fatalf("read mipstack ICMP echo reply: %v", readErr)
		}
		if err = validateICMPEcho(family, storage[:read], true, identifier, uint16(index+1), payload, family.gvisorAddress, family.mipstackAddress); err != nil {
			t.Fatal(err)
		}
	}
}

// testGVisorICMPEcho sends fitting and fragmented echo requests through a
// native gVisor ping endpoint and validates mipstack's replies.
func testGVisorICMPEcho(t *testing.T, network *interopNetwork, family interopFamily, mtu uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var queue waiter.Queue
	endpoint, tcpipErr := network.gvisor.NewEndpoint(family.icmpProtocol, family.networkProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor ICMP endpoint: %s", tcpipErr.String())
	}
	defer endpoint.Close()
	const identifier = 0x5201
	if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, identifier)); tcpipErr != nil {
		t.Fatalf("bind gVisor ICMP endpoint: %s", tcpipErr.String())
	}
	if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
		t.Fatalf("connect gVisor ICMP endpoint: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	defer queue.EventUnregister(&entry)

	for index, size := range []int{31, fragmentedInteropPayloadSize(mtu, 4096)} {
		payload := patternedPayload(size, byte(71+index))
		request := makeICMPEcho(family, false, identifier, uint16(index+1), payload, family.gvisorAddress, family.mipstackAddress)
		written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
		if writeErr != nil || written != int64(len(request)) {
			t.Fatalf("write gVisor ICMP echo: n=%d, error=%v", written, tcpipErrorString(writeErr))
		}
		reply, _, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
		if readErr != nil {
			t.Fatalf("read gVisor ICMP echo reply: %v", readErr)
		}
		if err := validateICMPEcho(family, reply, true, identifier, uint16(index+1), payload, family.mipstackAddress, family.gvisorAddress); err != nil {
			t.Fatal(err)
		}
	}
}

// makeICMPEcho builds a checksum-valid echo request or reply for one family.
func makeICMPEcho(family interopFamily, reply bool, identifier, sequence uint16, payload []byte, source, target netip.Addr) []byte {
	message := make([]byte, 8+len(payload))
	copy(message[8:], payload)
	if family.networkProtocol == header.IPv4ProtocolNumber {
		icmpHeader := header.ICMPv4(message[:8])
		messageType := header.ICMPv4Echo
		if reply {
			messageType = header.ICMPv4EchoReply
		}
		icmpHeader.SetType(messageType)
		icmpHeader.SetCode(0)
		icmpHeader.SetIdent(identifier)
		icmpHeader.SetSequence(sequence)
		icmpHeader.SetChecksum(^checksum.Checksum(message, 0))
		return message
	}

	icmpHeader := header.ICMPv6(message[:8])
	messageType := header.ICMPv6EchoRequest
	if reply {
		messageType = header.ICMPv6EchoReply
	}
	icmpHeader.SetType(messageType)
	icmpHeader.SetCode(0)
	icmpHeader.SetIdent(identifier)
	icmpHeader.SetSequence(sequence)
	icmpHeader.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHeader,
		Src:         gvisorAddress(source),
		Dst:         gvisorAddress(target),
		PayloadCsum: checksum.Checksum(message[8:], 0),
		PayloadLen:  len(message) - 8,
	}))
	return message
}

// validateICMPEcho checks framing, type, checksum, identity, sequence, and
// payload without retaining the message.
func validateICMPEcho(family interopFamily, message []byte, reply bool, identifier, sequence uint16, payload []byte, source, target netip.Addr) error {
	if len(message) != 8+len(payload) {
		return fmt.Errorf("ICMP echo length: got %d, want %d", len(message), 8+len(payload))
	}
	if family.networkProtocol == header.IPv4ProtocolNumber {
		icmpHeader := header.ICMPv4(message[:8])
		expectedType := header.ICMPv4Echo
		if reply {
			expectedType = header.ICMPv4EchoReply
		}
		if icmpHeader.Type() != expectedType || icmpHeader.Code() != 0 {
			return fmt.Errorf("ICMPv4 echo type/code: got %d/%d, want %d/0", icmpHeader.Type(), icmpHeader.Code(), expectedType)
		}
		if checksum.Checksum(message, 0) != 0xffff {
			return errors.New("ICMPv4 echo checksum is invalid")
		}
	} else {
		icmpHeader := header.ICMPv6(message[:8])
		expectedType := header.ICMPv6EchoRequest
		if reply {
			expectedType = header.ICMPv6EchoReply
		}
		if icmpHeader.Type() != expectedType || icmpHeader.Code() != 0 {
			return fmt.Errorf("ICMPv6 echo type/code: got %d/%d, want %d/0", icmpHeader.Type(), icmpHeader.Code(), expectedType)
		}
		actualChecksum := icmpHeader.Checksum()
		icmpHeader.SetChecksum(0)
		expectedChecksum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHeader,
			Src:         gvisorAddress(source),
			Dst:         gvisorAddress(target),
			PayloadCsum: checksum.Checksum(message[8:], 0),
			PayloadLen:  len(message) - 8,
		})
		icmpHeader.SetChecksum(actualChecksum)
		if actualChecksum != expectedChecksum {
			return fmt.Errorf("ICMPv6 echo checksum: got %#04x, want %#04x", actualChecksum, expectedChecksum)
		}
	}
	var actualIdentifier, actualSequence uint16
	if family.networkProtocol == header.IPv4ProtocolNumber {
		actualIdentifier = header.ICMPv4(message[:8]).Ident()
		actualSequence = header.ICMPv4(message[:8]).Sequence()
	} else {
		actualIdentifier = header.ICMPv6(message[:8]).Ident()
		actualSequence = header.ICMPv6(message[:8]).Sequence()
	}
	if actualIdentifier != identifier || actualSequence != sequence {
		return fmt.Errorf("ICMP echo identifier/sequence: got %#x/%d, want %#x/%d", actualIdentifier, actualSequence, identifier, sequence)
	}
	if !bytes.Equal(message[8:], payload) {
		return errors.New("ICMP echo payload mismatch")
	}
	return nil
}

// tcpipErrorString formats gVisor's non-standard error interface safely.
func tcpipErrorString(err tcpip.Error) string {
	if err == nil {
		return "<nil>"
	}
	return err.String()
}
