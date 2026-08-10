package gvisorinterop_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/waiter"
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
