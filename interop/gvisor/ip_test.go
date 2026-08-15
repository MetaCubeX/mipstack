package gvisorinterop_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

// TestRawIPInterop verifies bidirectional opaque upper-layer payload delivery
// for IPv4 and IPv6.
func TestRawIPInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				testRawIP(t, network, family, mtu)
			})
		}
	}
}

// TestPublicIPPacketCodecInterop sends a public-codec packet through gVisor's
// native raw endpoint and decodes gVisor's native response with the same API.
func TestPublicIPPacketCodecInterop(t *testing.T) {
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
			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := []byte("public-ip-codec-request")
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: int(interopRawIPProtocol), HopLimit: 37, TrafficClass: 0x2e, Payload: request,
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public IP packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public IP packet: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			received, _, err := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
			if err != nil {
				t.Fatalf("read public packet in gVisor: %v", err)
			}
			received, err = stripGVisorRawHeader(family, received)
			if err != nil || !bytes.Equal(received, request) {
				t.Fatalf("gVisor raw payload = %x, %v", received, err)
			}

			response := []byte("gvisor-native-response")
			if written, writeErr := endpoint.Write(bytes.NewReader(response), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(response)) {
				t.Fatalf("write gVisor raw response: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			select {
			case responseWire := <-captured:
				parsed, parseErr := mipstack.ParseIPPacket(responseWire)
				if parseErr != nil {
					t.Fatalf("parse gVisor response: %v", parseErr)
				}
				protocol, payload, upperErr := parsed.UpperLayer()
				if upperErr != nil || protocol != int(interopRawIPProtocol) || parsed.Source != family.gvisorAddress || parsed.Destination != family.mipstackAddress || !bytes.Equal(payload, response) {
					t.Fatalf("parsed gVisor response = protocol %d source %s target %s payload %x, %v", protocol, parsed.Source, parsed.Destination, payload, upperErr)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

// TestPublicIPHeaderOptionsInterop verifies that gVisor accepts IPv4 options
// and an IPv6 extension chain constructed through the semantic API.
func TestPublicIPHeaderOptionsInterop(t *testing.T) {
	const (
		mipstackPort = 44031
		gvisorPort   = 44032
	)
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			peer := newGVisorUDPSocket(
				t, network, family.networkProtocol,
				gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {},
			)
			defer peer.Close()

			payload := []byte("public-ip-options")
			datagram := mipstack.UDPDatagram{
				Source:      netipAddrPort(family.mipstackAddress, mipstackPort),
				Destination: netipAddrPort(family.gvisorAddress, gvisorPort),
				Payload:     payload,
			}
			udpWire, err := datagram.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public UDP datagram: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: mipstack.ProtocolUDP, HopLimit: 37, TrafficClass: 0x2e, Payload: udpWire,
			}
			if family.mipstackAddress.Is4() {
				if err = packet.SetIPv4HeaderOptions([]mipstack.IPv4HeaderOption{
					{Type: mipstack.IPv4HeaderOptionNOP},
					{Type: mipstack.IPv4HeaderOptionRouterAlert, Data: []byte{0, 0}},
				}); err != nil {
					t.Fatalf("construct public IPv4 options: %v", err)
				}
			} else {
				hopByHop := mipstack.IPv6ExtensionHeader{Type: mipstack.IPv6ExtensionHeaderHopByHop}
				if err = hopByHop.SetOptions([]mipstack.IPv6ExtensionOption{
					{Type: mipstack.IPv6ExtensionOptionRouterAlert, Data: []byte{0, 0}},
				}); err != nil {
					t.Fatalf("construct public Hop-by-Hop options: %v", err)
				}
				destination := mipstack.IPv6ExtensionHeader{Type: mipstack.IPv6ExtensionHeaderDestination}
				if err = destination.SetOptions([]mipstack.IPv6ExtensionOption{
					{Type: 0x1e, Data: []byte("opaque")},
				}); err != nil {
					t.Fatalf("construct public Destination options: %v", err)
				}
				if err = packet.SetIPv6ExtensionHeaders(
					[]mipstack.IPv6ExtensionHeader{hopByHop, destination}, mipstack.ProtocolUDP, udpWire,
				); err != nil {
					t.Fatalf("construct public IPv6 extension chain: %v", err)
				}
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public option packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public option packet: %v", err)
			}
			if err = peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			storage := make([]byte, 64)
			read, source, err := peer.ReadFrom(storage)
			if err != nil {
				t.Fatalf("read public option packet in gVisor: %v", err)
			}
			if !bytes.Equal(storage[:read], payload) || source.String() != netipAddrPort(family.mipstackAddress, mipstackPort).String() {
				t.Fatalf("gVisor option payload/source = %q/%v", storage[:read], source)
			}
		})
	}
}

// TestIPv6RawChecksumInterop verifies RFC 3542 IPV6_CHECKSUM insertion and
// receive verification in both directions. Fragmented output is delivered to
// gVisor's UDP transport because the pinned gVisor raw demultiplexer observes
// the outer IPv6 Fragment header but does not revisit raw sockets after
// reassembly.
func TestIPv6RawChecksumInterop(t *testing.T) {
	family := interopFamilies[1]
	for _, mtu := range interopMTUsForFamily(family) {
		mtu := mtu
		t.Run(interopMTUName(mtu), func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, mtu)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			connection, err := (&mipstack.ListenConfig{Options: []mipstack.SocketOption{
				mipstack.SocketOptions.IPv6Checksum(true, 2),
			}}).ListenIP(ctx, network.mipstack, family.rawNetwork, family.mipstackAddress)
			if err != nil {
				t.Fatalf("listen with mipstack IPv6 checksum: %v", err)
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
				t.Fatalf("set mipstack raw checksum deadline: %v", err)
			}

			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor checksummed raw endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.SetSockOptInt(tcpip.IPv6Checksum, 2); tcpipErr != nil {
				t.Fatalf("enable gVisor IPv6 checksum: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor checksummed raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor checksummed raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := patternedPayload(257, 0x61)
			request[2], request[3] = 0, 0
			written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
			if writeErr != nil || written != int64(len(request)) {
				t.Fatalf("write gVisor checksummed payload: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			storage := make([]byte, 65535)
			read, source, readErr := connection.ReadFromIP(storage)
			if readErr != nil {
				t.Fatalf("read gVisor checksummed payload in mipstack: %v", readErr)
			}
			sourceAddress, valid := netip.AddrFromSlice(source.IP)
			if !valid || sourceAddress != family.gvisorAddress || !validIPv6RawChecksum(storage[:read], family.gvisorAddress, family.mipstackAddress, byte(interopRawIPProtocol)) {
				t.Fatalf("mipstack received invalid gVisor checksum: source=%v payload=%x", source, storage[:read])
			}
			storage[2], storage[3] = 0, 0
			if !bytes.Equal(storage[:read], request) {
				t.Fatal("gVisor checksum insertion changed bytes outside its field")
			}

			response := patternedPayload(263, 0x71)
			original := append([]byte(nil), response...)
			writtenInt, writeToErr := connection.WriteToIP(response, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
			if writeToErr != nil || writtenInt != len(response) {
				t.Fatalf("write mipstack checksummed payload: n=%d, error=%v", writtenInt, writeToErr)
			}
			if !bytes.Equal(response, original) {
				t.Fatal("mipstack checksum insertion mutated caller payload")
			}
			packet, remote, endpointErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
			if endpointErr != nil {
				t.Fatalf("read mipstack checksummed payload in gVisor: %v", endpointErr)
			}
			if remote.Addr != gvisorAddress(family.mipstackAddress) || !validIPv6RawChecksum(packet, family.mipstackAddress, family.gvisorAddress, byte(interopRawIPProtocol)) {
				t.Fatalf("gVisor received invalid mipstack checksum: source=%v payload=%x", remote.Addr, packet)
			}
			packet[2], packet[3] = 0, 0
			original[2], original[3] = 0, 0
			if !bytes.Equal(packet, original) {
				t.Fatal("mipstack checksum insertion changed bytes outside its field")
			}

			testIPv6RawChecksumFragmentInterop(t, ctx, network, family, mtu)
		})
	}
}

// testIPv6RawChecksumFragmentInterop sends a raw UDP datagram whose checksum
// is owned by mipstack to gVisor's native UDP endpoint. This exercises the
// configurable offset before IPv6 source fragmentation and gVisor reassembly.
func testIPv6RawChecksumFragmentInterop(t *testing.T, ctx context.Context, network *interopNetwork, family interopFamily, mtu uint32) {
	t.Helper()
	const (
		mipstackPort = 32101
		gvisorPort   = 32102
		udpHeaderLen = 8
	)
	connection, err := (&mipstack.ListenConfig{Options: []mipstack.SocketOption{
		mipstack.SocketOptions.IPv6Checksum(true, 6),
	}}).ListenIP(ctx, network.mipstack, "ip6:udp", family.mipstackAddress)
	if err != nil {
		t.Fatalf("listen with raw UDP checksum: %v", err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set raw UDP checksum deadline: %v", err)
	}
	gvisorConnection := newGVisorUDPSocket(t, network, family.networkProtocol, gvisorFullAddress(family.gvisorAddress, gvisorPort), func(tcpip.Endpoint) {})
	defer gvisorConnection.Close()
	if err = gvisorConnection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set gVisor UDP checksum deadline: %v", err)
	}

	request := patternedPayload(211, 0x81)
	written, writeErr := gvisorConnection.WriteTo(request, net.UDPAddrFromAddrPort(netipAddrPort(family.mipstackAddress, mipstackPort)))
	if writeErr != nil || written != len(request) {
		t.Fatalf("write gVisor UDP checksum request: n=%d, error=%v", written, writeErr)
	}
	storage := make([]byte, 65535)
	read, source, readErr := connection.ReadFromIP(storage)
	if readErr != nil {
		t.Fatalf("read checksummed gVisor UDP payload: %v", readErr)
	}
	if read < udpHeaderLen || binary.BigEndian.Uint16(storage[0:2]) != gvisorPort ||
		binary.BigEndian.Uint16(storage[2:4]) != mipstackPort || int(binary.BigEndian.Uint16(storage[4:6])) != read ||
		!validIPv6RawChecksum(storage[:read], family.gvisorAddress, family.mipstackAddress, byte(udp.ProtocolNumber)) ||
		!bytes.Equal(storage[udpHeaderLen:read], request) {
		t.Fatalf("mipstack received invalid gVisor UDP datagram: source=%v payload=%x", source, storage[:read])
	}

	payload := patternedPayload(fragmentedInteropPayloadSize(mtu, 4096)-udpHeaderLen, 0x91)
	datagram := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(datagram[0:2], mipstackPort)
	binary.BigEndian.PutUint16(datagram[2:4], gvisorPort)
	binary.BigEndian.PutUint16(datagram[4:6], uint16(len(datagram)))
	copy(datagram[udpHeaderLen:], payload)
	original := append([]byte(nil), datagram...)
	written, writeErr = connection.WriteToIP(datagram, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
	if writeErr != nil || written != len(datagram) {
		t.Fatalf("write fragmented raw UDP checksum response: n=%d, error=%v", written, writeErr)
	}
	if !bytes.Equal(datagram, original) {
		t.Fatal("fragmented raw checksum insertion mutated caller payload")
	}
	read, _, readErr = gvisorConnection.ReadFrom(storage)
	if readErr != nil || !bytes.Equal(storage[:read], payload) {
		t.Fatalf("read fragmented raw UDP checksum response in gVisor: n=%d, error=%v", read, readErr)
	}
}

// TestIPDualStackWildcardInterop verifies that one generic mipstack raw socket
// receives and replies to native gVisor IPv4 and IPv6 protocol payloads.
func TestIPDualStackWildcardInterop(t *testing.T) {
	network := newInteropNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := network.mipstack.ListenIP(ctx, "ip:99", netip.Addr{})
	if err != nil {
		t.Fatalf("listen on dual-stack raw IP wildcard: %v", err)
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set dual-stack raw IP deadline: %v", err)
	}
	storage := make([]byte, 65535)

	for index, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := patternedPayload(53+index, byte(31+index))
			written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
			if writeErr != nil || written != int64(len(request)) {
				t.Fatalf("write dual-stack raw IP request: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			read, source, readErr := listener.ReadFromIP(storage)
			if readErr != nil || !bytes.Equal(storage[:read], request) {
				t.Fatalf("read dual-stack raw IP request: n=%d, source=%v, error=%v", read, source, readErr)
			}
			sourceAddress, valid := netip.AddrFromSlice(source.IP)
			if !valid || sourceAddress.Unmap() != family.gvisorAddress {
				t.Fatalf("dual-stack raw IP source = %v, want %v", source, family.gvisorAddress)
			}

			response := patternedPayload(79+index, byte(67+index))
			writtenInt, writeToErr := listener.WriteToIP(response, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
			if writeToErr != nil || writtenInt != len(response) {
				t.Fatalf("write dual-stack raw IP response: n=%d, error=%v", writtenInt, writeToErr)
			}
			packet, remote, endpointErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
			if endpointErr != nil {
				t.Fatalf("read gVisor dual-stack raw IP response: %v", endpointErr)
			}
			payload, stripErr := stripGVisorRawHeader(family, packet)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			if remote.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(payload, response) {
				t.Fatalf("gVisor dual-stack raw IP response: source=%v, bytes=%d", remote.Addr, len(payload))
			}
		})
	}
}

// TestIPControlMessageInterop verifies bidirectional raw-socket ancillary
// metadata and explicit per-packet IP header fields against gVisor.
func TestIPControlMessageInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			outbound := make(chan []byte, 1)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				mipstackToGVisor: func(packet []byte) bool {
					copyPacket := append([]byte(nil), packet...)
					select {
					case outbound <- copyPacket:
					default:
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			connection, err := network.mipstack.ListenIP(ctx, family.rawNetwork, family.mipstackAddress)
			if err != nil {
				t.Fatalf("listen with mipstack raw IP: %v", err)
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
				t.Fatalf("set mipstack raw IP deadline: %v", err)
			}

			var queue waiter.Queue
			endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			options := endpoint.SocketOptions()
			if family.mipstackAddress.Is4() {
				options.SetReceiveTOS(true)
				options.SetReceiveTTL(true)
				options.SetReceivePacketInfo(true)
				if tcpipErr = endpoint.SetSockOptInt(tcpip.IPv4TOSOption, 0x2e); tcpipErr == nil {
					tcpipErr = endpoint.SetSockOptInt(tcpip.IPv4TTLOption, 37)
				}
			} else {
				options.SetReceiveTClass(true)
				options.SetReceiveHopLimit(true)
				options.SetIPv6ReceivePacketInfo(true)
				if tcpipErr = endpoint.SetSockOptInt(tcpip.IPv6TrafficClassOption, 0x2e); tcpipErr == nil {
					tcpipErr = endpoint.SetSockOptInt(tcpip.IPv6HopLimitOption, 37)
				}
			}
			if tcpipErr != nil {
				t.Fatalf("configure gVisor raw IP header options: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
			}
			entry, notifications := registerReadable(&queue)
			defer queue.EventUnregister(&entry)

			request := []byte("raw-control-request")
			written, tcpipErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
			if tcpipErr != nil || written != int64(len(request)) {
				t.Fatalf("write gVisor raw control request: n=%d, error=%s", written, tcpipErrorString(tcpipErr))
			}
			payload := make([]byte, 256)
			control := make([]byte, 256)
			read, controlRead, flags, source, err := connection.ReadMsgIP(payload, control)
			if err != nil || flags != 0 || !bytes.Equal(payload[:read], request) {
				t.Fatalf("read mipstack raw control request: n=%d, oob=%d, flags=%#x, source=%v, error=%v", read, controlRead, flags, source, err)
			}
			sourceAddress, valid := netip.AddrFromSlice(source.IP)
			if !valid || sourceAddress.Unmap() != family.gvisorAddress {
				t.Fatalf("mipstack raw control source = %v, want %v", source, family.gvisorAddress)
			}
			if family.mipstackAddress.Is4() {
				var message mipstack.IPv4ControlMessage
				if err = message.Parse(control[:controlRead]); err != nil {
					t.Fatalf("parse mipstack raw IPv4 control message: %v", err)
				}
				if message.Dst != family.mipstackAddress || message.TTL != 37 || message.TOS != 0x2e {
					t.Fatalf("mipstack raw IPv4 control message = %+v", message)
				}
				control, err = (&mipstack.IPv4ControlMessage{TTL: 41, TOS: 0xb8}).Marshal()
			} else {
				var message mipstack.IPv6ControlMessage
				if err = message.Parse(control[:controlRead]); err != nil {
					t.Fatalf("parse mipstack raw IPv6 control message: %v", err)
				}
				if message.Dst != family.mipstackAddress || message.HopLimit != 37 || message.TrafficClass != 0x2e {
					t.Fatalf("mipstack raw IPv6 control message = %+v", message)
				}
				control, err = (&mipstack.IPv6ControlMessage{HopLimit: 41, TrafficClass: 0xb8, FlowLabel: 0x34567}).Marshal()
			}
			if err != nil {
				t.Fatalf("marshal mipstack raw control message: %v", err)
			}

			response := []byte("raw-control-response")
			writtenInt, controlWritten, err := connection.WriteMsgIP(response, control, source)
			if err != nil || writtenInt != len(response) || controlWritten != len(control) {
				t.Fatalf("write mipstack raw control response: n=%d, oob=%d, error=%v", writtenInt, controlWritten, err)
			}
			select {
			case packet := <-outbound:
				validateControlledIPHeader(t, family, packet, 41)
			case <-ctx.Done():
				t.Fatalf("capture mipstack raw control response: %v", ctx.Err())
			}
			packet, result, readErr := readGVisorEndpointResult(ctx, endpoint, notifications, 65535)
			if readErr != nil {
				t.Fatalf("read gVisor raw control response: %v", readErr)
			}
			received, stripErr := stripGVisorRawHeader(family, packet)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			if result.RemoteAddr.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(received, response) {
				t.Fatalf("gVisor raw control response: source=%v, bytes=%d", result.RemoteAddr, len(received))
			}
			messages := result.ControlMessages
			if family.mipstackAddress.Is4() {
				if !messages.HasTTL || messages.TTL != 41 || !messages.HasTOS || messages.TOS != 0xb8 || !messages.HasIPPacketInfo ||
					messages.PacketInfo.DestinationAddr != gvisorAddress(family.gvisorAddress) {
					t.Fatalf("gVisor raw IPv4 control messages = %+v", messages)
				}
			} else if !messages.HasHopLimit || messages.HopLimit != 41 || !messages.HasTClass || messages.TClass != 0xb8 || !messages.HasIPv6PacketInfo ||
				messages.IPv6PacketInfo.Addr != gvisorAddress(family.gvisorAddress) {
				t.Fatalf("gVisor raw IPv6 control messages = %+v", messages)
			}
		})
	}
}

// TestIPHeaderIncludedInterop verifies complete-packet writes and receives
// through both stacks' native raw-socket APIs. Linux-specific field repair is
// covered in mipstack's root module; gVisor is used here only as a wire peer.
// gVisor performs IPv6 raw fan-out before walking extension headers and does
// not permit a raw endpoint for an extension-header protocol number, so the
// IPv6 interop packet has no extension header. Mipstack's extension-header
// complete-packet behavior is covered by its native tests.
func TestIPHeaderIncludedInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				config := mipstack.ListenConfig{Options: []mipstack.SocketOption{
					mipstack.SocketOptions.IPHeaderIncludedOnWrite(true),
					mipstack.SocketOptions.IPHeaderIncludedOnRead(true),
				}}
				mips, err := config.ListenIP(ctx, network.mipstack, family.rawNetwork, family.mipstackAddress)
				if err != nil {
					t.Fatalf("listen with complete-packet mipstack raw socket: %v", err)
				}
				defer mips.Close()
				if err = mips.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
					t.Fatalf("set mipstack complete-packet deadline: %v", err)
				}

				var queue waiter.Queue
				peer, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create gVisor complete-packet raw endpoint: %s", tcpipErr.String())
				}
				defer peer.Close()
				peer.SocketOptions().SetHeaderIncluded(true)
				if tcpipErr = peer.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
					t.Fatalf("bind gVisor complete-packet raw endpoint: %s", tcpipErr.String())
				}
				if tcpipErr = peer.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
					t.Fatalf("connect gVisor complete-packet raw endpoint: %s", tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				defer queue.EventUnregister(&entry)

				request := buildHeaderIncludedInteropPacket(family, family.mipstackAddress, family.gvisorAddress, patternedPayload(19, 0xa1))
				written, writeErr := mips.WriteToIP(request, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
				if writeErr != nil || written != len(request) {
					t.Fatalf("write mipstack complete packet: n=%d, error=%v", written, writeErr)
				}
				received, remote, readErr := readGVisorEndpoint(ctx, peer, notifications, int(mtu))
				if readErr != nil || remote.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(received, request) {
					t.Fatalf("gVisor complete-packet read: bytes=%d, source=%v, error=%v", len(received), remote, readErr)
				}

				response := buildHeaderIncludedInteropPacket(family, family.gvisorAddress, family.mipstackAddress, patternedPayload(23, 0xb2))
				written64, tcpipErr := peer.Write(bytes.NewReader(response), tcpip.WriteOptions{})
				if tcpipErr != nil || written64 != int64(len(response)) {
					t.Fatalf("write gVisor complete packet: n=%d, error=%s", written64, tcpipErrorString(tcpipErr))
				}
				storage := make([]byte, mtu)
				read, source, readErr := mips.ReadFromIP(storage)
				if readErr != nil || source.String() != family.gvisorAddress.String() || !bytes.Equal(storage[:read], response) {
					t.Fatalf("mipstack complete-packet read: bytes=%d, source=%v, error=%v", read, source, readErr)
				}
			})
		}
	}
}

// TestIPCompletePacketReassemblyInterop verifies that an
// IPHeaderIncludedOnRead raw socket observes one complete reconstructed packet
// after gVisor source fragmentation at every supported link MTU.
func TestIPCompletePacketReassemblyInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				rawNetwork := "ip4:udp"
				if family.mipstackAddress.Is6() {
					rawNetwork = "ip6:udp"
				}
				config := mipstack.ListenConfig{Options: []mipstack.SocketOption{mipstack.SocketOptions.IPHeaderIncludedOnRead(true)}}
				rawConnection, err := config.ListenIP(ctx, network.mipstack, rawNetwork, family.mipstackAddress)
				if err != nil {
					t.Fatalf("listen for complete reassembled packets: %v", err)
				}
				defer rawConnection.Close()
				if err = rawConnection.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
					t.Fatalf("set complete-packet read deadline: %v", err)
				}
				const destinationPort = 45117
				udpListener, err := network.mipstack.ListenUDP(ctx, family.udpNetwork, netipAddrPort(family.mipstackAddress, destinationPort))
				if err != nil {
					t.Fatalf("listen for fragmented UDP interop: %v", err)
				}
				defer udpListener.Close()

				var queue waiter.Queue
				peer, tcpipErr := network.gvisor.NewEndpoint(udp.ProtocolNumber, family.networkProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create gVisor UDP fragment source: %s", tcpipErr.String())
				}
				defer peer.Close()
				if tcpipErr = peer.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
					t.Fatalf("bind gVisor UDP fragment source: %s", tcpipErr.String())
				}
				if tcpipErr = peer.Connect(gvisorFullAddress(family.mipstackAddress, destinationPort)); tcpipErr != nil {
					t.Fatalf("connect gVisor UDP fragment source: %s", tcpipErr.String())
				}
				localAddress, tcpipErr := peer.GetLocalAddress()
				if tcpipErr != nil {
					t.Fatalf("get gVisor UDP fragment source: %s", tcpipErr.String())
				}
				payload := patternedPayload(fragmentedInteropPayloadSize(mtu, 4096), 0xc3)
				written, tcpipErr := peer.Write(bytes.NewReader(payload), tcpip.WriteOptions{})
				if tcpipErr != nil || written != int64(len(payload)) {
					t.Fatalf("write fragmented gVisor UDP datagram: n=%d, error=%s", written, tcpipErrorString(tcpipErr))
				}
				packet := make([]byte, 65535)
				read, source, readErr := rawConnection.ReadFromIP(packet)
				if readErr != nil || source.String() != family.gvisorAddress.String() {
					t.Fatalf("read complete reassembled packet: bytes=%d, source=%v, error=%v", read, source, readErr)
				}
				if err = validateCompleteUDPInteropPacket(family, packet[:read], localAddress.Port, destinationPort, payload); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// buildHeaderIncludedInteropPacket constructs a valid complete packet. IPv4
// options exercise its variable header length; see TestIPHeaderIncludedInterop
// for why the IPv6 interop packet intentionally has no extension header.
func buildHeaderIncludedInteropPacket(family interopFamily, source, target netip.Addr, payload []byte) []byte {
	if source.Is4() {
		packet := make([]byte, header.IPv4MinimumSize+4+len(payload))
		packet[0], packet[1], packet[8], packet[9] = 0x46, 0x2e, 37, byte(interopRawIPProtocol)
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:6], 0x4321)
		copy(packet[12:16], source.AsSlice())
		copy(packet[16:20], target.AsSlice())
		copy(packet[20:24], []byte{1, 1, 0, 0})
		copy(packet[24:], payload)
		binary.BigEndian.PutUint16(packet[10:12], ^checksum.Checksum(packet[:24], 0))
		return packet
	}
	packet := make([]byte, header.IPv6MinimumSize+len(payload))
	packet[0], packet[1], packet[2], packet[3] = 0x6a, 0x55, 0x43, 0x21
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6], packet[7] = byte(interopRawIPProtocol), 37
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], target.AsSlice())
	copy(packet[40:], payload)
	return packet
}

// validateCompleteUDPInteropPacket checks the reconstructed IP and UDP
// envelopes plus the application payload without accepting fragment headers.
func validateCompleteUDPInteropPacket(family interopFamily, packet []byte, sourcePort, targetPort uint16, payload []byte) error {
	offset := 0
	if family.mipstackAddress.Is4() {
		if len(packet) < header.IPv4MinimumSize || packet[0]>>4 != 4 {
			return errors.New("reassembled IPv4 packet has no valid base header")
		}
		offset = int(packet[0]&0x0f) * 4
		if offset < header.IPv4MinimumSize || offset > len(packet) || packet[9] != byte(udp.ProtocolNumber) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return errors.New("reassembled IPv4 packet retained invalid fragmentation state")
		}
	} else {
		if len(packet) < header.IPv6MinimumSize || packet[0]>>4 != 6 || packet[6] != byte(udp.ProtocolNumber) {
			return errors.New("reassembled IPv6 packet retained an extension or fragment header")
		}
		offset = header.IPv6MinimumSize
	}
	if len(packet)-offset != header.UDPMinimumSize+len(payload) {
		return errors.New("reassembled UDP packet has an unexpected length")
	}
	udpHeader := header.UDP(packet[offset : offset+header.UDPMinimumSize])
	if udpHeader.SourcePort() != sourcePort || udpHeader.DestinationPort() != targetPort || !bytes.Equal(packet[offset+header.UDPMinimumSize:], payload) {
		return errors.New("reassembled UDP packet tuple or payload mismatch")
	}
	return nil
}

// testRawIP connects mipstack's IPConn to a native gVisor raw endpoint and
// validates multiple datagrams in both directions.
func testRawIP(t *testing.T, network *interopNetwork, family interopFamily, mtu uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mipstackConnection, err := network.mipstack.ListenIP(ctx, family.rawNetwork, family.mipstackAddress)
	if err != nil {
		t.Fatalf("listen with mipstack IP socket: %v", err)
	}
	defer mipstackConnection.Close()
	if err = mipstackConnection.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set mipstack IP deadline: %v", err)
	}

	var queue waiter.Queue
	gvisorEndpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor raw IP endpoint: %s", tcpipErr.String())
	}
	defer gvisorEndpoint.Close()
	if tcpipErr = gvisorEndpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
		t.Fatalf("bind gVisor raw IP endpoint: %s", tcpipErr.String())
	}
	if tcpipErr = gvisorEndpoint.Connect(gvisorFullAddress(family.mipstackAddress, 0)); tcpipErr != nil {
		t.Fatalf("connect gVisor raw IP endpoint: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	defer queue.EventUnregister(&entry)

	storage := make([]byte, 65535)
	maximumPayload := rawInteropPayloadCapacity(family, mtu)
	cases := []struct {
		requestSize  int
		responseSize int
	}{
		{requestSize: 17, responseSize: 23},
		{requestSize: maximumPayload - 7, responseSize: maximumPayload},
	}
	for index, testCase := range cases {
		request := patternedPayload(testCase.requestSize, byte(113+index))
		written, writeErr := gvisorEndpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
		if writeErr != nil || written != int64(len(request)) {
			t.Fatalf("write gVisor raw IP payload: n=%d, error=%s", written, tcpipErrorString(writeErr))
		}
		read, source, readErr := mipstackConnection.ReadFromIP(storage)
		if readErr != nil {
			t.Fatalf("read mipstack raw IP payload: %v", readErr)
		}
		sourceAddress, validSource := netip.AddrFromSlice(source.IP)
		if !validSource || sourceAddress.Unmap() != family.gvisorAddress || !bytes.Equal(storage[:read], request) {
			t.Fatalf("mipstack raw IP request mismatch: source=%v, bytes=%d", source, read)
		}

		response := patternedPayload(testCase.responseSize, byte(149+index))
		writtenInt, writeToErr := mipstackConnection.WriteToIP(response, &net.IPAddr{IP: net.IP(family.gvisorAddress.AsSlice())})
		if writeToErr != nil || writtenInt != len(response) {
			t.Fatalf("write mipstack raw IP payload: n=%d, error=%v", writtenInt, writeToErr)
		}
		packet, remote, endpointErr := readGVisorEndpoint(ctx, gvisorEndpoint, notifications, 65535)
		if endpointErr != nil {
			stats := network.gvisor.Stats().IP
			t.Fatalf("read gVisor raw IP payload: %v (received=%d valid=%d delivered=%d malformed=%d malformed-fragments=%d)", endpointErr,
				stats.PacketsReceived.Value(), stats.ValidPacketsReceived.Value(), stats.PacketsDelivered.Value(),
				stats.MalformedPacketsReceived.Value(), stats.MalformedFragmentsReceived.Value())
		}
		payload, stripErr := stripGVisorRawHeader(family, packet)
		if stripErr != nil {
			t.Fatal(stripErr)
		}
		if remote.Addr != gvisorAddress(family.mipstackAddress) || !bytes.Equal(payload, response) {
			prefix := len(payload)
			if prefix > 16 {
				prefix = 16
			}
			wantPrefix := len(response)
			if wantPrefix > 16 {
				wantPrefix = 16
			}
			t.Fatalf("gVisor raw IP response mismatch: source=%v, bytes=%d, prefix=%x, want=%x", remote.Addr, len(payload), payload[:prefix], response[:wantPrefix])
		}
	}
}

// stripGVisorRawHeader normalizes Linux-compatible gVisor raw reads: IPv4
// includes its IP header while IPv6 exposes only the upper-layer payload.
func stripGVisorRawHeader(family interopFamily, packet []byte) ([]byte, error) {
	if family.networkProtocol == header.IPv6ProtocolNumber {
		return packet, nil
	}
	if len(packet) < header.IPv4MinimumSize || packet[0]>>4 != 4 {
		return nil, errors.New("gVisor raw IPv4 socket returned an invalid IPv4 header")
	}
	headerSize := int(packet[0]&0x0f) * 4
	if headerSize < header.IPv4MinimumSize || headerSize > len(packet) {
		return nil, errors.New("gVisor raw IPv4 socket returned an invalid header length")
	}
	return packet[headerSize:], nil
}

// validIPv6RawChecksum verifies one upper-layer payload against its IPv6
// pseudo-header using gVisor's native checksum primitives.
func validIPv6RawChecksum(payload []byte, source, target netip.Addr, protocol byte) bool {
	if len(payload) > 65535 {
		return false
	}
	sum := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(protocol), gvisorAddress(source), gvisorAddress(target), uint16(len(payload)))
	return checksum.Checksum(payload, sum) == 0xffff
}
