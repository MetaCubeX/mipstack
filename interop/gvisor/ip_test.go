package gvisorinterop_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
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
				validateControlledIPHeader(t, family, packet)
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
