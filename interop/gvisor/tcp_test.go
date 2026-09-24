package gvisorinterop_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

// interopCongestionController leaves TCP's transport-owned initial state
// unchanged while exercising the public custom-controller event path.
type interopCongestionController struct{}

func (*interopCongestionController) HandleCongestionEvent(*mipstack.CongestionEvent) {}

// TestTCPInterop verifies active and passive opens in both directions for each
// address family.
func TestTCPInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, mipstackListens := range []bool{true, false} {
				mipstackListens := mipstackListens
				direction := "gvisor-listens"
				if mipstackListens {
					direction = "mipstack-listens"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+direction, func(t *testing.T) {
					network := newFamilyInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
					defer listener.Close()
					defer client.Close()
					defer server.Close()
					exerciseFullDuplexTCP(t, client, server, tcpInteropStreamSize(mtu))
					var mipstackConnection *mipstack.TCPConn
					if mipstackListens {
						mipstackConnection = server.(*mipstack.TCPConn)
					} else {
						mipstackConnection = client.(*mipstack.TCPConn)
					}
					validateTCPMTUInfo(t, mipstackConnection.Info(), family, mtu)
				})
			}
		}
	}
}

// TestTCPPeerMSSWithTimestampInterop configures a native gVisor TCP socket
// with TCP_MAXSEG, then verifies that mipstack uses the peer's advertised MSS
// after charging the negotiated timestamp option on the wire.
func TestTCPPeerMSSWithTimestampInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var maximumPayload atomic.Int32
			var timestampedPayloads atomic.Int32
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family},
				mtu:      1500,
				mipstackToGVisor: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if !ok || payloadLength == 0 {
						return true
					}
					for {
						current := maximumPayload.Load()
						if payloadLength <= int(current) || maximumPayload.CompareAndSwap(current, int32(payloadLength)) {
							break
						}
					}
					if tcpHeader.ParsedOptions().TS {
						timestampedPayloads.Add(1)
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			const (
				port        = 41003
				peerMSS     = 1200
				wantSendMSS = peerMSS - 12
			)
			var queue waiter.Queue
			endpoint, tcpipErr := network.gvisor.NewEndpoint(tcp.ProtocolNumber, family.networkProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create native gVisor TCP listener: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.SetSockOptInt(tcpip.MaxSegOption, peerMSS); tcpipErr != nil {
				t.Fatalf("set gVisor TCP_MAXSEG: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, port)); tcpipErr != nil {
				t.Fatalf("bind native gVisor TCP listener: %s", tcpipErr.String())
			}
			if tcpipErr = endpoint.Listen(1); tcpipErr != nil {
				t.Fatalf("listen with native gVisor TCP endpoint: %s", tcpipErr.String())
			}
			listener := gonet.NewTCPListener(network.gvisor, &queue, endpoint)
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- connection
			}()

			client, err := network.mipstack.DialTCP(ctx, family.tcpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, port))
			if err != nil {
				t.Fatalf("mipstack dial with gVisor TCP_MAXSEG peer: %v", err)
			}
			defer client.Close()
			var server net.Conn
			select {
			case server = <-accepted:
			case err = <-acceptErr:
				t.Fatalf("accept native gVisor TCP connection: %v", err)
			case <-ctx.Done():
				t.Fatalf("accept native gVisor TCP connection: %v", ctx.Err())
			}
			defer server.Close()

			info := client.(*mipstack.TCPConn).Info()
			if info.MaximumSegmentSize != wantSendMSS || !info.Timestamps {
				t.Fatalf("mipstack TCP info = MSS:%d timestamps:%v, want MSS:%d timestamps:true", info.MaximumSegmentSize, info.Timestamps, wantSendMSS)
			}
			deadline := time.Now().Add(8 * time.Second)
			if err = client.SetDeadline(deadline); err != nil {
				t.Fatalf("set mipstack TCP deadline: %v", err)
			}
			if err = server.SetDeadline(deadline); err != nil {
				t.Fatalf("set gVisor TCP deadline: %v", err)
			}
			payload := patternedPayload(64*1024+137, 211)
			writeResult := make(chan error, 1)
			go func() {
				n, writeErr := client.Write(payload)
				if writeErr == nil && n != len(payload) {
					writeErr = io.ErrShortWrite
				}
				writeResult <- writeErr
			}()
			received := make([]byte, len(payload))
			if _, err = io.ReadFull(server, received); err != nil {
				t.Fatalf("read low-MSS gVisor payload: %v", err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("low-MSS gVisor payload mismatch")
			}
			if err = <-writeResult; err != nil {
				t.Fatalf("write low-MSS mipstack payload: %v", err)
			}
			if got := maximumPayload.Load(); got != wantSendMSS || timestampedPayloads.Load() == 0 {
				t.Fatalf("mipstack wire payload = %d, timestamped segments = %d; want max %d and timestamp coverage", got, timestampedPayloads.Load(), wantSendMSS)
			}
		})
	}
}

// TestTCPReadWithBufferInterop verifies that lazy caller-owned receive buffers
// consume native gVisor streams in both endpoint roles and address families.
func TestTCPReadWithBufferInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{false, true} {
			mipstackListens := mipstackListens
			role := "gvisor-listens"
			if mipstackListens {
				role = "mipstack-listens"
			}
			t.Run(family.name+"/"+role, func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, 1500)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				var connection *mipstack.TCPConn
				var peer net.Conn
				if mipstackListens {
					connection = server.(*mipstack.TCPConn)
					peer = client
				} else {
					connection = client.(*mipstack.TCPConn)
					peer = server
				}
				deadline := time.Now().Add(8 * time.Second)
				if err := connection.SetReadDeadline(deadline); err != nil {
					t.Fatalf("set mipstack read deadline: %v", err)
				}
				if err := peer.SetWriteDeadline(deadline); err != nil {
					t.Fatalf("set gVisor write deadline: %v", err)
				}

				payload := patternedPayload(64*1024+137, 59)
				written := make(chan error, 1)
				go func() {
					n, err := peer.Write(payload)
					if err == nil && n != len(payload) {
						err = io.ErrShortWrite
					}
					written <- err
				}()
				readTCPPayloadWithBuffer(t, connection, payload)
				if err := <-written; err != nil {
					t.Fatalf("write gVisor TCP payload: %v", err)
				}
				exchangeTCPPayload(t, connection, peer, patternedPayload(8*1024+73, 137))
			})
		}
	}
}

// TestTCPTimeWaitReuseInterop verifies that a gVisor active opener can reuse
// the same local port against a mipstack listener while the first server-side
// incarnation remains in TIME-WAIT. Both handshakes exercise the RFC 6191
// wire timestamp admission check.
func TestTCPTimeWaitReuseInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newFamilyInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			const (
				serverPort = 41011
				clientPort = 41012
			)
			listener, err := network.mipstack.ListenTCP(ctx, family.tcpNetwork, netipAddrPort(family.mipstackAddress, serverPort))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accept := func() net.Conn {
				connection, acceptErr := listener.Accept()
				if acceptErr != nil {
					t.Fatalf("Accept: %v", acceptErr)
				}
				return connection
			}
			local := gvisorFullAddress(family.gvisorAddress, clientPort)
			remote := gvisorFullAddress(family.mipstackAddress, serverPort)
			first, err := gonet.DialTCPWithBind(ctx, network.gvisor, local, remote, family.networkProtocol)
			if err != nil {
				t.Fatalf("first gVisor DialTCPWithBind: %v", err)
			}
			firstServer := accept()
			if err = firstServer.(*mipstack.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = first.SetReadDeadline(time.Now().Add(time.Second))
			if n, readErr := first.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
				t.Fatalf("first gVisor FIN read = %d, %v", n, readErr)
			}
			if err = first.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = firstServer.SetReadDeadline(time.Now().Add(time.Second))
			if n, readErr := firstServer.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
				t.Fatalf("first mipstack FIN read = %d, %v", n, readErr)
			}
			deadline := time.Now().Add(time.Second)
			for firstServer.(*mipstack.TCPConn).Info().State != mipstack.TCPStateTimeWait && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if state := firstServer.(*mipstack.TCPConn).Info().State; state != mipstack.TCPStateTimeWait {
				t.Fatalf("first mipstack state = %v, want TIME-WAIT", state)
			}
			_ = first.Close()
			_ = firstServer.Close()
			// gVisor's timestamp clock has millisecond granularity; cross one
			// tick before reusing the tuple so RFC 6191's newer-TS branch is
			// deterministic rather than scheduler-dependent.
			time.Sleep(2 * time.Millisecond)

			second, err := gonet.DialTCPWithBind(ctx, network.gvisor, local, remote, family.networkProtocol)
			if err != nil {
				t.Fatalf("same-tuple gVisor DialTCPWithBind: %v", err)
			}
			defer second.Close()
			secondServer := accept()
			defer secondServer.Close()
			if got := second.LocalAddr().(*net.TCPAddr).Port; got != clientPort {
				t.Fatalf("replacement gVisor local port = %d, want %d", got, clientPort)
			}
		})
	}
}

// TestTCPStoppedDeviceReadInterop verifies that a full embedding-link queue
// does not couple TCP socket or actor progress to Stack.Read and that the
// connection resumes without losing either direction when device reads return.
func TestTCPStoppedDeviceReadInterop(t *testing.T) {
	family := interopFamilies[0]
	bridgeStopped := make(chan struct{})
	releaseBridge := make(chan struct{})
	var bridgeArmed atomic.Bool
	var stopOnce, releaseOnce sync.Once
	network := newInteropNetworkWithOptions(t, interopNetworkOptions{
		families: []interopFamily{family}, mtu: 1500,
		mipstackToGVisor: func([]byte) bool {
			if bridgeArmed.Load() {
				stopOnce.Do(func() {
					close(bridgeStopped)
					<-releaseBridge
				})
			}
			return true
		},
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseBridge) }) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gvisorTCP, mipstackTCP, listener := openTCPPair(t, ctx, network, family, true)
	defer listener.Close()
	defer gvisorTCP.Close()
	defer mipstackTCP.Close()
	mipstackUDP, gvisorUDP := openUDPPair(t, ctx, network, family, true)
	defer mipstackUDP.Close()
	defer gvisorUDP.Close()
	udpConnection := mipstackUDP.(*mipstack.UDPConn)
	if err := udpConnection.SetReceiveErrors(true); err != nil {
		t.Fatal(err)
	}

	bridgeArmed.Store(true)
	if written, err := udpConnection.Write([]byte("bridge-stop")); err != nil || written != len("bridge-stop") {
		t.Fatalf("write bridge-stop datagram: n=%d, error=%v", written, err)
	}
	select {
	case <-bridgeStopped:
	case <-ctx.Done():
		t.Fatal("mipstack output bridge did not stop")
	}

	overloaded := make(chan error, 1)
	go func() {
		payload := []byte("queue-pressure")
		for write := 0; write < 2048; write++ {
			if written, err := udpConnection.Write(payload); err != nil {
				overloaded <- err
				return
			} else if written != len(payload) {
				overloaded <- fmt.Errorf("short UDP write: %d", written)
				return
			}
		}
		overloaded <- nil
	}()
	select {
	case err := <-overloaded:
		if err != nil {
			t.Fatalf("stopped-read overload: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("UDP writes blocked while Stack.Read was stopped")
	}

	outbound := patternedPayload(4096, 43)
	tcpWrite := make(chan error, 1)
	go func() {
		written, err := mipstackTCP.Write(outbound)
		if err == nil && written != len(outbound) {
			err = io.ErrShortWrite
		}
		tcpWrite <- err
	}()
	select {
	case err := <-tcpWrite:
		if err != nil {
			t.Fatalf("buffer TCP output while Stack.Read was stopped: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("TCP Write blocked on the stopped device reader")
	}

	infoResult := make(chan mipstack.TCPConnInfo, 1)
	go func() { infoResult <- mipstackTCP.(*mipstack.TCPConn).Info() }()
	select {
	case info := <-infoResult:
		if info.SendBufferSize != len(outbound) || info.BytesSent != 0 {
			t.Fatalf("TCP output escaped a full device queue: buffered=%d sent=%d", info.SendBufferSize, info.BytesSent)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("TCP Info blocked on the stopped device reader")
	}

	inbound := patternedPayload(4096, 97)
	peerWrite := make(chan error, 1)
	go func() {
		written, err := gvisorTCP.Write(inbound)
		if err == nil && written != len(inbound) {
			err = io.ErrShortWrite
		}
		peerWrite <- err
	}()
	receivedInbound := make(chan error, 1)
	go func() {
		storage := make([]byte, len(inbound))
		_, err := io.ReadFull(mipstackTCP, storage)
		if err == nil && !bytes.Equal(storage, inbound) {
			err = errors.New("inbound TCP payload mismatch")
		}
		receivedInbound <- err
	}()
	select {
	case err := <-receivedInbound:
		if err != nil {
			t.Fatalf("receive TCP input while Stack.Read was stopped: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("TCP input processing blocked on the stopped device reader")
	}
	select {
	case err := <-peerWrite:
		if err != nil {
			t.Fatalf("write gVisor TCP input while Stack.Read was stopped: %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseBridge) })
		t.Fatal("gVisor TCP input write did not complete")
	}

	releaseOnce.Do(func() { close(releaseBridge) })
	if err := gvisorTCP.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	receivedOutbound := make([]byte, len(outbound))
	if _, err := io.ReadFull(gvisorTCP, receivedOutbound); err != nil {
		t.Fatalf("read TCP output after device-read recovery: %v", err)
	}
	if !bytes.Equal(receivedOutbound, outbound) {
		t.Fatal("recovered outbound TCP payload mismatch")
	}
	exchangeTCPPayload(t, mipstackTCP, gvisorTCP, patternedPayload(32*1024, 151))
	exchangeTCPPayload(t, gvisorTCP, mipstackTCP, patternedPayload(32*1024, 211))
}

// TestTCPQuickACKInterop verifies that transient Linux-style quick-ACK
// requests preserve application data in both endpoint roles and address
// families. Wire timing remains an implementation policy rather than a peer
// requirement, so the test asserts complete duplex behavior after each mode.
func TestTCPQuickACKInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{true, false} {
			mipstackListens := mipstackListens
			role := "gvisor-listens"
			if mipstackListens {
				role = "mipstack-listens"
			}
			t.Run(family.name+"/"+role, func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, 1500)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				connection, peer := client, server
				if mipstackListens {
					connection, peer = server, client
				}
				quick := connection.(*mipstack.TCPConn)
				if err := quick.SetQuickACK(false); err != nil {
					t.Fatalf("disable quick ACK: %v", err)
				}
				exchangeTCPPayload(t, peer, connection, patternedPayload(4096, 31))
				if err := quick.SetQuickACK(true); err != nil {
					t.Fatalf("enable quick ACK: %v", err)
				}
				exchangeTCPPayload(t, peer, connection, patternedPayload(4096, 79))
				exchangeTCPPayload(t, connection, peer, patternedPayload(4096, 113))
			})
		}
	}
}

// TestPublicTCPSegmentCodecInterop verifies that gVisor accepts a SYN built by
// the public codec and that its native SYN-ACK is decoded by the same API.
func TestPublicTCPSegmentCodecInterop(t *testing.T) {
	const (
		mipstackPort = 44011
		gvisorPort   = 44012
	)
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
			listener, err := gonet.ListenTCP(network.gvisor, gvisorFullAddress(family.gvisorAddress, gvisorPort), family.networkProtocol)
			if err != nil {
				t.Fatalf("listen with gVisor TCP: %v", err)
			}
			defer listener.Close()

			var maximumSegmentSize, windowScale, sackPermitted, timestamp mipstack.TCPHeaderOption
			maximumSegmentSize.SetMaximumSegmentSize(1460)
			windowScale.SetWindowScale(7)
			sackPermitted.SetSACKPermitted()
			timestamp.SetTimestamp(0x10203040, 0)
			segment := mipstack.TCPSegment{
				Source:         netipAddrPort(family.mipstackAddress, mipstackPort),
				Destination:    netipAddrPort(family.gvisorAddress, gvisorPort),
				SequenceNumber: 1000, Flags: mipstack.TCPFlagSYN, WindowSize: 65535,
			}
			if err := segment.SetHeaderOptions([]mipstack.TCPHeaderOption{
				maximumSegmentSize, sackPermitted, timestamp,
				{Kind: mipstack.TCPHeaderOptionNOP}, windowScale,
			}); err != nil {
				t.Fatalf("construct public TCP SYN options: %v", err)
			}
			tcpWire, err := segment.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public TCP SYN: %v", err)
			}
			packet := mipstack.IPPacket{
				Source: family.mipstackAddress, Destination: family.gvisorAddress,
				Protocol: mipstack.ProtocolTCP, HopLimit: 64, Payload: tcpWire,
			}
			wire, err := packet.AppendBinary(nil)
			if err != nil {
				t.Fatalf("encode public TCP packet: %v", err)
			}
			if err = network.deliverToGVisor(wire); err != nil {
				t.Fatalf("deliver public TCP SYN: %v", err)
			}
			select {
			case responseWire := <-captured:
				parsedPacket, parseErr := mipstack.ParseIPPacket(responseWire)
				if parseErr != nil {
					t.Fatalf("parse gVisor SYN-ACK packet: %v", parseErr)
				}
				parsed, parseErr := parsedPacket.TCPSegment()
				if parseErr != nil || parsed.Source != segment.Destination || parsed.Destination != segment.Source || parsed.Flags&(mipstack.TCPFlagSYN|mipstack.TCPFlagACK) != mipstack.TCPFlagSYN|mipstack.TCPFlagACK || parsed.Flags&mipstack.TCPFlagRST != 0 || parsed.AcknowledgmentNumber != segment.SequenceNumber+1 {
					t.Fatalf("parsed gVisor SYN-ACK = %+v, %v", parsed, parseErr)
				}
				options, optionsErr := parsed.HeaderOptions()
				if optionsErr != nil {
					t.Fatalf("parse gVisor SYN-ACK options: %v", optionsErr)
				}
				var foundMSS, foundWindowScale, foundSACK, foundTimestamp bool
				for _, option := range options {
					if value, ok := option.MaximumSegmentSize(); ok {
						foundMSS = value != 0
					}
					if value, ok := option.WindowScale(); ok {
						foundWindowScale = value <= 14
					}
					foundSACK = foundSACK || option.IsSACKPermitted()
					if _, _, ok := option.Timestamp(); ok {
						foundTimestamp = true
					}
				}
				if !foundMSS || !foundWindowScale || !foundSACK || !foundTimestamp {
					t.Fatalf("gVisor SYN-ACK options did not negotiate the offered features: %+v", options)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("timed out waiting for gVisor SYN-ACK")
			}
		})
	}
}

// TestTCPCongestionControlInterop verifies that every built-in mipstack
// controller completes active and passive transfers after an actual data loss
// against gVisor's TCP implementation.
func TestTCPCongestionControlInterop(t *testing.T) {
	controllers := mipstack.AvailableCongestionControls()
	for _, family := range interopFamilies {
		family := family
		for _, controller := range controllers {
			controller := controller
			for _, mipstackListens := range []bool{false, true} {
				mipstackListens := mipstackListens
				direction := "active"
				if mipstackListens {
					direction = "passive"
				}
				t.Run(family.name+"/"+string(controller)+"/"+direction, func(t *testing.T) {
					var dropped atomic.Bool
					network := newInteropNetworkWithOptions(t, interopNetworkOptions{
						families: []interopFamily{family}, mtu: 1500,
						tcp:              mipstack.TCPSocketDefaults{CongestionControl: controller},
						mipstackToGVisor: newTCPDropHook(&dropped),
					})
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()

					client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
					defer listener.Close()
					defer client.Close()
					defer server.Close()
					exerciseFullDuplexTCP(t, client, server, 256*1024)
					if !dropped.Load() {
						t.Fatal("mipstack TCP data-loss hook did not match a segment")
					}
					connection := client
					if mipstackListens {
						connection = server
					}
					info := connection.(*mipstack.TCPConn).Info()
					if info.CongestionControl != controller || info.Retransmissions == 0 {
						t.Fatalf("mipstack TCP controller/retransmissions = %s/%d, want %s/nonzero", info.CongestionControl, info.Retransmissions, controller)
					}
				})
			}
		}
	}
}

// TestTCPACKClockedFlightReplacementInterop keeps more data queued than the
// initial congestion window so each gVisor cumulative ACK replaces old flight
// with new flight. The final half-closes also verify that acknowledging the
// last range leaves no stale retransmission or tail-probe work behind.
func TestTCPACKClockedFlightReplacementInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var dataSegments, acknowledgments atomic.Uint32
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				mipstackToGVisor: func(packet []byte) bool {
					if _, data := tcpDataSequence(packet); data {
						dataSegments.Add(1)
					}
					return true
				},
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if ok && payloadLength == 0 && tcpHeader.Flags() == header.TCPFlagAck {
						acknowledgments.Add(1)
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			deadline := time.Now().Add(8 * time.Second)
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)

			exchangeTCPPayload(t, client, server, patternedPayload(256*1024, 211))
			connection := client.(*mipstack.TCPConn)
			for connection.Info().BytesAcknowledged < 256*1024 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			info := connection.Info()
			if info.BytesAcknowledged < 256*1024 || info.Retransmissions != 0 || dataSegments.Load() <= 10 || acknowledgments.Load() <= 2 {
				t.Fatalf("ACK-clocked flight = acknowledged:%d retransmissions:%d data-segments:%d ACKs:%d", info.BytesAcknowledged, info.Retransmissions, dataSegments.Load(), acknowledgments.Load())
			}
			if err := connection.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n, err := server.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("gVisor read after mipstack FIN = %d, %v", n, err)
			}
			if err := server.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("mipstack read after gVisor FIN = %d, %v", n, err)
			}
		})
	}
}

// TestTCPLocalCongestionControlFactoryInterop verifies that an unregistered
// local factory receives the correct connection identity and interoperates
// with gVisor after real data loss in both active and passive roles.
func TestTCPLocalCongestionControlFactoryInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mipstackListens := range []bool{false, true} {
			mipstackListens := mipstackListens
			role := "active"
			if mipstackListens {
				role = "passive"
			}
			t.Run(family.name+"/"+role, func(t *testing.T) {
				contexts := make(chan mipstack.CongestionControlContext, 1)
				name := "interop-local-" + family.name + "-" + role
				factory, err := mipstack.NewCongestionControlFactory(mipstack.CongestionControlDefinition{
					Name: name,
					New: func(context mipstack.CongestionControlContext) mipstack.CongestionController {
						contexts <- context
						return &interopCongestionController{}
					},
					Features: mipstack.CongestionControlFeatureTransmissionEvents,
				})
				if err != nil {
					t.Fatal(err)
				}
				var dropped atomic.Bool
				network := newInteropNetworkWithOptions(t, interopNetworkOptions{
					families: []interopFamily{family}, mtu: 1500,
					tcp:              mipstack.TCPSocketDefaults{CongestionControlFactory: factory},
					mipstackToGVisor: newTCPDropHook(&dropped),
				})
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				exerciseFullDuplexTCP(t, client, server, 256*1024)
				if !dropped.Load() {
					t.Fatal("mipstack local-controller data-loss hook did not match a segment")
				}
				connection := client
				if mipstackListens {
					connection = server
				}
				info := connection.(*mipstack.TCPConn).Info()
				if info.CongestionControl != name || info.Retransmissions == 0 {
					t.Fatalf("local controller/retransmissions = %s/%d, want %s/nonzero", info.CongestionControl, info.Retransmissions, name)
				}
				select {
				case factoryContext := <-contexts:
					if factoryContext.LocalAddress.Addr() != family.mipstackAddress || factoryContext.RemoteAddress.Addr() != family.gvisorAddress ||
						factoryContext.Passive != mipstackListens || factoryContext.Forwarded {
						t.Fatalf("local factory context = %+v", factoryContext)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			})
		}
	}
}

// TestTCPControlLossInterop verifies retransmission of handshake and shutdown
// control segments emitted by either implementation.
func TestTCPControlLossInterop(t *testing.T) {
	type controlLoss struct {
		name        string
		flags       header.TCPFlags
		clientSends bool
	}
	for _, family := range interopFamilies {
		family := family
		for _, loss := range []controlLoss{
			{name: "syn", flags: header.TCPFlagSyn, clientSends: true},
			{name: "syn-ack", flags: header.TCPFlagSyn | header.TCPFlagAck},
			{name: "final-ack", flags: header.TCPFlagAck, clientSends: true},
		} {
			loss := loss
			for _, mipstackListens := range []bool{false, true} {
				mipstackListens := mipstackListens
				direction := "mipstack-listens"
				if !mipstackListens {
					direction = "gvisor-listens"
				}
				t.Run(family.name+"/"+loss.name+"/"+direction, func(t *testing.T) {
					var dropped atomic.Bool
					options := interopNetworkOptions{families: []interopFamily{family}, mtu: 1500}
					mipstackSends := loss.clientSends != mipstackListens
					if mipstackSends {
						options.mipstackToGVisor = newTCPControlDropHook(loss.flags, &dropped)
					} else {
						options.gvisorToMipstack = newTCPControlDropHook(loss.flags, &dropped)
					}
					network := newInteropNetworkWithOptions(t, options)
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					client, server, listener := openTCPPair(t, ctx, network, family, mipstackListens)
					defer listener.Close()
					defer client.Close()
					defer server.Close()
					exerciseFullDuplexTCP(t, client, server, 32*1024)
					if !dropped.Load() {
						t.Fatalf("TCP %s loss hook did not match a segment", loss.name)
					}
				})
			}
		}

		t.Run(family.name+"/fin", func(t *testing.T) {
			var mipstackDropped, gvisorDropped atomic.Bool
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				mipstackToGVisor: newTCPControlDropHook(header.TCPFlagFin, &mipstackDropped),
				gvisorToMipstack: newTCPControlDropHook(header.TCPFlagFin, &gvisorDropped),
			})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, true)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			exerciseFullDuplexTCP(t, client, server, 32*1024)
			if !mipstackDropped.Load() || !gvisorDropped.Load() {
				t.Fatalf("TCP FIN loss coverage = mipstack:%v gVisor:%v", mipstackDropped.Load(), gvisorDropped.Load())
			}
		})
	}
}

// TestTCPDualStackWildcardInterop verifies that one generic mipstack listener
// accepts native gVisor IPv4 and IPv6 connections with concrete local
// endpoint addresses.
func TestTCPDualStackWildcardInterop(t *testing.T) {
	network := newInteropNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	listener, err := network.mipstack.ListenTCP(ctx, "tcp", netip.AddrPort{})
	if err != nil {
		t.Fatalf("listen on dual-stack TCP wildcard: %v", err)
	}
	defer listener.Close()
	port := requireAddrPort(t, listener.Addr()).Port()

	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			type acceptResult struct {
				connection net.Conn
				err        error
			}
			accepted := make(chan acceptResult, 1)
			go func() {
				connection, acceptErr := listener.Accept()
				accepted <- acceptResult{connection: connection, err: acceptErr}
			}()

			client, dialErr := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(family.mipstackAddress, port), family.networkProtocol)
			if dialErr != nil {
				t.Fatalf("dial dual-stack TCP listener: %v", dialErr)
			}
			defer client.Close()
			var result acceptResult
			select {
			case result = <-accepted:
			case <-ctx.Done():
				t.Fatalf("accept dual-stack TCP connection: %v", ctx.Err())
			}
			if result.err != nil {
				t.Fatalf("accept dual-stack TCP connection: %v", result.err)
			}
			defer result.connection.Close()
			wantLocal := netipAddrPort(family.mipstackAddress, port)
			if local := requireAddrPort(t, result.connection.LocalAddr()); local != wantLocal {
				t.Fatalf("accepted dual-stack TCP local endpoint = %v, want %v", local, wantLocal)
			}
			exerciseFullDuplexTCP(t, client, result.connection, 64*1024)
		})
	}
}

// TestTCPClosedPortInterop verifies that each stack recognizes the peer's
// reset for a connection attempt to an unbound local TCP port.
func TestTCPClosedPortInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				connection, err := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(family.mipstackAddress, 44991), family.networkProtocol)
				if connection != nil {
					_ = connection.Close()
				}
				if !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("gVisor dial to closed mipstack port = %v, want ECONNREFUSED", err)
				}

				mipstackConnection, err := network.mipstack.DialTCP(ctx, family.tcpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, 44992))
				if mipstackConnection != nil {
					_ = mipstackConnection.Close()
				}
				if !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("mipstack dial to closed gVisor port = %v, want ECONNREFUSED", err)
				}
			})
		}
	}
}

// TestTCPEstablishedResetInterop verifies abortive close and established-state
// reset validation in both directions.
func TestTCPEstablishedResetInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu)+"/mipstack-resets", func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				client, server, listener := openTCPPair(t, ctx, network, family, true)
				defer listener.Close()
				defer client.Close()
				connection := server.(*mipstack.TCPConn)
				if err := connection.SetLinger(0); err != nil {
					t.Fatalf("set mipstack abortive linger: %v", err)
				}
				if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatalf("set gVisor reset deadline: %v", err)
				}
				if err := connection.Close(); err != nil {
					t.Fatalf("abort mipstack TCP connection: %v", err)
				}
				if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("gVisor read after mipstack abort = %v, want ECONNRESET", err)
				}
			})

			t.Run(family.name+"/"+interopMTUName(mtu)+"/gvisor-resets", func(t *testing.T) {
				network := newFamilyInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				const port = 44981
				var queue waiter.Queue
				listener, tcpipErr := network.gvisor.NewEndpoint(tcp.ProtocolNumber, family.networkProtocol, &queue)
				if tcpipErr != nil {
					t.Fatalf("create native gVisor TCP listener: %s", tcpipErr.String())
				}
				defer listener.Close()
				if tcpipErr = listener.Bind(gvisorFullAddress(family.gvisorAddress, port)); tcpipErr != nil {
					t.Fatalf("bind native gVisor TCP listener: %s", tcpipErr.String())
				}
				if tcpipErr = listener.Listen(1); tcpipErr != nil {
					t.Fatalf("listen with native gVisor TCP endpoint: %s", tcpipErr.String())
				}
				entry, notifications := registerReadable(&queue)
				defer queue.EventUnregister(&entry)
				type dialResult struct {
					connection net.Conn
					err        error
				}
				dialed := make(chan dialResult, 1)
				go func() {
					connection, err := network.mipstack.DialTCP(ctx, family.tcpNetwork, netip.AddrPort{}, netipAddrPort(family.gvisorAddress, port))
					dialed <- dialResult{connection: connection, err: err}
				}()
				accepted, _, err := acceptGVisorTCP(ctx, listener, notifications)
				if err != nil {
					t.Fatalf("accept native gVisor TCP connection: %v", err)
				}
				defer accepted.Close()
				result := <-dialed
				if result.err != nil {
					t.Fatalf("dial native gVisor TCP listener: %v", result.err)
				}
				connection := result.connection.(*mipstack.TCPConn)
				defer connection.Close()
				if err = connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatalf("set mipstack reset deadline: %v", err)
				}
				accepted.SocketOptions().SetLinger(tcpip.LingerOption{Enabled: true})
				accepted.Close()
				if _, err = connection.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("mipstack read after gVisor abort = %v, want ECONNRESET", err)
				}
			})
		}
	}
}

// TestTCPImpairedLinkInterop verifies bidirectional recovery when the bridge
// drops or reorders the first TCP data packets emitted by both stacks.
func TestTCPImpairedLinkInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, impairment := range []string{"loss", "reorder"} {
			impairment := impairment
			t.Run(family.name+"/"+impairment, func(t *testing.T) {
				var network *interopNetwork
				var mipstackImpaired, gvisorImpaired atomic.Bool
				bridgeErrors := make(chan error, 2)
				options := interopNetworkOptions{families: []interopFamily{family}, mtu: 1500}
				if impairment == "loss" {
					options.mipstackToGVisor = newTCPDropHook(&mipstackImpaired)
					options.gvisorToMipstack = newTCPDropHook(&gvisorImpaired)
				} else {
					options.mipstackToGVisor = newTCPReorderHook(func(packet []byte) error {
						return network.deliverToGVisor(packet)
					}, &mipstackImpaired, bridgeErrors)
					options.gvisorToMipstack = newTCPReorderHook(func(packet []byte) error {
						return network.deliverToMipstack(packet)
					}, &gvisorImpaired, bridgeErrors)
				}
				network = newInteropNetworkWithOptions(t, options)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()

				client, server, listener := openTCPPair(t, ctx, network, family, true)
				defer listener.Close()
				defer client.Close()
				defer server.Close()
				exerciseFullDuplexTCP(t, client, server, 256*1024)
				if impairment == "loss" {
					if info := server.(*mipstack.TCPConn).Info(); info.Retransmissions == 0 {
						t.Fatalf("mipstack TCP retransmissions = 0 after an outbound data loss")
					}
				}
				if !mipstackImpaired.Load() || !gvisorImpaired.Load() {
					t.Fatalf("TCP impairment coverage = mipstack:%v gVisor:%v", mipstackImpaired.Load(), gvisorImpaired.Load())
				}
				select {
				case err := <-bridgeErrors:
					t.Fatal(err)
				default:
				}
			})
		}
	}
}

// TestTCPCompressedSACKInterop withholds gVisor's first data segment and the
// first four mipstack SACK acknowledgements. Releasing those acknowledgements
// as one batch verifies that Linux-style compressed feedback still gives the
// peer enough prompt loss evidence to recover without an RTO.
func TestTCPCompressedSACKInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var network *interopNetwork
			var dropped, released atomic.Bool
			var sackACKs atomic.Uint32
			bridgeErrors := make(chan error, 1)
			var heldACKs [][]byte
			network = newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					_, data := tcpDataSequence(packet)
					return !data || !dropped.CompareAndSwap(false, true)
				},
				mipstackToGVisor: func(packet []byte) bool {
					if !dropped.Load() || released.Load() {
						return true
					}
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if !ok || payloadLength != 0 || tcpHeader.Flags() != header.TCPFlagAck || !tcpHasSACKOption(tcpHeader) {
						return true
					}
					heldACKs = append(heldACKs, append([]byte(nil), packet...))
					if sackACKs.Add(1) < 4 {
						return false
					}
					released.Store(true)
					for _, acknowledgement := range heldACKs {
						if err := network.deliverToGVisor(acknowledgement); err != nil {
							select {
							case bridgeErrors <- err:
							default:
							}
						}
					}
					return false
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, true)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			exchangeTCPPayload(t, client, server, patternedPayload(256*1024, 149))
			if !dropped.Load() || !released.Load() || sackACKs.Load() != 4 {
				t.Fatalf("compressed SACK coverage = dropped:%v released:%v ACKs:%d", dropped.Load(), released.Load(), sackACKs.Load())
			}
			select {
			case err := <-bridgeErrors:
				t.Fatal(err)
			default:
			}
		})
	}
}

// TestTCPFRTOInterop delays gVisor's first data acknowledgement past mipstack's
// retransmission timer. A later forward ACK must let RFC 5682 undo the spurious
// timeout without losing or duplicating application bytes.
func TestTCPFRTOInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			var armed, delayed atomic.Bool
			var delayNanos atomic.Int64
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if ok && payloadLength == 0 && tcpHeader.Flags() == header.TCPFlagAck && armed.Load() && delayed.CompareAndSwap(false, true) {
						time.Sleep(time.Duration(delayNanos.Load()))
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			tcpConnection := client.(*mipstack.TCPConn)
			delayNanos.Store(int64(4*tcpConnection.Info().RetransmissionTimeout + time.Second))
			armed.Store(true)
			deadline := time.Now().Add(6 * time.Second)
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)
			payload := patternedPayload(128*1024, 191)
			result := make(chan error, 1)
			go writeTCPPayload(client, payload, "mipstack F-RTO sender", result)
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(server, received); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("F-RTO interop payload mismatch")
			}
			if !delayed.Load() {
				t.Fatal("gVisor ACK delay hook did not match")
			}
			info := tcpConnection.Info()
			if info.Retransmissions == 0 || info.SpuriousRecoveryUndos == 0 {
				t.Fatalf("mipstack F-RTO diagnostics = retransmissions:%d undos:%d", info.Retransmissions, info.SpuriousRecoveryUndos)
			}
		})
	}
}

// TestTCPKeepAliveInterop verifies that receive activity restarts the idle
// period and that the connection remains usable after the following probe.
func TestTCPKeepAliveInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			keepAlive := mipstack.KeepAliveConfig{Idle: 200 * time.Millisecond, Interval: 20 * time.Millisecond, Count: 20}
			observer := newTCPKeepAliveObserver()
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				tcp:              mipstack.TCPSocketDefaults{KeepAlive: true, KeepAliveConfig: keepAlive},
				mipstackToGVisor: observer.observeOutbound,
				gvisorToMipstack: observer.observeInbound,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, false)
			defer listener.Close()
			defer client.Close()
			defer server.Close()

			select {
			case <-observer.probes:
			case <-time.After(2 * time.Second):
				t.Fatalf("mipstack did not emit the initial TCP keepalive probe; info=%+v", client.(*mipstack.TCPConn).Info())
			}
			activityStartedAt := observer.elapsed()
			exchangeTCPPayload(t, client, server, patternedPayload(32*1024, 29))
			exchangeTCPPayload(t, server, client, patternedPayload(32*1024, 71))
			lastActivity := time.Duration(observer.lastInboundData.Load())
			if lastActivity < activityStartedAt {
				t.Fatalf("bidirectional transfer produced no inbound TCP data after %v; last inbound data at %v", activityStartedAt, lastActivity)
			}

			var laterProbe tcpKeepAliveObservation
			probeDeadline := time.NewTimer(2 * time.Second)
			defer probeDeadline.Stop()
			for laterProbe.lastInbound < lastActivity {
				select {
				case observation := <-observer.probes:
					laterProbe = observation
				case <-probeDeadline.C:
					t.Fatalf("mipstack did not emit a TCP keepalive probe after bidirectional activity; info=%+v", client.(*mipstack.TCPConn).Info())
				}
			}
			// A reset probe series waits Idle; an unreset series continues after
			// Interval. Their midpoint avoids depending on timer granularity.
			minimumRestart := (keepAlive.Idle + keepAlive.Interval) / 2
			if elapsed := laterProbe.sentAt - laterProbe.lastInbound; elapsed < minimumRestart {
				t.Fatalf("mipstack emitted a TCP keepalive probe %v after inbound activity; want the restarted idle period (at least %v)", elapsed, minimumRestart)
			}
			if observer.dropped.Load() {
				t.Fatal("TCP keepalive observation queue overflowed")
			}
			info := client.(*mipstack.TCPConn).Info()
			if !info.KeepAlive || info.KeepAliveConfig != keepAlive || info.State != mipstack.TCPStateEstablished {
				t.Fatalf("mipstack TCP keepalive state = enabled:%v config:%+v state:%v", info.KeepAlive, info.KeepAliveConfig, info.State)
			}
			exerciseFullDuplexTCP(t, client, server, 32*1024)
		})
	}
}

// TestTCPReceiveWindowReopenInterop verifies that gVisor honors a zero window
// advertised by mipstack and resumes after application reads reopen it.
func TestTCPReceiveWindowReopenInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			const receiveCapacity = 4 * 1024
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				tcp: mipstack.TCPSocketDefaults{ReceiveBuffer: receiveCapacity, MaximumReceiveBuffer: receiveCapacity},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, true)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			deadline := time.Now().Add(8 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatalf("set gVisor zero-window deadline: %v", err)
			}
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatalf("set mipstack zero-window deadline: %v", err)
			}

			payload := patternedPayload(256*1024, 157)
			writeResult := make(chan error, 1)
			go writeTCPPayload(client, payload, "gVisor zero-window sender", writeResult)
			connection := server.(*mipstack.TCPConn)
			windowDeadline := time.Now().Add(2 * time.Second)
			var windowClosed bool
			for time.Now().Before(windowDeadline) {
				info := connection.Info()
				if info.ReceiveWindow == 0 && info.ReceiveBufferSize == receiveCapacity {
					windowClosed = true
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !windowClosed {
				info := connection.Info()
				t.Fatalf("mipstack receive window did not close: window=%d buffered=%d capacity=%d", info.ReceiveWindow, info.ReceiveBufferSize, info.ReceiveBufferCapacity)
			}
			received, err := io.ReadAll(server)
			if err != nil || !bytes.Equal(received, payload) {
				t.Fatalf("read after reopening mipstack receive window: bytes=%d, error=%v", len(received), err)
			}
			if err = <-writeResult; err != nil {
				t.Fatal(err)
			}
			if info := connection.Info(); info.BytesReceived != uint64(len(payload)) || info.ReceiveBufferSize != 0 {
				t.Fatalf("mipstack post-window TCP info = received:%d buffered:%d", info.BytesReceived, info.ReceiveBufferSize)
			}
		})
	}
}

// TestTCPZeroWindowFINInterop verifies that a FIN-only segment is consumed at
// RCV.NXT while mipstack's application receive buffer is full. The bridge
// counts FINs so a delayed close caused by peer retransmission cannot pass.
func TestTCPZeroWindowFINInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			const receiveCapacity = 1
			var finCount atomic.Int32
			finObserved := make(chan struct{}, 1)
			network := newInteropNetworkWithOptions(t, interopNetworkOptions{
				families: []interopFamily{family}, mtu: 1500,
				tcp: mipstack.TCPSocketDefaults{ReceiveBuffer: receiveCapacity, MaximumReceiveBuffer: receiveCapacity},
				gvisorToMipstack: func(packet []byte) bool {
					tcpHeader, payloadLength, ok := tcpSegment(packet)
					if ok && payloadLength == 0 && tcpHeader.Flags().Contains(header.TCPFlagFin) &&
						!tcpHeader.Flags().Contains(header.TCPFlagSyn) {
						if finCount.Add(1) == 1 {
							select {
							case finObserved <- struct{}{}:
							default:
							}
						}
					}
					return true
				},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, server, listener := openTCPPair(t, ctx, network, family, true)
			defer listener.Close()
			defer client.Close()
			defer server.Close()
			connection := server.(*mipstack.TCPConn)
			deadline := time.Now().Add(5 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if written, err := client.Write([]byte{'x'}); err != nil || written != 1 {
				t.Fatalf("gVisor one-byte write = %d, %v", written, err)
			}
			windowDeadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(windowDeadline) {
				info := connection.Info()
				if info.ReceiveWindow == 0 && info.ReceiveBufferSize == receiveCapacity {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if info := connection.Info(); info.ReceiveWindow != 0 || info.ReceiveBufferSize != receiveCapacity {
				t.Fatalf("mipstack receive window did not close: window=%d buffered=%d", info.ReceiveWindow, info.ReceiveBufferSize)
			}
			closeWriter, ok := client.(interface{ CloseWrite() error })
			if !ok {
				t.Fatal("gVisor TCP connection has no CloseWrite")
			}
			if err := closeWriter.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-finObserved:
			case <-time.After(2 * time.Second):
				t.Fatal("gVisor FIN was not observed")
			}
			stateDeadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(stateDeadline) && connection.Info().State != mipstack.TCPStateCloseWait {
				time.Sleep(5 * time.Millisecond)
			}
			if info := connection.Info(); info.State != mipstack.TCPStateCloseWait || finCount.Load() != 1 {
				t.Fatalf("mipstack close after first FIN = state:%v FINs:%d", info.State, finCount.Load())
			}
			if n, err := server.Read(make([]byte, 1)); n != 1 || err != nil {
				t.Fatalf("buffered byte before EOF = %d, %v", n, err)
			}
			if n, err := server.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("zero-window FIN read = %d, %v; want 0, EOF", n, err)
			}
		})
	}
}

// validateTCPMTUInfo verifies that mipstack retained the configured path MTU
// and negotiated an MSS that can fit one fixed-header packet on that path.
func validateTCPMTUInfo(t *testing.T, info mipstack.TCPConnInfo, family interopFamily, mtu uint32) {
	t.Helper()
	maximumSegmentSize := int(mtu) - header.IPv4MinimumSize - header.TCPMinimumSize
	if family.mipstackAddress.Is6() {
		maximumSegmentSize = int(mtu) - header.IPv6MinimumSize - header.TCPMinimumSize
	}
	if info.PathMTU != int(mtu) || info.MaximumSegmentSize <= 0 || info.MaximumSegmentSize > maximumSegmentSize {
		t.Fatalf("mipstack TCP MTU info = path %d, MSS %d; want path %d and MSS 1..%d", info.PathMTU, info.MaximumSegmentSize, mtu, maximumSegmentSize)
	}
	if !info.SACK || !info.Timestamps || !info.WindowScaling {
		t.Fatalf("mipstack TCP negotiated options = SACK:%v timestamps:%v window-scaling:%v", info.SACK, info.Timestamps, info.WindowScaling)
	}
}

// newTCPDropHook drops exactly the first complete TCP segment with payload.
func newTCPDropHook(dropped *atomic.Bool) interopPacketHook {
	return func(packet []byte) bool {
		_, data := tcpDataSequence(packet)
		return !data || !dropped.CompareAndSwap(false, true)
	}
}

// newTCPControlDropHook drops exactly the first segment with the requested
// control-flag shape. A SYN matcher excludes SYN-ACK, while combined flags and
// FIN match by containment.
func newTCPControlDropHook(want header.TCPFlags, dropped *atomic.Bool) interopPacketHook {
	return func(packet []byte) bool {
		tcpHeader, payloadLength, ok := tcpSegment(packet)
		if !ok {
			return true
		}
		flags := tcpHeader.Flags()
		matched := flags.Contains(want)
		if want == header.TCPFlagSyn {
			matched = matched && !flags.Contains(header.TCPFlagAck)
		} else if want == header.TCPFlagAck {
			matched = flags == header.TCPFlagAck && payloadLength == 0
		}
		return !matched || !dropped.CompareAndSwap(false, true)
	}
}

// newTCPReorderHook withholds the first TCP data segment and delivers the next
// distinct segment before it. Later packets retain normal bridge order.
func newTCPReorderHook(deliver func([]byte) error, reordered *atomic.Bool, bridgeErrors chan<- error) interopPacketHook {
	var held []byte
	var heldSequence uint32
	return func(packet []byte) bool {
		sequence, data := tcpDataSequence(packet)
		if !data || reordered.Load() {
			return true
		}
		if held == nil {
			held = append([]byte(nil), packet...)
			heldSequence = sequence
			return false
		}
		if sequence == heldSequence {
			return true
		}
		if err := deliver(packet); err != nil {
			select {
			case bridgeErrors <- err:
			default:
			}
		}
		if err := deliver(held); err != nil {
			select {
			case bridgeErrors <- err:
			default:
			}
		}
		held = nil
		reordered.Store(true)
		return false
	}
}

// tcpDataSequence returns a TCP sequence number only for a complete IPv4 or
// extension-free IPv6 segment carrying application payload.
func tcpDataSequence(packet []byte) (uint32, bool) {
	tcpHeader, payloadLength, ok := tcpSegment(packet)
	if !ok || payloadLength == 0 {
		return 0, false
	}
	return tcpHeader.SequenceNumber(), true
}

// tcpKeepAliveObservation records one keepalive probe and the most recent
// inbound TCP data observed before it on the bridge's monotonic clock.
type tcpKeepAliveObservation struct {
	sentAt, lastInbound time.Duration
}

// tcpKeepAliveObserver recognizes wire keepalive probes without depending on
// when the test goroutine is scheduled. The outbound hook alone owns sendNext.
type tcpKeepAliveObserver struct {
	origin       time.Time
	haveSendNext bool
	sendNext     uint32
	// lastInboundData is an event the established connection necessarily
	// accepts as activity; a later duplicate control packet need not be.
	lastInboundData atomic.Int64
	probes          chan tcpKeepAliveObservation
	dropped         atomic.Bool
}

func newTCPKeepAliveObserver() *tcpKeepAliveObserver {
	return &tcpKeepAliveObserver{origin: time.Now(), probes: make(chan tcpKeepAliveObservation, 16)}
}

// elapsed returns a positive monotonic offset suitable for atomic storage.
func (o *tcpKeepAliveObserver) elapsed() time.Duration {
	elapsed := time.Since(o.origin)
	if elapsed <= 0 {
		return 1
	}
	return elapsed
}

// observeInbound records TCP data immediately before bridge delivery.
func (o *tcpKeepAliveObserver) observeInbound(packet []byte) bool {
	if _, payloadLength, ok := tcpSegment(packet); ok && payloadLength != 0 {
		o.lastInboundData.Store(int64(o.elapsed()))
	}
	return true
}

// observeOutbound tracks transmitted sequence space and recognizes the RFC
// keepalive form: a payload-free ACK at SND.NXT-1.
func (o *tcpKeepAliveObserver) observeOutbound(packet []byte) bool {
	tcpHeader, payloadLength, ok := tcpSegment(packet)
	if !ok {
		return true
	}
	flags := tcpHeader.Flags()
	sequence := tcpHeader.SequenceNumber()
	if flags.Contains(header.TCPFlagSyn) {
		o.sendNext = sequence + 1
		o.haveSendNext = true
	} else if o.haveSendNext && sequence == o.sendNext {
		o.sendNext += uint32(payloadLength)
		if flags.Contains(header.TCPFlagFin) {
			o.sendNext++
		}
	}
	control := header.TCPFlagSyn | header.TCPFlagFin | header.TCPFlagRst
	if o.haveSendNext && payloadLength == 0 && flags.Contains(header.TCPFlagAck) && flags&control == 0 && sequence == o.sendNext-1 {
		observation := tcpKeepAliveObservation{
			sentAt: o.elapsed(), lastInbound: time.Duration(o.lastInboundData.Load()),
		}
		select {
		case o.probes <- observation:
		default:
			o.dropped.Store(true)
		}
	}
	return true
}

// tcpHasSACKOption reports whether one validated gVisor TCP header carries a
// well-formed SACK option. The bridge already excludes fragmented packets.
func tcpHasSACKOption(tcpHeader header.TCP) bool {
	headerLength := int(tcpHeader.DataOffset())
	if headerLength < header.TCPMinimumSize || headerLength > len(tcpHeader) {
		return false
	}
	for options := tcpHeader[header.TCPMinimumSize:headerLength]; len(options) != 0; {
		kind := options[0]
		if kind == mipstack.TCPHeaderOptionEnd {
			return false
		}
		if kind == mipstack.TCPHeaderOptionNOP {
			options = options[1:]
			continue
		}
		if len(options) < 2 || int(options[1]) > len(options) || options[1] < 2 {
			return false
		}
		if kind == mipstack.TCPHeaderOptionSACK && options[1] >= 10 && (options[1]-2)%8 == 0 {
			return true
		}
		options = options[options[1]:]
	}
	return false
}

// tcpSegment returns one complete extension-free TCP header and its payload
// length. TCP under test is packetized below the link MTU and is not fragmented.
func tcpSegment(packet []byte) (header.TCP, int, bool) {
	if len(packet) == 0 {
		return nil, 0, false
	}
	transportOffset := 0
	switch packet[0] >> 4 {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return nil, 0, false
		}
		ipHeader := header.IPv4(packet)
		if ipHeader.TransportProtocol() != header.TCPProtocolNumber {
			return nil, 0, false
		}
		transportOffset = int(ipHeader.HeaderLength())
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize || header.IPv6(packet).TransportProtocol() != header.TCPProtocolNumber {
			return nil, 0, false
		}
		transportOffset = header.IPv6MinimumSize
	default:
		return nil, 0, false
	}
	if len(packet) < transportOffset+header.TCPMinimumSize {
		return nil, 0, false
	}
	tcpHeader := header.TCP(packet[transportOffset:])
	headerSize := int(tcpHeader.DataOffset())
	if headerSize < header.TCPMinimumSize || len(packet) < transportOffset+headerSize {
		return nil, 0, false
	}
	return tcpHeader, len(packet) - transportOffset - headerSize, true
}

// acceptGVisorTCP waits for one native endpoint without wrapping away access
// to its socket options.
func acceptGVisorTCP(ctx context.Context, listener tcpip.Endpoint, notifications <-chan struct{}) (tcpip.Endpoint, *waiter.Queue, error) {
	for {
		endpoint, queue, tcpipErr := listener.Accept(nil)
		if tcpipErr == nil {
			return endpoint, queue, nil
		}
		if _, wouldBlock := tcpipErr.(*tcpip.ErrWouldBlock); !wouldBlock {
			return nil, nil, errors.New(tcpipErr.String())
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-notifications:
		}
	}
}

// openTCPPair creates one cross-stack connection with the selected listener
// owner and returns all caller-owned endpoints.
func openTCPPair(t *testing.T, ctx context.Context, network *interopNetwork, family interopFamily, mipstackListens bool) (net.Conn, net.Conn, net.Listener) {
	t.Helper()
	const port = 41001

	var listener net.Listener
	var err error
	if mipstackListens {
		listener, err = network.mipstack.ListenTCP(ctx, family.tcpNetwork, netipAddrPort(family.mipstackAddress, port))
	} else {
		listener, err = gonet.ListenTCP(network.gvisor, gvisorFullAddress(family.gvisorAddress, port), family.networkProtocol)
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	type acceptResult struct {
		connection net.Conn
		err        error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		accepted <- acceptResult{connection: connection, err: acceptErr}
	}()

	var client net.Conn
	if mipstackListens {
		client, err = gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(family.mipstackAddress, port), family.networkProtocol)
	} else {
		client, err = network.mipstack.DialTCP(ctx, family.tcpNetwork, netipAddrPort(family.mipstackAddress, 0), netipAddrPort(family.gvisorAddress, port))
	}
	if err != nil {
		_ = listener.Close()
		t.Fatalf("dial: %v", err)
	}

	select {
	case result := <-accepted:
		if result.err != nil {
			_ = client.Close()
			_ = listener.Close()
			t.Fatalf("accept: %v", result.err)
		}
		return client, result.connection, listener
	case <-ctx.Done():
		_ = client.Close()
		_ = listener.Close()
		t.Fatalf("accept: %v", ctx.Err())
		return nil, nil, nil
	}
}

// exerciseFullDuplexTCP transfers independent streams concurrently and uses
// half-close to delimit each stream.
func exerciseFullDuplexTCP(t *testing.T, client, server net.Conn, payloadSize int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		t.Fatalf("set server deadline: %v", err)
	}

	clientPayload := patternedPayload(payloadSize, 17)
	serverPayload := patternedPayload(payloadSize, 83)
	results := make(chan error, 4)
	go writeTCPPayload(client, clientPayload, "client", results)
	go writeTCPPayload(server, serverPayload, "server", results)
	go readTCPPayload(client, serverPayload, "client", results)
	go readTCPPayload(server, clientPayload, "server", results)
	for index := 0; index < 4; index++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}

// exchangeTCPPayload transfers one length-delimited payload without closing
// either write half, allowing the same connection to exercise later policy
// changes.
func exchangeTCPPayload(t *testing.T, sender, receiver net.Conn, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	if err := sender.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set sender write deadline: %v", err)
	}
	if err := receiver.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set receiver read deadline: %v", err)
	}
	written := make(chan error, 1)
	go func() {
		_, err := io.Copy(sender, bytes.NewReader(payload))
		written <- err
	}()
	received := make([]byte, len(payload))
	_, readErr := io.ReadFull(receiver, received)
	writeErr := <-written
	if writeErr != nil {
		t.Fatalf("write payload: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("read payload: %v", readErr)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("payload mismatch")
	}
}

// readTCPPayloadWithBuffer consumes one expected stream through the public
// lazy-buffer API while reusing the same caller-owned storage across reads.
func readTCPPayloadWithBuffer(t *testing.T, connection *mipstack.TCPConn, expected []byte) {
	t.Helper()
	storage := make([]byte, 4*1024)
	received := make([]byte, 0, len(expected))
	for len(received) < len(expected) {
		remaining := len(expected) - len(received)
		var provided []byte
		n, err := connection.ReadWithBuffer(func(sizeHint int) []byte {
			if sizeHint <= 0 {
				t.Fatalf("ReadWithBuffer reported non-positive size hint %d", sizeHint)
			}
			provided = storage
			if sizeHint < len(provided) {
				provided = provided[:sizeHint]
			}
			if remaining < len(provided) {
				provided = provided[:remaining]
			}
			return provided
		})
		if n < 0 || n > len(provided) {
			t.Fatalf("ReadWithBuffer returned %d bytes for a %d-byte buffer", n, len(provided))
		}
		if n != 0 {
			received = append(received, provided[:n]...)
		}
		if err != nil {
			t.Fatalf("ReadWithBuffer after %d bytes: %v", len(received), err)
		}
		if n == 0 {
			t.Fatal("ReadWithBuffer returned no data and no error")
		}
	}
	if !bytes.Equal(received, expected) {
		t.Fatal("ReadWithBuffer payload mismatch")
	}
}

// writeTCPPayload sends one complete stream, closes its write half, and reports
// exactly one result.
func writeTCPPayload(connection net.Conn, payload []byte, side string, result chan<- error) {
	written, err := io.Copy(connection, bytes.NewReader(payload))
	if err == nil && written != int64(len(payload)) {
		err = io.ErrShortWrite
	}
	if err == nil {
		if closeWriter, ok := connection.(interface{ CloseWrite() error }); ok {
			err = closeWriter.CloseWrite()
		} else {
			err = errors.New("connection does not implement CloseWrite")
		}
	}
	if err != nil {
		err = fmt.Errorf("%s write: %w", side, err)
	}
	result <- err
}

// readTCPPayload reads through the peer's FIN and validates the complete byte
// stream before reporting exactly one result.
func readTCPPayload(connection net.Conn, expected []byte, side string, result chan<- error) {
	payload, err := io.ReadAll(connection)
	if err == nil && !bytes.Equal(payload, expected) {
		err = fmt.Errorf("payload mismatch: got %d bytes, want %d", len(payload), len(expected))
	}
	if err != nil {
		err = fmt.Errorf("%s read: %w", side, err)
	}
	result <- err
}
