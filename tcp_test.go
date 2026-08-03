package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestTCPListenerAcceptAndClose verifies passive open, bidirectional stream
// I/O, Accept deadlines, and listener ownership of only unaccepted flows.
func TestTCPListenerAcceptAndClose(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.1")
	serverAddress := netip.MustParseAddr("192.0.2.2")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	serverEndpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	clientConnection, err := client.DialTCP(context.Background(), "tcp", netip.AddrPort{}, serverEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	serverConnection, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()
	_ = clientConnection.SetDeadline(time.Now().Add(2 * time.Second))
	_ = serverConnection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = clientConnection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	if _, err = io.ReadFull(serverConnection, buffer[:7]); err != nil || string(buffer[:7]) != "request" {
		t.Fatalf("server Read = %q, %v", buffer[:7], err)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = serverConnection.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(clientConnection, buffer); err != nil || string(buffer) != "response" {
		t.Fatalf("client Read = %q, %v", buffer, err)
	}
	if err = listener.Close(); err == nil {
		t.Fatal("second listener Close succeeded")
	} else {
		checkNetOpError(t, err, "close", "tcp")
	}

	deadlineListener, err := server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer deadlineListener.Close()
	if err = deadlineListener.SetDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = deadlineListener.Accept(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Accept error = %v, want deadline", err)
	} else {
		checkNetOpError(t, err, "accept", "tcp")
	}
}

func TestTCPReaderFromWriterToAndMultipathQuery(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.201")
	serverAddress := netip.MustParseAddr("192.0.2.202")
	clientStack, serverStack := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, clientStack, serverStack)
	listener, err := serverStack.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, 45100))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := clientStack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 45100))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	payload := strings.Repeat("reader-from-writer-to-", 4096)
	n, err := client.(*TCPConn).ReadFrom(strings.NewReader(payload))
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("ReadFrom = %d, %v, want %d", n, err, len(payload))
	}
	if err = client.(*TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var received bytes.Buffer
	n, err = server.WriteTo(&received)
	if err != nil || n != int64(len(payload)) || received.String() != payload {
		t.Fatalf("WriteTo = %d bytes, %v, content match = %v", n, err, received.String() == payload)
	}
	if multipath, queryErr := client.(*TCPConn).MultipathTCP(); queryErr != nil || multipath {
		t.Fatalf("MultipathTCP = %v, %v, want false, nil", multipath, queryErr)
	}
}

// TestTCPListenerIPv6WildcardAndBinding verifies wildcard dispatch and
// standard address-in-use errors for overlapping passive endpoints.
func TestTCPListenerIPv6WildcardAndBinding(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::1")
	serverAddress := netip.MustParseAddr("2001:db8::2")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(netip.IPv6Unspecified(), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).AddrPort().Port()
	if _, err = server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, port)); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("overlapping ListenTCP error = %v", err)
	} else {
		checkNetOpError(t, err, "listen", "tcp")
	}
	clientConnection, err := client.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, port))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	serverConnection, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()
	if serverConnection.LocalAddr().(*net.TCPAddr).AddrPort().Addr() != serverAddress {
		t.Fatalf("accepted local address = %v, want %v", serverConnection.LocalAddr(), serverAddress)
	}
	if stats := server.Stats(); stats.ActiveTCPListeners != 1 || stats.ActiveTCPConnections != 1 {
		t.Fatalf("passive stats = listeners %d connections %d", stats.ActiveTCPListeners, stats.ActiveTCPConnections)
	}
}

// TestTCPListenerCloseAbortsQueuedConnection verifies that Close wakes Accept
// and resets a completed flow that has not yet been handed to the application.
func TestTCPListenerCloseAbortsQueuedConnection(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.1")
	serverAddress := netip.MustParseAddr("192.0.2.2")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := client.DialTCP(context.Background(), "tcp", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close error = %v", err)
	} else {
		checkNetOpError(t, err, "accept", "tcp")
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = connection.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("queued connection Read error = %v", err)
	}
}

// TestTCPStandardOperationErrors verifies TCP operation metadata and sentinel
// preservation after closure and invalid dial requests.
func TestTCPStandardOperationErrors(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	if _, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPort{}); err == nil {
		t.Fatal("invalid DialTCP succeeded")
	} else {
		checkNetOpError(t, err, "dial", "tcp")
	}
	if _, err := stack.DialTCP(context.Background(), "udp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 80)); err == nil {
		t.Fatal("DialTCP with UDP network succeeded")
	} else {
		var unknown net.UnknownNetworkError
		if !errors.As(err, &unknown) {
			t.Fatalf("DialTCP unknown network error = %v", err)
		}
	}
	if _, err := stack.DialTCP(context.Background(), "tcp6", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 80)); !errors.Is(err, syscall.EAFNOSUPPORT) {
		t.Fatalf("DialTCP family mismatch = %v, want EAFNOSUPPORT", err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8088))
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close error = %v", err)
	} else {
		checkNetOpError(t, err, "close", "tcp")
	}
	if _, err = connection.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close error = %v", err)
	} else {
		checkNetOpError(t, err, "read", "tcp")
	}
	if _, err = connection.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close error = %v", err)
	} else {
		checkNetOpError(t, err, "write", "tcp")
	}
	if err = connection.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetDeadline after Close error = %v", err)
	} else {
		checkNetOpError(t, err, "set", "tcp")
	}
}

// TestTCPCloseReadKeepsReceiveWindow verifies that shutting down application
// reads still consumes and acknowledges peer sequence space.
func TestTCPCloseReadKeepsReceiveWindow(t *testing.T) {
	connection := &TCPConn{readChanged: make(chan struct{}), writeChanged: make(chan struct{}), readNotify: make(chan struct{}), receiveCapacity: tcpReceiveCapacity}
	if err := connection.CloseRead(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("discarded peer data")
	if accepted := connection.appendReadBuffer(payload, 0); accepted != len(payload) {
		t.Fatalf("discarded bytes accepted = %d, want %d", accepted, len(payload))
	}
	if window := connection.receiveWindow(0, true); window == 0 {
		t.Fatal("CloseRead advertised a zero receive window")
	}
	if len(connection.readBuffer) != 0 {
		t.Fatal("CloseRead retained discarded peer data")
	}
}

// TestTCPWindowUpdateOrdering verifies stale and wrapped ACK ordering.
func TestTCPWindowUpdateOrdering(t *testing.T) {
	if tcpWindowUpdateAllowed(99, 200, 100, 100) {
		t.Fatal("older segment sequence updated the send window")
	}
	if tcpWindowUpdateAllowed(100, 99, 100, 100) {
		t.Fatal("older acknowledgement updated the send window")
	}
	if !tcpWindowUpdateAllowed(101, 1, 100, 100) || !tcpWindowUpdateAllowed(100, 100, 100, 100) {
		t.Fatal("fresh send-window update was rejected")
	}
	if !tcpWindowUpdateAllowed(1, 1, 0xffffffff, 0xffffffff) {
		t.Fatal("wrapped send-window update was rejected")
	}
}

// TestTCPSegmentAcceptability verifies receive-window tests across ordinary
// and wrapped sequence ranges.
func TestTCPSegmentAcceptability(t *testing.T) {
	if !tcpSegmentAcceptable(100, 0, 100, 0) || tcpSegmentAcceptable(100, 1, 100, 0) {
		t.Fatal("zero-window segment acceptance is incorrect")
	}
	if !tcpSegmentAcceptable(99, 2, 100, 10) {
		t.Fatal("segment overlapping the left window edge was rejected")
	}
	if tcpSegmentAcceptable(110, 1, 100, 10) {
		t.Fatal("segment beyond the right window edge was accepted")
	}
	if !tcpSegmentAcceptable(0xfffffff8, 16, 0, 32) {
		t.Fatal("wrapped segment overlapping the receive window was rejected")
	}
}

// TestTCPWindowScalingRequiresPeerOption verifies that receive windows are not
// shifted unless the SYN-ACK also advertises window scaling.
func TestTCPWindowScalingRequiresPeerOption(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.disableTCPWindowScale = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7999))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs != 0
	})
	link.mu.Lock()
	window := link.lastClientWindow
	link.mu.Unlock()
	if window != 65535 {
		t.Fatalf("unscaled receive window = %d, want 65535", window)
	}
	if connection.(*TCPConn).peerWindowScaling {
		t.Fatal("window scaling was enabled without the peer option")
	}
}

// TestTCPRejectsOutOfWindowACK verifies that ACK and window fields are ignored
// until SEG.SEQ passes the RFC receive-window test.
func TestTCPRejectsOutOfWindowACK(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7998))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write([]byte("unacknowledged")); err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[tcpConnection.key.local.Port()]
		return peer != nil && peer.highestClientEnd != peer.clientNext
	})
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	validSequence, acknowledgement := peer.serverNext, peer.highestClientEnd
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), validSequence+300000, acknowledgement, tcpFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	tcpConnection.mu.Lock()
	retained := len(tcpConnection.sendBuffer)
	tcpConnection.mu.Unlock()
	if retained == 0 {
		t.Fatal("out-of-window segment acknowledged the send buffer")
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), validSequence, acknowledgement, tcpFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		tcpConnection.mu.Lock()
		defer tcpConnection.mu.Unlock()
		return len(tcpConnection.sendBuffer) == 0
	})
}

// TestTCPConcurrentSlidingWindowAndHalfClose verifies tuple isolation,
// multiple in-flight segments, receive reordering, and FIN behavior.
func TestTCPConcurrentSlidingWindowAndHalfClose(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.holdTCPACKs = 3
	link.reverseTCPResponses = true

	connections := make([]net.Conn, 2)
	for index := range connections {
		connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, uint16(8000+index)))
		if err != nil {
			t.Fatal(err)
		}
		connections[index] = connection
		defer connection.Close()
	}
	if connections[0].LocalAddr().String() == connections[1].LocalAddr().String() {
		t.Fatal("TCP connections received the same ephemeral port")
	}

	payload := bytes.Repeat([]byte("sliding-window-"), 600)
	var wait sync.WaitGroup
	for _, connection := range connections {
		connection := connection
		wait.Add(1)
		go func() {
			defer wait.Done()
			if deadlineErr := connection.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
				t.Error(deadlineErr)
				return
			}
			if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
				t.Errorf("TCP Write = %d, %v", n, writeErr)
				return
			}
			response := make([]byte, len(payload))
			if _, readErr := io.ReadFull(connection, response); readErr != nil {
				t.Error(readErr)
				return
			}
			if !bytes.Equal(response, payload) {
				t.Error("TCP echo payload mismatch")
				return
			}
			closer, ok := connection.(interface{ CloseWrite() error })
			if !ok {
				t.Error("TCP connection has no CloseWrite")
				return
			}
			if closeErr := closer.CloseWrite(); closeErr != nil {
				t.Error(closeErr)
				return
			}
			one := make([]byte, 1)
			if n, readErr := connection.Read(one); n != 0 || readErr != io.EOF {
				t.Errorf("read after peer FIN = %d, %v", n, readErr)
			}
		}()
	}
	wait.Wait()
	link.mu.Lock()
	maximumBurst := link.maximumTCPBurst
	clientSACKs := link.clientSACKs
	link.mu.Unlock()
	if maximumBurst < 3 {
		t.Fatalf("maximum unacknowledged TCP burst = %d, want at least 3", maximumBurst)
	}
	if clientSACKs == 0 {
		t.Fatal("client did not report reversed receive ranges with SACK")
	}
}

// TestTCPRetransmitsLostHandshakeAndData drops the first SYN and data segment.
func TestTCPRetransmitsLostHandshakeAndData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPSYN = 1
	link.dropTCPData = 1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
	payload := []byte("retransmitted payload")
	if n, err := connection.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("response = %q", response)
	}
}

// TestTCPWriteReturnsAfterBuffering verifies that Write does not wait for a
// peer acknowledgement once the bounded send buffer accepts the payload.
func TestTCPWriteReturnsAfterBuffering(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 100
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8084))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	started := time.Now()
	if n, writeErr := connection.Write([]byte("buffered without ACK")); writeErr != nil || n != 20 {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
		t.Fatalf("Write waited %v for peer acknowledgement", elapsed)
	}
}

// TestTCPSendBufferDeadlineIsRecoverable verifies bounded partial writes and
// that a write deadline does not reset the TCP stream.
func TestTCPSendBufferDeadlineIsRecoverable(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 1000
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8085))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, tcpSendCapacity+1)
	n, err := connection.Write(payload)
	if n != tcpSendCapacity || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("bounded Write = %d, %v, want %d, os.ErrDeadlineExceeded", n, err, tcpSendCapacity)
	}
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	acknowledgement := peer.highestClientEnd
	peer.clientNext = acknowledgement
	serverSequence := peer.serverNext
	link.dropTCPData = 0
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), serverSequence, acknowledgement, tcpFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err = connection.Write(payload[tcpSendCapacity:]); n != 1 || err != nil {
		t.Fatalf("Write after timeout = %d, %v", n, err)
	}
}

// TestTCPSACKRecoversMultipleSegments verifies that three duplicate SACK ACKs
// recover a leading hole without waiting for the retransmission timeout.
func TestTCPSACKRecoversMultipleSegments(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8081))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte("selective-ack-"), 600)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("SACK recovery payload mismatch")
	}
	link.mu.Lock()
	recovered := link.sackRecovery
	link.mu.Unlock()
	if !recovered {
		t.Fatal("peer did not observe selective-ack hole recovery")
	}
}

// TestTCPSACKRecoversMultipleHolesPerRound verifies that disjoint losses below
// a SACK edge are retransmitted without requiring one RTT per hole.
func TestTCPSACKRecoversMultipleHolesPerRound(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPOrdinals = map[int]bool{1: true, 3: true}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8087))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("multiple-sack-holes-"), 700)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("multiple-hole recovery payload mismatch")
	}
	link.mu.Lock()
	recoveries := link.sackRecoveries
	link.mu.Unlock()
	if recoveries < 2 {
		t.Fatalf("SACK hole recoveries = %d, want at least 2", recoveries)
	}
}

// TestTCPTailLossProbe verifies that a lone lost tail is retried before RTO
// once the connection has an RTT sample.
func TestTCPTailLossProbe(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8082))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	for _, payload := range [][]byte{[]byte("warmup"), []byte("lost tail")} {
		if bytes.Equal(payload, []byte("lost tail")) {
			link.mu.Lock()
			link.dropTCPData = 1
			link.mu.Unlock()
		}
		if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
			t.Fatalf("Write = %d, %v", n, writeErr)
		}
		response := make([]byte, len(payload))
		if _, err = io.ReadFull(connection, response); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(response, payload) {
			t.Fatal("tail-loss response mismatch")
		}
	}
	link.mu.Lock()
	retransmitted, delay := link.tailRetransmission, link.tailRecoveryDelay
	link.mu.Unlock()
	if !retransmitted || delay >= tcpInitialRTO {
		t.Fatalf("tail retransmission = %v after %v, want before initial RTO %v", retransmitted, delay, tcpInitialRTO)
	}
}

// TestTCPPathMTUReduction verifies that Packet Too Big resegments outstanding
// data and keeps an established stream alive.
func TestTCPPathMTUReduction(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.tcpPathMTU = 1000
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8083))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0x6d}, 1300)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("PMTU TCP response mismatch")
	}
	link.mu.Lock()
	injected, maximum := link.pathMTUInjected, link.postPathMTUMaximum
	link.mu.Unlock()
	if !injected || maximum > int(link.tcpPathMTU) {
		t.Fatalf("Packet Too Big injected = %v, later maximum packet = %d, PMTU = %d", injected, maximum, link.tcpPathMTU)
	}
}

func TestTCPPathMTUReductionNotifiesSiblingFlows(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.37"), netip.MustParseAddr("192.0.2.38"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.tcpPathMTU = 1000
	link.mu.Unlock()
	first, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8092))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8093))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = first.SetDeadline(time.Now().Add(3 * time.Second))
	_ = second.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, first, bytes.Repeat([]byte{0x41}, 1300))
	link.mu.Lock()
	link.postPathMTUMaximum = 0
	link.mu.Unlock()
	writeAndReadTCPEcho(t, second, bytes.Repeat([]byte{0x42}, 1100))
	link.mu.Lock()
	maximum := link.postPathMTUMaximum
	link.mu.Unlock()
	if maximum > 1000 {
		t.Fatalf("sibling TCP flow emitted %d-byte packet after destination PMTU update", maximum)
	}
}

func TestTCPMTUIncreaseRaisesMSS(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.31"), netip.MustParseAddr("192.0.2.32"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	localPrefix := netip.PrefixFrom(link.local, 32)
	if err := stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{localPrefix}, MTU: 1280}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8089))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	link.mu.Lock()
	link.maximumTCPData = 0
	link.mu.Unlock()
	if err = stack.UpdateConfig(Config{LocalAddresses: []netip.Prefix{localPrefix}, MTU: 2000}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	payload := bytes.Repeat([]byte{0x4d}, 1280)
	writeAndReadTCPEcho(t, connection, payload)
	link.mu.Lock()
	maximum := link.maximumTCPData
	link.mu.Unlock()
	if maximum != len(payload) {
		t.Fatalf("TCP payload after MTU increase = %d, want %d", maximum, len(payload))
	}
}

func TestTCPPathMTUExpiryRaisesMSS(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.35"), netip.MustParseAddr("192.0.2.36"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	if !stack.observePathMTU(link.remote, 1000) {
		t.Fatal("failed to install test PMTU")
	}
	stack.pathMTUMu.Lock()
	entry := stack.pathMTU[link.remote]
	entry.updated = time.Now().Add(-pathMTULifetime + 100*time.Millisecond)
	stack.pathMTU[link.remote] = entry
	stack.pathMTUMu.Unlock()

	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8090))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x31}, 1100))
	link.mu.Lock()
	before := link.maximumTCPData
	link.maximumTCPData = 0
	link.mu.Unlock()
	if before > 960 {
		t.Fatalf("TCP payload before PMTU expiry = %d, want <= 960", before)
	}

	payload := bytes.Repeat([]byte{0x32}, 1200)
	deadline := time.Now().Add(time.Second)
	after := 0
	for after != len(payload) && time.Now().Before(deadline) {
		link.mu.Lock()
		link.maximumTCPData = 0
		link.mu.Unlock()
		writeAndReadTCPEcho(t, connection, payload)
		link.mu.Lock()
		after = link.maximumTCPData
		link.mu.Unlock()
		if after != len(payload) {
			time.Sleep(time.Millisecond)
		}
	}
	if after != len(payload) {
		t.Fatalf("TCP payload after PMTU expiry = %d, want %d", after, len(payload))
	}
}

func TestTCPRouteRemovalReportsNetworkUnreachable(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.33"), netip.MustParseAddr("192.0.2.34"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8091))
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(link.local, 32)},
		Routes:         []Route{},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Read(make([]byte, 1)); !errors.Is(err, syscall.ENETUNREACH) {
		t.Fatalf("Read after route removal = %v, want ENETUNREACH", err)
	}
}

// TestTCPSilentPathMTUBlackHole verifies that repeated RTOs reduce the MSS
// when an IPv4 path silently drops oversized packets instead of returning
// Fragmentation Needed.
func TestTCPSilentPathMTUBlackHole(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPAbove = 1280
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8086))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
	payload := bytes.Repeat([]byte{0x7a}, 1300)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("black-hole recovery payload mismatch")
	}
	if mtu := stack.mtuFor(link.remote); mtu != 1280 {
		t.Fatalf("inferred PMTU = %d, want 1280", mtu)
	}
}

// TestTCPTimeoutErrorPreservesSoftFailure verifies that a validated ICMP
// failure remains observable when retransmission ultimately gives up.
func TestTCPTimeoutErrorPreservesSoftFailure(t *testing.T) {
	want := ICMPError{Reporter: netip.MustParseAddr("192.0.2.254"), Type: 3, Code: 1}
	var gotICMP ICMPError
	if got := tcpTimeoutError(want); !errors.As(got, &gotICMP) || gotICMP.Reporter != want.Reporter || gotICMP.Type != want.Type || gotICMP.Code != want.Code {
		t.Fatalf("timeout error = %v, want %v", got, want)
	}
	if got := tcpTimeoutError(nil); got != os.ErrDeadlineExceeded {
		t.Fatalf("timeout error = %v, want os.ErrDeadlineExceeded", got)
	}
}

// TestRACKMarksOlderTransmission verifies time-based loss inference without
// relying on wall-clock scheduling in the packet-link tests.
func TestRACKMarksOlderTransmission(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, sentAt: base},
		{sequence: 200, end: 300, sentAt: base.Add(20 * time.Millisecond)},
	}
	_, _, latest := applyTCPSACK(outstanding, []tcpSACKBlock{{left: 200, right: 300}})
	markRACKLoss(outstanding, latest, 10*time.Millisecond)
	if !outstanding[0].rackLost || outstanding[1].rackLost {
		t.Fatalf("RACK loss state = [%v %v]", outstanding[0].rackLost, outstanding[1].rackLost)
	}
}

// TestTCPSequenceWrapAndSACK verifies wrapped sequence comparisons and SACK
// validation across the 32-bit boundary.
func TestTCPSequenceWrapAndSACK(t *testing.T) {
	acknowledged, sendNext := uint32(0xfffffff0), uint32(0x30)
	options := make([]byte, 10)
	options[0], options[1] = 5, 10
	binary.BigEndian.PutUint32(options[2:6], 0)
	binary.BigEndian.PutUint32(options[6:10], 0x20)
	blocks := parseTCPSACKOptions(options, acknowledged, sendNext)
	if len(blocks) != 1 || blocks[0].left != 0 || blocks[0].right != 0x20 {
		t.Fatalf("wrapped SACK blocks = %#v", blocks)
	}
	if !tcpSequenceLess(0xfffffff0, 0x10) || !tcpSequenceGreater(0x10, 0xfffffff0) {
		t.Fatal("wrapped sequence ordering failed")
	}
}

// TestTCPConnectionResourceLimit verifies the optional embedding limit.
func TestTCPConnectionResourceLimit(t *testing.T) {
	const maximumConnections = 3
	local := netip.MustParseAddr("192.0.2.1")
	stack, err := New(Config{
		LocalAddresses:    []netip.Prefix{netip.PrefixFrom(local, 32)},
		MTU:               1400,
		MaxTCPConnections: maximumConnections,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	remote := netip.MustParseAddr("192.0.2.2")
	stack.mu.Lock()
	for index := 0; index < maximumConnections; index++ {
		port := uint16(dynamicPortFirst + index)
		key := tcpKey{local: netip.AddrPortFrom(local, port), remote: netip.AddrPortFrom(remote, uint16(index+1))}
		stack.tcp[key] = &TCPConn{}
	}
	stack.mu.Unlock()
	_, err = stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, 443))
	if !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("DialTCP error = %v, want ErrResourceLimit", err)
	}
	stack.mu.Lock()
	stack.tcp = make(map[tcpKey]*TCPConn)
	stack.mu.Unlock()
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestTCPConcurrentCloseAndDeadlines exercises socket state broadcasts while
// Read, Write, deadline changes, and Close race at the public API boundary.
func TestTCPConcurrentCloseAndDeadlines(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 1000
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9106))
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(3)
	go func() {
		defer wait.Done()
		_, _ = connection.Write(make([]byte, tcpSendCapacity*2))
	}()
	go func() {
		defer wait.Done()
		_, _ = connection.Read(make([]byte, 1))
	}()
	go func() {
		defer wait.Done()
		for index := 0; index < 100; index++ {
			_ = connection.SetDeadline(time.Now().Add(time.Duration(index+1) * time.Millisecond))
		}
	}()
	time.Sleep(5 * time.Millisecond)
	_ = connection.Close()
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent socket operations did not terminate")
	}
}

// TestTCPPortReuseByFourTuple verifies that TCP port ownership is scoped to a
// complete tuple rather than reserving a local port across every destination.
func TestTCPPortReuseByFourTuple(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	first, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9100))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	firstPort := first.LocalAddr().(*net.TCPAddr).Port
	stack.mu.Lock()
	stack.nextPort[0].dynamic = uint16(firstPort - dynamicPortFirst)
	stack.mu.Unlock()
	second, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9101))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.LocalAddr().(*net.TCPAddr).Port != firstPort {
		t.Fatalf("second local port = %v, want reused %d", second.LocalAddr(), firstPort)
	}
	if stats := stack.Stats(); stats.ActiveTCPConnections != 2 {
		t.Fatalf("active TCP connections = %d, want 2", stats.ActiveTCPConnections)
	}
}

// TestTCPDelayedACK verifies ACK-every-two-segments and the bounded timer for
// a lone in-order segment.
func TestTCPDelayedACK(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9102))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs != 0
	})
	deliver := func(payload byte) {
		link.mu.Lock()
		peer := link.tcp[tcpConnection.key.local.Port()]
		sequence, acknowledgement := peer.serverNext, peer.clientNext
		peer.serverNext++
		link.mu.Unlock()
		if err := link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 65535, nil, []byte{payload}); err != nil {
			t.Fatal(err)
		}
	}
	link.mu.Lock()
	baseline := link.clientACKs
	link.mu.Unlock()
	deliver(1)
	deliver(2)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= baseline+1
	})
	link.mu.Lock()
	afterPair := link.clientACKs
	link.mu.Unlock()
	if afterPair != baseline+1 {
		t.Fatalf("ACKs for two segments = %d, want 1", afterPair-baseline)
	}
	deliver(3)
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs >= afterPair+1
	})
}

// TestTCPZeroWindowProbeCarriesData verifies that persist recovery probes one
// byte of pending sequence space instead of relying on an empty ACK response.
func TestTCPZeroWindowProbeCarriesData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9105))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	link.mu.Lock()
	link.echoTCP = false
	link.mu.Unlock()
	if n, writeErr := connection.Write([]byte("probe")); writeErr != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	select {
	case packet := <-link.outbound:
		parsed, ok := parseIPPacket(packet)
		if !ok || parsed.protocol != protocolTCP {
			t.Fatalf("invalid persist packet: %x", packet)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		if data := parsed.payload[headerSize:]; !bytes.Equal(data, []byte("p")) {
			t.Fatalf("persist payload = %q, want %q", data, "p")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for persist probe")
	}
	if probes := stack.Stats().TCPZeroWindowProbes; probes != 1 {
		t.Fatalf("zero-window probes = %d, want 1", probes)
	}
}

// TestTCPTimestampsPAWSAndMSS verifies timestamp negotiation, PAWS rejection,
// and data segmentation that leaves room for the negotiated option.
func TestTCPTimestampsPAWSAndMSS(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.timestampTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9103))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	if !tcpConnection.peerTimestamp {
		t.Fatal("TCP timestamps were not negotiated")
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x4a}, 1300)
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(connection, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}

	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	oldTimestamp := peer.timestamp - 1
	link.mu.Unlock()
	stale := buildTestTCP(link.remote, link.local, tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 65535, tcpTimestampOptions(oldTimestamp, 0), []byte("stale"))
	if err = writeTestPacket(stack, stale); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, readErr := connection.Read(make([]byte, 5)); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("PAWS stale read = %d, %v", n, readErr)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	link.mu.Lock()
	peer.serverNext += 5
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 65535, nil, []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	fresh := make([]byte, 5)
	if _, err = io.ReadFull(connection, fresh); err != nil || string(fresh) != "fresh" {
		t.Fatalf("fresh timestamp read = %q, %v", fresh, err)
	}
}

// TestTCPECNNegotiation verifies ECT marking and both halves of the classic
// CE/ECE/CWR feedback handshake.
func TestTCPECNNegotiation(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9104))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if !connection.(*TCPConn).peerECN {
		t.Fatal("ECN was not negotiated")
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	link.mu.Lock()
	baselineECE, baselineCWR := link.clientECEs, link.clientCWRs
	link.markTCPCE = true
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("marked CE"))
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientECEs > baselineECE
	})
	link.mu.Lock()
	link.sendTCPECE = true
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("echo congestion"))
	link.mu.Lock()
	link.sendTCPECE = false
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("send CWR"))
	link.mu.Lock()
	ectPackets, cwrPackets := link.clientECTPackets, link.clientCWRs
	link.mu.Unlock()
	if ectPackets < 3 {
		t.Fatalf("ECT data packets = %d, want at least 3", ectPackets)
	}
	if cwrPackets <= baselineCWR {
		t.Fatal("client did not acknowledge ECE with CWR")
	}
}

// TestTCPRetransmissionsAreNotECT verifies RFC 3168's requirement that a
// retransmitted data segment cannot create a new ambiguous CE indication.
func TestTCPRetransmissionsAreNotECT(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9107))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	writeAndReadTCPEcho(t, connection, []byte("retransmitted without ECT"))
	link.mu.Lock()
	initialECT, retransmittedECT := link.clientECTPackets, link.clientRetransmittedECT
	link.mu.Unlock()
	if initialECT == 0 {
		t.Fatal("initial ECN-capable data was not marked ECT")
	}
	if retransmittedECT != 0 {
		t.Fatalf("ECT-marked retransmissions = %d, want 0", retransmittedECT)
	}
}

// TestTCPECNSYNFallback verifies that an ECN-intolerant path cannot prevent
// connection establishment after the first SYN timeout.
func TestTCPECNSYNFallback(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.dropECNSYN = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9108))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if connection.(*TCPConn).peerECN {
		t.Fatal("fallback connection unexpectedly negotiated ECN")
	}
	link.mu.Lock()
	legacySYNs := link.legacySYNSends
	link.mu.Unlock()
	if legacySYNs == 0 {
		t.Fatal("connection did not retry with a legacy SYN")
	}
}

// TestTCPRejectsUnboundPort verifies the active-only stack's RST response.
func TestTCPRejectsUnboundPort(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	syn := buildTestTCP(link.remote, link.local, 40000, 9000, 100, 0, tcpFlagSYN, 65535, nil, nil)
	if err := writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-link.outbound:
		parsed, ok := parseIPPacket(response)
		if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13] != tcpFlagRST|tcpFlagACK || binary.BigEndian.Uint32(parsed.payload[8:12]) != 101 {
			t.Fatalf("invalid TCP reset: %x", response)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP reset")
	}
}

func TestTCPReservedHeaderBitsAreDropped(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.92")
	remote := netip.MustParseAddr("198.51.100.92")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	packet := buildTestTCP(remote, local, 50000, 50001, 1, 0, tcpFlagSYN, 65535, nil, nil)
	tcp := packet[20:]
	tcp[12] |= 0x02
	tcp[16], tcp[17] = 0, 0
	binary.BigEndian.PutUint16(tcp[16:18], transportChecksum(remote, local, protocolTCP, tcp))
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 1 {
		t.Fatalf("reserved TCP header bits dropped packets = %d, want 1", dropped)
	}
	select {
	case response := <-stack.outbound:
		t.Fatalf("reserved TCP header produced a response: %x", response)
	default:
	}
}

// FuzzTCPOptions verifies bounded option parsing and wrapped SACK validation.
func FuzzTCPOptions(f *testing.F) {
	f.Add([]byte{2, 4, 0x05, 0xb4, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}, uint32(100), uint32(200))
	f.Add([]byte{5, 10, 0, 0, 0, 120, 0, 0, 0, 160}, uint32(100), uint32(200))
	f.Fuzz(func(t *testing.T, options []byte, acknowledged, sendNext uint32) {
		if len(options) > 256 {
			options = options[:256]
		}
		_, _, _, _, _, _ = parseTCPOptions(options, 536, 1360)
		_, _, _ = parseTCPTimestamp(options)
		_ = parseTCPSACKOptions(options, acknowledged, sendNext)
	})
}

func TestExplicitTCPSourceAndLocalLoopback(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.21")
	serverAddress := netip.MustParseAddr("192.0.2.22")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{
		netip.PrefixFrom(clientAddress, 32),
		netip.PrefixFrom(serverAddress, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	udpListener, err := stack.ListenUDP(context.Background(), `udp`, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer udpListener.Close()
	udpRemote := udpListener.LocalAddr().(*net.UDPAddr).AddrPort()
	udpSource := netip.AddrPortFrom(clientAddress, 46000)
	udpClient, err := stack.DialUDP(context.Background(), "udp", udpSource, udpRemote)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()
	if _, err = udpClient.Write([]byte("udp-loopback")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	n, source, err := udpListener.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "udp-loopback" || source.(*net.UDPAddr).AddrPort() != udpSource {
		t.Fatalf("UDP loopback = %q from %v", buffer[:n], source)
	}

	tcpListener, err := stack.ListenTCP(context.Background(), `tcp`, netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	tcpSource := netip.AddrPortFrom(clientAddress, 46001)
	tcpClient, err := stack.DialTCP(context.Background(), "tcp", tcpSource, tcpListener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer tcpClient.Close()
	tcpServer, err := tcpListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpServer.Close()
	if got := tcpClient.LocalAddr().(*net.TCPAddr).AddrPort(); got != tcpSource {
		t.Fatalf("DialTCP local endpoint = %v, want %v", got, tcpSource)
	}
	if _, err = tcpClient.Write([]byte("tcp-loopback")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(tcpServer, buffer[:12]); err != nil {
		t.Fatal(err)
	}
	if string(buffer[:12]) != "tcp-loopback" {
		t.Fatalf("TCP loopback = %q", buffer[:12])
	}
	if stack.Stats().LoopbackPackets == 0 {
		t.Fatal("local traffic did not use the loopback path")
	}
	select {
	case packet := <-stack.outbound:
		t.Fatalf("local traffic escaped to the link: %x", packet)
	default:
	}
}

func TestTCPKeepAliveIdleTimeoutAndSocketOptions(t *testing.T) {
	t.Run("keepalive", func(t *testing.T) {
		link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.60"), netip.MustParseAddr("198.51.100.60"))
		link.mu.Lock()
		link.echoTCP = true
		link.mu.Unlock()
		connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
		if err != nil {
			t.Fatal(err)
		}
		tcpConnection := connection.(*TCPConn)
		if err = tcpConnection.SetKeepAlivePeriod(10 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetKeepAlivePeriod(0); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("SetKeepAlivePeriod(0) = %v, want EINVAL", err)
		}
		if err = tcpConnection.SetKeepAliveConfig(KeepAliveConfig{Idle: 15 * time.Millisecond, Interval: 10 * time.Millisecond, Count: 2}); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetKeepAlive(true); err != nil {
			t.Fatal(err)
		}
		_, err = tcpConnection.Read(make([]byte, 1))
		if !errors.Is(err, syscall.ETIMEDOUT) {
			t.Fatalf("keepalive terminal error = %v, want ETIMEDOUT", err)
		}
		if stack.Stats().TCPKeepAliveProbes != 2 {
			t.Fatalf("keepalive probes = %d, want 2", stack.Stats().TCPKeepAliveProbes)
		}
	})

	t.Run("idle and options", func(t *testing.T) {
		link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.61"), netip.MustParseAddr("198.51.100.61"))
		link.mu.Lock()
		link.echoTCP = true
		link.mu.Unlock()
		connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8081))
		if err != nil {
			t.Fatal(err)
		}
		tcpConnection := connection.(*TCPConn)
		if err = tcpConnection.SetNoDelay(false); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetReadBuffer(4096); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetWriteBuffer(8192); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetReadBuffer(0); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("SetReadBuffer(0) = %v, want EINVAL", err)
		}
		if err = tcpConnection.SetReadBuffer(32 * 1024 * 1024); err != nil {
			t.Fatalf("large SetReadBuffer = %v", err)
		}
		if err = tcpConnection.SetWriteBuffer(32 * 1024 * 1024); err != nil {
			t.Fatalf("large SetWriteBuffer = %v", err)
		}
		if err = tcpConnection.SetIdleTimeout(20 * time.Millisecond); err != nil {
			t.Fatal(err)
		}
		_, err = tcpConnection.Read(make([]byte, 1))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("idle timeout error = %v, want os.ErrDeadlineExceeded", err)
		}
	})
}

func TestTCPCloseQueuesFIN(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.70"), netip.MustParseAddr("198.51.100.70"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8090))
	if err != nil {
		t.Fatal(err)
	}
	port := connection.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[port]
		return peer != nil && peer.finSent
	})
}

func TestTCPSetLingerAbortiveClose(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.71"), netip.MustParseAddr("198.51.100.71"))
	link.mu.Lock()
	link.echoTCP = true
	link.dropTCPData = 1
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8091))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	port := tcpConnection.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	if _, err = tcpConnection.Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetLinger(-1); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetLinger after Close = %v, want net.ErrClosed", err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[port]
		return peer != nil && peer.resetSeen
	})
	waitFor(t, time.Second, func() bool { return stack.Stats().ActiveTCPConnections == 0 })
}

func TestTCPSetLingerWaitsAndTimesOut(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.72"), netip.MustParseAddr("198.51.100.72"))
	link.mu.Lock()
	link.echoTCP = true
	link.dropTCPFIN = 100
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8092))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	port := tcpConnection.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	if err = tcpConnection.SetLinger(1); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("positive-linger Close duration = %v, want about 1s", elapsed)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[port]
		return peer != nil && peer.resetSeen
	})
}

func TestTCPLingerDurationSaturates(t *testing.T) {
	if duration := tcpLingerDuration(1); duration != time.Second {
		t.Fatalf("one-second linger duration = %v", duration)
	}
	if strconv.IntSize == 64 {
		const maximum = time.Duration(1<<63 - 1)
		if duration := tcpLingerDuration(int(^uint(0) >> 1)); duration != maximum {
			t.Fatalf("overflowing linger duration = %v, want %v", duration, maximum)
		}
	}
}

func BenchmarkTCPStreamRoundTrip(b *testing.B) {
	link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.240"), netip.MustParseAddr("198.51.100.240"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8443))
	if err != nil {
		b.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 32*1024)
	response := make([]byte, len(payload))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err = connection.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err = io.ReadFull(connection, response); err != nil {
			b.Fatal(err)
		}
	}
}
