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

func TestTCPPassiveCloserSkipsTimeWait(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.181")
	serverAddress := netip.MustParseAddr("192.0.2.182")
	client, server := newStackPair(t, clientAddress, serverAddress, 1500)
	_ = newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	clientConnection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	serverConnection := <-accepted
	if serverConnection == nil {
		t.Fatal("accept failed")
	}
	defer clientConnection.Close()
	defer serverConnection.Close()
	if err = serverConnection.(*TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = clientConnection.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := clientConnection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("client FIN read = %d, %v", n, readErr)
	}
	if err = clientConnection.(*TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = serverConnection.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := serverConnection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("server FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return client.Stats().ActiveTCPConnections == 0 })
	if active := server.Stats().ActiveTCPConnections; active != 1 {
		t.Fatalf("active closer connections = %d, want TIME-WAIT actor", active)
	}
}

func TestTCPPassiveHandshakeChallengeAndResetResponses(t *testing.T) {
	for _, test := range []struct {
		name      string
		segment   tcpSegment
		wantFlags byte
		wantSeq   uint32
		wantACK   uint32
	}{
		{
			name: "in-window RST", segment: tcpSegment{sequence: 102, flags: tcpFlagRST},
			wantFlags: tcpFlagACK, wantSeq: 1001, wantACK: 101,
		},
		{
			name: "unacceptable ACK", segment: tcpSegment{sequence: 101, acknowledgement: 999, flags: tcpFlagACK},
			wantFlags: tcpFlagRST, wantSeq: 999,
		},
		{
			name: "out-of-window sequence", segment: tcpSegment{sequence: 101 + 65535, acknowledgement: 1001, flags: tcpFlagACK},
			wantFlags: tcpFlagACK, wantSeq: 1001, wantACK: 101,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.71")
			remote := netip.MustParseAddr("198.51.100.71")
			link, stack := newTestStack(t, local, remote)
			connection := newTCPConn(stack, "tcp4", tcpKey{
				local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
			}, 1400)
			connection.passive = true
			result := make(chan error, 1)
			go func() {
				result <- connection.passiveHandshake(tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535}, 1000)
			}()
			readPacket := func() []byte {
				select {
				case packet := <-link.outbound:
					return packet
				case <-time.After(time.Second):
					t.Fatal("timed out waiting for passive-handshake response")
					return nil
				}
			}
			_ = readPacket() // initial SYN-ACK
			connection.inbound <- test.segment
			response := readPacket()
			parsed, ok := parseIPPacket(response)
			if !ok || parsed.protocol != protocolTCP || len(parsed.payload) < tcpHeaderSize {
				t.Fatalf("passive-handshake response = %x", response)
			}
			tcp := parsed.payload
			if tcp[13] != test.wantFlags || binary.BigEndian.Uint32(tcp[4:8]) != test.wantSeq || binary.BigEndian.Uint32(tcp[8:12]) != test.wantACK {
				t.Fatalf("passive-handshake TCP response flags=%02x seq=%d ack=%d", tcp[13], binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12]))
			}
			connection.abortWithoutReset(net.ErrClosed)
			select {
			case <-result:
			case <-time.After(time.Second):
				t.Fatal("passive handshake did not stop")
			}
		})
	}
}

func TestTCPPassiveHandshakeAcceptsOutOfOrderFinalACKData(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.72")
	remote := netip.MustParseAddr("198.51.100.72")
	link, stack := newTestStack(t, local, remote)
	defer stack.Close()
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
	}, 1400)
	connection.passive = true
	result := make(chan error, 1)
	go func() {
		result <- connection.passiveHandshake(tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535}, 1000)
	}()
	select {
	case <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SYN-ACK")
	}
	finalACK := tcpSegment{
		sequence: 102, acknowledgement: 1001, flags: tcpFlagACK, window: 65535,
		payload: []byte{0x42},
	}
	connection.inbound <- finalACK
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("acceptable out-of-order final ACK did not complete handshake")
	}
	select {
	case queued := <-connection.inbound:
		if queued.sequence != finalACK.sequence || !bytes.Equal(queued.payload, finalACK.payload) {
			t.Fatalf("queued final ACK = seq %d payload %x", queued.sequence, queued.payload)
		}
	default:
		t.Fatal("out-of-order final ACK data was not queued for established processing")
	}
}

func TestTCPPassiveHandshakeECNFallback(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.73")
	remote := netip.MustParseAddr("198.51.100.73")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
	}, 1400)
	connection.passive = true
	result := make(chan error, 1)
	go func() {
		result <- connection.passiveHandshake(tcpSegment{
			sequence: 100, flags: tcpFlagSYN | tcpFlagECE | tcpFlagCWR, window: 65535,
		}, 1000)
	}()
	readFlags := func() byte {
		select {
		case packet := <-link.outbound:
			parsed, ok := parseIPPacket(packet)
			if !ok || len(parsed.payload) < tcpHeaderSize {
				t.Fatalf("passive-handshake response = %x", packet)
			}
			return parsed.payload[13]
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for passive-handshake response")
			return 0
		}
	}
	if flags := readFlags(); flags&tcpFlagECE == 0 {
		t.Fatalf("initial ECN SYN-ACK flags = %02x", flags)
	}
	connection.inbound <- tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535}
	if flags := readFlags(); flags&tcpFlagECE != 0 {
		t.Fatalf("fallback SYN-ACK retained ECE: flags=%02x", flags)
	}
	connection.inbound <- tcpSegment{sequence: 101, acknowledgement: 1001, flags: tcpFlagACK, window: 65535}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback final ACK did not complete the passive handshake")
	}
	if connection.peerECN {
		t.Fatal("fallback passive connection retained ECN negotiation")
	}
}

func TestTCPPassiveRetransmittedSYNUpdatesTimestampEcho(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.77")
	remote := netip.MustParseAddr("198.51.100.77")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
	}, 1400)
	connection.passive = true
	result := make(chan error, 1)
	go func() {
		result <- connection.passiveHandshake(tcpSegment{
			sequence: 100, flags: tcpFlagSYN, window: 65535, options: tcpTimestampOptions(100, 0),
		}, 1000)
	}()
	readTimestampEcho := func() uint32 {
		select {
		case packet := <-link.outbound:
			parsed, ok := parseIPPacket(packet)
			if !ok || len(parsed.payload) < tcpHeaderSize {
				t.Fatalf("passive SYN-ACK = %x", packet)
			}
			headerSize := int(parsed.payload[12]>>4) * 4
			_, echo, present := parseTCPTimestamp(parsed.payload[tcpHeaderSize:headerSize])
			if !present {
				t.Fatal("passive SYN-ACK omitted negotiated timestamp")
			}
			return echo
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for timestamp SYN-ACK")
			return 0
		}
	}
	if echo := readTimestampEcho(); echo != 100 {
		t.Fatalf("initial SYN-ACK TSecr = %d, want 100", echo)
	}
	connection.inbound <- tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535, options: tcpTimestampOptions(200, 0)}
	if echo := readTimestampEcho(); echo != 200 {
		t.Fatalf("retransmitted SYN-ACK TSecr = %d, want 200", echo)
	}
	connection.inbound <- tcpSegment{
		sequence: 101, acknowledgement: 1001, flags: tcpFlagACK, window: 65535,
		options: tcpTimestampOptions(300, 1),
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timestamp handshake did not complete")
	}
}

func TestTCPHandshakeMaintenanceDoesNotConsumeRTOBudget(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.75")
	remote := netip.MustParseAddr("198.51.100.75")
	t.Run("active PMTU updates", func(t *testing.T) {
		link, stack := newTestStack(t, local, remote)
		connection := newTCPConn(stack, "tcp4", tcpKey{
			local: netip.AddrPortFrom(local, 45000), remote: netip.AddrPortFrom(remote, 8080),
		}, 1400)
		result := make(chan error, 1)
		go func() { result <- connection.handshake(1000) }()
		read := func() byte {
			select {
			case packet := <-link.outbound:
				parsed, ok := parseIPPacket(packet)
				if !ok || len(parsed.payload) < tcpHeaderSize {
					t.Fatalf("active-handshake packet = %x", packet)
				}
				return parsed.payload[13]
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for active SYN")
				return 0
			}
		}
		if flags := read(); flags&(tcpFlagECE|tcpFlagCWR) != tcpFlagECE|tcpFlagCWR {
			t.Fatalf("initial SYN flags = %02x", flags)
		}
		for index := 0; index < tcpActiveSYNMaximumAttempts+1; index++ {
			connection.pathMTUUpdate <- struct{}{}
			if flags := read(); flags&(tcpFlagECE|tcpFlagCWR) != tcpFlagECE|tcpFlagCWR {
				t.Fatalf("maintenance SYN %d flags = %02x", index, flags)
			}
		}
		// The original RTO still fires. It alone starts the legacy ECN fallback
		// and must not fail merely because maintenance retransmitted the SYN.
		if flags := read(); flags&(tcpFlagECE|tcpFlagCWR) != 0 {
			t.Fatalf("RTO fallback SYN flags = %02x", flags)
		}
		connection.inbound <- tcpSegment{
			sequence: 2000, acknowledgement: 1001, flags: tcpFlagSYN | tcpFlagACK, window: 65535,
		}
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("active handshake did not recover after maintenance retransmissions")
		}
	})

	t.Run("passive duplicate SYNs", func(t *testing.T) {
		link, stack := newTestStack(t, local, remote)
		connection := newTCPConn(stack, "tcp4", tcpKey{
			local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
		}, 1400)
		connection.passive = true
		syn := tcpSegment{sequence: 100, flags: tcpFlagSYN | tcpFlagECE | tcpFlagCWR, window: 65535}
		result := make(chan error, 1)
		go func() { result <- connection.passiveHandshake(syn, 1000) }()
		read := func() {
			select {
			case <-link.outbound:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for passive SYN-ACK")
			}
		}
		read()
		for index := 0; index < tcpPassiveSYNMaximumAttempts+1; index++ {
			connection.inbound <- syn
			read()
		}
		// A timer retransmission must still occur instead of treating duplicate
		// peer SYNs as exhausted timeout attempts.
		read()
		connection.inbound <- tcpSegment{sequence: 101, acknowledgement: 1001, flags: tcpFlagACK, window: 65535}
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("passive handshake did not recover after duplicate SYNs")
		}
	})
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

// TestTCPAcceptableSendSequence verifies pure ACK sequence selection after a
// peer window shrink, including window-scale precision and sequence wrap.
func TestTCPAcceptableSendSequence(t *testing.T) {
	tests := []struct {
		name                         string
		unacknowledged, next, window uint32
		scale                        uint8
		want                         uint32
	}{
		{name: "open window", unacknowledged: 100, next: 200, window: 200, scale: 2, want: 200},
		{name: "shrunken window", unacknowledged: 100, next: 200, window: 0, scale: 2, want: 100},
		{name: "zero window below scale quantum", unacknowledged: 100, next: 102, window: 0, scale: 8, want: 100},
		{name: "scaling precision", unacknowledged: 100, next: 200, window: 97, scale: 2, want: 200},
		{name: "wrapped open window", unacknowledged: 0xfffffff0, next: 16, window: 64, scale: 0, want: 16},
		{name: "wrapped shrunken window", unacknowledged: 0xfffffff0, next: 16, window: 0, scale: 0, want: 0xfffffff0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpAcceptableSendSequence(test.unacknowledged, test.next, test.window, test.scale); got != test.want {
				t.Fatalf("tcpAcceptableSendSequence(%d, %d, %d, %d) = %d, want %d", test.unacknowledged, test.next, test.window, test.scale, got, test.want)
			}
		})
	}
}

// TestTCPChallengeACKSequence verifies that challenge responses remain inside
// either a newly reported or the currently known peer receive window.
func TestTCPChallengeACKSequence(t *testing.T) {
	segment := tcpSegment{flags: tcpFlagACK, acknowledgement: 150, window: 0}
	if got := tcpChallengeACKSequence(segment, 100, 200, 0, 2); got != 150 {
		t.Fatalf("zero-window challenge sequence = %d, want 150", got)
	}
	segment.window = 20
	if got := tcpChallengeACKSequence(segment, 100, 200, 0, 2); got != 200 {
		t.Fatalf("open-window challenge sequence = %d, want 200", got)
	}
	segment.acknowledgement = 201
	if got := tcpChallengeACKSequence(segment, 100, 200, 0, 2); got != 100 {
		t.Fatalf("invalid-ACK challenge sequence = %d, want 100", got)
	}
	segment.acknowledgement = 150
	segment.flags |= tcpFlagFIN
	if got := tcpChallengeACKSequence(segment, 100, 200, 0, 2); got != 100 {
		t.Fatalf("non-pure challenge sequence = %d, want 100", got)
	}
	segment.payload = tcpZeroWindowProbe[:]
	if got := tcpChallengeACKSequence(segment, 100, 200, 40, 2); got != 140 {
		t.Fatalf("peer-probe challenge sequence = %d, want 140", got)
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

func TestTCPKeepAliveAndWindowProbeClassification(t *testing.T) {
	const receiveNext = uint32(100)
	if !tcpKeepAliveOrWindowProbe(tcpSegment{sequence: receiveNext - 1, flags: tcpFlagACK}, 0, receiveNext, 4096) {
		t.Fatal("keepalive probe was not recognized")
	}
	if !tcpKeepAliveOrWindowProbe(tcpSegment{sequence: receiveNext - 1, flags: tcpFlagACK, payload: []byte{0}}, 1, receiveNext, 0) {
		t.Fatal("zero-window probe was not recognized")
	}
	if !tcpKeepAliveOrWindowProbe(tcpSegment{sequence: receiveNext - 1, flags: tcpFlagACK, payload: []byte{0}}, 1, receiveNext, 4096) {
		t.Fatal("one-byte RFC 1122 keepalive was not recognized with an open window")
	}
	if tcpKeepAliveOrWindowProbe(tcpSegment{sequence: receiveNext - 1, flags: tcpFlagRST | tcpFlagACK}, 0, receiveNext, 4096) {
		t.Fatal("RST was classified as a keepalive probe")
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

// TestTCPReceiveWindowScaleMatchesDefaultCapacity verifies that the negotiated
// shift closely represents the default receive buffer.
func TestTCPReceiveWindowScaleMatchesDefaultCapacity(t *testing.T) {
	_, scale, enabled, _, _, _ := parseTCPOptions(tcpSYNOptions(1360, 1), 536, 1360)
	if !enabled || scale != tcpReceiveWindowScale {
		t.Fatalf("SYN window scale = %d, enabled=%t; want %d, true", scale, enabled, tcpReceiveWindowScale)
	}
	connection := &TCPConn{receiveCapacity: tcpReceiveCapacity}
	if window := connection.receiveWindow(0, true); window != 65535 {
		t.Fatalf("scaled default receive window = %d, want 65535", window)
	}
}

// TestTCPReceiveWindowPreservesRightEdge verifies that receiving out-of-order
// bytes cannot withdraw sequence space that was already promised to a peer.
func TestTCPReceiveWindowPreservesRightEdge(t *testing.T) {
	const receiveNext = uint32(100)
	window := newTCPReceiveWindow(receiveNext, 65535, true, false)
	if got := window.advertise(receiveNext, tcpReceiveCapacity, 0); got != 65535 {
		t.Fatalf("initial scaled window = %d, want 65535", got)
	}
	right := window.right
	if got := window.advertise(receiveNext, tcpReceiveCapacity/2, 0); got != 65535 {
		t.Fatalf("window after out-of-order storage = %d, want 65535", got)
	}
	if window.right != right {
		t.Fatalf("right edge moved from %d to %d", right, window.right)
	}
	advanced := receiveNext + 1380
	got := window.advertise(advanced, tcpReceiveCapacity-1380, 0)
	if advertisedRight := advanced + uint32(got)<<tcpReceiveWindowScale; tcpSequenceLess(advertisedRight+uint32(1<<tcpReceiveWindowScale)-1, right) {
		t.Fatalf("scaled right edge shrank from %d to %d", right, advertisedRight)
	}
}

// TestTCPReceiveWindowHandshakeScaling verifies that only an active opener's
// final ACK applies the negotiated window shift to its initial right edge.
func TestTCPReceiveWindowHandshakeScaling(t *testing.T) {
	const receiveNext = uint32(100)
	active := newTCPReceiveWindow(receiveNext, 65535, true, true)
	if got := active.size(receiveNext); got != uint32(65535)<<tcpReceiveWindowScale {
		t.Fatalf("active initial receive window = %d", got)
	}
	passive := newTCPReceiveWindow(receiveNext, 65535, true, false)
	if got := passive.size(receiveNext); got != 65535 {
		t.Fatalf("passive initial receive window = %d", got)
	}
}

func TestTCPReceiveWindowAvoidsSillyWindowGrowth(t *testing.T) {
	const receiveNext = uint32(100)
	window := newTCPReceiveWindow(receiveNext, 1000, false, false)
	advanced := receiveNext + 1000
	if got := window.advertise(advanced, 499, tcpReceiveWindowIncrease(1000, 600)); got != 0 {
		t.Fatalf("sub-threshold reopened window = %d, want 0", got)
	}
	if got := window.advertise(advanced, 500, tcpReceiveWindowIncrease(1000, 600)); got != 500 {
		t.Fatalf("threshold reopened window = %d, want 500", got)
	}
	maximumInt := int(^uint(0) >> 1)
	if got, want := tcpReceiveWindowIncrease(maximumInt, maximumInt), maximumInt/2+maximumInt%2; got != want {
		t.Fatalf("maximum-capacity threshold = %d, want %d", got, want)
	}
}

// TestTCPWindowUpdatePromotesContiguousData verifies that data retained at
// RCV.NXT while the application buffer was full is exposed after a read.
func TestTCPWindowUpdatePromotesContiguousData(t *testing.T) {
	connection := &TCPConn{
		readChanged: make(chan struct{}), readNotify: make(chan struct{}),
		windowUpdate: make(chan struct{}, 1), receiveCapacity: 4,
		readBuffer: []byte("full"),
	}
	receiveNext := uint32(100)
	outOfOrder := []tcpReceivedPiece{{sequence: receiveNext, payload: []byte("next")}}
	outOfOrderBytes := len(outOfOrder[0].payload)
	buffer := make([]byte, 4)
	if n, err := connection.Read(buffer); err != nil || n != 4 || string(buffer) != "full" {
		t.Fatalf("Read = %d, %v, %q; want 4, nil, full", n, err, buffer)
	}
	if delivered, closed := connection.promoteTCPReceived(&receiveNext, &outOfOrder, &outOfOrderBytes); !delivered || closed {
		t.Fatalf("promoteTCPReceived = %t, %t; want true, false", delivered, closed)
	}
	if receiveNext != 104 || len(outOfOrder) != 0 || outOfOrderBytes != 0 {
		t.Fatalf("receive state = next %d, pieces %d, bytes %d; want 104, 0, 0", receiveNext, len(outOfOrder), outOfOrderBytes)
	}
	if string(connection.readBuffer) != "next" {
		t.Fatalf("promoted read buffer = %q, want next", connection.readBuffer)
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
		if peer == nil || peer.highestClientEnd == peer.clientNext {
			return false
		}
		// Keep a TLP or RTO retransmission from racing the deliberately
		// injected ACK below. The test peer must acknowledge only the two
		// segments the test explicitly supplies from this point onward.
		link.echoTCP = false
		return true
	})
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	validSequence, acknowledgement := peer.serverNext, peer.highestClientEnd
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), validSequence+tcpReceiveCapacity+1, acknowledgement, tcpFlagACK, 65535, nil, nil); err != nil {
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

// TestTCPOldACKStillDeliversData verifies RFC 9293 processing for a duplicate
// cumulative ACK: its ACK and window fields are ignored, but acceptable stream
// data in the same segment must still be delivered.
func TestTCPOldACKStillDeliversData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7997))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	writeAndReadTCPEcho(t, connection, []byte("seed"))
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, oldACK := peer.serverNext, peer.clientNext-1
	peer.serverNext += 4
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, oldACK, tcpFlagACK|tcpFlagPSH, 65535, nil, []byte("data")); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 4)
	if _, err = io.ReadFull(connection, buffer); err != nil || string(buffer) != "data" {
		t.Fatalf("data with old ACK = %q, %v", buffer, err)
	}
}

// TestTCPTooOldACKDropsData verifies the RFC 5961 blind-injection mitigation:
// data cannot make an ACK older than the sender's legitimate history useful.
func TestTCPTooOldACKDropsData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7996))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	writeAndReadTCPEcho(t, connection, []byte("seed"))
	tcpConnection := connection.(*TCPConn)
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, tooOldACK := peer.serverNext, peer.clientNext-5
	peer.serverNext += 4
	baselineACKs := link.clientACKs
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, tooOldACK, tcpFlagACK|tcpFlagPSH, 65535, nil, []byte("data")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs > baselineACKs
	})
	_ = connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buffer := make([]byte, 4)
	if n, readErr := connection.Read(buffer); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("data with too-old ACK = %q, %v, want timeout", buffer[:n], readErr)
	}
}

func TestTCPACKRTTAmbiguity(t *testing.T) {
	segments := []sentTCPSegment{
		{sequence: 100, end: 200, transmissions: 2},
		{sequence: 200, end: 300, transmissions: 1},
	}
	if !tcpACKRTTAmbiguous(segments, 300) {
		t.Fatal("cumulative ACK covering a retransmission was treated as an RTT sample")
	}
	if tcpACKRTTAmbiguous(segments, 100) {
		t.Fatal("ACK covering no new range was treated as ambiguous")
	}
	segments[0].transmissions = 1
	if tcpACKRTTAmbiguous(segments, 300) {
		t.Fatal("ACK covering only original transmissions was treated as ambiguous")
	}
}

// TestTCPActiveOpenRetainsSoftNetworkError verifies that an asynchronous ICMP
// failure does not permanently fail an active open when a later SYN succeeds.
func TestTCPActiveOpenRetainsSoftNetworkError(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPSYN = 1
	result := make(chan error, 1)
	go func() {
		connection, dialErr := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7996))
		if connection != nil {
			_ = connection.Close()
		}
		result <- dialErr
	}()
	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		stack.mu.RLock()
		defer stack.mu.RUnlock()
		for _, candidate := range stack.tcp {
			connection = candidate
			return true
		}
		return false
	})
	connection.deliverError(ICMPError{Reporter: link.remote, Type: 3, Code: 1})
	connection.pathMTUUpdate <- struct{}{}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("active open failed after soft network error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active open did not recover after soft network error")
	}
}

// TestTCPActiveOpenRejectsHardNetworkError verifies that an authenticated
// port-unreachable does not wait through the complete SYN retry budget.
func TestTCPActiveOpenRejectsHardNetworkError(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.dropTCPSYN = 100
	result := make(chan error, 1)
	go func() {
		_, dialErr := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7997))
		result <- dialErr
	}()
	var connection *TCPConn
	waitFor(t, time.Second, func() bool {
		stack.mu.RLock()
		defer stack.mu.RUnlock()
		for _, candidate := range stack.tcp {
			connection = candidate
			return true
		}
		return false
	})
	want := ICMPError{Reporter: link.remote, Type: 3, Code: 3, QuotedSource: netip.MustParseAddr("192.0.2.1")}
	connection.deliverError(want)
	select {
	case err := <-result:
		var got ICMPError
		if !errors.As(err, &got) || got.Type != want.Type || got.Code != want.Code {
			t.Fatalf("hard active-open error = %v, want ICMP port unreachable", err)
		}
	case <-time.After(time.Second):
		t.Fatal("hard active-open error did not terminate Dial")
	}
}

// TestTCPSimultaneousOpen verifies the RFC 9293 crossed-SYN path by actively
// opening the same four-tuple from both endpoints at once.
func TestTCPSimultaneousOpen(t *testing.T) {
	firstAddress := netip.MustParseAddr("192.0.2.21")
	secondAddress := netip.MustParseAddr("192.0.2.22")
	first, second := newStackPair(t, firstAddress, secondAddress, 1500)
	type result struct {
		connection net.Conn
		err        error
	}
	firstResult := make(chan result, 1)
	secondResult := make(chan result, 1)
	go func() {
		connection, err := first.DialTCP(context.Background(), "tcp4", netip.AddrPortFrom(firstAddress, 40121), netip.AddrPortFrom(secondAddress, 40122))
		firstResult <- result{connection: connection, err: err}
	}()
	go func() {
		connection, err := second.DialTCP(context.Background(), "tcp4", netip.AddrPortFrom(secondAddress, 40122), netip.AddrPortFrom(firstAddress, 40121))
		secondResult <- result{connection: connection, err: err}
	}()
	// Do not deliver either SYN until both active-open TCBs exist. If one SYN
	// reaches an as-yet unbound peer first, RFC 9293 correctly requires a RST
	// and the test would exercise an ordinary refused open instead.
	waitFor(t, time.Second, func() bool {
		return first.Stats().ActiveTCPConnections == 1 && second.Stats().ActiveTCPConnections == 1
	})
	_ = newStackBridge(t, first, second)
	var firstConnection, secondConnection net.Conn
	for index, channel := range []<-chan result{firstResult, secondResult} {
		select {
		case opened := <-channel:
			if opened.err != nil {
				t.Fatalf("simultaneous open %d: %v", index, opened.err)
			}
			if index == 0 {
				firstConnection = opened.connection
			} else {
				secondConnection = opened.connection
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("simultaneous open %d timed out", index)
		}
	}
	defer firstConnection.Close()
	defer secondConnection.Close()
	payload := []byte("crossed-syn")
	if _, err := firstConnection.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = secondConnection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(secondConnection, buffer); err != nil || !bytes.Equal(buffer, payload) {
		t.Fatalf("simultaneous-open stream = %q, %v", buffer, err)
	}
}

// TestTCPNewRenoPartialACKRetransmitsNextHole verifies RFC 6582 recovery when
// SACK was not negotiated and two packets are lost from one flight.
func TestTCPNewRenoPartialACKRetransmitsNextHole(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.disableTCPSACK = true
	link.dropTCPOrdinals = map[int]bool{1: true, 3: true}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7995))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	payload := bytes.Repeat([]byte{0x5a}, 8*1280)
	start := time.Now()
	if _, err = connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("NewReno recovery corrupted the stream")
	}
	if elapsed := time.Since(start); elapsed >= tcpInitialRTO {
		t.Fatalf("NewReno recovery took %v, want less than initial RTO", elapsed)
	}
	if retransmissions := stack.Stats().TCPRetransmissions; retransmissions < 2 {
		t.Fatalf("TCP retransmissions = %d, want at least 2", retransmissions)
	}
}

func TestTCPNewRenoPartialACKWindow(t *testing.T) {
	const mss = 1000
	for _, test := range []struct {
		name                 string
		window, acknowledged uint32
		want                 uint32
	}{
		{name: "sub-MSS acknowledgement", window: 5000, acknowledged: 500, want: 4500},
		{name: "one MSS acknowledgement", window: 5000, acknowledged: 1000, want: 5000},
		{name: "large acknowledgement", window: 5000, acknowledged: 3000, want: 3000},
		{name: "acknowledgement consumes window", window: 2000, acknowledged: 3000, want: 1000},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := newRenoPartialACKWindow(test.window, test.acknowledged, mss); got != test.want {
				t.Fatalf("partial ACK window = %d, want %d", got, test.want)
			}
		})
	}
}

// TestTCPECNRecoveryBoundary verifies that one ECE echo cannot repeatedly
// reduce the congestion window at the same recovery boundary.
func TestTCPECNRecoveryBoundary(t *testing.T) {
	if !tcpECNStartsRecovery(false, 100, 0) {
		t.Fatal("first ECE did not start recovery")
	}
	if tcpECNStartsRecovery(true, 200, 200) {
		t.Fatal("ACK at the recovery boundary started another recovery")
	}
	if !tcpECNStartsRecovery(true, 201, 200) {
		t.Fatal("ACK beyond the recovery boundary did not start recovery")
	}
	if !tcpECNStartsRecovery(true, 1, 0xffffffff) {
		t.Fatal("wrapped ACK beyond the recovery boundary was rejected")
	}
}

// TestTCPECNAtMinimumWindowWaitsForRTO verifies RFC 3168's required sending
// rate reduction after another ECE arrives when cwnd is already one SMSS.
func TestTCPECNAtMinimumWindowWaitsForRTO(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.sendTCPECE = true
	if err := stack.UpdateConfig(Config{
		LocalAddresses:    []netip.Prefix{netip.PrefixFrom(link.local, 32)},
		CongestionControl: CongestionControlReno,
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7998))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, []byte{1})
	writeAndReadTCPEcho(t, connection, []byte{2})
	start := time.Now()
	writeAndReadTCPEcho(t, connection, []byte{3})
	if elapsed := time.Since(start); elapsed < tcpMinimumRTO-50*time.Millisecond {
		t.Fatalf("one-MSS repeated ECE delayed next send by %v, want approximately one RTO", elapsed)
	}
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

func TestTCPExpiredWriteDeadlineRejectsBufferedWrite(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8096))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, writeErr := connection.Write([]byte("late")); n != 0 || !errors.Is(writeErr, os.ErrDeadlineExceeded) {
		t.Fatalf("expired buffered Write = %d, %v, want 0, deadline", n, writeErr)
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

func TestTCPRTOPartialACKAdvancesLossRecovery(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.disableTCPSACK = true
	link.dropTCPData = 3
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8097))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x5a}, 3*1280)
	start := time.Now()
	writeAndReadTCPEcho(t, connection, payload)
	if elapsed := time.Since(start); elapsed >= tcpInitialRTO {
		t.Fatalf("RTO partial-ACK recovery took %v, want less than %v", elapsed, tcpInitialRTO)
	}
	if retransmissions := stack.Stats().TCPRetransmissions; retransmissions < 3 {
		t.Fatalf("RTO recovery retransmissions = %d, want at least 3", retransmissions)
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

// TestTCPRACKTimerRecoversSingleSACKHole verifies the RFC 8985 reordering
// timer path when one SACK is insufficient to reach DupThresh.
func TestTCPRACKTimerRecoversSingleSACKHole(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPOrdinals = map[int]bool{1: true}
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8093))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x53}, 2*1280)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	stats := stack.Stats()
	if stats.TCPRACKRetransmissions == 0 {
		t.Fatalf("RACK retransmissions = %d, want at least one", stats.TCPRACKRetransmissions)
	}
}

func TestTCPLimitedTransmitIsExcludedFromRecoveryFlight(t *testing.T) {
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200},
		{sequence: 200, end: 300, limited: true},
		{sequence: 300, end: 400, sacked: true},
	}
	if flight := lossRecoveryFlightSize(outstanding); flight != 100 {
		t.Fatalf("Limited Transmit recovery flight = %d, want 100", flight)
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

// TestTCPTailLossProbeSendsNewData verifies RFC 8985's preferred probe: one
// previously unsent segment beyond cwnd when the receive window permits it.
func TestTCPTailLossProbeSendsNewData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.holdTCPACKs = 11
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8092))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x4f}, 11*1280)
	if n, writeErr := connection.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	stats := stack.Stats()
	if stats.TCPTailLossProbes == 0 || stats.TCPRetransmissions != 0 {
		t.Fatalf("new-data TLP stats = probes %d retransmissions %d", stats.TCPTailLossProbes, stats.TCPRetransmissions)
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

func TestTCPPathMTUReductionPreservesFINSequence(t *testing.T) {
	original := sentTCPSegment{
		sequence: 100, end: 1101, flags: tcpFlagACK | tcpFlagPSH | tcpFlagFIN,
		payload: make([]byte, 1000),
	}
	segments := splitTCPSegments([]sentTCPSegment{original}, 600)
	if len(segments) != 2 {
		t.Fatalf("resegmented FIN ranges = %d, want 2", len(segments))
	}
	if segments[0].end != 700 || segments[0].flags&(tcpFlagPSH|tcpFlagFIN) != 0 {
		t.Fatalf("first resegmented range = [%d,%d) flags=%#x", segments[0].sequence, segments[0].end, segments[0].flags)
	}
	last := segments[1]
	if last.sequence != 700 || last.end != original.end || last.flags&(tcpFlagPSH|tcpFlagFIN) != tcpFlagPSH|tcpFlagFIN {
		t.Fatalf("last resegmented FIN range = [%d,%d) flags=%#x, want [700,1101) PSH|FIN", last.sequence, last.end, last.flags)
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
	initialMTU := stack.mtuFor(link.remote)
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
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
	if mtu := stack.mtuFor(link.remote); mtu != initialMTU {
		t.Fatalf("connection-local black-hole recovery changed cached path MTU to %d", mtu)
	}
}

// TestTCPBlackHoleMTUFloor verifies that heuristic probing never creates TCP
// segments below IPv4's conventional 536-byte default MSS.
func TestTCPBlackHoleMTUFloor(t *testing.T) {
	if got := nextBlackHoleMTU(1006, false); got != 576 {
		t.Fatalf("next IPv4 black-hole MTU = %d, want 576", got)
	}
	if got := nextBlackHoleMTU(576, false); got != 508 {
		t.Fatalf("next IPv4 black-hole MTU below 576 = %d, want 508", got)
	}
	if got := nextBlackHoleMTU(296, false); got != 68 {
		t.Fatalf("next IPv4 black-hole MTU at the minimum plateau = %d, want 68", got)
	}
	if got := nextBlackHoleMTU(68, false); got != 68 {
		t.Fatalf("IPv4 black-hole MTU below floor = %d, want 68", got)
	}
	if got := nextBlackHoleProbeMTU(1400, false, 1200, false); got != 1006 {
		t.Fatalf("IPv4 black-hole probe with 1200-byte peer MSS = %d, want 1006", got)
	}
	if got := nextBlackHoleProbeMTU(1500, false, 536, false); got != 508 {
		t.Fatalf("IPv4 black-hole probe below conventional MSS floor = %d, want 508", got)
	}
	if got := nextBlackHoleProbeMTU(1500, true, 1400, true); got != 1280 {
		t.Fatalf("IPv6 black-hole probe = %d, want 1280", got)
	}
}

func TestTCPOutOfOrderEarlierFINWins(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500)
	receiveNext := uint32(100)
	receiveWindow := uint32(1000)
	var pieces []tcpReceivedPiece
	bytes := 0
	if !connection.storeTCPOutOfOrder(receiveNext, receiveWindow, 200, nil, true, &pieces, &bytes) {
		t.Fatal("later out-of-order FIN was not retained")
	}
	if !connection.storeTCPOutOfOrder(receiveNext, receiveWindow, 150, nil, true, &pieces, &bytes) {
		t.Fatal("earlier out-of-order FIN was not retained")
	}
	if len(pieces) != 1 || pieces[0].sequence != 150 || !pieces[0].fin {
		t.Fatalf("normalized FIN pieces = %+v, want FIN at 150", pieces)
	}
}

func TestTCPOutOfOrderFINWaitsForSequenceGap(t *testing.T) {
	connection := &TCPConn{
		receiveCapacity: 32,
		readChanged:     make(chan struct{}),
		readNotify:      make(chan struct{}),
	}
	receiveNext := uint32(100)
	var pieces []tcpReceivedPiece
	outOfOrderBytes := 0
	if delivered, closed := connection.receiveTCPData(104, []byte("ef"), true, 32, &receiveNext, &pieces, &outOfOrderBytes); delivered || closed {
		t.Fatalf("out-of-order data plus FIN = delivered %t closed %t", delivered, closed)
	}
	if receiveNext != 100 || len(connection.readBuffer) != 0 {
		t.Fatalf("gapped receive state = next %d buffer %q", receiveNext, connection.readBuffer)
	}
	if delivered, closed := connection.receiveTCPData(100, []byte("abcd"), false, 32, &receiveNext, &pieces, &outOfOrderBytes); !delivered || !closed {
		t.Fatalf("gap completion = delivered %t closed %t", delivered, closed)
	}
	if receiveNext != 107 || string(connection.readBuffer) != "abcdef" || len(pieces) != 0 || outOfOrderBytes != 0 {
		t.Fatalf("completed receive state = next %d buffer %q pieces %d bytes %d", receiveNext, connection.readBuffer, len(pieces), outOfOrderBytes)
	}
	connection.setReadEOF()
	buffer := make([]byte, 6)
	if n, err := connection.Read(buffer); n != len(buffer) || err != nil || string(buffer) != "abcdef" {
		t.Fatalf("Read before EOF = %d, %v, %q", n, err, buffer)
	}
	if n, err := connection.Read(buffer[:1]); n != 0 || err != io.EOF {
		t.Fatalf("final Read = %d, %v; want 0, EOF", n, err)
	}
}

func TestTCPPartialACKCanLeaveFINOnly(t *testing.T) {
	segment := sentTCPSegment{
		sequence: 100, end: 104, flags: tcpFlagACK | tcpFlagPSH | tcpFlagFIN,
		payload: []byte{1, 2, 3}, cwr: true,
	}
	trimAcknowledgedTCPSegment(&segment, 103)
	if segment.sequence != 103 || segment.end != 104 || len(segment.payload) != 0 || segment.flags&tcpFlagFIN == 0 || segment.flags&tcpFlagPSH != 0 || segment.cwr {
		t.Fatalf("FIN-only remainder = %+v", segment)
	}
}

func TestTCPCloseWithUnreadDataIsAbortive(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500)
	connection.readBuffer = []byte("unread")
	connection.sendBuffer = []byte("unsent")
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.abortCh:
	default:
		t.Fatal("Close with unread data did not request an abortive reset")
	}
	if !connection.resetAfterAbort() {
		t.Fatal("unread-data close suppressed the reset")
	}
	if len(connection.sendBuffer) != 0 {
		t.Fatalf("abortive close retained %d send bytes", len(connection.sendBuffer))
	}
}

func TestTCPCloseWithoutUnreadDataRemainsGraceful(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.abortCh:
		t.Fatal("graceful Close unexpectedly requested a reset")
	default:
	}
	connection.abortWithoutReset(net.ErrClosed)
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
	var latest tcpRACKSample
	outstanding, _, _, _, latest, _ = applyTCPSACK(outstanding, []tcpSACKBlock{{left: 200, right: 300}})
	latest.rtt = 5 * time.Millisecond
	markRACKLoss(outstanding, latest, base.Add(20*time.Millisecond), 10*time.Millisecond)
	if !outstanding[0].rackLost || outstanding[1].rackLost {
		t.Fatalf("RACK loss state = [%v %v]", outstanding[0].rackLost, outstanding[1].rackLost)
	}
}

// TestRACKWaitsFromCurrentTime verifies that transmit-order evidence and the
// reordering timer are separate RFC 8985 conditions. A closely spaced later
// transmission starts a timer instead of postponing loss until RTO.
func TestRACKWaitsFromCurrentTime(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, sentAt: base},
		{sequence: 200, end: 300, sentAt: base.Add(time.Millisecond), sacked: true},
	}
	delivered := tcpRACKSample{sentAt: outstanding[1].sentAt, end: outstanding[1].end, rtt: 10 * time.Millisecond}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(15*time.Millisecond), 10*time.Millisecond); !ok || delay != 5*time.Millisecond {
		t.Fatalf("RACK loss delay = %v, %t; want 5ms, true", delay, ok)
	}
	markRACKLoss(outstanding, delivered, base.Add(19*time.Millisecond), 10*time.Millisecond)
	if outstanding[0].rackLost {
		t.Fatal("RACK declared loss before the reordering timer expired")
	}
	markRACKLoss(outstanding, delivered, base.Add(20*time.Millisecond), 10*time.Millisecond)
	if !outstanding[0].rackLost {
		t.Fatal("RACK did not declare loss when the reordering timer expired")
	}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(20*time.Millisecond), 10*time.Millisecond); ok {
		t.Fatalf("RACK rearmed an already declared loss with delay %v", delay)
	}
}

// TestRACKCanDetectLostRetransmission verifies that a recovery transmission
// is not immune from a later round of time-based loss detection.
func TestRACKCanDetectLostRetransmission(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, sentAt: base, sackRetried: true},
		{sequence: 200, end: 300, sentAt: base.Add(time.Millisecond), sacked: true},
	}
	delivered := tcpRACKSample{sentAt: outstanding[1].sentAt, end: outstanding[1].end, rtt: 5 * time.Millisecond}
	markRACKLoss(outstanding, delivered, base.Add(15*time.Millisecond), 10*time.Millisecond)
	if !outstanding[0].rackLost || outstanding[0].sackRetried {
		t.Fatalf("lost retransmission state = lost %t retried %t", outstanding[0].rackLost, outstanding[0].sackRetried)
	}
}

func TestRACKUsesMaximumRemainingWait(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, sentAt: base},
		{sequence: 200, end: 300, sentAt: base.Add(3 * time.Millisecond)},
		{sequence: 300, end: 400, sentAt: base.Add(5 * time.Millisecond), sacked: true},
	}
	delivered := tcpRACKSample{sentAt: outstanding[2].sentAt, end: outstanding[2].end, rtt: 10 * time.Millisecond}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(10*time.Millisecond), 5*time.Millisecond); !ok || delay != 8*time.Millisecond {
		t.Fatalf("RACK maximum loss delay = %v, %t; want 8ms, true", delay, ok)
	}
}

func TestRACKRejectsAmbiguousRetransmissionRTT(t *testing.T) {
	sample := tcpRACKSample{sentAt: time.Unix(100, 0), end: 200, rtt: 5 * time.Millisecond, retransmitted: true}
	if got := validRACKSample(sample, 10*time.Millisecond); !got.sentAt.IsZero() {
		t.Fatalf("ambiguous retransmission sample was accepted: %+v", got)
	}
	sample.retransmitted = false
	if got := validRACKSample(sample, 10*time.Millisecond); got.sentAt.IsZero() {
		t.Fatal("original transmission sample was rejected")
	}
}

func TestRACKDetectsOriginalDataReordering(t *testing.T) {
	var forward uint32
	var set bool
	if reordered := rackAdvanceForwardACK(&forward, &set, 300, false); reordered || !set || forward != 300 {
		t.Fatalf("initial FACK = %d, %t, reordered %t", forward, set, reordered)
	}
	if reordered := rackAdvanceForwardACK(&forward, &set, 200, false); !reordered {
		t.Fatal("original data below FACK did not record reordering")
	}
	if reordered := rackAdvanceForwardACK(&forward, &set, 100, true); reordered {
		t.Fatal("retransmitted data below FACK recorded path reordering")
	}
}

func TestRACKReorderingWindowUsesMinimumRTT(t *testing.T) {
	if window := rackReorderingWindow(4*time.Millisecond, 20*time.Millisecond, 1); window != time.Millisecond {
		t.Fatalf("RACK reordering window = %v, want 1ms", window)
	}
	if window := rackReorderingWindow(80*time.Millisecond, 10*time.Millisecond, 1); window != 10*time.Millisecond {
		t.Fatalf("SRTT-bounded RACK window = %v, want 10ms", window)
	}
	if window := rackReorderingWindow(0, 10*time.Millisecond, 1); window != 0 {
		t.Fatalf("unsampled RACK window = %v, want 0", window)
	}
	if window := rackReorderingWindow(4*time.Millisecond, 20*time.Millisecond, 4); window != 4*time.Millisecond {
		t.Fatalf("DSACK-expanded RACK window = %v, want 4ms", window)
	}
	var estimator rttEstimator
	estimator.observe(20 * time.Millisecond)
	estimator.observe(4 * time.Millisecond)
	if estimator.minimum != 4*time.Millisecond {
		t.Fatalf("minimum RTT = %v, want 4ms", estimator.minimum)
	}
}

func TestTCPRTTSampleUsesSegmentArrivalTime(t *testing.T) {
	base := time.Unix(100, 0)
	if sample := elapsedRTTSampleAt(base, base.Add(10*time.Millisecond)); sample != 10*time.Millisecond {
		t.Fatalf("RTT sample = %v, want 10ms", sample)
	}
	if sample := elapsedRTTSampleAt(base, base.Add(-time.Second)); sample != time.Microsecond {
		t.Fatalf("reordered clock sample = %v, want 1us", sample)
	}
	if sample := elapsedRTTSampleAt(time.Time{}, base); sample != 0 {
		t.Fatalf("missing RTT sample = %v, want 0", sample)
	}
}

func TestTCPSegmentEventTime(t *testing.T) {
	now := time.Unix(200, 0)
	receivedAt := now.Add(-10 * time.Millisecond)
	if got := tcpSegmentEventTime(tcpSegment{receivedAt: receivedAt}, now); got != receivedAt {
		t.Fatalf("segment event time = %v, want %v", got, receivedAt)
	}
	if got := tcpSegmentEventTime(tcpSegment{}, now); got != now {
		t.Fatalf("missing segment event time = %v, want %v", got, now)
	}
	if got := tcpSegmentEventTime(tcpSegment{receivedAt: now.Add(time.Second)}, now); got != now {
		t.Fatalf("future segment event time = %v, want %v", got, now)
	}
}

func TestTCPDispatchPreservesPacketArrivalTime(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	remote := netip.MustParseAddr("192.0.2.2")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	key := tcpKey{local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 50000)}
	connection := newTCPConn(stack, "tcp4", key, 1500)
	stack.tcp[key] = connection
	packet, ok := parseIPPacket(buildTestTCP(remote, local, key.remote.Port(), key.local.Port(), 1, 1, tcpFlagACK, 65535, nil, nil))
	if !ok {
		t.Fatal("test TCP packet did not parse")
	}
	receivedAt := time.Unix(250, 0)
	if err = stack.handleTCP(packet, receivedAt); err != nil {
		t.Fatal(err)
	}
	select {
	case segment := <-connection.inbound:
		segment = connection.consumeInbound(segment)
		if segment.receivedAt != receivedAt {
			t.Fatalf("dispatched arrival time = %v, want %v", segment.receivedAt, receivedAt)
		}
	default:
		t.Fatal("TCP segment was not dispatched")
	}
}

func TestTCPTimestampUsesEventTime(t *testing.T) {
	epoch := time.Unix(300, 0)
	stack := &Stack{timestampEpoch: epoch}
	if got := stack.tcpTimestampAt(epoch.Add(1234 * time.Millisecond)); got != 1235 {
		t.Fatalf("TCP timestamp = %d, want 1235", got)
	}
}

func TestTCPDSACKParsing(t *testing.T) {
	options := make([]byte, 10)
	options[0], options[1] = 5, 10
	binary.BigEndian.PutUint32(options[2:6], 200)
	binary.BigEndian.PutUint32(options[6:10], 300)
	if block, ok := parseTCPDSACKOption(options, 300, 500, 200); !ok || block != (tcpSACKBlock{left: 200, right: 300}) {
		t.Fatalf("below-ACK DSACK = %#v, %t", block, ok)
	}
	if _, ok := parseTCPDSACKOption(options, 300, 500, 50); ok {
		t.Fatal("DSACK older than retained send history was accepted")
	}

	options = make([]byte, 18)
	options[0], options[1] = 5, 18
	binary.BigEndian.PutUint32(options[2:6], 250)
	binary.BigEndian.PutUint32(options[6:10], 300)
	binary.BigEndian.PutUint32(options[10:14], 200)
	binary.BigEndian.PutUint32(options[14:18], 350)
	if block, ok := parseTCPDSACKOption(options, 100, 400, 0); !ok || block != (tcpSACKBlock{left: 250, right: 300}) {
		t.Fatalf("contained DSACK = %#v, %t", block, ok)
	}
}

// TestTCPRepeatedSACKIsNotNewInformation verifies that an unchanged SACK
// block cannot repeatedly inflate duplicate-ACK recovery.
func TestTCPRepeatedSACKIsNotNewInformation(t *testing.T) {
	outstanding := []sentTCPSegment{{sequence: 100, end: 200}, {sequence: 200, end: 300}}
	blocks := []tcpSACKBlock{{left: 200, right: 300}}
	var present, fresh bool
	outstanding, _, present, fresh, _, _ = applyTCPSACK(outstanding, blocks)
	if !present || !fresh {
		t.Fatalf("first SACK state = present %t, fresh %t; want true, true", present, fresh)
	}
	outstanding, _, present, fresh, _, _ = applyTCPSACK(outstanding, blocks)
	if !present || fresh {
		t.Fatalf("repeated SACK state = present %t, fresh %t; want true, false", present, fresh)
	}
}

// TestTCPPartialSACKSplitsScoreboard verifies byte-accurate RFC 6675 state
// when a valid SACK block covers only the middle of one transmission.
func TestTCPPartialSACKSplitsScoreboard(t *testing.T) {
	payload := make([]byte, 300)
	outstanding := []sentTCPSegment{{sequence: 100, end: 400, flags: tcpFlagACK | tcpFlagPSH, payload: payload, transmissions: 1}}
	var present, fresh bool
	var delivered []sentTCPSegment
	outstanding, _, present, fresh, _, delivered = applyTCPSACK(outstanding, []tcpSACKBlock{{left: 200, right: 300}})
	if !present || !fresh || len(delivered) != 1 || len(outstanding) != 3 {
		t.Fatalf("partial SACK state = present %t fresh %t delivered %d segments %d", present, fresh, len(delivered), len(outstanding))
	}
	for index, want := range []struct {
		start, end uint32
		sacked     bool
		payload    int
		push       bool
	}{{100, 200, false, 100, false}, {200, 300, true, 100, false}, {300, 400, false, 100, true}} {
		segment := outstanding[index]
		if segment.sequence != want.start || segment.end != want.end || segment.sacked != want.sacked || len(segment.payload) != want.payload || segment.flags&tcpFlagPSH != 0 != want.push {
			t.Fatalf("segment %d = [%d,%d) sacked=%t payload=%d flags=%#x", index, segment.sequence, segment.end, segment.sacked, len(segment.payload), segment.flags)
		}
	}
}

func TestTCPSACKSplitMetadataIsBounded(t *testing.T) {
	payload := make([]byte, 4*tcpMaximumSACKSplitRanges)
	outstanding := []sentTCPSegment{{sequence: 0, end: uint32(len(payload)), payload: payload, transmissions: 1}}
	for offset := uint32(1); offset+1 < uint32(len(payload)); offset += 2 {
		outstanding, _, _, _, _, _ = applyTCPSACK(outstanding, []tcpSACKBlock{{left: offset, right: offset + 1}})
	}
	splitRanges := 0
	for _, segment := range outstanding {
		if segment.sackSplit {
			splitRanges++
		}
	}
	if splitRanges > tcpMaximumSACKSplitRanges {
		t.Fatalf("SACK-created ranges = %d, limit %d", splitRanges, tcpMaximumSACKSplitRanges)
	}
	if len(outstanding) > tcpMaximumSACKSplitRanges+1 {
		t.Fatalf("scoreboard ranges = %d after adversarial byte SACKs", len(outstanding))
	}
}

func TestTCPPeerMSSHasLinuxSafetyFloor(t *testing.T) {
	options := []byte{2, 4, 0, 1}
	mss, _, _, _, _, _ := parseTCPOptions(options, 536, 1400)
	if mss != tcpMinimumPeerMSS {
		t.Fatalf("one-byte peer MSS = %d, want Linux safety floor %d", mss, tcpMinimumPeerMSS)
	}
	if got := clampMSS(1, 16); got != 16 {
		t.Fatalf("path-derived MSS below peer safety floor = %d, want 16", got)
	}
	for _, test := range []struct {
		peer, path, options, want int
	}{
		{536, 1348, 28, 536},
		{48, 1348, 28, 48},
		{1348, 1348, 28, 1320},
	} {
		if got := tcpSegmentPayloadLimit(test.peer, test.path, test.options); got != test.want {
			t.Errorf("payload limit peer=%d path=%d options=%d = %d, want %d", test.peer, test.path, test.options, got, test.want)
		}
	}
}

// TestTCPSACKIsLostAndPipe verifies both RFC 6675 IsLost alternatives and
// SetPipe's required double accounting for a speculative retransmission.
func TestTCPSACKIsLostAndPipe(t *testing.T) {
	byRanges := []sentTCPSegment{
		{sequence: 0, end: 100},
		{sequence: 100, end: 150, sacked: true},
		{sequence: 150, end: 200, sacked: true},
		{sequence: 200, end: 250, sacked: true},
	}
	if !sackSegmentLost(byRanges, 0, 100) {
		t.Fatal("three SACKed transmitted ranges did not satisfy IsLost")
	}
	byBytes := []sentTCPSegment{{sequence: 0, end: 100}, {sequence: 100, end: 201, sacked: true}, {sequence: 201, end: 302, sacked: true}}
	if !sackSegmentLost(byBytes, 0, 100) {
		t.Fatal("more than 2*SMSS SACKed bytes did not satisfy IsLost")
	}
	byBytes[2].end = 300
	if sackSegmentLost(byBytes, 0, 100) {
		t.Fatal("exactly 2*SMSS SACKed bytes satisfied strict IsLost byte test")
	}
	speculative := []sentTCPSegment{{sequence: 0, end: 100, sackRetried: true}}
	if pipe := sackRecoveryPipe(speculative, 100); pipe != 200 {
		t.Fatalf("speculative retransmission pipe = %d, want 200", pipe)
	}
	lost := []sentTCPSegment{{sequence: 0, end: 100, rackLost: true}}
	if pipe := sackRecoveryPipe(lost, 100); pipe != 0 {
		t.Fatalf("unretransmitted lost range pipe = %d, want 0", pipe)
	}
	lost[0].sackRetried = true
	if pipe := sackRecoveryPipe(lost, 100); pipe != 100 {
		t.Fatalf("retransmitted RACK loss pipe = %d, want 100", pipe)
	}
	if flight := tcpCongestionFlight(speculative, true, true, 100); flight != 200 {
		t.Fatalf("SACK recovery congestion flight = %d, want 200", flight)
	}
	if flight := tcpCongestionFlight(speculative, true, false, 100); flight != 100 {
		t.Fatalf("ordinary congestion flight = %d, want 100", flight)
	}
	if !sackRecoveryCanSend(false, 1000, 100, 1000) {
		t.Fatal("recovery-entry retransmission was incorrectly cwnd-gated")
	}
	if sackRecoveryCanSend(true, 1000, 100, 1000) {
		t.Fatal("RFC 6675 allowed a retransmission without cwnd-Pipe space")
	}
	if !sackRecoveryCanSend(true, 900, 100, 1000) {
		t.Fatal("RFC 6675 rejected a retransmission with exactly one segment of space")
	}
	wrappedSACK := []sentTCPSegment{{sequence: 0xfffffff0, end: 0x10, sacked: true}, {sequence: 0x10, end: 0x30, sacked: true}}
	if highest := highestSACKedSequence(wrappedSACK); highest != 0x30 {
		t.Fatalf("wrapped HighSACK = %#x, want 0x30", highest)
	}
}

func TestTCPPRRDeliveryAndSendCount(t *testing.T) {
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, sacked: true},
		{sequence: 200, end: 300},
		{sequence: 300, end: 400},
	}
	if delivered := tcpNewlyAcknowledgedBytes(outstanding, 350); delivered != 150 {
		t.Fatalf("new cumulative delivery = %d, want 150", delivered)
	}
	if window := prrCongestionWindow(800, 500, 1000, 100, 0, 100, true, false, 100); window != 850 {
		t.Fatalf("PRR proportional window = %d, want 850", window)
	}
	if window := prrCongestionWindow(300, 500, 1000, 100, 0, 100, true, false, 100); window != 500 {
		t.Fatalf("PRR slow-start reduction window = %d, want 500", window)
	}
	if window := prrCongestionWindow(300, 500, 1000, 100, 0, 100, true, true, 100); window != 400 {
		t.Fatalf("PRR packet-conservation window with new loss = %d, want 400", window)
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

// TestTCPSACKCoalescesAdjacentPieces verifies that independently retained
// payloads still produce the contiguous SACK blocks required on the wire.
func TestTCPSACKCoalescesAdjacentPieces(t *testing.T) {
	pieces := []tcpReceivedPiece{
		{sequence: 100, payload: []byte("ab")},
		{sequence: 102, payload: []byte("cd")},
		{sequence: 106, payload: []byte("ef")},
	}
	options := tcpSACKOptions(pieces, 103, 4, tcpSACKBlock{}, false)
	blocks := parseTCPSACKOptions(options, 90, 120)
	if len(blocks) != 2 || blocks[0] != (tcpSACKBlock{left: 100, right: 104}) || blocks[1] != (tcpSACKBlock{left: 106, right: 108}) {
		t.Fatalf("coalesced SACK blocks = %#v", blocks)
	}
}

func TestTCPSACKBlockLimit(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")
	for _, test := range []struct {
		name           string
		mtu            int
		address        netip.Addr
		timestamp      bool
		reservePayload int
		want           int
	}{
		{name: "IPv4 maximum", mtu: 1500, address: ipv4, want: 4},
		{name: "IPv4 maximum with timestamp", mtu: 1500, address: ipv4, timestamp: true, want: 3},
		{name: "IPv4 minimum with payload", mtu: 68, address: ipv4, reservePayload: 1, want: 2},
		{name: "IPv4 small with timestamp", mtu: 68, address: ipv4, timestamp: true, reservePayload: 1, want: 1},
		{name: "too small", mtu: 59, address: ipv4, timestamp: true, want: 0},
		{name: "IPv6 minimum", mtu: 1280, address: ipv6, timestamp: true, reservePayload: 1, want: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpSACKBlockLimit(test.mtu, test.address, test.timestamp, test.reservePayload); got != test.want {
				t.Fatalf("tcpSACKBlockLimit = %d, want %d", got, test.want)
			}
		})
	}
}

// TestTCPSACKPiggybacksOnData verifies RFC 2018 feedback remains present on
// an ACK-bearing data segment while an out-of-order receive range is retained.
func TestTCPSACKPiggybacksOnData(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8081))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	clientPort := connection.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	link.mu.Lock()
	peer := link.tcp[clientPort]
	serverSequence := peer.serverNext
	clientAcknowledgement := peer.clientNext
	link.mu.Unlock()
	if err = link.deliverTCP(8081, clientPort, serverSequence+4, clientAcknowledgement, tcpFlagACK|tcpFlagPSH, 65535, nil, []byte("late")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientSACKs != 0
	})
	if _, err = connection.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientDataSACKs != 0
	})
}

func TestTCPDSACKGeneration(t *testing.T) {
	if block, ok := tcpDuplicateSACKBlock(90, 20, false, 100, nil); !ok || block != (tcpSACKBlock{left: 90, right: 100}) {
		t.Fatalf("below-ACK duplicate block = %#v, %t", block, ok)
	}
	pieces := []tcpReceivedPiece{{sequence: 120, payload: make([]byte, 20)}}
	block, ok := tcpDuplicateSACKBlock(125, 20, false, 100, pieces)
	if !ok || block != (tcpSACKBlock{left: 125, right: 140}) {
		t.Fatalf("contained duplicate block = %#v, %t", block, ok)
	}
	options := tcpSACKOptions(pieces, 125, 2, block, true)
	if len(options) != 18 || binary.BigEndian.Uint32(options[2:6]) != 125 || binary.BigEndian.Uint32(options[6:10]) != 140 ||
		binary.BigEndian.Uint32(options[10:14]) != 120 || binary.BigEndian.Uint32(options[14:18]) != 140 {
		t.Fatalf("DSACK-first options = %x", options)
	}
}

// TestTCPOutOfOrderOverlapPreservesFirstData verifies overlap handling while
// queued payloads remain independently allocated.
func TestTCPOutOfOrderOverlapPreservesFirstData(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readChanged: make(chan struct{}), readNotify: make(chan struct{})}
	receiveNext := uint32(100)
	outOfOrder := []tcpReceivedPiece{{sequence: 104, payload: []byte("old")}}
	outOfOrderBytes := 3
	if !connection.storeTCPOutOfOrder(receiveNext, 32, 102, []byte("abcdef"), false, &outOfOrder, &outOfOrderBytes) {
		t.Fatal("overlapping segment added no new data")
	}
	if len(outOfOrder) != 3 || outOfOrderBytes != 6 {
		t.Fatalf("out-of-order state = %d pieces, %d bytes; want 3, 6", len(outOfOrder), outOfOrderBytes)
	}
	if delivered, closed := connection.receiveTCPData(100, []byte("00"), false, 32, &receiveNext, &outOfOrder, &outOfOrderBytes); !delivered || closed {
		t.Fatalf("receiveTCPData = %t, %t; want true, false", delivered, closed)
	}
	if got := string(connection.readBuffer); got != "00aboldf" {
		t.Fatalf("overlap payload = %q, want %q", got, "00aboldf")
	}
}

// TestTCPOutOfOrderUsesPromisedWindow verifies that sparse data near the
// advertised right edge remains admissible after another range uses memory.
func TestTCPOutOfOrderUsesPromisedWindow(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readChanged: make(chan struct{}), readNotify: make(chan struct{})}
	receiveNext := uint32(100)
	var outOfOrder []tcpReceivedPiece
	outOfOrderBytes := 0
	if !connection.storeTCPOutOfOrder(receiveNext, 32, 120, []byte("first"), false, &outOfOrder, &outOfOrderBytes) {
		t.Fatal("first out-of-order range was rejected")
	}
	if !connection.storeTCPOutOfOrder(receiveNext, 32, 128, []byte("edge"), false, &outOfOrder, &outOfOrderBytes) {
		t.Fatal("range at the promised right edge was rejected after buffer use")
	}
	if outOfOrderBytes != 9 {
		t.Fatalf("out-of-order bytes = %d, want 9", outOfOrderBytes)
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

func TestTCPInboundQueueHasByteCapacity(t *testing.T) {
	_, stack := newTestStack(t, netip.MustParseAddr("192.0.2.76"), netip.MustParseAddr("198.51.100.76"))
	connection := newTCPConn(stack, "tcp4", tcpKey{}, 1500)
	segment := tcpSegment{payload: make([]byte, 65535)}
	accepted := 0
	for connection.enqueueInbound(segment) {
		accepted++
	}
	if accepted == 0 || accepted >= tcpInboundQueue {
		t.Fatalf("maximum-size queued segments = %d, want byte limit before count limit", accepted)
	}
	if queued := connection.inboundBytes.Load(); queued > tcpInboundByteCapacity {
		t.Fatalf("queued TCP bytes = %d, limit %d", queued, tcpInboundByteCapacity)
	}
	consumed := connection.consumeInbound(<-connection.inbound)
	if consumed.retainedBytes != 0 {
		t.Fatalf("consumed segment retained accounting = %d", consumed.retainedBytes)
	}
	if !connection.enqueueInbound(segment) {
		t.Fatal("released inbound byte capacity was not reusable")
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

// TestTCPZeroWindowProbePreservesSequenceSpace verifies that persist recovery
// probes an acknowledged byte without consuming pending sequence space.
func TestTCPZeroWindowProbePreservesSequenceSpace(t *testing.T) {
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
		if got := binary.BigEndian.Uint32(parsed.payload[4:8]); got != acknowledgement-1 {
			t.Fatalf("persist sequence = %d, want %d", got, acknowledgement-1)
		}
		if data := parsed.payload[headerSize:]; !bytes.Equal(data, tcpZeroWindowProbe[:]) {
			t.Fatalf("persist payload = %x, want %x", data, tcpZeroWindowProbe)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for persist probe")
	}
	if probes := stack.Stats().TCPZeroWindowProbes; probes != 1 {
		t.Fatalf("zero-window probes = %d, want 1", probes)
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-link.outbound:
		parsed, ok := parseIPPacket(packet)
		if !ok || parsed.protocol != protocolTCP {
			t.Fatalf("invalid post-persist packet: %x", packet)
		}
		headerSize := int(parsed.payload[12]>>4) * 4
		if got := binary.BigEndian.Uint32(parsed.payload[4:8]); got != acknowledgement {
			t.Fatalf("post-persist sequence = %d, want %d", got, acknowledgement)
		}
		if data := parsed.payload[headerSize:]; !bytes.Equal(data, []byte("probe")) {
			t.Fatalf("post-persist payload = %q, want %q", data, "probe")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pending data after window update")
	}
}

// TestTCPZeroWindowRetainsOutstandingRetransmission verifies Linux's split
// between packets_out recovery and persist: a zero window cannot abandon data
// that was already transmitted, while no persist probe is needed for it.
func TestTCPZeroWindowRetainsOutstandingRetransmission(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9106))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)

	link.mu.Lock()
	link.echoTCP = false
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	for {
		select {
		case <-link.outbound:
		default:
			goto drained
		}
	}

drained:
	if n, writeErr := connection.Write([]byte("outstanding")); writeErr != nil || n != len("outstanding") {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	select {
	case <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial data segment")
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return stack.Stats().TCPRetransmissions != 0 })
	stats := stack.Stats()
	if stats.TCPRetransmissions == 0 {
		t.Fatal("outstanding data lost its retransmission timer during zero window")
	}
	if stats.TCPZeroWindowProbes != 0 {
		t.Fatalf("zero-window probes with packets_out = %d, want 0", stats.TCPZeroWindowProbes)
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
	link.mu.Unlock()
	stale := buildTestTCP(link.remote, link.local, tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 65535, tcpTimestampOptions(1, 0), []byte("stale"))
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

// TestTCPPureACKAdvancesPAWS verifies RFC 7323's SEG.SEQ <= Last.ACK.sent
// update rule, which Linux applies to an acceptable timestamped pure ACK.
func TestTCPPureACKAdvancesPAWS(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.timestampTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9108))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)

	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	baseTimestamp := peer.timestamp
	link.mu.Unlock()
	deliver := func(timestamp uint32, payload []byte) {
		t.Helper()
		packet := buildTestTCP(link.remote, link.local, tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 65535, tcpTimestampOptions(timestamp, 0), payload)
		if writeErr := writeTestPacket(stack, packet); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	deliver(baseTimestamp+100, nil)
	deliver(baseTimestamp+1, []byte("data"))
	_ = connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	payload := make([]byte, 4)
	if n, readErr := connection.Read(payload); n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("stale data after newer pure ACK = %d, %v", n, readErr)
	}
	deliver(baseTimestamp+101, []byte("data"))
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = io.ReadFull(connection, payload); err != nil || string(payload) != "data" {
		t.Fatalf("fresh data after newer pure ACK = %q, %v", payload, err)
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
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	link.mu.Lock()
	baselineCWR := link.clientCWRs
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, []byte("retransmitted without ECT"))
	// A retransmitted TLP tail is confirmed as a loss only by the following
	// cumulative ACK. The next new segment then carries the reliable CWR.
	writeAndReadTCPEcho(t, connection, []byte("advance past TLP"))
	writeAndReadTCPEcho(t, connection, []byte("carry CWR"))
	link.mu.Lock()
	initialECT, retransmittedECT, cwrPackets := link.clientECTPackets, link.clientRetransmittedECT, link.clientCWRs
	link.mu.Unlock()
	if initialECT == 0 {
		t.Fatal("initial ECN-capable data was not marked ECT")
	}
	if retransmittedECT != 0 {
		t.Fatalf("ECT-marked retransmissions = %d, want 0", retransmittedECT)
	}
	if cwrPackets <= baselineCWR {
		t.Fatal("loss recovery did not send CWR on subsequent new data")
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

func TestTCPDelayedECNSYNACKDoesNotUndoFallback(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.74")
	remote := netip.MustParseAddr("198.51.100.74")
	link, stack := newTestStack(t, local, remote)
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local: netip.AddrPortFrom(local, 45000), remote: netip.AddrPortFrom(remote, 8080),
	}, 1400)
	result := make(chan error, 1)
	go func() { result <- connection.handshake(1000) }()
	readSYN := func() []byte {
		select {
		case packet := <-link.outbound:
			return packet
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for active SYN")
			return nil
		}
	}
	first := readSYN()
	parsed, ok := parseIPPacket(first)
	if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13]&(tcpFlagECE|tcpFlagCWR) != tcpFlagECE|tcpFlagCWR {
		t.Fatalf("initial setup SYN = %x", first)
	}
	second := readSYN()
	parsed, ok = parseIPPacket(second)
	if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13]&(tcpFlagECE|tcpFlagCWR) != 0 {
		t.Fatalf("fallback SYN = %x", second)
	}
	connection.inbound <- tcpSegment{
		sequence: 2000, acknowledgement: 1001, flags: tcpFlagSYN | tcpFlagACK | tcpFlagECE, window: 65535,
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("delayed ECN SYN-ACK did not complete fallback handshake")
	}
	if connection.peerECN {
		t.Fatal("delayed setup SYN-ACK re-enabled ECN after fallback")
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

func TestTCPReservedHeaderBitsAreIgnored(t *testing.T) {
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
	if dropped := stack.Stats().InboundDroppedPackets; dropped != 0 {
		t.Fatalf("reserved TCP header bits dropped packets = %d, want 0", dropped)
	}
	select {
	case response := <-stack.outbound:
		parsed, ok := parseIPPacket(response)
		if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13] != tcpFlagRST|tcpFlagACK {
			t.Fatalf("reserved TCP header response = %x", response)
		}
	case <-time.After(time.Second):
		t.Fatal("reserved TCP header was not processed")
	}
}

func TestRTTSampleIsSaturatedBeforeArithmetic(t *testing.T) {
	estimator := rttEstimator{}
	estimator.observe(time.Duration(1<<63 - 1))
	if estimator.srtt != tcpMaximumRTO || estimator.rto != tcpMaximumRTO || estimator.minimum != tcpMaximumRTO {
		t.Fatalf("saturated RTT estimator = srtt %v rto %v minimum %v", estimator.srtt, estimator.rto, estimator.minimum)
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
	t.Run("outstanding data defers keepalive", func(t *testing.T) {
		link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
		defer stack.Close()
		link.echoTCP = true
		connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9303))
		if err != nil {
			t.Fatal(err)
		}
		tcpConnection := connection.(*TCPConn)
		defer tcpConnection.Close()
		if err = tcpConnection.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		link.mu.Lock()
		link.echoTCP = false
		link.mu.Unlock()
		if err = tcpConnection.SetKeepAliveConfig(KeepAliveConfig{Idle: 10 * time.Millisecond, Interval: 10 * time.Millisecond, Count: 1}); err != nil {
			t.Fatal(err)
		}
		if err = tcpConnection.SetKeepAlive(true); err != nil {
			t.Fatal(err)
		}
		if _, err = tcpConnection.Write([]byte("unacknowledged")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond)
		if probes := stack.Stats().TCPKeepAliveProbes; probes != 0 {
			t.Fatalf("keepalive probes with outstanding data = %d, want 0", probes)
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
