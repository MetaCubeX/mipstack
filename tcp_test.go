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
	"runtime"
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
	listenerInfo := listener.Info()
	if listenerInfo.LocalAddress != serverEndpoint || listenerInfo.Closed || listenerInfo.AcceptQueueConnections != 0 ||
		listenerInfo.SYNBacklogConnections != 0 || listenerInfo.AcceptQueueCapacity == 0 || listenerInfo.SYNBacklogCapacity == 0 ||
		listenerInfo.AcceptQueuePeak > 1 || listenerInfo.SYNBacklogPeak != 1 || listenerInfo.SYNsReceived != 1 ||
		listenerInfo.StatefulHandshakes != 1 || listenerInfo.HandshakeCompletions != 1 || listenerInfo.AcceptedConnections != 1 {
		t.Fatalf("listener diagnostics after Accept = %+v", listenerInfo)
	}
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
	if closedInfo := listener.Info(); !closedInfo.Closed || closedInfo.AcceptedConnections != 1 ||
		closedInfo.AcceptQueueCapacity != listenerInfo.AcceptQueueCapacity || closedInfo.SYNBacklogCapacity != listenerInfo.SYNBacklogCapacity {
		t.Fatalf("closed listener diagnostics = %+v", closedInfo)
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

func TestTCPDestinationPortZeroUsesProtocolPath(t *testing.T) {
	for _, test := range []struct {
		name           string
		network        string
		client, server netip.Addr
	}{
		{name: "IPv4", network: "tcp4", client: netip.MustParseAddr("192.0.2.232"), server: netip.MustParseAddr("192.0.2.233")},
		{name: "IPv6", network: "tcp6", client: netip.MustParseAddr("2001:db8::232"), server: netip.MustParseAddr("2001:db8::233")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newStackPair(t, test.client, test.server, 1400)
			newStackBridge(t, client, server)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := client.DialTCP(ctx, test.network, netip.AddrPort{}, netip.AddrPortFrom(test.server, 0)); !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("DialTCP to port zero = %v, want ECONNREFUSED", err)
			}
		})
	}
}

// TestTCPListenerCloseReleasesPendingOwnership verifies that a closed
// listener does not retain its accept channel or unaccepted connection maps.
func TestTCPListenerCloseReleasesPendingOwnership(t *testing.T) {
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.251/32")}})
	if err != nil {
		t.Fatal(err)
	}
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local:  netip.MustParseAddrPort("192.0.2.251:443"),
		remote: netip.MustParseAddrPort("198.51.100.251:50000"),
	}, 1400, tcpSocketOptionSet{})

	listener := &TCPListener{
		stack: stack, net: "tcp4", local: netip.MustParseAddrPort("192.0.2.251:443"), accept: make(chan *TCPConn, 1024), closed: make(chan struct{}),
		pending: map[*TCPConn]struct{}{connection: {}}, handshaking: map[*TCPConn]struct{}{connection: {}},
	}
	if err = listener.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	listener.accept <- connection
	listener.closeFromStack()
	listener.mu.Lock()
	released := listener.accept == nil && listener.pending == nil && listener.handshaking == nil && listener.deadline.timer == nil
	listener.mu.Unlock()
	if !released {
		t.Fatal("closed listener retained accept or pending connection storage")
	}
	select {
	case <-connection.abortCh:
	default:
		t.Fatal("closed listener did not abort its pending connection")
	}
}

// TestStackCloseEventuallyReleasesTCPBuffers verifies that Stack.Close only
// signals the actor synchronously but that actor termination releases all
// payload-bearing connection-owned queues within a bounded interval.
func TestStackCloseEventuallyReleasesTCPBuffers(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.252:40000")
	remote := netip.MustParseAddrPort("198.51.100.252:443")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local.Addr(), 32)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	connection := newTCPConn(stack, "tcp4", tcpKey{local: local, remote: remote}, 1400, tcpSocketOptionSet{})
	connection.connected = make(chan error, 1)
	payload := make([]byte, 1<<20)
	connection.mu.Lock()
	connection.readBuffer.append(payload)
	connection.sendBuffer.append(payload)
	connection.mu.Unlock()
	if err = connection.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	connection.deliverError(errors.New("retained network error"))
	stack.tcp[connection.key] = connection
	stack.stats.activeTCPConnections.Add(1)
	go connection.run(1)
	if err = stack.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.done:
	case <-time.After(time.Second):
		t.Fatal("TCP actor did not terminate after Stack.Close")
	}
	connection.mu.Lock()
	released := connection.readBuffer.size == 0 && connection.readBuffer.chunks == nil &&
		connection.sendBuffer.size == 0 && connection.sendBuffer.chunks == nil && connection.sendBuffer.spare == nil &&
		connection.networkError == nil && connection.readDeadline.timer == nil && connection.writeDeadline.timer == nil
	connection.mu.Unlock()
	if !released || connection.inbound.retainedBytes() != 0 {
		t.Fatal("terminated TCP connection retained payload-bearing buffers")
	}
}

func TestTCPListenerCompletedConnectionsLeaveSYNBacklog(t *testing.T) {
	listener := &TCPListener{
		accept: make(chan *TCPConn, 2), closed: make(chan struct{}), backlog: 1,
		pending: make(map[*TCPConn]struct{}), handshaking: make(map[*TCPConn]struct{}),
	}
	first, second := &TCPConn{}, &TCPConn{}
	if !listener.trackHandshake(first) || !listener.enqueue(first) {
		t.Fatal("first handshake did not enter the accept queue")
	}
	info := listener.Info()
	if info.SYNBacklogConnections != 0 || info.AcceptQueueConnections != 1 {
		t.Fatalf("completed handshake queue accounting = %+v", info)
	}
	if !listener.trackHandshake(second) {
		t.Fatal("completed connection continued to consume the SYN backlog")
	}
}

func TestTCPStateString(t *testing.T) {
	tests := []struct {
		state TCPState
		name  string
	}{
		{TCPStateClosed, "CLOSED"},
		{TCPStateSYNReceived, "SYN-RECEIVED"},
		{TCPStateSYNSent, "SYN-SENT"},
		{TCPStateEstablished, "ESTABLISHED"},
		{TCPStateFINWait1, "FIN-WAIT-1"},
		{TCPStateFINWait2, "FIN-WAIT-2"},
		{TCPStateCloseWait, "CLOSE-WAIT"},
		{TCPStateClosing, "CLOSING"},
		{TCPStateLastACK, "LAST-ACK"},
		{TCPStateTimeWait, "TIME-WAIT"},
		{TCPState(255), "CLOSED"},
	}
	for _, test := range tests {
		if name := test.state.String(); name != test.name {
			t.Errorf("TCPState(%d).String() = %q, want %q", test.state, name, test.name)
		}
	}
}

func TestTCPConnectionInfo(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.211")
	serverAddress := netip.MustParseAddr("192.0.2.212")
	client, server := newStackPair(t, clientAddress, serverAddress, 1400)
	newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp", netip.AddrPortFrom(serverAddress, 45200))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := client.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, 45200))
	if err != nil {
		t.Fatal(err)
	}
	clientConnection := connection.(*TCPConn)
	serverConnection, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConnection.Close()

	payload := []byte("connection diagnostics")
	if _, err = clientConnection.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(serverConnection, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return clientConnection.Info().BytesAcknowledged >= uint64(len(payload)) })
	info := clientConnection.Info()
	if info.State != TCPStateEstablished || info.State.String() != "ESTABLISHED" || info.LocalAddress.Addr() != clientAddress || info.RemoteAddress.Addr() != serverAddress {
		t.Fatalf("connection identity/state = %+v", info)
	}
	if info.CongestionControl != CongestionControlCUBIC || info.RTT <= 0 || info.RetransmissionTimeout <= 0 ||
		info.CongestionWindow == 0 || info.MaximumSegmentSize <= 0 || info.PathMTU != 1400 ||
		!info.WindowScaling || info.ReceiveWindowScale == 0 || !info.SACK || !info.Timestamps || !info.NoDelay ||
		info.KeepAliveConfig.Idle <= 0 || info.KeepAliveConfig.Interval <= 0 || info.KeepAliveConfig.Count <= 0 ||
		info.BytesSent < uint64(len(payload)) {
		t.Fatalf("incomplete live TCP diagnostics: %+v", info)
	}
	if err = clientConnection.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err = clientConnection.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clientConnection.done:
	case <-time.After(time.Second):
		t.Fatal("abortive close did not terminate TCP actor")
	}
	closed := clientConnection.Info()
	if closed.State != TCPStateClosed || closed.LastError == nil || closed.BytesAcknowledged < uint64(len(payload)) {
		t.Fatalf("final TCP diagnostics = %+v", closed)
	}
}

func TestTCPIPv6FlowLabelPolicy(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::194")
	remote := netip.MustParseAddr("2001:db8::195")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}})
	if err != nil {
		t.Fatal(err)
	}
	key := tcpKey{local: netip.AddrPortFrom(local, 40000), remote: netip.AddrPortFrom(remote, 443)}
	connection := newTCPConn(stack, "tcp6", key, 1500, tcpSocketOptionSet{})
	if connection.flowLabel == 0 {
		t.Fatal("automatic TCP flow label is zero")
	}
	if second := newTCPConn(stack, "tcp6", key, 1500, tcpSocketOptionSet{}); second.flowLabel != connection.flowLabel {
		t.Fatalf("automatic TCP flow labels = %#x and %#x", connection.flowLabel, second.flowLabel)
	}
	explicit, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)},
		TCP:            TCPSocketDefaults{FlowLabel: 0x45678},
	})
	if err != nil {
		t.Fatal(err)
	}
	if label := newTCPConn(explicit, "tcp6", key, 1500, tcpSocketOptionSet{}).flowLabel; label != 0x45678 {
		t.Fatalf("configured TCP flow label = %#x, want 0x45678", label)
	}
}

func TestTCPUserTimeoutClosesUnacknowledgedConnection(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.132"), netip.MustParseAddr("192.0.2.133"))
	link.echoTCP = true
	link.dropTCPData = 100
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.133:443"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*TCPConn)
	if err = tcp.SetUserTimeout(75 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err = tcp.SetUserTimeout(-time.Second); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("negative SetUserTimeout = %v, want EINVAL", err)
	}
	if _, err = tcp.Write([]byte("unacknowledged")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tcp.done:
	case <-time.After(time.Second):
		t.Fatal("TCP user timeout did not terminate the connection")
	}
	info := tcp.Info()
	if info.UserTimeout != 75*time.Millisecond || !errors.Is(info.LastError, syscall.ETIMEDOUT) {
		t.Fatalf("TCP user-timeout info = %+v", info)
	}
}

func TestTCPUserTimeoutClosesZeroWindowConnection(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.136"), netip.MustParseAddr("192.0.2.137"))
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.137:443"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*TCPConn)
	if err = tcp.SetUserTimeout(75 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	link.useTCPWindow = true
	link.advertisedTCPWindow = 0
	link.mu.Unlock()
	if _, err = tcp.Write([]byte("close the window")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return tcp.Info().PeerWindow == 0 })
	if _, err = tcp.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tcp.done:
	case <-time.After(time.Second):
		t.Fatal("TCP user timeout did not terminate a zero-window connection")
	}
	if !errors.Is(tcp.Info().LastError, syscall.ETIMEDOUT) {
		t.Fatalf("zero-window user timeout = %+v", tcp.Info())
	}
}

func TestTCPUserTimeoutDisarmsAfterAcknowledgement(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.138"), netip.MustParseAddr("192.0.2.139"))
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.139:443"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*TCPConn)
	if err = tcp.SetUserTimeout(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err = tcp.Write([]byte("acknowledge")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if n, readErr := io.ReadFull(tcp, buffer[:11]); readErr != nil || string(buffer[:n]) != "acknowledge" {
		t.Fatalf("acknowledged echo = %q, %v", buffer[:n], readErr)
	}
	time.Sleep(100 * time.Millisecond)
	select {
	case <-tcp.done:
		t.Fatalf("acknowledged connection hit user timeout: %+v", tcp.Info())
	default:
	}
	_ = tcp.Close()
}

func TestTCPUserTimeoutOverridesKeepAliveCount(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.140"), netip.MustParseAddr("192.0.2.141"))
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.MustParseAddrPort("192.0.2.141:443"))
	if err != nil {
		t.Fatal(err)
	}
	tcp := connection.(*TCPConn)
	if err = tcp.SetKeepAliveConfig(KeepAliveConfig{Idle: 20 * time.Millisecond, Interval: 10 * time.Millisecond, Count: 1}); err != nil {
		t.Fatal(err)
	}
	if err = tcp.SetUserTimeout(150 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err = tcp.SetKeepAlive(true); err != nil {
		t.Fatal(err)
	}
	link.mu.Lock()
	link.echoTCP = false
	link.mu.Unlock()
	started := time.Now()
	select {
	case <-tcp.done:
	case <-time.After(time.Second):
		t.Fatal("keepalive user timeout did not terminate the connection")
	}
	elapsed := time.Since(started)
	if elapsed < 100*time.Millisecond || !errors.Is(tcp.Info().LastError, syscall.ETIMEDOUT) {
		t.Fatalf("keepalive user timeout after %v: %+v", elapsed, tcp.Info())
	}
}

func TestTCPFullDuplexSustainedTrafficHasNoLocalDrops(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.142")
	serverAddress := netip.MustParseAddr("192.0.2.143")
	client, server := newStackPair(t, clientAddress, serverAddress, 1500)
	newStackBridge(t, client, server)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- connection
		_, _ = io.Copy(connection, connection)
	}()
	connection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, listener.Addr().(*net.TCPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	serverConnection := <-accepted
	if serverConnection == nil {
		t.Fatal("server did not accept stress connection")
	}
	t.Cleanup(func() {
		_ = connection.Close()
		_ = serverConnection.Close()
		_ = listener.Close()
	})
	payload := bytes.Repeat([]byte{0x5c}, 8*1024*1024)
	received := make([]byte, len(payload))
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := connection.Write(payload)
		writeDone <- writeErr
	}()
	if _, err = io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if err = <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("full-duplex stress payload mismatch")
	}
	tcp := connection.(*TCPConn)
	waitFor(t, 2*time.Second, func() bool { return tcp.Info().BytesInFlight == 0 })
	clientStats, serverStats := client.Stats(), server.Stats()
	if clientStats.InboundDroppedPackets != 0 || serverStats.InboundDroppedPackets != 0 {
		t.Fatalf("full-duplex stress diagnostics: client=%+v server=%+v connection=%+v", clientStats, serverStats, tcp.Info())
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

type tcpTestWriterFunc func([]byte) (int, error)

func (f tcpTestWriterFunc) Write(payload []byte) (int, error) { return f(payload) }

func TestTCPWriteToKeepsDirectChunkStableWhileReceiving(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.mu.Lock()
	connection.readBuffer.append([]byte("first"))
	connection.readErr = io.EOF
	connection.mu.Unlock()
	var received bytes.Buffer
	writes := 0
	n, err := connection.WriteTo(tcpTestWriterFunc(func(payload []byte) (int, error) {
		writes++
		if writes == 1 {
			if string(payload) != "first" {
				t.Fatalf("first direct WriteTo chunk = %q", payload)
			}
			second := []byte("second")
			if accepted := connection.appendReadBuffer(second, second, 0); accepted != len(second) {
				t.Fatalf("concurrent receive accepted %d bytes", accepted)
			}
			if string(payload) != "first" {
				t.Fatalf("concurrent receive changed direct WriteTo chunk to %q", payload)
			}
		}
		return received.Write(payload)
	}))
	if err != nil || n != int64(len("firstsecond")) || received.String() != "firstsecond" || writes != 2 {
		t.Fatalf("direct WriteTo = %d, %v, data %q, writes %d", n, err, received.String(), writes)
	}
}

func TestTCPReadBufferAdoptsOwnedPayload(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	payload := []byte("data")
	payload = payload[:len(payload):len(payload)]
	if accepted := connection.appendReadBuffer(payload, payload, 0); accepted != len(payload) {
		t.Fatalf("appendReadBuffer accepted %d bytes, want %d", accepted, len(payload))
	}
	if &connection.readBuffer.chunks[0][0] != &payload[0] {
		t.Fatal("empty receive buffer did not adopt actor-owned payload")
	}
	buffer := make([]byte, len(payload))
	if n, err := connection.read(buffer); err != nil || n != len(payload) || string(buffer) != "data" {
		t.Fatalf("Read = %d, %q, %v; want 4, data, nil", n, buffer, err)
	}
}

func TestTCPReadCrossesReceiveChunks(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	for _, payload := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
		if accepted := connection.appendReadBuffer(payload, payload, 0); accepted != len(payload) {
			t.Fatalf("accepted %d of %d bytes", accepted, len(payload))
		}
	}
	buffer := make([]byte, len("onetwothree"))
	if n, err := connection.Read(buffer); err != nil || n != len(buffer) || string(buffer) != "onetwothree" {
		t.Fatalf("cross-chunk Read = %d, %v, %q", n, err, buffer)
	}
	if connection.readBuffer.size != 0 || connection.readBuffer.head != 0 || len(connection.readBuffer.chunks) != 0 {
		t.Fatalf("drained receive deque = size %d head %d chunks %d", connection.readBuffer.size, connection.readBuffer.head, len(connection.readBuffer.chunks))
	}
}

func TestTCPWriteToBatchesReceiveChunks(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	const chunks = 40
	chunk := bytes.Repeat([]byte{0x5a}, 1024)
	for index := 0; index < chunks; index++ {
		connection.readBuffer.append(append([]byte(nil), chunk...))
	}
	connection.readErr = io.EOF
	writes := 0
	n, err := connection.WriteTo(tcpTestWriterFunc(func(payload []byte) (int, error) {
		writes++
		if len(payload) > 32*1024 {
			t.Fatalf("WriteTo batch = %d bytes", len(payload))
		}
		return len(payload), nil
	}))
	if err != nil || n != chunks*1024 || writes != 2 {
		t.Fatalf("chunked WriteTo = %d, %v, writes %d; want %d, nil, 2", n, err, writes, chunks*1024)
	}
}

func TestTCPReadDequeReleasesLargeMetadataBurst(t *testing.T) {
	var buffer tcpReadBuffer
	for index := 0; index <= tcpReadChunkRetain; index++ {
		buffer.append([]byte{byte(index)})
	}
	destination := make([]byte, buffer.size)
	if n := buffer.read(destination, len(destination), nil); n != len(destination) {
		t.Fatalf("deque read = %d, want %d", n, len(destination))
	}
	if buffer.chunks != nil {
		t.Fatalf("large drained deque retained capacity %d", cap(buffer.chunks))
	}
}

func TestTCPSegmentQueueReusesOneReceivePayload(t *testing.T) {
	queue := newTCPSegmentQueue()
	first := bytes.Repeat([]byte{0x31}, 1500)
	if !queue.enqueueCopy(tcpSegment{}, first) {
		t.Fatal("first copied segment was rejected")
	}
	segment, ok := queue.dequeue()
	if !ok || !bytes.Equal(segment.payload, first) {
		t.Fatal("first copied segment payload mismatch")
	}
	backing := &segment.payload[0]
	queue.recyclePayload(segment.payload)
	second := bytes.Repeat([]byte{0x52}, 1500)
	if !queue.enqueueCopy(tcpSegment{}, second) {
		t.Fatal("second copied segment was rejected")
	}
	segment, ok = queue.dequeue()
	if !ok || !bytes.Equal(segment.payload, second) || &segment.payload[0] != backing {
		t.Fatal("receive payload backing was not safely reused")
	}
	queue.recyclePayload(segment.payload)
	queue.bytes = tcpInboundByteCapacity
	if allocations := testing.AllocsPerRun(100, func() {
		if queue.enqueueCopy(tcpSegment{}, second[:1]) {
			t.Fatal("full actor queue accepted another payload")
		}
	}); allocations != 0 {
		t.Fatalf("full-queue drop allocations = %v, want 0", allocations)
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

func TestTCPTimeWaitAcceptsRetransmittedFINWithAdditionalFlags(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.183"), netip.MustParseAddr("192.0.2.184"))
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8080))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	defer connection.Close()
	if err = tcpConnection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("peer FIN read = %d, %v", n, readErr)
	}
	waitFor(t, time.Second, func() bool { return stack.Stats().ActiveTCPConnections == 1 })
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	if peer == nil || !peer.finSent {
		link.mu.Unlock()
		t.Fatal("test peer did not complete the active close")
	}
	sequence := peer.serverNext - 1
	acknowledgement := peer.clientNext
	ackCount := link.clientACKs
	link.mu.Unlock()
	stack.controlMu.Lock()
	stack.controlLimiters[controlResponseTCPChallengeACK] = tokenBucket{updated: time.Now().Add(time.Hour)}
	stack.controlMu.Unlock()
	if err = link.deliverTCP(8080, tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK|tcpFlagFIN|tcpFlagPSH, 65535, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs > ackCount
	})
}

func testTCPHandshake(connection *TCPConn, initialSequence uint32) error {
	timer := newOwnedTimer()
	defer timer.close()
	return connection.handshake(initialSequence, timer, nil)
}

func testTCPPassiveHandshake(connection *TCPConn, syn tcpSegment, initialSequence uint32) error {
	timer := newOwnedTimer()
	defer timer.close()
	return connection.passiveHandshake(syn, initialSequence, timer)
}

func TestTCPActiveHandshakeProcessesSYNACKText(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.69")
	remote := netip.MustParseAddr("198.51.100.69")
	link, stack := newTestStack(t, local, remote)
	type dialResult struct {
		connection net.Conn
		err        error
	}
	result := make(chan dialResult, 1)
	go func() {
		connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(remote, 8080))
		result <- dialResult{connection: connection, err: err}
	}()
	var synPacket []byte
	select {
	case synPacket = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for active SYN")
	}
	parsed, ok := parseIPPacket(synPacket)
	if !ok || parsed.protocol != protocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("active SYN = %x", synPacket)
	}
	tcp := parsed.payload
	clientPort := binary.BigEndian.Uint16(tcp[0:2])
	clientSequence := binary.BigEndian.Uint32(tcp[4:8])
	payload := []byte("syn-ack text")
	response := buildTestTCP(remote, local, 8080, clientPort, 2000, clientSequence+1, tcpFlagSYN|tcpFlagACK|tcpFlagFIN, 65535, nil, payload)
	if err := writeTestPacket(stack, response); err != nil {
		t.Fatal(err)
	}
	var connection net.Conn
	select {
	case opened := <-result:
		if opened.err != nil {
			t.Fatal(opened.err)
		}
		connection = opened.connection
	case <-time.After(time.Second):
		t.Fatal("SYN-ACK text did not complete active open")
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("SYN-ACK text = %q, want %q", received, payload)
	}
	if n, err := connection.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("SYN-ACK FIN read = %d, %v", n, err)
	}
}

func TestTCPPassiveHandshakeProcessesSYNText(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.70")
	remote := netip.MustParseAddr("198.51.100.70")
	link, stack := newTestStack(t, local, remote)
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	localPort := listener.Addr().(*net.TCPAddr).AddrPort().Port()
	const (
		remotePort     = 45000
		remoteSequence = 100
	)
	payload := []byte("syn text")
	syn := buildTestTCP(remote, local, remotePort, localPort, remoteSequence, 0, tcpFlagSYN|tcpFlagFIN, 65535, nil, payload)
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	var synACKPacket []byte
	select {
	case synACKPacket = <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for passive SYN-ACK")
	}
	parsed, ok := parseIPPacket(synACKPacket)
	if !ok || parsed.protocol != protocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("passive SYN-ACK = %x", synACKPacket)
	}
	tcp := parsed.payload
	serverSequence := binary.BigEndian.Uint32(tcp[4:8])
	if acknowledgement := binary.BigEndian.Uint32(tcp[8:12]); acknowledgement != remoteSequence+1 {
		t.Fatalf("SYN-ACK acknowledgement = %d, want SYN-only %d", acknowledgement, remoteSequence+1)
	}
	finalSequence := uint32(remoteSequence + 1 + len(payload) + 1)
	finalACK := buildTestTCP(remote, local, remotePort, localPort, finalSequence, serverSequence+1, tcpFlagACK, 65535, nil, nil)
	if err = writeTestPacket(stack, finalACK); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("SYN text = %q, want %q", received, payload)
	}
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("SYN FIN read = %d, %v", n, readErr)
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
		{
			name: "unexpected SYN", segment: tcpSegment{sequence: 101, acknowledgement: 1001, flags: tcpFlagSYN | tcpFlagACK},
			wantFlags: tcpFlagACK, wantSeq: 1001, wantACK: 101,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := netip.MustParseAddr("192.0.2.71")
			remote := netip.MustParseAddr("198.51.100.71")
			link, stack := newTestStack(t, local, remote)
			connection := newTCPConn(stack, "tcp4", tcpKey{
				local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 45000),
			}, 1400, tcpSocketOptionSet{})

			connection.passive = true
			result := make(chan error, 1)
			go func() {
				result <- testTCPPassiveHandshake(connection, tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535}, 1000)
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
			enqueueTCPTestSegment(t, connection, test.segment)
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
	}, 1400, tcpSocketOptionSet{})

	connection.passive = true
	result := make(chan error, 1)
	go func() {
		result <- testTCPPassiveHandshake(connection, tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535}, 1000)
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
	enqueueTCPTestSegment(t, connection, finalACK)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("acceptable out-of-order final ACK did not complete handshake")
	}
	select {
	case <-connection.inbound.notify:
		queued, ok := connection.inbound.dequeue()
		if !ok {
			t.Fatal("out-of-order final ACK notification had no segment")
		}
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
	}, 1400, tcpSocketOptionSet{})

	connection.passive = true
	result := make(chan error, 1)
	go func() {
		result <- testTCPPassiveHandshake(connection, tcpSegment{
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
	enqueueTCPTestSegment(t, connection, tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535})
	if flags := readFlags(); flags&tcpFlagECE != 0 {
		t.Fatalf("fallback SYN-ACK retained ECE: flags=%02x", flags)
	}
	enqueueTCPTestSegment(t, connection, tcpSegment{sequence: 101, acknowledgement: 1001, flags: tcpFlagACK, window: 65535})
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
	}, 1400, tcpSocketOptionSet{})

	connection.passive = true
	result := make(chan error, 1)
	initialSYN := tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535}
	initialSYN.setOptions(tcpTimestampOptions(100, 0))
	go func() {
		result <- testTCPPassiveHandshake(connection, initialSYN, 1000)
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
	retransmittedSYN := tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535}
	retransmittedSYN.setOptions(tcpTimestampOptions(200, 0))
	enqueueTCPTestSegment(t, connection, retransmittedSYN)
	if echo := readTimestampEcho(); echo != 200 {
		t.Fatalf("retransmitted SYN-ACK TSecr = %d, want 200", echo)
	}
	finalACK := tcpSegment{sequence: 101, acknowledgement: 1001, flags: tcpFlagACK, window: 65535}
	finalACK.setOptions(tcpTimestampOptions(300, 1))
	enqueueTCPTestSegment(t, connection, finalACK)
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
		}, 1400, tcpSocketOptionSet{})

		result := make(chan error, 1)
		go func() { result <- testTCPHandshake(connection, 1000) }()
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
			connection.wakeActor(tcpActorWakePathMTU)
			if flags := read(); flags&(tcpFlagECE|tcpFlagCWR) != tcpFlagECE|tcpFlagCWR {
				t.Fatalf("maintenance SYN %d flags = %02x", index, flags)
			}
		}
		// The original RTO still fires. It alone starts the legacy ECN fallback
		// and must not fail merely because maintenance retransmitted the SYN.
		if flags := read(); flags&(tcpFlagECE|tcpFlagCWR) != 0 {
			t.Fatalf("RTO fallback SYN flags = %02x", flags)
		}
		enqueueTCPTestSegment(t, connection, tcpSegment{
			sequence: 2000, acknowledgement: 1001, flags: tcpFlagSYN | tcpFlagACK, window: 65535,
		})
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
		}, 1400, tcpSocketOptionSet{})

		connection.passive = true
		syn := tcpSegment{sequence: 100, flags: tcpFlagSYN | tcpFlagECE | tcpFlagCWR, window: 65535}
		result := make(chan error, 1)
		go func() { result <- testTCPPassiveHandshake(connection, syn, 1000) }()
		read := func() {
			select {
			case <-link.outbound:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for passive SYN-ACK")
			}
		}
		read()
		for index := 0; index < tcpPassiveSYNMaximumAttempts+1; index++ {
			enqueueTCPTestSegment(t, connection, syn)
			read()
		}
		// A timer retransmission must still occur instead of treating duplicate
		// peer SYNs as exhausted timeout attempts.
		read()
		enqueueTCPTestSegment(t, connection, tcpSegment{sequence: 101, acknowledgement: 1001, flags: tcpFlagACK, window: 65535})
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
	connection := &TCPConn{readNotify: make(chan struct{}), receiveCapacity: tcpReceiveCapacity}
	if err := connection.CloseRead(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("discarded peer data")
	if accepted := connection.appendReadBuffer(payload, payload, 0); accepted != len(payload) {
		t.Fatalf("discarded bytes accepted = %d, want %d", accepted, len(payload))
	}
	if window := connection.receiveWindow(0, true); window == 0 {
		t.Fatal("CloseRead advertised a zero receive window")
	}
	if connection.readBuffer.size != 0 {
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

func TestTCPDuplicateACKEvidence(t *testing.T) {
	pure := tcpSegment{acknowledgement: 100, flags: tcpFlagACK, window: 200}
	tests := []struct {
		name                          string
		segment                       tcpSegment
		peerSACK, newSACK, advanced   bool
		previousWindow, currentWindow uint32
		want                          bool
	}{
		{name: "classic pure", segment: pure, previousWindow: 200, currentWindow: 200, want: true},
		{name: "classic cumulative", segment: pure, advanced: true, previousWindow: 200, currentWindow: 200},
		{name: "classic window update", segment: pure, previousWindow: 199, currentWindow: 200},
		{name: "classic data", segment: tcpSegment{acknowledgement: 100, flags: tcpFlagACK, window: 200, payload: []byte{1}}, previousWindow: 200, currentWindow: 200},
		{name: "classic FIN", segment: tcpSegment{acknowledgement: 100, flags: tcpFlagACK | tcpFlagFIN, window: 200}, previousWindow: 200, currentWindow: 200},
		{name: "SACK pure without new block", segment: pure, peerSACK: true, previousWindow: 200, currentWindow: 200},
		{name: "SACK new block", segment: pure, peerSACK: true, newSACK: true, previousWindow: 200, currentWindow: 200, want: true},
		{name: "SACK cumulative data and window update", segment: tcpSegment{acknowledgement: 100, flags: tcpFlagACK, window: 200, payload: []byte{1}}, peerSACK: true, newSACK: true, advanced: true, previousWindow: 199, currentWindow: 200, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := tcpDuplicateACKEvidence(test.segment, test.peerSACK, test.newSACK, test.advanced, 100, test.previousWindow, test.currentWindow); got != test.want {
				t.Fatalf("tcpDuplicateACKEvidence = %v, want %v", got, test.want)
			}
		})
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

// TestTCPReceiveWindowScaleSupportsAutoTuning verifies that the SYN reserves
// enough scaled sequence space for the automatic receive ceiling.
func TestTCPReceiveWindowScaleSupportsAutoTuning(t *testing.T) {
	windowScale := tcpReceiveWindowScaleFor(tcpMaximumReceiveCapacity)
	_, scale, enabled, _, _, _ := parseTCPOptions(tcpSYNOptions(nil, 1360, windowScale, 1), 536, 1360)
	if !enabled || scale != windowScale {
		t.Fatalf("SYN window scale = %d, enabled=%t; want %d, true", scale, enabled, windowScale)
	}
	connection := &TCPConn{receiveCapacity: tcpReceiveCapacity, receiveWindowScale: windowScale}
	if window, want := connection.receiveWindow(0, true), uint16(int(tcpReceiveCapacity)>>windowScale); window != want {
		t.Fatalf("scaled default receive window = %d, want %d", window, want)
	}
	if maximum := uint64(65535) << windowScale; maximum < tcpMaximumReceiveCapacity {
		t.Fatalf("maximum scaled receive window = %d, want at least %d", maximum, tcpMaximumReceiveCapacity)
	}
	if got := tcpReceiveWindowScaleFor(128 * 1024); got != 2 {
		t.Fatalf("128 KiB receive ceiling selected window scale %d, want 2", got)
	}
}

// TestTCPReceiveWindowPreservesRightEdge verifies that receiving out-of-order
// bytes cannot withdraw sequence space that was already promised to a peer.
func TestTCPReceiveWindowPreservesRightEdge(t *testing.T) {
	const receiveNext = uint32(100)
	windowScale := tcpReceiveWindowScaleFor(tcpMaximumReceiveCapacity)
	window := newTCPReceiveWindow(receiveNext, 65535, true, false, windowScale)
	want := uint16(int(tcpReceiveCapacity) >> windowScale)
	if got := window.advertise(receiveNext, tcpReceiveCapacity, 0); got != want {
		t.Fatalf("initial scaled window = %d, want %d", got, want)
	}
	right := window.right
	if got := window.advertise(receiveNext, tcpReceiveCapacity/2, 0); got != want {
		t.Fatalf("window after out-of-order storage = %d, want %d", got, want)
	}
	if window.right != right {
		t.Fatalf("right edge moved from %d to %d", right, window.right)
	}
	advanced := receiveNext + 1380
	got := window.advertise(advanced, tcpReceiveCapacity-1380, 0)
	if advertisedRight := advanced + uint32(got)<<windowScale; tcpSequenceLess(advertisedRight+uint32(1<<windowScale)-1, right) {
		t.Fatalf("scaled right edge shrank from %d to %d", right, advertisedRight)
	}
}

func TestTCPBufferAutoTuning(t *testing.T) {
	base := time.Now()
	fast := tcpBufferAutoTune{updated: base}
	if target := fast.target(base.Add(500*time.Microsecond), 100*time.Microsecond, tcpReceiveCapacity, tcpMaximumSendCapacity); target != 0 {
		t.Fatalf("sub-interval auto tuning target = %d, want 0", target)
	}
	if target := fast.target(base.Add(time.Millisecond), 100*time.Microsecond, tcpReceiveCapacity, tcpMaximumSendCapacity); target >= tcpSendCapacity {
		t.Fatalf("scheduler-batched low-RTT target = %d, want below initial send capacity", target)
	}
	receive := &TCPConn{receiveCapacity: tcpReceiveCapacity, receiveAutoTune: true}
	tuner := tcpBufferAutoTune{updated: base}
	receive.applicationReads.Store(tcpReceiveCapacity)
	target := tuner.target(base.Add(100*time.Millisecond), 100*time.Millisecond, receive.applicationReads.Load(), tcpMaximumReceiveCapacity)
	if !receive.growReceiveCapacity(target) || receive.receiveCapacity != 2*tcpReceiveCapacity {
		t.Fatalf("receive auto tuning capacity = %d, want %d", receive.receiveCapacity, 2*tcpReceiveCapacity)
	}
	receive.receiveAutoTune = false
	receive.applicationReads.Add(4 * tcpReceiveCapacity)
	target = tuner.target(base.Add(200*time.Millisecond), 100*time.Millisecond, receive.applicationReads.Load(), tcpMaximumReceiveCapacity)
	if receive.growReceiveCapacity(target) || receive.receiveCapacity != 2*tcpReceiveCapacity {
		t.Fatalf("user-locked receive capacity changed to %d", receive.receiveCapacity)
	}
	customMaximum := 32 * 1024 * 1024
	customTuner := tcpBufferAutoTune{updated: base}
	if target = customTuner.target(base.Add(100*time.Millisecond), 100*time.Millisecond, uint64(customMaximum), customMaximum); target != customMaximum {
		t.Fatalf("custom automatic maximum target = %d, want %d", target, customMaximum)
	}

	send := &TCPConn{sendCapacity: tcpSendCapacity, sendAutoTune: true, sendChanged: make(chan struct{})}
	sendTuner := tcpBufferAutoTune{updated: base}
	target = sendTuner.target(base.Add(100*time.Millisecond), 100*time.Millisecond, 512*1024, tcpMaximumSendCapacity)
	if !send.growSendCapacity(target) || send.sendCapacity != 512*1024 {
		t.Fatalf("first send auto tuning capacity = %d, want %d", send.sendCapacity, 512*1024)
	}
	target = sendTuner.target(base.Add(200*time.Millisecond), 100*time.Millisecond, 1536*1024, tcpMaximumSendCapacity)
	if !send.growSendCapacity(target) || send.sendCapacity != 1024*1024 {
		t.Fatalf("second send auto tuning capacity = %d, want %d", send.sendCapacity, 1024*1024)
	}
	send.sendAutoTune = false
	if send.growSendCapacity(4*1024*1024) || send.sendCapacity != 1024*1024 {
		t.Fatalf("user-locked send capacity changed to %d", send.sendCapacity)
	}
}

func TestTCPMSSChangePreservesCongestionUnits(t *testing.T) {
	if got := tcpCongestionValueForMSS(12_000, 1200, 600, true); got != 6000 {
		t.Fatalf("congestion value after MSS reduction = %d, want 6000", got)
	}
	if got := tcpCongestionValueForMSS(12_000, 600, 1200, true); got != 12_000 {
		t.Fatalf("congestion value after MSS increase = %d, want 12000", got)
	}
	if got := tcpCongestionValueForMSS(500, 1200, 600, true); got != 600 {
		t.Fatalf("congestion window floor after MSS reduction = %d, want 600", got)
	}
	if got := tcpCongestionValueForMSS(500, 1200, 600, false); got != 250 {
		t.Fatalf("threshold after MSS reduction = %d, want 250", got)
	}
}

func TestTCPPLPMTUProbeHeadway(t *testing.T) {
	if got := tcpPLPMTUProbeHeadway(10_000, 1000, 100*time.Millisecond); got != time.Second {
		t.Fatalf("ten-packet PLPMTU headway = %v, want 1s", got)
	}
	if got := tcpPLPMTUProbeHeadway(100_000, 1000, 100*time.Millisecond); got != 10*time.Second {
		t.Fatalf("hundred-packet PLPMTU headway = %v, want 10s", got)
	}
	if got := tcpPLPMTUTimeoutDelay(10 * time.Second); got != 50*time.Second {
		t.Fatalf("timeout PLPMTU delay = %v, want 50s", got)
	}
	now := time.Unix(100, 0)
	probe := tcpPLPMTU{searchLow: 1000, searchHigh: 1500, probeMTU: 1250, active: true, searching: true}
	probe.failed(now, 10*time.Second)
	if probe.searchHigh != 1249 || probe.active || probe.nextProbe != now.Add(10*time.Second) {
		t.Fatalf("failed PLPMTU probe state = %+v", probe)
	}
	probe = tcpPLPMTU{searchLow: 1000, searchHigh: 1500, probeMTU: 1250, active: true, searching: true}
	probe.inconclusive(now, 50*time.Second)
	if probe.searchLow != 1000 || probe.searchHigh != 1500 || probe.active || probe.nextProbe != now.Add(50*time.Second) {
		t.Fatalf("inconclusive PLPMTU probe state = %+v", probe)
	}
	probe.start(1495, 1500, now)
	if probe.searching {
		t.Fatalf("sub-threshold PLPMTU search remained active: %+v", probe)
	}
}

func TestTCPPLPMTURequiresIsolatedLossEvidence(t *testing.T) {
	segments := []sentTCPSegment{
		{sequence: 1000, end: 2200},
		{sequence: 2200, end: 3200, state: sentTCPSegmentSACKed},
		{sequence: 3200, end: 4200, state: sentTCPSegmentSACKed},
	}
	if isolatedPLPMTUProbeLoss(segments, 1000, 4200, 1000) {
		t.Fatal("PLPMTU accepted fewer than DupThresh SACKed ranges")
	}
	segments = append(segments, sentTCPSegment{sequence: 4200, end: 5200, state: sentTCPSegmentSACKed})
	if !isolatedPLPMTUProbeLoss(segments, 1000, 5200, 1000) {
		t.Fatal("PLPMTU rejected an isolated probe with ordinary loss evidence")
	}
	segments[2].state.set(sentTCPSegmentSACKed, false)
	if isolatedPLPMTUProbeLoss(segments, 1000, 5200, 1000) {
		t.Fatal("PLPMTU suppressed congestion with a second hole below HighSACK")
	}
}

func TestTCPProvenLossAccountingUsesTransmissionGenerations(t *testing.T) {
	speculative := sentTCPSegment{sequence: 0, end: 1000, state: sentTCPSegmentTransmitted}
	if loss := recordTCPSegmentLoss(&speculative, false); loss != 0 || speculative.lossAlreadyReported() {
		t.Fatalf("speculative retransmission loss = %d, reported %t", loss, speculative.lossAlreadyReported())
	}
	segments := []sentTCPSegment{
		{sequence: 0, end: 1000, state: sentTCPSegmentTransmitted},
		{sequence: 1000, end: 2000, state: sentTCPSegmentTransmitted},
		{sequence: 2000, end: 3000, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		{sequence: 3000, end: 4000, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		{sequence: 4000, end: 5000, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
	}
	if losses := recordProvenTCPLosses(segments, 1000); losses != 2000 {
		t.Fatalf("initial proven losses = %d, want 2000", losses)
	}
	if losses := recordProvenTCPLosses(segments, 1000); losses != 0 {
		t.Fatalf("repeated proven losses = %d", losses)
	}
	segments[0].advanceTransmissionGeneration()
	segments[0].state.set(sentTCPSegmentSACKRetried, true)
	if losses := recordProvenTCPLosses(segments, 1000); losses != 0 {
		t.Fatalf("speculative replacement loss = %d", losses)
	}
	segments[0].state.set(sentTCPSegmentRACKLost, true)
	if losses := recordProvenTCPLosses(segments, 1000); losses != 1000 {
		t.Fatalf("RACK-proven replacement loss = %d, want 1000", losses)
	}
	segments[0].state |= sentTCPSegmentLossReported
	segments[0].advanceTransmissionGeneration()
	if !segments[0].isTransmitted() || !segments[0].isRetransmitted() || segments[0].lossAlreadyReported() {
		t.Fatalf("replacement generation state = %#x", segments[0].state)
	}
}

func TestTCPRecoveryUndoEvidence(t *testing.T) {
	controller := newTCPCongestionController(CongestionControlCUBIC)
	rtt := rttEstimator{initialized: true, srtt: 100 * time.Millisecond, variation: 20 * time.Millisecond, rto: time.Second}
	var eifel tcpRecoveryUndo
	eifel.begin(true, 4000, 12000, 8000, 10000, &controller, rtt)
	eifel.recordRetransmission(1000, 2000, 200, false)
	if eifel.detectEifel(199, false, false, 4000) {
		t.Fatal("Eifel accepted an all-data ACK without prior DSACK evidence")
	}
	eifel.eifelChecked = false
	if !eifel.detectEifel(199, false, true, 4000) {
		t.Fatal("Eifel rejected conservative timestamp and prior-DSACK evidence")
	}
	response := eifel.eifelRTOResponse()
	window, threshold := eifel.restore(6000, 4000, 1000, &controller, time.Unix(100, 0))
	if window != 10000 || threshold != 10000 || controller.algorithmName() != CongestionControlCUBIC {
		t.Fatalf("Eifel restore = cwnd %d ssthresh %d controller %q", window, threshold, controller.algorithmName())
	}
	currentRTT := rttEstimator{initialized: true, srtt: 80 * time.Millisecond, variation: 10 * time.Millisecond, rto: tcpMinimumRTO}
	if response.observe(4000, 300*time.Millisecond, &currentRTT) {
		t.Fatal("Eifel RTO response used an RTT sample that did not cover new data")
	}
	if !response.observe(4001, 300*time.Millisecond, &currentRTT) || currentRTT.srtt != 300*time.Millisecond || currentRTT.variation != 150*time.Millisecond || currentRTT.rto != 900*time.Millisecond {
		t.Fatalf("Eifel RTO response = srtt %v variation %v rto %v", currentRTT.srtt, currentRTT.variation, currentRTT.rto)
	}
	var highThreshold tcpRecoveryUndo
	highThreshold.begin(false, 4000, 12000, 18000, 10000, &controller, rtt)
	_, threshold = highThreshold.restore(6000, 0, 1000, &controller, time.Unix(100, 0))
	if threshold != 18000 {
		t.Fatalf("RFC 4015 pipe_prev = %d, want max(FlightSize, ssthresh) = 18000", threshold)
	}

	var dsack tcpRecoveryUndo
	dsack.begin(false, 5000, 16000, 12000, 14000, &controller, rtt)
	dsack.recordRetransmission(1000, 2000, 300, false)
	dsack.recordRetransmission(2000, 3000, 301, false)
	if dsack.observeDSACK(tcpSACKBlock{left: 1000, right: 2000}, 3000, 1000, false) {
		t.Fatal("DSACK undo completed before every retransmission was duplicated")
	}
	if !dsack.observeDSACK(tcpSACKBlock{left: 2000, right: 3000}, 3000, 1000, false) {
		t.Fatal("DSACK undo did not complete after every retransmission was duplicated")
	}

	var repeated tcpRecoveryUndo
	repeated.begin(false, 5000, 16000, 12000, 14000, &controller, rtt)
	repeated.recordRetransmission(1000, 2000, 300, false)
	repeated.recordRetransmission(1000, 2000, 301, true)
	if repeated.observeDSACK(tcpSACKBlock{left: 1000, right: 2000}, 2000, 1000, false) {
		t.Fatal("DSACK undid a range retransmitted more than once")
	}
	var repacketized tcpRecoveryUndo
	repacketized.begin(false, 5000, 16000, 12000, 14000, &controller, rtt)
	repacketized.recordRetransmission(1000, 2200, 300, false)
	repacketized.recordRetransmission(1000, 2000, 301, true)
	if !repacketized.dsackDisabled {
		t.Fatal("DSACK undo retained a repacketized range retransmitted more than once")
	}

	var emptyScoreboard tcpRecoveryUndo
	emptyScoreboard.begin(false, 5000, 16000, 12000, 14000, &controller, rtt)
	emptyScoreboard.recordRetransmission(1000, 2000, 300, false)
	if emptyScoreboard.observeDSACK(tcpSACKBlock{left: 1000, right: 2000}, 2000, 1000, true) || !emptyScoreboard.dsackDisabled {
		t.Fatal("RFC 3708 empty-scoreboard exception did not disable undo")
	}

	var history tcpRetransmissionHistory
	history.record(1000, 2000)
	if matched, repeatedRange := history.match(tcpSACKBlock{left: 1000, right: 2000}); !matched || repeatedRange {
		t.Fatalf("single retransmission history match = %t, %t", matched, repeatedRange)
	}
	history.record(1000, 2000)
	if matched, repeatedRange := history.match(tcpSACKBlock{left: 1000, right: 2000}); !matched || !repeatedRange {
		t.Fatalf("repeated retransmission history match = %t, %t", matched, repeatedRange)
	}
	var overlappingHistory tcpRetransmissionHistory
	overlappingHistory.record(1000, 2200)
	overlappingHistory.record(1000, 2000)
	if matched, repeatedRange := overlappingHistory.match(tcpSACKBlock{left: 1000, right: 2000}); !matched || !repeatedRange {
		t.Fatalf("overlapping retransmission history match = %t, %t", matched, repeatedRange)
	}
}

// TestTCPReceiveWindowHandshakeScaling verifies that only an active opener's
// final ACK applies the negotiated window shift to its initial right edge.
func TestTCPReceiveWindowHandshakeScaling(t *testing.T) {
	const receiveNext = uint32(100)
	windowScale := tcpReceiveWindowScaleFor(tcpMaximumReceiveCapacity)
	active := newTCPReceiveWindow(receiveNext, 65535, true, true, windowScale)
	if got := active.size(receiveNext); got != uint32(65535)<<windowScale {
		t.Fatalf("active initial receive window = %d", got)
	}
	passive := newTCPReceiveWindow(receiveNext, 65535, true, false, windowScale)
	if got := passive.size(receiveNext); got != 65535 {
		t.Fatalf("passive initial receive window = %d", got)
	}
}

func TestTCPReceiveWindowAvoidsSillyWindowGrowth(t *testing.T) {
	const receiveNext = uint32(100)
	window := newTCPReceiveWindow(receiveNext, 1000, false, false, 0)
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
		readNotify:      make(chan struct{}),
		receiveCapacity: 4,
	}
	connection.readBuffer.append([]byte("full"))
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
	if got := string(testTCPReadBufferBytes(&connection.readBuffer)); got != "next" {
		t.Fatalf("promoted read buffer = %q, want next", got)
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
	retained := tcpConnection.sendBuffer.size
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
		return tcpConnection.sendBuffer.size == 0
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
		{sequence: 100, end: 200, state: sentTCPSegmentTransmitted | sentTCPSegmentRetransmitted},
		{sequence: 200, end: 300, state: sentTCPSegmentTransmitted},
	}
	if !tcpACKRTTAmbiguous(segments, 300) {
		t.Fatal("cumulative ACK covering a retransmission was treated as an RTT sample")
	}
	if tcpACKRTTAmbiguous(segments, 100) {
		t.Fatal("ACK covering no new range was treated as ambiguous")
	}
	segments[0].state &^= sentTCPSegmentRetransmitted
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
	connection.wakeActor(tcpActorWakePathMTU)
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

// TestTCPMaximumPacingRateLiveUpdate verifies actor-visible option changes and
// the standard closed-connection error.
func TestTCPMaximumPacingRateLiveUpdate(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.31"), netip.MustParseAddr("192.0.2.32"))
	defer stack.Close()
	link.echoTCP = true
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7994))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	const limit = uint64(1_000_000)
	if err = tcpConnection.SetMaximumPacingRate(limit); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		info := tcpConnection.Info()
		return info.MaximumPacingRate == limit && info.PacingRate <= limit
	})
	if err = tcpConnection.SetMaximumPacingRate(0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return tcpConnection.Info().MaximumPacingRate == 0 })
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetMaximumPacingRate(limit); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed SetMaximumPacingRate = %v, want net.ErrClosed", err)
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
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(link.local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlReno},
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

func TestTCPBBRECNPreservesModelWindow(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.33"), netip.MustParseAddr("192.0.2.34"))
	defer stack.Close()
	link.echoTCP = true
	link.ecnTCP = true
	link.sendTCPECE = true
	if err := stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(link.local, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: CongestionControlBBR},
	}); err != nil {
		t.Fatal(err)
	}
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 7997))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	writeAndReadTCPEcho(t, connection, bytes.Repeat([]byte{0x5a}, 4096))
	info := connection.(*TCPConn).Info()
	if info.CongestionWindow > 1024*1024 {
		t.Fatalf("BBR cwnd after ECE = %d, want model-sized window", info.CongestionWindow)
	}
	if info.SlowStartThreshold != ^uint32(0)>>1 {
		t.Fatalf("BBR ssthresh after ECE = %d, want preserved infinite threshold", info.SlowStartThreshold)
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
	if rto := connection.(*TCPConn).Info().RetransmissionTimeout; rto != 3*time.Second {
		t.Fatalf("data RTO after SYN timeout = %v, want 3s per RFC 6298 section 5.7", rto)
	}
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

func TestTCPDialCancellationUnblocksFullPacketQueue(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.101")
	remote := netip.MustParseAddrPort("192.0.2.102:8080")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	fillTestPacketQueue(t, &stack.outbound, []byte{0x45})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err = stack.DialTCP(ctx, "tcp4", netip.AddrPort{}, remote); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialTCP with a full packet queue = %v", err)
	}
	waitFor(t, time.Second, func() bool { return stack.Stats().ActiveTCPConnections == 0 })
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

// TestTCPSACKIgnoresPureDuplicateACKs verifies RFC 6675's SACK-specific
// DupAcks definition. Repeated cumulative ACKs without new SACK information,
// including zero-window probe responses, are not loss evidence.
func TestTCPSACKIgnoresPureDuplicateACKs(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	defer stack.Close()
	link.echoTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8086))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	if !tcpConnection.Info().SACK {
		t.Fatal("test connection did not negotiate SACK")
	}
	if n, writeErr := connection.Write([]byte("unacknowledged")); writeErr != nil || n != len("unacknowledged") {
		t.Fatalf("Write = %d, %v", n, writeErr)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.dropTCPData == 0
	})
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	// The first ACK closes the window. The following three would trigger
	// classic fast retransmit if they were incorrectly counted as DupAcks.
	for range [4]struct{}{} {
		if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 0, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if retransmissions := stack.Stats().TCPRetransmissions; retransmissions != 0 {
		t.Fatalf("retransmissions after pure SACK-less duplicate ACKs = %d, want 0", retransmissions)
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
		{sequence: 200, end: 300, state: sentTCPSegmentLimited},
		{sequence: 300, end: 400, state: sentTCPSegmentSACKed},
	}
	if flight := lossRecoveryFlightSize(outstanding); flight != 100 {
		t.Fatalf("Limited Transmit recovery flight = %d, want 100", flight)
	}
}

func TestTCPRateApplicationLimitedWaitsForKnownLoss(t *testing.T) {
	const mss = 1000
	outstanding := []sentTCPSegment{
		{sequence: 0, end: mss, state: sentTCPSegmentTransmitted},
		{sequence: mss, end: 2 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		{sequence: 2 * mss, end: 3 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
		{sequence: 3 * mss, end: 4 * mss, state: sentTCPSegmentTransmitted | sentTCPSegmentSACKed},
	}
	if tcpRateApplicationLimited(0, false, mss, 10*mss, true, true, outstanding, mss) {
		t.Fatal("known unretransmitted SACK loss was classified as application limited")
	}
	outstanding[0].state.set(sentTCPSegmentSACKRetried, true)
	if !tcpRateApplicationLimited(0, false, mss, 10*mss, true, true, outstanding, mss) {
		t.Fatal("drained application queue after retransmitting known losses was not classified as application limited")
	}
	if !tcpRateApplicationLimited(0, false, mss, 10*mss, false, true, outstanding, mss) {
		t.Fatal("known loss outside recovery incorrectly blocked application-limited state")
	}
	if tcpRateApplicationLimited(mss, false, mss, 10*mss, true, true, outstanding, mss) ||
		tcpRateApplicationLimited(0, true, mss, 10*mss, true, true, outstanding, mss) ||
		tcpRateApplicationLimited(0, false, 10*mss, 10*mss, true, true, outstanding, mss) {
		t.Fatal("write queue, host queue, or congestion window limitation was classified as application limited")
	}
}

// TestTCPTailLossProbe verifies that a lost tail is retried by an RFC 8985
// probe, rather than merely by the later retransmission timeout.
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
	writeAndReadTCPEcho(t, connection, []byte("warmup"))
	link.mu.Lock()
	link.holdTCPACKs = 2
	link.dropTCPOrdinals = map[int]bool{3: true}
	link.mu.Unlock()
	writeAndReadTCPEcho(t, connection, make([]byte, 2000))
	link.mu.Lock()
	retransmitted, delay := link.tailRetransmission, link.tailRecoveryDelay
	link.mu.Unlock()
	if probes := stack.Stats().TCPTailLossProbes; !retransmitted || probes == 0 || delay >= tcpInitialRTO {
		t.Fatalf("tail retransmission = %v after %v with %d probes, want an RFC 8985 probe before initial RTO %v", retransmitted, delay, probes, tcpInitialRTO)
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

func TestTCPTailLossProbeAllowsRemoteDelayedACK(t *testing.T) {
	const smoothedRTT = 20 * time.Millisecond
	if delay := tailLossProbeDelay(smoothedRTT, time.Second, true); delay != 2*smoothedRTT+tcpTailLossProbeACKDelay {
		t.Fatalf("single-segment TLP delay = %v, want %v", delay, 2*smoothedRTT+tcpTailLossProbeACKDelay)
	}
	if delay := tailLossProbeDelay(smoothedRTT, time.Second, false); delay != 2*smoothedRTT {
		t.Fatalf("multi-segment TLP delay = %v, want %v", delay, 2*smoothedRTT)
	}
	if delay := tailLossProbeDelay(450*time.Millisecond, time.Second, true); delay != time.Second {
		t.Fatalf("RTO-capped TLP delay = %v, want %v", delay, time.Second)
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
	waitFor(t, time.Second, func() bool {
		info := connection.(*TCPConn).Info()
		return info.PathMTU == 2000 && info.MaximumSegmentSize == 1280
	})
	payload := bytes.Repeat([]byte{0x4d}, 1280)
	writeAndReadTCPEcho(t, connection, payload)
	link.mu.Lock()
	maximum := link.maximumTCPData
	link.mu.Unlock()
	if maximum != len(payload) {
		t.Fatalf("TCP payload after MTU increase = %d, want %d", maximum, len(payload))
	}
}

func TestTCPPathMTUExpiryProbesUpward(t *testing.T) {
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

	payload := bytes.Repeat([]byte{0x32}, 8*1024)
	deadline := time.Now().Add(time.Second)
	after := 0
	for after <= 960 && time.Now().Before(deadline) {
		link.mu.Lock()
		link.maximumTCPData = 0
		link.mu.Unlock()
		writeAndReadTCPEcho(t, connection, payload)
		link.mu.Lock()
		after = link.maximumTCPData
		link.mu.Unlock()
		if after <= 960 {
			time.Sleep(time.Millisecond)
		}
	}
	if after <= 960 || stack.Stats().PathMTUProbeSuccesses == 0 {
		t.Fatalf("TCP payload/probe successes after PMTU expiry = %d/%d, want payload > 960 and a confirmed probe", after, stack.Stats().PathMTUProbeSuccesses)
	}
}

func TestTCPPathMTUSubthresholdConvergenceRefreshesCache(t *testing.T) {
	const linkMTU = 1400
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.45"), netip.MustParseAddr("192.0.2.46"))
	defer stack.Close()
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	if !stack.observePathMTU(link.remote, linkMTU-5) {
		t.Fatal("failed to install test PMTU")
	}
	stack.pathMTUMu.Lock()
	entry := stack.pathMTU[link.remote]
	entry.updated = time.Now().Add(-pathMTULifetime + 25*time.Millisecond)
	stack.pathMTU[link.remote] = entry
	stack.pathMTUMu.Unlock()

	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8095))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	waitFor(t, time.Second, func() bool {
		expiry, exists := stack.pathMTUExpiry(link.remote)
		return exists && time.Until(expiry) > pathMTULifetime-time.Minute
	})
	if info := connection.(*TCPConn).Info(); info.PathMTUDiscovery || info.PathMTU != linkMTU-5 {
		t.Fatalf("sub-threshold PLPMTU state = searching %t MTU %d", info.PathMTUDiscovery, info.PathMTU)
	}
}

func TestTCPPathMTUIsolatedProbeFailure(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.39"), netip.MustParseAddr("192.0.2.40"))
	link.mu.Lock()
	link.echoTCP = true
	link.sackTCP = true
	link.dropTCPAbove = 1100
	link.mu.Unlock()
	if !stack.observePathMTU(link.remote, 1000) {
		t.Fatal("failed to install test PMTU")
	}
	stack.pathMTUMu.Lock()
	entry := stack.pathMTU[link.remote]
	entry.updated = time.Now().Add(-pathMTULifetime + 50*time.Millisecond)
	stack.pathMTU[link.remote] = entry
	stack.pathMTUMu.Unlock()

	connection, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8094))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(75 * time.Millisecond)
	payload := bytes.Repeat([]byte{0x33}, 16*1024)
	writeAndReadTCPEcho(t, connection, payload)
	stats := stack.Stats()
	if stats.PathMTUProbeFailures == 0 || stats.PathMTUProbes == 0 {
		t.Fatalf("isolated PLPMTU failure stats = probes %d failures %d", stats.PathMTUProbes, stats.PathMTUProbeFailures)
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
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	receiveNext := uint32(100)
	receiveWindow := uint32(1000)
	var pieces []tcpReceivedPiece
	bytes := 0
	if !connection.storeTCPOutOfOrder(receiveNext, receiveWindow, 200, nil, nil, true, &pieces, &bytes) {
		t.Fatal("later out-of-order FIN was not retained")
	}
	if !connection.storeTCPOutOfOrder(receiveNext, receiveWindow, 150, nil, nil, true, &pieces, &bytes) {
		t.Fatal("earlier out-of-order FIN was not retained")
	}
	if len(pieces) != 1 || pieces[0].sequence != 150 || !pieces[0].fin {
		t.Fatalf("normalized FIN pieces = %+v, want FIN at 150", pieces)
	}
}

func TestTCPOutOfOrderFINCompactsTruncatedRange(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	owner := make([]byte, 32)
	copy(owner, "abcdefghijklmnopqrstuvwxyz")
	pieces := []tcpReceivedPiece{{sequence: 104, payload: owner}}
	bytes := len(owner)
	if !connection.storeTCPOutOfOrder(100, 64, 106, nil, nil, true, &pieces, &bytes) {
		t.Fatal("earlier FIN was not retained")
	}
	if len(pieces) != 1 || !pieces[0].fin || string(pieces[0].payload) != "ab" ||
		&pieces[0].payload[0] == &owner[0] || cap(pieces[0].payload) != len(pieces[0].payload) || bytes != 2 {
		t.Fatalf("FIN-truncated range retained owner backing: pieces=%+v bytes=%d capacity=%d", pieces, bytes, cap(pieces[0].payload))
	}
}

func TestTCPOutOfOrderFINWaitsForSequenceGap(t *testing.T) {
	connection := &TCPConn{
		receiveCapacity: 32,
		readNotify:      make(chan struct{}),
	}
	receiveNext := uint32(100)
	var pieces []tcpReceivedPiece
	outOfOrderBytes := 0
	if delivered, closed := connection.receiveTCPData(104, []byte("ef"), true, 32, &receiveNext, &pieces, &outOfOrderBytes); delivered || closed {
		t.Fatalf("out-of-order data plus FIN = delivered %t closed %t", delivered, closed)
	}
	if receiveNext != 100 || connection.readBuffer.size != 0 {
		t.Fatalf("gapped receive state = next %d buffer %q", receiveNext, testTCPReadBufferBytes(&connection.readBuffer))
	}
	if delivered, closed := connection.receiveTCPData(100, []byte("abcd"), false, 32, &receiveNext, &pieces, &outOfOrderBytes); !delivered || !closed {
		t.Fatalf("gap completion = delivered %t closed %t", delivered, closed)
	}
	if receiveNext != 107 || string(testTCPReadBufferBytes(&connection.readBuffer)) != "abcdef" || len(pieces) != 0 || outOfOrderBytes != 0 {
		t.Fatalf("completed receive state = next %d buffer %q pieces %d bytes %d", receiveNext, testTCPReadBufferBytes(&connection.readBuffer), len(pieces), outOfOrderBytes)
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
		state: sentTCPSegmentCWR, delivery: tcpDeliverySnapshot{deliveredStamp: 1},
	}
	trimAcknowledgedTCPSegment(&segment, 103)
	if segment.sequence != 103 || segment.end != 104 || segment.dataSize() != 0 || segment.flags&tcpFlagFIN == 0 || segment.flags&tcpFlagPSH != 0 || segment.state.has(sentTCPSegmentCWR) || segment.delivery.deliveredStamp == 0 {
		t.Fatalf("FIN-only remainder = %+v", segment)
	}
}

func TestTCPCloseWithUnreadDataIsAbortive(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	connection.readBuffer.append([]byte("unread"))
	connection.sendBuffer.append([]byte("unsent"))
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
	if connection.sendBuffer.size != 0 {
		t.Fatalf("abortive close retained %d send bytes", connection.sendBuffer.size)
	}
}

func TestTCPSendBufferChunkOwnership(t *testing.T) {
	payload := make([]byte, tcpSendChunkMaximum+512)
	for index := range payload {
		payload[index] = byte(index*37 + 11)
	}
	var buffer tcpSendBuffer
	buffer.append(payload)
	if buffer.size != len(payload) || len(buffer.chunks) != 2 {
		t.Fatalf("chunked send buffer = %d bytes in %d chunks", buffer.size, len(buffer.chunks))
	}
	const gather = 300
	offset := tcpSendChunkMaximum - 100
	var view tcpPayloadView
	total := buffer.view(offset, gather, &view)
	snapshot := make([]byte, view.size)
	view.copyTo(snapshot)
	if total != len(payload) || !bytes.Equal(snapshot, payload[offset:offset+gather]) {
		t.Fatalf("cross-chunk snapshot = %d/%d bytes, equal %t", len(snapshot), total, bytes.Equal(snapshot, payload[offset:offset+gather]))
	}
	buffer.acknowledge(tcpSendChunkMaximum)
	total = buffer.view(0, len(payload), &view)
	remaining := make([]byte, view.size)
	view.copyTo(remaining)
	if total != 512 || !bytes.Equal(remaining, payload[tcpSendChunkMaximum:]) {
		t.Fatalf("acknowledged send buffer = %d/%d bytes, equal %t", len(remaining), total, bytes.Equal(remaining, payload[tcpSendChunkMaximum:]))
	}

	var reusable tcpSendBuffer
	reusable.append([]byte("first"))
	firstStorage := &reusable.chunks[0].storage[0]
	reusable.acknowledge(len("first"))
	reusable.append([]byte("second"))
	if &reusable.chunks[0].storage[0] != firstStorage {
		t.Fatal("acknowledged storage was not reused")
	}
}

func TestTCPCloseWithoutUnreadDataRemainsGraceful(t *testing.T) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
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
		{sequence: 100, end: 200, hostQueue: testPacketQueueTicketAt(base, base)},
		{sequence: 200, end: 300, hostQueue: testPacketQueueTicketAt(base, base.Add(20*time.Millisecond))},
	}
	var latest tcpRACKSample
	outstanding, _, _, _, latest, _ = applyTCPSACK(outstanding, []tcpSACKBlock{{left: 200, right: 300}}, base)
	latest.rtt = 5 * time.Millisecond
	markRACKLoss(outstanding, latest, base.Add(20*time.Millisecond), 10*time.Millisecond, base)
	if !outstanding[0].state.has(sentTCPSegmentRACKLost) || outstanding[1].state.has(sentTCPSegmentRACKLost) {
		t.Fatalf("RACK loss state = [%v %v]", outstanding[0].state.has(sentTCPSegmentRACKLost), outstanding[1].state.has(sentTCPSegmentRACKLost))
	}
}

// TestRACKWaitsFromCurrentTime verifies that transmit-order evidence and the
// reordering timer are separate RFC 8985 conditions. A closely spaced later
// transmission starts a timer instead of postponing loss until RTO.
func TestRACKWaitsFromCurrentTime(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, hostQueue: testPacketQueueTicketAt(base, base)},
		{sequence: 200, end: 300, hostQueue: testPacketQueueTicketAt(base, base.Add(time.Millisecond)), state: sentTCPSegmentSACKed},
	}
	delivered := tcpRACKSample{sentAt: outstanding[1].transmittedAt(base), end: outstanding[1].end, rtt: 10 * time.Millisecond}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(15*time.Millisecond), 10*time.Millisecond, base); !ok || delay != 5*time.Millisecond {
		t.Fatalf("RACK loss delay = %v, %t; want 5ms, true", delay, ok)
	}
	markRACKLoss(outstanding, delivered, base.Add(19*time.Millisecond), 10*time.Millisecond, base)
	if outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatal("RACK declared loss before the reordering timer expired")
	}
	markRACKLoss(outstanding, delivered, base.Add(20*time.Millisecond), 10*time.Millisecond, base)
	if !outstanding[0].state.has(sentTCPSegmentRACKLost) {
		t.Fatal("RACK did not declare loss when the reordering timer expired")
	}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(20*time.Millisecond), 10*time.Millisecond, base); ok {
		t.Fatalf("RACK rearmed an already declared loss with delay %v", delay)
	}
}

// TestRACKCanDetectLostRetransmission verifies that a recovery transmission
// is not immune from a later round of time-based loss detection.
func TestRACKCanDetectLostRetransmission(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, state: sentTCPSegmentSACKRetried, hostQueue: testPacketQueueTicketAt(base, base)},
		{sequence: 200, end: 300, state: sentTCPSegmentSACKed, hostQueue: testPacketQueueTicketAt(base, base.Add(time.Millisecond))},
	}
	delivered := tcpRACKSample{sentAt: outstanding[1].transmittedAt(base), end: outstanding[1].end, rtt: 5 * time.Millisecond}
	markRACKLoss(outstanding, delivered, base.Add(15*time.Millisecond), 10*time.Millisecond, base)
	if !outstanding[0].state.has(sentTCPSegmentRACKLost) || outstanding[0].state.has(sentTCPSegmentSACKRetried) {
		t.Fatalf("lost retransmission state = lost %t retried %t", outstanding[0].state.has(sentTCPSegmentRACKLost), outstanding[0].state.has(sentTCPSegmentSACKRetried))
	}
}

func TestRACKUsesMaximumRemainingWait(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, hostQueue: testPacketQueueTicketAt(base, base)},
		{sequence: 200, end: 300, hostQueue: testPacketQueueTicketAt(base, base.Add(3*time.Millisecond))},
		{sequence: 300, end: 400, state: sentTCPSegmentSACKed, hostQueue: testPacketQueueTicketAt(base, base.Add(5*time.Millisecond))},
	}
	delivered := tcpRACKSample{sentAt: outstanding[2].transmittedAt(base), end: outstanding[2].end, rtt: 10 * time.Millisecond}
	if delay, ok := rackLossDelay(outstanding, delivered, base.Add(10*time.Millisecond), 5*time.Millisecond, base); !ok || delay != 8*time.Millisecond {
		t.Fatalf("RACK maximum loss delay = %v, %t; want 8ms, true", delay, ok)
	}
}

func TestRACKRejectsAmbiguousRetransmissionRTT(t *testing.T) {
	sample := tcpRACKSample{sentAt: time.Unix(100, 0), end: 200, rtt: 5 * time.Millisecond, timestamp: 200, retransmitted: true}
	if got := validRACKSample(sample, 10*time.Millisecond, 200); !got.sentAt.IsZero() {
		t.Fatalf("ambiguous retransmission sample was accepted: %+v", got)
	}
	sample.rtt = 20 * time.Millisecond
	if got := validRACKSample(sample, 10*time.Millisecond, 199); !got.sentAt.IsZero() {
		t.Fatalf("sample for an older timestamped copy was accepted: %+v", got)
	}
	if got := validRACKSample(sample, 10*time.Millisecond, 200); got.sentAt.IsZero() {
		t.Fatal("sample matching the latest timestamped retransmission was rejected")
	}
	sample.retransmitted = false
	if got := validRACKSample(sample, 10*time.Millisecond, 0); got.sentAt.IsZero() {
		t.Fatal("original transmission sample was rejected")
	}
}

func TestRACKRepeatedSACKIsNotNewDelivery(t *testing.T) {
	base := time.Unix(100, 0)
	outstanding := []sentTCPSegment{{sequence: 100, end: 200, timestamp: 10, hostQueue: testPacketQueueTicketAt(base, base)}}
	outstanding, _, _, newInformation, latest, _ := applyTCPSACK(outstanding, []tcpSACKBlock{{left: 100, right: 200}}, base)
	if !newInformation || latest.sentAt != base {
		t.Fatalf("initial SACK = new %t latest %+v", newInformation, latest)
	}
	_, _, _, newInformation, latest, _ = applyTCPSACK(outstanding, []tcpSACKBlock{{left: 100, right: 200}}, base)
	if newInformation || !latest.sentAt.IsZero() {
		t.Fatalf("repeated SACK = new %t latest %+v", newInformation, latest)
	}
}

func TestFirstRACKLossRequiresTimeBasedEvidence(t *testing.T) {
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200},
		{sequence: 200, end: 300, state: sentTCPSegmentRACKLost | sentTCPSegmentSACKed},
		{sequence: 300, end: 400, state: sentTCPSegmentRACKLost},
	}
	if index := firstRACKLoss(outstanding); index != 2 {
		t.Fatalf("first RACK loss = %d, want 2", index)
	}
	outstanding[2].state.set(sentTCPSegmentRACKLost, false)
	if index := firstRACKLoss(outstanding); index != -1 {
		t.Fatalf("RACK loss without evidence = %d, want -1", index)
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
	epoch := receivedAt.Add(-time.Second)
	if got := tcpSegmentEventTime(tcpSegment{receivedAt: monotonicStampAt(epoch, receivedAt)}, now, time.Time{}, epoch); got != receivedAt {
		t.Fatalf("segment event time = %v, want %v", got, receivedAt)
	}
	if got := tcpSegmentEventTime(tcpSegment{}, now, time.Time{}, epoch); got != now {
		t.Fatalf("missing segment event time = %v, want %v", got, now)
	}
	if got := tcpSegmentEventTime(tcpSegment{receivedAt: monotonicStampAt(epoch, now.Add(time.Second))}, now, time.Time{}, epoch); got != now {
		t.Fatalf("future segment event time = %v, want %v", got, now)
	}
	previous := receivedAt.Add(time.Second)
	if got := tcpSegmentEventTime(tcpSegment{receivedAt: monotonicStampAt(epoch, receivedAt)}, now, previous, epoch); got != previous {
		t.Fatalf("regressing segment event time = %v, want %v", got, previous)
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
	connection := newTCPConn(stack, "tcp4", key, 1500, tcpSocketOptionSet{})
	stack.tcp[key] = connection
	packet, ok := parseIPPacket(buildTestTCP(remote, local, key.remote.Port(), key.local.Port(), 1, 1, tcpFlagACK, 65535, nil, nil))
	if !ok {
		t.Fatal("test TCP packet did not parse")
	}
	receivedAt := stack.timestampEpoch.Add(250 * time.Millisecond)
	if err = stack.handleTCP(packet, receivedAt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.inbound.notify:
		segment, dequeued := connection.inbound.dequeue()
		if !dequeued {
			t.Fatal("TCP dispatch notification had no segment")
		}
		if got := segment.receivedAt.time(stack.timestampEpoch); got != receivedAt {
			t.Fatalf("dispatched arrival time = %v, want %v", got, receivedAt)
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

func TestTCPInitialSequenceRFC6528(t *testing.T) {
	epoch := time.Unix(400, 0)
	stack := &Stack{timestampEpoch: epoch}
	for index := range stack.tcpISNSecret {
		stack.tcpISNSecret[index] = byte(index)
	}
	key := tcpKey{
		local:  netip.MustParseAddrPort("192.0.2.1:40000"),
		remote: netip.MustParseAddrPort("198.51.100.1:443"),
	}
	base := stack.tcpInitialSequence(key, epoch)
	if got := stack.tcpInitialSequence(key, epoch.Add(4*time.Microsecond)); got != base+1 {
		t.Fatalf("ISN after one RFC timer tick = %#x, want %#x", got, base+1)
	}
	if got := stack.tcpInitialSequence(key, epoch.Add(-time.Second)); got != base {
		t.Fatalf("ISN before epoch = %#x, want clamped value %#x", got, base)
	}
	wrap := time.Duration(uint64(1)<<32) * 4 * time.Microsecond
	if got := stack.tcpInitialSequence(key, epoch.Add(wrap)); got != base {
		t.Fatalf("ISN after timer wrap = %#x, want %#x", got, base)
	}
	differentTuple := key
	differentTuple.remote = netip.MustParseAddrPort("198.51.100.1:444")
	if got := stack.tcpInitialSequence(differentTuple, epoch); got == base {
		t.Fatal("different TCP four-tuples received the same keyed offset")
	}
	differentSecret := &Stack{timestampEpoch: epoch, tcpISNSecret: stack.tcpISNSecret}
	differentSecret.tcpISNSecret[0] ^= 0xff
	if got := differentSecret.tcpInitialSequence(key, epoch); got == base {
		t.Fatal("different RFC 6528 secrets received the same keyed offset")
	}
	key6 := tcpKey{
		local:  netip.MustParseAddrPort("[2001:db8::1]:40000"),
		remote: netip.MustParseAddrPort("[2001:db8:1::1]:443"),
	}
	if got := stack.tcpInitialSequence(key6, epoch); got == base {
		t.Fatal("IPv4 and IPv6 connection spaces received the same keyed offset")
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
	outstanding := []sentTCPSegment{{sequence: 100, end: 200}, {sequence: 200, end: 300, delivery: tcpDeliverySnapshot{deliveredStamp: 1}}}
	blocks := []tcpSACKBlock{{left: 200, right: 300}}
	var present, fresh bool
	var delivered []sentTCPSegment
	outstanding, _, present, fresh, _, delivered = applyTCPSACK(outstanding, blocks, time.Time{})
	if !present || !fresh || len(delivered) != 1 || delivered[0].delivery.deliveredStamp == 0 || outstanding[1].delivery.deliveredStamp != 0 {
		t.Fatalf("first SACK state = present %t, fresh %t; want true, true", present, fresh)
	}
	outstanding, _, present, fresh, _, delivered = applyTCPSACK(outstanding, blocks, time.Time{})
	if !present || fresh || len(delivered) != 0 {
		t.Fatalf("repeated SACK state = present %t, fresh %t; want true, false", present, fresh)
	}
}

// TestTCPPartialSACKSplitsScoreboard verifies byte-accurate RFC 6675 state
// when a valid SACK block covers only the middle of one transmission.
func TestTCPPartialSACKSplitsScoreboard(t *testing.T) {
	outstanding := []sentTCPSegment{{sequence: 100, end: 400, flags: tcpFlagACK | tcpFlagPSH, state: sentTCPSegmentTransmitted}}
	var present, fresh bool
	var delivered []sentTCPSegment
	outstanding, _, present, fresh, _, delivered = applyTCPSACK(outstanding, []tcpSACKBlock{{left: 200, right: 300}}, time.Time{})
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
		if segment.sequence != want.start || segment.end != want.end || segment.state.has(sentTCPSegmentSACKed) != want.sacked || segment.dataSize() != want.payload || segment.flags&tcpFlagPSH != 0 != want.push {
			t.Fatalf("segment %d = [%d,%d) sacked=%t payload=%d flags=%#x", index, segment.sequence, segment.end, segment.state.has(sentTCPSegmentSACKed), segment.dataSize(), segment.flags)
		}
	}
	if ranges, bytes := tcpSACKedState(outstanding); ranges != 1 || bytes != 100 {
		t.Fatalf("partial SACK aggregate = %d ranges/%d bytes, want 1/100", ranges, bytes)
	}
}

func TestTCPSACKSplitMetadataIsBounded(t *testing.T) {
	payloadSize := uint32(4 * tcpMaximumSACKSplitRanges)
	outstanding := []sentTCPSegment{{sequence: 0, end: payloadSize, state: sentTCPSegmentTransmitted}}
	for offset := uint32(1); offset+1 < payloadSize; offset += 2 {
		outstanding, _, _, _, _, _ = applyTCPSACK(outstanding, []tcpSACKBlock{{left: offset, right: offset + 1}}, time.Time{})
	}
	splitRanges := 0
	for _, segment := range outstanding {
		if segment.state.has(sentTCPSegmentSACKSplit) {
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
		{sequence: 100, end: 150, state: sentTCPSegmentSACKed},
		{sequence: 150, end: 200, state: sentTCPSegmentSACKed},
		{sequence: 200, end: 250, state: sentTCPSegmentSACKed},
	}
	if !sackSegmentLost(byRanges, 0, 100) {
		t.Fatal("three SACKed transmitted ranges did not satisfy IsLost")
	}
	byBytes := []sentTCPSegment{{sequence: 0, end: 100}, {sequence: 100, end: 201, state: sentTCPSegmentSACKed}, {sequence: 201, end: 302, state: sentTCPSegmentSACKed}}
	if !sackSegmentLost(byBytes, 0, 100) {
		t.Fatal("more than 2*SMSS SACKed bytes did not satisfy IsLost")
	}
	byBytes[2].end = 300
	if sackSegmentLost(byBytes, 0, 100) {
		t.Fatal("exactly 2*SMSS SACKed bytes satisfied strict IsLost byte test")
	}
	speculative := []sentTCPSegment{{sequence: 0, end: 100, state: sentTCPSegmentSACKRetried}}
	if pipe := sackRecoveryPipe(speculative, 100); pipe != 200 {
		t.Fatalf("speculative retransmission pipe = %d, want 200", pipe)
	}
	lost := []sentTCPSegment{{sequence: 0, end: 100, state: sentTCPSegmentRACKLost}}
	if pipe := sackRecoveryPipe(lost, 100); pipe != 0 {
		t.Fatalf("unretransmitted lost range pipe = %d, want 0", pipe)
	}
	lost[0].state.set(sentTCPSegmentSACKRetried, true)
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
	wrappedSACK := []sentTCPSegment{{sequence: 0xfffffff0, end: 0x10, state: sentTCPSegmentSACKed}, {sequence: 0x10, end: 0x30, state: sentTCPSegmentSACKed}}
	if highest := highestSACKedSequence(wrappedSACK); highest != 0x30 {
		t.Fatalf("wrapped HighSACK = %#x, want 0x30", highest)
	}
}

func TestTCPPRRDeliveryAndSendCount(t *testing.T) {
	outstanding := []sentTCPSegment{
		{sequence: 100, end: 200, state: sentTCPSegmentSACKed},
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
	var workspace [34]byte
	options := tcpSACKOptions(pieces, 103, 4, tcpSACKBlock{}, false, &workspace)
	blocks := parseTCPSACKOptions(options, 90, 120)
	if len(blocks) != 2 || blocks[0] != (tcpSACKBlock{left: 100, right: 104}) || blocks[1] != (tcpSACKBlock{left: 106, right: 108}) {
		t.Fatalf("coalesced SACK blocks = %#v", blocks)
	}
}

func TestTCPSACKOptionsDoNotAllocate(t *testing.T) {
	pieces := []tcpReceivedPiece{
		{sequence: 100, payload: []byte("ab")},
		{sequence: 102, payload: []byte("cd")},
		{sequence: 108, payload: []byte("ef")},
	}
	allocations := testing.AllocsPerRun(100, func() {
		var workspace [34]byte
		if options := tcpSACKOptions(pieces, 103, 4, tcpSACKBlock{}, false, &workspace); len(options) != 18 {
			panic("unexpected SACK option size")
		}
	})
	if allocations != 0 {
		t.Fatalf("SACK option allocations = %v, want 0", allocations)
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
	var workspace [34]byte
	options := tcpSACKOptions(pieces, 125, 2, block, true, &workspace)
	if len(options) != 18 || binary.BigEndian.Uint32(options[2:6]) != 125 || binary.BigEndian.Uint32(options[6:10]) != 140 ||
		binary.BigEndian.Uint32(options[10:14]) != 120 || binary.BigEndian.Uint32(options[14:18]) != 140 {
		t.Fatalf("DSACK-first options = %x", options)
	}
}

// TestTCPOutOfOrderOverlapPreservesFirstData verifies overlap handling while
// queued payloads remain independently allocated.
func TestTCPOutOfOrderOverlapPreservesFirstData(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
	receiveNext := uint32(100)
	outOfOrder := []tcpReceivedPiece{{sequence: 104, payload: []byte("old")}}
	outOfOrderBytes := 3
	incoming := []byte("abcdef")
	if !connection.storeTCPOutOfOrder(receiveNext, 32, 102, incoming, incoming, false, &outOfOrder, &outOfOrderBytes) {
		t.Fatal("overlapping segment added no new data")
	}
	if len(outOfOrder) != 3 || outOfOrderBytes != 6 {
		t.Fatalf("out-of-order state = %d pieces, %d bytes; want 3, 6", len(outOfOrder), outOfOrderBytes)
	}
	if delivered, closed := connection.receiveTCPData(100, []byte("00"), false, 32, &receiveNext, &outOfOrder, &outOfOrderBytes); !delivered || closed {
		t.Fatalf("receiveTCPData = %t, %t; want true, false", delivered, closed)
	}
	if got := string(testTCPReadBufferBytes(&connection.readBuffer)); got != "00aboldf" {
		t.Fatalf("overlap payload = %q, want %q", got, "00aboldf")
	}
}

func TestTCPOutOfOrderAdoptsCompleteOwnedRange(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
	payload := []byte("owned")
	payload = payload[:len(payload):len(payload)]
	var pieces []tcpReceivedPiece
	bytes := 0
	if !connection.storeTCPOutOfOrder(100, 32, 104, payload, payload, false, &pieces, &bytes) {
		t.Fatal("out-of-order payload was not retained")
	}
	if len(pieces) != 1 || &pieces[0].payload[0] != &payload[0] {
		t.Fatal("single uncovered range did not transfer its backing")
	}
}

func TestTCPOutOfOrderCompactsPartialOwnedRange(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
	owner := make([]byte, 32)
	copy(owner[28:], "tail")
	payload := owner[28:]
	var pieces []tcpReceivedPiece
	bytes := 0
	if !connection.storeTCPOutOfOrder(100, 32, 104, payload, owner, false, &pieces, &bytes) {
		t.Fatal("partial out-of-order payload was not retained")
	}
	if len(pieces) != 1 || string(pieces[0].payload) != "tail" || &pieces[0].payload[0] == &owner[28] || cap(pieces[0].payload) != len(pieces[0].payload) {
		t.Fatalf("partial payload retained owner backing: pieces=%+v capacity=%d", pieces, cap(pieces[0].payload))
	}
}

func TestTCPPromoteCompactsPartiallyDeliveredRange(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 2, readNotify: make(chan struct{})}
	owner := make([]byte, 32)
	copy(owner, "data")
	pieces := []tcpReceivedPiece{{sequence: 100, payload: owner[:4]}}
	bytes := 4
	receiveNext := uint32(100)
	if delivered, closed := connection.promoteTCPReceived(&receiveNext, &pieces, &bytes); !delivered || closed {
		t.Fatalf("partial promotion = delivered %t closed %t", delivered, closed)
	}
	if receiveNext != 102 || bytes != 2 || len(pieces) != 1 || string(pieces[0].payload) != "ta" ||
		&pieces[0].payload[0] == &owner[2] || cap(pieces[0].payload) != len(pieces[0].payload) {
		t.Fatalf("partial promotion retained owner backing: next=%d bytes=%d pieces=%+v capacity=%d", receiveNext, bytes, pieces, cap(pieces[0].payload))
	}
}

// TestTCPOutOfOrderUsesPromisedWindow verifies that sparse data near the
// advertised right edge remains admissible after another range uses memory.
func TestTCPOutOfOrderUsesPromisedWindow(t *testing.T) {
	connection := &TCPConn{receiveCapacity: 32, readNotify: make(chan struct{})}
	receiveNext := uint32(100)
	var outOfOrder []tcpReceivedPiece
	outOfOrderBytes := 0
	first := []byte("first")
	if !connection.storeTCPOutOfOrder(receiveNext, 32, 120, first, first, false, &outOfOrder, &outOfOrderBytes) {
		t.Fatal("first out-of-order range was rejected")
	}
	edge := []byte("edge")
	if !connection.storeTCPOutOfOrder(receiveNext, 32, 128, edge, edge, false, &outOfOrder, &outOfOrderBytes) {
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
	connection := newTCPConn(stack, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	segment := tcpSegment{payload: make([]byte, 65535)}
	accepted := 0
	for connection.enqueueInbound(segment) {
		accepted++
	}
	if accepted == 0 {
		t.Fatal("inbound byte queue accepted no segments")
	}
	if queued := connection.inbound.retainedBytes(); queued > tcpInboundByteCapacity {
		t.Fatalf("queued TCP bytes = %d, limit %d", queued, tcpInboundByteCapacity)
	}
	consumed, ok := connection.inbound.dequeue()
	if !ok {
		t.Fatal("full inbound queue did not return a segment")
	}
	if consumed.retainedBytes != 0 {
		t.Fatalf("consumed segment retained accounting = %d", consumed.retainedBytes)
	}
	if !connection.enqueueInbound(segment) {
		t.Fatal("released inbound byte capacity was not reusable")
	}
	peak := connection.inbound.peakBytes()
	connection.inbound.close()
	if connection.enqueueInbound(segment) {
		t.Fatal("closed inbound queue accepted a segment")
	}
	if queued := connection.inbound.retainedBytes(); queued != 0 {
		t.Fatalf("closed inbound queue retained %d bytes", queued)
	}
	if retainedPeak := connection.inbound.peakBytes(); retainedPeak != peak {
		t.Fatalf("closed inbound queue peak = %d, want %d", retainedPeak, peak)
	}
}

func TestTCPInboundQueueOverloadUpdatesDiagnostics(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.77")
	remote := netip.MustParseAddr("198.51.100.77")
	_, stack := newTestStack(t, local, remote)
	key := tcpKey{
		local:  netip.AddrPortFrom(local, 8080),
		remote: netip.AddrPortFrom(remote, 45000),
	}
	connection := newTCPConn(stack, "tcp4", key, 1400, tcpSocketOptionSet{})
	connection.inbound.mu.Lock()
	connection.inbound.bytes = tcpInboundByteCapacity
	connection.inbound.mu.Unlock()
	stack.mu.Lock()
	stack.tcp[key] = connection
	stack.mu.Unlock()
	t.Cleanup(func() {
		stack.mu.Lock()
		delete(stack.tcp, key)
		stack.mu.Unlock()
		connection.inbound.close()
	})
	packet := buildTestTCP(remote, local, 45000, 8080, 1, 1, tcpFlagACK, 65535, nil, []byte("overload"))
	if err := writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	if dropped := connection.inboundQueueDrops.Load(); dropped != 1 {
		t.Fatalf("connection inbound queue drops = %d, want 1", dropped)
	}
	stats := stack.Stats()
	if stats.TCPInboundQueueDrops != 1 || stats.InboundDroppedPackets != 1 {
		t.Fatalf("stack overload diagnostics = %+v", stats)
	}
}

func TestTCPInboundQueuePrependHonorsByteCapacity(t *testing.T) {
	queue := newTCPSegmentQueue()
	segment := tcpSegment{payload: make([]byte, 65535)}
	for queue.enqueue(segment) {
	}
	if queue.prepend(segment) {
		t.Fatal("inbound queue prepend exceeded byte capacity")
	}
	if queued := queue.retainedBytes(); queued > tcpInboundByteCapacity {
		t.Fatalf("queued TCP bytes = %d, limit %d", queued, tcpInboundByteCapacity)
	}
}

func TestTCPInboundQueueRetainsOnlySmallBacking(t *testing.T) {
	queue := newTCPSegmentQueue()
	for index := 0; index < tcpMetadataQueueRetain; index++ {
		if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
			t.Fatal("small inbound queue rejected a segment")
		}
	}
	for index := 0; index < tcpMetadataQueueRetain; index++ {
		segment, ok := queue.dequeue()
		if !ok || segment.sequence != uint32(index) {
			t.Fatalf("small inbound queue dequeue = %d, %v, want %d, true", segment.sequence, ok, index)
		}
	}
	if len(queue.segments) != 0 || cap(queue.segments) == 0 || cap(queue.segments) > tcpMetadataQueueRetain {
		t.Fatalf("small drained inbound queue = len %d cap %d", len(queue.segments), cap(queue.segments))
	}
	for index := 0; index < tcpMetadataQueueRetain+1; index++ {
		if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
			t.Fatal("large inbound queue rejected a segment")
		}
	}
	for index := 0; index < tcpMetadataQueueRetain+1; index++ {
		if _, ok := queue.dequeue(); !ok {
			t.Fatal("large inbound queue lost a segment")
		}
	}
	if queue.segments != nil || queue.head != 0 {
		t.Fatalf("large drained inbound queue retained len %d cap %d head %d", len(queue.segments), cap(queue.segments), queue.head)
	}
}

func TestTCPInboundQueueCompactsConsumedPrefixBeforeGrowing(t *testing.T) {
	queue := newTCPSegmentQueue()
	queue.segments = make([]tcpSegment, 0, 8)
	for index := 0; index < cap(queue.segments); index++ {
		segment := tcpSegment{sequence: uint32(index), payload: []byte{byte(index)}}
		segment.setOptions([]byte{1, byte(index)})
		if !queue.enqueue(segment) {
			t.Fatal("inbound queue rejected a segment")
		}
	}
	backing := &queue.segments[0]
	capacity := cap(queue.segments)
	for index := 0; index < capacity/2; index++ {
		segment, ok := queue.dequeue()
		if !ok || segment.sequence != uint32(index) {
			t.Fatalf("inbound queue dequeue = %d, %v, want %d, true", segment.sequence, ok, index)
		}
	}
	last := tcpSegment{sequence: uint32(capacity), payload: []byte{byte(capacity)}}
	last.setOptions([]byte{1, byte(capacity)})
	if !queue.enqueue(last) {
		t.Fatal("inbound queue rejected a segment after consuming its prefix")
	}
	if queue.head != 0 || cap(queue.segments) != capacity || &queue.segments[0] != backing {
		t.Fatalf("inbound queue grew instead of compacting: head %d len %d cap %d", queue.head, len(queue.segments), cap(queue.segments))
	}
	for index := capacity / 2; index <= capacity; index++ {
		segment, ok := queue.dequeue()
		if !ok || segment.sequence != uint32(index) || !bytes.Equal(segment.payload, []byte{byte(index)}) || !bytes.Equal(segment.optionBytes(), []byte{1, byte(index)}) {
			t.Fatalf("compacted inbound queue dequeue = %+v, %v, want sequence %d", segment, ok, index)
		}
	}
}

func BenchmarkTCPInboundQueueSmallBurst(b *testing.B) {
	queue := newTCPSegmentQueue()
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		for index := 0; index < tcpMetadataQueueRetain; index++ {
			if !queue.enqueue(tcpSegment{sequence: uint32(index)}) {
				b.Fatal("small inbound queue rejected a segment")
			}
		}
		for index := 0; index < tcpMetadataQueueRetain; index++ {
			if _, ok := queue.dequeue(); !ok {
				b.Fatal("small inbound queue lost a segment")
			}
		}
	}
}

func BenchmarkTCPHandlePureACK(b *testing.B) {
	local := netip.MustParseAddr("192.0.2.241")
	remote := netip.MustParseAddr("198.51.100.241")
	_, stack := newTestStack(b, local, remote)
	key := tcpKey{
		local:  netip.AddrPortFrom(local, 8443),
		remote: netip.AddrPortFrom(remote, 49152),
	}
	connection := newTCPConn(stack, "tcp4", key, 1500, tcpSocketOptionSet{})
	stack.mu.Lock()
	stack.tcp[key] = connection
	stack.mu.Unlock()
	packet, ok := parseIPPacket(buildTestTCP(remote, local, key.remote.Port(), key.local.Port(), 100, 200, tcpFlagACK, 65535, tcpTimestampOptions(123, 456), nil))
	if !ok {
		b.Fatal("failed to parse benchmark packet")
	}
	receivedAt := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := stack.handleTCP(packet, receivedAt); err != nil {
			b.Fatal(err)
		}
		if _, ok = connection.inbound.dequeue(); !ok {
			b.Fatal("TCP segment was not queued")
		}
	}
}

func TestBuildTCPPacketIntoOverwritesReusedBuffer(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.242")
	target := netip.MustParseAddr("198.51.100.242")
	options := tcpTimestampOptions(123, 456)
	payload := []byte("reused TCP packet")
	want, err := buildTCPPacket(source, target, 49152, 8443, 100, 200, tcpFlagACK|tcpFlagPSH, 32768, options, payload, 1500, 0x28, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	dirty := make([]byte, len(want))
	for index := range dirty {
		dirty[index] = 0xff
	}
	got, err := buildTCPPacketInto(dirty, source, target, 49152, 8443, 100, 200, tcpFlagACK|tcpFlagPSH, 32768, options, payload, 1500, 0x28, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reused TCP packet differs:\n got %x\nwant %x", got, want)
	}
}

func TestTCPSegmentTimestampOptionsUseFixedWorkspace(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.243")
	remote := netip.MustParseAddr("198.51.100.243")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	connection := newTCPConn(stack, "tcp4", tcpKey{
		local:  netip.AddrPortFrom(local, 49152),
		remote: netip.AddrPortFrom(remote, 8443),
	}, 1500, tcpSocketOptionSet{})

	connection.peerTimestamp = true
	connection.recentTimestamp = 0x10203040
	extra := []byte{1, 1, 5, 10, 0, 0, 0, 1, 0, 0, 0, 2}
	timestamp, _, err := connection.sendSegmentForMTU(100, 200, tcpFlagACK, 32768, extra, nil, false, 1500)
	if err != nil {
		t.Fatal(err)
	}
	packet, ok := parseIPPacket(readOutboundPacket(t, stack))
	if !ok || len(packet.payload) < tcpHeaderSize {
		t.Fatal("timestamped TCP segment could not be parsed")
	}
	headerSize := int(packet.payload[12]>>4) * 4
	if headerSize < tcpHeaderSize || headerSize > len(packet.payload) {
		t.Fatalf("timestamped TCP header size = %d", headerSize)
	}
	want := append(tcpTimestampOptions(timestamp, connection.recentTimestamp), extra...)
	if got := packet.payload[tcpHeaderSize:headerSize]; !bytes.Equal(got, want) {
		t.Fatalf("timestamped TCP options = %x, want %x", got, want)
	}
	if _, _, err = connection.sendSegmentForMTU(100, 200, tcpFlagACK, 32768, make([]byte, 29), nil, false, 1500); err == nil || err.Error() != "mipstack: invalid TCP options" {
		t.Fatalf("oversized timestamp options error = %v", err)
	}
	if entry, ok := stack.outbound.tryDequeue(); ok {
		stack.outbound.release(entry)
		t.Fatal("oversized timestamp options emitted a packet")
	}
}

func TestTCPActorWakeCoalescesStateChanges(t *testing.T) {
	connection := &TCPConn{actorWake: make(chan struct{}, 1)}
	connection.wakeActor(tcpActorWakeSend)
	connection.wakeActor(tcpActorWakeWindow)
	connection.wakeActor(tcpActorWakeOptions | tcpActorWakePathMTU)
	select {
	case <-connection.actorWake:
	default:
		t.Fatal("actor wake was not published")
	}
	want := uint32(tcpActorWakeSend | tcpActorWakeWindow | tcpActorWakeOptions | tcpActorWakePathMTU)
	if got := connection.takeActorWake(); got != want {
		t.Fatalf("actor wake flags = %#x, want %#x", got, want)
	}
	select {
	case <-connection.actorWake:
		t.Fatal("coalesced actor wake published more than one token")
	default:
	}
	connection.wakeActor(tcpActorWakeSend)
	select {
	case <-connection.actorWake:
	default:
		t.Fatal("actor wake did not rearm after consumption")
	}
}

// TestTCPTimerOrderingDrainsPreDeadlineBacklog verifies that scheduler delay
// cannot turn a large, already-arrived packet backlog into synthetic loss.
// The backlog deliberately exceeds the former 1024-event deferral limit.
func TestTCPTimerOrderingDrainsPreDeadlineBacklog(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.77"), netip.MustParseAddr("198.51.100.77"))
	link.echoTCP = true
	link.dropTCPData = 1
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 9077))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tcpConnection := connection.(*TCPConn)
	if _, err = connection.Write([]byte("timer ordering")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		peer := link.tcp[tcpConnection.key.local.Port()]
		return peer != nil && tcpSequenceGreater(peer.highestClientEnd, peer.clientNext)
	})

	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, cumulativeACK := peer.serverNext, peer.highestClientEnd
	link.mu.Unlock()
	baseline := tcpConnection.retransmissions.Load()
	// armLiveness takes c.mu while processing the first segment. Holding it
	// models an actor that was not scheduled while the remaining packets and
	// its loss timer became ready concurrently.
	tcpConnection.mu.Lock()
	arrival := time.Now().Add(-time.Second)
	arrivalStamp := monotonicStampAt(tcpConnection.stack.timestampEpoch, arrival)
	queued := true
	for index := 0; index < 2048; index++ {
		queued = tcpConnection.enqueueInbound(tcpSegment{sequence: sequence, window: 65535, receivedAt: arrivalStamp}) && queued
	}
	queued = tcpConnection.enqueueInbound(tcpSegment{
		sequence: sequence, acknowledgement: cumulativeACK, flags: tcpFlagACK, window: 65535, receivedAt: arrivalStamp,
	}) && queued
	time.Sleep(tcpMinimumRTO + 50*time.Millisecond)
	tcpConnection.mu.Unlock()
	if !queued {
		t.Fatal("pre-deadline TCP backlog exceeded its byte capacity")
	}
	waitFor(t, time.Second, func() bool { return tcpConnection.inbound.len() == 0 })
	if retransmissions := tcpConnection.retransmissions.Load(); retransmissions != baseline {
		t.Fatalf("pre-deadline backlog caused %d retransmissions, want 0", retransmissions-baseline)
	}
}

func TestTCPTimerBacklogSnapshotDoesNotGrow(t *testing.T) {
	deadline := time.Now().Add(-time.Second)
	var backlog tcpTimerBacklog
	drain, forceTimer := backlog.order(2048, deadline, time.Now())
	if !drain || forceTimer {
		t.Fatalf("initial backlog = drain %t force %t", drain, forceTimer)
	}
	backlog.consumed()
	for remaining := 2047; remaining > 0; remaining-- {
		drain, forceTimer := backlog.order(4096, deadline, time.Now())
		if !drain || forceTimer {
			t.Fatalf("backlog with %d snapshot events = drain %t force %t", remaining, drain, forceTimer)
		}
		backlog.consumed()
	}
	if drain, forceTimer := backlog.order(4096, deadline, time.Now()); drain || !forceTimer {
		t.Fatalf("drained snapshot = drain %t force %t, want false/true", drain, forceTimer)
	}
	if drain, forceTimer := backlog.order(4096, time.Now().Add(time.Second), time.Now()); drain || forceTimer {
		t.Fatalf("future deadline = drain %t force %t, want false/false", drain, forceTimer)
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
	secondRemote := netip.AddrPortFrom(link.remote, 9101)
	stack.mu.Lock()
	cursor := &stack.nextPort[0]
	offset := automaticTCPPortOffsets(cursor.secret, link.local, secondRemote)[0] % dynamicPortCount
	position := uint32(firstPort - dynamicPortFirst)
	cursor.dynamic = uint16((position + dynamicPortCount - offset) % dynamicPortCount)
	stack.mu.Unlock()
	second, err := stack.DialTCP(context.Background(), "tcp", netip.AddrPort{}, secondRemote)
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
	// Dial returns after the connection actor queues its final ACK; the device
	// consumer may not have observed that packet yet. Synchronize with the
	// emulated peer before disabling echo so the handshake ACK cannot be
	// mistaken for the later persist probe under single-P scheduling.
	waitFor(t, time.Second, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.clientACKs != 0
	})
	link.mu.Lock()
	peer := link.tcp[tcpConnection.key.local.Port()]
	sequence, acknowledgement := peer.serverNext, peer.clientNext
	link.mu.Unlock()
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return tcpConnection.Info().PeerWindow == 0 })
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
	initialData := false
	deadline := time.After(time.Second)
	for !initialData {
		select {
		case packet := <-link.outbound:
			parsed, ok := parseIPPacket(packet)
			if !ok || parsed.protocol != protocolTCP || len(parsed.payload) < tcpHeaderSize {
				continue
			}
			headerSize := int(parsed.payload[12]>>4) * 4
			initialData = headerSize >= tcpHeaderSize && headerSize < len(parsed.payload)
		case <-deadline:
			t.Fatal("timed out waiting for initial data segment")
		}
	}
	if err = link.deliverTCP(tcpConnection.key.remote.Port(), tcpConnection.key.local.Port(), sequence, acknowledgement, tcpFlagACK, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return stack.Stats().TCPRetransmissions != 0 })
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
	}, 1400, tcpSocketOptionSet{})

	result := make(chan error, 1)
	go func() { result <- testTCPHandshake(connection, 1000) }()
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
	enqueueTCPTestSegment(t, connection, tcpSegment{
		sequence: 2000, acknowledgement: 1001, flags: tcpFlagSYN | tcpFlagACK | tcpFlagECE, window: 65535,
	})
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
	if entry, ok := waitTestPacketEntry(&stack.outbound, time.Second); ok {
		response := consumeTestPacket(&stack.outbound, entry)
		parsed, ok := parseIPPacket(response)
		if !ok || len(parsed.payload) < tcpHeaderSize || parsed.payload[13] != tcpFlagRST|tcpFlagACK {
			t.Fatalf("reserved TCP header response = %x", response)
		}
	} else {
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

func TestTCPRFC6069RTOBackoffRevert(t *testing.T) {
	estimator := newRTTEstimator(time.Second)
	estimator.backoff()
	estimator.backoff()
	quote := make([]byte, 8)
	binary.BigEndian.PutUint32(quote[4:8], 100)
	networkUnreachable := ICMPError{
		Type: 3, Code: 0, QuotedSource: netip.MustParseAddr("192.0.2.1"), QuotedPayload: quote,
	}
	if !tcpRevertRTOBackoff(networkUnreachable, 100, 2, &estimator) || estimator.rto != 2*time.Second || estimator.backoffs != 1 {
		t.Fatalf("RFC 6069 IPv4 revert = RTO %v backoffs %d", estimator.rto, estimator.backoffs)
	}
	if tcpRevertRTOBackoff(networkUnreachable, 101, 2, &estimator) {
		t.Fatal("RFC 6069 accepted a quote outside SND.UNA")
	}
	portUnreachable := networkUnreachable
	portUnreachable.Code = 3
	if tcpRevertRTOBackoff(portUnreachable, 100, 2, &estimator) {
		t.Fatal("RFC 6069 accepted port unreachable")
	}
	ipv6NoRoute := ICMPError{
		Type: 1, Code: 0, QuotedSource: netip.MustParseAddr("2001:db8::1"), QuotedPayload: quote,
	}
	if !tcpRevertRTOBackoff(ipv6NoRoute, 100, 2, &estimator) || estimator.rto != time.Second || estimator.backoffs != 0 {
		t.Fatalf("RFC 6069 IPv6 revert = RTO %v backoffs %d", estimator.rto, estimator.backoffs)
	}

	capped := newRTTEstimator(80 * time.Second)
	capped.backoff()
	capped.backoff()
	if capped.rto != tcpMaximumRTO || !capped.revertBackoff() || capped.rto != tcpMaximumRTO || !capped.revertBackoff() || capped.rto != 80*time.Second {
		t.Fatalf("capped RTO revert = RTO %v backoffs %d", capped.rto, capped.backoffs)
	}
}

func TestTCPMinimumRTTAdaptsToLongerPath(t *testing.T) {
	var filter tcpMinimumRTTFilter
	start := time.Unix(1, 0)
	if minimum := filter.observe(start, 10*time.Millisecond); minimum != 10*time.Millisecond {
		t.Fatalf("initial minimum RTT = %v", minimum)
	}
	// Populate Linux's quarter- and half-window backup samples while the
	// original path minimum remains valid.
	if minimum := filter.observe(start.Add(tcpMinimumRTTWindow/4+time.Second), 20*time.Millisecond); minimum != 10*time.Millisecond {
		t.Fatalf("quarter-window minimum RTT = %v", minimum)
	}
	if minimum := filter.observe(start.Add(tcpMinimumRTTWindow/2+time.Second), 30*time.Millisecond); minimum != 10*time.Millisecond {
		t.Fatalf("half-window minimum RTT = %v", minimum)
	}
	if minimum := filter.observe(start.Add(tcpMinimumRTTWindow+time.Second), 40*time.Millisecond); minimum != 20*time.Millisecond {
		t.Fatalf("expired path minimum RTT = %v, want 20ms", minimum)
	}
	// A genuinely lower sample immediately replaces every stale candidate.
	if minimum := filter.observe(start.Add(tcpMinimumRTTWindow+2*time.Second), 5*time.Millisecond); minimum != 5*time.Millisecond {
		t.Fatalf("new lower minimum RTT = %v, want 5ms", minimum)
	}
}

// FuzzTCPOptions verifies bounded option parsing and wrapped SACK validation.
func FuzzTCPOptions(f *testing.F) {
	f.Add([]byte{2, 4, 0x05, 0xb4, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}, uint32(100), uint32(200))
	f.Add([]byte{5, 10, 0, 0, 0, 120, 0, 0, 0, 160}, uint32(100), uint32(200))
	f.Fuzz(func(t *testing.T, options []byte, acknowledged, sendNext uint32) {
		if len(options) > 40 {
			options = options[:40]
		}
		before := append([]byte(nil), options...)
		window := sendNext % (tcpMaximumScaledWindow + 1)
		sendNext = acknowledged + window
		mss, scale, _, _, _, _ := parseTCPOptions(options, 536, 1360)
		if mss < tcpMinimumPeerMSS || mss > 1360 {
			t.Fatalf("parsed MSS %d is outside [%d, 1360]", mss, tcpMinimumPeerMSS)
		}
		if scale > 14 {
			t.Fatalf("parsed window scale = %d, want <= 14", scale)
		}
		_, _, _ = parseTCPTimestamp(options)
		blocks := parseTCPSACKOptions(options, acknowledged, sendNext)
		for index, block := range blocks {
			leftDistance, rightDistance := block.left-acknowledged, block.right-acknowledged
			if leftDistance >= rightDistance || rightDistance > window {
				t.Fatalf("SACK block %d = [%#x,%#x) outside %#x-byte send window", index, block.left, block.right, window)
			}
			if index != 0 && blocks[index-1].right-acknowledged >= leftDistance {
				t.Fatalf("SACK blocks %d and %d are unordered or unmerged", index-1, index)
			}
		}
		if block, ok := parseTCPDSACKOption(options, acknowledged, sendNext, window); ok && !tcpSequenceLess(block.left, block.right) {
			t.Fatalf("invalid DSACK block [%#x,%#x)", block.left, block.right)
		}
		if !bytes.Equal(options, before) {
			t.Fatal("TCP option parsing modified its input")
		}
	})
}

// FuzzTCPSACKScoreboard verifies sender-side SACK splitting and marking keep
// sequence ranges byte-exact, bounded, and internally consistent.
func FuzzTCPSACKScoreboard(f *testing.F) {
	f.Add([]byte{0, 0, 10, 0, 0, 20, 40, 1}, uint32(100), uint16(256), uint16(64))
	f.Add([]byte{0, 1, 1, 0, 0, 2, 1, 0}, uint32(0xfffffff0), uint16(96), uint16(32))
	f.Add([]byte(nil), uint32(0xfffffff0), uint16(4095), uint16(0))
	f.Fuzz(func(t *testing.T, events []byte, base uint32, totalValue, segmentValue uint16) {
		if len(events) > 128 {
			events = events[:128]
		}
		total := int(totalValue%4096) + 1
		segmentSize := int(segmentValue%512) + 1
		epoch := time.Unix(300, 0)
		outstanding := make([]sentTCPSegment, 0, (total+segmentSize-1)/segmentSize)
		for start := 0; start < total; start += segmentSize {
			end := start + segmentSize
			if end > total {
				end = total
			}
			flags := byte(tcpFlagACK)
			if end == total {
				flags |= tcpFlagPSH
			}
			outstanding = append(outstanding, sentTCPSegment{
				sequence:  base + uint32(start),
				end:       base + uint32(end),
				flags:     flags,
				state:     sentTCPSegmentTransmitted,
				timestamp: uint32(start),
				hostQueue: testPacketQueueTicketAt(epoch, epoch.Add(time.Duration(start)*time.Microsecond)),
				delivery:  tcpDeliverySnapshot{deliveredStamp: tcpDeliveryTimestamp(start + 1), deliveredFlags: uint32(start)},
			})
		}
		check := func() {
			var totalBytes, sackedBytes uint32
			sackedRanges := 0
			for index, segment := range outstanding {
				start := segment.sequence - base
				end := segment.end - base
				if start >= end || end > uint32(total) {
					t.Fatalf("segment %d outside send window: [%#x,%#x) base %#x total %d", index, segment.sequence, segment.end, base, total)
				}
				if index != 0 && outstanding[index-1].end != segment.sequence {
					t.Fatalf("segments %d and %d are not contiguous: %#x != %#x", index-1, index, outstanding[index-1].end, segment.sequence)
				}
				size := segment.end - segment.sequence
				totalBytes += size
				if segment.state.has(sentTCPSegmentSACKed) {
					sackedRanges++
					sackedBytes += size
				}
			}
			if totalBytes != uint32(total) {
				t.Fatalf("scoreboard covers %d bytes, want %d", totalBytes, total)
			}
			if ranges, bytes := tcpSACKedState(outstanding); ranges != sackedRanges || bytes != sackedBytes {
				t.Fatalf("SACK aggregate = %d/%d, want %d/%d", ranges, bytes, sackedRanges, sackedBytes)
			}
			splitRanges := 0
			for index := range outstanding {
				if outstanding[index].state.has(sentTCPSegmentSACKSplit) {
					splitRanges++
				}
			}
			if splitRanges > tcpMaximumSACKSplitRanges {
				t.Fatalf("SACK-created ranges = %d, limit %d", splitRanges, tcpMaximumSACKSplitRanges)
			}
		}
		check()
		for offset := 0; offset+4 <= len(events); offset += 4 {
			left := int(binary.BigEndian.Uint16(events[offset:offset+2])) % total
			width := int(events[offset+2])%(total-left) + 1
			right := left + width
			if events[offset+3]&1 != 0 && right-left > 1 {
				left++
			}
			block := tcpSACKBlock{left: base + uint32(left), right: base + uint32(right)}
			var highest uint32
			var present, fresh bool
			var newlySACKed []sentTCPSegment
			outstanding, highest, present, fresh, _, newlySACKed = applyTCPSACK(outstanding, []tcpSACKBlock{block}, epoch)
			if !present || highest != block.right {
				t.Fatalf("SACK apply metadata = present %t highest %#x, want true/%#x", present, highest, block.right)
			}
			if fresh != (len(newlySACKed) != 0) {
				t.Fatalf("fresh SACK metadata = %t with %d newly SACKed ranges", fresh, len(newlySACKed))
			}
			for _, segment := range newlySACKed {
				if segment.sequence-base < uint32(left) || segment.end-base > uint32(right) || !segment.state.has(sentTCPSegmentTransmitted) {
					t.Fatalf("newly SACKed range [%#x,%#x) outside block [%#x,%#x)", segment.sequence, segment.end, block.left, block.right)
				}
			}
			check()
		}
	})
}

// FuzzTCPOutOfOrderRanges verifies receive scoreboard accounting, ordering,
// overlap removal, FIN placement, and sequence-number wraparound.
func FuzzTCPOutOfOrderRanges(f *testing.F) {
	f.Add([]byte{0, 4, 8, 1, 0, 0, 0, 8, 2, 0, 0, 8, 8, 3, 1}, uint32(100), uint16(64))
	f.Add([]byte{0, 16, 16, 4, 0, 0, 0, 32, 5, 1, 0, 8, 32, 6, 0}, uint32(0xfffffff0), uint16(128))
	f.Fuzz(func(t *testing.T, events []byte, receiveNext uint32, capacityValue uint16) {
		if len(events) > 320 {
			events = events[:320]
		}
		capacity := int(capacityValue)
		if capacity == 0 {
			capacity = 1
		}
		connection := &TCPConn{receiveCapacity: capacity}
		var pieces []tcpReceivedPiece
		outOfOrderBytes := 0
		check := func() {
			bytes := 0
			previousEnd := uint32(0)
			finCount := 0
			for index, piece := range pieces {
				start := piece.sequence - receiveNext
				end := start + uint32(len(piece.payload))
				if len(piece.payload) == 0 && !piece.fin {
					t.Fatalf("empty non-FIN receive piece at %d", index)
				}
				if end > uint32(capacity) || index != 0 && start < previousEnd {
					t.Fatalf("receive piece %d = [%d,%d) outside or overlapping a %d-byte window", index, start, end, capacity)
				}
				if piece.fin {
					finCount++
					if index != len(pieces)-1 {
						t.Fatalf("FIN appears before receive piece %d", index+1)
					}
				}
				previousEnd = end
				bytes += len(piece.payload)
			}
			if finCount > 1 || len(pieces) > tcpMaximumOutOfOrder || bytes != outOfOrderBytes || bytes > capacity {
				t.Fatalf("receive scoreboard = %d FINs, %d pieces, %d/%d bytes", finCount, len(pieces), bytes, outOfOrderBytes)
			}
			if got := connection.outOfOrderUnread.Load(); got != int64(outOfOrderBytes) {
				t.Fatalf("published out-of-order bytes = %d, want %d", got, outOfOrderBytes)
			}
		}
		for offset := 0; offset+5 <= len(events); offset += 5 {
			distance := uint32(binary.BigEndian.Uint16(events[offset : offset+2]))
			length := int(events[offset+2] & 63)
			payload := make([]byte, length)
			for index := range payload {
				payload[index] = events[offset+3] + byte(index)
			}
			connection.storeTCPOutOfOrder(
				receiveNext, uint32(capacity), receiveNext+distance, payload, payload,
				events[offset+4]&1 != 0, &pieces, &outOfOrderBytes,
			)
			check()
		}
		normalized := normalizeTCPReceivedPieces(receiveNext, append([]tcpReceivedPiece(nil), pieces...))
		if len(normalized) != len(pieces) {
			t.Fatalf("normalizing an existing scoreboard changed its length from %d to %d", len(pieces), len(normalized))
		}
		for index := range pieces {
			if normalized[index].sequence != pieces[index].sequence || normalized[index].fin != pieces[index].fin || !bytes.Equal(normalized[index].payload, pieces[index].payload) {
				t.Fatalf("normalizing an existing scoreboard changed piece %d", index)
			}
		}
	})
}

// FuzzTCPEstablishedSegmentSequence drives checksum-valid peer segments
// through a live established connection and verifies bounded actor ownership.
func FuzzTCPEstablishedSegmentSequence(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0xff, 0xff, 4, 0, 'a', 0, 0, 1, 0xff, 0xff, 4, 1, 'b'}, false)
	f.Add([]byte{4, 0, 1, 0x40, 0, 6, 2, 'c', 0, 0, 3, 0x20, 0, 0, 0, 0}, true)
	f.Add([]byte{0, 0, 4, 0xff, 0xff, 0, 0, 0}, false)
	f.Fuzz(func(t *testing.T, events []byte, ipv6 bool) {
		if len(events) > 128 {
			events = events[:128]
		}
		local := netip.MustParseAddr("192.0.2.250")
		remote := netip.MustParseAddr("198.51.100.250")
		if ipv6 {
			local = netip.MustParseAddr("2001:db8::250")
			remote = netip.MustParseAddr("2001:db8:1::250")
		}
		link, stack := newTestStack(t, local, remote)
		link.echoTCP = true
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		netConnection, err := stack.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPortFrom(remote, 8080))
		if err != nil {
			t.Fatal(err)
		}
		connection := netConnection.(*TCPConn)

		link.mu.Lock()
		peer := link.tcp[connection.key.local.Port()]
		if peer == nil {
			link.mu.Unlock()
			t.Fatal("emulated peer did not retain the established connection")
		}
		remoteNext, localNext := peer.serverNext, peer.clientNext
		link.mu.Unlock()

		for offset := 0; offset+8 <= len(events); offset += 8 {
			event := events[offset : offset+8]
			sequence := remoteNext + uint32(int32(int8(event[0])))
			acknowledgement := localNext + uint32(int32(int8(event[1])))
			switch event[6] >> 6 {
			case 1:
				sequence = uint32(event[0])
			case 2:
				sequence = ^uint32(event[0])
			case 3:
				acknowledgement = ^uint32(event[1])
			}
			flags := byte(tcpFlagACK)
			if event[2]&1 != 0 {
				flags |= tcpFlagPSH
			}
			if event[2]&2 != 0 {
				flags |= tcpFlagFIN
			}
			if event[2]&4 != 0 {
				flags |= tcpFlagRST
			}
			if event[2]&8 != 0 {
				flags |= tcpFlagSYN
			}
			if event[2]&16 != 0 {
				flags |= tcpFlagECE
			}
			if event[2]&32 != 0 {
				flags |= tcpFlagCWR
			}
			if event[2]&64 != 0 {
				flags |= 0x20
			}
			if event[2]&128 != 0 {
				flags &^= tcpFlagACK
			}
			window := binary.BigEndian.Uint16(event[3:5])
			payload := bytes.Repeat(event[7:8], int(event[5]&15))
			var options []byte
			switch event[6] & 3 {
			case 1:
				options = tcpTimestampOptions(uint32(event[7])<<24|uint32(event[0]), uint32(event[1]))
			case 2:
				options = make([]byte, 12)
				options[0], options[1], options[2], options[3] = 1, 1, 5, 10
				left := localNext + uint32(int32(int8(event[0])))
				right := left + 1 + uint32(event[7]&15)
				binary.BigEndian.PutUint32(options[4:8], left)
				binary.BigEndian.PutUint32(options[8:12], right)
			case 3:
				options = append([]byte(nil), event[4:8]...)
			}
			packet := buildTestTCP(remote, local, 8080, connection.key.local.Port(), sequence, acknowledgement, flags, window, options, payload)
			if event[6]&0x10 != 0 {
				setPacketECN(packet, 3)
			}
			if err = writeTestPacket(stack, packet); err != nil {
				t.Fatal(err)
			}
			if sequence == remoteNext && acknowledgement == localNext && flags&tcpFlagACK != 0 && flags&(tcpFlagSYN|tcpFlagRST) == 0 {
				remoteNext += uint32(len(payload))
				if flags&tcpFlagFIN != 0 {
					remoteNext++
				}
			}
			if flags&tcpFlagRST != 0 {
				break
			}
		}

		deadline := time.Now().Add(time.Second)
		for connection.inbound.len() != 0 && time.Now().Before(deadline) {
			runtime.Gosched()
		}
		if queued := connection.inbound.len(); queued != 0 {
			t.Fatalf("established connection retained %d actor segments after drain deadline", queued)
		}
		if retained := connection.inbound.retainedBytes(); retained < 0 || retained > tcpInboundByteCapacity {
			t.Fatalf("established input retained %d bytes, capacity %d", retained, tcpInboundByteCapacity)
		}
		info := connection.Info()
		if info.InboundQueueBytes < 0 || info.InboundQueueBytes > int64(info.InboundQueueCapacity) || info.InboundQueuePeak > int64(info.InboundQueueCapacity) {
			t.Fatalf("established input queue diagnostics = %+v", info)
		}
		if err = stack.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-connection.done:
		case <-time.After(time.Second):
			t.Fatal("established connection did not stop with its stack")
		}
		if connection.inbound.len() != 0 || connection.inbound.retainedBytes() != 0 {
			t.Fatalf("closed established connection retained %d segments and %d bytes", connection.inbound.len(), connection.inbound.retainedBytes())
		}
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
	if entry, ok := stack.outbound.tryDequeue(); ok {
		packet := consumeTestPacket(&stack.outbound, entry)
		t.Fatalf("local traffic escaped to the link: %x", packet)
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

// TestTCPTrafficClassSocketOption verifies validation, ECN masking, and the
// traffic class emitted after a live per-connection update.
func TestTCPTrafficClassSocketOption(t *testing.T) {
	link, stack := newTestStack(t, netip.MustParseAddr("192.0.2.68"), netip.MustParseAddr("198.51.100.68"))
	link.mu.Lock()
	link.echoTCP = true
	link.mu.Unlock()
	connection, err := stack.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(link.remote, 8082))
	if err != nil {
		t.Fatal(err)
	}
	tcpConnection := connection.(*TCPConn)
	if err = tcpConnection.SetTrafficClass(0xab); err != nil {
		t.Fatal(err)
	}
	if got := tcpConnection.Info().TrafficClass; got != 0xa8 {
		t.Fatalf("TCP traffic class = %#x, want %#x", got, 0xa8)
	}
	for _, invalid := range []int{-1, 256} {
		if err = tcpConnection.SetTrafficClass(invalid); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("SetTrafficClass(%d) = %v, want EINVAL", invalid, err)
		}
	}
	link.mu.Lock()
	link.echoTCP = false
	link.mu.Unlock()
	if _, err = tcpConnection.Write([]byte("traffic class")); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)

trafficClassPackets:
	for {
		select {
		case packet := <-link.outbound:
			parsed, ok := parseIPPacket(packet)
			if !ok || parsed.protocol != protocolTCP || len(parsed.payload) < tcpHeaderSize {
				continue
			}
			headerSize := int(parsed.payload[12]>>4) * 4
			if headerSize < tcpHeaderSize || headerSize >= len(parsed.payload) {
				continue
			}
			if parsed.trafficClass&0xfc != 0xa8 {
				t.Fatalf("TCP traffic-class packet = %+v", parsed)
			}
			break trafficClassPackets
		case <-deadline:
			t.Fatal("timed out waiting for TCP traffic-class data packet")
		}
	}
	if err = tcpConnection.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tcpConnection.SetTrafficClass(0); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetTrafficClass after Close = %v, want net.ErrClosed", err)
	}
}

// TestTCPPassiveHandshakeInfoAndFailure verifies diagnostic snapshots during
// SYN-RECEIVED and listener accounting when that handshake is aborted.
func TestTCPPassiveHandshakeInfoAndFailure(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.69")
	remote := netip.MustParseAddr("198.51.100.69")
	link, stack := newTestStack(t, local, remote)
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 8083))
	if err != nil {
		t.Fatal(err)
	}
	packet := buildTestTCP(remote, local, 45000, 8083, 100, 0, tcpFlagSYN, 65535, nil, nil)
	if err = writeTestPacket(stack, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-link.outbound:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for passive SYN-ACK")
	}
	listener.mu.Lock()
	var connection *TCPConn
	for candidate := range listener.handshaking {
		connection = candidate
		break
	}
	listener.mu.Unlock()
	if connection == nil {
		t.Fatal("passive handshake was not tracked")
	}
	info := connection.Info()
	if info.State != TCPStateSYNReceived || info.MaximumSegmentSize == 0 || info.PathMTU != 1400 || info.RetransmissionTimeout != tcpInitialRTO {
		t.Fatalf("passive handshake info = %+v", info)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.done:
	case <-time.After(time.Second):
		t.Fatal("passive handshake remained active after listener close")
	}
	waitFor(t, time.Second, func() bool { return listener.Info().HandshakeFailures == 1 })
	closed := listener.Info()
	if closed.HandshakeTimeouts != 0 || closed.HandshakeFailures != 1 {
		t.Fatalf("aborted passive handshake diagnostics = %+v", closed)
	}
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

func BenchmarkTCPReadFrom(b *testing.B) {
	link, stack := newTestStack(b, netip.MustParseAddr("192.0.2.244"), netip.MustParseAddr("198.51.100.244"))
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
	go io.Copy(io.Discard, connection)
	payload := bytes.Repeat([]byte{0x6c}, 4*1024*1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if n, readErr := connection.(*TCPConn).ReadFrom(bytes.NewReader(payload)); readErr != nil || n != int64(len(payload)) {
			b.Fatalf("ReadFrom = %d, %v", n, readErr)
		}
	}
}

func BenchmarkTCPSetDeadline(b *testing.B) {
	connection := newTCPConn(nil, "tcp4", tcpKey{}, 1500, tcpSocketOptionSet{})
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := connection.SetDeadline(time.Time{}); err != nil {
			b.Fatal(err)
		}
	}
}

// TestTCPImpairedNetworkConditions exercises recovery from individual and
// combined delay, jitter, loss, and bottleneck-queue conditions.
func TestTCPImpairedNetworkConditions(t *testing.T) {
	conditions := []struct {
		name      string
		direction testLinkCondition
		check     func(testLinkDirectionStats, time.Duration) bool
	}{
		{name: "latency-jitter", direction: testLinkCondition{Latency: 50 * time.Millisecond, Jitter: 15 * time.Millisecond}, check: func(_ testLinkDirectionStats, elapsed time.Duration) bool { return elapsed >= 50*time.Millisecond }},
		{name: "random-loss", direction: testLinkCondition{Latency: 2 * time.Millisecond, LossRate: 0.08}, check: func(stats testLinkDirectionStats, _ time.Duration) bool { return stats.RandomDrops != 0 }},
		{name: "burst-loss", direction: testLinkCondition{Latency: 2 * time.Millisecond, BurstEnterRate: 0.04, BurstExitRate: 0.35}, check: func(stats testLinkDirectionStats, _ time.Duration) bool { return stats.MaximumDropBurst >= 2 }},
		{name: "high-delay-loss", direction: testLinkCondition{Latency: 50 * time.Millisecond, Jitter: 15 * time.Millisecond, LossRate: 0.08, BurstEnterRate: 0.02, BurstExitRate: 0.4}, check: func(stats testLinkDirectionStats, elapsed time.Duration) bool {
			return stats.RandomDrops >= 2 && elapsed >= 100*time.Millisecond
		}},
		{name: "bandwidth-queue", direction: testLinkCondition{Latency: 3 * time.Millisecond, Bandwidth: 256 * 1024, QueueBytes: 16 * 1024}, check: func(stats testLinkDirectionStats, elapsed time.Duration) bool {
			return stats.QueueDrops != 0 && stats.MaximumQueued > 0 && elapsed >= 300*time.Millisecond
		}},
	}
	for _, test := range conditions {
		t.Run(test.name, func(t *testing.T) {
			client, server, link := newTestTCPConnectionPair(t, CongestionControlCUBIC, testLinkConditions{
				Seed: 9917, ClientToPeer: test.direction, PeerToClient: test.direction,
			})
			started := time.Now()
			transferTestTCPPayload(t, client, server, 96*1024, 15*time.Second)
			if test.check != nil && !test.check(link.Stats(0), time.Since(started)) {
				t.Fatalf("client link condition was not exercised: %+v", link.Stats(0))
			}
		})
	}
}

// TestTCPIPv6FullDuplexUnderAsymmetricImpairment verifies that both stream
// directions make progress when their IPv6 paths have different conditions.
func TestTCPIPv6FullDuplexUnderAsymmetricImpairment(t *testing.T) {
	clientAddress := netip.MustParseAddr("2001:db8::201")
	serverAddress := netip.MustParseAddr("2001:db8::202")
	client, server, link := newTestTCPConnectionPairForAddresses(t, CongestionControlCUBIC, testLinkConditions{
		Seed: 4811,
		ClientToPeer: testLinkCondition{
			Latency: 30 * time.Millisecond, Jitter: 8 * time.Millisecond, LossRate: 0.06,
			BurstEnterRate: 0.01, BurstExitRate: 0.5, Bandwidth: 1024 * 1024, QueueBytes: 48 * 1024,
		},
		PeerToClient: testLinkCondition{
			Latency: 5 * time.Millisecond, Jitter: 2 * time.Millisecond, LossRate: 0.04,
			DuplicateRate: 0.03, Bandwidth: 2 * 1024 * 1024, QueueBytes: 64 * 1024,
		},
	}, clientAddress, serverAddress)
	results := make(chan error, 2)
	go func() { results <- exchangeTestTCPPayload(client, server, 128*1024, 20*time.Second, 0x11111111) }()
	go func() { results <- exchangeTestTCPPayload(server, client, 128*1024, 20*time.Second, 0x22222222) }()
	for direction := 0; direction < 2; direction++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	clientStats, serverStats := link.Stats(0), link.Stats(1)
	if clientStats.RandomDrops == 0 || serverStats.RandomDrops == 0 || clientStats.Delivered == 0 || serverStats.Delivered == 0 {
		t.Fatalf("asymmetric IPv6 link was not exercised: client=%+v server=%+v", clientStats, serverStats)
	}
}

// TestTCPConnectionChurnUnderImpairment repeatedly establishes, transfers,
// and closes concurrent flows while loss and reordering remain active.
func TestTCPConnectionChurnUnderImpairment(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.221")
	serverAddress := netip.MustParseAddr("192.0.2.222")
	condition := testLinkCondition{
		Latency: 4 * time.Millisecond, Jitter: 2 * time.Millisecond,
		LossRate:      0.01,
		DuplicateRate: 0.01, Bandwidth: 4 * 1024 * 1024, QueueBytes: 128 * 1024,
	}
	clientStack, serverStack, link := newTestImpairedStackPair(t, CongestionControlCUBIC, testLinkConditions{
		Seed: 8179, ClientToPeer: condition, PeerToClient: condition,
	}, clientAddress, serverAddress)
	listener, err := serverStack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	const waves, flows = 3, 8
	for wave := 0; wave < waves; wave++ {
		accepted := make(chan *TCPConn, flows)
		acceptError := make(chan error, 1)
		go func() {
			for flow := 0; flow < flows; flow++ {
				connection, acceptErr := listener.AcceptTCP()
				if acceptErr != nil {
					acceptError <- acceptErr
					return
				}
				accepted <- connection
			}
		}()
		type dialResult struct {
			connection *TCPConn
			err        error
		}
		dialed := make(chan dialResult, flows)
		for flow := 0; flow < flows; flow++ {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				connection, dialErr := clientStack.DialTCP(ctx, "tcp4", netip.AddrPort{}, endpoint)
				if dialErr != nil {
					dialed <- dialResult{err: dialErr}
					return
				}
				dialed <- dialResult{connection: connection.(*TCPConn)}
			}()
		}
		clients := make([]*TCPConn, 0, flows)
		for flow := 0; flow < flows; flow++ {
			result := <-dialed
			if result.err != nil {
				t.Fatal(result.err)
			}
			clients = append(clients, result.connection)
		}
		servers := make(map[uint16]*TCPConn, flows)
		acceptDeadline := time.After(15 * time.Second)
		for len(servers) < flows {
			select {
			case connection := <-accepted:
				port := connection.RemoteAddr().(*net.TCPAddr).AddrPort().Port()
				servers[port] = connection
			case err = <-acceptError:
				t.Fatal(err)
			case <-acceptDeadline:
				t.Fatal("timed out accepting impaired TCP churn wave")
			}
		}
		transfers := make(chan error, flows)
		for flow, client := range clients {
			server := servers[client.LocalAddr().(*net.TCPAddr).AddrPort().Port()]
			if server == nil {
				t.Fatalf("missing accepted connection for %v", client.LocalAddr())
			}
			go func(flow int, client, server *TCPConn) {
				transfers <- exchangeTestTCPPayload(client, server, 16*1024, 10*time.Second, uint32(wave<<16|flow))
			}(flow, client, server)
		}
		for flow := 0; flow < flows; flow++ {
			if transferErr := <-transfers; transferErr != nil {
				t.Fatal(transferErr)
			}
		}
		for _, client := range clients {
			_ = client.Close()
		}
		for _, server := range servers {
			_ = server.Close()
		}
	}
	info := listener.Info()
	if info.AcceptedConnections != waves*flows || info.HandshakeCompletions != waves*flows {
		t.Fatalf("listener churn diagnostics = %+v", info)
	}
	if clientStats, serverStats := link.Stats(0), link.Stats(1); clientStats.RandomDrops == 0 || serverStats.RandomDrops == 0 {
		t.Fatalf("churn link loss was not exercised: client=%+v server=%+v", clientStats, serverStats)
	}
}
