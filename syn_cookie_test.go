package mipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSYNCookieBacklogHandshake(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.51")
	remote := netip.MustParseAddr("198.51.100.51")
	initialTCP := TCPSocketDefaults{ReceiveBuffer: 128 * 1024, MaximumReceiveBuffer: 2 * 1024 * 1024}
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, TCP: initialTCP})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 47002))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for index := 0; index < tcpSYNBacklog; index++ {
		connection := &TCPConn{}
		if !listener.trackHandshake(connection) {
			t.Fatalf("failed to fill SYN backlog at %d", index)
		}
	}
	defer func() {
		listener.mu.Lock()
		listener.pending = make(map[*TCPConn]struct{})
		listener.handshaking = make(map[*TCPConn]struct{})
		listener.mu.Unlock()
	}()

	clientSequence := uint32(0x12345678)
	clientTimestamp := uint32(1000)
	options := []byte{2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 5}
	options = append(options, tcpTimestampOptions(clientTimestamp, 0)...)
	syn := buildTestTCP(remote, local, 43001, 47002, clientSequence, 0, TCPFlagSYN|TCPFlagECE|TCPFlagCWR, 4096, options, nil)
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	response := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid SYN-cookie response: %x", response)
	}
	tcp := parsed.payload
	headerSize := int(tcp[12]>>4) * 4
	if tcp[13] != TCPFlagSYN|TCPFlagACK|TCPFlagECE || binary.BigEndian.Uint32(tcp[8:12]) != clientSequence+1 {
		t.Fatalf("SYN-cookie flags/ack = %#x/%#x", tcp[13], binary.BigEndian.Uint32(tcp[8:12]))
	}
	serverSequence := binary.BigEndian.Uint32(tcp[4:8])
	_, serverWindowScale, serverWindowScaling, _, _, _ := parseTCPOptions(tcp[tcpHeaderSize:headerSize], 536, 65535)
	if !serverWindowScaling {
		t.Fatal("SYN cookie did not advertise window scaling")
	}
	serverTimestamp, _, timestampPresent := parseTCPTimestamp(tcp[tcpHeaderSize:headerSize])
	if !timestampPresent {
		t.Fatal("SYN cookie did not preserve timestamp negotiation")
	}
	stack.mu.RLock()
	connectionsBeforeACK := len(stack.tcp)
	stack.mu.RUnlock()
	if connectionsBeforeACK != 0 {
		t.Fatalf("SYN cookie retained %d connections before final ACK", connectionsBeforeACK)
	}

	if err = stack.UpdateConfig(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{ReceiveBuffer: 64 * 1024, MaximumReceiveBuffer: 128 * 1024},
	}); err != nil {
		t.Fatal(err)
	}
	ackOptions := tcpTimestampOptions(clientTimestamp+1, serverTimestamp)
	forgedACK := buildTestTCP(remote, local, 43001, 47002, clientSequence+1, serverSequence+2, TCPFlagACK, 1234, ackOptions, nil)
	if err = writeTestPacket(stack, forgedACK); err != nil {
		t.Fatal(err)
	}
	reset := readOutboundPacket(t, stack)
	if parsedReset, parsedResetOK := parseIPPacket(reset); !parsedResetOK || len(parsedReset.payload) < tcpHeaderSize || parsedReset.payload[13]&TCPFlagRST == 0 {
		t.Fatalf("forged cookie ACK response = %x", reset)
	}
	ack := buildTestTCP(remote, local, 43001, 47002, clientSequence+1, serverSequence+1, TCPFlagACK, 1234, ackOptions, nil)
	if err = writeTestPacket(stack, ack); err != nil {
		t.Fatal(err)
	}
	if err = listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if connection.peerMSS != 1440 || !connection.peerWindowScaling || connection.peerWindowScale != 5 ||
		!connection.peerSACK || !connection.peerTimestamp || !connection.peerECN || connection.recentTimestamp != clientTimestamp+1 {
		t.Fatalf("restored SYN-cookie options = MSS %d scale %d/%v SACK %v TS %v/%d ECN %v",
			connection.peerMSS, connection.peerWindowScale, connection.peerWindowScaling, connection.peerSACK,
			connection.peerTimestamp, connection.recentTimestamp, connection.peerECN)
	}
	if connection.peerWindow != uint32(1234)<<5 {
		t.Fatalf("restored peer window = %d, want %d", connection.peerWindow, uint32(1234)<<5)
	}
	if connection.receiveWindowScale != serverWindowScale {
		t.Fatalf("restored local window scale = %d, want advertised %d", connection.receiveWindowScale, serverWindowScale)
	}
	if connection.RemoteAddr().(*net.TCPAddr).AddrPort() != netip.AddrPortFrom(remote, 43001) {
		t.Fatalf("cookie connection remote = %v", connection.RemoteAddr())
	}
	info := listener.Info()
	if info.SYNsReceived != 1 || info.SYNCookiesSent != 1 || info.SYNCookiesRejected != 1 || info.SYNCookiesAccepted != 1 ||
		info.HandshakeCompletions != 1 || info.AcceptedConnections != 1 || info.AcceptQueuePeak > 1 ||
		info.SYNBacklogConnections != tcpSYNBacklog || info.SYNBacklogPeak != tcpSYNBacklog {
		t.Fatalf("SYN cookie listener diagnostics = %+v", info)
	}
	stats := stack.Stats()
	if stats.TCPSYNCookiesSent != 1 || stats.TCPSYNCookiesRejected != 1 || stats.TCPSYNCookiesAccepted != 1 {
		t.Fatalf("SYN cookie stack diagnostics = %+v", stats)
	}
}

func TestSYNCookieFastOpenFallsBackToFinalACK(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.53")
	remote := netip.MustParseAddr("198.51.100.53")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 47003))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	for index := 0; index < tcpSYNBacklog; index++ {
		if !listener.trackHandshake(&TCPConn{}) {
			t.Fatalf("failed to fill SYN backlog at %d", index)
		}
	}
	t.Cleanup(func() {
		listener.mu.Lock()
		listener.pending = make(map[*TCPConn]struct{})
		listener.handshaking = make(map[*TCPConn]struct{})
		listener.mu.Unlock()
	})

	const clientSequence = uint32(0x23456789)
	payload := []byte("fast-open request")
	syn := buildTestTCP(remote, local, 43003, 47003, clientSequence, 0, TCPFlagSYN, 65535, nil, payload)
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	response := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid SYN-cookie response: %x", response)
	}
	tcp := parsed.payload
	if tcp[13]&byte(TCPFlagSYN|TCPFlagACK) != byte(TCPFlagSYN|TCPFlagACK) || binary.BigEndian.Uint32(tcp[8:12]) != clientSequence+1 {
		t.Fatalf("SYN-cookie flags/ack = %#x/%#x", tcp[13], binary.BigEndian.Uint32(tcp[8:12]))
	}
	serverSequence := binary.BigEndian.Uint32(tcp[4:8])
	finalACK := buildTestTCP(remote, local, 43003, 47003, clientSequence+1, serverSequence+1, TCPFlagACK|TCPFlagFIN, 65535, nil, payload)
	if err = writeTestPacket(stack, finalACK); err != nil {
		t.Fatal(err)
	}
	if err = listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err = connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if _, err = io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, payload) {
		t.Fatalf("retransmitted SYN data = %q, want %q", buffer, payload)
	}
	if n, readErr := connection.Read(make([]byte, 1)); n != 0 || readErr != io.EOF {
		t.Fatalf("read after retransmitted FIN = %d, %v, want 0, EOF", n, readErr)
	}
}

// TestSYNCookieListenerCloseResetsPendingConnection covers the race where a
// validated cookie ACK creates state immediately before the listener closes.
func TestSYNCookieListenerCloseResetsPendingConnection(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.52")
	remote := netip.MustParseAddr("198.51.100.52")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).AddrPort().Port()
	key := tcpKey{
		local:  netip.AddrPortFrom(local, port),
		remote: netip.AddrPortFrom(remote, 43002),
	}
	connection := newTCPConn(stack, "tcp4", key, 1500, tcpSocketOptionSet{})
	connection.passive = true
	connection.receiveNext = 0x12345679
	if !listener.trackCompleted(connection) {
		t.Fatal("failed to track pending cookie connection")
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	const initialSequence = uint32(0x87654321)
	connection.runPassiveCookie(listener, tcpSegment{}, initialSequence)
	packet := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(packet)
	if !ok || parsed.protocol != ProtocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid abort reset: %x", packet)
	}
	tcp := parsed.payload
	if tcp[13] != TCPFlagRST|TCPFlagACK || binary.BigEndian.Uint32(tcp[4:8]) != initialSequence+1 ||
		binary.BigEndian.Uint32(tcp[8:12]) != connection.receiveNext {
		t.Fatalf("abort reset flags/sequence/ack = %#x/%#x/%#x", tcp[13], binary.BigEndian.Uint32(tcp[4:8]), binary.BigEndian.Uint32(tcp[8:12]))
	}
}

func TestSYNCookieHonorsConfiguredReceiveWindow(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.61")
	stack, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)},
		TCP:            TCPSocketDefaults{ReceiveBuffer: 4096, MaximumReceiveBuffer: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	key := tcpKey{local: netip.MustParseAddrPort("192.0.2.61:8080"), remote: netip.MustParseAddrPort("198.51.100.61:40000")}
	syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
	if err = (&tcpPassiveState{}).sendSYNCookie(stack, nil, key, syn, time.Now()); err != nil {
		t.Fatal(err)
	}
	packet := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(packet)
	if !ok || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid SYN-cookie packet: %x", packet)
	}
	if window := binary.BigEndian.Uint16(parsed.payload[14:16]); window != 4096 {
		t.Fatalf("SYN-cookie receive window = %d, want 4096", window)
	}
}

func TestSYNCookieHonorsListenerCreationOptions(t *testing.T) {
	local := netip.MustParseAddr("2001:db8::62")
	remote := netip.MustParseAddr("2001:db8:1::62")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 128)}, MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	parsed, err := parseSocketOptions([]SocketOption{
		SocketOptions.ReadBuffer(4321), SocketOptions.TrafficClass(0xaf), SocketOptions.FlowLabel(0x45678),
	}, socketOptionTCPListen)
	if err != nil {
		t.Fatal(err)
	}
	listener := &TCPListener{options: parsed.tcp}
	key := tcpKey{local: netip.AddrPortFrom(local, 8080), remote: netip.AddrPortFrom(remote, 40000)}
	syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
	if err = (&tcpPassiveState{}).sendSYNCookie(stack, listener, key, syn, time.Now()); err != nil {
		t.Fatal(err)
	}
	packet := readOutboundPacket(t, stack)
	parsedPacket, ok := parseIPPacket(packet)
	if !ok || len(parsedPacket.payload) < tcpHeaderSize {
		t.Fatalf("invalid listener-option SYN-cookie packet: %x", packet)
	}
	if window := binary.BigEndian.Uint16(parsedPacket.payload[14:16]); window != 4321 {
		t.Fatalf("listener-option SYN-cookie receive window = %d, want 4321", window)
	}
	if parsedPacket.trafficClass != 0xac || parsedPacket.flowLabel != 0x45678 {
		t.Fatalf("listener-option SYN-cookie IP policy = class %#x label %#x", parsedPacket.trafficClass, parsedPacket.flowLabel)
	}

	parsed, err = parseSocketOptions([]SocketOption{SocketOptions.FlowLabel(0)}, socketOptionTCPListen)
	if err != nil {
		t.Fatal(err)
	}
	listener.options = parsed.tcp
	if err = (&tcpPassiveState{}).sendSYNCookie(stack, listener, key, syn, time.Now()); err != nil {
		t.Fatal(err)
	}
	packet = readOutboundPacket(t, stack)
	parsedPacket, ok = parseIPPacket(packet)
	if !ok || parsedPacket.flowLabel != 0 {
		t.Fatalf("explicit zero SYN-cookie flow label = %#x, parsed=%v", parsedPacket.flowLabel, ok)
	}
}

func TestSYNCookieValidationIPv4AndIPv6(t *testing.T) {
	now := time.Unix(2000000000, 0)
	for _, test := range []struct {
		name   string
		local  netip.Addr
		remote netip.Addr
	}{
		{name: "IPv4", local: netip.MustParseAddr("192.0.2.61"), remote: netip.MustParseAddr("198.51.100.61")},
		{name: "IPv6", local: netip.MustParseAddr("2001:db8::61"), remote: netip.MustParseAddr("2001:db8:1::61")},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &tcpPassiveState{
				cookieSet: true, cookieActive: true, cookieEpoch: now, cookiePeriod: 0,
				cookieScaleSet: true, cookieScalePeriod: 0, cookieWindowScale: 4,
			}
			for index := range state.cookieKey {
				state.cookieKey[index] = byte(index + 1)
			}
			key := tcpKey{local: netip.AddrPortFrom(test.local, 443), remote: netip.AddrPortFrom(test.remote, 50000)}
			syn := tcpSegment{sequence: 100, flags: TCPFlagSYN, window: 65535}
			syn.setOptions([]byte{2, 4, 0x05, 0xb4, 4, 2})
			_, data := encodeSYNCookieOptions(syn, test.remote)
			cookie := synCookieSequence(state.cookieKey, key, syn.sequence, synCookiePeriodNumber(now, state.cookieEpoch), data, data)
			ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK, window: 4096}
			if _, _, valid := state.validateSYNCookie(key, ack, now); !valid {
				t.Fatal("valid SYN cookie was rejected")
			}
			forged := ack
			forged.acknowledgement ^= 1 << synCookieDataBits
			if _, _, valid := state.validateSYNCookie(key, forged, now); valid {
				t.Fatal("forged SYN cookie was accepted")
			}
			if _, _, valid := state.validateSYNCookie(key, ack, now.Add(2*synCookiePeriod)); valid {
				t.Fatal("expired SYN cookie was accepted")
			}
			state.cookieActive = false
			if _, _, valid := state.validateSYNCookie(key, ack, now); valid {
				t.Fatal("cookie ACK was accepted without recent cookie issuance")
			}
		})
	}
}

func TestSYNCookieWindowScaleRotatesByPeriod(t *testing.T) {
	now := time.Unix(2000001000, 0)
	state := &tcpPassiveState{}
	secret, period, firstScale, err := state.synCookieKey(now, 2)
	if err != nil {
		t.Fatal(err)
	}
	state.noteSYNCookie(period)
	if firstScale != 2 {
		t.Fatalf("first SYN-cookie scale = %d, want 2", firstScale)
	}
	_, samePeriod, stableScale, err := state.synCookieKey(now.Add(time.Second), 7)
	if err != nil {
		t.Fatal(err)
	}
	if samePeriod != period || stableScale != 2 {
		t.Fatalf("same-period SYN-cookie scale = period %d scale %d, want %d/2", samePeriod, stableScale, period)
	}

	key := tcpKey{
		local:  netip.MustParseAddrPort("192.0.2.70:443"),
		remote: netip.MustParseAddrPort("198.51.100.70:50000"),
	}
	clientSequence := uint32(100)
	data := uint32(0)
	cookie := synCookieSequence(secret, key, clientSequence, period, data, data)
	ack := tcpSegment{sequence: clientSequence + 1, acknowledgement: cookie + 1, flags: TCPFlagACK}

	next := now.Add(synCookiePeriod)
	_, nextPeriod, nextScale, err := state.synCookieKey(next, 7)
	if err != nil {
		t.Fatal(err)
	}
	state.noteSYNCookie(nextPeriod)
	if nextPeriod != period+1 || nextScale != 7 {
		t.Fatalf("next-period SYN-cookie scale = period %d scale %d, want %d/7", nextPeriod, nextScale, period+1)
	}
	_, options, valid := state.validateSYNCookie(key, ack, next)
	if !valid || options.localWindowScale != 2 {
		t.Fatalf("previous-period cookie = valid %t scale %d, want true/2", valid, options.localWindowScale)
	}
}
