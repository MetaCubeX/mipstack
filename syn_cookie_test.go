package mipstack

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSYNCookieBacklogHandshake(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.51")
	remote := netip.MustParseAddr("198.51.100.51")
	stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
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
	listener.mu.Lock()
	for index := 0; index < tcpSYNBacklog; index++ {
		listener.pending[&TCPConn{}] = struct{}{}
	}
	listener.mu.Unlock()
	defer func() {
		listener.mu.Lock()
		listener.pending = make(map[*TCPConn]struct{})
		listener.mu.Unlock()
	}()

	clientSequence := uint32(0x12345678)
	clientTimestamp := uint32(1000)
	options := []byte{2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 5}
	options = append(options, tcpTimestampOptions(clientTimestamp, 0)...)
	syn := buildTestTCP(remote, local, 43001, 47002, clientSequence, 0, tcpFlagSYN|tcpFlagECE|tcpFlagCWR, 4096, options, nil)
	if err = writeTestPacket(stack, syn); err != nil {
		t.Fatal(err)
	}
	response := readOutboundPacket(t, stack)
	parsed, ok := parseIPPacket(response)
	if !ok || parsed.protocol != protocolTCP || len(parsed.payload) < tcpHeaderSize {
		t.Fatalf("invalid SYN-cookie response: %x", response)
	}
	tcp := parsed.payload
	headerSize := int(tcp[12]>>4) * 4
	if tcp[13] != tcpFlagSYN|tcpFlagACK|tcpFlagECE || binary.BigEndian.Uint32(tcp[8:12]) != clientSequence+1 {
		t.Fatalf("SYN-cookie flags/ack = %#x/%#x", tcp[13], binary.BigEndian.Uint32(tcp[8:12]))
	}
	serverSequence := binary.BigEndian.Uint32(tcp[4:8])
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

	listener.mu.Lock()
	listener.pending = make(map[*TCPConn]struct{})
	listener.mu.Unlock()
	ackOptions := tcpTimestampOptions(clientTimestamp+1, serverTimestamp)
	ack := buildTestTCP(remote, local, 43001, 47002, clientSequence+1, serverSequence+1, tcpFlagACK, 1234, ackOptions, nil)
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
	if connection.RemoteAddr().(*net.TCPAddr).AddrPort() != netip.AddrPortFrom(remote, 43001) {
		t.Fatalf("cookie connection remote = %v", connection.RemoteAddr())
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
			state := &tcpPassiveState{cookieSet: true, cookieActive: true, cookieEpoch: now, cookiePeriod: 0}
			for index := range state.cookieKey {
				state.cookieKey[index] = byte(index + 1)
			}
			key := tcpKey{local: netip.AddrPortFrom(test.local, 443), remote: netip.AddrPortFrom(test.remote, 50000)}
			syn := tcpSegment{sequence: 100, flags: tcpFlagSYN, window: 65535, options: []byte{2, 4, 0x05, 0xb4, 4, 2}}
			_, data := encodeSYNCookieOptions(syn, test.remote)
			cookie := synCookieSequence(state.cookieKey, key, syn.sequence, synCookiePeriodNumber(now, state.cookieEpoch), data, data)
			ack := tcpSegment{sequence: syn.sequence + 1, acknowledgement: cookie + 1, flags: tcpFlagACK, window: 4096}
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
