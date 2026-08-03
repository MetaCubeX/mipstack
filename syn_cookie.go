package mipstack

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

const (
	// synCookiePeriod is short enough to limit replay while allowing normal
	// retransmission delays. The current and immediately previous period are
	// accepted.
	synCookiePeriod = 64 * time.Second
	// Eight low sequence-number bits carry conservative, reconstructible peer
	// options. The remaining 24 bits authenticate the tuple, client ISN, time
	// period, and all negotiated option flags.
	synCookieDataBits = 8
	synCookieDataMask = uint32(1<<synCookieDataBits - 1)
)

// synCookieMSSValues are safe lower bounds for common advertised MSS values.
// Selecting the greatest entry no larger than the peer's offer never causes a
// reconstructed connection to transmit oversized segments.
var synCookieMSSValues = [...]uint16{1, 256, 536, 1200, 1220, 1360, 1440, 8960}

// synCookieOptions is the handshake state that can be reconstructed from a
// final ACK without retaining the original SYN.
type synCookieOptions struct {
	mss           int
	windowScale   uint8
	windowScaling bool
	sack          bool
	timestamp     bool
	ecn           bool
	timestampNow  uint32
}

// key returns the lazily initialized per-stack-listener secret. A random
// source failure is retried on a later SYN instead of permanently disabling
// cookies.
func (state *tcpPassiveState) synCookieKey() ([16]byte, error) {
	state.cookieMu.Lock()
	defer state.cookieMu.Unlock()
	if !state.cookieSet {
		if _, err := rand.Read(state.cookieKey[:]); err != nil {
			return [16]byte{}, err
		}
		state.cookieSet = true
	}
	return state.cookieKey, nil
}

// sendSYNCookie replies to a SYN without allocating a TCPConn.
func (state *tcpPassiveState) sendSYNCookie(stack *Stack, key tcpKey, syn tcpSegment, now time.Time) error {
	secret, err := state.synCookieKey()
	if err != nil {
		return err
	}
	options, data := encodeSYNCookieOptions(syn, key.remote.Addr())
	authenticatedData := synCookieAuthenticatedData(data, options.timestamp, options.ecn)
	sequence := synCookieSequence(secret, key, syn.sequence, synCookiePeriodNumber(now), data, authenticatedData)
	localMSS := tcpMSSForMTU(stack.mtuFor(key.remote.Addr()), key.local.Addr())
	if localMSS < 1 {
		return errors.New("mipstack: MTU is too small for TCP")
	}
	timestamp := stack.tcpTimestamp()
	if options.timestamp {
		timestamp &^= 1
		if options.ecn {
			timestamp |= 1
		}
	}
	tcpOptions := tcpPassiveSYNOptions(localMSS, options.sack, options.windowScaling, options.timestamp, timestamp, options.timestampNow)
	flags := byte(tcpFlagSYN | tcpFlagACK)
	if options.ecn {
		flags |= tcpFlagECE
	}
	return stack.writeTCP(key.local.Addr(), key.remote.Addr(), key.local.Port(), key.remote.Port(), sequence, syn.sequence+1, flags, 65535, tcpOptions, nil)
}

// validateSYNCookie authenticates a final ACK against the current or previous
// time period and reconstructs its negotiated options.
func (state *tcpPassiveState) validateSYNCookie(key tcpKey, ack tcpSegment, now time.Time) (uint32, synCookieOptions, bool) {
	if ack.flags&tcpFlagACK == 0 || ack.flags&(tcpFlagSYN|tcpFlagRST) != 0 || ack.acknowledgement == 0 {
		return 0, synCookieOptions{}, false
	}
	secret, err := state.synCookieKey()
	if err != nil {
		return 0, synCookieOptions{}, false
	}
	serverSequence := ack.acknowledgement - 1
	clientSequence := ack.sequence - 1
	data := serverSequence & synCookieDataMask
	timestampValue, timestampEcho, timestamp := parseTCPTimestamp(ack.options)
	ecn := timestamp && timestampEcho&1 != 0
	authenticatedData := synCookieAuthenticatedData(data, timestamp, ecn)
	period := synCookiePeriodNumber(now)
	valid := false
	for attempt := uint64(0); attempt < 2; attempt++ {
		if attempt > period {
			break
		}
		expected := synCookieSequence(secret, key, clientSequence, period-attempt, data, authenticatedData)
		if subtle.ConstantTimeEq(int32(expected), int32(serverSequence)) == 1 {
			valid = true
		}
	}
	if !valid {
		return 0, synCookieOptions{}, false
	}
	options, ok := decodeSYNCookieOptions(data)
	if !ok {
		return 0, synCookieOptions{}, false
	}
	options.timestamp = timestamp
	options.timestampNow = timestampValue
	options.ecn = ecn
	return serverSequence, options, true
}

// encodeSYNCookieOptions converts a SYN's offered options into ten bits.
func encodeSYNCookieOptions(syn tcpSegment, remoteAddress netip.Addr) (synCookieOptions, uint32) {
	mss, scale, scaling, sack, timestamp, timestampValue := parseTCPOptions(syn.options, defaultTCPPeerMSS(remoteAddress), 65535)
	mssIndex := 0
	for index, value := range synCookieMSSValues {
		if int(value) > mss {
			break
		}
		mssIndex = index
	}
	encodedScale := uint32(15)
	if scaling {
		encodedScale = uint32(scale)
	}
	data := uint32(mssIndex) | encodedScale<<3
	if sack {
		data |= 1 << 7
	}
	// The server timestamp echo carries ECN state for the final ACK. Without
	// timestamps, cookie mode conservatively declines ECN rather than spending
	// sequence bits that would weaken the authentication tag.
	ecn := timestamp && syn.flags&(tcpFlagECE|tcpFlagCWR) == tcpFlagECE|tcpFlagCWR
	return synCookieOptions{
		mss: int(synCookieMSSValues[mssIndex]), windowScale: scale, windowScaling: scaling,
		sack: sack, timestamp: timestamp, ecn: ecn, timestampNow: timestampValue,
	}, data
}

// decodeSYNCookieOptions reconstructs peer options from authenticated data.
func decodeSYNCookieOptions(data uint32) (synCookieOptions, bool) {
	if data & ^synCookieDataMask != 0 {
		return synCookieOptions{}, false
	}
	mssIndex := int(data & 7)
	encodedScale := uint8(data >> 3 & 15)
	options := synCookieOptions{
		mss: int(synCookieMSSValues[mssIndex]), sack: data&(1<<7) != 0,
	}
	if encodedScale != 15 {
		options.windowScaling = true
		options.windowScale = encodedScale
	}
	return options, true
}

// synCookieAuthenticatedData adds option flags recovered from the ACK's
// timestamp to the compact sequence data. They consume no sequence bits but
// remain covered by the keyed tag.
func synCookieAuthenticatedData(data uint32, timestamp, ecn bool) uint32 {
	if timestamp {
		data |= 1 << 8
	}
	if ecn {
		data |= 1 << 9
	}
	return data
}

// synCookiePeriodNumber returns the monotonically advancing cookie period.
func synCookiePeriodNumber(now time.Time) uint64 {
	return uint64(now.Unix()) / uint64(synCookiePeriod/time.Second)
}

// synCookieSequence authenticates one tuple and its compact option data.
func synCookieSequence(secret [16]byte, key tcpKey, clientSequence uint32, period uint64, data, authenticatedData uint32) uint32 {
	var input [51]byte
	if key.local.Addr().Is6() {
		input[0] = 6
	} else {
		input[0] = 4
	}
	local := key.local.Addr().As16()
	remote := key.remote.Addr().As16()
	copy(input[1:17], local[:])
	copy(input[17:33], remote[:])
	binary.BigEndian.PutUint16(input[33:35], key.local.Port())
	binary.BigEndian.PutUint16(input[35:37], key.remote.Port())
	binary.BigEndian.PutUint32(input[37:41], clientSequence)
	binary.BigEndian.PutUint64(input[41:49], period)
	binary.BigEndian.PutUint16(input[49:51], uint16(authenticatedData))
	tag := uint32(sipHash24(secret, input[:])) &^ synCookieDataMask
	return tag | data
}

// runPassiveCookie owns a server-side connection reconstructed from a final
// cookie ACK.
func (c *TCPConn) runPassiveCookie(listener *TCPListener, finalACK tcpSegment, initialSequence uint32) {
	queued := false
	defer func() {
		if !queued {
			listener.removePending(c)
		}
	}()
	defer c.stack.removeTCP(c)
	defer close(c.done)
	if len(finalACK.payload) != 0 || finalACK.flags&tcpFlagFIN != 0 {
		c.inbound <- finalACK
	}
	if !listener.enqueue(c) {
		_ = c.sendSegment(initialSequence+1, c.receiveNext, tcpFlagRST|tcpFlagACK, 0, nil)
		c.finish(net.ErrClosed)
		return
	}
	queued = true
	c.finish(c.established(initialSequence + 1))
}
