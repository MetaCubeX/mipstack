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
var synCookieMSSValues = [...]uint16{tcpMinimumPeerMSS, 256, 536, 1200, 1220, 1360, 1440, 8960}

// synCookieOptions is the handshake state that can be reconstructed from a
// final ACK without retaining the original SYN.
type synCookieOptions struct {
	mss              int
	windowScale      uint8
	localWindowScale uint8
	windowScaling    bool
	sack             bool
	timestamp        bool
	ecn              bool
	timestampNow     uint32
}

// synCookieKey returns the lazily initialized per-stack-listener secret and
// fixes the advertised receive scale for one cookie period. A random source
// failure is retried on a later SYN instead of permanently disabling cookies.
func (state *tcpPassiveState) synCookieKey(now time.Time, windowScale uint8) ([16]byte, uint64, uint8, error) {
	state.cookieMu.Lock()
	defer state.cookieMu.Unlock()
	if !state.cookieSet {
		if _, err := rand.Read(state.cookieKey[:]); err != nil {
			return [16]byte{}, 0, 0, err
		}
		state.cookieEpoch = now
		state.cookieSet = true
	}
	period := synCookiePeriodNumber(now, state.cookieEpoch)
	if !state.cookieScaleSet || period > state.cookieScalePeriod {
		if state.cookieScaleSet {
			state.previousScaleSet = true
			state.previousScalePeriod = state.cookieScalePeriod
			state.previousWindowScale = state.cookieWindowScale
		}
		state.cookieScaleSet = true
		state.cookieScalePeriod = period
		state.cookieWindowScale = windowScale
	}
	return state.cookieKey, period, state.cookieWindowScale, nil
}

// noteSYNCookie records the Linux-style recent-overflow window in which a
// stateless final ACK is eligible for cookie validation.
func (state *tcpPassiveState) noteSYNCookie(period uint64) {
	state.cookieMu.Lock()
	if !state.cookieActive || period > state.cookiePeriod {
		state.cookiePeriod = period
	}
	state.cookieActive = true
	state.cookieMu.Unlock()
}

// recentSYNCookieState returns the secret and per-period receive scales only
// after this passive state issued a recent cookie.
func (state *tcpPassiveState) recentSYNCookieState(now time.Time) ([16]byte, uint64, [2]uint64, [2]uint8, [2]bool, bool) {
	state.cookieMu.Lock()
	defer state.cookieMu.Unlock()
	period := synCookiePeriodNumber(now, state.cookieEpoch)
	if !state.cookieSet || !state.cookieActive || period < state.cookiePeriod || period-state.cookiePeriod > 1 {
		return [16]byte{}, 0, [2]uint64{}, [2]uint8{}, [2]bool{}, false
	}
	periods := [2]uint64{state.cookieScalePeriod, state.previousScalePeriod}
	scales := [2]uint8{state.cookieWindowScale, state.previousWindowScale}
	set := [2]bool{state.cookieScaleSet, state.previousScaleSet}
	return state.cookieKey, period, periods, scales, set, true
}

// sendSYNCookie replies to a SYN without allocating a TCPConn.
func (state *tcpPassiveState) sendSYNCookie(stack *Stack, key tcpKey, syn tcpSegment, now time.Time) error {
	defaults := stack.network.Load().tcpDefaults
	configuredScale := tcpReceiveWindowScaleFor(defaults.MaximumReceiveBuffer)
	secret, period, windowScale, err := state.synCookieKey(now, configuredScale)
	if err != nil {
		return err
	}
	options, data := encodeSYNCookieOptions(syn, key.remote.Addr())
	authenticatedData := synCookieAuthenticatedData(data, options.timestamp, options.ecn)
	sequence := synCookieSequence(secret, key, syn.sequence, period, data, authenticatedData)
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
	var optionStorage [40]byte
	tcpOptions := tcpPassiveSYNOptions(optionStorage[:0], localMSS, options.sack, options.windowScaling, options.timestamp, windowScale, timestamp, options.timestampNow)
	flags := byte(tcpFlagSYN | tcpFlagACK)
	if options.ecn {
		flags |= tcpFlagECE
	}
	receiveWindow := defaults.ReceiveBuffer
	if receiveWindow > 65535 {
		receiveWindow = 65535
	}
	state.noteSYNCookie(period)
	return stack.tryWriteTCP(key.local.Addr(), key.remote.Addr(), key.local.Port(), key.remote.Port(), sequence, syn.sequence+1, flags, uint16(receiveWindow), tcpOptions, nil, stack.mtuFor(key.remote.Addr()), defaults.TrafficClass, 0)
}

// validateSYNCookie authenticates a final ACK against the current or previous
// time period and reconstructs its negotiated options.
func (state *tcpPassiveState) validateSYNCookie(key tcpKey, ack tcpSegment, now time.Time) (uint32, synCookieOptions, bool) {
	sequence, options, valid, _ := state.validateSYNCookieCandidate(key, ack, now)
	return sequence, options, valid
}

// validateSYNCookieCandidate additionally reports whether a recent cookie
// made this ACK eligible for authentication diagnostics.
func (state *tcpPassiveState) validateSYNCookieCandidate(key tcpKey, ack tcpSegment, now time.Time) (uint32, synCookieOptions, bool, bool) {
	if ack.flags&tcpFlagACK == 0 || ack.flags&(tcpFlagSYN|tcpFlagRST) != 0 {
		return 0, synCookieOptions{}, false, false
	}
	secret, period, scalePeriods, windowScales, scalesSet, active := state.recentSYNCookieState(now)
	if !active {
		return 0, synCookieOptions{}, false, false
	}
	serverSequence := ack.acknowledgement - 1
	clientSequence := ack.sequence - 1
	data := serverSequence & synCookieDataMask
	timestampValue, timestampEcho, timestamp := parseTCPTimestamp(ack.optionBytes())
	ecn := timestamp && timestampEcho&1 != 0
	authenticatedData := synCookieAuthenticatedData(data, timestamp, ecn)
	valid := false
	localWindowScale := uint8(0)
	for attempt := uint64(0); attempt < 2; attempt++ {
		if attempt > period {
			break
		}
		candidatePeriod := period - attempt
		candidateScale, scaleFound := uint8(0), false
		for index := range scalePeriods {
			if scalesSet[index] && scalePeriods[index] == candidatePeriod {
				candidateScale, scaleFound = windowScales[index], true
				break
			}
		}
		if !scaleFound {
			continue
		}
		expected := synCookieSequence(secret, key, clientSequence, candidatePeriod, data, authenticatedData)
		if subtle.ConstantTimeEq(int32(expected), int32(serverSequence)) == 1 {
			valid = true
			localWindowScale = candidateScale
		}
	}
	if !valid {
		return 0, synCookieOptions{}, false, true
	}
	options, ok := decodeSYNCookieOptions(data)
	if !ok {
		return 0, synCookieOptions{}, false, true
	}
	options.timestamp = timestamp
	options.timestampNow = timestampValue
	options.ecn = ecn
	options.localWindowScale = localWindowScale
	return serverSequence, options, true, true
}

// encodeSYNCookieOptions converts a SYN's offered options into eight sequence
// bits. Timestamp and ECN flags are authenticated separately.
func encodeSYNCookieOptions(syn tcpSegment, remoteAddress netip.Addr) (synCookieOptions, uint32) {
	mss, scale, scaling, sack, timestamp, timestampValue := parseTCPOptions(syn.optionBytes(), defaultTCPPeerMSS(remoteAddress), 65535)
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
func synCookiePeriodNumber(now, epoch time.Time) uint64 {
	elapsed := now.Sub(epoch)
	if elapsed <= 0 {
		return 0
	}
	return uint64(elapsed / synCookiePeriod)
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
	protocolTimer := newOwnedTimer()
	defer protocolTimer.close()
	if len(finalACK.payload) != 0 || finalACK.flags&tcpFlagFIN != 0 {
		c.inbound.prepend(finalACK)
	}
	if !listener.enqueue(c) {
		_ = c.sendAbortReset(initialSequence+1, c.receiveNext, 0)
		c.finish(net.ErrClosed)
		return
	}
	queued = true
	c.finish(c.established(initialSequence+1, protocolTimer))
}
