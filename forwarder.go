package mipstack

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
)

// ForwarderFlow identifies one inbound TCP or UDP four-tuple. Source is the
// remote endpoint and Destination is the original packet destination.
type ForwarderFlow struct {
	// Source is the remote endpoint that sent the packet.
	Source netip.AddrPort
	// Destination is the original local endpoint from the packet.
	Destination netip.AddrPort
}

// TCPForwarderOptions configures interception of otherwise unhandled TCP
// connection attempts. Zero fields retain stack defaults.
type TCPForwarderOptions struct {
	// MaxInFlight bounds requests on which the handler has not yet selected an
	// action. Zero uses the configured TCP SYN backlog.
	MaxInFlight int
}

// UDPForwarderOptions reserves UDP interception policy for future extension.
type UDPForwarderOptions struct{}

// IPForwarderOptions reserves otherwise unhandled IP protocol interception
// policy for future extension.
type IPForwarderOptions struct{}

// ICMPForwarderOptions reserves ICMP interception policy for future extension.
type ICMPForwarderOptions struct{}

// TCPForwarderHandler decides the fate of one valid, otherwise unhandled SYN.
// MIPS starts a separate goroutine for each unique request, so handlers may run
// concurrently and must synchronize shared state. A handler may block, but an
// undecided request occupies the forwarder's MaxInFlight capacity for the
// entire block. The handler must call Accept, Drop, or Reject before returning;
// returning without an action drops the request. Accept must be called and
// allowed to return in the handler's own call; neither the request nor an
// in-progress action may be handed to another goroutine. After Accept returns,
// the resulting TCPConn is independent of the request: the handler may return
// immediately, retain the connection, or hand the connection to another
// goroutine.
type TCPForwarderHandler func(*TCPForwarderRequest)

// UDPForwarderHandler decides the fate of one valid, otherwise unhandled UDP
// datagram. MIPS calls it synchronously from Stack.Write or the loopback worker.
// It must return promptly and must not wait for traffic whose delivery depends
// on the blocked call. Concurrent Stack.Write calls may invoke the handler
// concurrently, so shared state must be synchronized. While one request is
// undecided, concurrent datagrams for the same four-tuple are dropped. The
// handler must call Accept, Listen, Detach, DetachForReplies, Drop, Reject, or
// at least one Reply before returning; returning without an action drops the
// datagram. Reply may be repeated and does not prevent a later terminal action.
// Except for Detach and DetachForReplies, every action and Reply call must
// finish before the handler returns. The request and its Payload must not be
// retained after that point, but a UDPConn returned by Accept or Listen and a
// responder returned by either detach method may outlive the callback.
// Responder output remains subject to the originating forwarder's state. The
// initial datagram remains subject to the returned UDPConn's configured receive
// capacity.
type UDPForwarderHandler func(*UDPForwarderRequest)

// IPForwarderHandler processes one valid, reassembled upper-layer IP payload
// that matched neither a raw IP socket nor a built-in protocol. MIPS
// calls it synchronously with the same concurrency, blocking, ownership, and
// action rules as ICMPForwarderHandler. The handler must call Detach,
// DetachForReplies, Drop, Reject, or at least one Reply before returning.
type IPForwarderHandler func(*IPForwarderRequest)

// ICMPForwarderHandler processes one checksum-valid ICMP message not consumed
// by the stack's built-in echo or asynchronous-error handling. Its synchronous,
// concurrent-call, and blocking rules are the same as UDPForwarderHandler.
// The handler must call Detach, DetachForReplies, Drop, Reject, or at least one
// Reply before returning; returning without an action drops the message. Reply
// may be repeated and does not prevent a later terminal action. Except for
// Detach and DetachForReplies, every action and Reply call must finish before
// the handler returns. The request and Message.Payload must not be retained
// after that point, but a responder returned by either detach method may
// outlive the callback. Responder output remains subject to the originating
// forwarder's state.
type ICMPForwarderHandler func(*ICMPForwarderRequest)

// ForwarderInfo is a diagnostic snapshot of endpoint, request, and reply
// activity for one protocol forwarder.
type ForwarderInfo struct {
	// Closed reports whether this forwarder has been unregistered and closed.
	Closed bool
	// Pending is the number of callback-scoped requests that have not completed
	// or transferred traffic ownership. It excludes detached responders and
	// handlers that continue running after selecting an action.
	Pending int
	// MaxInFlight is the TCP pending-request bound, or zero for protocols that
	// do not retain asynchronous requests.
	MaxInFlight int
	// Requests counts requests delivered to the handler.
	Requests uint64
	// Accepted counts successfully created TCP connections, connected UDP
	// flows, and unconnected UDP listeners.
	Accepted uint64
	// Replies counts successfully queued request and responder replies.
	Replies uint64
	// ReplyErrors counts argument, state, and output failures after a Reply call
	// has entered its request or responder lifetime. Calls rejected because a
	// terminal action already completed that lifetime are not output attempts.
	ReplyErrors uint64
	// Dropped counts explicit, implicit, invalidated, and capacity drops.
	Dropped uint64
	// Rejected counts explicit protocol rejection decisions.
	Rejected uint64
}

// forwarderRequestState serializes the exactly-once terminal action selected
// for a request while separately remembering whether a reply was attempted.
type forwarderRequestState uint32

const (
	// forwarderRequestPending has not yet selected an action.
	forwarderRequestPending forwarderRequestState = iota
	// forwarderRequestClaimed is performing a terminal endpoint or ownership
	// action.
	forwarderRequestClaimed
	// forwarderRequestReplyStarted records that at least one Reply call began. It
	// permits more replies and one later terminal action until the handler ends.
	forwarderRequestReplyStarted
	// forwarderRequestDetached transferred ownership to an asynchronous
	// responder and prevents further use of the callback-scoped request.
	forwarderRequestDetached
	// forwarderRequestAccepted successfully created output or an endpoint.
	forwarderRequestAccepted
	// forwarderRequestDropped consumed input without a protocol response.
	forwarderRequestDropped
	// forwarderRequestRejected selected an explicit protocol rejection.
	forwarderRequestRejected
	// forwarderRequestCompleted ended a callback that replied without selecting
	// a later terminal action.
	forwarderRequestCompleted
)

// forwarderResponderState controls the capabilities retained by a detached
// responder. Unlike request state, it remains reply-capable after input
// ownership has been discarded.
type forwarderResponderState uint32

const (
	// forwarderResponderActive retains the input snapshot and all detached
	// responder actions.
	forwarderResponderActive forwarderResponderState = iota
	// forwarderResponderRepliesOnly retains only asynchronous reply operations.
	forwarderResponderRepliesOnly
	// forwarderResponderDropped selected explicit input disposal.
	forwarderResponderDropped
	// forwarderResponderRejected selected an explicit protocol rejection.
	forwarderResponderRejected
)

// forwarderDetachMode selects whether detachment retains caller-visible input
// storage and rejection capabilities.
type forwarderDetachMode uint8

const (
	// forwarderDetachWithInput retains the caller-visible snapshot and Reject.
	forwarderDetachWithInput forwarderDetachMode = iota
	// forwarderDetachForReplies omits all input-dependent capabilities.
	forwarderDetachForReplies
)

// forwarderRuntime owns state and diagnostics shared by every protocol
// forwarder. Protocol-specific request tracking remains on the outer type.
type forwarderRuntime struct {
	stack  *Stack
	closed atomic.Bool
	done   chan struct{}

	requestCount atomic.Uint64
	accepted     atomic.Uint64
	replies      atomic.Uint64
	replyErrors  atomic.Uint64
	dropped      atomic.Uint64
	rejected     atomic.Uint64
}

// validateDestination checks state shared by responder output operations.
func (f *forwarderRuntime) validateDestination(destination netip.Addr) error {
	if f.closed.Load() {
		return net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(destination) {
		return syscall.EADDRNOTAVAIL
	}
	return nil
}

// count records one successfully selected terminal action.
func (f *forwarderRuntime) count(state forwarderRequestState) {
	switch state {
	case forwarderRequestAccepted:
		f.accepted.Add(1)
	case forwarderRequestDropped:
		f.dropped.Add(1)
	case forwarderRequestRejected:
		f.rejected.Add(1)
	}
}

// info returns the common portion of a forwarder diagnostic snapshot.
func (f *forwarderRuntime) info(pending, maxInFlight int) ForwarderInfo {
	return ForwarderInfo{
		Closed:      f.closed.Load(),
		Pending:     pending,
		MaxInFlight: maxInFlight,
		Requests:    f.requestCount.Load(),
		Accepted:    f.accepted.Load(),
		Replies:     f.replies.Load(),
		ReplyErrors: f.replyErrors.Load(),
		Dropped:     f.dropped.Load(),
		Rejected:    f.rejected.Load(),
	}
}

// close publishes permanent forwarder closure exactly once. Callers serialize
// it with protocol-specific request removal before releasing their lock.
func (f *forwarderRuntime) close() bool {
	if f.closed.Swap(true) {
		return false
	}
	close(f.done)
	return true
}

// Done is closed when the forwarder is closed directly or by Stack.Close.
func (f *forwarderRuntime) Done() <-chan struct{} { return f.done }

// forwarderResponder owns state common to detached UDP, IP, and ICMP
// responders. runtime is the responder's one-way reference to its originating
// forwarder state; neither the forwarder nor the stack retains the responder.
// packet always retains reply direction metadata and, while active, may also
// retain the protocol-specific input needed for rejection.
type forwarderResponder struct {
	runtime *forwarderRuntime
	packet  ipPacket
	state   atomic.Uint32
}

// beginReply admits an output operation in either reply-capable state.
func (r *forwarderResponder) beginReply() error {
	state := forwarderResponderState(r.state.Load())
	if state != forwarderResponderActive && state != forwarderResponderRepliesOnly {
		return net.ErrClosed
	}
	if err := r.runtime.validateDestination(r.packet.target); err != nil {
		r.runtime.replyErrors.Add(1)
		return err
	}
	return nil
}

// beginInputReply admits an output operation that requires the retained input
// snapshot. It is used by ReplyEcho, whose source data is discarded when a
// responder is restricted to replies.
func (r *forwarderResponder) beginInputReply() error {
	if forwarderResponderState(r.state.Load()) != forwarderResponderActive {
		return net.ErrClosed
	}
	if err := r.runtime.validateDestination(r.packet.target); err != nil {
		r.runtime.replyErrors.Add(1)
		return err
	}
	return nil
}

// recordReply records the result of an admitted output operation.
func (r *forwarderResponder) recordReply(err error) error {
	if err != nil {
		r.runtime.replyErrors.Add(1)
	} else {
		r.runtime.replies.Add(1)
	}
	return err
}

// finish selects exactly one responder terminal action and records it.
func (r *forwarderResponder) finish(state forwarderResponderState) error {
	if state != forwarderResponderDropped && state != forwarderResponderRejected {
		panic("invalid forwarder responder terminal state")
	}
	if !r.state.CompareAndSwap(uint32(forwarderResponderActive), uint32(state)) {
		return net.ErrClosed
	}
	switch state {
	case forwarderResponderDropped:
		r.runtime.dropped.Add(1)
	case forwarderResponderRejected:
		r.runtime.rejected.Add(1)
	}
	return nil
}

// restrictToReplies irreversibly removes input-dependent responder actions.
func (r *forwarderResponder) restrictToReplies() error {
	for {
		switch forwarderResponderState(r.state.Load()) {
		case forwarderResponderRepliesOnly:
			return nil
		case forwarderResponderActive:
			if r.state.CompareAndSwap(uint32(forwarderResponderActive), uint32(forwarderResponderRepliesOnly)) {
				return nil
			}
		default:
			return net.ErrClosed
		}
	}
}

// beginReject selects rejection and validates its current output policy.
func (r *forwarderResponder) beginReject() error {
	if err := r.finish(forwarderResponderRejected); err != nil {
		return err
	}
	return r.runtime.validateDestination(r.packet.target)
}

// Drop terminates the detached input without packet I/O. It remains valid
// after replies while the responder is active. It reports net.ErrClosed when
// the responder is already terminal or restricted to replies, including one
// returned by DetachForReplies.
func (r *forwarderResponder) Drop() error {
	return r.finish(forwarderResponderDropped)
}

// Done is closed when the originating protocol forwarder is closed directly
// or by Stack.Close.
func (r *forwarderResponder) Done() <-chan struct{} { return r.runtime.done }

// TCPForwarder owns the single fallback TCP handler installed on a stack. It
// may be installed before or after Stack.Start.
type TCPForwarder struct {
	*forwarderRuntime

	handler     TCPForwarderHandler
	maxInFlight int

	mu       sync.Mutex
	requests map[tcpKey]*TCPForwarderRequest
	handlers map[*TCPForwarderRequest]struct{}
}

// TCPForwarderRequest is one valid initial SYN that did not match an ordinary
// TCP connection or listener. Exactly one terminal action is permitted during
// its handler call. A repeated or invalidated action reports
// ErrForwarderRequestCompleted.
type TCPForwarderRequest struct {
	forwarder  *TCPForwarder
	key        tcpKey
	segment    tcpSegment
	state      atomic.Uint32
	done       chan struct{}
	doneClosed atomic.Bool
}

// UDPForwarder owns the single fallback UDP handler installed on a stack. It
// may be installed before or after Stack.Start.
type UDPForwarder struct {
	*forwarderRuntime

	handler UDPForwarderHandler

	mu       sync.Mutex
	requests map[udpFlowKey]*UDPForwarderRequest
}

// UDPForwarderRequest is one valid datagram that did not match an ordinary or
// previously forwarded UDP endpoint. The handler may reply repeatedly before
// selecting at most one terminal action. Payload is valid only until the
// handler returns; Accept and Listen offer a copy to the returned UDPConn's
// capacity-bounded receive queue.
type UDPForwarderRequest struct {
	forwarder *UDPForwarder
	flow      ForwarderFlow
	packet    ipPacket
	options   ipPacketOptions
	state     atomic.Uint32
}

// UDPForwarderResponder owns one detached datagram. A responder returned by
// Detach owns its payload snapshot; DetachForReplies omits that snapshot. It
// may outlive the handler because the caller, not the forwarder, owns it. It
// retains access to the originating forwarder's state for output, diagnostics,
// and Done; neither the forwarder nor the stack retains the responder. Reply
// calls may be repeated while active or restricted to replies; Reject and Drop
// are available only while active. The responder may be discarded without a
// terminal action.
type UDPForwarderResponder struct {
	forwarderResponder

	flow    ForwarderFlow
	payload []byte
}

// IPForwarderMessage describes one valid, reassembled upper-layer IP payload.
// Its ownership and lifetime are specified by the method that returned it.
type IPForwarderMessage struct {
	// Source is the sender of the IP payload.
	Source netip.Addr
	// Destination is the original packet destination.
	Destination netip.Addr
	// Protocol is the IPv4 Protocol or final IPv6 Next Header value.
	Protocol uint8
	// HopLimit is the received IPv4 TTL or IPv6 Hop Limit.
	HopLimit uint8
	// TrafficClass is the received IPv4 TOS or IPv6 Traffic Class byte.
	TrafficClass uint8
	// FlowLabel is the received IPv6 Flow Label and is zero for IPv4.
	FlowLabel uint32
	// Payload contains the bytes following the IP or extension headers.
	Payload []byte
}

// IPForwarder owns the single fallback handler for otherwise unhandled IP
// protocols installed on a stack. It may be installed before or after
// Stack.Start.
type IPForwarder struct {
	*forwarderRuntime

	handler IPForwarderHandler

	mu       sync.Mutex
	requests map[*IPForwarderRequest]struct{}
}

// IPForwarderRequest is one upper-layer IP payload not consumed by a raw IP
// socket or built-in protocol. The handler may reply repeatedly before
// selecting at most one terminal action.
type IPForwarderRequest struct {
	forwarder *IPForwarder
	packet    ipPacket
	state     atomic.Uint32
}

// IPForwarderResponder owns one detached IP message. A responder returned by
// Detach owns its payload snapshot; DetachForReplies omits that snapshot. It
// may outlive the handler because the caller, not the forwarder, owns it. It
// retains access to the originating forwarder's state for output, diagnostics,
// and Done; neither the forwarder nor the stack retains the responder. Reply
// calls may be repeated while active or restricted to replies; Reject and Drop
// are available only while active. The responder may be discarded without a
// terminal action.
type IPForwarderResponder struct {
	forwarderResponder

	message IPForwarderMessage
}

// ICMPForwarderMessage describes one checksum-validated, reassembled ICMP
// protocol message. Payload contains the complete ICMP header and body. Its
// ownership and lifetime are specified by the method that returned the
// message.
type ICMPForwarderMessage struct {
	// Source is the sender of the ICMP message.
	Source netip.Addr
	// Destination is the original packet destination.
	Destination netip.Addr
	// Type and Code retain the wire classification. Unknown or unassigned
	// values can reach an ICMP forwarder when no built-in handler consumes them.
	Type uint8
	// Code retains the wire subtype within Type.
	Code uint8
	// Payload contains the complete ICMP header and body.
	Payload []byte
}

// IsEchoRequest reports whether the message is a complete IPv4 or IPv6 Echo
// Request whose Type and Code fields agree with Payload. Source and Destination
// must identify the same address family.
func (m ICMPForwarderMessage) IsEchoRequest() bool {
	if len(m.Payload) < 2 || m.Type != m.Payload[0] || m.Code != m.Payload[1] {
		return false
	}
	protocol := byte(0)
	switch {
	case m.Source.Is4() && m.Destination.Is4():
		protocol = protocolICMPv4
	case m.Source.Is6() && m.Destination.Is6():
		protocol = protocolICMPv6
	default:
		return false
	}
	return isICMPEchoRequest(protocol, m.Payload)
}

// ICMPForwarder owns the single fallback ICMP handler installed on a stack. It
// may be installed before or after Stack.Start.
type ICMPForwarder struct {
	*forwarderRuntime

	handler ICMPForwarderHandler

	mu       sync.Mutex
	requests map[*ICMPForwarderRequest]struct{}
}

// ICMPForwarderRequest is one checksum-valid ICMP message not consumed by
// built-in protocol handling. The handler may reply repeatedly before
// selecting at most one terminal action.
type ICMPForwarderRequest struct {
	forwarder *ICMPForwarder
	packet    ipPacket
	state     atomic.Uint32
}

// ICMPForwarderResponder owns one detached message. A responder returned by
// Detach owns its packet snapshot; DetachForReplies omits that snapshot. It may
// outlive the handler because the caller, not the forwarder, owns it. It retains
// access to the originating forwarder's state for output, diagnostics, and
// Done; neither the forwarder nor the stack retains the responder. Reply and
// ReplyIPPacket calls may be repeated while active or restricted to replies;
// ReplyEcho, Reject, and Drop are available only while active. The responder
// may be discarded without a terminal action.
type ICMPForwarderResponder struct {
	forwarderResponder

	message      ICMPForwarderMessage
	rejectPacket ipPacket
	rejectable   bool
}

// tcpForwarderEndpoints is the small dispatch surface retained by Stack.
type tcpForwarderEndpoints interface {
	// handleSegment offers one otherwise unhandled SYN to the forwarder.
	handleSegment(segment tcpSegment, key tcpKey) bool
	// updateConfig invalidates requests no longer admitted by network policy.
	updateConfig(network *networkState)
	// closeFromStack cancels pending requests during stack closure.
	closeFromStack()
}

// udpForwarderEndpoints is the small dispatch surface retained by Stack.
type udpForwarderEndpoints interface {
	// handlePacket offers one otherwise unhandled datagram to the forwarder.
	handlePacket(packet ipPacket, flow ForwarderFlow, options ipPacketOptions) bool
	// updateConfig invalidates requests no longer admitted by network policy.
	updateConfig(network *networkState)
	// closeFromStack cancels pending requests during stack closure.
	closeFromStack()
}

// ipForwarderEndpoints is the small dispatch surface retained by Stack.
type ipForwarderEndpoints interface {
	// handlePacket offers one otherwise unhandled upper-layer IP payload.
	handlePacket(packet ipPacket) bool
	// updateConfig invalidates requests no longer admitted by network policy.
	updateConfig(network *networkState)
	// closeFromStack cancels pending requests during stack closure.
	closeFromStack()
}

// icmpForwarderEndpoints is the small dispatch surface retained by Stack.
type icmpForwarderEndpoints interface {
	// handlePacket offers one otherwise unhandled ICMP message to the forwarder.
	handlePacket(packet ipPacket) bool
	// updateConfig invalidates requests no longer admitted by network policy.
	updateConfig(network *networkState)
	// closeFromStack cancels pending requests during stack closure.
	closeFromStack()
}

// NewTCPForwarder installs a fallback handler for otherwise unhandled TCP
// connection attempts. Only one TCP forwarder may be active per stack.
// Promiscuous mode is not required for unhandled traffic addressed to
// LocalAddresses; Config.Promiscuous is required only for nonlocal destination
// addresses. Installing a forwarder does not start the stack.
func NewTCPForwarder(stack *Stack, options TCPForwarderOptions, handler TCPForwarderHandler) (*TCPForwarder, error) {
	if stack == nil || handler == nil {
		return nil, syscall.EINVAL
	}
	if options.MaxInFlight < 0 {
		return nil, syscall.EINVAL
	}
	maximum := options.MaxInFlight
	if maximum == 0 {
		maximum = stack.network.Load().tcpDefaults.SYNBacklog
	}
	forwarder := &TCPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		handler:          handler,
		maxInFlight:      maximum,
		requests:         make(map[tcpKey]*TCPForwarderRequest),
		handlers:         make(map[*TCPForwarderRequest]struct{}),
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.tcpForwarder != nil {
		return nil, syscall.EADDRINUSE
	}
	stack.tcpForwarder = forwarder
	return forwarder, nil
}

// NewUDPForwarder installs a fallback handler for otherwise unhandled UDP
// datagrams. Only one UDP forwarder may be active per stack. Promiscuous mode
// is not required for unhandled traffic addressed to LocalAddresses;
// Config.Promiscuous is required only for nonlocal destination addresses.
// Installing a forwarder does not start the stack.
func NewUDPForwarder(stack *Stack, options UDPForwarderOptions, handler UDPForwarderHandler) (*UDPForwarder, error) {
	if stack == nil || handler == nil {
		return nil, syscall.EINVAL
	}
	forwarder := &UDPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		handler:          handler,
		requests:         make(map[udpFlowKey]*UDPForwarderRequest),
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.udpForwarder != nil {
		return nil, syscall.EADDRINUSE
	}
	stack.udpForwarder = forwarder
	return forwarder, nil
}

// NewIPForwarder installs a fallback handler for otherwise unhandled IP
// protocols. A matching IPConn has priority, and TCP, UDP,
// ICMP, and IPv6 No Next Header never reach this handler. Only one IP
// forwarder may be active per stack. Promiscuous mode is required only for
// nonlocal destinations. Installing a forwarder does not start the stack.
func NewIPForwarder(stack *Stack, options IPForwarderOptions, handler IPForwarderHandler) (*IPForwarder, error) {
	if stack == nil || handler == nil {
		return nil, syscall.EINVAL
	}
	forwarder := &IPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		handler:          handler,
		requests:         make(map[*IPForwarderRequest]struct{}),
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.ipForwarder != nil {
		return nil, syscall.EADDRINUSE
	}
	stack.ipForwarder = forwarder
	return forwarder, nil
}

// NewICMPForwarder installs a fallback handler for otherwise unhandled ICMP
// messages. Only one ICMP forwarder may be active per stack. Promiscuous mode
// is not required for unhandled traffic addressed to LocalAddresses;
// Config.Promiscuous is required only for nonlocal destination addresses.
// Installing a forwarder does not start the stack.
func NewICMPForwarder(stack *Stack, options ICMPForwarderOptions, handler ICMPForwarderHandler) (*ICMPForwarder, error) {
	if stack == nil || handler == nil {
		return nil, syscall.EINVAL
	}
	forwarder := &ICMPForwarder{
		forwarderRuntime: &forwarderRuntime{stack: stack, done: make(chan struct{})},
		handler:          handler,
		requests:         make(map[*ICMPForwarderRequest]struct{}),
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.closed {
		return nil, ErrClosed
	}
	if stack.icmpForwarder != nil {
		return nil, syscall.EADDRINUSE
	}
	stack.icmpForwarder = forwarder
	return forwarder, nil
}

// Flow returns the original inbound TCP four-tuple. The method may be called
// only during the handler, but the returned value is an independent copy that
// may be retained.
func (r *TCPForwarderRequest) Flow() ForwarderFlow {
	return ForwarderFlow{Source: r.key.remote, Destination: r.key.local}
}

// Done is closed when the handler returns or the request is invalidated by a
// configuration update or forwarder closure. It lets a blocking TCP handler
// abandon external work before attempting its terminal action.
func (r *TCPForwarderRequest) Done() <-chan struct{} { return r.done }

// closeDone publishes request cancellation exactly once across handler return,
// configuration invalidation, and forwarder closure.
func (r *TCPForwarderRequest) closeDone() {
	if r.doneClosed.CompareAndSwap(false, true) {
		close(r.done)
	}
}

// Accept creates a passive TCP endpoint and blocks until the handshake
// completes, ctx is canceled, or the stack closes. The accepted connection
// preserves the original destination in LocalAddr and the sender in
// RemoteAddr. The handler must wait for Accept to return before returning
// itself. Once Accept returns, the connection is independent of both the
// request and the forwarder: the handler may return immediately or hand the
// connection to another goroutine, and closing the forwarder does not close
// it. Options are validated before the request is claimed and are not
// retained; an invalid option leaves the request available for another
// action. After validation succeeds, Accept consumes the request even when
// endpoint creation or the handshake returns an error.
func (r *TCPForwarderRequest) Accept(ctx context.Context, options ...SocketOption) (*TCPConn, error) {
	if ctx == nil {
		panic("nil Context")
	}
	parsed, err := parseSocketOptions(options, socketOptionTCPDial)
	if err != nil {
		return nil, err
	}
	if err = parsed.validateFamily(socketOptionTCPDial, r.key.local.Addr().Is6(), false); err != nil {
		return nil, err
	}
	if !r.claim() {
		return nil, ErrForwarderRequestCompleted
	}
	connection, result, err := r.forwarder.acceptTCP(r, parsed.tcp)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	select {
	case err = <-result:
		if err != nil {
			r.finish(forwarderRequestDropped)
			return nil, err
		}
		r.finish(forwarderRequestAccepted)
		return connection, nil
	case <-ctx.Done():
		connection.abort(ctx.Err())
		r.finish(forwarderRequestDropped)
		return nil, ctx.Err()
	case <-r.forwarder.stack.closeCh:
		connection.abortWithoutReset(ErrClosed)
		r.finish(forwarderRequestDropped)
		return nil, ErrClosed
	}
}

// Drop consumes the TCP request without packet I/O. It may wait briefly for
// forwarder bookkeeping but does not wait for the network or output queue.
func (r *TCPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return ErrForwarderRequestCompleted
	}
	return nil
}

// Reject consumes the TCP request and attempts to enqueue the RFC 9293 reset
// response without waiting for outbound capacity. It reports ErrResourceLimit
// when the queue is full, syscall.EADDRNOTAVAIL when the intercepted destination
// is no longer admitted, and syscall.ENETUNREACH when no return route remains;
// the rejection decision remains terminal.
func (r *TCPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return ErrForwarderRequestCompleted
	}
	return r.forwarder.stack.rejectTCPSegment(r.key, r.segment)
}

// Flow returns the original inbound UDP four-tuple. The method may be called
// only during the handler, but the returned value is an independent copy that
// may be retained.
func (r *UDPForwarderRequest) Flow() ForwarderFlow { return r.flow }

// Payload returns the triggering UDP payload. The returned slice aliases
// packet-delivery storage, must not be modified, and is valid only until the
// handler returns.
func (r *UDPForwarderRequest) Payload() []byte { return r.packet.payload[udpHeaderSize:] }

// Accept creates a connected UDP endpoint, offers a copy of the triggering
// datagram to its receive queue, and registers the complete intercepted
// four-tuple for future delivery. It does not wait for remote traffic. The
// returned UDPConn is bound to Destination and connected to Source: Read
// receives only that source, Write replies to it, and destination-taking
// methods such as WriteTo return net.ErrWriteToConnected. The endpoint remains
// open if the forwarder closes.
// The handler must wait for Accept to return before returning itself, but may
// then retain the connection or hand it to another goroutine. The triggering
// datagram may be dropped when it exceeds the configured receive capacity;
// later datagrams still use the registered endpoint. Accept consumes the
// request even when endpoint creation returns an error and may be called after
// any number of Reply or ReplyFrom attempts. Options are validated before the
// request is claimed; an invalid option leaves it available for another
// action, and the option slice is not retained.
func (r *UDPForwarderRequest) Accept(options ...SocketOption) (*UDPConn, error) {
	parsed, err := parseSocketOptions(options, socketOptionUDPDial)
	if err != nil {
		return nil, err
	}
	if err = parsed.validateFamily(socketOptionUDPDial, r.flow.Destination.Addr().Is6(), false); err != nil {
		return nil, err
	}
	if _, ok := r.claim(); !ok {
		return nil, ErrForwarderRequestCompleted
	}
	connection, err := r.forwarder.acceptUDP(r, parsed.datagram)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	r.finish(forwarderRequestAccepted)
	return connection, nil
}

// Listen creates an unconnected UDP endpoint bound to Destination, offers a
// copy of the triggering datagram to its receive queue, and registers that
// local endpoint for future datagrams from any source. It does not wait for
// remote traffic. ReadFrom reports each source and WriteTo may address
// different peers. The destination must not already have an ordinary binding
// or an accepted forwarded flow; such an ownership conflict reports
// syscall.EADDRINUSE. The endpoint remains open if the forwarder closes. The
// handler must wait for Listen to return before returning itself, but may then
// retain the connection or hand it to another goroutine. The triggering
// datagram may be dropped when it exceeds the configured receive capacity;
// later datagrams still use the registered endpoint. Listen consumes the
// request even when endpoint creation returns an error and may be called after
// any number of Reply or ReplyFrom attempts. Options are validated before the
// request is claimed; an invalid option leaves it available for another
// action, and the option slice is not retained.
func (r *UDPForwarderRequest) Listen(options ...SocketOption) (*UDPConn, error) {
	// Forwarded listeners have exclusive flow ownership, so listener reuse
	// policies are deliberately rejected by the connected UDP option class.
	parsed, err := parseSocketOptions(options, socketOptionUDPDial)
	if err != nil {
		return nil, err
	}
	if err = parsed.validateFamily(socketOptionUDPDial, r.flow.Destination.Addr().Is6(), false); err != nil {
		return nil, err
	}
	if _, ok := r.claim(); !ok {
		return nil, ErrForwarderRequestCompleted
	}
	connection, err := r.forwarder.listenUDP(r, parsed.datagram)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	r.finish(forwarderRequestAccepted)
	return connection, nil
}

// Reply sends one reverse-flow datagram from Destination to Source without
// retaining a UDP endpoint. Use ReplyFrom to select a different source. The
// method may be called repeatedly or concurrently, including before a later
// terminal action, but every call must finish before the handler returns. Each
// call atomically queues the complete datagram or all of its fragments without
// waiting for outbound capacity and may be retried after any error.
func (r *UDPForwarderRequest) Reply(payload []byte) (int, error) {
	return r.replyFrom(payload, r.flow.Destination)
}

// ReplyFrom sends one datagram to Flow().Source using source as its IP address
// and UDP port, without retaining an endpoint. Source may be any valid address
// in the same family as Flow().Source; it need not belong to LocalAddresses and
// is not classified as unicast, multicast, or broadcast here. It is unzoned and
// unmapped, and port zero is preserved on the wire. ReplyFrom has the same
// lifecycle, ownership, and output behavior as Reply.
func (r *UDPForwarderRequest) ReplyFrom(payload []byte, source netip.AddrPort) (int, error) {
	return r.replyFrom(payload, source)
}

// replyFrom records one request-scoped output attempt and emits its datagram.
func (r *UDPForwarderRequest) replyFrom(payload []byte, source netip.AddrPort) (int, error) {
	if err := r.beginReply(); err != nil {
		return 0, err
	}
	validated, err := validateUDPForwarderReply(r.flow, payload, source)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return 0, err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return 0, net.ErrClosed
	}
	n, err := r.forwarder.replyUDPFlow(r.flow, payload, validated)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return n, err
	}
	r.forwarder.replies.Add(1)
	return n, nil
}

// Drop consumes the UDP datagram without packet I/O. It may follow any number
// of Reply or ReplyFrom attempts, may wait briefly for forwarder bookkeeping,
// and does not wait for the network or output queue.
func (r *UDPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return ErrForwarderRequestCompleted
	}
	return nil
}

// Reject consumes the UDP datagram and attempts to enqueue ICMP Port
// Unreachable without waiting for outbound capacity. It reports
// ErrResourceLimit when the queue is full, syscall.EADDRNOTAVAIL when the
// intercepted destination is no longer admitted, and syscall.ENETUNREACH when
// no return route remains. It may follow any number of Reply or ReplyFrom
// attempts; the rejection decision remains terminal.
func (r *UDPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return ErrForwarderRequestCompleted
	}
	return r.forwarder.stack.sendPortUnreachable(r.packet)
}

// Message returns the validated upper-layer IP payload presented to the
// handler. Payload aliases packet-delivery storage, must not be modified, and
// is valid only until the handler returns. Message does not select an action.
func (r *IPForwarderRequest) Message() IPForwarderMessage {
	return ipForwarderMessage(r.packet, r.packet.payload)
}

// Reply sends one payload with the triggering protocol number from Destination
// to Source. Calls may be repeated or concurrent before a later terminal action
// and must finish before the handler returns. Each reply atomically queues all
// required fragments without waiting for capacity and may be retried on error.
func (r *IPForwarderRequest) Reply(payload []byte) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return net.ErrClosed
	}
	err := r.forwarder.replyIPPayload(r.packet, payload)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return err
	}
	r.forwarder.replies.Add(1)
	return nil
}

// Drop consumes the IP payload without packet I/O and may follow any number of
// Reply attempts.
func (r *IPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return ErrForwarderRequestCompleted
	}
	return nil
}

// Reject consumes the IP payload and attempts to enqueue the address-family
// protocol-unreachable response without waiting for outbound capacity. It
// reports syscall.EADDRNOTAVAIL when the intercepted destination is no longer
// admitted and syscall.ENETUNREACH when no return route remains. It may follow
// any number of Reply attempts.
func (r *IPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return ErrForwarderRequestCompleted
	}
	return r.forwarder.stack.sendProtocolUnreachable(r.packet)
}

// Message returns the checksum-validated ICMP message presented to the handler.
// Payload aliases packet-delivery storage, must not be modified, and is valid
// only until the handler returns. Message does not select an action.
func (r *ICMPForwarderRequest) Message() ICMPForwarderMessage {
	return ICMPForwarderMessage{
		Source: r.packet.source, Destination: r.packet.target,
		Type: r.packet.payload[0], Code: r.packet.payload[1], Payload: r.packet.payload,
	}
}

// IPPacket returns the complete, reassembled L3 packet that contains Message.
// The returned slice aliases packet-delivery storage, is read-only, and is
// valid only until the handler returns. Message().Payload aliases the ICMP
// portion of the same packet.
func (r *ICMPForwarderRequest) IPPacket() []byte { return r.packet.original }

// Reply sends a complete ICMP protocol message from Destination to Source. The
// method may be called repeatedly or concurrently, including before a later
// terminal action, but every call must finish before the handler returns. The
// stack copies payload, recalculates its checksum, and atomically queues every
// required fragment without waiting for outbound capacity. A call may be
// retried after any error.
func (r *ICMPForwarderRequest) Reply(payload []byte) error {
	return r.reply(payload, false)
}

// reply records one callback-scoped output attempt and writes either borrowed
// or stack-owned payload storage.
func (r *ICMPForwarderRequest) reply(payload []byte, owned bool) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	return r.writeReply(payload, owned)
}

// writeReply emits one reply after the request output attempt was recorded.
func (r *ICMPForwarderRequest) writeReply(payload []byte, owned bool) error {
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return net.ErrClosed
	}
	var err error
	if owned {
		err = r.forwarder.stack.writeOwnedICMPReply(r.packet, payload)
	} else {
		err = r.forwarder.stack.writeICMPReply(r.packet, payload)
	}
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return err
	}
	r.forwarder.replies.Add(1)
	return nil
}

// ReplyIPPacket sends a complete IPv4 ICMP or IPv6 ICMP packet whose final
// destination is the triggering packet's source. It is a restricted
// header-included ICMP operation, not arbitrary packet injection. Its source may
// be any valid same-family address; it need not belong to LocalAddresses and is
// not classified as unicast, multicast, or broadcast here. MIPS copies packet,
// normalizes its IP length and outer IPv4 and ICMP checksums,
// preserves other legal header fields and extension headers, and atomically
// source-fragments it when permitted. A non-atomic input fragment is invalid.
// An IPv6 atomic Fragment header is preserved when the packet fits; when
// fragmentation is required, it is replaced by the emitted fragment sequence
// instead of nesting another header. The method may be retried after validation
// or output failure and does not prevent a later terminal action.
func (r *ICMPForwarderRequest) ReplyIPPacket(packet []byte) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	reply, err := prepareICMPForwarderIPPacket(packet, r.packet.source)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return net.ErrClosed
	}
	if err = r.forwarder.stack.writeICMPForwarderIPPacket(r.packet, reply); err != nil {
		r.forwarder.replyErrors.Add(1)
		return err
	}
	r.forwarder.replies.Add(1)
	return nil
}

// ReplyEcho copies the triggering Echo Request into an Echo Reply, preserving
// its identifier, sequence, and data. It reports syscall.EINVAL when the
// triggering message is not an IPv4 or IPv6 Echo Request. Like Reply, it may be
// retried and does not prevent a later terminal action; every call must finish
// before the handler returns.
func (r *ICMPForwarderRequest) ReplyEcho() error {
	if err := r.beginReply(); err != nil {
		return err
	}
	reply, ok := makeICMPEchoReply(r.packet.protocol, r.packet.payload)
	if !ok {
		r.forwarder.replyErrors.Add(1)
		return syscall.EINVAL
	}
	return r.writeReply(reply, true)
}

// Drop consumes the ICMP message without packet I/O. It may follow any number
// of Reply, ReplyIPPacket, or ReplyEcho attempts, may wait briefly for forwarder
// bookkeeping, and does not wait for the network or output queue.
func (r *ICMPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return ErrForwarderRequestCompleted
	}
	return nil
}

// Reject consumes the ICMP message and emits an administratively prohibited
// response when ICMP rules permit an error response. It does not wait for
// outbound capacity and reports ErrResourceLimit when the queue is full,
// syscall.EADDRNOTAVAIL when the intercepted destination is no longer admitted,
// and syscall.ENETUNREACH when no return route remains. The rejection decision
// remains terminal and may follow any number of reply attempts.
func (r *ICMPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return ErrForwarderRequestCompleted
	}
	return r.forwarder.stack.sendAdministrativeUnreachable(r.packet)
}

// Close removes the TCP fallback handler and invalidates undecided requests.
// It does not wait for running handlers to return. An action already claimed
// by a handler may finish, and accepted connections remain open.
func (f *TCPForwarder) Close() error {
	f.stack.mu.Lock()
	if f.stack.tcpForwarder != f {
		f.stack.mu.Unlock()
		return net.ErrClosed
	}
	f.stack.tcpForwarder = nil
	f.stack.mu.Unlock()
	f.closeFromStack()
	return nil
}

// Close removes the UDP fallback handler and invalidates undecided requests.
// It does not wait for running handlers to return. An action already claimed
// by a handler or detached responder may finish, and accepted UDP endpoints
// remain open.
func (f *UDPForwarder) Close() error {
	f.stack.mu.Lock()
	if f.stack.udpForwarder != f {
		f.stack.mu.Unlock()
		return net.ErrClosed
	}
	f.stack.udpForwarder = nil
	f.stack.mu.Unlock()
	f.closeFromStack()
	return nil
}

// Close removes the otherwise unhandled IP protocol fallback handler and
// invalidates undecided requests. It does not wait for running handlers or
// replies.
func (f *IPForwarder) Close() error {
	f.stack.mu.Lock()
	if f.stack.ipForwarder != f {
		f.stack.mu.Unlock()
		return net.ErrClosed
	}
	f.stack.ipForwarder = nil
	f.stack.mu.Unlock()
	f.closeFromStack()
	return nil
}

// Close removes the ICMP fallback handler and invalidates undecided requests.
// It does not wait for running handlers to return. An action already claimed
// by a handler or detached responder may finish.
func (f *ICMPForwarder) Close() error {
	f.stack.mu.Lock()
	if f.stack.icmpForwarder != f {
		f.stack.mu.Unlock()
		return net.ErrClosed
	}
	f.stack.icmpForwarder = nil
	f.stack.mu.Unlock()
	f.closeFromStack()
	return nil
}

// Info returns one TCP forwarder diagnostic snapshot.
func (f *TCPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	pending := len(f.requests)
	f.mu.Unlock()
	return f.info(pending, f.maxInFlight)
}

// Info returns one UDP forwarder diagnostic snapshot.
func (f *UDPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	pending := len(f.requests)
	f.mu.Unlock()
	return f.info(pending, 0)
}

// Info returns one IP forwarder diagnostic snapshot.
func (f *IPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	pending := len(f.requests)
	f.mu.Unlock()
	return f.info(pending, 0)
}

// Info returns one ICMP forwarder diagnostic snapshot.
func (f *ICMPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	pending := len(f.requests)
	f.mu.Unlock()
	return f.info(pending, 0)
}

// handleSegment coalesces one valid initial SYN into the bounded request set.
func (f *TCPForwarder) handleSegment(segment tcpSegment, key tcpKey) bool {
	if key.remote.Port() == 0 || segment.flags&tcpFlagSYN == 0 || segment.flags&(tcpFlagACK|tcpFlagRST|tcpFlagFIN) != 0 {
		return false
	}
	f.mu.Lock()
	if f.closed.Load() {
		f.mu.Unlock()
		return false
	}
	if _, exists := f.requests[key]; exists {
		f.mu.Unlock()
		return true
	}
	if len(f.requests) >= f.maxInFlight {
		f.dropped.Add(1)
		f.mu.Unlock()
		f.stack.stats.inboundDroppedPackets.Add(1)
		return true
	}
	request := &TCPForwarderRequest{forwarder: f, key: key, segment: segment, done: make(chan struct{})}
	f.requests[key] = request
	f.handlers[request] = struct{}{}
	f.requestCount.Add(1)
	f.mu.Unlock()
	go func() {
		defer func() {
			_ = request.Drop()
			request.closeDone()
			f.removeHandler(request)
		}()
		f.handler(request)
	}()
	return true
}

// handlePacket serializes the first undecided datagram for a four-tuple and
// invokes the synchronous handler.
func (f *UDPForwarder) handlePacket(packet ipPacket, flow ForwarderFlow, options ipPacketOptions) bool {
	key := udpFlowKey{local: flow.Destination, remote: flow.Source}
	f.mu.Lock()
	if f.closed.Load() {
		f.mu.Unlock()
		return false
	}
	if _, exists := f.requests[key]; exists {
		f.dropped.Add(1)
		f.mu.Unlock()
		f.stack.stats.inboundDroppedPackets.Add(1)
		return true
	}
	request := &UDPForwarderRequest{forwarder: f, flow: flow, packet: packet, options: options}
	f.requests[key] = request
	f.requestCount.Add(1)
	f.mu.Unlock()
	defer request.finishHandler()
	f.handler(request)
	return true
}

// handlePacket invokes the synchronous handler for one validated upper-layer
// IP payload.
func (f *IPForwarder) handlePacket(packet ipPacket) bool {
	request := &IPForwarderRequest{forwarder: f, packet: packet}
	f.mu.Lock()
	if f.closed.Load() {
		f.mu.Unlock()
		return false
	}
	f.requests[request] = struct{}{}
	f.requestCount.Add(1)
	f.mu.Unlock()
	defer request.finishHandler()
	f.handler(request)
	return true
}

// handlePacket invokes the synchronous handler for one validated message.
func (f *ICMPForwarder) handlePacket(packet ipPacket) bool {
	request := &ICMPForwarderRequest{forwarder: f, packet: packet}
	f.mu.Lock()
	if f.closed.Load() {
		f.mu.Unlock()
		return false
	}
	f.requests[request] = struct{}{}
	f.requestCount.Add(1)
	f.mu.Unlock()
	defer request.finishHandler()
	f.handler(request)
	return true
}

// claim reserves the TCP request for an action that can fail asynchronously.
func (r *TCPForwarderRequest) claim() bool {
	return r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestClaimed))
}

// complete publishes an immediate terminal TCP action.
func (r *TCPForwarderRequest) complete(state forwarderRequestState) bool {
	if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(state)) {
		return false
	}
	r.forwarder.remove(r)
	r.forwarder.count(state)
	return true
}

// finish publishes the result of a previously claimed TCP action.
func (r *TCPForwarderRequest) finish(state forwarderRequestState) {
	r.state.Store(uint32(state))
	r.forwarder.remove(r)
	r.forwarder.count(state)
}

// remove deletes one TCP request if it remains the tuple's current request.
func (f *TCPForwarder) remove(request *TCPForwarderRequest) {
	f.mu.Lock()
	if f.requests[request.key] == request {
		delete(f.requests, request.key)
	}
	f.mu.Unlock()
}

// removeHandler releases one TCP request after its handler has returned.
func (f *TCPForwarder) removeHandler(request *TCPForwarderRequest) {
	f.mu.Lock()
	delete(f.handlers, request)
	f.mu.Unlock()
}

// claim reserves the UDP request for a terminal action and reports whether a
// reply began first. A reply that linearized first may still finish.
func (r *UDPForwarderRequest) claim() (replied, ok bool) {
	for {
		state := forwarderRequestState(r.state.Load())
		if state != forwarderRequestPending && state != forwarderRequestReplyStarted {
			return false, false
		}
		if r.state.CompareAndSwap(uint32(state), uint32(forwarderRequestClaimed)) {
			return state == forwarderRequestReplyStarted, true
		}
	}
}

// beginReply records the first UDP reply or continues callback-scoped output.
func (r *UDPForwarderRequest) beginReply() error {
	for {
		switch forwarderRequestState(r.state.Load()) {
		case forwarderRequestPending:
			if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestReplyStarted)) {
				continue
			}
			return nil
		case forwarderRequestReplyStarted:
			return nil
		default:
			return ErrForwarderRequestCompleted
		}
	}
}

// finishHandler drops an undecided datagram or completes a reply-only handler.
func (r *UDPForwarderRequest) finishHandler() {
	if r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
		r.forwarder.remove(r)
		r.forwarder.count(forwarderRequestDropped)
		return
	}
	if r.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
		r.forwarder.remove(r)
	}
}

// complete publishes an immediate terminal UDP action.
func (r *UDPForwarderRequest) complete(state forwarderRequestState) bool {
	for {
		current := forwarderRequestState(r.state.Load())
		if current != forwarderRequestPending && current != forwarderRequestReplyStarted {
			return false
		}
		if r.state.CompareAndSwap(uint32(current), uint32(state)) {
			break
		}
	}
	r.forwarder.remove(r)
	r.forwarder.count(state)
	return true
}

// finish publishes the result of a previously claimed UDP action.
func (r *UDPForwarderRequest) finish(state forwarderRequestState) {
	r.state.Store(uint32(state))
	r.forwarder.remove(r)
	r.forwarder.count(state)
}

// remove deletes one UDP request if it remains the tuple's current request.
func (f *UDPForwarder) remove(request *UDPForwarderRequest) {
	key := udpFlowKey{local: request.flow.Destination, remote: request.flow.Source}
	f.mu.Lock()
	if f.requests[key] == request {
		delete(f.requests, key)
	}
	f.mu.Unlock()
}

// claim reserves the IP request for a terminal action and reports whether a
// reply began first. A reply that linearized first may still finish.
func (r *IPForwarderRequest) claim() (replied, ok bool) {
	for {
		state := forwarderRequestState(r.state.Load())
		if state != forwarderRequestPending && state != forwarderRequestReplyStarted {
			return false, false
		}
		if r.state.CompareAndSwap(uint32(state), uint32(forwarderRequestClaimed)) {
			return state == forwarderRequestReplyStarted, true
		}
	}
}

// beginReply records the first IP reply or continues callback-scoped output.
func (r *IPForwarderRequest) beginReply() error {
	for {
		switch forwarderRequestState(r.state.Load()) {
		case forwarderRequestPending:
			if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestReplyStarted)) {
				continue
			}
			return nil
		case forwarderRequestReplyStarted:
			return nil
		default:
			return ErrForwarderRequestCompleted
		}
	}
}

// finishHandler drops an undecided payload or completes a reply-only handler.
func (r *IPForwarderRequest) finishHandler() {
	if r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
		r.forwarder.remove(r)
		r.forwarder.count(forwarderRequestDropped)
		return
	}
	if r.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
		r.forwarder.remove(r)
	}
}

// complete publishes an immediate terminal IP action.
func (r *IPForwarderRequest) complete(state forwarderRequestState) bool {
	for {
		current := forwarderRequestState(r.state.Load())
		if current != forwarderRequestPending && current != forwarderRequestReplyStarted {
			return false
		}
		if r.state.CompareAndSwap(uint32(current), uint32(state)) {
			break
		}
	}
	r.forwarder.remove(r)
	r.forwarder.count(state)
	return true
}

// finish publishes the result of a previously claimed IP action.
func (r *IPForwarderRequest) finish(state forwarderRequestState) {
	r.state.Store(uint32(state))
	r.forwarder.remove(r)
	r.forwarder.count(state)
}

// remove deletes one IP request if it remains active.
func (f *IPForwarder) remove(request *IPForwarderRequest) {
	f.mu.Lock()
	delete(f.requests, request)
	f.mu.Unlock()
}

// claim reserves the ICMP request for a terminal action and reports whether a
// reply began first. A reply that linearized first may still finish.
func (r *ICMPForwarderRequest) claim() (replied, ok bool) {
	for {
		state := forwarderRequestState(r.state.Load())
		if state != forwarderRequestPending && state != forwarderRequestReplyStarted {
			return false, false
		}
		if r.state.CompareAndSwap(uint32(state), uint32(forwarderRequestClaimed)) {
			return state == forwarderRequestReplyStarted, true
		}
	}
}

// beginReply records the first ICMP reply or continues callback-scoped output.
func (r *ICMPForwarderRequest) beginReply() error {
	for {
		switch forwarderRequestState(r.state.Load()) {
		case forwarderRequestPending:
			if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestReplyStarted)) {
				continue
			}
			return nil
		case forwarderRequestReplyStarted:
			return nil
		default:
			return ErrForwarderRequestCompleted
		}
	}
}

// finishHandler drops an undecided message or completes a reply-only handler.
func (r *ICMPForwarderRequest) finishHandler() {
	if r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
		r.forwarder.remove(r)
		r.forwarder.count(forwarderRequestDropped)
		return
	}
	if r.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
		r.forwarder.remove(r)
	}
}

// complete publishes an immediate terminal ICMP action.
func (r *ICMPForwarderRequest) complete(state forwarderRequestState) bool {
	for {
		current := forwarderRequestState(r.state.Load())
		if current != forwarderRequestPending && current != forwarderRequestReplyStarted {
			return false
		}
		if r.state.CompareAndSwap(uint32(current), uint32(state)) {
			break
		}
	}
	r.forwarder.remove(r)
	r.forwarder.count(state)
	return true
}

// finish publishes the result of a previously claimed ICMP action.
func (r *ICMPForwarderRequest) finish(state forwarderRequestState) {
	r.state.Store(uint32(state))
	r.forwarder.remove(r)
	r.forwarder.count(state)
}

// remove deletes one ICMP request if it remains active.
func (f *ICMPForwarder) remove(request *ICMPForwarderRequest) {
	f.mu.Lock()
	delete(f.requests, request)
	f.mu.Unlock()
}

// updateConfig invalidates pending TCP requests whose intercepted destination
// is no longer admitted by the current network configuration.
func (f *TCPForwarder) updateConfig(network *networkState) {
	f.mu.Lock()
	for key, request := range f.requests {
		if network.acceptsInboundDestination(key.local.Addr()) {
			continue
		}
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			delete(f.requests, key)
			f.dropped.Add(1)
			request.closeDone()
		}
	}
	f.mu.Unlock()
}

// updateConfig invalidates pending UDP requests whose intercepted destination
// is no longer admitted by the current network configuration.
func (f *UDPForwarder) updateConfig(network *networkState) {
	f.mu.Lock()
	for key, request := range f.requests {
		if network.acceptsInboundDestination(key.local.Addr()) {
			continue
		}
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			delete(f.requests, key)
			f.dropped.Add(1)
		} else if request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
			delete(f.requests, key)
		}
	}
	f.mu.Unlock()
}

// updateConfig invalidates pending IP requests whose intercepted destination
// is no longer admitted by the current network configuration.
func (f *IPForwarder) updateConfig(network *networkState) {
	f.mu.Lock()
	for request := range f.requests {
		if network.acceptsInboundDestination(request.packet.target) {
			continue
		}
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			delete(f.requests, request)
			f.dropped.Add(1)
		} else if request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
			delete(f.requests, request)
		}
	}
	f.mu.Unlock()
}

// updateConfig invalidates pending ICMP requests whose intercepted
// destination is no longer admitted by the current network configuration.
func (f *ICMPForwarder) updateConfig(network *networkState) {
	f.mu.Lock()
	for request := range f.requests {
		if network.acceptsInboundDestination(request.packet.target) {
			continue
		}
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			delete(f.requests, request)
			f.dropped.Add(1)
		} else if request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted)) {
			delete(f.requests, request)
		}
	}
	f.mu.Unlock()
}

// closeFromStack detaches the TCP handler and drops undecided requests.
func (f *TCPForwarder) closeFromStack() {
	f.mu.Lock()
	if !f.forwarderRuntime.close() {
		f.mu.Unlock()
		return
	}
	requests := make([]*TCPForwarderRequest, 0, len(f.requests))
	for _, request := range f.requests {
		requests = append(requests, request)
	}
	handlers := make([]*TCPForwarderRequest, 0, len(f.handlers))
	for request := range f.handlers {
		handlers = append(handlers, request)
	}
	f.requests = nil
	f.handlers = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		}
	}
	for _, request := range handlers {
		request.closeDone()
	}
}

// closeFromStack detaches the UDP handler and drops undecided requests.
func (f *UDPForwarder) closeFromStack() {
	f.mu.Lock()
	if !f.forwarderRuntime.close() {
		f.mu.Unlock()
		return
	}
	requests := make([]*UDPForwarderRequest, 0, len(f.requests))
	for _, request := range f.requests {
		requests = append(requests, request)
	}
	f.requests = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		} else {
			request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted))
		}
	}
}

// closeFromStack detaches the IP handler and drops undecided requests.
func (f *IPForwarder) closeFromStack() {
	f.mu.Lock()
	if !f.forwarderRuntime.close() {
		f.mu.Unlock()
		return
	}
	requests := make([]*IPForwarderRequest, 0, len(f.requests))
	for request := range f.requests {
		requests = append(requests, request)
	}
	f.requests = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		} else {
			request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted))
		}
	}
}

// closeFromStack detaches the ICMP handler and drops undecided requests.
func (f *ICMPForwarder) closeFromStack() {
	f.mu.Lock()
	if !f.forwarderRuntime.close() {
		f.mu.Unlock()
		return
	}
	requests := make([]*ICMPForwarderRequest, 0, len(f.requests))
	for request := range f.requests {
		requests = append(requests, request)
	}
	f.requests = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		} else {
			request.state.CompareAndSwap(uint32(forwarderRequestReplyStarted), uint32(forwarderRequestCompleted))
		}
	}
}

// Detach transfers one UDP request out of the synchronous handler lifetime.
// On success it removes the request from the forwarder's pending set and
// returns a caller-owned flow and payload snapshot. The responder points back
// to the originating forwarder's state for output and Done, but the forwarder does not
// retain the responder or impose a capacity or timeout. The caller may hand it
// to another goroutine or discard it without a terminal action. Detach itself
// is the request's action and consumes the request even when it returns an
// error. It may be called after any number of Reply or ReplyFrom attempts; the
// responder remains available for further replies.
func (r *UDPForwarderRequest) Detach() (*UDPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachWithInput)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

// DetachForReplies transfers the UDP request into an asynchronous responder
// that retains only Flow, reply operations, and Done. Payload returns nil, and
// Reject and Drop report net.ErrClosed. Unlike Detach, it does not copy the
// triggering payload or retain an ICMP rejection quote. The caller owns the
// responder and may discard it without a terminal action. RestrictToReplies is
// an idempotent no-op on the returned responder.
func (r *UDPForwarderRequest) DetachForReplies() (*UDPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachForReplies)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

// copyForwarderRejectPacket retains only the original bytes that an ICMP error
// is permitted to quote. Detached payload ownership is kept separately.
func copyForwarderRejectPacket(packet ipPacket) ipPacket {
	quoteLength := len(packet.original)
	if packet.source.Is4() {
		headerLength := int(packet.original[0]&0x0f) * 4
		if quoteLength > headerLength+8 {
			quoteLength = headerLength + 8
		}
	} else if maximum := ipv6MinimumMTU - 48; quoteLength > maximum {
		quoteLength = maximum
	}
	packet.payload = nil
	packet.original = append([]byte(nil), packet.original[:quoteLength]...)
	return packet
}

// copyForwarderPacket returns one independently owned packet whose parsed
// slices all refer to the same backing storage.
func copyForwarderPacket(packet ipPacket) ipPacket {
	original := append([]byte(nil), packet.original...)
	copied, ok := parseIPPacket(original)
	if !ok || copied.parameterError {
		return ipPacket{}
	}
	return copied
}

// detach transfers one UDP request while holding the forwarder lock. It copies
// input storage only when the caller retains input-dependent capabilities.
func (f *UDPForwarder) detach(request *UDPForwarderRequest, mode forwarderDetachMode) (*UDPForwarderResponder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(request.flow.Destination.Addr()) {
		return nil, syscall.EADDRNOTAVAIL
	}
	packet := request.packet
	var payload []byte
	if mode == forwarderDetachForReplies {
		packet.payload = nil
		packet.original = nil
	} else {
		packet = copyForwarderRejectPacket(packet)
		payload = append([]byte(nil), request.Payload()...)
	}
	responder := &UDPForwarderResponder{
		forwarderResponder: forwarderResponder{
			runtime: f.forwarderRuntime,
			packet:  packet,
		},
		flow:    request.flow,
		payload: payload,
	}
	if mode == forwarderDetachForReplies {
		responder.state.Store(uint32(forwarderResponderRepliesOnly))
	}
	key := udpFlowKey{local: request.flow.Destination, remote: request.flow.Source}
	if f.requests[key] == request {
		delete(f.requests, key)
	}
	request.state.Store(uint32(forwarderRequestDetached))
	return responder, nil
}

// Flow returns the detached datagram's original four-tuple.
func (r *UDPForwarderResponder) Flow() ForwarderFlow { return r.flow }

// Payload returns an independently owned copy of the triggering UDP payload.
// It returns nil after DetachForReplies or RestrictToReplies. The caller may
// retain or modify a returned slice and must synchronize concurrent access.
func (r *UDPForwarderResponder) Payload() []byte { return r.payload }

// RestrictToReplies irreversibly discards the triggering payload and rejection
// quote while retaining Flow, Reply, ReplyFrom, and Done. On success, Reject
// and Drop report net.ErrClosed. Calls made after a successful restriction or
// on a responder returned by DetachForReplies are no-ops that return nil. It
// reports net.ErrClosed only if the responder is terminal and does not itself
// count as a terminal action. The caller must invoke it while no other
// responder method is running. A previously returned Payload slice remains
// valid and keeps its storage live for as long as the caller retains it. After
// this method returns, Reply and ReplyFrom may again be called concurrently.
func (r *UDPForwarderResponder) RestrictToReplies() error {
	if err := r.restrictToReplies(); err != nil {
		return err
	}
	r.payload = nil
	r.packet.payload = nil
	r.packet.original = nil
	return nil
}

// Reply atomically queues one reverse-flow datagram from Destination to Source
// without waiting for outbound capacity. Use ReplyFrom to select a different
// source. It reports ErrResourceLimit without emitting partial fragments when
// the queue is full. Calls may be repeated or concurrent while the responder
// is active or restricted to replies, with no ordering guarantee between
// concurrent calls. Any call may be retried after failure; each call
// revalidates the forwarder and current destination policy and copies payload
// before returning. It reports net.ErrClosed after a terminal action or when
// the originating forwarder is closed.
func (r *UDPForwarderResponder) Reply(payload []byte) (int, error) {
	return r.replyFrom(payload, r.flow.Destination)
}

// ReplyFrom sends one datagram to Flow().Source with the caller-selected source
// IP address and UDP port. Source may be any valid address in the same family as
// Flow().Source; it need not belong to LocalAddresses and is not classified as
// unicast, multicast, or broadcast here. It is unzoned and unmapped, and port
// zero is preserved on the wire. Its lifecycle, ownership, concurrency, and
// output behavior match Reply.
func (r *UDPForwarderResponder) ReplyFrom(payload []byte, source netip.AddrPort) (int, error) {
	return r.replyFrom(payload, source)
}

// replyFrom records one detached output attempt and emits its datagram.
func (r *UDPForwarderResponder) replyFrom(payload []byte, source netip.AddrPort) (int, error) {
	if err := r.beginReply(); err != nil {
		return 0, err
	}
	validated, err := validateUDPForwarderReply(r.flow, payload, source)
	if err != nil {
		return 0, r.recordReply(err)
	}
	n, err := r.runtime.replyUDPFlow(r.flow, payload, validated)
	return n, r.recordReply(err)
}

// Reject terminates the detached datagram and attempts to enqueue ICMP Port
// Unreachable without waiting for outbound capacity. It remains valid after
// replies and revalidates the forwarder and current destination policy. Once
// selected, the rejection decision remains terminal on output error. It
// reports net.ErrClosed if the responder is already terminal or restricted to
// replies, including one returned by DetachForReplies, or if the originating
// forwarder is closed.
func (r *UDPForwarderResponder) Reject() error {
	if err := r.beginReject(); err != nil {
		return err
	}
	return r.runtime.stack.sendPortUnreachable(r.packet)
}

// Detach transfers one IP request out of the synchronous handler lifetime and
// on success removes it from the forwarder's pending set. It returns a
// caller-owned message snapshot whose responder points back to the originating
// forwarder's state for output and Done; the forwarder does not retain the
// responder. The caller may discard it without a terminal action. Detach may be
// called after any number of Reply attempts; the responder remains available
// for further replies.
func (r *IPForwarderRequest) Detach() (*IPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachWithInput)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

// DetachForReplies transfers the IP request into an asynchronous responder
// that retains only Message metadata, Reply, and Done. Message().Payload is
// nil, and Reject and Drop report net.ErrClosed. Unlike Detach, it does not
// copy the upper-layer payload or retain an ICMP rejection quote. The caller
// owns the responder and may discard it without a terminal action.
// RestrictToReplies is an idempotent no-op on the returned responder.
func (r *IPForwarderRequest) DetachForReplies() (*IPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachForReplies)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

// detach transfers one IP request while holding the forwarder lock. It copies
// input storage only when the caller retains input-dependent capabilities.
func (f *IPForwarder) detach(request *IPForwarderRequest, mode forwarderDetachMode) (*IPForwarderResponder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(request.packet.target) {
		return nil, syscall.EADDRNOTAVAIL
	}
	packet := request.packet
	var payload []byte
	if mode == forwarderDetachForReplies {
		packet.payload = nil
		packet.original = nil
	} else {
		packet = copyForwarderRejectPacket(packet)
		payload = append([]byte(nil), request.packet.payload...)
	}
	responder := &IPForwarderResponder{
		forwarderResponder: forwarderResponder{
			runtime: f.forwarderRuntime,
			packet:  packet,
		},
		message: ipForwarderMessage(packet, payload),
	}
	if mode == forwarderDetachForReplies {
		responder.state.Store(uint32(forwarderResponderRepliesOnly))
	}
	delete(f.requests, request)
	request.state.Store(uint32(forwarderRequestDetached))
	return responder, nil
}

// ipForwarderMessage constructs public metadata around supplied payload
// ownership.
func ipForwarderMessage(packet ipPacket, payload []byte) IPForwarderMessage {
	return IPForwarderMessage{
		Source: packet.source, Destination: packet.target, Protocol: packet.protocol,
		HopLimit: packet.hopLimit, TrafficClass: packet.trafficClass,
		FlowLabel: packet.flowLabel, Payload: payload,
	}
}

// reply validates current transparent-source and route policy before queuing
// one reverse protocol payload.
func (f *forwarderRuntime) replyIPPayload(packet ipPacket, payload []byte) error {
	network := f.stack.network.Load()
	if !network.acceptsInboundDestination(packet.target) {
		return syscall.EADDRNOTAVAIL
	}
	if _, routed := network.routeFor(packet.source); !routed {
		return syscall.ENETUNREACH
	}
	defaults := network.ipDefaults
	options := ipPacketOptions{
		hopLimit: byte(defaults.HopLimit), trafficClass: defaults.TrafficClass,
		flowLabel: defaults.FlowLabel, flowLabelSet: defaults.FlowLabel != 0,
	}
	mtu, fragmentation := f.stack.pathMTUOutputPolicy(packet.source, defaults.PathMTUDiscovery)
	packets, err := f.stack.ipPayloadPacketsForMTU(packet.target, packet.source, packet.protocol, payload, fragmentation, options, mtu)
	if err != nil {
		return err
	}
	return f.stack.tryWritePackets(packets)
}

// Message returns the detached IP metadata and independently owned payload.
// Payload is nil after DetachForReplies or RestrictToReplies. The caller may
// retain or modify a returned payload and must synchronize concurrent access.
func (r *IPForwarderResponder) Message() IPForwarderMessage { return r.message }

// RestrictToReplies irreversibly discards the upper-layer payload and rejection
// quote while retaining Message metadata, Reply, and Done. On success, Reject
// and Drop report net.ErrClosed. Calls made after a successful restriction or
// on a responder returned by DetachForReplies are no-ops that return nil. It
// reports net.ErrClosed only if the responder is terminal and does not itself
// count as a terminal action. The caller must invoke it while no other
// responder method is running. A previously returned Message().Payload slice
// remains valid and keeps its storage live for as long as the caller retains
// it. After this method returns, Reply may again be called concurrently.
func (r *IPForwarderResponder) RestrictToReplies() error {
	if err := r.restrictToReplies(); err != nil {
		return err
	}
	r.message.Payload = nil
	r.packet.payload = nil
	r.packet.original = nil
	return nil
}

// Reply atomically queues one reverse protocol payload without waiting for
// outbound capacity. Calls may be repeated or concurrent until a terminal
// action or while restricted to replies, with no ordering guarantee between
// concurrent calls. Failed calls may be retried, and Drop or Reject may follow
// any number of replies while the responder remains active. It reports
// net.ErrClosed after a terminal action or when the originating forwarder is
// closed.
func (r *IPForwarderResponder) Reply(payload []byte) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	return r.recordReply(r.runtime.replyIPPayload(r.packet, payload))
}

// Reject terminates the detached payload and attempts to enqueue a protocol-
// unreachable response. It remains valid after replies and revalidates current
// destination policy. It reports net.ErrClosed if the responder is already
// terminal or restricted to replies, including one returned by
// DetachForReplies, or if the originating forwarder is closed.
func (r *IPForwarderResponder) Reject() error {
	if err := r.beginReject(); err != nil {
		return err
	}
	return r.runtime.stack.sendProtocolUnreachable(r.packet)
}

// Detach transfers one ICMP request out of the synchronous handler lifetime.
// On success it removes the request from the forwarder's pending set and
// returns a caller-owned message snapshot. The responder points back to the
// originating forwarder's state for output and Done, but the forwarder does
// not retain the responder or impose a capacity or timeout. The caller may hand
// it to another goroutine or discard it without a terminal action. Detach
// itself is the request's action and consumes the request even when it returns
// an error. It may be called after any number of Reply, ReplyIPPacket, or
// ReplyEcho attempts; the responder remains available for further replies.
func (r *ICMPForwarderRequest) Detach() (*ICMPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachWithInput)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

// DetachForReplies transfers the ICMP request into an asynchronous responder
// that retains only Message metadata, Reply, ReplyIPPacket, and Done.
// Message().Payload and IPPacket return nil, while ReplyEcho, Reject, and Drop
// report net.ErrClosed. Unlike Detach, it does not copy the triggering packet
// or retain an ICMP rejection quote. The caller owns the responder and may
// discard it without a terminal action. RestrictToReplies is an idempotent
// no-op on the returned responder.
func (r *ICMPForwarderRequest) DetachForReplies() (*ICMPForwarderResponder, error) {
	_, ok := r.claim()
	if !ok {
		return nil, ErrForwarderRequestCompleted
	}
	responder, err := r.forwarder.detach(r, forwarderDetachForReplies)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

// detach transfers one ICMP request while holding the forwarder lock. It copies
// input storage only when the caller retains input-dependent capabilities.
func (f *ICMPForwarder) detach(request *ICMPForwarderRequest, mode forwarderDetachMode) (*ICMPForwarderResponder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(request.packet.target) {
		return nil, syscall.EADDRNOTAVAIL
	}
	packet := request.packet
	if mode == forwarderDetachForReplies {
		packet.payload = nil
		packet.original = nil
	} else {
		packet = copyForwarderPacket(packet)
		if len(packet.original) == 0 {
			return nil, syscall.EINVAL
		}
	}
	responder := &ICMPForwarderResponder{
		forwarderResponder: forwarderResponder{
			runtime: f.forwarderRuntime,
			packet:  packet,
		},
		message: ICMPForwarderMessage{
			Source: packet.source, Destination: packet.target,
			Type: request.packet.payload[0], Code: request.packet.payload[1], Payload: packet.payload,
		},
	}
	if mode == forwarderDetachForReplies {
		responder.state.Store(uint32(forwarderResponderRepliesOnly))
	} else {
		responder.rejectPacket = copyForwarderRejectPacket(request.packet)
		responder.rejectable = !packetInvokesICMPError(request.packet.original)
	}
	delete(f.requests, request)
	request.state.Store(uint32(forwarderRequestDetached))
	return responder, nil
}

// Message returns the detached ICMP metadata and independently owned payload.
// Payload is nil after DetachForReplies or RestrictToReplies. The caller may
// retain or modify a returned payload and must synchronize concurrent access.
// Type and Code remain the original classification; changing the first two
// Payload bytes makes the snapshot inconsistent and causes ReplyEcho to report
// syscall.EINVAL.
func (r *ICMPForwarderResponder) Message() ICMPForwarderMessage { return r.message }

// IPPacket returns the complete, reassembled packet snapshot retained by
// Detach, or nil after DetachForReplies or RestrictToReplies. The caller owns a
// returned slice and may retain or modify it, but must synchronize concurrent
// access. Message().Payload aliases its ICMP region.
func (r *ICMPForwarderResponder) IPPacket() []byte { return r.packet.original }

// RestrictToReplies irreversibly discards the complete packet, message payload,
// and rejection quote while retaining Message metadata, Reply, ReplyIPPacket,
// and Done. On success, ReplyEcho, Reject, and Drop report net.ErrClosed.
// Calls made after a successful restriction or on a responder returned by
// DetachForReplies are no-ops that return nil. It reports net.ErrClosed only if
// the responder is terminal and does not itself count as a terminal action.
// The caller must invoke it while no other responder method is running.
// Previously returned snapshots remain valid and keep their storage live for
// as long as the caller retains them. After this method returns, Reply and
// ReplyIPPacket may again be called concurrently.
func (r *ICMPForwarderResponder) RestrictToReplies() error {
	if err := r.restrictToReplies(); err != nil {
		return err
	}
	r.message.Payload = nil
	r.packet.payload = nil
	r.packet.original = nil
	r.rejectPacket = ipPacket{}
	r.rejectable = false
	return nil
}

// Reply atomically queues one reverse ICMP message without waiting for
// outbound capacity. It reports ErrResourceLimit without emitting partial
// fragments when the queue is full. Calls may be repeated or concurrent until
// a terminal action or while restricted to replies, with no ordering guarantee
// between concurrent calls. Any call may be retried after failure; each call
// revalidates the forwarder and current destination policy and copies payload
// before returning. It reports net.ErrClosed after a terminal action or when
// the originating forwarder is closed.
func (r *ICMPForwarderResponder) Reply(payload []byte) error {
	return r.reply(payload, false)
}

// reply records one detached output attempt and writes either borrowed or
// stack-owned payload storage.
func (r *ICMPForwarderResponder) reply(payload []byte, owned bool) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	return r.writeReply(payload, owned)
}

// writeReply emits one reply after the detached output attempt was recorded.
func (r *ICMPForwarderResponder) writeReply(payload []byte, owned bool) error {
	var err error
	if owned {
		err = r.runtime.stack.writeOwnedICMPReply(r.packet, payload)
	} else {
		err = r.runtime.stack.writeICMPReply(r.packet, payload)
	}
	return r.recordReply(err)
}

// ReplyIPPacket is the detached form of ICMPForwarderRequest.ReplyIPPacket.
// Calls may be repeated or concurrent until a terminal action or while
// restricted to replies. The packet is copied before return, concurrent calls
// have no ordering guarantee, and a failed call may be retried or followed by
// Drop or Reject while the responder remains active. It reports net.ErrClosed
// after a terminal action or when the originating forwarder is closed.
func (r *ICMPForwarderResponder) ReplyIPPacket(packet []byte) error {
	if err := r.beginReply(); err != nil {
		return err
	}
	reply, err := prepareICMPForwarderIPPacket(packet, r.packet.source)
	if err != nil {
		return r.recordReply(err)
	}
	return r.recordReply(r.runtime.stack.writeICMPForwarderIPPacket(r.packet, reply))
}

// ReplyEcho copies the detached Echo Request into an Echo Reply, preserving its
// identifier, sequence, and data. It reports syscall.EINVAL when the retained
// message is not an IPv4 or IPv6 Echo Request. Calls may be repeated or
// concurrent until a terminal action and may be followed by Drop or Reject. It
// reports net.ErrClosed if the responder is terminal or restricted to replies,
// including one returned by DetachForReplies, or if the originating forwarder
// is closed.
func (r *ICMPForwarderResponder) ReplyEcho() error {
	if err := r.beginInputReply(); err != nil {
		return err
	}
	if !r.message.IsEchoRequest() {
		return r.recordReply(syscall.EINVAL)
	}
	reply, ok := makeICMPEchoReply(r.packet.protocol, r.message.Payload)
	if !ok {
		return r.recordReply(syscall.EINVAL)
	}
	return r.writeReply(reply, true)
}

// Reject terminates the detached message and attempts to enqueue an
// administratively prohibited response without waiting for outbound capacity.
// It remains valid after replies and revalidates the forwarder and current
// destination policy. Once selected, the decision remains terminal on output
// error. It reports net.ErrClosed if the responder is already terminal or
// restricted to replies, including one returned by DetachForReplies, or if the
// originating forwarder is closed.
func (r *ICMPForwarderResponder) Reject() error {
	if err := r.beginReject(); err != nil {
		return err
	}
	var err error
	if r.rejectable {
		err = r.runtime.stack.sendAdministrativeUnreachable(r.rejectPacket)
	}
	return err
}
