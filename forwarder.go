package mipstack

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
)

// TransportFlow identifies one inbound TCP or UDP four-tuple. Source is the
// remote endpoint and Destination is the original packet destination.
type TransportFlow struct {
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
// handler must call Accept, Listen, Detach, Drop, Reject, or at least one Reply
// before returning; returning without an action drops the datagram. Reply may
// be repeated after it selects callback-scoped reply mode. Except for Detach,
// every action and Reply call must finish before the handler returns. The
// request and its Payload must not be retained after that point, but a UDPConn
// returned by Accept or Listen and a responder returned by Detach have
// independent lifetimes. The initial datagram remains subject to the returned
// UDPConn's configured receive capacity.
type UDPForwarderHandler func(*UDPForwarderRequest)

// ICMPForwarderHandler processes one checksum-valid ICMP message not consumed
// by the stack's built-in echo or asynchronous-error handling. Its synchronous,
// concurrent-call, and blocking rules are the same as UDPForwarderHandler.
// The handler must call Detach, Drop, Reject, or at least one Reply before
// returning; returning without an action drops the message. Reply may be
// repeated after it selects callback-scoped reply mode. Except for Detach,
// every action and Reply call must finish before the handler returns. The
// request and Message.Payload must not be retained after that point, but a
// responder returned by Detach has an independent lifetime.
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
	// ReplyErrors counts failed reply attempts after reply mode was selected.
	ReplyErrors uint64
	// Dropped counts explicit, implicit, invalidated, and capacity drops.
	Dropped uint64
	// Rejected counts explicit protocol rejection decisions.
	Rejected uint64
}

// forwarderRequestState serializes the exactly-once action selected for a
// request while allowing configuration and forwarder closure to invalidate it.
type forwarderRequestState uint32

const (
	// forwarderRequestPending has not yet selected an action.
	forwarderRequestPending forwarderRequestState = iota
	// forwarderRequestClaimed is performing a terminal endpoint or ownership
	// action.
	forwarderRequestClaimed
	// forwarderRequestReplying permits repeatable Reply calls until the
	// synchronous handler returns.
	forwarderRequestReplying
	// forwarderRequestDetached transferred ownership to an asynchronous
	// responder and prevents further use of the callback-scoped request.
	forwarderRequestDetached
	// forwarderRequestAccepted successfully created output or an endpoint.
	forwarderRequestAccepted
	// forwarderRequestDropped consumed input without a protocol response.
	forwarderRequestDropped
	// forwarderRequestRejected selected an explicit protocol rejection.
	forwarderRequestRejected
	// forwarderRequestCompleted ended callback-scoped reply mode regardless of
	// individual output results.
	forwarderRequestCompleted
)

// forwarderResponderState separates a detached responder's repeatable output
// lifetime from the callback-scoped request action that created it.
type forwarderResponderState uint32

const (
	// forwarderResponderPending has not selected reply, rejection, or drop.
	forwarderResponderPending forwarderResponderState = iota
	// forwarderResponderActive permits repeatable and concurrent Reply calls.
	forwarderResponderActive
	// forwarderResponderClosed rejects every later action.
	forwarderResponderClosed
)

// forwarderRequestActionError distinguishes active reply mode from a terminal
// or invalidated callback-scoped request.
func forwarderRequestActionError(state uint32) error {
	if forwarderRequestState(state) == forwarderRequestReplying {
		return ErrForwarderReplyActive
	}
	return ErrForwarderRequestCompleted
}

// forwarderResponderActionError distinguishes active reply mode from a closed
// caller-owned responder.
func forwarderResponderActionError(state uint32) error {
	if forwarderResponderState(state) == forwarderResponderActive {
		return ErrForwarderReplyActive
	}
	return net.ErrClosed
}

// forwarderResponderLifecycle owns the protocol-independent Pending, Active,
// and Closed transitions of one caller-owned responder.
type forwarderResponderLifecycle struct {
	state atomic.Uint32
}

// beginReply selects or continues repeatable reply mode.
func (l *forwarderResponderLifecycle) beginReply() error {
	for {
		switch forwarderResponderState(l.state.Load()) {
		case forwarderResponderPending:
			if !l.state.CompareAndSwap(uint32(forwarderResponderPending), uint32(forwarderResponderActive)) {
				continue
			}
			return nil
		case forwarderResponderActive:
			return nil
		default:
			return net.ErrClosed
		}
	}
}

// closePending selects a terminal action only before reply mode begins.
func (l *forwarderResponderLifecycle) closePending() error {
	if !l.state.CompareAndSwap(uint32(forwarderResponderPending), uint32(forwarderResponderClosed)) {
		return forwarderResponderActionError(l.state.Load())
	}
	return nil
}

// close terminates either Pending or Active state and reports which one ended.
func (l *forwarderResponderLifecycle) close() (pending bool, err error) {
	for {
		state := forwarderResponderState(l.state.Load())
		if state == forwarderResponderClosed {
			return false, net.ErrClosed
		}
		if !l.state.CompareAndSwap(uint32(state), uint32(forwarderResponderClosed)) {
			continue
		}
		return state == forwarderResponderPending, nil
	}
}

// TCPForwarder owns the single fallback TCP handler installed on a stack. It
// may be installed before or after Stack.Start.
type TCPForwarder struct {
	stack       *Stack
	handler     TCPForwarderHandler
	maxInFlight int

	mu       sync.Mutex
	closed   atomic.Bool
	done     chan struct{}
	requests map[tcpKey]*TCPForwarderRequest
	handlers map[*TCPForwarderRequest]struct{}

	requestCount atomic.Uint64
	accepted     atomic.Uint64
	replies      atomic.Uint64
	replyErrors  atomic.Uint64
	dropped      atomic.Uint64
	rejected     atomic.Uint64
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
	stack   *Stack
	handler UDPForwarderHandler

	mu       sync.Mutex
	closed   atomic.Bool
	done     chan struct{}
	requests map[udpFlowKey]*UDPForwarderRequest

	requestCount atomic.Uint64
	accepted     atomic.Uint64
	replies      atomic.Uint64
	replyErrors  atomic.Uint64
	dropped      atomic.Uint64
	rejected     atomic.Uint64
}

// UDPForwarderRequest is one valid datagram that did not match an ordinary or
// previously forwarded UDP endpoint. The handler may select one terminal
// action or enter repeatable reply mode. Payload is valid only until the
// handler returns; Accept and Listen offer a copy to the returned UDPConn's
// capacity-bounded receive queue.
type UDPForwarderRequest struct {
	forwarder *UDPForwarder
	flow      TransportFlow
	packet    ipPacket
	options   ipPacketOptions
	state     atomic.Uint32
}

// UDPForwarderResponder owns one detached datagram snapshot. It may outlive
// the handler and permits repeatable Reply calls until Close. Reject and Drop
// are available only before the first Reply begins. The caller owns its
// lifetime, concurrency bound, and timeout; the forwarder does not retain it.
type UDPForwarderResponder struct {
	forwarder *UDPForwarder
	flow      TransportFlow
	payload   []byte
	packet    ipPacket
	lifecycle forwarderResponderLifecycle
}

// ICMPMessage describes one checksum-validated, reassembled ICMP protocol
// message. Payload contains the complete ICMP header and body. Its ownership
// and lifetime are specified by the method that returned the message.
type ICMPMessage struct {
	// Source is the sender of the ICMP message.
	Source netip.Addr
	// Destination is the original packet destination.
	Destination netip.Addr
	// Type and Code retain the wire classification. Unknown or unassigned
	// values can reach an ICMP forwarder when no built-in handler consumes them.
	Type uint8
	Code uint8
	// Payload contains the complete ICMP header and body.
	Payload []byte
}

// IsEchoRequest reports whether the message is a complete IPv4 or IPv6 Echo
// Request whose Type and Code fields agree with Payload. Source and Destination
// must identify the same address family.
func (m ICMPMessage) IsEchoRequest() bool {
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
	stack   *Stack
	handler ICMPForwarderHandler

	mu       sync.Mutex
	closed   atomic.Bool
	done     chan struct{}
	requests map[*ICMPForwarderRequest]struct{}

	requestCount atomic.Uint64
	accepted     atomic.Uint64
	replies      atomic.Uint64
	replyErrors  atomic.Uint64
	dropped      atomic.Uint64
	rejected     atomic.Uint64
}

// ICMPForwarderRequest is one checksum-valid ICMP message not consumed by
// built-in protocol handling. The handler may select one terminal action or
// enter repeatable reply mode.
type ICMPForwarderRequest struct {
	forwarder *ICMPForwarder
	packet    ipPacket
	state     atomic.Uint32
}

// ICMPForwarderResponder owns one detached message snapshot. It may outlive
// the handler and permits repeatable Reply calls until Close. Reject and Drop
// are available only before the first Reply begins. The caller owns its
// lifetime, concurrency bound, and timeout; the forwarder does not retain it.
type ICMPForwarderResponder struct {
	forwarder  *ICMPForwarder
	message    ICMPMessage
	packet     ipPacket
	rejectable bool
	lifecycle  forwarderResponderLifecycle
}

// tcpForwarderEndpoints is the small dispatch surface retained by Stack.
type tcpForwarderEndpoints interface {
	handleSegment(segment tcpSegment, key tcpKey) bool
	updateConfig(network *networkState)
	closeFromStack()
}

// udpForwarderEndpoints is the small dispatch surface retained by Stack.
type udpForwarderEndpoints interface {
	handlePacket(packet ipPacket, flow TransportFlow, options ipPacketOptions) bool
	updateConfig(network *networkState)
	closeFromStack()
}

// icmpForwarderEndpoints is the small dispatch surface retained by Stack.
type icmpForwarderEndpoints interface {
	handlePacket(packet ipPacket) bool
	updateConfig(network *networkState)
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
		stack: stack, handler: handler, maxInFlight: maximum,
		done: make(chan struct{}), requests: make(map[tcpKey]*TCPForwarderRequest),
		handlers: make(map[*TCPForwarderRequest]struct{}),
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
		stack: stack, handler: handler,
		done: make(chan struct{}), requests: make(map[udpFlowKey]*UDPForwarderRequest),
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
		stack: stack, handler: handler,
		done: make(chan struct{}), requests: make(map[*ICMPForwarderRequest]struct{}),
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
func (r *TCPForwarderRequest) Flow() TransportFlow {
	return TransportFlow{Source: r.key.remote, Destination: r.key.local}
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
// it. Accept consumes the request even when it returns an error.
func (r *TCPForwarderRequest) Accept(ctx context.Context) (*TCPConn, error) {
	if ctx == nil {
		panic("nil Context")
	}
	if !r.claim() {
		return nil, forwarderRequestActionError(r.state.Load())
	}
	connection, result, err := r.forwarder.acceptTCP(r)
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
		return forwarderRequestActionError(r.state.Load())
	}
	return nil
}

// Reject consumes the TCP request and attempts to enqueue the RFC 9293 reset
// response without waiting for outbound capacity. It reports ErrResourceLimit
// when the queue is full; the rejection decision remains terminal.
func (r *TCPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return forwarderRequestActionError(r.state.Load())
	}
	return r.forwarder.stack.rejectTCPSegment(r.key, r.segment)
}

// Flow returns the original inbound UDP four-tuple. The method may be called
// only during the handler, but the returned value is an independent copy that
// may be retained.
func (r *UDPForwarderRequest) Flow() TransportFlow { return r.flow }

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
// request even when it returns an error.
func (r *UDPForwarderRequest) Accept() (*UDPConn, error) {
	if !r.claim() {
		return nil, forwarderRequestActionError(r.state.Load())
	}
	connection, err := r.forwarder.acceptUDP(r)
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
// request even when it returns an error.
func (r *UDPForwarderRequest) Listen() (*UDPConn, error) {
	if !r.claim() {
		return nil, forwarderRequestActionError(r.state.Load())
	}
	connection, err := r.forwarder.listenUDP(r)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	r.finish(forwarderRequestAccepted)
	return connection, nil
}

// Reply sends one reverse-flow datagram from Destination to Source without
// retaining a UDP endpoint. The first call selects reply mode; calls may be
// repeated or concurrent but must all finish before the handler returns. Each
// call atomically queues the complete datagram without waiting for outbound
// capacity and may be retried after any error. Once reply mode begins, other
// request actions report ErrForwarderReplyActive.
func (r *UDPForwarderRequest) Reply(payload []byte) (int, error) {
	if err := r.beginReply(); err != nil {
		return 0, err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return 0, net.ErrClosed
	}
	n, err := r.forwarder.replyUDP(r, payload)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return n, err
	}
	r.forwarder.replies.Add(1)
	return n, nil
}

// Drop consumes the UDP datagram without packet I/O. It may wait briefly for
// forwarder bookkeeping but does not wait for the network or output queue.
func (r *UDPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return forwarderRequestActionError(r.state.Load())
	}
	return nil
}

// Reject consumes the UDP datagram and attempts to enqueue ICMP Port
// Unreachable without waiting for outbound capacity. It reports
// ErrResourceLimit when the queue is full; the rejection decision remains
// terminal.
func (r *UDPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return forwarderRequestActionError(r.state.Load())
	}
	return r.forwarder.stack.sendPortUnreachable(r.packet)
}

// Message returns the checksum-validated ICMP message presented to the handler.
// Payload aliases packet-delivery storage, must not be modified, and is valid
// only until the handler returns. Message does not select an action.
func (r *ICMPForwarderRequest) Message() ICMPMessage {
	return ICMPMessage{
		Source: r.packet.source, Destination: r.packet.target,
		Type: r.packet.payload[0], Code: r.packet.payload[1], Payload: r.packet.payload,
	}
}

// Reply sends a complete ICMP protocol message from Destination to Source. The
// first call selects reply mode; calls may be repeated or concurrent but must
// all finish before the handler returns. The stack copies payload, recalculates
// its checksum, and atomically queues every required fragment without waiting
// for outbound capacity. A call may be retried after any error; once reply mode
// begins, other request actions report ErrForwarderReplyActive.
func (r *ICMPForwarderRequest) Reply(payload []byte) error {
	return r.reply(payload, false)
}

// reply selects callback-scoped reply mode and writes either borrowed or
// stack-owned payload storage.
func (r *ICMPForwarderRequest) reply(payload []byte, owned bool) error {
	if err := r.beginReply(); err != nil {
		return err
	}
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

// ReplyEcho copies the triggering Echo Request into an Echo Reply, preserving
// its identifier, sequence, and data. It reports syscall.EINVAL without
// selecting an action when the triggering message is not an IPv4 or IPv6 Echo
// Request. Like Reply, it may be repeated but every call must finish before the
// handler returns.
func (r *ICMPForwarderRequest) ReplyEcho() error {
	switch forwarderRequestState(r.state.Load()) {
	case forwarderRequestPending, forwarderRequestReplying:
	default:
		return forwarderRequestActionError(r.state.Load())
	}
	reply, ok := makeICMPEchoReply(r.packet.protocol, r.packet.payload)
	if !ok {
		return syscall.EINVAL
	}
	return r.reply(reply, true)
}

// Drop consumes the ICMP message without packet I/O. It may wait briefly for
// forwarder bookkeeping but does not wait for the network or output queue.
func (r *ICMPForwarderRequest) Drop() error {
	if !r.complete(forwarderRequestDropped) {
		return forwarderRequestActionError(r.state.Load())
	}
	return nil
}

// Reject consumes the ICMP message and emits an administratively prohibited
// response when ICMP rules permit an error response. It does not wait for
// outbound capacity and reports ErrResourceLimit when the queue is full; the
// rejection decision remains terminal.
func (r *ICMPForwarderRequest) Reject() error {
	if !r.complete(forwarderRequestRejected) {
		return forwarderRequestActionError(r.state.Load())
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

// Done is closed when the TCP forwarder is closed directly or by Stack.Close.
func (f *TCPForwarder) Done() <-chan struct{} { return f.done }

// Done is closed when the UDP forwarder is closed directly or by Stack.Close.
func (f *UDPForwarder) Done() <-chan struct{} { return f.done }

// Done is closed when the ICMP forwarder is closed directly or by Stack.Close.
func (f *ICMPForwarder) Done() <-chan struct{} { return f.done }

// Info returns one TCP forwarder diagnostic snapshot.
func (f *TCPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	info := ForwarderInfo{Closed: f.closed.Load(), Pending: len(f.requests), MaxInFlight: f.maxInFlight}
	f.mu.Unlock()
	info.Requests, info.Accepted = f.requestCount.Load(), f.accepted.Load()
	info.Replies, info.ReplyErrors = f.replies.Load(), f.replyErrors.Load()
	info.Dropped, info.Rejected = f.dropped.Load(), f.rejected.Load()
	return info
}

// Info returns one UDP forwarder diagnostic snapshot.
func (f *UDPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	info := ForwarderInfo{Closed: f.closed.Load(), Pending: len(f.requests)}
	f.mu.Unlock()
	info.Requests, info.Accepted = f.requestCount.Load(), f.accepted.Load()
	info.Replies, info.ReplyErrors = f.replies.Load(), f.replyErrors.Load()
	info.Dropped, info.Rejected = f.dropped.Load(), f.rejected.Load()
	return info
}

// Info returns one ICMP forwarder diagnostic snapshot.
func (f *ICMPForwarder) Info() ForwarderInfo {
	f.mu.Lock()
	info := ForwarderInfo{Closed: f.closed.Load(), Pending: len(f.requests)}
	f.mu.Unlock()
	info.Requests, info.Accepted = f.requestCount.Load(), f.accepted.Load()
	info.Replies, info.ReplyErrors = f.replies.Load(), f.replyErrors.Load()
	info.Dropped, info.Rejected = f.dropped.Load(), f.rejected.Load()
	return info
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
func (f *UDPForwarder) handlePacket(packet ipPacket, flow TransportFlow, options ipPacketOptions) bool {
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

// claim reserves the UDP request for a non-Reply action.
func (r *UDPForwarderRequest) claim() bool {
	return r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestClaimed))
}

// beginReply selects repeatable callback-scoped reply mode and releases the
// tuple so later datagrams need not wait for this handler to return.
func (r *UDPForwarderRequest) beginReply() error {
	for {
		switch forwarderRequestState(r.state.Load()) {
		case forwarderRequestPending:
			if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestReplying)) {
				continue
			}
			r.forwarder.remove(r)
			return nil
		case forwarderRequestReplying:
			return nil
		default:
			return ErrForwarderRequestCompleted
		}
	}
}

// finishHandler closes reply mode or implicitly drops an undecided datagram.
func (r *UDPForwarderRequest) finishHandler() {
	if r.complete(forwarderRequestDropped) {
		return
	}
	r.state.CompareAndSwap(uint32(forwarderRequestReplying), uint32(forwarderRequestCompleted))
}

// complete publishes an immediate terminal UDP action.
func (r *UDPForwarderRequest) complete(state forwarderRequestState) bool {
	if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(state)) {
		return false
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

// claim reserves the ICMP request for a non-Reply action.
func (r *ICMPForwarderRequest) claim() bool {
	return r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestClaimed))
}

// beginReply selects repeatable callback-scoped reply mode and releases the
// request from forwarder bookkeeping.
func (r *ICMPForwarderRequest) beginReply() error {
	for {
		switch forwarderRequestState(r.state.Load()) {
		case forwarderRequestPending:
			if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestReplying)) {
				continue
			}
			r.forwarder.remove(r)
			return nil
		case forwarderRequestReplying:
			return nil
		default:
			return ErrForwarderRequestCompleted
		}
	}
}

// finishHandler closes reply mode or implicitly drops an undecided message.
func (r *ICMPForwarderRequest) finishHandler() {
	if r.complete(forwarderRequestDropped) {
		return
	}
	r.state.CompareAndSwap(uint32(forwarderRequestReplying), uint32(forwarderRequestCompleted))
}

// complete publishes an immediate terminal ICMP action.
func (r *ICMPForwarderRequest) complete(state forwarderRequestState) bool {
	if !r.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(state)) {
		return false
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

// count updates the TCP action counter for one terminal state.
func (f *TCPForwarder) count(state forwarderRequestState) {
	switch state {
	case forwarderRequestAccepted:
		f.accepted.Add(1)
	case forwarderRequestDropped:
		f.dropped.Add(1)
	case forwarderRequestRejected:
		f.rejected.Add(1)
	}
}

// count updates the UDP action counter for one terminal state.
func (f *UDPForwarder) count(state forwarderRequestState) {
	switch state {
	case forwarderRequestAccepted:
		f.accepted.Add(1)
	case forwarderRequestDropped:
		f.dropped.Add(1)
	case forwarderRequestRejected:
		f.rejected.Add(1)
	}
}

// count updates the ICMP action counter for one terminal state.
func (f *ICMPForwarder) count(state forwarderRequestState) {
	switch state {
	case forwarderRequestAccepted:
		f.accepted.Add(1)
	case forwarderRequestDropped:
		f.dropped.Add(1)
	case forwarderRequestRejected:
		f.rejected.Add(1)
	}
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
		}
	}
	f.mu.Unlock()
}

// closeFromStack detaches the TCP handler and drops undecided requests.
func (f *TCPForwarder) closeFromStack() {
	f.mu.Lock()
	if f.closed.Swap(true) {
		f.mu.Unlock()
		return
	}
	close(f.done)
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
	if f.closed.Swap(true) {
		f.mu.Unlock()
		return
	}
	close(f.done)
	requests := make([]*UDPForwarderRequest, 0, len(f.requests))
	for _, request := range f.requests {
		requests = append(requests, request)
	}
	f.requests = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		}
	}
}

// closeFromStack detaches the ICMP handler and drops undecided requests.
func (f *ICMPForwarder) closeFromStack() {
	f.mu.Lock()
	if f.closed.Swap(true) {
		f.mu.Unlock()
		return
	}
	close(f.done)
	requests := make([]*ICMPForwarderRequest, 0, len(f.requests))
	for request := range f.requests {
		requests = append(requests, request)
	}
	f.requests = nil
	f.mu.Unlock()
	for _, request := range requests {
		if request.state.CompareAndSwap(uint32(forwarderRequestPending), uint32(forwarderRequestDropped)) {
			f.dropped.Add(1)
		}
	}
}

// Detach transfers one UDP request out of the synchronous handler lifetime.
// It returns an independently owned flow and payload snapshot whose responder
// may be handed to another goroutine. The forwarder does not retain the
// responder or impose a capacity or timeout; the caller must bound its
// lifetime and eventually close it. Detach itself is the request's action and
// consumes the request even when it returns an error.
func (r *UDPForwarderRequest) Detach() (*UDPForwarderResponder, error) {
	if !r.claim() {
		return nil, forwarderRequestActionError(r.state.Load())
	}
	responder, err := r.forwarder.detach(r)
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

// detach copies one UDP request into caller-owned storage while holding the
// forwarder lock. No reference to the responder is retained by the stack.
func (f *UDPForwarder) detach(request *UDPForwarderRequest) (*UDPForwarderResponder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(request.flow.Destination.Addr()) {
		return nil, syscall.EADDRNOTAVAIL
	}
	responder := &UDPForwarderResponder{
		forwarder: f, flow: request.flow, payload: append([]byte(nil), request.Payload()...),
		packet: copyForwarderRejectPacket(request.packet),
	}
	key := udpFlowKey{local: request.flow.Destination, remote: request.flow.Source}
	if f.requests[key] == request {
		delete(f.requests, key)
	}
	request.state.Store(uint32(forwarderRequestDetached))
	return responder, nil
}

// Flow returns the detached datagram's original four-tuple.
func (r *UDPForwarderResponder) Flow() TransportFlow { return r.flow }

// Payload returns an independently owned copy of the triggering UDP payload.
// The caller may retain or modify it and must synchronize concurrent access.
func (r *UDPForwarderResponder) Payload() []byte { return r.payload }

// beginReply atomically enters or continues repeatable reply mode before
// validating the current output policy.
func (r *UDPForwarderResponder) beginReply() error {
	if err := r.lifecycle.beginReply(); err != nil {
		return err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return net.ErrClosed
	}
	if !r.forwarder.stack.network.Load().acceptsInboundDestination(r.flow.Destination.Addr()) {
		r.forwarder.replyErrors.Add(1)
		return syscall.EADDRNOTAVAIL
	}
	return nil
}

// Reply atomically queues one reverse-flow datagram without waiting for
// outbound capacity. It reports ErrResourceLimit without emitting partial
// fragments when the queue is full. Calls may be repeated or concurrent until
// Close, with no ordering guarantee between concurrent calls. The first call
// selects reply mode before validation, and an output error does not close the
// responder. Each call revalidates the forwarder and current destination
// policy and copies payload before returning.
func (r *UDPForwarderResponder) Reply(payload []byte) (int, error) {
	if err := r.beginReply(); err != nil {
		return 0, err
	}
	n, err := r.forwarder.replyUDPFlow(r.flow, payload)
	if err != nil {
		r.forwarder.replyErrors.Add(1)
		return n, err
	}
	r.forwarder.replies.Add(1)
	return n, nil
}

// Drop completes the detached datagram without packet I/O. It is valid only
// before the first Reply begins; use Close to finish an active responder.
// Drop reports ErrForwarderReplyActive in reply mode and net.ErrClosed after
// closure.
func (r *UDPForwarderResponder) Drop() error {
	if err := r.lifecycle.closePending(); err != nil {
		return err
	}
	r.forwarder.count(forwarderRequestDropped)
	return nil
}

// Reject attempts to enqueue ICMP Port Unreachable without waiting for
// outbound capacity. It is valid only before the first Reply begins and
// revalidates the forwarder and current destination policy. Once selected,
// the rejection decision remains terminal on output error. Reject reports
// ErrForwarderReplyActive in reply mode and net.ErrClosed after closure.
func (r *UDPForwarderResponder) Reject() error {
	if err := r.lifecycle.closePending(); err != nil {
		return err
	}
	r.forwarder.count(forwarderRequestRejected)
	if r.forwarder.closed.Load() {
		return net.ErrClosed
	}
	if !r.forwarder.stack.network.Load().acceptsInboundDestination(r.flow.Destination.Addr()) {
		return syscall.EADDRNOTAVAIL
	}
	return r.forwarder.stack.sendPortUnreachable(r.packet)
}

// Close prevents new Reply calls. A Reply that began before Close may finish.
// Closing a responder before its first Reply is equivalent to Drop. Close is
// a logical state transition and does not wait for concurrent calls; it reports
// net.ErrClosed after a previous terminal action.
func (r *UDPForwarderResponder) Close() error {
	pending, err := r.lifecycle.close()
	if err != nil {
		return err
	}
	if pending {
		r.forwarder.count(forwarderRequestDropped)
	}
	return nil
}

// Done is closed when the originating UDP forwarder is closed. Configuration
// changes remain dynamic and are revalidated by each Reply.
func (r *UDPForwarderResponder) Done() <-chan struct{} { return r.forwarder.done }

// Detach transfers one ICMP request out of the synchronous handler lifetime.
// It returns an independently owned message snapshot whose responder may be
// handed to another goroutine. The forwarder does not retain the responder or
// impose a capacity or timeout; the caller must bound its lifetime and
// eventually close it. Detach itself is the request's action and consumes the
// request even when it returns an error.
func (r *ICMPForwarderRequest) Detach() (*ICMPForwarderResponder, error) {
	if !r.claim() {
		return nil, forwarderRequestActionError(r.state.Load())
	}
	responder, err := r.forwarder.detach(r)
	if err != nil {
		r.finish(forwarderRequestDropped)
		return nil, err
	}
	return responder, nil
}

// detach copies one ICMP request into caller-owned storage while holding the
// forwarder lock. No reference to the responder is retained by the stack.
func (f *ICMPForwarder) detach(request *ICMPForwarderRequest) (*ICMPForwarderResponder, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed.Load() {
		return nil, net.ErrClosed
	}
	if !f.stack.network.Load().acceptsInboundDestination(request.packet.target) {
		return nil, syscall.EADDRNOTAVAIL
	}
	payload := append([]byte(nil), request.packet.payload...)
	responder := &ICMPForwarderResponder{
		forwarder: f,
		message: ICMPMessage{
			Source: request.packet.source, Destination: request.packet.target,
			Type: payload[0], Code: payload[1], Payload: payload,
		},
		packet:     copyForwarderRejectPacket(request.packet),
		rejectable: !packetInvokesICMPError(request.packet.original),
	}
	delete(f.requests, request)
	request.state.Store(uint32(forwarderRequestDetached))
	return responder, nil
}

// Message returns the detached, independently owned ICMP message snapshot.
// The caller may retain or modify Payload and must synchronize concurrent
// access. Type and Code remain the original classification; changing the first
// two Payload bytes makes the snapshot inconsistent and causes ReplyEcho to
// report syscall.EINVAL.
func (r *ICMPForwarderResponder) Message() ICMPMessage { return r.message }

// beginReply atomically enters or continues repeatable reply mode before
// validating the current output policy.
func (r *ICMPForwarderResponder) beginReply() error {
	if err := r.lifecycle.beginReply(); err != nil {
		return err
	}
	if r.forwarder.closed.Load() {
		r.forwarder.replyErrors.Add(1)
		return net.ErrClosed
	}
	if !r.forwarder.stack.network.Load().acceptsInboundDestination(r.message.Destination) {
		r.forwarder.replyErrors.Add(1)
		return syscall.EADDRNOTAVAIL
	}
	return nil
}

// Reply atomically queues one reverse ICMP message without waiting for
// outbound capacity. It reports ErrResourceLimit without emitting partial
// fragments when the queue is full. Calls may be repeated or concurrent until
// Close, with no ordering guarantee between concurrent calls. The first call
// selects reply mode before validation, and an output error does not close the
// responder. Each call revalidates the forwarder and current destination
// policy and copies payload before returning.
func (r *ICMPForwarderResponder) Reply(payload []byte) error {
	return r.reply(payload, false)
}

// reply selects detached reply mode and writes either borrowed or stack-owned
// payload storage.
func (r *ICMPForwarderResponder) reply(payload []byte, owned bool) error {
	if err := r.beginReply(); err != nil {
		return err
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

// ReplyEcho copies the detached Echo Request into an Echo Reply, preserving its
// identifier, sequence, and data. It reports syscall.EINVAL without selecting
// reply mode when the retained message is not an IPv4 or IPv6 Echo Request.
// Calls may be repeated or concurrent until Close.
func (r *ICMPForwarderResponder) ReplyEcho() error {
	if forwarderResponderState(r.lifecycle.state.Load()) == forwarderResponderClosed {
		return net.ErrClosed
	}
	if !r.message.IsEchoRequest() {
		return syscall.EINVAL
	}
	reply, ok := makeICMPEchoReply(r.packet.protocol, r.message.Payload)
	if !ok {
		return syscall.EINVAL
	}
	return r.reply(reply, true)
}

// Drop completes the detached message without packet I/O. It is valid only
// before the first Reply begins; use Close to finish an active responder.
// Drop reports ErrForwarderReplyActive in reply mode and net.ErrClosed after
// closure.
func (r *ICMPForwarderResponder) Drop() error {
	if err := r.lifecycle.closePending(); err != nil {
		return err
	}
	r.forwarder.count(forwarderRequestDropped)
	return nil
}

// Reject attempts to enqueue an administratively prohibited response without
// waiting for outbound capacity. It is valid only before the first Reply
// begins and revalidates the forwarder and current destination policy. Once
// selected, the decision remains terminal on output error. Reject reports
// ErrForwarderReplyActive in reply mode and net.ErrClosed after closure.
func (r *ICMPForwarderResponder) Reject() error {
	if err := r.lifecycle.closePending(); err != nil {
		return err
	}
	r.forwarder.count(forwarderRequestRejected)
	if r.forwarder.closed.Load() {
		return net.ErrClosed
	}
	if !r.forwarder.stack.network.Load().acceptsInboundDestination(r.message.Destination) {
		return syscall.EADDRNOTAVAIL
	}
	var err error
	if r.rejectable {
		err = r.forwarder.stack.sendAdministrativeUnreachable(r.packet)
	}
	return err
}

// Close prevents new Reply calls. A Reply that began before Close may finish.
// Closing a responder before its first Reply is equivalent to Drop. Close is
// a logical state transition and does not wait for concurrent calls; it reports
// net.ErrClosed after a previous terminal action.
func (r *ICMPForwarderResponder) Close() error {
	pending, err := r.lifecycle.close()
	if err != nil {
		return err
	}
	if pending {
		r.forwarder.count(forwarderRequestDropped)
	}
	return nil
}

// Done is closed when the originating ICMP forwarder is closed. Configuration
// changes remain dynamic and are revalidated by each Reply.
func (r *ICMPForwarderResponder) Done() <-chan struct{} { return r.forwarder.done }
