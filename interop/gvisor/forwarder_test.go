package gvisorinterop_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/checksum"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/raw"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/mipstack"
)

const (
	// forwardTCPPort is the intercepted destination port shared by isolated
	// TCP Forwarder subtests.
	forwardTCPPort = 44001
	// forwardUDPPort is the intercepted destination port shared by isolated
	// UDP Forwarder subtests.
	forwardUDPPort = 44002
)

// TestTCPForwarderInterop verifies that gVisor can complete and use a TCP
// connection accepted for a nonlocal mipstack destination.
func TestTCPForwarderInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			t.Run(family.name+"/"+interopMTUName(mtu), func(t *testing.T) {
				network := newForwarderInteropNetwork(t, family, mtu)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()

				type acceptResult struct {
					connection *mipstack.TCPConn
					flow       mipstack.TransportFlow
					err        error
				}
				accepted := make(chan acceptResult, 1)
				forwarder, err := mipstack.NewTCPForwarder(network.mipstack, mipstack.TCPForwarderOptions{}, func(request *mipstack.TCPForwarderRequest) {
					flow := request.Flow()
					connection, acceptErr := request.Accept(ctx)
					accepted <- acceptResult{connection: connection, flow: flow, err: acceptErr}
				})
				if err != nil {
					t.Fatalf("create TCP forwarder: %v", err)
				}
				defer forwarder.Close()

				target := netipAddrPort(family.forwardAddress, forwardTCPPort)
				client, err := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(target.Addr(), target.Port()), family.networkProtocol)
				if err != nil {
					t.Fatalf("dial forwarded TCP destination: %v", err)
				}
				defer client.Close()

				var result acceptResult
				select {
				case result = <-accepted:
				case <-ctx.Done():
					t.Fatalf("accept forwarded TCP connection: %v", ctx.Err())
				}
				if result.err != nil {
					t.Fatalf("accept forwarded TCP connection: %v", result.err)
				}
				defer result.connection.Close()
				wantSource := requireAddrPort(t, client.LocalAddr())
				if result.flow.Source != wantSource || result.flow.Destination != target {
					t.Fatalf("forwarded TCP flow = %+v, want %v -> %v", result.flow, wantSource, target)
				}
				if local, remote := requireAddrPort(t, result.connection.LocalAddr()), requireAddrPort(t, result.connection.RemoteAddr()); local != target || remote != wantSource {
					t.Fatalf("forwarded TCP endpoints = %v -> %v, want %v -> %v", remote, local, wantSource, target)
				}

				exerciseFullDuplexTCP(t, client, result.connection, tcpInteropStreamSize(mtu))
				validateTCPMTUInfo(t, result.connection.Info(), family, mtu)
				if info := forwarder.Info(); info.Requests != 1 || info.Accepted != 1 || info.Pending != 0 {
					t.Fatalf("TCP forwarder info = %+v", info)
				}
			})
		}
	}
}

// TestTCPForwarderRejectInterop verifies that a nonlocal TCP rejection is
// recognized by gVisor as a connection-refused reset.
func TestTCPForwarderRejectInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			type rejectResult struct {
				flow mipstack.TransportFlow
				err  error
			}
			results := make(chan rejectResult, 1)
			forwarder, err := mipstack.NewTCPForwarder(network.mipstack, mipstack.TCPForwarderOptions{}, func(request *mipstack.TCPForwarderRequest) {
				results <- rejectResult{flow: request.Flow(), err: request.Reject()}
			})
			if err != nil {
				t.Fatalf("create TCP reject forwarder: %v", err)
			}
			defer forwarder.Close()

			target := netipAddrPort(family.forwardAddress, forwardTCPPort)
			connection, err := gonet.DialContextTCP(ctx, network.gvisor, gvisorFullAddress(target.Addr(), target.Port()), family.networkProtocol)
			if connection != nil {
				_ = connection.Close()
			}
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("gVisor dial after TCP Forwarder Reject = %v, want ECONNREFUSED", err)
			}
			select {
			case result := <-results:
				if result.err != nil || result.flow.Destination != target || result.flow.Source.Addr() != family.gvisorAddress {
					t.Fatalf("TCP Forwarder Reject = flow %+v, error=%v", result.flow, result.err)
				}
			case <-ctx.Done():
				t.Fatalf("receive TCP Forwarder Reject result: %v", ctx.Err())
			}
			if info := forwarder.Info(); info.Requests != 1 || info.Rejected != 1 || info.Pending != 0 {
				t.Fatalf("TCP reject forwarder info = %+v", info)
			}
		})
	}
}

// TestUDPForwarderRejectInterop verifies that a nonlocal UDP rejection reaches
// the matching native gVisor endpoint as a connection-refused ICMP error.
func TestUDPForwarderRejectInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			type rejectResult struct {
				flow mipstack.TransportFlow
				err  error
			}
			results := make(chan rejectResult, 1)
			forwarder, err := mipstack.NewUDPForwarder(network.mipstack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
				results <- rejectResult{flow: request.Flow(), err: request.Reject()}
			})
			if err != nil {
				t.Fatalf("create UDP reject forwarder: %v", err)
			}
			defer forwarder.Close()

			var queue waiter.Queue
			endpoint, tcpipErr := network.gvisor.NewEndpoint(udp.ProtocolNumber, family.networkProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor UDP endpoint: %s", tcpipErr.String())
			}
			defer endpoint.Close()
			if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor UDP endpoint: %s", tcpipErr.String())
			}
			target := netipAddrPort(family.forwardAddress, forwardUDPPort)
			if tcpipErr = endpoint.Connect(gvisorFullAddress(target.Addr(), target.Port())); tcpipErr != nil {
				t.Fatalf("connect gVisor UDP endpoint: %s", tcpipErr.String())
			}
			entry, notifications := waiter.NewChannelEntry(waiter.EventErr)
			queue.EventRegister(&entry)
			defer queue.EventUnregister(&entry)
			written, tcpipErr := endpoint.Write(bytes.NewReader([]byte("reject")), tcpip.WriteOptions{})
			if tcpipErr != nil || written != 6 {
				t.Fatalf("write gVisor rejected UDP datagram: n=%d, error=%s", written, tcpipErrorString(tcpipErr))
			}

			select {
			case result := <-results:
				if result.err != nil || result.flow.Destination != target || result.flow.Source.Addr() != family.gvisorAddress {
					t.Fatalf("UDP Forwarder Reject = flow %+v, error=%v", result.flow, result.err)
				}
			case <-ctx.Done():
				t.Fatalf("receive UDP Forwarder Reject result: %v", ctx.Err())
			}
			select {
			case <-notifications:
			case <-ctx.Done():
				t.Fatalf("wait for gVisor UDP rejection: %v", ctx.Err())
			}
			if lastError := endpoint.LastError(); lastError == nil {
				t.Fatal("gVisor UDP endpoint signaled rejection without LastError")
			} else if _, refused := lastError.(*tcpip.ErrConnectionRefused); !refused {
				t.Fatalf("gVisor UDP rejection = %T %s, want ErrConnectionRefused", lastError, lastError.String())
			}
			if info := forwarder.Info(); info.Requests != 1 || info.Rejected != 1 || info.Pending != 0 {
				t.Fatalf("UDP reject forwarder info = %+v", info)
			}
		})
	}
}

// TestIPForwarderRejectInterop verifies that protocol rejection reaches a
// native gVisor raw ICMP socket with a valid quote of the triggering payload.
func TestIPForwarderRejectInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results := make(chan error, 1)
			forwarder, err := mipstack.NewIPForwarder(network.mipstack, mipstack.IPForwarderOptions{}, func(request *mipstack.IPForwarderRequest) {
				results <- request.Reject()
			})
			if err != nil {
				t.Fatalf("create IP reject forwarder: %v", err)
			}
			defer forwarder.Close()

			monitor, notifications := newGVisorRawICMPMonitor(t, network, family)
			var queue waiter.Queue
			sender, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor raw IP sender: %s", tcpipErr.String())
			}
			defer sender.Close()
			if tcpipErr = sender.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
				t.Fatalf("bind gVisor raw IP sender: %s", tcpipErr.String())
			}
			if tcpipErr = sender.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor raw IP sender: %s", tcpipErr.String())
			}
			payload := []byte("reject-raw-protocol")
			if written, writeErr := sender.Write(bytes.NewReader(payload), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(payload)) {
				t.Fatalf("write rejected gVisor raw IP payload: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			select {
			case rejectErr := <-results:
				if rejectErr != nil {
					t.Fatalf("reject IP Forwarder request: %v", rejectErr)
				}
			case <-ctx.Done():
				t.Fatalf("wait for IP Forwarder Reject: %v", ctx.Err())
			}
			packet, remote, readErr := readGVisorEndpoint(ctx, monitor, notifications, 2048)
			if readErr != nil {
				t.Fatalf("read gVisor IP Forwarder rejection: %v", readErr)
			}
			message, stripErr := stripGVisorRawHeader(family, packet)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			wantType, wantCode := byte(header.ICMPv4DstUnreachable), byte(header.ICMPv4ProtoUnreachable)
			wantPointer, checkPointer := uint32(0), false
			if family.mipstackAddress.Is6() {
				wantType, wantCode = byte(header.ICMPv6ParamProblem), 1
				wantPointer, checkPointer = 6, true
			}
			validateForwarderICMPError(t, family, message, remote, uint8(interopRawIPProtocol), wantType, wantCode, wantPointer, checkPointer)
			if info := forwarder.Info(); info.Requests != 1 || info.Rejected != 1 || info.Pending != 0 {
				t.Fatalf("IP reject forwarder info = %+v", info)
			}
		})
	}
}

// TestICMPForwarderRejectInterop verifies administratively prohibited output
// for a rejectable Echo Request against a native gVisor raw ICMP socket.
func TestICMPForwarderRejectInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		t.Run(family.name, func(t *testing.T) {
			network := newForwarderInteropNetwork(t, family, 1500)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results := make(chan error, 1)
			forwarder, err := mipstack.NewICMPForwarder(network.mipstack, mipstack.ICMPForwarderOptions{}, func(request *mipstack.ICMPForwarderRequest) {
				results <- request.Reject()
			})
			if err != nil {
				t.Fatalf("create ICMP reject forwarder: %v", err)
			}
			defer forwarder.Close()

			monitor, notifications := newGVisorRawICMPMonitor(t, network, family)
			var queue waiter.Queue
			sender, tcpipErr := network.gvisor.NewEndpoint(family.icmpProtocol, family.networkProtocol, &queue)
			if tcpipErr != nil {
				t.Fatalf("create gVisor ICMP sender: %s", tcpipErr.String())
			}
			defer sender.Close()
			const identifier = 0x6401
			if tcpipErr = sender.Bind(gvisorFullAddress(family.gvisorAddress, identifier)); tcpipErr != nil {
				t.Fatalf("bind gVisor ICMP sender: %s", tcpipErr.String())
			}
			if tcpipErr = sender.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
				t.Fatalf("connect gVisor ICMP sender: %s", tcpipErr.String())
			}
			request := makeICMPEcho(family, false, identifier, 1, []byte("reject-echo"), family.gvisorAddress, family.forwardAddress)
			if written, writeErr := sender.Write(bytes.NewReader(request), tcpip.WriteOptions{}); writeErr != nil || written != int64(len(request)) {
				t.Fatalf("write rejected gVisor ICMP request: n=%d, error=%s", written, tcpipErrorString(writeErr))
			}
			select {
			case rejectErr := <-results:
				if rejectErr != nil {
					t.Fatalf("reject ICMP Forwarder request: %v", rejectErr)
				}
			case <-ctx.Done():
				t.Fatalf("wait for ICMP Forwarder Reject: %v", ctx.Err())
			}
			packet, remote, readErr := readGVisorEndpoint(ctx, monitor, notifications, 2048)
			if readErr != nil {
				t.Fatalf("read gVisor ICMP Forwarder rejection: %v", readErr)
			}
			message, stripErr := stripGVisorRawHeader(family, packet)
			if stripErr != nil {
				t.Fatal(stripErr)
			}
			protocol := uint8(header.ICMPv4ProtocolNumber)
			wantType, wantCode := byte(header.ICMPv4DstUnreachable), byte(header.ICMPv4AdminProhibited)
			if family.mipstackAddress.Is6() {
				protocol = uint8(header.ICMPv6ProtocolNumber)
				wantType, wantCode = byte(header.ICMPv6DstUnreachable), byte(header.ICMPv6Prohibited)
			}
			validateForwarderICMPError(t, family, message, remote, protocol, wantType, wantCode, 0, false)
			if info := forwarder.Info(); info.Requests != 1 || info.Rejected != 1 || info.Pending != 0 {
				t.Fatalf("ICMP reject forwarder info = %+v", info)
			}
		})
	}
}

// TestUDPForwarderEndpointInterop verifies connected Accept and unconnected
// Listen endpoints, including fragmented traffic and a second source flow.
func TestUDPForwarderEndpointInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, listen := range []bool{false, true} {
				listen := listen
				mode := "accept"
				if listen {
					mode = "listen"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					type endpointResult struct {
						connection *mipstack.UDPConn
						flow       mipstack.TransportFlow
						err        error
					}
					endpoints := make(chan endpointResult, 1)
					forwarder, err := mipstack.NewUDPForwarder(network.mipstack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
						flow := request.Flow()
						var connection *mipstack.UDPConn
						var endpointErr error
						if listen {
							connection, endpointErr = request.Listen()
						} else {
							connection, endpointErr = request.Accept()
						}
						endpoints <- endpointResult{connection: connection, flow: flow, err: endpointErr}
					})
					if err != nil {
						t.Fatalf("create UDP forwarder: %v", err)
					}
					defer forwarder.Close()

					target := netipAddrPort(family.forwardAddress, forwardUDPPort)
					firstClient := dialGVisorForwardUDP(t, network, family, target)
					defer firstClient.Close()
					clients := []*gonet.UDPConn{firstClient, firstClient}
					if listen {
						secondClient := dialGVisorForwardUDP(t, network, family, target)
						defer secondClient.Close()
						clients[1] = secondClient
					}

					var forwarded *mipstack.UDPConn
					buffer := make([]byte, 65535)
					for index, size := range []int{37, fragmentedInteropPayloadSize(mtu, 12_000)} {
						request := patternedPayload(size, byte(11+index))
						response := patternedPayload(size+19, byte(47+index))
						client := clients[index]
						written, writeErr := client.Write(request)
						if writeErr != nil || written != len(request) {
							t.Fatalf("write forwarded UDP request: n=%d, error=%v", written, writeErr)
						}
						if index == 0 {
							select {
							case result := <-endpoints:
								if result.err != nil {
									t.Fatalf("create forwarded UDP endpoint: %v", result.err)
								}
								forwarded = result.connection
								wantSource := requireAddrPort(t, client.LocalAddr())
								if result.flow.Source != wantSource || result.flow.Destination != target {
									t.Fatalf("forwarded UDP flow = %+v, want %v -> %v", result.flow, wantSource, target)
								}
								if local := requireAddrPort(t, forwarded.LocalAddr()); local != target {
									t.Fatalf("forwarded UDP local endpoint = %v, want %v", local, target)
								}
								if listen {
									if remote := forwarded.RemoteAddr(); remote != nil {
										t.Fatalf("listened UDP remote endpoint = %v, want nil", remote)
									}
								} else if remote := requireAddrPort(t, forwarded.RemoteAddr()); remote != wantSource {
									t.Fatalf("accepted UDP remote endpoint = %v, want %v", remote, wantSource)
								}
							case <-ctx.Done():
								t.Fatalf("receive forwarded UDP endpoint: %v", ctx.Err())
							}
							defer forwarded.Close()
							if err = forwarded.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
								t.Fatalf("set forwarded UDP deadline: %v", err)
							}
						}

						wantSource := requireAddrPort(t, client.LocalAddr())
						var read int
						var source netip.AddrPort
						if listen {
							read, source, err = forwarded.ReadFromUDPAddrPort(buffer)
						} else {
							read, err = forwarded.Read(buffer)
							source = wantSource
						}
						if err != nil || source != wantSource || !bytes.Equal(buffer[:read], request) {
							t.Fatalf("read forwarded UDP request: n=%d, source=%v, error=%v", read, source, err)
						}
						if listen {
							written, err = forwarded.WriteToUDPAddrPort(response, source)
						} else {
							written, err = forwarded.Write(response)
						}
						if err != nil || written != len(response) {
							t.Fatalf("write forwarded UDP response: n=%d, error=%v", written, err)
						}
						read, err = client.Read(buffer)
						if err != nil || !bytes.Equal(buffer[:read], response) {
							t.Fatalf("read gVisor UDP response: n=%d, error=%v", read, err)
						}
					}
					if info := forwarder.Info(); info.Requests != 1 || info.Accepted != 1 || info.Pending != 0 {
						t.Fatalf("UDP endpoint forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

// TestUDPForwarderReplyInterop verifies callback-scoped and detached
// stateless replies against a native gVisor UDP socket.
func TestUDPForwarderReplyInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, detached := range []bool{false, true} {
				detached := detached
				mode := "callback"
				if detached {
					mode = "detached"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					type replyResult struct {
						flow      mipstack.TransportFlow
						request   []byte
						response  []byte
						responder *mipstack.UDPForwarderResponder
						err       error
					}
					results := make(chan replyResult, 1)
					forwarder, err := mipstack.NewUDPForwarder(network.mipstack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
						payload := append([]byte(nil), request.Payload()...)
						response := append([]byte("udp-forward:"), payload...)
						result := replyResult{flow: request.Flow(), request: payload, response: response}
						if detached {
							result.responder, result.err = request.Detach()
						} else {
							var written int
							written, result.err = request.Reply(response)
							if result.err == nil && written != len(response) {
								result.err = io.ErrShortWrite
							}
						}
						results <- result
					})
					if err != nil {
						t.Fatalf("create UDP reply forwarder: %v", err)
					}
					defer forwarder.Close()

					target := netipAddrPort(family.forwardAddress, forwardUDPPort)
					client := dialGVisorForwardUDP(t, network, family, target)
					defer client.Close()
					payload := patternedPayload(fragmentedInteropPayloadSize(mtu, 12_000), 79)
					written, err := client.Write(payload)
					if err != nil || written != len(payload) {
						t.Fatalf("write gVisor UDP request: n=%d, error=%v", written, err)
					}

					var result replyResult
					select {
					case result = <-results:
					case <-ctx.Done():
						t.Fatalf("receive UDP reply request: %v", ctx.Err())
					}
					if result.err != nil {
						t.Fatalf("prepare UDP reply: %v", result.err)
					}
					wantSource := requireAddrPort(t, client.LocalAddr())
					if result.flow.Source != wantSource || result.flow.Destination != target || !bytes.Equal(result.request, payload) {
						t.Fatalf("UDP reply request = flow %+v, payload %d bytes", result.flow, len(result.request))
					}
					if detached {
						written, err = result.responder.Reply(result.response)
						if err != nil || written != len(result.response) {
							t.Fatalf("write detached UDP reply: n=%d, error=%v", written, err)
						}
						if err = result.responder.Close(); err != nil {
							t.Fatalf("close detached UDP responder: %v", err)
						}
					}
					buffer := make([]byte, 65535)
					read, err := client.Read(buffer)
					if err != nil || !bytes.Equal(buffer[:read], result.response) {
						t.Fatalf("read gVisor UDP reply: n=%d, error=%v", read, err)
					}
					if info := forwarder.Info(); info.Requests != 1 || info.Replies != 1 || info.Pending != 0 {
						t.Fatalf("UDP reply forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

// TestICMPForwarderInterop verifies checksum-valid fragmented Echo traffic and
// both callback-scoped and detached ReplyEcho output against gVisor.
func TestICMPForwarderInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, detached := range []bool{false, true} {
				detached := detached
				mode := "callback"
				if detached {
					mode = "detached"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()

					type echoResult struct {
						message   mipstack.ICMPMessage
						responder *mipstack.ICMPForwarderResponder
						err       error
					}
					results := make(chan echoResult, 2)
					forwarder, err := mipstack.NewICMPForwarder(network.mipstack, mipstack.ICMPForwarderOptions{}, func(request *mipstack.ICMPForwarderRequest) {
						message := request.Message()
						message.Payload = append([]byte(nil), message.Payload...)
						result := echoResult{message: message}
						if detached {
							result.responder, result.err = request.Detach()
						} else {
							result.err = request.ReplyEcho()
						}
						results <- result
					})
					if err != nil {
						t.Fatalf("create ICMP forwarder: %v", err)
					}
					defer forwarder.Close()

					var queue waiter.Queue
					endpoint, tcpipErr := network.gvisor.NewEndpoint(family.icmpProtocol, family.networkProtocol, &queue)
					if tcpipErr != nil {
						t.Fatalf("create gVisor ICMP endpoint: %s", tcpipErr.String())
					}
					defer endpoint.Close()
					identifier := uint16(0x6101)
					if detached {
						identifier = 0x6201
					}
					if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, identifier)); tcpipErr != nil {
						t.Fatalf("bind gVisor ICMP endpoint: %s", tcpipErr.String())
					}
					if tcpipErr = endpoint.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
						t.Fatalf("connect gVisor ICMP endpoint: %s", tcpipErr.String())
					}
					entry, notifications := registerReadable(&queue)
					defer queue.EventUnregister(&entry)

					for index, size := range []int{31, fragmentedInteropPayloadSize(mtu, 4096)} {
						payload := patternedPayload(size, byte(101+index))
						sequence := uint16(index + 1)
						request := makeICMPEcho(family, false, identifier, sequence, payload, family.gvisorAddress, family.forwardAddress)
						written, writeErr := endpoint.Write(bytes.NewReader(request), tcpip.WriteOptions{})
						if writeErr != nil || written != int64(len(request)) {
							t.Fatalf("write gVisor forwarded ICMP echo: n=%d, error=%s", written, tcpipErrorString(writeErr))
						}

						var result echoResult
						select {
						case result = <-results:
						case <-ctx.Done():
							t.Fatalf("receive forwarded ICMP echo: %v", ctx.Err())
						}
						if result.err != nil {
							t.Fatalf("prepare ICMP echo reply: %v", result.err)
						}
						if result.message.Source != family.gvisorAddress || result.message.Destination != family.forwardAddress || !result.message.IsEchoRequest() || !bytes.Equal(result.message.Payload, request) {
							t.Fatalf("forwarded ICMP message = %+v", result.message)
						}
						if detached {
							if err = result.responder.ReplyEcho(); err != nil {
								t.Fatalf("write detached ICMP echo reply: %v", err)
							}
							if err = result.responder.Close(); err != nil {
								t.Fatalf("close detached ICMP responder: %v", err)
							}
						}
						reply, remote, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
						if readErr != nil {
							t.Fatalf("read gVisor ICMP echo reply: %v", readErr)
						}
						if remote.Addr != gvisorAddress(family.forwardAddress) {
							t.Fatalf("ICMP echo reply source = %v, want %v", remote.Addr, family.forwardAddress)
						}
						if err = validateICMPEcho(family, reply, true, identifier, sequence, payload, family.forwardAddress, family.gvisorAddress); err != nil {
							t.Fatal(err)
						}
					}
					if info := forwarder.Info(); info.Requests != 2 || info.Replies != 2 || info.Pending != 0 {
						t.Fatalf("ICMP forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

// TestIPForwarderInterop verifies callback-scoped and detached arbitrary-IP
// replies against a native gVisor raw socket.
func TestIPForwarderInterop(t *testing.T) {
	for _, family := range interopFamilies {
		family := family
		for _, mtu := range interopMTUsForFamily(family) {
			mtu := mtu
			for _, detached := range []bool{false, true} {
				detached := detached
				mode := "callback"
				if detached {
					mode = "detached"
				}
				t.Run(family.name+"/"+interopMTUName(mtu)+"/"+mode, func(t *testing.T) {
					network := newForwarderInteropNetwork(t, family, mtu)
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()

					type replyResult struct {
						message   mipstack.IPMessage
						response  []byte
						responder *mipstack.IPForwarderResponder
						err       error
					}
					results := make(chan replyResult, 1)
					forwarder, err := mipstack.NewIPForwarder(network.mipstack, mipstack.IPForwarderOptions{}, func(request *mipstack.IPForwarderRequest) {
						message := request.Message()
						message.Payload = append([]byte(nil), message.Payload...)
						result := replyResult{message: message, response: append([]byte("ip-forward:"), message.Payload...)}
						if detached {
							result.responder, result.err = request.Detach()
						} else {
							result.err = request.Reply(result.response)
						}
						results <- result
					})
					if err != nil {
						t.Fatalf("create IP forwarder: %v", err)
					}
					defer forwarder.Close()

					var queue waiter.Queue
					endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, interopRawIPProtocol, &queue)
					if tcpipErr != nil {
						t.Fatalf("create gVisor raw endpoint: %s", tcpipErr.String())
					}
					defer endpoint.Close()
					if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
						t.Fatalf("bind gVisor raw endpoint: %s", tcpipErr.String())
					}
					if tcpipErr = endpoint.Connect(gvisorFullAddress(family.forwardAddress, 0)); tcpipErr != nil {
						t.Fatalf("connect gVisor raw endpoint: %s", tcpipErr.String())
					}
					entry, notifications := registerReadable(&queue)
					defer queue.EventUnregister(&entry)

					payloadSize := rawInteropPayloadCapacity(family, mtu) - len("ip-forward:")
					payload := patternedPayload(payloadSize, 137)
					written, writeErr := endpoint.Write(bytes.NewReader(payload), tcpip.WriteOptions{})
					if writeErr != nil || written != int64(len(payload)) {
						t.Fatalf("write gVisor forwarded IP payload: n=%d, error=%s", written, tcpipErrorString(writeErr))
					}
					var result replyResult
					select {
					case result = <-results:
					case <-ctx.Done():
						t.Fatalf("receive forwarded IP payload: %v", ctx.Err())
					}
					if result.err != nil {
						t.Fatalf("prepare IP forwarder reply: %v", result.err)
					}
					if result.message.Source != family.gvisorAddress || result.message.Destination != family.forwardAddress || result.message.Protocol != uint8(interopRawIPProtocol) || !bytes.Equal(result.message.Payload, payload) {
						t.Fatalf("forwarded IP message = %+v", result.message)
					}
					if detached {
						if err = result.responder.Reply(result.response); err != nil {
							t.Fatalf("write detached IP reply: %v", err)
						}
						if err = result.responder.Close(); err != nil {
							t.Fatalf("close detached IP responder: %v", err)
						}
					}
					packet, remote, readErr := readGVisorEndpoint(ctx, endpoint, notifications, 65535)
					if readErr != nil {
						t.Fatalf("read gVisor IP forwarder reply: %v", readErr)
					}
					response, stripErr := stripGVisorRawHeader(family, packet)
					if stripErr != nil {
						t.Fatal(stripErr)
					}
					if remote.Addr != gvisorAddress(family.forwardAddress) || !bytes.Equal(response, result.response) {
						t.Fatalf("gVisor IP forwarder reply: source=%v, bytes=%d", remote.Addr, len(response))
					}
					if info := forwarder.Info(); info.Requests != 1 || info.Replies != 1 || info.Pending != 0 {
						t.Fatalf("IP forwarder info = %+v", info)
					}
				})
			}
		}
	}
}

// dialGVisorForwardUDP creates a connected native gVisor UDP socket for one
// intercepted destination and applies a bounded test deadline.
func dialGVisorForwardUDP(t *testing.T, network *interopNetwork, family interopFamily, target netip.AddrPort) *gonet.UDPConn {
	t.Helper()
	local := gvisorFullAddress(family.gvisorAddress, 0)
	remote := gvisorFullAddress(target.Addr(), target.Port())
	connection, err := gonet.DialUDP(network.gvisor, &local, &remote, family.networkProtocol)
	if err != nil {
		t.Fatalf("dial gVisor forwarded UDP destination: %v", err)
	}
	if err = connection.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		_ = connection.Close()
		t.Fatalf("set gVisor UDP deadline: %v", err)
	}
	return connection
}

// newGVisorRawICMPMonitor opens a raw endpoint that observes complete ICMP
// errors after gVisor's network layer has accepted the packet.
func newGVisorRawICMPMonitor(t *testing.T, network *interopNetwork, family interopFamily) (tcpip.Endpoint, <-chan struct{}) {
	t.Helper()
	var queue waiter.Queue
	endpoint, tcpipErr := raw.NewEndpoint(network.gvisor, family.networkProtocol, family.icmpProtocol, &queue)
	if tcpipErr != nil {
		t.Fatalf("create gVisor raw ICMP monitor: %s", tcpipErr.String())
	}
	if tcpipErr = endpoint.Bind(gvisorFullAddress(family.gvisorAddress, 0)); tcpipErr != nil {
		endpoint.Close()
		t.Fatalf("bind gVisor raw ICMP monitor: %s", tcpipErr.String())
	}
	entry, notifications := registerReadable(&queue)
	t.Cleanup(func() {
		queue.EventUnregister(&entry)
		endpoint.Close()
	})
	return endpoint, notifications
}

// validateForwarderICMPError checks a rejection's checksum, outer source,
// type-specific data, and quoted original network header.
func validateForwarderICMPError(t *testing.T, family interopFamily, message []byte, remote tcpip.FullAddress, quotedProtocol, wantType, wantCode byte, wantPointer uint32, checkPointer bool) {
	t.Helper()
	if remote.Addr != gvisorAddress(family.forwardAddress) {
		t.Fatalf("Forwarder ICMP rejection source = %v, want %v", remote.Addr, family.forwardAddress)
	}
	if len(message) < 8 {
		t.Fatalf("short Forwarder ICMP rejection: %d bytes", len(message))
	}
	if family.mipstackAddress.Is4() {
		icmpHeader := header.ICMPv4(message[:8])
		if byte(icmpHeader.Type()) != wantType || byte(icmpHeader.Code()) != wantCode {
			t.Fatalf("Forwarder ICMPv4 rejection type/code = %d/%d, want %d/%d", icmpHeader.Type(), icmpHeader.Code(), wantType, wantCode)
		}
		if checksum.Checksum(message, 0) != 0xffff {
			t.Fatal("Forwarder ICMPv4 rejection checksum is invalid")
		}
	} else {
		icmpHeader := header.ICMPv6(message[:8])
		if byte(icmpHeader.Type()) != wantType || byte(icmpHeader.Code()) != wantCode {
			t.Fatalf("Forwarder ICMPv6 rejection type/code = %d/%d, want %d/%d", icmpHeader.Type(), icmpHeader.Code(), wantType, wantCode)
		}
		if checkPointer && icmpHeader.TypeSpecific() != wantPointer {
			t.Fatalf("Forwarder ICMPv6 rejection pointer = %d, want %d", icmpHeader.TypeSpecific(), wantPointer)
		}
		actualChecksum := icmpHeader.Checksum()
		icmpHeader.SetChecksum(0)
		expectedChecksum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHeader,
			Src:         gvisorAddress(family.forwardAddress),
			Dst:         gvisorAddress(family.gvisorAddress),
			PayloadCsum: checksum.Checksum(message[8:], 0),
			PayloadLen:  len(message) - 8,
		})
		icmpHeader.SetChecksum(actualChecksum)
		if actualChecksum != expectedChecksum {
			t.Fatalf("Forwarder ICMPv6 rejection checksum = %#04x, want %#04x", actualChecksum, expectedChecksum)
		}
	}

	quote := message[8:]
	if family.mipstackAddress.Is4() {
		if len(quote) < header.IPv4MinimumSize {
			t.Fatalf("short Forwarder ICMPv4 quote: %d bytes", len(quote))
		}
		inner := header.IPv4(quote)
		if inner.SourceAddress() != gvisorAddress(family.gvisorAddress) || inner.DestinationAddress() != gvisorAddress(family.forwardAddress) || byte(inner.TransportProtocol()) != quotedProtocol {
			t.Fatalf("Forwarder ICMPv4 quote = %v -> %v protocol %d", inner.SourceAddress(), inner.DestinationAddress(), inner.TransportProtocol())
		}
		return
	}
	if len(quote) < header.IPv6MinimumSize {
		t.Fatalf("short Forwarder ICMPv6 quote: %d bytes", len(quote))
	}
	inner := header.IPv6(quote)
	if inner.SourceAddress() != gvisorAddress(family.gvisorAddress) || inner.DestinationAddress() != gvisorAddress(family.forwardAddress) || byte(inner.TransportProtocol()) != quotedProtocol {
		t.Fatalf("Forwarder ICMPv6 quote = %v -> %v protocol %d", inner.SourceAddress(), inner.DestinationAddress(), inner.TransportProtocol())
	}
}

// requireAddrPort converts the standard address types returned by both stacks
// and fails the current test for an unexpected net.Addr implementation.
func requireAddrPort(t *testing.T, address net.Addr) netip.AddrPort {
	t.Helper()
	switch typed := address.(type) {
	case *net.TCPAddr:
		return typed.AddrPort()
	case *net.UDPAddr:
		return typed.AddrPort()
	default:
		t.Fatalf("unexpected network address %T (%v)", address, address)
		return netip.AddrPort{}
	}
}
