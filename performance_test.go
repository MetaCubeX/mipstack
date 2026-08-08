package mipstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func benchmarkTCPControllerConnection(b *testing.B, algorithm CongestionControl) (net.Conn, *Stack, *stackBridge) {
	b.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.201")
	serverAddress := netip.MustParseAddr("192.0.2.202")
	client, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(clientAddress, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: algorithm},
	})
	if err != nil {
		b.Fatal(err)
	}
	server, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)},
		TCP:            TCPSocketDefaults{CongestionControl: algorithm},
	})
	if err != nil {
		b.Fatal(err)
	}
	if err = client.Start(); err != nil {
		b.Fatal(err)
	}
	if err = server.Start(); err != nil {
		b.Fatal(err)
	}
	// Benchmarks use the same packet pump as tests and own its lifetime here.
	bridge := &stackBridge{client: client, peer: server, done: make(chan struct{}, 2)}
	go bridge.run(client, server, true)
	go bridge.run(server, client, false)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		b.Fatal(err)
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
		_ = connection.Close()
	}()
	connection, err := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, netip.AddrPortFrom(serverAddress, listener.Addr().(*net.TCPAddr).AddrPort().Port()))
	if err != nil {
		b.Fatal(err)
	}
	serverConnection := <-accepted
	if serverConnection == nil {
		b.Fatal("benchmark accept failed")
	}
	b.Cleanup(func() {
		_ = connection.Close()
		_ = serverConnection.Close()
		_ = listener.Close()
		_ = client.Close()
		_ = server.Close()
		<-bridge.done
		<-bridge.done
	})
	return connection, server, bridge
}

func BenchmarkTCPControllerThroughput(b *testing.B) {
	const size = 4 * 1024 * 1024
	for _, algorithm := range []CongestionControl{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(string(algorithm), func(b *testing.B) {
			connection, peer, bridge := benchmarkTCPControllerConnection(b, algorithm)
			payload := bytes.Repeat([]byte{0x5a}, size)
			received := make([]byte, size)
			b.SetBytes(2 * size)
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				writeDone := make(chan error, 1)
				go func() {
					_, writeErr := connection.Write(payload)
					writeDone <- writeErr
				}()
				if _, err := io.ReadFull(connection, received); err != nil {
					b.Fatal(err)
				}
				if err := <-writeDone; err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(received, payload) {
					b.Fatal("echo payload mismatch")
				}
			}
			if tcp, ok := connection.(*TCPConn); ok {
				info := tcp.Info()
				stats := tcp.stack.Stats()
				peerStats := peer.Stats()
				b.ReportMetric(float64(info.CongestionWindow), "cwnd-B")
				b.ReportMetric(float64(info.DeliveryRate), "delivery-B/s")
				b.ReportMetric(float64(info.BytesInFlight), "flight-B")
				b.ReportMetric(float64(info.PacingRate), "pacing-B/s")
				b.ReportMetric(float64(info.SchedulerLimitedEvents), "scheduler-limited-events")
				b.ReportMetric(float64(info.SlowStartThreshold), "ssthresh-B")
				b.ReportMetric(float64(info.RTT)/float64(time.Microsecond), "rtt-us")
				b.ReportMetric(float64(info.Retransmissions), "retransmissions")
				b.ReportMetric(float64(info.InboundQueueDrops), "connection-queue-drops")
				b.ReportMetric(float64(stats.InboundDroppedPackets), "rx-drops")
				b.ReportMetric(float64(stats.TCPInboundQueueDrops), "queue-drops")
				b.ReportMetric(float64(peerStats.InboundDroppedPackets), "peer-rx-drops")
				b.ReportMetric(float64(peerStats.TCPInboundQueueDrops), "peer-queue-drops")
				b.ReportMetric(float64(stats.TCPSACKRetransmissions), "sack-retransmissions")
				b.ReportMetric(float64(stats.TCPRACKRetransmissions), "rack-retransmissions")
				b.ReportMetric(float64(stats.TCPTailLossProbes), "tail-loss-probes")
				b.ReportMetric(float64(info.SendBufferCapacity), "send-buffer-B")
				b.ReportMetric(float64(info.InboundQueuePeak), "inbound-queue-peak-B")
				bridge.mu.Lock()
				b.ReportMetric(float64(bridge.clientGaps), "wire-gaps")
				b.ReportMetric(float64(bridge.clientRepeats), "wire-repeats")
				b.ReportMetric(float64(bridge.peerSACKs), "peer-sack-acks")
				b.ReportMetric(float64(bridge.peerDSACKs), "peer-dsack-acks")
				bridge.mu.Unlock()
			}
		})
	}
}

func BenchmarkTCPControllerLatency(b *testing.B) {
	for _, algorithm := range []CongestionControl{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		b.Run(string(algorithm), func(b *testing.B) {
			connection, _, _ := benchmarkTCPControllerConnection(b, algorithm)
			_ = connection.SetDeadline(time.Now().Add(time.Minute))
			request := []byte{0x5a}
			response := make([]byte, 1)
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := connection.Write(request); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(connection, response); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkTCPControllerConnections(b *testing.B, algorithm CongestionControl, count int) []net.Conn {
	b.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.211")
	serverAddress := netip.MustParseAddr("192.0.2.212")
	client, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(clientAddress, 32)}, TCP: TCPSocketDefaults{CongestionControl: algorithm}})
	if err != nil {
		b.Fatal(err)
	}
	server, err := New(Config{
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(serverAddress, 32)},
		TCP: TCPSocketDefaults{
			CongestionControl: algorithm,
			// This benchmark measures established-flow concurrency rather than
			// the independently tested accept-queue overload policy.
			AcceptQueue: count,
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	if err = client.Start(); err != nil {
		b.Fatal(err)
	}
	if err = server.Start(); err != nil {
		b.Fatal(err)
	}
	bridge := &stackBridge{client: client, peer: server, done: make(chan struct{}, 2)}
	go bridge.run(client, server, true)
	go bridge.run(server, client, false)
	listener, err := server.ListenTCP(context.Background(), "tcp4", netip.AddrPortFrom(serverAddress, 0))
	if err != nil {
		b.Fatal(err)
	}
	accepted := make(chan net.Conn, count)
	acceptErrors := make(chan error, 1)
	go func() {
		for index := 0; index < count; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				acceptErrors <- acceptErr
				return
			}
			accepted <- connection
			go func(connection net.Conn) { _, _ = io.Copy(connection, connection) }(connection)
		}
		acceptErrors <- nil
	}()
	endpoint := netip.AddrPortFrom(serverAddress, listener.Addr().(*net.TCPAddr).AddrPort().Port())
	connections := make([]net.Conn, count)
	dialErrors := make(chan error, count)
	dialLimit := make(chan struct{}, 32)
	for index := range connections {
		go func(index int) {
			dialLimit <- struct{}{}
			connection, dialErr := client.DialTCP(context.Background(), "tcp4", netip.AddrPort{}, endpoint)
			<-dialLimit
			connections[index] = connection
			dialErrors <- dialErr
		}(index)
	}
	for range connections {
		if err = <-dialErrors; err != nil {
			b.Fatal(err)
		}
	}
	serverConnections := make([]net.Conn, 0, count)
	for len(serverConnections) < count {
		select {
		case connection := <-accepted:
			serverConnections = append(serverConnections, connection)
		case err = <-acceptErrors:
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Cleanup(func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
		for _, connection := range serverConnections {
			_ = connection.Close()
		}
		_ = listener.Close()
		_ = client.Close()
		_ = server.Close()
		<-bridge.done
		<-bridge.done
	})
	return connections
}

func BenchmarkTCPControllerConcurrency(b *testing.B) {
	const size = 128 * 1024
	for _, algorithm := range []CongestionControl{CongestionControlReno, CongestionControlCUBIC, CongestionControlBBR, CongestionControlBBR3} {
		for _, count := range []int{16, 64, 256, 512, 1024, 2048, 4096} {
			b.Run(fmt.Sprintf("%s-%d", algorithm, count), func(b *testing.B) {
				connections := benchmarkTCPControllerConnections(b, algorithm, count)
				payload := bytes.Repeat([]byte{0x6b}, size)
				b.SetBytes(int64(2 * size * count))
				b.ResetTimer()
				for iteration := 0; iteration < b.N; iteration++ {
					results := make(chan error, count)
					for _, connection := range connections {
						go func(connection net.Conn) {
							_ = connection.SetDeadline(time.Now().Add(2 * time.Minute))
							writeDone := make(chan error, 1)
							go func() {
								_, writeErr := connection.Write(payload)
								writeDone <- writeErr
							}()
							received := make([]byte, size)
							_, readErr := io.ReadFull(connection, received)
							if writeErr := <-writeDone; readErr == nil {
								readErr = writeErr
							}
							if readErr == nil && !bytes.Equal(received, payload) {
								readErr = errors.New("echo payload mismatch")
							}
							results <- readErr
						}(connection)
					}
					for range connections {
						if err := <-results; err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func BenchmarkPacketDeviceBatchRead(b *testing.B) {
	const payloadSize = 1200
	for _, batch := range []int{1, deviceBatchSize} {
		b.Run(fmt.Sprintf("batch-%d", batch), func(b *testing.B) {
			local := netip.MustParseAddr("192.0.2.221")
			remote := netip.MustParseAddrPort("192.0.2.222:9000")
			stack, err := New(Config{LocalAddresses: []netip.Prefix{netip.PrefixFrom(local, 32)}})
			if err != nil {
				b.Fatal(err)
			}
			if err = stack.Start(); err != nil {
				b.Fatal(err)
			}
			connection, err := stack.DialUDP(context.Background(), "udp4", netip.AddrPort{}, remote)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				_ = connection.Close()
				_ = stack.Close()
			})
			payload := make([]byte, payloadSize)
			buffers := make([][]byte, batch)
			for index := range buffers {
				buffers[index] = make([]byte, 1500)
			}
			sizes := make([]int, batch)
			b.SetBytes(payloadSize * deviceBatchSize)
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				for packet := 0; packet < deviceBatchSize; packet++ {
					if _, err = connection.Write(payload); err != nil {
						b.Fatal(err)
					}
				}
				read := 0
				for read < deviceBatchSize {
					count, readErr := stack.Read(buffers, sizes, 0)
					if readErr != nil {
						b.Fatal(readErr)
					}
					read += count
				}
			}
		})
	}
}
