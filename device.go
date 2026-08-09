package mipstack

// deviceBatchSize is the maximum packet count exchanged by one device call.
const deviceBatchSize = 64

// MTU returns the current link MTU.
func (s *Stack) MTU() (int, error) { return s.network.Load().mtu, nil }

// Name returns the stable packet-device implementation name.
func (s *Stack) Name() (string, error) { return "mihomo IP stack", nil }

// BatchSize reports the maximum number of packets returned by one Read call.
func (s *Stack) BatchSize() int { return deviceBatchSize }
