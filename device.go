package mipstack

// deviceBatchSize is the maximum packet count returned by one Read call.
const deviceBatchSize = 64

// MTU returns the current link MTU.
func (s *Stack) MTU() (int, error) { return s.network.Load().mtu, nil }

// Name returns the stable packet-device implementation name.
func (s *Stack) Name() (string, error) { return "mihomo IP stack", nil }

// BatchSize reports the maximum number of packets returned by one Read call.
// Write accepts larger batches so Stack remains compatible with composite
// packet devices whose network side has a larger batch size.
func (s *Stack) BatchSize() int { return deviceBatchSize }
