package mipstack

// MTU returns the current link MTU.
func (s *Stack) MTU() (int, error) { return s.network.Load().mtu, nil }

// Name returns the stable packet-device implementation name.
func (s *Stack) Name() (string, error) { return "mihomo IP stack", nil }

// BatchSize reports that one packet is returned by each Read call.
func (s *Stack) BatchSize() int { return 1 }
