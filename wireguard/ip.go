package wireguard

import (
	"encoding/binary"
	"fmt"
	"net"
)

func (s *Service) NextIP() (string, error) {
	_, network, err := net.ParseCIDR(s.cfg.Subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet %q: %w", s.cfg.Subnet, err)
	}

	peers, err := s.store.List()
	if err != nil {
		return "", err
	}
	used := make(map[string]bool, len(peers))
	for _, p := range peers {
		used[p.IP] = true
	}

	base := binary.BigEndian.Uint32(network.IP.To4())
	ones, bits := network.Mask.Size()
	size := uint32(1) << (bits - ones)

	// skip .0 (network) and .1 (server); skip last address (broadcast)
	for i := uint32(2); i < size-1; i++ {
		candidate := make(net.IP, 4)
		binary.BigEndian.PutUint32(candidate, base+i)
		addr := candidate.String()
		if !used[addr] {
			return addr, nil
		}
	}
	return "", fmt.Errorf("no free IPs in subnet %s", s.cfg.Subnet)
}
