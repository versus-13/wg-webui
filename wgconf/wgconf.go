package wgconf

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// InterfaceConfig holds the [Interface] section fields we care about.
type InterfaceConfig struct {
	// Subnet is derived from Address by masking host bits: "10.8.0.1/24" -> "10.8.0.0/24"
	Subnet     string
	ListenPort int
	PrivateKey string
}

// ParseFile reads a WireGuard config file and returns the [Interface] fields.
func ParseFile(path string) (*InterfaceConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wg config %s: %w", path, err)
	}
	defer f.Close()

	cfg := &InterfaceConfig{ListenPort: 51820}
	inInterface := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// strip inline comments
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		if line == "[Interface]" {
			inInterface = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inInterface = false
			continue
		}
		if !inInterface {
			continue
		}

		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)

		switch k {
		case "Address":
			// may be comma-separated list; take first IPv4 CIDR
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(part)
				ip, ipNet, err := net.ParseCIDR(part)
				if err != nil {
					continue
				}
				if ip.To4() != nil {
					// zero out host bits to get the network address
					cfg.Subnet = ipNet.String()
					break
				}
			}
		case "ListenPort":
			n, err := strconv.Atoi(v)
			if err == nil {
				cfg.ListenPort = n
			}
		case "PrivateKey":
			cfg.PrivateKey = v
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan wg config: %w", err)
	}
	if cfg.Subnet == "" {
		return nil, fmt.Errorf("Address not found in [Interface] section of %s", path)
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("PrivateKey not found in [Interface] section of %s", path)
	}
	return cfg, nil
}
