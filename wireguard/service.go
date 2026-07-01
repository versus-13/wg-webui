package wireguard

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PeerLister is the minimal interface Service requires from a peer store.
type PeerLister interface {
	List() ([]*Peer, error)
}

type ServiceConfig struct {
	Interface  string
	ConfigFile string // full path to wg0.conf
	Subnet     string
	ServerHost string
	ServerPort int
	DNS        string
}

type Service struct {
	mu           sync.Mutex
	cfg          ServiceConfig
	store        PeerLister
	pubKeyOnce   sync.Once
	cachedPub    string
	cachedPubErr error
}

func NewService(cfg ServiceConfig, store PeerLister) *Service {
	return &Service{cfg: cfg, store: store}
}

func (s *Service) ServerPubKey() (string, error) {
	s.pubKeyOnce.Do(func() {
		data, err := os.ReadFile(s.cfg.ConfigFile)
		if err != nil {
			s.cachedPubErr = fmt.Errorf("read wg config: %w", err)
			return
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "PrivateKey") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					privKey := strings.TrimSpace(parts[1])
					pub, err := derivePubKey(privKey)
					if err != nil {
						s.cachedPubErr = err
						return
					}
					s.cachedPub = pub
					return
				}
			}
		}
		s.cachedPubErr = fmt.Errorf("PrivateKey not found in %s", s.cfg.ConfigFile)
	})
	return s.cachedPub, s.cachedPubErr
}

func (s *Service) GenerateKeys() (priv, pub, psk string, err error) {
	return GenerateKeys()
}

// Reload rewrites [Peer] sections in the server config and applies via wg syncconf.
func (s *Service) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	cfg := string(data)
	if idx := strings.Index(cfg, "\n[Peer]"); idx != -1 {
		cfg = cfg[:idx]
	}
	cfg = strings.TrimRight(cfg, "\n") + "\n"

	peers, err := s.store.List()
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}
	for _, p := range peers {
		if !p.Enabled {
			continue
		}
		cfg += fmt.Sprintf("\n[Peer]\n# %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n",
			p.Name, p.PubKey, p.PSK, p.IP)
	}

	tmpPath := s.cfg.ConfigFile + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(cfg), 0600); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}
	if err := os.Rename(tmpPath, s.cfg.ConfigFile); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename config: %w", err)
	}

	cmd := fmt.Sprintf("wg syncconf %s <(wg-quick strip %s)", s.cfg.Interface, s.cfg.Interface)
	out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg syncconf: %w: %s", err, out)
	}
	return nil
}

func (s *Service) Status() (string, error) {
	out, err := exec.Command("wg", "show", s.cfg.Interface).Output()
	if err != nil {
		return "", nil
	}
	return string(out), nil
}

// Handshakes returns map[pubkey]formatted_time.
func (s *Service) Handshakes() (map[string]string, error) {
	out, err := exec.Command("wg", "show", s.cfg.Interface, "latest-handshakes").Output()
	if err != nil {
		return map[string]string{}, nil
	}
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		pub, rawTs := parts[0], parts[1]
		ts, err := strconv.ParseInt(rawTs, 10, 64)
		if err != nil || ts == 0 {
			result[pub] = "никогда"
		} else {
			result[pub] = time.Unix(ts, 0).Format("02.01.2006 15:04")
		}
	}
	return result, nil
}

func (s *Service) PeerConfigText(p *Peer) (string, error) {
	srvPub, err := s.ServerPubKey()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = %s:%d
PersistentKeepalive = 25
`, p.PrivKey, p.IP, s.cfg.DNS, srvPub, p.PSK, s.cfg.ServerHost, s.cfg.ServerPort), nil
}
