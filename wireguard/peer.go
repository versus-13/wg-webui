package wireguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Peer struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	PrivKey string `json:"privkey"`
	PubKey  string `json:"pubkey"`
	PSK     string `json:"psk"`
	Enabled bool   `json:"enabled"`
	Created string `json:"created"`
}

type PeerStore struct {
	dir string
}

func NewPeerStore(dir string) *PeerStore {
	return &PeerStore{dir: dir}
}

func (s *PeerStore) List() ([]*Peer, error) {
	entries, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)

	var peers []*Peer
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var p Peer
		if err := json.Unmarshal(data, &p); err != nil {
			continue
		}
		peers = append(peers, &p)
	}
	return peers, nil
}

func (s *PeerStore) Get(name string) (*Peer, error) {
	path := filepath.Join(s.dir, name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var p Peer
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *PeerStore) Save(p *Peer) error {
	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, p.Name+".json"), data, 0600)
}

func (s *PeerStore) SaveConf(name, content string) error {
	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, name+".conf"), []byte(content), 0600)
}

func (s *PeerStore) ConfPath(name string) string {
	return filepath.Join(s.dir, name+".conf")
}

func (s *PeerStore) Delete(name string) error {
	var errs []error
	for _, ext := range []string{".json", ".conf"} {
		path := filepath.Join(s.dir, name+ext)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("delete peer files: %v", errs)
	}
	return nil
}
