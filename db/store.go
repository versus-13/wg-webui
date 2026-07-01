package db

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/versus/wg-webui/wireguard"
)

// DBStore is a database-backed peer store.
type DBStore struct {
	db *sql.DB
}

// NewStore creates a DBStore using the underlying connection from DB.
func NewStore(d *DB) *DBStore {
	return &DBStore{db: d.sql}
}

// List returns all peers ordered by name.
func (s *DBStore) List() ([]*wireguard.Peer, error) {
	rows, err := s.db.Query(
		`SELECT name, ip, privkey, pubkey, psk, enabled, created FROM clients ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	var peers []*wireguard.Peer
	for rows.Next() {
		p := &wireguard.Peer{}
		var enabled int
		if err := rows.Scan(&p.Name, &p.IP, &p.PrivKey, &p.PubKey, &p.PSK, &enabled, &p.Created); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		p.Enabled = enabled != 0
		peers = append(peers, p)
	}
	return peers, rows.Err()
}

// Get returns the peer with the given name, or nil if not found.
func (s *DBStore) Get(name string) (*wireguard.Peer, error) {
	p := &wireguard.Peer{}
	var enabled int
	err := s.db.QueryRow(
		`SELECT name, ip, privkey, pubkey, psk, enabled, created FROM clients WHERE name = ?`, name,
	).Scan(&p.Name, &p.IP, &p.PrivKey, &p.PubKey, &p.PSK, &enabled, &p.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get peer %s: %w", name, err)
	}
	p.Enabled = enabled != 0
	return p, nil
}

// Save inserts or replaces a peer (upsert by name).
func (s *DBStore) Save(p *wireguard.Peer) error {
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO clients (name, ip, privkey, pubkey, psk, enabled, created)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		     ip      = excluded.ip,
		     privkey = excluded.privkey,
		     pubkey  = excluded.pubkey,
		     psk     = excluded.psk,
		     enabled = excluded.enabled,
		     created = excluded.created`,
		p.Name, p.IP, p.PrivKey, p.PubKey, p.PSK, enabled, p.Created,
	)
	if err != nil {
		return fmt.Errorf("save peer %s: %w", p.Name, err)
	}
	return nil
}

// Delete removes the peer with the given name.
func (s *DBStore) Delete(name string) error {
	_, err := s.db.Exec(`DELETE FROM clients WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete peer %s: %w", name, err)
	}
	return nil
}
