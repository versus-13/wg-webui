package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT UNIQUE NOT NULL,
    ip      TEXT NOT NULL,
    privkey TEXT NOT NULL,
    pubkey  TEXT NOT NULL,
    psk     TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created TEXT NOT NULL
);
`

// DB wraps the SQLite connection and exposes settings helpers.
type DB struct {
	sql *sql.DB
}

// Open opens (or creates) the SQLite database at path and initialises the schema.
func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := sqlDB.Exec(schema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &DB{sql: sqlDB}, nil
}

// SQL returns the underlying *sql.DB for use by DBStore.
func (d *DB) SQL() *sql.DB { return d.sql }

// Close closes the database connection.
func (d *DB) Close() error { return d.sql.Close() }

// GetSetting returns the value for key. The second return value is false when the key does not exist.
func (d *DB) GetSetting(key string) (string, bool, error) {
	var v string
	err := d.sql.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetSetting upserts key=value in settings.
func (d *DB) SetSetting(key, value string) error {
	_, err := d.sql.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// EnsureSessionKey returns the stored session key, generating and saving one if absent.
func (d *DB) EnsureSessionKey() (string, error) {
	v, ok, err := d.GetSetting("session_key")
	if err != nil {
		return "", err
	}
	if ok {
		return v, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session key: %w", err)
	}
	key := hex.EncodeToString(b)
	return key, d.SetSetting("session_key", key)
}

// GetPasswordHash returns the bcrypt hash stored in settings.
// The second return value is false when no password has been set yet.
func (d *DB) GetPasswordHash() (string, bool, error) {
	return d.GetSetting("password_hash")
}

// SetPasswordHash stores the bcrypt hash of the web UI password.
func (d *DB) SetPasswordHash(hash string) error {
	return d.SetSetting("password_hash", hash)
}
