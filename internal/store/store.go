package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store provides access to the SQLite database for credentials, sessions,
// and user-created rules.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at the given path and runs
// schema migrations. The directory is created if it doesn't exist.
func Open(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	// foreign_keys pragma is per-connection so we pass it in the DSN
	// to ensure it's set on every connection the pool creates.
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	return s, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Add is_admin column to existing databases. Ignore "duplicate column"
	// error for databases that already have it.
	s.db.Exec("ALTER TABLE credentials ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
	// Promote the earliest credential to admin if no admin exists yet.
	// Handles both fresh migrations of existing databases and the edge case
	// where the only admin credential was deleted.
	s.db.Exec(`UPDATE credentials SET is_admin = 1
		WHERE rowid = (SELECT MIN(rowid) FROM credentials)
		AND NOT EXISTS (SELECT 1 FROM credentials WHERE is_admin = 1)`)
	return nil
}

const schema = `
CREATE TABLE IF NOT EXISTS credentials (
	id         TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	sign_count INTEGER NOT NULL DEFAULT 0,
	is_admin   INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
	token         TEXT PRIMARY KEY,
	credential_id TEXT NOT NULL REFERENCES credentials(id),
	created_at    TEXT NOT NULL DEFAULT (datetime('now')),
	expires_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
	id            INTEGER PRIMARY KEY,
	credential_id TEXT NOT NULL REFERENCES credentials(id),
	rule          TEXT NOT NULL,
	domain        TEXT NOT NULL DEFAULT '',
	enabled       INTEGER NOT NULL DEFAULT 1,
	created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blocklist_subscriptions (
	id            INTEGER PRIMARY KEY,
	credential_id TEXT NOT NULL REFERENCES credentials(id),
	url           TEXT NOT NULL,
	name          TEXT NOT NULL DEFAULT '',
	enabled       INTEGER NOT NULL DEFAULT 1,
	created_at    TEXT NOT NULL DEFAULT (datetime('now')),
	UNIQUE(credential_id, url)
);

CREATE TABLE IF NOT EXISTS blocklist_cache (
	url        TEXT PRIMARY KEY,
	content    BLOB NOT NULL,
	fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`
