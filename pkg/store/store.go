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
	return s.migrations()
}

const schema = `
CREATE TABLE IF NOT EXISTS credentials (
	id         TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	sign_count INTEGER NOT NULL DEFAULT 0,
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
	is_default    INTEGER NOT NULL DEFAULT 0,
	created_at    TEXT NOT NULL DEFAULT (datetime('now')),
	UNIQUE(credential_id, url)
);

CREATE TABLE IF NOT EXISTS blocklist_cache (
	url        TEXT PRIMARY KEY,
	content    BLOB NOT NULL,
	fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`

// migrations runs ALTER TABLE statements for columns added after the
// initial schema. Each uses IF NOT EXISTS-style guards (SQLite doesn't
// support IF NOT EXISTS on ALTER TABLE, so we check pragma table_info).
func (s *Store) migrations() error {
	// Add is_default column to blocklist_subscriptions (added 2026-02-27)
	if !s.columnExists("blocklist_subscriptions", "is_default") {
		if _, err := s.db.Exec("ALTER TABLE blocklist_subscriptions ADD COLUMN is_default INTEGER NOT NULL DEFAULT 0"); err != nil {
			return fmt.Errorf("add is_default column: %w", err)
		}
	}
	return nil
}

// columnExists checks whether a column exists on a table using pragma table_info.
func (s *Store) columnExists(table, column string) bool {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt *string
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if name == column {
			return true
		}
	}
	return false
}
