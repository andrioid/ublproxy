package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Credential represents a WebAuthn passkey credential stored in the database.
type Credential struct {
	ID        string
	PublicKey []byte
	SignCount uint32
	CreatedAt time.Time
}

// SaveCredential stores a new passkey credential.
func (s *Store) SaveCredential(id string, publicKey []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO credentials (id, public_key) VALUES (?, ?)",
		id, publicKey,
	)
	if err != nil {
		return fmt.Errorf("save credential: %w", err)
	}
	return nil
}

// GetCredential retrieves a credential by ID. Returns sql.ErrNoRows if not found.
func (s *Store) GetCredential(id string) (*Credential, error) {
	var c Credential
	var createdAt string
	err := s.db.QueryRow(
		"SELECT id, public_key, sign_count, created_at FROM credentials WHERE id = ?",
		id,
	).Scan(&c.ID, &c.PublicKey, &c.SignCount, &createdAt)
	if err != nil {
		return nil, err
	}
	var parseErr error
	c.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05", createdAt)
	if parseErr != nil {
		return nil, fmt.Errorf("parse created_at: %w", parseErr)
	}
	return &c, nil
}

// ListCredentialIDs returns all credential IDs. Used during WebAuthn login
// to tell the browser which credentials are accepted.
func (s *Store) ListCredentialIDs() ([]string, error) {
	rows, err := s.db.Query("SELECT id FROM credentials")
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan credential id: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// UpdateSignCount updates the signature counter for a credential.
// Used to detect cloned authenticators.
func (s *Store) UpdateSignCount(id string, count uint32) error {
	result, err := s.db.Exec(
		"UPDATE credentials SET sign_count = ? WHERE id = ?",
		count, id,
	)
	if err != nil {
		return fmt.Errorf("update sign count: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
