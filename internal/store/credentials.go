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
	IsAdmin   bool
	CreatedAt time.Time
}

// SaveCredential stores a new passkey credential. The first credential
// registered is automatically promoted to admin.
func (s *Store) SaveCredential(id string, publicKey []byte) error {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM credentials").Scan(&count)
	isAdmin := 0
	if count == 0 {
		isAdmin = 1
	}
	_, err := s.db.Exec(
		"INSERT INTO credentials (id, public_key, is_admin) VALUES (?, ?, ?)",
		id, publicKey, isAdmin,
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
	var isAdmin int
	err := s.db.QueryRow(
		"SELECT id, public_key, sign_count, is_admin, created_at FROM credentials WHERE id = ?",
		id,
	).Scan(&c.ID, &c.PublicKey, &c.SignCount, &isAdmin, &createdAt)
	if err != nil {
		return nil, err
	}
	c.IsAdmin = isAdmin != 0
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

// IsAdmin returns whether the credential has admin privileges.
func (s *Store) IsAdmin(credentialID string) (bool, error) {
	var isAdmin int
	err := s.db.QueryRow(
		"SELECT is_admin FROM credentials WHERE id = ?",
		credentialID,
	).Scan(&isAdmin)
	if err != nil {
		return false, err
	}
	return isAdmin != 0, nil
}

// SetAdmin sets or removes admin privileges for a credential.
// Returns sql.ErrNoRows if the credential does not exist.
func (s *Store) SetAdmin(credentialID string, admin bool) error {
	val := 0
	if admin {
		val = 1
	}
	result, err := s.db.Exec(
		"UPDATE credentials SET is_admin = ? WHERE id = ?",
		val, credentialID,
	)
	if err != nil {
		return fmt.Errorf("set admin: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListCredentials returns all credentials with their admin status and creation
// time. Public keys are not included — this is for the admin users page.
func (s *Store) ListCredentials() ([]Credential, error) {
	rows, err := s.db.Query("SELECT id, is_admin, created_at FROM credentials ORDER BY created_at ASC")
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()

	var creds []Credential
	for rows.Next() {
		var c Credential
		var isAdmin int
		var createdAt string
		if err := rows.Scan(&c.ID, &isAdmin, &createdAt); err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		c.IsAdmin = isAdmin != 0
		c.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		creds = append(creds, c)
	}
	return creds, rows.Err()
}
