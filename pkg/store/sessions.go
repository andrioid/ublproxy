package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"
)

const sessionDuration = 30 * 24 * time.Hour // 30 days

// Session represents an authenticated session tied to a credential.
type Session struct {
	Token        string
	CredentialID string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// CreateSession generates a new session token for the given credential.
func (s *Store) CreateSession(credentialID string) (*Session, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	expiresAt := now.Add(sessionDuration)

	_, err := s.db.Exec(
		"INSERT INTO sessions (token, credential_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
		token, credentialID,
		now.Format("2006-01-02 15:04:05"),
		expiresAt.Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &Session{
		Token:        token,
		CredentialID: credentialID,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
	}, nil
}

// ValidateSession checks if a token is valid and not expired.
// Returns the session if valid, sql.ErrNoRows if not found or expired.
func (s *Store) ValidateSession(token string) (*Session, error) {
	var sess Session
	var createdAt, expiresAt string
	err := s.db.QueryRow(
		"SELECT token, credential_id, created_at, expires_at FROM sessions WHERE token = ?",
		token,
	).Scan(&sess.Token, &sess.CredentialID, &createdAt, &expiresAt)
	if err != nil {
		return nil, err
	}

	var parseErr error
	sess.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05", createdAt)
	if parseErr != nil {
		return nil, fmt.Errorf("parse created_at: %w", parseErr)
	}
	sess.ExpiresAt, parseErr = time.Parse("2006-01-02 15:04:05", expiresAt)
	if parseErr != nil {
		return nil, fmt.Errorf("parse expires_at: %w", parseErr)
	}

	if time.Now().UTC().After(sess.ExpiresAt) {
		// Clean up expired session
		s.db.Exec("DELETE FROM sessions WHERE token = ?", token)
		return nil, sql.ErrNoRows
	}

	return &sess, nil
}

// DeleteSession removes a session (logout).
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

// CleanExpiredSessions removes all expired sessions.
func (s *Store) CleanExpiredSessions() error {
	_, err := s.db.Exec(
		"DELETE FROM sessions WHERE expires_at < ?",
		time.Now().UTC().Format("2006-01-02 15:04:05"),
	)
	return err
}
