package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Subscription represents a user's blocklist URL subscription.
type Subscription struct {
	ID           int64
	CredentialID string
	URL          string
	Name         string
	Enabled      bool
	CreatedAt    time.Time
}

// CreateSubscription adds a blocklist URL subscription for a credential.
func (s *Store) CreateSubscription(credentialID, url, name string) (*Subscription, error) {
	result, err := s.db.Exec(
		"INSERT INTO blocklist_subscriptions (credential_id, url, name) VALUES (?, ?, ?)",
		credentialID, url, name,
	)
	if err != nil {
		return nil, fmt.Errorf("create subscription: %w", err)
	}

	id, _ := result.LastInsertId()
	return &Subscription{
		ID:           id,
		CredentialID: credentialID,
		URL:          url,
		Name:         name,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}, nil
}

// ListSubscriptions returns all subscriptions for a credential.
func (s *Store) ListSubscriptions(credentialID string) ([]Subscription, error) {
	rows, err := s.db.Query(
		"SELECT id, credential_id, url, name, enabled, created_at FROM blocklist_subscriptions WHERE credential_id = ? ORDER BY created_at DESC",
		credentialID,
	)
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}
	defer rows.Close()
	return scanSubscriptions(rows)
}

// ListEnabledSubscriptionURLs returns all enabled subscription URLs for a
// single credential. Used when building a per-user RuleSet.
func (s *Store) ListEnabledSubscriptionURLs(credentialID string) ([]string, error) {
	rows, err := s.db.Query(
		"SELECT url FROM blocklist_subscriptions WHERE credential_id = ? AND enabled = 1",
		credentialID,
	)
	if err != nil {
		return nil, fmt.Errorf("list enabled subscription urls: %w", err)
	}
	defer rows.Close()

	var urls []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, fmt.Errorf("scan url: %w", err)
		}
		urls = append(urls, url)
	}
	return urls, rows.Err()
}

// ListAllEnabledSubscriptionURLs returns all unique enabled subscription URLs
// across all users. Used when rebuilding the in-memory RuleSet.
func (s *Store) ListAllEnabledSubscriptionURLs() ([]string, error) {
	rows, err := s.db.Query(
		"SELECT DISTINCT url FROM blocklist_subscriptions WHERE enabled = 1",
	)
	if err != nil {
		return nil, fmt.Errorf("list subscription urls: %w", err)
	}
	defer rows.Close()

	var urls []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, fmt.Errorf("scan url: %w", err)
		}
		urls = append(urls, url)
	}
	return urls, rows.Err()
}

// DeleteSubscription deletes a subscription by ID, scoped to the credential that owns it.
func (s *Store) DeleteSubscription(id int64, credentialID string) error {
	result, err := s.db.Exec(
		"DELETE FROM blocklist_subscriptions WHERE id = ? AND credential_id = ?",
		id, credentialID,
	)
	if err != nil {
		return fmt.Errorf("delete subscription: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetSubscriptionEnabled enables or disables a subscription.
func (s *Store) SetSubscriptionEnabled(id int64, credentialID string, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	result, err := s.db.Exec(
		"UPDATE blocklist_subscriptions SET enabled = ? WHERE id = ? AND credential_id = ?",
		val, id, credentialID,
	)
	if err != nil {
		return fmt.Errorf("set subscription enabled: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanSubscriptions(rows *sql.Rows) ([]Subscription, error) {
	var subs []Subscription
	for rows.Next() {
		var sub Subscription
		var createdAt string
		var enabled int
		if err := rows.Scan(&sub.ID, &sub.CredentialID, &sub.URL, &sub.Name, &enabled, &createdAt); err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}
		sub.Enabled = enabled != 0
		var parseErr error
		sub.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05", createdAt)
		if parseErr != nil {
			return nil, fmt.Errorf("parse created_at: %w", parseErr)
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}
