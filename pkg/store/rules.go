package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Rule represents a user-created blocking rule.
type Rule struct {
	ID           int64
	CredentialID string
	Rule         string
	Domain       string
	Enabled      bool
	CreatedAt    time.Time
}

// CreateRule adds a new blocking rule for a credential.
func (s *Store) CreateRule(credentialID, rule, domain string) (*Rule, error) {
	result, err := s.db.Exec(
		"INSERT INTO rules (credential_id, rule, domain) VALUES (?, ?, ?)",
		credentialID, rule, domain,
	)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}

	id, _ := result.LastInsertId()
	return &Rule{
		ID:           id,
		CredentialID: credentialID,
		Rule:         rule,
		Domain:       domain,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}, nil
}

// ListRules returns all rules for a credential.
func (s *Store) ListRules(credentialID string) ([]Rule, error) {
	rows, err := s.db.Query(
		"SELECT id, credential_id, rule, domain, enabled, created_at FROM rules WHERE credential_id = ? ORDER BY created_at DESC",
		credentialID,
	)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		var createdAt string
		var enabled int
		if err := rows.Scan(&r.ID, &r.CredentialID, &r.Rule, &r.Domain, &enabled, &createdAt); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		r.Enabled = enabled != 0
		var parseErr error
		r.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05", createdAt)
		if parseErr != nil {
			return nil, fmt.Errorf("parse created_at: %w", parseErr)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// ListAllEnabledRules returns all enabled rules across all credentials.
// Used when rebuilding the in-memory RuleSet.
func (s *Store) ListAllEnabledRules() ([]Rule, error) {
	rows, err := s.db.Query(
		"SELECT id, credential_id, rule, domain, enabled, created_at FROM rules WHERE enabled = 1",
	)
	if err != nil {
		return nil, fmt.Errorf("list all rules: %w", err)
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		var createdAt string
		var enabled int
		if err := rows.Scan(&r.ID, &r.CredentialID, &r.Rule, &r.Domain, &enabled, &createdAt); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		r.Enabled = enabled != 0
		var parseErr error
		r.CreatedAt, parseErr = time.Parse("2006-01-02 15:04:05", createdAt)
		if parseErr != nil {
			return nil, fmt.Errorf("parse created_at: %w", parseErr)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// DeleteRule deletes a rule by ID, scoped to the credential that owns it.
func (s *Store) DeleteRule(id int64, credentialID string) error {
	result, err := s.db.Exec(
		"DELETE FROM rules WHERE id = ? AND credential_id = ?",
		id, credentialID,
	)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// SetRuleEnabled enables or disables a rule, scoped to the credential that owns it.
func (s *Store) SetRuleEnabled(id int64, credentialID string, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	result, err := s.db.Exec(
		"UPDATE rules SET enabled = ? WHERE id = ? AND credential_id = ?",
		val, id, credentialID,
	)
	if err != nil {
		return fmt.Errorf("set rule enabled: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
