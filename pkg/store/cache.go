package store

import (
	"database/sql"
	"fmt"
	"time"
)

// CachedBlocklist holds cached content for a blocklist URL.
type CachedBlocklist struct {
	URL       string
	Content   []byte
	FetchedAt time.Time
}

// GetCachedBlocklist returns the cached content for a blocklist URL.
// Returns nil if no cache entry exists.
func (s *Store) GetCachedBlocklist(url string) (*CachedBlocklist, error) {
	var c CachedBlocklist
	var fetchedAt string
	err := s.db.QueryRow(
		"SELECT url, content, fetched_at FROM blocklist_cache WHERE url = ?", url,
	).Scan(&c.URL, &c.Content, &fetchedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cached blocklist: %w", err)
	}
	var parseErr error
	c.FetchedAt, parseErr = time.Parse("2006-01-02 15:04:05", fetchedAt)
	if parseErr != nil {
		return nil, fmt.Errorf("parse fetched_at: %w", parseErr)
	}
	return &c, nil
}

// SetCachedBlocklist upserts the cache entry for a blocklist URL.
func (s *Store) SetCachedBlocklist(url string, content []byte) error {
	_, err := s.db.Exec(
		"INSERT INTO blocklist_cache (url, content, fetched_at) VALUES (?, ?, datetime('now')) "+
			"ON CONFLICT(url) DO UPDATE SET content = excluded.content, fetched_at = excluded.fetched_at",
		url, content,
	)
	if err != nil {
		return fmt.Errorf("set cached blocklist: %w", err)
	}
	return nil
}

// ClearBlocklistCache removes all cached blocklist entries.
func (s *Store) ClearBlocklistCache() error {
	_, err := s.db.Exec("DELETE FROM blocklist_cache")
	return err
}
