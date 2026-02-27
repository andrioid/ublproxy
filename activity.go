package main

import (
	"sync"
	"time"
)

// Activity types for the proxy event log.
const (
	ActivityBlocked       = "blocked"
	ActivityAllowed       = "allowed"
	ActivityPassthrough   = "passthrough"
	ActivityElementHidden = "element-hidden"
)

// ActivityEntry represents a single proxy event.
type ActivityEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Host      string    `json:"host"`
	URL       string    `json:"url,omitempty"`
	Rule      string    `json:"rule,omitempty"`
}

// ActivityLog is a thread-safe ring buffer of recent proxy events.
type ActivityLog struct {
	mu      sync.Mutex
	entries []ActivityEntry
	head    int
	count   int
}

// NewActivityLog creates a ring buffer with the given capacity.
func NewActivityLog(capacity int) *ActivityLog {
	return &ActivityLog{
		entries: make([]ActivityEntry, capacity),
	}
}

// Add records a new event in the ring buffer.
func (l *ActivityLog) Add(entry ActivityEntry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	l.mu.Lock()
	l.entries[l.head] = entry
	l.head = (l.head + 1) % len(l.entries)
	if l.count < len(l.entries) {
		l.count++
	}
	l.mu.Unlock()
}

// Recent returns the most recent entries, newest first.
// If limit <= 0 or limit > count, returns all stored entries.
func (l *ActivityLog) Recent(limit int) []ActivityEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	if limit <= 0 || limit > l.count {
		limit = l.count
	}
	if limit == 0 {
		return nil
	}

	result := make([]ActivityEntry, limit)
	for i := range limit {
		// Walk backwards from head
		idx := (l.head - 1 - i + len(l.entries)) % len(l.entries)
		result[i] = l.entries[idx]
	}
	return result
}

// Stats returns summary counts by type from the current buffer contents.
func (l *ActivityLog) Stats() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()

	stats := make(map[string]int)
	for i := range l.count {
		idx := (l.head - 1 - i + len(l.entries)) % len(l.entries)
		stats[l.entries[idx].Type]++
	}
	return stats
}
