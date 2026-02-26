package main

import "sync"

// sessionEntry holds the session token and credential ID for an
// authenticated client. The credential ID identifies the user (passkey)
// and is used to look up per-user rules.
type sessionEntry struct {
	Token        string
	CredentialID string
}

// sessionMap maps client IP addresses to their active sessions.
// When a user authenticates on the portal (via passkey), their session
// is associated with their IP. The proxy uses this to embed the
// correct token in the bootstrap script and to resolve per-user rules.
type sessionMap struct {
	mu      sync.RWMutex
	entries map[string]sessionEntry // client IP -> session
}

func newSessionMap() *sessionMap {
	return &sessionMap{entries: make(map[string]sessionEntry)}
}

// Set associates a session with a client IP.
func (m *sessionMap) Set(clientIP string, entry sessionEntry) {
	m.mu.Lock()
	m.entries[clientIP] = entry
	m.mu.Unlock()
}

// Get returns the session entry for a client IP, or nil if none.
func (m *sessionMap) Get(clientIP string) *sessionEntry {
	m.mu.RLock()
	entry, ok := m.entries[clientIP]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	return &entry
}

// Delete removes the session for a client IP.
func (m *sessionMap) Delete(clientIP string) {
	m.mu.Lock()
	delete(m.entries, clientIP)
	m.mu.Unlock()
}
