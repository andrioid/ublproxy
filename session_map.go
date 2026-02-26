package main

import "sync"

// sessionMap maps client IP addresses to their active session tokens.
// When a user authenticates on the portal (via passkey), their session
// token is associated with their IP. The proxy uses this to embed the
// correct token in the bootstrap script injected into HTML responses.
type sessionMap struct {
	mu     sync.RWMutex
	tokens map[string]string // client IP -> session token
}

func newSessionMap() *sessionMap {
	return &sessionMap{tokens: make(map[string]string)}
}

// Set associates a session token with a client IP.
func (m *sessionMap) Set(clientIP, token string) {
	m.mu.Lock()
	m.tokens[clientIP] = token
	m.mu.Unlock()
}

// Get returns the session token for a client IP, or empty string if none.
func (m *sessionMap) Get(clientIP string) string {
	m.mu.RLock()
	token := m.tokens[clientIP]
	m.mu.RUnlock()
	return token
}

// Delete removes the session for a client IP.
func (m *sessionMap) Delete(clientIP string) {
	m.mu.Lock()
	delete(m.tokens, clientIP)
	m.mu.Unlock()
}
