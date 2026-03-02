package main

import (
	"net"
	"sync"
	"time"
)

// Circuit breaker thresholds for auto-passthrough of cert-pinned hosts.
// When a host accumulates enough TLS handshake failures within a window,
// subsequent connections skip MITM and are tunneled directly to upstream.
const (
	handshakeFailureThreshold = 3
	handshakeFailureWindow    = 10 * time.Minute
	handshakeTrippedTTL       = 1 * time.Hour
)

type failureRecord struct {
	count       int
	firstSeen   time.Time
	trippedAt   time.Time // zero = not tripped
	prevTripped bool      // re-trip on single failure after TTL expires
}

// handshakeTracker implements a circuit breaker for TLS handshake failures.
// Hosts that repeatedly reject the proxy's MITM certificate (e.g. due to
// certificate pinning) are automatically switched to passthrough mode.
type handshakeTracker struct {
	mu       sync.Mutex
	failures map[string]*failureRecord
	excluded map[string]bool
}

func newHandshakeTracker(portalHost string, portalIPs []net.IP) *handshakeTracker {
	excluded := map[string]bool{
		portalHost:  true,
		"localhost": true,
		"127.0.0.1": true,
	}
	for _, ip := range portalIPs {
		if ip != nil {
			excluded[ip.String()] = true
		}
	}
	return &handshakeTracker{
		failures: make(map[string]*failureRecord),
		excluded: excluded,
	}
}

// RecordFailure records a TLS handshake failure for a host. Returns true
// if the circuit breaker tripped (threshold reached). Excluded hosts
// (portal) are ignored.
func (t *handshakeTracker) RecordFailure(host string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.excluded[host] {
		return false
	}

	now := time.Now()
	rec, ok := t.failures[host]
	if !ok {
		t.failures[host] = &failureRecord{
			count:     1,
			firstSeen: now,
		}
		return false
	}

	// Already tripped -- nothing to do
	if !rec.trippedAt.IsZero() && now.Before(rec.trippedAt.Add(handshakeTrippedTTL)) {
		return false
	}

	// Previously tripped host: re-trip on a single failure
	if rec.prevTripped {
		rec.count = handshakeFailureThreshold
		rec.trippedAt = now
		rec.prevTripped = false
		return true
	}

	// Window expired: reset counter
	if now.After(rec.firstSeen.Add(handshakeFailureWindow)) {
		rec.count = 1
		rec.firstSeen = now
		rec.trippedAt = time.Time{}
		return false
	}

	rec.count++
	if rec.count >= handshakeFailureThreshold {
		rec.trippedAt = now
		return true
	}

	return false
}

// IsTripped returns whether a host is in auto-passthrough due to repeated
// TLS handshake failures. Excluded hosts (portal) always return false.
func (t *handshakeTracker) IsTripped(host string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.excluded[host] {
		return false
	}

	rec, ok := t.failures[host]
	if !ok {
		return false
	}

	if rec.trippedAt.IsZero() {
		return false
	}

	// TTL expired: enter half-open state
	if time.Now().After(rec.trippedAt.Add(handshakeTrippedTTL)) {
		rec.prevTripped = true
		rec.trippedAt = time.Time{}
		rec.count = 0
		rec.firstSeen = time.Time{}
		return false
	}

	return true
}

// RecordSuccess clears all failure state for a host. A successful MITM
// handshake proves the host is not cert-pinned.
func (t *handshakeTracker) RecordSuccess(host string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, host)
}
