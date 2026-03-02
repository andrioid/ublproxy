package main

import (
	"net"
	"testing"
	"time"
)

func TestBelowThresholdDoesNotTrip(t *testing.T) {
	tr := newHandshakeTracker("portal.local", nil)

	tr.RecordFailure("pinned.example.com")
	tr.RecordFailure("pinned.example.com")

	if tr.IsTripped("pinned.example.com") {
		t.Error("expected not tripped after only 2 failures")
	}
}

func TestThresholdReachedTrips(t *testing.T) {
	tr := newHandshakeTracker("portal.local", nil)

	tr.RecordFailure("pinned.example.com")
	tr.RecordFailure("pinned.example.com")
	tripped := tr.RecordFailure("pinned.example.com")

	if !tripped {
		t.Error("expected RecordFailure to return true when breaker trips")
	}
	if !tr.IsTripped("pinned.example.com") {
		t.Error("expected host to be tripped after 3 failures")
	}
}

func TestWindowExpiryResetsCounter(t *testing.T) {
	tr := newHandshakeTracker("portal.local", nil)

	tr.RecordFailure("pinned.example.com")
	tr.RecordFailure("pinned.example.com")

	// Simulate window expiry by backdating firstSeen
	tr.mu.Lock()
	tr.failures["pinned.example.com"].firstSeen = time.Now().Add(-handshakeFailureWindow - time.Second)
	tr.mu.Unlock()

	// This failure should start a new window, not accumulate
	tr.RecordFailure("pinned.example.com")

	if tr.IsTripped("pinned.example.com") {
		t.Error("expected not tripped after window expired and only 1 new failure")
	}
}

func TestTrippedTTLExpires(t *testing.T) {
	tr := newHandshakeTracker("portal.local", nil)

	// Trip the breaker
	tr.RecordFailure("pinned.example.com")
	tr.RecordFailure("pinned.example.com")
	tr.RecordFailure("pinned.example.com")

	if !tr.IsTripped("pinned.example.com") {
		t.Fatal("expected tripped")
	}

	// Simulate TTL expiry
	tr.mu.Lock()
	tr.failures["pinned.example.com"].trippedAt = time.Now().Add(-handshakeTrippedTTL - time.Second)
	tr.mu.Unlock()

	if tr.IsTripped("pinned.example.com") {
		t.Error("expected not tripped after TTL expired")
	}
}

func TestSuccessClearsAllState(t *testing.T) {
	tr := newHandshakeTracker("portal.local", nil)

	tr.RecordFailure("pinned.example.com")
	tr.RecordFailure("pinned.example.com")

	tr.RecordSuccess("pinned.example.com")

	// A single new failure should not trip (counter was reset)
	tr.RecordFailure("pinned.example.com")
	if tr.IsTripped("pinned.example.com") {
		t.Error("expected not tripped after success cleared state")
	}
}

func TestDifferentHostsIndependent(t *testing.T) {
	tr := newHandshakeTracker("portal.local", nil)

	tr.RecordFailure("host-a.example.com")
	tr.RecordFailure("host-a.example.com")
	tr.RecordFailure("host-a.example.com")

	if tr.IsTripped("host-b.example.com") {
		t.Error("failures on host-a should not trip host-b")
	}
	if !tr.IsTripped("host-a.example.com") {
		t.Error("host-a should be tripped")
	}
}

func TestPreviouslyTrippedHostRetripsOnSingleFailure(t *testing.T) {
	tr := newHandshakeTracker("portal.local", nil)

	// Trip the breaker
	tr.RecordFailure("pinned.example.com")
	tr.RecordFailure("pinned.example.com")
	tr.RecordFailure("pinned.example.com")

	// Expire the TTL (this should set prevTripped=true)
	tr.mu.Lock()
	tr.failures["pinned.example.com"].trippedAt = time.Now().Add(-handshakeTrippedTTL - time.Second)
	tr.mu.Unlock()

	// Confirm it's no longer tripped
	if tr.IsTripped("pinned.example.com") {
		t.Fatal("expected not tripped after TTL expired")
	}

	// A single failure should re-trip immediately
	tripped := tr.RecordFailure("pinned.example.com")
	if !tripped {
		t.Error("expected RecordFailure to return true for previously tripped host")
	}
	if !tr.IsTripped("pinned.example.com") {
		t.Error("expected re-tripped after single failure on previously tripped host")
	}
}

func TestExcludedHostNeverTrips(t *testing.T) {
	tr := newHandshakeTracker("portal.local", nil)

	for range 10 {
		tr.RecordFailure("portal.local")
	}

	if tr.IsTripped("portal.local") {
		t.Error("portal host should never be tripped")
	}
}

func TestExcludedIPNeverTrips(t *testing.T) {
	lanIP := net.ParseIP("192.168.1.100")
	tr := newHandshakeTracker("portal.local", []net.IP{lanIP})

	for range 10 {
		tr.RecordFailure("192.168.1.100")
	}

	if tr.IsTripped("192.168.1.100") {
		t.Error("portal IP should never be tripped")
	}
}
