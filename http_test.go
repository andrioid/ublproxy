package main

import (
	"net/http"
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.5", "192.168.1.5"},
		{"::ffff:192.168.1.5", "192.168.1.5"},
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"::1", "::1"},
		{"fe80::1", "fe80::1"},
		{"2001:db8::1", "2001:db8::1"},
		// Unparseable strings are returned as-is
		{"not-an-ip", "not-an-ip"},
		{"", ""},
	}
	for _, tt := range tests {
		got := normalizeIP(tt.input)
		if got != tt.want {
			t.Errorf("normalizeIP(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestClientIPFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"ipv4 with port", "192.168.1.5:12345", "192.168.1.5"},
		{"ipv6 mapped with port", "[::ffff:192.168.1.5]:12345", "192.168.1.5"},
		{"ipv6 with port", "[::1]:12345", "::1"},
		{"ipv4 no port", "192.168.1.5", "192.168.1.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tt.remoteAddr}
			got := clientIPFromRequest(r)
			if got != tt.want {
				t.Errorf("clientIPFromRequest(RemoteAddr=%q) = %q, want %q", tt.remoteAddr, got, tt.want)
			}
		})
	}
}

func TestSessionLookupWithNormalizedIP(t *testing.T) {
	sm := newSessionMap()

	// Store session with plain IPv4
	sm.Set("192.168.1.5", sessionEntry{
		Token:        "tok-abc",
		CredentialID: "cred-xyz-12345678",
	})

	// Lookup with same IPv4 should hit
	entry := sm.Get("192.168.1.5")
	if entry == nil {
		t.Fatal("expected session for 192.168.1.5, got nil")
	}
	if entry.CredentialID != "cred-xyz-12345678" {
		t.Errorf("got credID %q, want %q", entry.CredentialID, "cred-xyz-12345678")
	}

	// Lookup with different IP should miss
	entry = sm.Get("192.168.1.6")
	if entry != nil {
		t.Errorf("expected nil for 192.168.1.6, got %+v", entry)
	}

	// Delete and verify
	sm.Delete("192.168.1.5")
	entry = sm.Get("192.168.1.5")
	if entry != nil {
		t.Errorf("expected nil after delete, got %+v", entry)
	}
}
