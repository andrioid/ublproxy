package blocklist_test

import (
	"os"
	"testing"

	"ublproxy/pkg/blocklist"
)

func TestRuleSetHostnameBlocking(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddHostname("ads.example.com")
	rs.AddHostname("tracker.net")

	tests := []struct {
		url  string
		want bool
	}{
		// Exact hostname match
		{"http://ads.example.com/tracking.js", true},
		{"https://ads.example.com/pixel.gif", true},

		// Subdomain match
		{"http://cdn.ads.example.com/banner.gif", true},

		// Non-matching
		{"http://example.com/page.html", false},
		{"http://good.example.com/page.html", false},

		// Second hostname
		{"http://tracker.net/collect", true},
		{"http://sub.tracker.net/event", true},
		{"http://nottracker.net/page", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := rs.ShouldBlock(tt.url)
			if got != tt.want {
				t.Errorf("ShouldBlock(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestRuleSetPatternBlocking(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddRule("||example.com/ads/*.gif")
	rs.AddRule("/tracking.js")

	tests := []struct {
		url  string
		want bool
	}{
		// URL pattern match
		{"http://example.com/ads/banner123.gif", true},
		{"https://example.com/ads/small.gif", true},
		{"http://example.com/ads/tracker.js", false},
		{"http://example.com/images/photo.gif", false},

		// Substring pattern match
		{"http://other.com/tracking.js", true},
		{"http://example.com/tracking.js?v=1", true},
		{"http://example.com/page.html", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := rs.ShouldBlock(tt.url)
			if got != tt.want {
				t.Errorf("ShouldBlock(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestRuleSetMixed(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddHostname("ads.example.com")
	rs.AddRule("/tracking.js")

	// Hostname rule blocks whole domain
	if !rs.ShouldBlock("http://ads.example.com/page.html") {
		t.Error("hostname rule should block ads.example.com")
	}

	// Pattern rule blocks matching URLs on any domain
	if !rs.ShouldBlock("http://good.example.com/tracking.js") {
		t.Error("pattern rule should block tracking.js on any domain")
	}

	// Neither rule matches
	if rs.ShouldBlock("http://good.example.com/page.html") {
		t.Error("should not block unrelated URL")
	}
}

func TestRuleSetNilSafe(t *testing.T) {
	var rs *blocklist.RuleSet
	if rs.ShouldBlock("http://example.com/") {
		t.Error("nil RuleSet should not block anything")
	}
}

func TestRuleSetLoadFile(t *testing.T) {
	content := `! Comment line
[Adblock Plus 2.0]
||ads.example.com^
0.0.0.0 tracker.net
/banner*.gif
||cdn.example.com/ads/*
example.org##.ad-class
@@||allowed.com^
`
	f, err := os.CreateTemp("", "ruleset-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	rs := blocklist.NewRuleSet()
	if err := rs.LoadFile(f.Name()); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	tests := []struct {
		url  string
		want bool
	}{
		// Hostname from adblock format
		{"http://ads.example.com/tracking.js", true},
		{"http://sub.ads.example.com/pixel.gif", true},

		// Hostname from hosts-file format
		{"http://tracker.net/collect", true},

		// URL pattern rule
		{"http://example.com/banner123.gif", true},
		{"http://example.com/bannerXYZ.gif", true},
		{"http://example.com/page.html", false},

		// Domain-anchored URL pattern
		{"http://cdn.example.com/ads/popup.js", true},
		{"http://cdn.example.com/images/photo.gif", false},

		// Element hiding rules are skipped (not blocking rules)
		{"http://example.org/page.html", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := rs.ShouldBlock(tt.url)
			if got != tt.want {
				t.Errorf("ShouldBlock(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestRuleSetConnectBlocking(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddHostname("ads.example.com")

	// For CONNECT requests, the proxy synthesizes a URL from host:port
	// The proxy should check IsHostBlocked for CONNECT efficiency
	if !rs.IsHostBlocked("ads.example.com") {
		t.Error("IsHostBlocked should return true for blocked hostname")
	}
	if !rs.IsHostBlocked("sub.ads.example.com") {
		t.Error("IsHostBlocked should return true for subdomain of blocked hostname")
	}
	if rs.IsHostBlocked("example.com") {
		t.Error("IsHostBlocked should return false for non-blocked hostname")
	}
}
