package blocklist_test

import (
	"testing"

	"ublproxy/pkg/blocklist"
)

func TestPatternMatch(t *testing.T) {
	tests := []struct {
		pattern string
		url     string
		want    bool
	}{
		// Plain substring match
		{"ad.gif", "http://example.com/ad.gif", true},
		{"ad.gif", "http://example.com/ad.gif?q=1", true},
		{"ad.gif", "http://example.com/page.html", false},
		{"banner", "http://example.com/ads/banner123.gif", true},
		{"banner", "http://example.com/page.html", false},

		// Wildcard
		{"/ads/banner*.gif", "http://example.com/ads/banner123.gif", true},
		{"/ads/banner*.gif", "http://example.com/ads/banner.gif", true},
		{"/ads/banner*.gif", "http://example.com/ads/bannerXYZ.gif", true},
		{"/ads/banner*.gif", "http://example.com/ads/tracking.js", false},
		{"ad*banner", "http://example.com/ad-and-banner", true},
		{"ad*banner", "http://example.com/adbanner", true},
		{"ad*banner", "http://example.com/banner-ad", false},

		// Separator character (^)
		// ^ matches any non-alphanumeric except _ - . %
		{"example.com^", "http://example.com/", true},
		{"example.com^", "http://example.com:8000/", true},
		{"example.com^", "http://example.com.ar/", false},
		{"^foo.bar^", "http://example.com/foo.bar?a=1", true},
		{"^foo.bar^", "http://example.com/foo.bar", true}, // end of string counts as separator

		// Address start anchor (|)
		{"|http://example.com", "http://example.com/banner.gif", true},
		{"|http://example.com", "https://example.com/banner.gif", false},
		{"|http://bad.example/", "http://bad.example/banner.gif", true},
		{"|http://bad.example/", "http://good.example/analyze?http://bad.example/", false},

		// Address end anchor (|)
		{"swf|", "http://example.com/annoyingflash.swf", true},
		{"swf|", "http://example.com/swf/index.html", false},
		{".gif|", "http://example.com/banner.gif", true},
		{".gif|", "http://example.com/banner.gif?q=1", false},

		// Domain anchor (||)
		{"||example.com", "http://example.com/banner.gif", true},
		{"||example.com", "https://example.com/banner.gif", true},
		{"||example.com", "http://www.example.com/banner.gif", true},
		{"||example.com", "http://badexample.com/banner.gif", false},
		{"||example.com/banner.gif", "http://example.com/banner.gif", true},
		{"||example.com/banner.gif", "http://example.com/other.gif", false},

		// Domain anchor with separator
		{"||ads.example.com^", "http://ads.example.com/tracking.js", true},
		{"||ads.example.com^", "http://ads.example.com:8080/tracking.js", true},
		{"||ads.example.com^", "http://ads.example.com.ar/tracking.js", false},

		// Combined features
		{"||example.com/ads/*.gif", "http://example.com/ads/banner123.gif", true},
		{"||example.com/ads/*.gif", "http://example.com/ads/tracker.js", false},
		{"||example.com^*/tracking", "http://example.com/path/tracking", true},

		// Case insensitivity (default)
		{"AdVeRt", "http://example.com/advert.js", true},
		{"BANNER", "http://example.com/banner.gif", true},

		// Empty / edge cases
		{"", "http://example.com/", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.url, func(t *testing.T) {
			rule, err := blocklist.Compile(tt.pattern)
			if tt.pattern == "" {
				if err == nil {
					t.Fatal("expected error for empty pattern, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.pattern, err)
			}
			got := rule.Match(tt.url)
			if got != tt.want {
				t.Errorf("Compile(%q).Match(%q) = %v, want %v", tt.pattern, tt.url, got, tt.want)
			}
		})
	}
}

func TestMatchCase(t *testing.T) {
	// Without $match-case, matching is case-insensitive (default)
	rule, _ := blocklist.Compile("BannerAd.gif")
	if !rule.Match("http://example.com/bannerad.gif") {
		t.Error("default should be case-insensitive")
	}

	// With $match-case, matching is case-sensitive
	rule, _ = blocklist.Compile("BannerAd.gif$match-case")
	if !rule.Match("http://example.com/BannerAd.gif") {
		t.Error("$match-case should match exact case")
	}
	if rule.Match("http://example.com/bannerad.gif") {
		t.Error("$match-case should not match wrong case")
	}
}

func TestThirdPartyOption(t *testing.T) {
	// $third-party: only match when request is cross-origin
	rule, _ := blocklist.Compile("/ads/*$third-party")

	ctx := blocklist.MatchContext{PageDomain: "example.com"}

	// Same origin: should not match
	if rule.MatchWithContext("http://example.com/ads/banner.gif", ctx) {
		t.Error("$third-party should not match same-origin request")
	}

	// Cross origin: should match
	if !rule.MatchWithContext("http://adserver.net/ads/banner.gif", ctx) {
		t.Error("$third-party should match cross-origin request")
	}

	// $~third-party: only match when request is same-origin
	rule, _ = blocklist.Compile("/ads/*$~third-party")

	if !rule.MatchWithContext("http://example.com/ads/banner.gif", ctx) {
		t.Error("$~third-party should match same-origin request")
	}
	if rule.MatchWithContext("http://adserver.net/ads/banner.gif", ctx) {
		t.Error("$~third-party should not match cross-origin request")
	}
}

func TestDomainOption(t *testing.T) {
	// $domain=example.com: only apply on pages from example.com
	rule, _ := blocklist.Compile("/ads/*$domain=example.com")

	if !rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "example.com"}) {
		t.Error("should match when page is example.com")
	}
	if !rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "sub.example.com"}) {
		t.Error("should match subdomain of domain option")
	}
	if rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "other.com"}) {
		t.Error("should not match when page is other.com")
	}

	// $domain=example.com|example.org: multiple domains
	rule, _ = blocklist.Compile("/ads/*$domain=example.com|example.org")

	if !rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "example.com"}) {
		t.Error("should match first domain")
	}
	if !rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "example.org"}) {
		t.Error("should match second domain")
	}
	if rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "other.com"}) {
		t.Error("should not match unlisted domain")
	}

	// $domain=~example.com: exclude domain
	rule, _ = blocklist.Compile("/ads/*$domain=~example.com")

	if rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "example.com"}) {
		t.Error("should not match excluded domain")
	}
	if !rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "other.com"}) {
		t.Error("should match non-excluded domain")
	}
}

func TestOptionsStrippedFromPattern(t *testing.T) {
	// The $options suffix should not be part of the URL pattern
	rule, _ := blocklist.Compile("/ads/banner.gif$match-case")
	if !rule.Match("http://example.com/ads/banner.gif") {
		t.Error("pattern should match URL without $options suffix")
	}

	// With $match-case, pattern should be case-sensitive
	if rule.Match("http://example.com/ads/Banner.gif") {
		t.Error("$match-case pattern should not match different case")
	}

	// Verify options don't leak into the pattern by using an end anchor
	rule2, _ := blocklist.Compile("/ads/banner.gif|$match-case")
	if !rule2.Match("http://example.com/ads/banner.gif") {
		t.Error("end-anchored pattern should match exact ending")
	}
	if rule2.Match("http://example.com/ads/banner.gif?v=1") {
		t.Error("end-anchored pattern should not match with trailing chars")
	}
}
