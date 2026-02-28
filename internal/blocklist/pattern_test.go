package blocklist_test

import (
	"testing"

	"ublproxy/internal/blocklist"
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

func BenchmarkMatchSubstring(b *testing.B) {
	// Non-anchored pattern: must scan the URL for a substring match
	rule, _ := blocklist.Compile("/ads/banner*.gif")
	url := "http://cdn.example.com/static/resources/images/v3/long/path/that/forces/many/scans/ads/banner123.gif"
	b.ResetTimer()
	for range b.N {
		rule.Match(url)
	}
}

func BenchmarkMatchWildcard(b *testing.B) {
	// Pattern with multiple wildcards: forces backtracking
	rule, _ := blocklist.Compile("ad*track*pixel*.gif")
	url := "http://example.com/ad-network/track-event/pixel-data.gif?v=123"
	b.ResetTimer()
	for range b.N {
		rule.Match(url)
	}
}

func BenchmarkMatchDomainAnchor(b *testing.B) {
	// Domain-anchored with path: typical adblock rule
	rule, _ := blocklist.Compile("||example.com/ads/*.gif")
	url := "http://example.com/ads/banner123.gif"
	b.ResetTimer()
	for range b.N {
		rule.Match(url)
	}
}

func BenchmarkMatchNoMatch(b *testing.B) {
	// Non-anchored pattern against a long URL that doesn't match: worst case
	rule, _ := blocklist.Compile("zzz-nonexistent-pattern")
	url := "http://cdn.example.com/static/resources/images/v3/long/path/that/forces/many/scans/and/never/matches.gif"
	b.ResetTimer()
	for range b.N {
		rule.Match(url)
	}
}

func TestResourceTypeOption(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		url     string
		resType blocklist.ResourceType
		want    bool
	}{
		// $script only blocks script requests
		{
			name:    "script rule matches script request",
			pattern: "/ads/*.js$script",
			url:     "http://example.com/ads/tracker.js",
			resType: blocklist.ResourceScript,
			want:    true,
		},
		{
			name:    "script rule does not match image request",
			pattern: "/ads/*.js$script",
			url:     "http://example.com/ads/tracker.js",
			resType: blocklist.ResourceImage,
			want:    false,
		},
		{
			name:    "script rule matches unknown type (backward compat)",
			pattern: "/ads/*.js$script",
			url:     "http://example.com/ads/tracker.js",
			resType: 0,
			want:    true,
		},

		// $image only blocks image requests
		{
			name:    "image rule matches image request",
			pattern: "/ads/banner$image",
			url:     "http://example.com/ads/banner.png",
			resType: blocklist.ResourceImage,
			want:    true,
		},
		{
			name:    "image rule does not match script request",
			pattern: "/ads/banner$image",
			url:     "http://example.com/ads/banner.png",
			resType: blocklist.ResourceScript,
			want:    false,
		},

		// $stylesheet blocks CSS requests
		{
			name:    "stylesheet rule matches stylesheet request",
			pattern: "/ads/style$stylesheet",
			url:     "http://example.com/ads/style.css",
			resType: blocklist.ResourceStylesheet,
			want:    true,
		},

		// Multiple types: $script,stylesheet
		{
			name:    "multi-type rule matches script",
			pattern: "/ads/*$script,stylesheet",
			url:     "http://example.com/ads/file.js",
			resType: blocklist.ResourceScript,
			want:    true,
		},
		{
			name:    "multi-type rule matches stylesheet",
			pattern: "/ads/*$script,stylesheet",
			url:     "http://example.com/ads/file.css",
			resType: blocklist.ResourceStylesheet,
			want:    true,
		},
		{
			name:    "multi-type rule does not match image",
			pattern: "/ads/*$script,stylesheet",
			url:     "http://example.com/ads/file.png",
			resType: blocklist.ResourceImage,
			want:    false,
		},

		// Negated types: $~script means "everything except scripts"
		{
			name:    "negated script does not match script request",
			pattern: "/ads/*$~script",
			url:     "http://example.com/ads/file.js",
			resType: blocklist.ResourceScript,
			want:    false,
		},
		{
			name:    "negated script matches image request",
			pattern: "/ads/*$~script",
			url:     "http://example.com/ads/file.png",
			resType: blocklist.ResourceImage,
			want:    true,
		},

		// $subdocument for iframe blocking
		{
			name:    "subdocument rule matches iframe",
			pattern: "||adserver.com^$subdocument",
			url:     "http://adserver.com/widget",
			resType: blocklist.ResourceSubdocument,
			want:    true,
		},
		{
			name:    "subdocument rule does not match document",
			pattern: "||adserver.com^$subdocument",
			url:     "http://adserver.com/widget",
			resType: blocklist.ResourceDocument,
			want:    false,
		},

		// $xmlhttprequest
		{
			name:    "xhr rule matches xhr request",
			pattern: "/api/track$xmlhttprequest",
			url:     "http://example.com/api/track",
			resType: blocklist.ResourceXMLHTTPRequest,
			want:    true,
		},

		// $popup is parsed but never matches network requests
		{
			name:    "popup rule does not match document request",
			pattern: "||popup.example.com^$popup",
			url:     "http://popup.example.com/page",
			resType: blocklist.ResourceDocument,
			want:    false,
		},
		{
			name:    "popup rule matches unknown type (backward compat)",
			pattern: "||popup.example.com^$popup",
			url:     "http://popup.example.com/page",
			resType: 0,
			want:    true,
		},

		// Combined with other options: $script,third-party
		{
			name:    "script+third-party matches cross-origin script",
			pattern: "/ads/*$script,third-party",
			url:     "http://adserver.net/ads/tracker.js",
			resType: blocklist.ResourceScript,
			want:    true,
		},

		// $document for page-level blocking
		{
			name:    "document rule matches document request",
			pattern: "||malware.com^$document",
			url:     "http://malware.com/page",
			resType: blocklist.ResourceDocument,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := blocklist.Compile(tt.pattern)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.pattern, err)
			}
			ctx := blocklist.MatchContext{
				PageDomain:   "other.com",
				ResourceType: tt.resType,
			}
			got := rule.MatchWithContext(tt.url, ctx)
			if got != tt.want {
				t.Errorf("Compile(%q).MatchWithContext(%q, type=%d) = %v, want %v",
					tt.pattern, tt.url, tt.resType, got, tt.want)
			}
		})
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
