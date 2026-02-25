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
