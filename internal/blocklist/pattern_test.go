package blocklist_test

import (
	"net/http"
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

func TestTypeAliases(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		url     string
		resType blocklist.ResourceType
		want    bool
	}{
		// $doc alias for $document
		{"doc matches document", "||malware.com^$doc", "http://malware.com/page", blocklist.ResourceDocument, true},
		{"doc does not match script", "||malware.com^$doc", "http://malware.com/page", blocklist.ResourceScript, false},

		// $css alias for $stylesheet
		{"css matches stylesheet", "||adserver.com^$css", "http://adserver.com/style.css", blocklist.ResourceStylesheet, true},
		{"css does not match script", "||adserver.com^$css", "http://adserver.com/style.css", blocklist.ResourceScript, false},

		// $xhr alias for $xmlhttprequest
		{"xhr matches xmlhttprequest", "||adserver.com^$xhr", "http://adserver.com/api/track", blocklist.ResourceXMLHTTPRequest, true},
		{"xhr does not match image", "||adserver.com^$xhr", "http://adserver.com/api/track", blocklist.ResourceImage, false},

		// $frame alias for $subdocument
		{"frame matches subdocument", "||adserver.com^$frame", "http://adserver.com/widget", blocklist.ResourceSubdocument, true},
		{"frame does not match document", "||adserver.com^$frame", "http://adserver.com/widget", blocklist.ResourceDocument, false},
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
				t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestPartyShorthands(t *testing.T) {
	ctx := blocklist.MatchContext{PageDomain: "example.com"}

	// $1p is equivalent to $~third-party (first-party only)
	rule, _ := blocklist.Compile("/ads/*$1p")
	if !rule.MatchWithContext("http://example.com/ads/banner.gif", ctx) {
		t.Error("$1p should match same-origin request")
	}
	if rule.MatchWithContext("http://adserver.net/ads/banner.gif", ctx) {
		t.Error("$1p should not match cross-origin request")
	}

	// $first-party is equivalent to $~third-party
	rule, _ = blocklist.Compile("/ads/*$first-party")
	if !rule.MatchWithContext("http://example.com/ads/banner.gif", ctx) {
		t.Error("$first-party should match same-origin request")
	}
	if rule.MatchWithContext("http://adserver.net/ads/banner.gif", ctx) {
		t.Error("$first-party should not match cross-origin request")
	}

	// $3p is equivalent to $third-party
	rule, _ = blocklist.Compile("/ads/*$3p")
	if !rule.MatchWithContext("http://adserver.net/ads/banner.gif", ctx) {
		t.Error("$3p should match cross-origin request")
	}
	if rule.MatchWithContext("http://example.com/ads/banner.gif", ctx) {
		t.Error("$3p should not match same-origin request")
	}
}

func TestFromAlias(t *testing.T) {
	// $from= is an alias for $domain=
	rule, _ := blocklist.Compile("/ads/*$from=example.com")

	if !rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "example.com"}) {
		t.Error("$from= should work like $domain=")
	}
	if rule.MatchWithContext("http://adserver.net/ads/banner.gif", blocklist.MatchContext{PageDomain: "other.com"}) {
		t.Error("$from= should restrict to specified domain")
	}
}

func TestAllOption(t *testing.T) {
	rule, err := blocklist.Compile("||malware.com^$all")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// $all should match every resource type
	types := []blocklist.ResourceType{
		blocklist.ResourceDocument,
		blocklist.ResourceScript,
		blocklist.ResourceStylesheet,
		blocklist.ResourceImage,
		blocklist.ResourceFont,
		blocklist.ResourceXMLHTTPRequest,
		blocklist.ResourceSubdocument,
		blocklist.ResourceMedia,
		blocklist.ResourceWebSocket,
		blocklist.ResourceObject,
		blocklist.ResourcePopup,
		blocklist.ResourceOther,
	}
	for _, rt := range types {
		ctx := blocklist.MatchContext{PageDomain: "other.com", ResourceType: rt}
		if !rule.MatchWithContext("http://malware.com/page", ctx) {
			t.Errorf("$all should match resource type %d", rt)
		}
	}
}

func TestNoopPlaceholder(t *testing.T) {
	// Single noop should be silently ignored
	rule, err := blocklist.Compile("||example.com^$script,_")
	if err != nil {
		t.Fatalf("Compile with noop: %v", err)
	}
	ctx := blocklist.MatchContext{PageDomain: "other.com", ResourceType: blocklist.ResourceScript}
	if !rule.MatchWithContext("http://example.com/ad.js", ctx) {
		t.Error("noop _ should not affect rule matching")
	}

	// Multiple noops
	rule, err = blocklist.Compile("||example.com^$_,image,___")
	if err != nil {
		t.Fatalf("Compile with multiple noops: %v", err)
	}
	ctx = blocklist.MatchContext{PageDomain: "other.com", ResourceType: blocklist.ResourceImage}
	if !rule.MatchWithContext("http://example.com/ad.png", ctx) {
		t.Error("multiple noops should not affect rule matching")
	}
}

func TestDenyallowOption(t *testing.T) {
	// $denyallow=x.com|y.com: block everything except requests to x.com or y.com
	rule, err := blocklist.Compile("*$3p,script,denyallow=x.com|y.com,domain=a.com")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctx := blocklist.MatchContext{PageDomain: "a.com", ResourceType: blocklist.ResourceScript}

	// Requests to x.com should be allowed (denyallow exception)
	if rule.MatchWithContext("https://x.com/script.js", ctx) {
		t.Error("denyallow should exempt x.com")
	}

	// Requests to y.com should be allowed
	if rule.MatchWithContext("https://y.com/lib.js", ctx) {
		t.Error("denyallow should exempt y.com")
	}

	// Requests to other domains should be blocked
	if !rule.MatchWithContext("https://tracker.net/ads.js", ctx) {
		t.Error("denyallow should block non-exempted domains")
	}

	// Subdomain of allowed domain should also be exempted
	if rule.MatchWithContext("https://cdn.x.com/script.js", ctx) {
		t.Error("denyallow should exempt subdomains of allowed domains")
	}
}

func TestToOption(t *testing.T) {
	// $to=tracker.com: only block requests going TO tracker.com
	rule, err := blocklist.Compile("*$script,to=tracker.com")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctx := blocklist.MatchContext{PageDomain: "example.com", ResourceType: blocklist.ResourceScript}

	if !rule.MatchWithContext("https://tracker.com/script.js", ctx) {
		t.Error("$to should match requests to the specified domain")
	}
	if rule.MatchWithContext("https://other.com/script.js", ctx) {
		t.Error("$to should not match requests to other domains")
	}
	// Subdomain should match
	if !rule.MatchWithContext("https://sub.tracker.com/script.js", ctx) {
		t.Error("$to should match subdomains")
	}
}

func TestToNegated(t *testing.T) {
	// $to=~example.it: block requests to all domains EXCEPT example.it
	rule, err := blocklist.Compile("||it^$3p,to=~example.it")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctx := blocklist.MatchContext{PageDomain: "other.com", ResourceType: blocklist.ResourceScript}

	if rule.MatchWithContext("https://example.it/page", ctx) {
		t.Error("$to=~ should exclude the negated domain")
	}
	if !rule.MatchWithContext("https://tracker.it/page", ctx) {
		t.Error("$to=~ should match non-excluded domains")
	}
}

func TestToMultipleDomains(t *testing.T) {
	rule, err := blocklist.Compile("*$script,to=a.com|b.com")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctx := blocklist.MatchContext{PageDomain: "example.com", ResourceType: blocklist.ResourceScript}

	if !rule.MatchWithContext("https://a.com/x.js", ctx) {
		t.Error("$to should match first domain")
	}
	if !rule.MatchWithContext("https://b.com/x.js", ctx) {
		t.Error("$to should match second domain")
	}
	if rule.MatchWithContext("https://c.com/x.js", ctx) {
		t.Error("$to should not match unlisted domain")
	}
}

func TestMethodOption(t *testing.T) {
	// $method=post: only match POST requests
	rule, err := blocklist.Compile("||tracker.com^$method=post")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ctx := blocklist.MatchContext{PageDomain: "example.com", Method: "POST"}
	if !rule.MatchWithContext("https://tracker.com/collect", ctx) {
		t.Error("$method=post should match POST requests")
	}

	ctx = blocklist.MatchContext{PageDomain: "example.com", Method: "GET"}
	if rule.MatchWithContext("https://tracker.com/collect", ctx) {
		t.Error("$method=post should not match GET requests")
	}
}

func TestMethodOptionMultiple(t *testing.T) {
	rule, err := blocklist.Compile("||tracker.com^$method=post|get")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	for _, method := range []string{"POST", "GET"} {
		ctx := blocklist.MatchContext{PageDomain: "example.com", Method: method}
		if !rule.MatchWithContext("https://tracker.com/collect", ctx) {
			t.Errorf("$method=post|get should match %s", method)
		}
	}

	ctx := blocklist.MatchContext{PageDomain: "example.com", Method: "PUT"}
	if rule.MatchWithContext("https://tracker.com/collect", ctx) {
		t.Error("$method=post|get should not match PUT")
	}
}

func TestMethodOptionNegated(t *testing.T) {
	rule, err := blocklist.Compile("||tracker.com^$method=~get")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ctx := blocklist.MatchContext{PageDomain: "example.com", Method: "GET"}
	if rule.MatchWithContext("https://tracker.com/collect", ctx) {
		t.Error("$method=~get should not match GET requests")
	}

	ctx = blocklist.MatchContext{PageDomain: "example.com", Method: "POST"}
	if !rule.MatchWithContext("https://tracker.com/collect", ctx) {
		t.Error("$method=~get should match non-GET requests")
	}
}

func TestRegexPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		url     string
		want    bool
	}{
		{"basic regex", "/banner\\d+/", "http://example.com/banner123.gif", true},
		{"regex no match", "/banner\\d+/", "http://example.com/bannerXYZ.gif", false},
		{"regex with anchors", "/^https?:\\/\\/ads\\./", "https://ads.example.com/track", true},
		{"regex no match anchor", "/^https?:\\/\\/ads\\./", "https://example.com/ads/", false},
		{"regex case insensitive default", "/BaNnEr/", "http://example.com/banner.gif", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := blocklist.Compile(tt.pattern)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.pattern, err)
			}
			got := rule.Match(tt.url)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestRegexWithOptions(t *testing.T) {
	rule, err := blocklist.Compile("/tracker\\.js/$script,3p")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ctx := blocklist.MatchContext{PageDomain: "example.com", ResourceType: blocklist.ResourceScript}
	if !rule.MatchWithContext("https://ads.net/tracker.js/", ctx) {
		t.Error("regex with options should match")
	}

	ctx = blocklist.MatchContext{PageDomain: "example.com", ResourceType: blocklist.ResourceImage}
	if rule.MatchWithContext("https://ads.net/tracker.js/", ctx) {
		t.Error("regex $script should not match image type")
	}
}

func TestRegexMatchCase(t *testing.T) {
	// Without $match-case, regex should be case-insensitive
	rule, _ := blocklist.Compile("/BannerAd/")
	if !rule.Match("http://example.com/bannerad.gif") {
		t.Error("regex without $match-case should be case-insensitive")
	}

	// With $match-case, regex should be case-sensitive
	rule, _ = blocklist.Compile("/BannerAd/$match-case")
	if !rule.Match("http://example.com/BannerAd.gif") {
		t.Error("regex with $match-case should match exact case")
	}
	if rule.Match("http://example.com/bannerad.gif") {
		t.Error("regex with $match-case should not match wrong case")
	}
}

func TestRegexInvalid(t *testing.T) {
	_, err := blocklist.Compile("/[invalid/")
	if err == nil {
		t.Error("invalid regex should return compile error")
	}
}

func TestEntityMatchingInDomainOption(t *testing.T) {
	// $domain=google.*: match on any google TLD
	rule, err := blocklist.Compile("/ads/*$domain=google.*")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	tests := []struct {
		page string
		want bool
	}{
		{"google.com", true},
		{"google.co.uk", true},
		{"google.de", true},
		{"sub.google.com", true},
		{"notgoogle.com", false},
		{"example.com", false},
	}
	for _, tt := range tests {
		ctx := blocklist.MatchContext{PageDomain: tt.page}
		got := rule.MatchWithContext("http://adserver.net/ads/banner.gif", ctx)
		if got != tt.want {
			t.Errorf("$domain=google.* page=%s: got %v, want %v", tt.page, got, tt.want)
		}
	}
}

func TestEntityMatchingInDenyallow(t *testing.T) {
	// $denyallow=google.*: exempt requests to any google TLD
	rule, err := blocklist.Compile("*$3p,script,denyallow=google.*,domain=example.com")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctx := blocklist.MatchContext{PageDomain: "example.com", ResourceType: blocklist.ResourceScript}

	if rule.MatchWithContext("https://google.com/script.js", ctx) {
		t.Error("denyallow=google.* should exempt google.com")
	}
	if rule.MatchWithContext("https://google.co.uk/script.js", ctx) {
		t.Error("denyallow=google.* should exempt google.co.uk")
	}
	if !rule.MatchWithContext("https://tracker.net/script.js", ctx) {
		t.Error("denyallow=google.* should not exempt tracker.net")
	}
}

func TestEntityMatchingInTo(t *testing.T) {
	rule, err := blocklist.Compile("*$script,to=google.*")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ctx := blocklist.MatchContext{PageDomain: "example.com", ResourceType: blocklist.ResourceScript}

	if !rule.MatchWithContext("https://google.de/script.js", ctx) {
		t.Error("$to=google.* should match google.de")
	}
	if rule.MatchWithContext("https://other.com/script.js", ctx) {
		t.Error("$to=google.* should not match other.com")
	}
}

func TestRemoveParam(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||example.com^$removeparam=fbclid")

	tests := []struct {
		url  string
		want string
	}{
		// Strip the matching param
		{"https://example.com/page?fbclid=abc123", "https://example.com/page"},
		// Preserve other params
		{"https://example.com/page?q=hello&fbclid=abc123", "https://example.com/page?q=hello"},
		{"https://example.com/page?fbclid=abc&q=hello", "https://example.com/page?q=hello"},
		{"https://example.com/page?a=1&fbclid=abc&b=2", "https://example.com/page?a=1&b=2"},
		// No matching param — no change
		{"https://example.com/page?q=hello", "https://example.com/page?q=hello"},
		// No query string — no change
		{"https://example.com/page", "https://example.com/page"},
		// Non-matching domain — no change
		{"https://other.com/page?fbclid=abc123", "https://other.com/page?fbclid=abc123"},
	}

	ctx := blocklist.MatchContext{}
	for _, tt := range tests {
		got := rs.ApplyRemoveParams(tt.url, ctx)
		if got != tt.want {
			t.Errorf("ApplyRemoveParams(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestRemoveParamRegex(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("*$removeparam=/^utm_/")

	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com/page?utm_source=twitter&utm_medium=social", "https://example.com/page"},
		{"https://example.com/page?q=hello&utm_source=twitter", "https://example.com/page?q=hello"},
		{"https://example.com/page?q=hello", "https://example.com/page?q=hello"},
	}

	ctx := blocklist.MatchContext{}
	for _, tt := range tests {
		got := rs.ApplyRemoveParams(tt.url, ctx)
		if got != tt.want {
			t.Errorf("ApplyRemoveParams(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestRemoveParamEmpty(t *testing.T) {
	// $removeparam without a value strips ALL query parameters
	rs := blocklist.NewRuleSet()
	rs.AddLine("||tracker.com^$removeparam")

	got := rs.ApplyRemoveParams("https://tracker.com/page?a=1&b=2", blocklist.MatchContext{})
	want := "https://tracker.com/page"
	if got != want {
		t.Errorf("ApplyRemoveParams = %q, want %q", got, want)
	}
}

func TestCSPHeaders(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||example.com^$csp=script-src 'none'")
	rs.AddLine("||example.com^$csp=style-src 'self'")

	ctx := blocklist.MatchContext{}
	headers := rs.ApplyCSPHeaders("https://example.com/page", ctx)
	if len(headers) != 2 {
		t.Fatalf("got %d CSP headers, want 2", len(headers))
	}

	// Should not apply to non-matching URLs
	headers = rs.ApplyCSPHeaders("https://other.com/page", ctx)
	if len(headers) != 0 {
		t.Fatalf("got %d CSP headers for non-matching URL, want 0", len(headers))
	}
}

func TestCSPException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||example.com^$csp=script-src 'none'")
	rs.AddLine("||example.com^$csp=style-src 'self'")
	// Blanket exception disables all CSP for this domain
	rs.AddLine("@@||example.com/safe^$csp")

	ctx := blocklist.MatchContext{}

	// The exception should disable all CSP injection for /safe paths
	headers := rs.ApplyCSPHeaders("https://example.com/safe/page", ctx)
	if len(headers) != 0 {
		t.Fatalf("got %d CSP headers, want 0 (blanket exception)", len(headers))
	}

	// Non-excepted path still gets CSP
	headers = rs.ApplyCSPHeaders("https://example.com/other", ctx)
	if len(headers) != 2 {
		t.Fatalf("got %d CSP headers, want 2", len(headers))
	}
}

func TestCSPSpecificException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||example.com^$csp=script-src 'none'")
	rs.AddLine("||example.com^$csp=style-src 'self'")
	// Specific exception disables only the matching CSP directive
	rs.AddLine("@@||example.com^$csp=script-src 'none'")

	ctx := blocklist.MatchContext{}
	headers := rs.ApplyCSPHeaders("https://example.com/page", ctx)
	if len(headers) != 1 {
		t.Fatalf("got %d CSP headers, want 1", len(headers))
	}
	if headers[0] != "style-src 'self'" {
		t.Errorf("CSP header = %q, want %q", headers[0], "style-src 'self'")
	}
}

func TestPermissionsHeaders(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||example.com^$permissions=browsing-topics=()")
	rs.AddLine("||example.com^$permissions=autoplay=()")

	ctx := blocklist.MatchContext{}
	headers := rs.ApplyPermissionsHeaders("https://example.com/page", ctx)
	if len(headers) != 2 {
		t.Fatalf("got %d Permissions headers, want 2", len(headers))
	}

	// Should not apply to non-matching URLs
	headers = rs.ApplyPermissionsHeaders("https://other.com/page", ctx)
	if len(headers) != 0 {
		t.Fatalf("got %d Permissions headers for non-matching URL, want 0", len(headers))
	}
}

func TestPermissionsException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||example.com^$permissions=browsing-topics=()")
	// Blanket exception
	rs.AddLine("@@||example.com/safe^$permissions")

	ctx := blocklist.MatchContext{}

	headers := rs.ApplyPermissionsHeaders("https://example.com/safe/page", ctx)
	if len(headers) != 0 {
		t.Fatalf("got %d Permissions headers, want 0 (blanket exception)", len(headers))
	}

	headers = rs.ApplyPermissionsHeaders("https://example.com/other", ctx)
	if len(headers) != 1 {
		t.Fatalf("got %d Permissions headers, want 1", len(headers))
	}
}

func TestHeaderBlockPresence(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("*$script,header=via")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}
	headers := http.Header{}

	// No header present — should not block
	if rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers) {
		t.Error("should not block when header is absent")
	}

	// Header present — should block
	headers.Set("Via", "1.1 google")
	if !rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers) {
		t.Error("should block when header is present")
	}
}

func TestHeaderBlockLiteralValue(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("*$script,header=via:1.1 google")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}

	// Matching value
	headers := http.Header{}
	headers.Set("Via", "1.1 google")
	if !rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers) {
		t.Error("should block when header value matches")
	}

	// Non-matching value
	headers2 := http.Header{}
	headers2.Set("Via", "1.1 varnish")
	if rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers2) {
		t.Error("should not block when header value doesn't match")
	}
}

func TestHeaderBlockRegex(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`*$script,header=via:/1\.1\s+google/`)

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}

	headers := http.Header{}
	headers.Set("Via", "1.1  google")
	if !rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers) {
		t.Error("should block when regex matches")
	}

	headers2 := http.Header{}
	headers2.Set("Via", "1.1 varnish")
	if rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers2) {
		t.Error("should not block when regex doesn't match")
	}
}

func TestHeaderBlockNegated(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("*$script,header=via:~1.1 google")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}

	// Non-matching value — should block (negated)
	headers := http.Header{}
	headers.Set("Via", "1.1 varnish")
	if !rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers) {
		t.Error("should block when negated value doesn't match")
	}

	// Matching value — should NOT block (negated)
	headers2 := http.Header{}
	headers2.Set("Via", "1.1 google")
	if rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers2) {
		t.Error("should not block when negated value matches")
	}
}

func TestHeaderException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("*$script,header=via:1.1 google")
	rs.AddLine("@@*$script,header")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}
	headers := http.Header{}
	headers.Set("Via", "1.1 google")

	// Blanket exception should disable all $header blocking
	if rs.ShouldBlockByHeader("https://example.com/script.js", ctx, headers) {
		t.Error("blanket header exception should prevent blocking")
	}
}

func TestCSPPipeAsSeparator(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// Per uBO spec, $permissions uses | as separator (converted to , internally)
	rs.AddLine("||example.com^$permissions=browsing-topics=()|autoplay=()")

	ctx := blocklist.MatchContext{}
	headers := rs.ApplyPermissionsHeaders("https://example.com/page", ctx)
	// Should produce one header with comma-separated policies
	if len(headers) != 1 {
		t.Fatalf("got %d Permissions headers, want 1", len(headers))
	}
	want := "browsing-topics=(), autoplay=()"
	if headers[0] != want {
		t.Errorf("Permissions header = %q, want %q", headers[0], want)
	}
}

func TestRedirectBasic(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// $redirect creates a block rule AND a redirect directive
	rs.AddLine("||ad.example.com/banner.js$script,redirect=noopjs")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}

	// URL should be blocked
	if !rs.ShouldBlockRequest("https://ad.example.com/banner.js", ctx) {
		t.Error("$redirect rule should block the request")
	}

	// Should return the redirect resource
	resource, ok := rs.MatchRedirect("https://ad.example.com/banner.js", ctx)
	if !ok {
		t.Fatal("should match a redirect resource")
	}
	if resource != "noopjs" {
		t.Errorf("redirect resource = %q, want %q", resource, "noopjs")
	}

	// Non-matching URL should not redirect
	_, ok = rs.MatchRedirect("https://other.com/script.js", ctx)
	if ok {
		t.Error("should not match redirect for non-matching URL")
	}
}

func TestRedirectRuleOnly(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// $redirect-rule only redirects if independently blocked
	rs.AddLine("||ad.example.com/banner.js$script,redirect-rule=noopjs")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}

	// Should NOT be blocked (redirect-rule doesn't create a block rule)
	if rs.ShouldBlockRequest("https://ad.example.com/banner.js", ctx) {
		t.Error("$redirect-rule should NOT block the request on its own")
	}

	// Should still match redirect directive (proxy checks after independent block)
	resource, ok := rs.MatchRedirect("https://ad.example.com/banner.js", ctx)
	if !ok {
		t.Fatal("should match redirect-rule directive")
	}
	if resource != "noopjs" {
		t.Errorf("redirect resource = %q, want %q", resource, "noopjs")
	}
}

func TestRedirectException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ad.example.com/banner.js$script,redirect=noopjs")
	rs.AddLine("@@||ad.example.com/banner.js$script,redirect-rule=noopjs")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}

	// Specific exception should disable the redirect
	_, ok := rs.MatchRedirect("https://ad.example.com/banner.js", ctx)
	if ok {
		t.Error("redirect exception should prevent redirect")
	}
}

func TestRedirectBlanketException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ad.example.com/banner.js$script,redirect=noopjs")
	rs.AddLine("@@||ad.example.com^$script,redirect-rule")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceScript}

	// Blanket exception should disable all redirects
	_, ok := rs.MatchRedirect("https://ad.example.com/banner.js", ctx)
	if ok {
		t.Error("blanket redirect exception should prevent all redirects")
	}
}

func TestRedirectEmptyAlias(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// $empty is alias for $redirect=empty
	rs.AddLine("||tracker.com^$empty")

	ctx := blocklist.MatchContext{}

	if !rs.ShouldBlockRequest("https://tracker.com/pixel", ctx) {
		t.Error("$empty should block")
	}

	resource, ok := rs.MatchRedirect("https://tracker.com/pixel", ctx)
	if !ok {
		t.Fatal("$empty should create a redirect to 'empty'")
	}
	if resource != "empty" {
		t.Errorf("redirect resource = %q, want %q", resource, "empty")
	}
}

func TestRedirectMp4Alias(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// $mp4 is alias for $redirect=noopmp4-1s,$media
	rs.AddLine("||ads.example.com^$mp4")

	ctx := blocklist.MatchContext{ResourceType: blocklist.ResourceMedia}

	if !rs.ShouldBlockRequest("https://ads.example.com/video", ctx) {
		t.Error("$mp4 should block")
	}

	resource, ok := rs.MatchRedirect("https://ads.example.com/video", ctx)
	if !ok {
		t.Fatal("$mp4 should create a redirect to 'noopmp4-1s'")
	}
	if resource != "noopmp4-1s" {
		t.Errorf("redirect resource = %q, want %q", resource, "noopmp4-1s")
	}
}

func TestRedirectResourceLookup(t *testing.T) {
	// Verify the resource library resolves common resource names
	tests := []struct {
		name        string
		wantType    string
		wantNonZero bool
	}{
		{"noopjs", "application/javascript", true},
		{"noop.js", "application/javascript", true},
		{"1x1.gif", "image/gif", true},
		{"2x2.png", "image/png", true},
		{"3x2.png", "image/png", true},
		{"32x32.png", "image/png", true},
		{"noop.css", "text/css", false}, // empty content is fine
		{"noop.html", "text/html", true},
		{"noopframe", "text/html", true}, // alias for noop.html
		{"noop.txt", "text/plain", false},
		{"noop.json", "application/json", true},
		{"empty", "", false},
		{"none", "", false},
		{"noopmp4-1s", "video/mp4", true},
		{"noop-1s.mp4", "video/mp4", true}, // alias
		{"noop-0.1s.mp3", "audio/mpeg", true},
		{"noop-0.5s.mp3", "audio/mpeg", true},
		{"unknown-resource", "", false},
	}

	for _, tt := range tests {
		res, ok := blocklist.LookupRedirectResource(tt.name)
		if tt.name == "unknown-resource" {
			if ok {
				t.Errorf("LookupRedirectResource(%q) should return false", tt.name)
			}
			continue
		}
		if !ok {
			t.Errorf("LookupRedirectResource(%q) not found", tt.name)
			continue
		}
		if res.ContentType != tt.wantType {
			t.Errorf("LookupRedirectResource(%q).ContentType = %q, want %q", tt.name, res.ContentType, tt.wantType)
		}
		if tt.wantNonZero && len(res.Body) == 0 {
			t.Errorf("LookupRedirectResource(%q).Body is empty, want non-zero", tt.name)
		}
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
