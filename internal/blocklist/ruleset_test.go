package blocklist_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"ublproxy/internal/blocklist"
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

func TestRuleSetExceptionOverridesBlock(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddHostname("ads.example.com")
	rs.AddException("@@||ads.example.com/safe-page^")

	// The exception should allow this specific path
	if rs.ShouldBlock("http://ads.example.com/safe-page") {
		t.Error("exception should allow /safe-page")
	}

	// Other paths on the blocked domain should still be blocked
	if !rs.ShouldBlock("http://ads.example.com/tracking.js") {
		t.Error("non-excepted path should still be blocked")
	}
}

func TestRuleSetExceptionHostname(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddHostname("ads.example.com")
	rs.AddException("@@||ads.example.com^")

	// Full hostname exception should allow everything on that domain
	if rs.ShouldBlock("http://ads.example.com/anything") {
		t.Error("hostname exception should allow all paths")
	}
	if rs.ShouldBlock("http://ads.example.com/tracking.js") {
		t.Error("hostname exception should allow all paths")
	}
}

func TestMatchesException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddException("@@||safe.example.com^")
	rs.AddException("@@/ads/acceptable*")

	// Hostname-level exception
	if !rs.MatchesException("https://safe.example.com/page", blocklist.MatchContext{}) {
		t.Error("should match hostname exception")
	}
	// Path-level exception
	if !rs.MatchesException("https://example.com/ads/acceptable-banner.png", blocklist.MatchContext{}) {
		t.Error("should match path exception")
	}
	// No exception for unrelated URL
	if rs.MatchesException("https://ads.example.com/tracker.js", blocklist.MatchContext{}) {
		t.Error("should not match unrelated URL")
	}
	// Nil receiver
	var nilRS *blocklist.RuleSet
	if nilRS.MatchesException("https://safe.example.com/", blocklist.MatchContext{}) {
		t.Error("nil receiver should return false")
	}
}

func TestMatchesExceptionHost(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddException("@@||safe.example.com^")

	if !rs.MatchesExceptionHost("safe.example.com") {
		t.Error("should match excepted host")
	}
	if rs.MatchesExceptionHost("ads.example.com") {
		t.Error("should not match non-excepted host")
	}
}

func TestRuleSetLoadFileWithExceptions(t *testing.T) {
	content := `||ads.example.com^
/tracking.js
@@||ads.example.com/approved^
@@/tracking.js?partner=trusted
`
	f, err := os.CreateTemp("", "exception-test-*.txt")
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
		// Blocked by hostname
		{"http://ads.example.com/banner.gif", true},
		// Exception allows this specific path
		{"http://ads.example.com/approved", false},
		// Blocked by URL pattern
		{"http://other.com/tracking.js", true},
		// Exception allows this specific query
		{"http://other.com/tracking.js?partner=trusted", false},
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

func TestHostnameRuleWithOptionsNotFastPathed(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^$third-party")

	// Same-origin request: $third-party means only block cross-origin.
	// The hostname fast-path would ignore the option and block everything.
	ctx := blocklist.MatchContext{PageDomain: "ads.example.com"}
	if rs.ShouldBlockRequest("http://ads.example.com/page.html", ctx) {
		t.Error("||hostname^$third-party should NOT block same-origin requests")
	}

	// Cross-origin request: should be blocked
	ctx = blocklist.MatchContext{PageDomain: "other.com"}
	if !rs.ShouldBlockRequest("http://ads.example.com/page.html", ctx) {
		t.Error("||hostname^$third-party should block cross-origin requests")
	}
}

func TestLoadURL(t *testing.T) {
	rules := `||ads.example.com^
/tracking.js
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, rules)
	}))
	defer srv.Close()

	rs := blocklist.NewRuleSet()
	if err := rs.LoadURL(srv.URL); err != nil {
		t.Fatalf("LoadURL: %v", err)
	}

	if rs.HostCount() != 1 {
		t.Errorf("expected 1 hostname, got %d", rs.HostCount())
	}
	if !rs.ShouldBlock("http://ads.example.com/banner.gif") {
		t.Error("hostname rule should block")
	}
	if !rs.ShouldBlock("http://other.com/tracking.js") {
		t.Error("pattern rule should block")
	}
}

func TestLoadURLError(t *testing.T) {
	// 404 response should return an error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	rs := blocklist.NewRuleSet()
	err := rs.LoadURL(srv.URL)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("expected HTTP 404 in error, got: %v", err)
	}
}

func TestLoadURLUnreachable(t *testing.T) {
	rs := blocklist.NewRuleSet()
	err := rs.LoadURL("http://127.0.0.1:0/nonexistent")
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestHostnameRuleWithDomainOption(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||tracker.example.com^$domain=news.com")

	// Should only block when page domain is news.com
	ctx := blocklist.MatchContext{PageDomain: "news.com"}
	if !rs.ShouldBlockRequest("http://tracker.example.com/pixel.gif", ctx) {
		t.Error("should block when page domain matches $domain option")
	}

	// Should not block when page domain is different
	ctx = blocklist.MatchContext{PageDomain: "other.com"}
	if rs.ShouldBlockRequest("http://tracker.example.com/pixel.gif", ctx) {
		t.Error("should not block when page domain doesn't match $domain option")
	}
}

// loadEasyList fetches the full EasyList for benchmarking.
// Skips if the download fails (e.g. no network access in CI).
func loadEasyList(tb testing.TB) *blocklist.RuleSet {
	tb.Helper()
	const url = "https://easylist.to/easylist/easylist.txt"
	rs := blocklist.NewRuleSet()
	if err := rs.LoadURL(url); err != nil {
		tb.Skipf("easylist not available: %v", err)
	}
	return rs
}

func BenchmarkShouldBlockEasyList(b *testing.B) {
	rs := loadEasyList(b)
	b.Logf("Loaded %d hostnames, %d URL rules", rs.HostCount(), rs.RuleCount())

	ctx := blocklist.MatchContext{
		PageDomain:   "example.com",
		ResourceType: blocklist.ResourceDocument,
	}

	// Non-blocked URL (worst case): must check all tiers to prove no match
	b.Run("not-blocked", func(b *testing.B) {
		url := "https://www.example.com/articles/2024/interesting-article?ref=home"
		b.ResetTimer()
		for range b.N {
			rs.ShouldBlockRequest(url, ctx)
		}
	})

	// Blocked by hostname map (best case): fast-path hash lookup
	b.Run("blocked-hostname", func(b *testing.B) {
		url := "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"
		b.ResetTimer()
		for range b.N {
			rs.ShouldBlockRequest(url, ctx)
		}
	})

	// Blocked by domain-indexed rule (path pattern match)
	b.Run("blocked-domain-rule", func(b *testing.B) {
		url := "https://cdn.example.com/ads/banner123.gif"
		b.ResetTimer()
		for range b.N {
			rs.ShouldBlockRequest(url, ctx)
		}
	})

	// Blocked by generic rule (substring pattern match)
	b.Run("blocked-generic-rule", func(b *testing.B) {
		url := "https://www.example.com/assets/ad-manager/loader.js"
		b.ResetTimer()
		for range b.N {
			rs.ShouldBlockRequest(url, ctx)
		}
	})

	// Realistic mix: long URL on a CDN that isn't blocked
	b.Run("not-blocked-cdn", func(b *testing.B) {
		url := "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
		b.ResetTimer()
		for range b.N {
			rs.ShouldBlockRequest(url, ctx)
		}
	})
}

func TestImportantOverridesException(t *testing.T) {
	rs := blocklist.NewRuleSet()

	// Block google-analytics, add an exception, then override with $important
	rs.AddLine("||google-analytics.com^")
	rs.AddLine("@@||google-analytics.com^")
	rs.AddLine("||google-analytics.com^$important,third-party")

	ctx := blocklist.MatchContext{PageDomain: "example.com"}

	// $important should override the exception for third-party requests
	if !rs.ShouldBlockRequest("https://google-analytics.com/analytics.js", ctx) {
		t.Error("$important,third-party should override exception for cross-origin requests")
	}

	// Same-origin should not be blocked (the $important rule has $third-party)
	ctx = blocklist.MatchContext{PageDomain: "google-analytics.com"}
	if rs.ShouldBlockRequest("https://google-analytics.com/analytics.js", ctx) {
		t.Error("$important,third-party should not block same-origin requests")
	}
}

func TestImportantWithoutException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||tracker.com^$important")

	// $important without an exception should just block normally
	if !rs.ShouldBlock("https://tracker.com/track") {
		t.Error("$important should block")
	}
}

func TestBadfilterDisablesRule(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^")
	rs.AddLine("||ads.example.com^$badfilter")

	if rs.ShouldBlock("https://ads.example.com/banner.gif") {
		t.Error("$badfilter should disable the matching block rule")
	}
}

func TestBadfilterWithOptions(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||tracker.com^$third-party")
	rs.AddLine("||tracker.com^$third-party,badfilter")

	ctx := blocklist.MatchContext{PageDomain: "example.com"}
	if rs.ShouldBlockRequest("https://tracker.com/collect", ctx) {
		t.Error("$badfilter should disable the matching block rule with options")
	}
}

func TestBadfilterDisablesException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^")
	rs.AddLine("@@||ads.example.com^")
	rs.AddLine("@@||ads.example.com^$badfilter")

	// The exception is badfiltered, so the block rule should take effect
	if !rs.ShouldBlock("https://ads.example.com/banner.gif") {
		t.Error("$badfilter on exception should re-enable the block rule")
	}
}

func TestBadfilterSubstringInURL(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// "badfilter" appears in the URL pattern, not as an option
	rs.AddLine("||badfilter.example.com^")

	if !rs.ShouldBlock("https://badfilter.example.com/page") {
		t.Error("badfilter in URL pattern should not be treated as $badfilter option")
	}
}

func TestBadfilterNoEffectOnNonMatching(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^")
	rs.AddLine("||other.com^$badfilter") // doesn't match the rule above

	if !rs.ShouldBlock("https://ads.example.com/banner.gif") {
		t.Error("$badfilter on a different rule should not affect ads.example.com")
	}
}

func TestParseErrorsCountAndWarning(t *testing.T) {
	rs := blocklist.NewRuleSet()

	var warnings []string
	rs.OnWarning = func(msg string) {
		warnings = append(warnings, msg)
	}

	rs.AddLine("||good.com^")
	rs.AddLine("/[invalid/")    // bad regex
	rs.AddLine("@@/[also-bad/") // bad regex in exception
	rs.AddLine("||also-good.com^")

	if rs.ParseErrors() != 2 {
		t.Errorf("ParseErrors() = %d, want 2", rs.ParseErrors())
	}
	if len(warnings) != 2 {
		t.Errorf("got %d warnings, want 2", len(warnings))
	}
	// Valid rules should still work
	if !rs.ShouldBlock("https://good.com/page") {
		t.Error("valid rule should still block")
	}
	if !rs.ShouldBlock("https://also-good.com/page") {
		t.Error("valid rule added after bad regex should still block")
	}
}

func TestPreparseIfDirective(t *testing.T) {
	// !#if false should skip the enclosed block
	rs := blocklist.NewRuleSet()
	err := rs.LoadReader(strings.NewReader(`||always-blocked.com^
!#if false
||should-be-skipped.com^
!#endif
||also-blocked.com^
`))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}

	if !rs.ShouldBlock("https://always-blocked.com/page") {
		t.Error("rule before !#if should be active")
	}
	if rs.ShouldBlock("https://should-be-skipped.com/page") {
		t.Error("rule inside !#if false should be skipped")
	}
	if !rs.ShouldBlock("https://also-blocked.com/page") {
		t.Error("rule after !#endif should be active")
	}
}

func TestPreparseIfElseDirective(t *testing.T) {
	rs := blocklist.NewRuleSet()
	err := rs.LoadReader(strings.NewReader(`!#if false
||skipped.com^
!#else
||included.com^
!#endif
`))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}

	if rs.ShouldBlock("https://skipped.com/page") {
		t.Error("rule in false branch should be skipped")
	}
	if !rs.ShouldBlock("https://included.com/page") {
		t.Error("rule in else branch should be included")
	}
}

func TestPreparseIfNegation(t *testing.T) {
	// !#if !false evaluates to true
	rs := blocklist.NewRuleSet()
	err := rs.LoadReader(strings.NewReader(`!#if !false
||included.com^
!#endif
`))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}

	if !rs.ShouldBlock("https://included.com/page") {
		t.Error("rule in !#if !false should be included")
	}
}

func TestPreparseIfEnvTokens(t *testing.T) {
	// env_chromium is false for a proxy
	rs := blocklist.NewRuleSet()
	err := rs.LoadReader(strings.NewReader(`!#if env_chromium
||chromium-only.com^
!#endif
!#if cap_html_filtering
||html-filter.com^
!#endif
`))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}

	if rs.ShouldBlock("https://chromium-only.com/page") {
		t.Error("env_chromium should be false for proxy")
	}
	if !rs.ShouldBlock("https://html-filter.com/page") {
		t.Error("cap_html_filtering should be true for proxy")
	}
}

func TestPreparseIfNested(t *testing.T) {
	// Nested !#if blocks
	rs := blocklist.NewRuleSet()
	err := rs.LoadReader(strings.NewReader(`!#if ext_ublock
||outer-true.com^
!#if false
||inner-false.com^
!#endif
||after-inner.com^
!#endif
`))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}

	if !rs.ShouldBlock("https://outer-true.com/page") {
		t.Error("outer true block should be active")
	}
	if rs.ShouldBlock("https://inner-false.com/page") {
		t.Error("inner false block should be skipped")
	}
	if !rs.ShouldBlock("https://after-inner.com/page") {
		t.Error("rule after inner !#endif should be active")
	}
}

func TestPreparseIfLogicalOperators(t *testing.T) {
	rs := blocklist.NewRuleSet()
	err := rs.LoadReader(strings.NewReader(`!#if ext_ublock && cap_html_filtering
||both-true.com^
!#endif
!#if ext_ublock && env_firefox
||one-false.com^
!#endif
!#if false || ext_ublock
||or-true.com^
!#endif
`))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}

	if !rs.ShouldBlock("https://both-true.com/page") {
		t.Error("true && true should be true")
	}
	if rs.ShouldBlock("https://one-false.com/page") {
		t.Error("true && false should be false")
	}
	if !rs.ShouldBlock("https://or-true.com/page") {
		t.Error("false || true should be true")
	}
}

func TestImportantHostnameRule(t *testing.T) {
	rs := blocklist.NewRuleSet()

	// $important on a hostname rule — should NOT go to hostname fast path
	// because it needs option evaluation
	rs.AddLine("||analytics.com^$important")
	rs.AddLine("@@||analytics.com^")

	if !rs.ShouldBlock("https://analytics.com/collect") {
		t.Error("$important should override the exception")
	}
}
