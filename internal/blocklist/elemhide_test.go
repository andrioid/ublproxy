package blocklist_test

import (
	"strings"
	"testing"

	"ublproxy/internal/blocklist"
)

// selectorPresent returns true if the selector appears in the CSS.
func selectorPresent(eh *blocklist.ElementHiding, sel string) bool {
	if eh == nil {
		return false
	}
	return strings.Contains(eh.CSS, sel)
}

func TestElementHidingForDomain(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")
	rs.AddLine("##.tracking-pixel")
	rs.AddLine("example.com##.site-specific-ad")
	rs.AddLine("~example.com##.not-on-example")
	rs.AddLine("other.com,example.com##.multi-domain")

	tests := []struct {
		domain   string
		contains []string
		excludes []string
	}{
		{
			domain:   "example.com",
			contains: []string{".ad-banner", ".tracking-pixel", ".site-specific-ad", ".multi-domain"},
			excludes: []string{".not-on-example"},
		},
		{
			domain:   "sub.example.com",
			contains: []string{".ad-banner", ".tracking-pixel", ".site-specific-ad", ".multi-domain"},
			excludes: []string{".not-on-example"},
		},
		{
			domain:   "other.com",
			contains: []string{".ad-banner", ".tracking-pixel", ".not-on-example", ".multi-domain"},
			excludes: []string{".site-specific-ad"},
		},
		{
			domain:   "random.org",
			contains: []string{".ad-banner", ".tracking-pixel", ".not-on-example"},
			excludes: []string{".site-specific-ad", ".multi-domain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			eh := rs.ElementHidingForDomain(tt.domain)
			for _, sel := range tt.contains {
				if !selectorPresent(eh, sel) {
					t.Errorf("ElementHiding for %q should contain %q", tt.domain, sel)
				}
			}
			for _, sel := range tt.excludes {
				if selectorPresent(eh, sel) {
					t.Errorf("ElementHiding for %q should NOT contain %q", tt.domain, sel)
				}
			}
		})
	}
}

func TestElementHidingComplexSelector(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com##div .ad-child")

	eh := rs.ElementHidingForDomain("example.com")
	if eh == nil {
		t.Fatal("expected non-nil ElementHiding")
	}

	if !strings.Contains(eh.CSS, "div .ad-child") {
		t.Errorf("complex selector should be in CSS, got:\n%s", eh.CSS)
	}
	if !strings.Contains(eh.CSS, "display: none !important") {
		t.Errorf("CSS should use 'display: none !important', got:\n%s", eh.CSS)
	}
}

func TestElementHidingEmpty(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com##.ad")

	eh := rs.ElementHidingForDomain("other.com")
	if eh != nil {
		t.Errorf("expected nil ElementHiding for non-matching domain, got: %+v", eh)
	}
}

func TestElementHidingNilSafe(t *testing.T) {
	var rs *blocklist.RuleSet
	eh := rs.ElementHidingForDomain("example.com")
	if eh != nil {
		t.Errorf("nil RuleSet should return nil, got: %+v", eh)
	}
}

func TestElementHideException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")
	rs.AddLine("example.com#@#.ad-banner")

	// On example.com, the exception should prevent .ad-banner from appearing
	eh := rs.ElementHidingForDomain("example.com")
	if selectorPresent(eh, ".ad-banner") {
		t.Error("exception should prevent .ad-banner on example.com")
	}

	// On other domains, .ad-banner should still be present
	eh = rs.ElementHidingForDomain("other.com")
	if !selectorPresent(eh, ".ad-banner") {
		t.Error(".ad-banner should be present on other.com")
	}
}

func TestCosmeticFilterExceptions(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("@@||example.com^$elemhide")
	rs.AddLine("@@||news.com^$generichide")
	rs.AddLine("@@||blog.com^$specifichide")

	tests := []struct {
		url  string
		want blocklist.CosmeticFilter
	}{
		{"https://example.com/page", blocklist.CosmeticElemHide},
		{"https://sub.example.com/page", blocklist.CosmeticElemHide},
		{"https://news.com/article", blocklist.CosmeticGenericHide},
		{"https://blog.com/post", blocklist.CosmeticSpecificHide},
		{"https://other.com/page", 0},
	}

	for _, tt := range tests {
		got := rs.CosmeticFilterExceptions(tt.url)
		if got != tt.want {
			t.Errorf("CosmeticFilterExceptions(%q) = %d, want %d", tt.url, got, tt.want)
		}
	}
}

func TestCosmeticFilterExceptionAliases(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("@@||a.com^$ehide")
	rs.AddLine("@@||b.com^$ghide")
	rs.AddLine("@@||c.com^$shide")

	if rs.CosmeticFilterExceptions("https://a.com/") != blocklist.CosmeticElemHide {
		t.Error("$ehide should work as alias for $elemhide")
	}
	if rs.CosmeticFilterExceptions("https://b.com/") != blocklist.CosmeticGenericHide {
		t.Error("$ghide should work as alias for $generichide")
	}
	if rs.CosmeticFilterExceptions("https://c.com/") != blocklist.CosmeticSpecificHide {
		t.Error("$shide should work as alias for $specifichide")
	}
}

func TestElementHideEntityMatching(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("google.*##.ad-banner")

	// Should match any google TLD
	if !selectorPresent(rs.ElementHidingForDomain("google.com"), ".ad-banner") {
		t.Error("google.* should match google.com")
	}
	if !selectorPresent(rs.ElementHidingForDomain("google.co.uk"), ".ad-banner") {
		t.Error("google.* should match google.co.uk")
	}
	if !selectorPresent(rs.ElementHidingForDomain("google.de"), ".ad-banner") {
		t.Error("google.* should match google.de")
	}
	if !selectorPresent(rs.ElementHidingForDomain("sub.google.com"), ".ad-banner") {
		t.Error("google.* should match sub.google.com")
	}
	if selectorPresent(rs.ElementHidingForDomain("notgoogle.com"), ".ad-banner") {
		t.Error("google.* should not match notgoogle.com")
	}
	if selectorPresent(rs.ElementHidingForDomain("example.com"), ".ad-banner") {
		t.Error("google.* should not match example.com")
	}
}

func TestScriptletNotStoredAsCSS(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com##+js(nowebrtc)")
	rs.AddLine("example.com##+js(set-constant, ads, true)")
	rs.AddLine("example.com##.real-ad")

	eh := rs.ElementHidingForDomain("example.com")
	if eh == nil {
		t.Fatal("should have element hiding for example.com")
	}

	// The ##+js() lines must NOT appear as CSS selectors
	if selectorPresent(eh, "+js(") {
		t.Error("##+js() lines should not be stored as CSS selectors")
	}

	// The real CSS selector should still work
	if !selectorPresent(eh, ".real-ad") {
		t.Error(".real-ad selector should be present")
	}
}

func TestScriptletExceptionNotStoredAsCSS(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com#@#+js(nowebrtc)")
	rs.AddLine("example.com##.real-ad")

	eh := rs.ElementHidingForDomain("example.com")
	if eh == nil {
		t.Fatal("should have element hiding for example.com")
	}

	// The #@#+js() exception must NOT interfere with CSS selectors
	if !selectorPresent(eh, ".real-ad") {
		t.Error(".real-ad selector should be present")
	}
}

func TestScriptletRuleParsing(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com##+js(set-constant, ads, true)")
	rs.AddLine("other.com##+js(nowebrtc)")
	rs.AddLine("##+js(abort-on-property-read, detectAdBlock)") // generic

	scriptlets := rs.ScriptletsForDomain("example.com")
	if len(scriptlets) != 2 {
		t.Fatalf("got %d scriptlets for example.com, want 2 (1 specific + 1 generic)", len(scriptlets))
	}

	scriptlets = rs.ScriptletsForDomain("other.com")
	if len(scriptlets) != 2 {
		t.Fatalf("got %d scriptlets for other.com, want 2 (1 specific + 1 generic)", len(scriptlets))
	}

	scriptlets = rs.ScriptletsForDomain("unrelated.com")
	if len(scriptlets) != 1 {
		t.Fatalf("got %d scriptlets for unrelated.com, want 1 (generic only)", len(scriptlets))
	}
}

func TestScriptletException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##+js(nowebrtc)")
	rs.AddLine("example.com#@#+js(nowebrtc)")

	// Generic scriptlet applies to other domains
	scriptlets := rs.ScriptletsForDomain("other.com")
	if len(scriptlets) != 1 {
		t.Fatalf("got %d scriptlets for other.com, want 1", len(scriptlets))
	}

	// Exception should suppress the scriptlet for example.com
	scriptlets = rs.ScriptletsForDomain("example.com")
	if len(scriptlets) != 0 {
		t.Fatalf("got %d scriptlets for example.com, want 0 (exception should suppress)", len(scriptlets))
	}
}
