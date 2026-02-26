package blocklist_test

import (
	"strings"
	"testing"

	"ublproxy/pkg/blocklist"
)

// selectorPresent returns true if the selector appears in either the matchers
// or the fallback CSS.
func selectorPresent(eh *blocklist.ElementHiding, sel string) bool {
	if eh == nil {
		return false
	}
	for _, m := range eh.Matchers {
		if m.Selector == sel {
			return true
		}
	}
	return strings.Contains(eh.FallbackCSS, sel)
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

func TestElementHidingSimpleSelectors(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	eh := rs.ElementHidingForDomain("example.com")
	if eh == nil {
		t.Fatal("expected non-nil ElementHiding")
	}

	if len(eh.Matchers) != 1 {
		t.Fatalf("expected 1 matcher, got %d", len(eh.Matchers))
	}
	if eh.Matchers[0].Selector != ".ad-banner" {
		t.Errorf("matcher selector = %q, want %q", eh.Matchers[0].Selector, ".ad-banner")
	}
	if eh.FallbackCSS != "" {
		t.Errorf("expected no fallback CSS for simple selector, got:\n%s", eh.FallbackCSS)
	}
}

func TestElementHidingComplexFallback(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// Complex selector: has descendant combinator (space)
	rs.AddLine("example.com##div .ad-child")

	eh := rs.ElementHidingForDomain("example.com")
	if eh == nil {
		t.Fatal("expected non-nil ElementHiding")
	}

	if len(eh.Matchers) != 0 {
		t.Errorf("expected 0 matchers for complex selector, got %d", len(eh.Matchers))
	}
	if !strings.Contains(eh.FallbackCSS, "div .ad-child") {
		t.Errorf("complex selector should be in fallback CSS, got:\n%s", eh.FallbackCSS)
	}
	if !strings.Contains(eh.FallbackCSS, "display: none !important") {
		t.Errorf("fallback CSS should use 'display: none !important', got:\n%s", eh.FallbackCSS)
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

func TestElementHideFromLoadFile(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.global-ad")
	rs.AddLine("||ads.example.com^")
	rs.AddLine("/tracking.js")

	// Element hiding should work alongside blocking rules
	eh := rs.ElementHidingForDomain("example.com")
	if !selectorPresent(eh, ".global-ad") {
		t.Error("element hiding rules should be parsed alongside blocking rules")
	}

	// Blocking rules should still work
	if !rs.ShouldBlock("http://ads.example.com/banner.gif") {
		t.Error("blocking rules should still work alongside element hiding")
	}
}
