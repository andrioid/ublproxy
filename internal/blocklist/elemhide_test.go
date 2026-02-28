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
