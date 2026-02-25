package blocklist_test

import (
	"strings"
	"testing"

	"ublproxy/pkg/blocklist"
)

func TestCSSForDomain(t *testing.T) {
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
			css := rs.CSSForDomain(tt.domain)
			for _, sel := range tt.contains {
				if !strings.Contains(css, sel) {
					t.Errorf("CSS for %q should contain %q, got:\n%s", tt.domain, sel, css)
				}
			}
			for _, sel := range tt.excludes {
				if strings.Contains(css, sel) {
					t.Errorf("CSS for %q should NOT contain %q, got:\n%s", tt.domain, sel, css)
				}
			}
		})
	}
}

func TestCSSForDomainFormat(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	css := rs.CSSForDomain("example.com")

	if !strings.Contains(css, "display: none !important") {
		t.Errorf("CSS should use 'display: none !important', got:\n%s", css)
	}
}

func TestCSSForDomainEmpty(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com##.ad")

	// No rules apply to this domain
	css := rs.CSSForDomain("other.com")
	if css != "" {
		t.Errorf("expected empty CSS for non-matching domain, got:\n%s", css)
	}
}

func TestCSSForDomainNilSafe(t *testing.T) {
	var rs *blocklist.RuleSet
	css := rs.CSSForDomain("example.com")
	if css != "" {
		t.Errorf("nil RuleSet should return empty CSS, got: %s", css)
	}
}

func TestElementHideException(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")
	rs.AddLine("example.com#@#.ad-banner")

	// On example.com, the exception should prevent .ad-banner from being hidden
	css := rs.CSSForDomain("example.com")
	if strings.Contains(css, ".ad-banner") {
		t.Errorf("exception should prevent .ad-banner on example.com, got:\n%s", css)
	}

	// On other domains, .ad-banner should still be hidden
	css = rs.CSSForDomain("other.com")
	if !strings.Contains(css, ".ad-banner") {
		t.Errorf(".ad-banner should be hidden on other.com, got:\n%s", css)
	}
}

func TestElementHideFromLoadFile(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// addLine is used internally by LoadFile
	rs.AddLine("##.global-ad")
	rs.AddLine("||ads.example.com^")
	rs.AddLine("/tracking.js")

	// Element hiding should work alongside blocking rules
	css := rs.CSSForDomain("example.com")
	if !strings.Contains(css, ".global-ad") {
		t.Error("element hiding rules should be parsed alongside blocking rules")
	}

	// Blocking rules should still work
	if !rs.ShouldBlock("http://ads.example.com/banner.gif") {
		t.Error("blocking rules should still work alongside element hiding")
	}
}
