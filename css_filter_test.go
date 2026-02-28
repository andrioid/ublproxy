package main

import (
	"testing"
)

func TestExtractHTMLTokens(t *testing.T) {
	html := []byte(`<html>
		<head><title>Test</title></head>
		<body>
			<div class="container main-content" id="page">
				<aside class="augl fluid" id="slot-632">Ad</aside>
				<p class="text">Hello</p>
				<span class="augl-wide">Wide</span>
				<img src="test.png">
			</div>
		</body>
	</html>`)

	tokens := extractHTMLTokens(html)

	// Check classes
	wantClasses := []string{"container", "main-content", "augl", "fluid", "text", "augl-wide"}
	for _, c := range wantClasses {
		if !tokens.classes[c] {
			t.Errorf("missing class %q", c)
		}
	}

	// Check IDs
	wantIDs := []string{"page", "slot-632"}
	for _, id := range wantIDs {
		if !tokens.ids[id] {
			t.Errorf("missing id %q", id)
		}
	}

	// Check that non-existent tokens are absent
	if tokens.classes["nonexistent"] {
		t.Error("should not contain class 'nonexistent'")
	}
	if tokens.ids["nonexistent"] {
		t.Error("should not contain id 'nonexistent'")
	}
}

func TestExtractHTMLTokensEmpty(t *testing.T) {
	tokens := extractHTMLTokens([]byte(`<html><body><p>No classes or ids</p></body></html>`))
	if len(tokens.classes) != 0 {
		t.Errorf("expected no classes, got %d", len(tokens.classes))
	}
	if len(tokens.ids) != 0 {
		t.Errorf("expected no ids, got %d", len(tokens.ids))
	}
}

func TestSelectorMatchesTokens(t *testing.T) {
	tokens := htmlTokens{
		classes: map[string]bool{
			"ad-banner": true,
			"container": true,
			"augl":      true,
			"fluid":     true,
			"mt-5":      true,
			"mb-5":      true,
			"augl-wide": true,
			"sponsored": true,
		},
		ids: map[string]bool{
			"slot-668": true,
			"page":     true,
		},
	}

	tests := []struct {
		selector string
		want     bool
		desc     string
	}{
		// Simple class selectors
		{".ad-banner", true, "class present"},
		{".nonexistent", false, "class absent"},
		{".augl", true, "class present"},

		// Simple ID selectors
		{"#slot-668", true, "id present"},
		{"#missing-id", false, "id absent"},
		{"#page", true, "id present"},

		// Compound class selectors (.a.b)
		{".mt-5.mb-5", true, "both classes present"},
		{".mt-5.nonexistent", false, "one class missing"},
		{".augl.fluid", true, "both classes present"},

		// Tag + class
		{"div.ad-banner", true, "class present (tag ignored for matching)"},
		{"aside.augl", true, "class present"},

		// Tag + ID
		{"div#page", true, "id present"},
		{"div#missing", false, "id absent"},

		// Attribute selectors — always included (can't pre-match)
		{`div[class^="col-"]`, true, "attribute selector always matches"},
		{`[data-ad]`, true, "attribute selector always matches"},
		{`a[href^="/ads/"]`, true, "attribute selector always matches"},

		// Complex selectors with combinators — always included
		{"div .ad-child", true, "descendant combinator always matches"},
		{"div > .ad-child", true, "child combinator always matches"},
		{"div + .sibling", true, "adjacent sibling always matches"},
		{"div ~ .sibling", true, "general sibling always matches"},

		// Pseudo-classes — always included
		{".foo:has(.bar)", true, "pseudo-class always matches"},
		{":not(.foo)", true, "pseudo-class always matches"},

		// Tag-only selectors — always included (too broad to pre-filter)
		{"aside", true, "tag-only always matches"},
		{"div", true, "tag-only always matches"},
	}

	for _, tt := range tests {
		got := selectorMatchesTokens(tt.selector, tokens)
		if got != tt.want {
			t.Errorf("selectorMatchesTokens(%q) = %v, want %v (%s)", tt.selector, got, tt.want, tt.desc)
		}
	}
}

func TestFilterSelectorsAgainstHTML(t *testing.T) {
	html := []byte(`<html><head></head><body>
		<aside class="augl" id="slot-668">Ad</aside>
		<div class="mt-5 mb-5">Spacer</div>
		<p>Content</p>
	</body></html>`)

	selectors := []string{
		".augl",         // matches class="augl"
		".nonexistent",  // no match
		"#slot-668",     // matches id="slot-668"
		"#missing",      // no match
		".mt-5.mb-5",    // matches both classes
		".mt-5.missing", // one class missing
		".ad-banner",    // no match
		`div[data-ad]`,  // attribute selector — always included
		"div .child",    // combinator — always included
	}

	filtered := filterSelectors(selectors, html)

	want := map[string]bool{
		".augl":        true,
		"#slot-668":    true,
		".mt-5.mb-5":   true,
		`div[data-ad]`: true,
		"div .child":   true,
	}

	if len(filtered) != len(want) {
		t.Errorf("filtered %d selectors, want %d: %v", len(filtered), len(want), filtered)
	}
	for _, sel := range filtered {
		if !want[sel] {
			t.Errorf("unexpected selector in filtered output: %q", sel)
		}
	}
}
