package blocklist

import (
	"testing"
)

func TestClassifySelector_Simple(t *testing.T) {
	tests := []struct {
		selector string
		wantTag  string
		wantID   string
		classes  []string
		attrs    int // number of attribute matchers
	}{
		{".ad-banner", "", "", []string{"ad-banner"}, 0},
		{"#sidebar-ad", "", "sidebar-ad", nil, 0},
		{"div.ad-banner", "div", "", []string{"ad-banner"}, 0},
		{"DIV.ad-banner", "div", "", []string{"ad-banner"}, 0},
		{".su-column.su-column-1-3", "", "", []string{"su-column", "su-column-1-3"}, 0},
		{"div#banner", "div", "banner", nil, 0},
		{"aside", "aside", "", nil, 0},
		{"OBJECT[width=\"300\"]", "object", "", nil, 1},
		{"div[class*=\"advertisement\"]", "div", "", nil, 1},
		{"div[class^=\"ad\"]", "div", "", nil, 1},
		{"[id*=\"HeaderAd\"]", "", "", nil, 1},
		{"A[href^=\"/framework/resources/forms/ads.aspx\"]", "a", "", nil, 1},
		{".row.ad", "", "", []string{"row", "ad"}, 0},
		{"div[id*=\"advImg\"]", "div", "", nil, 1},
		{"IMG[src=\"/thumb/550x200/53d278ef882dd.jpg\"]", "img", "", nil, 1},
		{"[href^=\"/is/moya/adverts/\"]", "", "", nil, 1},
		{"[id^=\"box_aitem\"]", "", "", nil, 1},
	}

	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			sm := ClassifySelector(tt.selector)
			if sm == nil {
				t.Fatalf("ClassifySelector(%q) = nil, want non-nil", tt.selector)
			}
			if sm.Tag != tt.wantTag {
				t.Errorf("Tag = %q, want %q", sm.Tag, tt.wantTag)
			}
			if sm.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", sm.ID, tt.wantID)
			}
			if len(sm.Classes) != len(tt.classes) {
				t.Errorf("Classes = %v, want %v", sm.Classes, tt.classes)
			} else {
				for i, c := range tt.classes {
					if sm.Classes[i] != c {
						t.Errorf("Classes[%d] = %q, want %q", i, sm.Classes[i], c)
					}
				}
			}
			if len(sm.Attrs) != tt.attrs {
				t.Errorf("Attrs count = %d, want %d", len(sm.Attrs), tt.attrs)
			}
		})
	}
}

func TestClassifySelector_Complex(t *testing.T) {
	// These should all return nil (too complex for single-element matching)
	complex := []string{
		"div[class^=\"col-\"]:has([class*=\"advertisement-spot-\"])",
		"div > .ad",
		".parent .child",
		"div + span",
		"div ~ span",
		":not(.ad)",
		"div:first-child",
		"div:nth-child(2)",
		"", // empty
	}

	for _, sel := range complex {
		t.Run(sel, func(t *testing.T) {
			sm := ClassifySelector(sel)
			if sm != nil {
				t.Errorf("ClassifySelector(%q) = %+v, want nil (complex)", sel, sm)
			}
		})
	}
}

func TestClassifySelector_AttrWithSpaces(t *testing.T) {
	// Attribute values with spaces should NOT be rejected as having
	// descendant combinators
	sel := `DIV[style="padding: 20px 0; text-align: center;"]`
	sm := ClassifySelector(sel)
	if sm == nil {
		t.Fatalf("ClassifySelector(%q) = nil, want non-nil", sel)
	}
	if sm.Tag != "div" {
		t.Errorf("Tag = %q, want %q", sm.Tag, "div")
	}
	if len(sm.Attrs) != 1 {
		t.Fatalf("Attrs count = %d, want 1", len(sm.Attrs))
	}
	if sm.Attrs[0].Op != AttrEquals {
		t.Errorf("Op = %v, want AttrEquals", sm.Attrs[0].Op)
	}
	if sm.Attrs[0].Value != "padding: 20px 0; text-align: center;" {
		t.Errorf("Value = %q, want %q", sm.Attrs[0].Value, "padding: 20px 0; text-align: center;")
	}
}

func TestSelectorMatch_MatchesAttrs(t *testing.T) {
	sm := ClassifySelector("div.ad-banner#main")
	if sm == nil {
		t.Fatal("expected non-nil SelectorMatch")
	}

	attrFn := func(name string) string {
		switch name {
		case "id":
			return "main"
		case "class":
			return "ad-banner featured"
		}
		return ""
	}

	if !sm.MatchesAttrs("div", attrFn) {
		t.Error("expected match for div.ad-banner#main")
	}

	// Wrong tag
	if sm.MatchesAttrs("span", attrFn) {
		t.Error("expected no match for span")
	}

	// Wrong id
	wrongID := func(name string) string {
		if name == "id" {
			return "other"
		}
		if name == "class" {
			return "ad-banner"
		}
		return ""
	}
	if sm.MatchesAttrs("div", wrongID) {
		t.Error("expected no match for wrong id")
	}

	// Missing class
	missingClass := func(name string) string {
		if name == "id" {
			return "main"
		}
		if name == "class" {
			return "featured"
		}
		return ""
	}
	if sm.MatchesAttrs("div", missingClass) {
		t.Error("expected no match for missing class")
	}
}

func TestSelectorMatch_AttrContains(t *testing.T) {
	sm := ClassifySelector(`div[class*="advertisement"]`)
	if sm == nil {
		t.Fatal("expected non-nil")
	}

	match := func(name string) string {
		if name == "class" {
			return "some-advertisement-box"
		}
		return ""
	}
	if !sm.MatchesAttrs("div", match) {
		t.Error("expected match")
	}

	noMatch := func(name string) string {
		if name == "class" {
			return "ad-box"
		}
		return ""
	}
	if sm.MatchesAttrs("div", noMatch) {
		t.Error("expected no match")
	}
}

func TestSelectorMatch_AttrPrefix(t *testing.T) {
	sm := ClassifySelector(`[id^="box_aitem"]`)
	if sm == nil {
		t.Fatal("expected non-nil")
	}

	match := func(name string) string {
		if name == "id" {
			return "box_aitem_123"
		}
		return ""
	}
	if !sm.MatchesAttrs("div", match) {
		t.Error("expected match")
	}
	if !sm.MatchesAttrs("span", match) {
		t.Error("expected match with any tag")
	}
}
