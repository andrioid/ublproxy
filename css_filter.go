package main

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
)

// htmlTokens holds the classes and IDs found in an HTML document.
// Used to pre-filter CSS selectors before injection — only selectors
// that could match something in the document are injected.
type htmlTokens struct {
	classes map[string]bool
	ids     map[string]bool
}

// extractHTMLTokens does a fast pass over the HTML to collect all class
// names and id attribute values. It uses the tokenizer (not a full DOM
// parse) so it's O(n) in document size with minimal allocation.
func extractHTMLTokens(src []byte) htmlTokens {
	tokens := htmlTokens{
		classes: make(map[string]bool),
		ids:     make(map[string]bool),
	}

	tokenizer := html.NewTokenizer(bytes.NewReader(src))
	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		for {
			key, val, more := tokenizer.TagAttr()
			k := string(key)
			if k == "class" {
				for _, c := range strings.Fields(string(val)) {
					tokens.classes[c] = true
				}
			} else if k == "id" {
				v := strings.TrimSpace(string(val))
				if v != "" {
					tokens.ids[v] = true
				}
			}
			if !more {
				break
			}
		}
	}

	return tokens
}

// selectorMatchesTokens returns true if the CSS selector could match
// something in the document based on the extracted tokens.
//
// For simple selectors (.class, #id, .a.b compound), it checks whether
// the referenced classes/IDs exist in the HTML. For complex selectors
// (combinators, attribute selectors, pseudo-classes, tag-only), it
// returns true unconditionally since we can't pre-evaluate them without
// a full DOM and CSS selector engine.
func selectorMatchesTokens(selector string, tokens htmlTokens) bool {
	// Complex selectors that we can't pre-filter — always include.
	// Combinators: space (descendant), > (child), + (adjacent), ~ (general sibling)
	if strings.ContainsAny(selector, " >+~") {
		return true
	}
	// Attribute selectors
	if strings.ContainsAny(selector, "[]") {
		return true
	}
	// Pseudo-classes/elements
	if strings.Contains(selector, ":") {
		return true
	}

	// Strip leading tag name (e.g. "div.foo" -> ".foo", "aside#bar" -> "#bar")
	// Tags don't have . or # so find the first class/id marker.
	rest := selector
	if dotIdx := strings.IndexByte(rest, '.'); dotIdx >= 0 {
		rest = rest[dotIdx:]
	} else if hashIdx := strings.IndexByte(rest, '#'); hashIdx >= 0 {
		rest = rest[hashIdx:]
	} else {
		// Tag-only selector (e.g. "aside") — always include
		return true
	}

	// ID selector: #foo or tag#foo
	if rest[0] == '#' {
		id := rest[1:]
		return tokens.ids[id]
	}

	// Class selector(s): .foo or .foo.bar.baz
	// Split on '.' — first element is empty (before the leading dot).
	parts := strings.Split(rest, ".")
	for _, part := range parts {
		if part == "" {
			continue
		}
		if !tokens.classes[part] {
			return false
		}
	}
	return true
}

// filterSelectors returns only the selectors that could match something
// in the given HTML document. This avoids injecting tens of thousands of
// CSS selectors that don't match any element on the page.
func filterSelectors(selectors []string, htmlBody []byte) []string {
	tokens := extractHTMLTokens(htmlBody)
	var matched []string
	for _, sel := range selectors {
		if selectorMatchesTokens(sel, tokens) {
			matched = append(matched, sel)
		}
	}
	return matched
}
