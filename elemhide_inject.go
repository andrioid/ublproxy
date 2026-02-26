package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"golang.org/x/net/html"

	"ublproxy/pkg/blocklist"
)

// voidElements are HTML elements that have no closing tag.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true,
	"embed": true, "hr": true, "img": true, "input": true,
	"link": true, "meta": true, "param": true, "source": true,
	"track": true, "wbr": true,
}

// srcBlockableTags maps element names to the attribute that carries their
// external resource URL. If the resolved URL is blocked, the element is stripped.
var srcBlockableTags = map[string]string{
	"script": "src",
	"iframe": "src",
	"object": "data",
	"embed":  "src",
}

// srcBlockContext carries the page context needed to resolve relative src
// attributes and check them against URL blocking rules.
type srcBlockContext struct {
	scheme string
	host   string
	rules  *blocklist.RuleSet
}

// resolveSrc resolves an element's src attribute to an absolute URL.
// Protocol-relative (//host/path), absolute (/path), and fully qualified
// URLs are all handled.
func (sc srcBlockContext) resolveSrc(src string) string {
	if strings.HasPrefix(src, "//") {
		return sc.scheme + ":" + src
	}
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return src
	}
	if strings.HasPrefix(src, "/") {
		return sc.scheme + "://" + sc.host + src
	}
	return sc.scheme + "://" + sc.host + "/" + src
}

// applyElementHiding checks if the response is HTML and applies element hiding
// and src-based stripping if applicable. Matched elements are replaced with
// placeholder divs; complex selectors that can't be matched on a single element
// fall back to CSS injection. Elements that load external resources (script,
// iframe, object, embed) whose URL resolves to a blocked address are stripped.
// Returns the modified body and true, or nil and false if unmodified.
// Handles gzip and brotli compressed responses transparently.
func (p *proxyHandler) applyElementHiding(resp *http.Response, host string) ([]byte, bool) {
	if p.rules == nil {
		return nil, false
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return nil, false
	}

	eh := p.rules.ElementHidingForDomain(host)

	// Nothing to do if there are no element hiding rules and no URL rules
	// that could match resource URLs on blockable elements.
	hasURLRules := p.rules.HostCount() > 0 || p.rules.RuleCount() > 0
	if eh == nil && !hasURLRules {
		return nil, false
	}

	var body []byte
	var err error
	encoding := resp.Header.Get("Content-Encoding")
	switch {
	case strings.Contains(encoding, "gzip"):
		gr, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return nil, false
		}
		body, err = io.ReadAll(gr)
		gr.Close()
	case strings.Contains(encoding, "br"):
		body, err = io.ReadAll(brotli.NewReader(resp.Body))
	case encoding == "":
		body, err = io.ReadAll(resp.Body)
	default:
		// Unknown encoding (e.g. zstd) — pass through unmodified
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	var matchers []blocklist.SelectorMatch
	if eh != nil {
		matchers = eh.Matchers
	}

	sc := srcBlockContext{scheme: "https", host: host, rules: p.rules}
	modified := replaceElements(body, matchers, sc)

	if eh != nil && eh.FallbackCSS != "" {
		styleTag := []byte("<style>" + eh.FallbackCSS + "</style>")
		modified = injectStyleTag(modified, styleTag)
	}

	// Remove Content-Encoding since we send uncompressed to the client.
	// The proxy-to-client hop is typically localhost so this is fine.
	resp.Header.Del("Content-Encoding")

	return modified, true
}

// replaceElements uses the html tokenizer to walk through the HTML and replace
// elements matching any of the simple selectors with placeholder divs.
// It also strips elements (script, iframe, object, embed) whose resource URL
// resolves to a blocked address.
func replaceElements(src []byte, matchers []blocklist.SelectorMatch, sc srcBlockContext) []byte {
	if len(matchers) == 0 && sc.rules == nil {
		return src
	}

	var buf bytes.Buffer
	buf.Grow(len(src))

	tokenizer := html.NewTokenizer(bytes.NewReader(src))

	for {
		tt := tokenizer.Next()

		switch tt {
		case html.ErrorToken:
			if tokenizer.Err() == io.EOF {
				return buf.Bytes()
			}
			// On error, append remaining raw bytes and return
			buf.Write(tokenizer.Raw())
			return buf.Bytes()

		case html.StartTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagNameLower := strings.ToLower(string(tn))

			// Save raw bytes before consuming attributes. TagAttr()
			// causes Raw() to return reconstructed HTML with lowercased
			// attribute names, which breaks React hydration.
			rawBytes := copyBytes(tokenizer.Raw())

			// For elements with a blockable resource URL (script, iframe,
			// object, embed), check if the URL resolves to a blocked
			// address before falling through to element hiding.
			if urlAttr, blockable := srcBlockableTags[tagNameLower]; blockable && hasAttr && sc.rules != nil {
				attrs := collectAttrs(tokenizer, hasAttr)
				if urlVal, ok := attrs[urlAttr]; ok && urlVal != "" {
					resolved := sc.resolveSrc(urlVal)
					ctx := blocklist.MatchContext{PageDomain: sc.host}
					if sc.rules.ShouldBlockRequest(resolved, ctx) {
						replacement := fmt.Sprintf("<!-- ublproxy: blocked %s %s -->", tagNameLower, urlVal)
						buf.WriteString(replacement)
						if !voidElements[tagNameLower] {
							skipUntilClose(tokenizer, tagNameLower)
						}
						continue
					}
				}
				// Not blocked — check element hiding with pre-collected attrs
				if matched, selector := matchesAnyWithAttrs(tagNameLower, attrs, matchers); matched {
					replacement := fmt.Sprintf("<div><!-- ublproxy: replaced %s --></div>", selector)
					buf.WriteString(replacement)
					if !voidElements[tagNameLower] {
						skipUntilClose(tokenizer, tagNameLower)
					}
					continue
				}
				buf.Write(rawBytes)
				continue
			}

			if matched, selector := matchesAny(tagNameLower, tokenizer, hasAttr, matchers); matched {
				replacement := fmt.Sprintf("<div><!-- ublproxy: replaced %s --></div>", selector)
				buf.WriteString(replacement)

				if voidElements[tagNameLower] {
					continue
				}
				skipUntilClose(tokenizer, tagNameLower)
				continue
			}

			buf.Write(rawBytes)

		case html.SelfClosingTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagNameLower := strings.ToLower(string(tn))
			rawBytes := copyBytes(tokenizer.Raw())

			if matched, selector := matchesAny(tagNameLower, tokenizer, hasAttr, matchers); matched {
				replacement := fmt.Sprintf("<div><!-- ublproxy: replaced %s --></div>", selector)
				buf.WriteString(replacement)
				continue
			}

			buf.Write(rawBytes)

		default:
			buf.Write(tokenizer.Raw())
		}
	}
}

// matchesAny checks if the current element matches any of the simple selectors.
// Collects attributes lazily from the tokenizer on first need.
// Returns true and the matched selector string, or false.
func matchesAny(tagName string, tokenizer *html.Tokenizer, hasAttr bool, matchers []blocklist.SelectorMatch) (bool, string) {
	var attrs map[string]string

	for i := range matchers {
		sm := &matchers[i]

		if sm.Tag != "" && sm.Tag != tagName {
			continue
		}

		if attrs == nil {
			attrs = collectAttrs(tokenizer, hasAttr)
		}

		attrFn := func(name string) string {
			return attrs[name]
		}

		if sm.MatchesAttrs(tagName, attrFn) {
			return true, sm.Selector
		}
	}

	return false, ""
}

// matchesAnyWithAttrs checks if the element matches any selector using
// a pre-collected attribute map. Used when attributes were already read
// from the tokenizer (e.g. for script src checking).
func matchesAnyWithAttrs(tagName string, attrs map[string]string, matchers []blocklist.SelectorMatch) (bool, string) {
	for i := range matchers {
		sm := &matchers[i]

		if sm.Tag != "" && sm.Tag != tagName {
			continue
		}

		attrFn := func(name string) string {
			return attrs[name]
		}

		if sm.MatchesAttrs(tagName, attrFn) {
			return true, sm.Selector
		}
	}

	return false, ""
}

// copyBytes returns a copy of b. The tokenizer's Raw() returns a slice into
// an internal buffer that is overwritten on the next call, so we must copy.
func copyBytes(b []byte) []byte {
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

// collectAttrs reads all attributes from the tokenizer for the current tag.
func collectAttrs(tokenizer *html.Tokenizer, hasAttr bool) map[string]string {
	attrs := make(map[string]string)
	if !hasAttr {
		return attrs
	}
	for {
		key, val, more := tokenizer.TagAttr()
		attrs[strings.ToLower(string(key))] = string(val)
		if !more {
			break
		}
	}
	return attrs
}

// skipUntilClose consumes tokens until the matching end tag for the given
// tag name is found, tracking nesting depth for same-name tags.
func skipUntilClose(tokenizer *html.Tokenizer, tagName string) {
	depth := 1
	for depth > 0 {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return
		case html.StartTagToken:
			tn, _ := tokenizer.TagName()
			if strings.ToLower(string(tn)) == tagName {
				depth++
			}
		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			if strings.ToLower(string(tn)) == tagName {
				depth--
			}
		}
	}
}

// injectStyleTag inserts the style tag before </head>, </body>, or at
// the end if neither is found. Uses case-insensitive search without
// allocating a full lowercase copy of the HTML.
func injectStyleTag(htmlDoc, styleTag []byte) []byte {
	if idx := indexCaseInsensitive(htmlDoc, []byte("</head>")); idx >= 0 {
		return insertAt(htmlDoc, styleTag, idx)
	}
	if idx := indexCaseInsensitive(htmlDoc, []byte("</body>")); idx >= 0 {
		return insertAt(htmlDoc, styleTag, idx)
	}
	return append(htmlDoc, styleTag...)
}

func insertAt(original, insert []byte, pos int) []byte {
	result := make([]byte, len(original)+len(insert))
	copy(result, original[:pos])
	copy(result[pos:], insert)
	copy(result[pos+len(insert):], original[pos:])
	return result
}

// indexCaseInsensitive finds needle in haystack without allocating a
// full lowercase copy. needle must already be lowercase.
func indexCaseInsensitive(haystack, needle []byte) int {
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if bytes.EqualFold(haystack[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}
