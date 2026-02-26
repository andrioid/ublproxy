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

// applyElementHiding checks if the response is HTML and applies element hiding
// if applicable. Matched elements are replaced with placeholder divs; complex
// selectors that can't be matched on a single element fall back to CSS injection.
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
	if eh == nil {
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

	modified := replaceElements(body, eh.Matchers)

	if eh.FallbackCSS != "" {
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
func replaceElements(src []byte, matchers []blocklist.SelectorMatch) []byte {
	if len(matchers) == 0 {
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
			tagName := string(tn)
			tagNameLower := strings.ToLower(tagName)

			if matched, selector := matchesAny(tagNameLower, tokenizer, hasAttr, matchers); matched {
				replacement := fmt.Sprintf("<div><!-- ublproxy: replaced %s --></div>", selector)
				buf.WriteString(replacement)

				if voidElements[tagNameLower] {
					continue
				}
				skipUntilClose(tokenizer, tagNameLower)
				continue
			}

			buf.Write(tokenizer.Raw())

		case html.SelfClosingTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagNameLower := strings.ToLower(string(tn))

			if matched, selector := matchesAny(tagNameLower, tokenizer, hasAttr, matchers); matched {
				replacement := fmt.Sprintf("<div><!-- ublproxy: replaced %s --></div>", selector)
				buf.WriteString(replacement)
				continue
			}

			buf.Write(tokenizer.Raw())

		default:
			buf.Write(tokenizer.Raw())
		}
	}
}

// matchesAny checks if the current element matches any of the simple selectors.
// Returns true and the matched selector string, or false.
func matchesAny(tagName string, tokenizer *html.Tokenizer, hasAttr bool, matchers []blocklist.SelectorMatch) (bool, string) {
	// Collect attributes lazily — only if we need them
	var attrs map[string]string

	for i := range matchers {
		sm := &matchers[i]

		// Quick tag-name check before collecting attributes
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
