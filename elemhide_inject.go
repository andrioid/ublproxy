package main

import (
	"bytes"
	"compress/gzip"
	htmlpkg "html"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/html"

	"ublproxy/internal/blocklist"
)

// styleCloseRe matches </style in any case — used to prevent XSS via
// user-created CSS rules that contain a closing </style> tag.
var styleCloseRe = regexp.MustCompile(`(?i)</style`)

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
// attributes and check them against URL blocking rules. Uses the proxy's
// layered shouldBlock for per-user rule evaluation.
type srcBlockContext struct {
	scheme   string
	host     string
	proxy    *proxyHandler
	clientIP string
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

// applyElementHiding checks if the response is HTML and applies CSS-based
// element hiding, src-based resource stripping, and bootstrap script injection.
// Elements that load external resources (script, iframe, object, embed) whose
// URL resolves to a blocked address are stripped from the DOM. All other element
// hiding selectors are applied via CSS display:none injection only — content
// elements are never removed from the DOM to avoid stripping legitimate page
// content that happens to match generic selectors.
// The bootstrap script for the element picker is injected when a session
// exists for the client IP, unless insecure is true (plain HTTP proxy
// connection) — the token must not be sent over unencrypted connections.
// Returns the modified body and true, or nil and false if unmodified.
// Handles gzip, brotli, and zstd compressed responses transparently.
func (p *proxyHandler) applyElementHiding(resp *http.Response, host, clientIP string, insecure bool) ([]byte, bool) {
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return nil, false
	}

	baseline := p.getBaselineRules()
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)

	// Merge element hiding from baseline and user rules
	var baselineEH, userEH *blocklist.ElementHiding
	if baseline != nil {
		baselineEH = baseline.ElementHidingForDomain(host)
	}
	if userRS != nil {
		userEH = userRS.ElementHidingForDomain(host)
	}

	hasURLRules := (baseline != nil && (baseline.HostCount() > 0 || baseline.RuleCount() > 0)) ||
		(userRS != nil && (userRS.HostCount() > 0 || userRS.RuleCount() > 0))

	// Generate bootstrap script tag (empty string if no session).
	// Skip on insecure (plain HTTP) connections to avoid leaking the
	// session token over unencrypted traffic.
	var scriptTag string
	if !insecure {
		scriptTag = p.bootstrapScriptTag(clientIP, host)
	}

	// Nothing to do if there are no rules AND no script to inject
	if baselineEH == nil && userEH == nil && !hasURLRules && scriptTag == "" {
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
	case strings.Contains(encoding, "zstd"):
		var zr *zstd.Decoder
		zr, err = zstd.NewReader(resp.Body)
		if err != nil {
			return nil, false
		}
		body, err = io.ReadAll(zr)
		zr.Close()
	case encoding == "":
		body, err = io.ReadAll(resp.Body)
	default:
		return nil, false
	}
	if err != nil {
		return nil, false
	}

	// For src-based resource stripping, use the layered shouldBlock
	// approach via a proxy-aware srcBlockContext.
	sc := srcBlockContext{scheme: "https", host: host, proxy: p, clientIP: clientIP}
	modified := stripBlockedResources(body, sc)

	// Merge baseline + user element hiding CSS, applying user #@# exceptions
	css := mergeElementHidingCSS(baselineEH, userEH, userRS, host)
	if css != "" {
		safeCSS := styleCloseRe.ReplaceAllString(css, `<\/style`)
		styleTag := []byte("<style>" + safeCSS + "</style>")
		modified = injectStyleTag(modified, styleTag)
	}

	// Inject the bootstrap script for the element picker
	if scriptTag != "" {
		modified = injectBeforeClose(modified, []byte(scriptTag), []byte("</body>"), []byte("</html>"))
	}

	// Remove Content-Encoding since we send uncompressed to the client.
	// The proxy-to-client hop is typically localhost so this is fine.
	resp.Header.Del("Content-Encoding")

	return modified, true
}

// mergeElementHidingCSS combines element hiding selectors from baseline and
// user RuleSets for a specific domain. User #@# exception rules suppress
// matching baseline ## selectors. Returns empty string if no CSS to inject.
func mergeElementHidingCSS(baseline, user *blocklist.ElementHiding, userRS *blocklist.RuleSet, domain string) string {
	var selectors []string

	// Add baseline selectors, filtering out any excepted by user #@# rules
	if baseline != nil {
		for _, sel := range baseline.Selectors {
			if userRS != nil && userRS.IsElementHideExcepted(sel, domain) {
				continue
			}
			selectors = append(selectors, sel)
		}
	}

	// Add user selectors (their own internal exceptions already applied)
	if user != nil {
		selectors = append(selectors, user.Selectors...)
	}

	if len(selectors) == 0 {
		return ""
	}

	return strings.Join(selectors, ",\n") + " {\n  display: none !important;\n}\n"
}

// injectBeforeClose inserts content before the first found closing tag,
// or appends if none is found. Tags are tried in order.
func injectBeforeClose(htmlDoc, content []byte, tags ...[]byte) []byte {
	for _, tag := range tags {
		if idx := indexCaseInsensitive(htmlDoc, tag); idx >= 0 {
			return insertAt(htmlDoc, content, idx)
		}
	}
	return append(htmlDoc, content...)
}

// stripBlockedResources uses the HTML tokenizer to walk through the HTML and
// strip elements (script, iframe, object, embed) whose external resource URL
// resolves to a blocked address. Other elements are passed through unchanged —
// element hiding for those is handled by CSS injection only.
func stripBlockedResources(src []byte, sc srcBlockContext) []byte {
	if sc.proxy == nil {
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
			buf.Write(tokenizer.Raw())
			return buf.Bytes()

		case html.StartTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagNameLower := strings.ToLower(string(tn))

			// Save raw bytes before consuming attributes. TagAttr()
			// causes Raw() to return reconstructed HTML with lowercased
			// attribute names, which breaks React hydration.
			rawBytes := copyBytes(tokenizer.Raw())

			urlAttr, blockable := srcBlockableTags[tagNameLower]
			if !blockable || !hasAttr {
				buf.Write(rawBytes)
				continue
			}

			attrs := collectAttrs(tokenizer, hasAttr)
			urlVal, ok := attrs[urlAttr]
			if !ok || urlVal == "" {
				buf.Write(rawBytes)
				continue
			}

			resolved := sc.resolveSrc(urlVal)
			ctx := blocklist.MatchContext{PageDomain: sc.host}
			if !sc.proxy.shouldBlock(sc.clientIP, resolved, ctx) {
				buf.Write(rawBytes)
				continue
			}

			// HTML-encode the URL to prevent breaking out of the comment
			replacement := "<!-- ublproxy: blocked " + tagNameLower + " " + htmlpkg.EscapeString(urlVal) + " -->"
			buf.WriteString(replacement)
			if !voidElements[tagNameLower] {
				skipUntilClose(tokenizer, tagNameLower)
			}

		default:
			buf.Write(tokenizer.Raw())
		}
	}
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
