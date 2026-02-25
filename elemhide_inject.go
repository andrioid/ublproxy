package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// injectElementHidingCSS checks if the response is HTML and injects element
// hiding CSS if applicable. Returns the (possibly modified) body and true if
// the response was modified, or the original body and false otherwise.
func (p *proxyHandler) injectElementHidingCSS(resp *http.Response, host string) ([]byte, bool) {
	if p.rules == nil {
		return nil, false
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return nil, false
	}

	css := p.rules.CSSForDomain(host)
	if css == "" {
		return nil, false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false
	}

	styleTag := []byte("<style>" + css + "</style>")

	// Inject before </head> if present, otherwise before </body>
	modified := injectStyleTag(body, styleTag)
	return modified, true
}

func injectStyleTag(html, styleTag []byte) []byte {
	// Try </head> first (case-insensitive)
	lower := bytes.ToLower(html)
	if idx := bytes.Index(lower, []byte("</head>")); idx >= 0 {
		return insertAt(html, styleTag, idx)
	}

	// Try </body>
	if idx := bytes.Index(lower, []byte("</body>")); idx >= 0 {
		return insertAt(html, styleTag, idx)
	}

	// No head or body tag — append at the end
	return append(html, styleTag...)
}

func insertAt(original, insert []byte, pos int) []byte {
	result := make([]byte, 0, len(original)+len(insert))
	result = append(result, original[:pos]...)
	result = append(result, insert...)
	result = append(result, original[pos:]...)
	return result
}

// stripAcceptEncoding removes Accept-Encoding from the request so we get
// uncompressed responses that we can modify for element hiding injection.
func stripAcceptEncoding(h http.Header) {
	h.Del("Accept-Encoding")
}
