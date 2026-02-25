package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

// injectElementHidingCSS checks if the response is HTML and injects element
// hiding CSS if applicable. Returns the (possibly modified) body and true if
// the response was modified, or the original body and false otherwise.
// Handles gzip-compressed responses transparently.
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

	// Only decompress gzip — bail on other encodings (e.g. brotli) to avoid
	// corrupting compressed bytes we can't decode
	var body []byte
	var err error
	encoding := resp.Header.Get("Content-Encoding")
	if encoding != "" && !strings.Contains(encoding, "gzip") {
		return nil, false
	}
	if strings.Contains(encoding, "gzip") {
		gr, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return nil, false
		}
		body, err = io.ReadAll(gr)
		gr.Close()
	} else {
		body, err = io.ReadAll(resp.Body)
	}
	if err != nil {
		return nil, false
	}

	styleTag := []byte("<style>" + css + "</style>")
	modified := injectStyleTag(body, styleTag)

	// Remove Content-Encoding since we send uncompressed to the client.
	// The proxy-to-client hop is typically localhost so this is fine.
	resp.Header.Del("Content-Encoding")

	return modified, true
}

// injectStyleTag inserts the style tag before </head>, </body>, or at
// the end if neither is found. Uses case-insensitive search without
// allocating a full lowercase copy of the HTML.
func injectStyleTag(html, styleTag []byte) []byte {
	if idx := indexCaseInsensitive(html, []byte("</head>")); idx >= 0 {
		return insertAt(html, styleTag, idx)
	}
	if idx := indexCaseInsensitive(html, []byte("</body>")); idx >= 0 {
		return insertAt(html, styleTag, idx)
	}
	return append(html, styleTag...)
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
