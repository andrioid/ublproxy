package main

import (
	"io"
	"net/http"
	"net/url"
	"time"

	"ublproxy/pkg/blocklist"
)

// Headers that must not be forwarded between hops.
// https://www.rfc-editor.org/rfc/rfc2616#section-13.5.1
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func (p *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := matchContextFromReferer(r.Header.Get("Referer"))
	if p.rules.ShouldBlockRequest(r.URL.String(), ctx) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	start := time.Now()

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		logError("http/new-request", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)

	// Downgrade to gzip-only when we may need to decompress HTML for CSS
	// injection. We can only decompress gzip, not brotli or other encodings.
	if p.rules.CSSForDomain(r.URL.Hostname()) != "" {
		outReq.Header.Set("Accept-Encoding", "gzip")
	}

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		logError("http/roundtrip", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Inject element hiding CSS into HTML responses (skip HEAD — no body to modify)
	if r.Method != http.MethodHead {
		if modified, ok := p.injectElementHidingCSS(resp, r.URL.Hostname()); ok {
			copyHeaders(w.Header(), resp.Header)
			removeHopByHopHeaders(w.Header())
			w.Header().Del("Content-Length")
			w.WriteHeader(resp.StatusCode)
			w.Write(modified)
			logRequest(r.Method, r.URL.String(), resp.StatusCode, time.Since(start))
			return
		}
	}

	copyHeaders(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	logRequest(r.Method, r.URL.String(), resp.StatusCode, time.Since(start))
}

// matchContextFromReferer extracts the page domain from the Referer header
// for evaluating context-dependent filter options ($third-party, $domain).
func matchContextFromReferer(referer string) blocklist.MatchContext {
	if referer == "" {
		return blocklist.MatchContext{}
	}
	parsed, err := url.Parse(referer)
	if err != nil {
		return blocklist.MatchContext{}
	}
	return blocklist.MatchContext{PageDomain: parsed.Hostname()}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(h http.Header) {
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}
