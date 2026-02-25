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

	// WebSocket and other protocol upgrades need special handling
	if isWebSocketUpgrade(r.Header) {
		p.handleHTTPUpgrade(w, r)
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

// handleHTTPUpgrade handles WebSocket and other protocol upgrade requests
// over plain HTTP. It preserves the upgrade headers, sends the request to
// the upstream, and if the upstream responds with 101, hijacks both sides
// and does bidirectional copy.
func (p *proxyHandler) handleHTTPUpgrade(w http.ResponseWriter, r *http.Request) {
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		logError("http/upgrade/new-request", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)

	// Re-add the upgrade headers that were stripped as hop-by-hop
	outReq.Header.Set("Connection", "Upgrade")
	outReq.Header.Set("Upgrade", r.Header.Get("Upgrade"))

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		logError("http/upgrade/roundtrip", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Not a 101 — fall back to normal response handling
		defer resp.Body.Close()
		copyHeaders(w.Header(), resp.Header)
		removeHopByHopHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// Get the raw upstream connection from the response body
	upstreamConn, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		http.Error(w, "upstream does not support hijacking", http.StatusInternalServerError)
		return
	}
	defer upstreamConn.Close()

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		logError("http/upgrade/hijack", err)
		return
	}
	defer clientConn.Close()

	// Write the 101 response to the client
	resp.Body = nil // don't write the body, just headers
	resp.Write(clientConn)
	clientBuf.Flush()

	// Bidirectional copy between client and upstream
	bidirectionalCopy(clientConn, upstreamConn)
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
