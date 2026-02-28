package main

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"ublproxy/internal/blocklist"
)

// clientIPFromRequest extracts the IP address from the request's RemoteAddr.
// The result is normalized so that IPv4-mapped IPv6 addresses (e.g.
// "::ffff:192.168.1.5") are returned as plain IPv4 ("192.168.1.5").
// Without this, session lookups can fail when the portal auth request
// arrives on a different address family than the proxy CONNECT request.
func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return normalizeIP(r.RemoteAddr)
	}
	return normalizeIP(host)
}

// normalizeIP parses an IP string and returns its canonical form.
// IPv4-mapped IPv6 addresses are unwrapped to plain IPv4.
func normalizeIP(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw
	}
	// Unmap IPv4-mapped IPv6 (e.g. ::ffff:192.168.1.5 -> 192.168.1.5)
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

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
	ctx := matchContextFromRequest(r)
	clientIP := clientIPFromRequest(r)
	credID := p.credentialForIP(clientIP)
	if p.shouldBlock(clientIP, r.URL.String(), ctx) {
		p.logActivity(ActivityBlocked, r.URL.Hostname(), r.URL.String(), "", clientIP, credID)
		logBlocked(r.URL.Hostname(), r.URL.String(), "", clientIP, credID)
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
		logError("http/new-request", err, clientIP, credID)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		logError("http/roundtrip", err, clientIP, credID)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Replace ad elements in HTML responses (skip HEAD — no body to modify).
	// If the proxy connection is plain HTTP (r.TLS == nil), skip the
	// bootstrap script injection to avoid leaking the session token.
	insecure := r.TLS == nil
	if r.Method != http.MethodHead {
		if modified, stats := p.applyElementHiding(resp, r.URL.Hostname(), clientIP, insecure); stats.Modified {
			copyHeaders(w.Header(), resp.Header)
			removeHopByHopHeaders(w.Header())
			w.Header().Del("Content-Length")
			w.Header().Set(statsHeaderName, stats.header())
			w.WriteHeader(resp.StatusCode)
			w.Write(modified)
			logRequest(r.Method, r.URL.String(), resp.StatusCode, time.Since(start), clientIP, credID)
			return
		}
	}

	copyHeaders(w.Header(), resp.Header)
	removeHopByHopHeaders(w.Header())
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	logRequest(r.Method, r.URL.String(), resp.StatusCode, time.Since(start), clientIP, credID)
}

// handleHTTPUpgrade handles WebSocket and other protocol upgrade requests
// over plain HTTP. It preserves the upgrade headers, sends the request to
// the upstream, and if the upstream responds with 101, hijacks both sides
// and does bidirectional copy.
func (p *proxyHandler) handleHTTPUpgrade(w http.ResponseWriter, r *http.Request) {
	clientIP := clientIPFromRequest(r)
	credID := p.credentialForIP(clientIP)

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		logError("http/upgrade/new-request", err, clientIP, credID)
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
		logError("http/upgrade/roundtrip", err, clientIP, credID)
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
		logError("http/upgrade/hijack", err, clientIP, credID)
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

// matchContextFromRequest builds a MatchContext from the HTTP request,
// extracting the page domain (from Referer) and resource type (from
// Sec-Fetch-Dest, Accept header, or URL extension).
func matchContextFromRequest(req *http.Request) blocklist.MatchContext {
	ctx := blocklist.MatchContext{
		ResourceType: blocklist.InferResourceType(req),
	}
	referer := req.Header.Get("Referer")
	if referer == "" {
		return ctx
	}
	parsed, err := url.Parse(referer)
	if err != nil {
		return ctx
	}
	ctx.PageDomain = parsed.Hostname()
	return ctx
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
