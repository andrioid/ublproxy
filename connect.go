package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

func (p *proxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		// CONNECT targets should always have a port, but handle gracefully
		host = r.Host
		port = "443"
	}
	clientIP := clientIPFromRequest(r)
	credID := p.credentialForIP(clientIP)
	if p.shouldBlockHost(clientIP, host) {
		p.logActivity(ActivityBlocked, host, "", "||"+host+"^", clientIP, credID)
		logBlocked(host, "", "||"+host+"^", clientIP, credID)
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	// Host-level @@ exception: tunnel traffic directly without MITM.
	// The proxy never sees the plaintext — the client's TLS session
	// goes straight to the upstream server.
	if p.isHostExcepted(clientIP, host) {
		p.logActivity(ActivityPassthrough, host, "", "@@||"+host+"^", clientIP, credID)
		p.tunnelPassthrough(w, r, host, port, clientIP, credID)
		return
	}

	// Circuit breaker: skip MITM for hosts with repeated handshake
	// failures (likely cert-pinned).
	if p.handshakeTracker != nil && p.handshakeTracker.IsTripped(host) {
		p.logActivity(ActivityAutoPassthrough, host, "", "auto-passthrough", clientIP, credID)
		logAutoPassthrough(host, clientIP, credID)
		p.tunnelPassthrough(w, r, host, port, clientIP, credID)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Tell the client the tunnel is established
	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logError("connect/hijack", err, clientIP, credID)
		return
	}
	defer clientConn.Close()

	tlsCert, err := p.certs.GetCert(host)
	if err != nil {
		logError("connect/cert", err, clientIP, credID)
		return
	}

	// TLS handshake with the client, presenting our dynamic cert.
	// Set a deadline to prevent slow/malicious clients from tying up goroutines.
	clientConn.SetDeadline(time.Now().Add(10 * time.Second))
	tlsClientConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	})
	if err := tlsClientConn.Handshake(); err != nil {
		logError("connect/client-tls", err, clientIP, credID)
		if p.handshakeTracker != nil {
			p.handshakeTracker.RecordFailure(host)
		}
		return
	}
	defer tlsClientConn.Close()

	if p.handshakeTracker != nil {
		p.handshakeTracker.RecordSuccess(host)
	}

	// Clear the deadline after successful handshake
	clientConn.SetDeadline(time.Time{})

	// If the outer connection is plain HTTP (r.TLS == nil), mark as insecure
	// so the bootstrap script (which contains the session token) is not injected.
	insecure := r.TLS == nil
	p.proxyTLSRequests(tlsClientConn, host, port, clientIP, credID, insecure)
}

// tunnelPassthrough establishes a transparent TCP tunnel between the client
// and upstream server. No MITM, no cert generation, no request inspection.
// The proxy only sees connection metadata (hostname, timing, bytes transferred).
func (p *proxyHandler) tunnelPassthrough(w http.ResponseWriter, r *http.Request, host, port, clientIP, credID string) {
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		logError("passthrough/dial", err, clientIP, credID)
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		logError("passthrough/hijack", err, clientIP, credID)
		return
	}
	defer clientConn.Close()

	logPassthrough(host, clientIP, credID)
	bidirectionalCopy(clientConn, upstream)
}

// proxyTLSRequests reads HTTP requests from the intercepted client TLS
// connection and forwards them to the upstream server. Supports keep-alive
// by looping until the client closes the connection or an error occurs.
// When insecure is true the outer proxy connection is plain HTTP, so the
// bootstrap script (which embeds the session token) is not injected.
func (p *proxyHandler) proxyTLSRequests(clientTLS *tls.Conn, host, port, clientIP, credID string, insecure bool) {
	clientReader := bufio.NewReader(clientTLS)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				logError("connect/read-request", err, clientIP, credID)
			}
			return
		}

		targetURL := "https://" + host + req.URL.String()

		// URL-level blocking for pattern rules (hostname was already
		// checked at CONNECT time; this catches path-specific rules)
		ctx := matchContextFromRequest(req)
		if p.shouldBlock(clientIP, targetURL, ctx) {
			p.logActivity(ActivityBlocked, host, targetURL, "", clientIP, credID)
			logBlocked(host, targetURL, "", clientIP, credID)
			req.Body.Close()
			blocked := &http.Response{
				StatusCode: http.StatusNoContent,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
			}
			blocked.Write(clientTLS)
			continue
		}

		upgradeReq := isWebSocketUpgrade(req.Header)

		start := time.Now()
		req.URL.Scheme = "https"
		req.URL.Host = net.JoinHostPort(host, port)
		req.RequestURI = ""

		removeHopByHopHeaders(req.Header)

		// Re-add upgrade headers that were stripped as hop-by-hop
		if upgradeReq {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
		}

		resp, err := p.transport.RoundTrip(req)
		if err != nil {
			logError("connect/roundtrip", err, clientIP, credID)
			return
		}

		// WebSocket upgrade: switch to bidirectional copy
		if upgradeReq && resp.StatusCode == http.StatusSwitchingProtocols {
			upstreamConn, ok := resp.Body.(io.ReadWriteCloser)
			if !ok {
				resp.Body.Close()
				logError("connect/upgrade", io.ErrUnexpectedEOF, clientIP, credID)
				return
			}
			defer upstreamConn.Close()

			resp.Body = nil
			resp.Write(clientTLS)

			logRequest(req.Method, targetURL+" [websocket]", resp.StatusCode, time.Since(start), clientIP, credID)

			// clientReader may have buffered bytes past the HTTP request,
			// so we read from it (not raw clientTLS). Writes go to clientTLS.
			bidirectionalCopy(&readerWriter{r: clientReader, w: clientTLS}, upstreamConn)
			return
		}

		// Replace ad elements in HTML responses (skip HEAD — no body to modify)
		if req.Method != http.MethodHead {
			if modified, stats := p.applyElementHiding(resp, host, clientIP, insecure); stats.Modified {
				resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(modified))
				resp.ContentLength = int64(len(modified))
				resp.Header.Del("Content-Length")
				resp.Header.Set(statsHeaderName, stats.header())
			}
		}

		if err := resp.Write(clientTLS); err != nil {
			resp.Body.Close()
			logError("connect/write-response", err, clientIP, credID)
			return
		}
		resp.Body.Close()

		logRequest(req.Method, targetURL, resp.StatusCode, time.Since(start), clientIP, credID)

		if resp.Close {
			return
		}
	}
}
