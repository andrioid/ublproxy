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
	if p.rules.IsHostBlocked(host) {
		w.WriteHeader(http.StatusNoContent)
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
		logError("connect/hijack", err)
		return
	}
	defer clientConn.Close()

	tlsCert, err := p.certs.getCert(host)
	if err != nil {
		logError("connect/cert", err)
		return
	}

	// TLS handshake with the client, presenting our dynamic cert
	tlsClientConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	})
	if err := tlsClientConn.Handshake(); err != nil {
		logError("connect/client-tls", err)
		return
	}
	defer tlsClientConn.Close()

	p.proxyTLSRequests(tlsClientConn, host, port)
}

// proxyTLSRequests reads HTTP requests from the intercepted client TLS
// connection and forwards them to the upstream server. Supports keep-alive
// by looping until the client closes the connection or an error occurs.
func (p *proxyHandler) proxyTLSRequests(clientTLS *tls.Conn, host, port string) {
	clientReader := bufio.NewReader(clientTLS)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				logError("connect/read-request", err)
			}
			return
		}

		targetURL := "https://" + host + req.URL.String()

		// URL-level blocking for pattern rules (hostname was already
		// checked at CONNECT time; this catches path-specific rules)
		ctx := matchContextFromReferer(req.Header.Get("Referer"))
		if p.rules.ShouldBlockRequest(targetURL, ctx) {
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
			logError("connect/roundtrip", err)
			return
		}

		// WebSocket upgrade: switch to bidirectional copy
		if upgradeReq && resp.StatusCode == http.StatusSwitchingProtocols {
			upstreamConn, ok := resp.Body.(io.ReadWriteCloser)
			if !ok {
				resp.Body.Close()
				logError("connect/upgrade", io.ErrUnexpectedEOF)
				return
			}
			defer upstreamConn.Close()

			resp.Body = nil
			resp.Write(clientTLS)

			logRequest(req.Method, targetURL+" [websocket]", resp.StatusCode, time.Since(start))

			// clientReader may have buffered bytes past the HTTP request,
			// so we read from it (not raw clientTLS). Writes go to clientTLS.
			bidirectionalCopy(&readerWriter{r: clientReader, w: clientTLS}, upstreamConn)
			return
		}

		// Inject element hiding CSS into HTML responses (skip HEAD — no body to modify)
		if req.Method != http.MethodHead {
			if modified, ok := p.injectElementHidingCSS(resp, host); ok {
				resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(modified))
				resp.ContentLength = int64(len(modified))
				resp.Header.Del("Content-Length")
			}
		}

		if err := resp.Write(clientTLS); err != nil {
			resp.Body.Close()
			logError("connect/write-response", err)
			return
		}
		resp.Body.Close()

		logRequest(req.Method, targetURL, resp.StatusCode, time.Since(start))

		if resp.Close {
			return
		}
	}
}
