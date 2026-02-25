package main

import (
	"bufio"
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
		if p.rules.ShouldBlock(targetURL) {
			blocked := &http.Response{
				StatusCode: http.StatusNoContent,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
			}
			blocked.Write(clientTLS)
			continue
		}

		start := time.Now()
		req.URL.Scheme = "https"
		req.URL.Host = net.JoinHostPort(host, port)
		req.RequestURI = ""

		removeHopByHopHeaders(req.Header)

		resp, err := p.transport.RoundTrip(req)
		if err != nil {
			logError("connect/roundtrip", err)
			return
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
