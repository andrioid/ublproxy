package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ublproxy/internal/blocklist"
	"ublproxy/internal/ca"
)

// --- SNI extraction tests ---

func TestExtractSNI(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	result := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		sni, err := extractSNI(br)
		if err != nil {
			errCh <- err
			return
		}
		result <- sni
	}()

	// Client: connect with SNI set to "example.com"
	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true,
		})
		// Initiate the handshake — server won't complete it but
		// the ClientHello is sent immediately.
		tlsConn.Handshake()
	}()

	select {
	case sni := <-result:
		if sni != "example.com" {
			t.Errorf("extractSNI = %q, want %q", sni, "example.com")
		}
	case err := <-errCh:
		t.Fatalf("extractSNI error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SNI extraction")
	}
}

func TestExtractSNINoSNI(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	result := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		sni, err := extractSNI(br)
		if err != nil {
			errCh <- err
			return
		}
		result <- sni
	}()

	// Client: connect without SNI (empty ServerName)
	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		tlsConn.Handshake()
	}()

	select {
	case sni := <-result:
		if sni != "" {
			t.Errorf("extractSNI = %q, want empty string for no SNI", sni)
		}
	case err := <-errCh:
		t.Fatalf("extractSNI error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SNI extraction")
	}
}

func TestExtractSNINonTLSData(t *testing.T) {
	clientData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	br := bufio.NewReader(bytes.NewReader(clientData))
	_, err := extractSNI(br)
	if err == nil {
		t.Error("extractSNI should return error for non-TLS data")
	}
}

// --- Transparent HTTPS proxy tests ---

type transparentTestEnv struct {
	proxyListener net.Listener
	proxy         *proxyHandler
	caCert        *x509.Certificate
	caPool        *x509.CertPool
	upstream      *httptest.Server
	upstreamPool  *x509.CertPool
	certs         *ca.Cache
	portalHost    string
	trustTracker  *caTrustTracker
}

func startTransparentTestEnv(t *testing.T, upstreamHandler http.Handler, rules *blocklist.RuleSet) *transparentTestEnv {
	t.Helper()

	upstream := httptest.NewTLSServer(upstreamHandler)

	caCert, caKey, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	certs := ca.NewCache(caCert, caKey)
	caCertPEM := ca.EncodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM)
	if rules != nil {
		handler.baselineRules.Store(rules)
	}
	handler.activityLog = NewActivityLog(100)

	upstreamCAPool := x509.NewCertPool()
	upstreamCAPool.AddCert(upstream.Certificate())
	handler.transport.TLSClientConfig = &tls.Config{
		RootCAs: upstreamCAPool,
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	portalHost := "proxy.local"
	handler.portalOrigin = fmt.Sprintf("https://%s", portalHost)
	handler.httpOrigin = fmt.Sprintf("http://%s", portalHost)

	trustTracker := newCATrustTracker()

	t.Cleanup(func() {
		ln.Close()
		upstream.Close()
	})

	return &transparentTestEnv{
		proxyListener: ln,
		proxy:         handler,
		caCert:        caCert,
		caPool:        caPool,
		upstream:      upstream,
		upstreamPool:  upstreamCAPool,
		certs:         certs,
		portalHost:    portalHost,
		trustTracker:  trustTracker,
	}
}

func (e *transparentTestEnv) serveTransparentHTTPS(t *testing.T) {
	t.Helper()
	go serveTransparentTLS(e.proxyListener, e.proxy, e.certs, e.portalHost, nil, e.trustTracker)
}

func TestTransparentHTTPSProxy(t *testing.T) {
	env := startTransparentTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello transparent"))
	}), nil)

	// The upstream is on 127.0.0.1, but TLS clients don't send SNI for
	// IP addresses. Use a fake hostname and override DNS resolution in
	// the proxy's transport to route it to the upstream.
	_, upstreamPort, _ := net.SplitHostPort(env.upstream.Listener.Addr().String())
	sniHost := "test.example.com"
	upstreamAddr := env.upstream.Listener.Addr().String()

	env.proxy.transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		// Redirect connections for our test hostname to the upstream
		h, _, _ := net.SplitHostPort(addr)
		if h == sniHost {
			return net.DialTimeout(network, upstreamAddr, 5*time.Second)
		}
		return net.DialTimeout(network, addr, 5*time.Second)
	}

	env.serveTransparentHTTPS(t)

	conn, err := net.DialTimeout("tcp", env.proxyListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: sniHost,
		RootCAs:    env.caPool,
	})
	defer tlsConn.Close()

	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%s/test", sniHost, upstreamPort), nil)
	req.Host = net.JoinHostPort(sniHost, upstreamPort)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "hello transparent" {
		t.Errorf("body = %q, want %q", body, "hello transparent")
	}
}

func TestTransparentHTTPSBlockedHost(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||blocked.example.com^")

	env := startTransparentTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached for blocked host")
	}), rs)
	env.serveTransparentHTTPS(t)

	conn, err := net.DialTimeout("tcp", env.proxyListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "blocked.example.com",
		InsecureSkipVerify: true,
	})

	// For a blocked host the proxy closes the connection.
	err = tlsConn.Handshake()
	if err == nil {
		// Handshake succeeded — read should fail or return blocked
		req, _ := http.NewRequest("GET", "https://blocked.example.com/", nil)
		req.Write(tlsConn)
		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		if err != nil {
			return // connection closed — acceptable
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want %d for blocked host", resp.StatusCode, http.StatusForbidden)
		}
	}
	// TLS error is acceptable — blocked host connection closed
}

func TestTransparentHTTPSPassthrough(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("@@||passthrough.test^")

	env := startTransparentTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("passthrough response"))
	}), rs)
	env.serveTransparentHTTPS(t)

	conn, err := net.DialTimeout("tcp", env.proxyListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// For passthrough, the proxy relays the raw TLS connection to
	// upstream. Since passthrough.test:443 doesn't exist, the dial
	// will fail and the proxy will close the connection. We verify
	// that the proxy does NOT perform MITM.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "passthrough.test",
		InsecureSkipVerify: true,
	})

	err = tlsConn.Handshake()
	if err == nil {
		// Handshake succeeded — check this is NOT our CA cert
		state := tlsConn.ConnectionState()
		for _, cert := range state.PeerCertificates {
			if cert.Issuer.CommonName == env.caCert.Subject.CommonName {
				t.Error("proxy performed MITM on excepted host — expected passthrough")
			}
		}
	}
	// Error expected: upstream dial failure for passthrough.test:443
}

func TestTransparentHTTPSTrustTracking(t *testing.T) {
	env := startTransparentTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	sniHost := "trust-test.example.com"
	upstreamAddr := env.upstream.Listener.Addr().String()
	env.proxy.transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(addr)
		if h == sniHost {
			return net.DialTimeout(network, upstreamAddr, 5*time.Second)
		}
		return net.DialTimeout(network, addr, 5*time.Second)
	}

	env.serveTransparentHTTPS(t)

	// Successful TLS handshake should mark client as trusted
	conn, err := net.DialTimeout("tcp", env.proxyListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: sniHost,
		RootCAs:    env.caPool,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	tlsConn.Close()

	// Allow a moment for the trust tracker to be updated
	time.Sleep(50 * time.Millisecond)

	if !env.trustTracker.isTrusted("127.0.0.1") {
		t.Error("client should be marked as trusted after successful TLS handshake")
	}
}

// --- Transparent HTTP proxy tests ---

type transparentHTTPTestEnv struct {
	server       *httptest.Server
	proxy        *proxyHandler
	trustTracker *caTrustTracker
}

func startTransparentHTTPTestEnv(t *testing.T) *transparentHTTPTestEnv {
	t.Helper()

	caCert, caKey, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	certs := ca.NewCache(caCert, caKey)
	caCertPEM := ca.EncodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM)
	handler.activityLog = NewActivityLog(100)
	handler.portalOrigin = "https://proxy.local:8443"
	handler.httpOrigin = "http://proxy.local:8080"

	trustTracker := newCATrustTracker()
	transparentH := &transparentHTTPHandler{
		proxy:        handler,
		trustTracker: trustTracker,
		portalHost:   "proxy.local",
	}

	server := httptest.NewServer(transparentH)
	t.Cleanup(server.Close)

	return &transparentHTTPTestEnv{
		server:       server,
		proxy:        handler,
		trustTracker: trustTracker,
	}
}

func TestTransparentHTTPProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello http transparent"))
	}))
	defer upstream.Close()

	env := startTransparentHTTPTestEnv(t)

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	req, _ := http.NewRequest("GET", env.server.URL+"/test", nil)
	req.Host = upstreamHost

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "hello http transparent" {
		t.Errorf("body = %q, want %q", body, "hello http transparent")
	}
}

// --- Captive portal tests ---

func TestCaptivePortalAppleDetection(t *testing.T) {
	env := startTransparentHTTPTestEnv(t)

	req, _ := http.NewRequest("GET", env.server.URL+"/hotspot-detect.html", nil)
	req.Host = "captive.apple.com"

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d for captive portal redirect", resp.StatusCode, http.StatusFound)
	}
	location := resp.Header.Get("Location")
	if location == "" {
		t.Error("missing Location header in captive portal redirect")
	}
}

func TestCaptivePortalTrustedClientBypass(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<HTML><BODY>Success</BODY></HTML>"))
	}))
	defer upstream.Close()

	env := startTransparentHTTPTestEnv(t)

	// Mark client IP as trusted
	env.trustTracker.markTrusted("127.0.0.1")

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")
	req, _ := http.NewRequest("GET", env.server.URL+"/hotspot-detect.html", nil)
	req.Host = upstreamHost

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d for trusted client", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Success") {
		t.Errorf("body = %q, want to contain 'Success'", body)
	}
}

func TestCaptivePortalAndroidDetection(t *testing.T) {
	env := startTransparentHTTPTestEnv(t)

	req, _ := http.NewRequest("GET", env.server.URL+"/generate_204", nil)
	req.Host = "connectivitycheck.gstatic.com"

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d for captive portal redirect", resp.StatusCode, http.StatusFound)
	}
}

func TestTransparentHTTPPortalAccess(t *testing.T) {
	env := startTransparentHTTPTestEnv(t)

	req, _ := http.NewRequest("GET", env.server.URL+"/", nil)
	req.Host = "proxy.local"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ublproxy") {
		t.Errorf("body should contain 'ublproxy' for portal page")
	}
}

// --- Transparent HTTPS portal access ---

func TestTransparentHTTPSPortalAccess(t *testing.T) {
	env := startTransparentTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be reached for portal access")
	}), nil)
	env.serveTransparentHTTPS(t)

	// Connect with SNI matching the portal hostname — the proxy should
	// serve the management portal instead of proxying to upstream.
	conn, err := net.DialTimeout("tcp", env.proxyListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: env.portalHost,
		RootCAs:    env.caPool,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	// Request the portal index page
	req, _ := http.NewRequest("GET", "https://"+env.portalHost+"/", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ublproxy") {
		t.Errorf("portal page should contain 'ublproxy', got %q", string(body[:min(len(body), 200)]))
	}
}

// --- URL-level blocking in transparent mode ---

func TestTransparentHTTPSBlocksByURLPattern(t *testing.T) {
	var requestPaths []string

	rs := blocklist.NewRuleSet()
	rs.AddRule("/ads/tracking.js")

	env := startTransparentTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream response"))
	}), rs)

	sniHost := "urlblock.example.com"
	upstreamAddr := env.upstream.Listener.Addr().String()
	_, upstreamPort, _ := net.SplitHostPort(upstreamAddr)

	env.proxy.transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(addr)
		if h == sniHost {
			return net.DialTimeout(network, upstreamAddr, 5*time.Second)
		}
		return net.DialTimeout(network, addr, 5*time.Second)
	}

	env.serveTransparentHTTPS(t)

	conn, err := net.DialTimeout("tcp", env.proxyListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: sniHost,
		RootCAs:    env.caPool,
	})
	defer tlsConn.Close()

	hostPort := net.JoinHostPort(sniHost, upstreamPort)
	br := bufio.NewReader(tlsConn)

	// Non-matching path should pass through
	req1, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/page.html", hostPort), nil)
	req1.Host = hostPort
	if err := req1.Write(tlsConn); err != nil {
		t.Fatalf("write request 1: %v", err)
	}
	resp1, err := http.ReadResponse(br, req1)
	if err != nil {
		t.Fatalf("read response 1: %v", err)
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Errorf("page.html: status = %d, want %d", resp1.StatusCode, http.StatusOK)
	}

	// Matching URL pattern should be blocked inside the MITM tunnel
	req2, _ := http.NewRequest("GET", fmt.Sprintf("https://%s/ads/tracking.js", hostPort), nil)
	req2.Host = hostPort
	if err := req2.Write(tlsConn); err != nil {
		t.Fatalf("write request 2: %v", err)
	}
	resp2, err := http.ReadResponse(br, req2)
	if err != nil {
		t.Fatalf("read response 2: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusNoContent {
		t.Errorf("tracking.js: status = %d, want %d", resp2.StatusCode, http.StatusNoContent)
	}

	// Only the allowed request should have reached upstream
	if len(requestPaths) != 1 || requestPaths[0] != "/page.html" {
		t.Errorf("upstream received %v, want [/page.html]", requestPaths)
	}
}

func TestTransparentHTTPBlocksByURLPattern(t *testing.T) {
	var requestPaths []string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream response"))
	}))
	defer upstream.Close()

	rs := blocklist.NewRuleSet()
	rs.AddRule("/ads/tracking.js")

	env := startTransparentHTTPTestEnv(t)
	env.proxy.baselineRules.Store(rs)

	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	// Non-matching path should pass through
	req1, _ := http.NewRequest("GET", env.server.URL+"/page.html", nil)
	req1.Host = upstreamHost

	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("GET /page.html: %v", err)
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Errorf("page.html: status = %d, want %d", resp1.StatusCode, http.StatusOK)
	}

	// Matching URL pattern should be blocked
	req2, _ := http.NewRequest("GET", env.server.URL+"/ads/tracking.js", nil)
	req2.Host = upstreamHost

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET /ads/tracking.js: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusNoContent {
		t.Errorf("tracking.js: status = %d, want %d", resp2.StatusCode, http.StatusNoContent)
	}

	// Only the allowed request should have reached upstream
	if len(requestPaths) != 1 || requestPaths[0] != "/page.html" {
		t.Errorf("upstream received %v, want [/page.html]", requestPaths)
	}
}

// --- WebSocket in transparent HTTP mode ---

func TestTransparentHTTPWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(wsEchoHandler))
	defer upstream.Close()

	env := startTransparentHTTPTestEnv(t)
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	// Connect raw TCP to the transparent HTTP test server and perform
	// a WebSocket upgrade with Host header pointing at the upstream.
	serverHost := strings.TrimPrefix(env.server.URL, "http://")
	conn, err := net.DialTimeout("tcp", serverHost, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send WebSocket upgrade request
	wsKey := "dGhlIHNhbXBsZSBub25jZQ=="
	reqStr := fmt.Sprintf(
		"GET /ws HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"\r\n",
		upstreamHost, wsKey)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	// Read the 101 response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}

	// Send a masked WebSocket text frame and read the echo back
	payload := []byte("hello transparent websocket")
	if err := writeMaskedWSFrame(conn, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	frame, err := readWSFrame(br)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if string(frame.payload) != string(payload) {
		t.Errorf("frame payload = %q, want %q", frame.payload, payload)
	}
}

// --- CA trust tracker tests ---

func TestCATrustTracker(t *testing.T) {
	tracker := newCATrustTracker()

	if tracker.isTrusted("192.168.1.100") {
		t.Error("new IP should not be trusted")
	}

	tracker.markTrusted("192.168.1.100")
	if !tracker.isTrusted("192.168.1.100") {
		t.Error("IP should be trusted after marking")
	}

	if tracker.isTrusted("192.168.1.101") {
		t.Error("different IP should not be trusted")
	}
}
