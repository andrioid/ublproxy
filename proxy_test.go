package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/andybalholm/brotli"

	"ublproxy/pkg/blocklist"
)

// testEnv holds everything needed to run a proxy e2e test.
type testEnv struct {
	proxyURL string
	httpURL  string
	httpsURL string
	caPool   *x509.CertPool
}

// startTestEnv spins up an upstream HTTP server, an upstream HTTPS server, and
// the proxy itself. The CA is generated in-memory — no disk I/O.
// Pass nil for rules to create a proxy without blocking.
func startTestEnv(t *testing.T, upstreamHandler http.Handler, rules *blocklist.RuleSet) *testEnv {
	t.Helper()

	// Upstream servers
	httpServer := httptest.NewServer(upstreamHandler)
	httpsServer := httptest.NewTLSServer(upstreamHandler)

	// In-memory CA
	caCert, caKey, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}

	certs := newCertCache(caCert, caKey)
	caCertPEM := encodeCertPEM(caCert)
	handler := newProxyHandler(certs, caCertPEM, rules)

	// Trust the test HTTPS server's certificate so the proxy can validate
	// upstream TLS connections (proxy validates upstream certs in production)
	upstreamCAPool := x509.NewCertPool()
	upstreamCAPool.AddCert(httpsServer.Certificate())
	handler.transport.TLSClientConfig = &tls.Config{
		RootCAs: upstreamCAPool,
	}

	// The proxy needs a real http.Server (not httptest) so that Hijack works
	// on the ResponseWriter. httptest.NewServer wraps net/http.Server, which
	// does support Hijack, so this is fine.
	proxyServer := httptest.NewServer(handler)

	// Build a CertPool that trusts our test CA so the HTTP client validates
	// the MITM certificates the proxy presents.
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	t.Cleanup(func() {
		proxyServer.Close()
		httpServer.Close()
		httpsServer.Close()
	})

	return &testEnv{
		proxyURL: proxyServer.URL,
		httpURL:  httpServer.URL,
		httpsURL: httpsServer.URL,
		caPool:   caPool,
	}
}

// httpsHost returns the host:port of the HTTPS upstream server.
func (e *testEnv) httpsHost() string {
	u, _ := url.Parse(e.httpsURL)
	return u.Host
}

// httpClient returns an *http.Client configured to route through the proxy.
// For HTTPS requests, it trusts the test CA.
func (e *testEnv) httpClient(t *testing.T) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse(e.proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: e.caPool,
			},
		},
	}
}

func TestHTTPProxy(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from upstream"))
	}), nil)

	client := env.httpClient(t)
	resp, err := client.Get(env.httpURL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from upstream" {
		t.Errorf("body = %q, want %q", body, "hello from upstream")
	}
}

func TestHTTPProxyHeaders(t *testing.T) {
	var receivedHeaders http.Header

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("X-Upstream-Header", "present")
		w.WriteHeader(http.StatusOK)
	}), nil)

	client := env.httpClient(t)

	req, err := http.NewRequest("GET", env.httpURL+"/headers", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Custom-Header", "test-value")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	// Custom header should be forwarded to upstream
	if got := receivedHeaders.Get("X-Custom-Header"); got != "test-value" {
		t.Errorf("upstream X-Custom-Header = %q, want %q", got, "test-value")
	}

	// Hop-by-hop headers should be stripped before forwarding
	if got := receivedHeaders.Get("Connection"); got != "" {
		t.Errorf("upstream Connection header = %q, want it stripped", got)
	}

	// Response headers from upstream should be forwarded to client
	if got := resp.Header.Get("X-Upstream-Header"); got != "present" {
		t.Errorf("response X-Upstream-Header = %q, want %q", got, "present")
	}
}

func TestHTTPSProxy(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from tls upstream"))
	}), nil)

	client := env.httpClient(t)
	resp, err := client.Get(env.httpsURL + "/secure")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from tls upstream" {
		t.Errorf("body = %q, want %q", body, "hello from tls upstream")
	}
}

func TestHTTPSProxyHeaders(t *testing.T) {
	var receivedHeaders http.Header

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("X-Upstream-Secure", "yes")
		w.WriteHeader(http.StatusOK)
	}), nil)

	client := env.httpClient(t)

	req, err := http.NewRequest("GET", env.httpsURL+"/secure-headers", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Custom-Secure", "secure-value")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := receivedHeaders.Get("X-Custom-Secure"); got != "secure-value" {
		t.Errorf("upstream X-Custom-Secure = %q, want %q", got, "secure-value")
	}

	if got := resp.Header.Get("X-Upstream-Secure"); got != "yes" {
		t.Errorf("response X-Upstream-Secure = %q, want %q", got, "yes")
	}
}

func TestHTTPProxyPOST(t *testing.T) {
	var receivedBody string

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}), nil)

	client := env.httpClient(t)
	resp, err := client.Post(env.httpURL+"/create", "text/plain", strings.NewReader("request body"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	if receivedBody != "request body" {
		t.Errorf("upstream body = %q, want %q", receivedBody, "request body")
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "created" {
		t.Errorf("response body = %q, want %q", body, "created")
	}
}

func TestPortalPage(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	// Direct request to the proxy (not through it as a proxy)
	resp, err := http.Get(env.proxyURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain %q", contentType, "text/html")
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	for _, want := range []string{"ublproxy", "ca.crt", "Install"} {
		if !strings.Contains(bodyStr, want) {
			t.Errorf("body does not contain %q", want)
		}
	}
}

func TestPortalCACertDownload(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	// Direct request to download the CA cert
	resp, err := http.Get(env.proxyURL + "/ca.crt")
	if err != nil {
		t.Fatalf("GET /ca.crt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-pem-file" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/x-pem-file")
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.HasPrefix(bodyStr, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("body does not start with PEM header, got %q", bodyStr[:min(len(bodyStr), 40)])
	}

	// Verify the PEM can be decoded and parsed as a valid certificate
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("failed to decode PEM block from response body")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if !cert.IsCA {
		t.Error("downloaded certificate is not a CA certificate")
	}

	if cert.Subject.CommonName != "ublproxy CA" {
		t.Errorf("certificate CN = %q, want %q", cert.Subject.CommonName, "ublproxy CA")
	}
}

func TestHTTPSProxyPOST(t *testing.T) {
	var receivedBody string

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created securely"))
	}), nil)

	client := env.httpClient(t)
	resp, err := client.Post(env.httpsURL+"/secure-create", "text/plain", strings.NewReader("secure body"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	if receivedBody != "secure body" {
		t.Errorf("upstream body = %q, want %q", receivedBody, "secure body")
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "created securely" {
		t.Errorf("response body = %q, want %q", body, "created securely")
	}
}

func TestBlocksHTTPByHostname(t *testing.T) {
	var upstreamHit atomic.Bool

	rs := blocklist.NewRuleSet()
	rs.AddHostname("127.0.0.1")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not see this"))
	}), rs)

	client := env.httpClient(t)
	resp, err := client.Get(env.httpURL + "/tracking.js")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("body = %q, want empty (blocked)", body)
	}

	if upstreamHit.Load() {
		t.Error("upstream was hit, but request should have been blocked")
	}
}

func TestBlocksHTTPSByHostname(t *testing.T) {
	var upstreamHit atomic.Bool

	rs := blocklist.NewRuleSet()
	rs.AddHostname("127.0.0.1")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not see this"))
	}), rs)

	client := env.httpClient(t)

	// HTTPS request to a blocked host — the CONNECT tunnel should be blocked
	// before any TLS handshake occurs, so the client will get an error.
	_, err := client.Get(env.httpsURL + "/secure-tracking.js")
	if err == nil {
		t.Error("expected error for blocked HTTPS host, got nil")
	}

	if upstreamHit.Load() {
		t.Error("upstream was hit, but request should have been blocked")
	}
}

func TestBlocksHTTPByURLPattern(t *testing.T) {
	var lastPath string

	rs := blocklist.NewRuleSet()
	rs.AddRule("/ads/banner*.gif")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream response"))
	}), rs)

	client := env.httpClient(t)

	// Matching URL pattern should be blocked
	resp, err := client.Get(env.httpURL + "/ads/banner123.gif")
	if err != nil {
		t.Fatalf("GET blocked URL: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("blocked status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Non-matching URL should pass through
	resp, err = client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET allowed URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "upstream response" {
		t.Errorf("body = %q, want %q", body, "upstream response")
	}

	if lastPath != "/page.html" {
		t.Errorf("upstream saw path = %q, want %q", lastPath, "/page.html")
	}
}

func TestBlocksHTTPSByURLPattern(t *testing.T) {
	var requestPaths []string

	rs := blocklist.NewRuleSet()
	rs.AddRule("/ads/tracking.js")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream response"))
	}), rs)

	client := env.httpClient(t)

	// Non-matching path should pass through (CONNECT succeeds, MITM proxies request)
	resp, err := client.Get(env.httpsURL + "/page.html")
	if err != nil {
		t.Fatalf("GET allowed HTTPS URL: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "upstream response" {
		t.Errorf("body = %q, want %q", body, "upstream response")
	}

	// Matching URL pattern should be blocked after MITM (CONNECT succeeds,
	// but the individual request inside the tunnel is blocked)
	resp, err = client.Get(env.httpsURL + "/ads/tracking.js")
	if err != nil {
		t.Fatalf("GET blocked HTTPS URL: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("blocked status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Only the allowed request should have reached upstream
	if len(requestPaths) != 1 || requestPaths[0] != "/page.html" {
		t.Errorf("upstream saw paths = %v, want [/page.html]", requestPaths)
	}
}

func TestExceptionAllowsBlockedHTTPPath(t *testing.T) {
	var requestPaths []string

	rs := blocklist.NewRuleSet()
	rs.AddRule("/ads/*")
	rs.AddException("@@/ads/approved*")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}), rs)

	client := env.httpClient(t)

	// Blocked by /ads/* rule
	resp, err := client.Get(env.httpURL + "/ads/tracking.js")
	if err != nil {
		t.Fatalf("GET blocked URL: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("blocked status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Exception allows /ads/approved*
	resp, err = client.Get(env.httpURL + "/ads/approved-banner.gif")
	if err != nil {
		t.Fatalf("GET excepted URL: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("excepted status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "ok" {
		t.Errorf("excepted body = %q, want %q", body, "ok")
	}

	// Only the excepted request should have reached upstream
	if len(requestPaths) != 1 || requestPaths[0] != "/ads/approved-banner.gif" {
		t.Errorf("upstream saw paths = %v, want [/ads/approved-banner.gif]", requestPaths)
	}
}

func TestThirdPartyOption(t *testing.T) {
	var requestPaths []string

	rs := blocklist.NewRuleSet()
	// Only block /ads/* when the request is cross-origin
	rs.AddRule("/ads/*$third-party")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPaths = append(requestPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}), rs)

	client := env.httpClient(t)

	// Same-origin request (Referer matches request host): should NOT be blocked.
	// The upstream runs on 127.0.0.1, so use a Referer from the same host.
	req, _ := http.NewRequest("GET", env.httpURL+"/ads/banner.gif", nil)
	req.Header.Set("Referer", env.httpURL+"/page.html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET same-origin: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("same-origin status = %d, want %d (should not be blocked)", resp.StatusCode, http.StatusOK)
	}

	// Cross-origin request (Referer from different domain): should be blocked.
	req, _ = http.NewRequest("GET", env.httpURL+"/ads/banner.gif", nil)
	req.Header.Set("Referer", "http://differentdomain.com/page.html")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET cross-origin: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("cross-origin status = %d, want %d (should be blocked)", resp.StatusCode, http.StatusNoContent)
	}

	// Only the same-origin request should have reached upstream
	if len(requestPaths) != 1 || requestPaths[0] != "/ads/banner.gif" {
		t.Errorf("upstream saw paths = %v, want [/ads/banner.gif]", requestPaths)
	}
}

func TestElementHidingReplacesElements(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")
	rs.AddLine("##.tracking-pixel")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test</title></head><body>` +
			`<div class="ad-banner"><script src="tracker.js"></script></div>` +
			`<img class="tracking-pixel" src="pixel.gif">` +
			`<p>Real content</p>` +
			`</body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Matched elements should be replaced with placeholder divs
	if !strings.Contains(bodyStr, "<!-- ublproxy: replaced .ad-banner -->") {
		t.Errorf("response should contain replacement for .ad-banner, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "<!-- ublproxy: replaced .tracking-pixel -->") {
		t.Errorf("response should contain replacement for .tracking-pixel, got:\n%s", bodyStr)
	}

	// The original ad content (script tag, pixel image) should be stripped
	if strings.Contains(bodyStr, "tracker.js") {
		t.Errorf("ad content should be stripped, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, "pixel.gif") {
		t.Errorf("tracking pixel should be stripped, got:\n%s", bodyStr)
	}

	// Non-ad content should be preserved
	if !strings.Contains(bodyStr, "<title>Test</title>") {
		t.Errorf("title should be preserved, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Real content") {
		t.Errorf("real content should be preserved, got:\n%s", bodyStr)
	}
}

func TestElementHidingSkipsNonHTML(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/api/data")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// JSON response should not be modified
	if strings.Contains(bodyStr, "<style>") {
		t.Errorf("non-HTML response should not be modified, got:\n%s", bodyStr)
	}
	if bodyStr != `{"status": "ok"}` {
		t.Errorf("body = %q, want %q", bodyStr, `{"status": "ok"}`)
	}
}

func TestNonHTMLPreservesCompression(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	svgContent := `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="40"/></svg>`

	// Upstream serves gzip-compressed SVG when client accepts gzip
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			gz.Write([]byte(svgContent))
			gz.Close()

			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
			w.WriteHeader(http.StatusOK)
			w.Write(buf.Bytes())
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(svgContent))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)
	client.Transport.(*http.Transport).DisableCompression = true

	req, _ := http.NewRequest("GET", env.httpsURL+"/icon.svg", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The proxy must not corrupt non-HTML resources. The gzip body and
	// Content-Encoding header should arrive intact at the client.
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", resp.Header.Get("Content-Encoding"), "gzip")
	}

	gr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("body is not valid gzip: %v", err)
	}
	decoded, _ := io.ReadAll(gr)
	gr.Close()

	if string(decoded) != svgContent {
		t.Errorf("decoded SVG = %q, want %q", decoded, svgContent)
	}
}

func TestElementHidingBrotli(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	htmlBody := `<html><head></head><body><div class="ad-banner">Ad</div><p>Hello</p></body></html>`

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		bw := brotli.NewWriter(&buf)
		bw.Write([]byte(htmlBody))
		bw.Close()

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "br")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "<!-- ublproxy: replaced .ad-banner -->") {
		t.Errorf("brotli HTML should have element replaced, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Hello") {
		t.Errorf("non-ad content should be preserved, got:\n%s", bodyStr)
	}
}

func TestElementHidingHTTPS(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head></head><body><div class="ad-banner">Ad</div><p>Hello</p></body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpsURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "<!-- ublproxy: replaced .ad-banner -->") {
		t.Errorf("HTTPS response should have element replaced, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Hello") {
		t.Errorf("non-ad content should be preserved, got:\n%s", bodyStr)
	}
}

func TestElementHidingNestedContent(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-container")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<div class="ad-container">` +
			`<div class="inner"><script src="ad.js"></script>` +
			`<iframe src="ad-network.com/serve"></iframe></div>` +
			`</div>` +
			`<p>Keep this</p>` +
			`</body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// All nested content should be stripped
	if strings.Contains(bodyStr, "ad.js") {
		t.Errorf("nested script should be stripped, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, "ad-network.com") {
		t.Errorf("nested iframe should be stripped, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "<!-- ublproxy: replaced .ad-container -->") {
		t.Errorf("should contain replacement comment, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Keep this") {
		t.Errorf("non-ad content should be preserved, got:\n%s", bodyStr)
	}
}

func TestElementHidingVoidElement(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.tracking-pixel")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<img class="tracking-pixel" src="track.gif">` +
			`<p>Content</p>` +
			`</body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "track.gif") {
		t.Errorf("void element should be replaced, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "<!-- ublproxy: replaced .tracking-pixel -->") {
		t.Errorf("should contain replacement comment, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("non-ad content should be preserved, got:\n%s", bodyStr)
	}
}

func TestElementHidingComplexFallbackCSS(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// Complex selector (descendant combinator) — falls back to CSS
	rs.AddLine("##div .ad-child")
	// Simple selector — element replacement
	rs.AddLine("##.ad-banner")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head></head><body>` +
			`<div class="ad-banner">Ad</div>` +
			`<div><span class="ad-child">Nested ad</span></div>` +
			`</body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Simple selector should be replaced
	if !strings.Contains(bodyStr, "<!-- ublproxy: replaced .ad-banner -->") {
		t.Errorf("simple selector should be replaced, got:\n%s", bodyStr)
	}

	// Complex selector should fall back to CSS injection
	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("complex selector should inject style tag, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "div .ad-child") {
		t.Errorf("fallback CSS should contain the complex selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "display: none !important") {
		t.Errorf("fallback CSS should use display:none, got:\n%s", bodyStr)
	}
}

func TestElementHidingByID(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("###sidebar-ad")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<div id="sidebar-ad"><a href="sponsor.html">Sponsor</a></div>` +
			`<div id="content">Main</div>` +
			`</body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "<!-- ublproxy: replaced #sidebar-ad -->") {
		t.Errorf("element with matching ID should be replaced, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, "sponsor.html") {
		t.Errorf("ad content should be stripped, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Main") {
		t.Errorf("non-ad content should be preserved, got:\n%s", bodyStr)
	}
}

func TestElementHidingAttributeSelector(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`##div[class*="advertisement"]`)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<div class="top-advertisement-box">Ad</div>` +
			`<div class="content">Keep</div>` +
			`</body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, `<!-- ublproxy: replaced div[class*="advertisement"] -->`) {
		t.Errorf("attribute selector should match, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Keep") {
		t.Errorf("non-matching content should be preserved, got:\n%s", bodyStr)
	}
}

func TestElementHidingPreservesUnmatchedElements(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test</title></head><body>` +
			`<div class="content">Keep this</div>` +
			`<p>Also keep</p>` +
			`</body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// No elements match, so the output should closely match the input
	// (tokenizer may normalize some whitespace but should preserve content)
	if !strings.Contains(bodyStr, "Keep this") {
		t.Errorf("unmatched content should be preserved, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Also keep") {
		t.Errorf("unmatched content should be preserved, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, "ublproxy") {
		t.Errorf("no elements should be replaced, got:\n%s", bodyStr)
	}
}

func TestHeadRequestNoInjection(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", "44")
		w.WriteHeader(http.StatusOK)
		// HEAD responses have no body per HTTP spec
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	resp, err := client.Head(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// HEAD responses must have no body, even when element hiding rules exist
	if len(body) != 0 {
		t.Errorf("HEAD response should have empty body, got %d bytes: %q", len(body), body)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// --- WebSocket test helpers ---

// wsEchoHandler is a minimal WebSocket echo server using only stdlib.
// It performs the WebSocket handshake, then echoes back any frames it receives.
func wsEchoHandler(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "not a websocket request", http.StatusBadRequest)
		return
	}

	// Compute Sec-WebSocket-Accept from the client key
	key := r.Header.Get("Sec-WebSocket-Key")
	acceptKey := computeWebSocketAccept(key)

	h := w.(http.Hijacker)
	conn, buf, err := h.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Write the 101 response
	buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	buf.WriteString("Upgrade: websocket\r\n")
	buf.WriteString("Connection: Upgrade\r\n")
	buf.WriteString("Sec-WebSocket-Accept: " + acceptKey + "\r\n")
	buf.WriteString("\r\n")
	buf.Flush()

	// Echo loop: read a frame, write it back
	for {
		frame, err := readWSFrame(buf.Reader)
		if err != nil {
			return
		}
		writeWSFrame(conn, frame)
	}
}

// computeWebSocketAccept computes the Sec-WebSocket-Accept value per RFC 6455.
func computeWebSocketAccept(key string) string {
	const websocketGUID = "258EAFA5-E914-47DA-95CA-5AB5DC76E45B"
	h := sha1.New()
	h.Write([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsFrame is a minimal WebSocket frame (text only, no masking on server side).
type wsFrame struct {
	payload []byte
}

// readWSFrame reads a single WebSocket frame. Handles client-masked frames.
func readWSFrame(r io.Reader) (wsFrame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return wsFrame{}, err
	}

	masked := header[1]&0x80 != 0
	length := int(header[1] & 0x7F)

	// Only support small frames for testing
	if length == 126 || length == 127 {
		return wsFrame{}, io.ErrUnexpectedEOF
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return wsFrame{}, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return wsFrame{}, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return wsFrame{payload: payload}, nil
}

// writeWSFrame writes a single unmasked text frame.
func writeWSFrame(w io.Writer, f wsFrame) error {
	header := []byte{0x81, byte(len(f.payload))} // FIN + text opcode, length
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(f.payload)
	return err
}

// writeMaskedWSFrame writes a single masked text frame (required for client-to-server).
func writeMaskedWSFrame(w io.Writer, payload []byte) error {
	maskKey := [4]byte{0x12, 0x34, 0x56, 0x78} // fixed mask for testing
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ maskKey[i%4]
	}
	header := []byte{0x81, byte(len(payload)) | 0x80} // FIN + text opcode, masked, length
	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(maskKey[:]); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

// dialWebSocketViaProxy performs a WebSocket handshake through the proxy.
// Returns the raw connection for sending/receiving frames.
func dialWebSocketViaProxy(proxyURL, targetURL string, tlsConfig *tls.Config) (net.Conn, error) {
	parsed, _ := url.Parse(targetURL)
	proxyParsed, _ := url.Parse(proxyURL)

	var conn net.Conn
	var err error

	if parsed.Scheme == "wss" {
		// For wss://, first CONNECT to establish the tunnel
		conn, err = net.Dial("tcp", proxyParsed.Host)
		if err != nil {
			return nil, fmt.Errorf("dial proxy: %w", err)
		}

		// Send CONNECT
		host := parsed.Host
		if !strings.Contains(host, ":") {
			host += ":443"
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)

		// Read CONNECT response
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("CONNECT response: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("CONNECT status: %d", resp.StatusCode)
		}

		// TLS handshake over the tunnel
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tlsConn
	} else {
		// For ws://, connect to the proxy directly
		conn, err = net.Dial("tcp", proxyParsed.Host)
		if err != nil {
			return nil, fmt.Errorf("dial proxy: %w", err)
		}
	}

	// Send WebSocket upgrade request. Over a CONNECT tunnel (wss://), use
	// only the path since the TLS connection is already to the right host.
	// Over plain HTTP proxy (ws://), use the full URL per HTTP proxy spec.
	requestURI := targetURL
	if parsed.Scheme == "wss" {
		requestURI = parsed.RequestURI()
	}
	wsKey := base64.StdEncoding.EncodeToString([]byte("test-websocket-key!"))
	reqStr := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		requestURI, parsed.Host, wsKey,
	)
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upgrade: %w", err)
	}

	// Read the 101 response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("expected 101, got %d", resp.StatusCode)
	}

	return conn, nil
}

func TestWebSocketHTTP(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(wsEchoHandler), nil)

	conn, err := dialWebSocketViaProxy(env.proxyURL, env.httpURL+"/ws", nil)
	if err != nil {
		t.Fatalf("WebSocket dial: %v", err)
	}
	defer conn.Close()

	// Send a message
	msg := []byte("hello websocket")
	if err := writeMaskedWSFrame(conn, msg); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	// Read echo
	frame, err := readWSFrame(conn)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}

	if string(frame.payload) != "hello websocket" {
		t.Errorf("echo = %q, want %q", frame.payload, "hello websocket")
	}
}

func TestWebSocketHTTPS(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(wsEchoHandler), nil)

	host, _, _ := net.SplitHostPort(env.httpsHost())
	tlsConfig := &tls.Config{RootCAs: env.caPool, ServerName: host}
	conn, err := dialWebSocketViaProxy(env.proxyURL, "wss://"+env.httpsHost()+"/ws", tlsConfig)
	if err != nil {
		t.Fatalf("WebSocket dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello secure websocket")
	if err := writeMaskedWSFrame(conn, msg); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	frame, err := readWSFrame(conn)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}

	if string(frame.payload) != "hello secure websocket" {
		t.Errorf("echo = %q, want %q", frame.payload, "hello secure websocket")
	}
}
