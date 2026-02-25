package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

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

func TestElementHidingInjectsCSS(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")
	rs.AddLine("##.tracking-pixel")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test</title></head><body><div class="ad-banner">Ad</div></body></html>`))
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

	// Should contain injected style tag
	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("response should contain <style> tag, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".ad-banner") {
		t.Errorf("response should contain .ad-banner selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".tracking-pixel") {
		t.Errorf("response should contain .tracking-pixel selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "display: none !important") {
		t.Errorf("response should contain 'display: none !important', got:\n%s", bodyStr)
	}

	// Original content should still be present
	if !strings.Contains(bodyStr, "<title>Test</title>") {
		t.Errorf("original content should be preserved, got:\n%s", bodyStr)
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

func TestElementHidingDowngradesAcceptEncoding(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	var receivedAcceptEncoding string

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head></head><body>Hello</body></html>`))
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	// Send a request with Accept-Encoding that includes brotli
	req, _ := http.NewRequest("GET", env.httpURL+"/page.html", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// The proxy should downgrade Accept-Encoding to gzip only, because
	// the domain has element hiding rules and the proxy needs to decompress
	// the response to inject CSS
	if receivedAcceptEncoding != "gzip" {
		t.Errorf("upstream Accept-Encoding = %q, want %q", receivedAcceptEncoding, "gzip")
	}
}

func TestElementHidingNonGzipPassesThrough(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	// Simulate a server that responds with brotli-encoded HTML. The proxy
	// cannot decompress brotli, so it must pass the response through
	// unmodified rather than corrupting it.
	htmlBody := `<html><head></head><body>Hello</body></html>`
	fakeCompressed := []byte{0x1b, 0x2f, 0x00, 0xf0} // not real brotli, just binary garbage
	fakeCompressed = append(fakeCompressed, []byte(htmlBody)...)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "br")
		w.WriteHeader(http.StatusOK)
		w.Write(fakeCompressed)
	})

	env := startTestEnv(t, upstream, rs)
	client := env.httpClient(t)

	// Disable automatic decompression so we can inspect raw bytes
	client.Transport.(*http.Transport).DisableCompression = true

	resp, err := client.Get(env.httpURL + "/page.html")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The response must be passed through exactly as the upstream sent it.
	// Before the fix, the proxy would try to inject CSS into the compressed
	// bytes, corrupting the response.
	if len(body) != len(fakeCompressed) {
		t.Errorf("body length = %d, want %d (response was modified)", len(body), len(fakeCompressed))
	}
	if resp.Header.Get("Content-Encoding") != "br" {
		t.Errorf("Content-Encoding = %q, want %q", resp.Header.Get("Content-Encoding"), "br")
	}
}

func TestElementHidingHTTPS(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head></head><body>Hello</body></html>`))
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

	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("HTTPS response should also have CSS injected, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".ad-banner") {
		t.Errorf("HTTPS response should contain .ad-banner selector, got:\n%s", bodyStr)
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
