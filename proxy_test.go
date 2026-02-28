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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"ublproxy/internal/blocklist"
	"ublproxy/internal/ca"
	"ublproxy/internal/store"
)

// testEnv holds everything needed to run a proxy e2e test.
type testEnv struct {
	proxyURL     string
	httpURL      string
	httpsURL     string
	caPool       *x509.CertPool
	upstreamPool *x509.CertPool
	handler      *proxyHandler
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
		proxyURL:     proxyServer.URL,
		httpURL:      httpServer.URL,
		httpsURL:     httpsServer.URL,
		caPool:       caPool,
		upstreamPool: upstreamCAPool,
		handler:      handler,
	}
}

// httpsHost returns the host:port of the HTTPS upstream server.
func (e *testEnv) httpsHost() string {
	u, _ := url.Parse(e.httpsURL)
	return u.Host
}

// httpClient returns an *http.Client configured to route through the proxy.
// For HTTPS requests, it trusts the test CA (MITM certs).
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

// passthroughClient returns an *http.Client configured to route through the
// proxy but trusting the upstream server's TLS cert (not the proxy CA).
// Used for testing passthrough tunnels where no MITM occurs.
func (e *testEnv) passthroughClient(t *testing.T) *http.Client {
	t.Helper()

	proxyURL, err := url.Parse(e.proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: e.upstreamPool,
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

func TestHTTPSHTMLRewriting(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")
	rs.AddLine("##.ad-banner")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head>` +
			`<script src="https://ads.tracker.com/serve.js"></script>` +
			`</head><body>` +
			`<div class="ad-banner">Ad</div>` +
			`<p>Content</p>` +
			`</body></html>`))
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

	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked script") {
		t.Errorf("blocked script should be stripped over HTTPS, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("element hiding CSS should be injected over HTTPS, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".ad-banner") {
		t.Errorf("CSS should contain .ad-banner selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("page content should be preserved, got:\n%s", bodyStr)
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

func TestProxyPAC(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	// Set portalOrigin so the PAC template can extract host:port
	env.handler.portalOrigin = "https://myhost:9443"

	resp, err := http.Get(env.proxyURL + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-ns-proxy-autoconfig" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/x-ns-proxy-autoconfig")
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "FindProxyForURL") {
		t.Error("PAC body does not contain FindProxyForURL function")
	}
	if !strings.Contains(bodyStr, "HTTPS myhost:9443") {
		t.Errorf("PAC body does not contain expected proxy directive, got:\n%s", bodyStr)
	}
}

func TestPACBypassesPrivateNetworks(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	env.handler.portalOrigin = "https://myhost.local:9443"
	env.handler.httpOrigin = "http://192.168.1.100:8080"

	// Desktop PAC should bypass private networks
	resp, err := http.Get(env.proxyURL + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	pac := string(body)

	privateRanges := []struct {
		pattern string
		desc    string
	}{
		{`isInNet(host, "10.0.0.0", "255.0.0.0")`, "10.0.0.0/8"},
		{`isInNet(host, "172.16.0.0", "255.240.0.0")`, "172.16.0.0/12"},
		{`isInNet(host, "192.168.0.0", "255.255.0.0")`, "192.168.0.0/16"},
		{`isInNet(host, "169.254.0.0", "255.255.0.0")`, "169.254.0.0/16"},
		{`*.local`, ".local mDNS"},
	}
	for _, r := range privateRanges {
		if !strings.Contains(pac, r.pattern) {
			t.Errorf("desktop PAC missing bypass for %s (%s)", r.desc, r.pattern)
		}
	}

	// Mobile PAC should also bypass private networks
	resp, err = http.Get(env.proxyURL + "/mobile.pac")
	if err != nil {
		t.Fatalf("GET /mobile.pac: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	mobilePac := string(body)

	for _, r := range privateRanges {
		if !strings.Contains(mobilePac, r.pattern) {
			t.Errorf("mobile PAC missing bypass for %s (%s)", r.desc, r.pattern)
		}
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

func TestElementHidingCSSInjection(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")
	rs.AddLine("##.tracking-pixel")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head><title>Test</title></head><body>` +
			`<div class="ad-banner">Ad content</div>` +
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

	// CSS should be injected to hide matching elements
	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("should contain injected style tag, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".ad-banner") {
		t.Errorf("CSS should contain .ad-banner selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".tracking-pixel") {
		t.Errorf("CSS should contain .tracking-pixel selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "display: none !important") {
		t.Errorf("CSS should use display:none, got:\n%s", bodyStr)
	}

	// Content elements should remain in DOM (hidden by CSS, not stripped)
	if !strings.Contains(bodyStr, "Ad content") {
		t.Errorf("ad element should remain in DOM (CSS hides it), got:\n%s", bodyStr)
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

	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("brotli HTML should have CSS injected, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".ad-banner") {
		t.Errorf("CSS should contain .ad-banner selector, got:\n%s", bodyStr)
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

	// Element hiding is CSS-only — container stays in DOM but is hidden
	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("should contain CSS injection, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".ad-container") {
		t.Errorf("CSS should contain .ad-container selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Keep this") {
		t.Errorf("non-ad content should be preserved, got:\n%s", bodyStr)
	}
}

func TestElementHidingAllSelectorsCSS(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##div .ad-child") // complex selector
	rs.AddLine("##.ad-banner")    // simple selector

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

	// Both simple and complex selectors should be in CSS
	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("should contain injected style tag, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".ad-banner") {
		t.Errorf("CSS should contain simple selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "div .ad-child") {
		t.Errorf("CSS should contain complex selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "display: none !important") {
		t.Errorf("CSS should use display:none, got:\n%s", bodyStr)
	}

	// Content elements stay in DOM (CSS hides them)
	if !strings.Contains(bodyStr, `class="ad-banner"`) {
		t.Errorf("ad element should remain in DOM, got:\n%s", bodyStr)
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

	// ID selector should be in CSS
	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("should contain CSS injection, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "#sidebar-ad") {
		t.Errorf("CSS should contain #sidebar-ad selector, got:\n%s", bodyStr)
	}
	// Element stays in DOM, hidden by CSS
	if !strings.Contains(bodyStr, "sponsor.html") {
		t.Errorf("ad element should remain in DOM (hidden by CSS), got:\n%s", bodyStr)
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

	// Attribute selector should be in CSS
	if !strings.Contains(bodyStr, `div[class*="advertisement"]`) {
		t.Errorf("CSS should contain attribute selector, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "display: none !important") {
		t.Errorf("CSS should use display:none, got:\n%s", bodyStr)
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

// --- Script stripping tests ---

func TestScriptStrippingBlockedHost(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head>` +
			`<script src="https://ads.tracker.com/serve.js"></script>` +
			`<script src="/local/app.js"></script>` +
			`</head><body><p>Content</p></body></html>`))
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

	// Blocked script should be stripped with a comment
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked script") {
		t.Errorf("blocked script should have replacement comment, got:\n%s", bodyStr)
	}
	// The <script> element itself should be gone (no opening tag)
	if strings.Contains(bodyStr, `<script src="https://ads.tracker.com`) {
		t.Errorf("blocked script element should be removed, got:\n%s", bodyStr)
	}

	// Non-blocked script should be preserved
	if !strings.Contains(bodyStr, "app.js") {
		t.Errorf("non-blocked script should be preserved, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("page content should be preserved, got:\n%s", bodyStr)
	}
}

func TestScriptStrippingProtocolRelative(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head>` +
			`<script src="//ads.tracker.com/ad.js"></script>` +
			`</head><body><p>Content</p></body></html>`))
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

	// Protocol-relative src should be resolved and blocked
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked script") {
		t.Errorf("protocol-relative blocked script should be stripped, got:\n%s", bodyStr)
	}
	// The <script> element itself should be gone
	if strings.Contains(bodyStr, `<script src="//ads.tracker.com`) {
		t.Errorf("blocked script element should be removed, got:\n%s", bodyStr)
	}
}

func TestScriptStrippingInlinePreserved(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head>` +
			`<script>var x = 1;</script>` +
			`</head><body><p>Content</p></body></html>`))
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

	// Inline scripts (no src) should not be stripped
	if !strings.Contains(bodyStr, "var x = 1") {
		t.Errorf("inline script should be preserved, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, "ublproxy") {
		t.Errorf("no replacement comment should appear for inline scripts, got:\n%s", bodyStr)
	}
}

func TestScriptStrippingWithElementHiding(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")
	rs.AddLine("##.ad-banner")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head>` +
			`<script src="https://ads.tracker.com/ad.js"></script>` +
			`</head><body>` +
			`<div class="ad-banner">Ad</div>` +
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

	// Script should be stripped via URL blocking (src-based)
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked script") {
		t.Errorf("blocked script should be stripped, got:\n%s", bodyStr)
	}

	// Element hiding should be CSS-only
	if !strings.Contains(bodyStr, "<style>") {
		t.Errorf("should contain CSS injection for element hiding, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, ".ad-banner") {
		t.Errorf("CSS should contain .ad-banner selector, got:\n%s", bodyStr)
	}

	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("page content should be preserved, got:\n%s", bodyStr)
	}
}

func TestScriptStrippingURLPattern(t *testing.T) {
	// Test that URL pattern rules (not just hostname rules) also strip scripts
	rs := blocklist.NewRuleSet()
	rs.AddLine("||example.com/ads/*")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head>` +
			`<script src="https://example.com/ads/tracker.js"></script>` +
			`<script src="https://example.com/lib/jquery.js"></script>` +
			`</head><body><p>Content</p></body></html>`))
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

	// Path-matching rule should block the ads script
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked script") {
		t.Errorf("URL pattern should strip matching script, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, `<script src="https://example.com/ads/`) {
		t.Errorf("blocked script element should be removed, got:\n%s", bodyStr)
	}

	// Non-matching path should be preserved
	if !strings.Contains(bodyStr, "jquery.js") {
		t.Errorf("non-matching script should be preserved, got:\n%s", bodyStr)
	}
}

// --- Iframe stripping tests ---

func TestIframeStrippingBlockedHost(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<iframe src="https://ads.tracker.com/ad-frame"></iframe>` +
			`<iframe src="https://safe.example.com/embed"></iframe>` +
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

	// Blocked iframe should be stripped
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked iframe") {
		t.Errorf("blocked iframe should have replacement comment, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, `<iframe src="https://ads.tracker.com`) {
		t.Errorf("blocked iframe element should be removed, got:\n%s", bodyStr)
	}

	// Non-blocked iframe should be preserved
	if !strings.Contains(bodyStr, "safe.example.com/embed") {
		t.Errorf("non-blocked iframe should be preserved, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("page content should be preserved, got:\n%s", bodyStr)
	}
}

func TestIframeStrippingProtocolRelative(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<iframe src="//ads.tracker.com/embed"></iframe>` +
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

	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked iframe") {
		t.Errorf("protocol-relative blocked iframe should be stripped, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, `<iframe src="//ads.tracker.com`) {
		t.Errorf("blocked iframe element should be removed, got:\n%s", bodyStr)
	}
}

// --- Object and embed stripping tests ---

func TestObjectStrippingBlockedHost(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<object data="https://ads.tracker.com/ad.swf" type="application/x-shockwave-flash"></object>` +
			`<object data="https://safe.example.com/video.swf" type="application/x-shockwave-flash"></object>` +
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

	// Blocked object should be stripped
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked object") {
		t.Errorf("blocked object should have replacement comment, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, `<object data="https://ads.tracker.com`) {
		t.Errorf("blocked object element should be removed, got:\n%s", bodyStr)
	}

	// Non-blocked object should be preserved
	if !strings.Contains(bodyStr, "safe.example.com/video.swf") {
		t.Errorf("non-blocked object should be preserved, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("page content should be preserved, got:\n%s", bodyStr)
	}
}

func TestObjectStrippingNestedContent(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<object data="https://ads.tracker.com/ad.swf">` +
			`<param name="movie" value="ad.swf">` +
			`<p>Fallback content</p>` +
			`</object>` +
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

	// Nested content inside blocked object should also be stripped
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked object") {
		t.Errorf("blocked object should have replacement comment, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, "Fallback content") {
		t.Errorf("nested content should be stripped with the object, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("page content should be preserved, got:\n%s", bodyStr)
	}
}

func TestEmbedStrippingBlockedHost(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<embed src="https://ads.tracker.com/ad.swf" type="application/x-shockwave-flash">` +
			`<embed src="https://safe.example.com/video.swf" type="application/x-shockwave-flash">` +
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

	// Blocked embed should be stripped
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked embed") {
		t.Errorf("blocked embed should have replacement comment, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, `<embed src="https://ads.tracker.com`) {
		t.Errorf("blocked embed element should be removed, got:\n%s", bodyStr)
	}

	// Non-blocked embed should be preserved
	if !strings.Contains(bodyStr, "safe.example.com/video.swf") {
		t.Errorf("non-blocked embed should be preserved, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("page content should be preserved, got:\n%s", bodyStr)
	}
}

func TestEmbedStrippingIsVoidElement(t *testing.T) {
	// Embed is a void element — no closing tag. Verify the tokenizer
	// handles it correctly without trying to skipUntilClose.
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>` +
			`<embed src="https://ads.tracker.com/ad.swf">` +
			`<p>After embed</p>` +
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

	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked embed") {
		t.Errorf("blocked embed should be stripped, got:\n%s", bodyStr)
	}
	// Content after the void embed must be preserved
	if !strings.Contains(bodyStr, "After embed") {
		t.Errorf("content after void embed should be preserved, got:\n%s", bodyStr)
	}
}

func TestAllBlockableElementsTogether(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.tracker.com^")

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><head>` +
			`<script src="https://ads.tracker.com/ad.js"></script>` +
			`</head><body>` +
			`<iframe src="https://ads.tracker.com/frame"></iframe>` +
			`<object data="https://ads.tracker.com/ad.swf"><param name="x" value="y"></object>` +
			`<embed src="https://ads.tracker.com/ad.swf">` +
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

	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked script") {
		t.Errorf("blocked script should be stripped, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked iframe") {
		t.Errorf("blocked iframe should be stripped, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked object") {
		t.Errorf("blocked object should be stripped, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "<!-- ublproxy: blocked embed") {
		t.Errorf("blocked embed should be stripped, got:\n%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Content") {
		t.Errorf("page content should be preserved, got:\n%s", bodyStr)
	}
}

// --- Hot-reload tests ---

func TestGetUserRulesLoadsFromDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reload.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create a credential and a rule in the database
	if err := db.SaveCredential("test-cred", []byte("test-pubkey")); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	if _, err := db.CreateRule("test-cred", "/ads/*", ""); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	caCert, caKey, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	handler := newProxyHandler(ca.NewCache(caCert, caKey), ca.EncodeCertPEM(caCert))
	handler.store = db

	// No user rules cached yet — getUserRules lazily loads them
	rules := handler.getUserRules("test-cred")
	if rules == nil {
		t.Fatal("getUserRules returned nil")
	}

	// The rule "/ads/*" should now be loaded
	ctx := blocklist.MatchContext{}
	if !rules.ShouldBlockRequest("http://example.com/ads/banner.gif", ctx) {
		t.Error("/ads/banner.gif should be blocked by user rules")
	}
	if rules.ShouldBlockRequest("http://example.com/page.html", ctx) {
		t.Error("/page.html should not be blocked")
	}

	// Invalidate and verify re-load works
	handler.invalidateUserRules("test-cred")
	rules2 := handler.getUserRules("test-cred")
	if rules2 == nil {
		t.Fatal("getUserRules returned nil after invalidation")
	}
	if !rules2.ShouldBlockRequest("http://example.com/ads/banner.gif", ctx) {
		t.Error("re-loaded rules should still block /ads/*")
	}
}

func TestReloadBaselineAndUserRulesSeparate(t *testing.T) {
	// Create a temporary blocklist file
	tmpDir := t.TempDir()
	blocklistPath := filepath.Join(tmpDir, "blocklist.txt")
	os.WriteFile(blocklistPath, []byte("||blocked-host.example.com^\n"), 0644)

	dbPath := filepath.Join(tmpDir, "reload.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Add a user rule
	if err := db.SaveCredential("cred1", []byte("pubkey1")); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	_, err = db.CreateRule("cred1", "##.user-ad", "")
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	caCert, caKey, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	handler := newProxyHandler(ca.NewCache(caCert, caKey), ca.EncodeCertPEM(caCert))
	handler.store = db
	handler.blocklistSources = []string{blocklistPath}

	// Reload baseline — should load static blocklist but NOT user rules
	handler.reloadBaseline()

	baseline := handler.getBaselineRules()
	if baseline == nil {
		t.Fatal("getBaselineRules() returned nil after reloadBaseline")
	}

	// Static blocklist rule should be in baseline
	if !baseline.IsHostBlocked("blocked-host.example.com") {
		t.Error("static blocklist hostname should be blocked in baseline")
	}

	// User element hiding rule should NOT be in baseline
	eh := baseline.ElementHidingForDomain("example.com")
	if eh != nil && eh.CSS != "" {
		t.Error("user element hiding rule should NOT be in baseline")
	}

	// User rules should be loadable separately
	userRules := handler.getUserRules("cred1")
	if userRules == nil {
		t.Fatal("getUserRules returned nil")
	}
	eh = userRules.ElementHidingForDomain("example.com")
	if eh == nil || eh.CSS == "" {
		t.Error("user element hiding rule should be loaded in user rules")
	}
}

func TestAPIRuleMutationTriggersReload(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "callback.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	sm := newSessionMap()
	api := newAPIHandler(db, testAPIConfig, sm)

	var reloadCount atomic.Int32
	api.onRulesChanged = func(credentialID string) {
		reloadCount.Add(1)
	}

	// Create a credential and session for authenticated requests
	if err := db.SaveCredential("test-cred-cb", []byte("test-pubkey-cb")); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	sess, err := db.CreateSession("test-cred-cb")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Create a rule — should trigger reload
	rec := doRequest(t, api, "POST", "/api/rules", createRuleRequest{Rule: "##.ad", Domain: "example.com"}, sess.Token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create rule: status %d, body: %s", rec.Code, rec.Body.String())
	}

	// The reload is async (go a.onRulesChanged()), give it a moment
	// But since we're in a test with a simple counter, it should complete quickly
	for i := 0; i < 100; i++ {
		if reloadCount.Load() >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if reloadCount.Load() < 1 {
		t.Error("onRulesChanged should have been called after create")
	}

	// Extract rule ID for delete/patch
	var created ruleResponse
	decodeJSON(t, rec, &created)

	// Patch rule — should trigger reload
	rec = doRequest(t, api, "PATCH", fmt.Sprintf("/api/rules/%d", created.ID), patchRuleRequest{Enabled: boolPtr(false)}, sess.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch rule: status %d, body: %s", rec.Code, rec.Body.String())
	}

	for i := 0; i < 100; i++ {
		if reloadCount.Load() >= 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if reloadCount.Load() < 2 {
		t.Error("onRulesChanged should have been called after patch")
	}

	// Delete rule — should trigger reload
	rec = doRequest(t, api, "DELETE", fmt.Sprintf("/api/rules/%d", created.ID), nil, sess.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete rule: status %d, body: %s", rec.Code, rec.Body.String())
	}

	for i := 0; i < 100; i++ {
		if reloadCount.Load() >= 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if reloadCount.Load() < 3 {
		t.Error("onRulesChanged should have been called after delete")
	}
}

func boolPtr(b bool) *bool { return &b }

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

func TestPassthroughTunnelForExceptedHost(t *testing.T) {
	var upstreamHit atomic.Bool

	rs := blocklist.NewRuleSet()
	// Block all subresources, but except the upstream host entirely
	rs.AddHostname("ads.example.com")
	rs.AddException("@@||127.0.0.1^")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit.Store(true)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("passthrough response"))
	}), rs)

	// Use passthroughClient which trusts the upstream cert directly.
	// If MITM were happening, this client would reject the proxy's MITM
	// cert because it doesn't trust the proxy CA.
	client := env.passthroughClient(t)

	resp, err := client.Get(env.httpsURL + "/secure-page")
	if err != nil {
		t.Fatalf("GET through passthrough tunnel: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "passthrough response" {
		t.Errorf("body = %q, want %q", body, "passthrough response")
	}
	if !upstreamHit.Load() {
		t.Error("upstream was not hit")
	}
}

func TestMITMClientFailsOnPassthroughTunnel(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddException("@@||127.0.0.1^")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rs)

	// The standard httpClient trusts only the proxy CA. For a passthrough
	// tunnel the client sees the upstream server's cert, not a MITM cert,
	// so this client should fail TLS verification.
	client := env.httpClient(t)
	_, err := client.Get(env.httpsURL + "/test")
	if err == nil {
		t.Error("expected TLS error from MITM client on passthrough tunnel, got nil")
	}
}

func TestNonExceptedHostStillMITMd(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// Exception only for a different domain, not the upstream host
	rs.AddException("@@||banking.example.com^")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mitm response"))
	}), rs)

	// Standard MITM client should work because the upstream host is not excepted
	client := env.httpClient(t)
	resp, err := client.Get(env.httpsURL + "/page")
	if err != nil {
		t.Fatalf("GET through MITM: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "mitm response" {
		t.Errorf("body = %q, want %q", body, "mitm response")
	}
}

func TestBlockedHostStillBlockedWithExceptions(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddHostname("127.0.0.1")
	// Exception for a different host should not affect the blocked one
	rs.AddException("@@||banking.example.com^")

	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rs)

	client := env.httpClient(t)
	_, err := client.Get(env.httpsURL + "/should-be-blocked")
	if err == nil {
		t.Error("expected error for blocked HTTPS host, got nil")
	}
}

func TestMobilePAC(t *testing.T) {
	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), nil)

	env.handler.httpOrigin = "http://192.168.1.100:8080"

	resp, err := http.Get(env.proxyURL + "/mobile.pac")
	if err != nil {
		t.Fatalf("GET /mobile.pac: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/x-ns-proxy-autoconfig" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/x-ns-proxy-autoconfig")
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "FindProxyForURL") {
		t.Error("mobile PAC body does not contain FindProxyForURL function")
	}
	if !strings.Contains(bodyStr, "PROXY 192.168.1.100:8080") {
		t.Errorf("mobile PAC body does not contain expected PROXY directive, got:\n%s", bodyStr)
	}
	if strings.Contains(bodyStr, "HTTPS") {
		t.Error("mobile PAC body should not contain HTTPS directive")
	}
}

func TestHTTPPortConnect(t *testing.T) {
	var receivedPath string
	env := startTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Write([]byte("hello from upstream"))
	}), nil)

	// The test proxy server uses httptest.NewServer (plain HTTP), which is
	// exactly the scenario we want: CONNECT over plain HTTP.
	proxyURL, _ := url.Parse(env.proxyURL)

	// Create an HTTP client that uses our plain-HTTP proxy for HTTPS requests
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: env.caPool,
			},
		},
	}

	resp, err := client.Get(env.httpsURL + "/test-path")
	if err != nil {
		t.Fatalf("GET through HTTP CONNECT: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if string(body) != "hello from upstream" {
		t.Errorf("body = %q, want %q", body, "hello from upstream")
	}
	if receivedPath != "/test-path" {
		t.Errorf("upstream received path = %q, want %q", receivedPath, "/test-path")
	}
}

func TestNoBootstrapInjectionOnInsecureProxy(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", sessionEntry{Token: "secret-token", CredentialID: "cred-1"})

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}

	htmlBody := `<html><head><title>Test</title></head><body><p>Hello</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	// With insecure=true (plain HTTP proxy), bootstrap script should NOT be injected
	modified, ok := p.applyElementHiding(resp, "example.com", "127.0.0.1", true)
	if ok {
		body := string(modified)
		if strings.Contains(body, "secret-token") {
			t.Error("session token must not be injected on insecure connections")
		}
		if strings.Contains(body, "<script>") {
			t.Error("bootstrap script must not be injected on insecure connections")
		}
	}

	// With insecure=false (HTTPS proxy), bootstrap script SHOULD be injected
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}
	modified2, ok2 := p.applyElementHiding(resp2, "example.com", "127.0.0.1", false)
	if !ok2 {
		t.Fatal("expected modification on secure connection")
	}
	body2 := string(modified2)
	if !strings.Contains(body2, "secret-token") {
		t.Error("session token should be injected on secure connections")
	}
}
