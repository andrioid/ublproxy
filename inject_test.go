package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"ublproxy/pkg/blocklist"
)

func TestBootstrapScriptTagWithSession(t *testing.T) {
	sm := newSessionMap()
	sm.Set("192.168.1.10", "test-token-abc")

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://192.168.1.1:8443",
	}

	tag := p.bootstrapScriptTag("192.168.1.10", "example.com")

	if !strings.Contains(tag, "<script>") {
		t.Error("should contain <script> tag")
	}
	if !strings.Contains(tag, "https://192.168.1.1:8443") {
		t.Error("should contain portal origin")
	}
	if !strings.Contains(tag, "test-token-abc") {
		t.Error("should contain session token")
	}
	if strings.Contains(tag, "__UBLPROXY_PORTAL__") {
		t.Error("should not contain template placeholder for portal")
	}
	if strings.Contains(tag, "__UBLPROXY_TOKEN__") {
		t.Error("should not contain template placeholder for token")
	}
	if strings.Contains(tag, "__UBLPROXY_HOST__") {
		t.Error("should not contain template placeholder for host")
	}
	if !strings.Contains(tag, "example.com") {
		t.Error("should contain the page host")
	}
}

func TestBootstrapScriptTagNoSession(t *testing.T) {
	sm := newSessionMap()

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://192.168.1.1:8443",
	}

	tag := p.bootstrapScriptTag("192.168.1.10", "example.com")
	if tag != "" {
		t.Errorf("should be empty for unknown IP, got: %s", tag)
	}
}

func TestBootstrapScriptTagNoSessionMap(t *testing.T) {
	p := &proxyHandler{}
	tag := p.bootstrapScriptTag("192.168.1.10", "example.com")
	if tag != "" {
		t.Errorf("should be empty with nil session map, got: %s", tag)
	}
}

func TestScriptInjectionInHTML(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", "my-token")

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

	modified, ok := p.applyElementHiding(resp, "example.com", "127.0.0.1")
	if !ok {
		t.Fatal("expected modification")
	}

	body := string(modified)
	if !strings.Contains(body, "<script>") {
		t.Error("should contain injected script tag")
	}
	if !strings.Contains(body, "my-token") {
		t.Error("should contain the session token")
	}
	if !strings.Contains(body, "https://127.0.0.1:8443") {
		t.Error("should contain the portal origin")
	}
	// Script should be before </body>
	scriptIdx := strings.Index(body, "<script>")
	bodyCloseIdx := strings.Index(body, "</body>")
	if scriptIdx >= bodyCloseIdx {
		t.Error("script should be injected before </body>")
	}
}

func TestNoScriptInjectionWithoutSession(t *testing.T) {
	sm := newSessionMap()

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}

	htmlBody := `<html><body><p>Hello</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	// No rules and no session -> no modification
	_, ok := p.applyElementHiding(resp, "example.com", "127.0.0.1")
	if ok {
		t.Error("should not modify HTML when there's no session and no rules")
	}
}

func TestNoScriptInjectionForNonHTML(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", "my-token")

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"data": true}`)),
	}

	_, ok := p.applyElementHiding(resp, "example.com", "127.0.0.1")
	if ok {
		t.Error("should not modify non-HTML responses")
	}
}

func TestScriptInjectionWithGzip(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", "gzip-token")

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}

	htmlBody := `<html><body><p>Compressed</p></body></html>`
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(htmlBody))
	gz.Close()

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":     []string{"text/html"},
			"Content-Encoding": []string{"gzip"},
		},
		Body: io.NopCloser(&buf),
	}

	modified, ok := p.applyElementHiding(resp, "example.com", "127.0.0.1")
	if !ok {
		t.Fatal("expected modification for gzipped HTML")
	}

	body := string(modified)
	if !strings.Contains(body, "gzip-token") {
		t.Error("should contain the session token in decompressed output")
	}
}

func TestScriptInjectionWithRules(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", "rules-token")

	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}
	p.rules.Store(rs)

	htmlBody := `<html><head></head><body><div class="ad-banner">Ad</div><p>Content</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, ok := p.applyElementHiding(resp, "example.com", "127.0.0.1")
	if !ok {
		t.Fatal("expected modification")
	}

	body := string(modified)

	// Element hiding via CSS and script injection should both work
	if !strings.Contains(body, "<style>") {
		t.Error("should contain CSS injection")
	}
	if !strings.Contains(body, ".ad-banner") {
		t.Error("CSS should contain the selector")
	}
	if !strings.Contains(body, "display: none !important") {
		t.Error("CSS should use display:none")
	}
	if !strings.Contains(body, "rules-token") {
		t.Error("should contain the session token")
	}
	// Content element should NOT be stripped from DOM (CSS-only hiding)
	if !strings.Contains(body, `class="ad-banner"`) {
		t.Error("content element should remain in DOM (hidden by CSS, not stripped)")
	}
}

func TestSessionMap(t *testing.T) {
	sm := newSessionMap()

	// Get from empty map
	if got := sm.Get("1.2.3.4"); got != "" {
		t.Errorf("Get empty = %q, want empty", got)
	}

	// Set and get
	sm.Set("1.2.3.4", "token-a")
	if got := sm.Get("1.2.3.4"); got != "token-a" {
		t.Errorf("Get = %q, want %q", got, "token-a")
	}

	// Overwrite
	sm.Set("1.2.3.4", "token-b")
	if got := sm.Get("1.2.3.4"); got != "token-b" {
		t.Errorf("Get after overwrite = %q, want %q", got, "token-b")
	}

	// Different IP
	if got := sm.Get("5.6.7.8"); got != "" {
		t.Errorf("Get different IP = %q, want empty", got)
	}

	// Delete
	sm.Delete("1.2.3.4")
	if got := sm.Get("1.2.3.4"); got != "" {
		t.Errorf("Get after delete = %q, want empty", got)
	}
}
