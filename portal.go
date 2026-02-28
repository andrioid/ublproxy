package main

import (
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"

	qrcode "github.com/skip2/go-qrcode"

	"ublproxy/internal/mobileconfig"
)

//go:embed static/portal.html
var portalHTML string

//go:embed static/rules.html
var rulesHTML string

//go:embed static/subscriptions.html
var subscriptionsHTML string

//go:embed static/activity.html
var activityHTML string

//go:embed static/users.html
var usersHTML string

//go:embed static/shared.css
var sharedCSS string

//go:embed static/shared.js
var sharedJS string

//go:embed static/setup.html
var setupHTML string

var setupTmpl = template.Must(template.New("setup").Parse(setupHTML))

// staticFiles maps /static/* paths to their embedded content and MIME type.
var staticFiles = map[string]struct {
	content     *string
	contentType string
}{
	"/static/shared.css": {&sharedCSS, "text/css; charset=utf-8"},
	"/static/shared.js":  {&sharedJS, "application/javascript; charset=utf-8"},
}

// serveStaticFile serves an embedded static file if it matches the path.
// Returns true if the file was served.
func serveStaticFile(w http.ResponseWriter, path string) bool {
	entry, ok := staticFiles[path]
	if !ok {
		return false
	}
	w.Header().Set("Content-Type", entry.contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(*entry.content))
	return true
}

// setupHandler serves the HTTP setup page, CA certificate, and mobile PAC
// file. It also accepts proxy traffic (CONNECT tunnels and HTTP forwarding)
// over plain HTTP for mobile devices that cannot use an HTTPS proxy.
// The API is not served here — it requires TLS on the HTTPS port.
type setupHandler struct {
	proxy        *proxyHandler
	caCert       *x509.Certificate
	caCertPEM    []byte
	portalOrigin string
	httpOrigin   string
}

func (s *setupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Proxy: CONNECT tunnels (mobile devices send HTTPS requests via HTTP proxy)
	if r.Method == http.MethodConnect {
		s.proxy.handleConnect(w, r)
		return
	}
	// Proxy: HTTP forward (absolute-URI requests through the proxy)
	if r.URL.Host != "" {
		s.proxy.handleHTTP(w, r)
		return
	}
	if r.URL.Path == "/ca.crt" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="ublproxy-ca.crt"`)
		w.WriteHeader(http.StatusOK)
		w.Write(s.caCertPEM)
		return
	}
	if r.URL.Path == "/ublproxy.mobileconfig" {
		pacURL := s.httpOrigin + "/mobile.pac"
		mobileconfig.Serve(w, s.caCert, pacURL)
		return
	}
	if r.URL.Path == "/proxy.pac" {
		s.handlePAC(w, r)
		return
	}
	if r.URL.Path == "/mobile.pac" {
		s.handleMobilePAC(w, r)
		return
	}
	if r.URL.Path == "/qr.png" {
		s.handleQR(w, r)
		return
	}
	if serveStaticFile(w, r.URL.Path) {
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/setup" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		setupTmpl.Execute(w, setupData{PortalURL: s.portalOrigin, HttpOrigin: s.httpOrigin})
		return
	}
	http.NotFound(w, r)
}

type pacData struct {
	ProxyDirective string // "HTTPS" for desktop, "PROXY" for mobile
	ProxyHost      string // e.g. "myhost:9443"
}

// handlePAC serves a Proxy Auto-Configuration file that directs browsers
// to use the ublproxy HTTPS proxy for all non-local traffic.
func (s *setupHandler) handlePAC(w http.ResponseWriter, r *http.Request) {
	parsed, err := url.Parse(s.portalOrigin)
	if err != nil {
		http.Error(w, "misconfigured portal origin", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	pacTmpl.Execute(w, pacData{ProxyDirective: "HTTPS", ProxyHost: parsed.Host})
}

type setupData struct {
	PortalURL   string
	HttpOrigin  string
	Transparent bool
}

// handleSetupVerify responds to /api/setup/verify on the HTTPS portal.
// If the fetch() from the setup wizard succeeds, the CA cert is trusted
// (the TLS handshake with the proxy's self-signed portal cert worked).
// The setup wizard on :8080 calls this cross-origin to check setup status.
func handleSetupVerify(w http.ResponseWriter, r *http.Request, httpOrigin string) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = httpOrigin
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Vary", "Origin")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{
		"ca_trusted": true,
	})
}

// pacTmpl is the single PAC template used by both desktop and mobile.
// Desktop uses ProxyDirective "HTTPS host:port", mobile uses "PROXY host:port"
// because iOS/Android do not support the HTTPS PAC proxy type.
var pacTmpl = template.Must(template.New("pac").Parse(`function FindProxyForURL(url, host) {
  if (isPlainHostName(host) ||
      host === "localhost" || host === "127.0.0.1" || host === "::1") {
    return "DIRECT";
  }
  // Private/reserved networks — no reason to proxy local traffic.
  if (isInNet(host, "10.0.0.0", "255.0.0.0") ||
      isInNet(host, "172.16.0.0", "255.240.0.0") ||
      isInNet(host, "192.168.0.0", "255.255.0.0") ||
      isInNet(host, "169.254.0.0", "255.255.0.0") ||
      shExpMatch(host, "*.local")) {
    return "DIRECT";
  }
  // Captive portal / connectivity checks must bypass the proxy
  // so the OS can verify internet access after wifi connects.
  if (host === "captive.apple.com" ||
      host === "connectivitycheck.gstatic.com" ||
      host === "connectivitycheck.android.com" ||
      host === "clients3.google.com" ||
      host === "www.msftconnecttest.com" ||
      host === "dns.msftncsi.com" ||
      host === "detectportal.firefox.com") {
    return "DIRECT";
  }
  return "{{.ProxyDirective}} {{.ProxyHost}}";
}
`))

func (s *setupHandler) handleMobilePAC(w http.ResponseWriter, r *http.Request) {
	parsed, err := url.Parse(s.httpOrigin)
	if err != nil {
		http.Error(w, "misconfigured http origin", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	pacTmpl.Execute(w, pacData{ProxyDirective: "PROXY", ProxyHost: parsed.Host})
}

func (s *setupHandler) handleQR(w http.ResponseWriter, r *http.Request) {
	png, err := qrcode.Encode(s.httpOrigin, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

// handlePortal routes direct requests on the proxy listener (used by
// proxyHandler.ServeHTTP when r.URL.Host is empty). In production the
// proxy runs on the HTTPS port and direct requests go through
// portalHandler instead, but this path is still exercised by tests
// that create an httptest.NewServer with proxyHandler.
func (p *proxyHandler) handlePortal(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ca.crt" {
		p.handlePortalCACert(w, r)
		return
	}
	if r.URL.Path == "/ublproxy.mobileconfig" {
		p.handleMobileconfig(w, r)
		return
	}
	if r.URL.Path == "/proxy.pac" {
		p.handlePAC(w, r)
		return
	}
	if r.URL.Path == "/mobile.pac" {
		p.handleMobilePAC(w, r)
		return
	}
	if r.URL.Path == "/qr.png" {
		p.handleQR(w, r)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/setup" {
		p.handleSetup(w, r)
		return
	}
	http.NotFound(w, r)
}

func (p *proxyHandler) handlePAC(w http.ResponseWriter, r *http.Request) {
	parsed, err := url.Parse(p.portalOrigin)
	if err != nil {
		http.Error(w, "misconfigured portal origin", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	pacTmpl.Execute(w, pacData{ProxyDirective: "HTTPS", ProxyHost: parsed.Host})
}

func (p *proxyHandler) handleQR(w http.ResponseWriter, r *http.Request) {
	png, err := qrcode.Encode(p.httpOrigin, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

func (p *proxyHandler) handleMobilePAC(w http.ResponseWriter, r *http.Request) {
	parsed, err := url.Parse(p.httpOrigin)
	if err != nil {
		http.Error(w, "misconfigured http origin", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	pacTmpl.Execute(w, pacData{ProxyDirective: "PROXY", ProxyHost: parsed.Host})
}

func serveHTML(w http.ResponseWriter, content string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))
}

func (p *proxyHandler) handlePortalIndex(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, portalHTML)
}

func (p *proxyHandler) handlePortalRules(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, rulesHTML)
}

func (p *proxyHandler) handlePortalSubscriptions(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, subscriptionsHTML)
}

func (p *proxyHandler) handlePortalActivity(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, activityHTML)
}

func (p *proxyHandler) handlePortalUsers(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, usersHTML)
}

func (p *proxyHandler) handleSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	setupTmpl.Execute(w, setupData{PortalURL: p.portalOrigin, HttpOrigin: p.httpOrigin})
}

func (p *proxyHandler) handleMobileconfig(w http.ResponseWriter, r *http.Request) {
	pacURL := p.httpOrigin + "/mobile.pac"
	mobileconfig.Serve(w, p.certs.CACert, pacURL)
}

func (p *proxyHandler) handlePortalCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ublproxy-ca.crt"`)
	w.WriteHeader(http.StatusOK)
	w.Write(p.caCertPEM)
}
