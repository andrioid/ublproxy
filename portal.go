package main

import (
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
)

//go:embed static/portal.html
var portalHTML string

//go:embed static/setup.html
var setupHTML string

var setupTmpl = template.Must(template.New("setup").Parse(setupHTML))

// setupHandler serves the HTTP-only setup page and CA certificate.
// No proxy, no API — those require TLS on the HTTPS port.
type setupHandler struct {
	caCertPEM    []byte
	portalOrigin string
}

func (s *setupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ca.crt" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="ublproxy-ca.crt"`)
		w.WriteHeader(http.StatusOK)
		w.Write(s.caCertPEM)
		return
	}
	if r.URL.Path == "/proxy.pac" {
		s.handlePAC(w, r)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/setup" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		setupTmpl.Execute(w, struct{ PortalURL string }{s.portalOrigin})
		return
	}
	http.NotFound(w, r)
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
	pacTmpl.Execute(w, struct{ ProxyHost string }{parsed.Host})
}

var pacTmpl = template.Must(template.New("pac").Parse(`function FindProxyForURL(url, host) {
  if (isPlainHostName(host) ||
      host === "localhost" || host === "127.0.0.1" || host === "::1") {
    return "DIRECT";
  }
  return "HTTPS {{.ProxyHost}}";
}
`))

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
	if r.URL.Path == "/proxy.pac" {
		p.handlePAC(w, r)
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
	pacTmpl.Execute(w, struct{ ProxyHost string }{parsed.Host})
}

func (p *proxyHandler) handlePortalIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(portalHTML))
}

func (p *proxyHandler) handleSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	setupTmpl.Execute(w, struct{ PortalURL string }{p.portalOrigin})
}

func (p *proxyHandler) handlePortalCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ublproxy-ca.crt"`)
	w.WriteHeader(http.StatusOK)
	w.Write(p.caCertPEM)
}
