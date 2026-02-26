package main

import (
	_ "embed"
	"net/http"
)

//go:embed static/portal.html
var portalHTML string

func (p *proxyHandler) handlePortal(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ca.crt" {
		p.handlePortalCACert(w, r)
		return
	}
	if r.URL.Path == "/" {
		p.handlePortalIndex(w, r)
		return
	}
	// Route API requests to the API handler (works on localhost where
	// HTTPS isn't required for the rule management endpoints)
	if p.api != nil && len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
		p.api.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func (p *proxyHandler) handlePortalIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(portalHTML))
}

func (p *proxyHandler) handlePortalCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ublproxy-ca.crt"`)
	w.WriteHeader(http.StatusOK)
	w.Write(p.caCertPEM)
}
