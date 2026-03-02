package main

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"

	"ublproxy/internal/ca"
)

// portalHandler routes requests on the HTTPS port. It serves the proxy
// (CONNECT tunnels and HTTP forwarding), the management portal, and
// the API. All traffic on this listener is TLS-encrypted.
type portalHandler struct {
	proxy *proxyHandler
	api   *apiHandler
}

func (h *portalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Proxy: CONNECT tunnels (browser requests HTTPS via the proxy)
	if r.Method == http.MethodConnect {
		h.proxy.handleConnect(w, r)
		return
	}
	// Proxy: HTTP forward (absolute-URI requests through the proxy)
	if r.URL.Host != "" {
		h.proxy.handleHTTP(w, r)
		return
	}
	// Direct requests to this server (portal, API, setup, CA cert, PAC, static)
	if r.URL.Path == "/ca.crt" {
		h.proxy.handlePortalCACert(w, r)
		return
	}
	if r.URL.Path == "/proxy.pac" {
		h.proxy.handlePAC(w, r)
		return
	}
	if r.URL.Path == "/mobile.pac" {
		h.proxy.handleMobilePAC(w, r)
		return
	}
	if r.URL.Path == "/qr.png" {
		h.proxy.handleQR(w, r)
		return
	}
	if r.URL.Path == "/setup" {
		h.proxy.handleSetup(w, r)
		return
	}
	if r.URL.Path == "/ublproxy.mobileconfig" {
		h.proxy.handleMobileconfig(w, r)
		return
	}
	if r.URL.Path == "/" {
		h.proxy.handlePortalIndex(w, r)
		return
	}
	if r.URL.Path == "/rules" {
		h.proxy.handlePortalRules(w, r)
		return
	}
	if r.URL.Path == "/subscriptions" {
		h.proxy.handlePortalSubscriptions(w, r)
		return
	}
	if r.URL.Path == "/activity" {
		h.proxy.handlePortalActivity(w, r)
		return
	}
	if r.URL.Path == "/users" {
		h.proxy.handlePortalUsers(w, r)
		return
	}
	if serveStaticFile(w, r.URL.Path) {
		return
	}
	if r.URL.Path == "/api/setup/verify" {
		handleSetupVerify(w, r, h.proxy.httpOrigin)
		return
	}
	if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
		h.api.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

// startPortalHTTPS starts the HTTPS server that handles both proxy
// traffic and the management portal. HTTP/2 is disabled because
// CONNECT tunnels require Hijack which only works with HTTP/1.1.
func startPortalHTTPS(listenAddr string, host string, extraIPs []net.IP, certs *ca.Cache, handler *portalHandler) {
	certs.SetPortalParams(host, extraIPs)

	tlsConfig := &tls.Config{
		// Dynamic cert lookup so the portal cert is regenerated when it
		// expires (24h). Without this the static cert baked at startup
		// would cause TLS errors after 24h of uptime.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certs.GetPortalCert()
		},
	}

	server := &http.Server{
		Addr:      listenAddr,
		Handler:   handler,
		TLSConfig: tlsConfig,
		// Disable HTTP/2 — CONNECT proxy requires Hijack() which is
		// only supported on HTTP/1.1 connections.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	slog.Info("ublproxy proxy+portal listening", "url", "https://"+listenAddr)

	if err := server.ListenAndServeTLS("", ""); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}
