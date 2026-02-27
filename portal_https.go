package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
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
	if r.URL.Path == "/setup" {
		h.proxy.handleSetup(w, r)
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
	if serveStaticFile(w, r.URL.Path) {
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
func startPortalHTTPS(listenAddr string, host string, extraIPs []net.IP, certs *certCache, handler *portalHandler) {
	cert, err := certs.portalCert(host, extraIPs...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portal: failed to generate TLS cert: %v\n", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	server := &http.Server{
		Addr:      listenAddr,
		Handler:   handler,
		TLSConfig: tlsConfig,
		// Disable HTTP/2 — CONNECT proxy requires Hijack() which is
		// only supported on HTTP/1.1 connections.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	fmt.Fprintf(os.Stderr, "ublproxy proxy+portal listening on https://%s\n", listenAddr)

	if err := server.ListenAndServeTLS("", ""); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
