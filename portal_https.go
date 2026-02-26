package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
)

// portalServer is the HTTPS server for the portal. It serves the dashboard,
// WebAuthn auth endpoints, and the rule management API. Separate from the
// HTTP proxy so that WebAuthn works (requires a secure context).
type portalServer struct {
	handler *portalHandler
	addr    string
}

// portalHandler routes requests on the HTTPS portal.
type portalHandler struct {
	proxy *proxyHandler
	api   *apiHandler
}

func (h *portalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ca.crt" {
		h.proxy.handlePortalCACert(w, r)
		return
	}
	if r.URL.Path == "/" {
		h.proxy.handlePortalIndex(w, r)
		return
	}
	if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
		h.api.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

// startPortalHTTPS starts the HTTPS portal server using a TLS certificate
// signed by the proxy's CA. The cert is generated for the listen address
// so clients that trust the CA can connect without warnings.
func startPortalHTTPS(listenAddr string, host string, certs *certCache, handler *portalHandler) {
	// Generate a TLS cert for the portal host, signed by our CA
	cert, err := certs.getCert(host)
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
	}

	fmt.Fprintf(os.Stderr, "ublproxy portal listening on https://%s\n", listenAddr)

	// TLS certs are already in the config, so pass empty strings
	if err := server.ListenAndServeTLS("", ""); err != nil {
		fmt.Fprintf(os.Stderr, "portal server error: %v\n", err)
		os.Exit(1)
	}
}
