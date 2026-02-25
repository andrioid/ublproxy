package main

import (
	"crypto/tls"
	"net/http"
)

type proxyHandler struct {
	certs     *certCache
	caCertPEM []byte
	transport *http.Transport
}

func newProxyHandler(certs *certCache, caCertPEM []byte) *proxyHandler {
	return &proxyHandler{
		certs:     certs,
		caCertPEM: caCertPEM,
		transport: &http.Transport{
			// Skip verification when connecting to upstream servers since
			// we are acting as a proxy, not validating end-server identity
			// for the user. The user's trust is in our CA certificate.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// Direct request to the proxy itself, not a proxy request
	if r.URL.Host == "" {
		p.handlePortal(w, r)
		return
	}
	p.handleHTTP(w, r)
}
