package main

import (
	"net/http"

	"ublproxy/pkg/blocklist"
)

type proxyHandler struct {
	certs     *certCache
	caCertPEM []byte
	rules     *blocklist.RuleSet
	transport *http.Transport
}

func newProxyHandler(certs *certCache, caCertPEM []byte, rules *blocklist.RuleSet) *proxyHandler {
	return &proxyHandler{
		certs:     certs,
		caCertPEM: caCertPEM,
		rules:     rules,
		transport: &http.Transport{},
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
