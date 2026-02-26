package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ublproxy/pkg/blocklist"
	"ublproxy/pkg/store"
)

type proxyHandler struct {
	certs        *certCache
	caCertPEM    []byte
	rules        atomic.Pointer[blocklist.RuleSet]
	transport    *http.Transport
	store        *store.Store
	api          *apiHandler
	sessions     *sessionMap
	portalOrigin string

	// blocklistSources are the static blocklist file paths/URLs loaded at
	// startup. Needed to rebuild the RuleSet when user rules change.
	blocklistSources []string

	// reloadMu serializes rule reloads to prevent concurrent rebuilds.
	reloadMu sync.Mutex
}

func newProxyHandler(certs *certCache, caCertPEM []byte, rules *blocklist.RuleSet) *proxyHandler {
	p := &proxyHandler{
		certs:     certs,
		caCertPEM: caCertPEM,
		// Force HTTP/1.1 upstream. Go's default HTTP/2 support causes hangs
		// with certain Cloudflare hosts in a MITM proxy scenario.
		transport: &http.Transport{
			TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
	}
	if rules != nil {
		p.rules.Store(rules)
	}
	return p
}

// getRules returns the current RuleSet, or nil if none is loaded.
func (p *proxyHandler) getRules() *blocklist.RuleSet {
	return p.rules.Load()
}

// reloadRules rebuilds the in-memory RuleSet from static blocklists and
// user-created rules in the database. Called after any rule mutation.
func (p *proxyHandler) reloadRules() {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	rs := blocklist.NewRuleSet()

	// Reload static blocklists
	for _, src := range p.blocklistSources {
		var err error
		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
			err = rs.LoadURL(src)
		} else {
			err = rs.LoadFile(src)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "reload: failed to load blocklist %s: %v\n", src, err)
		}
	}

	// Add user-created rules from the database
	if p.store != nil {
		dbRules, err := p.store.ListAllEnabledRules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "reload: failed to load user rules: %v\n", err)
		} else {
			for _, r := range dbRules {
				rs.AddLine(r.Rule)
			}
		}
	}

	// Atomic swap — all concurrent readers immediately see the new rules
	p.rules.Store(rs)
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
