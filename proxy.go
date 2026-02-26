package main

import (
	"crypto/tls"
	"fmt"
	"io"
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

// blocklistCacheTTL is how long a cached blocklist download is considered
// fresh. Stale entries are re-downloaded on next reload.
const blocklistCacheTTL = 24 * time.Hour

// reloadRules rebuilds the in-memory RuleSet from static blocklists,
// user-subscribed blocklists, and user-created rules. Remote URLs are
// cached in the database to avoid re-downloading on every rule change.
func (p *proxyHandler) reloadRules() {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	rs := blocklist.NewRuleSet()

	// Reload static blocklists (CLI --blocklist flags)
	for _, src := range p.blocklistSources {
		if err := p.loadBlocklistSource(rs, src); err != nil {
			fmt.Fprintf(os.Stderr, "reload: failed to load blocklist %s: %v\n", src, err)
		}
	}

	if p.store != nil {
		// Load user-subscribed blocklist URLs
		subURLs, err := p.store.ListAllEnabledSubscriptionURLs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "reload: failed to load subscription urls: %v\n", err)
		} else {
			for _, url := range subURLs {
				if err := p.loadBlocklistSource(rs, url); err != nil {
					fmt.Fprintf(os.Stderr, "reload: failed to load subscription %s: %v\n", url, err)
				}
			}
		}

		// Add user-created rules from the database
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

// loadBlocklistSource loads a blocklist from a file path or URL into the
// RuleSet. Remote URLs are cached in the database with a 24-hour TTL.
func (p *proxyHandler) loadBlocklistSource(rs *blocklist.RuleSet, src string) error {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return rs.LoadFile(src)
	}
	return p.loadBlocklistURL(rs, src)
}

// loadBlocklistURL loads a remote blocklist, using the DB cache when
// available and fresh. Downloads and caches when stale or missing.
func (p *proxyHandler) loadBlocklistURL(rs *blocklist.RuleSet, url string) error {
	// Try cache first
	if p.store != nil {
		cached, err := p.store.GetCachedBlocklist(url)
		if err == nil && cached != nil && time.Since(cached.FetchedAt) < blocklistCacheTTL {
			return rs.LoadReader(strings.NewReader(string(cached.Content)))
		}
	}

	// Download fresh
	content, err := downloadBlocklist(url)
	if err != nil {
		// Fall back to stale cache if download fails
		if p.store != nil {
			cached, cacheErr := p.store.GetCachedBlocklist(url)
			if cacheErr == nil && cached != nil {
				fmt.Fprintf(os.Stderr, "reload: using stale cache for %s (download failed: %v)\n", url, err)
				return rs.LoadReader(strings.NewReader(string(cached.Content)))
			}
		}
		return err
	}

	// Save to cache
	if p.store != nil {
		if cacheErr := p.store.SetCachedBlocklist(url, content); cacheErr != nil {
			fmt.Fprintf(os.Stderr, "reload: failed to cache %s: %v\n", url, cacheErr)
		}
	}

	return rs.LoadReader(strings.NewReader(string(content)))
}

// downloadBlocklist fetches a blocklist URL and returns its raw content.
func downloadBlocklist(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	// Limit to 50MB to prevent memory exhaustion
	body := http.MaxBytesReader(nil, resp.Body, 50<<20)
	var buf strings.Builder
	if _, err := io.Copy(&buf, body); err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	return []byte(buf.String()), nil
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
