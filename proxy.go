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
	certs     *certCache
	caCertPEM []byte
	transport *http.Transport
	store     *store.Store
	api       *apiHandler
	sessions  *sessionMap

	portalOrigin string

	// baselineRules are the always-active rules loaded from --blocklist
	// sources and --default-subscription lists. These apply to all traffic
	// regardless of user.
	baselineRules atomic.Pointer[blocklist.RuleSet]

	// userRules caches per-user RuleSets keyed by credential ID. Each
	// user's RuleSet contains their custom rules and subscription lists.
	// Loaded lazily on first proxied request for that user.
	userRules sync.Map // credential ID -> *blocklist.RuleSet

	// blocklistSources are the static blocklist file paths/URLs loaded at
	// startup (from CLI --blocklist flags).
	blocklistSources []string

	// defaultSubscriptions are the default blocklist subscription URLs
	// (from CLI --default-subscription flags or the built-in defaults).
	defaultSubscriptions []string

	// reloadMu serializes baseline rule reloads to prevent concurrent rebuilds.
	reloadMu sync.Mutex
}

func newProxyHandler(certs *certCache, caCertPEM []byte) *proxyHandler {
	return &proxyHandler{
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
}

// getBaselineRules returns the baseline RuleSet, or nil if none is loaded.
func (p *proxyHandler) getBaselineRules() *blocklist.RuleSet {
	return p.baselineRules.Load()
}

// getUserRules returns the cached per-user RuleSet for the given credential,
// loading it lazily from the database on first access. Returns nil if the
// user has no custom rules or subscriptions, or if the store is unavailable.
func (p *proxyHandler) getUserRules(credentialID string) *blocklist.RuleSet {
	if credentialID == "" || p.store == nil {
		return nil
	}

	if cached, ok := p.userRules.Load(credentialID); ok {
		return cached.(*blocklist.RuleSet)
	}

	rs := p.loadUserRules(credentialID)
	p.userRules.Store(credentialID, rs)
	return rs
}

// loadUserRules builds a RuleSet from a user's DB rules and subscriptions.
func (p *proxyHandler) loadUserRules(credentialID string) *blocklist.RuleSet {
	rs := blocklist.NewRuleSet()

	subURLs, err := p.store.ListEnabledSubscriptionURLs(credentialID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "user-rules: failed to load subscriptions for %s: %v\n", credentialID, err)
	} else {
		for _, url := range subURLs {
			if err := p.loadBlocklistSource(rs, url); err != nil {
				fmt.Fprintf(os.Stderr, "user-rules: failed to load subscription %s: %v\n", url, err)
			}
		}
	}

	dbRules, err := p.store.ListEnabledRules(credentialID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "user-rules: failed to load rules for %s: %v\n", credentialID, err)
	} else {
		for _, r := range dbRules {
			rs.AddLine(r.Rule)
		}
	}

	return rs
}

// invalidateUserRules evicts the cached RuleSet for a user so it will be
// reloaded from the database on the next proxied request.
func (p *proxyHandler) invalidateUserRules(credentialID string) {
	p.userRules.Delete(credentialID)
}

// credentialForIP returns the credential ID for the authenticated session
// on the given client IP, or empty string if not authenticated.
func (p *proxyHandler) credentialForIP(clientIP string) string {
	if p.sessions == nil {
		return ""
	}
	entry := p.sessions.Get(clientIP)
	if entry == nil {
		return ""
	}
	return entry.CredentialID
}

// shouldBlock checks whether a URL should be blocked, applying layered
// evaluation: user exceptions override baseline blocks, then user blocks
// are checked, then baseline blocks.
func (p *proxyHandler) shouldBlock(clientIP, url string, ctx blocklist.MatchContext) bool {
	baseline := p.getBaselineRules()
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)

	// User exception overrides baseline block
	if userRS != nil && userRS.MatchesException(url, ctx) {
		return false
	}

	// User-specific block
	if userRS != nil && userRS.ShouldBlockRequest(url, ctx) {
		return true
	}

	// Baseline block
	if baseline != nil && baseline.ShouldBlockRequest(url, ctx) {
		return true
	}

	return false
}

// shouldBlockHost checks whether a host should be blocked at the CONNECT
// level, applying layered evaluation like shouldBlock.
func (p *proxyHandler) shouldBlockHost(clientIP, host string) bool {
	baseline := p.getBaselineRules()
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)

	// User exception overrides baseline block
	if userRS != nil && userRS.MatchesExceptionHost(host) {
		return false
	}

	// User-specific block
	if userRS != nil && userRS.IsHostBlocked(host) {
		return true
	}

	// Baseline block
	if baseline != nil && baseline.IsHostBlocked(host) {
		return true
	}

	return false
}

// blocklistCacheTTL is how long a cached blocklist download is considered
// fresh. Stale entries are re-downloaded on next reload.
const blocklistCacheTTL = 24 * time.Hour

// reloadBaseline rebuilds the baseline RuleSet from --blocklist sources
// and --default-subscription URLs. Remote URLs are cached in the database
// to avoid re-downloading on every reload. This does not include per-user
// rules — those are loaded lazily via getUserRules.
func (p *proxyHandler) reloadBaseline() {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	rs := blocklist.NewRuleSet()

	// Load static blocklists (CLI --blocklist flags)
	for _, src := range p.blocklistSources {
		if err := p.loadBlocklistSource(rs, src); err != nil {
			fmt.Fprintf(os.Stderr, "baseline: failed to load blocklist %s: %v\n", src, err)
		}
	}

	// Load default subscription URLs (EasyList, EasyPrivacy, etc.)
	for _, url := range p.defaultSubscriptions {
		if err := p.loadBlocklistSource(rs, url); err != nil {
			fmt.Fprintf(os.Stderr, "baseline: failed to load subscription %s: %v\n", url, err)
		}
	}

	p.baselineRules.Store(rs)
	fmt.Fprintf(os.Stderr, "baseline: loaded %d hostnames, %d URL rules\n", rs.HostCount(), rs.RuleCount())
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
	client := &http.Client{Timeout: 5 * time.Second}
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
