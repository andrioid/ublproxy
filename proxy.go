package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ublproxy/internal/blocklist"
	"ublproxy/internal/ca"
	"ublproxy/internal/store"
)

type proxyHandler struct {
	certs     *ca.Cache
	caCertPEM []byte
	transport *http.Transport
	store     *store.Store
	api       *apiHandler
	sessions  *sessionMap

	portalOrigin string
	httpOrigin   string

	// activityLog records recent proxy events for the activity feed.
	activityLog *ActivityLog

	// handshakeTracker detects cert-pinned hosts via repeated TLS
	// handshake failures and auto-switches them to passthrough.
	handshakeTracker *handshakeTracker

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

	// reloadMu serializes baseline rule reloads to prevent concurrent rebuilds.
	reloadMu sync.Mutex
}

func newProxyHandler(certs *ca.Cache, caCertPEM []byte) *proxyHandler {
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
	if credentialID == "" {
		return nil
	}

	if cached, ok := p.userRules.Load(credentialID); ok {
		return cached.(*blocklist.RuleSet)
	}

	if p.store == nil {
		return nil
	}

	rs := p.loadUserRules(credentialID)
	p.userRules.Store(credentialID, rs)
	return rs
}

// loadUserRules builds a RuleSet from a user's DB rules and subscriptions.
func (p *proxyHandler) loadUserRules(credentialID string) *blocklist.RuleSet {
	rs := blocklist.NewRuleSet()
	rs.OnWarning = func(msg string) {
		slog.Warn("filter parse", "user", shortUserID(credentialID), "msg", msg)
	}

	subURLs, err := p.store.ListEnabledSubscriptionURLs(credentialID)
	if err != nil {
		slog.Warn("user-rules: failed to load subscriptions", "user", shortUserID(credentialID), "err", err)
	} else {
		for _, url := range subURLs {
			if err := p.loadBlocklistSource(rs, url); err != nil {
				slog.Warn("user-rules: failed to load subscription", "url", url, "err", err)
			}
		}
	}

	dbRules, err := p.store.ListEnabledRules(credentialID)
	if err != nil {
		slog.Warn("user-rules: failed to load rules", "user", shortUserID(credentialID), "err", err)
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

// matchRedirect checks whether a blocked URL has a $redirect or $redirect-rule
// directive that provides a neutered resource. Returns the resource name and true
// if found. The caller should serve the resource instead of 204 No Content.
func (p *proxyHandler) matchRedirect(clientIP, rawURL string, ctx blocklist.MatchContext) (string, bool) {
	baseline := p.getBaselineRules()
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)

	// Check user rules first (higher priority)
	if userRS != nil {
		if name, ok := userRS.MatchRedirect(rawURL, ctx); ok {
			return name, true
		}
	}
	if baseline != nil {
		if name, ok := baseline.MatchRedirect(rawURL, ctx); ok {
			return name, true
		}
	}
	return "", false
}

// serveRedirectResource writes a neutered resource response. Returns true if
// the resource was found and served, false if the resource name is unknown.
func serveRedirectResource(w http.ResponseWriter, resourceName string) bool {
	res, ok := blocklist.LookupRedirectResource(resourceName)
	if !ok {
		return false
	}
	if res.ContentType != "" {
		w.Header().Set("Content-Type", res.ContentType)
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(res.Body)))
	w.WriteHeader(http.StatusOK)
	w.Write(res.Body)
	return true
}

// applyRemoveParams strips URL query parameters matched by $removeparam rules.
// Returns the original URL if no parameters were stripped.
func (p *proxyHandler) applyRemoveParams(clientIP, rawURL string, ctx blocklist.MatchContext) string {
	baseline := p.getBaselineRules()
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)

	url := rawURL
	if baseline != nil {
		url = baseline.ApplyRemoveParams(url, ctx)
	}
	if userRS != nil {
		url = userRS.ApplyRemoveParams(url, ctx)
	}
	return url
}

// shouldBlockByHeader checks whether a response should be blocked based on
// $header= rules matching the response headers.
func (p *proxyHandler) shouldBlockByHeader(clientIP, rawURL string, ctx blocklist.MatchContext, respHeaders http.Header) bool {
	baseline := p.getBaselineRules()
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)

	if userRS != nil && userRS.ShouldBlockByHeader(rawURL, ctx, respHeaders) {
		return true
	}
	if baseline != nil && baseline.ShouldBlockByHeader(rawURL, ctx, respHeaders) {
		return true
	}
	return false
}

// applyModifierHeaders collects $csp and $permissions header values from
// baseline and user rulesets and injects them into the response headers.
func (p *proxyHandler) applyModifierHeaders(resp *http.Response, clientIP, rawURL string, ctx blocklist.MatchContext) {
	baseline := p.getBaselineRules()
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)

	// Collect CSP directives from both rulesets
	var cspValues []string
	if baseline != nil {
		cspValues = append(cspValues, baseline.ApplyCSPHeaders(rawURL, ctx)...)
	}
	if userRS != nil {
		cspValues = append(cspValues, userRS.ApplyCSPHeaders(rawURL, ctx)...)
	}
	for _, v := range cspValues {
		resp.Header.Add("Content-Security-Policy", v)
	}

	// Collect Permissions-Policy directives from both rulesets
	var permValues []string
	if baseline != nil {
		permValues = append(permValues, baseline.ApplyPermissionsHeaders(rawURL, ctx)...)
	}
	if userRS != nil {
		permValues = append(permValues, userRS.ApplyPermissionsHeaders(rawURL, ctx)...)
	}
	for _, v := range permValues {
		resp.Header.Add("Permissions-Policy", v)
	}
}

// isHostExcepted checks whether a host has an active @@ exception rule.
// Used at CONNECT time to decide between MITM and passthrough tunneling.
func (p *proxyHandler) isHostExcepted(clientIP, host string) bool {
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)
	if userRS != nil && userRS.MatchesExceptionHost(host) {
		return true
	}

	baseline := p.getBaselineRules()
	if baseline != nil && baseline.MatchesExceptionHost(host) {
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
// (static files/URLs). Default subscriptions are per-user (provisioned on
// auth) and loaded via getUserRules, not included here.
func (p *proxyHandler) reloadBaseline() {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	rs := blocklist.NewRuleSet()
	rs.OnWarning = func(msg string) {
		slog.Debug("filter parse", "msg", msg)
	}

	// Load static blocklists (CLI --blocklist flags)
	for _, src := range p.blocklistSources {
		if err := p.loadBlocklistSource(rs, src); err != nil {
			slog.Warn("baseline: failed to load blocklist", "source", src, "err", err)
		}
	}

	p.baselineRules.Store(rs)
	if rs.HostCount() > 0 || rs.RuleCount() > 0 {
		slog.Info("baseline loaded", "hostnames", rs.HostCount(), "rules", rs.RuleCount(), "parse_errors", rs.ParseErrors())
	}
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
				slog.Warn("reload: using stale cache", "url", url, "err", err)
				return rs.LoadReader(strings.NewReader(string(cached.Content)))
			}
		}
		return err
	}

	// Save to cache
	if p.store != nil {
		if cacheErr := p.store.SetCachedBlocklist(url, content); cacheErr != nil {
			slog.Warn("reload: failed to cache", "url", url, "err", cacheErr)
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

// logActivity records a proxy event to the activity log if available.
func (p *proxyHandler) logActivity(entryType, host, url, rule, clientIP, credentialID string) {
	if p.activityLog == nil {
		return
	}
	p.activityLog.Add(ActivityEntry{
		Type: entryType,
		Host: host,
		URL:  url,
		Rule: rule,
		IP:   clientIP,
		User: shortUserID(credentialID),
	})
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
