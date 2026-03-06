package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// WarnFunc is called when a non-fatal issue is encountered during rule parsing.
type WarnFunc func(msg string)

// RuleSet holds blocking rules for URL filtering. It combines a hostname map
// (fast path for ||hostname^ rules) with compiled URL pattern rules.
// Exception rules (@@) override blocking rules when they match.
// Element hiding rules (##) provide CSS selectors to hide page elements.
type RuleSet struct {
	hosts            map[string]struct{}
	rules            []*Rule             // generic rules (no domain anchor)
	domainRules      map[string][]*Rule  // domain-anchored rules keyed by domain suffix
	exceptions       []*Rule             // generic exceptions
	domainExc        map[string][]*Rule  // domain-anchored exceptions keyed by domain suffix
	badfilters       map[string]struct{} // normalized targets of $badfilter rules
	removeParamRules []*Rule             // rules with $removeparam option
	cspRules         []*Rule             // rules with $csp= option (inject CSP headers)
	cspExceptions    []*Rule             // exception rules with $csp or $csp= (disable CSP injection)
	permRules        []*Rule             // rules with $permissions= option
	permExceptions   []*Rule             // exception rules with $permissions or $permissions=
	headerRules      []*Rule             // rules with $header= option (block based on response header)
	headerExceptions []*Rule             // exception rules with $header (disable header-based blocking)
	redirectRules    []*Rule             // rules with $redirect= or $redirect-rule= (serve neutered resources)
	redirectExc      []*Rule             // exception rules with $redirect-rule or $redirect-rule= (disable redirect)
	elemHideRules    []*ElementHideRule
	scriptletRules   []*ScriptletRule // rules with ##+js() (scriptlet injection)
	elemHideIdx      *elemHideIndex
	OnWarning        WarnFunc // optional callback for parse warnings
	parseErrors      int      // count of rules that failed to compile
}

func NewRuleSet() *RuleSet {
	return &RuleSet{
		hosts:       make(map[string]struct{}),
		domainRules: make(map[string][]*Rule),
		domainExc:   make(map[string][]*Rule),
		badfilters:  make(map[string]struct{}),
		elemHideIdx: newElemHideIndex(),
	}
}

// ParseErrors returns the number of rules that failed to compile during loading.
func (rs *RuleSet) ParseErrors() int {
	if rs == nil {
		return 0
	}
	return rs.parseErrors
}

func (rs *RuleSet) warn(msg string) {
	rs.parseErrors++
	if rs.OnWarning != nil {
		rs.OnWarning(msg)
	}
}

// AddHostname adds a hostname to the fast-path blocklist.
// Matches the hostname and all its subdomains.
func (rs *RuleSet) AddHostname(host string) {
	rs.hosts[strings.ToLower(host)] = struct{}{}
}

// AddException compiles an adblock exception pattern (with or without @@
// prefix) and adds it to the exception list. Domain-anchored exceptions are
// indexed by domain suffix for fast lookup; all others go into the generic list.
func (rs *RuleSet) AddException(pattern string) error {
	rawLine := pattern
	pattern = strings.TrimPrefix(pattern, "@@")
	rule, err := Compile(pattern)
	if err != nil {
		return err
	}
	// Preserve original line (with @@) for $badfilter matching
	rule.raw = rawLine

	// CSP exceptions go to a separate list
	if rule.options.CSP != "" || rule.options.CSPAll {
		rs.cspExceptions = append(rs.cspExceptions, rule)
		return nil
	}

	// Permissions exceptions go to a separate list
	if rule.options.Permissions != "" || rule.options.PermissionsAll {
		rs.permExceptions = append(rs.permExceptions, rule)
		return nil
	}

	// Header exceptions go to a separate list
	if rule.options.Header != nil {
		rs.headerExceptions = append(rs.headerExceptions, rule)
		return nil
	}

	// Redirect exceptions: @@...$redirect-rule or @@...$redirect-rule=resource
	if rule.options.RedirectRule != "" || rule.options.RedirectAll {
		rs.redirectExc = append(rs.redirectExc, rule)
		return nil
	}

	if rule.DomainAnchor() && rule.DomainSuffix() != "" {
		key := rule.DomainSuffix()
		rs.domainExc[key] = append(rs.domainExc[key], rule)
	} else {
		rs.exceptions = append(rs.exceptions, rule)
	}
	return nil
}

// AddRule compiles an adblock URL pattern and adds it to the rule list.
// Domain-anchored rules (||domain...) are indexed by domain suffix for fast
// lookup; all other rules go into the generic list.
// $removeparam rules are stored separately since they modify URLs rather than block.
func (rs *RuleSet) AddRule(pattern string) error {
	rule, err := Compile(pattern)
	if err != nil {
		return err
	}

	// $removeparam rules go to a separate list
	if rule.options.RemoveParam != "" || rule.options.RemoveParamAll {
		rs.removeParamRules = append(rs.removeParamRules, rule)
		return nil
	}

	// $csp rules go to a separate list (they inject headers, not block)
	if rule.options.CSP != "" {
		rs.cspRules = append(rs.cspRules, rule)
		return nil
	}

	// $permissions rules go to a separate list
	if rule.options.Permissions != "" {
		rs.permRules = append(rs.permRules, rule)
		return nil
	}

	// $header rules go to a separate list (they block based on response headers)
	if rule.options.Header != nil && rule.options.Header.Name != "" {
		rs.headerRules = append(rs.headerRules, rule)
		return nil
	}

	// $redirect= creates both a redirect directive AND a blocking rule.
	// The redirect directive is stored separately; the blocking rule falls
	// through to the normal block lists below.
	if rule.options.Redirect != "" {
		rs.redirectRules = append(rs.redirectRules, rule)
		// Fall through to also add as a blocking rule
	}

	// $redirect-rule= creates only a redirect directive (no block rule)
	if rule.options.RedirectRule != "" {
		rs.redirectRules = append(rs.redirectRules, rule)
		return nil
	}

	if rule.DomainAnchor() && rule.DomainSuffix() != "" {
		key := rule.DomainSuffix()
		rs.domainRules[key] = append(rs.domainRules[key], rule)
	} else {
		rs.rules = append(rs.rules, rule)
	}
	return nil
}

// LoadReader reads rules line-by-line from any io.Reader.
// Handles !#if / !#else / !#endif pre-parsing directives for conditional blocks.
func (rs *RuleSet) LoadReader(r io.Reader) error {
	scanner := bufio.NewScanner(r)

	// Stack tracks nested !#if state. Each entry is true if the block is active.
	// An empty stack means all lines are active.
	var stack []bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "!#if ") {
			expr := strings.TrimSpace(line[5:])
			active := parentActive(stack) && evaluatePreparseExpr(expr)
			stack = append(stack, active)
			continue
		}
		if line == "!#else" {
			if len(stack) > 0 {
				// Flip the current level, but only if the parent is active
				wasActive := stack[len(stack)-1]
				stack[len(stack)-1] = parentActive(stack[:len(stack)-1]) && !wasActive
			}
			continue
		}
		if line == "!#endif" {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}

		if !parentActive(stack) {
			continue
		}

		rs.AddLine(line)
	}
	return scanner.Err()
}

// parentActive returns true if all entries in the stack are true (i.e. we're
// inside active conditional blocks at every nesting level).
func parentActive(stack []bool) bool {
	for _, v := range stack {
		if !v {
			return false
		}
	}
	return true
}

// Pre-parse environment tokens. We're a proxy, not a browser extension.
var preparseTokens = map[string]bool{
	"ext_ublock":          true,
	"ext_abp":             false,
	"ext_devbuild":        false,
	"env_chromium":        false,
	"env_firefox":         false,
	"env_edge":            false,
	"env_safari":          false,
	"env_mobile":          false,
	"env_mv3":             false,
	"cap_html_filtering":  true, // proxy can modify HTML responses
	"cap_user_stylesheet": false,
	"false":               false,
	"true":                true,
}

// evaluatePreparseExpr evaluates a simple boolean expression used in !#if directives.
// Supports tokens, ! (negation), && (AND), || (OR). No parentheses or precedence —
// uBO filter lists use simple expressions (single token, negation, or one operator).
func evaluatePreparseExpr(expr string) bool {
	expr = strings.TrimSpace(expr)

	// Handle || (OR) — split and evaluate each side
	if parts := strings.SplitN(expr, "||", 2); len(parts) == 2 {
		return evaluatePreparseExpr(parts[0]) || evaluatePreparseExpr(parts[1])
	}

	// Handle && (AND)
	if parts := strings.SplitN(expr, "&&", 2); len(parts) == 2 {
		return evaluatePreparseExpr(parts[0]) && evaluatePreparseExpr(parts[1])
	}

	// Handle ! (negation)
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "!") {
		return !evaluatePreparseExpr(expr[1:])
	}

	// Token lookup
	expr = strings.TrimSpace(expr)
	if val, ok := preparseTokens[expr]; ok {
		return val
	}

	// Unknown tokens default to false
	return false
}

// LoadFile reads a blocklist file and adds all parsed rules.
// Hostname-only rules go to the fast path; URL patterns become compiled rules.
func (rs *RuleSet) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open blocklist %s: %w", path, err)
	}
	defer f.Close()
	return rs.LoadReader(f)
}

// LoadURL fetches a blocklist from an HTTP(S) URL and adds all parsed rules.
// Uses a 30-second timeout to avoid blocking startup on unresponsive servers.
func (rs *RuleSet) LoadURL(url string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("fetch blocklist %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch blocklist %s: HTTP %d", url, resp.StatusCode)
	}
	return rs.LoadReader(resp.Body)
}

// AddLine parses a single line from a blocklist file and adds it to the
// appropriate data structure (hostname map, compiled rule, or element hiding rule).
func (rs *RuleSet) AddLine(line string) {
	line = strings.TrimSpace(line)

	if line == "" || line[0] == '!' || line[0] == '[' {
		return
	}

	// Comments: lines starting with # that aren't element hiding rules (##).
	// Hosts-file comments start with "# " but element hiding rules start with "##".
	if line[0] == '#' && !strings.HasPrefix(line, "##") {
		return
	}

	// $badfilter: compute the target rule and add to the badfilter set.
	// The target is the same line with $badfilter (and ,badfilter) removed,
	// which is the raw pattern of the rule being disabled.
	// Check after the $ delimiter to avoid matching "badfilter" in URL patterns.
	if idx := strings.LastIndexByte(line, '$'); idx >= 0 && strings.Contains(line[idx:], "badfilter") {
		target := normalizeBadfilterTarget(line)
		if target != "" {
			rs.badfilters[target] = struct{}{}
			return
		}
	}

	// Exception rules (@@)
	if strings.HasPrefix(line, "@@") {
		if err := rs.AddException(line); err != nil {
			rs.warn("skip exception rule " + line + ": " + err.Error())
		}
		return
	}

	// Scriptlet injection rules (##+js, #@#+js) go to a separate list
	if isScriptletLine(line) {
		if rule := parseScriptletRule(line); rule != nil {
			rs.scriptletRules = append(rs.scriptletRules, rule)
		}
		return
	}

	// Element hiding rules (##, #@#) and unsupported filters (#?#, #$#).
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") {
		if rule := parseElementHideRule(line); rule != nil {
			rs.elemHideRules = append(rs.elemHideRules, rule)
			if rule.Exception {
				rs.elemHideIdx.addException(rule)
			}
		}
		return
	}
	if strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
		return
	}

	// Strip options for hostname extraction checks (Compile handles options itself)
	rawPattern := line
	hasOptions := strings.IndexByte(rawPattern, '$') >= 0
	if hasOptions {
		rawPattern = rawPattern[:strings.IndexByte(rawPattern, '$')]
	}

	// Try to extract a hostname-only rule for the fast path.
	// Rules with $options (e.g. $third-party, $domain) must go through Compile
	// so the options are evaluated at match time.
	if !hasOptions {
		if host, ok := extractHostnameRule(rawPattern); ok {
			rs.AddHostname(host)
			return
		}
	}

	// Hosts-file format: "0.0.0.0 hostname" or "127.0.0.1 hostname"
	if host, ok := parseHostsFileLine(rawPattern); ok {
		rs.AddHostname(host)
		return
	}

	// IPv6 loopback in hosts files
	if strings.HasPrefix(rawPattern, "::1 ") {
		return
	}

	// Compile as a URL pattern rule (routed to domain index or generic list)
	if err := rs.AddRule(line); err != nil {
		rs.warn("skip rule " + line + ": " + err.Error())
	}
}

// normalizeBadfilterTarget extracts the target rule string from a $badfilter
// line. Returns the filter string that would be disabled. Returns "" if the
// line does not contain $badfilter.
func normalizeBadfilterTarget(line string) string {
	// Remove $badfilter or ,badfilter from the options
	idx := strings.LastIndexByte(line, '$')
	if idx < 0 {
		return ""
	}
	prefix := line[:idx]
	optStr := line[idx+1:]

	var opts []string
	for _, opt := range strings.Split(optStr, ",") {
		opt = strings.TrimSpace(opt)
		if opt == "badfilter" {
			continue
		}
		opts = append(opts, opt)
	}

	if len(opts) == 0 {
		return prefix
	}
	return prefix + "$" + strings.Join(opts, ",")
}

// extractHostnameRule checks if the pattern is a hostname-only rule
// (||hostname^ with no path or wildcards). Returns the hostname and true
// if it qualifies for the fast-path map.
func extractHostnameRule(pattern string) (string, bool) {
	if !strings.HasPrefix(pattern, "||") {
		return "", false
	}

	host := pattern[2:]

	// Must end with ^ for a hostname-only rule
	if !strings.HasSuffix(host, "^") {
		return "", false
	}
	host = host[:len(host)-1]

	// If it contains path or wildcard characters, it's a URL pattern
	if strings.ContainsAny(host, "/*:") {
		return "", false
	}

	if !isValidHostname(host) {
		return "", false
	}

	return host, true
}

// ShouldBlock returns true if the URL matches any blocking rule and no
// exception rule overrides it. Safe to call on a nil receiver (returns false).
// Does not evaluate context-dependent options ($third-party, $domain).
func (rs *RuleSet) ShouldBlock(rawURL string) bool {
	return rs.ShouldBlockRequest(rawURL, MatchContext{})
}

// ShouldBlockRequest returns true if the URL matches any blocking rule
// (considering context-dependent options) and no exception rule overrides it.
// Rules with $important bypass exception filters entirely.
// Safe to call on a nil receiver (returns false).
func (rs *RuleSet) ShouldBlockRequest(rawURL string, ctx MatchContext) bool {
	if rs == nil {
		return false
	}

	// Pre-lowercase once to avoid redundant ToLower in each rule match
	lowerURL := strings.ToLower(rawURL)
	lowerCtx := MatchContext{
		PageDomain:   strings.ToLower(ctx.PageDomain),
		ResourceType: ctx.ResourceType,
		Method:       strings.ToUpper(ctx.Method),
	}
	host := extractHostFromURL(lowerURL)

	hasBadfilters := len(rs.badfilters) > 0

	// Check $important rules first — these bypass all exceptions
	if rs.matchImportantDomainIndexed(host, rawURL, lowerURL, lowerCtx, hasBadfilters) {
		return true
	}
	for _, rule := range rs.rules {
		if rule.Important() && rule.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			if !hasBadfilters || !rs.isBadfiltered(rule) {
				return true
			}
		}
	}

	blocked := false

	// Fast path: check hostname against the hostname map
	if rs.isHostBlocked(host) {
		if !hasBadfilters || !rs.isHostBadfiltered(host) {
			blocked = true
		}
	}

	// Check domain-indexed rules by walking up the hostname hierarchy
	if !blocked {
		blocked = rs.matchDomainIndexedFiltered(rs.domainRules, host, rawURL, lowerURL, lowerCtx, hasBadfilters)
	}

	// Fall through to generic rules (non-domain-anchored)
	if !blocked {
		for _, rule := range rs.rules {
			if rule.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
				if !hasBadfilters || !rs.isBadfiltered(rule) {
					blocked = true
					break
				}
			}
		}
	}

	if !blocked {
		return false
	}

	// Check domain-indexed exceptions
	if rs.matchDomainIndexedFiltered(rs.domainExc, host, rawURL, lowerURL, lowerCtx, hasBadfilters) {
		return false
	}

	// Check generic exceptions
	for _, exc := range rs.exceptions {
		if exc.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			if !hasBadfilters || !rs.isBadfiltered(exc) {
				return false
			}
		}
	}

	return true
}

// matchImportantDomainIndexed walks up the hostname hierarchy and checks
// only $important rules in the domain-indexed map.
func (rs *RuleSet) matchImportantDomainIndexed(host, rawURL, lowerURL string, ctx MatchContext, hasBadfilters bool) bool {
	h := host
	for {
		for _, rule := range rs.domainRules[h] {
			if rule.Important() && rule.matchWithContextLower(rawURL, lowerURL, ctx) {
				if !hasBadfilters || !rs.isBadfiltered(rule) {
					return true
				}
			}
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			return false
		}
		h = h[dot+1:]
	}
}

// matchDomainIndexedFiltered is like matchDomainIndexed but skips badfiltered rules.
func (rs *RuleSet) matchDomainIndexedFiltered(index map[string][]*Rule, host, rawURL, lowerURL string, ctx MatchContext, hasBadfilters bool) bool {
	h := host
	for {
		for _, rule := range index[h] {
			if rule.matchWithContextLower(rawURL, lowerURL, ctx) {
				if !hasBadfilters || !rs.isBadfiltered(rule) {
					return true
				}
			}
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			return false
		}
		h = h[dot+1:]
	}
}

// isBadfiltered returns true if the rule has been disabled by a $badfilter entry.
func (rs *RuleSet) isBadfiltered(rule *Rule) bool {
	_, ok := rs.badfilters[rule.raw]
	return ok
}

// isHostBadfiltered returns true if a hostname-only rule has been badfiltered.
// Hostname rules are stored as "||host^" in the badfilter set.
func (rs *RuleSet) isHostBadfiltered(host string) bool {
	_, ok := rs.badfilters["||"+host+"^"]
	return ok
}

// matchDomainIndexed walks up the hostname hierarchy and checks rules in the
// domain-indexed map. Returns true if any rule matches the URL.
func (rs *RuleSet) matchDomainIndexed(index map[string][]*Rule, host, rawURL, lowerURL string, ctx MatchContext) bool {
	h := host
	for {
		for _, rule := range index[h] {
			if rule.matchWithContextLower(rawURL, lowerURL, ctx) {
				return true
			}
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			return false
		}
		h = h[dot+1:]
	}
}

// IsHostBlocked returns true if the hostname (or any parent domain) is in
// the fast-path hostname map. Safe to call on a nil receiver.
// Use this for CONNECT-level blocking where only the hostname is available.
func (rs *RuleSet) IsHostBlocked(host string) bool {
	if rs == nil {
		return false
	}
	return rs.isHostBlocked(strings.ToLower(host))
}

func (rs *RuleSet) isHostBlocked(host string) bool {
	for {
		if _, ok := rs.hosts[host]; ok {
			return true
		}
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			return false
		}
		host = host[dot+1:]
	}
}

// MatchesException returns true if the URL matches any exception rule (@@)
// in this RuleSet. This is used for per-user exception checking where user
// exceptions need to override baseline blocking rules.
// Safe to call on a nil receiver (returns false).
func (rs *RuleSet) MatchesException(rawURL string, ctx MatchContext) bool {
	if rs == nil {
		return false
	}

	lowerURL := strings.ToLower(rawURL)
	lowerCtx := MatchContext{
		PageDomain:   strings.ToLower(ctx.PageDomain),
		ResourceType: ctx.ResourceType,
	}
	host := extractHostFromURL(lowerURL)

	if rs.matchDomainIndexed(rs.domainExc, host, rawURL, lowerURL, lowerCtx) {
		return true
	}
	for _, exc := range rs.exceptions {
		if exc.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			return true
		}
	}
	return false
}

// MatchesExceptionHost returns true if the hostname matches any hostname-level
// exception rule (@@||hostname^). Used at CONNECT time where only the host is
// known. Safe to call on a nil receiver (returns false).
func (rs *RuleSet) MatchesExceptionHost(host string) bool {
	if rs == nil {
		return false
	}
	// Build a synthetic URL so the exception rule matching works
	syntheticURL := "https://" + host + "/"
	return rs.MatchesException(syntheticURL, MatchContext{})
}

// CosmeticFilterExceptions returns a bitmask of cosmetic filter exceptions
// that apply to the given page URL. Checks exception rules with $elemhide,
// $generichide, or $specifichide options.
// Safe to call on a nil receiver (returns 0).
func (rs *RuleSet) CosmeticFilterExceptions(pageURL string) CosmeticFilter {
	if rs == nil {
		return 0
	}

	lowerURL := strings.ToLower(pageURL)
	lowerCtx := MatchContext{
		PageDomain: extractHostFromURL(lowerURL),
	}
	host := lowerCtx.PageDomain

	var result CosmeticFilter

	// Check domain-indexed exceptions
	h := host
	for {
		for _, rule := range rs.domainExc[h] {
			if rule.CosmeticOpt() != 0 && rule.matchWithContextLower(pageURL, lowerURL, lowerCtx) {
				result |= rule.CosmeticOpt()
			}
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			break
		}
		h = h[dot+1:]
	}

	// Check generic exceptions
	for _, exc := range rs.exceptions {
		if exc.CosmeticOpt() != 0 && exc.matchWithContextLower(pageURL, lowerURL, lowerCtx) {
			result |= exc.CosmeticOpt()
		}
	}

	return result
}

// ApplyRemoveParams modifies the URL by stripping query parameters matched by
// $removeparam rules. Returns the original URL if no parameters were stripped.
// Safe to call on a nil receiver (returns url unchanged).
func (rs *RuleSet) ApplyRemoveParams(rawURL string, ctx MatchContext) string {
	if rs == nil || len(rs.removeParamRules) == 0 {
		return rawURL
	}

	// Find the query string
	qIdx := strings.IndexByte(rawURL, '?')
	if qIdx < 0 {
		return rawURL
	}

	lowerURL := strings.ToLower(rawURL)
	lowerCtx := MatchContext{
		PageDomain:   strings.ToLower(ctx.PageDomain),
		ResourceType: ctx.ResourceType,
		Method:       strings.ToUpper(ctx.Method),
	}

	// Collect which params to remove
	var stripAll bool
	var literalParams []string
	var regexParams []*regexp.Regexp

	for _, rule := range rs.removeParamRules {
		if !rule.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			continue
		}
		if rule.options.RemoveParamAll {
			stripAll = true
			break
		}
		if rule.options.RemoveParamRe != nil {
			regexParams = append(regexParams, rule.options.RemoveParamRe)
		} else if rule.options.RemoveParam != "" {
			literalParams = append(literalParams, rule.options.RemoveParam)
		}
	}

	if stripAll {
		return rawURL[:qIdx]
	}

	if len(literalParams) == 0 && len(regexParams) == 0 {
		return rawURL
	}

	// Parse and filter query parameters
	base := rawURL[:qIdx]
	query := rawURL[qIdx+1:]
	var kept []string
	for _, pair := range strings.Split(query, "&") {
		paramName := pair
		if eqIdx := strings.IndexByte(pair, '='); eqIdx >= 0 {
			paramName = pair[:eqIdx]
		}

		stripped := false
		for _, lit := range literalParams {
			if paramName == lit {
				stripped = true
				break
			}
		}
		if !stripped {
			for _, re := range regexParams {
				if re.MatchString(paramName) {
					stripped = true
					break
				}
			}
		}

		if !stripped {
			kept = append(kept, pair)
		}
	}

	if len(kept) == 0 {
		return base
	}
	return base + "?" + strings.Join(kept, "&")
}

// MatchRedirect returns the redirect resource name for a URL that is being
// blocked, if any $redirect or $redirect-rule directive matches.
// Exception filters with $redirect-rule (blanket) or $redirect-rule=resource
// (specific) can disable matching redirect directives.
// Safe to call on a nil receiver (returns "", false).
func (rs *RuleSet) MatchRedirect(rawURL string, ctx MatchContext) (string, bool) {
	if rs == nil || len(rs.redirectRules) == 0 {
		return "", false
	}

	lowerURL := strings.ToLower(rawURL)
	lowerCtx := MatchContext{
		PageDomain:   strings.ToLower(ctx.PageDomain),
		ResourceType: ctx.ResourceType,
		Method:       strings.ToUpper(ctx.Method),
	}

	// Check for blanket exception first
	for _, exc := range rs.redirectExc {
		if exc.options.RedirectAll && exc.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			return "", false
		}
	}

	// Find the best matching redirect (highest priority)
	var bestResource string
	var bestPriority int
	found := false

	for _, rule := range rs.redirectRules {
		if !rule.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			continue
		}

		resource := rule.options.Redirect
		if resource == "" {
			resource = rule.options.RedirectRule
		}

		// Check for specific exception
		excepted := false
		for _, exc := range rs.redirectExc {
			if !exc.options.RedirectAll && exc.options.RedirectRule == resource &&
				exc.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
				excepted = true
				break
			}
		}
		if excepted {
			continue
		}

		// For now, use simple first-match (priority support can be added later)
		priority := 0
		if !found || priority > bestPriority {
			bestResource = resource
			bestPriority = priority
			found = true
		}
	}

	return bestResource, found
}

// ShouldBlockByHeader checks whether a response should be blocked based on
// $header= rules matching the response headers. Returns true if any
// $header= rule matches and no exception overrides it.
// Safe to call on a nil receiver (returns false).
func (rs *RuleSet) ShouldBlockByHeader(rawURL string, ctx MatchContext, respHeaders http.Header) bool {
	if rs == nil || len(rs.headerRules) == 0 {
		return false
	}

	lowerURL := strings.ToLower(rawURL)
	lowerCtx := MatchContext{
		PageDomain:   strings.ToLower(ctx.PageDomain),
		ResourceType: ctx.ResourceType,
		Method:       strings.ToUpper(ctx.Method),
	}

	// Check for blanket exception first (@@...$header without value)
	for _, exc := range rs.headerExceptions {
		if exc.options.Header != nil && exc.options.Header.Name == "" && exc.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			return false
		}
	}

	for _, rule := range rs.headerRules {
		if !rule.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			continue
		}

		h := rule.options.Header
		headerValues := respHeaders.Values(h.Name)

		if !headerMatchesOpt(h, headerValues) {
			continue
		}

		// Check for specific exception
		excepted := false
		for _, exc := range rs.headerExceptions {
			if exc.options.Header == nil || exc.options.Header.Name == "" {
				continue
			}
			if exc.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
				// An exception with $header (no specific name) acts as blanket
				// An exception with $header=name matches by type options only
				excepted = true
				break
			}
		}
		if !excepted {
			return true
		}
	}

	return false
}

// headerMatchesOpt checks if the response header values satisfy the HeaderOpt.
func headerMatchesOpt(h *HeaderOpt, values []string) bool {
	if h.Value == "" && h.Re == nil {
		// Presence check: header must exist
		return !h.Negated && len(values) > 0
	}

	for _, v := range values {
		var matches bool
		if h.Re != nil {
			matches = h.Re.MatchString(v)
		} else {
			matches = strings.Contains(v, h.Value)
		}

		if h.Negated {
			if !matches {
				return true
			}
		} else {
			if matches {
				return true
			}
		}
	}

	// For negated: if all values matched (none satisfied !match), return false
	// For non-negated: if no values matched, return false
	// Also: if no header values exist (header absent)
	if h.Negated && len(values) > 0 {
		return false
	}
	return false
}

// applyModifierHeaders is the shared logic for $csp and $permissions.
// It checks block rules for matches, then filters out any that are
// disabled by exception rules (blanket or specific value match).
// Returns the list of header values to inject.
func applyModifierHeaders(
	rawURL string,
	ctx MatchContext,
	blockRules []*Rule,
	excRules []*Rule,
	getValue func(*Rule) string,
	isBlanket func(*Rule) bool,
) []string {
	if len(blockRules) == 0 {
		return nil
	}

	lowerURL := strings.ToLower(rawURL)
	lowerCtx := MatchContext{
		PageDomain:   strings.ToLower(ctx.PageDomain),
		ResourceType: ctx.ResourceType,
		Method:       strings.ToUpper(ctx.Method),
	}

	// Check for blanket exception first
	for _, exc := range excRules {
		if isBlanket(exc) && exc.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			return nil
		}
	}

	// Collect matching block rules
	var values []string
	for _, rule := range blockRules {
		if !rule.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
			continue
		}
		val := getValue(rule)
		// Check for specific exception
		excepted := false
		for _, exc := range excRules {
			if !isBlanket(exc) && getValue(exc) == val && exc.matchWithContextLower(rawURL, lowerURL, lowerCtx) {
				excepted = true
				break
			}
		}
		if !excepted {
			values = append(values, val)
		}
	}

	return values
}

// ApplyCSPHeaders returns CSP directive values to inject as Content-Security-Policy
// response headers for the given URL. Exception filters with $csp (blanket) or
// $csp=<value> (specific) can disable matching CSP rules.
// Safe to call on a nil receiver (returns nil).
func (rs *RuleSet) ApplyCSPHeaders(rawURL string, ctx MatchContext) []string {
	if rs == nil {
		return nil
	}
	return applyModifierHeaders(rawURL, ctx, rs.cspRules, rs.cspExceptions,
		func(r *Rule) string { return r.options.CSP },
		func(r *Rule) bool { return r.options.CSPAll },
	)
}

// ApplyPermissionsHeaders returns Permissions-Policy directive values to inject
// for the given URL. Works the same as ApplyCSPHeaders but for $permissions.
// Safe to call on a nil receiver (returns nil).
func (rs *RuleSet) ApplyPermissionsHeaders(rawURL string, ctx MatchContext) []string {
	if rs == nil {
		return nil
	}
	return applyModifierHeaders(rawURL, ctx, rs.permRules, rs.permExceptions,
		func(r *Rule) string { return r.options.Permissions },
		func(r *Rule) bool { return r.options.PermissionsAll },
	)
}

// IsElementHideExcepted returns true if this RuleSet contains an element
// hiding exception (#@#) for the given CSS selector on the given domain.
// Used to let user #@# exceptions suppress baseline ## rules.
// Safe to call on a nil receiver (returns false).
func (rs *RuleSet) IsElementHideExcepted(selector, domain string) bool {
	if rs == nil || rs.elemHideIdx == nil {
		return false
	}
	return rs.elemHideIdx.isExcepted(selector, strings.ToLower(domain))
}

// extractHostFromURL pulls the hostname from a URL string.
func extractHostFromURL(url string) string {
	schemeEnd := strings.Index(url, "://")
	if schemeEnd < 0 {
		return ""
	}
	hostStart := schemeEnd + 3

	hostEnd := len(url)
	for i := hostStart; i < len(url); i++ {
		if url[i] == '/' || url[i] == ':' {
			hostEnd = i
			break
		}
	}

	return url[hostStart:hostEnd]
}

// HostCount returns the number of hostnames in the fast-path map.
func (rs *RuleSet) HostCount() int {
	if rs == nil {
		return 0
	}
	return len(rs.hosts)
}

// RuleCount returns the number of compiled URL pattern rules
// (both domain-indexed and generic).
func (rs *RuleSet) RuleCount() int {
	if rs == nil {
		return 0
	}
	n := len(rs.rules)
	for _, rules := range rs.domainRules {
		n += len(rules)
	}
	return n
}
