package blocklist

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// segment represents one piece of a compiled adblock pattern.
type segment struct {
	kind    segmentKind
	literal string // for segLiteral
}

type segmentKind int

const (
	segLiteral   segmentKind = iota // match exact string
	segWildcard                     // match any sequence of characters (including empty)
	segSeparator                    // match a single separator char or end of string
)

// ResourceType is a bitmask representing the type of a network request.
// Rules can restrict which types they apply to using options like $script,
// $image, etc. A zero value means "unknown" and matches any type constraint.
type ResourceType int

const (
	ResourceDocument       ResourceType = 1 << iota // top-level page navigation
	ResourceScript                                  // JavaScript files
	ResourceStylesheet                              // CSS files
	ResourceImage                                   // images (png, jpg, gif, svg, webp, ico, etc.)
	ResourceFont                                    // web fonts (woff, woff2, ttf, otf, eot)
	ResourceXMLHTTPRequest                          // XHR / fetch requests
	ResourceSubdocument                             // iframes, frames
	ResourceMedia                                   // audio, video
	ResourceWebSocket                               // WebSocket connections
	ResourceObject                                  // plugins (object, embed)
	ResourcePopup                                   // popup windows (not enforceable at proxy level)
	ResourceOther                                   // anything not covered above
)

// MatchContext provides additional information about a request for evaluating
// context-dependent filter options like $third-party, $domain, and $script.
type MatchContext struct {
	PageDomain   string       // domain of the page that initiated the request (from Referer)
	ResourceType ResourceType // type of the network request (0 = unknown, matches any)
	Method       string       // HTTP method (GET, POST, etc.) for $method option (empty = match any)
}

// Options holds parsed filter options from the $... suffix of a rule.
// CosmeticFilter is a bitmask indicating which cosmetic filtering an exception disables.
type CosmeticFilter uint8

const (
	CosmeticElemHide     CosmeticFilter = 1 << iota // $elemhide: disable all element hiding
	CosmeticGenericHide                             // $generichide: disable generic selectors
	CosmeticSpecificHide                            // $specifichide: disable domain-specific selectors
)

// HeaderOpt represents a parsed $header= option.
// It specifies which response header to check and how to match its value.
type HeaderOpt struct {
	Name    string         // header name (lowercased)
	Value   string         // literal value to match (empty = presence check only)
	Re      *regexp.Regexp // compiled regex for /regex/ values
	Negated bool           // true if value was prefixed with ~ (match must fail)
}

type Options struct {
	MatchCase      bool           // $match-case: case-sensitive matching
	Important      bool           // $important: overrides exception filters
	BadFilter      bool           // $badfilter: disables the matching rule
	CosmeticOpt    CosmeticFilter // bitmask of cosmetic filtering options
	ThirdParty     *bool          // $third-party (true) or $~third-party (false), nil if unset
	IncludeDomains []string       // $domain=example.com|other.com
	ExcludeDomains []string       // $domain=~example.com
	DenyAllow      []string       // $denyallow=x.com|y.com: exempt these request destinations
	IncludeTo      []string       // $to=tracker.com: restrict to these request destinations
	ExcludeTo      []string       // $to=~example.com: exclude these request destinations
	RemoveParam    string         // $removeparam=name or $removeparam=/regex/ (empty = all params)
	RemoveParamAll bool           // true if $removeparam with no value (strip all)
	RemoveParamRe  *regexp.Regexp // compiled regex for $removeparam=/regex/
	CSP            string         // $csp=directive: Content-Security-Policy header to inject
	CSPAll         bool           // true if $csp with no value (blanket exception marker)
	Permissions    string         // $permissions=directive: Permissions-Policy header to inject
	PermissionsAll bool           // true if $permissions with no value (blanket exception marker)
	Header         *HeaderOpt     // $header=name:value — block based on response header
	Redirect       string         // $redirect=resource: block and serve neutered resource
	RedirectRule   string         // $redirect-rule=resource: redirect only if independently blocked
	RedirectAll    bool           // true if $redirect-rule with no value (blanket exception marker)
	IncludeMethods uint16         // $method=post|get: bitmask of allowed methods
	ExcludeMethods uint16         // $method=~get: bitmask of excluded methods
	IncludeTypes   ResourceType   // bitmask of types this rule applies to (0 = all types)
	ExcludeTypes   ResourceType   // bitmask of negated types ($~script, $~image)
}

// Rule represents a compiled adblock filter pattern.
type Rule struct {
	raw          string         // original filter string for $badfilter matching
	regex        *regexp.Regexp // compiled regex for /regex/ patterns (nil for non-regex)
	segments     []segment
	anchorStart  bool      // |  at start: must match beginning of URL
	anchorEnd    bool      // |  at end: must match end of URL
	domainAnchor bool      // || at start: must match at domain boundary
	domainSuffix string    // the domain part after || (e.g. "example.com")
	pathPattern  []segment // the pattern after the domain part (e.g. "/ads/*.gif")
	options      Options
}

// Compile parses an adblock filter pattern string into a Rule.
func Compile(pattern string) (*Rule, error) {
	if pattern == "" {
		return nil, errors.New("empty pattern")
	}

	r := &Rule{raw: pattern}

	// Extract $options suffix before processing the pattern
	if idx := strings.LastIndexByte(pattern, '$'); idx >= 0 {
		optStr := pattern[idx+1:]
		pattern = pattern[:idx]
		r.options = parseOptions(optStr)
	}

	if pattern == "" {
		return nil, errors.New("empty pattern after options")
	}

	// Handle regex patterns: /regex/
	if len(pattern) >= 2 && pattern[0] == '/' && pattern[len(pattern)-1] == '/' {
		expr := pattern[1 : len(pattern)-1]
		if !r.options.MatchCase {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
		}
		r.regex = re
		return r, nil
	}

	// Handle domain anchor (||)
	if strings.HasPrefix(pattern, "||") {
		r.domainAnchor = true
		pattern = pattern[2:]
		return compileDomainAnchor(r, pattern)
	}

	// Handle start anchor (|)
	if strings.HasPrefix(pattern, "|") {
		r.anchorStart = true
		pattern = pattern[1:]
	}

	// Handle end anchor (|)
	if strings.HasSuffix(pattern, "|") {
		r.anchorEnd = true
		pattern = pattern[:len(pattern)-1]
	}

	r.segments = compileSegments(pattern, r.options.MatchCase)
	return r, nil
}

// HTTP method bitmask constants for $method option.
const (
	methodConnect uint16 = 1 << iota
	methodDelete
	methodGet
	methodHead
	methodOptions
	methodPatch
	methodPost
	methodPut
)

var httpMethodBit = map[string]uint16{
	"connect": methodConnect,
	"delete":  methodDelete,
	"get":     methodGet,
	"head":    methodHead,
	"options": methodOptions,
	"patch":   methodPatch,
	"post":    methodPost,
	"put":     methodPut,
}

// resourceTypeOption maps adblock option names to ResourceType constants.
var resourceTypeOption = map[string]ResourceType{
	"document":          ResourceDocument,
	"doc":               ResourceDocument, // uBO alias
	"script":            ResourceScript,
	"stylesheet":        ResourceStylesheet,
	"css":               ResourceStylesheet, // uBO alias
	"image":             ResourceImage,
	"font":              ResourceFont,
	"xmlhttprequest":    ResourceXMLHTTPRequest,
	"xhr":               ResourceXMLHTTPRequest, // uBO alias
	"subdocument":       ResourceSubdocument,
	"frame":             ResourceSubdocument, // uBO alias
	"media":             ResourceMedia,
	"websocket":         ResourceWebSocket,
	"object":            ResourceObject,
	"ping":              ResourceOther, // navigator.sendBeacon / <a ping>
	"popup":             ResourcePopup,
	"other":             ResourceOther,
	"object-subrequest": ResourceObject, // legacy alias
}

func parseOptions(optStr string) Options {
	var opts Options
	for _, opt := range strings.Split(optStr, ",") {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}

		// Check for negated resource type (~script, ~image, etc.)
		if strings.HasPrefix(opt, "~") {
			if rt, ok := resourceTypeOption[opt[1:]]; ok {
				opts.ExcludeTypes |= rt
				continue
			}
		}

		// Check for positive resource type (script, image, etc.)
		if rt, ok := resourceTypeOption[opt]; ok {
			opts.IncludeTypes |= rt
			continue
		}

		// Noop placeholder (_) used for readability or regex disambiguation
		if strings.Trim(opt, "_") == "" {
			continue
		}

		switch {
		case opt == "match-case":
			opts.MatchCase = true
		case opt == "important":
			opts.Important = true
		case opt == "badfilter":
			opts.BadFilter = true
		case opt == "third-party" || opt == "3p":
			tp := true
			opts.ThirdParty = &tp
		case opt == "~third-party" || opt == "first-party" || opt == "1p":
			tp := false
			opts.ThirdParty = &tp
		case opt == "all":
			opts.IncludeTypes = ResourceDocument | ResourceScript | ResourceStylesheet |
				ResourceImage | ResourceFont | ResourceXMLHTTPRequest | ResourceSubdocument |
				ResourceMedia | ResourceWebSocket | ResourceObject | ResourcePopup | ResourceOther
		case strings.HasPrefix(opt, "domain=") || strings.HasPrefix(opt, "from="):
			// $from= is an alias for $domain=
			val := opt[strings.IndexByte(opt, '=')+1:]
			domains := strings.Split(val, "|")
			for _, d := range domains {
				d = strings.TrimSpace(d)
				if strings.HasPrefix(d, "~") {
					opts.ExcludeDomains = append(opts.ExcludeDomains, strings.ToLower(d[1:]))
				} else {
					opts.IncludeDomains = append(opts.IncludeDomains, strings.ToLower(d))
				}
			}
		case strings.HasPrefix(opt, "denyallow="):
			domains := strings.Split(opt[len("denyallow="):], "|")
			for _, d := range domains {
				d = strings.TrimSpace(d)
				if d != "" {
					opts.DenyAllow = append(opts.DenyAllow, strings.ToLower(d))
				}
			}
		case strings.HasPrefix(opt, "to="):
			domains := strings.Split(opt[len("to="):], "|")
			for _, d := range domains {
				d = strings.TrimSpace(d)
				if d == "" {
					continue
				}
				if strings.HasPrefix(d, "~") {
					opts.ExcludeTo = append(opts.ExcludeTo, strings.ToLower(d[1:]))
				} else {
					opts.IncludeTo = append(opts.IncludeTo, strings.ToLower(d))
				}
			}
		case strings.HasPrefix(opt, "method="):
			methods := strings.Split(opt[len("method="):], "|")
			for _, m := range methods {
				m = strings.TrimSpace(strings.ToLower(m))
				if strings.HasPrefix(m, "~") {
					if bit, ok := httpMethodBit[m[1:]]; ok {
						opts.ExcludeMethods |= bit
					}
				} else {
					if bit, ok := httpMethodBit[m]; ok {
						opts.IncludeMethods |= bit
					}
				}
			}
		case opt == "removeparam":
			opts.RemoveParamAll = true
		case strings.HasPrefix(opt, "removeparam="):
			val := opt[len("removeparam="):]
			if len(val) >= 2 && val[0] == '/' && val[len(val)-1] == '/' {
				re, err := regexp.Compile(val[1 : len(val)-1])
				if err == nil {
					opts.RemoveParamRe = re
				}
			}
			opts.RemoveParam = val
		case opt == "elemhide" || opt == "ehide":
			opts.CosmeticOpt |= CosmeticElemHide
		case opt == "generichide" || opt == "ghide":
			opts.CosmeticOpt |= CosmeticGenericHide
		case opt == "specifichide" || opt == "shide":
			opts.CosmeticOpt |= CosmeticSpecificHide
		case opt == "csp":
			opts.CSPAll = true
		case strings.HasPrefix(opt, "csp="):
			opts.CSP = opt[len("csp="):]
		case opt == "permissions":
			opts.PermissionsAll = true
		case strings.HasPrefix(opt, "permissions="):
			// Per uBO spec, | is used as separator, converted to ", " internally
			val := opt[len("permissions="):]
			opts.Permissions = strings.ReplaceAll(val, "|", ", ")
		case opt == "header":
			// Blanket $header in exception filters disables all header-based blocking
			opts.Header = &HeaderOpt{}
		case strings.HasPrefix(opt, "header="):
			val := opt[len("header="):]
			opts.Header = parseHeaderOpt(val)
		case strings.HasPrefix(opt, "redirect="):
			opts.Redirect = opt[len("redirect="):]
		case opt == "redirect-rule":
			opts.RedirectAll = true
		case strings.HasPrefix(opt, "redirect-rule="):
			opts.RedirectRule = opt[len("redirect-rule="):]
		case opt == "empty":
			// Deprecated: $empty is alias for $redirect=empty
			opts.Redirect = "empty"
		case opt == "mp4":
			// Deprecated: $mp4 is alias for $redirect=noopmp4-1s,$media
			opts.Redirect = "noopmp4-1s"
			opts.IncludeTypes |= ResourceMedia
			// Silently ignore options we can't enforce at proxy level:
			// $rewrite=, $genericblock
		}
	}
	return opts
}

// parseHeaderOpt parses a $header= value into a HeaderOpt.
// Formats: "name", "name:value", "name:~value", "name:/regex/"
func parseHeaderOpt(val string) *HeaderOpt {
	h := &HeaderOpt{}
	colonIdx := strings.IndexByte(val, ':')
	if colonIdx < 0 {
		// Presence check only: $header=via
		h.Name = strings.ToLower(val)
		return h
	}

	h.Name = strings.ToLower(val[:colonIdx])
	value := val[colonIdx+1:]

	if strings.HasPrefix(value, "~") {
		h.Negated = true
		value = value[1:]
	}

	if len(value) >= 2 && value[0] == '/' && value[len(value)-1] == '/' {
		re, err := regexp.Compile(value[1 : len(value)-1])
		if err == nil {
			h.Re = re
		}
	}

	h.Value = value
	return h
}

// compileDomainAnchor handles ||domain.com/path patterns.
// Splits the pattern into a domain part and an optional path pattern.
func compileDomainAnchor(r *Rule, pattern string) (*Rule, error) {
	// Find where the domain ends: first ^, /, :, or * after ||
	domainEnd := len(pattern)
	for i, c := range pattern {
		if c == '/' || c == ':' || c == '^' || c == '*' {
			domainEnd = i
			break
		}
	}

	r.domainSuffix = strings.ToLower(pattern[:domainEnd])
	if domainEnd < len(pattern) {
		// Handle end anchor on the remaining part
		rest := pattern[domainEnd:]
		if strings.HasSuffix(rest, "|") {
			r.anchorEnd = true
			rest = rest[:len(rest)-1]
		}
		r.pathPattern = compileSegments(rest, r.options.MatchCase)
	}

	return r, nil
}

func compileSegments(pattern string, matchCase bool) []segment {
	// Default is case-insensitive: lowercase the pattern
	if !matchCase {
		pattern = strings.ToLower(pattern)
	}

	var segments []segment
	i := 0
	for i < len(pattern) {
		switch pattern[i] {
		case '*':
			// Collapse consecutive wildcards
			if len(segments) == 0 || segments[len(segments)-1].kind != segWildcard {
				segments = append(segments, segment{kind: segWildcard})
			}
			i++
		case '^':
			segments = append(segments, segment{kind: segSeparator})
			i++
		default:
			// Collect literal characters until we hit * or ^
			start := i
			for i < len(pattern) && pattern[i] != '*' && pattern[i] != '^' {
				i++
			}
			segments = append(segments, segment{kind: segLiteral, literal: pattern[start:i]})
		}
	}
	return segments
}

// Match reports whether the rule's URL pattern matches the given URL.
// Does not evaluate context-dependent options ($third-party, $domain).
// Use MatchWithContext for full option evaluation.
func (r *Rule) Match(rawURL string) bool {
	if r.regex != nil {
		return r.regex.MatchString(rawURL)
	}
	url := rawURL
	if !r.options.MatchCase {
		url = strings.ToLower(rawURL)
	}
	return r.matchURL(url)
}

// matchURL matches the pre-cased URL against the rule's pattern.
// Callers must ensure url is already lowercased for case-insensitive rules.
func (r *Rule) matchURL(url string) bool {
	if r.domainAnchor {
		return r.matchDomainAnchor(url)
	}

	if r.anchorStart {
		return matchSegments(r.segments, url, r.anchorEnd)
	}

	// No start anchor: find substring match. Use strings.Index to skip to
	// positions where the leading literal actually appears.
	if len(r.segments) > 0 && r.segments[0].kind == segLiteral {
		lit := r.segments[0].literal
		rest := url
		offset := 0
		for {
			idx := strings.Index(rest, lit)
			if idx < 0 {
				return false
			}
			pos := offset + idx
			if matchSegments(r.segments, url[pos:], r.anchorEnd) {
				return true
			}
			offset = pos + 1
			if offset >= len(url) {
				return false
			}
			rest = url[offset:]
		}
	}

	// Leading segment is separator or wildcard — fall back to scanning
	for i := range len(url) {
		if matchSegments(r.segments, url[i:], r.anchorEnd) {
			return true
		}
	}
	return false
}

// MatchWithContext reports whether the rule matches the URL and all
// context-dependent options ($third-party, $domain) are satisfied.
func (r *Rule) MatchWithContext(rawURL string, ctx MatchContext) bool {
	if !r.Match(rawURL) {
		return false
	}
	return r.checkOptions(rawURL, ctx)
}

// matchWithContextLower matches using a pre-lowercased URL to avoid redundant
// ToLower calls when checking many rules against the same URL. The rawURL is
// needed for $match-case rules and regex rules which must compare against the
// original case.
func (r *Rule) matchWithContextLower(rawURL, lowerURL string, ctx MatchContext) bool {
	if r.regex != nil {
		// Regex handles its own case sensitivity via (?i) flag
		if !r.regex.MatchString(rawURL) {
			return false
		}
		return r.checkOptionsLower(lowerURL, ctx)
	}
	if r.options.MatchCase {
		// $match-case needs the original-case URL
		if !r.matchURL(rawURL) {
			return false
		}
		return r.checkOptionsLower(lowerURL, ctx)
	}
	if !r.matchURL(lowerURL) {
		return false
	}
	return r.checkOptionsLower(lowerURL, ctx)
}

// DomainAnchor returns true if the rule uses a || domain anchor.
func (r *Rule) DomainAnchor() bool { return r.domainAnchor }

// DomainSuffix returns the domain part of a || domain-anchored rule (e.g. "example.com").
func (r *Rule) DomainSuffix() string { return r.domainSuffix }

// Important returns true if the rule has the $important option,
// meaning it should override exception filters.
func (r *Rule) Important() bool { return r.options.Important }

// CosmeticOpt returns the cosmetic filter bitmask for this rule.
func (r *Rule) CosmeticOpt() CosmeticFilter { return r.options.CosmeticOpt }

// HasContextOptions returns true if the rule has options that require
// a MatchContext to evaluate (e.g. $third-party, $domain, $script).
func (r *Rule) HasContextOptions() bool {
	return r.options.ThirdParty != nil ||
		len(r.options.IncludeDomains) > 0 ||
		len(r.options.ExcludeDomains) > 0 ||
		r.options.IncludeTypes != 0 ||
		r.options.ExcludeTypes != 0
}

func (r *Rule) checkOptions(rawURL string, ctx MatchContext) bool {
	lowerURL := strings.ToLower(rawURL)
	lowerCtx := MatchContext{
		PageDomain:   strings.ToLower(ctx.PageDomain),
		ResourceType: ctx.ResourceType,
		Method:       strings.ToUpper(ctx.Method),
	}
	return r.checkOptionsLower(lowerURL, lowerCtx)
}

// checkOptionsLower evaluates context-dependent options using pre-lowercased
// URL and context to avoid redundant ToLower calls in hot paths.
func (r *Rule) checkOptionsLower(lowerURL string, ctx MatchContext) bool {
	// Resource type filtering: when the rule specifies types and we know
	// the request type, check the bitmask. Unknown type (0) matches any
	// constraint for backward compatibility.
	if ctx.ResourceType != 0 {
		if r.options.IncludeTypes != 0 && ctx.ResourceType&r.options.IncludeTypes == 0 {
			return false
		}
		if r.options.ExcludeTypes != 0 && ctx.ResourceType&r.options.ExcludeTypes != 0 {
			return false
		}
	}

	if r.options.ThirdParty != nil {
		requestDomain := extractHostFromURL(lowerURL)
		isThirdParty := !domainMatchesOrIsSubdomain(requestDomain, ctx.PageDomain)

		if *r.options.ThirdParty && !isThirdParty {
			return false
		}
		if !*r.options.ThirdParty && isThirdParty {
			return false
		}
	}

	if len(r.options.IncludeDomains) > 0 {
		matched := false
		for _, d := range r.options.IncludeDomains {
			if domainMatchesOrIsSubdomain(ctx.PageDomain, d) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, d := range r.options.ExcludeDomains {
		if domainMatchesOrIsSubdomain(ctx.PageDomain, d) {
			return false
		}
	}

	// $denyallow: exempt requests to these destination domains
	if len(r.options.DenyAllow) > 0 {
		requestDomain := extractHostFromURL(lowerURL)
		for _, d := range r.options.DenyAllow {
			if domainMatchesOrIsSubdomain(requestDomain, d) {
				return false
			}
		}
	}

	// $to: restrict to specific request destination domains
	if len(r.options.IncludeTo) > 0 {
		requestDomain := extractHostFromURL(lowerURL)
		matched := false
		for _, d := range r.options.IncludeTo {
			if domainMatchesOrIsSubdomain(requestDomain, d) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(r.options.ExcludeTo) > 0 {
		requestDomain := extractHostFromURL(lowerURL)
		for _, d := range r.options.ExcludeTo {
			if domainMatchesOrIsSubdomain(requestDomain, d) {
				return false
			}
		}
	}

	// $method: filter by HTTP method
	if ctx.Method != "" {
		methodLower := strings.ToLower(ctx.Method)
		if bit, ok := httpMethodBit[methodLower]; ok {
			if r.options.IncludeMethods != 0 && r.options.IncludeMethods&bit == 0 {
				return false
			}
			if r.options.ExcludeMethods != 0 && r.options.ExcludeMethods&bit != 0 {
				return false
			}
		}
	}

	return true
}

// domainMatchesOrIsSubdomain returns true if domain equals target
// or is a subdomain of target. If target is an entity pattern (ending
// with ".*"), matches any TLD variant.
func domainMatchesOrIsSubdomain(domain, target string) bool {
	// Entity matching: "google.*" matches google.com, google.co.uk, sub.google.de, etc.
	if strings.HasSuffix(target, ".*") {
		entity := target[:len(target)-2] // "google"
		return domainMatchesEntity(domain, entity)
	}

	if domain == target {
		return true
	}
	return strings.HasSuffix(domain, "."+target)
}

// domainMatchesEntity checks if domain matches an entity pattern.
// Entity "google" matches: google.com, google.co.uk, sub.google.com, etc.
// It checks if the domain is "entity.something" or "sub.entity.something"
// at a domain boundary.
func domainMatchesEntity(domain, entity string) bool {
	// Direct: google.com → domain starts with "google." and has at least one more part
	if strings.HasPrefix(domain, entity+".") {
		return true
	}
	// Subdomain: sub.google.com → domain contains ".google." as a segment boundary
	return strings.Contains(domain, "."+entity+".")
}

// matchDomainAnchor checks if the URL contains the domain at a domain boundary
// (after :// or after a dot), then matches the remaining path pattern.
func (r *Rule) matchDomainAnchor(url string) bool {
	// Find the host portion of the URL
	hostStart, hostEnd := findHost(url)
	if hostStart < 0 {
		return false
	}

	host := url[hostStart:hostEnd]

	// Check if host matches domain suffix at a domain boundary
	if !matchesDomainSuffix(host, r.domainSuffix) {
		return false
	}

	// If no path pattern, the domain match alone is sufficient
	if len(r.pathPattern) == 0 {
		return true
	}

	// Match the path pattern against the rest of the URL after the host
	rest := url[hostEnd:]
	return matchSegments(r.pathPattern, rest, r.anchorEnd)
}

// findHost extracts the host portion from a URL string.
// Returns start and end indices, or (-1, -1) if no host found.
func findHost(url string) (int, int) {
	// Find ://
	schemeEnd := strings.Index(url, "://")
	if schemeEnd < 0 {
		return -1, -1
	}
	hostStart := schemeEnd + 3

	// Host ends at /, :, or end of string
	hostEnd := len(url)
	for i := hostStart; i < len(url); i++ {
		if url[i] == '/' || url[i] == ':' {
			hostEnd = i
			break
		}
	}

	return hostStart, hostEnd
}

// matchesDomainSuffix checks if host equals domain or ends with .domain.
func matchesDomainSuffix(host, domain string) bool {
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

// matchSegments matches a sequence of segments against text.
// If anchorEnd is true, the match must consume the entire text.
func matchSegments(segments []segment, text string, anchorEnd bool) bool {
	return matchSegmentsAt(segments, 0, text, 0, anchorEnd)
}

func matchSegmentsAt(segments []segment, si int, text string, ti int, anchorEnd bool) bool {
	for si < len(segments) {
		seg := segments[si]
		switch seg.kind {
		case segLiteral:
			if ti+len(seg.literal) > len(text) {
				return false
			}
			if text[ti:ti+len(seg.literal)] != seg.literal {
				return false
			}
			ti += len(seg.literal)
			si++

		case segSeparator:
			// Match a single separator character, or end of string
			if ti == len(text) {
				// End of string counts as separator
				si++
				continue
			}
			if !isSeparator(text[ti]) {
				return false
			}
			ti++
			si++

		case segWildcard:
			si++
			// If wildcard is the last segment, it matches everything
			if si == len(segments) {
				return true
			}
			// If the next segment is a literal, use strings.Index to skip
			// to positions where it could match instead of trying every byte
			if segments[si].kind == segLiteral {
				lit := segments[si].literal
				pos := ti
				for {
					idx := strings.Index(text[pos:], lit)
					if idx < 0 {
						return false
					}
					candidate := pos + idx
					if matchSegmentsAt(segments, si, text, candidate, anchorEnd) {
						return true
					}
					pos = candidate + 1
					if pos > len(text) {
						return false
					}
				}
			}
			// Next segment is separator or wildcard — scan all positions
			for pos := ti; pos <= len(text); pos++ {
				if matchSegmentsAt(segments, si, text, pos, anchorEnd) {
					return true
				}
			}
			return false
		}
	}

	// All segments consumed
	if anchorEnd {
		return ti == len(text)
	}
	return true
}

// isSeparator returns true if the byte is a separator character per adblock spec.
// A separator is anything except a letter, digit, _, -, ., or %.
func isSeparator(b byte) bool {
	if b >= 'a' && b <= 'z' {
		return false
	}
	if b >= 'A' && b <= 'Z' {
		return false
	}
	if b >= '0' && b <= '9' {
		return false
	}
	if b == '_' || b == '-' || b == '.' || b == '%' {
		return false
	}
	return true
}
