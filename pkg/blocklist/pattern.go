package blocklist

import (
	"errors"
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

// MatchContext provides additional information about a request for evaluating
// context-dependent filter options like $third-party and $domain.
type MatchContext struct {
	PageDomain string // domain of the page that initiated the request (from Referer)
}

// Options holds parsed filter options from the $... suffix of a rule.
type Options struct {
	MatchCase      bool     // $match-case: case-sensitive matching
	ThirdParty     *bool    // $third-party (true) or $~third-party (false), nil if unset
	IncludeDomains []string // $domain=example.com|other.com
	ExcludeDomains []string // $domain=~example.com
}

// Rule represents a compiled adblock filter pattern.
type Rule struct {
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

	r := &Rule{}

	// Extract $options suffix before processing the pattern
	if idx := strings.LastIndexByte(pattern, '$'); idx >= 0 {
		optStr := pattern[idx+1:]
		pattern = pattern[:idx]
		r.options = parseOptions(optStr)
	}

	if pattern == "" {
		return nil, errors.New("empty pattern after options")
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

func parseOptions(optStr string) Options {
	var opts Options
	for _, opt := range strings.Split(optStr, ",") {
		opt = strings.TrimSpace(opt)
		switch {
		case opt == "match-case":
			opts.MatchCase = true
		case opt == "third-party":
			tp := true
			opts.ThirdParty = &tp
		case opt == "~third-party":
			tp := false
			opts.ThirdParty = &tp
		case strings.HasPrefix(opt, "domain="):
			domains := strings.Split(opt[7:], "|")
			for _, d := range domains {
				d = strings.TrimSpace(d)
				if strings.HasPrefix(d, "~") {
					opts.ExcludeDomains = append(opts.ExcludeDomains, strings.ToLower(d[1:]))
				} else {
					opts.IncludeDomains = append(opts.IncludeDomains, strings.ToLower(d))
				}
			}
		}
	}
	return opts
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
// needed for $match-case rules which must compare against the original case.
func (r *Rule) matchWithContextLower(rawURL, lowerURL string, ctx MatchContext) bool {
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

// HasContextOptions returns true if the rule has options that require
// a MatchContext to evaluate (e.g. $third-party, $domain).
func (r *Rule) HasContextOptions() bool {
	return r.options.ThirdParty != nil ||
		len(r.options.IncludeDomains) > 0 ||
		len(r.options.ExcludeDomains) > 0
}

func (r *Rule) checkOptions(rawURL string, ctx MatchContext) bool {
	lowerURL := strings.ToLower(rawURL)
	lowerCtx := MatchContext{PageDomain: strings.ToLower(ctx.PageDomain)}
	return r.checkOptionsLower(lowerURL, lowerCtx)
}

// checkOptionsLower evaluates context-dependent options using pre-lowercased
// URL and context to avoid redundant ToLower calls in hot paths.
func (r *Rule) checkOptionsLower(lowerURL string, ctx MatchContext) bool {
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

	return true
}

// domainMatchesOrIsSubdomain returns true if domain equals target
// or is a subdomain of target.
func domainMatchesOrIsSubdomain(domain, target string) bool {
	if domain == target {
		return true
	}
	return strings.HasSuffix(domain, "."+target)
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
