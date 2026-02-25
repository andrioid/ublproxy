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

// Rule represents a compiled adblock filter pattern.
type Rule struct {
	segments     []segment
	anchorStart  bool      // |  at start: must match beginning of URL
	anchorEnd    bool      // |  at end: must match end of URL
	domainAnchor bool      // || at start: must match at domain boundary
	domainSuffix string    // the domain part after || (e.g. "example.com")
	pathPattern  []segment // the pattern after the domain part (e.g. "/ads/*.gif")
}

// Compile parses an adblock filter pattern string into a Rule.
func Compile(pattern string) (*Rule, error) {
	if pattern == "" {
		return nil, errors.New("empty pattern")
	}

	r := &Rule{}

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

	r.segments = compileSegments(pattern)
	return r, nil
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
		r.pathPattern = compileSegments(rest)
	}

	return r, nil
}

func compileSegments(pattern string) []segment {
	// Case-insensitive: lowercase the pattern (we'll lowercase the URL during match)
	pattern = strings.ToLower(pattern)

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

// Match reports whether the rule matches the given URL.
func (r *Rule) Match(rawURL string) bool {
	url := strings.ToLower(rawURL)

	if r.domainAnchor {
		return r.matchDomainAnchor(url)
	}

	if r.anchorStart {
		return matchSegments(r.segments, url, r.anchorEnd)
	}

	// No start anchor: try matching at every position
	for i := range len(url) {
		if matchSegments(r.segments, url[i:], r.anchorEnd) {
			return true
		}
	}
	return false
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
				if anchorEnd {
					return true
				}
				return true
			}
			// Try matching the rest of the pattern at every position
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
