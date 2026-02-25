package blocklist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// RuleSet holds blocking rules for URL filtering. It combines a hostname map
// (fast path for ||hostname^ rules) with compiled URL pattern rules.
// Exception rules (@@) override blocking rules when they match.
// Element hiding rules (##) provide CSS selectors to hide page elements.
type RuleSet struct {
	hosts         map[string]struct{}
	rules         []*Rule
	exceptions    []*Rule
	elemHideRules []*ElementHideRule
	elemHideIdx   *elemHideIndex
}

func NewRuleSet() *RuleSet {
	return &RuleSet{
		hosts:       make(map[string]struct{}),
		elemHideIdx: newElemHideIndex(),
	}
}

// AddHostname adds a hostname to the fast-path blocklist.
// Matches the hostname and all its subdomains.
func (rs *RuleSet) AddHostname(host string) {
	rs.hosts[strings.ToLower(host)] = struct{}{}
}

// AddException compiles an adblock exception pattern (with or without @@
// prefix) and adds it to the exception list. Exception rules override
// blocking rules when they match a URL.
func (rs *RuleSet) AddException(pattern string) error {
	pattern = strings.TrimPrefix(pattern, "@@")
	rule, err := Compile(pattern)
	if err != nil {
		return err
	}
	rs.exceptions = append(rs.exceptions, rule)
	return nil
}

// AddRule compiles an adblock URL pattern and adds it to the rule list.
// Returns an error if the pattern is invalid.
func (rs *RuleSet) AddRule(pattern string) error {
	rule, err := Compile(pattern)
	if err != nil {
		return err
	}
	rs.rules = append(rs.rules, rule)
	return nil
}

// LoadFile reads a blocklist file and adds all parsed rules.
// Hostname-only rules go to the fast path; URL patterns become compiled rules.
func (rs *RuleSet) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open blocklist %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rs.AddLine(scanner.Text())
	}
	return scanner.Err()
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

	// Exception rules (@@)
	if strings.HasPrefix(line, "@@") {
		rs.AddException(line)
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

	// Strip options after $ for now (Phase 3 will handle them)
	rawPattern := line
	if idx := strings.IndexByte(rawPattern, '$'); idx >= 0 {
		rawPattern = rawPattern[:idx]
	}

	// Try to extract a hostname-only rule for the fast path
	if host, ok := extractHostnameRule(rawPattern); ok {
		rs.AddHostname(host)
		return
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

	// Compile as a URL pattern rule
	rule, err := Compile(rawPattern)
	if err != nil {
		return // skip invalid patterns silently
	}
	rs.rules = append(rs.rules, rule)
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
// Safe to call on a nil receiver (returns false).
func (rs *RuleSet) ShouldBlockRequest(rawURL string, ctx MatchContext) bool {
	if rs == nil {
		return false
	}

	blocked := false

	// Fast path: check hostname against the hostname map
	url := strings.ToLower(rawURL)
	host := extractHostFromURL(url)
	if rs.isHostBlocked(host) {
		blocked = true
	}

	// Slow path: check URL against compiled pattern rules
	if !blocked {
		for _, rule := range rs.rules {
			if rule.MatchWithContext(rawURL, ctx) {
				blocked = true
				break
			}
		}
	}

	if !blocked {
		return false
	}

	// Check if any exception rule allows this URL
	for _, exc := range rs.exceptions {
		if exc.MatchWithContext(rawURL, ctx) {
			return false
		}
	}

	return true
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

// RuleCount returns the number of compiled URL pattern rules.
func (rs *RuleSet) RuleCount() int {
	if rs == nil {
		return 0
	}
	return len(rs.rules)
}
