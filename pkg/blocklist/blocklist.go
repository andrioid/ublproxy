package blocklist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Blocklist struct {
	hosts map[string]struct{}
}

func New() *Blocklist {
	return &Blocklist{hosts: make(map[string]struct{})}
}

func (b *Blocklist) Add(host string) {
	b.hosts[host] = struct{}{}
}

// LoadFile reads a blocklist file and adds all parsed hostnames.
// Supports adblock-style (||host^) and hosts-file formats.
func (b *Blocklist) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open blocklist %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if host, ok := ParseLine(scanner.Text()); ok {
			b.Add(host)
		}
	}

	return scanner.Err()
}

// IsBlocked returns true if the host or any of its parent domains are in the
// blocklist. Safe to call on a nil receiver (returns false).
func (b *Blocklist) IsBlocked(host string) bool {
	if b == nil {
		return false
	}

	// Walk up domain segments: "a.b.c.com" -> "b.c.com" -> "c.com" -> "com"
	for {
		if _, ok := b.hosts[host]; ok {
			return true
		}
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			return false
		}
		host = host[dot+1:]
	}
}

// Len returns the number of hostnames in the blocklist.
func (b *Blocklist) Len() int {
	if b == nil {
		return 0
	}
	return len(b.hosts)
}

// ParseLine parses a single line from a blocklist file. Returns the hostname
// and true if the line is a valid hostname block rule, or ("", false) if the
// line should be skipped.
func ParseLine(line string) (string, bool) {
	line = strings.TrimSpace(line)

	if line == "" {
		return "", false
	}

	// Comments
	if line[0] == '!' || line[0] == '#' {
		return "", false
	}

	// Adblock header
	if line[0] == '[' {
		return "", false
	}

	// Exception rules (not supported yet)
	if strings.HasPrefix(line, "@@") {
		return "", false
	}

	// Element hiding / snippet filters
	if strings.Contains(line, "##") || strings.Contains(line, "#$#") || strings.Contains(line, "#?#") || strings.Contains(line, "#@#") {
		return "", false
	}

	// Adblock domain anchor: ||hostname^
	if strings.HasPrefix(line, "||") {
		return parseAdblockDomainAnchor(line)
	}

	// Hosts-file format: "0.0.0.0 hostname" or "127.0.0.1 hostname"
	if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
		return parseHostsFileLine(line)
	}

	// IPv6 loopback in hosts files
	if strings.HasPrefix(line, "::1 ") {
		return "", false
	}

	// URL pattern rules (contains / but no ||)
	if strings.ContainsAny(line, "/*") {
		return "", false
	}

	// Plain hostname (one per line)
	if isValidHostname(line) {
		return line, true
	}

	return "", false
}

func parseAdblockDomainAnchor(line string) (string, bool) {
	// Strip "||" prefix
	host := line[2:]

	// Strip options after $
	if idx := strings.IndexByte(host, '$'); idx >= 0 {
		host = host[:idx]
	}

	// Must end with ^ (separator) for a hostname-only rule
	if !strings.HasSuffix(host, "^") {
		return "", false
	}
	host = host[:len(host)-1]

	// If it contains a path separator, it's a URL pattern, not hostname-only
	if strings.ContainsAny(host, "/:") {
		return "", false
	}

	if !isValidHostname(host) {
		return "", false
	}

	return host, true
}

func parseHostsFileLine(line string) (string, bool) {
	// Strip inline comments
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}

	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", false
	}

	host := fields[1]

	// Skip loopback/local entries that aren't real block rules
	if host == "localhost" || host == "local" || host == "0.0.0.0" || host == "broadcasthost" {
		return "", false
	}

	if !isValidHostname(host) {
		return "", false
	}

	return host, true
}

// isValidHostname does a basic check that the string looks like a domain name.
func isValidHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}

	// Must contain at least one dot (to be a real domain, not "localhost")
	if !strings.Contains(s, ".") {
		return false
	}

	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}

	return true
}
