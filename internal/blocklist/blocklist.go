package blocklist

import "strings"

func parseHostsFileLine(line string) (string, bool) {
	// Must start with a known loopback prefix
	if !strings.HasPrefix(line, "0.0.0.0 ") && !strings.HasPrefix(line, "127.0.0.1 ") {
		return "", false
	}

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
