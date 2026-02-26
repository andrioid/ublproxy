---
name: proxy-test
description: Verify ublproxy ad-blocking behavior by comparing responses with and without the proxy using curl. Use when the user asks to test, verify, or compare proxy behavior against a website.
allowed-tools: Bash(curl:*), Bash(mise:*), Bash(diff:*)
---

# Verifying Proxy Behavior with curl

Test ublproxy's ad-blocking (request blocking, element replacement, and CSS fallback injection) by comparing curl responses with and without the proxy.

## Prerequisites

The proxy must be running with a blocklist:

```bash
# Start the proxy with adblock rules
mise run dev -- --blocklist examples/is.rules
```

## Verification workflow

### 1. Find rules for the target domain

Before testing, check what rules the blocklist has for the target domain:

```bash
# Element hiding rules (##)
grep "example.is##" examples/is.rules

# URL blocking rules (||)
grep "||.*example" examples/is.rules

# Global element hiding rules (apply to all domains)
grep "^##" examples/is.rules
```

### 2. Verify request blocking

Blocked hostnames return 403 for HTTPS (CONNECT) requests:

```bash
curl -v --proxy http://127.0.0.1:8080 -k https://blocked-domain.com 2>&1 | grep "< HTTP"
# Expected: HTTP/1.1 403 Forbidden
```

### 3. Verify element replacement

Matched elements are replaced with `<!-- ublproxy: replaced .selector -->` comments. Check for them in the HTML output:

```bash
curl -s --proxy http://127.0.0.1:8080 -k https://example.is | grep 'ublproxy: replaced'
```

### 4. Verify CSS fallback injection

Complex selectors that can't be matched on a single element fall back to CSS `display: none` injection. Check for the injected style tag:

```bash
curl -s --proxy http://127.0.0.1:8080 -k https://example.is | grep 'display: none'
```

### 5. Compare proxy vs direct

Save responses and diff them to see exactly what the proxy changed:

```bash
curl -s --proxy http://127.0.0.1:8080 -k https://example.is > tmp/with-proxy.html
curl -s https://example.is --compressed > tmp/without-proxy.html
diff tmp/without-proxy.html tmp/with-proxy.html
```

## Example: testing against an Icelandic site

```bash
# Terminal 1: start proxy
mise run dev -- --blocklist examples/is.rules

# Terminal 2: check what rules apply
grep "1819.is" examples/is.rules

# Compare responses
curl -s --proxy http://127.0.0.1:8080 -k https://1819.is > tmp/with-proxy.html
curl -s https://1819.is --compressed > tmp/without-proxy.html

# Check for element replacements
grep 'ublproxy: replaced' tmp/with-proxy.html

# Check for CSS fallback injection
grep 'display: none' tmp/with-proxy.html

# Diff to see all changes
diff tmp/without-proxy.html tmp/with-proxy.html
```

## Troubleshooting

- **"proxy is not running"** — start the proxy first with `mise run dev -- --blocklist examples/is.rules`
- **Connection refused** — verify the proxy is listening: `curl --proxy http://127.0.0.1:8080 http://example.com`
- **No element replacements or CSS injection** — the page may not be HTML, or the response may use zstd compression (not yet supported). Check `Content-Encoding` with `curl -D-`.
- **Elements not found** — the site may have been redesigned since the blocklist rules were written. The selectors may no longer match anything in the server-rendered HTML (some elements are only added by JavaScript at runtime).
