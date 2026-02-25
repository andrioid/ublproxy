---
name: proxy-test
description: Verify ublproxy ad-blocking behavior by comparing browser sessions with and without the proxy. Use when the user asks to test, verify, or compare proxy behavior against a website.
allowed-tools: Bash(playwright-cli:*), Bash(mise:*), Bash(curl:*), Bash(grep:*)
---

# Verifying Proxy Behavior with Playwright

Test ublproxy's ad-blocking (request blocking + element hiding CSS injection) by comparing two browser sessions: one routed through the proxy and one without.

## Prerequisites

The proxy must be running with a blocklist before opening the browser:

```bash
# Start the proxy with the Icelandic adblock rules
mise run dev -- --blocklist examples/is.rules
```

## Opening browsers

Open two named browser sessions — one through the proxy, one without:

```bash
# Through the proxy (requires proxy to be running)
mise run browser -- https://example.is

# Without the proxy (for comparison)
mise run browser-no-proxy -- https://example.is
```

The `proxy` session routes all traffic through `http://127.0.0.1:8080` and ignores HTTPS certificate errors (so the proxy's MITM certificates are accepted without trusting the CA).

After opening, interact with either session using `playwright-cli -s=proxy <command>` or `playwright-cli -s=no-proxy <command>`.

## Verification workflow

### 1. Find rules for the target domain

Before testing, check what rules the blocklist has for the target domain:

```bash
# Element hiding rules (##)
grep "example.is##" examples/is.rules

# URL blocking rules (||)
grep "||.*example.is" examples/is.rules

# Global element hiding rules (apply to all domains)
grep "^##" examples/is.rules
```

### 2. Verify CSS injection

The proxy injects a `<style>` tag into HTML responses containing `display: none !important` rules. Check that it exists:

```bash
# With proxy — should find injected style tag
playwright-cli -s=proxy eval "() => {
  const injected = [...document.querySelectorAll('style')].filter(s =>
    s.textContent.includes('display: none !important')
  );
  return {
    found: injected.length > 0,
    css: injected.map(s => s.textContent).join('')
  };
}"

# Without proxy — should find nothing
playwright-cli -s=no-proxy eval "() => {
  const injected = [...document.querySelectorAll('style')].filter(s =>
    s.textContent.includes('display: none !important')
  );
  return { found: injected.length > 0 };
}"
```

### 3. Verify element hiding

Using the selectors found in step 1, check that targeted elements are hidden. For each domain-specific element hiding rule like `example.is##.ad-banner`, check the selector:

```bash
playwright-cli -s=proxy eval "() => {
  const selector = '.ad-banner';
  const els = document.querySelectorAll(selector);
  return {
    selector,
    count: els.length,
    allHidden: [...els].every(el =>
      window.getComputedStyle(el).display === 'none'
    )
  };
}"
```

If `count` is 0, the element doesn't exist on the page (the site may have been redesigned since the rules were written). If `count` > 0 and `allHidden` is true, the proxy is successfully hiding them.

### 4. Verify request blocking

Check the network log for failed requests to blocked domains:

```bash
playwright-cli -s=proxy network
```

Requests to domains matching `||` rules in the blocklist (e.g. `openad.visir.is`, `kynning.olis.is`) should appear as failed. Compare with the no-proxy session where the same requests succeed:

```bash
playwright-cli -s=no-proxy network
```

### 5. Take comparison screenshots

```bash
playwright-cli -s=proxy screenshot --filename=tmp/with-proxy.png
playwright-cli -s=no-proxy screenshot --filename=tmp/without-proxy.png
```

## Cleanup

```bash
playwright-cli -s=proxy close
playwright-cli -s=no-proxy close
```

## Example: testing against 1819.is

```bash
# Terminal 1: start proxy
mise run dev -- --blocklist examples/is.rules

# Terminal 2: open browsers
mise run browser -- https://1819.is
mise run browser-no-proxy -- https://1819.is

# Check what rules apply
grep "1819.is" examples/is.rules
# 1819.is##.augl-wrapper
# 1819.is##.side-augl-wrapper
# 1819.is##.augl.augl-size-1018

# Verify injection in proxy session
playwright-cli -s=proxy eval "() => {
  const injected = [...document.querySelectorAll('style')].filter(s =>
    s.textContent.includes('display: none !important')
  );
  return { found: injected.length > 0, css: injected.map(s => s.textContent).join('') };
}"

# Verify no injection without proxy
playwright-cli -s=no-proxy eval "() => {
  return [...document.querySelectorAll('style')].filter(s =>
    s.textContent.includes('display: none !important')
  ).length;
}"

# Compare screenshots
playwright-cli -s=proxy screenshot --filename=tmp/1819-with-proxy.png
playwright-cli -s=no-proxy screenshot --filename=tmp/1819-without-proxy.png

# Cleanup
playwright-cli -s=proxy close
playwright-cli -s=no-proxy close
```

## Troubleshooting

- **"proxy is not running"** — start the proxy first with `mise run dev -- --blocklist examples/is.rules`
- **Navigation timeout** — the target site may be down. Try `curl --max-time 5 https://example.is` to verify reachability.
- **Cloudflare challenge page** — some sites (e.g. mbl.is) block headless browsers. The page title will be "Just a moment...". Try a different site or use `--headed` mode.
- **No injected style tag** — the page may not be HTML, or the response may use zstd compression (not yet supported for injection).
- **Elements not found** — the site may have been redesigned since the blocklist rules were written. The CSS is still injected, but the selectors no longer match anything.
