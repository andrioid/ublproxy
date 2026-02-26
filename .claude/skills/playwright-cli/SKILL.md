---
name: playwright-cli
description: Automates browser interactions for web testing, form filling, screenshots, and data extraction. Use when the user needs to navigate websites, interact with web pages, fill forms, take screenshots, test web applications, or extract information from web pages.
allowed-tools: Bash(playwright-cli:*)
---

# Browser Automation with playwright-cli

## Quick start

```bash
# Open a browser through the proxy (proxy must be running)
mise run browser -- https://example.is

# Open a browser without the proxy (for comparison)
mise run browser-no-proxy -- https://example.is

# Interact with the proxy session
playwright-cli -s=proxy snapshot
playwright-cli -s=proxy screenshot --filename=tmp/with-proxy.png

# Interact with the no-proxy session
playwright-cli -s=no-proxy snapshot
playwright-cli -s=no-proxy screenshot --filename=tmp/without-proxy.png
```

## Proxy testing workflow

### Prerequisites

The proxy must be running with a blocklist:

```bash
mise run dev -- --blocklist examples/is.rules
```

### 1. Open browser sessions

```bash
# Through the proxy (uses playwright-cli-proxy.json config for proxy + ignoreHTTPSErrors)
mise run browser -- https://example.is

# Without the proxy (for comparison)
mise run browser-no-proxy -- https://example.is
```

### 2. Find rules for the target domain

```bash
# Element hiding rules (##)
grep "example.is##" examples/is.rules

# URL blocking rules (||)
grep "||.*example" examples/is.rules

# Global element hiding rules
grep "^##" examples/is.rules
```

### 3. Verify element replacement

Matched elements are replaced with `<!-- ublproxy: replaced .selector -->` comments in the DOM:

```bash
playwright-cli -s=proxy eval "() => {
  const html = document.documentElement.innerHTML;
  const matches = html.match(/<!-- ublproxy: replaced [^>]+ -->/g);
  return { found: (matches || []).length, replacements: matches || [] };
}"
```

### 4. Verify CSS fallback injection

Complex selectors fall back to CSS `display: none` injection. Check for injected `<style>` tags:

```bash
playwright-cli -s=proxy eval "() => {
  const injected = [...document.querySelectorAll('style')].filter(s =>
    s.textContent.includes('display: none !important')
  );
  return {
    found: injected.length > 0,
    css: injected.map(s => s.textContent).join('')
  };
}"
```

### 5. Verify request blocking

Check network log for failed requests to blocked domains:

```bash
playwright-cli -s=proxy network
```

Requests to blocked domains should appear as failed. Compare with the no-proxy session:

```bash
playwright-cli -s=no-proxy network
```

### 6. Take comparison screenshots

```bash
playwright-cli -s=proxy screenshot --filename=tmp/with-proxy.png
playwright-cli -s=no-proxy screenshot --filename=tmp/without-proxy.png
```

### 7. Cleanup

```bash
playwright-cli -s=proxy close
playwright-cli -s=no-proxy close
```

## Commands

### Core

```bash
playwright-cli open [url]               # open browser, optionally navigate
playwright-cli goto <url>               # navigate to a url
playwright-cli close                    # close the browser
playwright-cli type <text>              # type text into editable element
playwright-cli click <ref>              # click an element
playwright-cli fill <ref> <text>        # fill text into editable element
playwright-cli hover <ref>              # hover over element
playwright-cli select <ref> <val>       # select dropdown option
playwright-cli check <ref>              # check a checkbox
playwright-cli uncheck <ref>            # uncheck a checkbox
playwright-cli snapshot                 # capture page snapshot (element refs)
playwright-cli eval <func> [ref]        # evaluate javascript
playwright-cli resize <w> <h>           # resize browser window
```

### Navigation

```bash
playwright-cli go-back
playwright-cli go-forward
playwright-cli reload
```

### Keyboard and mouse

```bash
playwright-cli press <key>              # press a key (Enter, ArrowDown, etc.)
playwright-cli keydown <key>
playwright-cli keyup <key>
playwright-cli mousemove <x> <y>
playwright-cli mousedown [button]
playwright-cli mouseup [button]
playwright-cli mousewheel <dx> <dy>
```

### Save as

```bash
playwright-cli screenshot               # screenshot of current page
playwright-cli screenshot <ref>         # screenshot of element
playwright-cli screenshot --filename=f  # save to specific file
playwright-cli pdf --filename=page.pdf  # save page as pdf
```

### Tabs

```bash
playwright-cli tab-list
playwright-cli tab-new [url]
playwright-cli tab-close [index]
playwright-cli tab-select <index>
```

### Network

```bash
playwright-cli route <pattern>          # mock network requests
playwright-cli route-list               # list active routes
playwright-cli unroute [pattern]        # remove routes
playwright-cli network                  # list all network requests
```

### DevTools

```bash
playwright-cli console [min-level]      # list console messages
playwright-cli run-code <code>          # run playwright code snippet
playwright-cli tracing-start            # start trace recording
playwright-cli tracing-stop             # stop trace recording
```

### Sessions

```bash
playwright-cli -s=name <cmd>            # run command in named session
playwright-cli list                     # list all sessions
playwright-cli close-all                # close all browsers
playwright-cli kill-all                 # forcefully kill all browsers
```

### Open parameters

```bash
playwright-cli open --browser=chrome    # use specific browser
playwright-cli open --config=file.json  # use config file
playwright-cli open --persistent        # persist browser profile to disk
playwright-cli open --profile=<path>    # custom profile directory
```

## Snapshots

After each command, playwright-cli provides a snapshot of the current browser state with element refs (e.g. `e3`, `e15`) that can be used with `click`, `fill`, and other commands.

```bash
> playwright-cli -s=proxy goto https://example.is
### Page
- Page URL: https://example.is/
- Page Title: Example
### Snapshot
[Snapshot](.playwright-cli/page-2026-02-26T10-00-00-000Z.yml)
```

## Troubleshooting

- **"proxy is not running"** -- start the proxy first with `mise run dev -- --blocklist examples/is.rules`
- **HTTPS timeouts** -- the proxy config (`playwright-cli-proxy.json`) sets `ignoreHTTPSErrors: true`. Verify the config file exists and is passed via `--config`.
- **Navigation timeout** -- the target site may be down. Try `curl --max-time 5 https://example.is` to verify.
- **Cloudflare challenge** -- some sites block headless browsers. The page title will be "Just a moment...". Try a different site.
- **No element replacements** -- the page may use zstd compression (not yet supported) or the selectors may no longer match the current site markup.
- **Stale sessions** -- if browsers become unresponsive, run `playwright-cli kill-all`.
