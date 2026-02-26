# Contributing to ublproxy

## Prerequisites

- [Mise](https://mise.jdx.dev) (recommended) — manages Go version and project tasks
- Go 1.25 or later (installed automatically by Mise, or manually)

Dependencies are minimal — see `go.mod`.

## Getting started with Mise

Mise handles tool installation and provides project tasks. After [installing Mise](https://mise.jdx.dev/getting-started.html), run:

```sh
mise install    # installs Go 1.25
mise run build  # build the binary
mise run test   # run all tests
mise run dev    # build and start the proxy
```

Pass flags through to the underlying command with `--`:

```sh
mise run dev -- --port 9090
mise run test -- -v -run TestPortal
```

The scripts in `scripts/` are also runnable directly without Mise.

## Building

```sh
mise run build
# or directly:
go build -o ublproxy .
```

This produces the `ublproxy` binary in the project root.

## Running

```sh
mise run dev
# or directly:
./ublproxy [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--addr` | `127.0.0.1` | Address to listen on |
| `--port` | `8080` | Port to listen on |
| `--ca-dir` | `~/.ublproxy/` | Directory for CA certificate and key |
| `--blocklist` | *(none)* | Path to a blocklist file (can be specified multiple times) |

On first run, a CA certificate and key are generated in the `--ca-dir` directory. You need to trust the CA certificate (`ca.crt`) in your OS or browser for HTTPS interception to work without warnings.

### Manual testing with curl

Start the proxy with a blocklist, then use curl to verify behaviour:

```sh
# Terminal 1: start the proxy
mise run dev -- --blocklist examples/is.rules
```

```sh
# Plain HTTP
curl --proxy http://127.0.0.1:8080 http://example.com

# HTTPS (trusting the generated CA)
curl --proxy http://127.0.0.1:8080 --cacert ~/.ublproxy/ca.crt https://example.com

# HTTPS (skip certificate verification — quick and dirty)
curl --proxy http://127.0.0.1:8080 -k https://example.com
```

### Verifying request blocking

Blocked hostnames return 403 for HTTPS (CONNECT) requests:

```sh
curl -v --proxy http://127.0.0.1:8080 -k https://ads.example.com 2>&1 | grep "< HTTP"
# Expected: HTTP/1.1 403 Forbidden
```

### Verifying element replacement

Matched elements are replaced with `<!-- ublproxy: replaced .selector -->` comments. Check for them in the HTML output:

```sh
curl -s --proxy http://127.0.0.1:8080 -k https://some-site.com \
  | grep 'ublproxy: replaced'
```

### Verifying CSS fallback

Complex selectors that can't be matched on a single element fall back to CSS `display: none` injection. Check for the injected style tag:

```sh
curl -s --proxy http://127.0.0.1:8080 -k https://some-site.com \
  | grep 'display: none'
```

### Comparing proxy vs direct

```sh
# Through the proxy
curl -s --proxy http://127.0.0.1:8080 -k https://some-site.com > tmp/with-proxy.html

# Direct
curl -s https://some-site.com --compressed > tmp/without-proxy.html

diff tmp/without-proxy.html tmp/with-proxy.html
```

### Combining blocklists

```sh
mise run dev -- --blocklist examples/is.rules --blocklist examples/dk.rules
```

## Testing

```sh
mise run test
# or directly:
go test ./...
```

### Browser testing

For visual verification of proxy behavior in a real browser, use `playwright-cli` (installed via mise):

```sh
# Terminal 1: start the proxy
mise run dev -- --blocklist examples/is.rules

# Terminal 2: open a browser through the proxy
mise run browser -- https://example.is

# Terminal 2: open a browser without the proxy (for comparison)
mise run browser-no-proxy -- https://example.is
```

The proxy session uses `playwright-cli-proxy.json` which configures the proxy address and ignores HTTPS certificate errors from the MITM CA.

Interact with sessions using `playwright-cli -s=proxy <command>` or `playwright-cli -s=no-proxy <command>`:

```sh
# Take comparison screenshots
playwright-cli -s=proxy screenshot --filename=tmp/with-proxy.png
playwright-cli -s=no-proxy screenshot --filename=tmp/without-proxy.png

# Check for element replacements in the DOM
playwright-cli -s=proxy eval "document.documentElement.innerHTML.match(/<!-- ublproxy: replaced [^>]+ -->/g)"

# Close sessions when done
playwright-cli close-all
```

For verbose output:

```sh
mise run test -- -v
# or directly:
go test -v ./...
```

Tests are fully self-contained — they spin up in-memory CA certificates, local upstream HTTP/HTTPS servers, and a proxy instance per test. No network access or external services required.

## Project structure

Proxy code lives in `package main` in the project root. The `pkg/` directory contains reusable packages.

| File | Responsibility |
|---|---|
| `main.go` | CLI flag parsing, startup |
| `ca.go` | CA certificate loading, generation, and persistence to disk |
| `cert.go` | Per-host TLS certificate generation and in-memory cache |
| `proxy.go` | Top-level HTTP handler, dispatches to HTTP or CONNECT handler |
| `http.go` | Plain HTTP request forwarding, hop-by-hop header stripping |
| `connect.go` | CONNECT method handling, TLS MITM, request forwarding |
| `elemhide_inject.go` | HTML element replacement and CSS fallback injection |
| `portal.go` | Direct-access page with CA cert download and install instructions |
| `log.go` | Request and error logging to stderr |
| `proxy_test.go` | End-to-end tests for both HTTP and HTTPS proxy flows |
| `pkg/blocklist/` | Blocklist parsing (adblock + hosts-file), hostname matching, element hiding |
| `scripts/build` | Build task |
| `scripts/test` | Test task |
| `scripts/dev` | Build + run task for development |

## Code style

- Functional style over object-oriented
- Early returns, no `if/else` chains
- Descriptive names using domain wording
- Comments explain *why*, not *what*
- Minimal dependencies — warranted additions only
