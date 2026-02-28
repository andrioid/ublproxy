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
mise run dev -- --https-port 9090
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

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--addr` | `UBLPROXY_ADDR` | `0.0.0.0` | Address to listen on |
| `--http-port` | `UBLPROXY_HTTP_PORT` | `8080` | HTTP port for setup page, CA certificate download, and mobile proxy |
| `--https-port` | `UBLPROXY_HTTPS_PORT` | `8443` | HTTPS port for proxy, portal, and API |
| `--hostname` | `UBLPROXY_HOSTNAME` | `localhost` | Portal hostname for WebAuthn and TLS cert (must be a domain, not an IP) |
| `--ca-dir` | `UBLPROXY_CA_DIR` | `~/.ublproxy/` | Directory for CA certificate and key |
| `--db` | `UBLPROXY_DB` | `~/.ublproxy/ublproxy.db` | Path to SQLite database |
| `--blocklist` | `UBLPROXY_BLOCKLIST` | *(none)* | Path or URL to a blocklist file (repeatable, comma-separated in env var) |
| `--transparent` | `UBLPROXY_TRANSPARENT` | `false` | Run in transparent proxy mode (intercept redirected traffic) |

On first run, a CA certificate and key are generated in the `--ca-dir` directory. You need to trust the CA certificate (`ca.crt`) in your OS or browser for HTTPS interception to work without warnings. Restart your browser after trusting the certificate.

### Manual testing with curl

Start the proxy with a blocklist, then use curl to verify behaviour:

```sh
# Terminal 1: start the proxy
mise run dev -- --blocklist examples/is.rules
```

```sh
# HTTPS (trusting the generated CA)
curl --proxy https://127.0.0.1:8443 --proxy-cacert ~/.ublproxy/ca.crt --cacert ~/.ublproxy/ca.crt https://example.com

# HTTPS (skip certificate verification — quick and dirty)
curl --proxy https://127.0.0.1:8443 --proxy-insecure -k https://example.com

# Mobile proxy (plain HTTP CONNECT — how iOS/Android connect)
curl --proxy http://127.0.0.1:8080 --cacert ~/.ublproxy/ca.crt https://example.com

# Fetch the mobile PAC file
curl http://127.0.0.1:8080/mobile.pac
```

### Verifying request blocking

Blocked hostnames return 403 for HTTPS (CONNECT) requests:

```sh
curl -v --proxy https://127.0.0.1:8443 --proxy-insecure -k https://ads.example.com 2>&1 | grep "< HTTP"
# Expected: HTTP/1.1 403 Forbidden
```

### Verifying element hiding

Element hiding uses CSS injection (`display: none !important`). Check for the injected style tag:

```sh
curl -s --proxy https://127.0.0.1:8443 --proxy-insecure -k https://some-site.com \
  | grep 'display: none'
```

### Comparing proxy vs direct

```sh
# Through the proxy
curl -s --proxy https://127.0.0.1:8443 --proxy-insecure -k https://some-site.com > tmp/with-proxy.html

# Direct
curl -s https://some-site.com --compressed > tmp/without-proxy.html

diff tmp/without-proxy.html tmp/with-proxy.html
```

### Combining blocklists

```sh
mise run dev -- --blocklist examples/is.rules --blocklist examples/dk.rules
```

### Using remote blocklists

The `--blocklist` flag accepts URLs. Lists are downloaded once at startup (5-second timeout).

```sh
mise run dev -- --blocklist https://easylist.to/easylist/easylist.txt --blocklist examples/dk.rules
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

# Check for element hiding CSS in the page
playwright-cli -s=proxy eval "[...document.querySelectorAll('style')].map(s => s.textContent).filter(t => t.includes('display: none'))"

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

Proxy code lives in `package main` in the project root. The `internal/` directory contains packages that are internal to the application.

```mermaid
graph TB
    subgraph Main["package main (project root)"]
        direction TB
        MAIN["main.go<br/><i>CLI, wiring, startup</i>"]
        PROXY["proxy.go<br/><i>Rule loading, request dispatch</i>"]
        CONN["connect.go<br/><i>CONNECT, TLS MITM</i>"]
        HTTP["http.go<br/><i>HTTP forwarding</i>"]
        TRANS["transparent.go<br/><i>Transparent proxy, SNI, captive portal</i>"]
        PORTAL["portal.go / portal_https.go<br/><i>Portal UI, setup wizard</i>"]
        API["api*.go<br/><i>REST API, WebAuthn, rules, subscriptions</i>"]
        INJECT["elemhide_inject.go / inject.go<br/><i>CSS + script injection</i>"]
    end

    subgraph Internal["internal/"]
        BL["blocklist/<br/><i>Adblock parsing, matching,<br/>element hiding, resource types</i>"]
        CA["ca/<br/><i>CA generation, cert cache</i>"]
        ST["store/<br/><i>SQLite persistence</i>"]
        WA["webauthn/<br/><i>Minimal WebAuthn server</i>"]
        MC["mobileconfig/<br/><i>Apple .mobileconfig profiles</i>"]
    end

    subgraph Static["static/ (go:embed)"]
        UI["portal.html, rules.html,<br/>subscriptions.html, activity.html,<br/>users.html, setup.html"]
        JS["bootstrap.js, picker.js,<br/>shared.js"]
        CSS["shared.css"]
    end

    MAIN --> PROXY
    PROXY --> CONN
    PROXY --> HTTP
    PROXY --> TRANS
    PROXY --> INJECT
    MAIN --> PORTAL
    MAIN --> API

    PROXY --> BL
    PROXY --> ST
    CONN --> CA
    TRANS --> CA
    API --> WA
    API --> ST
    PORTAL --> MC
```

| File | Responsibility |
|---|---|
| `main.go` | CLI flag parsing, wiring, startup (explicit vs transparent mode) |
| `proxy.go` | Proxy handler, baseline/per-user rule loading, request dispatch |
| `http.go` | Plain HTTP request forwarding, hop-by-hop header stripping |
| `connect.go` | CONNECT method handling, TLS MITM, passthrough tunneling |
| `transparent.go` | Transparent proxy: SNI extraction, captive portal, trust tracking |
| `portal.go` | Portal, setup page, mobile PAC, and QR code serving (embeds static HTML) |
| `portal_https.go` | HTTPS listener, TLS termination, request routing |
| `api.go` | API handler, routing, CORS, and auth middleware |
| `api_auth.go` | WebAuthn registration and login API endpoints |
| `api_rules.go` | Per-user blocking rule CRUD API |
| `api_subscriptions.go` | Per-user blocklist subscription API |
| `api_activity.go` | Activity log API (recent events and stats) |
| `api_users.go` | Admin user management API |
| `activity.go` | In-memory activity log ring buffer |
| `elemhide_inject.go` | Element hiding CSS injection into HTML responses |
| `inject.go` | Bootstrap script and picker injection into HTML responses |
| `websocket.go` | WebSocket upgrade detection and tunnel support |
| `session_map.go` | Client IP to session/credential mapping |
| `log.go` | Request and error logging to stderr |
| `internal/blocklist/` | Blocklist parsing (adblock + hosts-file), hostname matching, element hiding, resource type detection |
| `internal/ca/` | CA certificate generation, loading, per-host cert cache |
| `internal/store/` | SQLite persistence for credentials, sessions, rules, subscriptions, and cache |
| `internal/webauthn/` | Minimal WebAuthn server (ES256/P-256 with "none" attestation) |
| `internal/mobileconfig/` | Apple .mobileconfig profile generation |
| `static/` | Embedded HTML, CSS, JS for portal UI, setup wizard, element picker |

## Code style

- Functional style over object-oriented
- Early returns, no `if/else` chains
- Descriptive names using domain wording
- Comments explain *why*, not *what*
- Minimal dependencies — warranted additions only
