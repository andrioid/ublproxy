# Contributing to ublproxy

## Prerequisites

- [Mise](https://mise.jdx.dev) (recommended) — manages Go version and project tasks
- Go 1.25 or later (installed automatically by Mise, or manually)

No third-party dependencies — the project uses only the Go standard library.

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

On first run, a CA certificate and key are generated in the `--ca-dir` directory. You need to trust the CA certificate (`ca.crt`) in your OS or browser for HTTPS interception to work without warnings.

### Manual testing with curl

```sh
# Plain HTTP
curl --proxy http://127.0.0.1:8080 http://example.com

# HTTPS (trusting the generated CA)
curl --proxy http://127.0.0.1:8080 --cacert ~/.ublproxy/ca.crt https://example.com
```

## Testing

```sh
mise run test
# or directly:
go test ./...
```

For verbose output:

```sh
mise run test -- -v
# or directly:
go test -v ./...
```

Tests are fully self-contained — they spin up in-memory CA certificates, local upstream HTTP/HTTPS servers, and a proxy instance per test. No network access or external services required.

## Project structure

All code lives in `package main` in the project root. Files are split by responsibility:

| File | Responsibility |
|---|---|
| `main.go` | CLI flag parsing, startup |
| `ca.go` | CA certificate loading, generation, and persistence to disk |
| `cert.go` | Per-host TLS certificate generation and in-memory cache |
| `proxy.go` | Top-level HTTP handler, dispatches to HTTP or CONNECT handler |
| `http.go` | Plain HTTP request forwarding, hop-by-hop header stripping |
| `connect.go` | CONNECT method handling, TLS MITM, request forwarding |
| `portal.go` | Direct-access page with CA cert download and install instructions |
| `log.go` | Request and error logging to stderr |
| `proxy_test.go` | End-to-end tests for both HTTP and HTTPS proxy flows |
| `scripts/build` | Build task |
| `scripts/test` | Test task |
| `scripts/dev` | Build + run task for development |

## Code style

- Functional style over object-oriented
- Early returns, no `if/else` chains
- Descriptive names using domain wording
- Comments explain *why*, not *what*
- No third-party dependencies unless strongly warranted
