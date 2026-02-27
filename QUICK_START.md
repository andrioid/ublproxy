# Quick Start

## Run locally

```bash
go build -o ublproxy .
./ublproxy
```

## Run with Docker

```bash
docker build -t ublproxy .

docker run -d \
  -p 8080:8080 \
  -p 8443:8443 \
  -v ~/.ublproxy:/data \
  ublproxy
```

### docker-compose.yml

```yaml
services:
  ublproxy:
    build: .
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ublproxy-data:/data
    environment:
      - UBLPROXY_HOSTNAME=localhost
    restart: unless-stopped

volumes:
  ublproxy-data:
```

To use custom ports:

```yaml
services:
  ublproxy:
    build: .
    ports:
      - "6080:6080"
      - "6443:6443"
    volumes:
      - ublproxy-data:/data
    environment:
      - UBLPROXY_HTTP_PORT=6080
      - UBLPROXY_HTTPS_PORT=6443
      - UBLPROXY_HOSTNAME=proxy.local
    restart: unless-stopped

volumes:
  ublproxy-data:
```

## Ports

The proxy listens on two ports:

- **HTTP** (default `8080`) — Setup page and CA certificate download
- **HTTPS** (default `8443`) — Proxy, management portal, and API

EasyList and EasyPrivacy blocklists are enabled by default.

## Install the CA certificate

The proxy generates a CA certificate on first run. Your browser must trust this certificate for HTTPS filtering to work.

1. Visit `http://<host>:<http-port>/` (e.g. `http://localhost:8080/`) to download the CA certificate
2. Install and trust it on your platform — the setup page has detailed instructions for macOS, Linux, Windows, and Firefox
3. **Restart your browser** after trusting the certificate — browsers cache certificate trust state and won't pick up changes until restarted

When running with Docker, the CA certificate persists in the mounted `/data` volume. Download it from the HTTP setup page or copy it directly from the volume (`ca.crt`).

## Configure your browser

The setup page at `http://<host>:<http-port>/` provides a PAC (Proxy Auto-Configuration) URL that routes all external traffic through the proxy. Configure it in your browser or OS network settings.

Alternatively, set `https://<host>:<https-port>` as an HTTPS proxy manually.

## Custom rules

### 1. Register an account

Visit `https://<host>:<https-port>/` and register a passkey. No username or password — the passkey is your identity. Anyone on the network can register.

### 2. Pick elements to block

Browse any website through the proxy and press **Alt+Shift+B** to open the element picker.

1. **Hover** over an element — a red highlight shows what will be selected
2. **Click** to select it — the generated CSS selector appears in the panel
3. **Block element** saves the rule and immediately hides the element
4. **Escape** to deselect, or close the picker entirely

Rules are stored in SQLite and take effect on the next page load.

### 3. Manage rules via the API

All endpoints require a Bearer token from the login flow.

```bash
# List your rules
curl -s https://localhost:8443/api/rules \
  -H "Authorization: Bearer <token>"

# Create a rule
curl -s https://localhost:8443/api/rules \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"rule": "example.com##.ad-banner", "domain": "example.com"}'

# Disable a rule
curl -s https://localhost:8443/api/rules/1 \
  -X PATCH -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"enabled": false}'

# Delete a rule
curl -s https://localhost:8443/api/rules/1 \
  -X DELETE -H "Authorization: Bearer <token>"
```

Rules follow [adblock filter syntax](https://adblockplus.org/filter-cheatsheet). Element hiding rules use `domain##selector` format.

## Passthrough exceptions

Domains with a `@@` host-level exception rule are tunneled directly without MITM interception. The proxy relays encrypted bytes between client and upstream without seeing the traffic content. This is useful for sensitive sites like banking where you don't want the proxy to inspect traffic.

**Global exception** (in a blocklist file passed via `--blocklist`):

```
@@||bankofamerica.com^
@@||chase.com^
```

**Per-user exception** (via the portal UI or API):

```bash
curl -s https://localhost:8443/api/rules \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"rule": "@@||bankofamerica.com^"}'
```

Exception rules match the domain and all subdomains (e.g. `@@||bankofamerica.com^` also covers `www.bankofamerica.com`, `login.bankofamerica.com`, etc.).

Per-user exceptions only affect that user's traffic. Other users still get normal MITM filtering for the same domain unless they also add an exception.

## CLI flags and environment variables

All flags can also be set via environment variables. Environment variables take precedence over defaults but CLI flags take precedence over environment variables.

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--addr` | `UBLPROXY_ADDR` | `0.0.0.0` | Address to listen on |
| `--http-port` | `UBLPROXY_HTTP_PORT` | `8080` | HTTP port for setup page and CA certificate download |
| `--https-port` | `UBLPROXY_HTTPS_PORT` | `8443` | HTTPS port for proxy, portal, and API |
| `--hostname` | `UBLPROXY_HOSTNAME` | `localhost` | Portal hostname for WebAuthn and TLS cert (must be a domain, not an IP) |
| `--ca-dir` | `UBLPROXY_CA_DIR` | `~/.ublproxy` | Directory for CA certificate and key |
| `--db` | `UBLPROXY_DB` | `~/.ublproxy/ublproxy.db` | Path to SQLite database |
| `--blocklist` | `UBLPROXY_BLOCKLIST` | *(none)* | Path or URL to a blocklist file (repeatable) |
| `--default-subscription` | `UBLPROXY_DEFAULT_SUBSCRIPTION` | EasyList + EasyPrivacy | Default blocklist subscription URL, auto-provisioned per user on login (repeatable) |
