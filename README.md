# ublproxy

A proxy-server that filters ads from HTTPS/TLS traffic using adblock rules, with interactive element picking for custom rules.

## Quick start

```bash
# Build
go build -o ublproxy .

# Run (EasyList + EasyPrivacy enabled by default)
./ublproxy
```

The proxy runs on two ports:

- **HTTP `http://0.0.0.0:8080`** — Setup page and CA certificate download
- **HTTPS `https://0.0.0.0:8443`** — Proxy, management portal, and API

Configure your browser or OS to use `https://127.0.0.1:8443` as an HTTPS proxy.

### CA certificate

The proxy generates a CA certificate to intercept HTTPS traffic. Visit `http://127.0.0.1:8080/` in your browser to download and install the CA certificate. Your browser/OS must trust this certificate for HTTPS filtering to work.

## Custom rules

ublproxy supports interactive element picking. You can visually select ad elements on any webpage and create blocking rules that persist across sessions.

### 1. Register an account

Visit `https://127.0.0.1:8443/` in your browser and register a passkey. No username or password needed — the passkey **is** your identity. Anyone on the local network can register.

Registration uses WebAuthn, so you need a browser that supports passkeys (all modern browsers do). The portal uses HTTPS with a certificate signed by the proxy's own CA, so you must have installed the CA certificate first.

### 2. Pick elements to block

After registering, browse any website through the proxy and press **Alt+Shift+B** to open the element picker. The picker overlay appears in the top-right corner.

1. **Hover** over an element — a red highlight shows what will be selected
2. **Click** to select it — the generated CSS selector appears in the panel
3. **Block element** saves the rule and immediately hides the element
4. **Escape** to deselect, or close the picker entirely

Rules are stored in SQLite and take effect on the next page load (or immediately on the current page via injected CSS).

### 3. Manage rules via the API

Rules can also be managed programmatically. All endpoints require a Bearer token from the login flow.

```bash
# List your rules
curl -s https://127.0.0.1:8443/api/rules \
  -H "Authorization: Bearer <token>"

# Create a rule
curl -s https://127.0.0.1:8443/api/rules \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"rule": "example.com##.ad-banner", "domain": "example.com"}'

# Disable a rule
curl -s https://127.0.0.1:8443/api/rules/1 \
  -X PATCH -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"enabled": false}'

# Delete a rule
curl -s https://127.0.0.1:8443/api/rules/1 \
  -X DELETE -H "Authorization: Bearer <token>"
```

Rules follow [adblock filter syntax](https://adblockplus.org/filter-cheatsheet). Element hiding rules use `domain##selector` format (e.g. `example.com##.ad-banner`).

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `0.0.0.0` | Address to listen on |
| `-http-port` | `8080` | HTTP port for setup page and CA certificate download |
| `-https-port` | `8443` | HTTPS port for proxy, portal, and API |
| `-hostname` | `localhost` | Portal hostname for WebAuthn and TLS cert (must be a domain, not an IP) |
| `-ca-dir` | `~/.ublproxy` | Directory for CA certificate and key |
| `-db` | `~/.ublproxy/ublproxy.db` | Path to SQLite database |
| `-blocklist` | (none) | Path or URL to a blocklist file (repeatable) |
| `-default-subscription` | EasyList + EasyPrivacy | Default blocklist subscription URL, always active for all users (repeatable) |

## Known limitations

- **Element hiding on zstd HTML**: CSS injection for element hiding works with gzip, brotli, and uncompressed HTML. Zstd-encoded HTML passes through without element hiding CSS.
- **No re-compression**: After decompressing gzip for CSS injection, HTML is served uncompressed to the client. This is fine when the proxy runs on localhost.
- **Cert cache**: Generated TLS certificates are cached indefinitely with no eviction. Certificates have 24-hour validity but expired entries are never cleaned up. Fine for personal use.
- **Session-to-IP mapping**: Sessions are bound to client IP. Multiple users behind the same NAT IP share a single session slot (last login wins).

## References

- [adblock rules cheatsheet](https://adblockplus.org/filter-cheatsheet)
