# ublproxy

A network-wide adblock proxy-server w. adblock list support, custom rules and passkey users. Easy to set up and host yourself.

## Problem domain

Browsers were supposed to be "user-agents", but modern browsers are far more catered to ad-selling corporations, than they are to users.

Existing solutions, such as [pihole](https://pi-hole.net/) and other dns-based solutions are only sufficient, if you want to block an entire hostname. Browser extensions used to work well, but with the latest [Manifest changes](https://adlock.com/blog/chrome-killing-adblock/), they are not as effective as they used to be.

## Architecture

ublproxy sits between your devices and the internet, intercepting HTTP/HTTPS traffic to block ads and tracking at the network level.

```mermaid
graph LR
    subgraph LAN["Local Network"]
        D1["Desktop"]
        D2["Laptop"]
        D3["Phone"]
    end

    subgraph UBL["ublproxy"]
        HTTP[":8080<br/>HTTP"]
        HTTPS[":8443<br/>HTTPS"]
        BL["Blocklist<br/>Engine"]
        CA["CA + Cert<br/>Cache"]
        DB["SQLite<br/>Store"]
    end

    UP["Upstream<br/>Servers"]

    D1 --> HTTPS
    D2 --> HTTPS
    D3 --> HTTP

    HTTPS --> BL
    HTTP --> BL
    BL --> CA
    BL --> UP

    HTTPS --> DB
```

The proxy operates in one of two modes:

### Explicit proxy mode (default)

Browsers are configured to send traffic through the proxy via PAC files or manual proxy settings.

```mermaid
sequenceDiagram
    participant B as Browser
    participant P as ublproxy
    participant U as Upstream

    B->>P: CONNECT example.com:443
    P->>P: Check blocklist
    alt Blocked
        P-->>B: 403 Forbidden
    else Excepted (@@)
        P->>U: TCP tunnel (passthrough)
        U-->>B: Direct TLS (no MITM)
    else Normal
        P-->>B: 200 OK
        B->>P: TLS handshake (MITM cert)
        P->>P: Generate cert for example.com
        B->>P: GET /page
        P->>U: GET /page (real TLS)
        U-->>P: HTML response
        P->>P: Strip blocked resources
        P->>P: Inject element-hiding CSS
        P-->>B: Modified HTML
    end
```

### Transparent proxy mode (`--transparent`)

A firewall redirects all traffic from a VLAN to the proxy. No client configuration needed.

```mermaid
sequenceDiagram
    participant D as Device
    participant FW as Firewall
    participant P as ublproxy
    participant U as Upstream

    Note over D,FW: New device joins VLAN

    D->>FW: HTTP to captive.apple.com
    FW->>P: Redirect to :8080
    P->>P: Untrusted client?
    P-->>D: 302 Redirect to setup page

    Note over D: OS shows captive portal UI
    Note over D: User installs CA cert

    D->>FW: HTTPS to example.com
    FW->>P: Redirect to :8443
    P->>P: Extract SNI from ClientHello
    P->>P: Generate MITM cert
    D->>P: TLS handshake (trusts CA)
    P->>P: Mark client as trusted
    P->>U: Forward request
    U-->>P: Response
    P-->>D: Modified response
```

## Features

### Adblock Plus lists

Subscribe to community-maintained blocklists like EasyList and EasyPrivacy. Lists are fetched and parsed automatically, and rules are applied to all proxied traffic.

### Custom rules

Add your own blocking and element-hiding rules using adblock filter syntax, or use the interactive element picker (Alt+Shift+B) to visually select elements to hide on any proxied page.

### Encrypted, all the way

Desktop browsers connect to the proxy over HTTPS. The proxy generates per-host TLS certificates on the fly using its own CA. Mobile devices (iOS/Android) connect over plain HTTP because they don't support HTTPS proxy connections — the MITM tunnel within the connection is still TLS-encrypted.

### Strips away scripts, images and embeds

Blocked requests for scripts, images, iframes and other embedded resources are stopped at the proxy before they reach your browser.

### Hides the rest

CSS is injected into HTML responses to hide elements matching element-hiding rules. The proxy decompresses HTML, injects the CSS, and serves it back — removing ad containers, banners and other unwanted elements visually.

### Users and custom rules

WebAuthn passkey authentication gives each user their own set of rules and subscriptions, layered on top of any server-configured blocklists.

### Transparent proxy mode

Deploy on a VLAN with firewall rules to intercept all traffic automatically — no client-side proxy configuration needed. A captive portal guides new devices through CA certificate installation. Enable with `--transparent`.

## Security

### Man-In-The-Middle

It's important to be aware, that by using this solution, you're essentially decrypting all of your traffic, messing with it and then encrypting it again before it reaches the browser. If ublproxy was a service on the Internet, that should make you very suspicious. But, this is intended to be run on small local networks to improve privacy, and ad-free browsing.

## Known limitations

- **No re-compression**: After decompressing HTML (gzip/brotli/zstd) for CSS injection, HTML is served uncompressed to the client. This is fine when the proxy runs on localhost.
- **Session-to-IP mapping**: Sessions are bound to client IP. Multiple users behind the same NAT IP share a single session slot (last login wins).
- **Mobile proxy connection is unencrypted**: iOS and Android don't support HTTPS proxy connections. Mobile devices use a plain HTTP CONNECT proxy on port 8080. The CONNECT metadata (target hostname) is visible on the LAN, though the tunneled content is TLS-encrypted. The element picker is disabled on mobile connections to avoid leaking the session token.

## References

- See [QUICK_START.md](QUICK_START.md) for setup instructions (local and Docker).
- See [CONTRIBUTING.md](CONTRIBUTING.md) for development.
- See [adblock rules cheatsheet](https://adblockplus.org/filter-cheatsheet) for adblock plus filter syntax details.
