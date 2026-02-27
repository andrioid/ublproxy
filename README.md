# ublproxy

A proxy-server that filters ads from HTTPS/TLS traffic using adblock rules, with interactive element picking for custom rules.

See [QUICK_START.md](QUICK_START.md) for setup instructions (local and Docker).

See [CONTRIBUTING.md](CONTRIBUTING.md) for development.

## Known limitations

- **Element hiding on zstd HTML**: CSS injection for element hiding works with gzip, brotli, and uncompressed HTML. Zstd-encoded HTML passes through without element hiding CSS.
- **No re-compression**: After decompressing gzip for CSS injection, HTML is served uncompressed to the client. This is fine when the proxy runs on localhost.
- **Cert cache**: Generated TLS certificates are cached indefinitely with no eviction. Certificates have 24-hour validity but expired entries are never cleaned up. Fine for personal use.
- **Session-to-IP mapping**: Sessions are bound to client IP. Multiple users behind the same NAT IP share a single session slot (last login wins).

## References

- [adblock rules cheatsheet](https://adblockplus.org/filter-cheatsheet)
