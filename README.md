# ublproxy

A proxy-server, that is capable of filtering ads from HTTPS/TLS traffic, using adblock rules.

### Known Limitations

- **Element hiding on brotli/zstd HTML**: CSS injection for element hiding only works when the upstream serves gzip-encoded or uncompressed HTML. Brotli/zstd HTML passes through without element hiding CSS.
- **No re-compression**: After decompressing gzip for CSS injection, HTML is served uncompressed to the client. This is fine when the proxy runs on localhost.
- **Cert cache**: Generated TLS certificates are cached indefinitely with no eviction. Certificates have 24-hour validity but expired entries are never cleaned up. Fine for personal use.

### References

- [adblock rules cheatsheet](https://adblockplus.org/filter-cheatsheet)
