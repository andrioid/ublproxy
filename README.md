# ublproxy

A proxy-server, that is capable of filtering ads from HTTPS/TLS traffic, using adblock rules.

### Known Limitations

- **WebSocket**: `Upgrade` and `Connection` headers are stripped as hop-by-hop headers, preventing WebSocket connections through the proxy.
- **Accept-Encoding downgrade**: For domains with element hiding (CSS injection) rules, `Accept-Encoding` is downgraded to `gzip` for all requests to that domain (not just HTML). Non-HTML resources lose brotli compression on those domains.
- **No re-compression**: After decompressing gzip for CSS injection, HTML is served uncompressed to the client. This is fine when the proxy runs on localhost.
- **Cert cache**: Generated TLS certificates are cached indefinitely with no eviction. Certificates have 24-hour validity but expired entries are never cleaned up. Fine for personal use.

### References

- [adblock rules cheatsheet](https://adblockplus.org/filter-cheatsheet)
