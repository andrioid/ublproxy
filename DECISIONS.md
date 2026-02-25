# Decisions

- 2026-02-25 m+git@andri.dk — Validate upstream TLS certificates (removed `InsecureSkipVerify`). The proxy is the user's trust boundary; it must verify upstream server identity.
- 2026-02-25 m+git@andri.dk — Downgrade `Accept-Encoding` to gzip only for domains with element hiding rules. We can only decompress gzip for CSS injection; brotli would corrupt the response.
- 2026-02-25 m+git@andri.dk — Skip CSS injection for HEAD requests. HEAD responses have no body per HTTP spec.
- 2026-02-25 m+git@andri.dk — Hostname-only rules with `$options` (e.g. `||host^$third-party`) bypass the fast-path hostname map and go through compiled rules to preserve option evaluation.
- 2026-02-25 m+git@andri.dk — `$match-case` rules receive both the original-case and lowercased URL so they match correctly through the optimized `ShouldBlockRequest` path.
- 2026-02-25 m+git@andri.dk — Domain-indexed rule lookup: `||domain` rules are partitioned into `map[string][]*Rule` keyed by domain suffix. At match time, walk up the hostname hierarchy instead of scanning all rules.
- 2026-02-25 m+git@andri.dk — Literal-skip pattern matching: use `strings.Index` to jump to candidate positions for leading literals and post-wildcard literals, avoiding byte-by-byte scanning.
- 2026-02-25 m+git@andri.dk — Cache `CSSForDomain` results in `sync.Map` since the ruleset is immutable after loading.
- 2026-02-25 m+git@andri.dk — Serve decompressed HTML to client after CSS injection (no re-compression). Proxy-to-client hop is typically localhost.
- 2026-02-25 m+git@andri.dk — Go stdlib only. No third-party dependencies unless strongly warranted.
- 2026-02-25 m+git@andri.dk — WebSocket upgrade is not supported (Upgrade header stripped as hop-by-hop). Acceptable for an ad-blocking proxy.
- 2026-02-25 m+git@andri.dk — Cert cache has no eviction. Certs are generated with 24h validity. Acceptable for personal use.
