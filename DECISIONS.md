# Decisions

- 2026-02-25 m+git@andri.dk — Validate upstream TLS certificates (removed `InsecureSkipVerify`). The proxy is the user's trust boundary; it must verify upstream server identity.
- 2026-02-25 m+git@andri.dk — Don't manipulate `Accept-Encoding`. The proxy forwards the client's encoding preferences to upstream and handles CSS injection based on the response `Content-Encoding`. Gzip HTML is decompressed for injection; brotli/zstd HTML passes through without injection. Non-HTML resources are never touched.
- 2026-02-25 m+git@andri.dk — Skip CSS injection for HEAD requests. HEAD responses have no body per HTTP spec.
- 2026-02-25 m+git@andri.dk — Hostname-only rules with `$options` (e.g. `||host^$third-party`) bypass the fast-path hostname map and go through compiled rules to preserve option evaluation.
- 2026-02-25 m+git@andri.dk — `$match-case` rules receive both the original-case and lowercased URL so they match correctly through the optimized `ShouldBlockRequest` path.
- 2026-02-25 m+git@andri.dk — Domain-indexed rule lookup: `||domain` rules are partitioned into `map[string][]*Rule` keyed by domain suffix. At match time, walk up the hostname hierarchy instead of scanning all rules.
- 2026-02-25 m+git@andri.dk — Literal-skip pattern matching: use `strings.Index` to jump to candidate positions for leading literals and post-wildcard literals, avoiding byte-by-byte scanning.
- 2026-02-25 m+git@andri.dk — Cache `CSSForDomain` results in `sync.Map` since the ruleset is immutable after loading.
- 2026-02-25 m+git@andri.dk — Serve decompressed HTML to client after CSS injection (no re-compression). Proxy-to-client hop is typically localhost.
- 2026-02-25 m+git@andri.dk — Go stdlib only. No third-party dependencies unless strongly warranted.
- 2026-02-25 m+git@andri.dk — WebSocket upgrade supported for both ws:// and wss://. Upgrade headers are re-added after hop-by-hop stripping, then bidirectional copy bridges client and upstream after 101.
- 2026-02-25 m+git@andri.dk — Cert cache has no eviction. Certs are generated with 24h validity. Acceptable for personal use.
