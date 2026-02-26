# Decisions

- 2026-02-25 m+git@andri.dk — Validate upstream TLS certificates (removed `InsecureSkipVerify`). The proxy is the user's trust boundary; it must verify upstream server identity.
- 2026-02-25 m+git@andri.dk — Don't manipulate `Accept-Encoding`. The proxy forwards the client's encoding preferences to upstream and handles CSS injection based on the response `Content-Encoding`. Gzip and brotli HTML are decompressed for injection; other encodings pass through without injection. Non-HTML resources are never touched.
- 2026-02-25 m+git@andri.dk — Skip CSS injection for HEAD requests. HEAD responses have no body per HTTP spec.
- 2026-02-25 m+git@andri.dk — Hostname-only rules with `$options` (e.g. `||host^$third-party`) bypass the fast-path hostname map and go through compiled rules to preserve option evaluation.
- 2026-02-25 m+git@andri.dk — `$match-case` rules receive both the original-case and lowercased URL so they match correctly through the optimized `ShouldBlockRequest` path.
- 2026-02-25 m+git@andri.dk — Domain-indexed rule lookup: `||domain` rules are partitioned into `map[string][]*Rule` keyed by domain suffix. At match time, walk up the hostname hierarchy instead of scanning all rules.
- 2026-02-25 m+git@andri.dk — Literal-skip pattern matching: use `strings.Index` to jump to candidate positions for leading literals and post-wildcard literals, avoiding byte-by-byte scanning.
- 2026-02-25 m+git@andri.dk — Cache `ElementHidingForDomain` results in `sync.Map` since the ruleset is immutable after loading.
- 2026-02-25 m+git@andri.dk — Serve decompressed HTML to client after CSS injection (no re-compression). Proxy-to-client hop is typically localhost.
- 2026-02-25 m+git@andri.dk — Added `github.com/andybalholm/brotli` (pure Go, zero transitive runtime deps) for brotli decompression in CSS injection. First third-party dependency — warranted because brotli is the dominant encoding for HTML on modern CDNs and the stdlib has no brotli support.
- 2026-02-25 m+git@andri.dk — WebSocket upgrade supported for both ws:// and wss://. Upgrade headers are re-added after hop-by-hop stripping, then bidirectional copy bridges client and upstream after 101.
- 2026-02-25 m+git@andri.dk — Cert cache has no eviction. Certs are generated with 24h validity. Acceptable for personal use.
- 2026-02-26 m+git@andri.dk — Element hiding via HTML element replacement instead of CSS `display: none` injection. Matched elements are replaced with `<div><!-- ublproxy: replaced .selector --></div>` using `golang.org/x/net/html` tokenizer. This strips ad content (scripts, iframes, images) from the DOM, reducing page weight. Complex selectors (descendant/sibling combinators, `:has()`, `:not()`) fall back to CSS injection.
- 2026-02-26 m+git@andri.dk — Added `golang.org/x/net` (zero transitive runtime deps, Go team maintained) for HTML tokenization in element replacement. Selectors are classified at cache time into simple (single-element matchable) and complex (needs CSS fallback).
- 2026-02-26 m+git@andri.dk — Blocked CONNECT requests return 403 Forbidden instead of 204 No Content. Browsers hang on 204 because they expect a tunnel; 403 makes them fail fast.
- 2026-02-26 m+git@andri.dk — Removed Playwright from the project. Playwright's screenshot and snapshot commands wait for `document.fonts.ready`, which never resolves when the MITM proxy blocks ad-network domains that serve fonts. curl is a better fit for proxy testing.
