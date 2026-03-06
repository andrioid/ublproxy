# Adblock Filter Syntax Support

References: [Adblock Plus filter cheatsheet](https://adblockplus.org/filter-cheatsheet), [uBlock Origin Static Filter Syntax](https://github.com/gorhill/uBlock/wiki/Static-filter-syntax)

Implementation: `internal/blocklist/`

## Network Filter Patterns

| Feature | Example | Status | Notes |
|---------|---------|--------|-------|
| Literal text | `ad.js` | Supported | `pattern.go` |
| Wildcard `*` | `ad*.js` | Supported | `segWildcard`, consecutive `*` collapsed |
| Separator `^` | `\|\|example.com^` | Supported | `segSeparator`, matches non-alnum except `_-.%` or end of string |
| Start anchor `\|` | `\|https://example.com` | Supported | `anchorStart` flag |
| End anchor `\|` | `example.com/ad\|` | Supported | `anchorEnd` flag |
| Domain anchor `\|\|` | `\|\|example.com^` | Supported | `domainAnchor` flag, O(1) map lookup for hostname-only rules |
| Regex patterns | `/banner\d+/` | Supported | Compiled to `regexp.Regexp`, case-insensitive by default |
| HOSTS file format | `0.0.0.0 example.com` | Supported | Treated as `\|\|hostname^` |
| Exception filters `@@` | `@@\|\|example.com^` | Supported | Layered evaluation |

## Network Filter Options (`$` modifiers)

### Resource Type Options

| Option | Status | Notes |
|--------|--------|-------|
| `$script` | Supported | |
| `$image` | Supported | |
| `$stylesheet` / `$css` | Supported | `$css` is alias for `$stylesheet` |
| `$xmlhttprequest` / `$xhr` | Supported | `$xhr` is alias for `$xmlhttprequest` |
| `$subdocument` / `$frame` | Supported | `$frame` is alias for `$subdocument` |
| `$media` | Supported | |
| `$font` | Supported | |
| `$object` | Supported | |
| `$object-subrequest` | Supported | Legacy alias for `$object` |
| `$websocket` | Supported | |
| `$document` / `$doc` | Supported | `$doc` is alias for `$document` |
| `$ping` | Supported | Maps to `ResourcePing` |
| `$other` | Supported | |
| `$popup` | Parsed, not enforced | Not enforceable at proxy level |
| `$popunder` | Not implemented | Not enforceable at proxy level |
| `$all` | Supported | Equivalent to all network-based types + `$popup` + `$document` + `$inline-font` + `$inline-script` |
| Negated types (`$~script`) | Supported | `ExcludeTypes` bitmask |
| Multiple types (`$script,image`) | Supported | |

### Party / Scope Options

| Option | Status | Notes |
|--------|--------|-------|
| `$third-party` / `$3p` | Supported | `$3p` is alias |
| `$~third-party` / `$first-party` / `$1p` | Supported | `$1p` and `$first-party` are aliases |
| `$strict1p` | Not implemented | MV2-only, hostname-exact match |
| `$strict3p` | Not implemented | MV2-only, hostname-exact match |
| `$domain=` / `$from=` | Supported | Multiple domains, `\|` separated, `~` negation. `$from=` is alias |
| Entity matching in `$domain=` | Supported | e.g. `$domain=google.*` |
| Regex values in `$domain=` | Not implemented | e.g. `$domain=/regex/` |
| `$to=` | Supported | Include/exclude with `~` negation, entity matching |
| `$denyallow=` | Supported | Exempt request destinations from blocking |

### Behavioral / Priority Options

| Option | Status | Notes |
|--------|--------|-------|
| `$match-case` | Supported | Case-sensitive matching |
| `$important` | Supported | Bypasses exception filters |
| `$badfilter` | Supported | Disables matching rules via normalized target, lazy evaluation |
| `$method=` | Supported | Bitmask-based, include/exclude/negation |
| `$header=` | Supported | Block by response header presence/value/regex, negation with `~` |
| `$cname` | Not implemented | Firefox MV2-only |
| `$ipaddress=` | Not implemented | Firefox MV2-only |

### Modifier / Redirect Options

| Option | Status | Notes |
|--------|--------|-------|
| `$csp=` | Supported | Injects `Content-Security-Policy` response header. Exceptions with `@@...$csp` (blanket) or `@@...$csp=value` (specific) |
| `$permissions=` | Supported | Injects `Permissions-Policy` response header. `\|` separator converted to `, ` internally |
| `$removeparam=` | Supported | Strips query parameters (literal or `/regex/`). `$removeparam` without value strips all params |
| `$redirect=` | Supported | 19 neutered resources (GIF, PNG, JS, CSS, HTML, JSON, TXT, MP3, MP4, VAST/VMAP XML, empty/none) with aliases. Exception handling (blanket + specific) |
| `$redirect-rule=` | Supported | Creates redirect directive only (no blocking rule) |
| `$empty` | Supported | Deprecated alias for `$redirect=empty` |
| `$mp4` | Supported | Deprecated alias for `$redirect=noopmp4-1s,$media` |
| `$replace=` | Not implemented | Trusted-source only |
| `$uritransform=` | Not implemented | Trusted-source only |
| `$urlskip=` | Not implemented | Trusted-source only |
| `$rewrite=` | Silently ignored | |

### Cosmetic Filtering Control Options

| Option | Status | Notes |
|--------|--------|-------|
| `$elemhide` / `$ehide` | Supported | Disables all cosmetic filtering on matching pages |
| `$generichide` / `$ghide` | Supported | Disables generic (non-domain-specific) cosmetic selectors |
| `$specifichide` / `$shide` | Supported | Disables domain-specific cosmetic selectors |
| `$genericblock` | Not supported | Per uBO spec, not supported |

### Noop / Placeholder

| Option | Status | Notes |
|--------|--------|-------|
| `_` (noop) | Supported | Placeholder for readability and regex disambiguation |

## Extended Filtering — Cosmetic Filters

| Feature | Status | Notes |
|---------|--------|-------|
| Basic element hiding `##selector` | Supported | CSS injection with `display: none !important` |
| Element hiding exceptions `#@#selector` | Supported | |
| Domain-scoped (`example.com##.ad`) | Supported | Include/exclude with `~` negation |
| Generic selectors (`##.ad-class`) | Supported | Pre-filtered by HTML class/ID token extraction |
| Entity matching (`google.*##.ad`) | Supported | Via `domainMatchesOrIsSubdomain` |
| Specific-generic (`*##.selector`) | Not implemented | Unconditional injection |
| Hostname regex (`/regex/##.ad`) | Not implemented | |

### Procedural Cosmetic Filters

All procedural operators are **not implemented**. Lines containing `#?#` are explicitly skipped.

- `:has()`, `:has-text()`, `:matches-attr()`, `:matches-css()`, `:matches-css-before()`, `:matches-css-after()`, `:matches-media()`, `:matches-path()`, `:matches-prop()`, `:min-text-length()`, `:not()` (extended), `:others()`, `:upward()`, `:watch-attr()`, `:xpath()`

### Action Operators

All action operators are **not implemented**.

- `:style()`, `:remove()`, `:remove-attr()`, `:remove-class()`

## HTML Filters

| Feature | Status | Notes |
|---------|--------|-------|
| `##^selector` (response-level) | Not implemented | |
| `##^responseheader()` | Not implemented | |
| `##^script:has-text()` | Not implemented | |

Note: ublproxy has its own resource stripping that removes `<script>`, `<iframe>`, `<object>`, `<embed>` elements whose `src`/`data` attribute resolves to a blocked URL. This is a different mechanism from uBO's HTML filters.

## Scriptlet Injection

| Feature | Status | Notes |
|---------|--------|-------|
| `##+js(token, args)` | Supported | 11 scriptlets: `set-constant`, `abort-on-property-read`, `abort-on-property-write`, `abort-current-inline-script`, `addEventListener-defuser`, `nowebrtc`, `no-setTimeout-if`, `no-setInterval-if`, `prevent-fetch`, `json-prune`, `remove-attr`. Aliases: `set`, `aopr`, `aopw`, `acis`, `aeld`, `ra`, `rc` |
| `#@#+js()` (exceptions) | Supported | Suppresses matching scriptlet by name for a domain |
| Domain-scoped scriptlets | Supported | e.g. `example.com##+js(nowebrtc)` |
| Generic scriptlets | Supported | e.g. `##+js(abort-on-property-read, detectAdBlock)` applies to all domains |

## Pre-parsing Directives

| Directive | Status | Notes |
|-----------|--------|-------|
| `!#if [condition]` | Supported | Stack-based evaluation with boolean expressions (`!`, `&&`, `\|\|`) |
| `!#else` | Supported | |
| `!#endif` | Supported | |
| `!#include [file]` | Not implemented | Dropped from scope — published filter lists are pre-compiled |

Environment tokens: `ext_ublock`=true, `cap_html_filtering`=true, `false`=false. Browser tokens (`env_firefox`, `env_chromium`, etc.) evaluate to false. AdGuard compatibility tokens supported.

## What ublproxy Handles Well

- **Fast hostname matching**: O(1) map lookup for `\|\|hostname^` rules (covers the majority of filter entries)
- **Domain-indexed rules**: `\|\|domain...` patterns indexed by domain suffix for fast lookup
- **Literal-skip optimization**: `strings.Index` jumps to candidate positions, avoiding byte-by-byte scanning
- **Element hiding token pre-filtering**: Extracts class/ID tokens from HTML, reduces ~64K EasyList selectors to ~200 per page
- **CSS chunking**: Breaks selectors into groups of 4096 for Chrome compatibility
- **DOM resource stripping**: Strips blocked `<script>`/`<iframe>`/`<object>`/`<embed>` elements at HTML rewrite time
- **Transparent decompression**: Handles gzip, brotli, and zstd HTML for injection
- **Layered evaluation**: Baseline rules + per-user rules with user `@@` exceptions overriding baseline blocks
- **$important priority**: Important rules bypass exception filters
- **$badfilter lazy evaluation**: Disabled rules checked at match time via normalized target set
- **Response header modification**: `$csp`, `$permissions`, `$removeparam` applied across all proxy paths (HTTP, CONNECT, transparent)
- **Response header blocking**: `$header=` checks response headers post-fetch to block matching requests
- **Redirect resources**: 19 neutered resources for `$redirect` / `$redirect-rule` with alias support
- **Scriptlet injection**: 11 most-used scriptlets injected via `<script>` tags before `</head>`, with `</script>` sanitization
- **Parse error visibility**: `OnWarning` callback and `ParseErrors()` counter for malformed rules
