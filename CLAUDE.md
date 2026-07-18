# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

cctools is a Go HTTP server that aggregates Clash subscription "airports" from multiple upstreams, dedupes/merges proxies, and renders a customizable Clash YAML config. The base config (mode, dns/tun internals, hosts, cors, the 21 rule-providers and 206 rules) is built entirely in Go — `defaultTemplate()` in `template.go` — not read from a file. A legacy Python/Flask version lives in `v1/`.

## Build, Run, Test

```bash
go build -o cctools                # build
./cctools                          # serve (default 127.0.0.1:9000)
LISTEN_ADDR=:8080 TOKEN=secret ./cctools
go test ./...                      # all tests
go test -run TestCollectSelectors  # single test by regex
```

`init()` in `main.go` preloads only `./upstreams.yaml` at startup, warning (not panicking) if missing — it can be supplied later via the token-gated upload endpoint. Use `upstreams-example.yaml` as the format reference. The template is **not** loaded from disk by default: `loadTemplate()` returns `defaultTemplate()` (Go), and only falls back to reading `./template.yaml` if that file exists (an optional, gitignored override — e.g. one uploaded via the endpoint). To change the built-in rules/rule-providers/dns/tun defaults, edit `template.go`.

Environment variables: `LISTEN_ADDR` (bind address), `TOKEN` (auth for `/upstreams.yaml` and `/template.yaml` GET/POST — **when unset, those endpoints are disabled, not open**), `DISABLE_CACHE` (skip both cache reads and writes).

`main` runs an explicit `http.Server` with Read/Write/Idle timeouts, a panic-recovery middleware around all handlers, and graceful shutdown on SIGINT/SIGTERM.

## Architecture

Single-package Go module (`package main`, all files in repo root). No web framework; `net/http` stdlib only.

**Request → config pipeline (`config.go`, entrypoint `Config.generate`):**
1. `handleConfig` parses query params into `Config`, detects platform from `User-Agent`, validates.
2. `fetchAirports` downloads each selected upstream's URLs concurrently (semaphore caps at 8) via `downloadUpstream` → `download` → `parseUpstream`. Each worker goroutine has a `recover` so a malformed upstream can't crash the process. Cached in `./cache/<sha1(url)>`; on error, falls back to cache when `use-cache-on-err: true` in `upstreams.yaml`. `download` takes an `allowLocalSchemes` flag: `file://`/`base64://` are permitted only for upstreams, never for request-time rule-provider URLs. All `http`/`https` fetches go through `safeHTTPClient` (`rule-provider-proxy.go`), which validates the resolved IP at dial time (`safeDialer.Control`) and bounds the body to `maxResponseBytes`.
3. `parseUpstream` strips proxies whose names match `PROXY_BLACKLIST` (DIRECT/REJECT/ads/expiry markers). It returns an error (never panics) on malformed proxy entries; upstream `proxy-groups` are not retained.
4. `resolveAirportNameConflicts` → `collectAllProxies` merge across upstreams in **sorted** airport order; name collisions get a deterministic numeric suffix (`mergeProxies` in `config.go`), so identical requests produce byte-identical output.
5. `buildProxyGroups` emits per-airport `url-test` groups, organizer subgroups (`cn`/`tw`/`us`/`sg`/`jp`/`oversea`/`udp` from `filter.go` regex matchers), and top-level selectors (`PROXY`, `UDP`, `FALLBACK`, `CNSITE` plus any custom chains discovered in template `rules` via `collectSelectors`/`extractRuleTarget`).
6. `transformRuleProviders` rewrites `rule-providers` per `rule_provider_transform` query: `none` (passthrough), `proxy` (rewrites URL to `/rule-providers?rule-set=…` on this server), or `inline` (downloads each provider and expands `RULE-SET` rules into literal rules per behavior `domain`/`ipcidr`/`classical`).
7. Marshaled YAML returned. The template is deep-copied per request via marshal/unmarshal (`deepCopyTemplate`) so concurrent requests don't mutate shared state.

**Filesystem abstraction (`fs.go`):** At startup, probes whether the working directory is writable. If read-only (e.g., serverless), writes go to an in-memory overlay `OVERLAYFS` keyed by absolute path; reads check overlay first then disk. All callers must use `fsLoad`/`fsStore`/`fsStat` — never `os.ReadFile`/`WriteFile` directly — so the same code path works on Vercel and on a server with disk.

**Cache (`cache.go`):** SHA1(url) → `./cache/<key>`; TTL is per-upstream from `upstreams.yaml`. `cache_is_ok` also rejects future mtimes (clock skew protection). When `DISABLE_CACHE` is set, both reads and writes are skipped (so it fully bypasses the cache, not just writes).

**DictList (`dictlist.go`):** ordered map of `YamlStrDict` (= `map[string]any`) keyed by the dict's `name` field. Used everywhere proxies/groups need stable insertion-order output. `set` injects `name` into the value automatically.

**Endpoints (registered in `main.main`):**
- `GET /clash/config.yaml` — main generator. With no query params, serves `index.html` (the form UI).
- `GET|POST /upstreams.yaml`, `GET|POST /template.yaml` — token-gated read/write of the two config files (token via `?token=`, `Authorization: Bearer …`, or `X-Auth-Token`; compared with `crypto/subtle.ConstantTimeCompare`). **If `TOKEN` is empty the handler returns 403 for everything** (fail closed).
- `GET /rule-providers?rule-set=NAME` — looks up `rule-providers[NAME].url` in the template and proxies it (used in `proxy` transform mode). Fetched through `download(..., allowLocalSchemes=false)`, so only `http`/`https`.
- `/convert?url=…` — reverse proxy that fetches a raw rule list and rewrites it into Clash `payload:` YAML (`convertRawListToRuleProvider`, which always emits a valid `payload:` even for empty/comment-only input and is not cached when degenerate). `validateProxyUpstream`/`isDisallowedUpstreamIP` block loopback/private/CGNAT(100.64/10)/link-local/multicast IPs (incl. IPv4-mapped); the reverse-proxy `Transport` is `safeTransport`, which re-validates the dialed IP to defeat DNS rebinding. Result cached for 24h.

## Conventions and Gotchas

- Stick to `gopkg.in/yaml.v3`; the common in-memory shape is `YamlStrDict` (`map[string]any`). Helpers `asString`, `asStringList`, `asAnyList`, `asStringAnyMap`, `asStringAnyMapField` exist in `common.go` for the recurring `any → typed` coercions — prefer them over inline type assertions. `NewDictList` returns an error on malformed input (do not reintroduce `panic` on untrusted data).
- Errors returned from `buildConfig`'s parameter parsing are wrapped in `*badRequestError` (→ HTTP 400); a zero-proxy result is `*upstreamUnavailableError` (→ HTTP 502); everything else is 500. Preserve that wrapping when adding new params/failure modes.
- Sensitive query params and headers are scrubbed by `logRequest` (`token`, `secret`, `external_controller_addr`, `nameserver_policy`, `url`, `authorization`, `x-auth-token`). Add new sensitive fields to that allowlist if you introduce them. Outbound URLs are also logged via `redactURL` (strips userinfo/query) to avoid leaking subscription tokens.
- New query params must be added to `knownConfigQueryKeys` in `main.go`, otherwise `warnUnknownQueryParams` will log a warning every request.
- The `tun` and `dns` template options are mutated only when their respective `tun=true`/`dns=true` query flags are set; otherwise the template's existing values pass through.
- Platform detection (`Windows`/`Linux`/`Darwin`/`Android`/`Other`) is from the request `User-Agent` and currently affects only `tun.auto-redir` on Windows.
- `upstreams.yaml` is gitignored (private). `cache/` is gitignored. `template.yaml` is also gitignored — it no longer exists in the repo; the base config lives in `template.go` (`defaultTemplate`). A `template.yaml` on disk is only an optional per-deployment override.
- `keep_upstream_selector`, `custom_rules`, and `tun_auto_route` are accepted by `knownConfigQueryKeys` (so the front-end form doesn't trigger warnings) but are **not implemented** by the backend — wiring them up (e.g. a line-based parser for `custom_rules`, since rule values contain commas) or removing the `index.html` controls is open work.
- Deployment: the supported target is the standalone Go binary (`./cctools`). `vercel.json` and `v1/` are legacy Python (the Flask app) and currently non-functional (`vercel.json` builds a root `index.py` that does not exist); don't assume the Go server is wired to Vercel.
