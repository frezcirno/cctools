# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

cctools is a Go HTTP server that aggregates Clash subscription "airports" from multiple upstreams, dedupes/merges proxies, and renders a customizable Clash YAML config from a template. A legacy Python/Flask version lives in `v1/`. See `AGENT.md` for additional context.

## Build, Run, Test

```bash
go build -o cctools                # build
./cctools                          # serve (default 127.0.0.1:9000)
LISTEN_ADDR=:8080 TOKEN=secret ./cctools
go test ./...                      # all tests
go test -run TestCollectSelectors  # single test by regex
```

`init()` in `main.go` requires `./upstreams.yaml` and `./template.yaml` to exist at startup or the process panics. Use `upstreams-example.yaml` as the format reference.

Environment variables: `LISTEN_ADDR` (bind address), `TOKEN` (auth for `/upstreams.yaml` and `/template.yaml` GET/POST), `DISABLE_CACHE` (skip writing `./cache/*`).

## Architecture

Single-package Go module (`package main`, all files in repo root). No web framework; `net/http` stdlib only.

**Request → config pipeline (`config.go`, entrypoint `Config.generate`):**
1. `handleConfig` parses query params into `Config`, detects platform from `User-Agent`, validates.
2. `fetchAirports` downloads each selected upstream's URLs concurrently (semaphore caps at 8) via `downloadUpstream` → `download` → `parseUpstream`. Cached in `./cache/<sha1(url)>`; on error, falls back to cache when `use-cache-on-err: true` in `upstreams.yaml`.
3. `parseUpstream` strips proxies whose names match `PROXY_BLACKLIST` (DIRECT/REJECT/ads/expiry markers).
4. `resolveAirportNameConflicts` → `collectAllProxies` merge across upstreams; name collisions get a random 3-char suffix (`mergeProxies`/`mergeGroups` in `config.go`).
5. `buildProxyGroups` emits per-airport `url-test` groups, organizer subgroups (`cn`/`tw`/`us`/`sg`/`jp`/`oversea`/`udp` from `filter.go` regex matchers), and top-level selectors (`PROXY`, `UDP`, `FALLBACK`, `CNSITE` plus any custom chains discovered in template `rules` via `collectSelectors`/`extractRuleTarget`).
6. `transformRuleProviders` rewrites `rule-providers` per `rule_provider_transform` query: `none` (passthrough), `proxy` (rewrites URL to `/rule-providers?rule-set=…` on this server), or `inline` (downloads each provider and expands `RULE-SET` rules into literal rules per behavior `domain`/`ipcidr`/`classical`).
7. Marshaled YAML returned. The template is deep-copied per request via marshal/unmarshal (`deepCopyTemplate`) so concurrent requests don't mutate shared state.

**Filesystem abstraction (`fs.go`):** At startup, probes whether the working directory is writable. If read-only (e.g., serverless), writes go to an in-memory overlay `OVERLAYFS` keyed by absolute path; reads check overlay first then disk. All callers must use `fsLoad`/`fsStore`/`fsStat` — never `os.ReadFile`/`WriteFile` directly — so the same code path works on Vercel and on a server with disk.

**Cache (`cache.go`):** SHA1(url) → `./cache/<key>`; TTL is per-upstream from `upstreams.yaml`. `cache_is_ok` also rejects future mtimes (clock skew protection). Writes are skipped when `DISABLE_CACHE` is set.

**DictList (`dictlist.go`):** ordered map of `YamlStrDict` (= `map[string]any`) keyed by the dict's `name` field. Used everywhere proxies/groups need stable insertion-order output. `set` injects `name` into the value automatically.

**Endpoints (registered in `main.main`):**
- `GET /clash/config.yaml` — main generator. With no query params, serves `index.html` (the form UI).
- `GET|POST /upstreams.yaml`, `GET|POST /template.yaml` — token-gated read/write of the two config files (token via `?token=`, `Authorization: Bearer …`, or `X-Auth-Token`).
- `GET /rule-providers?rule-set=NAME` — looks up `rule-providers[NAME].url` in the template and proxies it (used in `proxy` transform mode).
- `/convert?url=…` — reverse proxy that fetches a raw rule list and rewrites it into Clash `payload:` YAML (`convertRawListToRuleProvider`). `validateProxyUpstream` blocks loopback/private/link-local/multicast IPs (SSRF guard), and the result is cached for 24h.

## Conventions and Gotchas

- Stick to `gopkg.in/yaml.v3`; the common in-memory shape is `YamlStrDict` (`map[string]any`). Helpers `asString`, `asStringList`, `asAnyList`, `asStringAnyMap`, `asStringAnyMapField`, `normalizeProxyNames` exist in `common.go` for the recurring `any → typed` coercions — prefer them over inline type assertions.
- Errors returned from `buildConfig`'s parameter parsing are wrapped in `*badRequestError` so `handleConfig` can map them to HTTP 400 vs 500. Preserve that wrapping when adding new params.
- Sensitive query params and headers are scrubbed by `logRequest` (`token`, `secret`, `external_controller_addr`, `nameserver_policy`). Add new sensitive fields to that allowlist if you introduce them.
- New query params must be added to `knownConfigQueryKeys` in `main.go`, otherwise `warnUnknownQueryParams` will log a warning every request.
- The `tun` and `dns` template options are mutated only when their respective `tun=true`/`dns=true` query flags are set; otherwise the template's existing values pass through.
- Platform detection (`Windows`/`Linux`/`Darwin`/`Android`/`Other`) is from the request `User-Agent` and currently affects only `tun.auto-redir` on Windows.
- `upstreams.yaml` is gitignored (private). `cache/` is gitignored. `template.yaml` is committed and intentionally tracked.
