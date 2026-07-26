# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

cctools is a Go HTTP server that aggregates Clash subscription "airports" from multiple upstreams, dedupes/merges proxies, and renders a customizable Clash YAML config. The base config (mode, dns/tun internals, hosts, cors, the 21 rule-providers and 206 rules) is built entirely in Go — `DefaultTemplate()` in `internal/clash/template.go` — not read from a file. A legacy Python/Flask version lives in `v1/`.

## Build, Run, Test

```bash
go build -o cctools ./cmd/cctools      # build
./cctools                              # serve (default 127.0.0.1:9000)
LISTEN_ADDR=:8080 TOKEN=secret ./cctools
go test ./...                          # all tests
go test ./internal/clash/ -run TestCollectSelects   # single test by regex
```

`server.New` preloads only `./upstreams.yaml` at startup, warning (not panicking) if missing — it can be supplied later via the token-gated upload endpoint. Use `upstreams-example.yaml` as the format reference. The template is **not** loaded from disk by default: `loadTemplate()` returns `clash.DefaultTemplate()` (Go), and only falls back to reading `./template.yaml` if that file exists (an optional, gitignored override — e.g. one uploaded via the endpoint). To change the built-in rules/rule-providers/dns/tun defaults, edit `internal/clash/template.go`.

The form UI is `internal/server/index.html`, compiled into the binary with `//go:embed`. An `./index.html` next to the binary overrides the embedded copy, so it can still be iterated on without a rebuild.

Environment variables: `LISTEN_ADDR` (bind address), `TOKEN` (auth for `/upstreams.yaml` and `/template.yaml` GET/POST — **when unset, those endpoints are disabled, not open**), `DISABLE_CACHE` (skip both cache reads and writes).

`cmd/cctools` runs an explicit `http.Server` with Read/Write/Idle timeouts and graceful shutdown on SIGINT/SIGTERM; `server.Handler()` wraps all routes in panic-recovery middleware.

## Architecture

No web framework; `net/http` stdlib only. Packages, in dependency order (each depends only on those above it):

| Package | Role |
| --- | --- |
| `internal/vfs` | Filesystem abstraction: `Store`/`Load`/`Stat`. |
| `internal/safehttp` | SSRF-safe dialer/transport/client, URL validation, `RedactURL`, `MaxResponseBytes`. |
| `internal/cache` | `./cache/<sha1(url)>` with per-caller TTL. |
| `internal/fetch` | `Download()` — scheme handling + cache layering over `safehttp.Client`. |
| `internal/ruleset` | Resolves a template rule-provider `url` to its YAML body; `ConvertRawList` wraps a raw list as `payload:`. |
| `internal/clash` | The library: `Config`, `Generate`, `DefaultTemplate`, `DictList`, proxy filters. Knows nothing about `*http.Request`. |
| `internal/server` | HTTP handlers, query-param parsing, embedded `index.html`. |
| `cmd/cctools` | `main`: env, `http.Server`, signals. Nothing else. |

**Request → config pipeline (`internal/clash/config.go`, entrypoint `Config.Generate(clash.BaseURL)`):**
1. `buildConfig` (`internal/server/config.go`) parses query params into a `clash.Config`, detects platform from `User-Agent`, loads upstreams/template, then calls `Generate` — which validates the options itself. Parameter parsing runs **before** any I/O, so a malformed request is rejected without touching disk or network.
2. `fetchAirports` downloads each selected upstream's URLs concurrently (semaphore caps at 8) via `downloadUpstream` → `fetch.Download` → `parseUpstream`. Each worker goroutine has a `recover` so a malformed upstream can't crash the process. Cached in `./cache/<sha1(url)>`; on error, falls back to cache when `use-cache-on-err: true` in `upstreams.yaml`. `fetch.Download` takes an `allowLocalSchemes` flag: `file://`/`base64://` are permitted only for upstreams, never for request-time rule-provider URLs. All `http`/`https` fetches go through `safehttp.Client`, which validates the resolved IP at dial time and bounds the body to `safehttp.MaxResponseBytes`.
3. `parseUpstream` strips proxies whose names match `PROXY_BLACKLIST` (DIRECT/REJECT/ads/expiry markers). It returns an error (never panics) on malformed proxy entries; upstream `proxy-groups` are not retained.
4. `resolveAirportNameConflicts` → `collectAllProxies` merge across upstreams in **sorted** airport order; name collisions get a deterministic numeric suffix (`mergeProxies` in `airport.go`), so identical requests produce byte-identical output.
5. `buildProxyGroups` emits per-airport `url-test` groups, organizer subgroups (`cn`/`tw`/`us`/`sg`/`jp`/`oversea`/`claude`/`chatbot`/`udp` from `filter.go` matchers — `claude` takes any US node plus anything labelled Claude/Anthropic, `chatbot` is just `!isCN`, i.e. anything outside CN/HK/TW), and top-level selects (`PROXY`, `UDP`, `UNKNOWN`, `CNSITE` plus any custom chains discovered in template `rules` via `collectSelects`/`extractRuleTarget` — currently `CLAUDE`, `CHATBOT`, `ONEDRIVE`).
6. `transformRuleProviders` rewrites `rule-providers` per `rule_provider_transform` query: `none` (passthrough), `proxy` (rewrites URL to `/rule-providers?rule-set=…` on this server), or `inline` (downloads each provider via `ruleset.Fetch` — concurrently, capped at `maxConcurrentRuleProviders` — and expands `RULE-SET` rules into literal rules per behavior `domain`/`ipcidr`/`classical`). The default template's 21 providers total tens of MB, so `inline` depends on both the concurrency and `ruleset.Fetch`'s cache hit; downloading them serially on every request used to blow past `ruleProviderTimeout` and the server's `WriteTimeout`.
7. Marshaled YAML returned. The template is deep-copied per request via marshal/unmarshal (`deepCopyTemplate`) so concurrent requests don't mutate shared state.

**`clash.BaseURL`** is how the generated config addresses this server (`{Scheme, Host}`). The server builds it from the request's `X-Forwarded-*` headers (`baseURL(r)` in `internal/server/server.go`) and passes it into `Generate`; the clash package therefore never sees an `*http.Request`.

**Filesystem abstraction (`internal/vfs`):** At startup, probes whether the working directory is writable. If read-only (e.g., serverless), writes go to an in-memory overlay keyed by absolute path; reads check overlay first then disk. All callers must use `vfs.Load`/`vfs.Store`/`vfs.Stat` — never `os.ReadFile`/`WriteFile` directly — so the same code path works on a read-only host and on a server with disk.

**Cache (`internal/cache`):** `cache.Key(url)` = SHA1 → `./cache/<key>`; TTL is per-upstream from `upstreams.yaml`. `cache.IsOK` also rejects future mtimes (clock skew protection). When `DISABLE_CACHE` is set, both reads and writes are skipped (so it fully bypasses the cache, not just writes). Note `fetch.Download` treats the cache **only as an error fallback** — it never serves a hit. Callers that want a real cache hit must check `cache.IsOK` themselves, as `ruleset.Fetch` does.

**DictList (`internal/clash/dictlist.go`):** ordered map of `YamlStrDict` (= `map[string]any`) keyed by the dict's `name` field. Used everywhere proxies/groups need stable insertion-order output. `set` injects `name` into the value automatically.

**Endpoints (registered in `server.Handler`):**
- `GET /clash/config.yaml` — main generator. With no query params, serves the form UI (embedded `index.html`, or `./index.html` if present).
- `GET /upstreams-list` — JSON list of enabled upstreams for the form. Exposes only names and the `default` flag, never upstream URLs.
- `GET|POST /upstreams.yaml`, `GET|POST /template.yaml` — token-gated read/write of the two config files (token via `?token=`, `Authorization: Bearer …`, or `X-Auth-Token`; compared with `crypto/subtle.ConstantTimeCompare`). **If `TOKEN` is empty the handler returns 403 for everything** (fail closed).
- `GET /rule-providers?rule-set=NAME` — looks up `rule-providers[NAME].url` in the template and proxies it (used in `proxy` transform mode). Fetched through `fetch.Download(..., allowLocalSchemes=false)`, so only `http`/`https`.
- `/convert?url=…` — reverse proxy that fetches a raw rule list and rewrites it into Clash `payload:` YAML (`convertRawListToRuleProvider`, which always emits a valid `payload:` even for empty/comment-only input and is not cached when degenerate). `safehttp.ValidateUpstreamURL`/`IsDisallowedIP` block loopback/private/CGNAT(100.64/10)/link-local/multicast IPs (incl. IPv4-mapped); the reverse-proxy `Transport` is `safehttp.Transport`, which re-validates the dialed IP to defeat DNS rebinding. Result cached for 24h.

## Conventions and Gotchas

- Stick to `gopkg.in/yaml.v3`; the common in-memory shape is `YamlStrDict` (`map[string]any`). Helpers `asString`, `asStringList`, `asAnyList`, `asStringAnyMap`, `asStringAnyMapField` exist in `internal/clash/types.go` for the recurring `any → typed` coercions — prefer them over inline type assertions. `NewDictList` returns an error on malformed input (do not reintroduce `panic` on untrusted data).
- Errors returned from `buildConfig`'s parameter parsing are wrapped in `*badRequestError` (→ HTTP 400); inconsistent options are `*clash.InvalidConfigError` (→ 400); a zero-proxy result is `*clash.UpstreamUnavailableError` (→ 502); everything else is 500. `handleConfig` dispatches with `errors.As`, so preserve `Unwrap` when adding new failure modes.
- `Config.Generate` validates its own options first (unexported `validate()`) and returns `*InvalidConfigError` before fetching anything — there is no separate exported `Validate` for callers to forget.
- Sensitive query params and headers are scrubbed by `logRequest` (`token`, `secret`, `external_controller_addr`, `nameserver_policy`, `url`, `authorization`, `x-auth-token`). Add new sensitive fields to that allowlist if you introduce them. Outbound URLs are also logged via `safehttp.RedactURL` (strips userinfo/query) to avoid leaking subscription tokens.
- New query params must be added to `knownConfigQueryKeys` in `internal/server/config.go`, otherwise `warnUnknownQueryParams` will log a warning every request.
- The `tun` and `dns` template options are mutated only when their respective `tun=true`/`dns=true` query flags are set; otherwise the template's existing values pass through.
- Adding an organizer means: a matcher + entry in `DefaultNodeOrganizers` (`filter.go`), a checkbox in `index.html` (the JS derives the CSV from whatever `organizer-*` keys exist, so no JS change needed), and optionally a `healthCheckOverrides` entry in `config.go` if the group deserves a probe other than `generate_204`. Overrides are matched by **suffix** on the group name, so an airport named `foo-us` doesn't drag its `foo-us-jp` subgroup along.
- Platform detection (`Windows`/`Linux`/`Darwin`/`Android`/`Other`) is from the request `User-Agent` and currently affects only `tun.auto-redir` on Windows. Windows is matched first, so a UA naming two systems resolves to Windows.
- `upstreams.yaml` is gitignored (private). `cache/` is gitignored. `template.yaml` is also gitignored — it no longer exists in the repo; the base config lives in `internal/clash/template.go`. A `template.yaml` on disk is only an optional per-deployment override.
- `keep_upstream_select`, `custom_rules`, and `tun_auto_route` are accepted by `knownConfigQueryKeys` (so the front-end form doesn't trigger warnings) but are **not implemented** by the backend — wiring them up (e.g. a line-based parser for `custom_rules`, since rule values contain commas) or removing the `index.html` controls is open work.
- Template rule-provider URLs come in two forms: absolute (fetched as-is) and the relative `/convert?url=<raw list>` form. **The relative form is resolved in-process by `ruleset.Fetch`, never by calling our own `/convert` over HTTP** — a self-request is refused by `safehttp` whenever the server is bound to loopback or a private address, which is the default. This was a live 500 in both `inline` and `proxy` mode; don't reintroduce a `base.Resolve()` on these URLs. The SSRF guard still applies to the extracted target.
- Deployment: the supported target is the standalone Go binary (`./cctools`). `vercel.json` and `v1/` are legacy Python (the Flask app) and currently non-functional (`vercel.json` builds a root `index.py` that does not exist); don't assume the Go server is wired to Vercel.
