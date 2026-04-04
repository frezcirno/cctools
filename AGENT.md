# cctools - Clash Configuration Generator

## Project Overview

cctools is a Clash proxy configuration generator and management server. It aggregates proxies from multiple upstream subscription sources ("airports"), merges/deduplicates them, and dynamically generates customizable Clash YAML configurations via HTTP API.

## Tech Stack

- **Language:** Go 1.19
- **Dependencies:** `gopkg.in/yaml.v2`
- **Frontend:** Vanilla HTML/JS (`index.html`)
- **Legacy:** Python/Flask implementation in `v1/`

## Project Structure

```
├── main.go                   # HTTP server, request handlers, entry point
├── config.go                 # Configuration generation pipeline (core logic)
├── common.go                 # Core types and domain models
├── cache.go                  # TTL-based caching system
├── request.go                # HTTP/HTTPS/file downloads with caching
├── rule-provider-proxy.go    # Rule provider reverse proxy and conversion
├── fs.go                     # File system abstraction (real FS / in-memory overlay)
├── dictlist.go               # DictList data structure (name-keyed YAML dict)
├── filter.go                 # Regex-based proxy filtering (CN, HK, TW, US, UDP)
├── config_test.go            # Unit tests
├── template.yaml             # Clash config template
├── upstreams.yaml            # Upstream proxy sources (private)
├── upstreams-example.yaml    # Example upstreams format
├── index.html                # Web UI form
├── vercel.json               # Vercel deployment config (Python version)
├── v1/                       # Legacy Python implementation
└── cache/                    # Cached upstream configurations
```

## Build & Run

```bash
# Build
go build -o cctools

# Run (listens on 127.0.0.1:9000)
./cctools

# Test
go test ./...
```

## HTTP Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/clash/config.yaml` | GET | Generate Clash config (accepts query parameters) |
| `/upstreams.yaml` | GET/POST | Load/upload upstream configurations (token auth) |
| `/template.yaml` | GET/POST | Load/upload Clash template (token auth) |
| `/rule-providers` | GET | Download rule providers with caching |
| `/convert` | GET | Reverse proxy for rule provider format conversion |

## Architecture

**Data Flow:**

1. HTTP request with query parameters received
2. Parameters parsed into `Config` struct
3. Selected upstreams fetched concurrently (max 8 parallel, with caching)
4. Proxies and groups merged/deduplicated
5. Proxy groups built (URL-test groups for upstreams, organizers, selectors)
6. Rule providers transformed (none / proxy / inline modes)
7. Template deep-copied, modified, marshaled to YAML and returned

**Key Design Decisions:**

- **File system abstraction:** Dual-mode (real FS or in-memory) to support read-only/serverless deployments
- **Cache fallback:** On upstream download failure, falls back to cached data
- **Proxy conflict resolution:** Appends random suffix on name collision
- **Platform-aware:** Adjusts config for Windows/Linux/macOS/Android
- **Sensitive data sanitization:** Strips tokens/secrets from logs

## Key Query Parameters

- `upstream` - Comma-separated upstream names/tags
- `organizer` - Proxy organizers (cn, tw, us, oversea, udp)
- `port`, `socks_port`, `mixed_port` - Port numbers
- `tun` - Enable TUN mode
- `dns` - Enable DNS
- `rule_provider_transform` - Rule provider mode (none/proxy/inline)
- `allow_lan`, `bind_address` - Network binding
- `tproxy` - Transparent proxy mode

## Coding Conventions

- Single Go module, all source files in root package `main`
- YAML marshaling via `gopkg.in/yaml.v2` with `YamlStrDict` (`map[string]any`) as the common data type
- Error types: `ErrInvalid`, `ErrNotExist`
- No external web framework; uses `net/http` stdlib
