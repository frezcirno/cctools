# Repository Guidelines

## Project Structure & Module Organization

The supported application is the Go HTTP service. `cmd/cctools/` contains the executable entry point, while reusable implementation lives under `internal/`: `clash` generates and merges configurations, `server` owns HTTP handlers and the embedded `index.html`, `safehttp` protects outbound requests, and `fetch`, `ruleset`, `cache`, and `vfs` provide supporting layers. Keep tests beside their packages as `*_test.go`. Use `upstreams-example.yaml` as the public configuration example; local `upstreams.yaml`, `template.yaml`, and `cache/` are intentionally ignored. `v1/` and `vercel.json` describe the legacy Python deployment and should not drive new Go work.

## Build, Test, and Development Commands

- `go build -o cctools ./cmd/cctools` builds the standalone server.
- `./cctools` runs it on `127.0.0.1:9000`; use `LISTEN_ADDR=:8080 TOKEN=secret ./cctools` to override runtime settings.
- `go test ./...` runs the complete Go test suite.
- `go test ./internal/clash -run TestGenerateIsDeterministic` runs one focused test.
- `go vet ./...` performs standard static checks before review.
- `gofmt -w path/to/file.go` applies the required Go formatting.

## Coding Style & Naming Conventions

Follow idiomatic Go and `gofmt`; use tabs for Go indentation. Package names are short and lowercase, exported identifiers use `PascalCase`, and internal helpers use `camelCase`. Preserve package boundaries: HTTP request details belong in `internal/server`, while `internal/clash` remains transport-independent. Prefer existing YAML coercion helpers in `internal/clash/types.go` over unchecked assertions. Treat upstream data as untrusted: return descriptive errors rather than panicking, redact sensitive URLs, and route filesystem access through `internal/vfs`.

## Testing Guidelines

Use Go's standard `testing` package and table-driven cases where several inputs share behavior. Name tests `Test<Behavior>` and place them in the package being exercised. Add regression tests for malformed input, deterministic output, authentication, SSRF protections, and concurrency-sensitive changes. There is no stated coverage threshold; meaningful behavioral coverage and a passing `go test ./...` are required.

## Commit & Pull Request Guidelines

History is mixed, but recent descriptive commits use forms such as `feat: ...`, `refactor: ...`, and `harden: ...`. Prefer a concise imperative subject with an optional scope or type; avoid opaque messages such as dates or `update`. Pull requests should explain the problem and solution, note configuration or security impact, link relevant issues, and list verification commands. Include screenshots when changing `internal/server/index.html`, and never commit subscription URLs, tokens, generated caches, or private configuration.
