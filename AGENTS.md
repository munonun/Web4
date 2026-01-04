# Repository Guidelines

## Project Structure & Module Organization
This is a small Go CLI MVP. Key paths:
- `cmd/web4/main.go`: CLI entry point and command routing.
- `internal/crypto`, `internal/proto`, `internal/store`: core crypto, protocol types, and local storage.
- `README.md`: product/status notes and high-level command list.
Runtime data is written to `~/.web4mvp` (local keys plus `contracts.jsonl` and `acks.jsonl`).

## Build, Test, and Development Commands
- `go run ./cmd/web4`: run the CLI directly during development.
- `go build ./cmd/web4`: produce the `web4` binary.
- `go test ./...`: run all Go tests (none exist yet, but use this as the standard check).
CLI examples: `web4 keygen`, `web4 open --to <hex> --amount 1 --nonce 1`, `web4 list`.

## Coding Style & Naming Conventions
Follow standard Go conventions:
- Formatting: `gofmt` (tabs for indentation, gofmt-managed alignment).
- Naming: `CamelCase` for exported identifiers, `lowerCamel` for unexported, short package names like `crypto`.
- Keep protocol fields stable; changes in `internal/proto` impact stored data and command interop.

## Testing Guidelines
No automated tests are currently present. When adding tests:
- Place them alongside code as `*_test.go` in the same package.
- Prefer table-driven tests for protocol serialization and storage behavior.
- Run `go test ./...` before opening a PR.

## Commit & Pull Request Guidelines
Git history uses short, descriptive summaries (often with a version tag, e.g., `v0.0.2: ...`).
For PRs:
- Include a brief summary, how you tested (`go test ./...` or manual CLI steps), and any data format changes.
- Link related issues if applicable and call out breaking protocol/storage changes.

## Security & Configuration Tips
Keys are stored unencrypted in `~/.web4mvp` (`pub.hex`, `priv.hex`). Treat that directory as sensitive and avoid committing or syncing it.
This project is a research prototype; do not use with real value.
