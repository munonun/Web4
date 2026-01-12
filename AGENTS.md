# Repository Guidelines

## Project Structure & Module Organization
- `cmd/web4/` is the CLI entry point (binary build target).
- `internal/` holds core packages (crypto, proto, network/QUIC, peer/store, state, math4, node).
- `scripts/` contains operational tooling like the real-world smoke test.
- `docs/` contains design notes; `VULN.md` tracks risks and mitigations.

## Build, Test, and Development Commands
- `go build -o ./web4 ./cmd/web4` builds the CLI binary locally.
- `go test ./...` runs the unit test suite across all packages.
- `WEB4_STORE_MAX_BYTES=65536 ./scripts/smoke.sh` runs the smoke test that exercises QUIC, recv error handling, and store rotation.

## Coding Style & Naming Conventions
- Follow standard Go formatting (use `gofmt`); tabs for indentation.
- Package names are short and lowercase (Go convention).
- Exported identifiers use `PascalCase`, unexported use `camelCase`.
- Test files use `*_test.go` and live next to the code they cover.

## Testing Guidelines
- Unit tests are in `*_test.go` under `cmd/` and `internal/`.
- Run `go test ./...` before submitting changes.
- Smoke testing is required for changes that touch transport, storage, or recv logic; it needs `WEB4_STORE_MAX_BYTES` set and may open local QUIC listeners.

## Commit & Pull Request Guidelines
- Commit messages follow short, imperative summaries (e.g., "Update README").
- Keep commits focused and scoped to a single change.
- PRs should include: a brief summary, rationale, and test output (e.g., `go test ./...`, smoke test if applicable).

## Security & Configuration Notes
- Detailed recv errors are gated behind `WEB4_DEBUG=1`; keep default behavior generic.
- `--devtls` is for development only; avoid shipping it in production configs.
- Review `VULN.md` when modifying cryptography, validation, or transport.
