# Web4 MVP v0.0.3 Security Audit (Local, Pre-P2P)

Scope: current repository state in `cmd/web4`, `internal/network`, `internal/store`, `internal/math4`, `internal/proto`.

Legend:
- Risk: High / Med / Low
- Current: what code does now (with file/func)
- Patch plan: minimal change proposal
- Test/Repro: how to demonstrate or protect against regression

---------------------------------------------------------------------
A. Network/Transport (QUIC) — DoS/Slowloris/Resource Limits
---------------------------------------------------------------------

[A1] Connection/stream limits
- Risk: Med
- Scenario: attacker opens many connections/streams, consuming goroutines and memory.
- Current: `internal/network/quic.go:ListenAndServeWithReady` sets `MaxIncomingStreams`, `MaxIncomingUniStreams`, `MaxIdleTimeout`, and uses global semaphores `maxConnHandlers=128`, `maxStreamHandlers=128` with `acquireTimeout=100ms`.
- Patch plan: add per-IP connection and stream limits with TTL eviction; reject early with `CloseWithError` when per-IP quota exceeded.
- Test/Repro: open N connections from same IP in a loop; assert connection rejected after limit; add unit test for limiter map with TTL.

[A2] Timeouts/deadlines
- Risk: Low
- Scenario: slowloris by sending partial frame or extremely slow payload.
- Current: `readFrameWithTimeout` sets `SetReadDeadline` or uses context timeout (`streamRWTimeout=5s`), and `quic.Config.HandshakeIdleTimeout=10s`.
- Patch plan: keep as-is; optionally tighten `streamRWTimeout` or make configurable.
- Test/Repro: send only length prefix over QUIC and wait > timeout; ensure server closes stream (manual test).

[A3] Message size limits
- Risk: Med
- Scenario: repeated 1MiB frames with valid JSON to drive CPU/IO even if type-specific caps should reject.
- Current: frame cap `internal/proto/envelope.go:MaxFrameSize=1MiB`. Type caps applied after JSON unmarshal in `cmd/web4/main.go:recvData`.
- Patch plan: introduce a smaller QUIC read cap for message types, or parse a lightweight header with a streaming decoder to early-exit when size > type cap; alternatively reduce `MaxFrameSize` for QUIC path.
- Test/Repro: send many near-1MiB frames with type `contract_open` and verify rejection without excessive CPU; add load test (manual).

[A4] TLS/dev mode safeguards
- Risk: Med
- Scenario: dev deterministic TLS cert used in production by mistake.
- Current: `internal/network/quic.go:serverTLSConfig` always uses deterministic dev cert; no flag gate. Client supports `--insecure` to skip verify.
- Patch plan: add `--devtls` flag requirement; refuse `quic-listen` unless `--devtls` or explicit production cert path; log warning when `--insecure`.
- Test/Repro: run `web4 quic-listen` without `--devtls` and expect failure (test or manual).

---------------------------------------------------------------------
B. Message/Crypto (recv validation) — ordering/oracles
---------------------------------------------------------------------

[B1] recv validation order
- Risk: Low
- Scenario: store write before validation.
- Current: `cmd/web4/main.go:recvData` validates metadata, signatures, decrypts payload, matches header/payload, checks state machine, then writes to store. No store writes on failure.
- Patch plan: keep as-is; add regression test for store not mutated on failure (see test plan below).
- Test/Repro: tamper sig and assert contracts/acks/repayreqs files unchanged (new test).

[B2] Error oracle risk
- Risk: Med
- Scenario: detailed errors leak contract existence, role (creditor/debtor), or signature validity.
- Current: `cmd/web4/main.go:recvData` returns detailed error strings and `die` prints them; QUIC path also logs details.
- Patch plan: for external-facing recv, return/print a generic `invalid message` while logging detailed reasons only in debug mode.
- Test/Repro: send invalid message variants and confirm public error is constant; internal log still has details.

[B3] ACK reqnonce ambiguity
- Risk: Med
- Scenario: ACK always uses latest repay_req nonce (`MaxRepayReqNonce`), so concurrent repay requests can be mis-acked.
- Current: `cmd/web4/main.go` ignores ack reqnonce (not in protocol), decrypts using max nonce and validates payload without reqnonce field.
- Patch plan: protocol bump to include `reqnonce` in `AckMsg` and `AckPayload`; verify that ack matches specific repay request; keep backward compatibility if needed.
- MVP policy (documented): only one outstanding repay_req per contract. ACK always refers to latest.
- Test/Repro: create two repay requests, send ack for older one; expect rejection after patch.

[B4] AEAD AAD binding
- Risk: Low
- Scenario: encrypted payload not bound to header metadata.
- Current: AEAD uses nil AAD in `e2eSeal`/`e2eOpen`.
- Patch plan: bind header fields as AAD in a future protocol bump; document TODO.
- Test/Repro: (future) ensure header tamper causes decrypt failure.

---------------------------------------------------------------------
C. State Machine/Replay
---------------------------------------------------------------------

[C1] State transitions enforced
- Risk: Low
- Scenario: out-of-order or replay messages accepted.
- Current: OPEN creates only when no CLOSED; repay_req requires OPEN and monotonic nonce (`> max`); ACK requires repay_req and rejects on CLOSED.
- Patch plan: optionally enforce `reqnonce == max+1` for stricter ordering (document choice).
- Test/Repro: send repay_req with lower nonce and assert rejection (already in code). Add tests for `reqnonce != max+1` if strict mode added.

[C2] Idempotency
- Risk: Low
- Scenario: duplicate messages cause store duplicates.
- Current: `HasRepayReq`, `HasAck`, and OPEN duplicate checks avoid duplicates; duplicates after CLOSED are rejected.
- Patch plan: keep; consider returning typed duplicate error for analytics.
- Test/Repro: existing tests cover duplicates; extend to QUIC path if needed.

---------------------------------------------------------------------
D. Store/JSONL — disk DoS, atomicity
---------------------------------------------------------------------

[D1] Disk fill / unbounded growth
- Risk: High
- Scenario: attacker floods valid messages causing unlimited JSONL growth.
- Current: no size/line count limits in `internal/store/store.go`.
- Patch plan: add max file size/line limits with rotation or rejection; optionally per-contract event cap.
- Test/Repro: write N lines until limit and verify rejection/rotation; unit test for size cap.

[D2] Partial write / atomicity
- Risk: Low
- Scenario: crash mid-write leads to corrupted trailing line.
- Current: append writes are fsynced; reads ignore JSON parse failures and continue scanning; `MarkClosed` uses tmp+rename with fsync.
- Patch plan: optionally detect and truncate trailing partial line on startup or write via temp + append; document behavior.
- Test/Repro: inject a broken last line, ensure readers skip without panic; add unit test for parser.

[D3] Scanner token limit
- Risk: Low
- Scenario: oversized line triggers scan error and blocks reads.
- Current: scanner buffer max `2*MaxFrameSize`; methods return scanner errors.
- Patch plan: on `ErrTooLong`, return a typed error and refuse further processing; optionally cap by file size to avoid DoS.
- Test/Repro: write oversized line and assert `ErrTooLong` propagation.

---------------------------------------------------------------------
E. Local Math Layer (math4)
---------------------------------------------------------------------

[E1] Restart bypass (memory-only)
- Risk: Med
- Scenario: attacker restarts node to reset decay scores and inject bursts.
- Current: in-memory `internal/math4` scores reset on restart.
- Patch plan: add cold-start throttling (lower thresholds for first N updates or T seconds), or rate limit updates in memory.
- Test/Repro: simulate restart and immediate burst; expect rejection once cold-start is enabled.

[E2] Enforcement point
- Risk: Low
- Scenario: repay_req not checked; only OPEN and accepted ACK apply updates.
- Current: `cmd/web4/main.go:recvData` checks math4 on OPEN and decision==1 ACK.
- Patch plan: optional proposal-time check on repay_req, or explicitly document accept-time-only policy.
- Test/Repro: add test for proposal-time rejection if enabled.

---------------------------------------------------------------------
F. Exit Criteria (pre-P2P)
---------------------------------------------------------------------

Status summary against checklist:
- [ ] External input cannot grow goroutines/memory/disk without bounds (global semaphores exist, but per-IP limit and disk caps missing).
- [x] recv failures do not write to store (validated in flow).
- [x] State machine/replay mostly enforced (monotonic nonce, CLOSED rejects).
- [ ] Error messages are oracle-resistant (currently verbose).
- [~] Store handles partial lines but no explicit policy; size caps missing.
- [x] math4 prevents burst injection (unit/integration tests exist), but restart bypass remains.

Recommended minimal patch set before P2P:
1) Add disk size/line caps with rotation (`internal/store`).
2) Add per-IP rate/connection limiting in QUIC server.
3) Add generic error surface for recv while keeping debug logs.
4) Add `--devtls` guard for QUIC listener.
5) Decide strict ACK reqnonce behavior (document or bump protocol).
