# Web4

Web4 is an attempt to escape the structural limits of existing decentralized
systems.

Most systems marketed as “decentralized” still depend on global ordering,
permanent records, and consensus-driven state. These properties make anonymity
fragile, coercion inevitable, and history inescapable. Once data enters a global
ledger, it becomes impossible to forget, retract, or locally disagree.

Web4 starts from a simple premise:  
**if global history is the root of the problem, then global history must be
removed.**

Instead of ledgers or blockchains, Web4 is built around stateless, end-to-end
encrypted message flows. There is no global ordering, no shared timeline, and no
attempt to construct a single source of truth. Correctness is enforced locally,
at receive time, using cryptography and bounded local rules rather than network-
wide agreement.

This repository contains a hardened MVP implementation of that idea.

---

## From idea to running software

This codebase is not a conceptual proof-of-concept. It is a running,
abuse-hardened MVP that demonstrates the Web4 model as real software.

At its core, the system implements end-to-end encrypted message exchange with
per-message perfect forward secrecy. Each message uses a fresh ephemeral key,
so compromise of long-term keys does not reveal past traffic. Messages are
sealed and signed, providing tamper detection and replay protection.

There is no global ledger, no consensus layer, and no timestamps. All protocol
semantics are enforced strictly at receive time. If a message is invalid, it is
rejected locally and silently. External error handling is deliberately generic
(`invalid message`) to avoid signature, state, or decryption oracles. Detailed
failure information is only available in explicit debug mode.

Transport is implemented over QUIC and hardened against local denial-of-service.
Connections and streams are limited on a per-IP basis, oversized frames are
rejected early based on message type, and deterministic development TLS is gated
explicitly behind a dev flag. The system is designed to fail closed under abuse.

Local storage is append-only and intentionally limited in scope. Records are
stored only to support local validation and replay protection. To prevent
disk-fill attacks, storage rotates automatically under size and line caps while
preserving lookup correctness across rotated files. There is no attempt to
construct a durable or authoritative history.

In addition to cryptographic checks, the MVP enforces a local mathematical guard
on state transitions. Updates are bounded in magnitude, and stricter limits are
applied immediately after restart to prevent cold-start burst abuse. This
enforcement is local by design and does not rely on any form of global
coordination.

---

## Structure and verification

The repository is organized around a single CLI entry point in `cmd/web4`, with
internal packages handling cryptography, wire framing, storage, transport, and
local invariant checking. A real-world smoke test script (`scripts/smoke.sh`) is
included to validate runtime behavior under actual conditions rather than mocks.

All changes are expected to pass both unit tests and real-world smoke tests.
The smoke test performs actual actions to verify store rotation under disk
pressure, recv oracle suppression, and QUIC per-IP limiter behavior.

```bash
go test ./...

WEB4_STORE_MAX_BYTES=65536 ./scripts/smoke.sh
```

A record of identified risks, design trade-offs, and mitigations is maintained
in VULN.md. This document is part of the project, not an afterthought.

---

**Current status**

This project is currently in an MVP, pre-P2P and node state.

The core protocol, cryptographic layer, local invariants, and transport
hardening are implemented and tested. Peer discovery, routing, and any form of
network-level aggregation are intentionally out of scope at this stage and will
be built on top of the existing, hardened core.

Web4 deliberately avoids the construction of global truth. It enforces only what
can be enforced locally, cryptographically, and deterministically. The goal is
not to replace one global system with another, but to remove the need for global
systems altogether.

---

**Disclaimer**

This is experimental research software.

There are no stability guarantees, no backwards compatibility promises, and no
claims of production readiness. The purpose of this repository is to explore,
test, and refine the Web4 model as working code.