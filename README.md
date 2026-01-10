# Web4 MVP

This repository contains a hardened MVP implementation of the Web4 model.

Web4 is an attempt to remove the structural causes of deanonymization and coercion
in distributed systems by eliminating global ordering, permanent history, and
consensus-driven state. Instead of ledgers or blockchains, Web4 relies on stateless,
end-to-end encrypted message flows that are validated strictly at receive time.

This codebase is not a conceptual proof-of-concept. It is a tested and abuse-hardened
MVP that demonstrates the Web4 approach as running software. The design is grounded
in the accompanying whitepaper (Web4.pdf), but the repository intentionally focuses
on implementation correctness rather than theoretical exposition.

At its core, the system implements end-to-end encrypted message exchange with
per-message perfect forward secrecy. There is no global ledger, no consensus layer,
no timestamps, and no attempt to construct a shared notion of history. All protocol
semantics are enforced locally at receive time, and correctness is defined strictly
in terms of cryptographic validity, bounded behavior, and local invariants.

Messages are sealed and signed, providing tamper detection and replay protection.
External error handling is deliberately coarse: all invalid inputs are rejected
with a generic error to avoid signature, state, or decryption oracles. Detailed
failure information is only available in explicit debug mode.

Transport is implemented over QUIC and hardened against local denial-of-service.
Connections and streams are limited on a per-IP basis, oversized frames are rejected
early based on message type, and deterministic development TLS is gated explicitly
behind a dev flag. Local storage is append-only and rotates automatically under
size and line caps to prevent disk-fill attacks, while still preserving lookup
correctness across rotated files.

The system also enforces a local mathematical guard on state transitions. Updates
are bounded in magnitude, and stricter limits are applied immediately after restart
to prevent cold-start burst abuse. This enforcement is intentionally local and does
not rely on any global coordination.

The repository is structured around a single CLI entry point in `cmd/web4`, with
internal packages handling cryptography, wire framing, storage, transport, and
local invariant checking. A real-world smoke test script (`scripts/smoke.sh`) is
provided to validate runtime behavior under actual conditions rather than mocks.

All changes are expected to pass both unit tests and real-world smoke tests. The
smoke test performs actual actions to verify store rotation under disk pressure,
recv oracle suppression, and QUIC per-IP limiter behavior. It can be run as follows:

```bash
To run tests:
go test ./...

WEB4_STORE_MAX_BYTES=65536 ./scripts/smoke.sh
```

The project is currently in an MVP, pre-P2P state. The core protocol, cryptographic
layer, local invariants, and transport hardening are implemented and tested. Peer
discovery, routing, and any form of network-level aggregation are intentionally
out of scope at this stage and will be built on top of the existing, hardened core.

Web4 deliberately avoids the construction of global truth. Instead, it limits itself
to enforcing what can be enforced locally, cryptographically, and deterministically.
This repository exists to demonstrate that such a system can be built, tested, and
reasoned about as real software.

This is experimental research software. There are no stability guarantees, no
backwards compatibility promises, and no claims of production readiness.