> Status: experimental / test-validated

# Web4

Ledgerless P2P contracts.
Verified by tests, not promises.

Web4 is an experimental peer-to-peer protocol that removes the global ledger entirely.
No blockchain.
No validators.
No global consensus.

State correctness is enforced locally through structural constraints,
and validated through deterministic tests rather than social agreement.

---

## Motivation

Most distributed systems solve trust by adding structure:

- global ledgers
- consensus protocols
- validators and finality rules
- long-lived global history

Web4 explores the opposite direction.

What if we remove the global structure entirely,
and keep only what is mathematically unavoidable?

- no shared ledger
- no total ordering
- no replayable global history
- only local state transitions that must cancel out

If a transition does not conserve state locally,
it is invalid immediately.
There is no “later” reconciliation.

---

## Core design principles

### Ledgerless state

There is no global history to replay or synchronize.
Each node validates state transitions locally using conservation-style constraints.

If a state update cannot be balanced by another update,
it is rejected.

State correctness is local, not emergent.

---

### Gossip instead of ordering

Messages propagate probabilistically via gossip.
There is no canonical ordering of events.

If a message matters, it survives by redundancy.
If it does not propagate, it does not exist.

---

### Cryptography as enforcement

Cryptography is used to enforce invariants, not to decorate the protocol.

- all meaningful messages are signed
- payloads are end-to-end sealed with PFS
- message sizes and types are strictly capped
- malformed or replayed data is rejected structurally

Trust is minimized by construction.

---

### QUIC transport

All communication uses QUIC as the underlying transport.

- encrypted by default
- connection-oriented without TCP head-of-line blocking
- explicit framing and backpressure handling
- suitable for hostile or unreliable networks

## InviteCert + PoWaD admission (v0)
- NodeID = SHA3-256(pubkey).
- Admission uses a signed InviteCert from inviter to invitee.
- InviteCert fields include ids, times, scope, PoWaD params, and signature.
- Signing uses canonical binary encoding (not JSON).
- PoWaD digest: SHA3-256("web4:v0:powad|" || invite_id || invitee_nodeid || nonce_le).
- Valid if the top pow_bits of the digest are zero.
- Replay protection keys (inviter_nodeid, invite_id) are persisted.
- Scope bits gate gossip vs contract updates.
- Non-members are ignored for state-changing operations.

## Scopes, revocation, and approval bundles
- Scope bits: gossip (1), contract (2). Admin (4) is reserved for future use.
- Gossip and peer exchange require gossip scope; contract open/close/ack require contract scope.
- Revocation is inviter-scoped: only the original inviter can revoke an invitee.
  - Revocation is signed and replay-protected; it clears the target's scope to zero.
  - CLI: `web4 node revoke --to <nodeid> --reason <text>`.
- Optional 2-of-3 admission: set `WEB4_INVITE_THRESHOLD=2`.
  - Use invite bundles with ≥ threshold approvals over canonical bytes:
    `"web4:v0:invite_approve|" || invite_id || invitee_nodeid || expires_at || scope`.
  - CLI helpers: `web4 node approve-invite ...` and `web4 node join --bundle <file>`.

---

## Project scope

This repository is not a finished product.

What currently exists:

- cryptographic framing and signatures
- end-to-end sealed payloads with forward secrecy
- gossip push and forwarding logic with hop limits
- bounded storage with rotation invariants
- deterministic smoke testing for multi-node scenarios
- QUIC transport hardening (size caps, type caps, rate limits)

What does not exist yet:

- stable end-user CLI
- long-running public network
- production deployment assumptions

This is a protocol and testing infrastructure experiment.

---

## Deterministic testing focus

A core goal of Web4 is making non-deterministic P2P failures reproducible.

Distributed systems often fail in ways that cannot be replayed:
timing races, message loss, partial propagation, inconsistent forwarding.

Web4 includes deterministic multi-node smoke tests that:

- reproduce previously intermittent failures
- classify failures explicitly (timeout, no-conn, forwarding failure)
- allow repeated execution with identical outcomes

Correctness is demonstrated by tests, not claims.

---

## Validation

There is currently no stable user-facing workflow.

Instead, correctness is demonstrated through testing.

### Unit tests

```bash
go test ./...
```
### These verify:
- framing and size limits

- signature and tamper rejection

- storage rotation invariants

- sealed payload integrity

### Integration smoke tests
```bash
WEB4_STORE_MAX_BYTES=65536 ./scripts/smoke.sh
```
These tests exercise:

- real multi-node interaction

- gossip propagation paths

- persistence under load

- failure modes invisible to unit tests

If these pass, the system is behaving as designed.

## What this is not
- not a blockchain

- not a PoW or PoS system

- not a payment network (yet)

- not production-ready software

This repository is a research-driven protocol experiment.

## Philosophy
Most systems attempt to redistribute trust.

Web4 attempts to remove it.

Nodes do not reason about identity, reputation, or history.
They only enforce invariants and transport hygiene.

If a state transition violates conservation,
it should not exist at all.

Falsifiability is valued over completeness.

---

## Donation (optional)
This project is developed independently.

If you wish to support continued research and experimentation, donations are welcome.
(Monero: 42tRSXZRK4bNV18dqXcEsuDpb8UbrYu8oViosk1M5b6PFSYL1PxDhfW7d2xLFQaunaMwuH1jRMrPjbtk7niZDN9UMSmkum4)
(Bitcoin: bc1qaz5dz2cze0me979j9prhxr6dc5x9j7esyhcxzp)

No promises. No roadmap tied to donations.

---
