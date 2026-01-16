> Status: experimental / test-validated

# Web4-MVP

**Ledgerless P2P contracts. Verified by tests, not promises.**

Web4-MVP is an experimental peer-to-peer contract protocol that removes the global ledger entirely.  
No blockchain. No validators. No global consensus.

State is conserved locally through mathematical constraints,  
and correctness is demonstrated through tests and real smoke runs.

---

## Why this exists

Blockchains solve trust by **adding structure**:
ledgers, consensus, validators, staking, finality rules.

Web4 explores the opposite direction.

What if we **remove** the global structure entirely,
and only keep what is mathematically unavoidable?

- No shared ledger.
- No global history.
- Only local imbalance updates that must cancel out.

---

## What makes this different

- **No global ledger**  
  There is nothing to sync, replay, or finalize.

- **Local correctness instead of global consensus**  
  State transitions are validated locally using Laplacian-style constraints,
  meaning every local imbalance must be canceled by another.

- **Gossip instead of ordering**  
  Messages propagate probabilistically, not sequentially.

- **Cryptography as enforcement, not decoration**  
  Every meaningful message is signed, framed, size-capped, and E2E sealed.

---

## Project status (honest)

This is **not** a finished product.

What *is* ready:

- crypto primitives, framing, and signatures
- E2E sealed payloads with PFS
- gossip push plumbing with hop limits and fanout
- store rotation and lookup correctness
- QUIC transport hardening (type caps, size limits, rate limiting)

What is **not** ready yet:

- a stable end-user CLI
- long-running multi-node demo
- production deployment assumptions

---

## How this project is validated

There is currently no stable `./web4` workflow for users.

Instead, correctness is demonstrated via tests.

### 1) Unit tests

```bash
go test ./...
```
These tests verify:

- message framing and size caps
- signature and tamper rejection
- store rotation invariants
- sealed payload integrity


### 2) Integration smoke run

```bash
WEB4_STORE_MAX_BYTES=65536 ./scripts/smoke.sh
```

The smoke run exercises:

- real node interaction
- gossip forwarding paths
- persistence under pressure
- failure modes that unit tests do not cover

If these pass, the system is behaving as designed.

---

## Core ideas (no math, just intuition)

### Ledgerless state
Every update must cancel somewhere else.  
If it doesn’t, the update is invalid. There is no “later”.

### Gossip propagation
There is no ordering, only spread.  
If a message matters, it survives by redundancy.

### Trust minimization
Peers are authenticated, but not trusted.  
Validity is structural, not social.

---

## What this is NOT

- not a blockchain
- not a PoS / PoW system
- not a payment network (yet)
- not production-ready

This repository is a protocol experiment, not a startup pitch.

---

## Philosophy

Most systems try to redistribute trust.

Web4 tries to remove it.

If a state transition violates conservation,  
it should not exist at all.

---
This project values falsifiability over completeness.
