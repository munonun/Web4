> Status: experimental, test-validated.
>
> Web4 is a ledgerless peer-to-peer contract protocol.
> State is local. Consistency is structural.
> No global ordering.
> No global consensus, no global ledger, no replayable global history.
> Verified by tests, not promises.

# Web4

## Table of Contents
- [Quickstart](#quickstart)
- [CLI Basics](#cli-basics)
- [Crypto Handshake Suites](#crypto-handshake-suites)
- [P2P Survivability](#p2p-survivability)
- [Design Principles](#design-principles)
- [Validation](#validation)
- [What This Is / Is Not](#what-this-is--is-not)
- [Donation (Optional)](#donation-optional)

## Quickstart

Run tests first:

```bash
go test ./...
```

Run the smoke test used in this repo:

```bash
WEB4_DELTA_MODE=deltab WEB4_ZK_MODE=1 WEB4_STORE_MAX_BYTES=65536 ./scripts/smoke.sh
```

Run P2P stress harness (separate from smoke):

```bash
./scripts/p2p_stress.sh
```

Optional pprof (disabled by default):

```bash
WEB4_PPROF=1 WEB4_PPROF_ADDR=127.0.0.1:6060 web4-node run --devtls --addr 127.0.0.1:25050
go tool pprof "http://127.0.0.1:6060/debug/pprof/profile?seconds=30"
# heap:
go tool pprof "http://127.0.0.1:6060/debug/pprof/heap"
```

If tests and smoke pass, behavior matches current design.

## CLI Basics

`web4-node` is a local relay/verifier CLI.
It reports local observation only.

```bash
web4-node run --addr 127.0.0.1:25050
web4-node status
web4-node peers
```

## Crypto Handshake Suites

Handshake supports two suites:

- `Suite 0` (default): `X25519 + ML-KEM-768`, signatures by `SPHINCS+`
- `Suite 1` (legacy): `X25519`, signatures by `RSA-PSS`

Binding is explicit in the handshake signing scheme:

- session binding
- transcript binding
- ephemeral key binding

Meaning: transcript or suite tampering breaks verification.

## P2P Survivability

Network growth is daemon-side:

- bootstrap seeds for first contact
- connection manager for outbound maintenance
- periodic peer exchange (PEX) for discovery
- bounded peertable + eviction policy for spam resistance

Trust model separation is strict:

- seed/bootstrap is discovery only
- membership verification is separate
- hello/peer-exchange do not grant membership

## Design Principles

- No ledger, no global consensus, no replayable global history.
- DeltaB path transmits `Δb` updates only.
- Conservation constraint (`Lx = 0` form): invalid local imbalance is rejected.
- Gossip propagation instead of total ordering.
- Local verification over global narrative.

## Validation

Web4 prioritizes reproducibility of distributed behavior.

What validation focuses on:

- structural/message-size/type caps
- signature and tamper rejection
- bounded persistence and rotation invariants
- deterministic multi-node smoke behavior

This repository treats tests as the source of truth.

## What This Is / Is Not

What this is:

- a protocol experiment
- a ledgerless P2P contract model
- a test-first implementation

What this is not:

- a blockchain
- a PoW/PoS network
- production-ready software

## Donation (Optional)

Independent research project.

- Monero: `48NwwMKku48fKLYu7YN2S3hZM6iWX5WpRAoyC85AaUe8FZyTCHMRbJqGDNRdm3QdBDF8h71V9xJAJ1UUZKsnpyCRKXqQbiE`
- Bitcoin: `bc1qaz5dz2cze0me979j9prhxr6dc5x9j7esyhcxzp`

No promises. No donation-coupled roadmap.
