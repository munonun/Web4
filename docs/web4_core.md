# Web4 Core Invariants (Authoritative)

This document defines non-negotiable design constraints of Web4.
All code MUST respect these invariants.

## 1. State Model

- Web4 stores NO ledger, NO history, NO timestamps, and NO global ordering.
- The only system state is an instantaneous imbalance vector:
  Δ = (Δ₁, Δ₂, …, Δₙ)

## 2. Conservation Law

- The global sum of imbalances is always zero:
  ∑ Δᵢ = 0
- There is no issuance, minting, burning, or inflation.

## 3. Validity Condition

- A state x is valid if and only if:
  Lx = 0
  where L is the network Laplacian.
- Any update that violates this condition is invalid,
  without referencing any past state or history.

## 4. Transaction Model

- Transactions are local negotiations between participants.
- No consensus, blocks, or global synchronization exists.
- Only the resulting state vector matters.

## 5. Security Principle

- Security is enforced by mathematical impossibility
  (conservation + Laplacian constraints),
  not by historical comparison or consensus.
- Cryptography (XChaCha20, HMAC-SHA3, ZK, signatures)
  is an authentication and confidentiality layer only.

## 6. Prohibited Designs

The following are explicitly forbidden:

- Ledgers or transaction logs
- Global ordering or consensus mechanisms
- Account balances or UTXO-style models
