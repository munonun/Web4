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

## 7. Node Philosophy: Math Filter, No History

- Nodes enforce only invariants and transport hygiene.
- Nodes do not retain history or use reputation for validity.

---

**Additional Notes**
Interpretation and Extension of Δ **(Non-Normative)**


This section is non-normative.

It does not introduce new protocol rules, constraints, or consensus
mechanisms. All core invariants defined above remain unchanged.

The purpose of this section is to describe how Δ events MAY be
interpreted by implementations and users, without violating
the core invariants of Web4.

---

A Δ event is not a balance update, a transaction, or a state transition.

A Δ event represents a locally conserved change in obligations and
entitlements between participants.

Formally, Δ is a sparse vector Δb ∈ ℤⁿ such that:

    Σ Δb = 0

This expresses conservation of relations, not conservation of balances.

---

Δ is NOT:

- a global ledger entry
- a transfer of stored value
- a record of historical truth
- an object that requires global agreement

Web4 nodes do not agree on balances.
They only verify that a Δ event satisfies local conservation
at the moment it is received.

---

## Examples are illustrative; implementations MAY choose any interpretation consistent with invariants.

**Example 1: Bilateral relation**

    Δb = { A: -v, B: +v }

This MAY be interpreted as:
- A transferring an entitlement of size v to B, or
- A shifting an obligation of size v toward B.

The protocol does not distinguish between these interpretations.

---

**Example 2: Multi-party relation**

    Δb = { A: -10, B: +6, C: +4 }

This MAY represent a decomposition of a relation held by A
into relations held by B and C.

No balances are created or destroyed.
Only the structure of relations changes.

**Example 3: Reversal or revocation**

    Δb = { A: +5, B: -5 }

This MAY be interpreted as a partial reversal of a prior relation.
Such reversals are local interpretations and do not require
global history.

---

**The field φ is not part of the protocol.**

φ is a local observable derived from received Δ events.
Different nodes MAY compute different φ values.

φ is not transmitted, agreed upon, or verified.
Only Δ events are exchanged on the network.

---

Zero-knowledge proofs in Web4 are used solely to prove that
a Δ event satisfies the conservation constraints.

They do not prove ownership, intent, balance, or history.
They only prove validity of the relation at the time of interaction.

---

Future implementations MAY introduce additional interpretations
of Δ events, provided that:

- Δ remains locally conserved (ΣΔ = 0)
- No global history or ledger is introduced
- Verification remains local and bounded

Any such extensions are interpretations, not protocol changes.


## Net Position (Local Balance Definition)

Web4 does **not** define a global balance.

Instead, each node maintains a **local net position**, derived from the
rights it can immediately exercise and the obligations it must immediately honor.

Formally, for a node `X` at time `t`:
NetPosition(X, t)
= Σ ReceivableRights_X(t)
- Σ PayableObligations_X(t)

### Interpretation

- This value is **computed locally**.
- There is **no global ledger**, **no shared history**, and **no globally agreed balance**.
- Different nodes may observe different net positions for the same peer,
  depending on their local knowledge and scope membership.

A positive net position represents immediately exercisable rights.  
A negative net position represents immediately enforceable obligations.

### Relation to Δ (DeltaB)

State changes in Web4 are propagated as `Δb` messages, subject to the constraint:
ΣΔb = 0


This ensures that no value is created or destroyed at the network level.
All updates represent a **redistribution of rights and obligations** among participants.

### Enforcement Model

Web4 does not enforce balances globally.

Verification ensures only that:
- local constraints are satisfied (e.g., ΣΔ = 0),
- proofs are valid (when ZK is enabled),
- and updates are locally admissible.

Whether a right is exercised or an obligation is honored remains a **participant choice**,
not a network mandate.

### Design Implications

- No-chain
- No-global-history
- No-global-consensus
- Local verification only
- Rights and obligations exist only where they are observed and accepted

In Web4, a "balance" is not a fact.
It is a **local position**.