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

---

## Debt, Rights, and Net Position in Web4

Web4 does not define money as a balance.
It defines money as **constraints on future actions**.

### Extended Interpretation of Debt and Rights

Traditional definitions:
- **Debt**: something I must do later
- **Right**: something I may demand later

Web4 generalizes this:

- **Debt**  
  A state that **reduces my future action space**.  
  The more debt I hold, the fewer choices I can freely make.

- **Right**  
  A capability that **restricts another participant’s future actions**.  
  A right is effectively a *key* that can unlock or force behavior from others.

Debt shrinks *my* future.  
Rights shrink *your* future.

Value in Web4 is nothing more than the distribution of these constraints.

---

## Net Position (Local Balance Definition)

Web4 defines no global balance.

Instead, each node computes a **local net position**:

**`t` is not a global timestamp.
It denotes the moment of local observation only.**
NetPosition(X, t)
= Σ ReceivableRights_X(t)
− Σ PayableObligations_X(t)

---

This value represents:

- how much **freedom X has gained** over others,
- minus how much **freedom X has already surrendered**.

### Properties

- Computed **locally**
- Not globally agreed
- Not synchronized
- Not recorded historically

Two nodes may compute different net positions for the same peer.
Both can be correct within their local view.

A positive net position means:
> “I can act without restriction.”

A negative net position means:
> “My future actions are constrained.”

---

## Δ (Delta) as Redistribution of Constraints

All state changes propagate as `Δb` messages.

Each `Δb` represents a **redistribution of rights and obligations**, not a payment.

Constraint:
Σ Δb = 0

---

This guarantees:

- No creation of value
- No destruction of value
- Only redistribution of constraints

Money is not issued.  
Money emerges from relative imbalance.

---

## Why Double Spending Is Impossible

Double spending is **not prevented** in Web4.

It is **undefined**.

Why:

1. Every update must satisfy:
Σ Δ = 0
2. Every update must satisfy:
Lx = 0


Any attempt to “spend twice” violates at least one of these.

If it violates conservation → rejected  
If it violates Laplacian continuity → rejected  

There exists no valid vector that encodes “double spending”.

---

## Dispute Model

Web4 recognizes **two kinds of disputes**.

### 1. Mathematical Disputes

Question:
> “Is this state valid?”

Resolution:
> "Compute Lx"


- If `Lx = 0` → valid
- If `Lx ≠ 0` → invalid

No interpretation.
No voting.
No consensus.

Pure computation.

---

### 2. Social Disputes

A participant may say:
> “I refuse to honor this obligation.”

This is allowed.

Web4 does **not** force repayment.

However:

- Nodes track local behavior
- Repeated refusal increases perceived risk
- Transaction cost (trust, negotiation overhead) increases

Eventually:
- No one accepts updates involving the malicious node
- Its `Δ` remains permanently negative
- The node becomes economically isolated

No punishment is required.
Isolation emerges naturally.

---

## Enforcement Philosophy

Web4 enforces **validity**, not **obedience**.

The network guarantees:
- mathematical consistency,
- conservation,
- local admissibility.

The network does *not* guarantee:
- repayment,
- fairness,
- moral behavior.

Freedom includes the freedom to default.
Default includes the cost of exclusion.

---

## Summary

- No balance, only net position
- No money, only constraints
- No double spending, only invalid math
- No forced repayment, only social consequence
- No global truth, only local verification

In Web4:

**Value is not a fact.  
It is a position.**
