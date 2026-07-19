# Architecture

## Two preserved layers

The repository contains two explicitly different mechanisms.

### Legacy action wrapper

The v0.1.1 `gate(...)` context manager emits a local hash-chained receipt. It remains useful for small examples and backwards compatibility. Its records are unsigned.

### Proof-to-policy gateway

The v0.4 gateway receives already emitted source receipts or a pinned Assay
evidence bundle and produces a separately signed decision receipt. It never
edits or upgrades the source artifact.

```text
source bundle
  ├── OLP Wire Canon
  ├── Agent Receipts
  ├── Pipelock ActionReceipt v1
  ├── Assay Evidence Contract v1 bundle
  └── legacy Receipt Gate
        ↓
format adapter
        ↓
integrity / profile / provenance / coverage / source signal
        ↓
challenge, session, source, sequence, parent, freshness
        ↓
artifact hash + source commitment + policy assertion
        ↓
orthogonal outcome receipt
        ↓
policy evaluator
        ↓
signed decision receipt
        ↓ optional exact authorization
receiver-owned atomic consume → destination tool
```

## External authority

The policy file, trust store, signing key, session ledger, and optional Assay
executable are trusted caller inputs. They are not accepted from the untrusted
request body.

The request may carry source receipts or one Assay bundle descriptor,
disclosures, evidence locations, an outcome receipt, and a previously issued
binding. It cannot add a trusted key, select an executable, or change the
policy.

## Assessments

Each assessment has its own status and reason codes:

```text
pass
fail
partial
unavailable
```

`unavailable` differs from `fail`. Missing evidence produces `UNDECIDABLE`; altered evidence produces `REJECTED`.

For Pipelock, `source_signal` preserves the mediator's action verdict as a
required, separate input. `allow` does not imply `COMMIT`; `block` is a hard
failure. For Assay, it preserves the result of the receiver-registered exact-level
Trust Basis assertion: pass makes the bundle eligible as an input, while failure
is a hard failure. Other adapters carry a neutral pass for backward-compatible
semantics.

## Session state

`SessionLedger` issues a random one-time challenge bound to:

```text
run_id
session_id
sequence
parent_decision_hash
expected_source_hash
expiry
```

Successful validation consumes the nonce, remembers the source hash, advances the sequence, and records the decision hash as the next parent. Replayed or cross-run requests can receive signed rejection receipts without advancing the accepted decision chain.

## Semantic recomputation

The decision receipt carries the policy snapshot and every assessment. The Python and Node verifiers independently recompute:

```text
verdict
decision
reason codes
chain acceptance
policy hash
```

This catches a verdict, reason-code, or chain-acceptance rewrite that contradicts the included policy snapshot and assessment set, even if that inconsistent object is resealed with the gate key. The portable decision receipt does not include raw source or evidence, so these verifiers do not independently recompute the assessments themselves.

## Verified Model Swap boundary

The v0.5 model-swap profile is an orchestration layer over the two existing
systems. It does not copy Half-Life's compactor or create a second disposition
engine.

```text
verified raw Half-Life history -------------------+
                                                   +-> independent replay -> oracle
ordinary summary -> candidate projection ---------+                       |
verified capsule -> candidate projection ----------+-> exact comparison ---+
hash-addressed archive -> authenticated rehydrate -+                       |
                                                                           v
proof_card.json -> source-bound evidence -> Receipt Gate -> signed decision
                                                                           |
                                                                           v
                                                    DSM display-only projection
```

The receiver supplies the succession-policy pin, compaction-policy pin, trusted
gate key, policy, and grader identity. Model adapters supply candidate outputs;
they do not choose the oracle or disposition. `verified_model_swap.latest.json`
is a bounded display projection. A DSM client may render it but must not upgrade,
recompute, or certify the result.

## Verified Commit boundary

Verified Commit is a v0.4 extension inside the same signed decision. The
receiver's external policy selects the exact action; the request cannot grant
itself broader authority. The Gate hashes settings and a receiver-held one-use
code, binds them to tool, target, run, capsule, evidence, policy, and expiry,
and signs the result only when the disposition is already `COMMIT`.

```text
signed COMMIT + exact authorization + attempted action + receiver-held code
                                      |
                                      v
                           Python semantic verifier
                                      |
                                      v
                       receiver atomic consumption ledger
                          |                         |
                       BLOCK                    consume
                                                    |
                                                    v
                                            destination callback
```

The ledger is not portable proof. It is receiver-local enforcement state. Its
atomic consume occurs before callback invocation, so concurrent and sequential
replay fail closed within that shared ledger. Global coordination, bypass-path
mediation, and side-effect rollback remain deployment responsibilities.
