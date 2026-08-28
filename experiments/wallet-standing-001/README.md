# Wallet Standing 001

**Frozen verdict:** `EPOCH_REVOCATION_ENFORCED_WITH_BOUNDED_OFFLINE_LAG`

WALLET-STANDING-001 tests the smallest honest wallet boundary for OpenLine:

> Wallet owns continuity; Gate owns consequences.

The wallet holds principal history, replaceable epoch keys, signed mandates, and
selectively disclosed evidence. The receiver-owned Gate decides whether one
specific action may execute under its own freshness policy. A portable wallet
bundle has `policy_authority: NONE`.

This is an experiment kernel, not a production wallet, witness network, or
account-recovery system.

## What the kernel implements

- A long-lived principal root certifies replaceable epoch signing keys.
- Epoch keys issue subject-bound, expiring mandates.
- Each top-level mandate field receives a random 32-byte salt checked against
  an epoch-scoped reuse registry, then a Merkle commitment, allowing selected
  fields to be revealed with proofs.
- The subject signs a receiver challenge over the exact certificate, mandate,
  and projection, so a copied projection is not a bearer credential.
- High-risk actions require a fresh root-signed standing witness.
- Low-risk actions may use an expiry-only path when the signed lifetime fits
  the receiver's frozen offline limit.

No blockchain is involved. The principal root is a pinned trust anchor; the
receiver still owns admission policy and execution.

## Frozen test

The benchmark runs ten predeclared arms:

| Arm | Condition | Expected |
|---|---|---|
| 1 | High risk, fresh ACTIVE witness | pass |
| 2 | High risk, fresh REVOKED witness | block |
| 3 | High risk, stale ACTIVE witness | block |
| 4 | High risk, missing witness | block |
| 5 | Root-certified successor epoch | pass |
| 6 | Independent root-certified sibling epoch | pass |
| 7 | Low risk, within ten-minute TTL, no witness | pass |
| 8 | Low risk, revoked elsewhere but still unexpired offline | pass, declared exposure |
| 9 | Same low-risk mandate at exact expiry | block |
| 10 | Altered projection, proof, bearer, and challenge variants | block all |

All ten arms pass. High-risk stale execution is zero, and revoking the first
epoch causes no collateral loss to the independent sibling.

## The result, precisely

Given a controlled signed standing witness, the receiver enforces epoch
revocation within its declared freshness budget. Offline low-risk authority is
bounded by its signed lifetime. Selective disclosure preserves the signed
Merkle root, and holder proof prevents the revealed bundle from becoming a
tradeable permission slip.

The run also demonstrates the unavoidable limit: a Gate that has never learned
about a later revocation cannot infer it from an older offline bundle. In this
fixture the maximum admitted lag is 600 seconds. Lowering that bound requires
shorter mandates or fresher information, not a different slogan for local-first.

## Boundaries

- Witness creation is controlled and local. Distribution, replication,
  cross-device delivery, and availability are untested.
- The principal root remains intact. Root loss, compromise, recovery quorum,
  and root succession are untested.
- Merkle disclosure covers top-level fields under OpenLine's integer-only JSON
  profile. It does not provide unlinkability or hidden predicates.
- Deterministic salts are used only in the frozen fixture. Normal issuance uses
  `secrets.token_bytes(32)` and an epoch-scoped registry rejects reuse across
  mandates.
- No production CLI, secure key store, network service, or UI is claimed.

Those boundaries define the next falsifiers: root succession belongs in
WALLET-STANDING-002; real witness propagation to a virgin Gate belongs in
WALLET-STANDING-003.

## Run

From the repository root:

```bash
python -m unittest discover -s experiments/wallet-standing-001/tests -v
python experiments/wallet-standing-001/scripts/run_frozen.py
python experiments/wallet-standing-001/scripts/verify_release.py
```

The run rewrites `frozen_result.json` deterministically. The release verifier
checks every frozen file, arm, metric, boundary, and authority label.
