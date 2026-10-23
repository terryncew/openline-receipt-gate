# Trust Model

How an external receiver decides what to trust, and the explicit bounds
on every security property. No hand-waving.

## Principals

- **Owner:** Holds the Wallet root key. Issues and revokes mandates.
  Identified by `principal_id` (derived from the root public key).
- **Worker:** Holds a subject keypair. Named in a mandate. Proves key
  ownership per action via signed presentations.
- **Receiver:** You. Pins owner root keys, admits bundles, evaluates
  presentations, signs allow/stop decisions.

## Pinning (the root of trust)

The receiver calls `pin_principal(principal_id, root_public_key)`.
This is an **out-of-band trust decision**: you obtain the owner's root
public key through a channel you trust (in person, via a known website,
in a signed email — your choice, your responsibility).

- If the key doesn't match the principal ID, pinning fails
  (`PINNED_PRINCIPAL_ROOT_MISMATCH`).
- If you pin a different key for the same principal later, it fails
  (`PINNED_ROOT_CONFLICT`). Key rotation for owners is not supported
  in this prototype — generate a new principal instead.
- Bundles from unpinned principals are rejected (`ROOT_NOT_PINNED`).

There is no PKI, no certificate authority, no revocation list for owner
keys. If an owner's root key is compromised, stop pinning them and
tell your users.

## Bundles (the authority statement)

`Wallet.export_bundle(ttl_seconds)` produces a signed bundle containing:
- The owner's principal ID and root public key
- The epoch certificate (proves the Wallet's signing key is legitimate)
- The full event history (mandates issued, narrowed, revoked)
- The head hash (tamper-evident chain tip)
- `issued_at` and `expires_at` (the bundle's own TTL)

The receiver's `admit_bundle` checks:
1. Bundle signature valid (signed by the owner's root key).
2. Principal is pinned and the root key matches.
3. Bundle age ≤ `max_bundle_age_seconds` (default 300, hard max 600).
   Older bundles are rejected (`BUNDLE_OUTSIDE_GATE_FRESHNESS`).
4. The head is not stale or forked relative to the previously admitted
   bundle (`BUNDLE_HEAD_STALE`, `BUNDLE_FORK_QUARANTINED`).

**The freshness bound:** A bundle is a point-in-time statement. It does
not contain live revocation information. The receiver must admit a fresh
bundle to learn about revocations. The maximum staleness is
`max_bundle_age_seconds` + the time since the owner exported.

## Presentations (the per-action proof)

For each action, the worker:
1. Asks the receiver for a challenge (`issue_challenge`).
2. Signs a presentation binding: mandate ID, subject ID, subject public
   key, action, challenge, and the bundle head hash it saw.
3. Sends the presentation to the receiver.

The receiver's `evaluate` checks (in order):
1. Presentation shape and schema.
2. Signature valid against the subject public key (proves key ownership).
3. Challenge is known, unused, unexpired, and bound to this
   principal/subject/action (`CHALLENGE_UNKNOWN`, `PRESENTATION_REPLAYED`,
   `CHALLENGE_EXPIRED`, `CHALLENGE_BINDING_MISMATCH`).
4. Presentation is fresh (within `challenge_ttl_seconds` of issue).
5. Action matches the expected action (`ACTION_BINDING_MISMATCH`).
6. Principal not quarantined for forking.
7. A bundle is admitted and unexpired (`BUNDLE_NOT_ADMITTED`,
   `ADMITTED_BUNDLE_EXPIRED`).
8. **Presentation head matches admitted head** (`PRESENTATION_HEAD_STALE`).
   This is the revocation enforcement: if the owner issued a new bundle
   (e.g., containing a revocation), old presentations don't match.
9. Mandate exists and is `ACTIVE` (`MANDATE_UNKNOWN`, `MANDATE_REVOKED`,
   etc.).
10. Mandate not expired (`MANDATE_EXPIRED`).
11. Subject ID and public key match the mandate (`SUBJECT_BINDING_MISMATCH`).
12. Action is in the mandate's scopes (`ACTION_OUTSIDE_MANDATE`).

If all pass: `ALLOWED`, and the receiver signs a decision receipt.

## Revocation semantics

Revocation is `Wallet.revoke(mandate_id)`, which appends a
`MANDATE_REVOKED` event. It takes effect when the receiver admits a
bundle containing that event.

**The revocation bound:**
- **New presentations:** Stop immediately once the receiver admits the
  new bundle. The worker cannot present against the old head
  (`PRESENTATION_HEAD_STALE`).
- **In-flight presentations:** A presentation already evaluated as
  `ALLOWED` is not retroactively revoked. The challenge TTL (default
  60s) bounds how long a worker can wait between getting a challenge
  and presenting.
- **Stale receivers:** If the receiver doesn't admit fresh bundles,
  revocation doesn't propagate. The receiver operator is responsible
  for the refresh policy. The prototype has no automatic refresh.

**What this does NOT promise:** Instant global revocation. If you need
a worker to stop mid-action, you need a separate stop mechanism (see
the gateway's standing check for the in-flight case).

## Failure modes

| Failure | Receiver behavior |
|---------|------------------|
| Owner's root key compromised | You must unpin manually. No automatic revocation. |
| Worker key compromised | Owner revokes the mandate; you admit the new bundle. |
| Forked bundle (two heads) | Principal quarantined (`PRINCIPAL_FORK_QUARANTINED`). Manual intervention. |
| Bundle expires | `ADMITTED_BUNDLE_EXPIRED`. Worker must provide a fresh bundle. |
| Clock skew | Timestamps are checked with 5s tolerance on bundle age. Larger skew causes spurious rejections. Use NTP. |

## What the receiver signs

Every `evaluate` returns a signed decision receipt (`ALLOWED` or
`STOPPED` with reason codes). The receipt is signed by the receiver's
gate key and includes the presentation hash, so the decision is bound
to the specific proof presented. These receipts are the verifiable
evidence of what the receiver decided and why.
