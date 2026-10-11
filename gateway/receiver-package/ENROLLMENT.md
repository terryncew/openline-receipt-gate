# Receiver owner-root enrollment (reference procedure)

**Status: documented manual trust bootstrap, not an automated or
production-ready enrollment/rotation service.**

## First enrollment

1. The owner creates an OpenLine Wallet and exports its **public**
   `owner.root_public_key` and `owner.principal_id`. **Never** transfer
   the private key. The principal ID is **derived from the root public
   key**, not an arbitrary account ID, email address, or card token.
2. The receiver operator authenticates the owner using an independently
   established relationship and checks the root key fingerprint over a
   separate, trusted channel. A worker/agent cannot nominate its own
   owner's root key. Plain email or unverified HTTPS alone does not
   establish ownership.
3. The receiver pins exactly that owner root, using its real derived ID:

   ```python
   receiver.pin_owner(owner.principal_id, owner.root_public_key)
   ```

4. Configure the receiver's permitted scopes with
   `receiver.protect_action(action, required_scopes)`, **then** admit a
   bundle obtained from the owner:

   ```python
   admitted = receiver.admit_bundle(owner.export_bundle(ttl_seconds=300))
   assert admitted["decision"] == "BUNDLE_ADMITTED"
   ```

5. The receiver issues a one-use challenge, receives the holder's
   signed presentation, and calls `receiver.authorize(presentation, action)`.
   Check `decision["decision"] == "ALLOWED"` before any business effect.
   The receipt is a **decision receipt**, not proof of completed payment.

A fully executable, **same-process simulation** of these calls is in
`example_01.py`. The example does *not* implement secure transport,
identity proofing, or persistent trust registration.

## Renewal and revocation

The receiver must admit updated signed Wallet bundles to learn about
revoked or narrowed mandates. A receiver that never refreshes its
bundle cannot claim immediate revocation. Preserve the monotonic bundle
history and deny stale, expired or mismatched presentations.

## Root-key replacement — not implemented as a library API

The current `WalletReceiver` and underlying `ReferenceGate` do **not**
provide `get_pinned_key`, `unpin_owner`, or in-place root replacement.
Pinning the same principal ID with a different root raises an error.
**Do not** interpret an arbitrary signed rotation JSON document as
permission to replace the trust root.

A change of owner root requires a **new, independently authenticated
trust enrollment** for the newly derived principal ID, plus receiver-
operated deactivation/quarantine of the old identity and its mandates.
A fresh receiver instance may be necessary for the reference library.
Keep the old history for auditing; prevent all old effects before enabling
new authority. This is an operational migration with a safety gap until
proper root succession and persistent state are implemented and tested.

For a compromised root, stop the affected receiver's business effects
immediately and re-establish trust through independent authentication.
Do not use a compromised key to self-authorize its own replacement.

## Candidate Lithic ASA integration (not connected)

An integrator would need to authenticate the actual card/account owner,
map that **account relationship** to the derived OpenLine principal ID,
pin the approved owner's root using independently verified evidence,
and handle mapping changes separately from Wallet cryptography. The card
token itself is not a principal ID.

No test owner keys, webhook URLs, invitations, or external accounts were
created or contacted by this procedure.
