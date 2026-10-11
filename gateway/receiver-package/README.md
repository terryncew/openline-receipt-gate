# OpenLine Receiver — experimental Python library

A receiver can independently validate an owner's signed Wallet authority and
issue a **receiver-signed authorization decision**. It does not execute the
business side effect, distribute owner keys, or replace a payment gateway.

**Status:** Reference implementation, not production-ready. No Lithic
sandbox deployment or external receiver adoption is claimed.

## Install and run the working example

From this repository's root (Python 3.10+):

```sh
python3 -m venv /tmp/openline-receiver-venv
/tmp/openline-receiver-venv/bin/pip install ./gateway/receiver-package
/tmp/openline-receiver-venv/bin/python gateway/receiver-package/example_01.py
```

The example creates a throwaway owner and worker, pins the owner's public
root, admits a signed bundle, issues a receiver challenge, verifies a signed
worker presentation, and prints `receiver: ALLOWED`.

It deliberately simulates delivery of the owner's root key on the same
machine. An actual receiver must enroll that key over an authenticated,
separate channel. See [ENROLLMENT.md](ENROLLMENT.md).

The supported Python API, as used in the runnable example, is:

- `WalletReceiver(gate_id="...")`
- `pin_owner(owner.principal_id, owner.root_public_key)`
- `protect_action("read_reports", ["read_reports"])`
- `admit_bundle(bundle)` returning a dictionary with `decision`
- `issue_challenge(principal_id, subject_id, action)`
- `authorize(presentation, action)` returning a **signed decision dict**,
  where `decision` is `ALLOWED` or `STOPPED`
- `worker_present(...)` for the worker-side challenge-bound signature

There is **no** `WalletReceiver.decide()`, `sign_receipt()`,
`get_pinned_key()`, or `unpin_owner()` API in this package.

## Trust and consequence boundary

The owner signs grants and revocations. The receiver pins the owner's real
root key, admits a fresh, cryptographically verified bundle, issues a
one-use challenge, and evaluates the signed presentation against its own
protected-action policy.

The package's signed decision does **not** by itself prove an external
business effect occurred. The downstream receiver must enforce the
decision, durably record any effect, and provide evidence appropriate to
that effect. The separate Gateway/Poppy mock-ledger proof is experimental.

The package contains `openline_receiver.openline_wallet` (vendored Wallet
contracts) and `openline_receiver.wallet_bridge`. It has no Envoy,
network listeners, ledger, card integration, or public key infrastructure.

## Known limitations

- No built-in trusted enrollment, key rotation, key revocation registry,
  or persistent receiver state. The receiver operator must protect its
  pinned trust roots and maintain state across process restarts.
- Bundle-based revocation is effective only when the receiver admits
  a newer revocation-bearing bundle. A freshness window is **not**
  guaranteed instantaneous revocation.
- Approval/effect atomicity demonstrated elsewhere is not automatically
  inherited by consumers of this Python library.
- The Lithic adapter remains a local test, not a networked ASA integration.
- Do not install this package into production payment systems as-is.

See [ENROLLMENT.md](ENROLLMENT.md) for actual supported onboarding
and [LITHIC_CONTRACT.md](LITHIC_CONTRACT.md) for the proposed sandbox mapping.
