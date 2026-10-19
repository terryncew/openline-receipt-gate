# Wallet → synthetic receiver interoperability

**Demonstrated, bounded compatibility; not a production integration.** An authentic
`openline.wallet.receiver_bundle.v1` export is accepted without changing its signed
contents. The receiver pins the owner root, verifies the original Wallet evidence,
and projects only explicitly signed authority into its existing admission path.
It does not manufacture a native owner authorization.

See [SOURCE_AUDIT.md](SOURCE_AUDIT.md) for the incompatibility recorded before
implementation, [REPORT.md](REPORT.md) for results and limitations, and
[HANDOFF.md](HANDOFF.md) for review boundaries.

## Reproduce

Use Python 3.12. From the receiver repository root, in an isolated environment:

```sh
python -m venv /tmp/openline-interop-env
. /tmp/openline-interop-env/bin/activate
pip install -r examples/independent_receiver_kit/requirements.txt
git clone https://github.com/terryncew/openline-wallet.git /tmp/openline-wallet-source
git -C /tmp/openline-wallet-source checkout --detach f309aac8aecae36c4f354c7455281af6dbce486a
export PYTHONPATH="$PWD/src:/tmp/openline-wallet-source/src"
export PYTHONDONTWRITEBYTECODE=1
python -m examples.wallet_receiver_interop.run --output /tmp/wallet-interop-new-run
python -m unittest examples.independent_receiver_kit.test_receiver -v
```

Choose unused temporary paths. The runner refuses to overwrite an existing run.
No paid API, model, real payment or production credential is used. Only loopback
HTTP and synthetic local SQLite document writes occur. Fixture signing seeds are
public test material. Never use them for real authority. The clock is deliberately
fixed; production clock behavior is not demonstrated. Wallet generates random
epoch identifiers, so fresh runs have different hashes despite equivalent results.

The recorded run used the eight required, byte-verified Wallet source modules
listed in `evidence/wallet-source-hashes.json`, loaded by `PYTHONPATH`, not a full
installed Wallet distribution. The checkout procedure above supplies those same
modules; packaging/installability of Wallet itself was not evaluated.

Extract the preserved raw runs first:

```sh
tar -xzf examples/wallet_receiver_interop/evidence/runs.tar.gz -C examples/wallet_receiver_interop/evidence
```

Verify an already captured receiver database, without a receiver process or any
private signing key:

```sh
python -m examples.wallet_receiver_interop.verify \
  --state examples/wallet_receiver_interop/evidence/run-003/wallet/allow/state.sqlite3 \
  --config examples/wallet_receiver_interop/evidence/run-003/wallet/allow/config.json \
  --mode wallet
```

`mutated_document` is deliberately corrupt and must return `valid: false` with
exit status 1. Other captured cases must verify. Run folders contain signed
responses, captured rows, SQLite snapshots, verifier output, latency samples,
authentic exports, public configuration and SHA-256 manifests.

## Receiver contract

Receiver-owned configuration chooses keys, codec, policy and destination. HTTP
callers cannot select them. The only recognized scope is the exact signed string
`intake.submit:records://local-lab/intake`. A different scope grants no document
permission. The signed worker proof binds document, effect, receiver, policy,
authority head, nonce and expiry. Money, delegation and disclosures are denied.

This single-slot example selects the grant targeted by the last signed timeline
event. It does not implement Wallet's general multi-grant selection UX. Complete
snapshots may skip delivery steps, but cannot rewrite known ancestry. A detected
fork quarantines subsequent requests persistently. Duplicate heads do not renew
freshness. Recovery and key rotation require a separate design.

Native `openline` and `conventional` kit modes remain the default. The adapter is
explicitly injected by trusted receiver startup code; no new network bypass is
introduced. Wallet and canonical wire definitions are unchanged.
