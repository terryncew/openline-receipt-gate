# Native Wallet receiver bundle — compatibility gate

This independent local receiver accepts **the original unchanged** `Wallet.export_bundle()` object (schema `openline.wallet.receiver_bundle.v1`) through `NativeWalletReceiver.dispatch("/authority", bundle)`, or the existing local HTTP `make_server(receiver)` with `POST /authority`. There is **no app-specific conversion of Wallet's signed authority format**.

Verification uses `openline_wallet.verify_bundle` from the pinned official Wallet package. A receiver-controlled, externally pinned `principal_id` and root public key constrain the issuer, with certified epoch key, signed event history and head verified by Wallet itself. Newer bundles must preserve the accepted signed ancestor, and a duplicate head never refreshes freshness. SQLite records the complete native signed bundle and the durable latest head. It is a reference to be evaluated, not production issuer recovery/federation.

**Exact document execution is separately protected** by the kit's original worker-signed `receiver-kit-call/v1` object through `POST /submit`: it binds original Wallet head hash, worker public key, mandate ID, receiver policy hash, exact document ID/content, target, action and one-use nonce. The worker's key must match a current `intake.submit` Wallet mandate. A revoked mandate or stale/unknown head cannot be used. The receiver atomically checks signature, policy, scope, exact args, time, replay and local SQLite effect, then emits a signed receiver decision. This is local document intake only; **it does not intercept Codex's unrelated filesystem/shell/network capabilities**. The wallet does not sign the worker's exact call; the holder signs it with the existing kit call schema. Keeping both checks distinct is deliberate. No new Wallet canonical format, extra authority, unverified permission, or backward compatibility claim.

Run offline on clean sources (Python 3.11+, Git):
```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e . -r examples/independent_receiver_kit/requirements.txt
.venv/bin/python -m pip install 'git+https://github.com/terryncew/openline-wallet.git@f309aac8aecae36c4f354c7455281af6dbce486a'
.venv/bin/python -m unittest examples.independent_receiver_kit.test_native_wallet -v
.venv/bin/python -m unittest examples.independent_receiver_kit.test_receiver -v
```

The native test uses **real Wallet-created signed bundles**, exercises owner root mismatch, tampering, stale-head duplicates, worker possession, exact call tampering, replay, durable restart, revocation and A→B successor. No signing secrets come from a request, no real model/payment/external effect exists. Independently audit the signed decisions and effect rows by calling `verify_native_wallet.verify(state, externally_pinned_config)`.

**Fair matched alternatives:** The original EdDSA JWT arm remains byte-for-byte unchanged and runs all its existing adversarial scenarios. A JWT receiver correctly configured with equivalent key pinning, binding, replay detection, revocation freshness and provenance can provide the same safety. Wallet native admission currently requires installing the Wallet library and managing signed history; JWT requires its own issuer/configuration and engineering work. We do not assert superiority.

**Known limits:** The local operator is trusted, SQLite history can be rolled back by a privileged adversary unless externally checkpointed, keys are fixture values, `<60s` freshness does not guarantee immediate knowledge of withheld revocations, and a direct privileged DB mutation bypasses HTTP enforcement. The verifier is independent code but on the same trusted host. Effect callbacks outside the local SQLite receiver and durable multi-service exactly-once behavior remain untested.
