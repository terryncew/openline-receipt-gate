# Independent receiver evaluation kit

**A runnable, offline reference implementation — not a production service.**

This standalone local receiver accepts an external owner's native OpenLine authorization and a worker's signed exact document-intake request, enforces its **own** policy at the HTTP boundary, and records signed decisions plus the permitted local SQLite effect. A matched **conventional EdDSA JWT** mode performs the same job with equivalent controls. Both modes passed **16 adversarial cases each (32 total)** in a bounded internal clean-source run. **Result: PARITY, not superiority.**

This is deliberately a small example of **receiver acceptance**, not an arbitrary tool runner, payment product, or hosted authority service. No real services, accounts, payment processors, devices, credentials, or model providers are used. The provider A/B labels and signing keys are public **test fixtures**.

## Install from a fresh clone

Requires Python 3.10+ and Git. Commands assume a Unix-like shell; install packages into a disposable virtual environment.

```sh
git clone https://github.com/terryncew/openline-receipt-gate.git
cd openline-receipt-gate
python3 -m venv .venv
.venv/bin/python -m pip install -e . -r examples/independent_receiver_kit/requirements.txt
.venv/bin/python -m examples.independent_receiver_kit.demo --output /tmp/openline-receiver-eval
.venv/bin/python -m unittest examples.independent_receiver_kit.test_receiver -v
```

Choose a **new** `--output` path if you already ran the demo. Its two receiver processes bind to **loopback only**, use fixed local data, and save their decisions, databases and verifier inputs under `/tmp/openline-receiver-eval`. There are no real external consequences.

## Independently check the receipts and protected rows

```sh
.venv/bin/python -m examples.independent_receiver_kit.verify \
  --state /tmp/openline-receiver-eval/openline/state.sqlite3 \
  --config /tmp/openline-receiver-eval/openline/config.json \
  --mode openline

.venv/bin/python -m examples.independent_receiver_kit.verify \
  --state /tmp/openline-receiver-eval/conventional/state.sqlite3 \
  --config /tmp/openline-receiver-eval/conventional/config.json \
  --mode conventional
```

The verifier separately checks the signed history against public receiver keys supplied through the config, and reconstructs the allowed local SQLite records. A privileged actor able to directly modify the database can bypass the HTTP enforcement, but its inconsistent edits were **detectable afterward** in the exercised adversarial cases. This example does **not** prove control of an arbitrary external effect.

## What to compare

Run each mode with the same permitted document action and the same checks for wrong owner, mismatched worker key, replay, changed action parameters, stale/revoked authorization, and history consistency. Count **all** installation, trust-root setup, custom integration code, troubleshooting, evidence-verification steps, and required ongoing administration for *both* approaches. Do not compare against an intentionally weak bearer-token example. Ask the evaluator which approach they would choose and why.

### Important limits

- **Wallet export incompatibility:** Actual exported `openline.wallet.receiver_bundle.v1` evidence can verify cryptographically but **cannot be admitted unchanged** as native owner authorization by this kit; no adapter has been built. Its portable-authority test uses the kit's native owner-authorization format.
- **PARITY:** Conventional JWT with correctly configured receiver policy, possession proof, revocation freshness and signed evidence matched the observed OpenLine results. No unique capability, cost benefit, ease-of-use, or independent adoption advantage is established.
- **Revocation:** The receiver only knows admitted owner updates. Freshness is bounded to **less than 60 seconds** from signed issue time. Withheld revocation remains unknown until the existing permitted freshness window expires.
- **Trust:** All signing keys, simulated owners/providers and fixture clocks here are nonproduction. Production root enrollment/rotation, TLS, credential custody, distributed state, crashes/power loss and externally operated receivers remain unproven.
- **Evidence:** Decisions in this kit are signed in both modes. The separate [refund demo](../multi_hop_refund_drift/README.md) has an owner-limit denial performed by **unsigned local preflight**, distinct from signed Gate receipts.

## Raw research and provenance

The underlying **eight implementation files and pinned requirements** are copied byte-for-byte from the internally reproduced [PR #121](https://github.com/terryncew/openline-receipt-gate/pull/121), based on tested implementation commit `09b821da175f8dd3dbe2b0bcaf051b1fa0b840d3`, with the same blobs at final PR #121 commit `4d8565c844a26ad703a8f82332c1e18ec8acb5c1`. The source/evidence branch retains the original [full report and raw per-test records](https://github.com/terryncew/openline-receipt-gate/tree/study/independent-receiver-kit-001/examples/independent_receiver_kit/evidence). Large generated SQLite databases, public fixture private-key copies, virtual environments and run logs are deliberately **not** copied into this developer-facing tree.

Original internal measurements and a later bounded clean reproduction are historical observations, not a promise of external setup speed. This is a **development evaluation**, not production certification. No external organization has adopted or operated it yet.
