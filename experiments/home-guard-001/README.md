# HOME-GUARD-001 — offline OpenLine Home Guard prototype

Bounded, offline proof of concept for issue #110. Not a product, not a
release, not a live household security system.

## What it proves (supported scope only)

Two independently enforced, receiver-controlled boundaries, fully simulated:

1. **AI action authority** (`home_guard/receiver.py`, `home_guard/devices.py`):
   the assistant proposes actions; the Receiver admits owner-signed mandates,
   evaluates proposals, and signs ALLOW/DENY decision receipts. Devices
   execute only on a Receiver-signed ALLOW bound to the exact
   (device, action, params) triple with a fresh nonce. Revocation stops the
   next attempt.
2. **Device-to-device reachability** (`home_guard/net_policy.py`): a
   deterministic policy simulator. A simulated compromised TV attempting to
   reach a protected device is denied by receiver-owned policy, independent
   of the agent. DENY creates no route — blocked, not merely logged.

## Layout

- `home_guard/` — prototype package (keys, receiver, devices, net_policy, demo)
- `tests/test_home_guard_001.py` — **frozen security tests** (8, stdlib unittest)
- `THREAT_MODEL.md` — threat model, trust assumptions, explicit non-claims
- `REPRODUCE.md` — how to re-run everything
- `EVIDENCE.md` — recorded run results (tool versions, SHA, receipts, timings)
- `HANDOFF_CODEX.md` — Muse-to-Codex hardening handoff
- `FREEZE.json` — frozen test criteria record
- `results/` — receipts.jsonl + run.json from the evidence run

## Reuse

Receipt signing/verification reuses `olp_gate.crypto.sign_olp_body` /
`verify_olp_signature` and `olp_gate.receipts.sha256_json` from
openline-receipt-gate. No OpenLine library is claimed to protect network
traffic; the containment layer is new simulation code.

## Hard boundaries honored

$0 spend, no paid APIs, no real devices, no network changes, no Bureau or
Exchange contact, no merge, no publish. Branch: `study/home-guard-001`.
PR (if opened) stays Draft.

## Quick start

From repo root:

    python -m unittest discover -s experiments/home-guard-001/tests -v
    python experiments/home-guard-001/home_guard/demo.py

See REPRODUCE.md for the full verification procedure.
