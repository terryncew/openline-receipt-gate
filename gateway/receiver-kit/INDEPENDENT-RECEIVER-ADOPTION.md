# RECEIVER-001: independent receiver evaluation guide

Status: **synthetic local evaluation, NOT an external adoption or a production release**.
This is an incremental review of the existing unmerged Receiver Kit in PR #104.
No new Wallet wire format, hosted infrastructure, or Bureau/Exchange dependency.

## Reproduce without a paid service

Start from the pinned review branch `experiment/receiver-001-independent-boundaries` in `terryncew/openline-receipt-gate`. On Python 3.12:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install cryptography==50.0.1
python gateway/receiver-kit/examples/04-two-independent-receivers.py --out /tmp/openline-receiver-001
python gateway/receiver-kit/verify_two_receivers.py /tmp/openline-receiver-001 --trusted-keys /tmp/openline-receiver-001/trusted_receiver_keys.json
```

The exercise creates fictional owner and worker keys, two **separate local Python processes** with different receiver signing keys and local policies, and a shared owner-signed Wallet bundle. Alpha requires `read_reports`; Beta requires `read_reports` and `audit_reports`. Both trust the explicitly pinned owner root. They exercise old worker allowed at Alpha / refused at Beta, owner-authorized successor allowed at both, unknown action denied, replay denied, a freshly admitted revoked bundle denying the successor, and unknown roots rejected. One original signed mandate becomes stale after the new bundle is admitted.

Outputs: `summary.json`, `trusted_receiver_keys.json`, `decision_receipts.json`, `receiver-*-effects.jsonl` (untrusted *synthetic* local effect traces). GitHub CI preserves signed and corrupted negative evidence and SHA256SUMS.

**Important:** The demo-produced `trusted_receiver_keys.json` proves only that a local test fixed those receiver keys before verification. A *real* independent verifier must receive each organization's public key through a separate authenticated channel. It must not accept the signer key only because a receipt contains it. Receipt verification validates an authorization decision, **not the claimed execution of any external effect**.

## Five decisions each real receiver must make

1. Which owner's Wallet root key (principal ID + Ed25519 public key) is actually trusted, and how is it obtained/authenticated independently?
2. Which exact actions, resources and additional Wallet scopes can this receiver enforce? Start with an empty, deny-by-default action map. The owner's permission cannot override a receiver's local restriction.
3. Which receiver-owned key signs receipts, and how does an auditor pin that key independently? How are keys rotated, revoked and compromised keys removed? The prototype lacks an owner-root rotation workflow.
4. What is the maximum acceptable offline/revocation lag? The kit admits fresh signed bundles and rejects older *admitted* heads; it **does not know** about a newer revocation until one arrives. Bundle TTL (here 30 seconds) bounds the use of the admitted snapshot only. High-consequence effects may require online standing checks, and offline may need complete refusal.
5. Who owns atomic effect execution, audit storage, replay state, incident recovery and network bypass closure? The reference kit's in-memory challenge store and simulated effect log cannot fulfill production durability or cross-host exactly-once guarantees.

## Adoption blockers honestly exposed

- The prior PR #104 Docker full restart path had 20/21 passing, with an outstanding signed balance-read timeout after recreation. The independent Python fixture does NOT repair this gateway path.
- Wallet bundles export full signed event history. A receiver may learn events unrelated to its role; privacy minimization and selective disclosure are not established.
- The bridge reads `ReferenceGate._admitted` and calls `_receipt` (private, version-pinned APIs). An official supported public policy-denial hook would be needed for maintainable vendor upgrades, but is **not** being added in this experiment.
- Receiver configuration, bundle admission, and receipt verification were exercised in processes on ONE hosted machine. No independently operated organization, network transport, external reviewer, enterprise key custody or genuine buying decision was tested.
- The <30-minute first integration goal is **unmeasured** for an unfamiliar developer. A scripted CI duration is not a human setup benchmark.

## Concrete potential use case (not a customer claim)

Two independent B2B report repositories each receive an owner's agent request to retrieve an authorized project report. The owner can switch model workers without requesting a new credential from either AI provider. Each repository separately decides which client principals, report types and actions it recognizes, logs its own effect, and signs its own decision receipt. Alternative: OAuth with an owner-recognized authorization server and introspection plus local authorization (see MATCHED-BASELINE.md). Both receivers participate only if it reduces integration/compliance workload or increases legitimate agent transactions; neither has committed to do so.

OpenLine might charge a receiver/operator for **maintained trust onboarding, signed-evidence verification and revocation/freshness monitoring**, not for a synthetic two-process test. Economics, buyer demand, privacy, dispute resolution, and interorganization key lifecycle are untested.

**Next independent milestone:** one real receiver engineer voluntarily tries the existing kit under their OWN root-policy choices in a disposable environment and reports time-to-first-accepted/refused action versus their conventional system. Contact/invitation is explicitly **not authorized** here.
