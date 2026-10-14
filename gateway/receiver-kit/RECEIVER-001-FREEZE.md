# RECEIVER-001 / Frozen scope and discriminators

Research-only, internal integration exercise. This change is stacked on the EXISTING unmerged Receiver Kit PR #104, head `792dbc34a333fcc2150114558fe1ee7008cd354b`. Do not merge either PR or deploy, publish, contact anyone, transfer keys, or use paid APIs. No changes to Wallet, Bureau, Exchange, or protocol formats.

## Inventory first, actual gap

Already present: Wallet `Wallet.grant/revoke/export_bundle`, `ReferenceGate` pin/admit/challenge/evaluate and Ed25519 receipt verifier, `gateway/wallet_bridge.py`, receiver kit examples, a one-receiver 10/10 synthetic demo, and an Envoy/OPA comparison in PR #104. Bureau PR #6 / Exchange PR #1 remain separate Drafts and are not authority infrastructure.

Missing: (1) `WalletReceiver.protect_action` currently passes its receiver-required scopes to `ReferenceGate.protect_action`, but that method defines *carried recipient scopes for routing*, not a minimum scope set required of the presenting worker; the wrapper then checks its own newly recorded scopes. (2) No explicit default-deny of an action not configured by the receiver. (3) No independent two-receiver cross-verification fixture. (4) No evidence of an external adopter, measured clean-room install, or fairly matched OAuth/AuthZEN comparator. No rewrite of existing authority formats is justified.

## Fix scope

- Repair only the bridge's local receiver policy using the already cryptographically verified, currently admitted Wallet timeline. An owner mandate must actually include every scope the receiver requires for that action. Unknown receiver actions fail closed. Return signed Wallet-format STOPPED receipts, pinned by receiver key; do not return unsigned refusals. Preserve one-use challenge consumption. Distinguish a signed ALLOWED *decision* from a simulated effect; no claim of real external effect.
- Use existing `ReferenceGate` and `verify_record`; no new wire protocol. The bridge is pinned to the vendored Wallet contracts and any internal access must be noted as upgrade-sensitive.
- Add local two-process test fixture: one owner; two separately generated receiver gate keys/configured action policies/trust stores; two independently keyed worker subjects; both receivers admit identical signed bundle; A permits narrower grant while B refuses missing required scope; a properly scoped successor can pass both without original AI vendor; after revocation both refuse; replays, unknown actions/owners, forged receipts refuse.
- Self-contained local unit tests; no real operations. CI restricted to this branch, Python and pinned crypto dependency; no external paid providers.

## Falsifiers and stop

A single allowed effect missing locally required authority; unknown action allowed; signed refusal unverifiable by independently pinned receiver key; unpinned owner admitted; challenge replay allowed; old signed mandate accepted after *updated bundle is admitted*; one receiver can forge another receiver's identity; missing necessary test observation => FAIL/INCONCLUSIVE. Do not claim instant revocation before a newer bundle is delivered; offline freshness is bounded by the current admission/expiry policy and needs independent refresh.

Conventional comparator must match trust roots, authenticated owner/worker, one-use replay, revocation, scope and effect boundary, and signed evidence. The previously measured stateless OPA-A is not equivalent; no OpenLine advantage may be inferred from its omissions. No more feature development if a standards-based equivalent matches the result without demonstrated integration advantage.

## Evidence / limitations

Commit this document before implementation. Require actual CI test outputs and exact SHA, plus independently checked signed receipts. Do not assert <30 minute integration or adoption without unfamiliar external developer measurements. Isolated processes on one host are NOT independently operated organizations. No production storage durability, cross-host synchronization, automatic revocation delivery, protocol compatibility certification, or customer value demonstrated.
