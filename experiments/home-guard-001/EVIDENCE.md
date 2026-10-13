# HOME-GUARD-001 evidence (first working proof)

Recorded 2026-10-13. All claims below are properties of the offline
simulator unless labeled otherwise.

## Provenance

- Branch: `study/home-guard-001`, commit `d7542514fe4314de1ea2aa7e4ab258b60b9ea0b4`
  (cut from main @ `31070c80ad254284227ce04263138ad52cc04dc9`)
- Python 3.12.3, `cryptography` 50.0.1,
  Linux-7.0.0-39-generic-x86_64-with-glibc2.39
- Evidence run wall start (UTC): 2026-10-13T16:45:04Z, elapsed 0.011 s
- Frozen tests: 8/8 PASS
  (`python -m unittest discover -s experiments/home-guard-001/tests -v`);
  `def test_` count = 8, collected = 8.
- Demo receipts: `results/receipts.jsonl` (9 receipts),
  sha256 `3bc49332c75315a305d84e2afcf55cde6acf546e6f265f5c6fb04e40e31e49aa`
  — byte-identical across repeated runs (verified).

## Scenario outcomes (from the evidence run)

1. ALLOW `kitchen-light light.turn_on`: effect applied exactly once;
   decision receipt verifies against the receiver key.
2. DENY `front-door-lock lock.unlock` (`not_in_mandate_scope`): zero device
   effects; lock remains locked.
3. Revoke `mandate-home-001`: signed revocation record verifies; immediate
   re-attempt DENY (`mandate_revoked`), zero effect.
   **Revocation observation time: 0.245 ms, in-process** — a local
   measurement of revoke-to-DENY inside one process, not a network
   propagation claim.
4. `tv -> nvr` lateral attempt: DENY (`device_quarantined`), signed network
   decision verifies, **no route entry created** (blocked, not merely logged).
5. AI raw-credential bypass (missing / attacker-forged / wrong-action /
   replayed token): all four rejected, zero effects.
6. TV alternative paths: alternate port DENY, spoofed source DENY
   (`identity_mismatch`), relay via thermostat OUT_OF_SCOPE
   (`forwarding_not_modeled`); no route created by any path.
7. Control case `thermostat -> hvac-gateway`: ALLOW before and after the TV
   quarantine; overblocking in supported scope = 0/2 control attempts.

## Exact receipts

All nine signed receipts are in `results/receipts.jsonl`. Example (ALLOW):

- schema `openline.home_guard.decision.v1`, decision ALLOW,
  reason `in_scope`, device `kitchen-light`, action `light.turn_on`,
  nonce `nonce-0001`,
  payload_hash `8b44b0ed4beaa60005a8057cbedb2eb843c97e6f0ab5b9f2a6bc1c3a2955e912`,
  params_sha256 `7bd621e5f16d7bb410ef9f0110f486ae9095dcc6abf412259f998fecf70b866a`

Every receipt independently verifies with
`olp_gate.crypto.verify_olp_signature` against the receiver public key
(see REPRODUCE.md §4).

## Failures and limitations (preserved, not softened)

- Linux network-namespace packet-isolation test: NOT RUN — `ip netns`
  requires privileges this environment lacks (`setns: Operation not
  permitted`). Simulator PASS is not real packet isolation.
- Relay/forwarding (`tv -> X -> nvr`): OUT_OF_SCOPE, explicitly unmodeled.
- Nonce/revocation state is in-memory: a receiver restart would lose replay
  protection (top Codex hardening target, see HANDOFF_CODEX.md).
- No real-home, real-device, or real-firmware claims were tested.

## Outstanding effects

None. All simulated device effects exist only in the demo process's memory;
no state persists outside `results/` artifacts.
