# PLATFORM-EXIT-KILL-002 — Terminal Record

**Terminal state: PASS**

The claim ("Agent A can be stopped by owner authority, and Agent B can
continue under the same owner-controlled regime without breaking historical
continuity") was established on the second run of the identical frozen
scientific contract. 001's INCONCLUSIVE_APPARATUS was a harness envelope
mismatch, repaired here as the single disclosed apparatus change.

## What happened

- Phase 1: PR #97 merged by explicit owner approval. Baseline main
  `95c1ecfd77bd13b9e7b0f441559e69223ee7b20b` — verified clean, contract
  repair + PR #94/#95/#96 history intact, all experiment dirs present.
- Scientific contract carried verbatim from 001
  (001 preregistration sha256
  `bdc9bf10622b28fb74abb2bb510559fc7d41daa9205a53ac27ab7539145671be`;
  002 preregistration sha256
  `7e440cf5f6ddeb1e949476aceb8a74ddd3ddbadc86de36f2943b33f1b45ede38`).
- Pre-contact freeze: commit `5307b79` (preregistration + apparatus).
- One disclosed apparatus repair (APPARATUS-002-001): worker reads the
  attempt list from the driver's plan envelope (`plan["plan"]`). 001's
  worker iterated the envelope object directly and crashed with TypeError
  before case 1; per the 001 terminal record and the owner's order, that
  crash was apparatus, not authority evidence, and is not counted here.
- Pre-contact unit qualification: 7/7 green.
- Contact: driver ran all six preregistered cases end to end, exit 0,
  `failure: None` in `case_results.json`.
- Independent appraiser re-derived all case expectations from frozen run/
  evidence only: **213 checks, 0 violations**.

## Bounded case outcomes (driver + appraiser agreement)

- Case 1 — A operates: owner admits M_A ACTIVE seq1 on slot A; worker A
  subprocess effects 2 payments, both ACCEPTED and EFFECTED, attributed to
  agent-a; journal commit_seq 1,2; slot A ACTIVE.
- Case 2 — Owner stops A: owner-signed REVOKED seq2 on slot A admitted;
  standing ACTIVE -> REVOKED; STOP attributable to O.
- Case 3 — A cannot continue: 3 post-STOP attempts (2 fresh + 1 after full
  worker-process restart) all refused `owner_standing_revoked`,
  `execution_status: not_started`, zero markers, no head movement
  (slot A head stays seq 2); mandate preflight still computed allowed=True
  on the same settings — refusal is standing, not format.
- Case 4 — B continues under the same regime: owner admits M_B ACTIVE seq1
  on slot B, signed by the SAME owner key O (no succession event; succession
  sequence 0 on both slots); worker B subprocess (fresh keypair K_B, never
  held A material) effects 2 payments, both ACCEPTED and EFFECTED,
  attributed to agent-b; journal continues commit_seq 6,7 (shared ordered
  history with A-era attempts); slot A stays REVOKED.
- Case 5 — A stays stopped: after B is operating, A's fresh attempt and a
  replay of the exact pre-STOP effect payload with a fresh one-use code both
  refused `owner_standing_revoked`; slot A head stays seq 2; slot B still
  ACTIVE — no resurrection by fresh attempt, replay, or restart.
- Case 6 — History intact: appraiser verified from frozen evidence — every
  owner-signed admission verifies under O; slot-A seq1/seq2 and slot-B seq1
  present; A-era receipts attributable to agent-a, B-era to agent-b; STOP
  event present and attributable to O; per-case frozen ledger snapshots are
  byte-equal prefixes of the final journal; `MandateOwnerView.assess()` on
  the superseded A seq1 authorization reports verified=True, current=False
  while slot A stays REVOKED — historical verification confers no currency.

## Receipt distinctions (explicit, un-collapsed)

SIGNATURE_VALID / HISTORICALLY_VALID / CURRENT_AUTHORITY / AUTHORIZED_FOR_THIS_ACTION
/ ACCEPTED / EFFECTED were each exercised and independently reported; the
appraiser reports the distinction mapping in `run/appraise_report.json`.

## Downstream / collateral

- New unit tests: 7/7 pass.
- Full suite on this branch: **498 passed, 24 skipped, 132 subtests** —
  zero failures (491 passed at the 001 terminal record point, plus the 7 new
  experiment unit tests).
- CI-equivalent (unittest discovery, pytest import blocked): 380 tests run,
  1 error — `test_trust_root_succession_001` top-level `import pytest`.
  Reproduced byte-identically on clean baseline main (373 tests, same 1
  error): pre-existing environmental, not repaired per order.
- Branch diff vs baseline `95c1ecf` touches only
  `experiments/platform-exit-kill-002/` and the new test file —
  **zero product-code changes** (`olp_gate/` untouched).
- Evidence hygiene: driver shreds `keys_private/` at finalize; `keys.json`
  holds public keys only; no private key material committed.
- No prior PASS receipt rewritten; no prior terminal touched.

## Claim earned

"An agent operating under owner authority can be stopped by the owner and
replaced by a distinct agent that continues under the same owner-controlled
authority regime, with history intact across the switch and the stopped
agent unable to regain consequential authority."

Not claimed: real-provider portability, cloud-platform exit,
cross-organization handoff, Byzantine tolerance, unlosable keys, arbitrary
recovery, or a standard.

## Apparatus record

Pre-contact: 7/7 unit tests green. One disclosed pre-contact repair
(APPARATUS-002-001); the failed 001 run is preserved on main under
`experiments/platform-exit-kill-001/run_attempt1_failed_worker_plan_shape/`
and is not counted as evidence. No apparatus failures post-contact.
