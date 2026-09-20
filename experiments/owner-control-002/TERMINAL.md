# OWNER-CONTROL-002 — TERMINAL

**Verdict: PASS**

## Claim tested

THE OWNER HOLDS THE KILL AUTHORITY, AND SUCCESSION DOES NOT GIVE THE OLD
HOLDER POWER BACK. Consequential owner authority (owner-signed mandate
authorization admission; REVOKED = the owner STOP) is accepted only from
the currently pinned owner root; the in-band succession primitive moves
that authority forward to exactly one successor without resurrecting
superseded authority or destroying historical verification.

## Frozen references

- Baseline main: `41631b7c09f1d5c319d3a2e98685577fa99e52ef` (PR #95 merge)
- Preregistration: `experiments/owner-control-002/preregistration.json`
  sha256 `a8a9268237b4a04dc510166d0ce971f037a499c3a9f72c1d192b700fe7b66a57`
- Pre-contact freeze commit: `29e19a64cff060417ed437ecc96171f899b500f9`
  ("OWNER-CONTROL-002: freeze preregistration and apparatus (pre-contact)")
- Experiment branch: `study/owner-control-002`
- Product-code diff: zero lines (`git diff HEAD -- olp_gate/` empty).
  Harness-only experiment over the shipped succession primitive.

## What was built (apparatus only)

- `experiments/owner-control-002/harness/succession_worker.py` — unchanged
  reuse of the proven receiver worker (one OS process = one receiver).
- `experiments/owner-control-002/harness/run_owner_control_002.py` — new
  case driver: one owner driver holds keys A (genesis owner), B
  (successor), C (third party), W (non-owner worker); two receiver
  workers R1, R2 with independent durable state dirs.
- `experiments/owner-control-002/harness/appraise.py` — independent
  re-derivation of every preregistered expectation from frozen evidence.
- `tests/test_owner_control_002.py` — 7 in-process unit tests, pure
  unittest style (no pytest import; runs under pytest and CI unittest
  discovery).

## Consequential action under test (as preregistered)

Owner-signed mandate authorization admission for slot `owner/default`
(schema `openline.mandate_owner_authorization.v1`): ACTIVE admits
governing authority; REVOKED is the owner STOP. Acceptance = the
receiver's `admit()` decision; the effect boundary = mandate-head
admission.

## Case results (7 preregistered cases, driver-asserted, appraiser re-derived)

All expectations held on every receiver each case names.

| Case | Expectation | R1 | R2 |
|---|---|---|---|
| 1 owner authority works | A ACTIVE seq1 then owner STOP (REVOKED seq2) admitted; status ACTIVE→REVOKED; head seq 2 | pass | pass |
| 2 worker cannot self-elevate | W-signed owner STOP (full realistic worker knowledge: byte-identical mandate, head hash, correct naming; everything but the owner key) refused `mandate_authorization_owner_key_mismatch`; W signature cryptographically valid under W's own key (SIGNATURE_VALID, NOT AUTHORIZED); no head movement | pass | pass |
| 3 owner succession occurs | A→B succession seq1 admitted; B the single current owner (schedule len 2, succession seq 1) | pass | pass |
| 4 successor can act | B ACTIVE seq3 / STOP seq4 / ACTIVE seq5 admitted under the same gate semantics; status ACTIVE→REVOKED→ACTIVE | pass | pass |
| 5 superseded owner cannot return | A-signed fresh STOP seq6 refused `mandate_authorization_owner_key_mismatch`; A's signature independently verified SIGNATURE_VALID (cryptography ≠ standing); no head movement; B stays current | pass | pass |
| 6 restart preserves successor | R1 terminated, respawned from durable state only: B current, seq 1, schedule len 2, status ACTIVE, head seq 5; B ACTIVE seq6 admitted on R1; A ACTIVE seq7 refused | pass | — |
| 7 history survives succession | On R2: A-era receipt verified=True, current=False, `trust_root_succession_historical_key`, attributable to A's key without making A current; B-era head verified=True, current=True | — | pass |

Succession event hash:
`d57aee4754de401af6bf21de665ba8e02af19c9a739c5173daccc0d1b4b57453`
(signed by A, binds B, sequence 1, no predecessor; re-verified by the
appraiser against A's public key).

Receipt distinctions preserved in evidence (SIGNATURE VALID /
HISTORICALLY VALID / CURRENT OWNER / AUTHORIZED FOR THIS ACTION /
ACCEPTED / EFFECTED): cases 2 and 5 record SIGNATURE_VALID alongside
refusal; case 7 records HISTORICALLY_VALID vs CURRENT_OWNER side by side.

## Downstream checks

- Appraiser (`harness/appraise.py`, independent re-derivation from frozen
  evidence): **92 passed, 0 violations**.
- New unit tests `tests/test_owner_control_002.py`: 7 passed under both
  pytest and `python -m unittest`.
- Focused suites (mandate_owner + stop_standing adapter/integration +
  trust-root-succession + owner-control): **53 passed**.
- TRUST-ROOT-SUCCESSION-001 tests: 15 passed. Standing tests
  (foreign_standing, standing_seam): 10 passed, 3 subtests passed.
- Full `pytest tests/`: **484 passed, 24 skipped, 132 subtests passed**
  (477 baseline + 7 new), exit 0. No regressions.
- CI-equivalent (`unittest discover -s tests -t .` with pytest import
  blocked): branch **365 tests OK** (24 skipped); clean baseline main
  **358 tests OK**. No new CI failure introduced.
- Wallet tests: none exist in this repo (openline-wallet is a separate
  repo, untouched). Effect-closure/reconciliation: no dedicated test
  modules in this repo; covered by the full-suite pass.
- DISTRIBUTED-STOP-001: not rerun — that is a live lane owned elsewhere,
  not this study's lane to invoke (same disposition as
  TRUST-ROOT-SUCCESSION-001).

## Pre-existing failures classified (reproduced on clean baseline main)

- `tests/test_trust_root_succession_001.py` top-level `import pytest`:
  direct module import in a pytest-less environment fails with
  `ModuleNotFoundError: No module named 'pytest'`. Reproduced on a clean
  worktree of baseline main `41631b7` — environmental, pre-existing, not
  caused by this work. NOT repaired inside this experiment per the work
  order (do not repair CI or the baseline test file). Under the CI
  discovery path (`discover -s tests -t .`) the module contributes zero
  tests and no failure either way.

## Apparatus record

- Pre-contact repair 1 (disclosed): unit-test auth sequencing
  (`test_4_successor_can_exercise_owner_authority` admitted ACTIVE seq1
  then issued B's first auth as seq3; corrected to seq2). Test code only,
  semantics unchanged. Committed in the pre-contact freeze.
- Post-contact repair 1 (disclosed): appraiser `check()` called with 4
  positional args (TypeError) on the case-5 signature-validity check.
  Fixed the appraiser call only; the frozen run evidence was not touched,
  no case was rerun, preregistered semantics unchanged. Traceback
  preserved in the run log.

## Exact commands

- `git checkout -b study/owner-control-002` (from 41631b7)
- freeze: `git commit` preregistration + harness + tests → `29e19a6`
- `python experiments/owner-control-002/harness/run_owner_control_002.py`
- `python experiments/owner-control-002/harness/appraise.py`
- `python -m pytest tests/test_owner_control_002.py`
- `python -m pytest tests/`
- CI-equivalent: `python -m unittest discover -s tests -t .` (venv python,
  pytest import blocked)

All run with `~/workspace/.venvs/receipt-gate/bin/python`. $0 spend, no
model calls, no network.

## Claim earned

The owner holds the kill authority, and succession does not give the old
holder power back: current owner authority is accepted, worker
credentials cannot self-elevate, the successor becomes current through
the in-band mechanism, the superseded owner cannot regain current
authority, and historical receipts remain verifiable without conferring
current authority.

NOT claimed: perfect custody, unlosable keys, arbitrary account
recovery, compromise resistance beyond the tested model, malicious
receiver tolerance, or a standard.

## Downstream state

- PLATFORM-EXIT-KILL-001 is now earned (not started): its eventual
  question will be whether Agent A can be stopped and Agent B can
  continue under the same owner-controlled authority regime while
  history survives provider replacement. Awaits a new work order.
- Holmes remains independently parked pending maintainer response.
