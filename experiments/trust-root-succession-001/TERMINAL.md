# TRUST-ROOT-SUCCESSION-001 — TERMINAL

**Verdict: PASS**

## Claim tested
An owner trust root (the receiver-pinned owner key) can advance to a successor
through an in-band, owner-signed succession event, such that:
- exactly one owner key is current per slot at all times (atomic transition),
- the successor exercises owner authority and the predecessor's fresh
  authority is refused,
- pre-succession receipts stay signature-verifiable but are distinguishable
  from currently-standing authority,
- the transition survives receiver restart from durable state.

## Frozen references
- Baseline main: `01e01eb4e22ae4a15e573e81680a5e62c683d807` (PR #94 merge)
- Preregistration: `experiments/trust-root-succession-001/preregistration.json`
  sha256 `9870e844bc2c326c6b100646b324b27ef4606a9b820bf853657a6dcac477c922`
- Pre-contact freeze commit: `49676e62a8ed31cb9ede2d18ef2e767bca114622`
  ("freeze preregistration and succession primitive (pre-contact)")
- Experiment branch: `study/trust-root-succession-001`, HEAD `58b28fc35fef013f942e9277a33139db26cb5ba1`

## What was built (product surface)
`olp_gate/mandate_owner.py` only:
- Event `openline.owner_trust_root_succession.v1`: signed by the currently
  pinned owner key; binds `successor_public_key`, monotonic
  `succession_sequence` (first = 1), `predecessor_succession_hash` chaining
  to the prior event's payload hash.
- `MandateOwnerView.admit_trust_root_succession()`: persistence-before-decision
  via the durable trust-root store (`owner_trust_root/v1` identity, genesis
  slots pinned; restart reconstructs current root, sequence, schedule).
- `assess()` historical fallback: current-root verification first, then
  superseded roots newest-first; historical hits report
  `verified=True, current=False, reason_codes=["trust_root_succession_historical_key"]`.

## Authoritative transition rule (as preregistered)
Per-receiver admission. Each receiver advances its own slot root when it
admits a valid succession event. No broadcast or consensus semantics claimed.

## Case results (6 preregistered cases; driver-asserted, appraiser re-derived)
The driver records 12 assertion entries (sub-steps) across the 6 bounded
cases; every preregistered expectation held on both receivers.
| Preregistered case | Driver entries | Expectation | r1 | r2 |
|---|---|---|---|---|
| 1 valid_succession | 1a, 1b, 1c | A-signed ACTIVE admitted pre-succession; A→B succession admitted, B current on both; B exercises owner authority incl. STOP | pass | pass |
| 2 old_owner_and_worker_rejected | 2a, 2b | W-signed owner STOP refused; A-signed fresh auth refused post-succession (`mandate_authorization_owner_key_mismatch`); no head movement | pass | pass |
| 3 self_declared_successor_rejected | 3 | C self-declaration refused (`trust_root_succession_signer_not_current_owner`); sequence stays 1, owner stays B | pass | pass |
| 4 replay_reorder | 4a, 4b, 4c, 4d | replayed A→B refused; duplicate sequence refused (`trust_root_succession_sequence_invalid`); wrong predecessor refused (`trust_root_succession_predecessor_mismatch`); A-forged post-handover refused (signer_not_current_owner) | pass | pass |
| 5 restart | 5 | restart preserves B current (seq 1, schedule len 2); A stays refused | pass | — |
| 6 historical | 6 | A-era receipt: verified=True, current=False, historical-key reason; B-era: verified=True, current=True | pass | — |

Succession event hash: `dade0aa2f2923084970a3cab2a7e0fdab3ba21a3a7461be8f7b7c73a7abf344f`
(signed by A, binds B, sequence 1, no predecessor; independently re-verified
by the appraiser against A's public key).

## Downstream checks
- New unit tests `tests/test_trust_root_succession_001.py`: 15 passed.
- mandate_owner + stop-standing suites: 29 + 28 passed.
- Full `pytest tests/`: **477 passed, 24 skipped, 132 subtests passed**, exit 0.
- Appraiser (`harness/appraise.py`, independent re-derivation from frozen
  evidence): **56 passed, 0 violations**.
- DS-001 harness imports `mandate_owner`; with no succession events admitted
  its schedule stays single-entry and behavior is identical. The live
  DISTRIBUTED-STOP-001 lane was not rerun (not this study's lane to invoke).

## Apparatus record (all pre-contact, all disclosed, semantics unchanged)
Seven pre-contact repairs, each committed separately with the frozen
preregistration untouched; failed runs preserved, never overwritten:
`run_attempt1_failed_TypeError` (driver REPO path), `run_attempt1_failed_RuntimeError`
(sweep killed own worker — inverted cmdline anchor), `run_attempt_failed_TypeError`
(`os.environ` called), `run_attempt_failed_FileNotFoundError` (missing logs dir),
`run_attempt_failed_JSONDecodeError` (non-atomic res-file write TOCTOU),
`run_attempt_failed_RuntimeError` (double `.json` suffix on res writes),
plus `run_attempt_unfinished*` leftovers. Scientific contact began only after
repair 7; the successful run is `experiments/trust-root-succession-001/run/`.

## Claim earned
"An owner trust root can advance in-band through a currently-signed succession
event: exactly one owner key is current per slot, the predecessor's fresh
authority is refused, pre-succession receipts remain signature-verifiable
without standing as current, and the transition survives restart."
Nothing stronger is claimed: transition authority is per-receiver admission,
not broadcast; key custody and rotation policy are outside this study.

## Commands
- Driver: `~/workspace/.venvs/receipt-gate/bin/python experiments/trust-root-succession-001/harness/run_trust_root_succession_001.py`
- Appraiser: `~/workspace/.venvs/receipt-gate/bin/python experiments/trust-root-succession-001/harness/appraise.py`
- Unit tests: `python -m pytest tests/test_trust_root_succession_001.py -q`
- Full suite: `python -m pytest tests/ -q -p no:cacheprovider`
(all from `~/workspace/openline-receipt-gate`, venv `~/workspace/.venvs/receipt-gate`)

## Next roadmap state
OWNER-CONTROL-002 — needs a new work order; not started.
