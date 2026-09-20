# DISTRIBUTED-STOP-001 — TERMINAL RECORD

Terminal state: **PASS_DISTRIBUTED_STOP_001_PROPAGATES**
Independent appraiser: 36/36 checks PASS, 0 failures.
Date: 2026-09-20. Spend: $0. No model calls.

## What was tested

Whether an authoritative owner-signed STOP (mandate revocation) propagates
across multiple independently acting receiver processes — each with its own
durable heads, commit ledger, and effect dir — without stale authority
surviving long enough to permit a consequential effect. This lane was the
gap explicitly listed as NOT claimed in PORTABLE_STANDING_CLAIM.md
("Distributed STOP").

## Frozen coordinates

- Branch: `study/distributed-stop-001` (pushed, NOT merged, no PR merged)
- Base: `openline-receipt-gate` main `2f033464bb424b7a5be3d016ae21b97ac13fd554`
- Pre-contact freeze: `868d6e4ec139215434484af2a05ac25c444f70e2`
  (preregistration + harness v1, pushed before any run)
- Preregistration SHA256:
  `efcbd838588f237d90ac537be57ea70b532a3661b15ec9234c2cd33fe17e9a95`
  (`experiments/distributed-stop-001/preregistration.json`; byte-identical
  to the pre-contact frozen copy — never edited after contact)
- Product code: unchanged by this experiment (zero diffs under `olp_gate/`,
  `tests/`, docs). Only `experiments/distributed-stop-001/` was touched.

## Run history (apparatus failures preserved, not erased)

Scientific contact is attempt 5. Attempts 1–4 failed before producing any
valid observation; each is preserved under `run_attemptN_*` with its
run_log.jsonl intact.

1. `run_attempt1_failed_mandate_mismatch` — driver and worker built the
   mandate independently; `expires_at` timestamps differed by milliseconds
   → `mandate_authorization_hash_mismatch` on admit. Repair: mandate pinned
   out-of-band, driver writes `mandate.json`, workers load it.
2. `run_attempt2_failed_worker_race` — attempt-1 workers were never
   reaped (driver died before terminate); two R2 processes raced one inbox.
   Repair: driver try/finally termination, stale-worker sweep, worker
   state-dir `fcntl` exclusive lock (split-brain refuses loudly).
3. `run_attempt3_failed_stale_cmd_reprocessing` — respawned workers
   reprocessed the previous lifetime's cmd files (in-memory `seen` only,
   cmd dirs not namespaced); deterministic one-use codes made the phantom
   re-attempts visible as `one_use_code_replay`. 3 junk AUTHORIZED rows and
   5 junk BLOCKED rows polluted the journals. The genuine DS1/DS2 records
   survived intact in the `ds1_ds2` snapshot. Repair: driver wipes cmd/res
   dirs on every spawn; worker persists `seen_cmds.json` durably.
4. `run_attempt4_failed_sweep_killed_live` — the stale-worker sweep matched
   the driver's own live R1 worker by cmdline substring and SIGTERM'd it.
   Repair: sweep excludes PIDs in the driver's live worker table.
5. `run/` — the scientific run. Completed end to end, no stray processes.

No preregistration change was made at any point. All repairs are harness
apparatus; the frozen expectations were the fixed target throughout.

## Attack outcomes (attempt 5)

| Attack | Observation | Re-derivation (independent) |
|---|---|---|
| DS1 baseline | R1, R2 AUTHORIZED; 1 effect each | NO_STOP_ADMITTED / NO_STOP_ADMITTED |
| DS2 stale read | R1 post-STOP BLOCKED (`owner_standing_revoked`); R2 stale commit AUTHORIZED (expected residual, 1 effect); R2 post-admission BLOCKED | STOPPED/STOP_FIRST; PRE_STOP_COMMIT; STOPPED/STOP_FIRST |
| DS3 partition (5s lease) | R1 post-STOP BLOCKED; R2 mid-partition BLOCKED (`owner_standing_not_active:AUTHORIZATION_EXPIRED`), no effect; R2 post-admission BLOCKED | STOPPED/STOP_FIRST; UNKNOWN/NOT_ESTABLISHED (preregistered taxonomy: fail-closed expiry, no terminal head observed); STOPPED/STOP_FIRST |
| DS4 restart | status() == REVOKED after restart; attempt BLOCKED | STOPPED/STOP_FIRST |
| DS5 reordered | out-of-order seq-2 admit refused; seq-1 then seq-2 admitted in order; replayed seq-1 refused; attempt BLOCKED | STOPPED/STOP_FIRST |

Zero VIOLATIONs: no ESCAPED commit anywhere (independent re-derivation
over all 3 snapshots × all receivers); no commit under an expired ACTIVE
head (every AUTHORIZED attempt's observed `expires_at` > `checked_at`);
no commit after local REVOKED admission.

Counts: 5 receiver-process lifetimes, 10 genuine journaled attempts
(3 AUTHORIZED, 7 BLOCKED), 3 effects created (all pre-STOP, under
unexpired ACTIVE heads), 7 effect-absences independently re-observed.

## Commands (reproducible from the branch)

```
git checkout study/distributed-stop-001
PYTHONPATH=. <venv>/bin/python experiments/distributed-stop-001/harness/run_distributed_stop_001.py experiments/distributed-stop-001/run
PYTHONPATH=. <venv>/bin/python experiments/distributed-stop-001/harness/appraise.py experiments/distributed-stop-001/run
```

## Downstream test status (pre-existing, not caused by this experiment)

Full suite (`python -m unittest discover -s tests`): 392 tests —
3 FAILs + 1 order-dependent ERROR, all reproducing on the clean tree with
this experiment's changes stashed:

- `test_peer_authority_001` / `test_temporal_authority_001` /
  `test_x402_freeze`: `frozen_file_hash_mismatch` — pinned artifact hashes
  stale relative to main (environment/checkout drift; no product file was
  touched by this experiment).
- `test_protect`: ERROR under full discovery only; passes isolated
  (`python -m unittest tests.test_protect` → OK, 15 tests).

24 skipped (unchanged). The experiment's own gate — 36/36 appraiser
checks — is green.

## Claim earned (and its ceiling)

Earned: across five adversarial conditions, an owner-signed STOP admitted
by each receiver's independent durable-heads process blocked every
post-STOP and post-expiry commit attempt, with zero escaped effects and
zero stale-authority commits; the independent re-derivation agrees with
every live decision.

Not earned: cross-organization propagation (single owner key, local
processes, file transport — the transport and trust-establishment
questions are untouched); wall-clock bounds on propagation delay beyond
the lease mechanism; behavior under a malicious (non-crash) receiver.
The inequality T_detect + T_propagate + T_receiver + T_stop +
T_uncertainty < T_irreversible is still the governing constraint — this
experiment bounds the receiver term, not the propagation term.
