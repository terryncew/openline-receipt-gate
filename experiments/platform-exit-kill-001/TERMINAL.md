# PLATFORM-EXIT-KILL-001 — Terminal Record

**Terminal state: INCONCLUSIVE_APPARATUS**

The claim ("a revoked agent cannot make a protected effect; a fresh key under the
same owner can continue the same job") was neither established nor falsified.
The apparatus failed on first contact, before any bounded case produced evidence.

## What happened

- Pre-contact freeze: commit `49d642d` (preregistration sha256
  `bdc9bf10622b28fb74abb2bb510559fc7d41daa9205a53ac27ab7539145671be`).
- Pre-contact apparatus repairs (disclosed): commit `73eaf47`. 7/7 new unit
  tests passed. Preregistered semantics unchanged.
- Scientific contact began 2026-09-20T03:44:22Z. The driver admitted one
  owner-signed record (mandate A ACTIVE, seq 1) into the experiment receiver
  state, then spawned the first worker (case 1, agent A).
- The worker crashed immediately on plan deserialization:
  `TypeError: string indices must be integers, not 'str'`
  (`worker_agent.py` line 83: `item["attempt_id"]` where `item` was a string).
- Root cause (apparatus-only): the driver writes the plan file as
  `{"plan": [...]}`; the worker iterates the parsed JSON object directly and
  receives the dict key `"plan"` instead of the attempt list. A serialization
  envelope mismatch between driver and worker. No product code involved;
  no preregistered semantic changed.
- Result: **zero attempts executed, zero commits, zero case results**
  (`case_results: []`; commit ledger shows 0 attempts / 0 commits).
  The only scientific action was the setup admission; no bounded case ran.

## Why no repair and rerun

The work order is explicit: freeze the first real failure; do not patch and
rerun under PLATFORM-EXIT-KILL-001 after scientific contact. The preregistration
apparatus rule concurs: after contact, no repair-and-rerun under the same label.
Repairing now would be outcome-chasing insurance the rules forbid, even though
no outcome was observed. The failed attempt is preserved untouched as
`run_attempt1_failed_worker_plan_shape/`.

## Evidence hygiene

No private key material is committed. Private keys traveled to workers via
process environment and died with the processes; `keys.json` in the preserved
run holds public keys only; no `keys_private/` files exist on disk.

## What was NOT established

None of the six preregistered cases ran. Owner STOP semantics, platform-exit
refusal, agent distinction, replay discrimination, and historical verifiability
remain untested under this label. No claim is earned. No downstream conclusion
may cite this experiment.

## Downstream / collateral

- New unit tests: 7/7 pass (pre-contact qualification).
- Full suite on this branch: 491 passed, 24 skipped, 132 subtests passed.
  No product code was changed (branch diff vs baseline `3a4501c` touches only
  `experiments/platform-exit-kill-001/` and the new test file).

## Recommendation (at most one fresh label)

PLATFORM-EXIT-KILL-002, if authorized by a new work order: identical frozen
preregistration semantics, one-line apparatus fix (worker reads `plan["plan"]`
or driver writes the bare list), fresh run directory. This lane is closed;
nothing further was started.
