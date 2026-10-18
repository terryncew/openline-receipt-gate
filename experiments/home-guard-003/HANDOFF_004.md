# HANDOFF — HOME-GUARD-004 reproducer + costs

**Date:** 2026-10-18
**Branch:** `study/home-guard-004-reproducer-costs` (from frozen `44486057`)
**Status:** READY_FOR_OWNER_REVIEW — Draft PR only, unmerged.

## What was done

1. Branched from PR #113's frozen candidate; **did not modify** `policy_gate.py`,
   `verify_evidence.py`, `make_policies.py`, `run_virtual_network.sh`,
   `active_flow.py`, or `echo_endpoint.py` (verified byte-identical via CI diff step).
2. Added (new files only):
   - `run_measured.sh` — instrumented copy of the run script with monotonic cost markers.
   - `measure_phases.py` — wraps `policy_gate` phases (validate/apply/conntrack/record)
     with `time.monotonic_ns()` timing; does not alter the mechanism.
   - `COST_REPORT.md`, `RESULTS_004.md` — measured costs and results.
   - `.github/workflows/home-guard-004-reproducer.yml` — CI: full-fidelity run on
     ubuntu-latest (conntrack present) + hostile tamper test + artifact upload.
3. CI run 39152946810: **success**. Evidence artifact downloaded and
   independently verified locally (`verify_evidence.py` → PASS).
4. Hostile tamper test: verifier rejected corrupted receipt. Recorded.

## Key measurements

- Cold setup (scripted): 1.36 s; 3 manual operator steps.
- Revocation: 28.5 ms submit→signed receipt (validation 384 µs, kernel 23.7 ms
  incl. 5.6 ms conntrack evict, receipt 3.9 ms); 1.41 s to confirmed observation.
- Verification: 156 ms. Tamper rejection: yes.
- Marginal device: ~0.5 s machine time within schema; **5th device blocked by
  fixed 2-pair schema** (requires redesign).

## What requires owner decision

- Whether the 2-pair schema limitation is acceptable for the next step, or
  whether a parameterized device schema is authorized (that would be new
  engineering, not authorized by this task).
- Whether to keep the CI workflow for future reproducer runs.
- PR stays Draft and unmerged per standing rules.

## Limitations (not to be softened)

Local VM cannot execute the kernel experiment (no conntrack). Single receiver,
single run. Test-only keys. Trusted updater/root. See RESULTS_004.md.
