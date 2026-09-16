# PROVENANCE — COALITION-001

COALITION-001 did **not** execute in this repository and did **not** execute
in CI. It executed as a local lab run:

- Site: `~/workspace/coalition-001/` (file-based freeze, no git repo bound)
- Scientific contact: exactly **one** committed invocation of the frozen
  outcome-producing runner (`runner/runner.py`),
  2026-09-16T19:56:46.041211+00:00
- Pre-contact defect repair used a scratch driver that was deleted before
  sealing; the frozen runner was never invoked before seal.
- Nothing changed after contact except the freeze record's contact-event
  annotation (recorded in `FREEZE-RECORD.md`).

This PR binds the frozen evidence into the repository **byte-identical** to
the sealed local artifacts. The SHA-256 values in `SHA256SUMS` match the
sealed table in `FREEZE-RECORD.md`, which matches the runner's self-reported
artifact hashes inside the observations record.

No proof was manufactured here: every byte under `artifacts/` is a copy of
the sealed pre-contact artifact or the single-invocation observations record.

What this freeze does NOT do:

- It does not claim production support. Production OpenLine still lacks the
  represented primitive (`principal_mandate/v1` does not represent a shared
  cumulative authority origin/bound across distinct actor authorities).
  `NO_GO_COALITION_001_REQUIRES_SCOPE_EXPANSION` remains true.
- It does not re-run the experiment. The observations are from the single
  frozen invocation only.
