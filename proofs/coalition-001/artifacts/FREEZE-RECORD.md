# COALITION-001 — Freeze Record

**Experiment:** COALITION-001 — Mandate-Scoped Split-Consequence Bypass
**Freeze type:** file-based freeze (no git repo bound), following the
BOUND-FIRST-PERSISTENCE-001 Phase 0 pattern.

## Sealed artifacts (read-only at seal time)

| Artifact | SHA-256 |
|---|---|
| frozen/COALITION-001-contract.md | 6cced6ba154970af3160b0ec1f1a398e2a613548cc34ccc6bc3d9a09f1ad5474 |
| src/__init__.py | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| src/mandates.py | 64d2f7162bbf0bff3ac2217598be2a5c861d9d339420c30c410a4496f647690e |
| src/ledger.py | 071dcf3850406c87a37eca953b385146832eeadb95fd89b4330ccf444c01d8b0 |
| src/receiver.py | b32c12c1e7c3db01a98ac62729949665a4a125fbc88536d08c0ba2a4bcd6828b |
| runner/runner.py | 06be51abc180e0d2a270c80c96f79b65bc7ee7846f95e37e357cbcb27efd683f |
| tests/protected_tests.py | d33afaa1ede36bbeaced363e3be4f3aa3e3abdb9227fd849cb4a06c509a7b2d9 |

## Pre-contact history

- Contract written from the frozen specification, then sealed read-only.
- Lab apparatus implemented: atomic consequence ledger (one lock,
  check-and-consume indivisible), mandate/credential minting with immutable
  origin O (`origin:coalition-001:O`, bound 100), two distinct descendant
  authorities A and B, negative-control origin O2, dual-mode receiver
  (baseline = per-action authorization only; treatment = baseline checks +
  atomic cumulative origin accounting), frozen runner, 5 protected tests.
- Pre-contact defect repair: components exercised via a scratch driver
  (`scratch/defect_repair.py`, deleted after use). No defects found; no
  contract change. The frozen outcome-producing runner was NOT invoked
  before seal.
- Complexity-stop evaluation: single-directory lab apparatus, stdlib-only
  Python, one authoritative receiver, one atomic ledger. No production
  mandate-language redesign, no multi-receiver consensus, no cross-repo
  architecture. The NO_GO_COALITION_001_REQUIRES_SCOPE_EXPANSION is
  preserved, not weakened: the question is answered inside the controlled
  receiver set only.

## Scientific contact

- Contact begins with the first invocation of `runner/runner.py` after this
  record is written. Exactly one committed invocation is permitted.
- After contact: no seed swap, bound change, actor substitution, easier
  action sequence, altered negative control, receiver-topology change,
  threshold movement, rescue rerun, or contract edit.

## Contact event (filled after the single invocation)

- Runner invoked (UTC): 2026-09-16T19:56:46.041211+00:00 (exactly one committed invocation)
- Observations file: `evidence/COALITION-001-observations.json`
- Observations SHA-256: 6ec2d3b917bf812c292ef8ffab28eb822606c5fb2ac596323907ef6d5e11828f
- Runner-reported artifact hashes match the sealed table above: True (all 7)
- Verdict: PASS_COALITION_001_MANDATE_SCOPED_BOUND_ENFORCED (rule-6: all frozen conditions met)
