# OPENLINE-CONSEQUENCE-002: local atomic consequence experiment

**Final mission verdict: PARTIAL. Local comparison: PARITY.** The reconstructed
local SQLite contract passes for both implementations. The canonical twelve
OPENLINE-CONSEQUENCE-001 scenarios are absent from the supplied revision, and
GitHub API access currently prevents opening the required Draft PR. Do not
interpret the local result as completion of those unavailable requirements.
The `LOCAL_CONSEQUENCE_VERIFIED` designation is deliberately withheld.

Reference/starting branch: `feature/openline-consequence-001` at
`81db6acb72149df989aac1827e5f621b0873d57b`.
Implementation branch: `feature/openline-consequence-002`.
There is no dependency on PR #119. No merge, release, deployment, robot,
production system, money transfer, paid model call, or external outreach occurred.

## Actual evidence

| Check | Actual result | Raw evidence |
|---|---|---|
| Original JSON/SQLite dual-write contract | 2 intentional failures, 0 errors, exit 1 | `evidence/before/raw.log`, `negative-result.json` |
| Reconstructed matrix, both implementations | 42 run: 41 passed, 1 skipped, exit 0 | `evidence/after/raw.log` |
| Existing Verified Commit tests | 12 passed | `evidence/existing/verified_commit.log` |
| Existing subject-bound/stolen-authority tests | 8 passed | `evidence/existing/subject_bound.log` |
| Existing owner-control tests | 7 passed | `evidence/existing/owner_control.log` |
| Separate exact-head PR #119 tests | 4 passed | `evidence/pr119/tests.log` |
| Independent verifier after each matrix test | 38 valid snapshots, 4 expected tamper rejections | each `scenarios/*/*/verifier.json` |
| Additional consumption-tamper verifier processes | 2 expected rejections | `test_21*/tampered-ledger-verifier.json` |

The single skip is the OpenLine-only JSON ledger schema check on the conventional
implementation, which has no JSON consumption ledger. Its consumption table and
independent verifier are tested separately. All runner exit statuses are preserved.
Unittest success includes tests that correctly expect tampering to be rejected.

Actual SQLite databases, inspected rows, signed permission fixtures, owner heads,
subprocess stdout/stderr/exit statuses, immediate post-crash rows, and fixture
issuance artifacts are retained per scenario. `evidence/after/manifest.json`
contains hashes and exact commands. `evidence/attestation.json` binds the source
and evidence hashes with the public TEST-ONLY outcome key; it is an integrity
exercise, not an independent trusted witness. All fixture private keys and bearer
codes are public artificial test data. Production audit records store code hashes.

Early integration failures are preserved under `evidence/development/`: the first
runner had no verifier yet; the next collected a class alias twice; the next ran
before the verifier's new outcome field was installed. These are disclosed runner
and integration failures, superseded by the final run. They are not relabeled as
successful exploit evidence. Independent review additionally found and corrected
an advancing-clock expiry race and lost JSON-ledger schema validation.

## Reproduction

Python >=3.10 and `cryptography>=42` are required. Observed runtime: Python 3.12.14,
cryptography 50.0.0, SQLite version recorded in the manifest. From repository root:

```sh
python experiments/openline-consequence-002/run.py --output /tmp/consequence-002-new-run
```

Use a **new** output directory: the runner refuses to overwrite evidence. It
preserves the real test exit code and executes 42 tests plus independent verifier
subprocesses. Direct suite command:

```sh
PYTHONPATH=. python -m unittest discover -s experiments/openline-consequence-002 -p test_atomic.py -v
```

Verify a saved crash-recovered database with externally trusted fixture roots:

```sh
python experiments/openline-consequence-002/verify.py \
  experiments/openline-consequence-002/evidence/after/scenarios/openline/test_05_crash_immediately_after_commit/state.sqlite3 \
  --roots experiments/openline-consequence-002/evidence/after/scenarios/openline/test_05_crash_immediately_after_commit/roots.json
```

The roots file is an out-of-band trust input, **not** a key discovered from the DB.
Shipping it beside the fixture enables reproduction; it is not secure provisioning.
For portability, copy only the checkpointed database plus the separately trusted
roots, then invoke the same verifier in another process. Portable copies of the
archived evidence were verified, and the archive's file hashes checked afterward.

Reproduce the original failure into a fresh directory (expected exit 1):

```sh
CONSEQUENCE_NEGATIVE_OUTPUT=/tmp/consequence-002-negative-new \
  python experiments/openline-consequence-002/reproduce_dual_write.py \
  > /tmp/consequence-002-negative.log 2>&1
```

This still imports the unchanged original VerifiedCommitLedger, not the new
adapter. The original checked-in negative observations predate adapter changes.
The script now refuses to overwrite an existing negative-result archive.

Other exact commands:

```sh
python -m unittest discover -s tests -p test_verified_commit.py -v
python -m unittest discover -s tests -p test_stolen_authority_001.py -v
python -m unittest discover -s tests -p test_owner_control_002.py -v
python experiments/openline-consequence-002/evidence/pr119/reproduce.py
```

## The original boundary is falsified

`VerifiedCommitLedger.execute_once()` durably spends JSON permission, then runs an
external executor, then separately writes completion evidence. `os._exit(73)`
after consumption leaves a spent permission and SQLite `commissioned=0`.
`os._exit(74)` after the SQLite commit leaves `commissioned=1` and the JSON
execution status `started`, with no completed outcome. Fresh-worker retries are
rejected in both cases. The existing primitive provides one-use authorization;
it does not make an arbitrary external effect atomically recoverable.

## Narrow additive implementation

`olp_gate/sqlite_consequence.py` has a fixed commissioning operation. It accepts
no arbitrary executor and makes no external calls. A private transaction ledger
subclasses VerifiedCommitLedger and replaces only its storage context. The full
existing `check_and_consume()` method, including signed decision recomputation,
canonical exact-action binding, code, expiry and replay checks, runs unchanged.
The context requires an already-active SQLite transaction, checks ledger schema,
and cannot call the legacy external `execute_once()` route.

One `BEGIN IMMEDIATE` transaction covers:

1. Pinned receiver roots and implementation identity, current enabled policy,
   receiver time and a successful-transaction clock watermark.
2. The latest owner head read from SQLite (no cached MandateOwnerView), validated
   by existing owner-signature and monotonic-successor functions. The mandate's
   principal must equal the pinned owner; it must remain active and unexpired.
3. A receiver-owned zero-argument authenticated-subject source matching the
   mandate's stable subject. Claude/Codex worker labels confer no identity.
4. Exact settings binding the current mandate hash, simulation evidence digest,
   robot configuration digest, site version and signed idempotency key. The
   receiver checks current artifact bytes and the simulation's approved flag.
5. Unchanged Verified Commit consumption (or conventional validation), independent
   SQL uniqueness for decision, authorization, code, idempotency, and site/version.
6. A compare-and-swap of `sites.commissioned=0` to `1`, incrementing its version.
7. A signed outcome containing authorization/evidence references, authenticated
   subject, owner head, before/after rows, policy and prior-outcome hash, inserted
   into an immutable commitment row before the same database commit.

The existing principal mandate action vocabulary has no commissioning verb.
This narrow profile explicitly maps commissioning to `send` for the exact
`sqlite://commissioning/site-1` target and owner-signed purpose `commission site`.
It grants no arbitrary SQL, money operation, or other target permission.

All raw evidence/configuration and governing site references reside inside this
same SQLite database. Content-addressed files outside the transaction are not
silently treated as current state. Owner transitions share the same write lock.
Explicit genesis initialization refuses an existing path; reopening a missing DB
fails rather than silently constructing an empty replay authority. Worker roots,
implementation and signer must match retained receiver configuration.

## Reconstructed matrix and additional falsifiers

The original twelve-scenario source was not present in checkout text, historic
filenames or the supplied branch. `evidence/pr119/scenario-search.log` records the
search. The following matrix was reconstructed from this mission; it is **not**
a claim that the unavailable original twelve were executed verbatim.

| Test | Scenario | OpenLine / conventional |
|---|---|---|
| 01 | Exact commit, authenticated idempotent retry | PASS / PASS |
| 02 | Forgery, changed bindings and wrong bearer code | PASS / PASS |
| 03 | Four independent concurrent writer processes | PASS / PASS |
| 04 | Real process death immediately before COMMIT; recovery | PASS / PASS |
| 05 | Real process death immediately after COMMIT; recovery | PASS / PASS |
| 06 | Revocation and stale receiver worker | PASS / PASS |
| 07 | Authorization expiry while blocked on SQLite write lock | PASS / PASS |
| 08 | Stale simulation, configuration or site version | PASS / PASS |
| 09 | Changed/disabled current receiver policy | PASS / PASS |
| 10 | Worker succession under stable subject; foreign subject denied | PASS / PASS |
| 11 | Fresh valid receipt/code for an already-committed transition | PASS / PASS |
| 12 | Independent verifier detects artifact tampering | PASS / PASS |
| 13 | Missing database and attempted reinitialization | PASS / PASS |
| 14 | Clock rollback and mutable caller data after snapshot | PASS / PASS |
| 15 | Foreign owner principal and changed pinned roots | PASS / PASS |
| 16 | Expiry during authenticated-subject callback | PASS / PASS |
| 17 | Original JSON-ledger schema fails closed | PASS / N/A skip |
| 18 | Independent SQL uniqueness constraints | PASS / PASS |
| 19 | Signed revocation commits before a waiting writer acquires lock | PASS / PASS |
| 20 | Independent verifier detects durable row/outcome disagreement | PASS / PASS |
| 21 | Independent verifier detects consumed-state tampering | PASS / PASS |

## Crash contract and recovery

SQLite uses WAL, foreign keys and `synchronous=FULL`. The filesystem and SQLite's
commit guarantees are trusted. Before-commit process death rolls back mutation,
consumption, and outcome together. After-commit process death leaves all three.
The response can be lost; an exact authenticated retry returns `ALREADY_COMMITTED`
with the original signed outcome and no further effect. A different request
under the same idempotency key is refused. Different keys cannot recommission the
same site/version. Worker construction never resets policy, owner head or replay.

New mutation requires current authorization. After post-commit revocation or
expiry, `commission()` refuses even an exact retry; historical outcome recovery
remains available through the read-only independent verifier/database. This is
not a promise that a revoked worker retains a live consequence capability.

Time is sampled after acquiring the write lock, then sampled again immediately
before the protected UPDATE and checked against receipt, owner and mandate
expiry. Expiry is defined at that final validation instant, not an impossible
atomic wall-clock test inside the COMMIT syscall. Clock integrity is a trust
assumption. The watermark persists successful transactions only: failed checks
roll it back, and no claim is made to detect every rollback after a refusal.
Revocation ordering is SQLite transaction order; a revocation arriving after a
commissioning transaction commits cannot undo it.

The original JSON ledger's internal attempt remains `permitted`; it represents
permission consumption. The new signed SQLite outcome, not a fabricated legacy
`completed` flag, records the actual protected row transition. Denied attempts
roll back and are not a durable denial journal; raw test logs retain refusals.

## Fair conventional comparison

Both implementations use the **same signed OpenLine authorization inputs** and
cryptographic verifier, authenticated subject seam, pinned roots, write lock,
current owner/policy/evidence checks, SQL constraints, mutation and signed audit
schema. The conventional path validates exact permission then consumes using
SQL unique constraints directly. OpenLine additionally reuses its unchanged JSON
ledger algorithm with SQLite storage. This compares consumption integration,
not a separately built identity ecosystem or a weaker unsigned baseline.

| Dimension | Finding |
|---|---|
| Correctness | PARITY on the disclosed local matrix |
| Crash/restart recovery | PARITY: same SQLite commit and idempotency constraints |
| Revocation | PARITY: same signed owner heads and transactional observations |
| Evidence portability | PARITY: same signed outcome and independent verifier |
| Trust management | PARITY: same keys, authenticated subject, clock and protected DB |
| Implementation | Shared 315-line kernel; conventional validator 118 lines; OpenLine reuses the larger existing ledger through a small context override |
| State cost | OpenLine keeps redundant JSON consumption/attempt state in addition to indexed commitments; conventional uses the commitments table directly |

Line counts include comments/docstrings and are descriptive, not a maintainability
score. No throughput advantage or independent end-to-end baseline stack is
claimed. SQLite is responsible for local atomicity in both implementations.

## PR #119 review and delivery limitation

Exact reviewed PR head: `1749a226b5f77cabc98f04a8655636229e0b11c2`.
Four files change the refund simulation/docs/tests, enforcing the signed manager
cap and distinguishing unsigned preflight refusal from signed gate compilation.
Four isolated tests passed. No cryptography, Verified Commit or SQLite code from
that PR was merged, modified, or depended upon. Main was observed at the reference
SHA; neither main nor PR #119 was written by this mission.

Native HTTPS Git access works. GitHub API requests fail before authentication at
the environment proxy with `CONNECT tunnel failed, response 403` / `Forbidden`.
The existing `GH_TOKEN` is present; its value was never printed or copied. A
configuration draft adds only `api.github.com` to custom allowed domains,
preserving package-manager presets. Draft saving does not activate networking or
publish an environment. The required Draft PR cannot be claimed until that
network change is activated and PR creation succeeds. A ready PR body is supplied
in `PR_BODY.md`; creation uses `--draft --base feature/openline-consequence-001`.

Earlier HOME-GUARD work was preserved in Git stash
`5f0cb1ae81c1023e1a6cdc2236fd0575df7ae46b`; none was overwritten or included here.

## Limits and remaining falsifiers

- This is a real local SQLite state transition over simulated commissioning
  facts. It is not robot actuation, real deployment, packet enforcement, physical
  safety, a provider identity attestation, or an autonomous production service.
- `subject_source` consumes authentication established by a trusted receiver;
  this experiment supplies a fixture. It implements no mTLS/workload-identity
  protocol and does not turn a caller-asserted string into authentication.
- Signed outcomes are receiver testimony. The independent process recomputes
  signatures, exact bindings, owner chains, content hashes, consumption, and rows;
  it cannot prove historical secret possession, the true latest head at the time,
  admission order, signer integrity, or external facts without receiver trust.
- Whole-DB rollback/deletion, cloned independent ledgers, privileged file edits,
  key compromise, malicious trusted callbacks, inaccurate clocks, disk hardware
  ignoring fsync, physical power loss and arbitrary commit-syscall failures are
  outside this proof. Replacing the DB with an older internally valid snapshot
  requires an external monotonic checkpoint to detect; none is claimed.
- The crash tests use real `os._exit` at disclosed before/after-commit failpoints.
  They are not exhaustive instruction-level fault injection or a power-cut test.
- Any duplicate commitment, mutation lacking signed evidence/consumption,
  consumption without its corresponding mutation, stale or revoked authority
  admitted after serialization, or independently inconsistent protected rows
  falsifies the local contract. The first twelve must be reconciled with the
  missing canonical specification before claiming full mission verification.
