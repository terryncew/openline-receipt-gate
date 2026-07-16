# OLP × Pipelock Frozen Head-to-Head Protocol

Status: **FROZEN BEFORE SCORING**  
Protocol date: 2026-07-15  
Phase: ActionReceipt v1 only

## Question

Can a Pipelock ActionReceipt be valid and carry an `allow` action verdict while the
downstream claim still lacks the evidence a receiver's policy requires? If so, does
OLP distinguish that gap without laundering Pipelock's own `block` verdicts?

The strong preregistered hypothesis says Pipelock's appraisal layer does not catch
the evidence-sufficiency gap. The live AARP source makes that wording doubtful:
AARP explicitly separates verified claims from claimed-but-unverified claims and
lists properties it does not assert. Case 2 therefore freezes a harder, fairer
test: AARP must be allowed to catch the unsupported semantic claim, while OLP must
show any narrower additional value through artifact checking and an actionable
receiver disposition. If AARP catches the gap, the strong hypothesis is falsified.

## Source pins and corrections made before the freeze

| Source | Frozen commit |
|---|---|
| `terryncew/openline-receipt-gate` base | `2d8474f821df1ea4ffdd300f78f039b686811912` |
| `luckyPipewrench/pipelock` | `371893f0084ed693c1f69adf6da81c269e84aeff` |
| `luckyPipewrench/pipelock-verify-python` | `329f1c76fdfa5fc5b165a3794f7c62906a076c03` |
| `luckyPipewrench/agent-egress-bench` | `1a0d386f3d3d9370dbb6f9c86c92c403fb529cb4` |

Inspection of those pins corrected the draft before implementation:

- A shipped v1 receipt is `{version, action_record, signature, signer_key}`. The
  action fields are nested in `action_record`; stock v1 receipts omit
  `record_type`.
- ActionReceipt v1 canonicalization is the frozen Go `encoding/json` struct
  encoding, not RFC 8785. EvidenceReceipt v2 uses JCS.
- `pipelock-verify` 0.2.0 now verifies individual v2 envelopes. The OLP phase-1
  adapter will still return an explicit unsupported-format result for v2 rather
  than misreporting a bad signature.
- Because current native verification accepts valid v2, case 5 uses Pipelock's
  published malformed-v1 fixture. A genuine v2 boundary is tested separately as
  an adapter unit test and is not scored as a native rejection.
- Native receipt validity and the mediated action verdict are separate fields. A
  correctly signed receipt describing a blocked action is verifier-valid while
  its action verdict remains `block`.

## Frozen systems and trust

The authoritative native lane is the pinned `pipelock_verify` Python package. The
pinned in-repo Pipelock Python reference verifier is run as an independent parity
check. Any disagreement between those two official implementations makes the
affected case `undecidable`; the benchmark may not select whichever answer favors
OLP.

All native checks pin the public conformance key
`890726e93f89e773fb3b4298271245a69c1884fd1003846c3358b8b65a2288fa`.
An unpinned self-consistency result does not count as verified provenance.

AARP companion envelopes are clearly marked OLP-authored and use Pipelock's
public conformance-only AARP key and trust file. They are not represented as
artifacts emitted by a Pipelock deployment. Their sole purpose is to exercise
Pipelock's actual AARP appraisal logic against the frozen semantic claim.

The OLP policy is frozen in `fixtures/olp-policy.json`. Replay guarding, source
age, declared-tail completeness, independent witnessing, and outcome witnessing
are outside this five-case test so that the run isolates evidence sufficiency.
Trusted source provenance, named evidence, source binding, and one deterministic
content predicate remain required.

## Exact fixture set

`FIXTURE_MANIFEST.json` is the machine-readable complete list. Its pre-freeze
SHA-256 is `684f9046909e5fff4ebb7a643a12dcf8d4b724a2c30505de58deb56d684f746d`.
`CASES.json` SHA-256 is
`29698f0d517be8405331f49660758c7f3c22ba77ff536602ebf288471ecc8124`.

| Fixture path under `fixtures/` | SHA-256 |
|---|---|
| `aarp/case-01-clean-allow.aarp.json` | `fcbe8f5c93fe5733c84009394e65c22f2b67bdd81c6189e4040806d32322e60a` |
| `aarp/case-02-allow-missing-evidence.aarp.json` | `be36df99593fa4f420de9e45be7fe9ba04061f8769c73f11fcac0230d38b6d20` |
| `aarp/case-04-native-block.aarp.json` | `fdca7ece1e0156f6e1f0fd0c273a555c5b1a29153bc9ee488ac33fc9d948434b` |
| `aarp/pipelock-aarp-test-keys.json` | `ac68a3841dee0f524e86b7244d3ba26117f3f6d66d225016610f574db8efdfa4` |
| `aarp/pipelock-aarp-trust.json` | `781f2db33e6fdce6d1ce77c75f317bb63b3d0769bfaed18520f792d5381fcf99` |
| `evidence/case-01-downstream-evidence.json` | `df1744878237fb2c84b9c15c7da3292a060247ce39e34e035748a95197807b6f` |
| `olp-policy.json` | `910aad3ebf03ca8e33cfd13ce7a79221baa1200184398ea9fe09b137ea59bbc4` |
| `olp-trust.json` | `ec2dc0063c330e701acadacbbe74e2d553bd5eadd5448ce7302054d232895396` |
| `requests/case-01-clean-allow.request.json` | `e2fe064f211e9784487b10e555da8ec00adaa2df9ab4b6654a278f09120c6ae9` |
| `requests/case-02-allow-missing-evidence.request.json` | `0fb92ae665086dd51742d235e362701823038749dd752da896c5b32664b97988` |
| `requests/case-03-broken-chain.request.json` | `f3fc06ec49967ee11a024d1f7ca184224ba203c79f0148b76ab569645ed64ee6` |
| `requests/case-04-native-block.request.json` | `acfaa4c968d07fb470511b158b143d1b0b99b1133c6ed5dc3821a29fa9c985fe` |
| `requests/case-05-malformed-v1.request.json` | `83051c87a6889b33217dfaca868df4816c28fa948a05c194ab0b4574c74f8afa` |
| `upstream/case-01-clean-allow.json` | `9e09b65b77ecba26c564b4816ae1d67eec5ff64faf3a1ad83b39ac7276fb890a` |
| `upstream/case-01-clean-allow.upstream-expect.json` | `ebed9b73ea5a3a6a32394938b53760ad294958ddb5abbc38741d642acb7eb69d` |
| `upstream/case-02-allow-missing-evidence.json` | `52665c3b54b604a916a8742e798eed43b293d4a8b1c2361dec3bfec5fd3a29cf` |
| `upstream/case-02-allow-missing-evidence.upstream-expect.json` | `d13fd15436188e67139d9dbe34e45588776bf3a0ce6e6a2dc6a0e170f09bd05c` |
| `upstream/case-03-broken-chain.jsonl` | `0f69a43de0b9c62854299ac764b6d6dd62acc8c196c66bd98d52c2ffd9b63cc7` |
| `upstream/case-03-broken-chain.upstream-expect.json` | `d3260db60813d5cbff1a9e593276213afbd6b8c5f0fbb6b9d549e79706a080e4` |
| `upstream/case-04-native-block.json` | `400af9641503a49e48e8d549c9959b4e132fae637363be36503b28b351f8c414` |
| `upstream/case-04-native-block.upstream-expect.json` | `ed5d355dc70d50130e73bdfe7d93d7378d0cdc98b03dff7058da882bf72a3852` |
| `upstream/case-05-malformed-v1.json` | `ee930eb7dcbc220c9c887cf854b685a958af1a98ee269d76ace3caa7403b6152` |
| `upstream/case-05-malformed-v1.upstream-expect.json` | `1fd541bf4edb64e2d7a5fb4e2b92ffecc609c6224d1bc351637c94e4e8c88bce` |
| `upstream/pipelock-conformance-test-key.json` | `b944df5273ce1aacfd1a348ef99bc1cf62eb8b7d4c7736dbe40ae4ce2f38e6fc` |

## Frozen expectations

| Case | Native receipt result | Native action verdict | AARP result | OLP result |
|---|---|---|---|---|
| 1. Clean allow plus bound evidence | valid | `allow` | signed; narrow claims verified | `VERIFIED` → `COMMIT` |
| 2. Valid allow, required evidence absent | valid | `allow` | `downstream_claim_evidence_sufficient` is claimed-unverified | `UNDECIDABLE` → `QUARANTINE` |
| 3. Individually signed receipts with broken chain | rejected in chain mode | no controlling verdict | not applicable after native rejection | `REJECTED` → `DENY` |
| 4. Valid receipt carrying a Pipelock block | valid | `block` | signed; no action-safety claim | `REJECTED` → `DENY`, never `COMMIT` |
| 5. Required v1 verdict field missing | rejected | none | not applicable after native rejection | `REJECTED` → `DENY` |

## Scoring definitions

`correct` means the observed system result exactly matches the frozen expectation
for that lane. `incorrect` means it contradicts the expectation. `undecidable`
means the lane cannot produce a trustworthy comparison because an official
verifier is unavailable, the two official native implementations disagree, or a
required artifact cannot be read for reasons outside the fixture's intended test.

An OLP policy verdict of `UNDECIDABLE` in case 2 is an expected system result and
therefore a `correct` benchmark outcome. The report keeps these two concepts in
separate fields.

All aggregate tables must show counts for `correct`, `incorrect`, and
`undecidable`, including zeroes. AARP `not_applicable` is reported separately and
never converted into a win or loss.

The flagship claim survives only if case 2 behaves as frozen and the report can
name an OLP capability beyond AARP's claimed-unverified warning. If AARP flags the
unsupported claim, the strong claim that Pipelock's appraisal layer misses the
gap is falsified even if OLP still adds artifact retrieval and disposition.

## Exact commands

Run from the repository root with the three pinned source checkouts in the shown
sibling paths.

Native Pipelock package checks:

```bash
PYTHONPATH=../sources/pipelock-verify-python python3 -m pipelock_verify benchmarks/pipelock/fixtures/upstream/case-01-clean-allow.json --key 890726e93f89e773fb3b4298271245a69c1884fd1003846c3358b8b65a2288fa
PYTHONPATH=../sources/pipelock-verify-python python3 -m pipelock_verify benchmarks/pipelock/fixtures/upstream/case-02-allow-missing-evidence.json --key 890726e93f89e773fb3b4298271245a69c1884fd1003846c3358b8b65a2288fa
PYTHONPATH=../sources/pipelock-verify-python python3 -m pipelock_verify benchmarks/pipelock/fixtures/upstream/case-03-broken-chain.jsonl --key 890726e93f89e773fb3b4298271245a69c1884fd1003846c3358b8b65a2288fa
PYTHONPATH=../sources/pipelock-verify-python python3 -m pipelock_verify benchmarks/pipelock/fixtures/upstream/case-04-native-block.json --key 890726e93f89e773fb3b4298271245a69c1884fd1003846c3358b8b65a2288fa
PYTHONPATH=../sources/pipelock-verify-python python3 -m pipelock_verify benchmarks/pipelock/fixtures/upstream/case-05-malformed-v1.json --key 890726e93f89e773fb3b4298271245a69c1884fd1003846c3358b8b65a2288fa
```

Pipelock's in-repo Python reference uses the same five paths via
`python3 -m pipelock_aarp_verify receipt PATH --key KEY --json`, adding
`--chain` only for case 3. AARP is invoked exactly as follows:

```bash
PYTHONPATH=../sources/pipelock/sdk/verifiers/python/src python3 -m pipelock_aarp_verify aarp benchmarks/pipelock/fixtures/aarp/case-01-clean-allow.aarp.json --trust benchmarks/pipelock/fixtures/aarp/pipelock-aarp-trust.json --json
PYTHONPATH=../sources/pipelock/sdk/verifiers/python/src python3 -m pipelock_aarp_verify aarp benchmarks/pipelock/fixtures/aarp/case-02-allow-missing-evidence.aarp.json --trust benchmarks/pipelock/fixtures/aarp/pipelock-aarp-trust.json --json
PYTHONPATH=../sources/pipelock/sdk/verifiers/python/src python3 -m pipelock_aarp_verify aarp benchmarks/pipelock/fixtures/aarp/case-04-native-block.aarp.json --trust benchmarks/pipelock/fixtures/aarp/pipelock-aarp-trust.json --json
```

For direct OLP CLI reproduction, create a fresh test-only gate key, then invoke
each frozen request. Exit code 0 is expected only for case 1; the other four
non-commit dispositions return 1.

```bash
umask 077
python3 -m olp_gate.cli keygen benchmarks/pipelock/results/test-gate.key
python3 -m olp_gate.cli decide benchmarks/pipelock/fixtures/requests/case-01-clean-allow.request.json --policy benchmarks/pipelock/fixtures/olp-policy.json --trust benchmarks/pipelock/fixtures/olp-trust.json --key benchmarks/pipelock/results/test-gate.key --issuer frozen-pipelock-benchmark --ledger benchmarks/pipelock/results/session-ledger.json --out benchmarks/pipelock/results/direct-decisions.jsonl
python3 -m olp_gate.cli decide benchmarks/pipelock/fixtures/requests/case-02-allow-missing-evidence.request.json --policy benchmarks/pipelock/fixtures/olp-policy.json --trust benchmarks/pipelock/fixtures/olp-trust.json --key benchmarks/pipelock/results/test-gate.key --issuer frozen-pipelock-benchmark --ledger benchmarks/pipelock/results/session-ledger.json --out benchmarks/pipelock/results/direct-decisions.jsonl
python3 -m olp_gate.cli decide benchmarks/pipelock/fixtures/requests/case-03-broken-chain.request.json --policy benchmarks/pipelock/fixtures/olp-policy.json --trust benchmarks/pipelock/fixtures/olp-trust.json --key benchmarks/pipelock/results/test-gate.key --issuer frozen-pipelock-benchmark --ledger benchmarks/pipelock/results/session-ledger.json --out benchmarks/pipelock/results/direct-decisions.jsonl
python3 -m olp_gate.cli decide benchmarks/pipelock/fixtures/requests/case-04-native-block.request.json --policy benchmarks/pipelock/fixtures/olp-policy.json --trust benchmarks/pipelock/fixtures/olp-trust.json --key benchmarks/pipelock/results/test-gate.key --issuer frozen-pipelock-benchmark --ledger benchmarks/pipelock/results/session-ledger.json --out benchmarks/pipelock/results/direct-decisions.jsonl
python3 -m olp_gate.cli decide benchmarks/pipelock/fixtures/requests/case-05-malformed-v1.request.json --policy benchmarks/pipelock/fixtures/olp-policy.json --trust benchmarks/pipelock/fixtures/olp-trust.json --key benchmarks/pipelock/results/test-gate.key --issuer frozen-pipelock-benchmark --ledger benchmarks/pipelock/results/session-ledger.json --out benchmarks/pipelock/results/direct-decisions.jsonl
```

The scored run, including timing and evidence-read accounting, is exactly:

```bash
python3 -m benchmarks.pipelock.run_head_to_head --pipelock-verify-source ../sources/pipelock-verify-python --pipelock-source ../sources/pipelock --output benchmarks/pipelock/RUN_REPORT.json
```

## Measurements and claim limits

Each lane records its system result, benchmark outcome, wall time, CPU time,
verifier/tool calls, receipt bytes read, evidence bytes read, evidence reads, and
retrieval failures. Timing is descriptive and expected to vary. No combined
score is permitted.

Pipelock's `allow` means its mediated network action passed its enforcement
logic. It is not relabeled wrong when OLP quarantines a downstream claim. OLP's
receiver appraisal does not inherit Pipelock's inline, outside-agent mediation
guarantee. This benchmark tests the boundary between those layers, not which
project is universally better.

## Amendment rule

After the protocol freeze, fixture, command, policy, source-pin, or pass/fail
changes must be appended below with date, reason, old hash, new hash, and both old
and new results retained. Silent edits invalidate the run.

## Amendments

### A1 — 2026-07-15, before the scored run

The first post-freeze CLI development check exposed a path-containment error in
the case-1 request companion. Its `artifact_path` was
`../evidence/case-01-downstream-evidence.json`, while `olp-gate decide` correctly
confines reads to the request file's directory. The preliminary case therefore
returned `REJECTED` → `DENY` with
`evidence_artifact_unreadable:downstream-result`. That preliminary outcome is
retained here and is not represented as a Pipelock/OLP finding.

The same 138-byte evidence artifact was copied under `requests/evidence/`, and
the request now uses the contained path
`evidence/case-01-downstream-evidence.json`. No receipt, evidence content,
policy, expected outcome, source pin, or scoring rule changed.

| Changed object | Old SHA-256 | New SHA-256 |
|---|---|---|
| `requests/case-01-clean-allow.request.json` | `e2fe064f211e9784487b10e555da8ec00adaa2df9ab4b6654a278f09120c6ae9` | `dd360c83128bdfa582d3c39e6227a1869259f1dc6168b23bbc97743920b36c8c` |
| `FIXTURE_MANIFEST.json` | `684f9046909e5fff4ebb7a643a12dcf8d4b724a2c30505de58deb56d684f746d` | `8c09b5767aa6068eef401279f5e01af23f5b981a71b2122dc273c0814d5ddb27` |

Added file:

| Path | SHA-256 |
|---|---|
| `requests/evidence/case-01-downstream-evidence.json` | `df1744878237fb2c84b9c15c7da3292a060247ce39e34e035748a95197807b6f` |
