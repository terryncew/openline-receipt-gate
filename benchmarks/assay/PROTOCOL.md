# OLP × Assay Frozen Head-to-Head Protocol

Status: **FROZEN BEFORE THE FIRST SCORED RUN**  
Protocol date: 2026-07-16  
Target: Assay Evidence Contract / Trust Basis as shipped in Assay v3.32.0

## Question and correction to the proposed claim

The proposed question was whether Assay preserves sources and manages policy
gates while OLP uniquely signs what a receiving system may do next.

Primary-source inspection required a correction before scoring. Assay v3.32.0
already ships:

- offline-verifiable evidence bundles and exact-level Trust Basis assertions;
- fail-closed, pre-call MCP policy decisions;
- signed user mandates for scoped action authorization; and
- an Ed25519 DSSE/in-toto attestation command that signs an arbitrary
  caller-supplied JSON predicate over a verified evidence bundle.

Therefore, “OLP uniquely signs what the receiver may do next” is too broad and
is not a permitted benchmark conclusion. This protocol tests a narrower product
distinction: whether OLP consumes an unchanged Assay bundle, preserves Assay's
native claim boundary, evaluates a separate receiver-owned evidence requirement,
and emits OLP's standardized signed post-ingest disposition. A separate
capability control must demonstrate Assay's arbitrary-predicate signing and mark
the broad signing-uniqueness hypothesis falsified if it passes.

## Frozen source and executable

| Item | Pin |
|---|---|
| Assay repository | `https://github.com/Rul1an/assay` |
| Release | `v3.32.0` |
| Release commit | `04d3db10adbe191aa731d52a6c2b77dad8bc0ca7` |
| Linux archive | `assay-v3.32.0-x86_64-unknown-linux-gnu.tar.gz` |
| Archive SHA-256 | `243f5e3935530cb1405dbb54fa57acc944de2800d28537d08dfc305b2a117775` |
| OLP pre-track base | `7674f7d7bc95efc8eae5e12ad76d348f01d8b8f7` |

Assay v3.33.0 was the newest source release observed during preparation, but it
did not publish the Linux CLI archive required for this independently runnable
binary lane. v3.32.0 is selected because the official executable, source commit,
and archive digest can all be pinned. No result from a locally rebuilt or newer
Assay binary may be substituted into this run.

The runner verifies all of the following before scoring:

1. `assay --version` is exactly `assay 3.32.0`.
2. The downloaded archive has the frozen SHA-256.
3. The executed binary is byte-identical to the sole `assay` member in that
   archive.
4. The frozen upstream OpenFeature fixture regenerates a byte-identical Assay
   evidence bundle with the exact command below.

## Exact upstream fixture and preparation command

The source fixture is copied verbatim from:

`examples/openfeature-evaluation-details-evidence/fixtures/decision-details.openfeature.jsonl`

at the frozen Assay commit. Its SHA-256 is
`72b1eaa773be72f6ddfa56ae4547605c1f5e8be9e5db7841bd7947a4215979b0`.

The frozen Assay bundle is generated before scoring with exactly:

```bash
"$ASSAY_BIN" evidence import openfeature-details \
  --input benchmarks/assay/fixtures/upstream/decision-details.openfeature.jsonl \
  --bundle-out /tmp/regenerated-openfeature-bundle.tar.gz \
  --source-artifact-ref decision-details.openfeature.jsonl \
  --run-id olp_assay_h2h \
  --import-time 2026-07-16T12:00:00Z
```

The expected archive SHA-256 is
`06902924787b20aad33b5ec521fb82f3aeec361da290a3b2a862ea149946bc8b`.
The runner requires byte equality, not merely semantic equivalence.

## Frozen fixture set

`FIXTURE_MANIFEST.json` is the complete machine-readable list. Its SHA-256 is
`fd5dbe8358e495d9bcafb75db9ed693e0b554eb7d8e9a52a6bc386e0c6758f72`.
`CASES.json` SHA-256 is
`69d0a7a88294a935e1b1bef6d024ccdb79eefdf32a2aa7c4903f058522fb525e`.

| Fixture path under `fixtures/` | SHA-256 |
|---|---|
| `assay/openfeature-decision-receipts.tar.gz` | `06902924787b20aad33b5ec521fb82f3aeec361da290a3b2a862ea149946bc8b` |
| `case-01-clean-with-receiver-evidence.request.json` | `0f2a840ce9b8938b8a609533aabe526408e7cf03f734351bc29e493b5bf8c618` |
| `case-02-receiver-evidence-missing.request.json` | `710aa2a404aef680c6feaedec4afa20f6523982e310e54d7e5b8f1268748c5c3` |
| `case-03-tampered-bundle.request.json` | `18b0158519f6ad8836d2d3a8fde824f97a6f37246f0dc6fb39076f6e787cec29` |
| `case-04-assay-registered-claim-missing.request.json` | `12642fb02844293d7ad56b471c40ff60217e89837cd85ea8ad515fad43d9c682` |
| `case-05-source-hash-substitution.request.json` | `0cab473da8ce8a4afd65f9e7869b040aebf856ed2f0e3875d8edf1dcd602c0a0` |
| `evidence/receiver-release-approval.json` | `f4b7a95f186c7293a9b9a9a48fa963b6f070b522f3c51ce33e7abef3e41c24f3` |
| `olp-policy.json` | `e277b892177130ec2f63d1a94865b6b71343122cc1aadced5e5d7a6b430a20fb` |
| `olp-trust.json` | `755b6f135a7892adf30fad3ee287c568bd1a031f6dbe171a8117af8af16762bc` |
| `receiver-predicate.json` | `9a597c6aecdb71ad917dc4cd25584767ad84479419cce7d9b46af3f78e111b78` |
| `upstream/decision-details.openfeature.jsonl` | `72b1eaa773be72f6ddfa56ae4547605c1f5e8be9e5db7841bd7947a4215979b0` |

The Assay bundle and upstream JSONL are Assay-originated. The receiver policy,
requests, receiver evidence, and capability predicate are OLP-authored and are
identified as such in the manifest. They are not represented as artifacts
emitted by an Assay deployment.

## Lanes and authority

### Assay native lane

The official frozen CLI is authoritative for bundle integrity:

```bash
"$ASSAY_BIN" evidence verify <bundle.tar.gz>
```

OLP does not reimplement Assay's tar, JCS, content-hash, or bundle-root rules.

### Assay Trust Basis lane

For each natively valid bundle, the official CLI compiles and asserts the exact
requirements stored in that case's `source_bundle.trust_basis_requirements`:

```bash
"$ASSAY_BIN" trust-basis generate <bundle.tar.gz> --out /tmp/trust-basis.json
"$ASSAY_BIN" trust-basis assert \
  --input /tmp/trust-basis.json \
  --require <CLAIM=LEVEL> \
  --format json
```

A failed native assertion must remain a failed source signal in OLP. OLP may not
upgrade it using receiver evidence.

### OLP receiver lane

OLP receives the archive by path and receiver-declared SHA-256. Its adapter
delegates native bundle and registered-claim checks to the frozen Assay CLI,
preserves the archive hash, then applies `fixtures/olp-policy.json` to a separate
receiver evidence artifact. OLP emits and independently verifies a signed
five-disposition decision receipt.

The policy deliberately sets source age to `null`: this experiment uses a
frozen historical fixture and tests byte binding, claim assertions, receiver
evidence, and one-time challenge replay protection—not a claim that the fixture
was recently created.

### Assay DSSE capability control

The runner invokes:

```bash
"$ASSAY_BIN" evidence attest \
  --bundle benchmarks/assay/fixtures/assay/openfeature-decision-receipts.tar.gz \
  --key <temporary-deterministic-pkcs8-ed25519-key> \
  --predicate benchmarks/assay/fixtures/receiver-predicate.json \
  --out benchmarks/assay/results/assay_receiver_predicate.attestation.json
```

The runner independently verifies the Ed25519 DSSE signature, decodes the
in-toto statement, and requires the signed predicate to equal the frozen input.
The private key is temporary and is never written into a result or release.

Passing this control falsifies the claim that OLP alone can sign a
receiver-styled next-use predicate. It does not establish that Assay recomputed
that arbitrary predicate's receiver policy semantics or that Assay exposes
OLP's standardized five post-ingest dispositions.

## Frozen cases and expected results

| Case | Assay native | Assay Trust Basis | OLP receiver disposition | Mechanism |
|---|---|---|---|---|
| 1. Clean bundle and receiver evidence | valid | pass | `VERIFIED` → `COMMIT` | baseline agreement |
| 2. Same bundle, receiver artifact missing | valid | pass | `UNDECIDABLE` → `QUARANTINE` | receiver-required evidence is outside the two registered Assay claims |
| 3. One archive byte changed | rejected | unavailable | `REJECTED` → `DENY` | official Assay integrity failure is propagated |
| 4. Require absent Assay signing evidence | valid | fail | `REJECTED` → `DENY` | Assay itself catches a registered missing-evidence claim |
| 5. Internally valid bundle with false receiver SHA pin | valid | pass | `REJECTED` → `DENY` | receiver byte-binding mismatch; an Assay receiver could also add this external pin |

Case 2 is not scored as an Assay error. Assay correctly passes the two claims it
was asked to assert; the absent receiver artifact belongs to a different,
receiver-owned policy. The value under test is the composition and signed
next-use output, not a claim that Assay's result is wrong.

## Scoring definitions

Every lane reports all three categories, including zero counts:

- **correct**: the observed native validity, exact-level assertion status, or
  OLP verdict/disposition and named mechanism matches the frozen expectation;
- **incorrect**: the system executes but differs from its own frozen
  expectation;
- **undecidable**: the required system cannot execute, emits an unparseable
  result, or encounters a verifier/infrastructure error not equivalent to the
  expected policy rejection.

The semantic OLP verdict `UNDECIDABLE` is distinct from benchmark scoring. Case
2 is a correct benchmark outcome precisely when OLP emits the semantic
`UNDECIDABLE` verdict and `QUARANTINE` disposition.

Per case, the runner records wall time, CPU time, verifier-call count, bytes
read, and receiver evidence reads. These are reported separately. There is no
combined score, and timing is not part of a deterministic reproduction claim.

## Exact scored command

After downloading and extracting the frozen release archive, set the two paths
and execute exactly:

```bash
ASSAY_BIN="${ASSAY_BIN:?set ASSAY_BIN to the extracted v3.32.0 assay binary}"
ASSAY_ARCHIVE="${ASSAY_ARCHIVE:?set ASSAY_ARCHIVE to the downloaded v3.32.0 archive}"
python benchmarks/assay/run_head_to_head.py \
  --assay-bin "$ASSAY_BIN" \
  --assay-archive "$ASSAY_ARCHIVE" \
  --output benchmarks/assay/RUN_REPORT.json \
  --report benchmarks/assay/REPORT.md \
  --results-dir benchmarks/assay/results
```

## Pass and falsification rules

The run passes only if:

- every Assay native, Assay Trust Basis, and OLP lane matches its own frozen
  expectation with no infrastructure-undecidable case;
- the frozen upstream fixture regenerates byte-identically;
- all five OLP decision receipts verify under the recorded gate key; and
- the Assay DSSE capability control passes and the report visibly marks the
  broad signing-uniqueness hypothesis falsified.

If cases 1 and 2 do not produce different OLP dispositions, the claimed
receiver-evidence composition is falsified. If case 4 is not rejected by Assay's
Trust Basis assertion, the benchmark's representation of Assay is wrong and the
release fails. If the DSSE capability control does not pass, no uniqueness
conclusion is permitted; the result is infrastructure-undecidable until the
control is corrected without changing the fixture or expected semantics.

## Claim boundary

Permitted after a passing run:

> In this frozen run, OLP preserved an Assay bundle, delegated Assay-native
> claims to Assay, applied a separate receiver policy, and signed a standardized
> next-use disposition.

Not permitted:

- OLP beats Assay.
- Assay cannot sign receiver decisions or arbitrary predicates.
- Assay failed case 2.
- OLP provides Assay's inline MCP enforcement or kernel enforcement.
- A signature proves that a predicate is true.
- The five fixtures establish a universal product advantage.

## Freeze and amendment rule

This protocol, `CASES.json`, and `FIXTURE_MANIFEST.json` are committed before
`RUN_REPORT.json` is generated. `FREEZE.json` records that reachable commit and
all three hashes. Any later change to fixtures, commands, expectations, scoring,
or source pins requires a dated `AMENDMENT-NNN.json`; the original frozen
protocol remains available as `PROTOCOL-FROZEN-v0.4.0.md`, and earlier results
remain visible.
