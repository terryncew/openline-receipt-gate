# OpenLine Receipt Gate

Most receipts make the past verifiable. Receipt Gate makes verified history usable by the next decision.

It accepts signed OLP Wire Canon receipts, Agent Receipts v0.1–v0.5,
Pipelock ActionReceipt v1, Assay Evidence Contract v1 bundles, and the older
local Receipt Gate chain. It checks integrity, provenance, declared coverage,
the source system's action signal, freshness, evidence, and an independent
outcome separately. The result is a signed policy decision:

```text
COMMIT
QUARANTINE
DENY
NO_BADGE
ROLLBACK_REQUEST
```

A valid signature can still produce `UNDECIDABLE`. Signature validity is never treated as evidence sufficiency.

## Verified Commit (v0.5.0rc2)

Proof travels; permission belongs to the receiver.

Verified Commit keeps the existing `COMMIT` disposition and the existing
`proof_to_policy_decision_receipt`. When a receiver chooses to authorize a
consequential tool call, the signed receipt additionally binds the exact:

```text
tool · target · settings hash · run · capsule · evidence · policy · expiry · one-use code hash
```

The destination tool checks that signed authorization against its own trusted
gate key and atomically consumes it before calling the tool. Changed settings,
wrong targets, expiry, replay, and concurrent double use fail before execution.
An ordinary `COMMIT` without `commit_authorization` remains valid evidence, but
it grants no portable tool permission.

Run the disclosed Model A → Model B → one approved write proof:

```bash
pip install -r requirements-model-swap.txt
export OLP_HALF_LIFE_ROOT=../openline-half-life

olp-gate demo-verified-commit \
  --half-life-output "$OLP_HALF_LIFE_ROOT/examples/demo_output" \
  --succession-policy-key "$OLP_HALF_LIFE_ROOT/policy/succession_policy_public_key.hex" \
  --compaction-policy-key "$OLP_HALF_LIFE_ROOT/policy/compaction_policy_public_key.hex" \
  --source-model fixture/model-a \
  --target-model fixture/model-b \
  --output results/verified_commit_demo
```

The demo tries nine mutations, two simultaneous uses, and a sequential replay.
It records every receiver-side result and independently regrades the model-swap
proof. For a real tool adapter, keep the check and side effect in one entry
point:

```python
from olp_gate import VerifiedCommitLedger

result = VerifiedCommitLedger("state/commit-ledger.json").execute_once(
    signed_decision,
    exact_action,
    one_use_code=receiver_held_code,
    trusted_gate_keys=[receiver_gate_public_key],
    executor=lambda: destination_tool(**exact_action["settings"]),
)
if not result["authorized"]:
    raise PermissionError(result["reason_codes"])
```

`check_and_consume()` is exposed for adapter internals, but separating it from
the tool call creates a time-of-check/time-of-use boundary. Prefer
`execute_once()`. See [`docs/VERIFIED_COMMIT.md`](docs/VERIFIED_COMMIT.md).

## Verified Model Swap (introduced in v0.5.0rc1)

Verified Model Swap asks one bounded question: can a different model receive the
agent's decision-relevant state without changing what the receiver would allow?

It grades three lanes against an independent replay of the raw verified history:

```text
uninterrupted full history     -> receiver oracle
ordinary active-state summary -> measured omissions
Half-Life causal capsule      -> exact COMMIT / QUARANTINE / DENY comparison
```

The candidate adapter, Half-Life compactor, and DSM display cannot grade the
trial. Receipt Gate authenticates Half-Life's policies, chain, archive, and
decision-equivalence output; independently replays the raw history; restores the
cold archive; then binds the proof card as evidence in the existing
`proof_to_policy_decision_receipt`. No score, receipt family, disposition, or
automatic retirement rule is added.

Install the pinned integration and run the disclosed offline fixture:

```bash
pip install -r requirements-model-swap.txt
export OLP_HALF_LIFE_ROOT=../openline-half-life

olp-gate demo-model-swap \
  --half-life-output "$OLP_HALF_LIFE_ROOT/examples/demo_output" \
  --succession-policy-key "$OLP_HALF_LIFE_ROOT/policy/succession_policy_public_key.hex" \
  --compaction-policy-key "$OLP_HALF_LIFE_ROOT/policy/compaction_policy_public_key.hex" \
  --source-model fixture/source-model \
  --target-model fixture/target-model \
  --output results/verified_model_swap_demo
```

Verify it from the receiver side with the externally retained gate public key:

```bash
olp-gate verify-model-swap results/verified_model_swap_demo \
  --half-life-output "$OLP_HALF_LIFE_ROOT/examples/demo_output" \
  --succession-policy-key "$OLP_HALF_LIFE_ROOT/policy/succession_policy_public_key.hex" \
  --compaction-policy-key "$OLP_HALF_LIFE_ROOT/policy/compaction_policy_public_key.hex" \
  --gate-key <receiver-gate-public-key>
```

For a production run, use `olp-gate model-swap` with three distinct mode-0600
keys: source/orchestrator, independent grader, and receiver gate. Model and
adapter identifiers remain caller declarations until a provider adapter emits
separately verifiable execution evidence. The built-in demo proves the offline
protocol boundary, not a live commercial-provider swap. Separate keys establish
key separation only; the receiver must still establish controller independence,
custody, and trust roles outside this bundle.

## Run the discriminating test

```bash
python -m unittest discover -s tests -v
python -m olp_gate.cli demo-proof-to-policy --output results/proof_to_policy_demo
node verify-decision-node.mjs results/proof_to_policy_demo/decision_receipts.jsonl \
  --gate-key 17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce
```

Without optional integrations, the core suite passes and reports twenty-two
explicit skips: nine Pipelock tests, five Assay-binary tests, and eight Verified
Model Swap tests. Install `requirements-pipelock.txt`, set `OLP_ASSAY_BIN` to the
pinned Assay v3.32.0 executable, and install `requirements-model-swap.txt` with
`OLP_HALF_LIFE_ROOT` set to run every integration test. Two Assay fail-closed
boundary tests and the pure model-swap summary control always run. Because
Verified Commit is the flagship v0.5.0rc2 change, so the complete release gate
holds unless its pinned Half-Life runtime and fixture are present. The release
report records discovered, executed, and skipped counts for both the current and
dependency-absent modes.

Expected outcomes:

```text
valid signature + missing evidence       → UNDECIDABLE / QUARANTINE
bound evidence + orthogonal outcome      → VERIFIED / COMMIT
exact replay                             → REJECTED / DENY
unsupported benchmark score              → UNDECIDABLE / NO_BADGE
trusted harmful mutation + rollback path → REJECTED / ROLLBACK_REQUEST
```

The Python and independent Node verifiers both recompute the policy decision from the signed assessment set and policy snapshot. Rewriting a verdict and resealing it produces `decision_recompute_mismatch`.

Run the complete release gate, including hostile tamper controls and an offline
install of the built wheel into an empty target from an unrelated directory:

```bash
python scripts/release_check.py
python scripts/verify_manifest.py
```

The checked-in GitHub Actions workflow runs this same complete gate with Python
3.12, Node 24, and the exact Half-Life commit declared in
`requirements-model-swap.txt`. It does not treat the dependency-absent skip
suite as release evidence.

## Proof-to-policy flow

```text
source receipt
    ↓
integrity ─ provenance ─ coverage ─ freshness
    ↓
source-bound evidence + policy predicates
    ↓
orthogonal outcome witness, when required
    ↓
VERIFIED / REJECTED / UNDECIDABLE
    ↓
COMMIT / QUARANTINE / DENY / NO_BADGE / ROLLBACK_REQUEST
    ↓
signed, parent-linked decision receipt
    ↓ (only when exact permission is present)
receiver-side atomic consume → destination tool
```

Raw evidence is read for verification and excluded from the decision receipt.
The receipt contains artifact hashes, policy identity, reason codes,
assessments, binding fields, and the decision. Verified Commit additionally
stores exact non-secret identifiers plus hashes of settings and the receiver-held
one-use code; neither raw settings nor the raw code is stored in the signed
receipt.

## Supported inputs

### OLP Wire Canon 0.1

The gate independently verifies the payload hash, Ed25519 signature, strict receipt-kind profile, and amendment continuity. Wire Canon 0.1 remains `self`/`provisional`; a continuous chain therefore earns partial declared coverage rather than proof that every real event was captured.

### Agent Receipts v0.1–v0.5

The gate verifies the embedded Ed25519 proof, declared profile, chain ID, issuer continuity, sequence, previous-receipt hashes, and terminal marker. Verification keys come from an external trust store or a resolvable Ed25519 `did:key`. Trust still requires an explicit trust-store role; key resolution alone does not make an issuer trusted.

The bundled verifier supports the integer-only RFC 8785 subset used by current Agent Receipt protocol fields. A receipt containing floating-point values returns `canonicalization_unsupported`, not a false bad-signature verdict.

The interoperability test includes Agent Receipts' published v0.5 runtime vector at upstream commit `df6833a39743e17127d5ad4b10cdc8f6734d8e03` and independently matches its expected signature and receipt hash.

### Pipelock ActionReceipt v1

The adapter delegates signature, profile, and chain verification to the official
`pipelock-verify` 0.2.x source release for ActionReceipt v1. It pins the signer through the external OLP
trust store and keeps Pipelock's action verdict separate from OLP's receiver
disposition. An `allow` is advisory evidence, never an automatic `COMMIT`; a
verified `block` fails the required `source_signal` assessment and can never be
laundered into a commit.

EvidenceReceipt v2 is detected but deliberately unsupported in this phase. It
returns an explicit `canonicalization_unsupported`/phase-boundary result instead
of a false bad-signature diagnosis.

Install the exact verifier used by the frozen benchmark:

```bash
pip install -r requirements-pipelock.txt
```

If the official verifier is absent or outside the supported range, the
adapter returns `pipelock_verifier_unavailable` or a version-unsupported result.
It never falls back to locally reimplemented cryptography.

PyPI currently exposes v0.1.1. It is deliberately unsupported here: it verifies
the simplest public fixture but fails newer signed v1 fixtures whose action
records use fields added after its canonical field set. The pinned source
install avoids misreporting those receipts as bad signatures. When PipeLab
publishes v0.2.0, this can become a normal versioned package extra.

The frozen five-case benchmark is in [`benchmarks/pipelock`](benchmarks/pipelock/PROTOCOL.md).
It uses pinned public Pipelock fixtures and reports the result that actually
occurred: native Pipelock and OLP met all frozen expectations, while Pipelock
AARP also flagged the unsupported downstream claim. That falsifies the strongest
proposed wedge. The narrower observed difference is that OLP additionally read
the receiver-required artifact and emitted a signed `COMMIT` or `QUARANTINE`.

The Pipelock vendor subsequently reproduced the five native classifications and
the three applicable AARP classifications directly with Pipelock's own
verifiers. Their review confirmed the boundary description and found one public
reproduction blocker: v0.3.0 referred to an intermediate freeze commit that was
never pushed. v0.3.1 preserves that identifier and adds a byte-identical frozen
protocol snapshot, allowing a clean clone to verify the original hash without
silently substituting a later commit. The vendor review is recorded as boundary
confirmation, not neutral third-party reproduction.

For a fresh reproduction that leaves the sealed report untouched, use the same
pinned source checkouts and write to a new subdirectory:

```bash
python -m benchmarks.pipelock.run_head_to_head \
  --pipelock-verify-source ../sources/pipelock-verify-python \
  --pipelock-source ../sources/pipelock \
  --output benchmarks/pipelock/results/reproduction/RUN_REPORT.json \
  --report benchmarks/pipelock/results/reproduction/REPORT.md \
  --decision-log benchmarks/pipelock/results/reproduction/decision_receipts.jsonl
```

### Assay Evidence Contract / Trust Basis v3.32.0

The Assay adapter preserves the incoming `.tar.gz` archive by SHA-256 and
delegates bundle verification, manifest interpretation, Trust Basis generation,
and exact-level claim assertions to Assay's official CLI. OLP does not
reimplement Assay's tar, JCS, event-hash, or bundle-root logic. A failed Assay
assertion becomes a failed OLP `source_signal` and cannot be repaired or
laundered by receiver evidence.

The integration is pinned to Assay release `v3.32.0`, source commit
`04d3db10adbe191aa731d52a6c2b77dad8bc0ca7`, using the official Linux x86-64
archive with SHA-256
`243f5e3935530cb1405dbb54fa57acc944de2800d28537d08dfc305b2a117775`.
The benchmark runner proves that the executed binary is byte-identical to the
binary inside that archive. Set its path with `OLP_ASSAY_BIN` or pass
`--assay-bin` to `olp-gate decide`.

The frozen five-case track is in
[`benchmarks/assay`](benchmarks/assay/PROTOCOL.md). It found:

- Assay native verification met 5/5 frozen expectations;
- Assay Trust Basis assertions met 5/5, including correctly rejecting an
  absent registered claim;
- OLP met 5/5 receiver-policy expectations and never upgraded the failed Assay
  claim;
- the identical Assay-valid source bundle led OLP to signed `COMMIT` when the
  receiver-required artifact existed and signed `QUARANTINE` when it did not;
  and
- Assay successfully signed a caller-supplied receiver-style predicate using
  its DSSE/in-toto attestation command.

That last control falsifies the broad claim that only OLP can sign what a
receiver may do next. The narrower observed difference is that OLP exposes a
standardized post-ingest contract: receiver policy snapshot and hash, separate
assessment axes, three verdicts, five dispositions, replay binding, and
independent semantic recomputation. The benchmark does not claim Assay cannot
implement that contract, and it does not give OLP Assay's inline MCP or kernel
enforcement.

Run the frozen track without changing its sealed result:

```bash
python benchmarks/assay/run_head_to_head.py \
  --assay-bin "$OLP_ASSAY_BIN" \
  --assay-archive "$OLP_ASSAY_ARCHIVE" \
  --output benchmarks/assay/results/reproduction/RUN_REPORT.json \
  --report benchmarks/assay/results/reproduction/REPORT.md \
  --results-dir benchmarks/assay/results/reproduction/artifacts
```

### Legacy Receipt Gate v0.1.1

The original context-manager API and local JSONL hash chain still work. Legacy records can prove local continuity, but they remain unsigned and therefore cannot earn trusted provenance under the new gate.

## CLI

Create a gate key:

```bash
olp-gate keygen .secrets/gate.key
```

The command creates a mode-`0600` Ed25519 key and refuses to overwrite an existing file.

Issue a one-time challenge bound to the expected source receipt:

```bash
olp-gate challenge state/sessions.json \
  --run-id run-123 \
  --session-id session-123 \
  --source-hash 0123456789abcdef... \
  --ttl 300
```

Evaluate a request with policy and trust configuration kept outside the request:

```bash
olp-gate decide request.json \
  --policy policy.json \
  --trust trust.json \
  --key .secrets/gate.key \
  --issuer procurement-gate \
  --ledger state/sessions.json \
  --assay-bin "$OLP_ASSAY_BIN" \
  --out receipts/decision_receipts.jsonl
```

Verify the output independently:

```bash
olp-gate verify-decision receipts/decision_receipts.jsonl \
  --gate-key "$TRUSTED_GATE_PUBLIC_KEY"
node verify-decision-node.mjs receipts/decision_receipts.jsonl \
  --gate-key "$TRUSTED_GATE_PUBLIC_KEY"
```

The trusted gate key must come from receiver-controlled configuration, not from the receipt being checked. Multiple `--gate-key` arguments support an explicit rotation window.

## Legacy one-line wrapper

```python
from olp_gate import gate

with gate(
    action_type="tool_call",
    claim="Search customer records",
    evidence_required=True,
) as g:
    result = search_customer_records(query)
    g.commit(result, evidence={"query_hash": "sha256:..."})
```

This path continues to emit the v0.1.1 local hash chain. Use the proof-to-policy API for signed decisions and external inputs.

## Boundaries

- `ROLLBACK_REQUEST` is a signed request to a declared actuator. It does not undo an action by itself.
- A terminal receipt proves the declared receipt chain has an ending marker. It does not prove an actor emitted every consequential event.
- A matching evidence hash proves artifact correspondence. Policy predicates and independent outcomes determine whether the artifact is sufficient for the declared decision.
- The local session ledger prevents replay within its custody boundary. A host with full write access can replace the ledger and gate key; external anchoring remains a separate deployment requirement.
- Agent Receipts compatibility does not claim generic W3C VC ecosystem conformance.
- Pipelock compatibility does not give OLP Pipelock's inline mediation boundary.
- The benchmark's AARP companions are OLP-authored conformance inputs, not receipts captured from a deployed Pipelock instance.
- Assay compatibility does not give OLP Assay's pre-call MCP policy gate,
  signed mandate semantics, or kernel enforcement.
- Verified Commit is enforced only at a destination tool that enters through
  `VerifiedCommitLedger` (or an equivalent receiver implementation) and shares
  the same atomic consumption state. It does not constrain bypass paths.
- One-use authorization is not a claim of globally exactly-once side effects.
  A crash after consumption fails closed; retry requires a new authorization.
- Assay's frozen bundle is generated from its public OpenFeature fixture; the
  receiver policy, receiver evidence, and DSSE predicate are OLP-authored and
  are not represented as deployment captures.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md), and [`docs/CLAIM_BOUNDARY.md`](docs/CLAIM_BOUNDARY.md) before making production claims.

The five-case demo uses fixed, publicly disclosed fixture keys so its output is reproducible. Those keys have no production authority.

## Public line

Proof travels. Permission belongs to the receiver.

Small receipts. Big accountability.
