# OpenLine Receipt Gate

Most receipts make the past verifiable. Receipt Gate makes verified history usable by the next decision.

It accepts signed OLP Wire Canon receipts, Agent Receipts v0.1–v0.5, Pipelock ActionReceipt v1, and the older local Receipt Gate chain. It checks integrity, provenance, declared coverage, the source system's action signal, freshness, evidence, and an independent outcome separately. The result is a signed policy decision:

```text
COMMIT
QUARANTINE
DENY
NO_BADGE
ROLLBACK_REQUEST
```

A valid signature can still produce `UNDECIDABLE`. Signature validity is never treated as evidence sufficiency.

## Run the discriminating test

```bash
python -m unittest discover -s tests -v
python -m olp_gate.cli demo-proof-to-policy --output results/proof_to_policy_demo
node verify-decision-node.mjs results/proof_to_policy_demo/decision_receipts.jsonl \
  --gate-key 17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce
```

Without the optional Pipelock verifier, the core suite passes and reports nine
explicit skips. Install `requirements-pipelock.txt` to execute all integration
tests; the release report records discovered, executed, and skipped counts for
both modes.

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
```

Raw evidence is read for verification and excluded from the decision receipt. The receipt contains artifact hashes, policy identity, reason codes, assessments, binding fields, and the decision.

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

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md), and [`docs/CLAIM_BOUNDARY.md`](docs/CLAIM_BOUNDARY.md) before making production claims.

The five-case demo uses fixed, publicly disclosed fixture keys so its output is reproducible. Those keys have no production authority.

## Public line

Agent receipts make actions auditable. OpenLine makes accountability executable.

Small receipts. Big accountability.
