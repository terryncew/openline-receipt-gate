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

## Pinned upstream x402 consequence reproduction (v0.6.0rc6)

This release adds one comparative result against current, official upstream
code rather than another self-authored hostile fixture.

At x402 commit `167a828e8319aa7b403f4f4312489e9cffadff10`, the official
asynchronous Python MCP wrapper verifies payment, executes the tool handler,
and only then attempts settlement. The checked-in reproduction uses an actual
durable file effect: when settlement raises, the wrapper returns an error but
the handler's effect has already occurred once.

The matched Receipt Gate composition attempts the same failing settlement but
does not invoke the protected resource-release callback. A legitimate
settlement plus matching confirmation releases the resource exactly once.

```bash
python benchmarks/x402_upstream_consequence/run_comparison.py \
  --upstream-root /path/to/x402-at-167a828e
python scripts/verify_x402_upstream_consequence.py \
  --upstream-root /path/to/x402-at-167a828e
```

The runner refuses a different upstream commit or different source bytes. The
independent verifier imports no Receipt Gate modules and checks the upstream
call order, recorded observations, and durable effect bytes. This earns a
narrow consequence-order claim for the pinned Python MCP wrapper. It is not a
live-chain exploit, a claim about every x402 SDK, or production certification.
See
[`benchmarks/x402_upstream_consequence/PROTOCOL.md`](benchmarks/x402_upstream_consequence/PROTOCOL.md).

## Role-Confusion Consequence Gate (v0.6.0rc6)

The model can be fooled without the receiver being fooled.

This release adds a frozen receiver-side hostile suite for the case where an
authenticated agent has already adopted an untrusted instruction and requests a
protected action it is structurally allowed to request. Receipt Gate does not
classify the prompt or attempt to repair the model. It asks whether
receiver-pinned, action-bound evidence still justifies the protected effect.

```bash
olp-gate role-confusion-suite \
  --benchmark benchmarks/role_confusion_consequence \
  --output benchmarks/role_confusion_consequence/results/hostile_report.json
python scripts/verify_role_confusion_consequence.py
```

The frozen matrix contains 13 synthetic cases. The decisive matched pair uses
the exact same action and authorization structure: untrusted webpage evidence
returns `QUARANTINE`, while receiver-pinned signed evidence returns `COMMIT`.
The suite also covers fake-user text inside tool output, forged reasoning,
stale or stripped evidence, replay, action-binding mismatch, forged
trusted-origin keys, conflicting fresh trusted evidence, a mixed trusted bundle
containing both exact-action support and a receipt bound to a different action,
and unrelated untrusted content that must not cause a false block. A valid
trusted wrong-action receipt is treated as bundle incoherence and fails closed;
untrusted unrelated evidence remains ignorable.

Each case passes through a harmless receiver-side effect callback. Blocked
cases must leave that callback untouched; the three committed controls invoke
it exactly once. The independent verifier imports no consequence-gate code,
recomputes every decision and effect expectation, verifies the frozen source
closure, and checks the result report. Attack text, attack labels, model
reasoning, and detector scores are absent from the appraisal input.

**The model compromise is assumed, not reproduced. This demonstrates that
unsupported evidence can be stopped before consequence even when exact-action
authorization is otherwise valid.**

This is a deterministic post-compromise mechanism test, not a live attack
reproduction. The standalone callback is not an atomic replay ledger;
production effects must compose appraisal with Verified Commit. See
[`docs/ROLE_CONFUSION_CONSEQUENCE_GATE.md`](docs/ROLE_CONFUSION_CONSEQUENCE_GATE.md).

## OpenLine Handoff Check (v0.6.0rc6)

Change the agent without losing why the work was done.

Handoff Check imports a local Claude Code transcript, Codex rollout JSONL, or
a generic JSON/JSONL history; names the next important action; builds a bounded
fresh-agent capsule; and then separately replays the full canonicalized history
with a different traversal and validator to check whether the inherited state
still matches. The capsule cannot approve itself.

```bash
olp-gate handoff-check ~/.claude/projects/.../session.jsonl \
  --next "implement the authentication refactor" \
  --repo . \
  --output ./handoff
```

The public continuation result is one of:

```text
SAFE_TO_CONTINUE
DECISION_CHANGED
EVIDENCE_MISSING
UNDECIDABLE
```

The tool never converts ordinary assistant prose into trusted rationale. A
decision, evidence item, constraint, assumption, open question, rejected path,
or artifact becomes semantic handoff state only when the history contains an
explicit structured `semantic` object or an `OLP_*` marker. If the rationale is
not explicitly supported, the result is `EVIDENCE_MISSING`; malformed or
uninterpretable source material fails closed as `UNDECIDABLE`.

A successful run writes `capsule.json` and `capsule.md` for the new agent, a separate
`reference_replay.json`, a restore index, a machine-readable report,
an optional signed continuation receipt, and a shareable local proof card.
`handoff-inspect` can later compare the capsule against a changed history and
report a stale inherited decision, but the receiver must provide `--next`
again rather than trusting the capsule's action. `handoff-restore` rederives
the full archive index and can recover explicit state left outside the capsule
only when the original source-history hash still matches.

The included example is a deterministic conformance fixture, not evidence that
real Claude Code or Codex sessions preserve decisions better in practice. The
product claim remains bounded to the supplied local history and explicit state.
 See [`docs/HANDOFF_CHECK.md`](docs/HANDOFF_CHECK.md) for the adapter and marker contract.

## Warning Time benchmark (v0.5.0rc6)

An early-warning metric matters only when it creates a measurable window in
which Receipt Gate can prevent a bad action. The corrected DSM / Receipt Gate
benchmark freezes a **signed Calibration Profile** before held-out evaluation.
The profile binds the graph, prompts, observable-state metric source, clean
calibration evidence, thresholds, paired seed design, private custody anchor,
and the limited actions those thresholds may govern.

```text
warning_time_steps = bad_action_step - first_warning_step
gate_lead_time_steps = bad_action_step - gate_intervention_step
```

The metric function receives only seed, step, current observable state, and
previous observable state. It does not receive the case label, corruption type,
injection step, or expected result. A label-swap probe confirms that warnings
follow the state mutation rather than the displayed label. The same 20 held-out
seeds are reused across all three conditions so the seed cannot identify the
case.

The disclosed experiment uses 40 clean calibration runs and 60 held-out runs.
One hundred total runs is this fixture's starting design, not a universal
requirement. The held-out result is:

```text
clean controls               0 / 20 false alarms · 20 COMMIT
dropped counter-evidence     0 / 20 missed · reference warning +5 · 20 QUARANTINE
unflagged contradiction      0 / 20 missed · reference warning +5 · 20 DENY
Receipt Gate lead            +3 steps in both reference corruptions
```

Reproduce it:

```bash
python -m benchmarks.warning_time.run_benchmark \
  --output benchmarks/warning_time/results
python scripts/verify_warning_time_benchmark.py
```

The standalone verifier imports no warning-time benchmark modules and
independently recomputes the observable features, metric values, clean-only
thresholds, held-out trajectories, signatures, decisions, warning times, and
hashes. It also pins the exact external-anchor witness key and payload hash, so
an attacker-selected signer cannot certify substituted custody metadata. The
frozen publication's referenced private Library object must still be checked
outside the offline verifier. This proves bounded custody order for the
disclosed artifact, not a public transparency timestamp or production
authority.

The signed profile may emit a warning or require Receipt Gate reappraisal. It
may not issue COMMIT, QUARANTINE, or DENY, authorize execution, or retire a
model. Successful held-out separation establishes predictive usefulness for
the named synthetic stack and failures only; it does not prove the κ, Δ_hol,
or VKD ontology is true. See
[`benchmarks/warning_time/README.md`](benchmarks/warning_time/README.md).

## Verified Commit

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
The release suite additionally races 32 receiver processes against one
authorization and requires exactly one tool invocation.
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

## Verified Continuation (v0.5.0rc8)

Normal handoffs move context. OLP determines what the receiving system may
trust and do with it.

The frozen first outside trial holds the receiver, repository checkout, task,
tools, terminal tests, and tool-call budget constant. Only inherited state
changes:

```text
producer self-summary
no prior state
Half-Life bounded capsule + receiver appraisal
```

Receipt Gate derives direct repeated-exploration, trace-error,
terminal-defect, and budget counts from three recorded traces. It does not
accept caller-supplied scores. The continuation claim passes only when the OLP
lane stays within budget, is no worse than both baselines on repeated
exploration and defects, and is strictly better than each baseline on at least
one of those outcomes.

The included traces are synthetic harness-conformance data. They deliberately
produce a favorable direct-count pattern but remain `UNDECIDABLE` because no
outside provider execution is established:

```bash
olp-gate evaluate-continuation \
  benchmarks/verified_continuation \
  --output results/verified_continuation_fixture
python scripts/verify_verified_continuation.py
```

Authorization is a separate claim. The disclosed Git trial binds an existing
Verified Commit authorization to one exact compare-and-swap update of
`refs/heads/receiver-approved`. Wrong-branch, changed-commit, expired, replayed,
and simultaneous duplicate writes must stop before ref mutation:

```bash
olp-gate demo-continuation-authorization \
  --half-life-output "$OLP_HALF_LIFE_ROOT/examples/demo_output" \
  --succession-policy-key "$OLP_HALF_LIFE_ROOT/policy/succession_policy_public_key.hex" \
  --compaction-policy-key "$OLP_HALF_LIFE_ROOT/policy/compaction_policy_public_key.hex" \
  --source-model fixture/producer-model \
  --target-model fixture/receiving-model \
  --output results/verified_continuation_authorization
```

DSM receives only a display projection after evaluation. Because these compact
traces do not contain authoritative DSM snapshot state, κ, Φ*, and VKD remain
`UNDECIDABLE`; DSM cannot grade either claim. See
[`benchmarks/verified_continuation/PROTOCOL.md`](benchmarks/verified_continuation/PROTOCOL.md).

## x402 Transaction Airlock (v0.5.0rc6)

Settlement proof is evidence. It is not, by itself, permission for the receiver
to execute or release a protected resource.

The Transaction Airlock is a narrow profile inside Verified Commit. It binds
the exact scheme, network, asset, amount, recipient, resource, execution
template, run, evidence, receiver policy, expiry, and one-use code into the
existing signed `COMMIT`. At use time it consumes that permission, obtains a
fresh receiver-owned snapshot, and rechecks authorization authenticity, nonce,
balance, settleability, and verification-context hashes immediately before the
settlement callback. The shared receiver ledger also atomically reserves the
payment's scheme/network/asset/payer/signature-model/nonce scope, so distinct
valid COMMIT receipts cannot replay or race the same payment. Resource release
requires a separate confirmation matching the submitted transaction hash and
exact payment fields, followed by the receiver's positive acknowledgment of
that exact target and transaction hash.

The frozen hostile suite maps the eight rules from Wang et al.,
[*When HTTP 402 Meets the Blockchain*](https://arxiv.org/abs/2607.19545), to 56
synthetic cases:

```text
56 / 56 hostile cases passed
SR1–SR8 covered
network · asset · recipient · amount · expiry · replay ·
verification/settlement divergence blocked at the declared boundary
```

Reproduce and independently verify it:

```bash
python benchmarks/x402_airlock/run_hostile_suite.py
python scripts/verify_x402_airlock.py
```

The verifier uses only the Python standard library and imports neither the
candidate package nor benchmark modules. This is not a live facilitator,
wallet, or chain audit. Receiver snapshot and confirmation providers remain
trusted deployment components, and routes that bypass the airlock remain
outside the claim. See
[`docs/X402_TRANSACTION_AIRLOCK.md`](docs/X402_TRANSACTION_AIRLOCK.md).

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

Without optional integrations, the core suite passes and reports twenty-four
explicit skips: nine Pipelock tests, five Assay-binary tests, eight Verified
Model Swap tests, and two Verified Continuation integration tests. The
root-ready source archive includes a hash-pinned, pure-Python Half-Life wheel
and fixture used only by the complete deterministic release gate, so
`python scripts/release_check.py` runs green without a network checkout or
special environment variable. An explicitly supplied invalid
`OLP_HALF_LIFE_ROOT` still fails closed; it never falls back silently.

Local hashes establish bundle integrity, not independent upstream provenance.
GitHub Actions separately fetches the exact Half-Life commit declared in
`requirements-model-swap.txt` and byte-compares its source, fixture, policies,
and license with the vendored release bundle. The release report records
discovered, executed, and skipped counts for both the complete and
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
3.12 and Node 24, compares the vendored dependency against the independently
fetched Half-Life commit, and does not treat the dependency-absent skip suite
as release evidence. It installs the exact build prerequisites declared in
`pyproject.toml` before the no-build-isolation wheel check. Failed release
checks are named in the JSON summary with bounded stdout/stderr tails.

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
- The x402 Transaction Airlock is a synthetic exact-action adapter. It does not
  authenticate live chain state, make a facilitator safe, or mediate routes
  that bypass its receiver-owned snapshot, ledger, settlement, confirmation,
  and release boundary.
- Assay's frozen bundle is generated from its public OpenFeature fixture; the
  receiver policy, receiver evidence, and DSSE predicate are OLP-authored and
  are not represented as deployment captures.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md), and [`docs/CLAIM_BOUNDARY.md`](docs/CLAIM_BOUNDARY.md) before making production claims.

The five-case demo uses fixed, publicly disclosed fixture keys so its output is reproducible. Those keys have no production authority.

## Public line

Proof travels. Permission belongs to the receiver.

Small receipts. Big accountability.
