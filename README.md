# OpenLine Receipt Gate

**Let the agent propose. Make the receiver decide.**

OpenLine Receipt Gate is a Python safety boundary for consequential AI actions:
refunds, payments, deployments, file changes, data access, or any other tool call
that should require more than the model saying it is a good idea.

Before the protected function runs, the gate checks the exact call against:

- a receiver-owned mandate and permission policy;
- current receiver-owned state;
- fresh evidence from receiver-controlled providers;
- trusted receipt keys and source history; and
- local replay and one-use state.

If the evidence is sufficient, the call executes. If evidence is missing, the
call is quarantined. If a hard rule or integrity check fails, the call is
denied. The model cannot approve itself by writing a persuasive explanation.

> A receipt records what happened. A receiver-owned gate decides whether the
> next thing may happen.

## Status

| Item | Current state |
|---|---|
| Package | openline-receipt-gate |
| Version | 0.6.0rc6 |
| Python | 3.10 or newer |
| License | MIT |
| Maturity | Release candidate and reference implementation |

This repository is not a hosted authorization service or a production
certification. A production deployment must own its keys, policies, evidence
providers, replay state, and every route to the protected effect.

## Five-minute demo

From a clean checkout:

~~~bash
git clone https://github.com/terryncew/openline-receipt-gate.git
cd openline-receipt-gate
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python examples/langgraph_refund_guard/demo.py
~~~

On Windows PowerShell:

~~~powershell
.venv\Scripts\Activate.ps1
~~~

The demo protects a refund function:

| Proposed action | Result |
|---|---|
| Refund $25 under standing authority | Executes |
| Refund $500 without manager approval | QUARANTINE |
| Refund $500 after manager approval | Executes |
| Refund $1,000.01 despite approval | DENY |

The blocked calls never enter the refund function. The complete example and its
policy are in
[examples/langgraph_refund_guard](examples/langgraph_refund_guard/README.md).

## Choose the integration you need

| If you need to... | Start here |
|---|---|
| Protect a Python or LangGraph tool in the same process | @authorize |
| Turn existing receipts into a signed receiver decision | olp-gate decide |
| Carry one exact permission to another service or process | VerifiedCommitLedger |
| Check whether explicit decision state survived an agent handoff | Handoff Check |

## Guard a Python function

~~~python
from olp_gate import AuthorizationBlocked, authorize, payment_semantics


def current_state(call):
    customer_id = call.arguments["customer_id"]
    return {
        "customer_id": customer_id,
        "customer_version": customer_versions[customer_id],
        "manager_approved": customer_id in manager_approved,
    }


def refund_authority(call):
    amount = call.arguments["amount_cents"]
    customer_id = call.arguments["customer_id"]
    if amount <= 5_000:
        return {"basis": "standing_under_50_rule"}
    if customer_id in manager_approved:
        return {"basis": "manager_approval"}
    return None


@authorize(
    policy="refund_policy.json",
    tool="process_refund",
    target="refund://process",
    semantics=payment_semantics("amount_cents"),
    state_source=current_state,
    evidence_sources={"refund_authority": refund_authority},
)
def process_refund(amount_cents: int, customer_id: str):
    return payment_api.refund(amount_cents, customer_id)


try:
    process_refund(amount_cents=50_000, customer_id="C-1042")
except AuthorizationBlocked as blocked:
    print(blocked.decision, blocked.reason_codes)
~~~

The important boundary is ownership:

- The agent supplies the proposed tool arguments.
- The receiver supplies the policy, current-state callback, evidence callbacks,
  trusted keys, and replay state.
- Model output must never be wired into state_source or evidence_sources as
  trusted data.
- Arguments are frozen before evaluation. The executed call is rebuilt from
  those frozen values rather than caller-owned mutable objects.

For LangGraph, keep its decorator outside OpenLine's:

~~~python
@tool
@authorize(...)
def consequential_tool(...):
    ...
~~~

No LangGraph dependency is required by the gate itself. See
[docs/TOOL_ADAPTER.md](docs/TOOL_ADAPTER.md) for the adapter contract.

## Policy model

The guarded-tool policy has two parts:

| Part | Purpose |
|---|---|
| Mandate | Hard limits: agent, purpose, allowed action types, targets, amounts, delegation, and expiry |
| Permission policy | Evidence required for a particular tool and target, accepted issuers, freshness, and what to do when evidence is unavailable |

The request cannot add a trusted key, replace the receiver's policy, choose an
executable verifier, or broaden its own mandate. Start with the working
[refund_policy.json](examples/langgraph_refund_guard/refund_policy.json).

## Decisions

For protected function calls, the normal outcomes are:

| Decision | Meaning | Function runs? |
|---|---|---:|
| COMMIT | Required checks passed and the exact action was authorized | Yes |
| QUARANTINE | Required evidence is missing or the result is undecidable | No |
| DENY | A hard rule, integrity check, or trusted evidence check failed | No |

Two additional dispositions are used by specialized evaluation profiles:

- NO_BADGE: an evaluation claim lacks enough support.
- ROLLBACK_REQUEST: a signed request asks a declared external actuator to
  reverse an effect. It does not perform the rollback itself.

A valid signature proves who signed the bytes. It does not prove that the
evidence was sufficient. Signature validity alone can still produce
QUARANTINE.

## Command-line flow

Create a receiver signing key:

~~~bash
olp-gate keygen .secrets/gate.key
~~~

Issue a short-lived challenge bound to the expected source receipt:

~~~bash
olp-gate challenge state/sessions.json \
  --run-id run-123 \
  --session-id session-123 \
  --source-hash <source-receipt-sha256> \
  --ttl 300
~~~

Evaluate a request using receiver-controlled policy and trust files:

~~~bash
olp-gate decide request.json \
  --policy policy.json \
  --trust trust.json \
  --key .secrets/gate.key \
  --issuer procurement-gate \
  --ledger state/sessions.json \
  --out receipts/decision_receipts.jsonl
~~~

Verify the signed result independently:

~~~bash
olp-gate verify-decision receipts/decision_receipts.jsonl \
  --gate-key "$TRUSTED_GATE_PUBLIC_KEY"

node verify-decision-node.mjs receipts/decision_receipts.jsonl \
  --gate-key "$TRUSTED_GATE_PUBLIC_KEY"
~~~

The trusted public key must come from receiver configuration, not from the
receipt being checked. Repeat --gate-key only for an explicit key-rotation
window.

## Portable one-use permission

A signed COMMIT is evidence of a decision. It becomes portable tool permission
only when it also contains an exact Verified Commit authorization. That
authorization binds the tool, target, settings hash, run, evidence, policy,
expiry, and a receiver-held one-use code.

~~~python
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
~~~

Keep the check and the side effect inside one entry point. Calling
check_and_consume() separately creates a gap between approval and execution.
See [docs/VERIFIED_COMMIT.md](docs/VERIFIED_COMMIT.md).

## Supported evidence inputs

| Input | What Receipt Gate checks | Extra dependency |
|---|---|---|
| OLP Wire Canon 0.1 | Payload hash, Ed25519 signature, receipt kind, and amendment continuity | None |
| Agent Receipts v0.1-v0.5 | Signature, profile, chain, issuer continuity, sequence, parents, and terminal marker | None |
| Pipelock ActionReceipt v1 | Official verifier result plus receiver policy; an upstream allow is evidence, never automatic permission | Pinned pipelock-verify source |
| Assay Evidence Contract v1 | Official bundle and Trust Basis result plus receiver policy | Assay v3.32.0 CLI |
| Legacy Receipt Gate v0.1.1 | Local hash-chain continuity | None |

Adapters preserve the source system's result. They do not silently upgrade a
failed source claim, and compatibility does not grant OpenLine the source
system's enforcement powers. Details:
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Optional modules

| Module | Use it for | Boundary |
|---|---|---|
| [Handoff Check](docs/HANDOFF_CHECK.md) | Rebuild explicit decision state from Claude Code, Codex, or generic JSON/JSONL history | Ordinary assistant prose is not promoted to trusted rationale |
| [Verified Commit](docs/VERIFIED_COMMIT.md) | Bind one signed decision to one exact destination call | Local exactly-once authorization, not globally exactly-once side effects |
| [x402 Transaction Airlock](docs/X402_TRANSACTION_AIRLOCK.md) | Recheck exact payment state before settlement and release | Reference profile; receiver owns snapshot, settlement, confirmation, and release callbacks |
| [Role-Confusion Consequence Gate](docs/ROLE_CONFUSION_CONSEQUENCE_GATE.md) | Block an unsupported effect even after an agent adopts an untrusted instruction | Does not classify or repair the prompt |
| Verified Model Swap and Continuation | Test whether decision-relevant state survives a model or agent handoff | Current public runs are deterministic fixtures, not live-provider proof |

## Security boundaries

Receipt Gate is useful only where it actually controls the effect:

- Every consequential route must pass through the gate. A bypass remains a
  bypass.
- The receiver must control policy files, trust configuration, signing keys,
  evidence providers, and replay storage.
- The default local runtime is for reference use. A production service should
  use appropriate protected key custody and shared atomic state.
- Local one-use consumption prevents replay inside that ledger. It does not
  guarantee globally exactly-once side effects across external systems.
- A crash after authorization consumption fails closed and requires a new
  authorization.
- Raw evidence is verified locally but excluded from the portable decision
  receipt. The receipt carries hashes, assessments, policy identity, bindings,
  reason codes, and the decision.
- A terminal receipt proves that the declared chain has an ending marker. It
  cannot prove that every real-world event was recorded.

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/CLAIM_BOUNDARY.md](docs/CLAIM_BOUNDARY.md) before making production
claims.

## Test the repository

Run the unit and adversarial tests:

~~~bash
python -m unittest discover -s tests -v
~~~

Run the complete release gate with the archived warning-time policy:

~~~bash
python scripts/verify_warning_time_release.py --release-check
python scripts/verify_manifest.py
~~~

The full gate generates demonstration outputs. Run it in a disposable clean
checkout if you do not want those files in your working tree.

The warning-time calibration profile is historically intact but expired. The
wrapper accepts only that single archival condition. Any additional verifier
error still fails closed.

## Evidence and limits

The repository includes reproducible mechanism tests. They support narrow
claims; they are not product certifications.

| Test | Question | Current result |
|---|---|---|
| [Payment settlement ordering](benchmarks/x402_upstream_consequence/PROTOCOL.md) | Can a protected effect occur before a later settlement failure? | Yes, in the pinned official Python MCP wrapper; the matched airlock withheld release |
| [Post-compromise action gate](docs/ROLE_CONFUSION_CONSEQUENCE_GATE.md) | Can receiver-owned evidence stop an unsupported effect after model compromise? | 13 frozen cases met their expected receiver-side outcomes |
| [Early-warning benchmark](benchmarks/warning_time/README.md) | Did a synthetic trace metric create an intervention window? | Historical result preserved; calibration expired and has no live authority |
| [One-use execution](docs/VERIFIED_COMMIT.md) | Can one decision authorize one exact local execution? | Mutation, expiry, replay, and concurrent double use were blocked in the disclosed suite |
| [Measurement routing](docs/RMA_001.md) | Can prediction choose the next assay without replacing physical measurement? | No promotable signal; sequence routing saved 0.8% versus the best fixed order, below the frozen bar |

## Project map

| Path | Purpose |
|---|---|
| olp_gate/tool_adapter.py | @authorize function boundary |
| olp_gate/gateway.py | Receipt appraisal and signed decision creation |
| olp_gate/verified_commit.py | Exact one-use authorization and local atomic consumption |
| olp_gate/adapters.py | External receipt-format adapters |
| examples/ | Small runnable integrations |
| docs/ | Architecture, threat model, schemas, and module contracts |
| benchmarks/ | Frozen tests, protocols, and result artifacts |
| scripts/ | Independent verifiers and release checks |

## Legacy API

The original context-manager API still emits an unsigned local hash chain:

~~~python
from olp_gate import gate

with gate(
    action_type="tool_call",
    claim="Search customer records",
    evidence_required=True,
) as receipt:
    result = search_customer_records(query)
    receipt.commit(result, evidence={"query_hash": "sha256:..."})
~~~

Use @authorize or the proof-to-policy CLI for signed decisions and external
evidence. The legacy wrapper remains for backward compatibility.

## License

[MIT](LICENSE)

Proof travels. Permission belongs to the receiver.
