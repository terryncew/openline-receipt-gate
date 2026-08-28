# Agent-Mesh-Identity-001 — Identity Adequacy Regression Pack

**Verdict:** `CURRENT_EFFECT_BINDING_COVERS_ALL_FIVE_CASES`

**Evidence tier:** `PAPER_DERIVED_REGRESSION_FIXTURE_PACK`

**Policy authority:** `NONE`

Agent Mesh reports five production subsystems that confidently answered the
wrong question because their identity key collapsed states that differed or
split effects that were equivalent. This experiment translates those five
Table II failures into paired Receipt Gate proposals and runs the existing
`effect_hash` unchanged.

## Frozen result

| Paper subsystem | Failed identity error | Required relation | Current effect binding |
|---|---|---:|---:|
| circuit breaker | same check name hid changed progress | distinct | pass |
| effect ledger | transaction IDs split identical content | equal | pass |
| topology graph | logical name collapsed physical databases | distinct | pass |
| failure attribution | scenario coverage collapsed causal owners | distinct | pass |
| work planner | cross-component coupling collapsed component work | distinct | pass |

The paper-failed-identity control reproduced all five errors: four false
collisions and one false split. The current Receipt Gate effect binding matched
the sealed oracle on all five.

No production code changed. No new identity mechanism is warranted by this
fixture pack.

## What actually earned the result

Receipt Gate's effect identity excludes delegation provenance such as proposal
ID, producer, model, objective, and advisory material. It binds the semantic
effect instead:

```text
tool + physical target + settings + receiver state hash
```

That makes two retries of the same publication one effect while keeping two
physical databases, causal owners, component scopes, or workspace states
separate.

## Boundary

The receiver adapter still has to choose the right target, settings, and state
hash. This benchmark supplies that mapping explicitly. It proves the existing
primitive can represent the five distinctions; it does not prove arbitrary
integrations will identify the correct semantic object automatically.

The source is [Agent Mesh v1](https://arxiv.org/abs/2608.26225v1), Section V
and Table II. The authors' controlled fault harness and incident corpus are not
used, so this is neither a cold integration nor a reproduction of the private
production incidents.

## Reproduce

```bash
python experiments/agent-mesh-identity-001/scripts/run_experiment.py
python experiments/agent-mesh-identity-001/scripts/verify_result.py
python -m unittest discover -s experiments/agent-mesh-identity-001/tests -v
python experiments/agent-mesh-identity-001/scripts/verify_release.py
```

The independent verifier imports neither the runner nor Receipt Gate. It
recomputes all ten serialized identity rows directly from the sealed fixture
and representation-blind oracle.

