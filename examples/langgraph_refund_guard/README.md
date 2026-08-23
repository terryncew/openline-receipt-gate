# LangGraph refund guard — 5-minute reference demo

The adapter is ordinary Python. LangGraph can use the guarded callable without a custom graph integration.

```python
from langchain_core.tools import tool
from olp_gate import authorize, payment_semantics

@tool
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
```

`@tool` stays outside `@authorize`, so every LangGraph invocation reaches OpenLine before the consequential function body.

Run the dependency-free terminal version from the repository root:

```bash
python examples/langgraph_refund_guard/demo.py
```

The demo shows four cases: $25 executes; $500 without manager authority is blocked even when the agent has a compelling rationale; the same $500 executes after manager approval appears in receiver-owned state/evidence; and $1,000.01 is denied by the hard mandate ceiling even with approval.

The sub-10-minute Time to First Value goal is a product target, not a measured claim. The reference path intentionally requires only the decorator, one policy JSON file, a state callback, and receiver-owned evidence callbacks. No LangGraph package is required by OpenLine itself.
