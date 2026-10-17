# Multi-hop refund drift — an honest 60-second local replay

**Run:** from the [OpenLine Receipt Gate](https://github.com/terryncew/openline-receipt-gate) repository root:

```bash
python -m pip install -e .
python examples/multi_hop_refund_drift.py
```

The scenario is a **simulated** three-hop handoff. A manager authorizes a refund on ticket 8842 for **at most $500 USD**, bound to `invoice_v1`. The orchestrator compresses it into "clear the disputed balance", and the billing sub-agent proposes **POST /v1/payouts for $4,800**. There are no agents, payment credentials, network calls, or funds in this demo: a payment simulator only appends to an in-memory list.

The first run intentionally configures coarse service IAM with permission to call the payout endpoint but **without checking the manager's task-specific amount or action**. It returns a simulated HTTP 200 and records one synthetic effect. This is a failure of that deliberately incomplete configuration, **not a claim that OAuth, IAM, or OpenTelemetry cannot enforce richer policies**.

The second run routes the exact same $4,800 payout through the **existing `olp_gate.authorize`** decorator. The manager-signed local intent is independently checked in receiver-owned evidence; the receiver-owned `principal_mandate/v1` allows the refund target and has `max_payment_cents=50000`. The **payout route** fails admission and the payment simulator is not invoked. Two independent controls prove the real constraint: the correct refund endpoint at **$4,800** also hard-denies on the cap; an **in-scope $500 refund** does execute exactly once. The main payout DENY has **two actual compiler reasons**: `mandate:payment_limit_exceeded` and `mandate:target_not_allowed` (both shown in the diagram), not solely a wrong route.

**Independent cold-run correction (October 17):** A first external reviewer ran the demo successfully but found that the original manager-evidence callback compared amounts to a local `CAP` constant rather than to `owner_intent["max_amount_cents"]` from the verified manager signature. With all caps initially equal, the mistake was hidden. The corrected callback verifies the manager's signed instruction and enforces its **actual signed cap** independently of the receiver mandate. Regression tests isolate `$100 signed / $500 receiver` (local callback refusal `owner_signed_limit_exceeded`) and `$500 signed / $100 receiver` (Receipt Gate compiler refusal `mandate:payment_limit_exceeded`); each blocks a $500 refund and allows a legitimate $100 one. Importantly, the owner-limit callback raises `AuthorizationBlocked` **before** the compiler completes, so do not mistake that callback exception for a receiver-signed denial receipt. Original peer feedback is retained as received; these new tests do not constitute outside revalidation. Changing the receiver's invoice to `invoice_v2` blocks a further $500 attempt. This is a local gate demonstration, not an externally accepted portable signed mandate.

## Real OpenTelemetry mode (optional)

OpenLine's separate [`openline-otel` 0.2.0](https://github.com/terryncew/openline-otel) package can receive **real SDK spans** and produce signed *provisional, self-attested* trace receipts, including the gate's actual decision and reason codes recorded as span attributes.

```bash
python -m pip install "openline-otel @ git+https://github.com/terryncew/openline-otel.git@f8c05bf933c725aa1d108aebe7b2030867277dfb"
python examples/multi_hop_refund_drift.py --otel
```

When `--otel` is omitted, the terminal replay is illustrative; it does **not** secretly emit OTel spans. The `--otel` path actually uses the OpenTelemetry SDK with `OpenLineReceiptProcessor` and locally signs trace captures. Signed capture verifies byte integrity, **not observation truth, completeness, or independent receiver custody**. The demo does not claim a guaranteed 2 ms decision, native automatic middleware, production-grade policy distribution, or any real payment API call. The wall time printed is measured locally and is machine-dependent. Full tests: `python -m unittest tests.test_multi_hop_refund_drift_demo -v`.

## What the gate does and does not enforce

The trust boundary is the **actual wrapped Python function**. Real protection requires *every* consequential API or MCP path to pass through a receiver-owned enforcement point with no bypass. A green HTTP trace is evidence about transport/execution status, not proof the human's original restrictions were checked. OpenLine here demonstrates an additional explicit action/cap/receiver-state check; it is not a substitute for a competently configured IAM+OPA/authorization service. `GO/SPLIT/BRAKE` or any agent's reasoning cannot mint permissions.

The demo's independent authority check uses a locally generated manager Ed25519 signature plus a receiver policy loaded from this script. It does **not** demonstrate a full three-hop portable receipt chain: the intermediate agents are narrated in the trace, not actual distributed processes. Do not generalize from this offline proof to production transfers or multiple independent organizations.

To record a 60-second terminal GIF: run both conditions as one script, scroll through the positive/negative controls, and include the “LOCAL SIMULATION, NO FUNDS” line. Do not use invented trace IDs or invented durations.
