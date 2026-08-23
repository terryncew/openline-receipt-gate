from __future__ import annotations

from pathlib import Path

from olp_gate import AuthorizationBlocked, authorize, payment_semantics

HERE = Path(__file__).resolve().parent
manager_approved: set[str] = set()
customer_versions = {"C-1042": 7}
refunds: list[tuple[int, str]] = []


def refund_authority(call):
    amount = call.arguments["amount_cents"]
    customer = call.arguments["customer_id"]
    if amount <= 5_000:
        return {"basis": "standing_under_50_rule"}
    if customer in manager_approved:
        return {"basis": "manager_approval", "customer_id": customer}
    return None


def current_state(call):
    customer = call.arguments["customer_id"]
    return {
        "customer_id": customer,
        "customer_version": customer_versions[customer],
        "manager_approved": customer in manager_approved,
    }


@authorize(
    policy=HERE / "refund_policy.json",
    tool="process_refund",
    target="refund://process",
    semantics=payment_semantics("amount_cents"),
    state_source=current_state,
    evidence_sources={"refund_authority": refund_authority},
    producer_model="langgraph-agent",
    runtime_dir=HERE / ".openline-demo",
)
def process_refund(amount_cents: int, customer_id: str):
    refunds.append((amount_cents, customer_id))
    return {"status": "refunded", "amount_cents": amount_cents, "customer_id": customer_id}


def main():
    print("1) Agent proposes a normal $25 refund")
    print(process_refund(amount_cents=2_500, customer_id="C-1042"))
    print()

    print("2) Agent proposes $500 because a lawsuit threat makes it look optimal")
    try:
        process_refund(amount_cents=50_000, customer_id="C-1042")
    except AuthorizationBlocked as exc:
        print("OPENLINE BLOCKED:", exc.decision, list(exc.reason_codes))
    print("refunds after blocked attempt:", refunds)
    print()

    print("3) Manager approval arrives; the same $500 effect now earns authority")
    manager_approved.add("C-1042")
    print(process_refund(amount_cents=50_000, customer_id="C-1042"))
    print("refunds after approval:", refunds)
    print()

    print("4) Even manager approval cannot exceed the receiver's $1,000 hard ceiling")
    try:
        process_refund(amount_cents=100_001, customer_id="C-1042")
    except AuthorizationBlocked as exc:
        print("OPENLINE BLOCKED:", exc.decision, list(exc.reason_codes))


if __name__ == "__main__":
    main()
