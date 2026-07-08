import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from olp_gate import gate


RECEIPTS = "receipts/tool_call_receipts.jsonl"


def search_customer_records(query: str) -> dict:
    return {"matches": [{"customer_id": "cust_001", "name": "Example Customer"}], "query": query}


def clean_tool_call():
    with gate(
        action_type="tool_call",
        claim="Search customer records with approved query evidence.",
        evidence_required=True,
        receipt_path=RECEIPTS,
    ) as g:
        query = "customer_id:cust_001"
        result = search_customer_records(query)
        receipt = g.commit(result, evidence={"query_hash": "sha256:example-query", "user_intent_confirmed": True})
    return receipt


def missing_evidence_tool_call():
    with gate(
        action_type="tool_call",
        claim="Search customer records without evidence.",
        evidence_required=True,
        receipt_path=RECEIPTS,
    ) as g:
        result = search_customer_records("customer_id:cust_002")
        receipt = g.commit(result)
    return receipt


if __name__ == "__main__":
    Path(RECEIPTS).unlink(missing_ok=True)
    print("clean:", clean_tool_call()["decision"])
    print("missing_evidence:", missing_evidence_tool_call()["decision"])
    print("receipts:", RECEIPTS)
