import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from olp_gate import gate


RECEIPTS = "receipts/memory_write_receipts.jsonl"


def write_memory(key: str, value: str) -> dict:
    return {"key": key, "value": value, "written": True}


def allowed_memory_write():
    with gate(
        action_type="memory_write",
        claim="Write user preference after confirmed intent.",
        evidence_required=True,
        user_intent_required=True,
        receipt_path=RECEIPTS,
    ) as g:
        result = write_memory("preferred_report_style", "concise")
        receipt = g.commit(result, evidence={"user_intent_confirmed": True, "source": "explicit_user_request"})
    return receipt


def missing_intent_memory_write():
    with gate(
        action_type="memory_write",
        claim="Write user preference without confirmed intent.",
        evidence_required=True,
        user_intent_required=True,
        receipt_path=RECEIPTS,
    ) as g:
        result = write_memory("delete_old_files", "true")
        receipt = g.commit(result, evidence={"source": "model_inference"})
    return receipt


if __name__ == "__main__":
    Path(RECEIPTS).unlink(missing_ok=True)
    print("allowed:", allowed_memory_write()["decision"])
    print("missing_intent:", missing_intent_memory_write()["decision"])
    print("receipts:", RECEIPTS)
