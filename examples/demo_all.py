import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import json

from wrap_tool_call import clean_tool_call, missing_evidence_tool_call
from wrap_memory_write import allowed_memory_write, missing_intent_memory_write
from wrap_eval_score import supported_eval_score, missing_grader_eval_score, no_chain_eval_score
from olp_gate.receipts import summarize_badge, verify_chain, review_packet


def main():
    Path("receipts").mkdir(exist_ok=True)
    for p in Path("receipts").glob("*_receipts.jsonl"):
        p.unlink()

    actions = {
        "clean_tool_call": clean_tool_call(),
        "missing_evidence_tool_call": missing_evidence_tool_call(),
        "allowed_memory_write": allowed_memory_write(),
        "missing_intent_memory_write": missing_intent_memory_write(),
        "supported_eval_score": supported_eval_score(),
        "missing_grader_eval_score": missing_grader_eval_score(),
        "no_chain_eval_score": no_chain_eval_score(),
    }

    summary = {}
    for path in [
        "receipts/tool_call_receipts.jsonl",
        "receipts/memory_write_receipts.jsonl",
        "receipts/eval_score_receipts.jsonl",
    ]:
        summary[path] = {
            "verify": verify_chain(path),
            "badge": summarize_badge(path),
            "review": review_packet(path),
        }

    Path("results").mkdir(exist_ok=True)
    Path("results/demo_all_summary.json").write_text(json.dumps({"actions": actions, "summary": summary}, indent=2), encoding="utf-8")
    print(json.dumps({"actions": {k: v["decision"] for k, v in actions.items()}, "summary": {k: v["badge"]["badge"] for k, v in summary.items()}}, indent=2))


if __name__ == "__main__":
    main()
