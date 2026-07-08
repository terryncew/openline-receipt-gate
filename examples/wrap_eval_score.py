import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from olp_gate import gate


RECEIPTS = "receipts/eval_score_receipts.jsonl"


def publish_score(score: float) -> dict:
    return {"benchmark": "toy_eval", "score": score}


def supported_eval_score():
    with gate(
        action_type="eval_score_claim",
        claim="Publish eval score with grader receipt.",
        evidence_required=True,
        grader_required=True,
        receipt_path=RECEIPTS,
    ) as g:
        result = publish_score(1.0)
        receipt = g.commit(
            result,
            evidence={
                "task_set_hash": "sha256:task-set",
                "model_answer_hash": "sha256:model-answer",
                "grader_receipt_hash": "sha256:grader-receipt",
            },
        )
    return receipt


def missing_grader_eval_score():
    with gate(
        action_type="eval_score_claim",
        claim="Publish eval score without grader receipt.",
        evidence_required=True,
        grader_required=True,
        receipt_path=RECEIPTS,
    ) as g:
        result = publish_score(1.0)
        receipt = g.commit(
            result,
            evidence={
                "task_set_hash": "sha256:task-set",
                "model_answer_hash": "sha256:model-answer",
            },
        )
    return receipt


def no_chain_eval_score():
    with gate(
        action_type="eval_score_claim",
        claim="Publish eval score with no chain.",
        evidence_required=True,
        grader_required=True,
        receipt_path=RECEIPTS,
    ) as g:
        receipt = g.no_badge(reason="no_prompt_answer_grader_chain")
    return receipt


if __name__ == "__main__":
    Path(RECEIPTS).unlink(missing_ok=True)
    print("supported:", supported_eval_score()["decision"])
    print("missing_grader:", missing_grader_eval_score()["decision"])
    print("no_chain:", no_chain_eval_score()["decision"])
    print("receipts:", RECEIPTS)
