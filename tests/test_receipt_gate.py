from pathlib import Path

from olp_gate import gate
from olp_gate.receipts import verify_chain, summarize_badge, review_packet, load_receipts


def test_clean_tool_call_commits(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    with gate(action_type="tool_call", claim="Search records", evidence_required=True, receipt_path=str(path)) as g:
        receipt = g.commit({"ok": True}, evidence={"query_hash": "abc"})

    assert receipt["decision"] == "COMMIT"
    assert receipt["status"] == "committed"
    assert "evidence" not in receipt["metadata"]
    assert receipt["metadata"]["evidence_keys"] == ["query_hash"]
    assert verify_chain(path)["valid"] is True
    assert summarize_badge(path)["badge"] == "PASS"


def test_missing_evidence_quarantines(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    with gate(action_type="tool_call", claim="Search records", evidence_required=True, receipt_path=str(path)) as g:
        receipt = g.commit({"ok": True})

    assert receipt["decision"] == "QUARANTINE"
    assert "missing_evidence_hash" in receipt["policy_flags"]
    assert summarize_badge(path)["badge"] == "REVIEW"


def test_memory_write_requires_user_intent(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    with gate(
        action_type="memory_write",
        claim="Write memory",
        evidence_required=True,
        user_intent_required=True,
        receipt_path=str(path),
    ) as g:
        receipt = g.commit({"written": True}, evidence={"source": "model_inference"})

    assert receipt["decision"] == "QUARANTINE"
    assert "missing_user_intent" in receipt["policy_flags"]


def test_eval_score_requires_grader_receipt(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    with gate(
        action_type="eval_score_claim",
        claim="Publish score",
        evidence_required=True,
        grader_required=True,
        receipt_path=str(path),
    ) as g:
        receipt = g.commit({"score": 1.0}, evidence={"model_answer_hash": "abc"})

    assert receipt["decision"] == "QUARANTINE"
    assert "missing_grader_receipt" in receipt["policy_flags"]


def test_no_badge_when_context_exits_without_close(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    with gate(action_type="eval_score_claim", claim="Publish score", evidence_required=True, receipt_path=str(path)):
        pass

    receipt = load_receipts(path)[0]
    assert receipt["decision"] == "NO_BADGE"
    assert summarize_badge(path)["badge"] == "NO_BADGE"


def test_review_packet_lists_failures(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    with gate(action_type="tool_call", claim="Search records", evidence_required=True, receipt_path=str(path)) as g:
        g.commit({"ok": True})
    packet = review_packet(path)
    assert packet["badge"]["review_required"] is True
    assert len(packet["review_items"]) == 1


def test_chain_detects_tamper(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    with gate(action_type="tool_call", claim="Search records", evidence_required=True, receipt_path=str(path)) as g:
        g.commit({"ok": True}, evidence={"query_hash": "abc"})

    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("Search records", "Altered claim"), encoding="utf-8")
    assert verify_chain(path)["valid"] is False


def test_missing_receipt_file_does_not_pass(tmp_path: Path):
    path = tmp_path / "does_not_exist.jsonl"
    badge = summarize_badge(path)
    assert badge["badge"] == "NO_BADGE"
    assert badge["reason"] == "empty_or_missing_receipt_chain"
    assert badge["review_required"] is True


def test_empty_receipt_file_does_not_pass(tmp_path: Path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    badge = summarize_badge(path)
    assert badge["badge"] == "NO_BADGE"
    assert badge["reason"] == "empty_or_missing_receipt_chain"
    assert badge["review_required"] is True


def test_malformed_json_returns_invalid_chain(tmp_path: Path):
    path = tmp_path / "broken.jsonl"
    path.write_text('{"receipt_id": "abc"\n', encoding="utf-8")
    verify = verify_chain(path)
    badge = summarize_badge(path)

    assert verify["valid"] is False
    assert verify["errors"][0]["reason"] == "json_parse_error"
    assert verify["errors"][0]["line_number"] == 1
    assert badge["badge"] == "INVALID_CHAIN"


def test_raw_evidence_not_stored_unless_opt_in(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    with gate(action_type="tool_call", claim="Search", evidence_required=True, receipt_path=str(path)) as g:
        receipt = g.commit({"ok": True}, evidence={"secret_query": "customer ssn 123"})

    assert "evidence" not in receipt["metadata"]
    assert receipt["metadata"]["evidence_keys"] == ["secret_query"]

    opt_in_path = tmp_path / "raw.jsonl"
    with gate(
        action_type="tool_call",
        claim="Search",
        evidence_required=True,
        store_raw_evidence=True,
        receipt_path=str(opt_in_path),
    ) as g:
        raw_receipt = g.commit({"ok": True}, evidence={"secret_query": "customer ssn 123"})

    assert raw_receipt["metadata"]["raw_evidence_stored"] is True
    assert raw_receipt["metadata"]["evidence"]["secret_query"] == "customer ssn 123"


def test_exception_receipt_does_not_store_traceback_by_default(tmp_path: Path):
    path = tmp_path / "receipts.jsonl"
    try:
        with gate(action_type="tool_call", claim="Explode", receipt_path=str(path)):
            raise RuntimeError("boom")
    except RuntimeError:
        pass

    receipt = load_receipts(path)[0]
    assert receipt["decision"] == "QUARANTINE"
    assert receipt["metadata"]["exception_type"] == "RuntimeError"
    assert receipt["metadata"]["exception_message"] == "boom"
    assert "traceback" not in receipt["metadata"]
