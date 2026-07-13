from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from olp_gate import gate
from olp_gate.receipts import load_receipts, review_packet, summarize_badge, verify_chain


class LegacyReceiptGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def path(self, name: str = "receipts.jsonl") -> Path:
        return self.root / name

    def test_clean_tool_call_commits(self) -> None:
        path = self.path()
        with gate(action_type="tool_call", claim="Search records", evidence_required=True, receipt_path=str(path)) as g:
            receipt = g.commit({"ok": True}, evidence={"query_hash": "abc"})
        self.assertEqual(receipt["decision"], "COMMIT")
        self.assertEqual(receipt["status"], "committed")
        self.assertNotIn("evidence", receipt["metadata"])
        self.assertEqual(receipt["metadata"]["evidence_keys"], ["query_hash"])
        self.assertTrue(verify_chain(path)["valid"])
        self.assertEqual(summarize_badge(path)["badge"], "PASS")

    def test_missing_evidence_quarantines(self) -> None:
        path = self.path()
        with gate(action_type="tool_call", claim="Search records", evidence_required=True, receipt_path=str(path)) as g:
            receipt = g.commit({"ok": True})
        self.assertEqual(receipt["decision"], "QUARANTINE")
        self.assertIn("missing_evidence_hash", receipt["policy_flags"])
        self.assertEqual(summarize_badge(path)["badge"], "REVIEW")

    def test_memory_write_requires_user_intent(self) -> None:
        path = self.path()
        with gate(
            action_type="memory_write",
            claim="Write memory",
            evidence_required=True,
            user_intent_required=True,
            receipt_path=str(path),
        ) as g:
            receipt = g.commit({"written": True}, evidence={"source": "model_inference"})
        self.assertEqual(receipt["decision"], "QUARANTINE")
        self.assertIn("missing_user_intent", receipt["policy_flags"])

    def test_eval_score_requires_grader_receipt(self) -> None:
        path = self.path()
        with gate(
            action_type="eval_score_claim",
            claim="Publish score",
            evidence_required=True,
            grader_required=True,
            receipt_path=str(path),
        ) as g:
            receipt = g.commit({"score": 1}, evidence={"model_answer_hash": "abc"})
        self.assertEqual(receipt["decision"], "QUARANTINE")
        self.assertIn("missing_grader_receipt", receipt["policy_flags"])

    def test_no_badge_when_context_exits_without_close(self) -> None:
        path = self.path()
        with gate(action_type="eval_score_claim", claim="Publish score", evidence_required=True, receipt_path=str(path)):
            pass
        receipt = load_receipts(path)[0]
        self.assertEqual(receipt["decision"], "NO_BADGE")
        self.assertEqual(summarize_badge(path)["badge"], "NO_BADGE")

    def test_review_packet_lists_failures(self) -> None:
        path = self.path()
        with gate(action_type="tool_call", claim="Search records", evidence_required=True, receipt_path=str(path)) as g:
            g.commit({"ok": True})
        packet = review_packet(path)
        self.assertTrue(packet["badge"]["review_required"])
        self.assertEqual(len(packet["review_items"]), 1)

    def test_chain_detects_tamper(self) -> None:
        path = self.path()
        with gate(action_type="tool_call", claim="Search records", evidence_required=True, receipt_path=str(path)) as g:
            g.commit({"ok": True}, evidence={"query_hash": "abc"})
        path.write_text(path.read_text(encoding="utf-8").replace("Search records", "Altered claim"), encoding="utf-8")
        self.assertFalse(verify_chain(path)["valid"])

    def test_missing_or_empty_receipt_file_does_not_pass(self) -> None:
        missing = summarize_badge(self.path("missing.jsonl"))
        self.assertEqual(missing["badge"], "NO_BADGE")
        empty_path = self.path("empty.jsonl")
        empty_path.write_text("", encoding="utf-8")
        self.assertEqual(summarize_badge(empty_path)["badge"], "NO_BADGE")

    def test_malformed_json_returns_invalid_chain(self) -> None:
        path = self.path()
        path.write_text('{"receipt_id": "abc"\n', encoding="utf-8")
        verify = verify_chain(path)
        self.assertFalse(verify["valid"])
        self.assertEqual(verify["errors"][0]["reason"], "json_parse_error")
        self.assertEqual(summarize_badge(path)["badge"], "INVALID_CHAIN")

    def test_raw_evidence_not_stored_unless_opt_in(self) -> None:
        path = self.path()
        with gate(action_type="tool_call", claim="Search", evidence_required=True, receipt_path=str(path)) as g:
            receipt = g.commit({"ok": True}, evidence={"secret_query": "customer ssn 123"})
        self.assertNotIn("evidence", receipt["metadata"])
        opt_in = self.path("raw.jsonl")
        with gate(
            action_type="tool_call",
            claim="Search",
            evidence_required=True,
            store_raw_evidence=True,
            receipt_path=str(opt_in),
        ) as g:
            raw = g.commit({"ok": True}, evidence={"secret_query": "customer ssn 123"})
        self.assertEqual(raw["metadata"]["evidence"]["secret_query"], "customer ssn 123")

    def test_exception_receipt_does_not_store_traceback_by_default(self) -> None:
        path = self.path()
        with self.assertRaises(RuntimeError):
            with gate(action_type="tool_call", claim="Explode", receipt_path=str(path)):
                raise RuntimeError("boom")
        receipt = load_receipts(path)[0]
        self.assertEqual(receipt["decision"], "QUARANTINE")
        self.assertEqual(receipt["metadata"]["exception_type"], "RuntimeError")
        self.assertNotIn("traceback", receipt["metadata"])


if __name__ == "__main__":
    unittest.main()
