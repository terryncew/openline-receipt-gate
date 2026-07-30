from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import verify_olp_signature
from olp_gate.handoff import (
    HandoffCheckError,
    inspect_handoff,
    load_history,
    restore_items,
    write_handoff_outputs,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "handoff" / "generic-history.jsonl"


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(item, separators=(",", ":")) + "\n" for item in records), encoding="utf-8")


def _safe_records() -> list[dict]:
    return [
        {
            "event_id": "e1",
            "actor": "tool",
            "semantic": {
                "kind": "evidence",
                "item_id": "E1",
                "key": "E1",
                "statement": "The server-side authentication test passed.",
                "status": "active",
                "evidence_ids": [],
                "relevant_actions": ["authentication refactor"],
            },
        },
        {
            "event_id": "e2",
            "actor": "assistant",
            "semantic": {
                "kind": "decision",
                "item_id": "D1",
                "key": "auth.validation.location",
                "statement": "Keep authentication validation server-side.",
                "status": "active",
                "evidence_ids": ["E1"],
                "relevant_actions": ["authentication refactor"],
            },
        },
        {
            "event_id": "e3",
            "actor": "user",
            "semantic": {
                "kind": "constraint",
                "item_id": "C1",
                "key": "api.compatibility",
                "statement": "Do not change the public authentication API.",
                "status": "active",
                "evidence_ids": [],
                "relevant_actions": [],
            },
        },
    ]


class HandoffCheckTests(unittest.TestCase):
    def test_generic_explicit_history_is_safe_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "handoff"
            result = write_handoff_outputs(
                EXAMPLE,
                out,
                next_action="Implement the authentication refactor",
                source="auto",
            )
            self.assertEqual(result["disposition"], "SAFE_TO_CONTINUE")
            self.assertEqual(result["source"], "generic")
            self.assertGreaterEqual(result["metrics"]["repeated_reads_or_searches_observed"], 1)
            self.assertTrue((out / "capsule.json").is_file())
            self.assertTrue((out / "proof-card.html").is_file())
            report = json.loads((out / "handoff_report.json").read_text())
            self.assertIn("cannot approve itself", report["boundary"])

    def test_plain_history_never_gets_promoted_into_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "plain.jsonl"
            _write_jsonl(
                history,
                [
                    {"role": "user", "content": "Please refactor authentication."},
                    {"role": "assistant", "content": "I think we should keep validation server-side."},
                ],
            )
            result = write_handoff_outputs(
                history,
                Path(tmp) / "out",
                next_action="Continue the authentication refactor",
                source="generic",
            )
            self.assertEqual(result["disposition"], "EVIDENCE_MISSING")
            report = json.loads((Path(tmp) / "out" / "handoff_report.json").read_text())
            self.assertTrue(any(item.get("reason") == "no_explicit_decision_evidence_in_history" for item in report["evidence_missing"]))

    def test_missing_evidence_reference_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            records = _safe_records()
            records[1]["semantic"]["evidence_ids"] = ["E404"]
            _write_jsonl(history, records)
            result = write_handoff_outputs(
                history,
                Path(tmp) / "out",
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(result["disposition"], "EVIDENCE_MISSING")

    def test_stale_capsule_reports_decision_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            old = tmp_path / "old.jsonl"
            new = tmp_path / "new.jsonl"
            records = _safe_records()
            _write_jsonl(old, records)
            out = tmp_path / "handoff"
            first = write_handoff_outputs(
                old,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(first["disposition"], "SAFE_TO_CONTINUE")
            changed = list(records)
            changed.extend(
                [
                    {
                        "event_id": "e4",
                        "semantic": {
                            "kind": "evidence",
                            "item_id": "E2",
                            "key": "E2",
                            "statement": "The new client-side validation test passed.",
                            "status": "active",
                            "evidence_ids": [],
                            "relevant_actions": ["authentication refactor"],
                        },
                    },
                    {
                        "event_id": "e5",
                        "semantic": {
                            "kind": "decision",
                            "item_id": "D1",
                            "key": "auth.validation.location",
                            "statement": "Move authentication validation client-side.",
                            "status": "active",
                            "evidence_ids": ["E2"],
                            "relevant_actions": ["authentication refactor"],
                        },
                    },
                ]
            )
            _write_jsonl(new, changed)
            inspected = inspect_handoff(
                new,
                out / "capsule.json",
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(inspected["disposition"], "DECISION_CHANGED")
            self.assertEqual(inspected["decision_changes"][0]["key"], "auth.validation.location")

    def test_history_parse_error_is_undecidable_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "bad.jsonl"
            history.write_text('{"event_id":"e1","semantic":{"kind":"evidence"}}\n{"broken":\n', encoding="utf-8")
            result = write_handoff_outputs(
                history,
                Path(tmp) / "out",
                next_action="continue",
                source="generic",
            )
            self.assertEqual(result["disposition"], "UNDECIDABLE")

    def test_unsafe_semantic_control_character_is_undecidable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "bad.jsonl"
            records = _safe_records()
            records[1]["semantic"]["statement"] = "Keep server-side.\u202eexe"
            _write_jsonl(history, records)
            result = write_handoff_outputs(
                history,
                Path(tmp) / "out",
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(result["disposition"], "UNDECIDABLE")


    def test_semantic_reference_lists_reject_unsafe_control_characters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "bad-list.jsonl"
            records = _safe_records()
            records[1]["semantic"]["evidence_ids"] = ["E1\u202e"]
            _write_jsonl(history, records)
            result = write_handoff_outputs(
                history,
                Path(tmp) / "out",
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(result["disposition"], "UNDECIDABLE")

    def test_tampered_operational_state_cannot_reapprove_itself(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out = tmp_path / "handoff"
            write_handoff_outputs(
                EXAMPLE,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            capsule_path = out / "capsule.json"
            capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
            capsule["operational_state"].append(
                {
                    "kind": "test",
                    "tool": "shell",
                    "target": "invented-test --passed",
                    "event_id": "forged",
                    "sequence": 999,
                    "content_sha256": "0" * 64,
                }
            )
            from olp_gate.handoff.core import _json_hash
            capsule["capsule_sha256"] = _json_hash(
                {key: value for key, value in capsule.items() if key != "capsule_sha256"}
            )
            capsule_path.write_text(json.dumps(capsule), encoding="utf-8")
            inspected = inspect_handoff(
                EXAMPLE,
                capsule_path,
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(inspected["disposition"], "UNDECIDABLE")
            self.assertIn("operational_state_mismatch", inspected["blockers"])

    def test_claude_code_adapter_reads_tool_blocks_and_semantic_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "claude.jsonl"
            records = [
                {
                    "type": "assistant",
                    "uuid": "a1",
                    "sessionId": "s1",
                    "message": {
                        "content": [
                            {"type": "text", "text": "OLP_EVIDENCE[E1]: Tests passed || action=authentication"},
                            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "src/auth.py"}},
                        ]
                    },
                },
                {
                    "type": "assistant",
                    "uuid": "a2",
                    "sessionId": "s1",
                    "message": {"content": [{"type": "text", "text": "OLP_DECISION[auth.validation]: Keep validation server-side || evidence=E1;action=authentication"}]},
                },
            ]
            _write_jsonl(history, records)
            loaded = load_history(history)
            self.assertEqual(loaded["source"], "claude-code")
            self.assertTrue(any(event["kind"] == "read" for event in loaded["events"]))
            result = write_handoff_outputs(history, Path(tmp) / "out", next_action="authentication changes")
            self.assertEqual(result["disposition"], "SAFE_TO_CONTINUE")

    def test_codex_adapter_reads_rollout_items_and_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "rollout.jsonl"
            records = [
                {"type": "session_meta", "payload": {"id": "s1"}},
                {"type": "event_msg", "payload": {"type": "agent_message", "message": "OLP_EVIDENCE[E1]: Tests passed || action=authentication"}},
                {"type": "response_item", "payload": {"type": "function_call", "call_id": "c1", "name": "read_file", "arguments": "{\"path\":\"src/auth.py\"}"}},
                {"type": "event_msg", "payload": {"type": "agent_message", "message": "OLP_DECISION[auth.validation]: Keep validation server-side || evidence=E1;action=authentication"}},
                {"type": "event_msg", "payload": {"type": "context_compacted"}},
            ]
            _write_jsonl(history, records)
            loaded = load_history(history)
            self.assertEqual(loaded["source"], "codex")
            self.assertTrue(any(event["kind"] == "read" for event in loaded["events"]))
            self.assertTrue(any(event["kind"] == "compaction" for event in loaded["events"]))
            result = write_handoff_outputs(history, Path(tmp) / "out", next_action="authentication changes")
            self.assertEqual(result["disposition"], "SAFE_TO_CONTINUE")

    def test_proof_card_html_escapes_next_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            write_handoff_outputs(
                EXAMPLE,
                out,
                next_action='<script>alert("x")</script> authentication refactor',
                source="generic",
            )
            card = (out / "proof-card.html").read_text(encoding="utf-8")
            self.assertNotIn('<script>alert("x")</script>', card)
            self.assertIn("&lt;script&gt;", card)

    def test_optional_receipt_signature_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            key = Ed25519PrivateKey.generate()
            result = write_handoff_outputs(
                EXAMPLE,
                out,
                next_action="authentication refactor",
                source="generic",
                signing_key=key,
            )
            self.assertEqual(result["disposition"], "SAFE_TO_CONTINUE")
            receipt = json.loads((out / "continuation_receipt.json").read_text())
            self.assertEqual(receipt["proof_mode"], "SIGNED_ED25519")
            valid, error = verify_olp_signature(receipt)
            self.assertTrue(valid, error)

    def test_restore_returns_only_indexed_canonical_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            write_handoff_outputs(
                EXAMPLE,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            restored = restore_items(out, EXAMPLE, ["D1"], source="generic")
            self.assertEqual(restored["missing_item_ids"], [])
            self.assertEqual(restored["restored_event_count"], 1)
            semantic = restored["events"][0]["attributes"]["semantic"]
            self.assertEqual(semantic["kind"], "decision")

    def test_restore_rejects_wrong_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out = tmp_path / "out"
            write_handoff_outputs(EXAMPLE, out, next_action="authentication refactor", source="generic")
            wrong = tmp_path / "wrong.jsonl"
            _write_jsonl(wrong, _safe_records())
            with self.assertRaisesRegex(HandoffCheckError, "restore_history_hash_mismatch"):
                restore_items(out, wrong, ["D1"], source="generic")

    def test_restore_rejects_text_and_duplicate_item_collections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            write_handoff_outputs(
                EXAMPLE,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            for malformed in ("D1", ["D1", "D1"]):
                with self.subTest(malformed=malformed):
                    with self.assertRaisesRegex(
                        HandoffCheckError,
                        "restore_item_ids_invalid",
                    ):
                        restore_items(
                            out,
                            EXAMPLE,
                            malformed,
                            source="generic",
                        )

    def test_cli_one_command_writes_shareable_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "handoff"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "olp_gate.command",
                    "handoff-check",
                    str(EXAMPLE),
                    "--next",
                    "authentication refactor",
                    "--source",
                    "generic",
                    "--output",
                    str(out),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads(completed.stdout)
            self.assertEqual(summary["disposition"], "SAFE_TO_CONTINUE")
            expected = {
                "capsule.json",
                "capsule.md",
                "reference_replay.json",
                "archive_index.json",
                "handoff_report.json",
                "proof-card.html",
                "continuation_receipt.json",
            }
            self.assertTrue(expected.issubset({path.name for path in out.iterdir()}))

    def test_receiver_must_pin_the_next_action_during_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            write_handoff_outputs(
                EXAMPLE,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            unpinned = inspect_handoff(
                EXAMPLE,
                out / "capsule.json",
                source="generic",
            )
            self.assertEqual(unpinned["disposition"], "UNDECIDABLE")
            self.assertIn(
                "next_action_not_receiver_pinned",
                unpinned["blockers"],
            )
            wrong = inspect_handoff(
                EXAMPLE,
                out / "capsule.json",
                next_action="payments rollout",
                source="generic",
            )
            self.assertEqual(wrong["disposition"], "UNDECIDABLE")
            self.assertIn(
                "next_action_changed_since_capsule",
                wrong["blockers"],
            )

    def test_capsule_semantic_scope_status_and_provenance_are_compared(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            write_handoff_outputs(
                EXAMPLE,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            capsule_path = out / "capsule.json"
            capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
            capsule["semantic_state"][0]["source_event_ids"] = ["forged"]
            capsule["semantic_state"][0]["relevant_actions"] = ["payments"]
            capsule["semantic_state"][0]["status"] = "superseded"
            from olp_gate.handoff.core import _json_hash
            capsule["capsule_sha256"] = _json_hash(
                {
                    key: value
                    for key, value in capsule.items()
                    if key != "capsule_sha256"
                }
            )
            capsule_path.write_text(json.dumps(capsule), encoding="utf-8")
            inspected = inspect_handoff(
                EXAMPLE,
                capsule_path,
                next_action="authentication refactor",
                source="generic",
            )
            self.assertNotEqual(
                inspected["disposition"],
                "SAFE_TO_CONTINUE",
            )

    def test_repo_binding_hashes_changed_tracked_and_untracked_bytes(self) -> None:
        from olp_gate.handoff.core import _repo_state

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.test"],
                cwd=repo,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test"],
                cwd=repo,
                check=True,
            )
            tracked = repo / "tracked.txt"
            tracked.write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
            tracked.write_text("first\n", encoding="utf-8")
            first = _repo_state(repo)
            tracked.write_text("second\n", encoding="utf-8")
            second = _repo_state(repo)
            self.assertNotEqual(
                first["worktree_sha256"],
                second["worktree_sha256"],
            )
            untracked = repo / "new.txt"
            untracked.write_text("one\n", encoding="utf-8")
            third = _repo_state(repo)
            untracked.write_text("two\n", encoding="utf-8")
            fourth = _repo_state(repo)
            self.assertNotEqual(
                third["worktree_sha256"],
                fourth["worktree_sha256"],
            )

    def test_repo_change_during_check_is_undecidable(self) -> None:
        before = {
            "status": "BOUND",
            "path": "/repo",
            "head": "1" * 40,
            "worktree_sha256": "2" * 64,
        }
        after = {
            **before,
            "worktree_sha256": "3" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "olp_gate.handoff.core._repo_state",
                side_effect=[before, after],
            ):
                result = write_handoff_outputs(
                    EXAMPLE,
                    Path(tmp) / "out",
                    next_action="authentication refactor",
                    source="generic",
                    repo="/repo",
                )
            self.assertEqual(result["disposition"], "UNDECIDABLE")

    def test_restore_rederives_and_rejects_a_tampered_archive_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            write_handoff_outputs(
                EXAMPLE,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            archive_path = out / "archive_index.json"
            archive = json.loads(archive_path.read_text(encoding="utf-8"))
            archive["items"]["D1"]["event_ids"] = ["e1"]
            archive_path.write_text(json.dumps(archive), encoding="utf-8")
            with self.assertRaisesRegex(
                HandoffCheckError,
                "archive_index_mismatch",
            ):
                restore_items(
                    out,
                    EXAMPLE,
                    ["D1"],
                    source="generic",
                )

    def test_archive_indexes_explicit_state_left_outside_the_capsule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            records = _safe_records()
            records.append(
                {
                    "event_id": "e4",
                    "semantic": {
                        "kind": "evidence",
                        "item_id": "E-payments",
                        "key": "E-payments",
                        "statement": "Payment fixture passed.",
                        "status": "active",
                        "evidence_ids": [],
                        "relevant_actions": ["payments"],
                    },
                }
            )
            _write_jsonl(history, records)
            out = Path(tmp) / "out"
            result = write_handoff_outputs(
                history,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(result["disposition"], "SAFE_TO_CONTINUE")
            capsule = json.loads((out / "capsule.json").read_text())
            self.assertNotIn(
                "E-payments",
                {
                    item["item_id"]
                    for item in capsule["semantic_state"]
                },
            )
            restored = restore_items(
                out,
                history,
                ["E-payments"],
                source="generic",
            )
            self.assertEqual(restored["missing_item_ids"], [])
            self.assertEqual(restored["restored_event_count"], 1)

    def test_cross_action_evidence_does_not_support_a_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            records = _safe_records()
            records[0]["semantic"]["relevant_actions"] = [
                "payments refactor"
            ]
            _write_jsonl(history, records)
            out = Path(tmp) / "out"
            result = write_handoff_outputs(
                history,
                out,
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(result["disposition"], "EVIDENCE_MISSING")
            report = json.loads((out / "handoff_report.json").read_text())
            self.assertTrue(
                any(
                    item.get("incompatible_evidence_ids") == ["E1"]
                    for item in report["evidence_missing"]
                )
            )

    def test_every_oversized_unparsed_record_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            normal = "".join(
                json.dumps(item, separators=(",", ":")) + "\n"
                for item in _safe_records()
            )
            hidden = {
                "type": "image_generation_end",
                "padding": "x" * (8 * 1024 * 1024),
                "semantic": {
                    "kind": "decision",
                    "item_id": "D1",
                    "key": "auth.validation.location",
                    "statement": "Move authentication validation client-side.",
                    "status": "active",
                    "evidence_ids": ["E1"],
                    "relevant_actions": ["authentication refactor"],
                },
            }
            history.write_text(
                normal + json.dumps(hidden, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            result = write_handoff_outputs(
                history,
                Path(tmp) / "out",
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(result["disposition"], "UNDECIDABLE")

    def test_duplicate_canonical_event_ids_are_undecidable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.jsonl"
            records = _safe_records()
            records[1]["event_id"] = records[0]["event_id"]
            _write_jsonl(history, records)
            result = write_handoff_outputs(
                history,
                Path(tmp) / "out",
                next_action="authentication refactor",
                source="generic",
            )
            self.assertEqual(result["disposition"], "UNDECIDABLE")

    def test_capsule_extractor_defect_cannot_grade_itself(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "olp_gate.handoff.core._extract_capsule_state",
                return_value=[],
            ):
                result = write_handoff_outputs(
                    EXAMPLE,
                    Path(tmp) / "out",
                    next_action="authentication refactor",
                    source="generic",
                )
            self.assertEqual(result["disposition"], "EVIDENCE_MISSING")

    def test_json_shape_fuzz_never_leaks_raw_exception(self) -> None:
        malformed_semantics = [
            None,
            False,
            1,
            "decision",
            [],
            {"kind": "decision"},
            {"kind": [], "statement": "x"},
            {"kind": "decision", "statement": []},
            {"kind": "decision", "statement": "x", "evidence_ids": "E1"},
            {"kind": "decision", "statement": "x", "relevant_actions": [1]},
            {"kind": "decision", "statement": "x", "unknown": True},
        ]
        leaks: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            for index, semantic in enumerate(malformed_semantics):
                history = Path(tmp) / f"fuzz-{index}.jsonl"
                _write_jsonl(history, [{"event_id": "e1", "semantic": semantic}])
                try:
                    write_handoff_outputs(history, Path(tmp) / f"out-{index}", next_action="continue", source="generic")
                except (HandoffCheckError, ValueError):
                    pass
                except Exception as exc:  # pragma: no cover - asserted empty
                    leaks.append(f"{index}:{type(exc).__name__}:{exc}")
        self.assertEqual(leaks, [])


if __name__ == "__main__":
    unittest.main()
