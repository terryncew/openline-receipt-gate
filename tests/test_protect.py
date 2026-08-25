from __future__ import annotations

import json
import py_compile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

from olp_gate.protect import (
    PACKS,
    ProtectError,
    RefundProtectionConfig,
    SendMessageProtectionConfig,
    build_refund_policy,
    build_send_message_policy,
    main,
    parse_money_to_cents,
    write_refund_starter,
    write_send_message_starter,
)


def future_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=365)).isoformat().replace("+00:00", "Z")


def refund_config() -> RefundProtectionConfig:
    return RefundProtectionConfig(
        owner="merchant-001",
        autonomous_limit_cents=10_000,
        hard_limit_cents=100_000,
        approval_max_age_seconds=300,
        authorization_ttl_seconds=120,
        expires_at=future_iso(),
    )


def message_config(*, mode: str = "exact-approval") -> SendMessageProtectionConfig:
    return SendMessageProtectionConfig(
        owner="principal-001",
        allowed_recipients=("alice@example.com",),
        content_mode=mode,
        approval_max_age_seconds=300,
        authorization_ttl_seconds=120,
        expires_at=future_iso(),
    )


class ProtectTests(unittest.TestCase):
    def test_policy_pack_registry_exposes_two_distinct_actions(self):
        self.assertEqual(set(PACKS), {"refund", "send-message"})

    def test_money_parser_never_rounds_floats(self):
        self.assertEqual(parse_money_to_cents("$100.00"), 10_000)
        self.assertEqual(parse_money_to_cents("1,000.01"), 100_001)
        with self.assertRaisesRegex(ProtectError, "at_most_two_decimals"):
            parse_money_to_cents("1.001")

    def test_refund_policy_preserves_selected_limits_and_freshness(self):
        policy = build_refund_policy(refund_config())
        mandate = policy["mandate"]
        route = policy["permission_policy"]["routes"][0]
        self.assertEqual(mandate["principal_id"], "merchant-001")
        self.assertEqual(mandate["max_payment_cents"], 100_000)
        self.assertEqual(route["requirements"][0]["max_age_seconds"], 300)
        self.assertEqual(route["max_authorization_ttl_seconds"], 120)
        self.assertEqual(route["unknown_behavior"], "QUARANTINE")

    def test_refund_autonomy_cannot_exceed_hard_limit(self):
        config = RefundProtectionConfig(
            owner="merchant-001",
            autonomous_limit_cents=100_001,
            hard_limit_cents=100_000,
            approval_max_age_seconds=300,
            authorization_ttl_seconds=120,
            expires_at=future_iso(),
        )
        with self.assertRaisesRegex(ProtectError, "autonomous_limit_exceeds_hard_limit"):
            config.validate()

    def test_authorization_window_cannot_outlive_evidence(self):
        config = SendMessageProtectionConfig(
            owner="principal-001",
            allowed_recipients=(),
            content_mode="exact-approval",
            approval_max_age_seconds=60,
            authorization_ttl_seconds=120,
            expires_at=future_iso(),
        )
        with self.assertRaisesRegex(ProtectError, "authorization_ttl_exceeds_approval_freshness"):
            config.validate()

    def test_refund_starter_records_answers_and_fails_closed_high_value(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "refund"
            written = write_refund_starter(refund_config(), output)
            self.assertEqual(len(written), 5)
            answers = json.loads((output / "answers.json").read_text(encoding="utf-8"))
            self.assertEqual(answers["pack"], "refund")
            guard = (output / "refund_guard.py").read_text(encoding="utf-8")
            self.assertIn("def trusted_high_value_approval(call):", guard)
            self.assertIn("return None", guard)
            py_compile.compile(str(output / "refund_guard.py"), doraise=True)

    def test_message_policy_uses_send_and_explicit_disclosure(self):
        policy = build_send_message_policy(message_config())
        mandate = policy["mandate"]
        route = policy["permission_policy"]["routes"][0]
        self.assertEqual(mandate["allowed_action_types"], ["send"])
        self.assertEqual(mandate["allowed_disclosure_classes"], ["message_content"])
        self.assertEqual(mandate["max_payment_cents"], 0)
        self.assertEqual(route["requirements"][0]["requirement_id"], "message_authority")
        self.assertEqual(route["unknown_behavior"], "QUARANTINE")

    def test_autonomous_message_mode_requires_listed_recipient(self):
        config = SendMessageProtectionConfig(
            owner="principal-001",
            allowed_recipients=(),
            content_mode="autonomous-for-listed",
            approval_max_age_seconds=300,
            authorization_ttl_seconds=120,
            expires_at=future_iso(),
        )
        with self.assertRaisesRegex(ProtectError, "autonomous_content_requires_allowed_recipient"):
            config.validate()

    def test_message_starter_binds_lookup_to_recipient_and_body(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "message"
            written = write_send_message_starter(message_config(), output)
            self.assertEqual(len(written), 5)
            answers = json.loads((output / "answers.json").read_text(encoding="utf-8"))
            self.assertEqual(answers["pack"], "send-message")
            self.assertEqual(answers["content_mode"], "exact-approval")
            guard = (output / "message_guard.py").read_text(encoding="utf-8")
            self.assertIn('"recipient": recipient, "message": message', guard)
            self.assertIn("def trusted_exact_message_approval(call):", guard)
            self.assertIn("return None", guard)
            py_compile.compile(str(output / "message_guard.py"), doraise=True)

    def test_generated_message_policy_tests_pass(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "message"
            write_send_message_starter(message_config(), output)
            suite = unittest.defaultTestLoader.discover(str(output), pattern="test_*.py")
            result = unittest.TextTestRunner(stream=StringIO()).run(suite)
            self.assertTrue(result.wasSuccessful())

    def test_existing_starter_is_not_overwritten_without_force(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "refund"
            write_refund_starter(refund_config(), output)
            marker = output / "answers.json"
            before = marker.read_text(encoding="utf-8")
            with self.assertRaisesRegex(ProtectError, "output_exists"):
                write_refund_starter(refund_config(), output)
            self.assertEqual(marker.read_text(encoding="utf-8"), before)

    def test_noninteractive_refund_requires_all_consequential_values(self):
        out = StringIO()
        err = StringIO()
        code = main(
            [
                "refund",
                "--owner", "merchant-001",
                "--autonomous-limit", "100",
                "--hard-limit", "1000",
                "--expires-at", future_iso(),
                "--non-interactive",
                "--yes",
            ],
            out=out,
            err=err,
        )
        self.assertEqual(code, 2)
        self.assertIn("--approval-max-age", err.getvalue())
        self.assertIn("--authorization-ttl", err.getvalue())

    def test_noninteractive_message_requires_explicit_content_mode(self):
        out = StringIO()
        err = StringIO()
        code = main(
            [
                "send-message",
                "--owner", "principal-001",
                "--approval-max-age", "300",
                "--authorization-ttl", "120",
                "--expires-at", future_iso(),
                "--non-interactive",
                "--yes",
            ],
            out=out,
            err=err,
        )
        self.assertEqual(code, 2)
        self.assertIn("--content-mode", err.getvalue())

    def test_noninteractive_message_generation(self):
        with tempfile.TemporaryDirectory() as root:
            out = StringIO()
            err = StringIO()
            output = Path(root) / "message"
            code = main(
                [
                    "send-message",
                    "--owner", "principal-001",
                    "--allowed-recipient", "alice@example.com",
                    "--content-mode", "autonomous-for-listed",
                    "--approval-max-age", "300",
                    "--authorization-ttl", "120",
                    "--expires-at", future_iso(),
                    "--output", str(output),
                    "--non-interactive",
                    "--yes",
                ],
                out=out,
                err=err,
            )
            self.assertEqual(code, 0, err.getvalue())
            self.assertTrue((output / "message_policy.json").exists())
            self.assertIn("Content mode:          autonomous-for-listed", out.getvalue())

    def test_exact_approval_mode_allows_empty_recipient_list(self):
        config = SendMessageProtectionConfig(
            owner="principal-001",
            allowed_recipients=(),
            content_mode="exact-approval",
            approval_max_age_seconds=300,
            authorization_ttl_seconds=120,
            expires_at=future_iso(),
        ).validate()
        self.assertEqual(config.allowed_recipients, ())


if __name__ == "__main__":
    unittest.main()
