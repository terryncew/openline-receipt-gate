from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

from olp_gate.protect import (
    ProtectError,
    RefundProtectionConfig,
    build_refund_policy,
    main,
    parse_money_to_cents,
    write_refund_starter,
)


def future_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=365)).isoformat().replace("+00:00", "Z")


def sample_config() -> RefundProtectionConfig:
    return RefundProtectionConfig(
        owner="merchant-001",
        autonomous_limit_cents=10_000,
        hard_limit_cents=100_000,
        approval_max_age_seconds=300,
        authorization_ttl_seconds=120,
        expires_at=future_iso(),
    )


class ProtectTests(unittest.TestCase):
    def test_money_parser_never_rounds_floats(self):
        self.assertEqual(parse_money_to_cents("$100.00"), 10_000)
        self.assertEqual(parse_money_to_cents("1,000.01"), 100_001)
        with self.assertRaisesRegex(ProtectError, "at_most_two_decimals"):
            parse_money_to_cents("1.001")

    def test_policy_preserves_selected_principal_limits_and_freshness(self):
        config = sample_config()
        policy = build_refund_policy(config)
        mandate = policy["mandate"]
        route = policy["permission_policy"]["routes"][0]
        self.assertEqual(mandate["principal_id"], "merchant-001")
        self.assertEqual(mandate["max_payment_cents"], 100_000)
        self.assertEqual(route["requirements"][0]["max_age_seconds"], 300)
        self.assertEqual(route["max_authorization_ttl_seconds"], 120)
        self.assertEqual(route["unknown_behavior"], "QUARANTINE")

    def test_autonomous_limit_cannot_exceed_hard_limit(self):
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
        config = RefundProtectionConfig(
            owner="merchant-001",
            autonomous_limit_cents=10_000,
            hard_limit_cents=100_000,
            approval_max_age_seconds=60,
            authorization_ttl_seconds=120,
            expires_at=future_iso(),
        )
        with self.assertRaisesRegex(ProtectError, "authorization_ttl_exceeds_approval_freshness"):
            config.validate()

    def test_starter_records_answers_and_high_value_hook_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "refund"
            written = write_refund_starter(sample_config(), output)
            self.assertEqual(len(written), 5)
            answers = json.loads((output / "answers.json").read_text(encoding="utf-8"))
            self.assertEqual(answers["autonomous_limit_cents"], 10_000)
            self.assertEqual(answers["hard_limit_cents"], 100_000)
            guard = (output / "refund_guard.py").read_text(encoding="utf-8")
            self.assertIn("AUTONOMOUS_LIMIT_CENTS = 10000", guard)
            self.assertIn("def trusted_high_value_approval(call):", guard)
            self.assertIn("return None", guard)

    def test_existing_starter_is_not_overwritten_without_force(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "refund"
            write_refund_starter(sample_config(), output)
            marker = output / "answers.json"
            before = marker.read_text(encoding="utf-8")
            with self.assertRaisesRegex(ProtectError, "output_exists"):
                write_refund_starter(sample_config(), output)
            self.assertEqual(marker.read_text(encoding="utf-8"), before)

    def test_non_interactive_mode_requires_every_consequential_value(self):
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

    def test_non_interactive_generation(self):
        with tempfile.TemporaryDirectory() as root:
            out = StringIO()
            err = StringIO()
            code = main(
                [
                    "refund",
                    "--owner", "merchant-001",
                    "--autonomous-limit", "100",
                    "--hard-limit", "1000",
                    "--approval-max-age", "300",
                    "--authorization-ttl", "120",
                    "--expires-at", future_iso(),
                    "--output", str(Path(root) / "refund"),
                    "--non-interactive",
                    "--yes",
                ],
                out=out,
                err=err,
            )
            self.assertEqual(code, 0, err.getvalue())
            self.assertTrue((Path(root) / "refund" / "refund_policy.json").exists())
            self.assertIn("Acts for:              merchant-001", out.getvalue())


if __name__ == "__main__":
    unittest.main()
