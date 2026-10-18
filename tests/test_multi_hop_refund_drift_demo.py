"""Contract tests for the public, completely simulated multi-hop replay."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import unittest


PATH = Path(__file__).resolve().parents[1] / "examples" / "multi_hop_refund_drift.py"
spec = importlib.util.spec_from_file_location("multi_hop_refund_drift", PATH)
module = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class MultiHopRefundDriftTests(unittest.TestCase):
    def test_baseline_and_bounded_receiver_comparison(self):
        report = module.run(otel=False, verbose=False)
        self.assertEqual(report["baseline_effects"], 1)
        self.assertEqual(report["guarded_payout_effects"], 0)
        self.assertEqual(report["payout_decision"], "DENY")
        self.assertEqual(report["over_cap_decision"], "DENY")
        self.assertEqual(report["positive_refund_effects"], 1)
        self.assertEqual(report["funds_transferred"], 0)
        self.assertIn(report["stale_state_decision"], ("DENY", "QUARANTINE"))

    def test_owner_signed_100_blocks_500_even_if_receiver_allows_500(self):
        report = module.run(
            otel=False, verbose=False,
            owner_cap_cents=10_000, receiver_cap_cents=50_000,
        )
        self.assertEqual(report["independent_cap_probe_decision"], "DENY")
        self.assertEqual(report["independent_cap_probe_reasons"],
                         ["owner_signed_limit_exceeded"])
        self.assertEqual(report["positive_refund_amount_cents"], 10_000)
        self.assertEqual(report["positive_refund_effects"], 1)
        self.assertEqual(report["guarded_payout_effects"], 0)

    def test_receiver_100_blocks_500_even_if_owner_signs_500(self):
        report = module.run(
            otel=False, verbose=False,
            owner_cap_cents=50_000, receiver_cap_cents=10_000,
        )
        self.assertEqual(report["independent_cap_probe_decision"], "DENY")
        self.assertEqual(report["independent_cap_probe_reasons"],
                         ["mandate:payment_limit_exceeded"])
        self.assertEqual(report["positive_refund_amount_cents"], 10_000)
        self.assertEqual(report["positive_refund_effects"], 1)
        self.assertEqual(report["guarded_payout_effects"], 0)

    def test_policy_has_both_route_and_amount_bound(self):
        p = module.receiver_policy()
        mandate = p["mandate"]
        self.assertEqual(mandate["max_payment_cents"], 50000)
        self.assertEqual(mandate["allowed_targets"], ["refund://ticket/8842"])
        self.assertEqual(p["permission_policy"]["routes"][0]["target"],
                         "refund://ticket/8842")


if __name__ == "__main__":
    unittest.main()
