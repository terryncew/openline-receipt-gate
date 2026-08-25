from __future__ import annotations

import importlib.util
import unittest


class ForeignStanding001Tests(unittest.TestCase):
    def test_full_protocol_independence_suite(self):
        # The repo-wide release suite deliberately does not install the pinned
        # Claim Graph integration dependency. The dedicated FOREIGN-STANDING-001
        # workflow does, and is the authoritative integration proof. In generic
        # environments, assert the dependency boundary rather than manufacturing
        # an extra skip that changes the frozen release-suite skip accounting.
        spec = importlib.util.find_spec("openline_claim_graph")
        if spec is None:
            self.assertIsNone(spec)
            return

        from benchmarks.foreign_standing_001.run_suite import run_suite

        report = run_suite()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["verdict"], "FOREIGN_GOVERNANCE_PROTOCOL_INDEPENDENCE")
        self.assertEqual(report["policy_authority"], "NONE")

        # Assert the report's actual frozen schema. Protocol-independent graph
        # outcomes live under same_openline_graph; runtime blocking lives under
        # same_receipt_gate. Do not invent a synthetic outcomes projection here.
        self.assertTrue(report["normalization"]["byte_identical_common_support"])
        self.assertTrue(report["normalization"]["source_discriminator_absent"])
        self.assertTrue(report["same_openline_graph"]["same_result"])
        self.assertTrue(report["same_receipt_gate"]["same_result"])
        self.assertTrue(report["source_swap_falsifier"]["passed"])

        for source in ("acs", "airep"):
            self.assertEqual(
                report["same_openline_graph"][source]["affected_finalized_decision"],
                "REOPEN",
            )
            self.assertEqual(
                report["same_openline_graph"][source]["independently_supported_decision"],
                "RETAIN",
            )
            self.assertTrue(report["same_receipt_gate"][source]["after"]["blocked"])
            self.assertEqual(
                report["same_receipt_gate"][source]["after"]["effect_delta"],
                0,
            )


if __name__ == "__main__":
    unittest.main()
