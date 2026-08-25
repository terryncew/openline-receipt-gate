from __future__ import annotations

import importlib.util
import unittest


@unittest.skipUnless(
    importlib.util.find_spec("openline_claim_graph") is not None,
    "FOREIGN-STANDING-001 requires the pinned openline-claim-graph integration dependency",
)
class ForeignStanding001Tests(unittest.TestCase):
    def test_full_protocol_independence_suite(self):
        from benchmarks.foreign_standing_001.run_suite import run_suite

        report = run_suite()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["verdict"], "FOREIGN_GOVERNANCE_PROTOCOL_INDEPENDENCE")
        self.assertEqual(report["policy_authority"], "NONE")
        self.assertTrue(report["source_swap_falsifier"]["normalized_support_byte_identical"])
        self.assertTrue(report["source_swap_falsifier"]["source_discriminator_absent"])
        self.assertTrue(report["source_swap_falsifier"]["same_claim_graph_result"])
        self.assertTrue(report["source_swap_falsifier"]["same_gate_result"])
        self.assertFalse(report["source_swap_falsifier"]["triggered"])
        self.assertEqual(report["outcomes"]["affected_finalized_decision"], "REOPEN")
        self.assertEqual(report["outcomes"]["independently_supported_decision"], "RETAIN")
        self.assertEqual(report["outcomes"]["next_dependent_action"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
