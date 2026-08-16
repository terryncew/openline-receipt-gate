from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "x402_upstream_consequence" / "results"


class PinnedX402UpstreamConsequenceTests(unittest.TestCase):
    def test_checked_in_comparison_records_the_decisive_matched_outcome(self) -> None:
        report = json.loads(
            (RESULTS / "comparison.json").read_text(encoding="utf-8")
        )
        observations = report["observations"]
        self.assertTrue(report["passed"])
        self.assertTrue(
            observations["native_settlement_failure"]["returned_error"]
        )
        self.assertEqual(
            observations["native_settlement_failure"][
                "durable_tool_effect_count"
            ],
            1,
        )
        self.assertEqual(
            observations["airlock_settlement_failure"][
                "protected_release_calls"
            ],
            0,
        )
        self.assertFalse(
            observations["airlock_settlement_failure"][
                "protected_effect_exists"
            ]
        )
        self.assertTrue(
            observations["airlock_success_control"]["resource_released"]
        )

    def test_checked_in_effect_bytes_match_the_reported_boundary(self) -> None:
        effects = RESULTS / "effects"
        self.assertEqual(
            (effects / "native-failed-settlement.log").read_bytes(),
            b"native tool effect before failed settlement\n",
        )
        self.assertEqual(
            (effects / "native-success.log").read_bytes(),
            b"native tool effect before successful settlement\n",
        )
        self.assertEqual(
            (effects / "airlock-success.log").read_bytes(),
            b"airlock release after confirmed settlement\n",
        )
        self.assertFalse((effects / "airlock-failed-settlement.log").exists())


if __name__ == "__main__":
    unittest.main()

