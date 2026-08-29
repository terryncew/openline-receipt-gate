import json
import unittest
from pathlib import Path

from terrynce_early_warning.calibration import _failure_warning_threshold

class WarningSemanticsTests(unittest.TestCase):
    def test_high_failure_risk_warns(self):
        # Recovery labels/probabilities: first four recover, last two fail.
        y = [1, 1, 1, 1, 0, 0]
        p = [0.95, 0.90, 0.80, 0.70, 0.20, 0.10]
        t = _failure_warning_threshold(y, p, 0.10)
        risk = [1-x for x in p]
        warnings = [int(x >= t["threshold"]) for x in risk]
        self.assertEqual(warnings[-2:], [1, 1])
        self.assertEqual(sum(warnings[:4]), 0)
        self.assertEqual(t["positive_class"], "non_recovery_within_24m")

    def test_amendment_pins_existing_probability_hash(self):
        p = json.loads((Path(__file__).parents[1] / "config/pre_holdout_warning_amendment.json").read_text())
        self.assertFalse(p["holdout_labels_opened_before_amendment"])
        self.assertEqual(
            p["source_probability_only_sha256"],
            "a1d69a63fb2835da5f40550aaea03fd533f6bfc08f5f6ca2d1cc3a10a0e5b473"
        )
        self.assertEqual(p["frozen_model_change"], "NONE")
        self.assertEqual(p["frozen_probability_change"], "NONE")

    def test_calibration_warnings_use_one_minus_probability(self):
        text = (Path(__file__).parents[1] / "src/terrynce_early_warning/calibration.py").read_text()
        self.assertIn('row[f"{name}_failure_risk"] = 1.0 - pr', text)
        self.assertIn('int((1.0 - pr) >= thresholds[name]["threshold"])', text)

if __name__ == "__main__":
    unittest.main()
