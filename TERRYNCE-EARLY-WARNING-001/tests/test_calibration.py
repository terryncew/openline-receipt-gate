import json
import math
import unittest
from pathlib import Path

from terrynce_early_warning.modeling import (
    fit_logistic, predict_logistic, brier, auroc, threshold_at_fpr
)
from terrynce_early_warning.calibration import _prior_summary, _rm_components

class CalibrationTests(unittest.TestCase):
    def test_logistic_learns_simple_separation(self):
        rows = [{"x": float(i), "y": int(i >= 5)} for i in range(10)]
        m = fit_logistic(rows, ["x"], "y", l2=0.1)
        p = predict_logistic(m, rows)
        self.assertLess(brier([r["y"] for r in rows], p), 0.20)
        self.assertGreater(auroc([r["y"] for r in rows], p), 0.95)

    def test_threshold_respects_fpr_budget(self):
        y = [0,0,0,0,1,1,1,1]
        p = [0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8]
        t = threshold_at_fpr(y, p, 0.10)
        self.assertLessEqual(t["validation_fpr"], 0.10 + 1e-12)

    def test_history_capacity_penalizes_failed_history(self):
        good = _prior_summary([
            {"lag": 2.0, "y": 1, "capacity": 0.5},
            {"lag": 4.0, "y": 1, "capacity": 0.5},
        ])
        mixed = _prior_summary([
            {"lag": 2.0, "y": 1, "capacity": 0.5},
            {"lag": 4.0, "y": 0, "capacity": None},
        ])
        self.assertGreater(
            good["historical_recovery_capacity_per_month"],
            mixed["historical_recovery_capacity_per_month"]
        )

    def test_rm_burden_uses_lag(self):
        r = {
            "state_deficit": 1.0,
            "adverse_momentum": 0.2,
            "duration_months": 6.0,
            "mean_p_drought": 0.5,
            "response_lag_months": 4.0,
            "historical_recovery_capacity_per_month": 0.1,
        }
        c = _rm_components(r)
        self.assertAlmostEqual(c["rm_momentum_burden_raw"], 0.8)
        self.assertAlmostEqual(c["rm_available_recovery_raw"], 2.0)

    def test_holdout_lock_is_prediction_only(self):
        text = (Path(__file__).parents[1] / "src/terrynce_early_warning/calibration.py").read_text()
        self.assertIn('"holdout_labels_constructed": False', text)
        self.assertIn("Freeze predictions before labels are ever constructed", text)

    def test_protocol_freezes_ten_percent_fpr(self):
        p = json.loads((Path(__file__).parents[1] / "config/calibration_protocol.frozen.json").read_text())
        self.assertEqual(p["validation"]["false_positive_budget"], 0.10)
        self.assertEqual(p["history"]["training_burn_in_episodes"], 20)

if __name__ == "__main__":
    unittest.main()
