import json
import unittest
from datetime import date
from pathlib import Path

from terrynce_early_warning.episode_lock import _add_months, _months_between

class EpisodeLockTests(unittest.TestCase):
    def test_month_arithmetic(self):
        self.assertEqual(_add_months(date(2020, 1, 1), 24), date(2022, 1, 1))
        self.assertEqual(_months_between(date(2020, 12, 1), date(2021, 2, 1)), 2)

    def test_holdout_labels_are_not_constructed_in_lock_stage(self):
        p = Path(__file__).parents[1] / "src/terrynce_early_warning/episode_lock.py"
        text = p.read_text()
        self.assertIn("Holdout labels are deliberately not constructed here", text)
        self.assertIn('"labels_constructed": False', text)

    def test_predictors_exclude_outcome_series(self):
        cfg = json.loads((Path(__file__).parents[1] / "config/science_lock.frozen.json").read_text())
        self.assertIn("TWSA_deseason_mov", cfg["quarantined_predictor_material"])
        self.assertEqual(cfg["predictors"]["twsa_observed_columns"], ["CSR", "GSFC", "JPL"])

if __name__ == "__main__":
    unittest.main()
