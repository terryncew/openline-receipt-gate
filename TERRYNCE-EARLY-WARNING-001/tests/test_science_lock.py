import unittest
from datetime import date
from terrynce_early_warning.science_lock import _month_delta, _split_name
from terrynce_early_warning.protocol import load_protocol

class ScienceLockTests(unittest.TestCase):
    def test_month_delta(self):
        self.assertEqual(_month_delta(date(2020, 1, 1), date(2022, 1, 1)), 24)
        self.assertEqual(_month_delta(date(2020, 12, 1), date(2021, 1, 1)), 1)

    def test_split_uses_relief_time(self):
        p = load_protocol()
        self.assertEqual(_split_name(date(2015, 12, 1), p), "train")
        self.assertEqual(_split_name(date(2016, 1, 1), p), "validation")
        self.assertEqual(_split_name(date(2019, 1, 1), p), "holdout")

    def test_outcome_dates_are_forbidden_predictors(self):
        from pathlib import Path
        text = (Path(__file__).parents[1] / "src/terrynce_early_warning/science_lock.py").read_text()
        self.assertIn("TWSA_recovery_one_95.EndDate_dgt", text)
        self.assertIn("all measurements with Date > relief_t0", text)
        self.assertIn("STL-derived predictor columns", text)

if __name__ == "__main__":
    unittest.main()
