import unittest
from terrynce_early_warning.margin import PreReliefState, recoverability_margin

class MarginTests(unittest.TestCase):
    def test_more_lag_reduces_margin_when_other_terms_fixed(self):
        a = PreReliefState(1.0, 0.05, 0.5, 2.0, 0.1)
        b = PreReliefState(1.0, 0.05, 0.5, 8.0, 0.1)
        self.assertGreater(recoverability_margin(a), recoverability_margin(b))

    def test_more_capacity_increases_margin(self):
        a = PreReliefState(1.0, 0.05, 0.5, 4.0, 0.03)
        b = PreReliefState(1.0, 0.05, 0.5, 4.0, 0.08)
        self.assertGreater(recoverability_margin(b), recoverability_margin(a))

if __name__ == "__main__":
    unittest.main()
