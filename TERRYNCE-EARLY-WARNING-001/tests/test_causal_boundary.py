import unittest
from pathlib import Path

class BoundaryTests(unittest.TestCase):
    def test_preflight_refuses_to_guess_science_mapping(self):
        p = Path(__file__).parents[1] / "src" / "terrynce_early_warning" / "preflight.py"
        text = p.read_text()
        self.assertIn('"science_lock_ready": False', text)
        self.assertIn("No holdout scoring", text)

    def test_margin_object_has_no_post_relief_outcome(self):
        p = Path(__file__).parents[1] / "src" / "terrynce_early_warning" / "margin.py"
        text = p.read_text().lower()
        self.assertNotIn("recovery_outcome", text)
        self.assertNotIn("post_relief", text)

if __name__ == "__main__":
    unittest.main()
