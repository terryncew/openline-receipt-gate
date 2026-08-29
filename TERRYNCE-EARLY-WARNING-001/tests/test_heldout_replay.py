import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from terrynce_early_warning.heldout_replay import (
    _brier_delta, _cluster_bootstrap, _warning_metrics
)

class HeldoutReplayTests(unittest.TestCase):
    def test_brier_delta_positive_when_augmented_is_better(self):
        rows = [
            {"y": 1, "conventional_multivariable_probability": 0.6, "rm_augmented_conventional_probability": 0.8},
            {"y": 0, "conventional_multivariable_probability": 0.4, "rm_augmented_conventional_probability": 0.2},
        ]
        self.assertGreater(_brier_delta(rows), 0)

    def test_cluster_bootstrap_is_deterministic(self):
        rows = [
            {"ID": "1", "y": 1, "conventional_multivariable_probability": 0.6, "rm_augmented_conventional_probability": 0.8},
            {"ID": "1", "y": 0, "conventional_multivariable_probability": 0.4, "rm_augmented_conventional_probability": 0.2},
            {"ID": "2", "y": 1, "conventional_multivariable_probability": 0.7, "rm_augmented_conventional_probability": 0.75},
            {"ID": "2", "y": 0, "conventional_multivariable_probability": 0.3, "rm_augmented_conventional_probability": 0.25},
        ]
        a = _cluster_bootstrap(rows, 100, 7)
        b = _cluster_bootstrap(rows, 100, 7)
        self.assertEqual(a, b)

    def test_warning_positive_class_is_nonrecovery(self):
        # y=1 means recovery. Warn should detect y=0.
        m = _warning_metrics([1, 1, 0, 0], [0, 1, 1, 1])
        self.assertEqual(m["tp"], 2)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["fn"], 0)
        self.assertEqual(m["tn"], 1)

    def test_frozen_prediction_hash_is_pinned(self):
        root = Path(__file__).parents[1]
        proto = json.loads((root / "config/heldout_replay_protocol.frozen.json").read_text())
        p = root / "frozen/holdout_predictions.lock.csv"
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        self.assertEqual(got, proto["pinned_sha256"]["holdout_predictions"])

    def test_replay_source_does_not_call_calibrate(self):
        root = Path(__file__).parents[1]
        text = (root / "src/terrynce_early_warning/heldout_replay.py").read_text()
        self.assertNotIn("calibrate(", text)
        self.assertIn("Only now do we open the outcome-side data", text)

if __name__ == "__main__":
    unittest.main()
