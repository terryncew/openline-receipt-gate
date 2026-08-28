from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

EXP = Path(__file__).resolve().parents[1]
REPO = EXP.parents[1]
PIN = json.loads((EXP / "DEPENDENCY_PIN.json").read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ContractTests(unittest.TestCase):
    def test_six_named_schedules_are_frozen(self):
        prereg = json.loads((EXP / "preregistration.json").read_text())
        self.assertEqual(
            prereg["named_adversarial_schedules"],
            [
                "race_to_window",
                "split_brain_delivery",
                "successor_race",
                "cold_start_starvation",
                "duplicate_storm_replay",
                "cross_epoch_reorder",
            ],
        )

    def test_measurement_has_no_policy_authority(self):
        prereg = json.loads((EXP / "preregistration.json").read_text())
        self.assertEqual(prereg["authority"]["measurement_authority"], "NONE")
        source = (EXP / "wallet004" / "gate_runtime.py").read_text()
        self.assertNotIn("calibration", source.lower())

    def test_003_dependency_pin_when_base_repo_present(self):
        item = PIN["wallet_standing_003"]
        distribution = REPO / item["distribution_path"]
        public_surface = REPO / item["public_surface_path"]
        frozen = REPO / item["frozen_result_path"]
        manifest = REPO / item["release_manifest_path"]
        if not distribution.exists():
            self.skipTest("merged base checkout unavailable in overlay-only test environment")
        self.assertEqual(sha(distribution), item["distribution_sha256"])
        self.assertEqual(sha(public_surface), item["public_surface_sha256"])
        self.assertEqual(sha(frozen), item["frozen_result_sha256"])
        self.assertEqual(sha(manifest), item["release_manifest_sha256"])


if __name__ == "__main__":
    unittest.main()
