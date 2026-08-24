from __future__ import annotations

import importlib.util
import json
import math
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "benchmarks" / "trial_selector" / "external_001"

spec = importlib.util.spec_from_file_location(
    "external_selector", HERE / "external_selector.py"
)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def load_config():
    return json.loads((HERE / "CONFIG.json").read_text(encoding="utf-8"))


def synthetic_metric(mean_cost, false_reassurance, candidates=60, positive=30):
    return {
        "candidate_count": candidates,
        "liability_positive_count": positive,
        "liability_negative_count": candidates-positive,
        "mean_assays_to_first_liability_positive_only": mean_cost,
        "budgets": {
            str(b): {
                "positive_detected_count": 0,
                "positive_detected_fraction": 0.0,
                "survivor_count": candidates,
                "hidden_liability_count": positive,
                "false_reassurance_fraction": false_reassurance,
            }
            for b in (1,2,3,4,5)
        },
    }


def synthetic_random_metric(mean_cost, false_reassurance, candidates=60, positive=30):
    return {
        "candidate_count": candidates,
        "liability_positive_count": positive,
        "liability_negative_count": candidates-positive,
        "mean_assays_to_first_liability_positive_only": mean_cost,
        "budgets": {
            str(b): {
                "expected_positive_detected_count": 0.0,
                "expected_positive_detected_fraction": 0.0,
                "expected_survivor_count": float(candidates),
                "expected_hidden_liability_count": float(positive),
                "expected_false_reassurance_fraction": false_reassurance,
            }
            for b in (1,2,3,4,5)
        },
        "method": "analytic uniform random permutation expectation",
    }


def synthetic_run(selector_cost=2.0, champion_cost=2.5, selector_fr=0.10, champion_fr=0.12):
    ids = [f"P{i:02d}" for i in range(30)]
    negatives = [f"N{i:02d}" for i in range(30)]
    all_ids = ids + negatives
    flags = {cid: {"A": cid.startswith("P")} for cid in all_ids}

    def traces(cost):
        return [
            {
                "candidate_id": cid,
                "has_any_liability": cid.startswith("P"),
                "assays_spent": int(cost if cid.startswith("P") else 8),
                "steps": [],
            }
            for cid in all_ids
        ]

    metrics = {
        "continuous_value_conditional_risk": synthetic_metric(selector_cost, selector_fr),
        "fixed_prevalence": synthetic_metric(champion_cost, champion_fr),
        "greedy_fixed_coverage": synthetic_metric(champion_cost+0.2, champion_fr+0.02),
        "binary_dynamic": synthetic_metric(champion_cost+0.1, champion_fr+0.01),
        "expected_information_gain": synthetic_metric(champion_cost+0.3, champion_fr+0.03),
        "uniform_random_expected": synthetic_random_metric(champion_cost+0.4, champion_fr+0.04),
    }
    tr = {
        "continuous_value_conditional_risk": traces(2),
        "fixed_prevalence": traces(3),
        "greedy_fixed_coverage": traces(3),
        "binary_dynamic": traces(3),
        "expected_information_gain": traces(3),
    }
    return {
        "candidate_ids": all_ids,
        "liability_flags": flags,
        "traces": tr,
        "metrics": metrics,
    }


class TrialSelectorExternal001Tests(unittest.TestCase):
    def test_frozen_selector_hash_is_discovery_receipt_hash(self):
        cfg = load_config()
        self.assertEqual(
            cfg["discovery_parent"]["frozen_selector_sha256"],
            "4f959c4bec0de3ccd9b640aa367159bf8785c1e4bfbb94290e0da2cc10ddb44d",
        )

    def test_live_frozen_selector_hash_matches_when_base_repo_is_present(self):
        cfg = load_config()
        path = ROOT / cfg["discovery_parent"]["frozen_selector_path"]
        if not path.is_file():
            self.skipTest("overlay-only local preflight; base repository absent")
        self.assertEqual(
            mod.sha256_file(path),
            cfg["discovery_parent"]["frozen_selector_sha256"],
        )

    def test_assay_surface_is_frozen_to_eight_ginkgo_columns(self):
        assays = load_config()["assay_mapping"]["assay_order"]
        self.assertEqual(len(assays), 8)
        self.assertEqual(len(set(assays)), 8)
        self.assertEqual(
            assays,
            [
                "AC-SINS_pH6.0",
                "AC-SINS_pH7.4",
                "HIC",
                "PR_CHO",
                "PR_Ova",
                "SMAC",
                "Tm1",
                "Tm2",
            ],
        )

    def test_name_overlap_is_exact_after_strip_casefold(self):
        self.assertEqual(mod.normalize_name("  Adalimumab "), "adalimumab")
        self.assertEqual(mod.normalize_name("adalimumab"), "adalimumab")
        self.assertNotEqual(mod.normalize_name("adalimumab-biosimilar"), "adalimumab")

    def test_entropy_prefers_uncertain_probability(self):
        self.assertGreater(
            mod.bernoulli_entropy_bits(0.5),
            mod.bernoulli_entropy_bits(0.9),
        )
        self.assertGreater(
            mod.bernoulli_entropy_bits(0.5),
            mod.bernoulli_entropy_bits(0.1),
        )
        self.assertEqual(mod.bernoulli_entropy_bits(0.0), 0.0)
        self.assertEqual(mod.bernoulli_entropy_bits(1.0), 0.0)

    def test_percentile_is_deterministic_linear_interpolation(self):
        self.assertTrue(
            math.isclose(
                mod._percentile([0.0, 1.0, 2.0, 3.0, 4.0], 0.5),
                2.0,
            )
        )

    def test_signal_gate_requires_efficiency_bootstrap_and_safety(self):
        cfg = json.loads(json.dumps(load_config()))
        cfg["assay_mapping"]["assay_order"] = ["A"] * 8
        grade, verdict = mod.grade(synthetic_run(), cfg)
        self.assertTrue(grade["selector_strictly_lower_than_every_baseline"])
        self.assertTrue(grade["bootstrap_lower_bound_gt_zero"])
        self.assertTrue(grade["safety_nonworse_than_champion"])
        self.assertEqual(verdict["verdict"], "EXTERNAL_ALLOCATION_SIGNAL")

    def test_safety_failure_blocks_signal(self):
        cfg = json.loads(json.dumps(load_config()))
        cfg["assay_mapping"]["assay_order"] = ["A"] * 8
        grade, verdict = mod.grade(
            synthetic_run(selector_fr=0.20, champion_fr=0.12),
            cfg,
        )
        self.assertFalse(grade["safety_nonworse_than_champion"])
        self.assertEqual(
            verdict["verdict"],
            "EXTERNAL_GENERALIZATION_NOT_SUPPORTED",
        )

    def test_cohort_bar_precedes_signal(self):
        cfg = load_config()
        run = synthetic_run()
        for metric in run["metrics"].values():
            metric["candidate_count"] = 20
            metric["liability_positive_count"] = 5
            metric["liability_negative_count"] = 15
        grade, verdict = mod.grade(run, cfg)
        self.assertFalse(grade["cohort_ready"])
        self.assertEqual(verdict["verdict"], "INCONCLUSIVE_EXTERNAL_COHORT")

    def test_preflight_inconclusive_grade_does_not_require_selector_metrics(self):
        cfg = load_config()
        counts = {
            "candidate_count": 20,
            "liability_positive_count": 5,
            "liability_negative_count": 15,
        }
        grade, verdict = mod.inconclusive_grade(counts, cfg)
        self.assertFalse(grade["cohort_ready"])
        self.assertIsNone(grade["paired_bootstrap"])
        self.assertEqual(verdict["verdict"], "INCONCLUSIVE_EXTERNAL_COHORT")


if __name__ == "__main__":
    unittest.main()
