import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "benchmarks/trial_selector/jain_selector.py"

# The Jain selector is a frozen scientific benchmark with intentionally optional
# NumPy/scikit-learn dependencies. The repository release gate also runs the
# complete unittest suite in a core-only environment, so discovery must remain
# valid when those scientific packages are absent. The dedicated Jain workflow
# installs the frozen dependencies and executes these tests normally.
HAS_JAIN_DEPS = (
    importlib.util.find_spec("numpy") is not None
    and importlib.util.find_spec("sklearn") is not None
)

js = None
if HAS_JAIN_DEPS:
    spec = importlib.util.spec_from_file_location("jain_selector", MODULE)
    js = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = js
    assert spec.loader is not None
    spec.loader.exec_module(js)


@unittest.skipUnless(
    HAS_JAIN_DEPS,
    "requires optional Jain selector scientific dependencies",
)
class JainTrialSelectorTests(unittest.TestCase):
    def synthetic(self):
        # Ten assays are required by the frozen interface. Values are deliberately simple.
        thresholds = {a: js.Threshold("<=", 0.5) for a in js.ASSAY_ORDER}
        candidates = []
        for i in range(12):
            assays = {a: 0.0 for a in js.ASSAY_ORDER}
            if i % 3 == 0:
                assays["BVP"] = 1.0
            if i % 4 == 0:
                assays["ELISA"] = 1.0
            # Continuous AC_SINS value carries conditional information about PSR.
            assays["AC_SINS"] = i / 20
            if i >= 8:
                assays["PSR"] = 1.0
            candidates.append({"candidate_id": f"c{i:02d}", "assays": assays})
        return candidates, thresholds

    def test_threshold_direction(self):
        self.assertTrue(js.is_liability(0.6, js.Threshold("<=", 0.5)))
        self.assertFalse(js.is_liability(0.5, js.Threshold("<=", 0.5)))
        self.assertTrue(js.is_liability(0.4, js.Threshold(">=", 0.5)))
        self.assertFalse(js.is_liability(0.5, js.Threshold(">=", 0.5)))

    def test_fixed_prevalence_excludes_holdout(self):
        candidates, thresholds = self.synthetic()
        values, flags = js.build_liability_matrix(candidates, thresholds)
        ids = sorted(values)
        holdout = "c00"
        order = js.fixed_prevalence_order(flags, [cid for cid in ids if cid != holdout])
        # deterministic, unique, complete
        self.assertEqual(len(order), 10)
        self.assertEqual(len(set(order)), 10)

    def test_greedy_coverage_is_complete(self):
        candidates, thresholds = self.synthetic()
        values, flags = js.build_liability_matrix(candidates, thresholds)
        order = js.greedy_coverage_order(flags, sorted(values))
        self.assertEqual(set(order), set(js.ASSAY_ORDER))

    def test_dynamic_trace_stops_on_first_liability(self):
        candidates, thresholds = self.synthetic()
        values, flags = js.build_liability_matrix(candidates, thresholds)
        ids = sorted(values)
        trace = js.dynamic_trace(candidate_ids=ids, holdout="c00", values=values, flags=flags, binary_features=False)
        self.assertTrue(trace["steps"][-1]["liability"])
        self.assertEqual(trace["assays_spent"], len(trace["steps"]))
        self.assertEqual(len({s["assay"] for s in trace["steps"]}), len(trace["steps"]))

    def test_false_reassurance_definition(self):
        traces = [
            {"candidate_id": "a", "has_any_liability": True, "assays_spent": 2, "steps": []},
            {"candidate_id": "b", "has_any_liability": True, "assays_spent": 5, "steps": []},
            {"candidate_id": "c", "has_any_liability": False, "assays_spent": 10, "steps": []},
        ]
        summary = js.summarize_deterministic_traces(traces, budgets=(3,))
        self.assertEqual(summary["budgets"]["3"]["survivor_count"], 2)
        self.assertAlmostEqual(summary["budgets"]["3"]["false_reassurance_fraction"], 0.5)

    def test_random_expected_first_position(self):
        candidates, thresholds = self.synthetic()
        values, flags = js.build_liability_matrix(candidates, thresholds)
        summary = js.random_expected_summary(flags, sorted(values), budgets=(3,))
        self.assertGreaterEqual(summary["mean_assays_to_first_liability_positive_only"], 1.0)
        self.assertLessEqual(summary["mean_assays_to_first_liability_positive_only"], 10.0)

    def test_leave_one_out_returns_all_baselines(self):
        candidates, thresholds = self.synthetic()
        run = js.run_leave_one_out(candidates, thresholds)
        self.assertEqual(
            set(run["metrics"]),
            {"fixed_prevalence", "greedy_fixed_coverage", "binary_dynamic", "continuous_value_conditional_risk", "uniform_random_expected"},
        )
        for name in ("fixed_prevalence", "greedy_fixed_coverage", "binary_dynamic", "continuous_value_conditional_risk"):
            self.assertEqual(len(run["traces"][name]), len(candidates))


if __name__ == "__main__":
    unittest.main()
