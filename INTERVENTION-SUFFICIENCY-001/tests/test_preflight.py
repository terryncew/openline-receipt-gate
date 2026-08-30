import json
import tempfile
import unittest
from pathlib import Path

from intervention_sufficiency.preflight import run_preflight
from intervention_sufficiency.synthetic import generate

class InterventionSufficiencyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).parents[1]
        self.gate = self.root / "config/frozen_gate.json"
        self.tmp = Path(tempfile.mkdtemp())
        self.fx = generate(self.tmp / "fx")

    def _run(self, name):
        return run_preflight(
            Path(self.fx[name]["csv"]),
            Path(self.fx[name]["manifest"]),
            self.gate,
            self.tmp / f"out-{name}"
        )

    def test_positive_control_passes(self):
        r = self._run("pass")
        self.assertEqual(r["status"], "PASS_INTERVENTION_SUFFICIENCY")
        self.assertGreaterEqual(r["inventory"]["remedy_divergent_context_lag_groups"], 10)
        self.assertGreaterEqual(r["inventory"]["lag_contraction_context_action_groups"], 10)

    def test_one_action_fails(self):
        r = self._run("fail_one_action")
        self.assertEqual(r["status"], "UNTESTABLE_FOR_RECOVERABILITY")
        self.assertIn("unique_actions", r["failure_reasons"])
        self.assertIn("remedy_divergent_context_lag_groups", r["failure_reasons"])

    def test_no_remedy_divergence_fails(self):
        r = self._run("fail_no_remedy_divergence")
        self.assertEqual(r["status"], "UNTESTABLE_FOR_RECOVERABILITY")
        self.assertIn("remedy_divergent_context_lag_groups", r["failure_reasons"])

    def test_manifest_must_freeze_matching(self):
        mp = Path(self.fx["pass"]["manifest"])
        m = json.loads(mp.read_text())
        m["matching_frozen_before_outcome_analysis"] = False
        bad = self.tmp / "bad.manifest.json"
        bad.write_text(json.dumps(m))
        with self.assertRaises(ValueError):
            run_preflight(Path(self.fx["pass"]["csv"]), bad, self.gate, self.tmp/"badout")

    def test_dataset_hash_is_binding(self):
        mp = Path(self.fx["pass"]["manifest"])
        m = json.loads(mp.read_text())
        m["dataset_receipt_sha256"] = "0"*64
        bad = self.tmp / "badsha.manifest.json"
        bad.write_text(json.dumps(m))
        with self.assertRaises(ValueError):
            run_preflight(Path(self.fx["pass"]["csv"]), bad, self.gate, self.tmp/"badshaout")

    def test_closure_is_frozen(self):
        c = json.loads((self.root/"PROGRAM_CLOSURE.json").read_text())
        self.assertEqual(c["disposition"], "NO_DOMAIN_INDEPENDENT_RECOVERABILITY_MARGIN_SIGNAL")
        self.assertIn("transition under intervention", c["scientific_correction"])

if __name__ == "__main__":
    unittest.main()
