import json, unittest
from pathlib import Path
from iac001.generator import generate
from iac001.core import classify, evaluate
ROOT = Path(__file__).resolve().parents[1]
P = json.loads((ROOT / "preregistration.json").read_text())

class IAC001Tests(unittest.TestCase):
    def test_deterministic_generation(self):
        self.assertEqual(generate(P), generate(P))

    def test_unknown_fails_closed(self):
        case = {"compromised":"a","descendant_nodes":["b"],"represented_edges":[],"declared_roots":{},"created_at":{"b":1},"compromise_time":0,"detection_time":2,"true_tainted":["b"]}
        self.assertEqual(classify(case, "OLP_SELECTIVE")["b"], "QUARANTINE")

    def test_authority_none(self):
        self.assertEqual(evaluate(generate(P), P)["policy_authority"], "NONE")

    def test_result_is_bounded(self):
        self.assertIn(evaluate(generate(P), P)["verdict"], {"CONTROLLED_GROUND_TRUTH_SELECTIVE_CONTAINMENT", "SELECTIVE_CONTAINMENT_NOT_EARNED"})

if __name__ == "__main__":
    unittest.main()
