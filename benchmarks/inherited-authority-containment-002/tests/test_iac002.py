
import json, unittest
from pathlib import Path
from iac002.generator import generate
from iac002.core import evaluate, classify
R=Path(__file__).resolve().parents[1]
P=json.loads((R/"preregistration.json").read_text())
class IAC002Tests(unittest.TestCase):
    def test_generation_is_deterministic(self):
        self.assertEqual(generate(P),generate(P))
    def test_unknown_quarantines(self):
        c={"compromised":"a","pre_detection_descendants":["b"],"represented_edges":[],
           "declared_roots":{},"created_step":{"b":1},"compromise_step":0,"detection_step":4}
        self.assertEqual(classify(c,"OLP_SELECTIVE")["b"],"QUARANTINE")
    def test_policy_authority_none(self):
        self.assertEqual(evaluate(generate(P),P)["policy_authority"],"NONE")
    def test_bounded_verdict(self):
        self.assertIn(evaluate(generate(P),P)["verdict"],
          {"CONTROLLED_MACHINE_SPEED_AUTHORITY_CONTAINMENT","MACHINE_SPEED_CONTAINMENT_NOT_EARNED"})
if __name__=="__main__":
    unittest.main()
