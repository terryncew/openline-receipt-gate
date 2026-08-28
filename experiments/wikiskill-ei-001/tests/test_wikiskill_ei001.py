from __future__ import annotations
import copy, json, subprocess, sys, unittest
from pathlib import Path
EXP=Path(__file__).resolve().parents[1]
if str(EXP) not in sys.path: sys.path.insert(0,str(EXP))
from wikiskill_ei001 import broad_recall, minimal_extension, openline_recall, published_wikiskill
from wikiskill_ei001.common import sha256_json

class WikiSkillEI001Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenario=json.loads((EXP/"fixtures/scenario.json").read_text())
        cls.oracle=json.loads((EXP/"oracle.json").read_text())
        cls.state=cls.scenario["public_state"]
    def graph(self,world):
        return {"trace_to_patterns":self.scenario["sealed_worlds"][world]["derivation_truth"],"pattern_to_skills":self.scenario["pattern_to_skill"]}
    def test_worlds_share_exact_published_representation(self):
        self.assertTrue(self.scenario["invariants"]["public_state_same_for_all_worlds"])
        self.assertTrue(self.scenario["invariants"]["standing_event_same_for_all_worlds"])
    def test_oracle_is_discriminating(self):
        self.assertNotEqual(self.oracle["event_case"]["world-A"],self.oracle["event_case"]["world-B"])
    def test_published_wikiskill_is_out_of_scope_not_failed(self):
        r=published_wikiskill.evaluate(self.state,self.scenario["standing_event"])
        self.assertEqual(r["disposition"],"OUT_OF_SCOPE_POST_HOC_EXPERIENCE_INVALIDATION"); self.assertFalse(r["scored"])
    def test_broad_recall_overblocks_both_worlds(self):
        r=broad_recall.evaluate(self.state,self.scenario["standing_event"])
        self.assertEqual(set(r["outcome"]["patterns"].values()),{"REOPEN"})
        self.assertNotEqual(r["outcome"],self.oracle["event_case"]["world-A"])
        self.assertNotEqual(r["outcome"],self.oracle["event_case"]["world-B"])
    def test_minimal_extension_fails_closed_without_source_refs(self):
        r=minimal_extension.evaluate(self.state,self.scenario["standing_event"])
        self.assertEqual(r["disposition"],"UNRESOLVED_PROVENANCE")
    def test_openline_matches_world_a(self):
        r=openline_recall.evaluate(self.state,self.scenario["standing_event"],self.graph("world-A"))
        self.assertEqual(r["outcome"],self.oracle["event_case"]["world-A"])
    def test_openline_matches_world_b(self):
        r=openline_recall.evaluate(self.state,self.scenario["standing_event"],self.graph("world-B"))
        self.assertEqual(r["outcome"],self.oracle["event_case"]["world-B"])
    def test_positive_provenance_control_resolves(self):
        state=copy.deepcopy(self.state)
        for p,refs in self.scenario["provenance_control"]["explicit_source_trace_ids"].items(): state["wiki"]["patterns"][p]["source_trace_ids"]=refs
        r=minimal_extension.evaluate(state,self.scenario["standing_event"])
        self.assertEqual(r["outcome"],self.oracle["event_case"]["world-A"])
    def test_noop_preserves_all(self):
        expected=self.oracle["no_op_case"]
        self.assertEqual(broad_recall.evaluate(self.state,self.scenario["no_op_event"])["outcome"],expected)
        self.assertEqual(minimal_extension.evaluate(self.state,self.scenario["no_op_event"])["outcome"],expected)
        self.assertEqual(openline_recall.evaluate(self.state,self.scenario["no_op_event"],self.graph("world-A"))["outcome"],expected)
    def test_all_arms_leave_historical_bytes_unchanged(self):
        before=sha256_json(self.state)
        for result in [published_wikiskill.evaluate(copy.deepcopy(self.state),self.scenario["standing_event"]), broad_recall.evaluate(copy.deepcopy(self.state),self.scenario["standing_event"]), minimal_extension.evaluate(copy.deepcopy(self.state),self.scenario["standing_event"]), openline_recall.evaluate(copy.deepcopy(self.state),self.scenario["standing_event"],self.graph("world-A"))]:
            self.assertEqual(result["historical_before"],before); self.assertEqual(result["historical_after"],before)
    def test_independent_verifier_passes(self):
        proc=subprocess.run([sys.executable,str(EXP/"scripts/verify_result.py")],capture_output=True,text=True)
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)

if __name__=="__main__": unittest.main()
