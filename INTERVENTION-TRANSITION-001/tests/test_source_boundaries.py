import unittest
from pathlib import Path

class SourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).parents[1]

    def test_oracle_branches_restore_same_snapshot(self):
        text=(self.root/"src/intervention_transition/oracle.py").read_text()
        self.assertIn("bd,bw=a.restore(snap)",text)
        self.assertIn("snapshot_integration_sha256",text)
        self.assertIn("snapshot_wrapper_sha256",text)

    def test_oracle_has_no_model_fit(self):
        text=(self.root/"src/intervention_transition/oracle.py").read_text().lower()
        self.assertNotIn("logistic",text)
        self.assertNotIn("sklearn",text)
        self.assertNotIn("fit(",text)

    def test_snapshot_includes_python_wrapper(self):
        text=(self.root/"src/intervention_transition/adapter.py").read_text()
        for name in ("action=w.action.copy()","target_dof_pos=w.target_dof_pos.copy()",
                     "obs=w.obs.copy()","counter=int(w.counter)","cmd=w.cmd.copy()"):
            self.assertIn(name,text)

    def test_integration_state_uses_bound_numpy_namespace(self):
        text=(self.root/"src/intervention_transition/adapter.py").read_text()
        self.assertIn("x=self.np.empty(n,dtype=self.np.float64)",text)
        self.assertNotIn("x=self.np.empty(n,dtype=np.float64)",text)

    def test_counterfactual_restore_uses_full_mjdata_copy(self):
        text=(self.root/"src/intervention_transition/adapter.py").read_text()
        self.assertIn("self.mujoco.mj_copyData(dest,self.model,src)",text)
        restore=text.split("def restore(self,snap):",1)[1].split("def _policy_update",1)[0]
        self.assertIn('d=self.copy_data(snap["data"])',restore)
        self.assertNotIn("self.set_integration_state",restore)

    def test_protocol_freezes_full_copy_without_relaxing_tolerance(self):
        import json
        p=json.loads((self.root/"config/protocol.frozen.json").read_text())
        self.assertEqual(p["snapshot"]["clone_method"],"mj_copyData + branch-local recurrent policy memory")
        self.assertEqual(p["snapshot"]["portable_receipt_state"],"mjSTATE_INTEGRATION + recurrent-policy-state hashes")
        self.assertEqual(p["snapshot"]["max_abs_state_error"],1e-12)
        self.assertEqual(p["snapshot"]["max_abs_wrapper_error"],1e-12)

    def test_recurrent_policy_memory_is_branch_local(self):
        text=(self.root/"src/intervention_transition/adapter.py").read_text()
        self.assertIn("policy_hidden_state",text)
        self.assertIn("policy_cell_state",text)
        self.assertIn("self.policy.hidden_state.copy_(w.policy_hidden_state)",text)
        self.assertIn("w.policy_hidden_state=self.policy.hidden_state.detach().clone()",text)

    def test_oracle_hashes_recurrent_policy_state(self):
        text=(self.root/"src/intervention_transition/oracle.py").read_text()
        self.assertIn('"policy_state":a.policy_state_hashes(snap["wrapper"])',text)

if __name__=="__main__":
    unittest.main()
