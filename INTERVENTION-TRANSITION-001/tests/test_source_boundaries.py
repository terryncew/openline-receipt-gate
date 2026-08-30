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

if __name__=="__main__":
    unittest.main()
