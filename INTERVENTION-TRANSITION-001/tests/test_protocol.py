import json
import unittest
from pathlib import Path

class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).parents[1]
        self.p=json.loads((self.root/"config/protocol.frozen.json").read_text())

    def test_no_margin_in_stage_a(self):
        forbidden=" ".join(self.p["claim_boundary"]["forbidden"]).lower()
        self.assertIn("terrynce scalar",forbidden)
        self.assertEqual(self.p["stage"],"COUNTERFACTUAL_ORACLE_PREFLIGHT")

    def test_exact_context_count_meets_gate_minimum(self):
        self.assertGreaterEqual(self.p["context_generation"]["count"],50)

    def test_action_and_lag_grid_is_frozen(self):
        self.assertEqual(len(self.p["actions"]),6)
        self.assertEqual(self.p["lags_ms"],[0,40,80,120,160])

    def test_policy_update_matches_released_config(self):
        self.assertEqual(self.p["controller"]["control_decimation"],10)
        self.assertEqual(self.p["controller"]["simulation_dt_seconds"],0.002)
        self.assertEqual(self.p["controller"]["policy_update_hz"],50)

    def test_wrapper_snapshot_contains_released_mutable_state(self):
        fields=set(self.p["controller"]["snapshot_python_state"])
        self.assertEqual(fields,{"action","target_dof_pos","obs","counter","cmd","policy_hidden_state","policy_cell_state"})

    def test_controller_scope_is_operational(self):
        allowed=self.p["claim_boundary"]["allowed"].lower()
        self.assertIn("frozen controller",allowed)
        self.assertIn("physical non-viability", " ".join(self.p["claim_boundary"]["forbidden"]).lower())

if __name__=="__main__":
    unittest.main()
