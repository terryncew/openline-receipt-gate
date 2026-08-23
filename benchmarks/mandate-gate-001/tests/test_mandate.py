from datetime import datetime, timezone
import json, pathlib, unittest

def load_module(root):
    import importlib.util, sys
    path=root.parents[1]/"olp_gate"/"mandate.py"
    spec=importlib.util.spec_from_file_location("mandate_profile",path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    return module

ROOT=pathlib.Path(__file__).resolve().parents[1]
m=load_module(ROOT)
MANDATE=json.loads((ROOT/"alice_mandate.json").read_text())
NOW=datetime(2026,8,23,tzinfo=timezone.utc)

def eff(**kw):
    base={
      "profile":"principal_effect/v1","effect_id":"x",
      "mandate_id":"alice-medical-bill-001","principal_id":"alice",
      "agent_id":"medical-bill-agent","purpose":"dispute-medical-bill",
      "action_type":"send","target":"hospital-billing-office",
      "disclosures":["billing-record"],"value_cents":0,
      "delegatee":None,"producer_model":"a",
    }
    base.update(kw); return base

class T(unittest.TestCase):
    def test_allowed(self):
        self.assertTrue(m.assess_effect(MANDATE,eff(),now=NOW)["allowed"])
    def test_forbidden_disclosure(self):
        r=m.assess_effect(MANDATE,eff(disclosures=["psychiatric-note"]),now=NOW)
        self.assertFalse(r["allowed"]); self.assertIn("forbidden_disclosure",r["reason_codes"])
    def test_model_swap_does_not_expand(self):
        a=m.assess_effect(MANDATE,eff(producer_model="a"),now=NOW)
        b=m.assess_effect(MANDATE,eff(producer_model="b"),now=NOW)
        self.assertEqual(a["allowed"],b["allowed"])
    def test_settlement_ceiling(self):
        self.assertFalse(m.assess_effect(MANDATE,eff(action_type="accept_settlement",value_cents=50001),now=NOW)["allowed"])
    def test_payment_is_not_allowed(self):
        self.assertFalse(m.assess_effect(MANDATE,eff(action_type="authorize_payment",value_cents=1),now=NOW)["allowed"])
    def test_compile_refuses_denied_effect(self):
        with self.assertRaises(PermissionError):
            m.compile_verified_commit_settings(MANDATE,eff(disclosures=["unrelated-medical-record"]),now=NOW)
if __name__=="__main__": unittest.main()
