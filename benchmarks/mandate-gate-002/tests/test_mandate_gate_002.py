from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from olp_gate.mandate import compile_verified_commit_settings
from olp_gate.mandate_gate import mandate_preflight

ROOT=Path(__file__).resolve().parents[1]
M=json.loads((ROOT/"alice_mandate.json").read_text())
NOW=datetime(2026,8,23,5,0,0,tzinfo=timezone.utc)

def effect(disclosures):
    return {
      "profile":"principal_effect/v1","effect_id":"unit",
      "mandate_id":M["mandate_id"],"principal_id":M["principal_id"],
      "agent_id":M["agent_id"],"purpose":M["purpose"],
      "action_type":"send","target":"hospital-billing-office",
      "disclosures":disclosures,"value_cents":0,"delegatee":None,
      "producer_model":"unit-model",
    }

class Tests(unittest.TestCase):
    def test_allowed_preflight(self):
        settings=compile_verified_commit_settings(M,effect(["billing-record"]),now=NOW)
        self.assertTrue(mandate_preflight(M,settings,now=NOW)["allowed"])

    def test_receiver_preflight_rejects_forbidden_effect(self):
        settings=compile_verified_commit_settings(M,effect(["billing-record"]),now=NOW)
        settings["effect"]["disclosures"]=["psychiatric-note"]
        result=mandate_preflight(M,settings,now=NOW)
        self.assertFalse(result["allowed"])

    def test_receiver_preflight_rejects_hash_tamper(self):
        settings=compile_verified_commit_settings(M,effect(["billing-record"]),now=NOW)
        settings["mandate_hash"]="00"*32
        result=mandate_preflight(M,settings,now=NOW)
        self.assertFalse(result["allowed"])
        self.assertIn("mandate_hash_mismatch",result["reason_codes"])

if __name__=="__main__":
    unittest.main()
