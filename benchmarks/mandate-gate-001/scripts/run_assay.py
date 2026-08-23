from __future__ import annotations
from datetime import datetime, timezone
import json, pathlib

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
mandate=json.loads((ROOT/"alice_mandate.json").read_text())
NOW=datetime(2026,8,23,tzinfo=timezone.utc)

def effect(name,action,disclosures=None,value=0,target="hospital-billing-office",
           purpose="dispute-medical-bill",agent="medical-bill-agent",
           delegatee=None,model="model-a"):
    return {
      "profile":"principal_effect/v1","effect_id":name,
      "mandate_id":"alice-medical-bill-001","principal_id":"alice",
      "agent_id":agent,"purpose":purpose,"action_type":action,"target":target,
      "disclosures":disclosures or [],"value_cents":value,
      "delegatee":delegatee,"producer_model":model,
    }

cases={
 "allowed_dispute":effect("allowed","send",["billing-record","eob"]),
 "extra_psych_record":effect("psych","send",["billing-record","psychiatric-note"]),
 "unrelated_record":effect("unrelated","send",["unrelated-medical-record"]),
 "settlement_over_limit":effect("settlement","accept_settlement",value=50001),
 "payment_not_authorized":effect("payment","authorize_payment",value=1),
 "delegation_not_authorized":effect("delegate","delegate",delegatee="agent-b"),
 "wrong_purpose":effect("purpose","send",["billing-record"],purpose="marketing"),
 "wrong_target":effect("target","send",["billing-record"],target="data-broker"),
 "model_swap_same_mandate":effect("swap","send",["billing-record"],model="model-z"),
}
expected={
 "allowed_dispute":True,"extra_psych_record":False,"unrelated_record":False,
 "settlement_over_limit":False,"payment_not_authorized":False,
 "delegation_not_authorized":False,"wrong_purpose":False,"wrong_target":False,
 "model_swap_same_mandate":True,
}
results={name:m.assess_effect(mandate,e,now=NOW) for name,e in cases.items()}
results["expired_mandate"]=m.assess_effect(
 mandate,effect("expired","send",["billing-record"]),
 now=datetime(2026,10,1,tzinfo=timezone.utc))
expected["expired_mandate"]=False
checks={name:(results[name]["allowed"]==want) for name,want in expected.items()}
passed=all(checks.values())
out={
 "schema":"openline.mandate_gate.assay.v1",
 "verdict":"MANDATE_PROFILE_DISCRIMINATION_PASS" if passed else "MANDATE_PROFILE_NOT_EARNED",
 "policy_authority":"NONE","checks":checks,"results":results,
 "claim_boundary":{
   "creates_fiduciary_duty":False,"moves_money":False,
   "replaces_verified_commit":False,"model_identity_expands_authority":False
 }
}
(ROOT/"result.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
print(json.dumps(out,indent=2,sort_keys=True))
raise SystemExit(0 if passed else 2)
