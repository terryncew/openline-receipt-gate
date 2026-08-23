from pathlib import Path
import hashlib,json,sys
R=Path(__file__).resolve().parents[1]
res=json.loads((R/"result.json").read_text())
checks={
 "policy_authority_none":res.get("policy_authority")=="NONE",
 "standing_valid":res.get("standing") in {"UNWARE_RUNTIME_RACE_CONTAINMENT","UNWARE_RUNTIME_RACE_CONTAINMENT_NOT_EARNED"},
 "freeze_hash":res.get("freeze_sha256")==hashlib.sha256((R/"FREEZE.json").read_bytes()).hexdigest(),
 "runtime_hash":res.get("runtime_sha256")==hashlib.sha256((R/"runtime_unaware.py").read_bytes()).hexdigest(),
 "receiver_hash":res.get("receiver_sha256")==hashlib.sha256((R/"atomic_receiver.py").read_bytes()).hexdigest(),
 "pass_consistent":all(res["checks"].values()) if res.get("standing")=="UNWARE_RUNTIME_RACE_CONTAINMENT" else True
}
out={"schema":"openline.receipt_gate.iac004.verify.v2","verified":all(checks.values()),
     "checks":checks,"standing":res.get("standing"),"policy_authority":"NONE"}
print(json.dumps(out,indent=2,sort_keys=True))
raise SystemExit(0 if out["verified"] else 2)
