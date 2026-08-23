from pathlib import Path
import hashlib, json, sys
ROOT = Path(__file__).resolve().parents[1]
res = json.loads((ROOT / "result.json").read_text())
checks = {
    "authority_none": res.get("policy_authority") == "NONE",
    "valid_verdict": res.get("verdict") in {"CONTROLLED_GROUND_TRUTH_SELECTIVE_CONTAINMENT", "SELECTIVE_CONTAINMENT_NOT_EARNED"},
    "prereg_hash": res.get("preregistration_sha256") == hashlib.sha256((ROOT / "preregistration.json").read_bytes()).hexdigest(),
    "ground_truth_hash": res.get("ground_truth_sha256") == hashlib.sha256((ROOT / "ground_truth_cases.json").read_bytes()).hexdigest(),
}
out = {"schema": "openline.receipt_gate.iac001.verification.v1", "verified": all(checks.values()), "checks": checks, "verdict": res.get("verdict"), "policy_authority": "NONE"}
print(json.dumps(out, indent=2, sort_keys=True))
raise SystemExit(0 if out["verified"] else 2)
