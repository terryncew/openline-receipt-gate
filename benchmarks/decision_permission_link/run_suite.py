from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from olp_gate.authority_link import (
    EVIDENCE_PROFILE, POLICY_PROFILE, PROPOSAL_PROFILE,
    compile_link, effect_hash,
)

NOW = datetime(2026, 8, 23, 20, 0, tzinfo=timezone.utc)
H = lambda s: hashlib.sha256(s.encode()).hexdigest()

POLICY = {
    "profile": POLICY_PROFILE,
    "policy_id": "dpl001.receiver.payment",
    "version": "1",
    "routes": [{
        "route_id": "pay-approved-vendor",
        "tool": "payments.transfer",
        "target": "vendor:acme",
        "requirements": [
            {"requirement_id":"principal_mandate","kind":"authority","accepted_issuers":["receiver-mandate"],"max_age_seconds":86400,"independent_from_producer":True},
            {"requirement_id":"risk_check","kind":"evidence","accepted_issuers":["risk-oracle"],"max_age_seconds":300,"independent_from_producer":True},
        ],
        "unknown_behavior": "QUARANTINE",
        "max_authorization_ttl_seconds": 60,
    }],
}


def proposal(producer="optimizer-A", advisory="score-high", amount=12500, state="state-1", target="vendor:acme"):
    return {
        "profile": PROPOSAL_PROFILE,
        "proposal_id": f"{producer}:{advisory}:{amount}:{target}",
        "producer_id": producer,
        "producer_model": producer,
        "objective": "pay approved invoice",
        "tool": "payments.transfer",
        "target": target,
        "settings": {"amount_cents": amount, "currency": "USD", "invoice_id": "INV-7"},
        "state_hash": H(state),
        "advisory_hash": H(advisory),
    }


def receipt(p, rid, kind, issuer, *, subject=None, age=10, verified="VERIFIED", revoked=False):
    return {
        "profile": EVIDENCE_PROFILE,
        "requirement_id": rid,
        "kind": kind,
        "subject_hash": subject or effect_hash(p),
        "issuer_id": issuer,
        "issued_at": (NOW - timedelta(seconds=age)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "artifact_hash": H(f"artifact:{rid}:{issuer}:{age}"),
        "verification_receipt_hash": H(f"verify:{rid}:{issuer}:{age}"),
        "receiver_verification_status": verified,
        "revoked": revoked,
    }


def good(p):
    return [
        receipt(p,"principal_mandate","authority","receiver-mandate"),
        receipt(p,"risk_check","evidence","risk-oracle"),
    ]


def run_case(case_id, p, ev, *, state_hash=None, pol=None):
    linked = compile_link(pol or POLICY, p, ev, now=NOW, current_state_hash=state_hash or p["state_hash"])
    return {
        "case_id": case_id,
        "decision": linked["assessment"]["decision"],
        "reason_codes": linked["assessment"]["reason_codes"],
        "proposal_hash": linked["assessment"]["proposal_hash"],
        "effect_hash": linked["assessment"]["effect_hash"],
        "obligation_hash": linked["assessment"]["obligation_hash"],
        "verified_commit_settings_emitted": linked["verified_commit_settings"] is not None,
    }


def main():
    cases=[]
    a=proposal("optimizer-A","score-99")
    b=proposal("optimizer-B","score-12")
    cases.append(run_case("optimizer_a_clean",a,good(a)))
    cases.append(run_case("optimizer_b_clean",b,good(b)))
    cases.append(run_case("missing_risk_evidence",a,good(a)[:1]))
    wrong=good(a); wrong[1]=dict(wrong[1]); wrong[1]["subject_hash"]=H("other-effect")
    cases.append(run_case("wrong_subject_substitution",a,wrong))
    self_ev=good(a); self_ev[1]=dict(self_ev[1]); self_ev[1]["issuer_id"]="optimizer-A"
    pol=deepcopy(POLICY); pol["routes"][0]["requirements"][1]["accepted_issuers"].append("optimizer-A")
    cases.append(run_case("self_authorization_attempt",a,self_ev,pol=pol))
    stale=good(a); stale[1]=receipt(a,"risk_check","evidence","risk-oracle",age=301)
    cases.append(run_case("stale_evidence",a,stale))
    cases.append(run_case("state_drift",a,good(a),state_hash=H("state-2")))
    outside=proposal(target="vendor:evil")
    cases.append(run_case("unrouted_high_score",outside,[]))

    expected={
        "optimizer_a_clean":"COMMIT_ELIGIBLE",
        "optimizer_b_clean":"COMMIT_ELIGIBLE",
        "missing_risk_evidence":"QUARANTINE",
        "wrong_subject_substitution":"DENY",
        "self_authorization_attempt":"DENY",
        "stale_evidence":"QUARANTINE",
        "state_drift":"DENY",
        "unrouted_high_score":"DENY",
    }
    mismatches=[c["case_id"] for c in cases if c["decision"]!=expected[c["case_id"]]]
    report={
        "schema":"openline.dpl001.hostile_report.v1",
        "experiment_id":"DPL-001",
        "claim":"Decision quality does not grant permission; exact receiver-owned proof obligations bridge proposals to execution eligibility.",
        "cases":cases,
        "expected_decisions":expected,
        "mismatches":mismatches,
        "passed":not mismatches,
        "optimizer_swap_permission_invariant": cases[0]["decision"]==cases[1]["decision"]=="COMMIT_ELIGIBLE",
        "advisory_score_used_as_permission_evidence": False,
        "execution_authority":"NONE; Verified Commit required after COMMIT_ELIGIBLE",
    }
    out=Path(__file__).resolve().parent/"results"/"hostile_report.json"
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2,sort_keys=True))
    return 0 if report["passed"] else 1

if __name__=="__main__":
    raise SystemExit(main())
