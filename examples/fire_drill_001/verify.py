"""Independent, read-only Fire Drill verifier. Does NOT import runner/weak server.

Checks every bundle byte against manifest; existing receiver-kit independently
replays both signed recipient ledgers and persistent local SQLite effects.
Weak-mode effects are merely local observations: NOT cryptographic proof.
"""
from __future__ import annotations
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from olp_gate.crypto import olp_canonical_json,strict_json_loads
from examples.independent_receiver_kit.fixtures import fixture
from examples.independent_receiver_kit.verify import verify as verify_receiver

MODES=("intentionally_weak","conventional","openline")
A_POST=("a_new_effect_1","a_reuses_shared_bearer",
        "a_outside_named_http_route","fired_a_after_b_grant")
SECURE={"owner_grants_a":"ACCEPT","approved_a_work":"ALLOW","exact_replay_before_revocation":"DENY",
        "owner_revokes_a":"ACCEPT","a_new_effect_1":"DENY",
        "a_exact_replay":"DENY","a_reuses_shared_bearer":"DENY",
        "a_outside_named_http_route":"DENY","a_replays_old_grant":"DENY",
        "owner_grants_successor_b":"ACCEPT",
        "successor_b_finishes_approved_work":"ALLOW",
        "fired_a_after_b_grant":"DENY",
        "unrelated_grant_stays_active":"ACCEPT","unrelated_work_continues":"ALLOW"}
WEAK={**SECURE,**{k:"ALLOW" for k in A_POST},
      "a_replays_old_grant":"ACCEPT"}
OTHER={"slot_id":"intake/unrelated","receiver_id":"receiver:unrelated-lab"}

def sha(data):return hashlib.sha256(data).hexdigest()
def canon(x):return olp_canonical_json(x).decode("ascii")
def read_json(path):return strict_json_loads(Path(path).read_text(encoding="utf-8"))
def require(condition,code):
    if not condition:raise ValueError(code)

def manifest_check(root,expected):
    manifest_path=root/"MANIFEST.json"
    actual_sha=sha(manifest_path.read_bytes())
    if expected is not None:require(actual_sha==expected,"out_of_band_manifest_hash_mismatch")
    manifest=read_json(manifest_path)
    require(manifest.get("schema")=="openline.fire_drill.manifest.v1","manifest_schema_wrong")
    require(manifest.get("expected_modes")==list(MODES),"manifest_modes_wrong")
    files=manifest.get("files")
    require(isinstance(files,dict) and files,"manifest_empty")
    seen=[]
    for path in sorted(root.rglob("*")):
        if path.is_symlink():raise ValueError("bundle_symlink_forbidden")
        if path.is_file() and path.name!="MANIFEST.json":
            seen.append(path.relative_to(root).as_posix())
    require(set(files)==set(seen),"missing_extra_or_unlisted_bundle_file")
    for rel,metadata in files.items():
        require(isinstance(rel,str) and rel and not rel.startswith("/") and ".." not in rel.split("/"),
                "invalid_manifest_path")
        p=(root/rel).resolve()
        require(root==p or root in p.parents,"manifest_path_escape")
        data=p.read_bytes()
        require(metadata=={"sha256":sha(data),"bytes":len(data)},"bundle_file_integrity_mismatch:"+rel)
    return actual_sha

def query(root,mode):
    db=root/mode/"state.sqlite3"
    with closing(sqlite3.connect(db.as_uri()+"?mode=ro",uri=True)) as c:
        c.row_factory=sqlite3.Row
        if mode=="intentionally_weak":
            rows=[dict(x) for x in c.execute("SELECT seq,route,request,body FROM decisions ORDER BY seq")]
            documents=[dict(x) for x in c.execute("SELECT * FROM documents ORDER BY id")]
        else:
            rows=[dict(x) for x in c.execute("SELECT seq,request,body FROM decisions ORDER BY seq")]
            documents=[dict(x) for x in c.execute("SELECT * FROM documents ORDER BY id")]
    return rows,documents

def verify_mode(root,mode):
    rows,documents=query(root,mode)
    log=[strict_json_loads(line) for line in (root/mode/"events.jsonl").read_text().splitlines()]
    require(len(log)==len(rows)==14,"missing_duplicate_or_extra_http_decision:"+mode)
    expected=WEAK if mode=="intentionally_weak" else SECURE
    labels=[x["label"] for x in log]
    require(set(labels)==set(expected) and len(labels)==len(expected),"scenario_coverage_invalid:"+mode)
    for n,(ev,row) in enumerate(zip(log,rows),start=1):
        require(ev["event_number"]==n==row["seq"],"decision_sequence_wrong:"+mode)
        require(ev["label"] in expected and ev["decision"]["verdict"]==expected[ev["label"]],
                "unexpected_case_outcome:"+mode+":"+ev["label"])
        if mode=="intentionally_weak":
            require(ev["route"]==row["route"] and ev["request"]==read_inline(row["request"]),
                    "weak_row_request_mismatch")
        else:
            envelope=read_inline(row["request"])
            require(envelope=={"path":ev["route"],"request":ev["request"]},
                    "signed_row_request_mismatch")
        require(ev["decision"]==read_inline(row["body"]),"reported_decision_differs_from_receiver_db")
    if mode=="intentionally_weak":
        require(len(documents)==6,"weak_expected_persisted_documents_missing")
        cryptographic="NOT_AVAILABLE_UNSIGNED_WEAK_TEACHING_FIXTURE"
    else:
        standard=fixture(mode)["config"]
        require(read_json(root/mode/"config.json")==standard,"unexpected_main_trust_root")
        result=verify_receiver(root/mode/"state.sqlite3",standard,mode)
        require(result.get("valid") is True,"signed_receiver_verification_failed:"+str(result.get("errors")))
        require(result.get("counts",{}).get("documents")==len(documents),"db_counts_disagree")
        other={**standard,**OTHER}
        require(read_json(root/mode/"unrelated"/"config.json")==other,"unrelated_trust_root_changed")
        other_result=verify_receiver(root/mode/"unrelated"/"state.sqlite3",other,mode)
        require(other_result.get("valid") is True,"unrelated_signed_receiver_verification_failed:"+str(other_result.get("errors")))
        cryptographic="EXISTING_RECEIVER_KIT_SIGNED_RECEIPTS_AND_EFFECT_REPLAY_VALID"
    with closing(sqlite3.connect((root/mode/"unrelated"/"state.sqlite3").as_uri()+"?mode=ro",uri=True)) as c:
        other_count=c.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    require(other_count==1,"unrelated_permission_did_not_continue")
    # Independent direct-effect store: all modes have the same intentionally
    # unguarded SQLite path. Check actual row, without pretending it was gated.
    with closing(sqlite3.connect((root/mode/"unprotected.sqlite3").as_uri()+"?mode=ro",uri=True)) as c:
        outside=c.execute("SELECT id,note FROM effects").fetchall()
    require(len(outside)==1 and outside[0][0]=="outside-after-revocation",
            "outside_effect_not_recorded")
    outside_report=read_json(root/mode/"out_of_boundary.json")
    require(outside_report["effect_count"]==1 and not outside_report["receiver_intercepted"],
            "outside_path_misrepresented")
    protected_after=sum(ev["decision"]["documents_after"]-ev["decision"]["documents_before"]
                        for ev in log if ev["label"] in A_POST)
    denied_after=sum(1 for ev in log if ev["label"] in A_POST and ev["decision"]["verdict"]=="DENY")
    continued=[x["id"] for x in documents]
    require("job-before" in continued and "job-successor" in continued,
            "approved_or_successor_work_missing")
    return {"mode":mode,"protected_unauthorized_effects":protected_after,
            "protected_denied_old_agent_attempts":denied_after,
            "post_revocation_old_agent_attempts":len(A_POST),
            "retained_original_work":True,"successor_work":True,
            "unrelated_slot_effects":other_count,
            "outside_receiver_effects":len(outside),
            "outside_effect_custody":"LOCAL_SQLITE_ONLY_UNAUTHENTICATED",
            "receiver_cryptographic_evidence":cryptographic,
            "total_protected_effect_rows":len(documents),
            "attestation_limits":["Weak HTTP responses and all external effects have no signed origin",
                                  "Recorded local calls are not arbitrary-agent security enforcement"]}

def read_inline(text):return strict_json_loads(text)

def verify(root,expected_sha256=None):
    root=Path(root).resolve()
    report={"verdict":"BLOCKED","manifest_sha256":None,"modes":{},"errors":[],
            "claims_not_tested":["real Claude/Codex or third-party agents","OS shell/network or privileged DB access restrictions",
                                 "revocation withheld from receiver","unknown private destinations",
                                 "external deployment or commercial superiority"],
            "custody_limit":"Bundle created by scripted runner; external hash pin and receiver signer custody must be trusted independently."}
    try:
        h=manifest_check(root,expected_sha256)
        report["manifest_sha256"]=h
        challenge=read_json(root/"challenge.json")
        require(challenge.get("schema")=="openline.fire_drill.challenge.v1","challenge_schema_invalid")
        for mode in MODES:report["modes"][mode]=verify_mode(root,mode)
        require(report["modes"]["intentionally_weak"]["protected_unauthorized_effects"]>0,
                "weak_teaching_fixture_not_showing_intended_gap")
        for mode in ("conventional","openline"):
            require(report["modes"][mode]["protected_unauthorized_effects"]==0,"secured_receiver_post_revocation_effect")
        # Both secure modes must be treated as full competent peers, not as
        # a rigged win for one product.
        require(report["modes"]["conventional"]["protected_denied_old_agent_attempts"]==
                report["modes"]["openline"]["protected_denied_old_agent_attempts"],
                "strong_baseline_unfair_divergence")
        report["verdict"]="PASS_SCOPED_EVIDENCE"
    except (ValueError,KeyError,TypeError,OSError,sqlite3.Error) as exc:
        report["errors"].append(str(exc) or type(exc).__name__)
    return report

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle",type=Path,required=True)
    p.add_argument("--expected-sha256",help="Owner's independently supplied MANIFEST.json SHA-256")
    args=p.parse_args(argv)
    result=verify(args.bundle,args.expected_sha256)
    print(json.dumps(result,sort_keys=True,indent=2))
    return 0 if result["verdict"]=="PASS_SCOPED_EVIDENCE" else 2
if __name__=="__main__":raise SystemExit(main())
