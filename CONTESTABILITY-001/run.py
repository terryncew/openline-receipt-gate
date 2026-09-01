from pathlib import Path
import hashlib,json
from src.contestability_001.core import ContestabilityReceiver,sign_event
KEY=b"contestability-001-fixture-key"
BASE={"schema":"foreign.contestability.fixture.v1","authorization_id":"auth-001","action_digest":"sha256:action-001","forum":"forum.example/review","standing_policy_digest":"sha256:standing-policy-v1","effect_policy_digest":"sha256:effect-policy-v1"}
def event(i,state,**extra): return sign_event(dict(BASE,event_id=i,state=state,**extra),KEY)
def cases():
    out=[]
    r=ContestabilityReceiver(KEY); out.append(("filed_preserves",r.ingest(event("e1","filed")),{"D1":"PRESERVE","D1A":"PRESERVE","D2":"PRESERVE"}))
    r=ContestabilityReceiver(KEY); out.append(("accepted_quarantines",r.ingest(event("e2","accepted")),{"D1":"QUARANTINE","D1A":"QUARANTINE","D2":"PRESERVE"}))
    r=ContestabilityReceiver(KEY); out.append(("applied_reopens",r.ingest(event("e3","applied")),{"D1":"REOPEN","D1A":"REOPEN","D2":"PRESERVE"}))
    r=ContestabilityReceiver(KEY); x=event("e4","applied"); x["state"]="filed"; out.append(("tamper_rejected",r.ingest(x),"INVALID_SIGNATURE"))
    r=ContestabilityReceiver(KEY); out.append(("auth_substitution",r.ingest(event("e5","applied",authorization_id="auth-evil")),"AUTHORIZATION_MISMATCH"))
    r=ContestabilityReceiver(KEY); out.append(("forum_rejected",r.ingest(event("e6","applied",forum="forum.evil")),"UNRECOGNIZED_FORUM"))
    r=ContestabilityReceiver(KEY); x=event("e7","accepted"); r.ingest(x); out.append(("replay_rejected",r.ingest(x),"REPLAY"))
    r=ContestabilityReceiver(KEY); r.ingest(event("e8a","applied")); out.append(("ordering_regression",r.ingest(event("e8b","filed")),"ORDERING_REGRESSION"))
    r=ContestabilityReceiver(KEY); out.append(("foreign_directive_ignored",r.ingest(event("e9","filed",requested_local_consequence="REOPEN_ALL")),{"D1":"PRESERVE","D1A":"PRESERVE","D2":"PRESERVE"}))
    r=ContestabilityReceiver(KEY); out.append(("unrelated_auth",r.ingest(event("e10","applied",authorization_id="auth-other")),"AUTHORIZATION_MISMATCH"))
    return out
if __name__=='__main__':
    rows=[]; passed=0
    for name,res,expect in cases():
        ok=(res["consequences"]==expect and res["evidence_status"]=="ADMIT") if isinstance(expect,dict) else (res["evidence_status"]=="REJECT" and res["reason"]==expect)
        rows.append({"case":name,"pass":ok,"result":res}); passed+=int(ok)
    summary={"schema":"openline.contestability.summary.v1","cases_total":len(rows),"cases_passed":passed,"independent_reopens":sum(1 for x in rows if x["result"]["consequences"]["D2"]=="REOPEN"),"disposition":"PASS" if passed==len(rows) else "FAIL","cases":rows}
    out=Path('artifacts-confirmatory'); out.mkdir(exist_ok=True)
    sb=(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode(); (out/'summary.json').write_bytes(sb)
    receipt={"schema":"openline.contestability.receipt.v1","protocol_sha256":hashlib.sha256(Path('PREREGISTRATION.md').read_bytes()).hexdigest(),"summary_sha256":hashlib.sha256(sb).hexdigest(),"claim":"foreign contestation remains evidence; receiver owns consequence assignment","disposition":summary["disposition"]}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    print(f'{passed}/{len(rows)} cases passed; disposition={summary["disposition"]}')
    raise SystemExit(0 if summary['disposition']=='PASS' else 1)
