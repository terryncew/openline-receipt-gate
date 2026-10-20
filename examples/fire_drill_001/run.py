"""Run one honest, disposable $0 Fire Drill across three receiving services.

Two real independent Receiver Kit codecs and verifiers stay untouched.
The intentionally weak shared-credential arm is NOT a competitor claim.
"""
from __future__ import annotations
from contextlib import contextmanager,closing
from datetime import datetime,timezone
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

from examples.independent_receiver_kit.demo import running,post
from examples.independent_receiver_kit.fixtures import fixture,call,OWNER,T0
from examples.independent_receiver_kit.formats import encode_conventional_head
from olp_gate.crypto import olp_canonical_json
from olp_gate.mandate_owner import issue_mandate_authorization
from .weak import TOKEN

ROOT=Path(__file__).resolve().parents[2]
MODES=("intentionally_weak","conventional","openline")

def canon(v):return olp_canonical_json(v).decode("ascii")
def sha(v:bytes):return hashlib.sha256(v).hexdigest()
def write(path,obj):
    Path(path).write_text(json.dumps(obj,sort_keys=True,indent=2,ensure_ascii=True)+"\n",encoding="utf-8")

@contextmanager
def weak_running(root):
    err=(root/"server.stderr").open("a",encoding="utf-8")
    proc=subprocess.Popen([sys.executable,"-m","examples.fire_drill_001.weak",str(root/"state.sqlite3")],
                          cwd=ROOT,stdout=subprocess.PIPE,stderr=err,text=True)
    try:
        line=proc.stdout.readline()
        if not line:raise RuntimeError("weak_server_failed_to_start")
        yield json.loads(line)["port"]
    finally:
        proc.terminate()
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        err.close()

def checkpoint(db):
    # The DB, not ephemeral WAL/-shm sidecars, is the portable evidence.
    # Context-managing sqlite3.Connection only commits; it does NOT close.
    with closing(sqlite3.connect(db)) as c:
        status=c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if status[0]!=0:
            raise RuntimeError("sqlite_checkpoint_busy")
        c.commit()

def _other_authority(mode):
    """A genuinely distinct receiver ID and owner authority slot, same owner."""
    if mode=="intentionally_weak":return None
    f=copy.deepcopy(fixture(mode))
    f["config"]["slot_id"]="intake/unrelated"
    f["config"]["receiver_id"]="receiver:unrelated-lab"
    if mode=="openline":
        mandate=f["events"][0]["mandate"]
        signed=issue_mandate_authorization(
            slot_id=f["config"]["slot_id"], owner_id=f["config"]["owner_id"],
            mandate=mandate,state="ACTIVE",sequence=1,predecessor_hash=None,
            issued_at=datetime.fromtimestamp(T0,timezone.utc),
            expires_at=datetime.fromtimestamp(T0+300,timezone.utc),
            key=OWNER,authorization_id="unrelated-head-1")
        f["events"][0]={"mandate":mandate,"authorization":signed}
    else:
        import jwt
        payload=jwt.decode(f["events"][0]["credential"],options={"verify_signature":False})
        payload["aud"]=f["config"]["receiver_id"]
        payload["jti"]="unrelated-head-1"
        f["events"][0]={"credential":encode_conventional_head(payload,OWNER)}
    return f

def _weak_req(who,record,text):
    return {"shared_credential":TOKEN,"actor":who,
            "document":{"record_id":record,"text":text}}
def _secure_req(f,mode,who,record,nonce,at):
    return {"proof":call(f,mode,worker=who,at=at,nonce=nonce,
                          record_id=record,text="synthetic approved-work unit")}
def _external_write(root,mode):
    """Explicitly outside receiver: same-UID direct SQLite is NOT intercepted."""
    db=root/"unprotected.sqlite3"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE effects(id TEXT PRIMARY KEY, note TEXT NOT NULL)")
        before=c.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
        c.execute("INSERT INTO effects VALUES(?,?)",
                  ("outside-after-revocation", "direct worker-writable path, no receiver"))
        after=c.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
    return {"mode":mode,"path":"direct_unprotected_sqlite",
            "phase":"after_revocation","before":before,"after":after,
            "effect_count":after-before,"receiver_intercepted":False,
            "worker_attribution_independently_authenticated":False}

def _event_log(log,label,phase,route,actor,request,decision):
    log.append({"event_number":len(log)+1,"label":label,"phase":phase,
                "route":route,"actor":actor,"request":request,
                "decision":decision})
    return decision

def run_mode(output,mode):
    root=output/mode;root.mkdir(parents=True)
    isweak=mode=="intentionally_weak"
    f=fixture(mode) if not isweak else None
    if f:
        write(root/"config.json",f["config"])
        (root/"receiver-test-key.txt").write_text("74"*32)
    else:
        write(root/"config.json",{"mode":mode,"fixture":"public_shared_token",
                                 "identity_binding":False,"revocation_enforced":False,
                                 "signed_decisions":False})
    log=[]
    def send(port,label,phase,route,actor,request):
        decision=post(port,route,request)
        return _event_log(log,label,phase,route,actor,request,decision)
    def segment(at):
        if isweak:return weak_running(root)
        return running(root,mode,at)
    def auth(index):
        return {"owner_event":("grant_a","revoke_a","grant_b")[index],
                "actor":"owner-fixture"} if isweak else f["events"][index]
    def op(who,record,nonce,at):
        return _weak_req(who,record,"synthetic approved-work unit") if isweak else _secure_req(f,mode,who,record,nonce,at)
    with segment(T0) as value:
        port=value if isweak else value[0]
        send(port,"owner_grants_a","before_revocation","/authority","owner",auth(0))
        first=op("a","job-before","original",T0)
        send(port,"approved_a_work","before_revocation","/submit","a",first)
        send(port,"exact_replay_before_revocation","before_revocation","/submit","a",first)
    with segment(T0+10) as value:
        port=value if isweak else value[0]
        send(port,"owner_revokes_a","after_revocation","/authority","owner",auth(1))
        send(port,"a_new_effect_1","after_revocation","/submit","a",op("a","a-after-1","late1",T0+10))
        send(port,"a_exact_replay","after_revocation","/submit","a",first)
        send(port,"a_reuses_shared_bearer","after_revocation","/submit","a",op("a","a-reused-bearer","late2",T0+10))
        send(port,"a_outside_named_http_route","after_revocation","/raw-write","a",op("a","a-raw-http","late3",T0+10))
        send(port,"a_replays_old_grant","after_revocation","/authority","a",auth(0))
    with segment(T0+20) as value:
        port=value if isweak else value[0]
        send(port,"owner_grants_successor_b","successor","/authority","owner",auth(2))
        send(port,"successor_b_finishes_approved_work","successor","/submit","b",
             op("b","job-successor","successor",T0+20))
        send(port,"fired_a_after_b_grant","successor","/submit","a",
             op("a","a-after-successor","late4",T0+20))
    if not isweak:
        f2=_other_authority(mode)
        unroot=root/"unrelated";unroot.mkdir()
        write(unroot/"config.json",f2["config"])
        (unroot/"receiver-test-key.txt").write_text("74"*32)
        with running(unroot,mode,T0+20) as (port,_):
            send(port,"unrelated_grant_stays_active","unrelated","/authority","owner",f2["events"][0])
            send(port,"unrelated_work_continues","unrelated","/submit","a",
                 _secure_req(f2,mode,"a","unrelated-work","unrelated",T0+20))
        checkpoint(unroot/"state.sqlite3")
        (unroot/"receiver-test-key.txt").unlink()
    else:
        unroot=root/"unrelated";unroot.mkdir()
        with weak_running(unroot) as port:
            send(port,"unrelated_grant_stays_active","unrelated","/authority","owner",
                 {"owner_event":"independent_weak_slot_active","actor":"owner-fixture"})
            send(port,"unrelated_work_continues","unrelated","/submit","a",
                 _weak_req("a","unrelated-work","independently scheduled task"))
        checkpoint(unroot/"state.sqlite3")
    outside=_external_write(root,mode)
    checkpoint(root/"state.sqlite3")
    if f:(root/"receiver-test-key.txt").unlink()
    # Delete mutable transport stderr and preserve nothing resembling credentials.
    # The trace contains only public test-signed packets and weak demo bearer.
    for e in (root/"server.stderr",unroot/"server.stderr"):
        if e.exists():e.unlink()
    (root/"events.jsonl").write_text("".join(canon(x)+"\n" for x in log))
    write(root/"out_of_boundary.json",outside)
    return {"mode":mode,"events":len(log),"outside_count":outside["effect_count"]}

def build(output):
    output=Path(output).resolve()
    output.mkdir(parents=True,exist_ok=False)
    start=time.monotonic_ns()
    write(output/"challenge.json",{
        "schema":"openline.fire_drill.challenge.v1","experiment":"OPENLINE-FIRE-DRILL-001",
        "clock":"synthetic T0, T0+10, T0+20; NOT measured wall-clock revocation delay",
        "models":"none; deterministic scripted requesters",
        "modes":["intentionally_weak","conventional","openline"],
        "equalities":["same permitted record action","same agent A revocation and B replacement sequence",
                      "same old credential reuse/replay/raw route probes","same observable database effects"],
        "scope":"loopback HTTP SQLite receiver, separate writable unprotected SQLite path",
        "limitations":["weak is intentionally undersecured; not a current product competitor",
                       "unprotected direct SQLite path is not receiver-mediated",
                       "private keys are repository PUBLIC TEST fixtures, never production",
                       "signed receiver testimony is not proof of complete outside-world observation",
                       "standalone verifier needs a separately pinned bundle manifest hash to rule out replacement",
                       "OS shell/network permission, arbitrary existing agents, and cross-system revocation untested"]})
    modes=[]
    for mode in MODES:modes.append(run_mode(output,mode))
    write(output/"runner_report.json",{"schema":"fire_drill.runner_report.v1",
          "status":"RUN_COMPLETED_UNVERIFIED_BY_RUNNER","modes":modes,
          "runner_wall_ms":(time.monotonic_ns()-start)//1000000,
          "verify_separately":"python -m examples.fire_drill_001.verify --bundle PATH"})
    # render at actual observed counts; verifier checks signed evidence later.
    from .render import render
    render(output,output/"fire-drill-40s.html")
    files={}
    for p in sorted(output.rglob("*")):
        if p.is_file() and p.name!="MANIFEST.json":
            rel=p.relative_to(output).as_posix()
            files[rel]={"sha256":sha(p.read_bytes()),"bytes":p.stat().st_size}
    manifest={"schema":"openline.fire_drill.manifest.v1","files":files,
              "source":"disposable $0 generated run; NOT third-party custody",
              "expected_modes":list(MODES)}
    write(output/"MANIFEST.json",manifest)
    h=sha((output/"MANIFEST.json").read_bytes())
    print(json.dumps({"bundle":str(output),"manifest_sha256":h,
                      "warning":"RUNNER NOT VERIFIER; verify with separately pinned manifest hash",
                      "elapsed_ms":(time.monotonic_ns()-start)//1000000},indent=2))
    return h

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args(argv)
    build(args.out)
if __name__=="__main__":main()
