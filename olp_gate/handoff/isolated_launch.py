"""ADOPTION-002: root-owned, OS-separated, scripted successor launch.

Linux/root controller only, worker under a distinct unprivileged UID. This
is NOT a sandbox for arbitrary code, network effects, or cancellation. The
only launched worker is the bounded hard-coded synthetic continuation below.
Original ADOPTION-001 packet is explicitly not a launch authorization.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from olp_gate.crypto import olp_canonical_json,public_key_hex,sign_olp_body,verify_olp_signature
from olp_gate.handoff.adoption import snapshot,read_approval,hash_bytes

VERSION="openline.launch.authority.v1"
RECEIPT="openline.launch.receipt.v1"
WORKER=r'''
import hashlib,json,os,sys
from pathlib import Path
p=Path(sys.argv[1]);out=Path(sys.argv[2]);attack=Path(sys.argv[3])
packet=json.loads(p.read_text())
for path,hash_value in packet["file_sha256"].items():
    assert hashlib.sha256((p.parent/"project"/path).read_bytes()).hexdigest()==hash_value
# The descendant's only effect is a local synthetic report in its own scratch.
try:
    attack.write_text("worker attempting control write")
    control_modified=True
except OSError:
    control_modified=False
(out/"worker-result.json").write_text(json.dumps({
    "run":"scripted-codex", "source_head":packet["git_commit"],
    "requirements_seen":len(packet["approved_requirements"]),
    "tried_controller_write":True,"controller_write_succeeded":control_modified,
    "source_check":True, "runtime_effects":"synthetic-output-only"}))
if control_modified:sys.exit(77)
'''

def canonical(x):return olp_canonical_json(x)
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()
def load(path):return json.loads(Path(path).read_bytes())
def _json(path,value):
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(canonical(value)+b"\n");f.flush();os.fsync(f.fileno())
def _safe_admin_path(path, must_exist=True):
    p=Path(os.path.abspath(path))
    if not p.is_absolute():raise ValueError("absolute_path_required")
    parts=[p,*p.parents]
    for x in parts:
        if not x.exists():
            if must_exist:raise ValueError("owner_path_missing")
            continue
        s=os.lstat(x)
        if stat.S_ISLNK(s.st_mode):raise ValueError("symlink_in_control_path")
        if s.st_uid!=0:raise ValueError("control_not_root_owned")
        if x==p and (s.st_mode & 0o077):
            raise ValueError("control_accessible_to_worker")
        if (s.st_mode & 0o022) and not (s.st_mode & stat.S_ISVTX and s.st_uid==0):
            raise ValueError("writable_control_ancestor")
    return p

def _root_only():
    if os.name!="posix" or sys.platform!="linux" or os.geteuid()!=0:
        raise ValueError("BLOCKED_OS_ROOT_SEPARATION_REQUIRED")

def _worker(uid):
    if not isinstance(uid,int) or uid in (0,os.geteuid()) or uid<100:
        raise ValueError("distinct_unprivileged_uid_required")
    p=pwd.getpwuid(uid)
    if p.pw_uid==0 or p.pw_gid==0:raise ValueError("worker_identity_privileged")
    return p

def _owner_public(pin):
    pin=_safe_admin_path(pin)
    d=load(pin)
    if set(d)!={"schema","owner_public_key"} or d["schema"]!="openline.launch.pin.v1":
        raise ValueError("invalid_owner_pin")
    return d["owner_public_key"]

def _verify_signed(value,public):
    sig=value.get("signature") if isinstance(value,dict) else None
    if not isinstance(sig,dict) or sig.get("public_key")!=public:
        raise ValueError("untrusted_signer")
    ok,reason=verify_olp_signature(value)
    if not ok:raise ValueError("signature_invalid:"+str(reason))

def _read_state(control,pin):
    root=_owner_public(pin)
    rows=(control/"authority.jsonl").read_text().splitlines()
    if not rows:raise ValueError("authority_history_empty")
    previous=None
    for i,line in enumerate(rows):
        event=json.loads(line)
        _verify_signed(event,root)
        if (event.get("schema")!=VERSION or event.get("sequence")!=i
                or event.get("previous")!=(digest(previous) if previous else None)):
            raise ValueError("authority_history_invalid")
        if previous and event.get("checkpoint_sha256")!=previous.get("checkpoint_sha256"):
            raise ValueError("authority_checkpoint_replaced")
        if previous and previous["standing"]=="REVOKED" and event["standing"]!="REVOKED":
            raise ValueError("revocation_resurrected")
        if event.get("standing") not in ("ACTIVE","REVOKED"):
            raise ValueError("authority_standing_invalid")
        previous=event
    anchor=load(control/"frontier.json")
    if anchor!={"sequence":previous["sequence"],"hash":digest(previous)}:
        raise ValueError("authority_rollback_detected")
    return previous

def _seal_receipt(control,pin,status,reason,details=None):
    root=_owner_public(pin)
    key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(load(control/"owner-key.hex")))
    if public_key_hex(key)!=root:raise ValueError("owner_private_key_not_pinned")
    seq=len(list((control/"receipts").glob("*.json")))
    record=sign_olp_body({"schema":RECEIPT,"seq":seq,"decision":status,"reason":reason,
                          "time_ns":time.time_ns(),"facts":details or {}},key)
    _json(control/"receipts"/("%06d.json"%seq),record)
    return record

def _lock(control):
    fd=os.open(str(control/"controller.lock"),os.O_RDWR|os.O_NOFOLLOW)
    fcntl.flock(fd,fcntl.LOCK_EX)
    return fd

def owner_init(repo,approval,control,pin,uid):
    _root_only();_worker(uid)
    repo=Path(repo).resolve()
    ctl=Path(os.path.abspath(control))
    pin=Path(os.path.abspath(pin))
    if ctl.exists() or pin.exists():raise ValueError("existing_authority_not_overwritten")
    if repo==ctl or repo in ctl.parents:raise ValueError("control_inside_repo")
    if ctl.parent!=pin.parent or ctl.name==pin.name:
        raise ValueError("pin_must_be_separate_from_control")
    _safe_admin_path(ctl.parent)
    auth,approval_sha=read_approval(approval)
    head,files=snapshot(repo)
    key=Ed25519PrivateKey.generate()
    ctl.mkdir(mode=0o700)
    (ctl/"receipts").mkdir(mode=0o700)
    _json(ctl/"owner-key.hex",key.private_bytes_raw().hex())
    _json(pin,{"schema":"openline.launch.pin.v1","owner_public_key":public_key_hex(key)})
    os.chmod(pin,0o600)
    (ctl/"controller.lock").write_bytes(b"")
    os.chmod(ctl/"controller.lock",0o600)
    packet={"schema":"openline.launch.checkpoint.v1",
            "git_commit":head,"file_sha256":files,
            "approved_task_id":auth["task_id"],
            "approved_requirements":auth["requirements"],
            "approved_tests":auth["tests"],
            "unfinished_asserted":auth["unfinished"],
            "notes_unverified":auth["notes"],
            "approval_sha256":approval_sha,
            "worker_uid":uid}
    signed=sign_olp_body(packet,key)
    _json(ctl/"checkpoint.json",signed)
    event=sign_olp_body({"schema":VERSION,"sequence":0,"previous":None,
                        "checkpoint_sha256":digest(signed),"standing":"ACTIVE",
                        "action":"scripted-successor"},key)
    (ctl/"authority.jsonl").write_bytes(canonical(event)+b"\n")
    os.chmod(ctl/"authority.jsonl",0o600)
    _json(ctl/"frontier.json",{"sequence":0,"hash":digest(event)})
    return {"decision":"OWNER_INITIALIZED","checkpoint":head,
            "owner_public_key":public_key_hex(key),"worker_uid":uid}

def revoke(control,pin):
    _root_only()
    ctl=_safe_admin_path(control);_safe_admin_path(pin)
    fd=_lock(ctl)
    try:
        old=_read_state(ctl,pin)
        if old["standing"]=="REVOKED":raise ValueError("already_revoked")
        key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(load(ctl/"owner-key.hex")))
        event=sign_olp_body({"schema":VERSION,"sequence":old["sequence"]+1,
                             "previous":digest(old),"checkpoint_sha256":old["checkpoint_sha256"],
                             "standing":"REVOKED","action":old["action"]},key)
        with (ctl/"authority.jsonl").open("ab") as out:
            out.write(canonical(event)+b"\n");out.flush();os.fsync(out.fileno())
        temp=ctl/"frontier.new"
        _json(temp,{"sequence":event["sequence"],"hash":digest(event)})
        os.replace(temp,ctl/"frontier.json")
        receipt=_seal_receipt(ctl,pin,"REVOKED","owner_revocation",
                              {"sequence":event["sequence"]})
        return {"decision":"REVOKED","receipt_sha256":digest(receipt)}
    finally:os.close(fd)

def _snapshot_copy(repo,checkpoint,stage):
    h,files=snapshot(repo)
    if h!=checkpoint["git_commit"] or files!=checkpoint["file_sha256"]:
        raise ValueError("original_checkpoint_changed")
    root=stage/"project"
    root.mkdir(mode=0o755)
    for name,expected in sorted(files.items()):
        source=repo/name
        target=root/name
        target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        if source.is_symlink() or not source.is_file():
            raise ValueError("checkpoint_path_invalid")
        b=source.read_bytes()
        if hash_bytes(b)!=expected:raise ValueError("checkpoint_changed_during_copy")
        target.write_bytes(b)
        target.chmod(0o444)
    for d in sorted((x for x in root.rglob("*") if x.is_dir()),reverse=True):
        d.chmod(0o555)
    root.chmod(0o555)
    # The worker acts on this frozen root-owned snapshot, not the mutable repo.
    h2,f2=snapshot(repo)
    if h2!=h or f2!=files:raise ValueError("checkpoint_changed_during_snapshot")
    return h

def launch(repo,control,pin,uid,*,before_spawn=None,mode="openline"):
    """The conventional comparator uses exactly the same hard OS and source checks."""
    _root_only();p=_worker(uid)
    ctl=_safe_admin_path(control);_safe_admin_path(pin)
    repo=Path(repo).resolve()
    fd=_lock(ctl)
    stage=None
    try:
        state=_read_state(ctl,pin)
        packet=load(ctl/"checkpoint.json")
        _verify_signed(packet,_owner_public(pin))
        if digest(packet)!=state["checkpoint_sha256"]:
            raise ValueError("old_or_replaced_checkpoint")
        if packet.get("worker_uid")!=uid:raise ValueError("wrong_worker_identity")
        if state["standing"]!="ACTIVE":raise ValueError("owner_revoked")
        stage=Path(tempfile.mkdtemp(prefix="openline-adoption002-"))
        os.chmod(stage,0o755)
        _snapshot_copy(repo,packet,stage)
        _json(stage/"handoff.json",{k:v for k,v in packet.items() if k not in ("signature","payload_hash")})
        os.chmod(stage/"handoff.json",0o444)
        scratch=stage/"output";scratch.mkdir(mode=0o700)
        os.chown(scratch,p.pw_uid,p.pw_gid)
        # Revalidate under the exclusive controller lock, and permit a test
        # mutation hook before the final checkpoint check.
        if before_spawn is not None:before_spawn()
        if _read_state(ctl,pin)!=state:raise ValueError("authority_changed_before_spawn")
        h,files=snapshot(repo)
        if h!=packet["git_commit"] or files!=packet["file_sha256"]:
            raise ValueError("checkpoint_changed_before_spawn")
        attack_path=ctl/"authority.jsonl"
        def become_worker():
            os.setgroups([]);os.setgid(p.pw_gid);os.setuid(p.pw_uid)
        start=time.perf_counter_ns()
        worker=subprocess.run([sys.executable,"-I","-c",WORKER,
                               str(stage/"handoff.json"),str(scratch),str(attack_path)],
                              cwd=stage,stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              timeout=12,start_new_session=True,preexec_fn=become_worker,
                              env={"PATH":"/usr/bin:/bin","PYTHONDONTWRITEBYTECODE":"1",
                                   "HOME":str(scratch)})
        runtime_ms=round((time.perf_counter_ns()-start)/1e6,2)
        result=load(scratch/"worker-result.json") if (scratch/"worker-result.json").exists() else {}
        if worker.returncode!=0 or result.get("controller_write_succeeded") is not False:
            raise ValueError("worker_failed_or_control_modified")
        receipt=_seal_receipt(ctl,pin,"LAUNCHED","bounded_scripted_worker_exited",
                              {"checkpoint_sha256":digest(packet),"git_commit":h,
                               "worker_uid":uid,"worker_exit":worker.returncode,
                               "runtime_ms":runtime_ms,"worker_control_write_blocked":True,
                               "mode":mode})
        return {"decision":"LAUNCHED","receipt_sha256":digest(receipt),
                "worker_exit":0,"worker_uid":uid,"runtime_ms":runtime_ms}
    except (ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        receipt=_seal_receipt(ctl,pin,"REFUSED",str(error),
                              {"mode":mode,"worker_uid":uid})
        return {"decision":"REFUSED","reason":str(error),"receipt_sha256":digest(receipt)}
    finally:
        if stage is not None:shutil.rmtree(stage,ignore_errors=True)
        os.close(fd)

def verify_receipt(record,pin):
    _verify_signed(record,_owner_public(pin))
    if record.get("schema")!=RECEIPT:raise ValueError("receipt_schema_invalid")
    return True

def main(argv=None):
    p=argparse.ArgumentParser(description="Owner-isolated $0 scripted launcher, not real Codex")
    subs=p.add_subparsers(dest="cmd",required=True)
    i=subs.add_parser("owner-init")
    i.add_argument("--repo",required=True);i.add_argument("--approval",required=True)
    i.add_argument("--control",required=True);i.add_argument("--pin",required=True)
    i.add_argument("--worker-uid",type=int,required=True)
    r=subs.add_parser("owner-revoke")
    r.add_argument("--control",required=True);r.add_argument("--pin",required=True)
    l=subs.add_parser("launch")
    l.add_argument("--repo",required=True);l.add_argument("--control",required=True)
    l.add_argument("--pin",required=True);l.add_argument("--worker-uid",type=int,required=True)
    l.add_argument("--baseline",action="store_true")
    a=p.parse_args(argv)
    try:
        if a.cmd=="owner-init":v=owner_init(a.repo,a.approval,a.control,a.pin,a.worker_uid)
        elif a.cmd=="owner-revoke":v=revoke(a.control,a.pin)
        else:v=launch(a.repo,a.control,a.pin,a.worker_uid,
                      mode="conventional" if a.baseline else "openline")
    except (ValueError,OSError,KeyError,subprocess.CalledProcessError) as e:
        v={"decision":"BLOCKED","reason":str(e)}
    print(json.dumps(v,sort_keys=True))
    return 0 if v["decision"] in ("LAUNCHED","OWNER_INITIALIZED","REVOKED") else 2
if __name__=="__main__":raise SystemExit(main())
