"""openline handoff: receiver-checked Git checkpoint -> scripted successor packet.

No model is launched. No external action or shell sandbox is provided.
The owner/trusted controller must protect the separate control directory.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from olp_gate.crypto import olp_canonical_json, public_key_hex, sign_olp_body, verify_olp_signature

SCHEMA="openline.adoption.handoff.v1"
def canonical(x): return olp_canonical_json(x)
def hash_bytes(x): return hashlib.sha256(x).hexdigest()
def digest(x): return hash_bytes(canonical(x))
def load(path): return json.loads(Path(path).read_text(encoding="utf-8"))
def write_new(path,obj,*,mode=0o600):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as f:
        os.chmod(path,mode)
        f.write(json.dumps(obj,sort_keys=True,indent=2)+"\n")
        f.flush();os.fsync(f.fileno())
def git(repo,*cmd):
    x=subprocess.run(["git","-C",str(repo),*cmd],capture_output=True,check=True)
    return x.stdout
def snapshot(repo):
    repo=Path(repo).resolve()
    if git(repo,"status","--porcelain","--untracked-files=normal").strip():
        raise ValueError("dirty_checkpoint_commit_or_remove_untracked_files")
    sha=git(repo,"rev-parse","HEAD").decode().strip()
    names=git(repo,"ls-files","-z").split(b"\x00")
    files={}
    for name in names:
        if not name:continue
        path=name.decode("utf-8")
        actual=repo/path
        if actual.is_symlink() or not actual.is_file() or repo not in actual.resolve().parents:
            raise ValueError("unsafe_tracked_path")
        files[path]=hash_bytes(actual.read_bytes())
    if not files:raise ValueError("empty_repository")
    return sha,files

def read_approval(path):
    raw=Path(path).read_bytes()
    data=json.loads(raw)
    if set(data)!={"schema","task_id","requirements","tests","unfinished","notes"} or data["schema"]!="openline.approved_job.v1":
        raise ValueError("approved_job_shape_invalid")
    if not isinstance(data["requirements"],list) or not data["requirements"] or any(not isinstance(s,str) or not s for s in data["requirements"]):
        raise ValueError("approved_requirements_invalid")
    if not isinstance(data["unfinished"],list) or not isinstance(data["notes"],list):
        raise ValueError("approved_outstanding_invalid")
    if not isinstance(data["tests"],list) or not data["tests"]:
        raise ValueError("missing_checks")
    if not isinstance(data["task_id"],str) or not data["task_id"]:
        raise ValueError("missing_task_id")
    return data,hash_bytes(raw)

def authorized_tests(repo,defs):
    items=[]
    for item in defs:
        if not isinstance(item,dict) or set(item)!={"name","argv"} or not isinstance(item["name"],str) or not item["name"]:
            raise ValueError("test_definition_invalid")
        args=item["argv"]
        # No arbitrary commands, arguments, shell or tool installation. Python
        # unittest still runs repo code; this is NOT a sandbox.
        if (not isinstance(args,list) or len(args)<3 or args[0] not in ("python3","python")
                or args[1:3]!=["-m","unittest"]
                or any(not isinstance(x,str) or not x or x.startswith("-") and x not in ("-v","-q")
                       for x in args[3:])):
            raise ValueError("only_python_unittest_tests_supported")
        start=time.perf_counter()
        try:
            run=subprocess.run([sys.executable,*args[1:]],cwd=repo,timeout=20,
                               capture_output=True,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},
                               shell=False)
            code=run.returncode
            output=run.stdout+run.stderr
        except subprocess.TimeoutExpired as exc:
            code=124;output=(exc.stdout or b"")+(exc.stderr or b"")
        items.append({"name":item["name"],"argv":args,"exit_code":code,
                      "output_sha256":hash_bytes(output),
                      "elapsed_ms":round((time.perf_counter()-start)*1000),
                      "verified":"PROCESS_EXECUTED_ON_CHECKPOINT",
                      "interpretation":"Exit code only; not proof of every software claim"})
    return items

def check_root_separation(repo,control):
    repo=Path(repo).resolve()
    control=Path(control).resolve()
    if control==repo or repo in control.parents:
        raise ValueError("control_must_be_outside_worker_repository")
    return repo,control

def prepare(repo,control,approval):
    repo,control=check_root_separation(repo,control)
    if control.exists() and any(control.iterdir()):
        raise ValueError("control_must_be_empty_for_initial_prepare")
    data,approved_sha=read_approval(approval)
    head,files=snapshot(repo)
    controls=authorized_tests(repo,data["tests"])
    control.mkdir(parents=True,exist_ok=False)
    key=Ed25519PrivateKey.generate()
    seed=key.private_bytes_raw().hex()
    private=control/"receiver-private-key"
    with private.open("x") as f:
        os.chmod(private,0o600);f.write(seed+"\n");f.flush();os.fsync(f.fileno())
    public=public_key_hex(key)
    write_new(control/"trusted-receiver.json",{"public_key":public},mode=0o600)
    payload={"schema":SCHEMA,"approved_task_id":data["task_id"],
             "approved_requirements":data["requirements"],
             "approval_file_sha256":approved_sha,
             "git_commit":head,"file_sha256":files,
             "receiver_executed_tests":controls,
             "unfinished_asserted":data["unfinished"],
             "notes_unverified":data["notes"],
             "revocation_sequence":0,
             "permissions":{"continuation_packet_only":True,
                            "runtime_tool_enforcement":False,
                            "model_credentials_transfer":False}}
    signed=sign_olp_body(payload,key)
    write_new(control/"handoff.json",signed)
    write_new(control/"standing.json",{"revoked":False,"sequence":0,"reason":None})
    return {"verdict":"PREPARED","control_dir":str(control),"git_commit":head,
            "checks":[(x["name"],x["exit_code"]) for x in controls],
            "handoff_sha256":digest(signed)}

def continue_to(repo,control,agent):
    if agent not in ("codex","claude","scripted"):
        raise ValueError("unsupported_successor")
    repo,control=check_root_separation(repo,control)
    packet=load(control/"handoff.json")
    trust=load(control/"trusted-receiver.json")
    if packet.get("schema")!=SCHEMA or packet.get("signature",{}).get("public_key")!=trust.get("public_key"):
        raise ValueError("untrusted_checkpoint_signer")
    ok,reason=verify_olp_signature(packet)
    if not ok:raise ValueError("signed_handoff_invalid:"+str(reason))
    standing=load(control/"standing.json")
    if standing.get("revoked") is not False or standing.get("sequence")!=packet["revocation_sequence"]:
        raise ValueError("permission_revoked_or_stale")
    head,files=snapshot(repo)
    if head!=packet["git_commit"] or files!=packet["file_sha256"]:
        raise ValueError("git_checkpoint_mismatch")
    # The approval file hash is frozen into the signed handoff; the controller
    # verifies current approval file only when explicitly supplied at prepare.
    output={"schema":"openline.adoption.continuation.v1",
            "agent":agent,"owner_approved_requirements":packet["approved_requirements"],
            "verified_git_commit":head,"verified_file_hashes":files,
            "observed_test_exit_codes":packet["receiver_executed_tests"],
            "unfinished_asserted_not_verified":packet["unfinished_asserted"],
            "notes_unverified":packet["notes_unverified"],
            "permission_standing":"CURRENT_FOR_PACKET_ONLY",
            "runtime_permission":"NONE",
            "handoff_sha256":digest(packet),
            "warning":"This packet does not constrain Codex/Claude shell or filesystem access."}
    name=control/("continuation-"+agent+".json")
    write_new(name,output)
    return {"verdict":"CONTINUATION_PACKET_VERIFIED",
            "packet":str(name),"agent_invoked":False,"successor":agent,
            "runtime_enforcement":False}

def main(argv=None):
    parser=argparse.ArgumentParser(prog="openline",description="Verified synthetic developer handoff")
    root=parser.add_subparsers(dest="section",required=True)
    hand=root.add_parser("handoff")
    ops=hand.add_subparsers(dest="verb",required=True)
    prep=ops.add_parser("prepare")
    prep.add_argument("--repo",required=True);prep.add_argument("--control",required=True)
    prep.add_argument("--approval",required=True)
    cont=ops.add_parser("continue")
    cont.add_argument("--repo",required=True);cont.add_argument("--control",required=True)
    cont.add_argument("--agent",required=True)
    args=parser.parse_args(argv)
    try:
        result=(prepare(args.repo,args.control,args.approval) if args.verb=="prepare"
                else continue_to(args.repo,args.control,args.agent))
    except (ValueError,KeyError,OSError,subprocess.CalledProcessError) as exc:
        print(json.dumps({"verdict":"BLOCKED","reason":str(exc)}));return 2
    print(json.dumps(result,sort_keys=True));return 0

if __name__=="__main__":raise SystemExit(main())
