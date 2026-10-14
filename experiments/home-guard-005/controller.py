"""HOME-GUARD-005 experimental receiver-side nftables recovery controller.

Both OLP and conventional arms use the SAME signed owner policy, witness,
trust roots, rules and fail-closed semantics. Only receipt format differs.
All firewall operations MUST run within hg5-fw disposable namespace.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
HG1=REPO/"experiments/home-guard-001"
for x in (str(HG1),str(REPO)):
    if x not in sys.path: sys.path.insert(0,x)
from home_guard import keys
from olp_gate.crypto import sign_olp_body,verify_olp_signature,strict_json_loads

OWNER_PUB="bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5"
OWNER_POLICY_ID="hg3-isolated-veth-network"
OWNER_SCHEMA="openline.home_guard.firewall_policy.v1"
WITNESS_SCHEMA="hg5.witness.current.v1"


def canon(body):
    return json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")


def execute(*args,input=None):
    return subprocess.run(list(args),input=input,capture_output=True,check=True,timeout=6)


def kernel_rules():
    return execute("nft","-a","list","chain","inet","hg5","forward").stdout.decode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def kernel_snapshot():
    state=kernel_rules()
    return state,sha(state.encode())


def rules_for(allow):
    # This batch is committed atomically; the pre-existing base chain has
    # policy DROP even if this process never runs.
    rules=["flush chain inet hg5 forward"]
    if allow:
        rules += [
            'add rule inet hg5 forward iifname "fwtv" oifname "fwnvr" '
            'ip saddr 10.73.1.2 ip daddr 10.73.2.2 tcp dport 8080 counter accept',
            'add rule inet hg5 forward iifname "fwnvr" oifname "fwtv" '
            'ip saddr 10.73.2.2 ip daddr 10.73.1.2 tcp sport 8080 '
            'ct state established counter accept']
    rules += [
        'add rule inet hg5 forward iifname "fwthermo" oifname "fwhvac" '
        'ip saddr 10.73.3.2 ip daddr 10.73.4.2 tcp dport 9000 counter accept',
        'add rule inet hg5 forward iifname "fwhvac" oifname "fwthermo" '
        'ip saddr 10.73.4.2 ip daddr 10.73.3.2 tcp sport 9000 '
        'ct state established counter accept',
        "add rule inet hg5 forward counter drop"]
    return "\n".join(rules)+"\n"


def quarantine():
    execute("nft","-f","-",input=b"flush chain inet hg5 forward\n"
            b"add rule inet hg5 forward counter drop\n")
    state,h=kernel_snapshot()
    if "policy drop" not in state or " accept" in state:
        raise RuntimeError("cannot establish independent default deny")
    return state,h


def install(allow):
    execute("nft","-f","-",input=rules_for(allow).encode())
    state,h=kernel_snapshot()
    if "policy drop" not in state or ('iifname "fwtv"' in state)!=allow:
        quarantine()
        raise RuntimeError("unexpected installed nftables permission")
    if 'iifname "fwthermo"' not in state:
        quarantine()
        raise RuntimeError("control rule missing")
    if not allow:
        subprocess.run(["conntrack","-D","-p","tcp","-s","10.73.1.2",
                        "-d","10.73.2.2","--dport","8080"],
                       capture_output=True,timeout=3)
    return state,h


def owner_policy(raw, arm="olp"):
    p=strict_json_loads(raw.decode())
    if not isinstance(p,dict):raise ValueError("invalid owner document")
    if arm=="olp":
        valid,reason=verify_olp_signature(p)
    else:
        # Conventional verification uses only Ed25519+canonical JSON, no
        # OpenLine verifier. The signed owner fixture is *identical*.
        body={k:v for k,v in p.items() if k not in ("signature","payload_hash")}
        digest=sha(canon(body))
        valid=digest==p.get("payload_hash")
        reason="conventional canonical digest/signature failure"
        if valid:
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(OWNER_PUB)).verify(
                  bytes.fromhex(p["signature"]["value"]),canon(body))
            except (ValueError,InvalidSignature,KeyError):valid=False
    if not valid or p["signature"]["public_key"]!=OWNER_PUB:
        raise ValueError("owner signature or trust root invalid: "+str(reason))
    if p.get("schema")!=OWNER_SCHEMA or p.get("policy_id")!=OWNER_POLICY_ID:
        raise ValueError("wrong owner policy domain")
    rules=p.get("rules")
    if set(rules or {})!={"tv_to_nvr_tcp_8080","thermostat_to_hvac_tcp_9000"}:
        raise ValueError("unrecognized policy action")
    if type(rules["tv_to_nvr_tcp_8080"]) is not bool or rules["thermostat_to_hvac_tcp_9000"] is not True:
        raise ValueError("invalid scope or mandatory control")
    if type(p.get("version")) is not int:
        raise ValueError("invalid owner version")
    return p


def witness_query(socket_path,pub_path,replay=None,evidence=None):
    nonce=secrets.token_hex(16)
    if replay:
        response=json.loads(Path(replay).read_text())
    else:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(str(socket_path))
            s.sendall(canon({"nonce":nonce,"policy_id":OWNER_POLICY_ID})+b"\n")
            incoming=bytearray()
            while not incoming.endswith(b"\n") and len(incoming)<4096:
                piece=s.recv(4096)
                if not piece:break
                incoming+=piece
        response=json.loads(bytes(incoming).decode())
    if evidence is not None:
        evidence.parent.mkdir(parents=True,exist_ok=True)
        with evidence.open("a") as f:
            f.write(json.dumps(response,sort_keys=True)+"\n")
    body=response["body"]
    pub=bytes.fromhex(Path(pub_path).read_text().strip())
    Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(response["signature"]),canon(body))
    now=time.time_ns()
    if set(body)!={"schema","policy_id","nonce","version","policy_sha256","issued_ns","expires_ns"}:
        raise ValueError("witness field substitution")
    if body["schema"]!=WITNESS_SCHEMA or body["policy_id"]!=OWNER_POLICY_ID or body["nonce"]!=nonce:
        raise ValueError("witness nonce/domain mismatch")
    if not (now-600_000_000 <= body["issued_ns"]<=now+100_000_000 and
            now < body["expires_ns"]<=body["issued_ns"]+1_500_000_000):
        raise ValueError("witness freshness expired")
    return response


def local_state(path):
    # Never use the local DB as a trust anchor. It is diagnostic only.
    if not path.exists():return "MISSING"
    try:
        db=sqlite3.connect(str(path),timeout=0.2)
        row=db.execute("SELECT version,policy_hash FROM applied WHERE slot=1").fetchone()
        db.close()
        return dict(version=row[0],policy_hash=row[1]) if row else "EMPTY"
    except (sqlite3.Error,TypeError):
        return "CORRUPT"


def save_local(path,version,hashval):
    path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(str(path),timeout=1)
    try:
        db.execute("CREATE TABLE IF NOT EXISTS applied "
                   "(slot INTEGER PRIMARY KEY CHECK(slot=1), version INTEGER,"
                   " policy_hash TEXT)")
        db.execute("INSERT OR REPLACE INTO applied VALUES (1,?,?)",(version,hashval))
        db.commit()
    finally:
        db.close()


def signed_event(arm,body):
    key=keys.private_key("receiver")
    if arm=="olp":
        return sign_olp_body({"schema":"hg5.olp.kernel_receipt.v1",**body},key)
    payload={"schema":"hg5.conventional.signed_log.v1",**body}
    return {"body":payload,"signature_hex":key.sign(canon(payload)).hex(),
            "public_key":keys.public_key_hex_of("receiver")}


def log_event(a,body):
    obj=signed_event(a.arm,body)
    a.receipts.parent.mkdir(parents=True,exist_ok=True)
    with a.receipts.open("a") as f:
        f.write(json.dumps(obj,sort_keys=True)+"\n")
        f.flush()
        os.fsync(f.fileno())


def recover(a):
    first,first_hash=kernel_snapshot()
    policybytes=a.policy.read_bytes() if a.policy.exists() else b""
    witness_response=None
    decision="UNKNOWN"
    reason=""
    state="";after_hash=first_hash
    local=local_state(a.local)
    try:
        if a.crash=="before-witness":
            os._exit(73)
        witness_response=witness_query(a.socket,a.witness_pub,a.replay,a.witness_responses)
        if not policybytes:raise ValueError("policy bytes missing")
        policy=owner_policy(policybytes,a.arm)
        info=witness_response["body"]
        if (policy["version"]!=info["version"] or
            sha(policybytes)!=info["policy_sha256"]):
            raise ValueError("owner policy version/hash not current witness")
        if a.crash=="after-witness-before-install":
            os._exit(74)
        state,after_hash=install(policy["rules"]["tv_to_nvr_tcp_8080"])
        if a.crash=="after-install-before-receipt":
            os._exit(75)
        # Critical: compare same version + identical hash against witness;
        # local version 0, 1, or missing must not lower authoritative v2.
        save_local(a.local,info["version"],info["policy_sha256"])
        decision="RECOVERED_CURRENT"
        reason="authenticated_current_owner_policy_and_verified_nft"
    except (ValueError,KeyError,TypeError,OSError,TimeoutError,
            socket.timeout,InvalidSignature,sqlite3.Error) as exc:
        state,after_hash=quarantine()
        decision="UNKNOWN"
        reason=type(exc).__name__+":"+str(exc)
    body={"mode":a.arm,"decision":decision,"reason":reason,
          "policy_file_sha256":sha(policybytes),
          "witness_response_sha256":sha(canon(witness_response)) if witness_response else None,
          "previous_kernel_sha256":first_hash,
          "observed_kernel_sha256":after_hash,
          "local_state_seen":local,
          "observed_ns":time.time_ns()}
    a.snapshot.parent.mkdir(parents=True,exist_ok=True)
    a.snapshot.write_text(state if state else kernel_snapshot()[0])
    log_event(a,body)
    print(json.dumps(body,sort_keys=True),flush=True)
    return 0 if decision=="RECOVERED_CURRENT" else 10


def monitor(a):
    # No pre-existing permission survives loss of freshness. Respond to
    # witness outage by blocking immediately (strictly within 2-second bound).
    deadline=time.monotonic()+a.monitor_seconds
    while time.monotonic()<deadline:
        try:
            info=witness_query(a.socket,a.witness_pub,a.replay,a.witness_responses)["body"]
            raw=a.policy.read_bytes()
            p=owner_policy(raw,a.arm)
            if p["version"]!=info["version"] or sha(raw)!=info["policy_sha256"]:
                raise ValueError("stale current permission")
        except Exception as exc:
            state,h=quarantine()
            a.snapshot.parent.mkdir(parents=True,exist_ok=True)
            a.snapshot.write_text(state)
            log_event(a,{"mode":a.arm,"decision":"FRESHNESS_LOST","reason":str(exc),
                         "observed_kernel_sha256":h,"observed_ns":time.time_ns()})
            print("MONITOR_QUARANTINED",flush=True)
            return 0
        time.sleep(0.12)
    print("MONITOR_ENDED_WITH_VALID_FRESHNESS",flush=True)
    return 0


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--arm",choices=["olp","conventional"],required=True)
    p.add_argument("--policy",type=Path,required=True)
    p.add_argument("--local",type=Path,required=True)
    p.add_argument("--socket",type=Path,required=True)
    p.add_argument("--witness-pub",type=Path,required=True)
    p.add_argument("--receipts",type=Path,required=True)
    p.add_argument("--witness-responses",type=Path,required=True)
    p.add_argument("--snapshot",type=Path,required=True)
    p.add_argument("--replay",type=Path)
    p.add_argument("--crash",choices=["before-witness","after-witness-before-install",
                                     "after-install-before-receipt"])
    p.add_argument("--monitor",action="store_true")
    p.add_argument("--monitor-seconds",type=float,default=3.0)
    a=p.parse_args()
    return monitor(a) if a.monitor else recover(a)


if __name__=="__main__":raise SystemExit(main())
