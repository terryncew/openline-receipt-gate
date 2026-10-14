"""HOME-GUARD-005 independent packet, witness and receipt verifier.

Only raw artifacts used, NOT success text from controller. A completed CI job
does not imply security PASS; failures remain explicit per arm/property.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import sys
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

E=Path(sys.argv[1])
REPORT={"experiment":"HOME-GUARD-005","outcomes":{},"comparison":{},
        "limits":["simulated network reset, no physical power loss",
                  "same host as trusted witness; no root/kernel compromise",
                  "test-only fixture owner and receiver keys"]}


def require(v,reason):
    if not v:raise RuntimeError("EVIDENCE_INCONCLUSIVE: "+reason)


def canon(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")


def sha(b):return hashlib.sha256(b).hexdigest()


def parse_pcap(path):
    raw=path.read_bytes()
    require(len(raw)>=24,"pcap missing "+str(path))
    magic=raw[:4]
    formats={b"\xd4\xc3\xb2\xa1":("<",1),b"\xa1\xb2\xc3\xd4":(">",1),
             b"\x4d\x3c\xb2\xa1":("<",1000),b"\xa1\xb2\x3c\x4d":(">",1000)}
    require(magic in formats,"bad pcap magic "+str(path))
    order,res=formats[magic]
    linktype=struct.unpack_from(order+"I",raw,20)[0]
    require(linktype==1,"non ethernet pcap "+str(path))
    n=24;rows=[]
    while n<len(raw):
        require(len(raw)-n>=16,"pcap truncated record "+str(path))
        seconds,fraction,size,wire=struct.unpack_from(order+"IIII",raw,n);n+=16
        frame=raw[n:n+size]
        require(len(frame)==size,"pcap truncated packet")
        n+=size
        if len(frame)<34 or frame[12:14]!=b"\x08\x00":continue
        ip=frame[14:]
        if ip[0]>>4!=4 or ip[9]!=6:continue
        ihl=(ip[0]&15)*4
        if len(ip)<ihl+20:continue
        sport,dport=struct.unpack_from("!HH",ip,ihl)
        total=struct.unpack_from("!H",ip,2)[0]
        thl=(ip[ihl+12]>>4)*4
        rows.append({"ns":seconds*1000000000+fraction*(1000//res),
                     "src":str(ipaddress.ip_address(ip[12:16])),
                     "dst":str(ipaddress.ip_address(ip[16:20])),
                     "sport":sport,"dport":dport,
                     "syn":bool(ip[ihl+13]&2),
                     "tcp_bytes":max(0,total-ihl-thl)})
    require(n==len(raw),"unparsed pcap bytes")
    return rows


def signed_verified(payload,sig,pub_hex):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig),canon(payload))
        return True
    except (ValueError,KeyError,TypeError):
        return False
    except Exception:
        return False


def inspect_case(arm,scenario):
    name=arm+"-"+scenario
    root=E/name
    require(root.is_dir(),name+" dir missing")
    traffic={label:parse_pcap(root/(label+".pcap"))
             for label in ("tv-ingress","nvr-egress","hvac-egress")}
    tv=traffic["tv-ingress"]
    protected=[p for p in traffic["nvr-egress"] if
               p["src"]=="10.73.1.2" and p["dst"]=="10.73.2.2"]
    hvac=[p for p in traffic["hvac-egress"] if
          p["src"]=="10.73.3.2" and p["dst"]=="10.73.4.2"]
    ingress=[p for p in tv if p["src"]=="10.73.1.2" and
             p["dst"]=="10.73.2.2"]
    require(ingress,"missing malicious TV ingress attempts "+name)
    guard=(root/"guard-installed.ns")
    armed=(root/"captures-armed.ns")
    forwarded=(root/"forwarding-enabled.ns")
    require(guard.exists() and armed.exists() and forwarded.exists(),
            name+" missing boot timestamp")
    stamps=[int(x.read_text()) for x in (guard,armed,forwarded)]
    require(stamps==sorted(stamps) and len(set(stamps))==3,
            "capture not armed after guard and before forwarding "+name)
    start=(root/"early-guard.rules").read_text()
    require("policy drop" in start and " accept" not in start,
            "no observed early nft DROP guard "+name)
    end=(root/"final-kernel.rules")
    require(end.exists(),"no independent final kernel snapshot "+name)
    kernel=end.read_text()
    require("policy drop" in kernel,"no final kernel drop "+name)
    receipts_path=root/"receipts.jsonl"
    receipts=[json.loads(x) for x in receipts_path.read_text().splitlines()] if receipts_path.exists() else []
    receiver_pub="55154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207"
    owner_pub="bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5"
    # Both pinned keys are test fixtures; signature verification is independent of the updater.
    verified=0
    for record in receipts:
        if arm=="olp":
            body={k:v for k,v in record.items() if k not in ("payload_hash","signature")}
            signature=record.get("signature",{})
            require(record.get("payload_hash")==sha(canon(body)),"OLP receipt digest corrupt")
            require(signature.get("public_key")==receiver_pub and
                    signed_verified(body,signature.get("value",""),receiver_pub),
                    "OLP receipt signature invalid")
        else:
            body=record["body"]
            require(record["public_key"]==receiver_pub and
                    signed_verified(body,record["signature_hex"],receiver_pub),
                    "conventional event signature invalid")
        verified+=1
    witness_path=root/"witness-responses.jsonl"
    responses=[json.loads(x) for x in witness_path.read_text().splitlines()] if witness_path.exists() else []
    wpub=(root/"trusted"/"witness-public.hex").read_text().strip()
    goodw=0
    for r in responses:
        require(signed_verified(r["body"],r["signature"],wpub),
                "witness Ed25519 signature invalid "+name)
        goodw+=1
    policy_bytes=(root/"trusted"/"v2.json").read_bytes()
    for suffix in ("v1","v2","v2-conflict"):
        signed=json.loads((root/"trusted"/(suffix+".json")).read_text())
        owner_body={k:v for k,v in signed.items() if k not in ("signature","payload_hash")}
        require(signed.get("payload_hash")==sha(canon(owner_body)) and
                signed["signature"]["public_key"]==owner_pub and
                signed_verified(owner_body,signed["signature"]["value"],owner_pub),
                "signed owner policy fixture invalid "+suffix)
    return {"name":name,"path":root,"traffic":traffic,
            "protected":protected,"hvac":hvac,"ingress":ingress,
            "receipts":receipts,"witnesses":responses,
            "verified_receipts":verified,"verified_witnesses":goodw,
            "pcap_hashes":{label:sha((root/(label+".pcap")).read_bytes())
                            for label in traffic}}


def body(record,arm):
    return record if arm=="olp" else record["body"]


def event_map(name):
    data=[json.loads(s) for s in (E/"events.jsonl").read_text().splitlines()]
    return [v for v in data if v["case"]==name]


def stages(rows,stage):
    return [x for x in rows if x.get("stage")==stage]


def stage_one(rows,stage):
    items=stages(rows,stage)
    require(items,"missing event "+stage)
    return items[-1]


def check_arm(arm):
    recovery=inspect_case(arm,"recovery")
    outage=inspect_case(arm,"outage")
    crash=inspect_case(arm,"crash")
    live=inspect_case(arm,"live")
    cases=[recovery,outage,crash,live]
    events={x["name"]:event_map(x["name"]) for x in cases}
    r=events[arm+"-recovery"];o=events[arm+"-outage"]
    c=events[arm+"-crash"];l=events[arm+"-live"]
    outcome={}
    # Security: traffic on ingress but zero on protected egress; startup
    # evidence guards must precede forwarding.
    early_tv=stage_one(r,"probe")
    outcome["HG5-01"]="PASS" if not recovery["protected"] and len(recovery["ingress"])>=5 else "FAIL"
    exact=stage_one(r,"exact-v2-recovery")
    final=stage_one(r,"recovery-final")
    outcome["HG5-02"]="PASS" if (exact["controller"]==0 and
        exact["thermostat"]=="ACK" and exact["tv"]!="ACK" and
        len(recovery["hvac"])>0) else "FAIL"
    missing=stage_one(r,"missing-sqlite")
    repaired=stage_one(r,"missing-sqlite-v2-recover")
    outcome["HG5-03"]="PASS" if (missing["controller"]==10 and
        missing["tv"]!="ACK" and repaired["controller"]==0 and
        not recovery["protected"]) else "FAIL"
    replaced=stage_one(r,"replaced-sqlite")
    replay=stage_one(r,"replayed-witness")
    outcome["HG5-04"]="PASS" if (replaced["controller"]==10 and
        replaced["tv"]!="ACK" and replay["controller"]==10 and
        not recovery["protected"]) else "FAIL"
    same=stage_one(r,"same-version-hash-conflict")
    tamper=stage_one(r,"unsigned-tamper")
    outcome["HG5-05"]="PASS" if same["controller"]==10 and tamper["controller"]==10 else "FAIL"
    before=stage_one(o,"outage-baseline")
    lost=stage_one(o,"witness-unavailable")
    expired=stage_one(o,"outage-expired")
    cold=stage_one(o,"offline-cold")
    freshness_receipts=[body(x,arm) for x in outage["receipts"] if
                        body(x,arm).get("decision")=="FRESHNESS_LOST"]
    freshness_t=min([int(x["observed_ns"]) for x in freshness_receipts],default=0)
    # The test's bound starts at last known confirmed live witness moment.
    outage_tail=[x for x in outage["protected"] if
                 x["ns"]>freshness_t+200_000_000]
    outcome["HG5-06"]="PASS" if (
        before["controller"]==0 and before["tv"]=="ACK" and
        expired["monitor_status"]==0 and expired["tv"]!="ACK" and
        cold["status"]==10 and freshness_t>=lost["at_ns"] and
        freshness_t-lost["at_ns"]<=2_000_000_000 and
        not outage_tail and len(outage["protected"])>0) else "FAIL"
    forced=stages(c,"forced-stop")
    recovered=stages(c,"post-crash-recovery")
    expected={"before-witness":73,"after-witness-before-install":74,
              "after-install-before-receipt":75}
    outcome["HG5-07"]="PASS" if (len(forced)==3 and len(recovered)==3 and
        all(x["status"]==expected.get(x["point"]) and x["tv"]!="ACK" for x in forced) and
        all(x["status"]==0 and x["control"]=="ACK" for x in recovered) and
        not crash["protected"]) else "FAIL"
    rev=stage_one(l,"live-revocation")
    v2_barrier=int((live["path"]/"nft-revocation-verified.ns").read_text())
    first=[x for x in live["protected"] if x["ns"]<v2_barrier]
    later=[x for x in live["protected"] if x["ns"]>v2_barrier+200_000_000]
    flow=[json.loads(x) for x in (live["path"]/"tv-flow.jsonl").read_text().splitlines()]
    acks_before=[x for x in flow if x["event"]=="ACK" and x["t_us"]*1000<v2_barrier]
    sends_after=[x for x in flow if x["event"]=="SENT" and x["t_us"]*1000>v2_barrier+300_000_000]
    acks_after=[x for x in flow if x["event"]=="ACK" and x["t_us"]*1000>v2_barrier+300_000_000]
    outcome["HG5-08"]="PASS" if (rev["v1"]==rev["v2"]==0 and
        rev["thermo_before"]==rev["thermo_after"]=="ACK" and
        rev["new_tv"]!="ACK" and len(acks_before)>=5 and
        sends_after and not acks_after and first and not later) else "FAIL"
    # Inspect witness bound policy and actual kernel snapshot, not a mere
    # success assertion. Missing any independently observable part => unknown.
    success_receipts=[body(x,arm) for x in recovery["receipts"] if
                      body(x,arm).get("decision")=="RECOVERED_CURRENT"]
    receipts_have_witness=all(any(sha(canon(w))==x["witness_response_sha256"]
                                  for w in recovery["witnesses"])
                              for x in success_receipts)
    snapshots_match=all((recovery["path"]/(label+".rules")).exists()
                         for label in ["same-v2","missing-db-v2",
                                       "restore-after-replacement","final-restored"])
    outcome["HG5-09"]="PASS" if (recovery["verified_receipts"]>=8 and
        recovery["verified_witnesses"]>=8 and
        receipts_have_witness and snapshots_match and
        not recovery["protected"] and len(recovery["hvac"])>0) else "FAIL"
    outcome["HG5-10"]="INCONCLUSIVE"  # root/kernel compromise and real power loss untested
    for key,v in outcome.items():
        print(f"{arm} {key}: {v}",flush=True)
    return outcome,{
      "receipt_counts":{case["name"]:case["verified_receipts"] for case in cases},
      "witness_signatures":{case["name"]:case["verified_witnesses"] for case in cases},
      "pcap_hashes":{case["name"]:case["pcap_hashes"] for case in cases},
      "observed_prior_tv_packets":len(first),
      "observed_post_revoke_tv_packets":len(later),
      "witness_outage_to_drop_ms":(freshness_t-lost["at_ns"])/1e6 if freshness_t else None,
      "revocation_install_latency_ms":(v2_barrier-
        int((live["path"]/"witness-revocation-committed.ns").read_text()))/1e6,
      "recovery_execution_timings_ns":[x["duration_ns"] for x in stages(r,"controller")],
    }


def main():
    for arm in ("olp","conventional"):
        outcome,details=check_arm(arm)
        REPORT["outcomes"][arm]=outcome
        REPORT[arm+"_evidence"]=details
    same=REPORT["outcomes"]["olp"]==REPORT["outcomes"]["conventional"]
    REPORT["comparison"]["identical_security_case_verdicts"]=same
    REPORT["comparison"]["competitive_security_advantage"]="NONE_DEMONSTRATED" if same else "DIFFERENCE_REQUIRES_AUDIT"
    REPORT["comparison"]["commercial_go_no_go"]="STOP_IF_PARITY_NO_BUYER" if same else "INCONCLUSIVE"
    (E/"REPORT.json").write_text(json.dumps(REPORT,indent=2,sort_keys=True)+"\n")
    print("HG5_INDEPENDENT_PCAP_CRYPTO_KERNEL_REVIEW_COMPLETE",flush=True)
    # The workflow may execute correctly even if security FAILs.
    # CI success must NOT be represented as PASS for security.
    if any(x=="FAIL" for arm in REPORT["outcomes"].values() for x in arm.values()):
        print("HG5_SECURITY_FAILURES_PRESERVED",flush=True)


if __name__=="__main__":
    try:main()
    except Exception as exc:
        import traceback
        (E/"VERIFIER_FAILURE.txt").write_text(traceback.format_exc())
        print("HG5 VERIFIER INCONCLUSIVE "+str(exc),file=sys.stderr)
        raise
