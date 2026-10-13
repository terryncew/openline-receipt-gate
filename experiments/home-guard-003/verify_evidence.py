"""Independent verification of HOME-GUARD-003 signed receipts, kernel and PCAP."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys

EXP = Path(__file__).resolve().parents[1] / "home-guard-001"
ROOT = EXP.parents[1]
for folder in (str(EXP),str(ROOT)):
    if folder not in sys.path:
        sys.path.insert(0,folder)
from home_guard import keys
from olp_gate.crypto import strict_json_load,verify_olp_signature


def require(ok,why):
    if not ok:
        raise AssertionError("HOME-GUARD-003 FALSIFIER: "+why)


def pcap(path):
    content=path.read_bytes()
    require(len(content)>=24,"truncated PCAP "+str(path))
    formats={b"\xd4\xc3\xb2\xa1":("<",1),b"\xa1\xb2\xc3\xd4":(">",1),
             b"\x4d\x3c\xb2\xa1":("<",1000),b"\xa1\xb2\x3c\x4d":(">",1000)}
    require(content[:4] in formats,"unsupported PCAP format")
    order,resolution=formats[content[:4]]
    require(struct.unpack(order+"I",content[20:24])[0]==1,"non-Ethernet capture")
    records=[];offset=24
    while offset<len(content):
        require(len(content)-offset>=16,"truncated pcap record header")
        sec,frac,size,wire=struct.unpack(order+"IIII",content[offset:offset+16])
        offset+=16
        frame=content[offset:offset+size]
        require(len(frame)==size,"truncated frame")
        offset+=size
        if len(frame)<34 or frame[12:14]!=b"\x08\x00":
            continue
        data=frame[14:]
        if data[0]>>4 !=4 or data[9]!=6:
            continue
        header=(data[0]&15)*4
        if len(data)<header+20:
            continue
        sport,dport=struct.unpack("!HH",data[header:header+4])
        flags=data[header+13]
        total=struct.unpack("!H",data[2:4])[0]
        tcp_header=(data[header+12]>>4)*4
        records.append({"us":sec*1000000+frac//resolution,
                        "src":str(ipaddress.ip_address(data[12:16])),
                        "dst":str(ipaddress.ip_address(data[16:20])),
                        "sport":sport,"dport":dport,"syn":bool(flags&2),
                        "ackflag":bool(flags&16),
                        "payload":max(0,total-header-tcp_header)})
    require(offset==len(content),"pcap parse did not consume all bytes")
    return records


def main(root):
    barrier=int((root/"revocation-barrier-us.txt").read_text())
    tv=pcap(root/"tv-ingress.pcap")
    nvr=pcap(root/"nvr-egress.pcap")
    hvac=pcap(root/"hvac-egress.pcap")
    require(tv and nvr and hvac,"missing independent packet capture")
    target=lambda p:p["src"]=="10.73.1.2" and p["dst"]=="10.73.2.2" and p["dport"]==8080
    before=[p for p in nvr if target(p) and p["us"]<barrier and p["payload"]>0]
    after=[p for p in nvr if target(p) and p["us"]>=barrier+200000]
    require(len(before)>=3,"no proof that TV already transmitted on permitted connection")
    require(not after,"TV continued reaching NVR after owner revocation")
    later=[p for p in tv if target(p) and p["us"]>=barrier+200000]
    require(len(later)>=3,"TV did not continue attempting traffic after revocation")
    require(any(p["syn"] and not p["ackflag"] for p in later),
            "no new TV connection SYN observed after revoke")
    spoof=[p for p in tv if p["src"]=="10.73.3.2" and p["sport"]==42424 and
           p["dst"]=="10.73.4.2" and p["dport"]==9000]
    require(spoof,"source spoof attempt not present on TV ingress")
    require(not any(p["src"]=="10.73.3.2" and p["sport"]==42424 and
                    p["dst"]=="10.73.4.2" for p in hvac),
            "spoofed packet reached legitimate HVAC system")
    control=[p for p in hvac if p["src"]=="10.73.3.2" and
             p["dst"]=="10.73.4.2" and p["dport"]==9000]
    require(any(p["us"]<barrier for p in control) and
            any(p["us"]>barrier for p in control),
            "authorized thermostat flow not seen before and after revocation")

    probes=[json.loads(s) for s in (root/"client-probes.jsonl").read_text().splitlines()]
    expected=["control-before","new-TV-connection-after-revoke",
              "TV-alternative-port-after-revoke","TV-forged-thermostat-after-revoke",
              "control-after"]
    require([p["label"] for p in probes]==expected,"probe matrix incomplete")
    require(all(p.get("pass",p.get("status")=="RAW_SYN_SENT") for p in probes),
            "control/new unauthorized connection failed")
    require(probes[0]["response"]=="OK:hvac" and probes[-1]["response"]=="OK:hvac",
            "authorized controls not 2/2")
    require(all(p["status"]=="TIMEOUT" for p in probes[1:3]),
            "new denied connection established")

    flow=[json.loads(s) for s in (root/"tv-active-flow.jsonl").read_text().splitlines()]
    before_ack=[p for p in flow if p["event"]=="ACK" and p["t_us"]<barrier]
    after_sends=[p for p in flow if p["event"]=="SENT" and p["t_us"]>barrier+300000]
    after_acks=[p for p in flow if p["event"]=="ACK" and p["t_us"]>barrier+300000]
    require(len(before_ack)>=5,"no established application flow before revocation")
    require(len(after_sends)>=3,"pre-established socket did not try sending after revoke")
    require(not after_acks,"pre-established socket still receiving ACK after revoke")
    require(any(p["event"] in ("NO_ACK","READ_ERROR","WRITE_ERROR") and
                p["t_us"]>barrier+300000 for p in flow),
            "no observable disruption to established TV socket")

    rules=(root/"kernel-final.rules").read_text()
    kernel_hash=hashlib.sha256(rules.encode()).hexdigest()
    require("-P FORWARD DROP" in rules and "-i fwtv -j DROP" in rules,
            "kernel not fail-closed")
    require("--dport 8080 -j ACCEPT" not in rules,"revoked TV permission installed")
    counts={}
    for line in (root/"kernel-counters.rules").read_text().splitlines():
        m=re.match(r"^\[(\d+):(\d+)\] -A FORWARD (.*)$",line)
        if not m: continue
        qty=int(m.group(1)); spec=m.group(3)
        if "-i fwtv" in spec and "--dport 8080" in spec and "-j DROP" in spec:
            counts["revoked_existing_and_new_drop"]=qty
        if "-i fwtv -j DROP" in spec:
            counts["spoof_altport_drop"]=qty
        if "-i fwthermo" in spec and "--dport 9000" in spec and "-j ACCEPT" in spec:
            counts["legitimate_hvac_accept"]=qty
    for key in ("revoked_existing_and_new_drop","spoof_altport_drop","legitimate_hvac_accept"):
        require(counts.get(key,0)>0,"no kernel firewall counter: "+key)

    receipts=[strict_json_load(s) for s in (root/"apply-receipts.jsonl").read_text().splitlines()]
    applied=[r for r in receipts if r["decision"]=="APPLIED"]
    rejected=[r for r in receipts if r["decision"]=="REJECTED"]
    require(len(receipts)==7 and len(applied)==2 and len(rejected)==5,
            "unexpected signed policy decisions")
    for r in receipts:
        valid,why=verify_olp_signature(r)
        require(valid,"bad signed receipt: "+str(why))
        require(r["signature"]["public_key"]==keys.public_key_hex_of("receiver"),
                "untrusted receipt signer")
    require([r["requested_version"] for r in applied]==[1,2],
            "not exactly owner policy versions 1 -> 2 applied")
    require(applied[0]["kernel_rules_after_sha256"]!=kernel_hash,
            "revocation did not change kernel firewall")
    require(applied[1]["kernel_rules_after_sha256"]==kernel_hash,
            "signed application receipt not bound to observed installed rules")
    require(all(r["kernel_rules_before_sha256"]==
                r["kernel_rules_after_sha256"]==kernel_hash for r in rejected),
            "rejected policy altered kernel rules")
    require(any("untrusted_owner_key" in r["reason"] for r in rejected),
            "attacker-signed policy not rejected")
    require(sum("stale_or_rolled_back_version" in r["reason"] for r in rejected)==2,
            "rollback or replay accepted")
    require(any("expired_signed_policy" in r["reason"] for r in rejected),
            "expired owner-signed update accepted")
    require(any("invalid_owner_signature" in r["reason"] for r in rejected),
            "tampered signed update accepted")
    db=sqlite3.connect(root/"applied.sqlite")
    version,policy_hash,saved_kernel=db.execute(
        "SELECT version,policy_hash,kernel_hash FROM applied WHERE slot=1").fetchone()
    db.close()
    v2=strict_json_load((root/"policies/v2-owner-revoke.json").read_text())
    valid,why=verify_olp_signature(v2)
    require(valid and v2["signature"]["public_key"]==keys.public_key_hex_of("owner"),
            "owner revocation signature invalid")
    require(version==2 and saved_kernel==kernel_hash and policy_hash==v2["payload_hash"],
            "persisted version rollback or kernel mismatch")
    require(applied[1]["policy_file_sha256"]==hashlib.sha256(
        (root/"policies/v2-owner-revoke.json").read_bytes()).hexdigest(),
            "receipt not bound to exact version-2 policy bytes")

    packet_provenance={f.name:{"sha256":hashlib.sha256(f.read_bytes()).hexdigest(),
                              "bytes":f.stat().st_size,"tcp_packets":len(pcap(f))}
                       for f in sorted(root.glob("*.pcap"))}
    report={"experiment":"HOME-GUARD-003",
            "verdict":"PASS_SIGNED_POLICY_TO_KERNEL_REVOCATION_IN_VIRTUAL_NETWORK",
            "allowed_nvr_payload_packets_before":len(before),
            "established_tv_attempts_after":len(after_sends),
            "established_tv_acks_after":len(after_acks),
            "protected_nvr_packets_after":len(after),
            "authorized_thermostat_controls":2,
            "forged_source_packets_seen_on_tv_ingress":len(spoof),
            "rejected_hostile_updates":len(rejected),
            "signed_decision_receipts_verified":len(receipts),
            "accepted_policy_version":version,
            "kernel_firewall_sha256":kernel_hash,
            "kernel_counters":counts,"pcaps":packet_provenance,
            "limitations":"Trusted test-only signer and updater, virtual interfaces, no real devices/root compromise."}
    (root/"report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,indent=2,sort_keys=True))
    print("HOME-GUARD-003 SIGNED_AUTHORITY_AND_PACKET_FALSIFIERS_PASS")


if __name__=="__main__":
    main(Path(sys.argv[1]))
