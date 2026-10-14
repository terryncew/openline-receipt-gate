"""HOME-GUARD-005: bounded self-contained virtual-network experiment.

The local attacker edits ONLY case/local/*. sqlite/policy files. The
trusted witness and owner fixture are separate process/files outside that
scope. Root/kernel compromise and physical reboot are NOT tested.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
HG3=REPO/"experiments/home-guard-003"
HG4=REPO/"experiments/home-guard-004"
HG2=REPO/"experiments/home-guard-002"
PY=sys.executable
E=Path(sys.argv[1]).resolve()
E.mkdir(parents=True,exist_ok=True)
NS=["hg5-fw","hg5-tv","hg5-nvr","hg5-thermo","hg5-hvac"]
logs=[]
captures=[]
servers=[]
witness_proc=None
active_flow=None
CURRENT_CASE=None
D={"experiment":"HOME-GUARD-005","cases":{},"limits":["namespace restart not physical power loss","test fixture public owner keys","privileged host/kernel assumed uncompromised","witness only independent under local-file attacker model"]}


def call(cmd, *, timeout=10, ok=True, stdin=None):
    p=subprocess.run([str(x) for x in cmd],input=stdin,text=True,capture_output=True,timeout=timeout)
    if ok and p.returncode:
        raise RuntimeError("COMMAND_FAIL "+repr(cmd)+" rc="+str(p.returncode)+
                           " stderr="+p.stderr[-500:])
    return p


def fw(*args,timeout=10,ok=True):
    return call(["sudo","ip","netns","exec","hg5-fw",*args],timeout=timeout,ok=ok)


def root(*args,ok=True):
    return call(["sudo",*args],ok=ok)


def now():
    return time.time_ns()


def event(case,stage,**data):
    rec={"at_ns":now(),"case":case,"stage":stage,**data}
    with (E/"events.jsonl").open("a") as f:f.write(json.dumps(rec,sort_keys=True)+"\n")
    D["cases"].setdefault(case,{"events":[]})["events"].append(rec)
    return rec


def kill_process(p):
    if p is not None and p.poll() is None:
        p.terminate()
        try:p.wait(timeout=2)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)


def cleanup_network():
    global captures,servers,active_flow,CURRENT_CASE
    if CURRENT_CASE is not None:
        state=fw("nft","-a","list","table","inet","hg5",ok=False)
        if state.returncode==0:
            (E/CURRENT_CASE/"final-kernel.rules").write_text(state.stdout)
    kill_process(active_flow)
    active_flow=None
    for p,handle in captures:
        if p.poll() is None:p.send_signal(signal.SIGINT)
        try:p.wait(timeout=3)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)
        handle.close()
    captures=[]
    for name in NS:
        p=root("ip","netns","pids",name,ok=False)
        for pid in p.stdout.split():
            root("kill","-TERM",pid,ok=False)
    time.sleep(0.15)
    for name in NS:root("ip","netns","del",name,ok=False)
    for p,handle in servers:
        kill_process(p);handle.close()
    servers=[]
    CURRENT_CASE=None


def stop_witness():
    global witness_proc
    kill_process(witness_proc)
    witness_proc=None


def start_witness(case, trusted):
    global witness_proc
    stop_witness()
    socket_path=Path("/tmp")/("hg5-"+case.replace("/","-")+".sock")
    if socket_path.exists():socket_path.unlink()
    log=(E/case/"witness.log").open("a")
    witness_proc=subprocess.Popen([PY,str(HERE/"witness.py"),"--trusted",str(trusted),
                                   "--socket",str(socket_path)],stdout=log,stderr=subprocess.STDOUT)
    # log stays open, Popen inherits descriptor; harness closes on process exit
    log.close()
    for _ in range(50):
        if socket_path.exists() and witness_proc.poll() is None:
            return socket_path
        time.sleep(0.04)
    raise RuntimeError("witness process failed to become independently reachable")


def trusted_setup(case,policy):
    base=E/case
    trusted=base/"trusted"
    local=base/"local"
    trusted.mkdir(parents=True,exist_ok=True)
    local.mkdir(parents=True,exist_ok=True)
    trusted.chmod(0o700)
    import witness
    witness.create_key(trusted)
    owner_v1=fixture_policy(1,True)
    owner_v2=fixture_policy(2,False)
    # Signed conflicting v2 is a test fixture; the simulated attacker
    # cannot make this new owner signature in the real threat model.
    owner_v2_other=fixture_policy(2,True)
    for name,body in [("v1",owner_v1),("v2",owner_v2),("v2-conflict",owner_v2_other)]:
        (trusted/(name+".json")).write_text(json.dumps(body,sort_keys=True,indent=2)+"\n")
    select_policy(trusted,policy)
    return trusted,local


def select_policy(trusted,version):
    raw=(trusted/(version+".json")).read_bytes()
    temp=trusted/"current-new.json"
    temp.write_bytes(raw)
    os.replace(temp,trusted/"current-policy.json")


def fixture_policy(version,allow):
    spec=importlib.util.spec_from_file_location("hg3_fixture",HG3/"make_policies.py")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.policy(version,allow)


def marker(case,name):
    (E/case/(name+".ns")).write_text(str(now())+"\n")
    event(case,name)


def setup_net(case):
    global captures,servers,CURRENT_CASE
    CURRENT_CASE=case
    for name in NS:
        found=root("ip","netns","list").stdout
        if any(line.split()[0]==name for line in found.splitlines() if line):
            raise RuntimeError("pre-existing namespace "+name+" - refusing real changes")
    for ns in NS:
        root("ip","netns","add",ns)
        root("ip","-n",ns,"link","set","lo","up")
    # A freshly created namespace can inherit kernel ip_forward=1 from the
    # hosted runner. Force forwarding OFF before creating any veth path.
    fw("sysctl","-qw","net.ipv4.ip_forward=0")
    fw("sysctl","-qw","net.ipv6.conf.all.forwarding=0")
    for num,ns,fwif,hostif in [(1,"hg5-tv","fwtv","tveth"),
                               (2,"hg5-nvr","fwnvr","nvreth"),
                               (3,"hg5-thermo","fwthermo","tmeth"),
                               (4,"hg5-hvac","fwhvac","hveth")]:
        root("ip","link","add",fwif,"type","veth","peer","name",hostif)
        root("ip","link","set",fwif,"netns","hg5-fw")
        root("ip","link","set",hostif,"netns",ns)
        root("ip","-n","hg5-fw","addr","add",f"10.73.{num}.1/24","dev",fwif)
        root("ip","-n","hg5-fw","link","set",fwif,"up")
        root("ip","-n",ns,"addr","add",f"10.73.{num}.2/24","dev",hostif)
        root("ip","-n",ns,"link","set",hostif,"up")
        root("ip","-n",ns,"route","add","default","via",f"10.73.{num}.1")
    # CRITICAL: privileged boot supervisor installs guard before forwarding=1.
    current=fw("sysctl","-n","net.ipv4.ip_forward").stdout.strip()
    if current!="0":
        raise RuntimeError("environment did not start with forwarding disabled")
    fw("nft","add","table","inet","hg5")
    fw("nft","add","chain","inet","hg5","forward",
       "{ type filter hook forward priority -300; policy drop; }")
    state=fw("nft","-a","list","chain","inet","hg5","forward").stdout
    if "policy drop" not in state:raise RuntimeError("no kernel DROP in early boot")
    (E/case/"early-guard.rules").write_text(state)
    marker(case,"guard-installed")
    for ns,role,ip,port in [("hg5-nvr","nvr","10.73.2.2",8080),
                            ("hg5-hvac","hvac","10.73.4.2",9000)]:
        h=(E/case/(role+"-server.log")).open("w")
        p=subprocess.Popen(["sudo","ip","netns","exec",ns,PY,"-u",
                            str(HG3/"echo_endpoint.py"),"--role",role,
                            "--bind",ip,"--port",str(port)],stdout=h,stderr=subprocess.STDOUT)
        servers.append((p,h))
    time.sleep(0.35)
    for label,interface in [("tv-ingress","fwtv"),("nvr-egress","fwnvr"),("hvac-egress","fwhvac")]:
        path=E/case/(label+".pcap")
        h=(E/case/(label+".log")).open("w")
        p=subprocess.Popen(["sudo","ip","netns","exec","hg5-fw","tcpdump","-nn",
                            "-U","-s","0","-i",interface,"-w",str(path),
                            "ip or ip6"],stdout=h,stderr=subprocess.STDOUT)
        captures.append((p,h))
    time.sleep(0.4)
    marker(case,"captures-armed")
    fw("sysctl","-qw","net.ipv4.ip_forward=1")
    marker(case,"forwarding-enabled")


def probe(case,label,ns,host,port=8080):
    out=call(["sudo","ip","netns","exec",ns,PY,str(HG4/"probe.py"),
              label,host,str(port)],timeout=4)
    data=json.loads(out.stdout)
    event(case,"probe",**data)
    return data


def ctl(case,arm,policy,local,trusted,sock,stage,*,crash=None,replay=None,monitor=False,seconds=None):
    args=["sudo","ip","netns","exec","hg5-fw",PY,str(HERE/"controller.py"),
          "--arm",arm,"--policy",str(policy),"--local",str(local),
          "--socket",str(sock),"--witness-pub",str(trusted/"witness-public.hex"),
          "--receipts",str(E/case/"receipts.jsonl"),
          "--witness-responses",str(E/case/"witness-responses.jsonl"),
          "--snapshot",str(E/case/(stage+".rules"))]
    if crash:args+=["--crash",crash]
    if replay:args+=["--replay",str(replay)]
    if monitor:args+=["--monitor","--monitor-seconds",str(seconds or 3)]
    before=now()
    p=call(args,ok=False,timeout=10)
    after=now()
    (E/case/(stage+".log")).write_text(p.stdout+"\nSTDERR:\n"+p.stderr)
    event(case,"controller",label=stage,status=p.returncode,duration_ns=after-before,crash=crash)
    return p.returncode


def save_local(local,version,raw):
    if local.exists():local.unlink()
    db=sqlite3.connect(local)
    db.execute("CREATE TABLE applied(slot INTEGER PRIMARY KEY, version INTEGER,policy_hash TEXT)")
    db.execute("INSERT INTO applied VALUES (1,?,?)",
               (version,hashlib.sha256(raw).hexdigest()))
    db.commit();db.close()


def run_boot_and_tamper(arm):
    case=arm+"-recovery"
    case_dir=E/case
    trusted,localdir=trusted_setup(case,"v2")
    sock=start_witness(case,trusted)
    setup_net(case)
    db=localdir/"history.sqlite"
    cache=localdir/"candidate.json"
    v1=(trusted/"v1.json").read_bytes()
    v2=(trusted/"v2.json").read_bytes()
    save_local(db,2,v2)
    cache.write_bytes(v2)
    early=probe(case,"startup-tv","hg5-tv","10.73.2.2")
    alternate=probe(case,"startup-alt-port","hg5-tv","10.73.2.2",8443)
    marker(case,"recovery-start")
    status=ctl(case,arm,cache,db,trusted,sock,"same-v2")
    control=probe(case,"recovered-thermostat","hg5-thermo","10.73.4.2",9000)
    tv_after=probe(case,"after-v2-tv","hg5-tv","10.73.2.2")
    event(case,"exact-v2-recovery",controller=status,thermostat=control["status"],tv=tv_after["status"])
    # Local-file attacker deletes or forges records. A live independent witness
    # knows signed v2 is the latest; recovery never trusts SQLite.
    if db.exists():db.unlink()
    cache.write_bytes(v1)
    missing=ctl(case,arm,cache,db,trusted,sock,"missing-db-v1")
    tv_missing=probe(case,"missing-db-tv","hg5-tv","10.73.2.2")
    event(case,"missing-sqlite",controller=missing,tv=tv_missing["status"])
    cache.write_bytes(v2)
    missing_recover=ctl(case,arm,cache,db,trusted,sock,"missing-db-v2")
    event(case,"missing-sqlite-v2-recover",controller=missing_recover)
    # Attacker edits locally stored version back to zero, and replays v1.
    save_local(db,0,v1)
    cache.write_bytes(v1)
    downgrade=ctl(case,arm,cache,db,trusted,sock,"downgraded-v1")
    tv_down=probe(case,"downgraded-tv","hg5-tv","10.73.2.2")
    event(case,"replaced-sqlite",controller=downgrade,tv=tv_down["status"])
    cache.write_bytes(v2)
    ctl(case,arm,cache,db,trusted,sock,"restore-after-replacement")
    # Same numeric version with a different VALID owner fixture signature
    # still fails because authoritative external witness binds the bytes.
    cache.write_bytes((trusted/"v2-conflict.json").read_bytes())
    conflict=ctl(case,arm,cache,db,trusted,sock,"same-version-other-hash")
    event(case,"same-version-hash-conflict",controller=conflict)
    cache.write_bytes(v2)
    # Modified bytes keep old signature, so owner proof also fails.
    altered=json.loads(v2)
    altered["rules"]["tv_to_nvr_tcp_8080"]=True
    cache.write_text(json.dumps(altered,sort_keys=True)+"\n")
    altered_rc=ctl(case,arm,cache,db,trusted,sock,"tampered-signature")
    event(case,"unsigned-tamper",controller=altered_rc)
    cache.write_bytes(v2)
    ok=ctl(case,arm,cache,db,trusted,sock,"restore-after-tamper")
    event(case,"restore-after-tamper",controller=ok)
    # Replay a *correctly signed* old witness response with wrong challenge.
    response_path=case_dir/"old-witness-response.json"
    import socket as socketmod
    with socketmod.socket(socketmod.AF_UNIX,socketmod.SOCK_STREAM) as channel:
        channel.connect(str(sock))
        channel.sendall(json.dumps({"nonce":"a"*32,"policy_id":"hg3-isolated-veth-network"}).encode()+b"\n")
        response_path.write_bytes(channel.recv(4000).strip()+b"\n")
    replay=ctl(case,arm,cache,db,trusted,sock,"replayed-witness",replay=response_path)
    event(case,"replayed-witness",controller=replay)
    final=ctl(case,arm,cache,db,trusted,sock,"final-restored")
    final_control=probe(case,"control-after-attack","hg5-thermo","10.73.4.2",9000)
    event(case,"recovery-final",controller=final,control=final_control["status"])
    cleanup_network();stop_witness()


def run_witness_outage(arm):
    case=arm+"-outage"
    trusted,localdir=trusted_setup(case,"v1")
    sock=start_witness(case,trusted)
    setup_net(case)
    db=localdir/"history.sqlite";cache=localdir/"candidate.json"
    cache.write_bytes((trusted/"v1.json").read_bytes())
    initial=ctl(case,arm,cache,db,trusted,sock,"initial-v1")
    before=probe(case,"v1-tv-before-outage","hg5-tv","10.73.2.2")
    event(case,"outage-baseline",controller=initial,tv=before["status"])
    monitor_log=(E/case/"monitor.log").open("w")
    args=["sudo","ip","netns","exec","hg5-fw",PY,str(HERE/"controller.py"),
          "--arm",arm,"--policy",str(cache),"--local",str(db),
          "--socket",str(sock),"--witness-pub",str(trusted/"witness-public.hex"),
          "--receipts",str(E/case/"receipts.jsonl"),
          "--witness-responses",str(E/case/"witness-responses.jsonl"),
          "--snapshot",str(E/case/"watcher-quarantine.rules"),
          "--monitor","--monitor-seconds","4"]
    watcher=subprocess.Popen(args,stdout=monitor_log,stderr=subprocess.STDOUT)
    time.sleep(0.25)
    last_fresh=now()
    stop_witness()
    event(case,"witness-unavailable",last_fresh_ns=last_fresh)
    try:watcher.wait(timeout=5)
    except subprocess.TimeoutExpired:watcher.kill();watcher.wait()
    monitor_log.close()
    after=probe(case,"v1-tv-after-outage","hg5-tv","10.73.2.2")
    event(case,"outage-expired",monitor_status=watcher.returncode,tv=after["status"],
          bound_ns=2_000_000_000)
    # Cold recovery must not reopen even if a v1 cache remains valid.
    cold=ctl(case,arm,cache,db,trusted,sock,"offline-cold")
    event(case,"offline-cold",status=cold)
    cleanup_network();stop_witness()


def run_crash(arm):
    case=arm+"-crash"
    trusted,localdir=trusted_setup(case,"v2")
    sock=start_witness(case,trusted)
    setup_net(case)
    db=localdir/"history.sqlite";cache=localdir/"candidate.json"
    cache.write_bytes((trusted/"v2.json").read_bytes())
    for crash in ("before-witness","after-witness-before-install","after-install-before-receipt"):
        # Restore guard before each forced interruption. Witness still v2.
        fw("nft","-f","-",ok=True) if False else None
        call(["sudo","ip","netns","exec","hg5-fw","nft","-f","-"],
             stdin="flush chain inet hg5 forward\nadd rule inet hg5 forward counter drop\n")
        status=ctl(case,arm,cache,db,trusted,sock,crash,crash=crash)
        denied=probe(case,"post-crash-"+crash,"hg5-tv","10.73.2.2")
        event(case,"forced-stop",point=crash,status=status,tv=denied["status"])
        recovery=ctl(case,arm,cache,db,trusted,sock,"restored-"+crash)
        control=probe(case,"control-after-"+crash,"hg5-thermo","10.73.4.2",9000)
        event(case,"post-crash-recovery",point=crash,status=recovery,control=control["status"])
    cleanup_network();stop_witness()


def run_live_revoke(arm):
    global active_flow
    case=arm+"-live"
    trusted,localdir=trusted_setup(case,"v1")
    sock=start_witness(case,trusted)
    setup_net(case)
    db=localdir/"history.sqlite";cache=localdir/"candidate.json"
    cache.write_bytes((trusted/"v1.json").read_bytes())
    first=ctl(case,arm,cache,db,trusted,sock,"v1-allow")
    thermostat=probe(case,"thermo-before-revoke","hg5-thermo","10.73.4.2",9000)
    ready=E/case/"tv-flow-ready.txt";stopped=E/case/"tv-flow-stop.txt"
    log=(E/case/"tv-flow.jsonl").open("w")
    active_flow=subprocess.Popen(["sudo","ip","netns","exec","hg5-tv",PY,"-u",
                                  str(HG3/"active_flow.py"),"--ready",str(ready),
                                  "--stop",str(stopped)],stdout=log,stderr=subprocess.DEVNULL)
    ready_ok=False
    for _ in range(80):
        if ready.exists():ready_ok=True;break
        if active_flow.poll() is not None:break
        time.sleep(0.08)
    if not ready_ok:raise RuntimeError("initial v1 TV did not establish >=5 ACKs")
    marker(case,"witness-revocation-request")
    select_policy(trusted,"v2")
    marker(case,"witness-revocation-committed")
    cache.write_bytes((trusted/"v2.json").read_bytes())
    changed=ctl(case,arm,cache,db,trusted,sock,"v2-revoke")
    marker(case,"nft-revocation-verified")
    time.sleep(1.2)
    stopped.touch()
    active_flow.wait(timeout=5)
    log.close();active_flow=None
    new=probe(case,"TV-new-after-revoke","hg5-tv","10.73.2.2")
    after_control=probe(case,"thermo-after-revoke","hg5-thermo","10.73.4.2",9000)
    event(case,"live-revocation",v1=first,v2=changed,thermo_before=thermostat["status"],
          thermo_after=after_control["status"],new_tv=new["status"])
    cleanup_network();stop_witness()


def finish():
    import hashlib
    for f in sorted(E.rglob("*")):
        if f.is_file() and f.name!="SHA256SUMS":
            logs.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(E)}")
    (E/"SHA256SUMS").write_text("\n".join(logs)+"\n")
    (E/"execution.json").write_text(json.dumps(D,sort_keys=True,indent=2)+"\n")


def main():
    # Always initialize only disposable namespaced interfaces and no host NIC.
    if any(name in root("ip","netns","list").stdout for name in NS):
        raise RuntimeError("namespaces already exist; cannot touch them")
    for tool in ["ip","nft","tcpdump","conntrack"]:
        if not shutil.which(tool):raise RuntimeError("ENV_BLOCKED missing "+tool)
    (E/"environment.txt").write_text(call(["uname","-a"]).stdout+
                                     call(["nft","--version"]).stdout)
    for arm in ["olp","conventional"]:
        for scenario in [run_boot_and_tamper,run_witness_outage,run_crash,run_live_revoke]:
            case=arm+"-"+scenario.__name__.split("run_")[-1].replace("_and_tamper","").replace("_","-")
            try:scenario(arm)
            except BaseException as exc:
                D.setdefault("apparatus_failures",[]).append({"arm":arm,"scenario":str(scenario),
                                                               "error":repr(exc)})
                (E/"FAILURE.txt").write_text(repr(exc)+"\n")
                raise


if __name__=="__main__":
    try: main()
    except BaseException as exc:
        import traceback
        (E/"traceback.txt").write_text(traceback.format_exc())
        print("HG5 APPARATUS ERROR "+str(exc),file=sys.stderr)
        raise
    finally:
        try:cleanup_network();stop_witness()
        finally:finish()
