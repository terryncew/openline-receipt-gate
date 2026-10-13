"""HOME-GUARD-004 only: reboot-loss and rollback tests on disposable Linux netns.

Frozen criteria: PREREGISTRATION.md at freeze SHA 19a76732....
Does NOT alter HOME-GUARD-003 policy_gate.py or any host interface/netfilter.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
HG3 = REPO / 'experiments/home-guard-003'
ENV = Path(sys.argv[1]).resolve()
ENV.mkdir(parents=True, exist_ok=True)
PY = sys.executable
NAMES = ('hg4-fw','hg4-tv','hg4-nvr','hg4-thermo','hg4-hvac')
DEVICE = {'hg4-tv':(1,'fwtv','tveth'), 'hg4-nvr':(2,'fwnvr','nvreth'),
          'hg4-thermo':(3,'fwthermo','tmeth'), 'hg4-hvac':(4,'fwhvac','hveth')}
servers = []
captures = []
log = []


def command(args, *, check=True, timeout=25, input=None):
    p = subprocess.run([str(s) for s in args],input=input, capture_output=True,
                       text=True,timeout=timeout,check=False)
    if check and p.returncode != 0:
        raise RuntimeError(f'command failed {args} ({p.returncode}): {p.stderr[-500:]}')
    return p


def root(*args, **kwargs):
    return command(('sudo',)+args,**kwargs)


def ns(namespace,*args,**kwargs):
    return root('ip','netns','exec',namespace,*args,**kwargs)


def save(stage, key, value):
    path = ENV / stage
    path.mkdir(parents=True,exist_ok=True)
    (path/key).write_text(value if isinstance(value,str) else json.dumps(value,sort_keys=True,indent=2)+'\n')


def marker(stage,name):
    t=time.time_ns()
    save(stage, name+'.ns',str(t)+'\n')
    return t


def show_rules(stage,key='forward.rules'):
    p=ns('hg4-fw','iptables','-S','FORWARD')
    save(stage,key,p.stdout)
    return p.stdout


def listen(namespace, code, filename):
    output = open(ENV / filename, 'w')
    p = subprocess.Popen(['sudo','ip','netns','exec',namespace,PY,'-u',str(HG3/'echo_endpoint.py'),
                          '--role', code,'--bind','10.73.'+('2' if code=='nvr' else '4')+'.2',
                          '--port',str(8080 if code=='nvr' else 9000)],
                         stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
    servers.append((p,output))
    for _ in range(40):
        time.sleep(0.1)
        if 'READY' in (ENV/filename).read_text():return
        if p.poll() is not None:break
    raise RuntimeError('Endpoint did not start: '+filename+': '+(ENV/filename).read_text())


def first_setup():
    existing=root('ip','netns','list').stdout
    for name in NAMES:
        if any(line.startswith(name+' ') or line.strip()==name for line in existing.splitlines()):
            raise RuntimeError('ENV_BLOCKED namespace exists already: '+name)
    for name in NAMES:
        root('ip','netns','add',name)
        root('ip','-n',name,'link','set','lo','up')
    make_links()
    # Safe initial build; original HG3 experiment does not test restart.
    ns('hg4-fw','sysctl','-qw','net.ipv4.ip_forward=0')
    ns('hg4-fw','iptables','-w','-P','FORWARD','DROP')
    ns('hg4-fw','iptables','-w','-F','FORWARD')


def make_links():
    for name,(idx,fwif,devif) in DEVICE.items():
        root('ip','link','add',fwif,'type','veth','peer','name',devif)
        root('ip','link','set',fwif,'netns','hg4-fw')
        root('ip','link','set',devif,'netns',name)
        root('ip','-n','hg4-fw','addr','add',f'10.73.{idx}.1/24','dev',fwif)
        root('ip','-n','hg4-fw','link','set',fwif,'up')
        root('ip','-n',name,'addr','add',f'10.73.{idx}.2/24','dev',devif)
        root('ip','-n',name,'link','set',devif,'up')
        root('ip','-n',name,'route','add','default','via',f'10.73.{idx}.1')


def cycle(case):
    # Destroy exactly the firewall namespace: loses all firewall and conntrack.
    # Endpoint namespaces stay alive with listening applications.
    root('ip','netns','del','hg4-fw')
    root('ip','netns','add','hg4-fw')
    root('ip','-n','hg4-fw','link','set','lo','up')
    ns('hg4-fw','sysctl','-qw','net.ipv4.ip_forward=0')
    make_links()
    marker(case,'router-recreated')
    save(case,'cold-rules.txt',show_rules(case))
    save(case,'cold-forwarding.txt',ns('hg4-fw','sysctl','-n','net.ipv4.ip_forward').stdout)


def safe_drop(case):
    ns('hg4-fw','iptables','-w','-P','FORWARD','DROP')
    ns('hg4-fw','iptables','-w','-F','FORWARD')
    marker(case,'default-drop-installed')
    show_rules(case,'installed-default-drop.rules')


def enable_forwarding(case):
    ns('hg4-fw','sysctl','-qw','net.ipv4.ip_forward=1')
    marker(case,'forwarding-enabled')


def start_capture(case):
    global captures
    if captures:raise RuntimeError('capture already active')
    for namespace,devif,label in [('hg4-tv','tveth','tv'),('hg4-nvr','nvreth','nvr'),
                                 ('hg4-hvac','hveth','hvac')]:
        logfile=open(ENV/case/f'{label}.capture.log','w')
        file=ENV/case/f'{label}.pcap'
        p=subprocess.Popen(['sudo','ip','netns','exec',namespace,'tcpdump',
                            '-nn','-U','-s','0','-i',devif,'-w',str(file)],
                           stdout=logfile,stderr=subprocess.STDOUT,start_new_session=True)
        captures.append((namespace,p,logfile))
    for _ in range(60):
        time.sleep(0.1)
        if all('listening on' in (ENV/case/f'{label}.capture.log').read_text()
               for label in ['tv','nvr','hvac']):
            marker(case,'all-captures-armed')
            return
    raise RuntimeError('ENV_BLOCKED tcpdump did not arm before forwarding')


def stop_capture(case):
    global captures
    for namespace,_,_ in captures:
        pids=root('ip','netns','pids',namespace).stdout.split()
        for pid in pids:
            if command(('ps','-p',pid,'-o','comm='),check=False).stdout.strip()=='tcpdump':
                root('kill','-INT',pid,check=False)
    time.sleep(0.5)
    for _,p,fh in captures:
        try:p.wait(timeout=4)
        except subprocess.TimeoutExpired:p.terminate()
        fh.close()
    captures.clear()
    marker(case,'capture-finished')


def probe(case,label,namespace,host,port):
    p=ns(namespace,PY,str(HERE/'probe.py'),label,host,str(port),check=False,timeout=6)
    if p.returncode!=0: raise RuntimeError('probe crashed: '+p.stderr)
    event=json.loads(p.stdout)
    event['case']=case
    event['returncode']=p.returncode
    with (ENV/case/'probes.jsonl').open('a') as h:h.write(json.dumps(event,sort_keys=True)+'\n')
    return event


def fire(case, filename, ledger, *, missing=False):
    saved=ENV/case
    saved.mkdir(parents=True,exist_ok=True)
    target=(ENV/'policies'/filename) if not missing else (ENV/'policies'/'NOT_PRESENT.json')
    out=saved/('gate-'+filename+'.log')
    snap=saved/('gate-'+filename+'.rules')
    cmd=['sudo','ip','netns','exec','hg4-fw',PY,str(HG3/'policy_gate.py'),
         '--policy',str(target),'--ledger',str(ledger),
         '--receipts',str(saved/'receiver-receipts.jsonl'),'--snapshot',str(snap)]
    result=command(cmd,check=False,timeout=15)
    out.write_text(result.stdout+'\nSTDERR:\n'+result.stderr)
    marker(case,'gate-'+filename+'-return')
    return dict(status=result.returncode,stdout=result.stdout[-1200:],
                stderr=result.stderr[-1200:],snap_exists=snap.exists())


def copy_sqlite(src,dst):
    dst.parent.mkdir(parents=True,exist_ok=True)
    if dst.exists():dst.unlink()
    s=sqlite3.connect(src)
    t=sqlite3.connect(dst)
    try:s.backup(t)
    finally:s.close();t.close()


def version(path):
    if not path.exists():return None
    try:
        db=sqlite3.connect(path)
        row=db.execute('SELECT version FROM applied WHERE slot=1').fetchone()
        db.close()
        return row[0] if row else None
    except Exception:return 'UNREADABLE'


def record(case,data):
    data['ledger_version']=version(data['ledger_file']) if 'ledger_file' in data else None
    if 'ledger_file' in data: data['ledger_file']=str(data['ledger_file'])
    save(case,'observations.json',data)


def scenario(c,store,mode,action):
    cycle(c)
    if mode=='safe':safe_drop(c)
    start_capture(c)
    if mode=='unsafe':
        enable_forwarding(c)
        first=probe(c,'unsafe-before-drop','hg4-tv','10.73.2.2',8080)
        safe_drop(c)
        later=probe(c,'unsafe-after-drop','hg4-tv','10.73.2.2',8080)
        result={'first':first,'later':later,'legacy_order_default_rules':(ENV/c/'cold-rules.txt').read_text(),
                'ledger_file':store}
    else:
        enable_forwarding(c)
        pre=probe(c,'early-TV-before-policy','hg4-tv','10.73.2.2',8080)
        result={'pre':pre,'ledger_file':store}
        if action=='repeat-v2':
            result['v2_same']=fire(c,'v2-owner-revoke.json',store)
            result['tv_after']=probe(c,'tv-after-v2-repeat','hg4-tv','10.73.2.2',8080)
            result['hvac_after']=probe(c,'hvac-after-v2-repeat','hg4-thermo','10.73.4.2',9000)
            result['v3_reauthorize']=fire(c,'v3-owner-revoke.json',store)
            result['hvac_with_new_policy']=probe(c,'hvac-v3','hg4-thermo','10.73.4.2',9000)
            result['tv_with_new_policy']=probe(c,'tv-v3','hg4-tv','10.73.2.2',8080)
        elif action=='replay-v1':
            result['old_v1']=fire(c,'v1-owner-allow.json',store)
            result['tv_after']=probe(c,'tv-after-v1','hg4-tv','10.73.2.2',8080)
            result['hvac_after']=probe(c,'hvac-after-v1','hg4-thermo','10.73.4.2',9000)
        elif action=='stale-v1-v2':
            result['old_v1']=fire(c,'v1-owner-allow.json',store)
            result['tv_after']=probe(c,'tv-after-v1','hg4-tv','10.73.2.2',8080)
            result['current_v2']=fire(c,'v2-owner-revoke.json',store)
            result['hvac_after']=probe(c,'hvac-after-v2','hg4-thermo','10.73.4.2',9000)
            result['tv_after_current']=probe(c,'tv-after-v2','hg4-tv','10.73.2.2',8080)
        elif action=='missing-policy':
            result['policy_missing']=fire(c,'missing',store,missing=True)
            result['tv_after']=probe(c,'tv-missing-policy','hg4-tv','10.73.2.2',8080)
            result['hvac_after']=probe(c,'hvac-missing-policy','hg4-thermo','10.73.4.2',9000)
        else:raise RuntimeError('bad action '+str(action))
    # Capture an entire post-policy TCP exchange before SIGINT: tcpdump can
    # otherwise report received kernel-filter packets it has not flushed.
    time.sleep(2.2)
    result['final_rules']=show_rules(c,'final.rules')
    result['final_counters']=ns('hg4-fw','iptables-save','-c').stdout
    save(c,'final-counters.rules',result['final_counters'])
    stop_capture(c)
    record(c,result)


def cleanup():
    try:
        for case in [x.name for x in ENV.iterdir() if x.is_dir()]:
            pass
        if captures:stop_capture('cleanup')
    except Exception:pass
    for name in NAMES:
        try:
            pids=root('ip','netns','pids',name,check=False).stdout.split()
            for pid in pids:root('kill','-TERM',pid,check=False)
        except Exception:pass
    for name in NAMES:
        root('ip','netns','del',name,check=False)
    for proc,fh in servers:
        try:proc.wait(timeout=2)
        except Exception:proc.terminate()
        fh.close()


def main():
    pre=ENV/'precondition'
    pre.mkdir(exist_ok=True)
    (ENV/'state').mkdir(parents=True,exist_ok=True)
    first_setup()
    (ENV/'environment.txt').write_text(command(('uname','-a')).stdout + root('ip','netns','list').stdout)
    from pathlib import Path
    import importlib.util
    spec=importlib.util.spec_from_file_location('ownerfixtures',HG3/'make_policies.py')
    fixture=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    pol=ENV/'policies'
    pol.mkdir(exist_ok=True)
    fixture_policies={'v1-owner-allow.json':fixture.policy(1,True),
                      'v2-owner-revoke.json':fixture.policy(2,False),
                      'v3-owner-revoke.json':fixture.policy(3,False)}
    for name,x in fixture_policies.items():
        (pol/name).write_text(json.dumps(x,sort_keys=True,indent=2)+'\n')
    live=ENV/'state'/'live.sqlite'
    listen('hg4-nvr','nvr','nvr-server.log')
    listen('hg4-hvac','hvac','hvac-server.log')
    applied_v1=fire('precondition','v1-owner-allow.json',live)
    copy_sqlite(live,ENV/'state'/'v1-snapshot.sqlite')
    ns('hg4-fw','sysctl','-qw','net.ipv4.ip_forward=1')
    initial_tv=probe('precondition','tv-authorized-v1','hg4-tv','10.73.2.2',8080)
    initial_hvac=probe('precondition','hvac-before-revoke','hg4-thermo','10.73.4.2',9000)
    applied_v2=fire('precondition','v2-owner-revoke.json',live)
    copy_sqlite(live,ENV/'state'/'v2-snapshot.sqlite')
    stopped_tv=probe('precondition','tv-revoked-v2','hg4-tv','10.73.2.2',8080)
    good_hvac=probe('precondition','hvac-after-revoke','hg4-thermo','10.73.4.2',9000)
    rows=(ENV/'precondition'/'receiver-receipts.jsonl').read_text().splitlines()
    if len(rows)!=2:raise RuntimeError('PRECONDITION no two signed receipts')
    (ENV/'independent-witness').mkdir(exist_ok=True)
    (ENV/'independent-witness'/'signed-v2-receipt.json').write_text(rows[-1]+'\n')
    (ENV/'independent-witness'/'v2-policy.json').write_bytes((pol/'v2-owner-revoke.json').read_bytes())
    save('precondition','observations.json',{'v1':applied_v1,'v2':applied_v2,'tv_allow':initial_tv,
         'hvac_allow':initial_hvac,'tv_revoke':stopped_tv,'hvac_revoke':good_hvac,
         'v2_ledger':version(live)})
    if any([applied_v1['status']!=0, applied_v2['status']!=0,
            initial_tv['status']!='ACK',initial_hvac['status']!='ACK',
            good_hvac['status']!='ACK',stopped_tv['status']=='ACK']):
        raise RuntimeError('PRECONDITION failed; no meaningful reboot test')
    # Baseline 'legacy' ordering: ip_forward is enabled before DROP, like HG3.
    scenario('unsafe-startup',ENV/'state'/'v2-snapshot.sqlite','unsafe','')
    # All later stages use explicitly fail-closed boot sequence for clearer state tests.
    fresh=ENV/'state'/'intact-v2.sqlite'
    copy_sqlite(ENV/'state'/'v2-snapshot.sqlite',fresh)
    scenario('intact-v2-recovery',fresh,'safe','repeat-v2')
    absent=ENV/'state'/'missing-state.sqlite'
    if absent.exists():absent.unlink()
    scenario('missing-state',absent,'safe','replay-v1')
    stale=ENV/'state'/'stale-v1.sqlite'
    copy_sqlite(ENV/'state'/'v1-snapshot.sqlite',stale)
    scenario('stale-state',stale,'safe','stale-v1-v2')
    replaced=ENV/'state'/'attacker-replaced.sqlite'
    copy_sqlite(ENV/'state'/'v2-snapshot.sqlite',replaced)
    db=sqlite3.connect(replaced)
    db.execute('UPDATE applied SET version=0 WHERE slot=1')
    db.commit();db.close()
    scenario('attacker-replaced',replaced,'safe','replay-v1')
    missingpolicy=ENV/'state'/'v2-missing-policy.sqlite'
    copy_sqlite(ENV/'state'/'v2-snapshot.sqlite',missingpolicy)
    scenario('missing-policy',missingpolicy,'safe','missing-policy')
    save('meta','completed.json',{'case_count':6,'witness_sha256':hashlib.sha256(rows[-1].encode()).hexdigest(),
                                  'warning':'namespace reset is not physical power outage'})


if __name__=='__main__':
    try:
        main()
    except BaseException as e:
        import traceback
        (ENV/'runner-failure.txt').write_text(traceback.format_exc())
        print('HG4 APPARATUS ERROR:',repr(e),file=sys.stderr)
        sys.exit(2)
    finally:
        cleanup()