"""Independent PHONE-GUARD? No. HOME-GUARD-004 packet and witness verifier.

Reads artifact PCAPs and original HG3 signed policy/receiver receipts but never
imports HOME-GUARD-003's updater or trusts its status messages as evidence.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3
import struct
import sys

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
HG1=REPO/'experiments/home-guard-001'
for p in [HG1,REPO]:
    sys.path.insert(0,str(p))
from home_guard import keys
from olp_gate.crypto import strict_json_loads,verify_olp_signature

E=Path(sys.argv[1])
verdicts={}
claims={}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def parse_pcap(path):
    data=path.read_bytes()
    if len(data)<24:raise ValueError('PCAP missing global header: '+str(path))
    modes={b'\xd4\xc3\xb2\xa1':('<',1),b'\xa1\xb2\xc3\xd4':('>',1),
           b'\x4d\x3c\xb2\xa1':('<',1000),b'\xa1\xb2\x3c\x4d':('>',1000)}
    if data[:4] not in modes:raise ValueError('Bad PCAP magic: '+str(path))
    end,res=modes[data[:4]]
    if struct.unpack_from(end+'I',data,20)[0]!=1:raise ValueError('not Ethernet PCAP')
    at=24;rows=[]
    while at<len(data):
        if at+16>len(data):raise ValueError('truncated frame header')
        sec,frac,n,wire=struct.unpack_from(end+'IIII',data,at);at+=16
        p=data[at:at+n];at+=n
        if len(p)<n:raise ValueError('truncated frame')
        if len(p)<54 or p[12:14]!=b'\x08\x00':continue
        ip=p[14:];header=(ip[0]&15)*4
        if (ip[0]>>4)!=4 or ip[9]!=6 or len(ip)<header+20:continue
        sport,dport=struct.unpack_from('!HH',ip,header)
        rows.append({'us':sec*1000000+frac//res,
                     'src':str(ipaddress.ip_address(ip[12:16])),
                     'dst':str(ipaddress.ip_address(ip[16:20])),
                     'sport':sport,'dport':dport,
                     'syn':bool(ip[header+13]&2),'ackflag':bool(ip[header+13]&16),
                     'payload':max(0,struct.unpack_from('!H',ip,2)[0]-header-((ip[header+12]>>4)*4))})
    if at!=len(data):raise ValueError('Unaccounted bytes in PCAP')
    return rows


def check_case(name):
    f=E/name
    obs=json.loads((f/'observations.json').read_text())
    tv=parse_pcap(f/'tv.pcap')
    nvr=parse_pcap(f/'nvr.pcap')
    hvac=parse_pcap(f/'hvac.pcap')
    src=[p for p in tv if p['src']=='10.73.1.2' and p['dst']=='10.73.2.2' and p['dport']==8080]
    sink=[p for p in nvr if p['src']=='10.73.1.2' and p['dst']=='10.73.2.2' and p['dport']==8080]
    ctl=[p for p in hvac if p['src']=='10.73.3.2' and p['dst']=='10.73.4.2' and p['dport']==9000]
    def nsmark(key):return int((f/(key+'.ns')).read_text())
    timeline={k:nsmark(k) for k in ['router-recreated','all-captures-armed','forwarding-enabled','capture-finished']}
    if (f/'default-drop-installed.ns').exists():timeline['default-drop-installed']=nsmark('default-drop-installed')
    ordered=timeline['router-recreated']<timeline['all-captures-armed']<timeline['forwarding-enabled']<timeline['capture-finished']
    # Captures are linked to actual namespace interfaces; even a timeout does not prove filtering.
    result={'observations':obs,'tv_source_packets':len(src),'nvr_received_packets':len(sink),
            'nvr_received_timestamps_ns':[p['us']*1000 for p in sink],
            'hvac_control_packets':len(ctl),'capture_armed_before_forwarding':ordered,
            'timeline_ns':timeline,'pcaps':{p.name:{'sha256':sha(p),'bytes':p.stat().st_size}
                                      for p in [f/'tv.pcap',f/'nvr.pcap',f/'hvac.pcap']}}
    return result


def assess(condition,*,inconclusive_if=False):
    if inconclusive_if:return 'INCONCLUSIVE'
    return 'PASS' if condition else 'FAIL'


def main():
    pre=json.loads((E/'precondition'/'observations.json').read_text())
    good=pre['v1']['status']==pre['v2']['status']==0 and pre['tv_allow']['status']=='ACK' and pre['hvac_allow']['status']=='ACK' and pre['tv_revoke']['status']!='ACK' and pre['hvac_revoke']['status']=='ACK' and pre['v2_ledger']==2
    verdicts['HG4-0-valid-precondition']=assess(good)
    if not good:raise RuntimeError('Precondition invalid; case verdicts inconclusive')

    names=['unsafe-startup','intact-v2-recovery','missing-state','stale-state','attacker-replaced','missing-policy']
    for name in names:
        claims[name]=check_case(name)

    unsafe=claims['unsafe-startup'];uo=unsafe['observations']; unsafe_ing=unsafe['tv_source_packets']>0
    drop_at=unsafe['timeline_ns'].get('default-drop-installed')
    before_drop=[t for t in unsafe['nvr_received_timestamps_ns'] if drop_at is not None and t < drop_at]
    unsafe_leak=bool(before_drop) and uo['first']['status']=='ACK'
    unsafe['nvr_received_before_default_DROP']=len(before_drop)
    verdicts['HG4-1-original-startup-no-early-leak']=assess(not before_drop,
        inconclusive_if=not unsafe_ing or not unsafe['capture_armed_before_forwarding'] or drop_at is None)
    claims['unsafe-startup']['observed_exposure']=unsafe_leak

    safe=claims['intact-v2-recovery'];so=safe['observations']
    safe_boot=safe['tv_source_packets']>0 and safe['nvr_received_packets']==0 and safe['capture_armed_before_forwarding'] and so['pre']['status']!='ACK'
    safe_allow=so['hvac_with_new_policy']['status']=='ACK' and safe['hvac_control_packets']>0
    verdicts['HG4-2-explicit-safe-boot-ordering']=assess(safe_boot and safe_allow)
    intact=so['v2_same']['status']==0 and so['hvac_after']['status']=='ACK' and so['tv_after']['status']!='ACK'
    verdicts['HG4-3-intact-ledger-recovers-same-policy']=assess(intact)
    verdicts['HG4-3-traffic-stays-contained']=assess(safe_boot)
    claims['intact-v2-recovery']['fresh-v3-operator-action-required']=so['v2_same']['status']!=0 and so['v3_reauthorize']['status']==0

    miss=claims['missing-state'];mo=miss['observations']
    verdicts['HG4-4-missing-ledger-no-revoked-TV-reopen']=assess(mo['old_v1']['status']!=0 and miss['nvr_received_packets']==0,
                                                              inconclusive_if=miss['tv_source_packets']==0)

    stale=claims['stale-state'];st=stale['observations']
    # Strictly inspect PCAP timing: the NVR should never see TV during this case.
    verdicts['HG4-5-stale-ledger-refuses-old-and-accepts-new']=assess(
        st['old_v1']['status']!=0 and st['current_v2']['status']==0 and stale['nvr_received_packets']==0 and st['hvac_after']['status']=='ACK',
        inconclusive_if=stale['tv_source_packets']==0)

    repl=claims['attacker-replaced'];ro=repl['observations']
    verdicts['HG4-6-replaced-ledger-cannot-reopen-old-TV']=assess(
        ro['old_v1']['status']!=0 and repl['nvr_received_packets']==0,
        inconclusive_if=repl['tv_source_packets']==0)

    absent=claims['missing-policy'];ao=absent['observations']
    verdicts['HG4-7-missing-policy-containment']=assess(
        ao['tv_after']['status']!='ACK' and absent['nvr_received_packets']==0,
        inconclusive_if=absent['tv_source_packets']==0)
    receipt_path=E/'missing-policy'/'receiver-receipts.jsonl'
    has_signed_rejection=False
    if receipt_path.exists():
        for line in receipt_path.read_text().splitlines():
            rec=strict_json_loads(line)
            valid,_=verify_olp_signature(rec)
            has_signed_rejection|=valid and rec.get('decision')=='REJECTED'
    verdicts['HG4-7-missing-policy-signed-error-evidence']=assess(has_signed_rejection)
    claims['missing-policy']['exception_in_stderr']='FileNotFoundError' in ao['policy_missing']['stderr']

    # A separate, preserved witness allows an *observer* to expose rollback.
    # It is not checked by the existing policy_gate.py and not a secure remote archive.
    witness=strict_json_loads((E/'independent-witness'/'signed-v2-receipt.json').read_text())
    valid,why=verify_olp_signature(witness)
    pinned_receiver=keys.public_key_hex_of('receiver')
    signed_v2=strict_json_loads((E/'independent-witness'/'v2-policy.json').read_text())
    validp,whyp=verify_olp_signature(signed_v2)
    pinned_owner=keys.public_key_hex_of('owner')
    trusted=valid and witness['signature']['public_key']==pinned_receiver and witness['requested_version']==2 and validp and signed_v2['signature']['public_key']==pinned_owner and witness['policy_file_sha256']==sha(E/'independent-witness'/'v2-policy.json')
    flags={}
    for case in ['missing-state','attacker-replaced']:
        obs=claims[case]
        flags[case]={'ledger_below_signed_v2_witness':obs['observations']['ledger_version']<2,
                     'outcome_reopens_prohibited_tv':obs['nvr_received_packets']>0,
                     'witness_signed_valid':bool(trusted)}
    claims['witness']=flags
    verdicts['HG4-8-conditional-offline-witness-detects-local-rollback']=assess(trusted and all(v['ledger_below_signed_v2_witness'] and v['outcome_reopens_prohibited_tv'] for v in flags.values()))
    verdicts['HG4-8-existing-updater-enforces-witness']=assess(all(claims[x]['nvr_received_packets']==0 for x in ['missing-state','attacker-replaced']))
    verdicts['HG4-9-physical-power-loss']='INCONCLUSIVE'

    summary={'experiment':'HOME-GUARD-004','baseline':'44486057320e908ec091c327112d830f65e20caa',
             'preregistered_commit':'19a76732fcc456838f4ecc2991ca7fdb9f8e328f',
             'independent_witness_trust':'conditionally assumed archival fixture, TEST KEYS PUBLIC',
             'verdicts':verdicts,'observations':claims,
             'limitations':['no electrical power cut or boot firmware', 'not a compromised-root proof',
               'only earliest activity visible after recreated virtual interfaces','no independent tamperproof storage']}
    (E/'REPORT.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    for k,v in verdicts.items():print(k+': '+v)
    print('RAW_PCAP_AND_RECEIPT_REVIEW_COMPLETE')


if __name__=='__main__':
    main()
