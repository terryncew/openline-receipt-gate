"""Offline paired HTTP demonstration and adverse cases; no model/provider calls."""
import argparse,concurrent.futures,copy,hashlib,json,selectors,sqlite3,subprocess,sys,tempfile,time
from pathlib import Path
from contextlib import closing
from urllib.request import Request,urlopen
from . import adapter,fixtures as f
from openline_wallet import Wallet
from openline_wallet.crypto import sign_record,public_key_hex
from olp_gate.crypto import verify_olp_signature
from examples.independent_receiver_kit.formats import _jwt_encode,_jwt_decode

def save(p,v):Path(p).write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
class Server:
    def __init__(self,folder,config,mode,at):
        self.folder=folder;self.mode=mode;folder.mkdir(parents=True,exist_ok=True)
        save(folder/'config.json',config);(folder/'receiver-test-key.txt').write_text('74'*32+'\n')
        self.err=open(folder/'server.stderr','a')
        self.p=subprocess.Popen([sys.executable,'-m','examples.wallet_receiver_interop.serve','--state',str(folder/'state.sqlite3'),
            '--config',str(folder/'config.json'),'--key',str(folder/'receiver-test-key.txt'),'--mode',mode,'--fixture-clock',str(at)],
            stdout=subprocess.PIPE,stderr=self.err,text=True)
        sel=selectors.DefaultSelector();sel.register(self.p.stdout,selectors.EVENT_READ)
        if not sel.select(15):self.close();raise RuntimeError('server_start_timeout')
        line=self.p.stdout.readline();sel.close()
        if not line:self.close();raise RuntimeError((folder/'server.stderr').read_text())
        self.url='http://127.0.0.1:'+str(json.loads(line)['port'])
    def post(self,route,obj):
        with urlopen(Request(self.url+route,data=json.dumps(obj).encode(),headers={'Content-Type':'application/json'}),timeout=10) as r:
            result=json.load(r)
        assert result['signature']['public_key']==self.config_key
        assert verify_olp_signature(result)[0]
        return result
    @property
    def config_key(self):return public_key_hex(f.OUTCOME)
    def close(self):
        if self.p.poll() is None:self.p.terminate()
        self.p.wait(timeout=10);self.err.close()

def verify(folder,mode):
    p=subprocess.run([sys.executable,'-m','examples.wallet_receiver_interop.verify','--state',str(folder/'state.sqlite3'),
        '--config',str(folder/'config.json'),'--mode',mode],capture_output=True,text=True,timeout=20)
    (folder/'verification.stdout').write_text(p.stdout);(folder/'verification.stderr').write_text(p.stderr)
    return json.loads(p.stdout)

def run_case(root,fx,mode,name):
    folder=root/mode/name;s=Server(folder,fx['config'],mode,f.T0+20);out=[];start=time.perf_counter()
    def post(route,obj,expected):
        started=time.perf_counter();result=s.post(route,obj);latencies.append({'route':route,'seconds':time.perf_counter()-started});out.append(result);assert result['verdict']==expected,(name,result);return result
    a=f.authority(fx,mode,0);req=f.call(fx,mode)
    expected_docs=0;expected_valid=True;latencies=[]
    try:
        if name=='forged_authority':
            if mode=='wallet':a['events'][0]['data']['scopes']=['forged']
            else:a['credential']=a['credential'][:-8]+'AAAAAAAA'
            post('/authority',a,'DENY')
        elif name=='untrusted_root':
            other=copy.deepcopy(fx);other['config']['owner_key']=public_key_hex(f.ATTACKER)
            if mode=='wallet':
                a=sign_record({k:v for k,v in a.items() if k not in ('payload_hash','signature')},f.ATTACKER)
                a['principal']['root_public_key']=public_key_hex(f.ATTACKER)
            else:
                claims=_jwt_decode(a['credential'],public_key=fx['config']['owner_key'],issuer=fx['config']['owner_id'],audience=fx['config']['receiver_id'],at=f.T0+20)
                a={'credential':_jwt_encode(claims,f.ATTACKER)}
            post('/authority',a,'DENY')
        else:
            post('/authority',a,'ACCEPT')
            if name=='allow':post('/submit',req,'ALLOW');expected_docs=1
            elif name=='replay':post('/submit',req,'ALLOW');post('/submit',req,'DENY');expected_docs=1
            elif name=='oversize':post('/submit',f.call(fx,mode,text='x'*129),'DENY')
            elif name=='mismatch':post('/submit',f.call(fx,mode,changes=lambda c:c['effect'].update(target='records://other')),'DENY')
            elif name=='money':post('/submit',f.call(fx,mode,changes=lambda c:c['effect'].update(value_cents=1)),'DENY')
            elif name=='wrong_audience':post('/submit',f.call(fx,mode,changes=lambda c:c.update(aud='receiver:other')),'DENY')
            elif name=='forged_worker':post('/submit',f.call(fx,mode,worker=f.ATTACKER),'DENY')
            elif name=='wrong_principal':post('/submit',f.call(fx,mode,changes=lambda c:c['effect'].update(principal_id='other')),'DENY')
            elif name=='bundle_expiry':
                s.close();s=Server(folder,fx['config'],mode,f.T0+61);post('/authority',a,'DENY');post('/submit',req,'DENY')
            elif name=='duplicate_no_refresh':
                post('/authority',a,'ACCEPT')
                s.close();s=Server(folder,fx['config'],mode,f.T0+60);post('/submit',req,'DENY')
            elif name=='expiry':post('/submit',f.call(fx,mode,changes=lambda c:c.update(exp=f.T0+20)),'DENY')
            elif name=='revocation':
                post('/authority',f.authority(fx,mode,1),'ACCEPT');post('/submit',req,'DENY');post('/authority',a,'DENY');post('/submit',req,'DENY')
            elif name=='succession':
                post('/submit',req,'ALLOW');expected_docs=2
                post('/authority',f.authority(fx,mode,1),'ACCEPT');post('/submit',req,'DENY')
                s.close();s=Server(folder,fx['config'],mode,f.T0+20)
                post('/authority',f.authority(fx,mode,2),'ACCEPT');post('/submit',f.call(fx,mode,index=2,nonce='successor'),'ALLOW');post('/submit',req,'DENY')
            elif name=='unauthorized_successor':post('/submit',f.call(fx,mode,index=2),'DENY')
            elif name=='skipped_delivery':
                post('/authority',f.authority(fx,mode,2),'ACCEPT');post('/submit',req,'DENY');post('/submit',f.call(fx,mode,index=2),'ALLOW');expected_docs=1
            elif name=='freshness':
                s.close();s=Server(folder,fx['config'],mode,f.T0+60);post('/submit',req,'DENY')
            elif name=='policy':
                changed=copy.deepcopy(fx['config']);changed['policy']['max_document_chars']=0
                s.close()
                with closing(sqlite3.connect(folder/'state.sqlite3')) as c:
                    c.execute('UPDATE settings SET body=?',(json.dumps(changed),));c.commit()
                s=Server(folder,fx['config'],mode,f.T0+20);post('/submit',req,'DENY')
            elif name=='concurrent':
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:s.post('/submit',req),range(4)))
                out.extend(results);assert sorted(x['verdict'] for x in results)==['ALLOW','DENY','DENY','DENY'];expected_docs=1
            elif name=='bypass':post('/raw-write',{'document':{'text':'bypass'}},'DENY')
            elif name=='fork':
                with tempfile.TemporaryDirectory() as tmp:
                    w=Wallet.create(Path(tmp)/'fork',root_key=f.OWNER,epoch_key=f.key('76'),now=f.dt(f.T0))
                    w.grant(subject_id='other',subject_public_key=public_key_hex(f.B),scopes=[adapter.SCOPE],expires_at=f.dt(f.T0+300),now=f.dt(f.T0),mandate_id='fork-grant')
                    fork=copy.deepcopy(fx);fork['bundles'][0]=w.export_bundle(now=f.dt(f.T0),ttl_seconds=60)
                    post('/authority',f.authority(fork,mode,0),'DENY')
                s.close();s=Server(folder,fx['config'],mode,f.T0+20)
                post('/submit',req,'DENY');post('/authority',a,'DENY')
            elif name=='unknown_scope':
                with tempfile.TemporaryDirectory() as tmp:
                    w=Wallet.create(Path(tmp)/'other',root_key=f.OWNER,epoch_key=f.key('76'),now=f.dt(f.T0))
                    w.grant(subject_id='worker-a',subject_public_key=public_key_hex(f.A),scopes=['deploy:staging'],expires_at=f.dt(f.T0+300),now=f.dt(f.T0),mandate_id='other-scope')
                    other=copy.deepcopy(fx);other['bundles'][0]=w.export_bundle(now=f.dt(f.T0),ttl_seconds=60)
                    # Separate clean receiver: authentic unrelated scope has no document permission.
                    s.close();save(folder/'responses.json',out);assert verify(folder,mode)['valid'];folder=root/mode/(name+'-actual');s=Server(folder,fx['config'],mode,f.T0+20);out=[]
                    post('/authority',f.authority(other,mode,0),'ACCEPT');post('/submit',f.call(other,mode),'DENY')
            elif name=='mutated_document':
                post('/submit',req,'ALLOW');expected_docs=1;expected_valid=False
                s.close()
                with closing(sqlite3.connect(folder/'state.sqlite3')) as c:
                    c.execute("UPDATE documents SET body='{}'");c.commit()
                s=None
            else:raise AssertionError(name)
    finally:
        if s:s.close()
    save(folder/'responses.json',out)
    save(folder/'latency.json',latencies)
    with closing(sqlite3.connect(folder/'state.sqlite3')) as c:
        c.row_factory=sqlite3.Row
        rows={t:[dict(r) for r in c.execute('SELECT * FROM '+t)] for t in ('settings','history','documents','consumed','decisions')}
    c.close()
    save(folder/'rows.json',rows);assert len(rows['documents'])==expected_docs,(name,len(rows['documents']))
    result=verify(folder,mode);assert result['valid']==expected_valid,(name,result)
    return {'case':name,'mode':mode,'documents':expected_docs,'verifier_valid':result['valid'],
            'expected_verifier_valid':expected_valid,'seconds':time.perf_counter()-start,'path':str(folder.relative_to(root))}

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    root=a.output.resolve();root.mkdir(parents=True,exist_ok=False);start=time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:fx=f.create(tmp)
    save(root/'fixtures.json',fx)
    for i,b in enumerate(fx['bundles']):save(root/f'wallet-{i}.olw',b)
    cases=['allow','oversize','mismatch','money','wrong_audience','wrong_principal','bundle_expiry','duplicate_no_refresh','forged_authority','untrusted_root','forged_worker','replay','expiry','revocation','succession','unauthorized_successor','skipped_delivery','freshness','policy','concurrent','bypass','fork','unknown_scope','mutated_document']
    results=[]
    for mode in sorted(adapter.MODES):
        for case in cases:
            result=run_case(root,fx,mode,case);results.append(result);print(json.dumps(result),flush=True)
    assert [(r['case'],r['documents'],r['verifier_valid']) for r in results[:len(cases)]]==[(r['case'],r['documents'],r['verifier_valid']) for r in results[len(cases):]]
    save(root/'summary.json',{'verdict':'BOUNDED_PARITY','cases':len(results),'results':results,'elapsed_seconds':time.perf_counter()-start,
        'limitations':['Synthetic local documents only','Public test keys and fixed clock','No independent organizational adoption','Shared receiver and cryptographic codecs; separate-process state replay','No production or external-effect atomicity']})
    hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}
    save(root/'hashes.json',hashes)
if __name__=='__main__':main()
