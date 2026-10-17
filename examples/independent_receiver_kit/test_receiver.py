"""Exercise real local HTTP routes and inspect actual SQLite effects."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import jwt

from examples.independent_receiver_kit.fixtures import fixture,call,T0,A,OWNER,OUTCOME,ATTACKER
from examples.independent_receiver_kit.formats import encode_call
from examples.independent_receiver_kit.receiver import Receiver,make_server,canonical
from examples.independent_receiver_kit.demo import post
from olp_gate.crypto import sign_olp_body

OUTPUT=Path(os.environ.get('RECEIVER_KIT_EVIDENCE',tempfile.mkdtemp(prefix='receiver-kit-tests-')))


class OpenLineTests(unittest.TestCase):
    mode='openline'
    def setUp(self):
        self.root=OUTPUT/self.mode/self._testMethodName;self.root.mkdir(parents=True,exist_ok=False)
        self.f=fixture(self.mode);self.now=T0+20
        (self.root/'config.json').write_text(canonical(self.f['config']))
        self.db=self.root/'state.sqlite3'
        self.r=Receiver(self.db,self.f['config'],OUTCOME,self.mode,clock=lambda:self.now)
        self.server=make_server(self.r)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.01},daemon=True);self.thread.start()
        self.port=self.server.server_address[1]
        self.expected=0;self.verifier_ok=True

    def send(self,path,data):return post(self.port,path,data)
    def admit(self,index=0):return self.send('/authority',self.f['events'][index])
    def proof(self,**kw):return call(self.f,self.mode,at=self.now,**kw)
    def submit(self,proof=None):return self.send('/submit',{'proof':proof if proof is not None else self.proof()})
    def claims(self,token):
        return ({k:v for k,v in token.items() if k not in ('schema','payload_hash','signature')}
                if self.mode=='openline' else jwt.decode(token,options={'verify_signature':False}))
    def modified(self,field,value,key=A):
        body=self.claims(self.proof())
        if '.' in field:
            outer,inner=field.split('.');body[outer][inner]=value
        else:body[field]=value
        return encode_call(self.mode,body,key)
    def rows(self):
        with sqlite3.connect(self.db) as c:
            c.row_factory=sqlite3.Row
            return {name:[dict(r) for r in c.execute('SELECT * FROM '+name)]
                    for name in ('settings','history','documents','consumed','decisions')}
    def tearDown(self):
        self.server.shutdown();self.thread.join();self.server.server_close()
        rows=self.rows();(self.root/'rows.json').write_text(json.dumps(rows,indent=2)+'\n')
        self.assertEqual(len(rows['documents']),self.expected)
        run=subprocess.run([sys.executable,'-m','examples.independent_receiver_kit.verify','--state',str(self.db),
                            '--config',str(self.root/'config.json'),'--mode',self.mode],text=True,capture_output=True)
        (self.root/'verifier.json').write_text(run.stdout)
        (self.root/'verifier.stderr').write_text(run.stderr)
        self.assertEqual(run.returncode,0 if self.verifier_ok else 1,run.stdout+run.stderr)

    def test_01_external_owner_provider_succession(self):
        self.assertEqual(self.admit()['verdict'],'ACCEPT')
        self.assertEqual(self.submit(self.proof(nonce='a',record_id='a'))['verdict'],'ALLOW');self.expected=1
        self.assertEqual(self.admit(1)['verdict'],'ACCEPT')
        self.assertEqual(self.submit(self.proof(nonce='old-a',record_id='old-a'))['verdict'],'DENY')
        self.assertEqual(self.admit(2)['verdict'],'ACCEPT')
        self.assertEqual(self.submit(self.proof(worker='b',nonce='b',record_id='b'))['verdict'],'ALLOW');self.expected=2
        self.assertEqual(self.submit(self.proof(nonce='a-again',record_id='a-again'))['verdict'],'DENY')
        # Restart receiver object over persisted organization-owned history.
        restarted=Receiver(self.db,self.f['config'],OUTCOME,self.mode,clock=lambda:self.now)
        self.assertEqual(restarted.dispatch('/submit',{'proof':self.proof(nonce='stale-worker',record_id='stale-worker')})['verdict'],'DENY')
        self.assertEqual(len(self.rows()['history']),3)

    def test_02_forged_signatures(self):
        self.admit()
        self.assertEqual(self.submit(self.modified('jti','attacker-proof',ATTACKER))['verdict'],'DENY')
        e=copy.deepcopy(self.f['events'][0])
        if self.mode=='openline':
            body={k:v for k,v in e['authorization'].items() if k not in ('payload_hash','signature')}
            e['authorization']=sign_olp_body(body,ATTACKER)
        else:
            claims=jwt.decode(e['credential'],options={'verify_signature':False});e={'credential':jwt.encode(claims,ATTACKER,algorithm='EdDSA')}
        self.assertEqual(self.send('/authority',e)['verdict'],'DENY')

    def test_03_unknown_principal(self):
        alternate=fixture(self.mode)
        if self.mode=='openline':
            e=copy.deepcopy(alternate['events'][0]);body={k:v for k,v in e['authorization'].items() if k not in ('signature','payload_hash')}
            body['owner_id']='unknown';e['authorization']=sign_olp_body(body,OWNER)
        else:
            claims=jwt.decode(alternate['events'][0]['credential'],options={'verify_signature':False});claims['iss']='unknown'
            e={'credential':jwt.encode(claims,OWNER,algorithm='EdDSA')}
        self.assertEqual(self.send('/authority',e)['verdict'],'DENY')

    def test_04_wrong_subject_or_audience(self):
        self.admit()
        for field,value in [('sub','00'*32),('aud','receiver:wrong')]:
            self.assertEqual(self.submit(self.modified(field,value))['verdict'],'DENY')

    def test_05_changed_target_or_action_parameters(self):
        self.admit()
        self.assertEqual(self.submit(self.modified('effect.target','records://wrong/intake'))['verdict'],'DENY')
        self.assertEqual(self.submit(self.modified('document.text','x'*129))['verdict'],'DENY')
        token=self.proof()
        if self.mode=='openline':token['document']['text']='tampered'
        else:
            parts=token.split('.');import base64
            payload=jwt.decode(token,options={'verify_signature':False});payload['document']['text']='tampered'
            parts[1]=base64.urlsafe_b64encode(canonical(payload).encode()).decode().rstrip('=');token='.'.join(parts)
        self.assertEqual(self.submit(token)['verdict'],'DENY')

    def test_06_expired_call(self):
        self.admit();token=self.proof();self.now+=31
        self.assertEqual(self.submit(token)['verdict'],'DENY')

    def test_07_revoked_and_old_history_cannot_reinstall(self):
        self.admit();self.admit(1)
        self.assertEqual(self.admit()['verdict'],'DENY')
        self.assertEqual(self.submit()['verdict'],'DENY')
        self.assertEqual(len(self.rows()['history']),2)

    def test_08_missing_or_stale_history(self):
        self.assertEqual(self.submit()['verdict'],'DENY')
        self.admit();self.now=T0+61
        self.assertEqual(self.submit()['verdict'],'DENY')
        self.assertEqual(self.admit()['verdict'],'ACCEPT') # duplicate cannot refresh issue time
        self.assertEqual(self.submit()['verdict'],'DENY')

    def test_09_replay(self):
        self.admit();token=self.proof()
        self.assertEqual(self.submit(token)['verdict'],'ALLOW');self.expected=1
        d=self.submit(token);self.assertEqual(d['verdict'],'DENY');self.assertIsNone(d['effect_at'])

    def test_10_changed_receiver_policy(self):
        self.admit();token=self.proof()
        policy=copy.deepcopy(self.f['config']['policy']);policy['version']=2;self.r.policy(policy)
        self.assertEqual(self.submit(token)['verdict'],'DENY')

    def test_11_unauthorized_successor(self):
        self.admit()
        self.assertEqual(self.submit(self.proof(worker='b'))['verdict'],'DENY')
        self.assertEqual(self.admit(2)['verdict'],'DENY') # missing seq2 cannot jump history

    def test_12_unguarded_http_route(self):
        self.assertEqual(self.send('/raw-write',{'record_id':'bypass','text':'not accepted'})['verdict'],'DENY')
        self.assertEqual(self.send('/admin/policy',{'allow_all':True})['verdict'],'DENY')

    def test_13_privileged_database_bypass_out_of_scope(self):
        # Negative result: OS/database write access is outside this HTTP guard.
        with sqlite3.connect(self.db) as c:c.execute('INSERT INTO documents VALUES(?,?,?)',('privileged','{}','00'*32))
        self.expected=1;self.verifier_ok=False
        self.assertEqual(len(self.rows()['documents']),1)

    def test_14_concurrent_replay(self):
        self.admit();token=self.proof()
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(4) as pool:results=list(pool.map(lambda _:self.submit(token),range(4)))
        self.assertEqual([d['verdict'] for d in results].count('ALLOW'),1);self.expected=1

    def test_15_zero_value_and_request_binding(self):
        self.admit()
        self.assertEqual(self.submit(self.modified('effect.value_cents',1))['verdict'],'DENY')
        self.assertEqual(self.submit(self.modified('document.record_id','mismatch'))['verdict'],'DENY')
        self.assertEqual(self.send('/submit',{'proof':self.proof(),'untrusted_subject':'owner'})['verdict'],'DENY')

    def test_16_duplicate_history_never_renews_freshness(self):
        self.admit();self.now=T0+59
        self.assertEqual(self.admit()['verdict'],'ACCEPT')
        self.now=T0+60
        self.assertEqual(self.submit()['verdict'],'DENY')
        self.assertEqual(len(self.rows()['history']),1)


class ConventionalTests(OpenLineTests):mode='conventional'
