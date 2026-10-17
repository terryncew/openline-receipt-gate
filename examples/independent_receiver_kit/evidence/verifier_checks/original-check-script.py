from pathlib import Path
from contextlib import closing
import json,sqlite3,subprocess,sys,tempfile
sys.path.insert(0,'/workspace/openline-receipt-gate')
from examples.independent_receiver_kit.fixtures import fixture,call,OUTCOME,T0
from examples.independent_receiver_kit.receiver import Receiver,canonical
from examples.independent_receiver_kit.verify import verify
from olp_gate.crypto import sign_olp_body
out=Path('/tmp/independent-verifier-evidence');out.mkdir(exist_ok=True)
log=[]
for mode in ['openline','conventional']:
 f=fixture(mode)
 base=out/f'{mode}-clean.db'
 if base.exists():base.unlink()
 clock=[T0]
 r=Receiver(base,f['config'],OUTCOME,mode,clock=lambda:clock[0])
 r.dispatch('/authority',f['events'][0]);r.dispatch('/submit',{'proof':call(f,mode)})
 config=out/f'{mode}-config.json';config.write_text(json.dumps(f['config']))
 cmd=[sys.executable,'/workspace/openline-receipt-gate/examples/independent_receiver_kit/verify.py','--state',str(base),'--config',str(config),'--mode',mode]
 p=subprocess.run(cmd,capture_output=True,text=True)
 assert p.returncode==0,p.stdout+p.stderr
 log.append({'case':f'{mode}-clean-cli','command':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
 mutations={
  'document':"UPDATE documents SET body='{}'",
  'consumption':"DELETE FROM consumed",
  'history-time':"UPDATE history SET accepted_at=accepted_at+1",
  'decision-signature':"UPDATE decisions SET body=replace(body,'local_document_committed','forged') WHERE seq=2",
 }
 for case,sql in mutations.items():
  db=out/f'{mode}-{case}.db'
  if db.exists():db.unlink()
  with closing(sqlite3.connect(base)) as c,closing(sqlite3.connect(db)) as dest:c.backup(dest)
  with closing(sqlite3.connect(db)) as c:c.execute(sql);c.commit()
  result=verify(db,f['config'],mode)
  assert not result['valid'],case
  log.append({'case':f'{mode}-{case}','result':result})
 db=out/f'{mode}-signed-expiry.db'
 if db.exists():db.unlink()
 with closing(sqlite3.connect(base)) as c,closing(sqlite3.connect(db)) as dest:c.backup(dest)
 with closing(sqlite3.connect(db)) as c:
  body=json.loads(c.execute('SELECT body FROM decisions WHERE seq=2').fetchone()[0]);body.pop('signature');body.pop('payload_hash');body['effect_at']=T0+30
  c.execute('UPDATE decisions SET body=? WHERE seq=2',(canonical(sign_olp_body(body,OUTCOME)),));c.commit()
 result=verify(db,f['config'],mode);assert not result['valid']
 log.append({'case':f'{mode}-signed-expiry','result':result})
(out/'check-log.json').write_text(json.dumps(log,indent=2)+'\n')
print(json.dumps([{'case':x['case'],'result':x.get('result',{}).get('errors',[]),'returncode':x.get('returncode')} for x in log],indent=2))
