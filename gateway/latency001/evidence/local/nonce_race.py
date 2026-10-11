import sys,tempfile,json,time,hashlib,threading,uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0,'/workspace/openline-receipt-gate/gateway')
from authz_server import GatewayState,Authorizer,b64u_encode,canonical
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
source=Path('/workspace/openline-receipt-gate/gateway/authz_server.py')
result={'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'schedule':'two workers synchronized after nonce SELECT and before INSERT OR IGNORE; actual original _evaluate and GatewayState writes','rounds':[]}
with tempfile.TemporaryDirectory(prefix='nonce-race-',dir='/workspace/gateway-latency-scratch') as tmp:
  state=GatewayState(Path(tmp)/'gateway.db')
  priv=Ed25519PrivateKey.generate();aid='race'
  mandate={'profile':'principal_mandate/v1','mandate_id':'test','principal_id':'owner:gateway-owner','agent_id':aid,'purpose':'gateway-pilot','allowed_action_types':['authorize_payment','inspect'],'allowed_targets':['ledger'],'allowed_disclosure_classes':[],'forbidden_disclosure_classes':[],'max_settlement_cents':0,'max_payment_cents':10000,'delegation_allowed':False,'expires_at':'2030-10-11T00:00:00Z','version':'1'}
  state.db.execute('INSERT INTO agents VALUES(?,?,?,0)',(aid,b64u_encode(priv.public_key().public_bytes_raw()),json.dumps(mandate)));state.db.commit()
  authorizer=Authorizer.__new__(Authorizer);authorizer.state=state
  original_seen=state.nonce_seen
  for i in range(20):
    barrier=threading.Barrier(2)
    def amplified_seen(nonce):
      seen=original_seen(nonce)
      barrier.wait(timeout=5)
      return seen
    state.nonce_seen=amplified_seen
    action={'agent_id':aid,'action_type':'authorize_payment','target':'ledger','value_cents':100,'nonce':str(uuid.uuid4()),'ts':time.time()}
    action64=b64u_encode(canonical(action));sig64=b64u_encode(priv.sign(canonical(action)))
    def evaluate():
      try:return authorizer._evaluate(aid,action64,sig64)[0]
      except Exception as exc:return type(exc).__name__+': '+str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:
      futures=[pool.submit(evaluate) for _ in range(2)]
      out=[f.result() for f in futures]
    result['rounds'].append(out)
  result['duplicate_allow_rounds']=sum(v==['allow','allow'] for v in result['rounds'])
  state.db.close()
print(json.dumps(result,indent=2))
