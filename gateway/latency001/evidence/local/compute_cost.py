import json,time,sys,statistics
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
sys.path.insert(0,'/workspace/openline-receipt-gate')
from olp_gate.mandate import compile_verified_commit_settings
from olp_gate.mandate_gate import mandate_preflight

def summarize(x):
    x=sorted(x)
    def p(f):
      k=(len(x)-1)*f; i=int(k); j=min(i+1,len(x)-1);return x[i]+(x[j]-x[i])*(k-i)
    return {'n':len(x),'p50_ms':p(.5),'p95_ms':p(.95),'p99_ms':p(.99),'mean_ms':statistics.mean(x)}
def bench(f):
    xs=[]
    for i in range(11000):
        t=time.perf_counter();f();dt=(time.perf_counter()-t)*1000
        if i>=1000:xs.append(dt)
    return summarize(xs)
key=Ed25519PrivateKey.generate();pub_bytes=key.public_key().public_bytes_raw();raw=b'x'*300;sig=key.sign(raw)
mandate={'profile':'principal_mandate/v1','mandate_id':'test','principal_id':'owner:gateway-owner','agent_id':'bench','purpose':'gateway-pilot','allowed_action_types':['authorize_payment','inspect'],'allowed_targets':['ledger'],'allowed_disclosure_classes':[],'forbidden_disclosure_classes':[],'max_settlement_cents':0,'max_payment_cents':10000,'delegation_allowed':False,'expires_at':'2030-10-11T00:00:00Z','version':'1'}
effect={'profile':'principal_effect/v1','effect_id':'fx-test','mandate_id':'test','principal_id':'owner:gateway-owner','agent_id':'bench','purpose':'gateway-pilot','action_type':'authorize_payment','target':'ledger','disclosures':[],'value_cents':100,'delegatee':None,'producer_model':'unknown'}
def mandate_both():
    now=datetime.now(timezone.utc)
    settings=compile_verified_commit_settings(mandate,effect,now=now)
    assert mandate_preflight(mandate,settings,now=now)['allowed']
print(json.dumps({'verify_with_key_reconstruction':bench(lambda:Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig,raw)),'sign':bench(lambda:key.sign(raw)),'mandate_compile_and_preflight':bench(mandate_both)},indent=2))
