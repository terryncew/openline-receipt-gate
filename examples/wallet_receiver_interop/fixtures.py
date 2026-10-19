"""Real unchanged Wallet API, public fixture keys, synthetic document scope only."""
from copy import deepcopy
from datetime import datetime,timezone
from pathlib import Path
from openline_wallet import Wallet
from openline_wallet.crypto import public_key_hex
from examples.independent_receiver_kit.fixtures import OWNER,A,B,OUTCOME,ATTACKER,T0,key
from examples.independent_receiver_kit.formats import _jwt_encode
from . import adapter

def dt(t):return datetime.fromtimestamp(t,timezone.utc)

def create(root):
    wallet=Wallet.create(Path(root)/'issuer-private-test-fixture',root_key=OWNER,epoch_key=key('76'),now=dt(T0))
    wallet.grant(subject_id='worker-a',subject_public_key=public_key_hex(A),scopes=[adapter.SCOPE],
        expires_at=dt(T0+300),now=dt(T0),mandate_id='document-a')
    a=wallet.export_bundle(now=dt(T0),ttl_seconds=60)
    wallet.revoke('worker-a',now=dt(T0+10))
    revoked=wallet.export_bundle(now=dt(T0+10),ttl_seconds=60)
    wallet.grant(subject_id='worker-b',subject_public_key=public_key_hex(B),scopes=[adapter.SCOPE],
        expires_at=dt(T0+300),now=dt(T0+20),mandate_id='document-b')
    b=wallet.export_bundle(now=dt(T0+20),ttl_seconds=60)
    config=dict(receiver_id='receiver:local-lab',owner_id=wallet.principal_id,owner_key=wallet.root_public_key,
        slot_id='intake/default',outcome_key=public_key_hex(OUTCOME),policy=dict(version=1,tool='intake.submit',
        target=adapter.TARGET,max_document_chars=128,freshness_seconds=60))
    return {'config':config,'bundles':[a,revoked,b]}

def authority(f,mode,index):
    bundle=f['bundles'][index]
    if mode=='wallet':return deepcopy(bundle)
    # The OWNER issues the equivalent JWT, never the receiver. JWT carries a
    # root-endorsed complete snapshot; no Wallet/native signatures are invented.
    issued=adapter._epoch(bundle['issued_at']);_,views=adapter.wallet_views(bundle,issued)
    claims=dict(iss=f['config']['owner_id'],sub=views[-1]['subject'],aud=f['config']['receiver_id'],
        iat=issued,nbf=issued,exp=adapter._epoch(bundle['expires_at']),jti='snapshot-'+str(index),snapshot=views)
    return {'credential':_jwt_encode(claims,OWNER)}

def call(f,mode,index=0,at=T0+20,nonce='request-1',text='synthetic document',worker=None,changes=None):
    packet=authority(f,mode,index);h=adapter.parse_head(mode,packet,f['config'],at)
    k=worker or (B if index==2 else A);subject=public_key_hex(k)
    effect=dict(profile='principal_effect/v1',effect_id=nonce,mandate_id=h['mandate_id'],
        principal_id=f['config']['owner_id'],agent_id=subject,purpose=adapter.SCOPE,action_type='send',
        target=adapter.TARGET,disclosures=[],value_cents=0,delegatee=None,producer_model='synthetic worker')
    claims=dict(iss=subject,sub=subject,aud=f['config']['receiver_id'],iat=at,nbf=at,exp=at+30,jti=nonce,
        policy_hash=adapter.digest(f['config']['policy']),head_hash=h['hash'],effect=effect,
        document={'record_id':nonce,'text':text})
    if changes:changes(claims)
    return {'proof':adapter.encode_call(mode,claims,k)}
