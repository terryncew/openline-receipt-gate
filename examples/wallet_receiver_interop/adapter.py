"""Verified projection, never a replacement owner-signed native mandate.

Wallet source is an external pinned dependency. Only the named document scope
maps to this receiver operation. Owner authority and receiver policy stay distinct.
"""
from datetime import datetime, timezone
from openline_wallet.wallet import verify_bundle, replay_events
from openline_wallet.errors import WalletError
from openline_wallet.crypto import record_hash
from olp_gate.crypto import olp_canonical_json, sha256_hex
from examples.independent_receiver_kit import formats as base

SCOPE = 'intake.submit:records://local-lab/intake'
TARGET = 'records://local-lab/intake'
MODES = {'wallet', 'wallet-jwt'}
VIEW = {'event_hash','state','subject','mandate_id','mandate_hash','scopes','expires'}

def digest(value):
    return sha256_hex(olp_canonical_json(value))

def _mode(mode):
    if mode not in MODES:
        raise ValueError('mode_invalid')

def _epoch(s):
    return base._epoch(s)

def wallet_views(bundle, at):
    """Verify every signature and replay each prefix; select its last-event grant.

    A single-slot receiver may restrict an owner's wider set of grants. It must
    never synthesize extra scope or re-sign this projection as owner authority.
    """
    try:
        verified, _ = verify_bundle(bundle, now=datetime.fromtimestamp(at,timezone.utc))
        views=[]
        for i,event in enumerate(verified['events'],1):
            if _epoch(event['issued_at']) > min(at, _epoch(verified['issued_at'])):
                raise ValueError('wallet_event_from_future')
            timeline=replay_events(verified['events'][:i],principal=verified['principal']['principal_id'],
                root_public_key=verified['principal']['root_public_key'],epoch_certificate=verified['epoch_certificate'])
            mandate=timeline.mandates[event['data']['mandate_id']]
            # The original issuance hash stays stable across revocation.
            views.append(dict(event_hash=record_hash(event),state=mandate['status'],
                subject=mandate['subject_public_key'],mandate_id=mandate['mandate_id'],
                mandate_hash=mandate['event_payload_hash'],scopes=mandate['scopes'],
                expires=min(_epoch(mandate['expires_at']),_epoch(verified['epoch_certificate']['expires_at']))))
        return verified,views
    except WalletError as exc:
        raise ValueError(str(exc)) from exc

def parse_head(mode, packet, config, at):
    _mode(mode)
    if mode == 'wallet':
        bundle=base._object(packet,'wallet_bundle')
        principal=bundle.get('principal',{})
        if principal != {'principal_id':config['owner_id'],'root_public_key':config['owner_key']}:
            raise ValueError('wallet_root_not_pinned')
        bundle,views=wallet_views(bundle,at)
        issued,expires=_epoch(bundle['issued_at']),_epoch(bundle['expires_at'])
    else:
        if set(packet) != {'credential'}:
            raise ValueError('head_packet_shape_invalid')
        claims=base._jwt_decode(packet['credential'],public_key=config['owner_key'],issuer=config['owner_id'],
            audience=config['receiver_id'],at=at)
        if set(claims) != base._COMMON | {'snapshot'}:
            raise ValueError('jwt_snapshot_shape_invalid')
        views=claims['snapshot']; issued,expires=claims['iat'],claims['exp']
        if not views or claims['sub'] != views[-1]['subject']:
            raise ValueError('jwt_snapshot_subject_invalid')
    if not isinstance(views,list) or not views:
        raise ValueError('wallet_history_empty')
    for v in views:
        if not isinstance(v,dict) or set(v)!=VIEW or v['state'] not in {'ACTIVE','REVOKED'}:
            raise ValueError('wallet_snapshot_invalid')
        for field in ('event_hash','subject','mandate_hash'):base._hash(v[field],field)
        base._text(v['mandate_id'],'mandate_id');base._integer(v['expires'],'expires')
        if (not isinstance(v['scopes'],list) or not v['scopes'] or
            any(not isinstance(s,str) or not s for s in v['scopes']) or len(set(v['scopes']))!=len(v['scopes'])):
            raise ValueError('wallet_scopes_invalid')
    v=views[-1]
    if issued>at or expires<=at or expires<=issued or expires-issued>600:
        raise ValueError('wallet_export_time_invalid')
    return dict(hash=digest(views),seq=len(views),prev=digest(views[:-1]) if len(views)>1 else None,
        state=v['state'],issued=issued,expires=min(expires,v['expires']),subject=v['subject'],
        scope=['send'] if SCOPE in v['scopes'] else [],targets=[TARGET],mandate_id=v['mandate_id'],
        purpose=SCOPE,principal=config['owner_id'],mandate_hash=v['mandate_hash'],_history=views)

def transition(old,new):
    """Complete signed snapshots may skip delivery steps, never known ancestry."""
    if old is None:
        if new['state']!='ACTIVE':raise ValueError('initial_authority_not_active')
        return
    if new['seq']<old['seq']:raise ValueError('authority_history_rollback')
    if new['_history'][:old['seq']] != old['_history']:
        raise ValueError('authority_fork_quarantined')

def assess(mode,packet,effect,at):
    # Admission already authenticated the preserved packet. Scope is checked
    # again from its signed data; native typed fields never become new authority.
    if mode=='wallet':
        _,views=wallet_views(packet,at)
    else:
        import base64
        from olp_gate.crypto import strict_json_loads
        segment=packet['credential'].split('.')[1]
        views=strict_json_loads(base64.urlsafe_b64decode(segment+'='*(-len(segment)%4)).decode())['snapshot']
    v=views[-1];reasons=[]
    expected={'agent_id':v['subject'],'mandate_id':v['mandate_id'],'purpose':SCOPE,
              'action_type':'send','target':TARGET,'value_cents':0,'disclosures':[],'delegatee':None}
    for k,value in expected.items():
        if effect.get(k)!=value:reasons.append(k+'_mismatch')
    if SCOPE not in v['scopes']:reasons.append('wallet_scope_not_granted')
    if v['state']!='ACTIVE' or v['expires']<=at:reasons.append('wallet_mandate_not_active')
    # principal binding is enforced with the pinned identity in decode_call.
    return reasons

def decode_call(mode,token,subject,config,at):
    claims=base.decode_call('openline' if mode=='wallet' else 'conventional',token,subject,config,at)
    if claims['effect']['principal_id']!=config['owner_id']:raise ValueError('principal_mismatch')
    return claims

def encode_call(mode,claims,key):
    return base.encode_call('openline' if mode=='wallet' else 'conventional',claims,key)
