"""Offline reference receiver. Local SQLite effect only; no external consequences."""
from __future__ import annotations
import argparse
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from olp_gate.crypto import olp_canonical_json, public_key_hex, sha256_hex, sign_olp_body, strict_json_loads
from examples.independent_receiver_kit.formats import parse_head, decode_call, assess


def canonical(value):return olp_canonical_json(value).decode('ascii')
def digest(value):return sha256_hex(olp_canonical_json(value))


class Receiver:
    """Config, key and SQLite write access belong only to the receiving organization."""
    def __init__(self,path,config,key,mode,clock=None):
        if mode not in ('openline','conventional'):raise ValueError('mode_invalid')
        if public_key_hex(key)!=config['outcome_key']:raise ValueError('receiver_key_not_pinned')
        self.path,self.config,self.key,self.mode=Path(path),config,key,mode
        self.clock=clock or (lambda:int(time.time()))
        with closing(self.connect()) as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.executescript('''
            CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL,mode TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY,hash TEXT UNIQUE NOT NULL,packet TEXT NOT NULL,accepted_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY,body TEXT NOT NULL,request_hash TEXT UNIQUE NOT NULL);
            CREATE TABLE IF NOT EXISTS consumed(nonce TEXT PRIMARY KEY,proof_hash TEXT UNIQUE NOT NULL);
            CREATE TABLE IF NOT EXISTS decisions(seq INTEGER PRIMARY KEY,request TEXT NOT NULL,body TEXT NOT NULL);
            ''')
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM settings WHERE id=1').fetchone()
            if row is None:c.execute('INSERT INTO settings VALUES(1,?,?)',(canonical(config),mode))
            elif row['mode']!=mode or any(json.loads(row['body'])[k]!=config[k] for k in ('owner_id','owner_key','slot_id','receiver_id','outcome_key')):
                c.rollback();raise ValueError('receiver_roots_changed')
            c.commit()

    def connect(self):
        c=sqlite3.connect(self.path,isolation_level=None,timeout=10)
        c.row_factory=sqlite3.Row
        c.execute('PRAGMA synchronous=FULL')
        return c

    def policy(self,policy):
        """Local receiver-administration method; intentionally absent from HTTP API."""
        with closing(self.connect()) as c:
            c.execute('BEGIN IMMEDIATE')
            config=json.loads(c.execute('SELECT body FROM settings').fetchone()[0])
            config['policy']=policy
            c.execute('UPDATE settings SET body=?',(canonical(config),));c.commit()

    def dispatch(self,path,request):
        # Canonical snapshot prevents a nested caller changing data after checks.
        request=json.loads(canonical(request))
        with closing(self.connect()) as c:
            c.execute('BEGIN IMMEDIATE')
            now=int(self.clock()) # after serialization, never caller-supplied HTTP time
            config=json.loads(c.execute('SELECT body FROM settings').fetchone()[0])
            before=c.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
            history=c.execute('SELECT * FROM history ORDER BY seq').fetchall()
            head=parse_head(self.mode,json.loads(history[-1]['packet']),config,history[-1]['accepted_at']) if history else None
            verdict,reason,subject='DENY','unsupported_route',None
            effect_at=None
            # Refused attempts have a signed durable decision and zero mutation.
            c.execute('SAVEPOINT effect')
            try:
                if path=='/authority':
                    parsed=parse_head(self.mode,request,config,now)
                    if parsed['issued']>now:raise ValueError('future_authority')
                    if head and parsed['hash']==head['hash']:
                        verdict,reason='ACCEPT','authority_duplicate_no_refresh'
                    else:
                        if parsed['seq']!=(head['seq']+1 if head else 1) or parsed['prev']!=(head['hash'] if head else None):
                            raise ValueError('authority_history_gap_or_rollback')
                        if not head and parsed['state']!='ACTIVE':raise ValueError('initial_authority_not_active')
                        if parsed['state']=='REVOKED' and head and parsed['mandate_hash']!=head['mandate_hash']:
                            raise ValueError('revocation_target_mismatch')
                        c.execute('INSERT INTO history VALUES(?,?,?,?)',(parsed['seq'],parsed['hash'],canonical(request),now))
                        head=parsed;verdict,reason='ACCEPT','authority_admitted'
                elif path=='/submit':
                    if set(request)!={'proof'}:raise ValueError('request_shape_invalid')
                    if config['policy']['tool']!='intake.submit':raise ValueError('receiver_policy_disallows_operation')
                    if head is None:raise ValueError('authority_history_missing')
                    if head['state']!='ACTIVE':raise ValueError('owner_revoked')
                    freshness=config['policy']['freshness_seconds']
                    if not 0<=now-head['issued']<freshness or now>=head['expires']:
                        raise ValueError('authority_history_stale')
                    claims=decode_call(self.mode,request['proof'],head['subject'],config,now)
                    subject=claims['sub']
                    if claims['head_hash']!=head['hash']:raise ValueError('authority_head_changed')
                    if claims['policy_hash']!=digest(config['policy']):raise ValueError('receiver_policy_changed')
                    effect,document=claims['effect'],claims['document']
                    reasons=assess(self.mode,json.loads(history[-1]['packet']),effect,now)
                    if reasons:raise ValueError(','.join(reasons))
                    if set(document)!={'record_id','text'} or not isinstance(document['record_id'],str) or not document['record_id']:
                        raise ValueError('document_shape_invalid')
                    if not isinstance(document['text'],str) or len(document['text'])>config['policy']['max_document_chars']:
                        raise ValueError('document_outside_policy')
                    if (effect['value_cents']!=0 or effect['disclosures']!=[] or effect['delegatee'] is not None
                            or effect['effect_id']!=document['record_id'] or effect['action_type']!='send'
                            or effect['target']!=config['policy']['target']):
                        raise ValueError('protected_action_mismatch')
                    # Recheck time after expensive signature/auth work, before effect.
                    fresh=int(self.clock())
                    if fresh<now or fresh>=claims['exp'] or fresh>=head['expires'] or fresh-head['issued']>=freshness:
                        raise ValueError('authority_expired_before_effect')
                    effect_at=fresh
                    c.execute('INSERT INTO consumed VALUES(?,?)',(claims['jti'],digest(request)))
                    c.execute('INSERT INTO documents VALUES(?,?,?)',(document['record_id'],canonical(document),digest(request)))
                    verdict,reason='ALLOW','local_document_committed'
            except (ValueError,TypeError,KeyError,AttributeError,sqlite3.IntegrityError) as exc:
                c.execute('ROLLBACK TO effect')
                effect_at=None
                reason=str(exc) or type(exc).__name__
                # Rollback must also restore the observed head if validation failed.
                history=c.execute('SELECT * FROM history ORDER BY seq').fetchall()
                head=parse_head(self.mode,json.loads(history[-1]['packet']),config,history[-1]['accepted_at']) if history else None
            c.execute('RELEASE effect')
            after=c.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
            seq=c.execute('SELECT COALESCE(MAX(seq),0)+1 FROM decisions').fetchone()[0]
            body=dict(schema='receiver-kit-decision/v1',seq=seq,mode=self.mode,receiver_id=config['receiver_id'],
                verdict=verdict,reason=reason,subject=subject,request_hash=digest(request),policy_hash=digest(config['policy']),
                owner_head=head['hash'] if head else None,owner_sequence=head['seq'] if head else 0,
                observed_at=now,effect_at=effect_at,policy=config['policy'],documents_before=before,documents_after=after)
            decision=sign_olp_body(body,self.key)
            c.execute('INSERT INTO decisions VALUES(?,?,?)',(seq,canonical({'path':path,'request':request}),canonical(decision)))
            c.commit()
            return decision


def make_server(receiver,port=0):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=65536:raise ValueError('invalid_request_length')
                request=strict_json_loads(self.rfile.read(length).decode('utf-8'))
                result=receiver.dispatch(self.path,request)
                data=canonical(result).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)
            except (ValueError,TypeError,UnicodeError):
                self.send_error(400,'malformed_request')
    return ThreadingHTTPServer(('127.0.0.1',port),Handler)


def serve(receiver,port):
    server=make_server(receiver,port)
    print(json.dumps({'port':server.server_address[1],'mode':receiver.mode}),flush=True)
    server.serve_forever()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state',type=Path,required=True);p.add_argument('--config',type=Path,required=True)
    p.add_argument('--key',type=Path,required=True,help='receiver-owned signing seed; never supplied by a request')
    p.add_argument('--mode',choices=['openline','conventional'],required=True);p.add_argument('--port',type=int,default=0)
    p.add_argument('--fixture-clock',type=int,help='offline experiment ONLY; omit for actual system clock')
    args=p.parse_args()
    seed=bytes.fromhex(args.key.read_text().strip())
    serve(Receiver(args.state,strict_json_loads(args.config.read_text()),Ed25519PrivateKey.from_private_bytes(seed),args.mode,
                   (lambda:args.fixture_clock) if args.fixture_clock is not None else None),args.port)
