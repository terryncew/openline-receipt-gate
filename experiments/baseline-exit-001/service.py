"""Isolated loopback authority/AS and receiver services; no product changes."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from protocol import *
from olp_gate.crypto import public_key_hex
from olp_gate.mandate_owner import (
    MandateOwnerView, issue_mandate_authorization, authorize_owned,
)
from olp_gate.subject_bound_commit import authorize_subject_bound_owned
from olp_gate.tool_adapter import AuthorizationBlocked, LocalAuthorityRuntime, payment_semantics


class Authority:
    def __init__(self, config):
        self.config = config
        self.revoked = False
        self.sequence = 1
        self.records = [config['authorization']] if config['arm'].startswith('OL_') else []
        self.requests = []
        self.assertions = set()

    def status(self, token=None):
        c = self.config
        if c['arm'] == 'OAUTH_EXCHANGE':
            claims = grant_claims(token, c['contract'], exchanged=True)
            info = {'active': not self.revoked, 'sub': OWNER, 'job_id': JOB,
                    'jti': claims['jti'], 'exp': claims['exp'],
                    'scope': claims['scope'], 'client_id': claims['client_id']}
            return issue(private(c['as_private']), AS, RECEIVER, RECEIVER,
                         'token-introspection+jwt',
                         {'token_hash': digest(token), 'token_introspection': info}, ttl=1)
        fields = {'job_id': JOB, 'sequence': self.sequence,
                  'revoked': [c['grant_jti']] if self.revoked else []}
        typ = 'revocation-list+jwt'
        if c['arm'].startswith('OL_'):
            typ = 'owner-standing+jwt'
            fields.update(records=self.records, mandate=c['mandate'],
                          head_hash=self.records[-1]['payload_hash'])
        return issue(private(c['owner_private']), OWNER, RECEIVER, RECEIVER, typ, fields, ttl=1)

    def handle(self, path, body):
        start = stamp()
        c = self.config
        if path == '/status':
            result = {'snapshot': self.status()}
        elif path == '/introspect':
            # The receiver is an authenticated introspection client (RFC 7662).
            auth = verify(body['receiver_assertion'], c['contract']['receiver_key'],
                          RECEIVER, c['introspection_endpoint'], 'JWT')
            if auth['sub'] != RECEIVER or auth['jti'] in self.assertions:
                raise ValueError('invalid_introspection_client')
            self.assertions.add(auth['jti'])
            result = {'snapshot': self.status(body['token'])}
        elif path == '/exchange':
            ec = dict(c, revoked=self.revoked)
            result = exchange(body, ec, self.assertions)
        elif path == '/revoke':
            rev = verify(body['owner_request'], c['owner_key'], OWNER, RECEIVER,
                         'owner-revocation+jwt', required=['job_id', 'grant_hash'])
            if rev['job_id'] != JOB or rev['grant_hash'] != c['contract']['grant_hash']:
                raise ValueError('revocation_target_mismatch')
            self.revoked = True
            self.sequence = 2
            if c['arm'].startswith('OL_') and len(self.records) == 1:
                now = datetime.now(timezone.utc)
                self.records.append(issue_mandate_authorization(
                    slot_id=SLOT, owner_id=OWNER, mandate=c['mandate'], state='REVOKED',
                    sequence=2, predecessor_hash=self.records[0]['payload_hash'],
                    issued_at=now, expires_at=datetime.fromtimestamp(c['expires'], timezone.utc),
                    key=private(c['owner_private']),
                ))
            result = {'recorded': True, 'at': stamp(), 'sequence': self.sequence}
        else:
            raise ValueError('unknown_endpoint')
        self.requests.append({'endpoint': path, 'start': start, 'end': stamp(),
                              'body': body, 'response': result})
        return result

    def evidence(self):
        return {'requests': self.requests, 'records': self.records, 'revoked': self.revoked}


class ReceiverService:
    def __init__(self, config):
        self.config = config
        self.events = []
        self.count = 0
        self.worker = None
        self.seen = set()
        self.list_sequence = 0
        self.fetches = []
        self.view = None
        if config['arm'].startswith('OL_'):
            self.view = MandateOwnerView({SLOT: {'owner_id': OWNER, 'public_key': config['owner_key']}})
            self.view.admit(config['authorization'], config['mandate'])
            self.runtime = LocalAuthorityRuntime(config['runtime_dir'])
            permission = {
                'profile': 'decision_permission_policy/v1', 'policy_id': 'baseline-exit-J',
                'version': '1', 'routes': [{
                    'route_id': 'refund', 'tool': 'refund', 'target': 'refund://J',
                    'requirements': [{'requirement_id': 'owner_grant', 'kind': 'authority',
                        'accepted_issuers': ['owner_grant'], 'max_age_seconds': 1,
                        'independent_from_producer': True}],
                    'unknown_behavior': 'QUARANTINE', 'max_authorization_ttl_seconds': 1,
                }],
            }
            kw = dict(policy={'schema': 'openline.authorized_tool_policy.v1',
                              'mandate': config['mandate'], 'permission_policy': permission},
                      mandate_view=self.view, mandate_slot_id=SLOT, tool='refund',
                      target='refund://J', semantics=payment_semantics('amount_cents'),
                      state_source=lambda call: {'job_id': JOB, 'counter': self.count},
                      evidence_sources={'owner_grant': lambda call: {'head': self.view.head_hash(SLOT)}},
                      runtime=self.runtime, return_receipt=True)
            decorator = authorize_owned
            if config['arm'] == 'OL_BOUND':
                decorator = authorize_subject_bound_owned
                kw['subject_source'] = lambda: self.worker
            self.guarded = decorator(**kw)(self.refund)

    def refund(self, amount_cents, job_id):
        self.count += 1
        return {'job_id': job_id, 'effect_counter': self.count, 'amount_cents': amount_cents}

    def refresh(self, body):
        c = self.config
        if c['arm'] == 'JWT_OFFLINE':
            return None
        if c['arm'] == 'OAUTH_EXCHANGE':
            assertion = issue(private(c['receiver_private']), RECEIVER, RECEIVER,
                              c['authority_url'] + '/introspect', 'JWT', ttl=5)
            status, response = request(c['authority_url'] + '/introspect',
                                       {'token': body['token'], 'receiver_assertion': assertion})
        else:
            status, response = request(c['authority_url'] + '/status')
        self.fetches.append({'at': stamp(), 'status': status, 'response': response})
        if status != 200:
            raise ValueError('status_unavailable')
        snapshot = response['snapshot']
        if c['arm'].startswith('OL_'):
            claims = verify(snapshot, c['owner_key'], OWNER, RECEIVER, 'owner-standing+jwt')
            if claims['job_id'] != JOB or claims['mandate'] != c['mandate']:
                raise ValueError('standing_job_mismatch')
            if claims['sequence'] < self.list_sequence:
                raise ValueError('standing_rollback')
            for record in claims['records']:
                if record['sequence'] > self.view.head_sequence(SLOT):
                    self.view.admit(record, claims['mandate'])
            if claims['head_hash'] != self.view.head_hash(SLOT):
                raise ValueError('standing_head_mismatch')
            self.list_sequence = claims['sequence']
        elif c['arm'] in ('OWNER_LIST', 'JWT_BOUND'):
            claims = verify(snapshot, c['owner_key'], OWNER, RECEIVER, 'revocation-list+jwt')
            if claims['sequence'] < self.list_sequence:
                raise ValueError('list_rollback')
            self.list_sequence = claims['sequence']
        return snapshot

    def handle(self, path, body):
        if path != '/attempt':
            raise ValueError('unknown_endpoint')
        c = self.config
        started = stamp()
        before = self.count
        snapshot = None
        detail = None
        allowed = False
        actor = body.get('worker')
        evaluation = stamp()
        try:
            if actor not in c['contract']['workers'] or body['job_id'] != JOB:
                raise ValueError('worker_or_job_unknown')
            auth = verify(body['worker_assertion'], c['contract']['workers'][actor],
                          actor, RECEIVER, 'worker-request+jwt')
            unsigned = {k: v for k, v in body.items() if k != 'worker_assertion'}
            if auth['sub'] != actor or auth['body_hash'] != digest(json_bytes(unsigned)):
                raise ValueError('request_binding_mismatch')
            if auth['jti'] in self.seen:
                raise ValueError('request_replay')
            self.seen.add(auth['jti'])
            snapshot = self.refresh(body)
            evaluation = stamp()
            if c['arm'].startswith('OL_'):
                if body['authorization'] != c['authorization']:
                    raise ValueError('presented_authority_mismatch')
                self.worker = actor
                try:
                    outcome = self.guarded(amount_cents=body['amount_cents'], job_id=JOB)
                    allowed, reason = True, 'authorized'
                    detail = {'decision_receipt': outcome.decision_receipt,
                              'compilation': outcome.compilation, 'execution': outcome.execution}
                except AuthorizationBlocked as error:
                    reason = ','.join(error.reason_codes)
                    detail = {'decision_receipt': error.decision_receipt,
                              'compilation': error.compilation, 'execution': None}
            else:
                allowed, reason = evaluate_standard(c['arm'], body['token'], actor,
                    body['amount_cents'], snapshot, c['contract'])
                if allowed:
                    self.refund(body['amount_cents'], JOB)
        except Exception as error:
            # A trace is retained. Unexpected errors are apparatus failures,
            # never scored as legitimate refusals by the experiment runner.
            reason = 'apparatus_or_validation_error:' + type(error).__name__ + ':' + str(error)
        event = {'arm': c['arm'], 'job_id': JOB, 'worker': actor,
                 'request': body, 'snapshot': snapshot, 'request_start': started,
                 'evaluation': evaluation, 'observed': stamp(),
                 'allowed': allowed, 'reason': reason, 'before': before, 'after': self.count,
                 'openline': detail}
        signed = issue(private(c['receiver_private']), RECEIVER, actor or 'unknown',
                       'urn:baseline-exit:audit', 'receiver-event+jwt', {'event': event}, ttl=86400)
        entry = {'signed_event': signed}
        self.events.append(entry)
        return entry

    def evidence(self):
        return {'events': self.events, 'effect_counter': self.count, 'fetches': self.fetches}


def main():
    config = json.load(sys.stdin)
    role = sys.argv[1]
    app = ReceiverService(config) if role == 'receiver' else Authority(config)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def dispatch(self):
            path = urlparse(self.path).path
            if path == '/health':
                code, result = 200, {'ready': True}
            elif path == '/evidence':
                code, result = 200, app.evidence()
            else:
                try:
                    raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    body = {}
                    if raw:
                        if self.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
                            body = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                        else:
                            body = json.loads(raw)
                    code, result = 200, app.handle(path, body)
                except Exception as error:
                    code, result = 400, {'error': str(error), 'type': type(error).__name__}
            wire = json_bytes(result)
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)

        do_GET = dispatch
        do_POST = dispatch

    server = HTTPServer(('127.0.0.1', 0), Handler)
    config['token_endpoint'] = f'http://127.0.0.1:{server.server_port}/exchange'
    config['introspection_endpoint'] = f'http://127.0.0.1:{server.server_port}/introspect'
    print(json.dumps({'port': server.server_port, 'role': role}), flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
