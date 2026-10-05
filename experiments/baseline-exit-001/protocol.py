"""Frozen experiment profiles. JOSE is implemented by PyJWT, not this harness."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

ARMS = ('OL_JOB', 'JWT_OFFLINE', 'OAUTH_EXCHANGE', 'OWNER_LIST', 'OL_BOUND', 'JWT_BOUND')
OWNER = 'urn:baseline-exit:owner:O'
RECEIVER = 'urn:baseline-exit:receiver:R'
AS = 'urn:baseline-exit:authorization-server'
JOB = 'J'
SLOT = 'baseline-exit/J'
TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt'
EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange'
ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
REQUIRED = ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti']


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def private(hex_value):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_value))


def public(hex_value):
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_value))


def jwk(hex_value):
    return jwt.algorithms.OKPAlgorithm.to_jwk(public(hex_value), as_dict=True)


def issue(key, issuer, subject, audience, typ, fields=None, ttl=60):
    now = int(time.time())
    claims = dict(iss=issuer, sub=subject, aud=audience, iat=now, nbf=now,
                  exp=now + ttl, jti=uuid.uuid4().hex)
    claims.update(fields or {})
    return jwt.encode(claims, key, algorithm='EdDSA', headers={'typ': typ})


def verify(token, key_hex, issuer, audience, typ, *, at=None, required=()):
    header = jwt.get_unverified_header(token)
    if header.get('typ') != typ or header.get('alg') != 'EdDSA':
        raise ValueError('token_header_invalid')
    options = {'require': REQUIRED + list(required)}
    if at is not None:
        # PyJWT has no public historical-clock argument. Preserve signature,
        # issuer, audience and required-claim validation; check all NumericDates
        # against the recorded observation time explicitly, with zero leeway.
        options.update(verify_exp=False, verify_nbf=False, verify_iat=False)
    claims = jwt.decode(token, public(key_hex), algorithms=['EdDSA'],
                        issuer=issuer, audience=audience, options=options)
    if at is not None:
        for name in ('iat', 'nbf', 'exp'):
            if not isinstance(claims[name], int) or isinstance(claims[name], bool):
                raise ValueError('numeric_date_invalid')
        if at < claims['nbf'] or at < claims['iat']:
            raise jwt.ImmatureSignatureError('not_yet_valid')
        if at >= claims['exp']:
            raise jwt.ExpiredSignatureError('expired')
    return claims


def request(url, body=None, *, form=False):
    from urllib.parse import urlencode
    data = None if body is None else (urlencode(body).encode() if form else json_bytes(body))
    headers = {'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json'}
    req = Request(url, data=data, headers=headers)
    try:
        with urlopen(req, timeout=3) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def stamp():
    return {'utc_ns': str(time.time_ns()), 'monotonic_ns': str(time.monotonic_ns())}


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace('+00:00', 'Z')


def contract_claims(token, owner_key, *, at=None):
    return verify(token, owner_key, OWNER, RECEIVER, 'baseline-exit-contract+jwt', at=at,
                  required=['job_id', 'workers', 'receiver_key', 'as_key', 'profile'])


def grant_claims(token, contract, *, exchanged=False, at=None):
    issuer = AS if exchanged else OWNER
    key = contract['as_key'] if exchanged else contract['owner_key']
    claims = verify(token, key, issuer, RECEIVER, 'at+jwt', at=at,
                    required=['job_id', 'scope', 'client_id'])
    if claims['sub'] != OWNER or claims['job_id'] != JOB:
        raise ValueError('job_or_owner_mismatch')
    if claims['scope'] != 'refund' or claims.get('max_amount_cents') != 100:
        raise ValueError('scope_or_ceiling_mismatch')
    return claims


def evaluate_standard(arm, token, worker, amount, snapshot, contract, *, at=None):
    """Same rules for live receiver and offline verifier; reasons are explicit."""
    try:
        claims = grant_claims(token, contract, exchanged=arm == 'OAUTH_EXCHANGE', at=at)
        if amount < 0 or amount > claims['max_amount_cents']:
            return False, 'amount_out_of_scope'
        if arm == 'JWT_BOUND' and claims.get('cnf') != {'jwk': jwk(contract['workers'][worker])}:
            return False, 'holder_mismatch'
        if arm == 'OAUTH_EXCHANGE':
            if claims['client_id'] != worker or claims.get('act') != {'sub': worker}:
                return False, 'actor_mismatch'
            if claims.get('owner_grant_hash') != contract['grant_hash']:
                return False, 'delegation_grant_mismatch'
            status = verify(snapshot, contract['as_key'], AS, RECEIVER,
                            'token-introspection+jwt', at=at,
                            required=['token_hash', 'token_introspection'])
            if status['token_hash'] != digest(token):
                return False, 'introspection_token_mismatch'
            info = status['token_introspection']
            if info.get('sub') != OWNER or info.get('job_id') != JOB:
                return False, 'introspection_subject_mismatch'
            if info.get('active') is not True:
                return False, 'revoked_at_as'
        elif arm in ('OWNER_LIST', 'JWT_BOUND'):
            status = verify(snapshot, contract['owner_key'], OWNER, RECEIVER,
                            'revocation-list+jwt', at=at,
                            required=['sequence', 'revoked', 'job_id'])
            if status['job_id'] != JOB:
                return False, 'list_job_mismatch'
            if claims['jti'] in status['revoked']:
                return False, 'owner_revoked_jti'
        return True, 'authorized'
    except jwt.ExpiredSignatureError:
        return False, 'expired_token_or_status'
    except (jwt.PyJWTError, ValueError, KeyError, TypeError) as error:
        return False, 'invalid_authorization:' + type(error).__name__


def exchange(form, config, replay):
    """RFC 8693 local profile, with RFC 7523 authenticated clients."""
    if form.get('grant_type') != EXCHANGE or form.get('subject_token_type') != JWT_TYPE:
        raise ValueError('unsupported_grant_type')
    if form.get('requested_token_type') != TOKEN_TYPE or form.get('audience') != RECEIVER:
        raise ValueError('invalid_target')
    if form.get('scope') != 'refund':
        raise ValueError('invalid_scope')
    client = form.get('client_id')
    if client not in config['contract']['workers'] or form.get('client_assertion_type') != ASSERTION:
        raise ValueError('invalid_client')
    assertion = verify(form['client_assertion'], config['contract']['workers'][client], client,
                       config['token_endpoint'], 'JWT')
    if assertion['sub'] != client or assertion['exp'] - assertion['iat'] > 5:
        raise ValueError('invalid_client_assertion')
    if assertion['jti'] in replay:
        raise ValueError('client_assertion_replay')
    replay.add(assertion['jti'])
    subject = grant_claims(form['subject_token'], config['contract'])
    if digest(form['subject_token']) != config['contract']['grant_hash']:
        raise ValueError('invalid_subject_token')
    if config.get('revoked'):
        raise ValueError('invalid_grant_revoked')
    access = issue(private(config['as_private']), AS, OWNER, RECEIVER, 'at+jwt',
                   {'job_id': JOB, 'scope': 'refund', 'client_id': client,
                    'max_amount_cents': 100, 'act': {'sub': client},
                    'owner_grant_hash': digest(form['subject_token']),
                    'exp': subject['exp']})
    return {'access_token': access, 'issued_token_type': TOKEN_TYPE,
            'token_type': 'Bearer', 'expires_in': subject['exp'] - int(time.time()),
            'scope': 'refund'}
