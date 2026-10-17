"""One local SQLite commissioning consequence; no external executor.

The existing Verified Commit verifier/consumer is unchanged. Its private ledger
context is rebound to the SAME SQLite transaction as the fixed protected update.
Database access, pinned roots, clock and authenticated subject source are trusted
receiver inputs. This adapter neither authenticates a network caller nor controls
robots. Do not use this transaction to claim atomicity over an external effect.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .crypto import olp_canonical_json, sha256_hex, sign_olp_body, public_key_hex
from .mandate import MandateSpec, assess_effect
from .mandate_owner import validate_mandate_authorization, _apply_mandate_successor
from .verified_commit import VerifiedCommitLedger, COMMIT_LEDGER_SCHEMA

PROFILE = 'sqlite_commissioning/v1'
TOOL = 'sqlite.commission'
SETTINGS = {'profile', 'mandate_hash', 'simulation_digest', 'robot_config_digest',
            'site_version', 'site_id', 'idempotency_key'}


def canonical(value):
    return olp_canonical_json(value).decode('ascii')


def digest(value):
    return sha256_hex(olp_canonical_json(value))


def utc(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError('receiver_time_invalid')
    return value.astimezone(timezone.utc)


class Refused(ValueError):
    def __init__(self, *reasons):
        self.reasons = sorted(set(reasons))
        super().__init__(','.join(self.reasons))


class _TransactionalLedger(VerifiedCommitLedger):
    """Only check_and_consume is supported; no file IO, nested commit or executor."""
    def __init__(self, connection):
        self.connection = connection

    @contextmanager
    def _locked(self):
        if not self.connection.in_transaction:
            raise RuntimeError('sqlite_ledger_requires_outer_transaction')
        state = json.loads(self.connection.execute('SELECT body FROM ledger WHERE id=1').fetchone()[0])
        if state.get('schema') != COMMIT_LEDGER_SCHEMA or any(
                not isinstance(state.get(k), dict) for k in
                ('consumed_decisions', 'consumed_codes', 'consumed_replay_scopes')) or not isinstance(state.get('attempts'), list):
            raise Refused('sqlite_ledger_state_invalid')
        yield state
        self.connection.execute('UPDATE ledger SET body=? WHERE id=1', (canonical(state),))

    def execute_once(self, *args, **kwargs):
        raise RuntimeError('external_executor_forbidden')


SCHEMA = """
CREATE TABLE receiver(id INTEGER PRIMARY KEY CHECK(id=1), roots TEXT NOT NULL,
 policy_hash TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 time_watermark TEXT NOT NULL, implementation TEXT NOT NULL CHECK(implementation IN ('openline','conventional')));
CREATE TABLE artifacts(digest TEXT PRIMARY KEY CHECK(length(digest)=64), body TEXT NOT NULL);
CREATE TABLE sites(site_id TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK(version>=1),
 simulation_digest TEXT NOT NULL REFERENCES artifacts(digest),
 robot_config_digest TEXT NOT NULL REFERENCES artifacts(digest),
 commissioned INTEGER NOT NULL DEFAULT 0 CHECK(commissioned IN (0,1)));
CREATE TABLE owner_history(sequence INTEGER PRIMARY KEY CHECK(sequence>0),
 hash TEXT NOT NULL UNIQUE, authorization TEXT NOT NULL, mandate TEXT NOT NULL);
CREATE TABLE ledger(id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);
CREATE TABLE commitments(seq INTEGER PRIMARY KEY AUTOINCREMENT,
 idempotency_key TEXT NOT NULL UNIQUE, request_hash TEXT NOT NULL,
 decision_hash TEXT NOT NULL UNIQUE, authorization_hash TEXT NOT NULL UNIQUE,
 code_hash TEXT NOT NULL UNIQUE, site_id TEXT NOT NULL REFERENCES sites(site_id),
 before_version INTEGER NOT NULL, after_version INTEGER NOT NULL,
 receipt TEXT NOT NULL, action TEXT NOT NULL, owner_sequence INTEGER NOT NULL REFERENCES owner_history(sequence),
 outcome TEXT NOT NULL, UNIQUE(site_id,before_version),
 CHECK(after_version=before_version+1));
CREATE TRIGGER immutable_commitment_update BEFORE UPDATE ON commitments
 BEGIN SELECT RAISE(ABORT,'commitment_immutable'); END;
CREATE TRIGGER immutable_commitment_delete BEFORE DELETE ON commitments
 BEGIN SELECT RAISE(ABORT,'commitment_immutable'); END;
"""


def _connect(path):
    # A worker restart must never silently create an empty replacement authority.
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=rw', uri=True,
                                 timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute('PRAGMA synchronous=FULL')
    return connection


@contextmanager
def _transaction(connection):
    connection.execute('BEGIN IMMEDIATE')
    try:
        yield
        connection.execute('COMMIT')
    except BaseException:
        if connection.in_transaction:
            connection.execute('ROLLBACK')
        raise


def initialize(path, *, roots, site, artifacts, policy_hash, now, implementation='openline'):
    """Explicit receiver genesis only, refuses an existing path. No worker reset."""
    path = Path(path)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    with closing(_connect(path)) as connection:
        connection.execute('PRAGMA journal_mode=WAL')
        connection.executescript(SCHEMA)
        with _transaction(connection):
            connection.execute('INSERT INTO receiver VALUES (1,?,?,1,?,?)',
                               (canonical(roots), policy_hash, utc(now).isoformat(), implementation))
            for expected, body in artifacts.items():
                if sha256_hex(body.encode('utf-8')) != expected:
                    raise ValueError('artifact_digest_mismatch')
                connection.execute('INSERT INTO artifacts VALUES (?,?)', (expected, body))
            connection.execute('INSERT INTO sites VALUES (?,?,?,?,0)',
                               (site['site_id'], site['version'], site['simulation_digest'], site['robot_config_digest']))
            connection.execute('INSERT INTO ledger VALUES (1,?)', (canonical(VerifiedCommitLedger._empty()),))


class SQLiteConsequence:
    def __init__(self, path, *, roots, subject_source: Callable[[], str], signing_key,
                 clock=None, implementation='openline'):
        if implementation not in ('openline', 'conventional'):
            raise ValueError('implementation_invalid')
        if not callable(subject_source):
            raise ValueError('authenticated_subject_source_required')
        if public_key_hex(signing_key) != roots['outcome_key']:
            raise ValueError('outcome_key_not_pinned')
        self.path, self.roots = Path(path), json.loads(canonical(roots))
        self.subject_source, self.signing_key = subject_source, signing_key
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.implementation = implementation
        with closing(_connect(self.path)) as connection:
            self._receiver(connection)

    def _receiver(self, connection):
        row = connection.execute('SELECT * FROM receiver WHERE id=1').fetchone()
        if row is None or json.loads(row['roots']) != self.roots or row['implementation'] != self.implementation:
            raise Refused('receiver_roots_mismatch')
        return row

    def _time(self, connection):
        row = self._receiver(connection)
        now = utc(self.clock())  # sampled after acquiring write lock
        if now < utc(row['time_watermark']):
            raise Refused('receiver_clock_rollback')
        connection.execute('UPDATE receiver SET time_watermark=? WHERE id=1', (now.isoformat(),))
        return now

    def admit_owner(self, authorization, mandate):
        authorization, mandate = json.loads(canonical(authorization)), json.loads(canonical(mandate))
        with closing(_connect(self.path)) as connection, _transaction(connection):
            now = self._time(connection)
            checked = validate_mandate_authorization(authorization,
                expected_slot_id=self.roots['slot_id'], expected_owner_id=self.roots['owner_id'],
                expected_public_key=self.roots['owner_key'], now=now)
            spec = MandateSpec.from_mapping(mandate)
            if spec.principal_id != self.roots['owner_id']:
                raise Refused('mandate_principal_not_owner')
            if checked['mandate_hash'] != spec.mandate_hash:
                raise Refused('owner_mandate_hash_mismatch')
            previous = connection.execute('SELECT authorization FROM owner_history ORDER BY sequence DESC LIMIT 1').fetchone()
            _apply_mandate_successor({'authorization': json.loads(previous[0])} if previous else None, checked)
            connection.execute('INSERT INTO owner_history VALUES (?,?,?,?)',
                (checked['sequence'], checked['payload_hash'], canonical(checked), canonical(mandate)))

    def _authority(self, connection, action, now):
        row = self._receiver(connection)
        if not row['enabled'] or action['policy_hash'] != row['policy_hash']:
            raise Refused('receiver_policy_changed_or_disabled')
        head = connection.execute('SELECT * FROM owner_history ORDER BY sequence DESC LIMIT 1').fetchone()
        if head is None:
            raise Refused('owner_authority_missing')
        authorization, mandate = json.loads(head['authorization']), json.loads(head['mandate'])
        checked = validate_mandate_authorization(authorization,
            expected_slot_id=self.roots['slot_id'], expected_owner_id=self.roots['owner_id'],
            expected_public_key=self.roots['owner_key'], now=now)
        spec = MandateSpec.from_mapping(mandate)
        if spec.principal_id != self.roots['owner_id']:
            raise Refused('mandate_principal_not_owner')
        if checked['mandate_hash'] != spec.mandate_hash or checked['state'] != 'ACTIVE':
            raise Refused('owner_revoked_or_mismatched')
        subject = self.subject_source()  # trusted authentication seam, no request fields
        if not isinstance(subject, str) or subject != spec.agent_id:
            raise Refused('authenticated_subject_mismatch')
        settings = action['settings']
        if set(settings) != SETTINGS or settings['profile'] != PROFILE:
            raise Refused('commissioning_settings_invalid')
        if settings['mandate_hash'] != spec.mandate_hash:
            raise Refused('current_mandate_mismatch')
        if (type(settings['site_version']) is not int or not isinstance(settings['idempotency_key'], str)
                or not settings['idempotency_key']):
            raise Refused('commissioning_settings_invalid')
        effect = dict(profile='principal_effect/v1', effect_id=settings['idempotency_key'],
            mandate_id=spec.mandate_id, principal_id=spec.principal_id, agent_id=subject,
            purpose=spec.purpose, action_type='send', target=action['target'], disclosures=[],
            value_cents=0, delegatee=None, producer_model='untrusted-worker-label')
        assessment = assess_effect(spec, effect, now=now)
        if not assessment['allowed']:
            raise Refused(*assessment['reason_codes'])
        return head, subject

    def commission(self, receipt, action, *, one_use_code, fault=None):
        """Fixed local UPDATE only. fault is a trusted test failpoint, never a request field."""
        try:
            receipt, action = json.loads(canonical(receipt)), json.loads(canonical(action))
            request_hash = digest({'receipt': receipt, 'action': action})
            with closing(_connect(self.path)) as connection, _transaction(connection):
                now = self._time(connection)
                head, subject = self._authority(connection, action, now)
                settings = action['settings']
                if action['tool'] != TOOL or action['target'] != 'sqlite://commissioning/' + settings['site_id']:
                    raise Refused('commissioning_target_invalid')
                # The baseline checks the very same signed permission inputs.
                if self.implementation == 'openline':
                    result = _TransactionalLedger(connection).check_and_consume(receipt, action,
                        one_use_code=one_use_code, trusted_gate_keys=self.roots['gate_keys'], now=now)
                    errors = result['reason_codes']
                else:
                    from .consequence_baseline import validate_permission
                    errors = validate_permission(receipt, action, one_use_code=one_use_code,
                        trusted_gate_keys=self.roots['gate_keys'], now=now)
                previous = connection.execute('SELECT * FROM commitments WHERE idempotency_key=?',
                                              (settings['idempotency_key'],)).fetchone()
                # An exact authenticated retry may read its durable result. Only replay
                # errors from this same consumption may be ignored; no new effect occurs.
                if previous and previous['request_hash'] == request_hash:
                    if any(e not in {'authorization_replay', 'one_use_code_replay'} for e in errors):
                        raise Refused(*errors)
                    return {'status': 'ALREADY_COMMITTED', 'outcome': json.loads(previous['outcome'])}
                if errors:
                    raise Refused(*errors)
                if previous:
                    raise Refused('idempotency_conflict')
                site = connection.execute('SELECT * FROM sites WHERE site_id=?', (settings['site_id'],)).fetchone()
                if site is None:
                    raise Refused('site_missing')
                before = dict(site)
                if site['commissioned'] or site['version'] != settings['site_version']:
                    raise Refused('site_version_changed_or_commissioned')
                for name in ('simulation_digest', 'robot_config_digest'):
                    if site[name] != settings[name]:
                        raise Refused(name + '_changed')
                    artifact = connection.execute('SELECT body FROM artifacts WHERE digest=?', (settings[name],)).fetchone()
                    if artifact is None or sha256_hex(artifact[0].encode('utf-8')) != settings[name]:
                        raise Refused('artifact_digest_mismatch')
                if action['evidence_hashes'] != [settings['simulation_digest']]:
                    raise Refused('simulation_evidence_binding_mismatch')
                sim = json.loads(connection.execute('SELECT body FROM artifacts WHERE digest=?',
                                                    (settings['simulation_digest'],)).fetchone()[0])
                if sim.get('approved') is not True:
                    raise Refused('simulation_not_approved')
                # Also constrain future-issue handling missing from legacy check_and_consume.
                if utc(receipt['created_at']) > now:
                    raise Refused('authorization_from_future')
                # Fresh time immediately before protected mutation. Long crypto or
                # authentication work must not freeze the earlier expiry sample.
                now = self._time(connection)
                for expires in (receipt['commit_authorization']['expires_at'],
                                json.loads(head['authorization'])['expires_at'],
                                json.loads(head['mandate'])['expires_at']):
                    if now >= utc(expires):
                        raise Refused('authorization_expired_at_mutation')
                cursor = connection.execute('UPDATE sites SET commissioned=1, version=version+1 WHERE site_id=? AND version=? AND commissioned=0',
                                            (site['site_id'], site['version']))
                if cursor.rowcount != 1:
                    raise Refused('site_compare_and_swap_failed')
                after = dict(connection.execute('SELECT * FROM sites WHERE site_id=?', (site['site_id'],)).fetchone())
                auth = receipt['commit_authorization']
                last = connection.execute('SELECT seq,outcome FROM commitments ORDER BY seq DESC LIMIT 1').fetchone()
                seq = last['seq'] + 1 if last else 1
                body = {'schema': 'openline.sqlite_consequence.outcome.v1', 'status': 'COMMITTED',
                    'implementation': self.implementation, 'seq': seq, 'previous_outcome_hash': digest(json.loads(last['outcome'])) if last else None,
                    'idempotency_key': settings['idempotency_key'], 'request_hash': request_hash,
                    'decision_hash': receipt['payload_hash'], 'authorization_hash': auth['authorization_hash'],
                    'action_hash': auth['action_hash'], 'owner_head_hash': head['hash'],
                    'owner_sequence': head['sequence'], 'subject': subject, 'policy_hash': action['policy_hash'],
                    'before': before, 'after': after, 'committed_at': now.isoformat()}
                outcome = sign_olp_body(body, self.signing_key)
                connection.execute('INSERT INTO commitments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (seq, settings['idempotency_key'], request_hash, receipt['payload_hash'], auth['authorization_hash'],
                     auth['one_use_code_hash'], site['site_id'], before['version'], after['version'],
                     canonical(receipt), canonical(action), head['sequence'], canonical(outcome)))
                if fault:
                    fault('before_commit')
            # Killing this process here cannot roll back the durable tuple.
            if fault:
                fault('after_commit')
            return {'status': 'COMMITTED', 'outcome': outcome}
        except Refused as exc:
            return {'status': 'REFUSED', 'reason_codes': exc.reasons}
        except (ValueError, KeyError, TypeError, AttributeError, sqlite3.IntegrityError) as exc:
            return {'status': 'REFUSED', 'reason_codes': [f'fail_closed:{type(exc).__name__}:{exc}']}
