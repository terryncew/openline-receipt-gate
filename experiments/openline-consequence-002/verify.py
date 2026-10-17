#!/usr/bin/env python3
"""Read-only independent appraisal of the local consequence database.

Usage: python experiments/openline-consequence-002/verify.py STATE.sqlite3 \
    --roots trusted-roots.json

The roots file is an out-of-band trust input, never discovered from the database.
The verifier uses a single read transaction, checks existing signature primitives,
and reconstructs committed transitions without calling the consequence adapter.
It does not prove that a trusted receiver authenticated the claimed subject, that
the claimed historical owner head was latest, or that an entire valid database
has not been rolled back. Those require trusted execution/access and an external
checkpoint. Public experiment keys provide reproducibility, not real identity.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Mapping
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from olp_gate.adapters import parse_timestamp
from olp_gate.crypto import (
    olp_canonical_json, sha256_hex, strict_json_loads, verify_olp_signature,
)
from olp_gate.gateway import verify_decision_receipt
from olp_gate.mandate import MandateSpec, assess_effect
from olp_gate.mandate_owner import (
    _apply_mandate_successor, validate_mandate_authorization,
)
from olp_gate.verified_commit import (
    COMMIT_LEDGER_SCHEMA, _action_hash, _normalize_execution_action,
)


def digest(value):
    return sha256_hex(olp_canonical_json(value))


def check_hash(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= set('0123456789abcdef')


def parse_object(text):
    value = strict_json_loads(text)
    if not isinstance(value, Mapping):
        raise ValueError('expected_json_object')
    return value


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify(database, roots):
    errors = []
    result = {
        'valid': False, 'errors': errors, 'database': str(Path(database).resolve()),
        'row_counts': {}, 'ledger': None, 'signed_outcomes': 0,
        'trust_assumptions': [
            'Externally supplied roots and verifier dependencies are trusted.',
            'The receiver, its clock, subject authentication source, outcome signer and database write access are trusted.',
            'Signed owner-head/policy observations attest historical checks; admission ordering is not independently witnessed.',
            'Whole-database rollback, signer compromise and public fixture-key forgery require an external checkpoint or stronger custody.',
            'Only local SQLite state is appraised; no robot, packet, provider identity or external effect is established.',
        ],
    }
    try:
        require(set(roots) == {'slot_id', 'owner_id', 'owner_key', 'gate_keys', 'outcome_key'}, 'roots_shape_invalid')
        require(all(isinstance(roots[x], str) and roots[x] for x in ('slot_id', 'owner_id')), 'roots_identity_invalid')
        require(check_hash(roots['owner_key']) and check_hash(roots['outcome_key']), 'roots_key_invalid')
        require(isinstance(roots['gate_keys'], list) and roots['gate_keys'] and all(check_hash(x) for x in roots['gate_keys']), 'roots_gate_keys_invalid')
        uri = Path(database).resolve().as_uri() + '?mode=ro'
        connection = sqlite3.connect(uri, uri=True, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('BEGIN')
            require([x[0] for x in connection.execute('PRAGMA integrity_check')] == ['ok'], 'sqlite_integrity_check_failed')
            require(not connection.execute('PRAGMA foreign_key_check').fetchall(), 'sqlite_foreign_key_check_failed')
            # All observations below belong to this same consistent snapshot.
            tables = {table: [dict(row) for row in connection.execute(f'SELECT * FROM {table}')]
                      for table in ('receiver', 'artifacts', 'sites', 'owner_history', 'ledger', 'commitments')}
            result['row_counts'] = {table: len(rows) for table, rows in tables.items()}
            connection.execute('ROLLBACK')
        finally:
            connection.close()
        require(len(tables['receiver']) == 1 and tables['receiver'][0]['id'] == 1, 'receiver_row_invalid')
        receiver = tables['receiver'][0]
        require(parse_object(receiver['roots']) == roots, 'receiver_roots_mismatch')
        implementation = receiver['implementation']
        require(implementation in ('openline', 'conventional'), 'receiver_implementation_invalid')
        result['implementation'] = implementation
        watermark = parse_timestamp(receiver['time_watermark'])
        require(watermark is not None, 'receiver_watermark_invalid')
        require(check_hash(receiver['policy_hash']) and receiver['enabled'] in (0, 1), 'receiver_policy_invalid')
        artifacts = {}
        for row in tables['artifacts']:
            require(check_hash(row['digest']) and sha256_hex(row['body'].encode('utf-8')) == row['digest'], 'artifact_digest_mismatch')
            artifacts[row['digest']] = row['body']
        owners = {}
        current = None
        for row in sorted(tables['owner_history'], key=lambda item: item['sequence']):
            authorization, mandate = parse_object(row['authorization']), parse_object(row['mandate'])
            issued_at = parse_timestamp(authorization.get('issued_at'))
            require(issued_at is not None, 'owner_issued_at_invalid')
            checked = validate_mandate_authorization(authorization,
                expected_slot_id=roots['slot_id'], expected_owner_id=roots['owner_id'],
                expected_public_key=roots['owner_key'], now=issued_at)
            _apply_mandate_successor(current, checked)
            spec = MandateSpec.from_mapping(mandate)
            require(spec.principal_id == roots['owner_id'], 'mandate_principal_owner_mismatch')
            require(row['sequence'] == checked['sequence'] and row['hash'] == checked['payload_hash'], 'owner_row_binding_mismatch')
            require(checked['mandate_hash'] == spec.mandate_hash, 'owner_mandate_hash_mismatch')
            require(issued_at <= watermark, 'owner_after_receiver_watermark')
            owners[row['sequence']] = (row, checked, spec)
            current = {'authorization': checked}
        sites = {row['site_id']: row for row in tables['sites']}
        require(len(sites) == len(tables['sites']), 'duplicate_site')
        for site in sites.values():
            require(type(site['version']) is int and site['version'] >= 1 and site['commissioned'] in (0, 1), 'site_shape_invalid')
            require(site['simulation_digest'] in artifacts and site['robot_config_digest'] in artifacts, 'site_artifact_missing')
        commitments = sorted(tables['commitments'], key=lambda item: item['seq'])
        previous_outcome = None
        previous_owner_sequence = 0
        after_by_site = {}
        commitments_by_decision = {}
        for expected_sequence, row in enumerate(commitments, 1):
            try:
                require(row['seq'] == expected_sequence, 'commitment_sequence_gap')
                receipt, action, outcome = (parse_object(row[name]) for name in ('receipt', 'action', 'outcome'))
                verification = verify_decision_receipt(receipt, roots['gate_keys'])
                require(verification['valid'], 'signed_permission_invalid:' + ','.join(verification['errors']))
                require(receipt.get('decision') == 'COMMIT' and receipt.get('verdict') == 'VERIFIED', 'decision_not_commit')
                authorization = receipt['commit_authorization']
                binding, reasons = _normalize_execution_action(action)
                require(not reasons and binding is not None, 'execution_action_invalid:' + ','.join(reasons))
                require(all(binding[key] == authorization.get(key) for key in binding), 'exact_action_binding_mismatch')
                require(_action_hash(binding) == authorization['action_hash'], 'action_hash_mismatch')
                require(check_hash(row['code_hash']) and row['code_hash'] == authorization['one_use_code_hash'], 'stored_code_hash_mismatch')
                require(row['decision_hash'] == receipt['payload_hash'] and row['authorization_hash'] == authorization['authorization_hash'], 'commitment_authorization_mismatch')
                require(row['request_hash'] == digest({'receipt': receipt, 'action': action}), 'request_hash_mismatch')
                valid, reason = verify_olp_signature(outcome)
                require(valid, 'outcome_signature_invalid:' + str(reason))
                require(outcome['signature']['public_key'] == roots['outcome_key'], 'outcome_key_not_trusted')
                committed_at = parse_timestamp(outcome.get('committed_at'))
                created_at, expiry = parse_timestamp(receipt.get('created_at')), parse_timestamp(authorization.get('expires_at'))
                require(committed_at is not None and created_at is not None and expiry is not None, 'commit_time_invalid')
                require(created_at <= committed_at < expiry and committed_at <= watermark, 'commit_time_outside_authorization')
                require(row['owner_sequence'] in owners, 'commit_owner_missing')
                owner_row, checked_owner, spec = owners[row['owner_sequence']]
                validate_mandate_authorization(checked_owner,
                    expected_slot_id=roots['slot_id'], expected_owner_id=roots['owner_id'],
                    expected_public_key=roots['owner_key'], now=committed_at)
                require(checked_owner['state'] == 'ACTIVE', 'commit_owner_revoked')
                require(row['owner_sequence'] >= previous_owner_sequence, 'commit_owner_sequence_rollback')
                previous_owner_sequence = row['owner_sequence']
                settings = action['settings']
                require(set(settings) == {'profile', 'mandate_hash', 'simulation_digest', 'robot_config_digest', 'site_version', 'site_id', 'idempotency_key'}, 'commission_settings_shape_invalid')
                require(settings['profile'] == 'sqlite_commissioning/v1' and action['tool'] == 'sqlite.commission', 'commission_profile_invalid')
                require(action['target'] == 'sqlite://commissioning/' + settings['site_id'], 'commission_target_invalid')
                require(type(settings['site_version']) is int and settings['site_version'] >= 1, 'commission_version_invalid')
                require(isinstance(settings['idempotency_key'], str) and settings['idempotency_key'], 'idempotency_key_invalid')
                require(settings['mandate_hash'] == spec.mandate_hash, 'commit_mandate_mismatch')
                effect = dict(profile='principal_effect/v1', effect_id=settings['idempotency_key'], mandate_id=spec.mandate_id,
                    principal_id=spec.principal_id, agent_id=spec.agent_id, purpose=spec.purpose, action_type='send',
                    target=action['target'], disclosures=[], value_cents=0, delegatee=None, producer_model='independent-verifier')
                assessment = assess_effect(spec, effect, now=committed_at)
                require(assessment['allowed'], 'commit_outside_mandate:' + ','.join(assessment['reason_codes']))
                for name in ('simulation_digest', 'robot_config_digest'):
                    require(settings[name] in artifacts, 'commit_artifact_missing:' + name)
                require(action['evidence_hashes'] == [settings['simulation_digest']], 'simulation_evidence_binding_mismatch')
                simulation = parse_object(artifacts[settings['simulation_digest']])
                require(simulation.get('approved') is True, 'simulation_not_approved')
                before = dict(site_id=settings['site_id'], version=settings['site_version'],
                    simulation_digest=settings['simulation_digest'], robot_config_digest=settings['robot_config_digest'], commissioned=0)
                after = {**before, 'version': before['version'] + 1, 'commissioned': 1}
                require(row['site_id'] == settings['site_id'] and row['site_id'] in sites, 'commit_site_mismatch')
                require(row['before_version'] == before['version'] and row['after_version'] == after['version'], 'commit_version_mismatch')
                require(row['idempotency_key'] == settings['idempotency_key'], 'commit_idempotency_mismatch')
                if row['site_id'] in after_by_site:
                    require(after_by_site[row['site_id']] == before, 'site_transition_chain_mismatch')
                expected_body = {'schema': 'openline.sqlite_consequence.outcome.v1', 'status': 'COMMITTED',
                    'implementation': implementation, 'seq': row['seq'], 'previous_outcome_hash': digest(previous_outcome) if previous_outcome else None,
                    'idempotency_key': row['idempotency_key'], 'request_hash': row['request_hash'],
                    'decision_hash': row['decision_hash'], 'authorization_hash': row['authorization_hash'],
                    'action_hash': authorization['action_hash'], 'owner_head_hash': owner_row['hash'],
                    'owner_sequence': row['owner_sequence'], 'subject': spec.agent_id, 'policy_hash': action['policy_hash'],
                    'before': before, 'after': after, 'committed_at': outcome['committed_at']}
                require({key: value for key, value in outcome.items() if key not in ('payload_hash', 'signature')} == expected_body, 'outcome_body_reconstruction_mismatch')
                previous_outcome = outcome
                after_by_site[row['site_id']] = after
                commitments_by_decision[row['decision_hash']] = (row, authorization, committed_at)
                result['signed_outcomes'] += 1
            except Exception as exc:
                errors.append(f"commitment_{row['seq']}:{type(exc).__name__}:{exc}")
        for name in ('idempotency_key', 'decision_hash', 'authorization_hash', 'code_hash'):
            require(len({row[name] for row in commitments}) == len(commitments), 'duplicate_commitment:' + name)
        require(len({(row['site_id'], row['before_version']) for row in commitments}) == len(commitments), 'duplicate_site_version_commitment')
        for site_id, site in sites.items():
            if site_id in after_by_site:
                require(site == after_by_site[site_id], 'durable_site_differs_from_signed_outcome:' + site_id)
            else:
                require(site['commissioned'] == 0, 'commissioned_site_without_signed_commitment:' + site_id)
        require(len(tables['ledger']) == 1 and tables['ledger'][0]['id'] == 1, 'ledger_row_invalid')
        ledger = parse_object(tables['ledger'][0]['body'])
        result['ledger'] = ledger
        require(ledger.get('schema') == COMMIT_LEDGER_SCHEMA, 'ledger_schema_invalid')
        for name in ('consumed_decisions', 'consumed_codes', 'consumed_replay_scopes'):
            require(isinstance(ledger.get(name), dict), 'ledger_shape_invalid:' + name)
        require(isinstance(ledger.get('attempts'), list), 'ledger_attempts_invalid')
        nonempty = any(ledger[name] for name in ('consumed_decisions', 'consumed_codes', 'consumed_replay_scopes', 'attempts'))
        result['ledger_mode'] = implementation
        if implementation == 'conventional':
            require(not nonempty, 'conventional_ledger_must_be_empty')
            require(ledger.get('commit_seq_next') == 1, 'conventional_ledger_sequence_invalid')
        else:
            require(set(ledger['consumed_decisions']) == {row['decision_hash'] for row in commitments}, 'ledger_decisions_differ_from_commitments')
            require(set(ledger['consumed_codes']) == {row['code_hash'] for row in commitments}, 'ledger_codes_differ_from_commitments')
            require(not ledger['consumed_replay_scopes'], 'unexpected_replay_scope_consumption')
            attempts = ledger['attempts']
            require(len({attempt['attempt_id'] for attempt in attempts}) == len(attempts), 'duplicate_ledger_attempt')
            authorized = [attempt for attempt in attempts if attempt['result'] == 'AUTHORIZED']
            require(len(authorized) == len(commitments), 'authorized_attempts_differ_from_commitments')
            require({attempt['decision_payload_hash'] for attempt in authorized} == set(commitments_by_decision), 'authorized_decisions_differ_from_commitments')
            require([attempt['commit_seq'] for attempt in attempts] == list(range(1, len(attempts) + 1)), 'ledger_attempt_sequence_invalid')
            require(ledger['commit_seq_next'] == len(attempts) + 1, 'ledger_next_sequence_invalid')
            for attempt in attempts:
                require(attempt['result'] in ('AUTHORIZED', 'BLOCKED'), 'ledger_result_invalid')
                if attempt['result'] == 'BLOCKED':
                    require(attempt['execution_status'] == 'not_started' and attempt['reason_codes'], 'blocked_ledger_attempt_invalid')
                    continue
                require(attempt['decision_payload_hash'] in commitments_by_decision, 'ledger_commitment_missing')
                row, authorization, committed_at = commitments_by_decision[attempt['decision_payload_hash']]
                decision_state = ledger['consumed_decisions'][row['decision_hash']]
                code_state = ledger['consumed_codes'][row['code_hash']]
                expected_decision = dict(authorization_hash=row['authorization_hash'], one_use_code_hash=row['code_hash'],
                    action_hash=authorization['action_hash'], consumed_at=attempt['checked_at'], attempt_id=attempt['attempt_id'])
                expected_code = dict(decision_payload_hash=row['decision_hash'], consumed_at=attempt['checked_at'], attempt_id=attempt['attempt_id'])
                require(decision_state == expected_decision and code_state == expected_code, 'ledger_consumption_binding_mismatch')
                checked_at = parse_timestamp(attempt['checked_at'])
                receipt = parse_object(row['receipt'])
                created_at = parse_timestamp(receipt['created_at'])
                expiry = parse_timestamp(authorization['expires_at'])
                require(checked_at is not None and created_at <= checked_at <= committed_at < expiry, 'ledger_commit_time_mismatch')
                require(attempt['authorization_hash'] == row['authorization_hash'] and attempt['attempt_action_hash'] == authorization['action_hash'], 'ledger_attempt_binding_mismatch')
                require(attempt['execution_status'] == 'permitted' and attempt['reason_codes'] == [] and attempt['tool_result_hash'] is None, 'ledger_attempt_status_invalid')
        result['valid'] = not errors
    except Exception as exc:
        errors.append(f'{type(exc).__name__}:{exc}')
    result['errors'] = sorted(set(errors))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    parser.add_argument('--roots', type=Path, required=True, help='Externally trusted JSON roots; never inferred from database')
    args = parser.parse_args()
    try:
        roots = parse_object(args.roots.read_text(encoding='utf-8'))
        result = verify(args.database, roots)
    except Exception as exc:
        result = {'valid': False, 'errors': [f'{type(exc).__name__}:{exc}'], 'row_counts': {}, 'ledger': None}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
