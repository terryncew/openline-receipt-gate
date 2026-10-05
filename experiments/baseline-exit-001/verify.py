"""Fresh offline verifier: owner pin + portable presented artifacts only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
import tempfile

from protocol import *
from olp_gate.gateway import verify_decision_receipt
from olp_gate.mandate_owner import MandateOwnerView
from olp_gate.subject_bound_commit import SubjectBoundCommitGate
from olp_gate.verified_commit import VerifiedCommitLedger


def read(path):
    return json.loads(path.read_text())


def event_claims(entry, contract):
    unsigned = jwt.decode(entry['signed_event'], options={'verify_signature': False})
    # Audit authenticity has no authorization-expiry meaning. All nested
    # authority credentials are evaluated at their signed observation time.
    return verify(entry['signed_event'], contract['receiver_key'], RECEIVER,
                  'urn:baseline-exit:audit', 'receiver-event+jwt',
                  at=unsigned['iat'] + .001)['event']


def evaluate_openline(arm, presentation, event, contract, when):
    snapshot = verify(event['snapshot'], contract['owner_key'], OWNER, RECEIVER,
                      'owner-standing+jwt', at=when,
                      required=['records', 'mandate', 'sequence', 'head_hash'])
    if snapshot['mandate'] != presentation['mandate'] or snapshot['job_id'] != JOB:
        raise ValueError('standing_binding_invalid')
    view = MandateOwnerView({SLOT: {'owner_id': OWNER, 'public_key': contract['owner_key']}})
    dt = datetime.fromtimestamp(when, timezone.utc)
    for record in snapshot['records']:
        view.admit(record, snapshot['mandate'], now=dt)
    if view.head_hash(SLOT) != snapshot['head_hash'] or view.head_sequence(SLOT) != snapshot['sequence']:
        raise ValueError('standing_chain_invalid')
    if event['request']['authorization'] != presentation['grant']:
        return False, 'authority_mismatch'
    status = view.status(SLOT, now=dt)
    if status != 'ACTIVE':
        return False, 'owner_standing_' + status.lower()
    if event['request']['amount_cents'] > snapshot['mandate']['max_payment_cents']:
        return False, 'amount_out_of_scope'
    if arm == 'OL_BOUND':
        with tempfile.TemporaryDirectory(prefix='baseline-exit-verifier-') as temp:
            gate = SubjectBoundCommitGate(VerifiedCommitLedger(Path(temp) / 'unused.json'),
                mandate_view=view, mandate_slot_id=SLOT, subject_source=lambda: event['worker'])
            allowed, reasons, detail = gate._check_subject(now=dt)
            if not allowed:
                return False, ','.join(reasons)
    return True, 'authorized'


def verify_arm(path):
    if (path / 'APPARATUS_FAILURE.json').exists():
        return {'arm': path.name, 'properties': {f'P{i}': 'INCONCLUSIVE' for i in range(1, 7)},
                'apparatus_failure': read(path / 'APPARATUS_FAILURE.json')}
    presentation = read(path / 'presentation.json')
    timeline = read(path / 'timeline.json')
    earliest = int(timeline['finished']['utc_ns']) / 1e9
    root = presentation['owner_public_key']
    contract = contract_claims(presentation['contract'], root, at=earliest)
    if contract['owner_key'] != root or contract['profile'] != 'BASELINE-EXIT-001/' + path.name:
        raise ValueError('owner_contract_binding_invalid')
    if digest(json_bytes(presentation['grant']) if isinstance(presentation['grant'], dict)
              else presentation['grant']) != contract['grant_hash']:
        raise ValueError('grant_hash_mismatch')
    removal = read(path / 'removal.json')
    if not all(removal[k] for k in ('reaped', 'unique_directory_removed')):
        raise ValueError('permanent_exit_not_observed')
    receiver = read(path / 'receiver.json')
    revocation = read(path / 'revocation.json')
    revoke_at = int(revocation['owner_at']['utc_ns']) / 1e9
    revoke_mono = int(revocation['owner_at']['monotonic_ns'])
    owner_revoke = verify(revocation['owner_request'], root, OWNER, RECEIVER,
                          'owner-revocation+jwt', at=revoke_at)
    if owner_revoke['grant_hash'] != contract['grant_hash'] or owner_revoke['owner_revoked_at_ns'] != revocation['owner_at']['utc_ns']:
        raise ValueError('revocation_evidence_invalid')
    events = []
    checks = []
    expected_count = 0
    apparatus_errors = []
    for index, entry in enumerate(receiver['events']):
        event = event_claims(entry, contract)
        request_body = event['request']
        when = int(event['evaluation']['utc_ns']) / 1e9
        observed = int(event['observed']['utc_ns']) / 1e9
        start = int(event['request_start']['utc_ns']) / 1e9
        assertion = verify(request_body['worker_assertion'], contract['workers'][event['worker']],
                           event['worker'], RECEIVER, 'worker-request+jwt', at=start)
        unsigned_request = {k: v for k, v in request_body.items() if k != 'worker_assertion'}
        if assertion['body_hash'] != digest(json_bytes(unsigned_request)):
            raise ValueError('worker_request_binding_invalid')
        if event['reason'].startswith('apparatus_or_validation_error:'):
            apparatus_errors.append({'event_index': index, 'reason': event['reason']})
            allowed, why = False, event['reason']
        elif path.name.startswith('OL_'):
            allowed, why = evaluate_openline(path.name, presentation, event, contract, when)
            detail = event['openline'] or {}
            if detail.get('decision_receipt'):
                checked = verify_decision_receipt(detail['decision_receipt'], [contract['runtime_keys']['gate']])
                if not checked['valid']:
                    raise ValueError('openline_decision_receipt_invalid:' + str(checked))
        else:
            allowed, why = evaluate_standard(path.name, request_body['token'], event['worker'],
                request_body['amount_cents'], event['snapshot'], contract, at=when)
            if path.name == 'OAUTH_EXCHANGE':
                # Verify the owner-issued subject grant as well as delegated AS
                # output; AS attribution alone is insufficient for P1.
                grant_claims(presentation['grant'], contract, at=when)
        if allowed != event['allowed']:
            raise ValueError(f'decision_reconstruction_mismatch:{index}:{why}:{event["reason"]}')
        if event['before'] != expected_count:
            raise ValueError('effect_checkpoint_not_continuous')
        expected_count += int(allowed)
        if event['after'] != expected_count:
            raise ValueError('refused_action_effected_or_accepted_action_missing')
        if event['worker'] == 'B' and start < int(removal['at']['utc_ns']) / 1e9:
            raise ValueError('B_started_before_permanent_exit')
        checks.append({'event_index': index, 'worker': event['worker'], 'amount_cents': request_body['amount_cents'],
                       'observed_utc_ns': event['observed']['utc_ns'], 'reconstructed_allowed': allowed,
                       'reconstructed_reason': why, 'recorded_reason': event['reason'],
                       'effect_counter': event['after'], 'signature_and_authority_verified': True})
        events.append(event)
    if receiver['effect_counter'] != expected_count:
        raise ValueError('final_effect_query_mismatch')
    a = [e for e in events if e['worker'] == 'A']
    b = [e for e in events if e['worker'] == 'B' and e['request']['amount_cents'] == 25]
    caps = [e for e in events if e['worker'] == 'B' and e['request']['amount_cents'] == 101]
    if not a or not a[0]['allowed'] or not b or not caps or any(e['allowed'] for e in caps):
        raise ValueError('required_initial_or_scope_observation_missing')
    pre = [e for e in b if int(e['observed']['utc_ns']) / 1e9 < revoke_at and e['allowed']]
    post = [e for e in b if int(e['request_start']['utc_ns']) / 1e9 >= revoke_at]
    accepted = [e for e in b if e['allowed']]
    rejected = [e for e in post if not e['allowed']]
    last = accepted[-1] if accepted else None
    first = rejected[0] if rejected else None
    lag = ((int(first['observed']['monotonic_ns']) - revoke_mono) / 1e9
           if first and pre else None)
    bound = path.name in ('OL_BOUND', 'JWT_BOUND')
    props = {'P1': 'PASS', 'P2': 'PASS', 'P3': 'PASS' if pre else 'FAIL',
             'P4': ('PARTIAL' if bound or (lag is not None and lag > 1) else
                    'PASS' if lag is not None and first else 'FAIL'), 'P5': 'PASS', 'P6': 'PASS'}
    if not bound:
        if first is None or len(rejected) < 2:
            props['P4'] = 'FAIL'
        elif any(e['allowed'] for e in post[post.index(first):]):
            props['P4'] = 'FAIL'
    if path.name == 'JWT_OFFLINE' and first:
        if int(first['evaluation']['utc_ns']) / 1e9 > timeline['expiry_numeric_date'] + 1:
            props['P4'] = 'FAIL'
    if apparatus_errors:
        props = {f'P{i}': 'INCONCLUSIVE' for i in range(1, 7)}
    post_stop_probe = None
    if bound:
        probe_evidence = read(path / 'post-stop-status.json')
        status_token = probe_evidence['snapshot']
        at = int(probe_evidence['at']['utc_ns']) / 1e9
        if path.name == 'JWT_BOUND':
            allowed, why = evaluate_standard(path.name, presentation['grant'], 'A', 25,
                                             status_token, contract, at=at)
        else:
            probe = dict(b[-1], worker='A', snapshot=status_token)
            allowed, why = evaluate_openline(path.name, presentation, probe, contract, at)
        if allowed:
            raise ValueError('post_stop_original_grant_still_authorized')
        post_stop_probe = {'actor': 'A', 'executed': False, 'allowed': allowed, 'reason': why}
    return {'arm': path.name, 'properties': props, 'checks': checks,
        'apparatus_errors': apparatus_errors, 'signed_receiver_event_count': len(events),
        'observed_effect_count': expected_count, 'owner_revoked_utc_ns': revocation['owner_at']['utc_ns'],
        'last_B_accept_utc_ns': last['observed']['utc_ns'] if last else None,
        'first_post_revocation_B_refuse_utc_ns': first['observed']['utc_ns'] if first else None,
        'first_B_refuse_reason': first['reason'] if first else None,
        'revocation_lag_seconds': lag, 'sampling_interval_seconds': .1,
        'already_refused_before_revocation': bound,
        'request_straddling_revocation_indexes': [i for i, e in enumerate(events)
            if int(e['request_start']['utc_ns']) / 1e9 < revoke_at <= int(e['observed']['utc_ns']) / 1e9],
        'new_O_authorization_at_succession': False,
        'new_surviving_AS_token_for_B': path.name == 'OAUTH_EXCHANGE',
        'post_stop_original_holder_nonexecuting_probe': post_stop_probe,
        'verification_network_queries': 0,
        'verification_external_trust_pins': ['Owner O'],
        'freshness_limit': 'historical reconstruction uses signed observation times; current standing needs unexpired presented status/authority',
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run')
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    root = Path(args.run)
    results = []
    for arm in ARMS:
        result = verify_arm(root / arm)
        results.append(result)
        print(arm + ': ' + json.dumps(result['properties'], sort_keys=True))
    out = {'verifier': 'fresh process, services stopped; network not used', 'arms': results}
    Path(args.out).write_text(json.dumps(out, sort_keys=True, indent=2) + '\n')
    if any(x.get('apparatus_errors') or x.get('apparatus_failure') for x in results):
        raise SystemExit(2)


if __name__ == '__main__':
    main()
