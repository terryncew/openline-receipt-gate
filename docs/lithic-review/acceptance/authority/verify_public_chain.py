import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EVIDENCE = Path(__file__).resolve().parents[4] / 'gateway/receiver-package/evidence/preflight-001/ci-final/measurements'
data = json.loads((EVIDENCE / 'asa-sequence-public-evidence.json').read_text())
receiver = (EVIDENCE / 'receiver-pinned.pub').read_text().strip()
root = data['owner_root_public_key_pinned_before_admission']
principal = 'openline:principal:' + hashlib.sha256(bytes.fromhex(root)).hexdigest()
assert data['principal_id'] == principal
assert receiver == data['receiver_public_key_pinned_before_asa']

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

verified_count = 0
def verify(obj, expected):
    global verified_count
    body = dict(obj)
    sig = body.pop('signature')
    payload_hash = body.pop('payload_hash')
    assert sig['algorithm'] == 'Ed25519'
    assert sig['public_key'] == expected
    encoded = canonical(body)
    assert hashlib.sha256(encoded).hexdigest() == payload_hash
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected)).verify(bytes.fromhex(sig['value']), encoded)
    verified_count += 1

def rec_hash(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

prior_events = []
mandates = {}
event_types = []
for bundle in data['bundles']:
    verify(bundle, root)
    assert bundle['principal'] == {'principal_id': principal, 'root_public_key': root}
    epoch = bundle['epoch_certificate']
    verify(epoch, root)
    assert epoch['principal_id'] == principal
    assert epoch['authority'] == 'ISSUE_AND_NARROW_MANDATES'
    epoch_pub = epoch['epoch_public_key']
    assert bundle['events'][:len(prior_events)] == prior_events
    prior = None
    for seq, event in enumerate(bundle['events'], 1):
        verify(event, root if event['event_type'] == 'MANDATE_REVOKED' else epoch_pub)
        assert event['principal_id'] == principal
        assert event['sequence'] == seq
        assert event['previous_event_hash'] == prior
        prior = rec_hash(event)
        if event['event_type'] == 'MANDATE_ISSUED':
            mandates[event['data']['mandate_id']] = event['data']
    assert bundle['head'] == {'sequence': len(bundle['events']), 'event_hash': prior}
    prior_events = bundle['events']
    event_types.append([e['event_type'] for e in bundle['events']])

for receipt in data['receipts']:
    verify(receipt, receiver)
    assert receipt['principal_id'] == principal
    if receipt['authority_proof']:
        proof = receipt['authority_proof']
        decision, intent = proof['wallet_decision'], proof['worker_intent']
        verify(decision, receiver)
        mandate = mandates[receipt['mandate_id']]
        verify(intent, mandate['subject_public_key'])
        assert receipt['subject_id'] == mandate['subject_id'] == decision['subject_id'] == intent['subject_id']
        assert receipt['mandate_id'] == decision['mandate_id'] == intent['mandate_id']
        assert intent['principal_id'] == decision['principal_id'] == principal
        assert intent['presentation_hash'] == decision['presentation_hash']
        assert intent['details'] == receipt['payment_details']
        assert decision['action'] == 'lithic:authorize' and decision['decision'] == 'ALLOWED'
        assert decision['gate_public_key'] == receiver
        assert 'lithic:authorize' in mandate['scopes']

summary = {'result': 'PASS', 'signatures_checked_including_repeated_history': verified_count,
           'bundle_head_sequences': [b['head']['sequence'] for b in data['bundles']],
           'event_types_by_bundle': event_types,
           'receiver_receipt_sequence': [r['result'] for r in data['receipts']],
           'source_keys': 'separate receiver pin file and stated public owner pin',
           'evidence_limits': ['external provenance of owner and receiver pins is not demonstrated',
                               'worker presentation bytes and durable receiver challenges are not published',
                               'ASA authenticated raw bodies and HMAC credentials are not published',
                               'public evidence alone cannot prove pending invalidation, actual restart or SQLite commit atomicity']}
print(json.dumps(summary, indent=2))
