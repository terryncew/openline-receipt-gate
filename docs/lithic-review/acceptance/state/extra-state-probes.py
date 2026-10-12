"""Independent acceptance probes; synthetic local state only; no repository edits."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import test_lithic_preflight as fixture
from openline_receiver.openline_wallet.crypto import public_key_hex

ROOT = Path(__file__).resolve().parents[4] / 'gateway/receiver-package'
OUTPUT = Path(os.environ.get('OPENLINE_AUDIT_OUTPUT', '/tmp/openline-lithic-state-probes'))
OUTPUT.mkdir(parents=True, exist_ok=True)
results = {'scope': 'synthetic offline one-owner one-card exactly 100 USD cents; protected host, no old state restoration', 'probes': {}}

# Independently inspect the existing public evidence, with no adapter verification.
evidence_root = ROOT / 'evidence/preflight-001'
checksums = json.loads((evidence_root / 'SHA256SUMS.json').read_text())
hash_failures = [name for name, digest in checksums.items() if hashlib.sha256((evidence_root / name).read_bytes()).hexdigest() != digest]
assert not hash_failures, hash_failures
results['probes']['preserved_evidence_manifest'] = {'files': len(checksums), 'hash_mismatches': hash_failures}
public_path = evidence_root / 'ci-final/measurements/asa-sequence-public-evidence.json'
pin_path = evidence_root / 'ci-final/measurements/receiver-pinned.pub'
public = json.loads(public_path.read_text())
pin = pin_path.read_text().strip()
assert pin == public['receiver_public_key_pinned_before_asa']
for receipt in public['receipts']:
    fixture.independently_verify(receipt, pin)
assert len({r['txn_token'] for r in public['receipts']}) == 3
assert [r['result'] for r in public['receipts']] == ['APPROVED', 'CARD_PAUSED', 'APPROVED']
assert all(r['payment_details']['amounts']['cardholder']['amount'] == 100 for r in public['receipts'])
results['probes']['preserved_signed_sequence'] = {'receipts_verified': 3, 'unique_transaction_tokens': 3, 'receiver_pin_matches_explicit_file': True, 'results': [r['result'] for r in public['receipts']]}

def sensitive_names(value, prefix=''):
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            name = prefix + '.' + key
            if any(term in key.lower() for term in ('private_key', 'secret', 'bearer', 'password', 'credential')):
                found.append(name)
            found.extend(sensitive_names(item, name))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(sensitive_names(item, prefix + '[' + str(index) + ']'))
    return found
assert sensitive_names(public) == []
results['probes']['public_evidence_sensitive_field_scan'] = {'sensitive_field_names': []}

# Use the published standalone verifier and intentionally corrupt copies outside checkout.
negative_dir = OUTPUT / 'verifier-negative'
negative_dir.mkdir(exist_ok=True)
wrong_pin = negative_dir / 'wrong-pinned.pub'
wrong_pin.write_text(public_key_hex(Ed25519PrivateKey.generate()) + '\n')
changed_result = deepcopy(public)
changed_result['receipts'][0]['result'] = 'CARD_PAUSED'
changed_signature = deepcopy(public)
changed_signature['receipts'][0]['signature']['value'] = '00' * 64
cases = [('original', public_path, pin_path, True), ('wrong_pin', public_path, wrong_pin, False)]
for name, evidence in [('changed_result', changed_result), ('changed_signature', changed_signature)]:
    path = negative_dir / (name + '.json')
    path.write_text(json.dumps(evidence))
    cases.append((name, path, pin_path, False))
verifier_results = {}
for name, evidence, pinned, should_pass in cases:
    run = subprocess.run([sys.executable, str(ROOT / 'verify_pilot_receipts.py'), '--evidence', str(evidence), '--pinned-public-key', str(pinned)], capture_output=True, text=True)
    assert (run.returncode == 0) == should_pass, name
    verifier_results[name] = {'exit_code': run.returncode, 'expected_acceptance': should_pass}
results['probes']['standalone_verifier_positive_and_negatives'] = verifier_results

# HTTP bearer isolation and the documented old-complete-database rollback boundary.
pilot = fixture.HTTPPreflightTests(methodName='test_authenticated_receipt_retrieval_is_read_only_and_independently_pinned')
pilot.setUp()
try:
    pilot.authorize()
    backup_path = pilot.path / 'unsupported-old-complete-backup.sqlite3'
    with sqlite3.connect(backup_path) as backup:
        pilot.adapter.db.backup(backup)
    backup_path.chmod(0o600)
    file_modes = {suffix or 'main': oct(Path(str(pilot.db_path) + suffix).stat().st_mode & 0o777) for suffix in ('', '-wal', '-shm') if Path(str(pilot.db_path) + suffix).exists()}
    assert all(mode == '0o600' for mode in file_modes.values())
    hashes = pilot.adapter.db.execute('SELECT token_hash FROM integrators').fetchall()
    assert hashes == [(hashlib.sha256(pilot.bearer.encode()).hexdigest(),)]
    assert pilot.bearer.encode() not in pilot.db_path.read_bytes()
    assert pilot.asa()[:2] == (200, {'result':'APPROVED'})
    receipt_before = pilot.receipt()[1]
    total_changes = pilot.adapter.db.total_changes
    credential_cases = {
        'correct_bearer': pilot.receipt()[0],
        'asa_secret_as_bearer': pilot.receipt(bearer=fixture.TEST_ASA_SECRET)[0],
        'receiver_public_pin_as_bearer': pilot.receipt(bearer=pilot.pinned_public)[0],
        'worker_private_key_as_bearer': pilot.receipt(bearer=pilot.worker.private_bytes_raw().hex())[0],
        'unrelated_bearer': pilot.receipt(bearer='synthetic-wrong-credential-' + 'b'*40)[0],
        'correct_bearer_unknown_receipt': pilot.receipt(token=str(uuid.uuid4()))[0],
    }
    assert credential_cases == {'correct_bearer':200, 'asa_secret_as_bearer':401, 'receiver_public_pin_as_bearer':401, 'worker_private_key_as_bearer':401, 'unrelated_bearer':401, 'correct_bearer_unknown_receipt':401}
    assert pilot.adapter.db.total_changes == total_changes
    results['probes']['receipt_credential_isolation'] = {'http_statuses':credential_cases, 'receipt_reads_application_changes':0, 'stored_only_sha256_bearer_hash':True, 'receiver_file_permissions':file_modes}
    pilot.owner.revoke(pilot.mandate, reason='synthetic acceptance boundary probe')
    pilot.adapter.admit_bundle(pilot.owner.principal_id, pilot.owner.export_bundle())
    pilot.restart()
    old_retry = pilot.asa()[:2]
    after_revocation = deepcopy(pilot.request)
    after_revocation['token'] = str(uuid.uuid4())
    new_after_revocation = pilot.asa(after_revocation)[:2]
    assert old_retry == (200, {'result':'APPROVED'})
    assert new_after_revocation == (200, {'result':'CARD_PAUSED'})
    assert pilot.receipt()[1] == receipt_before
    pilot._stop_all()
    shutil.copyfile(backup_path, pilot.db_path)
    # Reopening intentionally restored coherent old state trusts the same separately pinned receiver key.
    pilot.adapter = fixture.SecureLithicAdapter(pilot.db_path, gate_id=pilot.gate, signing_secrets=fixture.TEST_ASA_SECRET, expected_receiver_public_key=pilot.pinned_public)
    pilot._start_server()
    restored_new = deepcopy(pilot.request)
    restored_new['token'] = str(uuid.uuid4())
    result = pilot.asa(restored_new)[:2]
    assert result == (200, {'result':'APPROVED'})
    fixture.independently_verify(pilot.receipt(restored_new['token'])[1], pilot.pinned_public)
    results['probes']['coherent_complete_database_restore_boundary'] = {'cached_old_retry_after_revocation':old_retry, 'new_token_after_revocation':new_after_revocation, 'new_token_after_unsupported_backup_restore':result, 'same_independently_pinned_receiver_key':True, 'classification':'Documented unsupported boundary, not an in-scope material blocker; protect storage and do not restore old state.'}
finally:
    pilot.doCleanups()
results['result'] = 'PASS; no material state or receipt blocker reproduced within documented offline pilot scope'
(OUTPUT / 'extra-state-probes.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
