"""Live-clock, process-removal experiment. Output directories are never reused."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from cryptography.hazmat.primitives import serialization
from protocol import *
from olp_gate.crypto import public_key_hex
from olp_gate.mandate_owner import issue_mandate_authorization
from olp_gate.tool_adapter import LocalAuthorityRuntime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def launch(script, args, config, cwd, log):
    process = subprocess.Popen([sys.executable, str(HERE / script), *args],
        cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
    process.stdin.write(json.dumps(config))
    process.stdin.close()
    process.stdin = None
    return process


def terminate(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def sleep_until(deadline):
    time.sleep(max(0, deadline - time.monotonic()))


def run_arm(arm, output):
    output.mkdir()
    processes = []
    opened = []
    with tempfile.TemporaryDirectory(prefix='baseline-exit-private-') as temp:
        secret_root = Path(temp)
        keys = {name: Ed25519PrivateKey.generate() for name in ('O', 'A', 'B', 'R', 'AS')}
        pubs = {name: public_key_hex(key) for name, key in keys.items()}

        def raw(name):
            return keys[name].private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()

        t0 = time.monotonic()
        issuance = stamp()
        now = int(time.time())
        expires = now + (8 if arm == 'JWT_OFFLINE' else 60)
        mandate = {
            'profile': 'principal_mandate/v1', 'mandate_id': JOB, 'principal_id': OWNER,
            'agent_id': 'A' if arm == 'OL_BOUND' else JOB, 'purpose': 'continue job J',
            'allowed_action_types': ['authorize_payment'], 'allowed_targets': ['refund://J'],
            'allowed_disclosure_classes': [], 'forbidden_disclosure_classes': [],
            'max_settlement_cents': 0, 'max_payment_cents': 100, 'delegation_allowed': False,
            'expires_at': iso(expires), 'version': '1',
        }
        authorization = None
        runtime_keys = {}
        runtime_dir = secret_root / 'receiver-runtime'
        if arm.startswith('OL_'):
            authorization = issue_mandate_authorization(
                slot_id=SLOT, owner_id=OWNER, mandate=mandate, state='ACTIVE',
                sequence=1, predecessor_hash=None,
                issued_at=datetime.fromtimestamp(now, timezone.utc),
                expires_at=datetime.fromtimestamp(expires, timezone.utc), key=keys['O'])
            runtime = LocalAuthorityRuntime(runtime_dir)
            runtime_keys = {name: public_key_hex(runtime._key(name))
                            for name in ('source', 'witness', 'gate')}
        fields = {'job_id': JOB, 'client_id': 'job-client', 'scope': 'refund',
                  'max_amount_cents': 100}
        if arm == 'JWT_BOUND':
            fields['cnf'] = {'jwk': jwk(pubs['A'])}
        token = issue(keys['O'], OWNER, OWNER, RECEIVER, 'at+jwt', fields,
                      ttl=8 if arm == 'JWT_OFFLINE' else 60)
        grant = jwt.decode(token, options={'verify_signature': False})
        grant_hash = digest(json_bytes(authorization)) if authorization else digest(token)
        contract_fields = {'profile': 'BASELINE-EXIT-001/' + arm, 'job_id': JOB,
            'owner_key': pubs['O'], 'receiver_key': pubs['R'], 'as_key': pubs['AS'],
            'workers': {'A': pubs['A'], 'B': pubs['B']}, 'grant_hash': grant_hash,
            'runtime_keys': runtime_keys, 'scope': 'refund', 'max_amount_cents': 100,
            'status_max_lifetime_seconds': 1, 'as_delegation': arm == 'OAUTH_EXCHANGE'}
        contract_token = issue(keys['O'], OWNER, OWNER, RECEIVER,
                               'baseline-exit-contract+jwt', contract_fields, ttl=120)
        contract = contract_claims(contract_token, pubs['O'])
        write(output / 'presentation.json', {'arm': arm, 'owner_public_key': pubs['O'],
            'contract': contract_token, 'grant': authorization if authorization else token,
            'mandate': mandate if authorization else None})
        common = {'arm': arm, 'contract': contract, 'owner_key': pubs['O'],
                  'grant_jti': grant['jti'], 'expires': expires,
                  'authorization': authorization, 'mandate': mandate}
        authority_config = dict(common)
        if arm == 'OAUTH_EXCHANGE':
            authority_config['as_private'] = raw('AS')
        else:
            authority_config['owner_private'] = raw('O')

        try:
            for role in ('authority', 'receiver'):
                log = (output / (role + '.stderr.log')).open('w')
                opened.append(log)
                if role == 'authority':
                    cfg = authority_config
                else:
                    cfg = dict(common, authority_url=authority_url,
                               receiver_private=raw('R'), runtime_dir=str(runtime_dir))
                process = launch('service.py', [role], cfg, secret_root, log)
                processes.append(process)
                line = process.stdout.readline()
                if not line:
                    raise RuntimeError('service_startup_failure:' + role)
                ready = json.loads(line)
                url = f"http://127.0.0.1:{ready['port']}"
                code, response = request(url + '/health')
                if code != 200 or response != {'ready': True}:
                    raise RuntimeError('health_failure:' + role)
                if role == 'authority':
                    authority_url = url
                else:
                    receiver_url = url

            def worker_config(name):
                return {'arm': arm, 'worker': name, 'worker_private': raw(name),
                        'token': token, 'authorization': authorization,
                        'receiver_url': receiver_url, 'authority_url': authority_url,
                        'deadline': t0 + 12, 'revoke_after': t0 + 1.2}

            a_dir = secret_root / 'provider-A'
            a_dir.mkdir()
            a_log = (output / 'worker-A.stderr.log').open('w')
            opened.append(a_log)
            a = launch('worker.py', [], worker_config('A'), a_dir, a_log)
            processes.append(a)
            a_messages = []
            while not any('attempt' in row for row in a_messages):
                line = a.stdout.readline()
                if not line:
                    raise RuntimeError('worker_A_failure')
                a_messages.append(json.loads(line))
            sleep_until(time.monotonic() + .4)
            terminate(a)
            shutil.rmtree(a_dir)
            del keys['A']
            removed = stamp()
            removal = {'pid': a.pid, 'returncode': a.returncode, 'reaped': a.poll() is not None,
                       'unique_directory_removed': not a_dir.exists(), 'at': removed,
                       'removed_roles': ['Worker A', 'Provider A'],
                       'remaining_departed_authority_services': []}
            write(output / 'removal.json', removal)

            b_dir = secret_root / 'provider-B'
            b_dir.mkdir()
            b_log = (output / 'worker-B.stderr.log').open('w')
            opened.append(b_log)
            b = launch('worker.py', [], worker_config('B'), b_dir, b_log)
            processes.append(b)
            b_messages = []

            def drain():
                for line in b.stdout:
                    b_messages.append(json.loads(line))

            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            deadline = time.monotonic() + 5
            while not any('attempt' in row for row in b_messages):
                if b.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('worker_B_startup_failure')
                time.sleep(.01)
            sleep_until(t0 + 1.2)
            owner_at = stamp()
            revoked = issue(keys['O'], OWNER, OWNER, RECEIVER, 'owner-revocation+jwt',
                            {'job_id': JOB, 'grant_hash': grant_hash,
                             'owner_revoked_at_ns': owner_at['utc_ns']})
            code, rev_response = request(authority_url + '/revoke', {'owner_request': revoked})
            if code != 200:
                raise RuntimeError('owner_revoke_failure')
            write(output / 'revocation.json', {'owner_at': owner_at, 'owner_request': revoked,
                                              'service_response': rev_response})
            b.wait(timeout=14)
            reader.join(timeout=2)
            if b.returncode != 0:
                raise RuntimeError('worker_B_failure')
            code, receiver_evidence = request(receiver_url + '/evidence')
            if code != 200:
                raise RuntimeError('receiver_evidence_failure')
            code, authority_evidence = request(authority_url + '/evidence')
            if code != 200:
                raise RuntimeError('authority_evidence_failure')
            write(output / 'receiver.json', receiver_evidence)
            write(output / 'authority.json', authority_evidence)
            write(output / 'workers.json', {'A': a_messages, 'B': b_messages})
            write(output / 'timeline.json', {'issuance': issuance, 'removal': removed,
                'revoke_due_monotonic_ns': str(int((t0 + 1.2) * 1e9)),
                'owner_revocation': owner_at, 'finished': stamp(),
                'sampling_interval_seconds': .1, 'expiry_numeric_date': grant['exp'],
                'shared_clock': 'all processes use the same host monotonic/UTC clocks',
                'B_pid': b.pid, 'B_directory_distinct': b_dir != a_dir})
            if arm.startswith('OL_'):
                # Only public logs, never the runtime's keys or one-use secrets.
                for name in ('compiler_results.jsonl', 'decision_receipts.jsonl'):
                    path = runtime_dir / name
                    if path.exists():
                        shutil.copy2(path, output / ('openline-' + name))
            # A non-executing probe determines post-STOP validity of A's grant
            # in bound controls. It does not resurrect A or sign as A.
            if arm in ('OL_BOUND', 'JWT_BOUND'):
                code, response = request(authority_url + '/status')
                write(output / 'post-stop-status.json', dict(response, at=stamp()))
            write(output / 'process-completion.json', {'worker_B_exit': b.returncode,
                'private_material_location': 'ephemeral TemporaryDirectory, removed at completion',
                'new_owner_authorization_at_succession': False,
                'departed_reauthorization': False,
                'surviving_AS_reissuance_at_succession': arm == 'OAUTH_EXCHANGE'})
        finally:
            for process in reversed(processes):
                terminate(process)
            for handle in opened:
                handle.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    output = Path(args.out).resolve()
    if output.exists():
        raise SystemExit('refusing to reuse evidence output directory')
    freeze = json.loads((HERE / 'FREEZE.json').read_text())
    if digest((HERE / 'PREREGISTRATION.md').read_bytes()) != freeze['preregistration_sha256']:
        raise SystemExit('preregistration_changed')
    if subprocess.check_output(['git', 'show', freeze['preregistration_commit'] +
        ':experiments/baseline-exit-001/PREREGISTRATION.md'], cwd=ROOT) != (HERE / 'PREREGISTRATION.md').read_bytes():
        raise SystemExit('preregistration_not_frozen')
    output.mkdir(parents=True)
    metadata = {'implementation_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                cwd=ROOT, text=True).strip(), 'preregistration_commit': freeze['preregistration_commit'],
                'python': sys.version, 'dependencies': {name: importlib.metadata.version(name)
                    for name in ('PyJWT', 'cryptography', 'setuptools', 'wheel', 'openline-receipt-gate')},
                'command': ' '.join(sys.argv), 'began': stamp(), 'arms': list(ARMS)}
    write(output / 'metadata.json', metadata)
    for arm in ARMS:
        try:
            run_arm(arm, output / arm)
            print(arm + ': completed', flush=True)
        except Exception as error:
            write(output / arm / 'APPARATUS_FAILURE.json', {'error': type(error).__name__,
                                                          'detail': str(error), 'at': stamp()})
            print(arm + ': INCONCLUSIVE_APPARATUS ' + str(error), flush=True)
    write(output / 'completion.json', {'finished': stamp()})


if __name__ == '__main__':
    main()
