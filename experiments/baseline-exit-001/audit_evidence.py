"""Post-run integrity controls and hash verification, without rerunning arms."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from protocol import *
from verify import verify_arm

HERE = Path(__file__).resolve().parent


def corrupt_payload(token, field, value):
    header, payload, signature = token.split('.')
    claims = json.loads(jwt.utils.base64url_decode(payload))
    claims[field] = value
    return '.'.join((header, jwt.utils.base64url_encode(json_bytes(claims)).decode(), signature))


def mutate_json(path, change):
    value = json.loads(path.read_text())
    change(value)
    path.write_text(json.dumps(value))


def controls(run, output):
    mutations = [
        ('receiver_decision_tamper', 'OL_JOB', 'receiver.json',
         lambda d: d['events'][0].update(signed_event=corrupt_payload(d['events'][0]['signed_event'], 'sub', 'forged'))),
        ('owner_contract_tamper', 'OWNER_LIST', 'presentation.json',
         lambda d: d.update(contract=corrupt_payload(d['contract'], 'as_key', '00' * 32))),
        ('owner_grant_scope_tamper', 'JWT_OFFLINE', 'presentation.json',
         lambda d: d.update(grant=corrupt_payload(d['grant'], 'scope', 'admin'))),
        ('owner_revocation_tamper', 'OAUTH_EXCHANGE', 'revocation.json',
         lambda d: d.update(owner_request=corrupt_payload(d['owner_request'], 'job_id', 'other-job'))),
        ('final_effect_query_tamper', 'OWNER_LIST', 'receiver.json',
         lambda d: d.update(effect_counter=d['effect_counter'] + 1)),
        ('receiver_event_deleted', 'OL_JOB', 'receiver.json',
         lambda d: d['events'].pop(0)),
    ]
    results = []
    for name, arm, filename, mutation in mutations:
        with tempfile.TemporaryDirectory(prefix='baseline-exit-tamper-') as temp:
            target = Path(temp) / arm
            shutil.copytree(run / arm, target)
            mutate_json(target / filename, mutation)
            try:
                verify_arm(target)
            except Exception as error:
                results.append({'control': name, 'detected': True,
                                'error_type': type(error).__name__, 'reason': str(error)})
            else:
                raise AssertionError('undetected evidence tamper:' + name)
    output.write_text(json.dumps({'controls': results, 'passed': len(results), 'failed': 0}, indent=2) + '\n')
    print(f'{len(results)} evidence-integrity controls passed')


def seal():
    files = {}
    for path in sorted(HERE.rglob('*')):
        if not path.is_file() or '__pycache__' in path.parts or path.name == 'ARTIFACT_MANIFEST.json':
            continue
        files[path.relative_to(HERE).as_posix()] = digest(path.read_bytes())
    (HERE / 'ARTIFACT_MANIFEST.json').write_text(json.dumps({'algorithm': 'SHA-256', 'files': files}, indent=2) + '\n')
    print(f'Sealed {len(files)} artifacts')


def check():
    manifest = json.loads((HERE / 'ARTIFACT_MANIFEST.json').read_text())
    for name, expected in manifest['files'].items():
        if digest((HERE / name).read_bytes()) != expected:
            raise AssertionError('artifact hash mismatch:' + name)
    print(f"Verified {len(manifest['files'])} artifact hashes")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['controls', 'seal', 'check'])
    parser.add_argument('--run', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.mode == 'controls':
        controls(args.run, args.out)
    elif args.mode == 'seal':
        seal()
    else:
        check()


if __name__ == '__main__':
    main()
