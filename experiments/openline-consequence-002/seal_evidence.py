"""Public-fixture integrity seal; no private production identity is implied."""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from fixtures import key
from olp_gate.crypto import sign_olp_body, verify_olp_signature

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
DEST=HERE/'evidence/attestation.json'


def paths():
    for p in HERE.rglob('*'):
        if p.is_file() and p!=DEST and '__pycache__' not in p.parts and p.suffix!='.pyc':
            yield p
    for name in ('sqlite_consequence.py','consequence_baseline.py','verified_commit.py','subject_bound_commit.py','evidence.py'):
        yield REPO/'olp_gate'/name


def verify():
    value=json.loads(DEST.read_text())
    ok,reason=verify_olp_signature(value)
    assert ok,reason
    from olp_gate.crypto import public_key_hex
    assert value['signature']['public_key']==public_key_hex(key('74'))
    for name,expected in value['files_sha256'].items():
        actual=hashlib.sha256((REPO/name).read_bytes()).hexdigest()
        assert actual==expected,name
    print(f"Verified public-fixture seal and {len(value['files_sha256'])} source/evidence hashes")


if __name__=='__main__':
    if '--verify' in sys.argv:
        verify()
    else:
        body=dict(schema='openline.consequence-002.evidence-manifest.v1',
            reference='81db6acb72149df989aac1827e5f621b0873d57b',
            comparison='PARITY',mission_verdict='PARTIAL',
            warning='Public TEST-ONLY key: integrity contract, not independent certification.',
            files_sha256={str(p.relative_to(REPO)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths())})
        DEST.write_text(json.dumps(sign_olp_body(body,key('74')),indent=2)+'\n')
        verify()
