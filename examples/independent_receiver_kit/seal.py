"""Public-fixture evidence integrity seal; never independent certification."""
import hashlib
import json
from pathlib import Path
import sys
from .fixtures import OUTCOME
from olp_gate.crypto import sign_olp_body,verify_olp_signature,public_key_hex

HERE=Path(__file__).resolve().parent
DEST=HERE/'evidence/seal.json'


def files():
    return [p for p in HERE.rglob('*') if p.is_file() and p!=DEST and '__pycache__' not in p.parts and p.suffix!='.pyc']


def check():
    value=json.loads(DEST.read_text())
    valid,reason=verify_olp_signature(value)
    assert valid,reason
    assert value['signature']['public_key']==public_key_hex(OUTCOME)
    for name,expected in value['files'].items():
        assert hashlib.sha256((HERE/name).read_bytes()).hexdigest()==expected,name
    print('Verified public-fixture seal and',len(value['files']),'source/evidence hashes')


if __name__=='__main__':
    if '--verify' not in sys.argv:
        body=dict(schema='receiver-kit-integrity/v1',verdict='PARITY',
            tested_commit='09b821da175f8dd3dbe2b0bcaf051b1fa0b840d3',
            trust='Public TEST-ONLY key, no independent certification or organizational adoption',
            files={str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files())})
        DEST.write_text(json.dumps(sign_olp_body(body,OUTCOME),indent=2)+'\n')
    check()
