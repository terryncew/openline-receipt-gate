#!/usr/bin/env python3
"""Run the local matrix into a NEW directory; preserve the real runner status."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    env=dict(os.environ,CONSEQUENCE_EVIDENCE=str(output/'scenarios'),PYTHONPATH=str(REPO))
    cmd=[sys.executable,'-m','unittest','discover','-s',str(HERE),'-p','test_atomic.py','-v']
    run=subprocess.run(cmd,cwd=REPO,env=env,text=True,capture_output=True)
    (output/'raw.log').write_text(run.stdout+run.stderr)
    verifiers=[]
    for path in sorted((output/'scenarios').glob('*/*/verifier.json')):
        value=json.loads(path.read_text())
        verifiers.append(dict(path=str(path.relative_to(output)),valid=value['valid'],errors=value['errors']))
    files={str(p.relative_to(output)):hashlib.sha256(p.read_bytes()).hexdigest()
           for p in output.rglob('*') if p.is_file()}
    manifest=dict(schema='openline.consequence-002.run.v1',reference='81db6acb72149df989aac1827e5f621b0873d57b',
        command=cmd,exit_status=run.returncode,python=sys.version,sqlite=__import__('sqlite3').sqlite_version,
        evidence_scope='Reconstructed scenarios: original CONSEQUENCE-001 specification unavailable.',
        verifiers=verifiers,files_sha256=files)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(run.stdout+run.stderr,end='')
    print('Evidence:',output)
    return run.returncode


if __name__=='__main__':raise SystemExit(main())
