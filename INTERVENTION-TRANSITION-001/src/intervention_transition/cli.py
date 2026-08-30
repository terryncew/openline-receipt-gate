from __future__ import annotations
from pathlib import Path
import argparse, json
from .inventory import inventory
from .snapshot import run_snapshot_fidelity
from .oracle import run_oracle

def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd",required=True)
    for name in ("inventory","snapshot-fidelity","oracle"):
        p=sub.add_parser(name)
        p.add_argument("--unitree-root",required=True)
        p.add_argument("--out",default="artifacts")
    args=ap.parse_args()
    unitree=Path(args.unitree_root)
    out=Path(args.out)
    if args.cmd=="inventory":
        r=inventory(unitree,out)
    elif args.cmd=="snapshot-fidelity":
        r=run_snapshot_fidelity(unitree,out)
    else:
        r=run_oracle(unitree,out)
    print(json.dumps(r,indent=2))

if __name__=="__main__":
    main()
