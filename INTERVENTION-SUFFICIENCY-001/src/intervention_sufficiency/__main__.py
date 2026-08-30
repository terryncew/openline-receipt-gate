from __future__ import annotations
from pathlib import Path
import argparse, json
from .preflight import run_preflight
from .synthetic import generate

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synthetic")
    s.add_argument("--out", required=True)
    p = sub.add_parser("preflight")
    p.add_argument("--dataset", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--gate", default="config/frozen_gate.json")
    p.add_argument("--out", default="artifacts")
    args = ap.parse_args()
    if args.cmd == "synthetic":
        print(json.dumps(generate(Path(args.out)), indent=2))
    else:
        r = run_preflight(Path(args.dataset), Path(args.manifest), Path(args.gate), Path(args.out))
        print(json.dumps(r, indent=2))
        if r["status"] != "PASS_INTERVENTION_SUFFICIENCY":
            raise SystemExit(3)

if __name__ == "__main__":
    main()
