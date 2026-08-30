from __future__ import annotations
from pathlib import Path
import argparse, json
from .verify import verify_stage_a
from .features import reconstruct_features
from .calibrate import run_calibration
from .replay import run_replay


def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="cmd",required=True)
    p=sub.add_parser("verify"); p.add_argument("--stage-a",required=True)
    p=sub.add_parser("features"); p.add_argument("--stage-a",required=True); p.add_argument("--unitree-root",required=True); p.add_argument("--out",required=True)
    p=sub.add_parser("calibrate"); p.add_argument("--stage-a",required=True); p.add_argument("--features",required=True); p.add_argument("--out",required=True)
    p=sub.add_parser("replay"); p.add_argument("--stage-a",required=True); p.add_argument("--calibration",required=True); p.add_argument("--out",required=True)
    args=ap.parse_args(); root=Path.cwd()
    if args.cmd=="verify": r=verify_stage_a(Path(args.stage_a),root)
    elif args.cmd=="features": r=reconstruct_features(Path(args.unitree_root),Path(args.stage_a),Path(args.out),root)
    elif args.cmd=="calibrate": r=run_calibration(Path(args.stage_a),Path(args.features),Path(args.out),root)
    else: r=run_replay(Path(args.stage_a),Path(args.calibration),Path(args.out),root)
    print(json.dumps(r,indent=2,sort_keys=True))

if __name__=="__main__": main()
