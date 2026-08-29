from __future__ import annotations
import argparse, json
from .acquire import acquire
from .preflight import preflight
from .synthetic import smoke_receipt
from .science_lock import diagnose_science_lock
from .episode_lock import build_episode_lock
from .calibration import calibrate
from .heldout_replay import replay

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("acquire")
    sub.add_parser("preflight")
    sub.add_parser("synthetic")
    sub.add_parser("science-lock-diagnostic")
    sub.add_parser("episode-lock")
    sub.add_parser("calibrate")
    sub.add_parser("heldout-replay")
    args = ap.parse_args()
    if args.cmd == "acquire":
        print(json.dumps(acquire(), indent=2))
    elif args.cmd == "preflight":
        print(json.dumps(preflight(), indent=2))
    elif args.cmd == "science-lock-diagnostic":
        print(json.dumps(diagnose_science_lock(), indent=2))
    elif args.cmd == "episode-lock":
        print(json.dumps(build_episode_lock(), indent=2))
    elif args.cmd == "calibrate":
        print(json.dumps(calibrate(), indent=2))
    elif args.cmd == "heldout-replay":
        print(json.dumps(replay(), indent=2))
    else:
        print(json.dumps(smoke_receipt(), indent=2))

if __name__ == "__main__":
    main()
