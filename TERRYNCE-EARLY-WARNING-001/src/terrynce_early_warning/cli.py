from __future__ import annotations
import argparse, json
from .acquire import acquire
from .preflight import preflight
from .synthetic import smoke_receipt

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("acquire")
    sub.add_parser("preflight")
    sub.add_parser("synthetic")
    args = ap.parse_args()
    if args.cmd == "acquire":
        print(json.dumps(acquire(), indent=2))
    elif args.cmd == "preflight":
        print(json.dumps(preflight(), indent=2))
    else:
        print(json.dumps(smoke_receipt(), indent=2))

if __name__ == "__main__":
    main()
