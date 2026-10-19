"""Separate process; never imports Receiver or its effect/dispatch code."""
import argparse,json
from pathlib import Path
from olp_gate.crypto import strict_json_loads
from examples.independent_receiver_kit.verify import verify
from . import adapter

def main():
    p=argparse.ArgumentParser();p.add_argument('--state',required=True);p.add_argument('--config',required=True)
    p.add_argument('--mode',choices=sorted(adapter.MODES),required=True);a=p.parse_args()
    result=verify(a.state,strict_json_loads(Path(a.config).read_text()),a.mode,codec=adapter)
    print(json.dumps(result,sort_keys=True));return 0 if result['valid'] else 1
if __name__=='__main__':raise SystemExit(main())
