"""Explicit trusted configuration selects the adapter; no HTTP codec selection."""
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from olp_gate.crypto import strict_json_loads
from examples.independent_receiver_kit.receiver import Receiver,serve
from . import adapter

def main():
    p=argparse.ArgumentParser();p.add_argument('--state',required=True);p.add_argument('--config',required=True)
    p.add_argument('--key',required=True);p.add_argument('--mode',choices=sorted(adapter.MODES),required=True)
    p.add_argument('--fixture-clock',type=int)
    a=p.parse_args();clock=(lambda:a.fixture_clock) if a.fixture_clock is not None else None
    serve(Receiver(a.state,strict_json_loads(Path(a.config).read_text()),
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(a.key).read_text().strip())),a.mode,clock,codec=adapter),0)
if __name__=='__main__':main()
