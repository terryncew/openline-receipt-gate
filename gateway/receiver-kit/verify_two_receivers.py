#!/usr/bin/env python3
"""Offline receipt verifier. Trust keys file must come from an independent pin.

A fixture-generated key list is useful for this *test*, but production users
must establish receiver public keys through their own authenticated channel.
Neither a signed decision nor a local trace proves a remote effect occurred.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from openline_wallet.crypto import verify_record


def verify(evidence: Path, keys_path: Path) -> dict:
    pins=json.loads(keys_path.read_text())
    rows=json.loads((evidence/"decision_receipts.json").read_text())
    if not rows or pins["alpha"]==pins["beta"]:
        raise ValueError("MISSING_OR_DUPLICATE_TRUST_ROOT")
    expected_ids={"alpha":"receiver-alpha","beta":"receiver-beta"}
    allow=Counter()
    refused=Counter()
    for n,row in enumerate(rows):
        org=row.get("receiver")
        if org not in expected_ids:
            raise ValueError(f"UNRECOGNIZED_RECEIVER at {n}")
        receipt=row["receipt"]
        valid,reason=verify_record(receipt,expected_public_key=pins[org])
        if not valid or receipt.get("gate_id")!=expected_ids[org] or receipt.get("gate_public_key")!=pins[org]:
            raise ValueError(f"INVALID_RECEIVER_RECEIPT at {n}: {reason}")
        decision=receipt.get("decision")
        if decision=="ALLOWED":
            allow[org]+=1
        elif decision=="STOPPED":
            refused[org]+=1
        else:
            raise ValueError(f"UNKNOWN_DECISION at {n}")
    if dict(allow)!={"alpha":2,"beta":1}:
        raise ValueError("UNEXPECTED_ALLOWED_DECISIONS")
    if refused["alpha"]==0 or refused["beta"]==0:
        raise ValueError("MISSING_DENIAL_RECEIPTS")
    return {"verdict":"VERIFIED_RECEIVER_DECISIONS_ONLY",
            "receipts":len(rows),"allowed":dict(allow),"denied":dict(refused),
            "effect_validation":"NOT_PROVEN_BY_SIGNED_DECISION"}


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("evidence",type=Path)
    parser.add_argument("--trusted-keys",required=True,type=Path)
    a=parser.parse_args()
    try:
        result=verify(a.evidence,a.trusted_keys)
        print(json.dumps(result,sort_keys=True))
    except Exception as exc:
        print("REFUSED_TO_VERIFY "+str(exc),file=sys.stderr)
        raise SystemExit(1)
