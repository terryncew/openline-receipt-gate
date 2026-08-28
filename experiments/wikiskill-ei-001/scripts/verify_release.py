#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json
from pathlib import Path
EXP=Path(__file__).resolve().parents[1]
def fh(p): return hashlib.sha256((EXP/p).read_bytes()).hexdigest()
def load(p): return json.loads((EXP/p).read_text())
def fail(s): raise SystemExit("WIKISKILL_EI_001_RELEASE_FAIL: "+s)
lock=load("DESIGN_LOCK.json")
for rel,want in lock["files"].items():
    if fh(rel)!=want: fail("design lock mismatch: "+rel)
manifest=load("RELEASE_MANIFEST.json")
for rel,want in manifest["files"].items():
    if fh(rel)!=want: fail("release hash mismatch: "+rel)
if load("result.json").get("verdict")!="WIKISKILL_POST_HOC_PROVENANCE_GAP": fail("result verdict")
print(f"WIKISKILL_EI_001_RELEASE_OK: {len(manifest['files'])} hashed experiment files")
