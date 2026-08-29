from __future__ import annotations
from pathlib import Path
import json, hashlib

def project_root() -> Path:
    return Path(__file__).resolve().parents[2]

def load_protocol(root: Path | None = None) -> dict:
    root = root or project_root()
    return json.loads((root / "config" / "frozen_protocol.json").read_text())

def protocol_sha256(root: Path | None = None) -> str:
    root = root or project_root()
    b = (root / "config" / "frozen_protocol.json").read_bytes()
    return hashlib.sha256(b).hexdigest()
