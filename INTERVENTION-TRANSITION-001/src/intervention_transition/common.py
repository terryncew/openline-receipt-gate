from __future__ import annotations
from pathlib import Path
import hashlib, json

def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for c in iter(lambda:f.read(1024*1024), b""):
            h.update(c)
    return h.hexdigest()

def canonical_sha256(obj) -> str:
    raw=json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()

def load_protocol(root: Path|None=None) -> dict:
    root=root or Path.cwd()
    return json.loads((root/"config/protocol.frozen.json").read_text())
