from __future__ import annotations
from pathlib import Path
import hashlib, json, time, urllib.request
from .protocol import project_root

def _md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def _download(url: str, dest: Path, attempts: int = 5) -> None:
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TERRYNCE-EARLY-WARNING-001/0.1"})
            with urllib.request.urlopen(req, timeout=120) as r, dest.open("wb") as f:
                while True:
                    chunk = r.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
            return
        except Exception as e:
            last = e
            if dest.exists():
                dest.unlink()
            time.sleep(min(20, 2 ** i))
    raise RuntimeError(f"download failed after {attempts} attempts: {url}: {last}")

def acquire(root: Path | None = None) -> dict:
    root = root or project_root()
    lock = json.loads((root / "config" / "sources.lock.json").read_text())
    raw = root / "data" / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    rows = []
    for item in lock["dataset"]["files"]:
        dest = raw / item["name"]
        if not dest.exists() or _md5(dest) != item["md5"]:
            _download(item["url"], dest)
        got = _md5(dest)
        ok = got == item["md5"]
        rows.append({
            "name": item["name"],
            "bytes": dest.stat().st_size,
            "expected_md5": item["md5"],
            "actual_md5": got,
            "verified": ok,
        })
        if not ok:
            raise ValueError(f"hash mismatch: {item['name']}")
    receipt = {"status": "PASS", "files": rows}
    out = root / "artifacts" / "acquisition_receipt.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt
