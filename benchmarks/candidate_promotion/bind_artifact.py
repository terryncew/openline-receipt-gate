from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="Bind an exact historical dataset artifact before replay.")
    ap.add_argument("artifact", type=Path)
    ap.add_argument("--dataset-id", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    if not args.artifact.is_file():
        raise SystemExit(f"artifact not found: {args.artifact}")
    record = {
        "schema": "openline.dataset_binding.v0.1",
        "dataset_id": args.dataset_id,
        "filename": args.artifact.name,
        "bytes": args.artifact.stat().st_size,
        "sha256": sha256_file(args.artifact),
        "bound_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "authority_note": "Binding identifies the exact file used for replay. It does not manufacture missing historical wet-lab batch/run provenance."
    }
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
