from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Bind the exact Jain 2017 PNAS supplements before CPG-001 normalization.")
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    requirements = json.loads((HERE / "JAIN_2017_SOURCE_REQUIREMENTS.json").read_text(encoding="utf-8"))
    records = []
    missing = []
    for item in requirements["required_artifacts"]:
        path = args.source_dir / item["filename"]
        if not path.is_file():
            missing.append(item["filename"])
            continue
        records.append({
            "filename": path.name,
            "role": item["role"],
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    if missing:
        raise SystemExit("missing required Jain artifacts: " + ", ".join(missing))

    record = {
        "schema": "openline.cpg001.jain_source_manifest.v0.1",
        "dataset_id": "JAIN_2017",
        "doi": requirements["doi"],
        "bound_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "artifacts": records,
        "complete": len(records) == len(requirements["required_artifacts"]),
        "authority_note": requirements["provenance_boundary"],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
