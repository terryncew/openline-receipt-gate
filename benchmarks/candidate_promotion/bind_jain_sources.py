from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from jain_design import sha256_json
from jain_xlsx import validate_xlsx_container


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bind_sources(source_dir: str | Path) -> dict[str, Any]:
    source_root = Path(source_dir)
    requirements = json.loads((HERE / "JAIN_2017_SOURCE_REQUIREMENTS.json").read_text(encoding="utf-8"))
    records = []
    missing = []
    for item in requirements["required_artifacts"]:
        path = source_root / item["filename"]
        if not path.is_file():
            missing.append(item["filename"])
            continue
        container = validate_xlsx_container(path)
        records.append({
            "filename": path.name,
            "role": item["role"],
            "label_access_stage": item["label_access_stage"],
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "xlsx_container_valid": container["valid"],
            "worksheet_part_count": container["worksheet_part_count"],
        })
    if missing:
        raise ValueError("missing required Jain artifacts: " + ", ".join(missing))

    stable = {
        "dataset_id": "JAIN_2017",
        "doi": requirements["doi"],
        "artifacts": records,
    }
    return {
        "schema": "openline.cpg001.jain_source_manifest.v0.2",
        **stable,
        "complete": len(records) == len(requirements["required_artifacts"]),
        "source_set_sha256": sha256_json(stable),
        "label_seal": {
            "sd01_cells_opened": False,
            "sd02_cells_opened": False,
            "sd03_cells_opened": False,
            "note": "Source binding hashes bytes and validates XLSX containers only; it does not inspect worksheet cell values.",
        },
        "authority_note": requirements["provenance_boundary"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bind exact Jain 2017 PNAS supplements without opening worksheet labels.")
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        record = bind_sources(args.source_dir)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
