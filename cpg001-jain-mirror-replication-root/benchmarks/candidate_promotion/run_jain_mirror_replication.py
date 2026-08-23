from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from jain_design import load_json, run_confirmatory, sha256_json

EXPECTED_ROWS = 137
EXPECTED_BYTES = 42777
EXPECTED_GIT_BLOB = "15235ba7afc16cd9564c34078fbc1670e7383d09"
MIRROR_COMMIT = "4ad3ec59ff1f6ddb886ca0cf2a9d47b1ba0f136a"
MIRROR_REPO = "HPuntu/hogroast-teaching"
MIRROR_PATH = "jain_data.csv"

COLUMN_MAP = {
    "PSR": "Poly-Specificity Reagent (PSR) SMP Score (0-1)",
    "AC_SINS": "Affinity-Capture Self-Interaction Nanoparticle Spectroscopy (AC-SINS) ∆λmax (nm) Average",
    "CSI_BLI": "CSI-BLI Delta Response (nm)",
    "CIC": "CIC Retention Time (Min)",
    "HIC": "HIC Retention Time (Min)a",
    "SMAC": "SMAC Retention Time (Min)a",
    "SGAC_SINS": "SGAC-SINS AS100 ((NH4)2SO4 mM)",
    "BVP": "BVP ELISA",
    "ELISA": "ELISA",
    "AS": "Slope for Accelerated Stability",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    prefix = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(prefix + data).hexdigest()


def _number(value: str | None) -> float | None:
    if value is None:
        return None
    text = value.strip()
    if not text or text.lower() in {"na", "n/a", "nan", "nd", "none"}:
        return None
    return float(text)


def normalize_mirror(path: Path, *, enforce_frozen_blob: bool = True) -> dict[str, Any]:
    data = path.read_bytes()
    if enforce_frozen_blob:
        if len(data) != EXPECTED_BYTES:
            raise ValueError(f"mirror_size_mismatch:{len(data)}")
        actual_blob = git_blob_sha1(path)
        if actual_blob != EXPECTED_GIT_BLOB:
            raise ValueError(f"mirror_git_blob_mismatch:{actual_blob}")

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        headers = set(reader.fieldnames or [])
        required = {"Name", *COLUMN_MAP.values()}
        missing = sorted(required - headers)
        if missing:
            raise ValueError("mirror_required_columns_missing:" + ",".join(missing))
        rows = list(reader)

    if len(rows) != EXPECTED_ROWS:
        raise ValueError(f"mirror_candidate_count_mismatch:{len(rows)}")

    seen: set[str] = set()
    candidates: list[dict[str, Any]] = []
    for raw in rows:
        candidate_id = str(raw.get("Name", "")).strip()
        if not candidate_id:
            raise ValueError("mirror_candidate_id_missing")
        if candidate_id in seen:
            raise ValueError(f"mirror_duplicate_candidate:{candidate_id}")
        seen.add(candidate_id)
        assays = {assay: _number(raw.get(column)) for assay, column in COLUMN_MAP.items()}
        candidates.append({
            "candidate_id": candidate_id,
            "stage_2017": None,
            "approved_2017": None,
            "assays": assays,
        })
    candidates.sort(key=lambda row: row["candidate_id"])
    return {
        "candidate_count": len(candidates),
        "candidates": candidates,
        "mirror_sha256": sha256_file(path),
        "mirror_git_blob_sha1": git_blob_sha1(path),
        "mirror_bytes": len(data),
    }


def run_replication(path: Path, *, enforce_frozen_blob: bool = True) -> dict[str, Any]:
    mirror = normalize_mirror(path, enforce_frozen_blob=enforce_frozen_blob)
    thresholds = load_json(HERE / "JAIN_2017_THRESHOLDS.json")
    design_lock = load_json(HERE / "JAIN_2017_DESIGN_LOCK.json")
    normalized = {
        "schema": "openline.cpg001.jain_normalized.v0.1",
        "dataset_id": "JAIN_2017",
        "source_artifacts": [{
            "filename": MIRROR_PATH,
            "source_repository": MIRROR_REPO,
            "source_commit": MIRROR_COMMIT,
            "git_blob_sha1": mirror["mirror_git_blob_sha1"],
            "sha256": mirror["mirror_sha256"],
            "bytes": mirror["mirror_bytes"],
            "authority": "THIRD_PARTY_TRANSCRIPTION_NONCONFIRMATORY",
        }],
        "design_lock_sha256": sha256_json(design_lock),
        "thresholds_sha256": sha256_json(thresholds),
        "labels_unsealed": False,
        "candidate_count": mirror["candidate_count"],
        "candidates": mirror["candidates"],
    }
    analysis = run_confirmatory(normalized, thresholds, design_lock)
    return {
        "schema": "openline.cpg001.jain_mirror_replication.v0.1",
        "experiment_id": "CPG-001",
        "execution_id": "CPG-001-JAIN-MIRROR-01",
        "execution_status": "COMPLETE",
        "evidence_tier": "NONCONFIRMATORY_PINNED_MIRROR_REPLICATION",
        "canonical_confirmatory": False,
        "canonical_runs_r1_r4": "BLOCKED_SOURCE_ACQUISITION",
        "source": normalized["source_artifacts"][0],
        "status_labels_available": False,
        "primary_verdict_uses_status_labels": False,
        "scientific_signal": analysis["primary_verdict"]["verdict"],
        "analysis": analysis,
        "interpretation_rule": (
            "This result is a replication signal only. A negative result is sufficient to stop canonical-source pursuit for CPG-001; "
            "a positive result justifies one later canonical confirmation and must not be described as canonical evidence before that confirmation."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run frozen CPG-001 primary analysis on a pinned public Jain transcription.")
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run_replication(args.csv)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "execution_id": result["execution_id"],
        "execution_status": result["execution_status"],
        "evidence_tier": result["evidence_tier"],
        "scientific_signal": result["scientific_signal"],
        "mirror_sha256": result["source"]["sha256"],
        "candidate_count": result["analysis"]["published_candidate_count"],
        "complete_case_candidate_count": result["analysis"]["complete_case_candidate_count"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
