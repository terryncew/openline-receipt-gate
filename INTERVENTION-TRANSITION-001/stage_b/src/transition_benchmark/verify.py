from __future__ import annotations
from pathlib import Path
import json
from .common import load_lock, sha256_file


def verify_stage_a(stage_a_dir: Path, project_root: Path) -> dict:
    lock = load_lock(project_root)
    files = {
        "dataset": stage_a_dir / "intervention_sufficiency_input.csv",
        "contexts": stage_a_dir / "context_receipts.json",
        "manifest": stage_a_dir / "intervention_sufficiency_manifest.json",
        "summary": stage_a_dir / "stage_a_summary.json",
    }
    for path in files.values():
        if not path.is_file():
            raise FileNotFoundError(path)
    actual = {
        "dataset": sha256_file(files["dataset"]),
        "contexts": sha256_file(files["contexts"]),
        "manifest": sha256_file(files["manifest"]),
    }
    expected = {
        "dataset": lock["stage_a_dataset_sha256"],
        "contexts": lock["stage_a_context_receipts_sha256"],
        "manifest": lock["stage_a_manifest_sha256"],
    }
    if actual != expected:
        raise RuntimeError(f"Stage A receipt mismatch: {actual} != {expected}")
    summary = json.loads(files["summary"].read_text())
    if not summary.get("stage_b_authorized"):
        raise RuntimeError("Stage A did not authorize Stage B")
    if summary["intervention_sufficiency"]["status"] != "PASS_INTERVENTION_SUFFICIENCY":
        raise RuntimeError("Intervention Sufficiency status is not PASS")
    return {"status": "PASS_STAGE_A_PIN", "actual": actual}
