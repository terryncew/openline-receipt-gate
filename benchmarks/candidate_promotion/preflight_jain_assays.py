from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from bind_jain_sources import bind_sources
from jain_design import complete_case_candidates, correlation_audit, load_json, sha256_json
from jain_xlsx import normalize_sd03_assays


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_preflight(source_dir: str | Path) -> dict[str, Any]:
    source_root = Path(source_dir)
    source_manifest = bind_sources(source_root)
    thresholds = load_json(HERE / "JAIN_2017_THRESHOLDS.json")
    design_lock = load_json(HERE / "JAIN_2017_DESIGN_LOCK.json")
    rules = load_json(HERE / "JAIN_2017_SD03_COLUMN_RULES.json")

    # Label firewall: only SD03 worksheet values are opened in this stage.
    assay_source = source_root / "pnas.1616408114.sd03.xlsx"
    parsed = normalize_sd03_assays(assay_source, rules)
    candidates = parsed["candidates"]
    complete, excluded = complete_case_candidates(candidates)
    coverage_fraction = len(complete) / 137.0
    corr = correlation_audit(complete) if len(complete) >= 2 else {
        "schema": "openline.cpg001.jain_correlation_audit.v0.1",
        "candidate_count": len(complete),
        "threshold_abs_rho": 0.70,
        "high_correlation_pairs": [],
        "statistical_independence_assumed": False,
        "policy_mutation_allowed": False,
    }

    assay_only = {
        "schema": "openline.cpg001.jain_assay_only.v0.1",
        "source_artifacts": source_manifest["artifacts"],
        "source_set_sha256": source_manifest["source_set_sha256"],
        "design_lock_sha256": sha256_json(design_lock),
        "thresholds_sha256": sha256_json(thresholds),
        "sd03_sheet_name": parsed["sheet_name"],
        "sd03_header_row_1_based": parsed["header_row_1_based"],
        "sd03_column_mapping": parsed["column_mapping"],
        "labels_unsealed": False,
        "candidates": candidates,
    }
    assay_only_sha = sha256_json(assay_only)

    observed_candidate_count_ok = parsed["candidate_count"] == 137
    receipt = {
        "schema": "openline.cpg001.jain_assay_preflight_receipt.v0.1",
        "experiment_id": "CPG-001",
        "source_set_sha256": source_manifest["source_set_sha256"],
        "assay_only_sha256": assay_only_sha,
        "design_lock_sha256": assay_only["design_lock_sha256"],
        "thresholds_sha256": assay_only["thresholds_sha256"],
        "label_seal": {
            "sd01_cells_opened": False,
            "sd02_cells_opened": False,
            "sd03_cells_opened": True,
            "approval_or_phase_labels_available_to_preflight": False,
        },
        "observed_sd03_candidate_count": parsed["candidate_count"],
        "expected_published_candidate_count": 137,
        "observed_candidate_count_ok": observed_candidate_count_ok,
        "complete_case_candidate_count": len(complete),
        "complete_case_coverage_fraction": coverage_fraction,
        "excluded_for_missing_thresholded_assay": excluded,
        "coverage_ge_0_70": coverage_fraction >= 0.70,
        "resolved_assay_columns": sorted(name for name in parsed["column_mapping"] if name != "candidate_id"),
        "high_correlation_pair_count": len(corr["high_correlation_pairs"]),
        "policy_mutation_allowed": False,
        "ready_for_label_unseal": observed_candidate_count_ok,
        "next_step": "Load publication-era status labels from the already-bound SD01 only after this receipt and assay-only artifact are sealed.",
    }
    return {
        "source_manifest": source_manifest,
        "assay_only": assay_only,
        "correlation_audit": corr,
        "preflight_receipt": receipt,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Seal CPG-001 Jain assay-only preflight before status-label unseal.")
    parser.add_argument("source_dir", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        bundle = run_preflight(args.source_dir)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    out = args.out_dir
    write_json(out / "JAIN_2017_SOURCE_MANIFEST.json", bundle["source_manifest"])
    write_json(out / "JAIN_2017_ASSAY_ONLY.normalized.json", bundle["assay_only"])
    write_json(out / "JAIN_2017_CORRELATION_AUDIT.json", bundle["correlation_audit"])
    write_json(out / "JAIN_2017_ASSAY_PREFLIGHT_RECEIPT.json", bundle["preflight_receipt"])
    print(json.dumps(bundle["preflight_receipt"], indent=2, sort_keys=True))
    return 0 if bundle["preflight_receipt"]["ready_for_label_unseal"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
