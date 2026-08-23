from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from jain_design import load_json, sha256_json
from jain_xlsx import JainXlsxError, normalize_header, read_first_sheet_rows


def _find_header(rows: Sequence[Sequence[Any]]) -> tuple[int, int, int]:
    name_aliases = {"name", "antibody", "antibody name"}
    status_aliases = {"clinical status", "status"}
    for row_index, row in enumerate(rows[:25]):
        normalized = [normalize_header(value) for value in row]
        name_matches = [i for i, value in enumerate(normalized) if value in name_aliases]
        status_matches = [i for i, value in enumerate(normalized) if value in status_aliases]
        if len(name_matches) == 1 and len(status_matches) == 1:
            return row_index, name_matches[0], status_matches[0]
    raise JainXlsxError("sd01_required_headers_not_found:name+clinical_status")


def read_sd01_labels(path: str | Path) -> dict[str, str]:
    _sheet, rows = read_first_sheet_rows(path)
    header_row, name_col, status_col = _find_header(rows)
    labels: dict[str, str] = {}
    for row in rows[header_row + 1 :]:
        raw_name = row[name_col] if name_col < len(row) else None
        raw_status = row[status_col] if status_col < len(row) else None
        if raw_name is None or not str(raw_name).strip():
            continue
        name = str(raw_name).strip()
        if raw_status is None or not str(raw_status).strip():
            raise JainXlsxError(f"sd01_status_missing:{name}")
        if name in labels:
            raise JainXlsxError(f"sd01_duplicate_candidate:{name}")
        labels[name] = str(raw_status).strip()
    return labels


def _approved(status: str) -> bool:
    return "approved" in normalize_header(status).split()


def unseal_labels(source_dir: str | Path, preflight_dir: str | Path) -> dict[str, Any]:
    source_root = Path(source_dir)
    preflight_root = Path(preflight_dir)
    receipt = load_json(preflight_root / "JAIN_2017_ASSAY_PREFLIGHT_RECEIPT.json")
    assay_only = load_json(preflight_root / "JAIN_2017_ASSAY_ONLY.normalized.json")

    if receipt.get("schema") != "openline.cpg001.jain_assay_preflight_receipt.v0.1":
        raise ValueError("preflight_receipt_schema_invalid")
    if receipt.get("ready_for_label_unseal") is not True:
        raise ValueError("preflight_not_ready_for_label_unseal")
    actual_assay_hash = sha256_json(assay_only)
    if receipt.get("assay_only_sha256") != actual_assay_hash:
        raise ValueError("assay_only_seal_hash_mismatch")
    if assay_only.get("labels_unsealed") is not False:
        raise ValueError("assay_only_label_state_invalid")
    if receipt.get("source_set_sha256") != assay_only.get("source_set_sha256"):
        raise ValueError("preflight_source_set_mismatch")

    labels = read_sd01_labels(source_root / "pnas.1616408114.sd01.xlsx")
    candidates = assay_only.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("assay_only_candidates_invalid")
    assay_ids = {str(row.get("candidate_id", "")) for row in candidates}
    label_ids = set(labels)
    if assay_ids != label_ids:
        missing = sorted(assay_ids - label_ids)
        extra = sorted(label_ids - assay_ids)
        raise ValueError(f"sd01_sd03_candidate_set_mismatch:missing={missing[:5]}:extra={extra[:5]}")
    if len(labels) != 137:
        raise ValueError(f"sd01_candidate_count_invalid:{len(labels)}")

    normalized_candidates = []
    for row in candidates:
        cid = str(row["candidate_id"])
        status = labels[cid]
        normalized_candidates.append({
            "candidate_id": cid,
            "stage_2017": status,
            "approved_2017": _approved(status),
            "assays": row["assays"],
        })
    normalized_candidates.sort(key=lambda item: item["candidate_id"])
    return {
        "schema": "openline.cpg001.jain_normalized.v0.1",
        "source_artifacts": assay_only["source_artifacts"],
        "source_set_sha256": assay_only["source_set_sha256"],
        "design_lock_sha256": assay_only["design_lock_sha256"],
        "thresholds_sha256": assay_only["thresholds_sha256"],
        "assay_preflight_receipt_sha256": sha256_json(receipt),
        "assay_only_sha256": actual_assay_hash,
        "labels_unsealed": True,
        "label_source": "bound_sd01_publication_era_clinical_status",
        "candidate_count": len(normalized_candidates),
        "candidates": normalized_candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Unseal Jain SD01 publication-era status only after verified assay preflight.")
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--preflight-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = unseal_labels(args.source_dir, args.preflight_dir)
    except (ValueError, JainXlsxError) as exc:
        raise SystemExit(str(exc)) from exc
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "schema": result["schema"],
        "candidate_count": result["candidate_count"],
        "labels_unsealed": result["labels_unsealed"],
        "source_set_sha256": result["source_set_sha256"],
        "assay_only_sha256": result["assay_only_sha256"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
