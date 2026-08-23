from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "candidate_promotion"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from run_jain_mirror_replication import COLUMN_MAP, normalize_mirror, run_replication


def make_csv(path: Path, count: int = 137, missing_column: str | None = None) -> None:
    headers = ["Name", *COLUMN_MAP.values()]
    if missing_column:
        headers.remove(missing_column)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for i in range(count):
            row = {"Name": f"mab-{i:03d}"}
            values = {
                "PSR": 0.05 + (i % 5) * 0.07,
                "AC_SINS": 1.0 + (i % 9) * 2.0,
                "CSI_BLI": -0.02 + (i % 6) * 0.01,
                "CIC": 8.0 + (i % 7) * 0.6,
                "HIC": 8.5 + (i % 7) * 0.7,
                "SMAC": 8.0 + (i % 8) * 0.8,
                "SGAC_SINS": 100.0 + (i % 8) * 130.0,
                "BVP": 1.0 + (i % 7) * 1.2,
                "ELISA": 0.8 + (i % 6) * 0.5,
                "AS": 0.01 + (i % 7) * 0.02,
            }
            for assay, col in COLUMN_MAP.items():
                if col in headers:
                    row[col] = values[assay]
            writer.writerow(row)


def test_parser_requires_137_rows(tmp_path: Path):
    path = tmp_path / "jain.csv"
    make_csv(path, 136)
    try:
        normalize_mirror(path, enforce_frozen_blob=False)
    except ValueError as exc:
        assert str(exc) == "mirror_candidate_count_mismatch:136"
    else:
        raise AssertionError("expected row-count rejection")


def test_parser_requires_all_frozen_columns(tmp_path: Path):
    path = tmp_path / "jain.csv"
    make_csv(path, missing_column=COLUMN_MAP["HIC"])
    try:
        normalize_mirror(path, enforce_frozen_blob=False)
    except ValueError as exc:
        assert "mirror_required_columns_missing" in str(exc)
        assert COLUMN_MAP["HIC"] in str(exc)
    else:
        raise AssertionError("expected column rejection")


def test_parser_maps_all_ten_thresholded_assays(tmp_path: Path):
    path = tmp_path / "jain.csv"
    make_csv(path)
    normalized = normalize_mirror(path, enforce_frozen_blob=False)
    assert normalized["candidate_count"] == 137
    assert set(normalized["candidates"][0]["assays"]) == set(COLUMN_MAP)
    assert normalized["candidates"][0]["approved_2017"] is None


def test_frozen_primary_analysis_runs_without_status_labels(tmp_path: Path):
    path = tmp_path / "jain.csv"
    make_csv(path)
    result = run_replication(path, enforce_frozen_blob=False)
    assert result["execution_status"] == "COMPLETE"
    assert result["canonical_confirmatory"] is False
    assert result["status_labels_available"] is False
    assert result["primary_verdict_uses_status_labels"] is False
    assert result["scientific_signal"] in {
        "SUPPORTED_WITHIN_SCOPE",
        "FRICTION_ONLY",
        "NO_COMPENSATION_SIGNAL",
        "INCONCLUSIVE_COVERAGE",
        "IMPLEMENTATION_MISMATCH",
    }
    assert result["analysis"]["complete_case_candidate_count"] == 137
