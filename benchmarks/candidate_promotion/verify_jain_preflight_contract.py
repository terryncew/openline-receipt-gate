from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main() -> int:
    contract = json.loads((HERE / "JAIN_2017_PREFLIGHT_CONTRACT.json").read_text(encoding="utf-8"))
    rules = json.loads((HERE / "JAIN_2017_SD03_COLUMN_RULES.json").read_text(encoding="utf-8"))
    required = json.loads((HERE / "JAIN_2017_SOURCE_REQUIREMENTS.json").read_text(encoding="utf-8"))
    errors = []
    expected = [item["filename"] for item in required["required_artifacts"]]
    if contract["required_source_files"] != expected:
        errors.append("source_file_set_mismatch")
    if contract["label_seal"]["sd01"].lower().find("must not") < 0:
        errors.append("sd01_label_seal_missing")
    if set(rules["assays"]) != {"PSR", "AC_SINS", "CSI_BLI", "CIC", "HIC", "SMAC", "SGAC_SINS", "BVP", "ELISA", "AS"}:
        errors.append("assay_column_set_mismatch")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8") if (ROOT / ".gitignore").exists() else ""
    if "benchmarks/candidate_promotion/jain_sources/" not in gitignore:
        errors.append("raw_source_dir_not_gitignored")
    result = {
        "schema": "openline.cpg001.jain_preflight_contract_verification.v0.1",
        "valid": not errors,
        "errors": errors,
        "raw_source_files_vendored": False,
        "sd01_cells_allowed_before_preflight_seal": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
