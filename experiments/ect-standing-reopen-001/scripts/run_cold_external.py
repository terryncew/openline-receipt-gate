#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DISCOVERY = ROOT / "evidence" / "public_artifact_discovery.json"
RESULT = ROOT / "cold_external_result.json"


def main() -> int:
    discovery = json.loads(DISCOVERY.read_text(encoding="utf-8"))
    if discovery["executable_author_verifier_status"] != "LOCATED_AND_PINNED":
        result = {
            "schema": "openline.ect001.external-result.v1",
            "experiment_id": "ECT-001",
            "disposition": "AUTHOR_VERIFIER_UNAVAILABLE",
            "t0": {
                "status": "UNASSESSED",
                "authority": "AUTHOR_VERIFIER_ONLY"
            },
            "t1": {
                "status": "UNASSESSED",
                "executed": False,
                "authority": "OPENLINE_T1_STANDING_ONLY"
            },
            "openline_reconstructed_ect_verifier": False,
            "claim_status": "NO_ECT_STANDING_RESULT",
            "reason": "Cold external boundary requires an authentic executable author verifier before any t0 certificate may be admitted."
        }
        RESULT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(result, sort_keys=True))
        return 0
    raise SystemExit("Author verifier marked available but no pinned invocation is configured; refuse implicit substitution.")


if __name__ == "__main__":
    raise SystemExit(main())
