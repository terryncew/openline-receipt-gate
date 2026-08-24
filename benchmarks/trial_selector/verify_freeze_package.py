from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULT_DIR = HERE / "results/jain_discovery_001"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    receipt_path = RESULT_DIR / "JAIN_SELECTOR_FREEZE_RECEIPT.json"
    result_path = RESULT_DIR / "JAIN_SELECTOR_DISCOVERY_RESULT.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    result = json.loads(result_path.read_text(encoding="utf-8"))
    checks = {
        "freeze_sha256": HERE / "JAIN_SELECTOR_FREEZE.json",
        "selector_code_sha256": HERE / "jain_selector.py",
        "runner_sha256": HERE / "run_jain_selector.py",
        "independent_verifier_sha256": HERE / "verify_jain_selector_result.py",
        "discovery_result_sha256": result_path,
    }
    for field, path in checks.items():
        actual = sha256_file(path)
        if actual != receipt[field]:
            raise SystemExit(f"package_hash_mismatch:{field}:{actual}")
    if canonical_json_sha256(result["metrics"]) != receipt["metrics_sha256"]:
        raise SystemExit("metrics_hash_mismatch")
    if result["status"] != "EXPLORATORY_DISCOVERY_ONLY":
        raise SystemExit("discovery_status_changed")
    print("JAIN_SELECTOR_FREEZE_PACKAGE_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
