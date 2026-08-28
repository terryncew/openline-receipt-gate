#!/usr/bin/env python3
"""Verify the SARA-SPEC-001 release closure."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys


EXP = Path(__file__).resolve().parents[1]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    manifest = json.loads((EXP / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    errors: list[str] = []
    for relative, expected in manifest.get("files", {}).items():
        path = EXP / relative
        if not path.is_file():
            errors.append(f"missing:{relative}")
        elif sha(path) != expected:
            errors.append(f"hash:{relative}")

    if manifest.get("base_commit") != "8538c88b907cf6bafbfc28ffe705c20fbe76ecba":
        errors.append("base_commit")
    if manifest.get("evidence_tier") != "PAPER_SPEC_RECONSTRUCTION":
        errors.append("evidence_tier")
    if manifest.get("verdict") != "SARA_EXTENSION_PARITY":
        errors.append("verdict")
    if manifest.get("production_code_changed") is not False:
        errors.append("production_code_changed")

    completed = subprocess.run(
        [sys.executable, str(EXP / "scripts" / "verify_result.py")],
        cwd=EXP,
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        verified = json.loads(completed.stdout)
    except json.JSONDecodeError:
        verified = {"valid": False}
    if completed.returncode != 0 or verified.get("valid") is not True:
        errors.append("independent_result_verifier")

    if errors:
        print("SARA_SPEC_001_RELEASE_FAILED:" + ",".join(errors))
        return 1
    print("SARA_SPEC_001_RELEASE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
