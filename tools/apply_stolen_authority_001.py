#!/usr/bin/env python3
"""STOLEN-AUTHORITY-001 source-closure guard.

The first builder attempted to patch frozen core primitives in-place.  That was
rejected by existing source-closure proofs.  The aligned remedy is additive:
``olp_gate/subject_bound_commit.py`` composes receiver-authenticated subject
identity outside Verified Commit.  This script never mutates production code.
"""

from __future__ import annotations

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "3ae2918d59125e13cf8f58147e482ebb940b6da6"
PROTECTED = (
    "olp_gate/verified_commit.py",
    "olp_gate/authority_compiler.py",
    "olp_gate/tool_adapter.py",
)


def main() -> int:
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", BASE_SHA, "HEAD"],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        ["git", "diff", "--exit-code", BASE_SHA, "--", *PROTECTED],
        cwd=ROOT,
        check=True,
    )
    required = (
        ROOT / "olp_gate/subject_bound_commit.py",
        ROOT / "tests/test_stolen_authority_001.py",
        ROOT / "STOLEN_AUTHORITY_001_CONTRACT.json",
    )
    missing = [path.relative_to(ROOT).as_posix() for path in required if not path.is_file()]
    if missing:
        raise SystemExit("missing additive closure files: " + ",".join(missing))
    print("STOLEN-AUTHORITY-001 additive source closure: PASS")
    print("frozen core files changed: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
