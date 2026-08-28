#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

EXP = Path(__file__).resolve().parents[1]
ROOT = EXP.parents[1]
BASE = "0d5666a1b0097ef2bac316a99cc1834ba73460bf"
PRODUCTION_PRIMITIVE = "olp_gate/authority_link.py"
PRODUCTION_PRIMITIVE_SHA256 = "61a03c9e9eae86006a1dbf7b8150cefe6cc55b7866937d93be82ca4687489a42"


def load(path: str) -> dict:
    return json.loads((EXP / path).read_text(encoding="utf-8"))


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(reason: str) -> None:
    raise SystemExit("AGENT_MESH_IDENTITY_001_RELEASE_FAIL: " + reason)


def main() -> int:
    lock = load("DESIGN_LOCK.json")
    for rel, expected in lock["files"].items():
        if file_hash(EXP / rel) != expected:
            fail("design_lock_mismatch:" + rel)

    manifest = load("RELEASE_MANIFEST.json")
    for rel, expected in manifest["files"].items():
        if file_hash(EXP / rel) != expected:
            fail("release_hash_mismatch:" + rel)

    result = load("result.json")
    if result.get("verdict") != "CURRENT_EFFECT_BINDING_COVERS_ALL_FIVE_CASES":
        fail("result_verdict")
    if result.get("summaries", {}).get("current_receipt_gate_effect_binding", {}).get("oracle_matches") != 5:
        fail("production_coverage")
    if result.get("summaries", {}).get("paper_failed_identity", {}).get("oracle_matches") != 0:
        fail("reproduction_control")

    production_path = ROOT / PRODUCTION_PRIMITIVE
    if file_hash(production_path) != PRODUCTION_PRIMITIVE_SHA256:
        fail("production_primitive_changed")

    try:
        changed = subprocess.run(
            ["git", "diff", "--name-only", BASE + "..HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        changed = []
    allowed = {
        ".github/workflows/agent-mesh-identity-001.yml",
        "AGENT_MESH_IDENTITY_001_HANDOFF.json",
    }
    forbidden = [
        path for path in changed
        if path not in allowed and not path.startswith("experiments/agent-mesh-identity-001/")
    ]
    if forbidden:
        fail("change_scope:" + ",".join(forbidden))

    print(
        "AGENT_MESH_IDENTITY_001_RELEASE_OK: "
        f"{len(manifest['files'])} hashed experiment files; production primitive unchanged"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
