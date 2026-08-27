#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "RELEASE_MANIFEST.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    errors = []
    for rel, expected in manifest["files"].items():
        path = ROOT / rel
        if not path.is_file():
            errors.append(f"missing:{rel}")
        elif sha256(path) != expected:
            errors.append(f"hash:{rel}")
    source = json.loads((ROOT / "SOURCE_PIN.json").read_text(encoding="utf-8"))
    if source["paper"]["version"] != "v1":
        errors.append("source_pin:not_v1")
    if source["author_executable_verifier"]["substitution_allowed"] is not False:
        errors.append("source_pin:substitution_must_be_false")
    result = json.loads((ROOT / "cold_external_result.json").read_text(encoding="utf-8"))
    if result["openline_reconstructed_ect_verifier"] is not False:
        errors.append("result:local_verifier_forbidden")
    if errors:
        print("ECT001_RELEASE_FAIL " + " ".join(errors))
        return 1
    print("ECT001_RELEASE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
