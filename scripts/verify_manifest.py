#!/usr/bin/env python3
"""Verify every file sealed by MANIFEST.json."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    manifest_path = root / "MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "errors": [f"manifest_unreadable:{exc}"]}, indent=2))
        return 2
    errors: list[str] = []
    files = manifest.get("files")
    if not isinstance(files, list):
        errors.append("manifest_files_invalid")
        files = []
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            errors.append("manifest_entry_invalid")
            continue
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"unsafe_path:{relative}")
            continue
        path = root / relative
        if path.is_symlink():
            errors.append(f"symlink_forbidden:{relative.as_posix()}")
            continue
        if not path.is_file():
            errors.append(f"missing:{relative.as_posix()}")
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            errors.append(f"hash_mismatch:{relative.as_posix()}")
        if len(data) != entry.get("bytes"):
            errors.append(f"size_mismatch:{relative.as_posix()}")
    result = {
        "valid": not errors,
        "repo": manifest.get("repo"),
        "version": manifest.get("version"),
        "count": len(files),
        "errors": sorted(set(errors)),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
