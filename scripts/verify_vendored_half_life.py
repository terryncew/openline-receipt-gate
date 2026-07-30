#!/usr/bin/env python3
"""Verify the offline Half-Life release fixture and optional source checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE_ROOT = REPO_ROOT / "vendor" / "openline-half-life-0.2.0rc5"
VERSION = "0.2.0rc5"
SOURCE_COMMIT = "70121b53e86196d69b2c3457174b38ad32667b43"
WHEEL_NAME = "openline_half_life-0.2.0rc5-py3-none-any.whl"
WHEEL_SHA256 = "02da94dc5f7896a733e883211d65dfd1292b1164d6317ca311294f1bc9c74d77"
SITE_TREE_SHA256 = "980e00cf6f6bd50556b1e9f754f268811cc2c468b1811f56dbcf95de2522559f"
SITE_FILE_COUNT = 40
FIXTURE_TREE_SHA256 = "4b133231ea7cb9e2734decd5ce53441a7718937b81c183f2339e48b1a158a50f"
FIXTURE_FILE_COUNT = 79
POLICY_TREE_SHA256 = "d63c35f1d17453b2c3da0da1ed32ac105b59b5f400922b801592699de843b2b3"
POLICY_FILE_COUNT = 4
LICENSE_SHA256 = "07674dfa9960dff5128d0cdcce58fee7543c26ff47e58e07ae6ac0254a0f58b1"
SOURCE_KEYS = {
    "schema",
    "project",
    "repository",
    "version",
    "source_commit",
    "wheel",
    "site",
    "fixture",
    "policy",
    "license",
    "claim_boundary",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_map(root: Path) -> dict[str, bytes]:
    if not root.is_dir():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if (
            path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    }


def tree_digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative, data in sorted(files.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def wheel_file_maps(
    wheel_path: Path,
    errors: list[str],
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    try:
        with zipfile.ZipFile(wheel_path) as archive:
            names = [item.filename for item in archive.infolist()]
            if len(names) != len(set(names)):
                errors.append("wheel_duplicate_entries")
            for name in names:
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                    errors.append(f"wheel_unsafe_path:{name}")
            metadata_name = (
                "openline_half_life-0.2.0rc5.dist-info/METADATA"
            )
            try:
                metadata = archive.read(metadata_name).decode("utf-8")
            except (KeyError, UnicodeDecodeError):
                errors.append("wheel_metadata_missing")
            else:
                if f"Version: {VERSION}\n" not in metadata:
                    errors.append("wheel_version_mismatch")
            prefix = "openline_half_life/"
            all_files = {
                name: archive.read(name)
                for name in names
                if not name.endswith("/")
            }
            package_files = {
                name[len(prefix):]: archive.read(name)
                for name in names
                if name.startswith(prefix) and not name.endswith("/")
            }
            return package_files, all_files
    except (OSError, zipfile.BadZipFile):
        errors.append("wheel_unreadable")
        return {}, {}


def compare_maps(
    label: str,
    bundled: dict[str, bytes],
    external: dict[str, bytes],
    errors: list[str],
) -> None:
    bundled_names = set(bundled)
    external_names = set(external)
    for name in sorted(bundled_names - external_names):
        errors.append(f"{label}_external_missing:{name}")
    for name in sorted(external_names - bundled_names):
        errors.append(f"{label}_bundle_missing:{name}")
    for name in sorted(bundled_names & external_names):
        if bundled[name] != external[name]:
            errors.append(f"{label}_content_mismatch:{name}")


def verify(bundle_root: Path, external_root: Path | None) -> dict[str, object]:
    bundle_root = bundle_root.resolve()
    errors: list[str] = []
    wheel_path = bundle_root / WHEEL_NAME
    site_root = bundle_root / "site"
    fixture_root = bundle_root / "examples" / "demo_output"
    policy_root = bundle_root / "policy"
    license_path = bundle_root / "LICENSE"
    source_path = bundle_root / "SOURCE.json"

    try:
        source = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        source = {}
        errors.append("source_metadata_unreadable")
    if isinstance(source, dict):
        unknown = sorted(set(source) - SOURCE_KEYS)
        missing = sorted(SOURCE_KEYS - set(source))
        errors.extend(f"source_metadata_unknown:{key}" for key in unknown)
        errors.extend(f"source_metadata_missing:{key}" for key in missing)
    else:
        source = {}
        errors.append("source_metadata_not_object")

    try:
        wheel_bytes = wheel_path.read_bytes()
    except OSError:
        wheel_bytes = b""
        errors.append("wheel_missing")
    wheel_hash = sha256_bytes(wheel_bytes)
    if wheel_hash != WHEEL_SHA256:
        errors.append("wheel_hash_mismatch")
    wheel_files, wheel_all_files = wheel_file_maps(wheel_path, errors)

    site_files = file_map(site_root)
    site_hash = tree_digest(site_files)
    if len(site_files) != SITE_FILE_COUNT:
        errors.append("site_file_count_mismatch")
    if site_hash != SITE_TREE_SHA256:
        errors.append("site_tree_hash_mismatch")
    compare_maps("wheel_site", wheel_all_files, site_files, errors)

    fixture_files = file_map(fixture_root)
    fixture_hash = tree_digest(fixture_files)
    if len(fixture_files) != FIXTURE_FILE_COUNT:
        errors.append("fixture_file_count_mismatch")
    if fixture_hash != FIXTURE_TREE_SHA256:
        errors.append("fixture_tree_hash_mismatch")

    policy_files = file_map(policy_root)
    policy_hash = tree_digest(policy_files)
    if len(policy_files) != POLICY_FILE_COUNT:
        errors.append("policy_file_count_mismatch")
    if policy_hash != POLICY_TREE_SHA256:
        errors.append("policy_tree_hash_mismatch")

    try:
        license_hash = sha256_bytes(license_path.read_bytes())
    except OSError:
        license_hash = ""
        errors.append("license_missing")
    if license_hash != LICENSE_SHA256:
        errors.append("license_hash_mismatch")

    expected_source = {
        "schema": "openline.vendored-source.v1",
        "project": "openline-half-life",
        "repository": "https://github.com/terryncew/openline-half-life",
        "version": VERSION,
        "source_commit": SOURCE_COMMIT,
        "wheel": {"path": WHEEL_NAME, "sha256": WHEEL_SHA256},
        "site": {
            "path": "site",
            "file_count": SITE_FILE_COUNT,
            "tree_sha256": SITE_TREE_SHA256,
        },
        "fixture": {
            "path": "examples/demo_output",
            "file_count": FIXTURE_FILE_COUNT,
            "tree_sha256": FIXTURE_TREE_SHA256,
        },
        "policy": {
            "path": "policy",
            "file_count": POLICY_FILE_COUNT,
            "tree_sha256": POLICY_TREE_SHA256,
        },
        "license": {"path": "LICENSE", "sha256": LICENSE_SHA256},
        "claim_boundary": (
            "The vendored bundle makes the deterministic release gate runnable "
            "offline. Its local hashes do not independently prove upstream "
            "provenance; CI compares it with the separately fetched pinned commit."
        ),
    }
    if source != expected_source:
        errors.append("source_metadata_mismatch")

    external_checked = False
    external_commit: str | None = None
    if external_root is not None:
        external_root = external_root.resolve()
        if external_root == bundle_root:
            errors.append("external_source_must_be_independent")
        else:
            completed = subprocess.run(
                ["git", "-C", str(external_root), "rev-parse", "HEAD"],
                check=False,
                capture_output=True,
                text=True,
            )
            external_commit = completed.stdout.strip() or None
            if completed.returncode != 0 or external_commit != SOURCE_COMMIT:
                errors.append("external_source_commit_mismatch")
            else:
                external_checked = True
                compare_maps(
                    "wheel_source",
                    wheel_files,
                    file_map(external_root / "src" / "openline_half_life"),
                    errors,
                )
                compare_maps(
                    "fixture",
                    fixture_files,
                    file_map(external_root / "examples" / "demo_output"),
                    errors,
                )
                compare_maps(
                    "policy",
                    policy_files,
                    file_map(external_root / "policy"),
                    errors,
                )
                try:
                    external_license = (external_root / "LICENSE").read_bytes()
                except OSError:
                    errors.append("external_license_missing")
                else:
                    if external_license != license_path.read_bytes():
                        errors.append("external_license_mismatch")

    return {
        "valid": not errors,
        "version": VERSION,
        "source_commit": SOURCE_COMMIT,
        "bundle_root": str(bundle_root),
        "wheel_sha256": wheel_hash,
        "site_tree_sha256": site_hash,
        "site_file_count": len(site_files),
        "fixture_tree_sha256": fixture_hash,
        "fixture_file_count": len(fixture_files),
        "policy_tree_sha256": policy_hash,
        "policy_file_count": len(policy_files),
        "external_source_checked": external_checked,
        "external_source_commit": external_commit,
        "errors": sorted(set(errors)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-root", type=Path, default=DEFAULT_BUNDLE_ROOT)
    parser.add_argument("--external-root", type=Path)
    args = parser.parse_args()
    external = args.external_root
    if external is None:
        value = os.environ.get("OLP_HALF_LIFE_SOURCE_ROOT")
        external = Path(value) if value else None
    result = verify(args.bundle_root, external)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
