#!/usr/bin/env python3
"""Historical source-closure governance for frozen experiments.

Separates two concepts the old test suite conflated:

1. HISTORICAL SOURCE CLOSURE -- can the exact bytes named by a frozen
   FREEZE manifest still be reconstructed and verified against the
   original hashes?  This is what makes a frozen experiment verifiable.

2. CURRENT SOURCE DRIFT -- has production source changed since that
   experiment froze?  Drift is expected when software evolves.  Drift is
   reported, and drift alone is NOT a failure of the historical
   experiment.

Mechanism
---------
For each affected manifest:

* take the recorded freeze commit locator from AFFECTED_MANIFESTS
  (recovered once from history; recorded explicitly so shallow CI
  checkouts need no history search);
* ensure the commit is present with an exact ``git fetch --depth 1
  origin <sha>`` if it is missing locally -- no full-history fetch;
* verify every pinned path's bytes AT THAT COMMIT against the existing
  FREEZE.json hashes; any mismatch is unrecoverable, never re-frozen;
* materialize that commit with ``git archive`` into a snapshot directory,
  preserving original relative paths;
* re-verify every extracted pinned path's sha256 against the manifest;
* run the original historical verifier / frozen test module against the
  snapshot root instead of current HEAD.

Frozen manifests, hashes, verifiers, results, and claims are never
modified.  The manifest remains authoritative; the recorded commit is only
a retrieval locator; the snapshot is a verified materialization of what
the manifest names.

Usage
-----
    python scripts/freeze_governance.py verify-all
        Reconstruct every affected snapshot, run every historical
        verifier, print the drift report.  Exit 0 unless a historical
        verification fails (exit 1) or frozen bytes are unrecoverable
        (exit 2).  Drift alone never fails.

    python scripts/freeze_governance.py verify <manifest>
        Same, for a single manifest (used by per-suite CI steps).

    python scripts/freeze_governance.py locate <manifest>
        Diagnostic only: compare the recorded freeze commit against a
        local history search.  Requires full history; never used by
        verification (shallow CI checkouts cannot run it).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

# Manifests whose FREEZE.json pins mutable production paths (olp_gate/*).
# Every other manifest in the repo pins only benchmark-local files and is
# unaffected by production evolution.
#
# "freeze_commit" is the exact historical commit whose tree matches every
# pinned hash.  It was recovered once from repository history and recorded
# here as an explicit retrieval locator, because CI uses shallow checkouts
# in which a history search cannot discover drifted freeze commits.  The
# locator is NOT trusted on its own: every retrieval first ensures the
# commit is present (exact fetch), then verifies EVERY pinned path's bytes
# at that commit against the EXISTING FREEZE.json hashes before any
# snapshot is materialized.  If any path hash differs from the manifest,
# the closure is unrecoverable -- the manifest remains authoritative.
AFFECTED_MANIFESTS: dict[str, dict[str, object]] = {
    "benchmarks/x402_airlock/FREEZE.json": {
        "suite": "x402_airlock",
        "freeze_commit": "870c51035f95a085e581e28661dd11b55b48c6aa",
        "frozen_tests": ["test_x402_freeze"],
    },
    "benchmarks/temporal_authority_001/FREEZE.json": {
        "suite": "temporal_authority_001",
        "freeze_commit": "efc63ead44f7da1eb3165ef1288b2f387674d70a",
        "frozen_tests": ["test_temporal_authority_001"],
    },
    "benchmarks/peer_authority_001/FREEZE.json": {
        "suite": "peer_authority_001",
        "freeze_commit": "77f88b4f965ace21ce12b1534464d1de58dc26d6",
        "frozen_tests": ["test_peer_authority_001"],
    },
    "benchmarks/role_confusion_consequence/FREEZE.json": {
        "suite": "role_confusion_consequence",
        "freeze_commit": "8840417f58264d047060544947e9ace33a3bda9f",
        "frozen_tests": ["test_role_confusion_freeze"],
    },
    "benchmarks/verified_continuation/FREEZE.json": {
        "suite": "verified_continuation",
        "freeze_commit": "97cfc43027f09c17ad81f38227d0b30d0856d8e9",
        "frozen_tests": ["test_verified_continuation"],
        # This suite's historical gate is the standalone script verifier,
        # which derives its root from its own __file__ location, so it is
        # loaded from the snapshot rather than given a root argument.
        "script_verifier": "scripts/verify_verified_continuation.py",
    },
}

# Byte-frozen historical test modules whose source-closure assertions
# ("current HEAD must equal historical source") are obsolete at HEAD.
# They are excluded from current-development discovery (see
# tests/__init__.py and conftest.py); their historical verification runs
# through verify_historical() against reconstructed snapshot roots.
# NOTE: test_verified_continuation.py is pinned as evidence but contains
# no closure assertion against HEAD, so it stays in discovery.
FROZEN_TEST_MODULES: tuple[str, ...] = (
    "test_x402_freeze",
    "test_temporal_authority_001",
    "test_peer_authority_001",
    "test_role_confusion_freeze",
)

_MAX_HISTORY_CANDIDATES = 500


class SourceBytesUnrecoverable(Exception):
    """Raised when the exact frozen bytes cannot be recovered from history."""


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=False
    )


def _ensure_commit_present(repo: Path, commit: str) -> None:
    if _git(repo, "cat-file", "-e", f"{commit}^{{commit}}").returncode == 0:
        return
    # Shallow CI checkouts may not contain the freeze commit; fetch exactly
    # that commit, nothing more.  No full-history fetch is ever required.
    fetched = _git(repo, "fetch", "--quiet", "--depth", "1", "origin", commit)
    if fetched.returncode != 0 or _git(
        repo, "cat-file", "-e", f"{commit}^{{commit}}"
    ).returncode != 0:
        raise SourceBytesUnrecoverable(
            f"freeze commit {commit} not present locally and could not be "
            f"fetched from origin"
        )


def _blob_sha256(repo: Path, commit: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return hashlib.sha256(proc.stdout).hexdigest()


def recorded_freeze_commit(manifest: str) -> str:
    """Return the recorded retrieval locator for a manifest's freeze commit.

    This is a locator, not an authority: callers must verify every pinned
    path at this commit against the manifest hashes before trusting it.
    """
    return str(AFFECTED_MANIFESTS[manifest]["freeze_commit"])


def verify_commit_hashes(
    manifest: str, commit: str, repo: Path = REPO_ROOT
) -> list[str]:
    """Return pinned paths whose bytes at <commit> differ from frozen hashes.

    The manifest remains authoritative; the commit is only a retrieval
    locator.  Any mismatch means the locator is wrong (or history was
    rewritten) and the closure is unrecoverable -- never "re-frozen".
    """
    frozen = json.loads((repo / manifest).read_text(encoding="utf-8"))["files"]
    mismatches: list[str] = []
    for relative, expected in sorted(frozen.items()):
        digest = _blob_sha256(repo, commit, relative)
        if digest is None:
            mismatches.append(f"{relative}:missing_at_{commit[:12]}")
        elif digest != expected:
            mismatches.append(f"{relative}:hash_mismatch_at_{commit[:12]}")
    return mismatches


def find_freeze_commit(
    manifest: str, repo: Path = REPO_ROOT
) -> str:
    """DIAGNOSTIC ONLY: search local history for the freeze commit.

    Returns the newest commit whose tree matches every pinned hash.
    Requires enough local history to contain the freeze commit, so it is
    NOT used by normal verification (shallow CI checkouts cannot run it).
    Use the recorded ``freeze_commit`` locator plus hash verification
    instead.  Exposed for diagnostics via ``freeze_governance.py locate``.
    """
    manifest_path = repo / manifest
    frozen = json.loads(manifest_path.read_text(encoding="utf-8"))["files"]
    log = _git(repo, "log", "--format=%H", "--", manifest)
    if log.returncode != 0:
        raise SourceBytesUnrecoverable(f"cannot read history of {manifest}")
    candidates = log.stdout.split()[:_MAX_HISTORY_CANDIDATES]
    for commit in candidates:
        if all(
            _blob_sha256(repo, commit, path) == expected
            for path, expected in frozen.items()
        ):
            return commit
    raise SourceBytesUnrecoverable(
        f"no commit in history of {manifest} reproduces all frozen hashes"
    )


def historical_freeze_root(
    manifest: str,
    snapshot_directory: str | Path,
    repo: Path = REPO_ROOT,
) -> Path:
    """Materialize the frozen source closure into snapshot_directory.

    Retrieval order is deterministic and history-search-free:
      1. take the recorded freeze commit locator from AFFECTED_MANIFESTS;
      2. ensure the commit is present (exact --depth 1 fetch if needed);
      3. verify EVERY pinned path's bytes AT THAT COMMIT against the
         manifest hashes -- any mismatch is unrecoverable, never re-frozen;
      4. only then archive the commit preserving original relative paths;
      5. re-verify the extracted snapshot bytes against the manifest.
    Returns the snapshot root.  Raises SourceBytesUnrecoverable if the
    exact bytes cannot be recovered or fail verification.
    """
    snapshot = Path(snapshot_directory)
    snapshot.mkdir(parents=True, exist_ok=True)
    commit = recorded_freeze_commit(manifest)
    _ensure_commit_present(repo, commit)
    mismatches = verify_commit_hashes(manifest, commit, repo)
    if mismatches:
        raise SourceBytesUnrecoverable(
            f"recorded freeze commit {commit} does not reproduce frozen "
            f"hashes: {mismatches}"
        )
    raw = subprocess.run(
        ["git", "archive", commit], cwd=repo, capture_output=True, check=False
    )
    if raw.returncode != 0:
        raise SourceBytesUnrecoverable(
            f"git archive failed for freeze commit {commit}"
        )
    extract = subprocess.run(
        ["tar", "-x", "-C", str(snapshot)],
        input=raw.stdout,
        capture_output=True,
        check=False,
    )
    if extract.returncode != 0:
        raise SourceBytesUnrecoverable(
            f"could not extract freeze commit {commit} into {snapshot}"
        )
    mismatches = verify_snapshot_hashes(manifest, snapshot)
    if mismatches:
        raise SourceBytesUnrecoverable(
            f"snapshot hash mismatch after reconstruction: {mismatches}"
        )
    return snapshot


def verify_snapshot_hashes(
    manifest: str, snapshot_root: str | Path, repo: Path = REPO_ROOT
) -> list[str]:
    """Return pinned paths whose snapshot bytes differ from frozen hashes."""
    frozen = json.loads((repo / manifest).read_text(encoding="utf-8"))["files"]
    root = Path(snapshot_root)
    mismatches: list[str] = []
    for relative, expected in sorted(frozen.items()):
        path = root / relative
        if not path.is_file():
            mismatches.append(f"{relative}:missing")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            mismatches.append(f"{relative}:hash_mismatch")
    return mismatches


def current_drift(manifest: str, repo: Path = REPO_ROOT) -> list[str]:
    """Return pinned paths whose working-tree bytes differ from frozen.

    Drift is information, not failure: production is allowed to evolve.
    """
    frozen = json.loads((repo / manifest).read_text(encoding="utf-8"))["files"]
    drifted: list[str] = []
    for relative, expected in sorted(frozen.items()):
        path = repo / relative
        if not path.is_file():
            drifted.append(f"{relative}:missing_from_working_tree")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            drifted.append(relative)
    return drifted


def _run_frozen_tests(snapshot: Path, modules: list[str]) -> dict[str, object]:
    """Run frozen test modules inside the snapshot via a clean subprocess.

    cwd is <snapshot>/tests and PYTHONPATH starts with <snapshot>, so the
    modules' ROOT resolves to the snapshot and every import resolves to
    frozen bytes.  Returns {"ok": bool, "output": str}.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(snapshot) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable, "-m", "unittest", "-v", *modules]
    proc = subprocess.run(
        cmd,
        cwd=snapshot / "tests",
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = proc.stdout + proc.stderr
    return {"ok": proc.returncode == 0, "output": output}


def _load_module_from(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_historical(
    manifest: str,
    snapshot_directory: str | Path,
    repo: Path = REPO_ROOT,
) -> dict[str, object]:
    """Reconstruct the snapshot and run the original historical verifier.

    The frozen test modules execute against the snapshot root with frozen
    imports; suites whose gate is a standalone script verifier get it
    loaded from the snapshot so its __file__-derived root is the snapshot.
    """
    snapshot = historical_freeze_root(manifest, snapshot_directory, repo)
    config = AFFECTED_MANIFESTS[manifest]
    result = _run_frozen_tests(snapshot, list(config["frozen_tests"]))
    details: dict[str, object] = {
        "manifest": manifest,
        "suite": config["suite"],
        "frozen_tests_ok": result["ok"],
    }
    script_verifier = config.get("script_verifier")
    if script_verifier:
        module = _load_module_from(
            snapshot / str(script_verifier),
            f"frozen_verifier_{config['suite']}",
        )
        verdict = module.verify()
        details["script_verifier_ok"] = bool(verdict.get("valid"))
        details["script_verifier_errors"] = verdict.get("errors", [])
    else:
        details["script_verifier_ok"] = None
    ok_tests = bool(details["frozen_tests_ok"])
    ok_script = details["script_verifier_ok"]
    details["ok"] = ok_tests and (ok_script is not False)
    if not details["ok"]:
        details["frozen_test_output_tail"] = str(result["output"])[-4000:]
    return details


def verify_all(
    repo: Path = REPO_ROOT, snapshot_base: str | Path | None = None
) -> dict[str, object]:
    """Verify every affected historical closure; report drift separately."""
    report: dict[str, object] = {"suites": {}, "ok": True}
    for manifest in sorted(AFFECTED_MANIFESTS):
        if snapshot_base is None:
            tmp = tempfile.TemporaryDirectory(prefix="freeze-governance-")
            snapshot_dir: Path = Path(tmp.name)
            cleanup = tmp.cleanup
        else:
            snapshot_dir = Path(snapshot_base) / Path(manifest).parent.name
            cleanup = None
        try:
            try:
                details = verify_historical(manifest, snapshot_dir, repo)
            except SourceBytesUnrecoverable as exc:
                details = {
                    "manifest": manifest,
                    "ok": False,
                    "error": f"source_bytes_unrecoverable: {exc}",
                }
            details["drift"] = current_drift(manifest, repo)
            details["freeze_commit"] = recorded_freeze_commit(manifest)
            report["suites"][manifest] = details
            if not details["ok"]:
                report["ok"] = False
        finally:
            if cleanup is not None:
                cleanup()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Historical source-closure governance."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "verify-all",
        help="verify every affected historical closure; report drift",
    )
    verify_one = sub.add_parser(
        "verify", help="verify a single manifest's historical closure"
    )
    verify_one.add_argument("manifest", help="manifest path, repo-relative")
    locate_one = sub.add_parser(
        "locate",
        help="diagnostic: compare recorded freeze commit against a local "
        "history search (requires full history; not used by verification)",
    )
    locate_one.add_argument("manifest", help="manifest path, repo-relative")
    args = parser.parse_args(argv)

    if args.command == "verify-all":
        report = verify_all()
    elif args.command == "verify":
        manifest = args.manifest
        if manifest not in AFFECTED_MANIFESTS:
            print(f"unknown manifest: {manifest}", file=sys.stderr)
            return 2
        with tempfile.TemporaryDirectory(prefix="freeze-governance-") as tmp:
            try:
                details = verify_historical(manifest, tmp)
            except SourceBytesUnrecoverable as exc:
                details = {
                    "manifest": manifest,
                    "ok": False,
                    "error": f"source_bytes_unrecoverable: {exc}",
                }
            details["drift"] = current_drift(manifest)
            details["freeze_commit"] = recorded_freeze_commit(manifest)
        report = {"suites": {manifest: details}, "ok": bool(details["ok"])}

    if args.command == "locate":
        manifest = args.manifest
        if manifest not in AFFECTED_MANIFESTS:
            print(f"unknown manifest: {manifest}", file=sys.stderr)
            return 2
        recorded = recorded_freeze_commit(manifest)
        print(f"recorded freeze commit: {recorded}")
        try:
            located = find_freeze_commit(manifest)
        except SourceBytesUnrecoverable as exc:
            print(f"history search unavailable or failed: {exc}")
            return 2
        print(f"history-search commit:  {located}")
        return 0 if located == recorded else 2

    print(json.dumps(report, indent=2, sort_keys=True))
    print()
    print("DRIFT REPORT (information, not failure):")
    suites = report["suites"]
    assert isinstance(suites, dict)
    for manifest in sorted(suites):
        details = suites[manifest]
        assert isinstance(details, dict)
        drift = details.get("drift", [])
        status = "VALID" if details.get("ok") else "INVALID"
        print(f"  historical closure: {status}  {manifest}")
        if drift:
            for path in drift:  # type: ignore[union-attr]
                print(f"    drift: {path}")
        else:
            print("    drift: none")
    if any(
        isinstance(d, dict) and d.get("error", "").startswith(
            "source_bytes_unrecoverable"
        )
        for d in suites.values()
    ):
        return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
