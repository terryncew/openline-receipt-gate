#!/usr/bin/env python3
"""Keep frozen warning-time evidence verifiable after live standing expires.

The independent verifier remains the authority. This wrapper accepts a clean,
current verification or the single archival condition ``profile_expired``.
Every other result fails closed.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
INDEPENDENT_VERIFIER = ROOT / "scripts" / "verify_warning_time_benchmark.py"
RELEASE_CHECK = ROOT / "scripts" / "release_check.py"
ARCHIVED_ONLY_ERRORS = ["profile_expired"]


def classify_verification(
    payload: object,
    returncode: int,
) -> tuple[bool, dict[str, Any]]:
    """Classify one independent-verifier result without weakening failures."""
    if not isinstance(payload, Mapping):
        return False, {
            "archive_integrity": "FAIL",
            "live_standing": "UNRESOLVED",
            "errors": ["verifier_output_not_object"],
        }

    valid = payload.get("valid")
    errors = payload.get("errors")
    if returncode == 0 and valid is True and errors == []:
        return True, {
            "archive_integrity": "PASS",
            "live_standing": "CURRENT",
            "accepted_release_condition": "fully_valid",
            "policy_authority": "UNCHANGED",
        }

    if returncode != 0 and valid is False and errors == ARCHIVED_ONLY_ERRORS:
        return True, {
            "archive_integrity": "PASS",
            "live_standing": "EXPIRED",
            "accepted_release_condition": "profile_expired_only",
            "policy_authority": "NONE",
        }

    return False, {
        "archive_integrity": "FAIL",
        "live_standing": "UNRESOLVED",
        "errors": errors if isinstance(errors, list) else ["verifier_errors_invalid"],
    }


def run_archive_check() -> int:
    completed = subprocess.run(
        [sys.executable, str(INDEPENDENT_VERIFIER)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        verifier = json.loads(completed.stdout)
    except json.JSONDecodeError:
        verifier = None

    accepted, status = classify_verification(verifier, completed.returncode)
    output = {
        **status,
        "independent_verifier_returncode": completed.returncode,
        "independent_verifier": verifier,
    }
    if completed.stderr:
        output["independent_verifier_stderr"] = completed.stderr[-4000:]
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if accepted else completed.returncode or 2


def run_release_check() -> int:
    """Run the existing release gate with one named command adapted for expiry."""
    spec = importlib.util.spec_from_file_location(
        "openline_release_check",
        RELEASE_CHECK,
    )
    if spec is None or spec.loader is None:
        print(json.dumps({"passed": False, "errors": ["release_check_import_failed"]}))
        return 2
    release_check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release_check)
    original_execute = release_check.execute

    def archive_aware_execute(
        name: str,
        command: list[str],
        **kwargs: Any,
    ) -> tuple[dict[str, Any], bool]:
        if name == "warning_time_benchmark_verifier":
            expected = [sys.executable, "scripts/verify_warning_time_benchmark.py"]
            if command != expected:
                return original_execute(name, command, **kwargs)
            command = [sys.executable, str(Path(__file__).resolve())]
        return original_execute(name, command, **kwargs)

    release_check.execute = archive_aware_execute
    return int(release_check.main())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--release-check",
        action="store_true",
        help="run the complete release gate with expiry-only archive semantics",
    )
    args = parser.parse_args()
    if args.release_check:
        return run_release_check()
    return run_archive_check()


if __name__ == "__main__":
    raise SystemExit(main())
