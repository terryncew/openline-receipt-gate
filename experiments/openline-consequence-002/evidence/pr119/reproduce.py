#!/usr/bin/env python3
"""Read PR #119 Git objects and run its demo tests without changing the checkout."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REFERENCE = "81db6acb72149df989aac1827e5f621b0873d57b"
PR_HEAD = "1749a226b5f77cabc98f04a8655636229e0b11c2"
FILES = ("examples/multi_hop_refund_drift.py", "tests/test_multi_hop_refund_drift_demo.py")
REPO = Path(__file__).resolve().parents[4]
OUT = Path(__file__).resolve().parent


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=REPO)


def main() -> int:
    for revision in (REFERENCE, PR_HEAD):
        git("cat-file", "-e", revision + "^{commit}")
    (OUT / "diff-stat.txt").write_bytes(git("diff", "--stat", REFERENCE, PR_HEAD))
    (OUT / "diff-name-status.txt").write_bytes(git("diff", "--name-status", REFERENCE, PR_HEAD))
    (OUT / "commits.txt").write_bytes(git("log", "--format=fuller", REFERENCE + ".." + PR_HEAD))
    hashes = {}
    # Extract only PR-owned demo and test source; imports use frozen reference
    # source extracted into a temporary directory rather than a changing checkout.
    with tempfile.TemporaryDirectory(prefix="openline-pr119-review-") as tmp:
        root = Path(tmp)
        source = root / "source"
        source.mkdir()
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(git("archive", REFERENCE, "olp_gate")), mode="r:") as archive:
            archive.extractall(source, filter="data")
        for relative in FILES:
            content = git("show", f"{PR_HEAD}:{relative}")
            dest = root / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
            hashes[relative] = hashlib.sha256(content).hexdigest()
        env = dict(os.environ)
        env["PYTHONPATH"] = str(source)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_multi_hop_refund_drift_demo.py", "-v"]
        result = subprocess.run(command, cwd=root, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log = (
            f"PR #119 head: {PR_HEAD}\nReference application imports: {REFERENCE}\n"
            "Isolated temporary extraction; no branch checkout or PR application.\n"
            "Command: PYTHONPATH=<temp>/source PYTHONDONTWRITEBYTECODE=1 "
            "python -m unittest discover -s tests -p test_multi_hop_refund_drift_demo.py -v\n\n"
            + result.stdout
        )
        (OUT / "tests.log").write_text(log)
        print(log, end="")
    (OUT / "fixture-hashes.json").write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n")
    review = {
        "pr": 119,
        "reference_revision": REFERENCE,
        "reviewed_head_revision": PR_HEAD,
        "review_method": "Read-only Git-object diff and isolated tests; no PR API read available and no PR API/network writes.",
        "test_command": "python experiments/openline-consequence-002/evidence/pr119/reproduce.py",
        "test_exit_code": result.returncode,
        "test_count": 4,
        "changes": "Refund simulation verifies actual signed manager cap independently from receiver policy, and documents preflight refusal versus signed compiler decisions.",
        "mission_relation": "No Verified Commit, subject binding, cryptography, SQLite, or consequence atomicity changes; mission implementation does not depend on this PR.",
        "findings": [],
        "limitations": [
            "Owner key generated and held in local simulation process.",
            "Owner-scope preflight refusal is not a receiver-signed denial receipt.",
            "PaymentSimulator effects only; no durable atomic outcome, restart recovery, portable owner trust, or real consequence enforcement established by this PR.",
            "This review covers the exact fetched Git head, not live PR metadata."
        ],
        "scenario_specification": {
            "starting_branch_observed": "feature/openline-consequence-001",
            "starting_branch_revision_observed": REFERENCE,
            "availability": "No OPENLINE-CONSEQUENCE-001 or commissioning scenario specification found in reference checkout or reachable historic filenames.",
            "scope": "Repository text/filename search and read-only remote branch discovery; not a claim that no external specification exists.",
            "consequence": "Reconstructed mission scenarios must be identified as reconstructed rather than canonical original twelve."
        }
    }
    (OUT / "review.json").write_text(json.dumps(review, indent=2, sort_keys=True) + "\n")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
