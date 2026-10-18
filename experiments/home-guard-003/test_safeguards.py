#!/usr/bin/env python3
"""Non-vacuous safeguard negative tests for HOME-GUARD-003 Reproducer.

Each test first establishes the POSITIVE baseline, then introduces the fault
and requires detection. A test that cannot fail is vacuous; these can.

  1. Frozen-mechanism: run the ACTUAL CI command
     (git diff --quiet <frozen> -- <6 files>) on a disposable git checkout.
     Baseline: unmodified checkout passes (exit 0). Fault: modify one
     protected file; the command must fail (exit 1).
  2. Manifest: build a recursive manifest on a fixture with the exact
     packaging command. Baseline: sha256sum -c passes. Faults: corrupt one
     file -> must fail; delete one file -> must fail (missing rejected).
  3. Tamper: run verify_evidence.py on tampered receipts. Require BOTH
     nonzero exit AND the specific 'signature_invalid' text.

Usage: python3 test_safeguards.py <evidence-dir> <repo-url-or-path>
  evidence-dir: downloaded CI artifact (tamper test source)
  repo:        git repo path or URL (frozen-mechanism test does a disposable clone)

All tests must PASS. No privileges required.
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FROZEN = "44486057320e908ec091c327112d830f65e20caa"
PROTECTED = [
    "experiments/home-guard-003/policy_gate.py",
    "experiments/home-guard-003/verify_evidence.py",
    "experiments/home-guard-003/make_policies.py",
    "experiments/home-guard-003/run_virtual_network.sh",
    "experiments/home-guard-003/active_flow.py",
    "experiments/home-guard-003/echo_endpoint.py",
]

# Exact manifest build command used by run_measured.sh and the workflow.
MANIFEST_CMD = (
    "find . -type f ! -name 'SHA256SUMS*' | LC_ALL=C sort | "
    "xargs sha256sum > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS"
)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def test_frozen_mechanism_ci_command(repo_src: str) -> bool:
    """Exercise the real CI comparison on a disposable checkout."""
    print("[1] frozen-mechanism CI command on disposable checkout")
    with tempfile.TemporaryDirectory() as td:
        clone = Path(td) / "clone"
        # Disposable checkout of the PR branch under test (the CI workflow
        # checks out the PR head; comparing main would be a false baseline).
        r = run(["git", "clone", "--quiet", "--branch",
                 "study/home-guard-003-reproducer-costs", repo_src, str(clone)])
        if r.returncode != 0:
            print("    SETUP FAIL: clone failed"); return False
        r = run(["git", "-C", str(clone), "fetch", "--quiet", "origin", FROZEN])
        # Baseline: unmodified checkout must PASS (exit 0)
        base = run(["git", "-C", str(clone), "diff", "--quiet", FROZEN, "--"] + PROTECTED)
        if base.returncode != 0:
            print("    BASELINE FAIL: unmodified checkout flagged a diff"); return False
        print("    baseline: unmodified checkout passes (exit 0)")
        # Fault: modify one protected file
        target = clone / PROTECTED[0]
        target.write_text(target.read_text() + "\n# INJECTED\n")
        fault = run(["git", "-C", str(clone), "diff", "--quiet", FROZEN, "--"] + PROTECTED)
        if fault.returncode == 0:
            print("    VACUOUS: modified file NOT detected"); return False
        print("    fault: modified file detected (exit 1)")
        # Also confirm a non-protected file does NOT trigger it
        target.write_text(target.read_text().replace("\n# INJECTED\n", ""))
        other = clone / "experiments/home-guard-003/COST_REPORT.md"
        other.write_text(other.read_text() + "\n")
        nonprot = run(["git", "-C", str(clone), "diff", "--quiet", FROZEN, "--"] + PROTECTED)
        if nonprot.returncode != 0:
            print("    FALSE POSITIVE: non-protected edit flagged"); return False
        print("    non-protected edit correctly ignored")
    print("    PASS")
    return True


def test_manifest_recursive_nonvacuous(evidence: Path) -> bool:
    """Baseline manifest passes; corruption and deletion both fail."""
    print("[2] recursive manifest: baseline pass, then corruption/deletion fail")
    with tempfile.TemporaryDirectory() as td:
        work = Path(td) / "e"
        # Fixture: subset including nested policies/ and .log files
        (work / "policies").mkdir(parents=True)
        for name in ["report.json", "cost-timeline.jsonl", "apply-receipts.jsonl",
                     "gate-log.txt", "tamper-test.log",
                     "policies/v2-owner-revoke.json", "policies/v1-owner-allow.json"]:
            src = evidence / name
            dst = work / name
            shutil.copy2(src, dst)
        # Build manifest with the exact packaging command
        r = run(["bash", "-c", MANIFEST_CMD], cwd=str(work))
        if r.returncode != 0:
            print("    SETUP FAIL: manifest build failed"); return False
        # BASELINE: must pass on uncorrupted fixture
        base = run(["sha256sum", "-c", "SHA256SUMS"], cwd=str(work))
        if base.returncode != 0:
            print("    BASELINE FAIL: valid manifest did not verify"); return False
        n = len((work / "SHA256SUMS").read_text().splitlines())
        print(f"    baseline: {n} entries verify OK (incl. policies/ and .log)")
        if n != 7:
            print(f"    BASELINE FAIL: expected 7 entries, got {n}"); return False
        # FAULT 1: corrupt one file (incl. a nested one)
        (work / "policies/v2-owner-revoke.json").write_bytes(b"corrupted")
        c1 = run(["sha256sum", "-c", "SHA256SUMS"], cwd=str(work))
        if c1.returncode == 0 or "FAILED" not in c1.stdout:
            print("    VACUOUS: corruption NOT detected"); return False
        print("    fault: corrupted nested file detected")
        # Restore, then FAULT 2: delete a file (missing must be rejected)
        shutil.copy2(evidence / "policies/v2-owner-revoke.json",
                     work / "policies/v2-owner-revoke.json")
        (work / "tamper-test.log").unlink()
        c2 = run(["sha256sum", "-c", "SHA256SUMS"], cwd=str(work))
        if c2.returncode == 0 or "FAILED" not in c2.stdout:
            print("    VACUOUS: missing file NOT detected"); return False
        print("    fault: missing file rejected")
    print("    PASS")
    return True


def test_tamper_dual_requirement(evidence: Path, repo: Path) -> bool:
    """Tampered evidence: require BOTH nonzero exit AND signature_invalid."""
    print("[3] tamper: nonzero exit AND signature_invalid required")
    with tempfile.TemporaryDirectory() as td:
        tampered = Path(td) / "t"
        shutil.copytree(evidence, tampered)
        # Baseline: untampered evidence verifies cleanly (exit 0)
        base = run([sys.executable,
                    str(repo / "experiments/home-guard-003/verify_evidence.py"),
                    str(tampered)])
        if base.returncode != 0:
            print("    BASELINE FAIL: untampered evidence did not verify"); return False
        print("    baseline: untampered evidence verifies (exit 0)")
        # Fault: flip one signature byte
        p = tampered / "apply-receipts.jsonl"
        lines = p.read_text().splitlines()
        r = json.loads(lines[0])
        sig = r["signature"]["value"]
        r["signature"]["value"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        lines[0] = json.dumps(r, sort_keys=True)
        p.write_text("\n".join(lines) + "\n")
        proc = run([sys.executable,
                    str(repo / "experiments/home-guard-003/verify_evidence.py"),
                    str(tampered)])
        out = proc.stdout + proc.stderr
        nonzero = proc.returncode != 0
        specific = "bad signed receipt: signature_invalid" in out
        print(f"    fault: exit={proc.returncode} (nonzero: {nonzero}), "
              f"signature_invalid present: {specific}")
        if not (nonzero and specific):
            print("    FAIL: dual requirement not met"); return False
    print("    PASS")
    return True


def main() -> int:
    evidence = Path(sys.argv[1])
    repo_src = sys.argv[2]
    repo = Path(repo_src) if Path(repo_src).is_dir() else Path(".")
    print("HOME-GUARD-003 safeguard negative tests (non-vacuous):")
    results = [
        test_frozen_mechanism_ci_command(repo_src),
        test_manifest_recursive_nonvacuous(evidence),
        test_tamper_dual_requirement(evidence, repo)
    ]
    if all(results):
        print("ALL SAFEGUARD NEGATIVE TESTS PASS")
        return 0
    print("SAFEGUARD TEST FAILURE", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
