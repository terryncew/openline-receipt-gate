"""Current-development tests for frozen source-closure governance.

These tests do NOT touch historical artifacts.  They assert:

* every affected FREEZE manifest is byte-identical to git HEAD
  (the invariant: no historical hash may change);
* every affected historical closure reconstructs byte-exact from
  repository history and its original verifier passes against the
  reconstructed snapshot root;
* the drift report is accurate (self-consistency, not fixed filenames);
* the pytest collection exclusion matches the canonical frozen-module
  list, so both runners exclude exactly the same historical modules.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.freeze_governance import (  # noqa: E402
    AFFECTED_MANIFESTS,
    FROZEN_TEST_MODULES,
    current_drift,
    find_freeze_commit,
    historical_freeze_root,
    verify_historical,
    verify_snapshot_hashes,
)


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    )


class FreezeGovernanceTests(unittest.TestCase):
    def test_manifests_byte_identical_to_git_head(self) -> None:
        for manifest in sorted(AFFECTED_MANIFESTS):
            with self.subTest(manifest=manifest):
                committed = subprocess.run(
                    ["git", "show", f"HEAD:{manifest}"],
                    cwd=ROOT,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(committed.returncode, 0)
                self.assertEqual(
                    (ROOT / manifest).read_bytes(),
                    committed.stdout,
                    f"{manifest} was modified in the working tree",
                )

    def test_historical_closures_reconstruct_and_verify(self) -> None:
        for manifest in sorted(AFFECTED_MANIFESTS):
            with self.subTest(manifest=manifest):
                commit = find_freeze_commit(manifest)
                self.assertRegex(commit, r"^[0-9a-f]{40}$")
                with tempfile.TemporaryDirectory(
                    prefix="freeze-governance-test-"
                ) as tmp:
                    snapshot = historical_freeze_root(manifest, tmp)
                    self.assertEqual(
                        verify_snapshot_hashes(manifest, snapshot), []
                    )
                    details = verify_historical(manifest, tmp)
                    self.assertTrue(
                        details["ok"],
                        json.dumps(details, indent=2, sort_keys=True)[:3000],
                    )

    def test_drift_report_is_accurate(self) -> None:
        for manifest in sorted(AFFECTED_MANIFESTS):
            with self.subTest(manifest=manifest):
                frozen = json.loads((ROOT / manifest).read_text())["files"]
                expected = sorted(
                    relative
                    for relative, digest in frozen.items()
                    if not (ROOT / relative).is_file()
                    or hashlib.sha256((ROOT / relative).read_bytes())
                    .hexdigest()
                    != digest
                )
                reported = sorted(
                    entry.split(":")[0] for entry in current_drift(manifest)
                )
                self.assertEqual(reported, expected)

    def test_pytest_exclusion_matches_canonical_list(self) -> None:
        conftest = (ROOT / "conftest.py").read_text(encoding="utf-8")
        for module in FROZEN_TEST_MODULES:
            self.assertIn(f"tests/{module}.py", conftest)
        # No extra exclusions beyond the canonical list.
        self.assertEqual(
            sorted(
                line.strip().strip('",')
                for line in conftest.splitlines()
                if line.strip().startswith('"tests/test_')
            ),
            sorted(f"tests/{module}.py" for module in FROZEN_TEST_MODULES),
        )

    def test_frozen_modules_excluded_from_discovery(self) -> None:
        loader = unittest.TestLoader()
        suite = loader.discover(
            str(ROOT / "tests"), pattern="test_*.py", top_level_dir=str(ROOT)
        )
        seen: set[str] = set()

        def walk(suite: unittest.TestSuite) -> None:
            for test in suite:
                if isinstance(test, unittest.TestSuite):
                    walk(test)
                else:
                    seen.add(test.__class__.__module__.split(".")[-1])

        walk(suite)
        for module in FROZEN_TEST_MODULES:
            self.assertNotIn(module, seen)
        # The governance tests themselves are discovered.
        self.assertIn("test_freeze_governance", seen)


if __name__ == "__main__":
    unittest.main()
