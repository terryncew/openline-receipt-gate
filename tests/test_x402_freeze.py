from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from benchmarks.x402_airlock.run_hostile_suite import run


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_x402_airlock.py"


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "independent_x402_verifier",
        VERIFIER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class X402FreezeTests(unittest.TestCase):
    def test_frozen_suite_reproduces_byte_exact_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="x402-reproduce-") as value:
            output = Path(value) / "report.json"
            report = run(
                ROOT / "benchmarks" / "x402_airlock" / "CASES.json",
                output,
            )
            self.assertTrue(report["valid"])
            self.assertEqual(report["case_count"], 56)
            self.assertEqual(
                output.read_bytes(),
                (
                    ROOT
                    / "benchmarks"
                    / "x402_airlock"
                    / "results"
                    / "hostile_report.json"
                ).read_bytes(),
            )

    def test_independent_verifier_accepts_frozen_source_closure(self) -> None:
        result = _load_verifier().verify(ROOT)
        self.assertTrue(result["valid"], result["errors"])
        self.assertTrue(result["independent_of_candidate_modules"])
        self.assertEqual(result["rule_count"], 8)
        self.assertEqual(result["case_count"], 56)

    def test_independent_verifier_imports_only_stdlib(self) -> None:
        tree = ast.parse(VERIFIER_PATH.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertEqual(
            imports,
            {
                "__future__",
                "ast",
                "hashlib",
                "json",
                "pathlib",
                "sys",
                "typing",
            },
        )

    def test_report_tamper_fails_independent_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="x402-tamper-") as value:
            copy_root = Path(value) / "candidate"
            shutil.copytree(ROOT, copy_root)
            report_path = (
                copy_root
                / "benchmarks"
                / "x402_airlock"
                / "results"
                / "hostile_report.json"
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["results"][1]["observed"]["settlement_calls"] = 1
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = _load_verifier().verify(copy_root)
            self.assertFalse(result["valid"])
            self.assertTrue(
                any("hostile_report.json" in error for error in result["errors"])
            )

    def test_all_required_axes_are_pre_effect_blocked(self) -> None:
        cases = json.loads(
            (
                ROOT / "benchmarks" / "x402_airlock" / "CASES.json"
            ).read_text(encoding="utf-8")
        )
        report = json.loads(
            (
                ROOT
                / "benchmarks"
                / "x402_airlock"
                / "results"
                / "hostile_report.json"
            ).read_text(encoding="utf-8")
        )
        required = set(cases["required_falsifier_axes"])
        self.assertEqual(
            required,
            {
                "network",
                "asset",
                "recipient",
                "amount",
                "expiry",
                "replay",
                "verification_settlement_divergence",
            },
        )
        self.assertEqual(
            report["required_falsifier_axes"],
            {axis: True for axis in sorted(required)},
        )

    def test_frozen_files_are_not_gitignored(self) -> None:
        git = shutil.which("git")
        self.assertIsNotNone(git)
        freeze = json.loads(
            (
                ROOT / "benchmarks" / "x402_airlock" / "FREEZE.json"
            ).read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory(prefix="x402-ignore-") as value:
            checkout = Path(value)
            subprocess.run(
                [str(git), "init", "-q"],
                cwd=checkout,
                check=True,
            )
            shutil.copy2(ROOT / ".gitignore", checkout / ".gitignore")
            for relative in [
                "benchmarks/x402_airlock/FREEZE.json",
                *sorted(freeze["files"]),
            ]:
                path = checkout / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")
                ignored = subprocess.run(
                    [
                        str(git),
                        "check-ignore",
                        "--no-index",
                        "--quiet",
                        "--",
                        relative,
                    ],
                    cwd=checkout,
                    check=False,
                )
                self.assertNotEqual(
                    ignored.returncode,
                    0,
                    f"ignored frozen artifact: {relative}",
                )


if __name__ == "__main__":
    unittest.main()
