from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FREEZE = ROOT / "benchmarks" / "role_confusion_consequence" / "FREEZE.json"
VERIFIER = ROOT / "scripts" / "verify_role_confusion_consequence.py"


class RoleConfusionFreezeTests(unittest.TestCase):
    def test_frozen_source_closure(self) -> None:
        freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
        self.assertEqual(
            freeze["schema"],
            "openline.role_confusion_consequence.freeze.v1",
        )
        files = freeze.get("files")
        self.assertIsInstance(files, dict)
        self.assertGreaterEqual(len(files), 8)
        self.assertNotIn(
            "benchmarks/role_confusion_consequence/results/"
            "independent_verification.json",
            files,
        )
        for relative, expected in files.items():
            with self.subTest(path=relative):
                path = ROOT / relative
                self.assertTrue(path.is_file())
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(actual, expected)

    def test_independent_verifier_rejects_source_tamper(self) -> None:
        freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            copied_root = Path(temporary)
            paths = [
                "benchmarks/role_confusion_consequence/FREEZE.json",
                *freeze["files"],
            ]
            for relative in paths:
                source = ROOT / relative
                destination = copied_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            cases = (
                copied_root
                / "benchmarks"
                / "role_confusion_consequence"
                / "cases.json"
            )
            cases.write_text(
                cases.read_text(encoding="utf-8").replace(
                    '"request_id": "r-clean"',
                    '"request_id": "r-tampered"',
                    1,
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(VERIFIER), "--root", str(copied_root)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            result = json.loads(proc.stdout)
            self.assertFalse(result["valid"])
            self.assertIn(
                "freeze_hash_mismatch:"
                "benchmarks/role_confusion_consequence/cases.json",
                result["errors"],
            )


if __name__ == "__main__":
    unittest.main()
