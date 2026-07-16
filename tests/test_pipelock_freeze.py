from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.pipelock.run_head_to_head import (
    repository_output_path,
    verify_original_protocol,
)


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmarks" / "pipelock"


class PipelockFreezeTests(unittest.TestCase):
    def freeze(self) -> dict[str, object]:
        return json.loads((BENCHMARK / "FREEZE.json").read_text(encoding="utf-8"))

    def test_clean_clone_falls_back_to_embedded_frozen_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = verify_original_protocol(
                self.freeze(),
                repository_root=Path(temporary),
                snapshot_path=BENCHMARK / "PROTOCOL-FROZEN-v0.3.0.md",
            )

        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["proof_mode"], "embedded_snapshot")
        self.assertFalse(result["freeze_commit_reachable"])
        self.assertEqual(
            result["embedded_snapshot_sha256"],
            self.freeze()["protocol_sha256"],
        )

    def test_fallback_rejects_a_resealed_or_wrong_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            wrong_snapshot = temporary_root / "PROTOCOL.md"
            wrong_snapshot.write_text("changed after scoring\n", encoding="utf-8")
            result = verify_original_protocol(
                self.freeze(),
                repository_root=temporary_root,
                snapshot_path=wrong_snapshot,
            )

        self.assertFalse(result["valid"])
        self.assertEqual(result["proof_mode"], "unavailable")
        self.assertIn("embedded_freeze_protocol_hash_mismatch", result["errors"])
        self.assertIn("original_freeze_protocol_unverifiable", result["errors"])

    def test_relative_reproduction_output_is_rooted_in_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository_root = Path(temporary)
            resolved = repository_output_path(
                Path("benchmarks/pipelock/results/reproduction/report.json"),
                repository_root=repository_root,
            )

        self.assertEqual(
            resolved,
            repository_root
            / "benchmarks"
            / "pipelock"
            / "results"
            / "reproduction"
            / "report.json",
        )


if __name__ == "__main__":
    unittest.main()
