from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ect001 import AuthorAttestationError, evaluate_t1_standing  # noqa: E402


def author_pass(basis=None):
    return {
        "source_pin": "arxiv:2608.23623v1",
        "verifier_authority": "AUTHOR",
        "verifier_result": "PASS",
        "certificate_sha256": hashlib.sha256(b"opaque-author-certificate-fixture").hexdigest(),
        "admitted_dependency_basis": basis or ["trace:evidence:17", "trace:evidence:29"],
    }


class ECT001BoundaryTests(unittest.TestCase):
    def test_bound_basis_loss_reopens(self):
        out = evaluate_t1_standing(author_pass(), {"lost_standing_basis": ["trace:evidence:29"]})
        self.assertEqual(out["disposition"], "REOPEN")
        self.assertEqual(out["affected_basis"], ["trace:evidence:29"])
        self.assertFalse(out["t0_reverified_by_openline"])

    def test_unrelated_loss_survives(self):
        out = evaluate_t1_standing(author_pass(), {"lost_standing_basis": ["trace:evidence:88"]})
        self.assertEqual(out["disposition"], "NO_REOPEN")
        self.assertEqual(out["affected_basis"], [])

    def test_openline_cannot_claim_t0_authority(self):
        x = author_pass()
        x["verifier_authority"] = "OPENLINE"
        with self.assertRaisesRegex(AuthorAttestationError, "must_be_author"):
            evaluate_t1_standing(x, {"lost_standing_basis": []})

    def test_nonpass_t0_is_not_admitted(self):
        x = author_pass()
        x["verifier_result"] = "FAIL"
        with self.assertRaisesRegex(AuthorAttestationError, "did_not_pass"):
            evaluate_t1_standing(x, {"lost_standing_basis": []})

    def test_dependency_basis_is_required(self):
        x = author_pass()
        x["admitted_dependency_basis"] = []
        with self.assertRaisesRegex(AuthorAttestationError, "dependency_basis"):
            evaluate_t1_standing(x, {"lost_standing_basis": []})

    def test_certificate_digest_is_opaque_but_bound(self):
        x = author_pass()
        x["certificate_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(AuthorAttestationError, "certificate_digest"):
            evaluate_t1_standing(x, {"lost_standing_basis": []})

    def test_wrong_source_pin_is_rejected(self):
        x = author_pass()
        x["source_pin"] = "arxiv:2608.23623v2"
        with self.assertRaisesRegex(AuthorAttestationError, "source_pin"):
            evaluate_t1_standing(x, {"lost_standing_basis": []})

    def test_cold_external_run_fails_closed(self):
        subprocess.run([sys.executable, str(ROOT / "scripts" / "run_cold_external.py")], check=True, cwd=ROOT)
        result = json.loads((ROOT / "cold_external_result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["disposition"], "AUTHOR_VERIFIER_UNAVAILABLE")
        self.assertFalse(result["t1"]["executed"])
        self.assertFalse(result["openline_reconstructed_ect_verifier"])


if __name__ == "__main__":
    unittest.main()
