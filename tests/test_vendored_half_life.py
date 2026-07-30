from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load_module(
    "verify_vendored_half_life_for_tests",
    ROOT / "scripts" / "verify_vendored_half_life.py",
)
release_check = load_module(
    "release_check_for_vendored_tests",
    ROOT / "scripts" / "release_check.py",
)


class VendoredHalfLifeTests(unittest.TestCase):
    def test_bundle_verifies_without_external_network_or_checkout(self) -> None:
        result = verifier.verify(verifier.DEFAULT_BUNDLE_ROOT, None)
        self.assertTrue(result["valid"], result["errors"])
        self.assertFalse(result["external_source_checked"])
        self.assertEqual(result["source_commit"], verifier.SOURCE_COMMIT)

    def test_wheel_fixture_and_policy_tampering_fail_closed(self) -> None:
        mutations = (
            (
                verifier.WHEEL_NAME,
                "wheel_hash_mismatch",
            ),
            (
                "site/openline_half_life/causal_compactor.py",
                "site_tree_hash_mismatch",
            ),
            (
                "examples/demo_output/half_life_receipt.json",
                "fixture_tree_hash_mismatch",
            ),
            (
                "policy/succession_policy_public_key.hex",
                "policy_tree_hash_mismatch",
            ),
        )
        for relative, expected_error in mutations:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                copied = Path(raw) / "bundle"
                shutil.copytree(verifier.DEFAULT_BUNDLE_ROOT, copied)
                target = copied / relative
                data = target.read_bytes()
                target.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
                result = verifier.verify(copied, None)
                self.assertFalse(result["valid"])
                self.assertIn(expected_error, result["errors"])

    def test_bundle_cannot_pose_as_its_own_external_source(self) -> None:
        result = verifier.verify(
            verifier.DEFAULT_BUNDLE_ROOT,
            verifier.DEFAULT_BUNDLE_ROOT,
        )
        self.assertFalse(result["valid"])
        self.assertIn("external_source_must_be_independent", result["errors"])

    def test_default_release_runtime_activates_vendored_fixture(self) -> None:
        site_value = str(release_check.VENDORED_HALF_LIFE_SITE)
        env = os.environ.copy()
        env.pop("OLP_HALF_LIFE_ROOT", None)
        env.pop("OLP_HALF_LIFE_SOURCE_ROOT", None)
        try:
            with mock.patch.dict(os.environ, env, clear=True):
                result = release_check.model_swap_runtime()
                self.assertTrue(result["supported"], result)
                self.assertEqual(
                    result["source_mode"],
                    "vendored_offline_fallback",
                )
                self.assertEqual(
                    Path(result["fixture_root"]),
                    release_check.VENDORED_HALF_LIFE_ROOT.resolve(),
                )
        finally:
            while site_value in sys.path:
                sys.path.remove(site_value)

    def test_invalid_explicit_runtime_never_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            env = os.environ.copy()
            env["OLP_HALF_LIFE_ROOT"] = raw
            env.pop("OLP_HALF_LIFE_SOURCE_ROOT", None)
            with mock.patch.dict(os.environ, env, clear=True):
                result = release_check.model_swap_runtime()
        self.assertFalse(result["supported"])
        self.assertEqual(result["source_mode"], "external_environment")


if __name__ == "__main__":
    unittest.main()
