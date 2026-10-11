#!/usr/bin/env python3
"""Run Gateway unit/race/regression tests without overwriting old evidence.

The older unit module sets repository config paths at import time, and the
older race module writes a dated, tracked measurements file. This runner
gives the unit module temporary receiver state and redirects new race
measurements to an explicit output directory. Test assertions are unchanged.

Usage: python3 gateway/ci/run_security_tests.py --output-dir /tmp/gw-security
Envoy and the complete Docker Compose verification remain separate checks.
"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "tests"))
    with tempfile.TemporaryDirectory(prefix="gateway-security-") as temporary:
        cfg = Path(temporary) / "config"
        cfg.mkdir()
        key = Ed25519PrivateKey.generate().private_bytes_raw()
        (cfg / "receiver.key").write_text(
            base64.urlsafe_b64encode(key).rstrip(b"=").decode())
        (cfg / "receiver.key").chmod(0o600)
        (cfg / "policy.json").write_text(json.dumps({"mode": "enforce"}))
        unit = importlib.import_module("test_gateway")
        # Apply after importing the legacy unit module, which sets its own
        # repo paths. No key or generated DB touches the historical checkout.
        os.environ["GATEWAY_CONFIG"] = str(cfg)
        os.environ["GATEWAY_DB"] = str(Path(temporary) / "gateway.db")
        for name in ("GATEWAY_PROFILE", "GATEWAY_STANDING_CHECK",
                     "GATEWAY_STANDING_URL", "GATEWAY_TEST_PRE_COMMIT_DELAY_MS",
                     "GATEWAY_AUTH_MODE"):
            os.environ.pop(name, None)
        race = importlib.import_module("test_standing_races")
        race.MEASUREMENTS_PATH = args.output_dir / "standing-measurements.json"
        regressions = importlib.import_module("test_latency_regressions")
        loader = unittest.defaultTestLoader
        suite = unittest.TestSuite(loader.loadTestsFromModule(module)
                                   for module in (unit, race, regressions))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
