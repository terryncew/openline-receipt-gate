#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
REPO = EXP.parents[1]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

manifest = json.loads((EXP / "RELEASE_MANIFEST.json").read_text())
errors = []
for rel, expected in manifest["files"].items():
    path = EXP / rel
    if not path.exists() or sha(path) != expected:
        errors.append(f"release:{rel}")

pin = json.loads((EXP / "DEPENDENCY_PIN.json").read_text())
if pin.get("base_commit") != "9278b6238bf4f04e56184135913f4a7859db66bf":
    errors.append("base_commit")
item = pin["wallet_standing_003"]
for path_key, hash_key in (
    ("distribution_path", "distribution_sha256"),
    ("public_surface_path", "public_surface_sha256"),
    ("frozen_result_path", "frozen_result_sha256"),
    ("release_manifest_path", "release_manifest_sha256"),
):
    path = REPO / item[path_key]
    if not path.exists():
        errors.append(f"dependency_missing:{path_key}")
    elif sha(path) != item[hash_key]:
        errors.append(f"dependency_hash:{path_key}")

prereg = json.loads((EXP / "preregistration.json").read_text())
if prereg["authority"] != {
    "wallet_policy_authority": "NONE",
    "relay_authority": "NONE",
    "measurement_authority": "NONE",
    "decision_authority": "RECEIVER_GATE",
}:
    errors.append("authority")
if prereg["clock_model"]["admission_uses_calibration"] is not False:
    errors.append("clock_authority")
if prereg["substrate"]["shared_database"] is not False:
    errors.append("shared_database")
if len(prereg["named_adversarial_schedules"]) != 6:
    errors.append("schedule_count")

if errors:
    raise SystemExit("WALLET004_RELEASE_FAILED:" + ",".join(errors))
print("WALLET004_RELEASE_OK")
