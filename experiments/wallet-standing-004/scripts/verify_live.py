#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
path = EXP / "live_result.json"
if not path.exists():
    raise SystemExit("LIVE_RESULT_MISSING")
result = json.loads(path.read_text())
expected = [
    "race_to_window",
    "split_brain_delivery",
    "successor_race",
    "cold_start_starvation",
    "duplicate_storm_replay",
    "cross_epoch_reorder",
]
errors = []
if result.get("verdict") != "LIVE_TRANSPORT_CONTINUITY_ENFORCED_WITH_MEASURED_PROPAGATION_LAG":
    errors.append("verdict")
if result.get("passed") is not True:
    errors.append("passed")
if result.get("durability_preflight", {}).get("passed") is not True:
    errors.append("durability")
scenarios = result.get("scenarios", [])
if [row.get("name") for row in scenarios] != expected:
    errors.append("scenario_order")
if any(row.get("passed") is not True for row in scenarios):
    errors.append("scenario_failure")
by_name = {row["name"]: row for row in scenarios if isinstance(row, dict) and "name" in row}
if by_name.get("race_to_window", {}).get("pre_delivery_effect") is not True:
    errors.append("race_exposure_hidden")
if by_name.get("race_to_window", {}).get("post_admission_block") is not True:
    errors.append("race_post_admission")
if by_name.get("split_brain_delivery", {}).get("pre_reconnect_effect") is not True:
    errors.append("split_exposure_hidden")
if by_name.get("split_brain_delivery", {}).get("post_reconnect_block") is not True:
    errors.append("split_post_admission")
if by_name.get("successor_race", {}).get("post_discovery_effects") != 0:
    errors.append("fork_post_discovery_effect")
if by_name.get("cold_start_starvation", {}).get("passes_after_lineage_and_checkpoint") is not True:
    errors.append("cold_start_recovery")
if by_name.get("duplicate_storm_replay", {}).get("revision") != 1:
    errors.append("duplicate_state_extension")
if by_name.get("cross_epoch_reorder", {}).get("generation_after_ordered_replay") != 3:
    errors.append("reorder_generation")
for row in scenarios:
    for key, value in row.items():
        if key.endswith("tau") and isinstance(value, dict) and value.get("status") == "MEASURED":
            for required in ("raw_ns", "offset_corrected_ns", "uncertainty_ns"):
                if required not in value:
                    errors.append(f"tau:{row.get('name')}:{required}")
if errors:
    raise SystemExit("LIVE_VERIFY_FAILED:" + ",".join(errors))
print("WALLET004_LIVE_OK")
