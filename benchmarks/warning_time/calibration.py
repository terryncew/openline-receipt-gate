"""Clean-only calibration and signed freeze artifacts for warning-time tests.

Calibration and held-out evaluation are intentionally separate phases. This
module may create a clean calibration bundle and a signed freeze publication,
but it cannot create the external custody anchor required by the held-out
runner.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.warning_time.metric_proxies import (
    METRICS,
    METRIC_VERSIONS,
    metrics_for_observation,
    observable_features,
)
from benchmarks.warning_time.observable_fixture import observable_state_for_step
from olp_gate.crypto import (
    olp_canonical_json,
    public_key_hex,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)

ROOT = Path(__file__).resolve().parent
SCENARIO_PATH = ROOT / "scenario.json"
THRESHOLDS_PATH = ROOT / "thresholds.json"
CALIBRATION_EVIDENCE_PATH = ROOT / "calibration-evidence.json"
CALIBRATION_PROFILE_PATH = ROOT / "calibration-profile.json"
FREEZE_PUBLICATION_PATH = ROOT / "calibration-freeze-publication.json"
FREEZE_ANCHOR_PATH = ROOT / "calibration-freeze-anchor.json"
METRIC_SOURCE_PATH = ROOT / "metric_proxies.py"
OBSERVABLE_SOURCE_PATH = ROOT / "observable_fixture.py"
PROMPTS_DIR = ROOT / "prompts"

# Deterministic fixture keys are deliberately public test material. They prove
# artifact integrity inside this benchmark, not production identity.
PROFILE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("73" * 32))
PUBLICATION_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("74" * 32))
PROFILE_SIGNER_ID = "openline-warning-time-calibration-fixture"
PUBLICATION_SIGNER_ID = "openline-warning-time-freeze-publication-fixture"
CASES = ("control", "dropped_counterevidence", "unflagged_contradiction")
MAX_FUTURE_SKEW_SECONDS = 300
EXPECTED_EXTERNAL_ANCHOR_PUBLIC_KEY = "b42a57cd7505596299c16e281d87ccf1963dfafce80f95c7793994617d4cc151"
EXPECTED_EXTERNAL_ANCHOR_PAYLOAD_HASH = "2d515119634f4252031488381b08e6ef9c53f0571460af2eee5a09871b2d5433"
PROFILE_VALIDITY_DAYS = 30


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def hash_json(value: Any) -> str:
    return sha256_hex(olp_canonical_json(value))


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prompt_hashes() -> dict[str, str]:
    return {path.name: file_hash(path) for path in sorted(PROMPTS_DIR.glob("*.txt"))}


def graph_structure(scenario: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "agent_stack_id": scenario["agent_stack_id"],
        "agents": list(scenario["agents"]),
        "steps": list(scenario["steps"]),
        "handoff_steps": list(scenario["handoff_steps"]),
        "injection_step": int(scenario["injection_step"]),
        "bad_action_step": int(scenario["bad_action_step"]),
    }


def seed_partition(scenario: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "calibration_clean": list(scenario["calibration_seeds"]),
        "heldout": {case: list(scenario["heldout_seeds"][case]) for case in CASES},
        "reference": dict(scenario["reference_seeds"]),
    }


def validate_seed_partition(scenario: Mapping[str, Any]) -> None:
    calibration = [int(seed) for seed in scenario["calibration_seeds"]]
    if len(set(calibration)) != len(calibration):
        raise ValueError("calibration seeds are not unique")

    heldout: dict[str, set[int]] = {}
    for case in CASES:
        values = [int(seed) for seed in scenario["heldout_seeds"][case]]
        if len(set(values)) != len(values):
            raise ValueError(f"heldout seeds are not unique for {case}")
        heldout[case] = set(values)
        if set(calibration) & heldout[case]:
            raise ValueError(f"calibration and heldout seeds overlap for {case}")

    paired = heldout["control"]
    for case in CASES[1:]:
        if heldout[case] != paired:
            raise ValueError("heldout cases must use the same paired seeds")


def _clean_trace(seed: int, scenario: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    previous: Mapping[str, Any] | None = None
    for step_item in scenario["steps"]:
        step = int(step_item["step"])
        observation = observable_state_for_step(
            seed,
            step,
            corruption=None,
            injection_step=int(scenario["injection_step"]),
        )
        features = observable_features(observation, previous)
        metrics = metrics_for_observation(seed, step, observation, previous)
        rows.append({
            "step": step,
            "observable_state": observation,
            "observable_features": features,
            "metrics": metrics,
        })
        previous = observation
    return rows


def build_calibration_evidence(scenario: Mapping[str, Any]) -> dict[str, Any]:
    validate_seed_partition(scenario)
    runs: list[dict[str, Any]] = []
    all_values: dict[str, list[int]] = {metric: [] for metric in METRICS}

    for raw_seed in scenario["calibration_seeds"]:
        seed = int(raw_seed)
        trace = _clean_trace(seed, scenario)
        maxima = {metric: max(int(row["metrics"][metric]) for row in trace) for metric in METRICS}
        for row in trace:
            for metric in METRICS:
                all_values[metric].append(int(row["metrics"][metric]))
        runs.append({
            "seed": seed,
            "trace": trace,
            "trace_hash": hash_json(trace),
            "maxima_micros": maxima,
        })

    ranges = {
        metric: {
            "minimum": min(values),
            "maximum": max(values),
            "range": max(values) - min(values),
        }
        for metric, values in all_values.items()
    }
    body = {
        "schema": "openline.warning-time.calibration-evidence.v3",
        "scenario_id": scenario["scenario_id"],
        "partition": "clean_calibration_only",
        "run_count": len(runs),
        "runs": runs,
        "clean_value_ranges_micros": ranges,
        "metric_source_sha256": file_hash(METRIC_SOURCE_PATH),
        "observable_fixture_source_sha256": file_hash(OBSERVABLE_SOURCE_PATH),
        "corrupted_runs_used": False,
        "heldout_runs_used": False,
        "sample_size_boundary": scenario["sample_size_note"],
    }
    return {**body, "evidence_hash": hash_json(body)}


def calibrate_thresholds(
    scenario: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    if evidence.get("partition") != "clean_calibration_only":
        raise ValueError("thresholds require clean-only calibration evidence")
    if evidence.get("corrupted_runs_used") is not False or evidence.get("heldout_runs_used") is not False:
        raise ValueError("calibration evidence is contaminated")

    ranges = evidence["clean_value_ranges_micros"]
    margins = {metric: max(1, 2 * int(ranges[metric]["range"])) for metric in METRICS}
    values = {
        metric: int(ranges[metric]["maximum"]) + margins[metric]
        for metric in METRICS
    }
    body = {
        "schema": "openline.warning-time.thresholds.v4",
        "scenario_id": scenario["scenario_id"],
        "calibration_method": "clean_max_plus_twice_clean_range_v3",
        "calibration_run_count": int(evidence["run_count"]),
        "calibration_evidence_hash": evidence["evidence_hash"],
        "clean_value_ranges_micros": ranges,
        "margins_micros": margins,
        "thresholds_micros": values,
        "corrupted_runs_used_for_calibration": False,
        "heldout_runs_used_for_calibration": False,
        "frozen_before_heldout_runs": True,
    }
    return {**body, "thresholds_hash": hash_json(body)}


def _profile_body(
    scenario: Mapping[str, Any],
    evidence: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    *,
    created_at: str,
) -> dict[str, Any]:
    created = parse_time(created_at)
    expires_at = (created + timedelta(days=PROFILE_VALIDITY_DAYS)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return {
        "schema": "openline.calibration-profile.v3",
        "profile_id": "dsm-receipt-gate-warning-time-v4",
        "profile_kind": "synthetic_warning_time_calibration",
        "created_at": created_at,
        "expires_at": expires_at,
        "signer_id": PROFILE_SIGNER_ID,
        "surfaces": ["openline-receipt-gate", "dynamic-sentience-maps"],
        "applicability": {
            "scenario_id": scenario["scenario_id"],
            "agent_stack_id": scenario["agent_stack_id"],
            "graph_structure_hash": hash_json(graph_structure(scenario)),
            "prompt_hashes": prompt_hashes(),
            "seed_partition_hash": hash_json(seed_partition(scenario)),
            "receipt_gate_policy": {
                "policy_id": "benchmark.warning-time.handoff",
                "version": "1",
            },
        },
        "metrics": {
            "versions": dict(METRIC_VERSIONS),
            "source_file": "metric_proxies.py",
            "source_sha256": file_hash(METRIC_SOURCE_PATH),
            "observable_fixture_source_sha256": file_hash(OBSERVABLE_SOURCE_PATH),
            "input_boundary": "observable_state_and_previous_observable_state_only",
            "forbidden_inputs": [
                "ground_truth_case_label",
                "corruption_label",
                "injection_step",
                "bad_action_label",
            ],
            "units": {metric: "micros" for metric in METRICS},
            "direction": {metric: "higher_is_more_warning" for metric in METRICS},
        },
        "calibration": {
            "method": thresholds["calibration_method"],
            "clean_run_count": int(evidence["run_count"]),
            "corrupted_runs_used": False,
            "heldout_runs_used": False,
            "calibration_evidence_artifact": "calibration-evidence.json",
            "calibration_evidence_hash": evidence["evidence_hash"],
            "thresholds_artifact": "thresholds.json",
            "thresholds_hash": thresholds["thresholds_hash"],
            "thresholds_micros": thresholds["thresholds_micros"],
        },
        "heldout_plan": {
            "clean_run_count": len(scenario["heldout_seeds"]["control"]),
            "corruption_run_count_by_case": {
                case: len(scenario["heldout_seeds"][case])
                for case in CASES
                if case != "control"
            },
            "results_not_used_to_set_thresholds": True,
            "external_freeze_anchor_required": True,
        },
        "freshness": {
            "created_at_must_not_be_future": True,
            "max_future_clock_skew_seconds": MAX_FUTURE_SKEW_SECONDS,
            "expires_at_enforced": True,
            "validity_days": PROFILE_VALIDITY_DAYS,
            "source_change_invalidates": True,
        },
        "governance": {
            "may_govern": ["emit_early_warning", "require_receipt_gate_reappraisal"],
            "may_not_govern": [
                "COMMIT",
                "QUARANTINE",
                "DENY",
                "downstream_tool_execution",
                "automatic_model_retirement",
            ],
            "receiver_gate_remains_authoritative": True,
        },
        "validity": {
            "named_stack_only": True,
            "portable_object": "calibration_provenance_not_universal_threshold",
            "invalidated_by": [
                "graph_structure_change",
                "prompt_change",
                "metric_version_change",
                "metric_source_change",
                "observable_fixture_change",
                "receipt_gate_policy_change",
                "seed_partition_change",
                "profile_expiration",
            ],
        },
        "claim_boundary": (
            "Successful held-out separation establishes predictive usefulness for the named synthetic "
            "agent stack and failure cases only. It does not prove the metric ontology is true, "
            "establish a universal threshold, supply live COLE scoring, or authorize an action."
        ),
        "trust_boundary": (
            "The bundled profile signing key is deterministic fixture material. The profile signature "
            "proves artifact integrity inside this benchmark, not production identity. Chronology must "
            "be established separately by the external freeze anchor."
        ),
    }


def build_calibration_profile(
    scenario: Mapping[str, Any],
    evidence: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    body = _profile_body(
        scenario,
        evidence,
        thresholds,
        created_at=created_at or iso_now(),
    )
    return sign_olp_body(body, PROFILE_KEY)


def build_freeze_publication(
    scenario: Mapping[str, Any],
    evidence: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    published_at: str | None = None,
) -> dict[str, Any]:
    body = {
        "schema": "openline.calibration-freeze-publication.v2",
        "publication_id": "dsm-receipt-gate-warning-time-v4-freeze",
        "scenario_id": scenario["scenario_id"],
        "published_at": published_at or iso_now(),
        "signer_id": PUBLICATION_SIGNER_ID,
        "profile_payload_hash": profile["payload_hash"],
        "calibration_evidence_hash": evidence["evidence_hash"],
        "thresholds_hash": thresholds["thresholds_hash"],
        "metric_source_sha256": file_hash(METRIC_SOURCE_PATH),
        "observable_fixture_source_sha256": file_hash(OBSERVABLE_SOURCE_PATH),
        "heldout_evaluation_started": False,
        "purpose": "Freeze the calibration digest before any held-out evaluation begins.",
        "next_required_step": "Deposit this exact publication in external custody and bind its returned identity in calibration-freeze-anchor.json.",
    }
    return sign_olp_body(body, PUBLICATION_KEY)


def verify_profile(
    profile: Mapping[str, Any],
    scenario: Mapping[str, Any],
    evidence: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    valid, error = verify_olp_signature(profile)
    if not valid:
        errors.append(error or "profile_signature_invalid")
    if profile.get("schema") != "openline.calibration-profile.v3":
        errors.append("profile_schema_invalid")
    if profile.get("signature", {}).get("public_key") != public_key_hex(PROFILE_KEY):
        errors.append("profile_signer_key_mismatch")

    applicability = profile.get("applicability", {})
    metrics = profile.get("metrics", {})
    calibration = profile.get("calibration", {})
    if applicability.get("graph_structure_hash") != hash_json(graph_structure(scenario)):
        errors.append("graph_structure_hash_mismatch")
    if applicability.get("prompt_hashes") != prompt_hashes():
        errors.append("prompt_hashes_mismatch")
    if applicability.get("seed_partition_hash") != hash_json(seed_partition(scenario)):
        errors.append("seed_partition_hash_mismatch")
    if metrics.get("source_sha256") != file_hash(METRIC_SOURCE_PATH):
        errors.append("metric_source_hash_mismatch")
    if metrics.get("observable_fixture_source_sha256") != file_hash(OBSERVABLE_SOURCE_PATH):
        errors.append("observable_fixture_hash_mismatch")
    if metrics.get("input_boundary") != "observable_state_and_previous_observable_state_only":
        errors.append("metric_input_boundary_invalid")
    if calibration.get("calibration_evidence_hash") != evidence.get("evidence_hash"):
        errors.append("calibration_evidence_hash_mismatch")
    if calibration.get("thresholds_hash") != thresholds.get("thresholds_hash"):
        errors.append("thresholds_hash_mismatch")
    if calibration.get("thresholds_micros") != thresholds.get("thresholds_micros"):
        errors.append("threshold_values_mismatch")
    if profile.get("governance", {}).get("receiver_gate_remains_authoritative") is not True:
        errors.append("receiver_gate_authority_missing")

    clock = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        created = parse_time(str(profile["created_at"]))
        expires = parse_time(str(profile["expires_at"]))
        if created > clock + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            errors.append("profile_created_at_in_future")
        if expires <= created:
            errors.append("profile_expiry_not_after_creation")
        if clock > expires:
            errors.append("profile_expired")
    except (KeyError, TypeError, ValueError):
        errors.append("profile_freshness_invalid")
    return {"valid": not errors, "errors": errors}


def verify_publication(
    publication: Mapping[str, Any],
    profile: Mapping[str, Any],
    evidence: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    valid, error = verify_olp_signature(publication)
    if not valid:
        errors.append(error or "freeze_publication_signature_invalid")
    if publication.get("schema") != "openline.calibration-freeze-publication.v2":
        errors.append("freeze_publication_schema_invalid")
    if publication.get("signature", {}).get("public_key") != public_key_hex(PUBLICATION_KEY):
        errors.append("freeze_publication_signer_key_mismatch")
    if publication.get("profile_payload_hash") != profile.get("payload_hash"):
        errors.append("freeze_publication_profile_mismatch")
    if publication.get("calibration_evidence_hash") != evidence.get("evidence_hash"):
        errors.append("freeze_publication_evidence_mismatch")
    if publication.get("thresholds_hash") != thresholds.get("thresholds_hash"):
        errors.append("freeze_publication_thresholds_mismatch")
    if publication.get("heldout_evaluation_started") is not False:
        errors.append("freeze_publication_claims_heldout_started")
    try:
        published = parse_time(str(publication["published_at"]))
        created = parse_time(str(profile["created_at"]))
        clock = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if published < created:
            errors.append("freeze_publication_before_profile_creation")
        if published > clock + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            errors.append("freeze_publication_in_future")
    except (KeyError, TypeError, ValueError):
        errors.append("freeze_publication_timestamp_invalid")
    return {"valid": not errors, "errors": errors}


def verify_external_anchor(
    anchor: Mapping[str, Any],
    publication: Mapping[str, Any],
    profile: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    valid, error = verify_olp_signature(anchor)
    if not valid:
        errors.append(error or "external_anchor_signature_invalid")
    if anchor.get("signature", {}).get("public_key") != EXPECTED_EXTERNAL_ANCHOR_PUBLIC_KEY:
        errors.append("external_anchor_signer_key_mismatch")
    if anchor.get("payload_hash") != EXPECTED_EXTERNAL_ANCHOR_PAYLOAD_HASH:
        errors.append("external_anchor_payload_not_receiver_approved")
    if anchor.get("schema") != "openline.calibration-freeze-anchor.v2":
        errors.append("external_anchor_schema_invalid")
    if anchor.get("anchor_type") != "private_external_custody":
        errors.append("external_anchor_type_invalid")
    if anchor.get("publication_payload_hash") != publication.get("payload_hash"):
        errors.append("external_anchor_publication_mismatch")
    if anchor.get("publication_file_sha256") != file_hash(FREEZE_PUBLICATION_PATH):
        errors.append("external_anchor_publication_file_mismatch")
    if anchor.get("profile_payload_hash") != profile.get("payload_hash"):
        errors.append("external_anchor_profile_mismatch")
    if anchor.get("thresholds_hash") != thresholds.get("thresholds_hash"):
        errors.append("external_anchor_thresholds_mismatch")
    if anchor.get("calibration_evidence_hash") != evidence.get("evidence_hash"):
        errors.append("external_anchor_evidence_mismatch")
    external = anchor.get("external_publication", {})
    if external.get("service") != "chatgpt_file_library":
        errors.append("external_anchor_service_invalid")
    if not str(external.get("file_id", "")).startswith("file_"):
        errors.append("external_anchor_file_id_invalid")
    if not str(external.get("library_file_id", "")).startswith("libfile_"):
        errors.append("external_anchor_library_file_id_invalid")
    if external.get("path") != "/OpenLine/Calibration Anchors/warning-time-v4-calibration-freeze-publication.json":
        errors.append("external_anchor_path_invalid")
    if int(external.get("size_bytes", -1)) != FREEZE_PUBLICATION_PATH.stat().st_size:
        errors.append("external_anchor_size_mismatch")
    try:
        published = parse_time(str(publication["published_at"]))
        custody_created = parse_time(str(external["custody_created_at"]))
        anchored = parse_time(str(anchor["anchored_at"]))
        clock = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if custody_created < published:
            errors.append("external_custody_before_freeze_publication")
        if anchored < custody_created:
            errors.append("anchor_record_before_external_custody")
        if anchored > clock + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            errors.append("external_anchor_in_future")
    except (KeyError, TypeError, ValueError):
        errors.append("external_anchor_timestamp_invalid")
    return {"valid": not errors, "errors": errors}


def write_calibration_bundle() -> dict[str, Any]:
    scenario = load_json(SCENARIO_PATH)
    evidence = build_calibration_evidence(scenario)
    thresholds = calibrate_thresholds(scenario, evidence)
    profile = build_calibration_profile(scenario, evidence, thresholds)
    publication = build_freeze_publication(scenario, evidence, thresholds, profile)
    write_json(CALIBRATION_EVIDENCE_PATH, evidence)
    write_json(THRESHOLDS_PATH, thresholds)
    write_json(CALIBRATION_PROFILE_PATH, profile)
    write_json(FREEZE_PUBLICATION_PATH, publication)
    FREEZE_ANCHOR_PATH.unlink(missing_ok=True)
    return {
        "calibration_evidence": evidence,
        "thresholds": thresholds,
        "calibration_profile": profile,
        "freeze_publication": publication,
    }


def verify_frozen_calibration() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    scenario = load_json(SCENARIO_PATH)
    evidence = load_json(CALIBRATION_EVIDENCE_PATH)
    thresholds = load_json(THRESHOLDS_PATH)
    profile = load_json(CALIBRATION_PROFILE_PATH)
    publication = load_json(FREEZE_PUBLICATION_PATH)
    if not FREEZE_ANCHOR_PATH.is_file():
        raise RuntimeError(
            "external calibration anchor missing: deposit the freeze publication outside the repository before held-out evaluation"
        )
    anchor = load_json(FREEZE_ANCHOR_PATH)

    expected_evidence = build_calibration_evidence(scenario)
    expected_thresholds = calibrate_thresholds(scenario, expected_evidence)
    errors: list[str] = []
    if evidence != expected_evidence:
        errors.append("clean_calibration_evidence_reproduction_mismatch")
    if thresholds != expected_thresholds:
        errors.append("threshold_reproduction_mismatch")
    errors.extend(verify_profile(profile, scenario, evidence, thresholds)["errors"])
    errors.extend(verify_publication(publication, profile, evidence, thresholds)["errors"])
    errors.extend(verify_external_anchor(anchor, publication, profile, thresholds, evidence)["errors"])
    if errors:
        raise RuntimeError(f"frozen calibration invalid: {sorted(set(errors))}")
    return evidence, thresholds, profile, publication, anchor
