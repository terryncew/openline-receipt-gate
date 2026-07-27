#!/usr/bin/env python3
"""Independent verifier for the warning-time calibration and held-out report.

This script deliberately does not import the calibration, fixture, metric, or
benchmark runner modules. It independently parses artifacts, recomputes the
observable-state features and metric formulas, verifies signatures, checks the
external-custody chronology, and recomputes held-out counts.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "warning_time"
RESULTS = BENCH / "results"
METRICS = ("kappa_micros", "delta_hol_micros", "vkd_micros")
CASES = ("control", "dropped_counterevidence", "unflagged_contradiction")
MAX_FUTURE_SKEW_SECONDS = 300
EXPECTED_EXTERNAL_ANCHOR_PUBLIC_KEY = "b42a57cd7505596299c16e281d87ccf1963dfafce80f95c7793994617d4cc151"
EXPECTED_EXTERNAL_ANCHOR_PAYLOAD_HASH = "2d515119634f4252031488381b08e6ef9c53f0571460af2eee5a09871b2d5433"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def canonical(value: Any) -> bytes:
    def validate(item: Any, path: str = "$") -> None:
        if item is None or isinstance(item, (str, bool)):
            return
        if isinstance(item, int) and not isinstance(item, bool):
            if abs(item) > (1 << 53) - 1:
                raise ValueError(f"{path}: integer outside canonical range")
            return
        if isinstance(item, float):
            raise ValueError(f"{path}: floats forbidden")
        if isinstance(item, list):
            for index, child in enumerate(item):
                validate(child, f"{path}[{index}]")
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str) or not key.isascii():
                    raise ValueError(f"{path}: invalid key")
                validate(child, f"{path}.{key}")
            return
        raise ValueError(f"{path}: unsupported {type(item).__name__}")

    validate(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def hash_json(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone missing")
    return parsed.astimezone(timezone.utc)


def verify_signed(value: Mapping[str, Any]) -> tuple[bool, str | None]:
    try:
        body = dict(value)
        signature = body.pop("signature")
        payload_hash = body.pop("payload_hash")
        encoded = canonical(body)
        if hashlib.sha256(encoded).hexdigest() != payload_hash:
            return False, "payload_hash_mismatch"
        if signature.get("algorithm") != "Ed25519":
            return False, "signature_algorithm_invalid"
        public = bytes.fromhex(str(signature["public_key"]))
        signed = bytes.fromhex(str(signature["value"]))
        if len(public) != 32 or len(signed) != 64:
            return False, "signature_encoding_invalid"
        Ed25519PublicKey.from_public_bytes(public).verify(signed, encoded)
        return True, None
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False, "signature_invalid"


def jitter(seed: int, step: int, channel: int) -> int:
    digest = hashlib.sha256(f"{seed}:{step}:{channel}".encode("ascii")).digest()
    return int.from_bytes(digest[:2], "big") % 8001 - 4000


def constraint_conflicts(observation: Mapping[str, Any]) -> int:
    active = {
        str(item.get("slot")): item
        for item in observation.get("constraints", [])
        if item.get("active") is True
    }
    flagged = {
        (str(item.get("claim_id")), str(item.get("constraint_id")))
        for item in observation.get("flagged_contradictions", [])
    }
    count = 0
    for claim in observation.get("claims", []):
        constraint = active.get(str(claim.get("slot")))
        if constraint is None:
            continue
        operator = constraint.get("operator")
        claim_value = claim.get("value")
        constraint_value = constraint.get("value")
        conflict = (
            operator == "equals" and claim_value != constraint_value
        ) or (
            operator == "lte"
            and isinstance(claim_value, int)
            and isinstance(constraint_value, int)
            and claim_value > constraint_value
        )
        pair = (str(claim.get("id")), str(constraint.get("id")))
        if conflict and pair not in flagged:
            count += 1
    return count


def features(
    observation: Mapping[str, Any],
    previous: Mapping[str, Any] | None,
) -> dict[str, int]:
    evidence_ids = set(str(key) for key in observation.get("evidence", {}))
    required_ids = set(str(value) for value in observation.get("required_evidence_ids", []))
    claim_refs = {
        str(ref)
        for claim in observation.get("claims", [])
        if claim.get("material") is True
        for ref in claim.get("evidence_refs", [])
    }
    previous_evidence: set[str] = set()
    previous_claims: set[str] = set()
    if previous is not None:
        previous_evidence = set(str(key) for key in previous.get("evidence", {}))
        previous_claims = {str(item.get("id")) for item in previous.get("claims", [])}
    current_claims = {str(item.get("id")) for item in observation.get("claims", [])}
    return {
        "missing_required_evidence": len(required_ids - evidence_ids),
        "orphaned_material_references": len(claim_refs - evidence_ids),
        "unflagged_constraint_conflicts": constraint_conflicts(observation),
        "evidence_edges_lost": len(previous_evidence - evidence_ids),
        "claim_nodes_added": len(current_claims - previous_claims),
    }


def metrics(seed: int, step: int, observed: Mapping[str, Any], previous: Mapping[str, Any] | None) -> dict[str, int]:
    item = features(observed, previous)
    missing = item["missing_required_evidence"]
    orphaned = item["orphaned_material_references"]
    conflicts = item["unflagged_constraint_conflicts"]
    lost = item["evidence_edges_lost"]
    added = item["claim_nodes_added"]
    return {
        "kappa_micros": 96_000 + jitter(seed, step, 1) + 88_000 * missing + 64_000 * orphaned + 132_000 * conflicts + 48_000 * lost + 2_000 * added,
        "delta_hol_micros": 61_000 + jitter(seed, step, 2) + 74_000 * missing + 58_000 * orphaned + 121_000 * conflicts + 72_000 * lost + 3_000 * added,
        "vkd_micros": 44_000 + jitter(seed, step, 3) + 126_000 * missing + 91_000 * orphaned + 103_000 * conflicts + 51_000 * lost + 1_000 * added,
    }


def metric_source_boundary(errors: list[str]) -> dict[str, Any]:
    source = (BENCH / "metric_proxies.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    parameters: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "metrics_for_observation":
            parameters = [argument.arg for argument in node.args.args]
            break
    forbidden = sorted(set(parameters) & {"case", "corruption", "injection_step", "bad_action", "expected_outcome"})
    if parameters != ["seed", "step", "observation", "previous_observation"]:
        errors.append("metric_function_signature_changed")
    if forbidden:
        errors.append("metric_function_accepts_ground_truth_label")
    return {"parameters": parameters, "forbidden": forbidden}


def verify_calibration(
    scenario: Mapping[str, Any],
    evidence: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    errors: list[str],
) -> None:
    expected_seeds = [int(seed) for seed in scenario["calibration_seeds"]]
    if [int(run["seed"]) for run in evidence.get("runs", [])] != expected_seeds:
        errors.append("calibration_seed_order_mismatch")
    if evidence.get("run_count") != len(expected_seeds):
        errors.append("calibration_run_count_mismatch")
    if evidence.get("corrupted_runs_used") is not False:
        errors.append("calibration_used_corrupted_runs")
    if evidence.get("heldout_runs_used") is not False:
        errors.append("calibration_used_heldout_runs")

    all_values: dict[str, list[int]] = {metric: [] for metric in METRICS}
    for run in evidence.get("runs", []):
        previous = None
        trace = run.get("trace", [])
        recalculated_maxima = {metric: -1 for metric in METRICS}
        for row in trace:
            observed = row["observable_state"]
            expected_features = features(observed, previous)
            expected_metrics = metrics(int(run["seed"]), int(row["step"]), observed, previous)
            if row.get("observable_features") != expected_features:
                errors.append(f"calibration_feature_mismatch:{run['seed']}:{row['step']}")
            if row.get("metrics") != expected_metrics:
                errors.append(f"calibration_metric_mismatch:{run['seed']}:{row['step']}")
            if any(expected_features[key] != 0 for key in (
                "missing_required_evidence",
                "orphaned_material_references",
                "unflagged_constraint_conflicts",
                "evidence_edges_lost",
            )):
                errors.append(f"calibration_trace_not_clean:{run['seed']}:{row['step']}")
            for metric in METRICS:
                value = int(expected_metrics[metric])
                all_values[metric].append(value)
                recalculated_maxima[metric] = max(recalculated_maxima[metric], value)
            previous = observed
        if run.get("trace_hash") != hash_json(trace):
            errors.append(f"calibration_trace_hash_mismatch:{run['seed']}")
        if run.get("maxima_micros") != recalculated_maxima:
            errors.append(f"calibration_maxima_mismatch:{run['seed']}")

    ranges = {
        metric: {
            "minimum": min(values),
            "maximum": max(values),
            "range": max(values) - min(values),
        }
        for metric, values in all_values.items()
    }
    if evidence.get("clean_value_ranges_micros") != ranges:
        errors.append("calibration_ranges_mismatch")
    evidence_body = dict(evidence)
    evidence_hash = evidence_body.pop("evidence_hash", None)
    if evidence_hash != hash_json(evidence_body):
        errors.append("calibration_evidence_hash_mismatch")

    margins = {metric: max(1, 2 * int(ranges[metric]["range"])) for metric in METRICS}
    threshold_values = {
        metric: int(ranges[metric]["maximum"]) + margins[metric]
        for metric in METRICS
    }
    if thresholds.get("thresholds_micros") != threshold_values:
        errors.append("threshold_values_mismatch")
    if thresholds.get("margins_micros") != margins:
        errors.append("threshold_margins_mismatch")
    if thresholds.get("calibration_evidence_hash") != evidence.get("evidence_hash"):
        errors.append("threshold_evidence_binding_mismatch")
    if thresholds.get("corrupted_runs_used_for_calibration") is not False:
        errors.append("thresholds_used_corrupted_runs")
    if thresholds.get("heldout_runs_used_for_calibration") is not False:
        errors.append("thresholds_used_heldout_runs")
    threshold_body = dict(thresholds)
    threshold_hash = threshold_body.pop("thresholds_hash", None)
    if threshold_hash != hash_json(threshold_body):
        errors.append("thresholds_hash_mismatch")


def expected_gate_decision(trajectory: Sequence[Mapping[str, Any]], handoff_step: int) -> str:
    state = trajectory[handoff_step - 1]["observable_state"]
    observed_features = features(state, trajectory[handoff_step - 2]["observable_state"] if handoff_step > 1 else None)
    if observed_features["missing_required_evidence"] > 0:
        return "QUARANTINE"
    if observed_features["unflagged_constraint_conflicts"] > 0:
        return "DENY"
    return "COMMIT"


def first_warning(trajectory: Sequence[Mapping[str, Any]], thresholds: Mapping[str, int]) -> tuple[int | None, dict[str, int | None]]:
    by_metric: dict[str, int | None] = {metric: None for metric in METRICS}
    for row in trajectory:
        for metric in METRICS:
            if int(row["metrics"][metric]) >= int(thresholds[metric]) and by_metric[metric] is None:
                by_metric[metric] = int(row["step"])
    values = [value for value in by_metric.values() if value is not None]
    return (min(values) if values else None), by_metric


def verify_heldout(
    scenario: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    errors: list[str],
) -> dict[str, Any]:
    paired = [int(seed) for seed in scenario["heldout_seeds"]["control"]]
    for case in CASES:
        if [int(seed) for seed in scenario["heldout_seeds"][case]] != paired:
            errors.append(f"heldout_not_paired:{case}")
    if len(rows) != 60:
        errors.append("heldout_row_count_mismatch")

    false_alarms = 0
    misses = 0
    no_advance = 0
    prevented = 0
    decisions: dict[str, Counter[str]] = {case: Counter() for case in CASES}
    warning_distributions: dict[str, list[int]] = {case: [] for case in CASES if case != "control"}

    for item in rows:
        case = str(item["case"])
        seed = int(item["seed"])
        if case not in CASES:
            errors.append(f"unknown_heldout_case:{case}")
            continue
        if seed not in paired:
            errors.append(f"heldout_seed_outside_partition:{case}:{seed}")
        trajectory = item.get("trajectory", [])
        if len(trajectory) != len(scenario["steps"]):
            errors.append(f"trajectory_length_mismatch:{case}:{seed}")
            continue
        previous = None
        for row in trajectory:
            observed = row["observable_state"]
            expected_features = features(observed, previous)
            expected_metrics = metrics(seed, int(row["step"]), observed, previous)
            if row.get("observable_features") != expected_features:
                errors.append(f"heldout_feature_mismatch:{case}:{seed}:{row['step']}")
            if row.get("metrics") != expected_metrics:
                errors.append(f"heldout_metric_mismatch:{case}:{seed}:{row['step']}")
            crossed = sorted(
                metric for metric in METRICS
                if int(expected_metrics[metric]) >= int(thresholds["thresholds_micros"][metric])
            )
            if row.get("thresholds_crossed") != crossed:
                errors.append(f"heldout_crossing_mismatch:{case}:{seed}:{row['step']}")
            if row.get("observable_state_hash") != hash_json(observed):
                errors.append(f"heldout_state_hash_mismatch:{case}:{seed}:{row['step']}")
            previous = observed

        warning_step, by_metric = first_warning(trajectory, thresholds["thresholds_micros"])
        bad_action = int(scenario["bad_action_step"])
        warning_time = bad_action - warning_step if warning_step is not None else None
        if item.get("first_warning_step") != warning_step:
            errors.append(f"first_warning_mismatch:{case}:{seed}")
        if item.get("first_crossing_by_metric") != by_metric:
            errors.append(f"metric_crossing_mismatch:{case}:{seed}")
        if item.get("warning_time_steps") != warning_time:
            errors.append(f"warning_time_mismatch:{case}:{seed}")

        expected_final = expected_gate_decision(trajectory, int(scenario["handoff_steps"][-1]))
        if item.get("final_gate_decision") != expected_final:
            errors.append(f"gate_decision_mismatch:{case}:{seed}")
        decisions[case][expected_final] += 1

        for receipt in item.get("decision_receipts", []):
            valid, reason = verify_signed(receipt)
            if not valid:
                errors.append(f"decision_receipt_invalid:{case}:{seed}:{reason}")
        receipt_hashes = [receipt.get("payload_hash") for receipt in item.get("decision_receipts", [])]
        gate_hashes = [event.get("decision_receipt_hash") for event in item.get("gate_trace", [])]
        if receipt_hashes != gate_hashes:
            errors.append(f"gate_receipt_binding_mismatch:{case}:{seed}")

        if case == "control":
            false_alarm = warning_step is not None
            false_alarms += int(false_alarm)
            if item.get("clean_run_false_alarm") != false_alarm:
                errors.append(f"false_alarm_flag_mismatch:{seed}")
        else:
            missed = warning_step is None or warning_time is None or warning_time < 0
            no_advance_item = warning_time is None or warning_time <= 0
            misses += int(missed)
            no_advance += int(no_advance_item)
            if warning_time is not None:
                warning_distributions[case].append(warning_time)
            if item.get("missed_corruption") != missed:
                errors.append(f"miss_flag_mismatch:{case}:{seed}")
            if item.get("no_advance_warning") != no_advance_item:
                errors.append(f"no_advance_flag_mismatch:{case}:{seed}")
            gate_step = item.get("gate_intervention_step")
            was_prevented = (
                isinstance(gate_step, int)
                and gate_step < bad_action
                and expected_final in {"QUARANTINE", "DENY"}
            )
            prevented += int(was_prevented)
            if item.get("bad_action_prevented_in_enforcement") != was_prevented:
                errors.append(f"enforcement_flag_mismatch:{case}:{seed}")

    return {
        "heldout_clean_run_false_alarms": false_alarms,
        "heldout_clean_runs_evaluated": len(paired),
        "missed_corruptions": misses,
        "no_advance_warning_corruptions": no_advance,
        "heldout_corruption_runs": len(paired) * 2,
        "prevented_bad_actions_in_enforcement": prevented,
        "final_decision_counts": {
            case: dict(sorted(counter.items())) for case, counter in decisions.items()
        },
    }


def main() -> int:
    errors: list[str] = []
    scenario = load_json(BENCH / "scenario.json")
    evidence = load_json(BENCH / "calibration-evidence.json")
    thresholds = load_json(BENCH / "thresholds.json")
    profile = load_json(BENCH / "calibration-profile.json")
    publication = load_json(BENCH / "calibration-freeze-publication.json")
    anchor = load_json(BENCH / "calibration-freeze-anchor.json")
    report = load_json(RESULTS / "benchmark_report.json")
    heldout_rows = load_jsonl(RESULTS / "heldout_results.jsonl")

    source_boundary = metric_source_boundary(errors)
    verify_calibration(scenario, evidence, thresholds, errors)

    for label, signed in (("profile", profile), ("publication", publication), ("anchor", anchor)):
        valid, reason = verify_signed(signed)
        if not valid:
            errors.append(f"{label}_signature_invalid:{reason}")
    if anchor.get("signature", {}).get("public_key") != EXPECTED_EXTERNAL_ANCHOR_PUBLIC_KEY:
        errors.append("anchor_signer_key_mismatch")
    if anchor.get("payload_hash") != EXPECTED_EXTERNAL_ANCHOR_PAYLOAD_HASH:
        errors.append("anchor_payload_not_receiver_approved")

    if profile.get("calibration", {}).get("calibration_evidence_hash") != evidence.get("evidence_hash"):
        errors.append("profile_evidence_binding_mismatch")
    if profile.get("calibration", {}).get("thresholds_hash") != thresholds.get("thresholds_hash"):
        errors.append("profile_threshold_binding_mismatch")
    if profile.get("metrics", {}).get("source_sha256") != file_hash(BENCH / "metric_proxies.py"):
        errors.append("profile_metric_source_hash_mismatch")
    if profile.get("metrics", {}).get("observable_fixture_source_sha256") != file_hash(BENCH / "observable_fixture.py"):
        errors.append("profile_observable_source_hash_mismatch")
    if publication.get("profile_payload_hash") != profile.get("payload_hash"):
        errors.append("publication_profile_binding_mismatch")
    if publication.get("thresholds_hash") != thresholds.get("thresholds_hash"):
        errors.append("publication_threshold_binding_mismatch")
    if anchor.get("publication_payload_hash") != publication.get("payload_hash"):
        errors.append("anchor_publication_binding_mismatch")
    if anchor.get("publication_file_sha256") != file_hash(BENCH / "calibration-freeze-publication.json"):
        errors.append("anchor_publication_file_mismatch")
    if anchor.get("profile_payload_hash") != profile.get("payload_hash"):
        errors.append("anchor_profile_binding_mismatch")

    now = datetime.now(timezone.utc)
    try:
        created = parse_time(str(profile["created_at"]))
        expires = parse_time(str(profile["expires_at"]))
        published = parse_time(str(publication["published_at"]))
        custody_created = parse_time(str(anchor["external_publication"]["custody_created_at"]))
        anchored = parse_time(str(anchor["anchored_at"]))
        evaluation_started = parse_time(str(report["evaluation_started_at"]))
        evaluation_completed = parse_time(str(report["evaluation_completed_at"]))
        if created > now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            errors.append("profile_created_at_in_future")
        if now > expires:
            errors.append("profile_expired")
        if not (created <= published <= custody_created <= anchored < evaluation_started <= evaluation_completed):
            errors.append("freeze_evaluation_chronology_invalid")
        if evaluation_completed > now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            errors.append("evaluation_timestamp_in_future")
    except (KeyError, TypeError, ValueError):
        errors.append("timestamp_parse_failed")

    external = anchor.get("external_publication", {})
    if external.get("service") != "chatgpt_file_library":
        errors.append("external_custody_service_mismatch")
    if external.get("path") != "/OpenLine/Calibration Anchors/warning-time-v4-calibration-freeze-publication.json":
        errors.append("external_custody_path_mismatch")
    if int(external.get("size_bytes", -1)) != (BENCH / "calibration-freeze-publication.json").stat().st_size:
        errors.append("external_custody_size_mismatch")

    aggregate = verify_heldout(scenario, thresholds, heldout_rows, errors)
    if report.get("aggregate") != aggregate:
        errors.append("reported_aggregate_mismatch")

    report_body = dict(report)
    report_hash = report_body.pop("report_hash", None)
    if report_hash != hash_json(report_body):
        errors.append("benchmark_report_hash_mismatch")

    for relative, expected_hash in report.get("artifact_hashes", {}).items():
        path = RESULTS / relative
        if not path.is_file() or file_hash(path) != expected_hash:
            errors.append(f"artifact_hash_mismatch:{relative}")

    probe = load_json(RESULTS / "label_leak_probe.json")
    if probe.get("passed") is not True:
        errors.append("label_leak_probe_failed")
    if probe.get("forbidden_metric_parameters"):
        errors.append("label_leak_probe_forbidden_parameters")
    if probe.get("clean_state_with_corrupt_display_label_first_warning") is not None:
        errors.append("clean_state_warned_under_swapped_label")
    if probe.get("corrupt_state_with_control_display_label_first_warning") is None:
        errors.append("corrupt_state_did_not_warn_under_swapped_label")

    expected_counts = {
        "control": {"COMMIT": 20},
        "dropped_counterevidence": {"QUARANTINE": 20},
        "unflagged_contradiction": {"DENY": 20},
    }
    if aggregate["heldout_clean_run_false_alarms"] != 0:
        errors.append("clean_false_alarms_nonzero")
    if aggregate["missed_corruptions"] != 0:
        errors.append("missed_corruptions_nonzero")
    if aggregate["no_advance_warning_corruptions"] != 0:
        errors.append("no_advance_warning_nonzero")
    if aggregate["final_decision_counts"] != expected_counts:
        errors.append("final_decision_counts_unexpected")

    output = {
        "schema": "openline.warning-time.independent-verification.v4",
        "valid": not errors,
        "errors": sorted(set(errors)),
        "independent_of_benchmark_modules": True,
        "metric_function_boundary": source_boundary,
        "paired_heldout_seeds": True,
        "profile_payload_hash": profile.get("payload_hash"),
        "calibration_evidence_hash": evidence.get("evidence_hash"),
        "thresholds_hash": thresholds.get("thresholds_hash"),
        "freeze_publication_payload_hash": publication.get("payload_hash"),
        "external_anchor_payload_hash": anchor.get("payload_hash"),
        "external_custody_path": external.get("path"),
        "report_hash": report.get("report_hash"),
        "calibration_clean_runs": evidence.get("run_count"),
        "heldout_clean_runs": aggregate["heldout_clean_runs_evaluated"],
        "heldout_corruption_runs": aggregate["heldout_corruption_runs"],
        "clean_false_alarms": aggregate["heldout_clean_run_false_alarms"],
        "missed_corruptions": aggregate["missed_corruptions"],
        "no_advance_warning_corruptions": aggregate["no_advance_warning_corruptions"],
        "final_decision_counts": aggregate["final_decision_counts"],
        "claim_boundary": report.get("claim_boundary"),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
