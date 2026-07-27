#!/usr/bin/env python3
"""Evaluate frozen warning-time thresholds on disjoint held-out runs.

Calibration is generated separately. Held-out evaluation is refused until the
exact calibration publication has been placed in external private custody and the
anchor artifact verifies.
"""

from __future__ import annotations

import argparse
import inspect
import json
import shutil
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median_low
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.warning_time.calibration import (
    CALIBRATION_EVIDENCE_PATH,
    CALIBRATION_PROFILE_PATH,
    FREEZE_ANCHOR_PATH,
    FREEZE_PUBLICATION_PATH,
    METRIC_SOURCE_PATH,
    OBSERVABLE_SOURCE_PATH,
    PROFILE_KEY,
    ROOT,
    SCENARIO_PATH,
    THRESHOLDS_PATH,
    file_hash,
    hash_json,
    iso_now,
    load_json,
    parse_time,
    verify_external_anchor,
    verify_frozen_calibration,
    verify_profile,
    verify_publication,
    write_calibration_bundle,
    write_json,
)
from benchmarks.warning_time.metric_proxies import (
    METRICS,
    metrics_for_observation,
    observable_features,
)
from benchmarks.warning_time.observable_fixture import (
    gate_observation,
    observable_state_for_step,
)
from olp_gate.adapters import TrustStore
from olp_gate.crypto import public_key_hex, sha256_hex
from olp_gate.demo import _agent_receipt, _request, _source_hash
from olp_gate.gateway import evaluate_request, verify_decision_log
from olp_gate.policy import PolicySpec

CASES = ("control", "dropped_counterevidence", "unflagged_contradiction")
FIXED_TIME = datetime(2026, 7, 26, 0, 0, 0, tzinfo=timezone.utc)
SOURCE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("71" * 32))
GATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("72" * 32))
SOURCE_METHOD = "did:example:warning-time-source#key-1"


def _timestamp_for_step(step: int) -> str:
    return (FIXED_TIME + timedelta(seconds=step)).isoformat().replace("+00:00", "Z")


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    temporary.replace(path)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _corruption_for_case(case: str) -> str | None:
    if case == "control":
        return None
    if case not in CASES:
        raise ValueError(f"unsupported case: {case}")
    return case


def build_trajectory(
    case: str,
    scenario: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    *,
    seed: int | None = None,
    display_case: str | None = None,
) -> list[dict[str, Any]]:
    """Build a trajectory from observable state only.

    ``display_case`` changes report metadata for the label-swap falsifier. It
    cannot change the observable state or metric values.
    """

    run_seed = int(seed if seed is not None else scenario["reference_seeds"][case])
    threshold_values = thresholds["thresholds_micros"]
    corruption = _corruption_for_case(case)
    rows: list[dict[str, Any]] = []
    previous: Mapping[str, Any] | None = None
    for item in scenario["steps"]:
        step = int(item["step"])
        state = observable_state_for_step(
            run_seed,
            step,
            corruption=corruption,
            injection_step=int(scenario["injection_step"]),
        )
        features = observable_features(state, previous)
        metrics = metrics_for_observation(run_seed, step, state, previous)
        crossed = sorted(
            metric for metric in METRICS
            if int(metrics[metric]) >= int(threshold_values[metric])
        )
        rows.append({
            "schema": "openline.warning-time.trajectory-step.v4",
            "scenario_id": scenario["scenario_id"],
            "case": display_case or case,
            "seed": run_seed,
            "step": step,
            "timestamp": _timestamp_for_step(step),
            "agent": item["agent"],
            "event": item["event"],
            "observable_state": state,
            "observable_state_hash": hash_json(state),
            "observable_features": features,
            "metrics": metrics,
            "thresholds_crossed": crossed,
            "warning": bool(crossed),
        })
        previous = state
    return rows


def _policy() -> PolicySpec:
    return PolicySpec.from_mapping({
        "policy_id": "benchmark.warning-time.handoff",
        "version": "1",
        "require_trusted_source": True,
        "require_replay_guard": False,
        "require_evidence": True,
        "require_source_bound_evidence": True,
        "required_evidence_ids": ["handoff_record"],
        "evidence_assertions": [
            {"evidence_id": "handoff_record", "path": "counterevidence_present", "op": "equals", "value": True},
            {"evidence_id": "handoff_record", "path": "claim_consistent", "op": "equals", "value": True},
            {"evidence_id": "handoff_record", "path": "required_constraint_preserved", "op": "equals", "value": True},
        ],
        "max_source_age_seconds": None,
        "metadata": {
            "benchmark": "warning_time",
            "receiver_authorization_scope": "handoff_only",
        },
    })


def _trust_store() -> TrustStore:
    return TrustStore.from_mapping({
        "keys": {
            SOURCE_METHOD: {
                "public_key": public_key_hex(SOURCE_KEY),
                "roles": ["source"],
                "independence": "operator",
                "controller": "warning-time-source",
            }
        }
    })


def _gate_trace(
    case: str,
    seed: int,
    scenario: Mapping[str, Any],
    trajectory: Sequence[Mapping[str, Any]],
    output: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    decisions = output / "decision_receipts.jsonl"
    decisions.unlink(missing_ok=True)
    decisions.with_suffix(decisions.suffix + ".lock").unlink(missing_ok=True)
    evidence_dir = output / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    trace: list[dict[str, Any]] = []

    for raw_step in scenario["handoff_steps"]:
        step = int(raw_step)
        row = trajectory[step - 1]
        gate_state = gate_observation(row["observable_state"])
        artifact = evidence_dir / f"handoff-{step:02d}.json"
        artifact.write_text(json.dumps(gate_state, sort_keys=True) + "\n", encoding="utf-8")
        artifact_hash = sha256_hex(artifact.read_bytes())
        action_id = f"{case}-{seed}-handoff-{step}"
        event_time = FIXED_TIME + timedelta(seconds=step)
        source = _agent_receipt(
            key=SOURCE_KEY,
            method=SOURCE_METHOD,
            chain_id=f"warning-time-{case}-{seed}",
            session_id=f"warning-time-{case}-{seed}",
            action_id=action_id,
            action_type="agent_handoff",
            response_hash=artifact_hash,
            timestamp=event_time.isoformat().replace("+00:00", "Z"),
        )
        evidence: list[dict[str, Any]] = []
        if not gate_state["missing_required_evidence_ids"]:
            evidence = [{
                "id": "handoff_record",
                "artifact_path": str(artifact.relative_to(output)),
                "content_hash": artifact_hash,
                "source_commitment_path": "credentialSubject.outcome.response_hash",
                "supports": [action_id],
            }]
        request = _request(
            request_id=f"warning-time-{case}-{seed}-{step}",
            receipt=source,
            binding={
                "run_id": f"warning-time-{case}-{seed}",
                "session_id": f"warning-time-{case}-{seed}",
                "expected_source_hash": _source_hash(source),
            },
            action_type="agent_handoff",
            claim="The next agent may rely on this handoff record.",
            evidence=evidence,
        )
        receipt = evaluate_request(
            request,
            policy=_policy(),
            trust_store=_trust_store(),
            signing_key=GATE_KEY,
            issuer_id="openline-warning-time-gate",
            decision_path=decisions,
            session_ledger=None,
            base_dir=output,
            now=event_time,
        )
        trace.append({
            "schema": "openline.warning-time.gate-event.v4",
            "case": case,
            "seed": seed,
            "step": step,
            "timestamp": _timestamp_for_step(step),
            "mode": "observe_only",
            "verdict": receipt["verdict"],
            "decision": receipt["decision"],
            "decision_receipt_hash": receipt["payload_hash"],
            "reason_codes": receipt["reason_codes"],
            "gate_observation": gate_state,
        })

    verification = verify_decision_log(decisions, [public_key_hex(GATE_KEY)])
    receipt_rows = _read_jsonl(decisions)
    decisions.with_suffix(decisions.suffix + ".lock").unlink(missing_ok=True)
    return trace, verification, receipt_rows


def _first_warning(trajectory: Sequence[Mapping[str, Any]]) -> tuple[int | None, dict[str, int | None]]:
    per_metric: dict[str, int | None] = {metric: None for metric in METRICS}
    for row in trajectory:
        for metric in row["thresholds_crossed"]:
            if per_metric[metric] is None:
                per_metric[metric] = int(row["step"])
    values = [value for value in per_metric.values() if value is not None]
    return (min(values) if values else None), per_metric


def _first_gate_intervention(trace: Sequence[Mapping[str, Any]]) -> int | None:
    for row in trace:
        if row["decision"] != "COMMIT":
            return int(row["step"])
    return None


def _enforcement_trace(
    case: str,
    seed: int,
    observe_trajectory: Sequence[Mapping[str, Any]],
    gate_trace: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    intervention = _first_gate_intervention(gate_trace)
    rows: list[dict[str, Any]] = []
    for row in observe_trajectory:
        step = int(row["step"])
        if intervention is not None and step > intervention:
            break
        rows.append({
            "schema": "openline.warning-time.enforcement-step.v4",
            "case": case,
            "seed": seed,
            "step": step,
            "timestamp": _timestamp_for_step(step),
            "status": "blocked" if intervention == step else "continued",
            "gate_decision": next(
                (event["decision"] for event in gate_trace if int(event["step"]) == step),
                None,
            ),
        })
    return rows


def _case_report(
    case: str,
    seed: int,
    scenario: Mapping[str, Any],
    trajectory: Sequence[Mapping[str, Any]],
    gate_trace: Sequence[Mapping[str, Any]],
    decision_verification: Mapping[str, Any],
) -> dict[str, Any]:
    bad_action_step = int(scenario["bad_action_step"])
    first_warning, per_metric = _first_warning(trajectory)
    gate_step = _first_gate_intervention(gate_trace)
    warning_time = bad_action_step - first_warning if first_warning is not None else None
    gate_lead = bad_action_step - gate_step if gate_step is not None else None
    final_decision = gate_trace[-1]["decision"] if gate_trace else None
    corrupted = case != "control"
    missed = bool(corrupted and (first_warning is None or warning_time is None or warning_time < 0))
    no_advance = bool(corrupted and (warning_time is None or warning_time <= 0))
    false_alarm = bool(not corrupted and first_warning is not None)
    prevented = bool(
        corrupted
        and gate_step is not None
        and gate_step < bad_action_step
        and final_decision in {"QUARANTINE", "DENY"}
    )
    return {
        "schema": "openline.warning-time.case-report.v4",
        "case": case,
        "seed": seed,
        "partition": "heldout",
        "corruption_injected": corrupted,
        "injection_step": int(scenario["injection_step"]) if corrupted else None,
        "bad_action_step": bad_action_step,
        "bad_action_timestamp": _timestamp_for_step(bad_action_step),
        "first_warning_step": first_warning,
        "first_warning_timestamp": _timestamp_for_step(first_warning) if first_warning is not None else None,
        "first_crossing_by_metric": per_metric,
        "warning_time_steps": warning_time,
        "warning_time_interpretation": (
            "positive_advance_warning" if warning_time is not None and warning_time > 0
            else "noticed_at_failure" if warning_time == 0
            else "late_warning" if warning_time is not None and warning_time < 0
            else "no_warning"
        ),
        "gate_intervention_step": gate_step,
        "gate_intervention_timestamp": _timestamp_for_step(gate_step) if gate_step is not None else None,
        "gate_lead_time_steps": gate_lead,
        "clean_run_false_alarm": false_alarm,
        "missed_corruption": missed,
        "no_advance_warning": no_advance,
        "final_gate_decision": final_decision,
        "bad_action_reached_in_observe_only": corrupted,
        "hypothetical_action_step_reached_in_observe_only": True,
        "bad_action_prevented_in_enforcement": prevented,
        "decision_log_valid": decision_verification.get("valid") is True,
    }


def _evaluate_case(
    case: str,
    seed: int,
    scenario: Mapping[str, Any],
    thresholds: Mapping[str, Any],
    output: Path,
    *,
    write_artifacts: bool,
    include_trace_in_result: bool,
) -> dict[str, Any]:
    trajectory = build_trajectory(case, scenario, thresholds, seed=seed)
    gate_trace, verification, decision_receipts = _gate_trace(case, seed, scenario, trajectory, output)
    enforcement = _enforcement_trace(case, seed, trajectory, gate_trace)
    report = _case_report(case, seed, scenario, trajectory, gate_trace, verification)
    if write_artifacts:
        metric_trace = [
            {
                "schema": "openline.warning-time.metric-event.v4",
                "case": case,
                "seed": seed,
                "step": row["step"],
                "timestamp": row["timestamp"],
                "observable_state_hash": row["observable_state_hash"],
                "observable_features": row["observable_features"],
                **row["metrics"],
                "thresholds_crossed": row["thresholds_crossed"],
            }
            for row in trajectory
        ]
        _write_jsonl(output / "trajectory.jsonl", trajectory)
        _write_jsonl(output / "metric_trace.jsonl", metric_trace)
        _write_jsonl(output / "gate_trace.jsonl", gate_trace)
        _write_jsonl(output / "enforcement_trace.jsonl", enforcement)
        write_json(output / "case_report.json", report)
    if include_trace_in_result:
        return {
            **report,
            "trajectory": trajectory,
            "gate_trace": gate_trace,
            "decision_receipts": decision_receipts,
        }
    return report


def _warning_distribution(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    values = sorted(
        int(row["warning_time_steps"])
        for row in rows
        if row.get("warning_time_steps") is not None
    )
    return {
        "count": len(values),
        "minimum_steps": min(values) if values else None,
        "median_low_steps": median_low(values) if values else None,
        "maximum_steps": max(values) if values else None,
        "counts": {str(key): value for key, value in sorted(Counter(values).items())},
    }


def label_leak_probe(scenario: Mapping[str, Any], thresholds: Mapping[str, Any]) -> dict[str, Any]:
    seed = 9901
    clean = build_trajectory(
        "control",
        scenario,
        thresholds,
        seed=seed,
        display_case="dropped_counterevidence",
    )
    corrupt = build_trajectory(
        "dropped_counterevidence",
        scenario,
        thresholds,
        seed=seed,
        display_case="control",
    )
    clean_warning, _ = _first_warning(clean)
    corrupt_warning, _ = _first_warning(corrupt)
    injection_index = int(scenario["injection_step"]) - 1
    same_pre_injection = all(
        clean[index]["metrics"] == corrupt[index]["metrics"]
        and clean[index]["observable_state_hash"] == corrupt[index]["observable_state_hash"]
        for index in range(injection_index)
    )
    metric_parameters = list(inspect.signature(metrics_for_observation).parameters)
    forbidden = {"case", "corruption", "injection_step", "bad_action", "expected_outcome"}
    forbidden_parameters = sorted(forbidden & set(metric_parameters))
    return {
        "schema": "openline.warning-time.label-leak-probe.v2",
        "seed": seed,
        "metric_function_parameters": metric_parameters,
        "forbidden_metric_parameters": forbidden_parameters,
        "clean_state_with_corrupt_display_label_first_warning": clean_warning,
        "corrupt_state_with_control_display_label_first_warning": corrupt_warning,
        "pre_injection_observations_and_metrics_identical": same_pre_injection,
        "passed": (
            not forbidden_parameters
            and clean_warning is None
            and corrupt_warning is not None
            and same_pre_injection
        ),
        "interpretation": (
            "Swapping report labels does not change metrics. Only the observable state mutation changes the warning result."
        ),
    }


def run_benchmark(output_dir: str | Path) -> dict[str, Any]:
    evidence, thresholds, profile, publication, anchor = verify_frozen_calibration()
    scenario = load_json(SCENARIO_PATH)
    evaluation_started_at = iso_now()
    if parse_time(evaluation_started_at) <= parse_time(
        str(anchor["external_publication"]["custody_created_at"])
    ):
        raise RuntimeError("held-out evaluation did not begin after the external custody calibration anchor")

    output = Path(output_dir)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    for path in (
        CALIBRATION_PROFILE_PATH,
        CALIBRATION_EVIDENCE_PATH,
        THRESHOLDS_PATH,
        FREEZE_PUBLICATION_PATH,
        FREEZE_ANCHOR_PATH,
    ):
        shutil.copy2(path, output / path.name)

    profile_result = verify_profile(profile, scenario, evidence, thresholds)
    publication_result = verify_publication(publication, profile, evidence, thresholds)
    anchor_result = verify_external_anchor(anchor, publication, profile, thresholds, evidence)

    reference_cases: dict[str, dict[str, Any]] = {}
    artifact_hashes: dict[str, str] = {}
    for case in CASES:
        case_dir = output / case
        case_dir.mkdir(parents=True)
        seed = int(scenario["reference_seeds"][case])
        reference_cases[case] = _evaluate_case(
            case,
            seed,
            scenario,
            thresholds,
            case_dir,
            write_artifacts=True,
            include_trace_in_result=False,
        )
        for path in sorted(case_dir.rglob("*")):
            if path.is_file() and not path.name.endswith(".lock"):
                artifact_hashes[str(path.relative_to(output))] = file_hash(path)

    heldout_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="warning-time-heldout-") as temporary:
        temp_root = Path(temporary)
        for case in CASES:
            for raw_seed in scenario["heldout_seeds"][case]:
                seed = int(raw_seed)
                run_dir = temp_root / case / str(seed)
                run_dir.mkdir(parents=True)
                heldout_rows.append(_evaluate_case(
                    case,
                    seed,
                    scenario,
                    thresholds,
                    run_dir,
                    write_artifacts=False,
                    include_trace_in_result=True,
                ))
    _write_jsonl(output / "heldout_results.jsonl", heldout_rows)
    artifact_hashes["heldout_results.jsonl"] = file_hash(output / "heldout_results.jsonl")

    probe = label_leak_probe(scenario, thresholds)
    write_json(output / "label_leak_probe.json", probe)
    artifact_hashes["label_leak_probe.json"] = file_hash(output / "label_leak_probe.json")

    by_case = {case: [row for row in heldout_rows if row["case"] == case] for case in CASES}
    clean_false_alarms = sum(1 for row in by_case["control"] if row["clean_run_false_alarm"])
    missed_corruptions = sum(
        1
        for case in CASES
        if case != "control"
        for row in by_case[case]
        if row["missed_corruption"]
    )
    no_advance_warning = sum(
        1
        for case in CASES
        if case != "control"
        for row in by_case[case]
        if row["no_advance_warning"]
    )
    final_decision_counts = {
        case: dict(sorted(Counter(str(row["final_gate_decision"]) for row in rows).items()))
        for case, rows in by_case.items()
    }
    report_body = {
        "schema": "openline.warning-time.benchmark-report.v4",
        "scenario_id": scenario["scenario_id"],
        "agent_stack_id": scenario["agent_stack_id"],
        "evaluation_started_at": evaluation_started_at,
        "evaluation_completed_at": iso_now(),
        "calibration_profile_payload_hash": profile["payload_hash"],
        "calibration_profile_signature_valid": profile_result["valid"],
        "calibration_profile_fresh": "profile_expired" not in profile_result["errors"],
        "calibration_evidence_hash": evidence["evidence_hash"],
        "thresholds_hash": thresholds["thresholds_hash"],
        "freeze_publication_payload_hash": publication["payload_hash"],
        "freeze_publication_signature_valid": publication_result["valid"],
        "external_freeze_anchor_payload_hash": anchor["payload_hash"],
        "external_freeze_anchor_valid": anchor_result["valid"],
        "external_freeze_anchor": {**anchor["external_publication"], "visibility": "private_user_library"},
        "thresholds_frozen_before_heldout_runs": thresholds["frozen_before_heldout_runs"],
        "thresholds_used_corrupted_runs": thresholds["corrupted_runs_used_for_calibration"],
        "thresholds_used_heldout_runs": thresholds["heldout_runs_used_for_calibration"],
        "metric_input_boundary": profile["metrics"]["input_boundary"],
        "paired_heldout_seeds": (
            bool(scenario.get("paired_heldout_design"))
            and all(
                scenario["heldout_seeds"][case] == scenario["heldout_seeds"]["control"]
                for case in CASES
            )
        ),
        "label_leak_probe": probe,
        "formula": "warning_time_steps = bad_action_step - first_warning_step",
        "reference_cases": reference_cases,
        "heldout": {
            "calibration_clean_runs": evidence["run_count"],
            "clean_runs": len(by_case["control"]),
            "corruption_runs_by_case": {
                case: len(by_case[case]) for case in CASES if case != "control"
            },
            "total_runs": int(evidence["run_count"]) + len(heldout_rows),
            "sample_size_boundary": scenario["sample_size_note"],
            "warning_time_distribution": {
                case: _warning_distribution(by_case[case])
                for case in CASES
                if case != "control"
            },
        },
        "aggregate": {
            "heldout_clean_run_false_alarms": clean_false_alarms,
            "heldout_clean_runs_evaluated": len(by_case["control"]),
            "missed_corruptions": missed_corruptions,
            "no_advance_warning_corruptions": no_advance_warning,
            "heldout_corruption_runs": sum(
                len(by_case[case]) for case in CASES if case != "control"
            ),
            "prevented_bad_actions_in_enforcement": sum(
                1
                for case in CASES
                if case != "control"
                for row in by_case[case]
                if row["bad_action_prevented_in_enforcement"]
            ),
            "final_decision_counts": final_decision_counts,
        },
        "gate_public_key": public_key_hex(GATE_KEY),
        "calibration_profile_public_key": public_key_hex(PROFILE_KEY),
        "metric_source_sha256": file_hash(METRIC_SOURCE_PATH),
        "observable_fixture_source_sha256": file_hash(OBSERVABLE_SOURCE_PATH),
        "artifact_hashes": dict(sorted(artifact_hashes.items())),
        "interpretation": (
            "Held-out separation shows that this disclosed observable-state representation is useful "
            "for predicting the named failures on this exact synthetic stack. It does not prove the ontology is true."
        ),
        "claim_boundary": scenario["claim_boundary"],
    }
    report = {**report_body, "report_hash": hash_json(report_body)}
    write_json(output / "benchmark_report.json", report)

    lines = [
        "# Warning-Time Held-Out Benchmark Report",
        "",
        f"Scenario: `{scenario['scenario_id']}`",
        f"Calibration profile: `{profile['payload_hash']}`",
        f"External custody anchor: `{anchor['external_publication']['path']}`",
        "",
        "Metrics were derived only from observable current/previous state. The ground-truth case label is not a metric input.",
        "",
        "Thresholds were learned from the clean calibration partition, deposited in external private custody, and then tested on disjoint held-out runs.",
        "",
        "Warning time is `bad-action step - first-warning step`. Positive means advance warning; zero means detection at failure; negative means late detection.",
        "",
        "| Reference case | Seed | First warning | Warning time | Gate intervention | Gate lead | Final decision |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for name in CASES:
        item = reference_cases[name]
        lines.append(
            f"| {name} | {item['seed']} | {item['first_warning_step'] if item['first_warning_step'] is not None else '—'} | "
            f"{item['warning_time_steps'] if item['warning_time_steps'] is not None else '—'} | "
            f"{item['gate_intervention_step'] if item['gate_intervention_step'] is not None else '—'} | "
            f"{item['gate_lead_time_steps'] if item['gate_lead_time_steps'] is not None else '—'} | {item['final_gate_decision']} |"
        )
    lines += [
        "",
        f"Held-out clean false alarms: **{clean_false_alarms}/{len(by_case['control'])}**",
        f"Held-out missed corruptions: **{missed_corruptions}/{report['aggregate']['heldout_corruption_runs']}**",
        f"Held-out corruptions without advance warning: **{no_advance_warning}/{report['aggregate']['heldout_corruption_runs']}**",
        f"Label-leak probe: **{'PASS' if probe['passed'] else 'FAIL'}**",
        "",
        report["interpretation"],
        "",
        scenario["sample_size_note"],
        "",
        scenario["claim_boundary"],
    ]
    (output / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(ROOT / "results"))
    parser.add_argument(
        "--write-calibration",
        action="store_true",
        help="Regenerate clean-only calibration and freeze publication artifacts. This removes any old external anchor.",
    )
    parser.add_argument(
        "--calibrate",
        action="store_true",
        help="Print the current frozen calibration artifacts and exit.",
    )
    args = parser.parse_args()
    if args.write_calibration:
        bundle = write_calibration_bundle()
        print(json.dumps({
            "profile_payload_hash": bundle["calibration_profile"]["payload_hash"],
            "thresholds_hash": bundle["thresholds"]["thresholds_hash"],
            "calibration_evidence_hash": bundle["calibration_evidence"]["evidence_hash"],
            "freeze_publication_payload_hash": bundle["freeze_publication"]["payload_hash"],
            "next_gate": "Deposit the freeze publication in external custody, then add calibration-freeze-anchor.json.",
        }, indent=2, sort_keys=True))
        return 0
    if args.calibrate:
        values = {
            "calibration_evidence": load_json(CALIBRATION_EVIDENCE_PATH),
            "thresholds": load_json(THRESHOLDS_PATH),
            "calibration_profile": load_json(CALIBRATION_PROFILE_PATH),
            "freeze_publication": load_json(FREEZE_PUBLICATION_PATH),
            "freeze_anchor": load_json(FREEZE_ANCHOR_PATH) if FREEZE_ANCHOR_PATH.is_file() else None,
        }
        print(json.dumps(values, indent=2, sort_keys=True))
        return 0
    report = run_benchmark(args.output)
    print(json.dumps({
        "passed": (
            report["aggregate"]["heldout_clean_run_false_alarms"] == 0
            and report["aggregate"]["missed_corruptions"] == 0
            and report["calibration_profile_signature_valid"]
            and report["external_freeze_anchor_valid"]
            and report["label_leak_probe"]["passed"]
        ),
        "profile_payload_hash": report["calibration_profile_payload_hash"],
        "external_anchor_path": report["external_freeze_anchor"]["path"],
        "heldout_clean_false_alarms": report["aggregate"]["heldout_clean_run_false_alarms"],
        "missed_corruptions": report["aggregate"]["missed_corruptions"],
        "reference_warning_times": {
            name: value["warning_time_steps"]
            for name, value in report["reference_cases"].items()
        },
        "label_leak_probe_passed": report["label_leak_probe"]["passed"],
        "report_hash": report["report_hash"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
