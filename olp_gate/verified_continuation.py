"""Frozen three-lane verified-continuation experiment.

The continuation evaluator never runs or grades a model.  It consumes three
recorded, matched execution traces and independently computes only direct
trajectory and terminal-test counts.  A synthetic fixture can prove the
harness works, but it can never earn the continuation claim.

The authorization trial is separate.  It reuses the existing signed
``proof_to_policy_decision_receipt`` and Verified Commit authorization to
permit one exact Git ref update.  Wrong-branch, changed-commit, expired,
replayed, and simultaneous-use attempts are checked before repository
mutation.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import threading
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import public_key_hex, sha256_hex, strict_json_load, strict_json_loads
from .model_swap import run_verified_model_swap, verify_model_swap_output
from .verified_commit import (
    VerifiedCommitError,
    VerifiedCommitLedger,
    execution_action_from_authorization,
    issue_one_use_code,
    parse_timestamp,
    settings_hash,
)


TRIAL_SPEC_SCHEMA = "openline.verified-continuation.trial-spec.v1"
LANE_RESULT_SCHEMA = "openline.verified-continuation.lane-result.v1"
CONTINUATION_REPORT_SCHEMA = "openline.verified-continuation.report.v1"
DSM_PROJECTION_SCHEMA = "openline.verified-continuation.dsm-projection.v1"
BRANCH_AUTHORIZATION_SCHEMA = (
    "openline.verified-continuation.branch-authorization.v1"
)
EXPERIMENT_SUMMARY_SCHEMA = "openline.verified-continuation.summary.v1"
FROZEN_TRIAL_SPEC_HASH = (
    "549bba4c904261cb7513e3e9d618941bc51184e8ec3fe5bc8dd75afe7b67c271"
)

LANE_IDS = ("self_summary", "no_prior_state", "olp_capsule")
INHERITED_STATE_KINDS = {
    "self_summary": "producer_self_summary",
    "no_prior_state": "none",
    "olp_capsule": "half_life_bounded_capsule",
}
TRACE_KINDS = {"search", "read", "edit", "test", "other"}
TRACE_STATUSES = {"ok", "error"}
TEST_STATUSES = {"PASS", "FAIL"}
EVIDENCE_CLASSES = {"synthetic_conformance", "external_reproduction"}
HASH_FIELDS = {
    "producer_history_sha256",
    "receiver_configuration_sha256",
    "repository_checkout_sha256",
    "task_sha256",
    "tool_manifest_sha256",
    "terminal_test_manifest_sha256",
}
CONTROL_KEYS = {
    "receiving_model",
    *HASH_FIELDS,
    "budget",
}
SPEC_KEYS = {
    "schema",
    "trial_id",
    "protocol_version",
    "status",
    "question",
    "lanes",
    "fixed_controls",
    "outcome_blinding",
    "terminal_test_ids",
    "claim_rules",
    "claim_boundary",
}
LANE_KEYS = {
    "schema",
    "trial_id",
    "lane_id",
    "evidence_class",
    "run_id",
    "provider_execution_attested",
    "inherited_state",
    "controls",
    "trace",
    "terminal_tests",
}
TRACE_KEYS = {"step", "kind", "target", "status"}
TERMINAL_TEST_KEYS = {"test_id", "status"}
INHERITED_STATE_KEYS = {"kind", "artifact_sha256"}
BRANCH_TOOL = "git.update_ref"
BRANCH_TARGET = "refs/heads/receiver-approved"
_HEX = frozenset("0123456789abcdef")


class VerifiedContinuationError(ValueError):
    """Raised when a trial input is malformed or cannot be evaluated."""


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _json_hash(value: Any) -> str:
    return sha256_hex(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _require_exact_keys(
    value: Mapping[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        raise VerifiedContinuationError(
            f"{label}_shape_invalid:missing={missing}:unknown={unknown}"
        )


def validate_trial_spec(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise VerifiedContinuationError("trial_spec_not_object")
    spec = dict(value)
    _require_exact_keys(spec, SPEC_KEYS, label="trial_spec")
    if spec.get("schema") != TRIAL_SPEC_SCHEMA:
        raise VerifiedContinuationError("trial_spec_schema_invalid")
    if not isinstance(spec.get("trial_id"), str) or not spec["trial_id"]:
        raise VerifiedContinuationError("trial_id_invalid")
    if (
        not isinstance(spec.get("protocol_version"), int)
        or isinstance(spec.get("protocol_version"), bool)
        or spec.get("protocol_version") != 1
        or spec.get("status") != "FROZEN"
    ):
        raise VerifiedContinuationError("trial_protocol_not_frozen_v1")
    if not isinstance(spec.get("question"), str) or not spec["question"]:
        raise VerifiedContinuationError("trial_question_invalid")
    lanes = spec.get("lanes")
    if lanes != list(LANE_IDS):
        raise VerifiedContinuationError("trial_lanes_invalid")
    fixed_controls = spec.get("fixed_controls")
    if fixed_controls != sorted(CONTROL_KEYS):
        raise VerifiedContinuationError("fixed_controls_invalid")
    outcome_blinding = spec.get("outcome_blinding")
    required_blinding = [
        "completion_status",
        "evaluation_report",
        "final_tests",
        "human_verdict",
    ]
    if outcome_blinding != required_blinding:
        raise VerifiedContinuationError("outcome_blinding_invalid")
    test_ids = spec.get("terminal_test_ids")
    if (
        not isinstance(test_ids, list)
        or not test_ids
        or not all(isinstance(item, str) and item for item in test_ids)
        or len(test_ids) != len(set(test_ids))
    ):
        raise VerifiedContinuationError("terminal_test_ids_invalid")
    claim_rules = spec.get("claim_rules")
    if not isinstance(claim_rules, Mapping) or set(claim_rules) != {
        "authorization",
        "continuation",
    }:
        raise VerifiedContinuationError("claim_rules_invalid")
    for claim in ("authorization", "continuation"):
        rule = claim_rules.get(claim)
        if not isinstance(rule, str) or not rule:
            raise VerifiedContinuationError(f"{claim}_claim_rule_invalid")
    if not isinstance(spec.get("claim_boundary"), str) or not spec["claim_boundary"]:
        raise VerifiedContinuationError("trial_claim_boundary_invalid")
    if _json_hash(spec) != FROZEN_TRIAL_SPEC_HASH:
        raise VerifiedContinuationError("frozen_trial_spec_hash_mismatch")
    return spec


def validate_lane_result(
    value: Mapping[str, Any],
    *,
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise VerifiedContinuationError("lane_result_not_object")
    lane = dict(value)
    _require_exact_keys(lane, LANE_KEYS, label="lane_result")
    if lane.get("schema") != LANE_RESULT_SCHEMA:
        raise VerifiedContinuationError("lane_schema_invalid")
    if lane.get("trial_id") != spec.get("trial_id"):
        raise VerifiedContinuationError("lane_trial_id_mismatch")
    lane_id = lane.get("lane_id")
    if lane_id not in LANE_IDS:
        raise VerifiedContinuationError("lane_id_invalid")
    evidence_class = lane.get("evidence_class")
    if (
        not isinstance(evidence_class, str)
        or evidence_class not in EVIDENCE_CLASSES
    ):
        raise VerifiedContinuationError("lane_evidence_class_invalid")
    if not isinstance(lane.get("run_id"), str) or not lane["run_id"]:
        raise VerifiedContinuationError("lane_run_id_invalid")
    if not isinstance(lane.get("provider_execution_attested"), bool):
        raise VerifiedContinuationError("provider_execution_attested_invalid")

    inherited = lane.get("inherited_state")
    if not isinstance(inherited, Mapping):
        raise VerifiedContinuationError("inherited_state_invalid")
    inherited = dict(inherited)
    _require_exact_keys(
        inherited,
        INHERITED_STATE_KEYS,
        label="inherited_state",
    )
    if inherited.get("kind") != INHERITED_STATE_KINDS[str(lane_id)]:
        raise VerifiedContinuationError("inherited_state_kind_mismatch")
    artifact_hash = inherited.get("artifact_sha256")
    if lane_id == "no_prior_state":
        if artifact_hash is not None:
            raise VerifiedContinuationError("no_state_artifact_must_be_null")
    elif not _is_hash(artifact_hash):
        raise VerifiedContinuationError("inherited_state_hash_invalid")

    controls = lane.get("controls")
    if not isinstance(controls, Mapping):
        raise VerifiedContinuationError("lane_controls_invalid")
    controls = dict(controls)
    _require_exact_keys(controls, CONTROL_KEYS, label="lane_controls")
    if (
        not isinstance(controls.get("receiving_model"), str)
        or not controls["receiving_model"]
    ):
        raise VerifiedContinuationError("receiving_model_invalid")
    for name in HASH_FIELDS:
        if not _is_hash(controls.get(name)):
            raise VerifiedContinuationError(f"{name}_invalid")
    budget = controls.get("budget")
    if not isinstance(budget, Mapping) or set(budget) != {"max_tool_calls"}:
        raise VerifiedContinuationError("budget_shape_invalid")
    max_calls = budget.get("max_tool_calls")
    if (
        not isinstance(max_calls, int)
        or isinstance(max_calls, bool)
        or max_calls <= 0
    ):
        raise VerifiedContinuationError("max_tool_calls_invalid")

    trace = lane.get("trace")
    if not isinstance(trace, list):
        raise VerifiedContinuationError("trace_invalid")
    normalized_trace: list[dict[str, Any]] = []
    for index, raw_event in enumerate(trace, start=1):
        if not isinstance(raw_event, Mapping):
            raise VerifiedContinuationError("trace_event_invalid")
        event = dict(raw_event)
        _require_exact_keys(event, TRACE_KEYS, label="trace_event")
        if (
            not isinstance(event.get("step"), int)
            or isinstance(event.get("step"), bool)
            or event.get("step") != index
        ):
            raise VerifiedContinuationError("trace_steps_not_contiguous")
        event_kind = event.get("kind")
        if not isinstance(event_kind, str) or event_kind not in TRACE_KINDS:
            raise VerifiedContinuationError("trace_kind_invalid")
        if not isinstance(event.get("target"), str) or not event["target"]:
            raise VerifiedContinuationError("trace_target_invalid")
        event_status = event.get("status")
        if (
            not isinstance(event_status, str)
            or event_status not in TRACE_STATUSES
        ):
            raise VerifiedContinuationError("trace_status_invalid")
        normalized_trace.append(event)

    terminal_tests = lane.get("terminal_tests")
    if not isinstance(terminal_tests, list):
        raise VerifiedContinuationError("terminal_tests_invalid")
    expected_test_ids = list(spec["terminal_test_ids"])
    normalized_tests: list[dict[str, str]] = []
    for raw_test in terminal_tests:
        if not isinstance(raw_test, Mapping):
            raise VerifiedContinuationError("terminal_test_invalid")
        test = dict(raw_test)
        _require_exact_keys(test, TERMINAL_TEST_KEYS, label="terminal_test")
        if not isinstance(test.get("test_id"), str) or not test["test_id"]:
            raise VerifiedContinuationError("terminal_test_id_invalid")
        test_status = test.get("status")
        if not isinstance(test_status, str) or test_status not in TEST_STATUSES:
            raise VerifiedContinuationError("terminal_test_status_invalid")
        normalized_tests.append(
            {"test_id": str(test["test_id"]), "status": str(test["status"])}
        )
    if sorted(test["test_id"] for test in normalized_tests) != sorted(
        expected_test_ids
    ):
        raise VerifiedContinuationError("terminal_test_set_mismatch")
    if len(normalized_tests) != len(expected_test_ids):
        raise VerifiedContinuationError("terminal_test_duplicate")

    return {
        **lane,
        "inherited_state": inherited,
        "controls": {**controls, "budget": dict(budget)},
        "trace": normalized_trace,
        "terminal_tests": normalized_tests,
    }


def _trajectory(lane: Mapping[str, Any]) -> tuple[dict[str, int], list[dict[str, Any]]]:
    seen_exploration: set[tuple[str, str]] = set()
    repeated = 0
    errors = 0
    points: list[dict[str, Any]] = []
    for event in lane["trace"]:
        kind = str(event["kind"])
        target = str(event["target"])
        if kind in {"search", "read"}:
            key = (kind, target)
            if key in seen_exploration:
                repeated += 1
            else:
                seen_exploration.add(key)
        if event["status"] == "error":
            errors += 1
        points.append(
            {
                "step": event["step"],
                "tool_calls": event["step"],
                "repeated_exploration": repeated,
                "errors": errors,
            }
        )
    defects = sum(
        test["status"] == "FAIL" for test in lane["terminal_tests"]
    )
    max_calls = lane["controls"]["budget"]["max_tool_calls"]
    return (
        {
            "tool_calls": len(lane["trace"]),
            "repeated_exploration": repeated,
            "trace_errors": errors,
            "terminal_defects": defects,
            "budget_max_tool_calls": max_calls,
            "budget_exceeded": len(lane["trace"]) > max_calls,
        },
        points,
    )


def evaluate_continuation_trial(
    spec_value: Mapping[str, Any],
    lane_values: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Independently evaluate matched lane outputs.

    A synthetic fixture always remains ``UNDECIDABLE``, even if its direct
    counts satisfy the continuation rule.
    """

    spec = validate_trial_spec(spec_value)
    if not isinstance(lane_values, Sequence) or isinstance(
        lane_values,
        (str, bytes, bytearray),
    ):
        raise VerifiedContinuationError("lane_results_not_sequence")
    lanes = [validate_lane_result(value, spec=spec) for value in lane_values]
    if len(lanes) != len(LANE_IDS):
        raise VerifiedContinuationError("exactly_three_lanes_required")
    by_id = {str(lane["lane_id"]): lane for lane in lanes}
    if set(by_id) != set(LANE_IDS) or len(by_id) != len(lanes):
        raise VerifiedContinuationError("lane_set_invalid")
    if len({str(lane["run_id"]) for lane in lanes}) != len(lanes):
        raise VerifiedContinuationError("lane_run_ids_must_differ")

    reference_controls = by_id["self_summary"]["controls"]
    controls_match = all(
        lane["controls"] == reference_controls for lane in lanes
    )
    evidence_classes = {str(lane["evidence_class"]) for lane in lanes}
    execution_attestations = {
        bool(lane["provider_execution_attested"]) for lane in lanes
    }
    outcomes: dict[str, dict[str, Any]] = {}
    trajectories: dict[str, list[dict[str, Any]]] = {}
    for lane_id in LANE_IDS:
        counts, points = _trajectory(by_id[lane_id])
        outcomes[lane_id] = counts
        trajectories[lane_id] = points

    olp = outcomes["olp_capsule"]
    baselines = [outcomes["self_summary"], outcomes["no_prior_state"]]
    noninferior = all(
        olp["repeated_exploration"] <= baseline["repeated_exploration"]
        and olp["terminal_defects"] <= baseline["terminal_defects"]
        for baseline in baselines
    )
    strictly_better_than_each = all(
        olp["repeated_exploration"] < baseline["repeated_exploration"]
        or olp["terminal_defects"] < baseline["terminal_defects"]
        for baseline in baselines
    )
    within_budget = olp["budget_exceeded"] is False
    mechanism_passed = bool(
        controls_match
        and noninferior
        and strictly_better_than_each
        and within_budget
    )
    external_evidence = (
        evidence_classes == {"external_reproduction"}
        and execution_attestations == {True}
    )
    if not controls_match:
        disposition = "INVALID"
        reasons = ["fixed_controls_mismatch"]
    elif not external_evidence:
        disposition = "UNDECIDABLE"
        reasons = ["outside_provider_execution_not_established"]
    elif mechanism_passed:
        disposition = "PASS"
        reasons = []
    else:
        disposition = "FAIL"
        reasons = []
        if not within_budget:
            reasons.append("olp_lane_budget_exceeded")
        if not noninferior:
            reasons.append("olp_lane_inferior_on_direct_outcome")
        if not strictly_better_than_each:
            reasons.append("olp_lane_not_strictly_better_than_each_baseline")

    body = {
        "schema": CONTINUATION_REPORT_SCHEMA,
        "trial_id": spec["trial_id"],
        "question": spec["question"],
        "input_boundary": (
            "recorded observable tool events plus post-run terminal-test statuses; "
            "no model text, judge report, human verdict, or completion label"
        ),
        "controls": {
            "matched": controls_match,
            "fixed_fields": sorted(CONTROL_KEYS),
            "binding_hash": _json_hash(reference_controls),
        },
        "lane_inputs": {
            lane_id: {
                "run_id": by_id[lane_id]["run_id"],
                "evidence_class": by_id[lane_id]["evidence_class"],
                "provider_execution_attested": by_id[lane_id][
                    "provider_execution_attested"
                ],
                "inherited_state_kind": by_id[lane_id]["inherited_state"]["kind"],
                "inherited_state_sha256": by_id[lane_id]["inherited_state"][
                    "artifact_sha256"
                ],
                "lane_result_hash": _json_hash(by_id[lane_id]),
            }
            for lane_id in LANE_IDS
        },
        "outcomes": outcomes,
        "trajectory": trajectories,
        "continuation_claim": {
            "disposition": disposition,
            "mechanism_rule_passed": mechanism_passed,
            "external_evidence_sufficient": external_evidence,
            "noninferior_on_repeated_exploration_and_defects": noninferior,
            "strictly_better_than_each_baseline": strictly_better_than_each,
            "olp_within_budget": within_budget,
            "reason_codes": reasons,
        },
        "authorization_claim": {
            "disposition": "NOT_EVALUATED",
            "reason_codes": ["authorization_is_evaluated_by_verified_commit"],
        },
        "claim_boundary": spec["claim_boundary"],
    }
    return {**body, "report_hash": _json_hash(body)}


def build_dsm_projection(
    report: Mapping[str, Any],
) -> dict[str, Any]:
    if report.get("schema") != CONTINUATION_REPORT_SCHEMA:
        raise VerifiedContinuationError("continuation_report_schema_invalid")
    report_body = dict(report)
    report_hash = report_body.pop("report_hash", None)
    if report_hash != _json_hash(report_body):
        raise VerifiedContinuationError("continuation_report_hash_invalid")
    return {
        "schema": DSM_PROJECTION_SCHEMA,
        "display_only": True,
        "grading_authority": (
            "Receipt Gate independently computed the direct counts; DSM must not "
            "grade or upgrade either claim"
        ),
        "trial_id": report["trial_id"],
        "report_hash": report_hash,
        "controls": report["controls"],
        "lanes": report["trajectory"],
        "direct_outcomes": report["outcomes"],
        "claims": {
            "continuation": report["continuation_claim"],
            "authorization": report["authorization_claim"],
        },
        "coherence_dynamics": {
            "kappa": {
                "status": "UNDECIDABLE",
                "reason": "the frozen trace lacks the authoritative DSM snapshot state",
            },
            "phi_star": {
                "status": "UNDECIDABLE",
                "reason": "the frozen trace lacks the authoritative DSM snapshot state",
            },
            "vkd": {
                "status": "UNDECIDABLE",
                "reason": "the frozen trace lacks the authoritative DSM snapshot state",
            },
        },
        "claim_boundary": (
            "This is an observation projection only. It does not infer scientific "
            "validity, provider execution, continuation quality, or permission."
        ),
    }


def load_and_evaluate_trial(trial_dir: str | Path) -> dict[str, Any]:
    root = Path(trial_dir)
    spec = strict_json_load(root / "trial_spec.json")
    lanes = [
        strict_json_load(root / "lanes" / f"{lane_id}.json")
        for lane_id in LANE_IDS
    ]
    if not isinstance(spec, Mapping) or not all(
        isinstance(lane, Mapping) for lane in lanes
    ):
        raise VerifiedContinuationError("trial_json_root_invalid")
    return evaluate_continuation_trial(spec, lanes)


def write_continuation_outputs(
    trial_dir: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report = load_and_evaluate_trial(trial_dir)
    projection = build_dsm_projection(report)
    _write_json(output / "continuation_report.json", report)
    _write_json(output / "dsm_projection.json", projection)
    return {
        "valid": True,
        "continuation_disposition": report["continuation_claim"]["disposition"],
        "mechanism_rule_passed": report["continuation_claim"][
            "mechanism_rule_passed"
        ],
        "report_hash": report["report_hash"],
        "dsm_metrics": projection["coherence_dynamics"],
        "output_dir": str(output),
    }


def _git(
    repository: Path,
    *arguments: str,
    input_text: str | None = None,
) -> str:
    completed = subprocess.run(
        ["git", f"--git-dir={repository}", *arguments],
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "OpenLine Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@openline.invalid",
            "GIT_COMMITTER_NAME": "OpenLine Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@openline.invalid",
            "GIT_AUTHOR_DATE": "2026-07-28T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-07-28T00:00:00Z",
        },
    )
    if completed.returncode != 0:
        raise VerifiedContinuationError(
            f"git_command_failed:{arguments}:{completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _git_object_graph(repository: Path) -> dict[str, str]:
    base_blob = _git(repository, "hash-object", "-w", "--stdin", input_text="base\n")
    base_tree = _git(
        repository,
        "mktree",
        input_text=f"100644 blob {base_blob}\tstate.txt\n",
    )
    base_commit = _git(
        repository,
        "commit-tree",
        base_tree,
        input_text="base fixture\n",
    )
    approved_blob = _git(
        repository,
        "hash-object",
        "-w",
        "--stdin",
        input_text="approved\n",
    )
    approved_tree = _git(
        repository,
        "mktree",
        input_text=f"100644 blob {approved_blob}\tstate.txt\n",
    )
    approved_commit = _git(
        repository,
        "commit-tree",
        approved_tree,
        "-p",
        base_commit,
        input_text="approved continuation\n",
    )
    mutated_blob = _git(
        repository,
        "hash-object",
        "-w",
        "--stdin",
        input_text="mutated\n",
    )
    mutated_tree = _git(
        repository,
        "mktree",
        input_text=f"100644 blob {mutated_blob}\tstate.txt\n",
    )
    mutated_commit = _git(
        repository,
        "commit-tree",
        mutated_tree,
        "-p",
        base_commit,
        input_text="mutated target\n",
    )
    _git(repository, "update-ref", BRANCH_TARGET, base_commit)
    return {
        "base_commit": base_commit,
        "approved_commit": approved_commit,
        "mutated_commit": mutated_commit,
    }


def _read_ref(repository: Path, ref: str) -> str | None:
    completed = subprocess.run(
        ["git", f"--git-dir={repository}", "rev-parse", "--verify", ref],
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def _deepcopy(value: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(dict(value))


def run_branch_authorization_trial(
    half_life_output: str | Path,
    output_dir: str | Path,
    *,
    succession_policy_public_key_path: str | Path,
    compaction_policy_public_key_path: str | Path,
    source_signing_key: Ed25519PrivateKey,
    grader_signing_key: Ed25519PrivateKey,
    gate_signing_key: Ed25519PrivateKey,
    source_model: str = "fixture/producer-model",
    target_model: str = "fixture/receiving-model",
    trial_id: str = "verified-continuation-authorization",
) -> dict[str, Any]:
    """Prove one exact branch update and pre-effect rejection of mutations."""

    output = Path(output_dir)
    if output.exists() and any(output.iterdir()):
        raise VerifiedContinuationError(
            "refusing_to_overwrite_branch_authorization_output"
        )
    output.mkdir(parents=True, exist_ok=True)
    gate_output = output / "gate"
    callbacks: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix="verified-continuation-git-"
    ) as temporary:
        repository = Path(temporary) / "fixture.git"
        completed = subprocess.run(
            ["git", "init", "--bare", str(repository)],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise VerifiedContinuationError(
                f"git_init_failed:{completed.stderr.strip()}"
            )
        objects = _git_object_graph(repository)
        initial_ref = _read_ref(repository, BRANCH_TARGET)
        action_core = {
            "tool": BRANCH_TOOL,
            "target": BRANCH_TARGET,
            "settings": {
                "expected_old_commit": objects["base_commit"],
                "new_commit": objects["approved_commit"],
                "update_mode": "compare_and_swap",
            },
        }
        code = issue_one_use_code()
        swap = run_verified_model_swap(
            half_life_output,
            gate_output,
            succession_policy_public_key_path=succession_policy_public_key_path,
            compaction_policy_public_key_path=compaction_policy_public_key_path,
            source_model=source_model,
            target_model=target_model,
            source_signing_key=source_signing_key,
            grader_signing_key=grader_signing_key,
            gate_signing_key=gate_signing_key,
            gate_issuer="openline-verified-continuation-gate",
            trial_id=trial_id,
            commit_action=action_core,
            commit_one_use_code=code,
            commit_ttl_seconds=300,
        )
        decision_lines = (
            gate_output / "decision_receipts.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        if len(decision_lines) != 1:
            raise VerifiedContinuationError("decision_receipt_count_invalid")
        decision = strict_json_loads(decision_lines[0])
        if not isinstance(decision, Mapping):
            raise VerifiedContinuationError("decision_receipt_invalid")
        authorization = decision.get("commit_authorization")
        if not isinstance(authorization, Mapping):
            raise VerifiedContinuationError("commit_authorization_missing")
        exact_action = execution_action_from_authorization(
            decision,
            settings=action_core["settings"],
        )
        gate_key = public_key_hex(gate_signing_key)
        ledger = VerifiedCommitLedger(output / "branch_commit_ledger.json")

        def forbidden_executor(label: str):
            def execute() -> dict[str, Any]:
                callbacks.append(label)
                return {"unexpected_execution": label}

            return execute

        probes: list[tuple[str, dict[str, Any], datetime | None, str]] = []
        wrong_branch = _deepcopy(exact_action)
        wrong_branch["target"] = "refs/heads/main"
        probes.append(("wrong_branch", wrong_branch, None, "target_mismatch"))
        changed_commit = _deepcopy(exact_action)
        changed_commit["settings"]["new_commit"] = objects["mutated_commit"]
        probes.append(
            ("mutated_target", changed_commit, None, "settings_mismatch")
        )
        expiry = parse_timestamp(authorization.get("expires_at"))
        if expiry is None:
            raise VerifiedContinuationError("authorization_expiry_invalid")
        probes.append(
            (
                "expired",
                _deepcopy(exact_action),
                expiry + timedelta(seconds=1),
                "authorization_expired",
            )
        )
        probe_results: list[dict[str, Any]] = []
        for label, action, now, expected_reason in probes:
            before = _read_ref(repository, BRANCH_TARGET)
            result = ledger.execute_once(
                decision,
                action,
                one_use_code=code,
                trusted_gate_keys=[gate_key],
                executor=forbidden_executor(label),
                now=now,
                attempt_label=label,
            )
            after = _read_ref(repository, BRANCH_TARGET)
            probe_results.append(
                {
                    "label": label,
                    "authorized": result["authorized"],
                    "expected_reason": expected_reason,
                    "observed_reasons": result["reason_codes"],
                    "ref_before": before,
                    "ref_after": after,
                    "blocked_before_mutation": (
                        result["authorized"] is False
                        and expected_reason in result["reason_codes"]
                        and before == after == objects["base_commit"]
                        and label not in callbacks
                    ),
                }
            )

        def approved_executor(label: str):
            def execute() -> dict[str, Any]:
                before = _read_ref(repository, BRANCH_TARGET)
                _git(
                    repository,
                    "update-ref",
                    BRANCH_TARGET,
                    objects["approved_commit"],
                    objects["base_commit"],
                )
                callbacks.append(label)
                return {
                    "target": BRANCH_TARGET,
                    "before": before,
                    "after": _read_ref(repository, BRANCH_TARGET),
                }

            return execute

        barrier = threading.Barrier(2)

        def simultaneous(index: int) -> dict[str, Any]:
            label = f"simultaneous_use_{index}"
            barrier.wait()
            return ledger.execute_once(
                decision,
                exact_action,
                one_use_code=code,
                trusted_gate_keys=[gate_key],
                executor=approved_executor(label),
                attempt_label=label,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            simultaneous_results = list(pool.map(simultaneous, (1, 2)))
        final_ref = _read_ref(repository, BRANCH_TARGET)
        replay_before = final_ref
        replay = ledger.execute_once(
            decision,
            exact_action,
            one_use_code=code,
            trusted_gate_keys=[gate_key],
            executor=forbidden_executor("replay"),
            attempt_label="replay",
        )
        replay_after = _read_ref(repository, BRANCH_TARGET)
        bundle_path = output / "authorized_repository.bundle"
        _git(repository, "bundle", "create", str(bundle_path), "--all")

    ledger_state = strict_json_load(output / "branch_commit_ledger.json")
    if not isinstance(ledger_state, Mapping):
        raise VerifiedContinuationError("branch_ledger_invalid")
    authorized_simultaneous = sum(
        result["authorized"] is True for result in simultaneous_results
    )
    blocked_simultaneous = sum(
        result["authorized"] is False for result in simultaneous_results
    )
    body = {
        "schema": BRANCH_AUTHORIZATION_SCHEMA,
        "trial_id": trial_id,
        "claim": (
            "A receiver-authorized exact branch write executes once; changed, "
            "expired, and replayed writes stop before repository mutation."
        ),
        "model_swap": {
            "provider_execution_attested": False,
            "decision": swap["decision"],
            "capsule_matches_oracle": swap["capsule_matches_oracle"],
            "archive_matches_oracle": swap["archive_matches_oracle"],
        },
        "authorization": {
            "gate_public_key": gate_key,
            "decision_payload_hash": decision["payload_hash"],
            "authorization_hash": authorization["authorization_hash"],
            "action_hash": authorization["action_hash"],
            "tool": authorization["tool"],
            "target": authorization["target"],
            "settings_hash": authorization["settings_hash"],
            "raw_one_use_code_stored": False,
        },
        "repository": {
            "initial_ref": initial_ref,
            "base_commit": objects["base_commit"],
            "approved_commit": objects["approved_commit"],
            "mutated_commit": objects["mutated_commit"],
            "final_ref": final_ref,
            "bundle": bundle_path.name,
            "bundle_sha256": sha256_hex(bundle_path.read_bytes()),
        },
        "pre_effect_probes": probe_results,
        "simultaneous_use": {
            "attempts": 2,
            "authorized": authorized_simultaneous,
            "blocked": blocked_simultaneous,
            "at_most_one_execution": authorized_simultaneous == 1,
        },
        "replay": {
            "authorized": replay["authorized"],
            "reason_codes": replay["reason_codes"],
            "ref_before": replay_before,
            "ref_after": replay_after,
            "blocked_before_mutation": (
                replay["authorized"] is False
                and "authorization_replay" in replay["reason_codes"]
                and replay_before == replay_after == objects["approved_commit"]
                and "replay" not in callbacks
            ),
        },
        "execution": {
            "callback_labels": callbacks,
            "authorized_attempts": sum(
                attempt.get("result") == "AUTHORIZED"
                for attempt in ledger_state.get("attempts", [])
            ),
            "completed_attempts": sum(
                attempt.get("execution_status") == "completed"
                for attempt in ledger_state.get("attempts", [])
            ),
        },
        "claim_boundary": (
            "This proves pre-effect receiver enforcement for the disclosed local Git "
            "ref and shared atomic ledger. It does not prove live provider execution, "
            "a tool that bypasses the checker, distributed exactly-once effects, or "
            "the separate continuation-quality claim."
        ),
    }
    body["passed"] = bool(
        swap["passed"]
        and all(item["blocked_before_mutation"] for item in probe_results)
        and authorized_simultaneous == 1
        and blocked_simultaneous == 1
        and final_ref == objects["approved_commit"]
        and body["replay"]["blocked_before_mutation"]
        and body["execution"]["authorized_attempts"] == 1
        and body["execution"]["completed_attempts"] == 1
        and len(callbacks) == 1
    )
    summary = {**body, "report_hash": _json_hash(body)}
    _write_json(output / "branch_authorization_report.json", summary)
    verification = verify_branch_authorization_trial(
        output,
        trusted_gate_keys=[gate_key],
        half_life_output=half_life_output,
        succession_policy_public_key_path=succession_policy_public_key_path,
        compaction_policy_public_key_path=compaction_policy_public_key_path,
    )
    if not verification["valid"]:
        raise VerifiedContinuationError(
            "branch_authorization_verification_failed:"
            + ",".join(verification["errors"])
        )
    return {
        "passed": summary["passed"] and verification["valid"],
        "gate_public_key": gate_key,
        "authorization_hash": authorization["authorization_hash"],
        "wrong_branch_blocked": probe_results[0]["blocked_before_mutation"],
        "mutated_target_blocked": probe_results[1]["blocked_before_mutation"],
        "expired_blocked": probe_results[2]["blocked_before_mutation"],
        "replay_blocked": summary["replay"]["blocked_before_mutation"],
        "simultaneous_authorized": authorized_simultaneous,
        "simultaneous_blocked": blocked_simultaneous,
        "final_ref": final_ref,
        "report_hash": summary["report_hash"],
        "output_dir": str(output),
        "verification": verification,
    }


def verify_branch_authorization_trial(
    output_dir: str | Path,
    *,
    trusted_gate_keys: Sequence[str],
    half_life_output: str | Path,
    succession_policy_public_key_path: str | Path,
    compaction_policy_public_key_path: str | Path,
) -> dict[str, Any]:
    """Independently verify the signed authorization, ledger, and Git bundle."""

    output = Path(output_dir)
    errors: list[str] = []
    model_swap = verify_model_swap_output(
        output / "gate",
        trusted_gate_keys=trusted_gate_keys,
        half_life_output=half_life_output,
        succession_policy_public_key_path=succession_policy_public_key_path,
        compaction_policy_public_key_path=compaction_policy_public_key_path,
    )
    if not model_swap["valid"]:
        errors.extend(f"model_swap:{error}" for error in model_swap["errors"])
    try:
        decision_lines = (
            output / "gate" / "decision_receipts.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        if len(decision_lines) != 1:
            raise ValueError("decision_receipt_count_invalid")
        decision = strict_json_loads(decision_lines[0])
        summary = strict_json_load(output / "branch_authorization_report.json")
        ledger = strict_json_load(output / "branch_commit_ledger.json")
        gate_request = strict_json_load(output / "gate" / "gate_request.json")
    except (OSError, ValueError) as exc:
        return {
            "valid": False,
            "errors": [f"branch_authorization_output_unreadable:{exc}"],
            "model_swap": model_swap,
        }
    if not isinstance(decision, Mapping):
        errors.append("decision_receipt_invalid")
        decision = {}
    if not isinstance(summary, Mapping):
        errors.append("branch_summary_invalid")
        summary = {}
    if not isinstance(ledger, Mapping):
        errors.append("branch_ledger_invalid")
        ledger = {}
    if not isinstance(gate_request, Mapping):
        errors.append("gate_request_invalid")
        gate_request = {}
    if summary.get("schema") != BRANCH_AUTHORIZATION_SCHEMA:
        errors.append("branch_summary_schema_invalid")
    summary_body = dict(summary)
    observed_report_hash = summary_body.pop("report_hash", None)
    if observed_report_hash != _json_hash(summary_body):
        errors.append("branch_summary_hash_invalid")
    authorization = decision.get("commit_authorization")
    if not isinstance(authorization, Mapping):
        errors.append("commit_authorization_missing")
        authorization = {}
    summary_authorization = summary.get("authorization")
    if not isinstance(summary_authorization, Mapping):
        errors.append("summary_authorization_invalid")
        summary_authorization = {}
    for name in (
        "authorization_hash",
        "action_hash",
        "tool",
        "target",
        "settings_hash",
    ):
        if summary_authorization.get(name) != authorization.get(name):
            errors.append(f"summary_authorization_{name}_mismatch")
    if authorization.get("tool") != BRANCH_TOOL:
        errors.append("branch_tool_mismatch")
    if authorization.get("target") != BRANCH_TARGET:
        errors.append("branch_target_mismatch")
    commit_request = gate_request.get("commit_request")
    if not isinstance(commit_request, Mapping):
        errors.append("gate_commit_request_invalid")
        commit_request = {}
    raw_settings = commit_request.get("settings")
    if not isinstance(raw_settings, Mapping):
        errors.append("gate_commit_settings_invalid")
        raw_settings = {}
    else:
        try:
            raw_settings_hash = settings_hash(raw_settings)
        except VerifiedCommitError:
            raw_settings_hash = None
            errors.append("gate_commit_settings_unhashable")
        if raw_settings_hash != authorization.get("settings_hash"):
            errors.append("gate_commit_settings_hash_mismatch")
    if commit_request.get("tool") != BRANCH_TOOL:
        errors.append("gate_commit_tool_mismatch")
    if commit_request.get("target") != BRANCH_TARGET:
        errors.append("gate_commit_target_mismatch")
    repository = summary.get("repository")
    if not isinstance(repository, Mapping):
        errors.append("repository_summary_invalid")
        repository = {}
    if repository.get("initial_ref") != repository.get("base_commit"):
        errors.append("repository_initial_ref_mismatch")
    if raw_settings.get("expected_old_commit") != repository.get("base_commit"):
        errors.append("authorized_old_commit_mismatch")
    if raw_settings.get("new_commit") != repository.get("approved_commit"):
        errors.append("authorized_new_commit_mismatch")
    if raw_settings.get("update_mode") != "compare_and_swap":
        errors.append("authorized_update_mode_invalid")
    bundle_path = output / str(repository.get("bundle", ""))
    if (
        not bundle_path.is_file()
        or sha256_hex(bundle_path.read_bytes()) != repository.get("bundle_sha256")
    ):
        errors.append("repository_bundle_hash_mismatch")
    else:
        completed = subprocess.run(
            ["git", "bundle", "list-heads", str(bundle_path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            errors.append("repository_bundle_invalid")
        else:
            heads: dict[str, str] = {}
            for line in completed.stdout.splitlines():
                parts = line.split()
                if len(parts) == 2:
                    heads[parts[1]] = parts[0]
            if heads.get(BRANCH_TARGET) != repository.get("approved_commit"):
                errors.append("repository_final_ref_mismatch")
            if "refs/heads/main" in heads:
                errors.append("wrong_branch_was_mutated")
    probes = summary.get("pre_effect_probes")
    if (
        not isinstance(probes, list)
        or [item.get("label") for item in probes if isinstance(item, Mapping)]
        != ["wrong_branch", "mutated_target", "expired"]
        or not all(
            isinstance(item, Mapping)
            and item.get("authorized") is False
            and item.get("blocked_before_mutation") is True
            for item in probes
        )
    ):
        errors.append("pre_effect_probes_invalid")
    simultaneous = summary.get("simultaneous_use")
    if not isinstance(simultaneous, Mapping) or (
        simultaneous.get("authorized"),
        simultaneous.get("blocked"),
        simultaneous.get("at_most_one_execution"),
    ) != (1, 1, True):
        errors.append("simultaneous_use_invalid")
    replay = summary.get("replay")
    if not isinstance(replay, Mapping) or not (
        replay.get("authorized") is False
        and replay.get("blocked_before_mutation") is True
        and replay.get("ref_before") == replay.get("ref_after")
        == repository.get("approved_commit")
    ):
        errors.append("replay_result_invalid")
    attempts = ledger.get("attempts") if isinstance(ledger, Mapping) else None
    if not isinstance(attempts, list):
        errors.append("branch_ledger_attempts_invalid")
        attempts = []
    by_label = {
        attempt.get("attempt_label"): attempt
        for attempt in attempts
        if isinstance(attempt, Mapping)
    }
    for label, reason in (
        ("wrong_branch", "target_mismatch"),
        ("mutated_target", "settings_mismatch"),
        ("expired", "authorization_expired"),
        ("replay", "authorization_replay"),
    ):
        attempt = by_label.get(label)
        if not isinstance(attempt, Mapping) or (
            attempt.get("result") != "BLOCKED"
            or attempt.get("execution_status") != "not_started"
            or reason not in attempt.get("reason_codes", [])
        ):
            errors.append(f"ledger_{label}_invalid")
    authorized_attempts = [
        attempt
        for attempt in attempts
        if isinstance(attempt, Mapping)
        and attempt.get("result") == "AUTHORIZED"
    ]
    if len(authorized_attempts) != 1 or authorized_attempts[0].get(
        "execution_status"
    ) != "completed":
        errors.append("ledger_exactly_one_execution_invalid")
    if summary.get("passed") is not True:
        errors.append("branch_summary_not_passed")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "model_swap": model_swap,
        "report_hash": observed_report_hash,
    }


def build_experiment_summary(
    continuation_report: Mapping[str, Any],
    authorization_report: Mapping[str, Any],
) -> dict[str, Any]:
    """Combine already-separated claims without allowing either to mask the other."""

    continuation = continuation_report.get("continuation_claim", {})
    authorization_passed = authorization_report.get("passed") is True
    continuation_disposition = (
        continuation.get("disposition")
        if isinstance(continuation, Mapping)
        else "INVALID"
    )
    if not authorization_passed or continuation_disposition in {"FAIL", "INVALID"}:
        disposition = "HOLD"
    elif continuation_disposition == "PASS":
        disposition = "CLEAR"
    else:
        disposition = "READY_FOR_OUTSIDE_CONTINUATION_TRIAL"
    body = {
        "schema": EXPERIMENT_SUMMARY_SCHEMA,
        "disposition": disposition,
        "claims": {
            "continuation": {
                "disposition": continuation_disposition,
                "report_hash": continuation_report.get("report_hash"),
            },
            "authorization": {
                "disposition": "PASS" if authorization_passed else "FAIL",
                "report_hash": authorization_report.get("report_hash"),
            },
        },
        "headline": (
            "Normal handoffs move context. OLP determines what the receiver may "
            "trust and do with it."
        ),
        "claim_boundary": (
            "Authorization and continuation are independent. The frozen synthetic "
            "fixture cannot establish cross-model continuation; an outside matched "
            "reproduction is still required."
        ),
    }
    return {**body, "summary_hash": _json_hash(body)}
