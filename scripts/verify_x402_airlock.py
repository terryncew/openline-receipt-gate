#!/usr/bin/env python3
"""Independently verify the frozen x402 Transaction Airlock report.

This verifier intentionally imports no Receipt Gate or benchmark module.  The
release gate first executes the candidate suite, then this script checks source
closure, frozen expectations, coverage, and the serialized observations using
only the Python standard library.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = Path("benchmarks/x402_airlock")
EXPECTED_FROZEN_FILES = {
    "benchmarks/x402_airlock/CASES.json",
    "benchmarks/x402_airlock/PROTOCOL.md",
    "benchmarks/x402_airlock/RULES.json",
    "benchmarks/x402_airlock/SOURCE.json",
    "benchmarks/x402_airlock/fixture.py",
    "benchmarks/x402_airlock/results/hostile_report.json",
    "benchmarks/x402_airlock/run_hostile_suite.py",
    "olp_gate/verified_commit.py",
    "olp_gate/x402_airlock.py",
    "scripts/verify_x402_airlock.py",
    "tests/test_x402_airlock.py",
    "tests/test_x402_freeze.py",
}
EXPECTED_RULES = {f"SR{index}" for index in range(1, 9)}
EXPECTED_AXES = {
    "network",
    "asset",
    "recipient",
    "amount",
    "expiry",
    "replay",
    "verification_settlement_divergence",
}
CASE_TOP_KEYS = {
    "id",
    "operation",
    "rule_ids",
    "expected",
    "mutations",
    "falsifier_axis",
}
EXPECTED_KEYS = {
    "receipt_decision",
    "authorized_count",
    "blocked_count",
    "settlement_calls",
    "release_calls",
    "released_count",
    "pre_effect_blocked",
    "reason_contains",
}
REPORT_TOP_KEYS = {
    "schema",
    "suite",
    "run_at",
    "source",
    "valid",
    "case_count",
    "passed_cases",
    "failed_cases",
    "rules_covered",
    "required_falsifier_axes",
    "settlement_callback_count",
    "release_callback_count",
    "resource_release_confirmed_count",
    "results",
}
RESULT_KEYS = {
    "case_id",
    "operation",
    "rule_ids",
    "falsifier_axis",
    "passed",
    "comparisons",
    "expected",
    "observed",
}
OBSERVED_KEYS = {
    "receipt_decision",
    "authorized_count",
    "blocked_count",
    "settlement_calls",
    "release_calls",
    "released_count",
    "pre_effect_blocked",
    "reason_codes",
}


class DuplicateKeyError(ValueError):
    pass


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate key: {key}")
        value[key] = item
    return value


def _load(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_object_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {value}")
        ),
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    root = root.resolve()
    base = root / BENCHMARK
    try:
        freeze = _load(base / "FREEZE.json")
        source = _load(base / "SOURCE.json")
        rules_document = _load(base / "RULES.json")
        cases_document = _load(base / "CASES.json")
        report = _load(base / "results" / "hostile_report.json")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "schema": "openline.x402-airlock.verification.v1",
            "valid": False,
            "errors": [f"input_invalid:{type(exc).__name__}:{exc}"],
        }

    if set(freeze) != {"schema", "suite", "frozen_at", "files"}:
        errors.append("freeze_shape_invalid")
    if freeze.get("schema") != "openline.x402-airlock.freeze.v1":
        errors.append("freeze_schema_invalid")
    if freeze.get("suite") != "x402-airlock-hostile-v1":
        errors.append("freeze_suite_invalid")
    files = freeze.get("files")
    if not isinstance(files, dict):
        files = {}
        errors.append("freeze_files_invalid")
    if set(files) != EXPECTED_FROZEN_FILES:
        errors.append("freeze_source_closure_mismatch")
    for relative, expected_hash in sorted(files.items()):
        path = root / relative
        if not path.is_file():
            errors.append(f"frozen_file_missing:{relative}")
        elif not isinstance(expected_hash, str) or _sha256(path) != expected_hash:
            errors.append(f"frozen_file_hash_mismatch:{relative}")

    if set(source) != {
        "schema",
        "checked_at",
        "study",
        "source_urls",
        "use_boundary",
    }:
        errors.append("source_shape_invalid")
    study = source.get("study")
    if not isinstance(study, dict):
        study = {}
        errors.append("source_study_invalid")
    expected_study = {
        "arxiv_id": "2607.19545",
        "published": "2026-07-21",
        "version": "v1",
    }
    for name, expected in expected_study.items():
        if study.get(name) != expected:
            errors.append(f"source_{name}_invalid")
    urls = source.get("source_urls")
    if not isinstance(urls, list) or (
        "https://arxiv.org/abs/2607.19545" not in urls
    ):
        errors.append("source_url_invalid")

    if set(rules_document) != {"schema", "source", "rules"}:
        errors.append("rules_document_shape_invalid")
    rules = rules_document.get("rules")
    if not isinstance(rules, list):
        rules = []
        errors.append("rules_invalid")
    rule_ids = [
        rule.get("id") for rule in rules if isinstance(rule, dict)
    ]
    if set(rule_ids) != EXPECTED_RULES or len(rule_ids) != 8:
        errors.append("rules_sr1_through_sr8_not_exact")
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {
            "id",
            "phase",
            "rule",
            "airlock_control",
        }:
            errors.append("rule_shape_invalid")
            continue
        if not all(
            isinstance(rule.get(name), str) and rule[name]
            for name in ("id", "phase", "rule", "airlock_control")
        ):
            errors.append(f"rule_value_invalid:{rule.get('id')}")

    if set(cases_document) != {
        "schema",
        "frozen_at",
        "falsifier",
        "required_falsifier_axes",
        "cases",
    }:
        errors.append("cases_document_shape_invalid")
    cases = cases_document.get("cases")
    if not isinstance(cases, list):
        cases = []
        errors.append("cases_invalid")
    if len(cases) != 56:
        errors.append("case_count_not_56")
    case_by_id: dict[str, dict[str, Any]] = {}
    covered_rules: set[str] = set()
    covered_axes: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            errors.append("case_invalid")
            continue
        if not set(case).issubset(CASE_TOP_KEYS):
            errors.append(f"case_unknown_field:{case.get('id')}")
        if not {"id", "operation", "rule_ids", "expected"}.issubset(case):
            errors.append(f"case_required_field_missing:{case.get('id')}")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            errors.append("case_id_invalid")
            continue
        if case_id in case_by_id:
            errors.append(f"case_id_duplicate:{case_id}")
        case_by_id[case_id] = case
        ids = case.get("rule_ids")
        if (
            not isinstance(ids, list)
            or not ids
            or not set(ids).issubset(EXPECTED_RULES)
            or len(ids) != len(set(ids))
        ):
            errors.append(f"case_rule_ids_invalid:{case_id}")
        else:
            covered_rules.update(ids)
        expected = case.get("expected")
        if not isinstance(expected, dict) or set(expected) != EXPECTED_KEYS:
            errors.append(f"case_expected_shape_invalid:{case_id}")
        axis = case.get("falsifier_axis")
        if axis is not None:
            if axis not in EXPECTED_AXES:
                errors.append(f"case_axis_invalid:{case_id}")
            elif (
                not isinstance(expected, dict)
                or expected.get("pre_effect_blocked") is not True
            ):
                errors.append(f"axis_not_pre_effect_blocked:{case_id}")
            else:
                covered_axes.add(axis)
    if covered_rules != EXPECTED_RULES:
        errors.append("case_rule_coverage_incomplete")
    declared_axes = cases_document.get("required_falsifier_axes")
    if not isinstance(declared_axes, list) or set(declared_axes) != EXPECTED_AXES:
        errors.append("required_falsifier_axes_invalid")
    if covered_axes != EXPECTED_AXES:
        errors.append("case_falsifier_axis_coverage_incomplete")

    if set(report) != REPORT_TOP_KEYS:
        errors.append("report_shape_invalid")
    results = report.get("results")
    if not isinstance(results, list):
        results = []
        errors.append("report_results_invalid")
    result_by_id: dict[str, dict[str, Any]] = {}
    for result in results:
        if not isinstance(result, dict):
            errors.append("report_result_invalid")
            continue
        if set(result) != RESULT_KEYS:
            errors.append(f"report_result_shape_invalid:{result.get('case_id')}")
        case_id = result.get("case_id")
        if not isinstance(case_id, str) or case_id in result_by_id:
            errors.append(f"report_result_id_invalid:{case_id}")
            continue
        result_by_id[case_id] = result
        case = case_by_id.get(case_id)
        if case is None:
            errors.append(f"report_result_unknown_case:{case_id}")
            continue
        if result.get("operation") != case.get("operation"):
            errors.append(f"report_operation_mismatch:{case_id}")
        if result.get("rule_ids") != case.get("rule_ids"):
            errors.append(f"report_rules_mismatch:{case_id}")
        if result.get("falsifier_axis") != case.get("falsifier_axis"):
            errors.append(f"report_axis_mismatch:{case_id}")
        if result.get("expected") != case.get("expected"):
            errors.append(f"report_expected_mismatch:{case_id}")
        observed = result.get("observed")
        if not isinstance(observed, dict) or set(observed) != OBSERVED_KEYS:
            errors.append(f"report_observed_shape_invalid:{case_id}")
            continue
        expected = case["expected"]
        for name in EXPECTED_KEYS - {"reason_contains"}:
            if observed.get(name) != expected.get(name):
                errors.append(f"report_observation_mismatch:{case_id}:{name}")
        reasons = observed.get("reason_codes")
        if (
            not isinstance(reasons, list)
            or not set(expected["reason_contains"]).issubset(reasons)
        ):
            errors.append(f"report_reason_mismatch:{case_id}")
        comparisons = result.get("comparisons")
        if (
            not isinstance(comparisons, dict)
            or set(comparisons) != EXPECTED_KEYS
            or not all(value is True for value in comparisons.values())
        ):
            errors.append(f"report_comparisons_invalid:{case_id}")
        if result.get("passed") is not True:
            errors.append(f"report_case_failed:{case_id}")
    if set(result_by_id) != set(case_by_id):
        errors.append("report_case_set_mismatch")

    recalculated_settlements = sum(
        int(result["observed"]["settlement_calls"])
        for result in result_by_id.values()
        if isinstance(result.get("observed"), dict)
    )
    recalculated_releases = sum(
        int(result["observed"]["release_calls"])
        for result in result_by_id.values()
        if isinstance(result.get("observed"), dict)
    )
    recalculated_confirmed_releases = sum(
        int(result["observed"]["released_count"])
        for result in result_by_id.values()
        if isinstance(result.get("observed"), dict)
    )
    if report.get("schema") != "openline.x402-airlock.hostile-report.v1":
        errors.append("report_schema_invalid")
    if report.get("suite") != "x402-airlock-hostile-v1":
        errors.append("report_suite_invalid")
    if report.get("source") != "arXiv:2607.19545v1":
        errors.append("report_source_invalid")
    if report.get("case_count") != len(cases):
        errors.append("report_case_count_invalid")
    if report.get("passed_cases") != len(cases):
        errors.append("report_passed_count_invalid")
    if report.get("failed_cases") != []:
        errors.append("report_failed_cases_not_empty")
    if set(report.get("rules_covered", [])) != EXPECTED_RULES:
        errors.append("report_rules_coverage_invalid")
    axis_report = report.get("required_falsifier_axes")
    if (
        not isinstance(axis_report, dict)
        or set(axis_report) != EXPECTED_AXES
        or not all(value is True for value in axis_report.values())
    ):
        errors.append("report_falsifier_axes_invalid")
    if report.get("settlement_callback_count") != recalculated_settlements:
        errors.append("report_settlement_count_invalid")
    if report.get("release_callback_count") != recalculated_releases:
        errors.append("report_release_callback_count_invalid")
    if (
        report.get("resource_release_confirmed_count")
        != recalculated_confirmed_releases
    ):
        errors.append("report_release_confirmation_count_invalid")
    if report.get("valid") is not True:
        errors.append("report_not_valid")

    confirmation_cases = [
        result
        for result in results
        if isinstance(result, dict)
        and (
            str(result.get("operation", "")).startswith("confirmation")
            or result.get("operation")
            == "settlement_transaction_divergence"
        )
    ]
    if any(
        result.get("observed", {}).get("release_calls") != 0
        for result in confirmation_cases
    ):
        errors.append("unconfirmed_or_mismatched_resource_released")
    release_hostile_cases = [
        result
        for result in results
        if isinstance(result, dict)
        and result.get("operation")
        in {"release_result_mutation", "release_provider_error"}
    ]
    if any(
        result.get("observed", {}).get("released_count") != 0
        for result in release_hostile_cases
    ):
        errors.append("invalid_release_acknowledgment_accepted")

    verifier_source = (
        root / "scripts" / "verify_x402_airlock.py"
    ).read_text(encoding="utf-8")
    verifier_tree = ast.parse(verifier_source)
    imported_roots = {
        alias.name.split(".")[0]
        for node in ast.walk(verifier_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".")[0]
        for node in ast.walk(verifier_tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    if "olp_gate" in imported_roots:
        errors.append("verifier_imports_candidate_package")
    if "benchmarks" in imported_roots:
        errors.append("verifier_imports_benchmark_module")

    errors = sorted(set(errors))
    return {
        "schema": "openline.x402-airlock.verification.v1",
        "valid": not errors,
        "errors": errors,
        "source": "arXiv:2607.19545v1",
        "frozen_file_count": len(files),
        "rule_count": len(rules),
        "case_count": len(cases),
        "passed_cases": report.get("passed_cases"),
        "required_falsifier_axes": axis_report,
        "independent_of_candidate_modules": (
            "verifier_imports_candidate_package" not in errors
            and "verifier_imports_benchmark_module" not in errors
        ),
    }


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT
    result = verify(root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
