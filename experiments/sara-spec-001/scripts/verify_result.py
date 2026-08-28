#!/usr/bin/env python3
"""Independent verifier for SARA-SPEC-001 serialized artifacts.

This verifier imports neither the experiment runner nor any arm. It recomputes
the representation-blind oracle directly from the sealed fixture, verifies the
design lock, audits the minimal extension source boundary, and checks the
frozen result.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


EXP = Path(__file__).resolve().parents[1]
MAX_SAFE_INTEGER = (1 << 53) - 1


class StrictJSONError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StrictJSONError(f"duplicate_json_key:{key}")
        value[key] = item
    return value


def strict_load(path: Path) -> Any:
    def reject_constant(value: str) -> None:
        raise StrictJSONError(f"non_finite_number:{value}")

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=reject_constant,
    )


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hex_digest(value: Any) -> bool:
    if not isinstance(value, str) or value != value.lower():
        return False
    try:
        return len(bytes.fromhex(value)) == 32
    except ValueError:
        return False


def _safe_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_SAFE_INTEGER


def _call_matches(call: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    arguments = call.get("arguments")
    static = contract.get("static_arguments")
    return bool(
        call.get("tool") == contract.get("operation")
        and isinstance(arguments, Mapping)
        and isinstance(static, Mapping)
        and arguments.get("source_uri") == contract.get("scope")
        and all(arguments.get(key) == value for key, value in static.items())
    )


def recompute_oracle(fixture: Mapping[str, Any]) -> dict[str, Any]:
    roots_by_token: dict[str, set[str]] = {}
    for entry in fixture["H"]:
        if entry.get("allowed") is not True or entry.get("success") is not True:
            continue
        observation = entry.get("observation", {})
        token = observation.get("evidence_token")
        if not _hex_digest(token):
            raise ValueError("fixture_evidence_token_invalid")
        roots = {
            contract["contract_item_id"]
            for contract in fixture["K"]
            if _call_matches(entry["call"], contract)
        }
        if len(roots) != 1:
            raise ValueError("fixture_history_root_ambiguous")
        roots_by_token[token] = roots

    controls: dict[str, dict[str, str]] = {}
    for control in fixture["controls"]:
        dispositions: dict[str, str] = {}
        for decision in fixture["decisions"]:
            roots = roots_by_token.get(decision.get("basis_token"), set())
            affected = bool(
                control.get("event_type") == "REVOKE"
                and control.get("standing") == "REVOKED"
                and control.get("contract_item_id") in roots
            )
            dispositions[decision["decision_id"]] = (
                "REOPEN" if affected else "PRESERVE"
            )
        dispositions["historical_evidence"] = "UNCHANGED"
        controls[control["control_id"]] = dispositions
    return {
        "schema": "openline.sara_spec_001.oracle.v1",
        "experiment_id": "SARA-SPEC-001",
        "representation_blind": True,
        "controls": controls,
    }


def _audit_minimal_source(errors: list[str]) -> None:
    path = EXP / "sara_spec001" / "minimal_sara.py"
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        errors.append("minimal_source_syntax_invalid")
        return
    if any(isinstance(node, ast.ClassDef) for node in ast.walk(tree)):
        errors.append("minimal_source_persistent_class_forbidden")
    forbidden_imports = {"pathlib", "pickle", "shelve", "sqlite3", "tempfile"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in forbidden_imports:
                    errors.append(f"minimal_source_import_forbidden:{alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module in forbidden_imports or module in {"oracle", "openline_recall"}:
                errors.append(f"minimal_source_import_forbidden:{node.module}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"open", "compile", "eval", "exec"}:
                errors.append(f"minimal_source_call_forbidden:{node.func.id}")
    for literal in ("oracle.json", "D1", "D2"):
        if literal in source:
            errors.append(f"minimal_source_fixture_answer_literal:{literal}")


def verify() -> dict[str, Any]:
    errors: list[str] = []
    try:
        lock = strict_load(EXP / "DESIGN_LOCK.json")
        source_pin = strict_load(EXP / "SOURCE_PIN.json")
        fixture = strict_load(EXP / "fixtures" / "scenario.json")
        oracle = strict_load(EXP / "oracle.json")
        prereg = strict_load(EXP / "preregistration.json")
        report = strict_load(EXP / "result.json")
    except (OSError, StrictJSONError, json.JSONDecodeError, ValueError) as exc:
        return {"valid": False, "errors": [f"load_failed:{exc}"]}

    if lock.get("run_status_at_lock") != "NOT_RUN":
        errors.append("design_lock_not_preoutcome")
    for relative, expected in lock.get("files", {}).items():
        path = EXP / relative
        if not path.is_file():
            errors.append(f"design_file_missing:{relative}")
        elif sha(path) != expected:
            errors.append(f"design_file_hash_mismatch:{relative}")
    if lock.get("frozen_counts") != {
        "arms": 4,
        "authorization_roots": 2,
        "controls": 2,
        "decisions": 2,
    }:
        errors.append("design_counts_invalid")

    paper = source_pin.get("paper", {})
    if source_pin.get("evidence_tier") != "PAPER_SPEC_RECONSTRUCTION":
        errors.append("source_evidence_tier_invalid")
    if paper.get("arxiv_id") != "2608.27146" or paper.get("version") != "v1":
        errors.append("source_version_invalid")
    if paper.get("pdf_sha256") != "acb6f5aae45da095c08f23ca6f472045be763bd8cdc19a6230ea270bb76ebe62":
        errors.append("source_pdf_pin_invalid")
    if paper.get("pdf_bytes") != 1043381:
        errors.append("source_pdf_size_invalid")
    if source_pin.get("author_implementation", {}).get("cold_external_integration_claimed") is not False:
        errors.append("source_externality_overclaimed")

    if fixture.get("task", {}).get("status") != "TERMINATED":
        errors.append("fixture_task_not_terminated")
    if [item.get("contract_item_id") for item in fixture.get("K", [])] != ["K1", "K2"]:
        errors.append("fixture_roots_invalid")
    if [item.get("decision_id") for item in fixture.get("decisions", [])] != ["D1", "D2"]:
        errors.append("fixture_decisions_invalid")
    if [item.get("control_id") for item in fixture.get("controls", [])] != [
        "revoke_k1_after_task",
        "noop_k1_after_task",
    ]:
        errors.append("fixture_controls_invalid")
    try:
        recomputed_oracle = recompute_oracle(fixture)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"oracle_recompute_failed:{exc}")
        recomputed_oracle = None
    if recomputed_oracle != oracle:
        errors.append("sealed_oracle_mismatch")

    arms = prereg.get("arms")
    if not isinstance(arms, list) or [item.get("arm_id") for item in arms] != [
        "published_sara",
        "broad_recall",
        "minimal_sara_extension",
        "openline_selective_recall",
    ]:
        errors.append("prereg_arms_invalid")
    minimal_prereg = arms[2] if isinstance(arms, list) and len(arms) == 4 else {}
    if minimal_prereg.get("forbidden_persistent_structures") != [
        "new edge class",
        "reverse index",
        "descendant table",
        "causal graph",
        "per-decision support structure",
    ]:
        errors.append("prereg_extension_budget_invalid")

    if report.get("schema") != "openline.sara_spec_001.result.v1":
        errors.append("report_schema_invalid")
    if report.get("design_lock_sha256") != sha(EXP / "DESIGN_LOCK.json"):
        errors.append("report_design_lock_mismatch")
    if report.get("source_pin_sha256") != sha(EXP / "SOURCE_PIN.json"):
        errors.append("report_source_pin_mismatch")
    if report.get("counts") != {"arms": 4, "controls": 2, "rows": 8, "scored_arms": 3}:
        errors.append("report_counts_invalid")
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != 8:
        errors.append("report_rows_invalid")
        rows = []
    indexed = {
        (row.get("arm_id"), row.get("control_id")): row
        for row in rows
        if isinstance(row, Mapping)
    }
    if len(indexed) != 8:
        errors.append("report_row_keys_invalid")

    for arm_id in (
        "published_sara",
        "broad_recall",
        "minimal_sara_extension",
        "openline_selective_recall",
    ):
        for control_id in ("revoke_k1_after_task", "noop_k1_after_task"):
            row = indexed.get((arm_id, control_id))
            if not isinstance(row, Mapping):
                errors.append(f"row_missing:{arm_id}:{control_id}")
                continue
            observed = row.get("observed")
            if not isinstance(observed, Mapping):
                errors.append(f"row_observed_invalid:{arm_id}:{control_id}")
                continue
            if observed.get("historical_hash_before") != observed.get("historical_hash_after"):
                errors.append(f"history_mutated:{arm_id}:{control_id}")
            if observed.get("historical_evidence") != "UNCHANGED":
                errors.append(f"history_status_invalid:{arm_id}:{control_id}")
            if arm_id == "published_sara":
                if row.get("scored") is not False or row.get("exact_oracle_match") is not None:
                    errors.append(f"published_sara_scored:{control_id}")
                if observed.get("scope_status") != "OUT_OF_SCOPE_AFTER_TASK_END":
                    errors.append(f"published_sara_scope_invalid:{control_id}")
                if set(observed.get("dispositions", {}).values()) != {"UNASSESSED"}:
                    errors.append(f"published_sara_disposition_invalid:{control_id}")
            else:
                expected = oracle["controls"][control_id]
                observed_oracle = {
                    "D1": observed.get("dispositions", {}).get("D1"),
                    "D2": observed.get("dispositions", {}).get("D2"),
                    "historical_evidence": observed.get("historical_evidence"),
                }
                exact = observed_oracle == expected
                if row.get("exact_oracle_match") is not exact:
                    errors.append(f"row_match_flag_invalid:{arm_id}:{control_id}")

    broad_revoke = indexed.get(("broad_recall", "revoke_k1_after_task"), {})
    if broad_revoke.get("observed", {}).get("dispositions") != {"D1": "REOPEN", "D2": "REOPEN"}:
        errors.append("broad_recall_control_invalid")
    for arm_id in ("minimal_sara_extension", "openline_selective_recall"):
        for control_id in ("revoke_k1_after_task", "noop_k1_after_task"):
            if indexed.get((arm_id, control_id), {}).get("exact_oracle_match") is not True:
                errors.append(f"exact_arm_failed:{arm_id}:{control_id}")

    expected_shape = {
        "persisted_keys": ["F", "H", "K"],
        "extension_keys": ["standing_updates"],
        "new_persistent_structure_count": 0,
        "returns_derived_relationships": False,
    }
    for control_id in ("revoke_k1_after_task", "noop_k1_after_task"):
        shape = indexed.get(("minimal_sara_extension", control_id), {}).get("observed", {}).get("state_shape")
        if shape != expected_shape:
            errors.append(f"minimal_state_shape_invalid:{control_id}")

    _audit_minimal_source(errors)
    if report.get("verdict") != "SARA_EXTENSION_PARITY":
        errors.append("report_verdict_invalid")
    if report.get("passed") is not True:
        errors.append("report_not_passed")
    if report.get("openline_novelty_falsifier_triggered") is not True:
        errors.append("novelty_falsifier_status_invalid")
    if report.get("claim_boundary") != {
        "published_sara_scored_as_failure": False,
        "cold_external_integration": False,
        "agentdojo_agentdyn_reproduced": False,
        "production_code_changed": False,
    }:
        errors.append("report_claim_boundary_invalid")
    if report.get("policy_authority") != "NONE":
        errors.append("report_policy_authority_invalid")

    return {
        "valid": not errors,
        "errors": errors,
        "verified_verdict": report.get("verdict"),
        "verified_rows": len(rows),
        "design_lock_files": len(lock.get("files", {})),
        "evidence_tier": source_pin.get("evidence_tier"),
    }


def main() -> int:
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
