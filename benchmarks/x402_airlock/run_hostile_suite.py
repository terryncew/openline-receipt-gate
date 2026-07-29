#!/usr/bin/env python3
"""Execute the frozen synthetic x402 Transaction Airlock hostile suite."""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(ROOT))

from benchmarks.x402_airlock.fixture import (  # noqa: E402
    FIXED_NOW,
    SyntheticX402Fixture,
    clone,
    set_path,
)
from olp_gate.verified_commit import VerifiedCommitLedger  # noqa: E402
from olp_gate.x402_airlock import (  # noqa: E402
    X402_RELEASE_RESULT_PROFILE,
    execute_x402_once,
)


DEFAULT_CASES = ROOT / "benchmarks" / "x402_airlock" / "CASES.json"
DEFAULT_OUTPUT = (
    ROOT
    / "benchmarks"
    / "x402_airlock"
    / "results"
    / "hostile_report.json"
)


def _mutate(value: dict[str, Any], mutations: list[dict[str, Any]]) -> None:
    for mutation in mutations:
        set_path(value, str(mutation["path"]), clone(mutation["value"]))


def _reason_codes(result: dict[str, Any]) -> list[str]:
    reasons = result.get("reason_codes", [])
    if not isinstance(reasons, list):
        return []
    return sorted({str(reason) for reason in reasons})


def _execute_case(case: dict[str, Any], root: Path) -> dict[str, Any]:
    case_id = str(case["id"])
    operation = str(case["operation"])
    mutations = list(case.get("mutations", []))
    fixture = SyntheticX402Fixture(root)
    settlement_calls: list[str] = []
    release_calls: list[str] = []
    reasons: list[str] = []
    authorized_count = 0
    blocked_count = 0
    case_results: list[dict[str, Any]] = []
    receipt_decision = "UNKNOWN"

    settings_mutations = [
        (str(item["path"]), clone(item["value"])) for item in mutations
    ]
    if operation == "issue_settings_mutation":
        bundle = fixture.issue(
            case_id,
            settings_mutations=settings_mutations,
        )
        receipt_decision = str(bundle["receipt"]["decision"])
        reasons = sorted(
            {str(reason) for reason in bundle["receipt"]["reason_codes"]}
        )
        blocked_count = 1
    else:
        bundle = fixture.issue(case_id)
        receipt_decision = str(bundle["receipt"]["decision"])

    def settlement_executor(_settings: dict[str, Any]) -> dict[str, Any]:
        settlement_calls.append(case_id)
        transaction_hash = bundle["confirmation"]["transaction_hash"]
        if operation == "settlement_transaction_divergence":
            transaction_hash = "aa" * 32
        return {
            "submitted": True,
            "transaction_hash": transaction_hash,
        }

    def release_executor(request: dict[str, Any]) -> dict[str, Any]:
        release_calls.append(case_id)
        if operation == "release_provider_error":
            raise RuntimeError("frozen release failure")
        release_result = {
            "profile": X402_RELEASE_RESULT_PROFILE,
            "released": True,
            "target": request["target"],
            "transaction_hash": request["confirmation"][
                "transaction_hash"
            ],
        }
        if operation == "release_result_mutation":
            _mutate(release_result, mutations)
        return release_result

    def run_once(
        ledger: VerifiedCommitLedger,
        *,
        selected_bundle: dict[str, Any] | None = None,
        action: dict[str, Any] | None = None,
        snapshot: dict[str, Any] | None = None,
        confirmation: dict[str, Any] | None = None,
        snapshot_error: bool = False,
        confirmation_error: bool = False,
        now=FIXED_NOW,
        label: str | None = None,
    ) -> dict[str, Any]:
        active_bundle = selected_bundle or bundle
        selected_action = (
            action if action is not None else active_bundle["action"]
        )

        def snapshot_provider() -> dict[str, Any]:
            if snapshot_error:
                raise RuntimeError("frozen receiver snapshot failure")
            return clone(
                (
                    snapshot
                    if snapshot is not None
                    else active_bundle["snapshot"]
                )
            )

        def confirmation_provider(_result: dict[str, Any]) -> dict[str, Any]:
            if confirmation_error:
                raise RuntimeError("frozen confirmation failure")
            return clone(
                confirmation
                if confirmation is not None
                else active_bundle["confirmation"]
            )

        return execute_x402_once(
            ledger,
            active_bundle["receipt"],
            selected_action,
            one_use_code=active_bundle["code"],
            trusted_gate_keys=[active_bundle["gate_public_key"]],
            snapshot_provider=snapshot_provider,
            settlement_executor=settlement_executor,
            confirmation_provider=confirmation_provider,
            release_executor=release_executor,
            now=now,
            attempt_label=label or case_id,
        )

    if operation == "clean":
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json")
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "action_mutation":
        action = clone(bundle["action"])
        _mutate(action, mutations)
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json"),
            action=action,
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "snapshot_mutation":
        snapshot = clone(bundle["snapshot"])
        _mutate(snapshot, mutations)
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json"),
            snapshot=snapshot,
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "snapshot_provider_error":
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json"),
            snapshot_error=True,
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "generic_bypass":
        calls: list[str] = []
        result = VerifiedCommitLedger(
            root / f"{case_id}-ledger.json"
        ).execute_once(
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            executor=lambda: calls.append(case_id),
            now=FIXED_NOW,
            attempt_label=case_id,
        )
        case_results = [result]
        settlement_calls.extend(calls)
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "confirmation_mutation":
        confirmation = clone(bundle["confirmation"])
        _mutate(confirmation, mutations)
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json"),
            confirmation=confirmation,
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "settlement_transaction_divergence":
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json")
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "confirmation_provider_error":
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json"),
            confirmation_error=True,
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "permission_expired":
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json"),
            now=bundle["expiry"],
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation == "replay":
        ledger = VerifiedCommitLedger(root / f"{case_id}-ledger.json")
        first = run_once(ledger, label=f"{case_id}-first")
        second = run_once(ledger, label=f"{case_id}-second")
        results = [first, second]
        case_results = results
        authorized_count = sum(
            int(bool(item.get("authorized"))) for item in results
        )
        blocked_count = len(results) - authorized_count
        reasons = sorted(
            {
                reason
                for item in results
                for reason in _reason_codes(item)
            }
        )
    elif operation == "concurrent":
        ledger = VerifiedCommitLedger(root / f"{case_id}-ledger.json")
        barrier = threading.Barrier(2)

        def concurrent_use(index: int) -> dict[str, Any]:
            barrier.wait()
            return run_once(ledger, label=f"{case_id}-{index}")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(concurrent_use, (1, 2)))
        case_results = results
        authorized_count = sum(
            int(bool(item.get("authorized"))) for item in results
        )
        blocked_count = len(results) - authorized_count
        reasons = sorted(
            {
                reason
                for item in results
                for reason in _reason_codes(item)
            }
        )
    elif operation in {
        "distinct_commit_replay",
        "distinct_commit_concurrent",
    }:
        distinct_bundles = [
            fixture.issue(f"{case_id}-first"),
            fixture.issue(f"{case_id}-second"),
        ]
        ledger = VerifiedCommitLedger(root / f"{case_id}-ledger.json")

        def distinct_use(index: int) -> dict[str, Any]:
            return run_once(
                ledger,
                selected_bundle=distinct_bundles[index],
                label=f"{case_id}-{index + 1}",
            )

        if operation == "distinct_commit_replay":
            results = [distinct_use(0), distinct_use(1)]
        else:
            barrier = threading.Barrier(2)

            def concurrent_distinct_use(index: int) -> dict[str, Any]:
                barrier.wait()
                return distinct_use(index)

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(
                    pool.map(concurrent_distinct_use, (0, 1))
                )
        case_results = results
        authorized_count = sum(
            int(bool(item.get("authorized"))) for item in results
        )
        blocked_count = len(results) - authorized_count
        reasons = sorted(
            {
                reason
                for item in results
                for reason in _reason_codes(item)
            }
        )
    elif operation in {"release_result_mutation", "release_provider_error"}:
        result = run_once(
            VerifiedCommitLedger(root / f"{case_id}-ledger.json")
        )
        case_results = [result]
        authorized_count = int(bool(result.get("authorized")))
        blocked_count = 1 - authorized_count
        reasons = _reason_codes(result)
    elif operation != "issue_settings_mutation":
        raise ValueError(f"unsupported operation: {operation}")

    released_count = sum(
        int(item.get("resource_released") is True)
        for item in case_results
    )
    observed = {
        "receipt_decision": receipt_decision,
        "authorized_count": authorized_count,
        "blocked_count": blocked_count,
        "settlement_calls": len(settlement_calls),
        "release_calls": len(release_calls),
        "released_count": released_count,
        "pre_effect_blocked": (
            blocked_count > 0
            and (
                len(settlement_calls) == 0
                or operation
                in {
                    "replay",
                    "concurrent",
                    "distinct_commit_replay",
                    "distinct_commit_concurrent",
                }
            )
        ),
        "reason_codes": reasons,
    }
    expected = dict(case["expected"])
    comparisons = {
        name: observed[name] == expected[name]
        for name in (
            "receipt_decision",
            "authorized_count",
            "blocked_count",
            "settlement_calls",
            "release_calls",
            "released_count",
            "pre_effect_blocked",
        )
    }
    comparisons["reason_contains"] = set(
        expected.get("reason_contains", [])
    ).issubset(observed["reason_codes"])
    return {
        "case_id": case_id,
        "operation": operation,
        "rule_ids": list(case["rule_ids"]),
        "falsifier_axis": case.get("falsifier_axis"),
        "passed": all(comparisons.values()),
        "comparisons": comparisons,
        "expected": expected,
        "observed": observed,
    }


def run(cases_path: Path, output_path: Path) -> dict[str, Any]:
    case_document = json.loads(cases_path.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="x402-hostile-suite-") as value:
        temporary = Path(value)
        results = [
            _execute_case(case, temporary / str(case["id"]))
            for case in case_document["cases"]
        ]
    rule_ids = sorted(
        {
            rule_id
            for result in results
            for rule_id in result["rule_ids"]
        }
    )
    required_axes = list(case_document["required_falsifier_axes"])
    axis_results = {
        axis: any(
            result["falsifier_axis"] == axis
            and result["passed"]
            and result["observed"]["pre_effect_blocked"]
            for result in results
        )
        for axis in required_axes
    }
    report = {
        "schema": "openline.x402-airlock.hostile-report.v1",
        "suite": "x402-airlock-hostile-v1",
        "run_at": "2026-07-28T08:00:00Z",
        "source": "arXiv:2607.19545v1",
        "valid": all(result["passed"] for result in results)
        and all(axis_results.values()),
        "case_count": len(results),
        "passed_cases": sum(result["passed"] for result in results),
        "failed_cases": [
            result["case_id"] for result in results if not result["passed"]
        ],
        "rules_covered": rule_ids,
        "required_falsifier_axes": axis_results,
        "settlement_callback_count": sum(
            result["observed"]["settlement_calls"] for result in results
        ),
        "release_callback_count": sum(
            result["observed"]["release_calls"] for result in results
        ),
        "resource_release_confirmed_count": sum(
            result["observed"]["released_count"] for result in results
        ),
        "results": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = run(args.cases, args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
