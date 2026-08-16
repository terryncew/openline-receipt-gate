#!/usr/bin/env python3
"""Execute a pinned official x402 wrapper and Receipt Gate side by side."""

from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.x402_airlock.fixture import (  # noqa: E402
    FIXED_NOW,
    SyntheticX402Fixture,
    clone,
)
from olp_gate.verified_commit import VerifiedCommitLedger  # noqa: E402
from olp_gate.x402_airlock import (  # noqa: E402
    X402_RELEASE_RESULT_PROFILE,
    execute_x402_once,
)


UPSTREAM_COMMIT = "167a828e8319aa7b403f4f4312489e9cffadff10"
UPSTREAM_SOURCE = Path("python/x402/mcp/server_async.py")
UPSTREAM_SOURCE_SHA256 = (
    "49354704d6a59e2d075fa21e258693632b26074097784edef76d3f9b8b4fd36c"
)
NATIVE_FAILURE_EFFECT = b"native tool effect before failed settlement\n"
NATIVE_SUCCESS_EFFECT = b"native tool effect before successful settlement\n"
AIRLOCK_SUCCESS_EFFECT = b"airlock release after confirmed settlement\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git_head(root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def verify_upstream_pin(root: Path) -> dict[str, Any]:
    source_path = root / UPSTREAM_SOURCE
    if _git_head(root) != UPSTREAM_COMMIT:
        raise RuntimeError("upstream_commit_mismatch")
    source_bytes = source_path.read_bytes()
    source_sha256 = sha256_bytes(source_bytes)
    if source_sha256 != UPSTREAM_SOURCE_SHA256:
        raise RuntimeError("upstream_source_sha256_mismatch")

    tree = ast.parse(source_bytes.decode("utf-8"))
    handler_lines: list[int] = []
    settlement_lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "handler":
            handler_lines.append(node.lineno)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "settle_payment"
        ):
            settlement_lines.append(node.lineno)
    if not handler_lines or not settlement_lines:
        raise RuntimeError("upstream_execution_calls_not_found")
    handler_line = min(handler_lines)
    settlement_line = min(settlement_lines)
    if handler_line >= settlement_line:
        raise RuntimeError("upstream_effect_no_longer_precedes_settlement")
    return {
        "commit": UPSTREAM_COMMIT,
        "source_path": UPSTREAM_SOURCE.as_posix(),
        "source_sha256": source_sha256,
        "handler_call_line": handler_line,
        "settlement_call_line": settlement_line,
        "handler_precedes_settlement": True,
    }


def _append_effect(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as handle:
        handle.write(value)


def _effect_count(path: Path, value: bytes) -> int:
    if not path.exists():
        return 0
    return path.read_bytes().count(value)


async def run_native(
    upstream_root: Path,
    effect_path: Path,
    *,
    settlement_succeeds: bool,
) -> dict[str, Any]:
    upstream_python = upstream_root / "python"
    sys.path.insert(0, str(upstream_python))
    try:
        from x402.mcp.server_async import (  # type: ignore[import-not-found]
            PaymentWrapperConfig,
            create_payment_wrapper,
        )
        from x402.schemas import (  # type: ignore[import-not-found]
            PaymentPayload,
            PaymentRequirements,
            SettleResponse,
        )
    finally:
        sys.path.pop(0)

    class ResourceServer:
        def __init__(self) -> None:
            self.verify_calls = 0
            self.settlement_calls = 0

        def find_matching_requirements(self, available, _payload):
            return available[0]

        async def verify_payment(self, _payload, _requirements):
            self.verify_calls += 1
            return SimpleNamespace(is_valid=True, invalid_reason=None)

        async def settle_payment(self, _payload, _requirements):
            self.settlement_calls += 1
            if not settlement_succeeds:
                raise RuntimeError("facilitator unavailable")
            return SettleResponse(
                success=True,
                transaction="0x" + "ab" * 32,
                network="eip155:84532",
            )

        async def create_payment_required_response(
            self, _accepts, _resource, error, _extensions=None
        ):
            return {"x402Version": 2, "accepts": [], "error": error}

    server = ResourceServer()
    requirements = PaymentRequirements(
        scheme="exact",
        network="eip155:84532",
        amount="1000",
        asset="USDC",
        pay_to="0xrecipient",
        max_timeout_seconds=300,
    )
    payload = PaymentPayload(
        x402_version=2,
        accepted=requirements,
        payload={"signature": "0x123"},
    )
    effect_bytes = (
        NATIVE_SUCCESS_EFFECT if settlement_succeeds else NATIVE_FAILURE_EFFECT
    )

    async def handler(_args, _context):
        _append_effect(effect_path, effect_bytes)
        return {
            "content": [{"type": "text", "text": "effect applied"}],
            "isError": False,
        }

    wrapped = create_payment_wrapper(
        server,
        PaymentWrapperConfig(accepts=[requirements]),
    )(handler)
    result = await wrapped(
        {"effect": "durable-write"},
        {
            "_meta": {"x402/payment": payload.model_dump()},
            "toolName": "paid_mutation",
        },
    )
    return {
        "verification_calls": server.verify_calls,
        "settlement_calls": server.settlement_calls,
        "returned_error": bool(result.is_error),
        "durable_tool_effect_count": _effect_count(effect_path, effect_bytes),
    }


def run_airlock_failure(effect_path: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="olp-x402-upstream-failure-") as temp:
        root = Path(temp)
        fixture = SyntheticX402Fixture(root)
        bundle = fixture.issue("pinned-upstream-failure")
        settlement_calls = 0
        release_calls = 0

        def settlement_executor(_settings):
            nonlocal settlement_calls
            settlement_calls += 1
            raise RuntimeError("facilitator unavailable")

        def release_executor(request):
            nonlocal release_calls
            release_calls += 1
            _append_effect(effect_path, AIRLOCK_SUCCESS_EFFECT)
            return {
                "profile": X402_RELEASE_RESULT_PROFILE,
                "released": True,
                "target": request["target"],
                "transaction_hash": request["confirmation"]["transaction_hash"],
            }

        raised = None
        try:
            execute_x402_once(
                VerifiedCommitLedger(root / "ledger.json"),
                bundle["receipt"],
                bundle["action"],
                one_use_code=bundle["code"],
                trusted_gate_keys=[bundle["gate_public_key"]],
                snapshot_provider=lambda: clone(bundle["snapshot"]),
                settlement_executor=settlement_executor,
                confirmation_provider=lambda _result: clone(bundle["confirmation"]),
                release_executor=release_executor,
                now=FIXED_NOW,
                attempt_label="pinned-upstream-failure",
            )
        except RuntimeError as exc:
            raised = str(exc)
        return {
            "settlement_calls": settlement_calls,
            "settlement_error": raised,
            "protected_release_calls": release_calls,
            "protected_effect_exists": effect_path.exists(),
        }


def run_airlock_success(effect_path: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="olp-x402-upstream-success-") as temp:
        root = Path(temp)
        fixture = SyntheticX402Fixture(root)
        bundle = fixture.issue("pinned-upstream-success")
        settlement_calls = 0
        release_calls = 0

        def settlement_executor(_settings):
            nonlocal settlement_calls
            settlement_calls += 1
            return {
                "submitted": True,
                "transaction_hash": bundle["confirmation"]["transaction_hash"],
            }

        def release_executor(request):
            nonlocal release_calls
            release_calls += 1
            _append_effect(effect_path, AIRLOCK_SUCCESS_EFFECT)
            return {
                "profile": X402_RELEASE_RESULT_PROFILE,
                "released": True,
                "target": request["target"],
                "transaction_hash": request["confirmation"]["transaction_hash"],
            }

        result = execute_x402_once(
            VerifiedCommitLedger(root / "ledger.json"),
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            snapshot_provider=lambda: clone(bundle["snapshot"]),
            settlement_executor=settlement_executor,
            confirmation_provider=lambda _result: clone(bundle["confirmation"]),
            release_executor=release_executor,
            now=FIXED_NOW,
            attempt_label="pinned-upstream-success",
        )
        return {
            "authorized": result.get("authorized") is True,
            "settlement_calls": settlement_calls,
            "settlement_confirmed": result.get("settlement_confirmed") is True,
            "protected_release_calls": release_calls,
            "protected_effect_count": _effect_count(
                effect_path, AIRLOCK_SUCCESS_EFFECT
            ),
            "resource_released": result.get("resource_released") is True,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--upstream-root",
        required=True,
        type=Path,
        help="Checkout of x402-foundation/x402 at the pinned commit.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            ROOT
            / "benchmarks"
            / "x402_upstream_consequence"
            / "results"
            / "comparison.json"
        ),
    )
    args = parser.parse_args()
    upstream_root = args.upstream_root.resolve()
    output = args.output.resolve()
    effect_root = output.parent / "effects"
    native_failure_path = effect_root / "native-failed-settlement.log"
    native_success_path = effect_root / "native-success.log"
    airlock_failure_path = effect_root / "airlock-failed-settlement.log"
    airlock_success_path = effect_root / "airlock-success.log"
    for path in (
        native_failure_path,
        native_success_path,
        airlock_failure_path,
        airlock_success_path,
    ):
        path.unlink(missing_ok=True)

    pin = verify_upstream_pin(upstream_root)
    native_failure = asyncio.run(
        run_native(upstream_root, native_failure_path, settlement_succeeds=False)
    )
    native_success = asyncio.run(
        run_native(upstream_root, native_success_path, settlement_succeeds=True)
    )
    airlock_failure = run_airlock_failure(airlock_failure_path)
    airlock_success = run_airlock_success(airlock_success_path)

    relative = lambda path: path.relative_to(ROOT).as_posix()
    artifacts = {
        relative(native_failure_path): sha256_bytes(native_failure_path.read_bytes()),
        relative(native_success_path): sha256_bytes(native_success_path.read_bytes()),
        relative(airlock_success_path): sha256_bytes(airlock_success_path.read_bytes()),
    }
    checks = {
        "upstream_handler_precedes_settlement": pin["handler_precedes_settlement"],
        "native_failure_returns_error": native_failure["returned_error"] is True,
        "native_failure_leaves_effect": (
            native_failure["durable_tool_effect_count"] == 1
        ),
        "native_success_control": (
            native_success["returned_error"] is False
            and native_success["durable_tool_effect_count"] == 1
        ),
        "airlock_failure_attempts_settlement": (
            airlock_failure["settlement_calls"] == 1
        ),
        "airlock_failure_withholds_release": (
            airlock_failure["protected_release_calls"] == 0
            and airlock_failure["protected_effect_exists"] is False
        ),
        "airlock_legitimate_control": (
            airlock_success["authorized"] is True
            and airlock_success["settlement_confirmed"] is True
            and airlock_success["resource_released"] is True
            and airlock_success["protected_release_calls"] == 1
            and airlock_success["protected_effect_count"] == 1
        ),
    }
    report = {
        "schema": "openline.x402_upstream_consequence_comparison.v1",
        "passed": all(checks.values()),
        "claim": (
            "At the pinned official Python MCP wrapper commit, a tool effect can "
            "precede a failed settlement; the disclosed Receipt Gate composition "
            "withholds protected release until matching settlement confirmation."
        ),
        "claim_boundary": (
            "Pinned Python MCP wrapper and local deterministic consequence only; "
            "not every x402 SDK, a live-chain exploit, or production certification."
        ),
        "upstream": pin,
        "observations": {
            "native_settlement_failure": native_failure,
            "native_success_control": native_success,
            "airlock_settlement_failure": airlock_failure,
            "airlock_success_control": airlock_success,
        },
        "checks": checks,
        "artifacts": artifacts,
        "expected_absent_artifact": relative(airlock_failure_path),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

