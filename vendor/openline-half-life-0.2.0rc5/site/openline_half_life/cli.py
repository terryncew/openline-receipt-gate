from __future__ import annotations

import argparse
import json
from contextlib import ExitStack
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from .causal_compactor import load_trusted_compaction_policy_keys
from .pipeline import run_pipeline
from .policy import load_trusted_policy_keys, write_demo_policy
from .receipts import verify_output_directory


def _command_succeeded(command: str, result: Mapping[str, Any]) -> bool:
    if command == "verify":
        return result.get("valid") is True
    if command in {"run", "demo"}:
        return (
            result.get("verification", {}).get("valid") is True
            and result.get("comparison", {}).get("passed") is True
            and result.get("compaction", {}).get("decision_equivalence_passed") is True
        )
    return True


def _resource(stack: ExitStack, *parts: str) -> Path:
    target = resources.files("openline_half_life").joinpath(*parts)
    return stack.enter_context(resources.as_file(target))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="openline-half-life")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="compare handoffs and compact the verified receipt chain")
    run.add_argument("trajectory", type=Path)
    run.add_argument("--exam", type=Path, required=True)
    run.add_argument("--policy", type=Path, required=True)
    run.add_argument("--policy-public-key", type=Path, required=True)
    run.add_argument("--compaction-policy", type=Path, required=True)
    run.add_argument("--compaction-policy-public-key", type=Path, required=True)
    run.add_argument("--signing-key", type=Path, required=True)
    run.add_argument("--receiver-approval-signing-key", type=Path, required=True)
    run.add_argument("--replay-latency-micros", type=int, required=True)
    run.add_argument("--receiver-disposition", choices=["APPROVE", "DENY"], required=True)
    run.add_argument("--out", type=Path, required=True)

    verify = sub.add_parser(
        "verify", help="verify policy trust, source chain, cold archive, compaction, and artifacts"
    )
    verify.add_argument("output_dir", type=Path)
    verify.add_argument("--policy-public-key", type=Path, required=True)
    verify.add_argument("--compaction-policy-public-key", type=Path, required=True)

    policy = sub.add_parser("build-demo-policy", help="regenerate the synthetic canonical succession policy")
    policy.add_argument("--out", type=Path, required=True)

    demo = sub.add_parser("demo", help="run the deterministic three-minute demo with causal compaction")
    demo.add_argument("--out", type=Path, default=Path("build/demo"))
    demo.add_argument("--replay-latency-micros", type=int, default=75_000)

    args = parser.parse_args(argv)
    if args.command == "run":
        result = run_pipeline(
            args.trajectory,
            args.exam,
            args.policy,
            args.policy_public_key,
            args.signing_key,
            args.out,
            compaction_policy_path=args.compaction_policy,
            compaction_policy_public_key_path=args.compaction_policy_public_key,
            replay_latency_micros=args.replay_latency_micros,
            receiver_approval_signing_key_path=args.receiver_approval_signing_key,
            receiver_disposition=args.receiver_disposition,
        )
    elif args.command == "verify":
        result = verify_output_directory(
            args.output_dir,
            expected_policy_public_keys=load_trusted_policy_keys(args.policy_public_key),
            expected_compaction_policy_public_keys=load_trusted_compaction_policy_keys(
                args.compaction_policy_public_key
            ),
        )
    elif args.command == "build-demo-policy":
        result = {"policy": str(args.out), "payload_hash": write_demo_policy(args.out)["payload_hash"]}
    else:
        with ExitStack() as stack:
            result = run_pipeline(
                _resource(stack, "data", "fixtures", "gradual_drift.jsonl"),
                _resource(stack, "data", "exams", "heldout_exam.json"),
                _resource(stack, "data", "policy", "succession_policy.json"),
                _resource(stack, "data", "policy", "succession_policy_public_key.hex"),
                _resource(stack, "data", "fixtures", "demo_signing_key.hex"),
                args.out,
                compaction_policy_path=_resource(stack, "data", "policy", "compaction_policy.json"),
                compaction_policy_public_key_path=_resource(
                    stack, "data", "policy", "compaction_policy_public_key.hex"
                ),
                replay_latency_micros=args.replay_latency_micros,
                receiver_approval_signing_key_path=_resource(
                    stack, "data", "fixtures", "demo_receiver_approval_key.hex"
                ),
                receiver_disposition="APPROVE",
            )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if _command_succeeded(args.command, result) else 1
