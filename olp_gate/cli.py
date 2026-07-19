from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapters import TrustStore
from .crypto import generate_private_key_file, load_private_key, strict_json_load
from .demo import run_demo
from .gateway import evaluate_request, verify_decision_log
from .model_swap import run_verified_model_swap, verify_model_swap_output
from .policy import PolicySpec
from .receipts import verify_chain, summarize_badge, review_packet
from .session import SessionLedger
from .verified_commit import run_verified_commit_demo, verify_verified_commit_output


def print_json(obj: object) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="olp-gate", description="Verify and inspect OpenLine Receipt Gate logs.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_verify = sub.add_parser("verify", help="Verify hash chain integrity.")
    p_verify.add_argument("path")

    p_badge = sub.add_parser("badge", help="Summarize receipt decisions into a badge.")
    p_badge.add_argument("path")

    p_review = sub.add_parser("review", help="Produce review packet for quarantined/no-badge actions.")
    p_review.add_argument("path")

    p_keygen = sub.add_parser("keygen", help="Create a mode-0600 Ed25519 decision-gate key.")
    p_keygen.add_argument("path")

    p_challenge = sub.add_parser("challenge", help="Issue a one-time decision challenge.")
    p_challenge.add_argument("ledger")
    p_challenge.add_argument("--run-id", required=True)
    p_challenge.add_argument("--session-id", required=True)
    p_challenge.add_argument("--source-hash", required=True)
    p_challenge.add_argument("--ttl", type=int, default=300)

    p_decide = sub.add_parser("decide", help="Evaluate evidence and emit a signed policy decision.")
    p_decide.add_argument("request")
    p_decide.add_argument("--policy", required=True)
    p_decide.add_argument("--trust", required=True)
    p_decide.add_argument("--key", required=True)
    p_decide.add_argument("--issuer", required=True)
    p_decide.add_argument("--ledger", required=True)
    p_decide.add_argument("--out", default="receipts/decision_receipts.jsonl")
    p_decide.add_argument(
        "--assay-bin",
        help=(
            "Trusted Assay 3.32.0 CLI path for assay_evidence_bundle_v1 input; "
            "may also be set with OLP_ASSAY_BIN."
        ),
    )

    p_verify_decision = sub.add_parser("verify-decision", help="Verify signed decision receipts and accepted chains.")
    p_verify_decision.add_argument("path")
    p_verify_decision.add_argument(
        "--gate-key",
        action="append",
        required=True,
        help="Trusted 32-byte gate public key in hex; repeat during key rotation.",
    )

    p_demo = sub.add_parser("demo-proof-to-policy", help="Run the five discriminating proof-to-policy cases.")
    p_demo.add_argument("--output", default="results/proof_to_policy_demo")

    def add_model_swap_inputs(target: argparse.ArgumentParser) -> None:
        target.add_argument("--half-life-output", required=True)
        target.add_argument("--succession-policy-key", required=True)
        target.add_argument("--compaction-policy-key", required=True)
        target.add_argument("--source-model", required=True)
        target.add_argument("--target-model", required=True)
        target.add_argument("--output", required=True)
        target.add_argument("--source-adapter", default="offline-deterministic-source-v1")
        target.add_argument("--target-adapter", default="offline-deterministic-target-v1")
        target.add_argument("--trial-id", default="verified-model-swap-demo")

    p_model_swap = sub.add_parser(
        "model-swap",
        help="Independently grade three continuity lanes and issue a receiver decision.",
    )
    add_model_swap_inputs(p_model_swap)
    p_model_swap.add_argument("--source-key", required=True)
    p_model_swap.add_argument("--grader-key", required=True)
    p_model_swap.add_argument("--gate-key", required=True)
    p_model_swap.add_argument("--issuer", required=True)
    p_model_swap.add_argument(
        "--commit-action",
        help="JSON file containing exactly tool, target, and settings.",
    )
    p_model_swap.add_argument(
        "--commit-code-file",
        help="Mode-0600 file containing the receiver-held 64-hex one-use code.",
    )
    p_model_swap.add_argument("--commit-ttl", type=int, default=300)

    p_model_swap_demo = sub.add_parser(
        "demo-model-swap",
        help="Run the offline model-swap fixture with public, non-production keys.",
    )
    add_model_swap_inputs(p_model_swap_demo)

    p_commit_demo = sub.add_parser(
        "demo-verified-commit",
        help="Prove Model A -> Model B followed by one receiver-approved action.",
    )
    add_model_swap_inputs(p_commit_demo)

    p_verify_model_swap = sub.add_parser(
        "verify-model-swap",
        help="Regrade a model-swap proof and verify its signed receiver decision.",
    )
    p_verify_model_swap.add_argument("output")
    p_verify_model_swap.add_argument("--half-life-output", required=True)
    p_verify_model_swap.add_argument("--succession-policy-key", required=True)
    p_verify_model_swap.add_argument("--compaction-policy-key", required=True)
    p_verify_model_swap.add_argument("--gate-key", action="append", required=True)

    p_verify_commit = sub.add_parser(
        "verify-verified-commit",
        help="Recheck the signed permission and receiver-side execution record.",
    )
    p_verify_commit.add_argument("output")
    p_verify_commit.add_argument("--half-life-output", required=True)
    p_verify_commit.add_argument("--succession-policy-key", required=True)
    p_verify_commit.add_argument("--compaction-policy-key", required=True)
    p_verify_commit.add_argument("--gate-key", action="append", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "verify":
        result = verify_chain(args.path)
        print_json(result)
        return 0 if result["valid"] else 2

    if args.cmd == "badge":
        result = summarize_badge(args.path)
        print_json(result)
        return 0 if result["badge"] == "PASS" else 1

    if args.cmd == "review":
        result = review_packet(args.path)
        print_json(result)
        return 0

    if args.cmd == "keygen":
        public_key = generate_private_key_file(args.path)
        print_json({"private_key_path": args.path, "public_key": public_key})
        return 0

    if args.cmd == "challenge":
        result = SessionLedger(args.ledger).issue_challenge(
            run_id=args.run_id,
            session_id=args.session_id,
            expected_source_hash=args.source_hash,
            ttl_seconds=args.ttl,
        )
        print_json(result)
        return 0

    if args.cmd == "decide":
        request_path = Path(args.request)
        request = strict_json_load(request_path)
        policy = PolicySpec.from_mapping(strict_json_load(args.policy))
        trust = TrustStore.from_mapping(strict_json_load(args.trust))
        result = evaluate_request(
            request,
            policy=policy,
            trust_store=trust,
            signing_key=load_private_key(args.key),
            issuer_id=args.issuer,
            decision_path=args.out,
            session_ledger=SessionLedger(args.ledger),
            base_dir=request_path.parent,
            assay_binary=args.assay_bin,
        )
        print_json(result)
        return 0 if result["decision"] == "COMMIT" else 1

    if args.cmd == "verify-decision":
        result = verify_decision_log(args.path, args.gate_key)
        print_json(result)
        return 0 if result["valid"] else 2

    if args.cmd == "demo-proof-to-policy":
        result = run_demo(args.output)
        print_json(result)
        return 0 if result["passed"] else 2

    if args.cmd in {"model-swap", "demo-model-swap"}:
        if args.cmd == "demo-model-swap":
            source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("51" * 32))
            grader_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("52" * 32))
            gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("53" * 32))
            issuer = "openline-public-model-swap-demo-gate"
        else:
            source_key = load_private_key(args.source_key)
            grader_key = load_private_key(args.grader_key)
            gate_key = load_private_key(args.gate_key)
            issuer = args.issuer
        commit_action = None
        commit_code = None
        if args.cmd == "model-swap":
            if bool(args.commit_action) != bool(args.commit_code_file):
                parser.error("--commit-action and --commit-code-file must be used together")
            if args.commit_action:
                commit_action = strict_json_load(args.commit_action)
                commit_code_path = Path(args.commit_code_file)
                if commit_code_path.stat().st_mode & 0o077:
                    parser.error("--commit-code-file must not be group/world accessible")
                commit_code = commit_code_path.read_text(encoding="ascii").strip()
        result = run_verified_model_swap(
            args.half_life_output,
            args.output,
            succession_policy_public_key_path=args.succession_policy_key,
            compaction_policy_public_key_path=args.compaction_policy_key,
            source_model=args.source_model,
            target_model=args.target_model,
            source_signing_key=source_key,
            grader_signing_key=grader_key,
            gate_signing_key=gate_key,
            gate_issuer=issuer,
            source_adapter=args.source_adapter,
            target_adapter=args.target_adapter,
            trial_id=args.trial_id,
            commit_action=commit_action,
            commit_one_use_code=commit_code,
            commit_ttl_seconds=(args.commit_ttl if args.cmd == "model-swap" else 300),
        )
        print_json(result)
        return 0 if result["passed"] else 2

    if args.cmd == "verify-model-swap":
        result = verify_model_swap_output(
            args.output,
            trusted_gate_keys=args.gate_key,
            half_life_output=args.half_life_output,
            succession_policy_public_key_path=args.succession_policy_key,
            compaction_policy_public_key_path=args.compaction_policy_key,
        )
        print_json(result)
        return 0 if result["valid"] else 2

    if args.cmd == "demo-verified-commit":
        source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("51" * 32))
        grader_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("52" * 32))
        gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("53" * 32))
        result = run_verified_commit_demo(
            args.half_life_output,
            args.output,
            succession_policy_public_key_path=args.succession_policy_key,
            compaction_policy_public_key_path=args.compaction_policy_key,
            source_model=args.source_model,
            target_model=args.target_model,
            source_signing_key=source_key,
            grader_signing_key=grader_key,
            gate_signing_key=gate_key,
            gate_issuer="openline-public-verified-commit-demo-gate",
            source_adapter=args.source_adapter,
            target_adapter=args.target_adapter,
            trial_id=args.trial_id,
        )
        print_json(result)
        return 0 if result["passed"] else 2

    if args.cmd == "verify-verified-commit":
        result = verify_verified_commit_output(
            args.output,
            trusted_gate_keys=args.gate_key,
            half_life_output=args.half_life_output,
            succession_policy_public_key_path=args.succession_policy_key,
            compaction_policy_public_key_path=args.compaction_policy_key,
        )
        print_json(result)
        return 0 if result["valid"] else 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
