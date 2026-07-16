from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapters import TrustStore
from .crypto import generate_private_key_file, load_private_key, strict_json_load
from .demo import run_demo
from .gateway import evaluate_request, verify_decision_log
from .policy import PolicySpec
from .receipts import verify_chain, summarize_badge, review_packet
from .session import SessionLedger


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

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
