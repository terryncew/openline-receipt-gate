"""Top-level CLI router.

The v0.5 frozen continuation experiment pins :mod:`olp_gate.cli` byte-for-byte.
New v0.6 Handoff Check commands therefore live in this additive router, which
delegates every pre-existing command to the frozen CLI unchanged.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from importlib import resources

from . import cli as legacy_cli
from .crypto import load_private_key, strict_json_load, strict_json_loads
from .handoff import (
    HandoffAdapterError,
    HandoffCheckError,
    inspect_handoff,
    restore_items,
    write_handoff_outputs,
)


HANDOFF_COMMANDS = {"handoff-check", "handoff-inspect", "handoff-restore"}
ROLE_CONFUSION_COMMANDS = {"role-confusion-suite"}


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _handoff_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="olp-gate",
        description="OpenLine Receipt Gate with Handoff Check.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    check = sub.add_parser(
        "handoff-check",
        help="Build and independently verify a bounded fresh-agent continuation capsule.",
    )
    check.add_argument("history")
    check.add_argument("--next", dest="next_action", required=True)
    check.add_argument(
        "--source",
        choices=("auto", "claude-code", "codex", "generic"),
        default="auto",
    )
    check.add_argument("--repo")
    check.add_argument("--output", required=True)
    check.add_argument(
        "--key",
        help="Optional mode-0600 Ed25519 private key for a signed continuation receipt.",
    )

    inspect = sub.add_parser(
        "handoff-inspect",
        help="Compare an existing capsule against a current full-history replay.",
    )
    inspect.add_argument("history")
    inspect.add_argument("capsule")
    inspect.add_argument(
        "--next",
        dest="next_action",
        required=True,
        help="Receiver-pinned intended next action; never inferred from the capsule.",
    )
    inspect.add_argument(
        "--source",
        choices=("auto", "claude-code", "codex", "generic"),
        default="auto",
    )
    inspect.add_argument("--repo")

    restore = sub.add_parser(
        "handoff-restore",
        help="Restore canonical source events for indexed handoff items.",
    )
    restore.add_argument("handoff")
    restore.add_argument("--history", required=True)
    restore.add_argument("--item", action="append", required=True)
    restore.add_argument(
        "--source",
        choices=("auto", "claude-code", "codex", "generic"),
        default="auto",
    )
    restore.add_argument("--output")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "handoff-check":
            signing_key = load_private_key(args.key) if args.key else None
            result = write_handoff_outputs(
                args.history,
                args.output,
                next_action=args.next_action,
                source=args.source,
                repo=args.repo,
                signing_key=signing_key,
            )
            _print_json(result)
            return 0 if result["disposition"] == "SAFE_TO_CONTINUE" else 1
        if args.cmd == "handoff-inspect":
            result = inspect_handoff(
                args.history,
                args.capsule,
                next_action=args.next_action,
                source=args.source,
                repo=args.repo,
            )
            _print_json(result)
            return 0 if result["disposition"] == "SAFE_TO_CONTINUE" else 1
        if args.cmd == "handoff-restore":
            result = restore_items(
                args.handoff,
                args.history,
                args.item,
                source=args.source,
                output_path=args.output,
            )
            _print_json(result)
            return 0 if not result["missing_item_ids"] else 1
    except (HandoffAdapterError, HandoffCheckError, OSError, ValueError) as exc:
        _print_json(
            {
                "disposition": "UNDECIDABLE",
                "error": str(exc),
                "error_type": type(exc).__name__,
            }
        )
        return 1
    return 2


def _role_confusion_main(argv: list[str]) -> int:
    from .role_confusion import ConsequenceGateError, run_case_matrix

    parser = argparse.ArgumentParser(
        prog="olp-gate",
        description="Run the frozen receiver-side role-confusion consequence suite.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    suite = sub.add_parser(
        "role-confusion-suite",
        help="Show that model compromise need not become receiver execution authority.",
    )
    suite.add_argument(
        "--benchmark",
        help=(
            "Frozen benchmark directory. If omitted, use the source-tree fixture "
            "when present, otherwise the fixture packaged in the installed wheel."
        ),
    )
    suite.add_argument(
        "--output",
        help="Optional path for the complete hostile_report.json.",
    )
    args = parser.parse_args(argv)
    try:
        if args.benchmark:
            root = Path(args.benchmark)
            policy = strict_json_load(root / "receiver-policy.json")
            cases = strict_json_load(root / "cases.json")
        else:
            source_root = Path("benchmarks/role_confusion_consequence")
            if source_root.is_dir():
                policy = strict_json_load(source_root / "receiver-policy.json")
                cases = strict_json_load(source_root / "cases.json")
            else:
                packaged = resources.files("benchmarks.role_confusion_consequence")
                policy = strict_json_loads(
                    packaged.joinpath("receiver-policy.json").read_text(encoding="utf-8")
                )
                cases = strict_json_loads(
                    packaged.joinpath("cases.json").read_text(encoding="utf-8")
                )
        result = run_case_matrix(cases, policy)
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        _print_json({key: value for key, value in result.items() if key != "rows"})
        return 0 if result["passed"] else 2
    except (ConsequenceGateError, OSError, ValueError, json.JSONDecodeError) as exc:
        _print_json(
            {
                "passed": False,
                "decision": "UNDECIDABLE",
                "error": str(exc),
            }
        )
        return 2


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["-h"], ["--help"]):
        try:
            legacy_cli.main(args)
        except SystemExit as exc:
            print(
                "\nAdditional commands:\n"
                "  handoff-check         Build and verify a bounded continuation capsule.\n"
                "  handoff-inspect       Compare a capsule with current full history.\n"
                "  handoff-restore       Restore canonical source events for handoff items.\n"
                "  role-confusion-suite  Run the receiver-side consequence suite."
            )
            return int(exc.code or 0)
    if args and args[0] in HANDOFF_COMMANDS:
        return _handoff_main(args)
    if args and args[0] in ROLE_CONFUSION_COMMANDS:
        return _role_confusion_main(args)
    return legacy_cli.main(args)


if __name__ == "__main__":
    raise SystemExit(main())
