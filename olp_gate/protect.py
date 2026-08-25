"""Guided policy authoring for consequential tool boundaries.

The public surface deliberately asks application questions rather than exposing
OpenLine's internal authorization vocabulary. The generator never chooses the
principal, money limits, freshness window, or policy lifetime on the caller's
behalf. Those values must be supplied or explicitly accepted interactively.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
import sys
from typing import Callable, Sequence


class ProtectError(ValueError):
    """Raised when a protection starter would be ambiguous or unsafe."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_rfc3339(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ProtectError("policy_expiry_required")
    raw = value.strip()
    candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ProtectError("policy_expiry_invalid") from exc
    if parsed.tzinfo is None:
        raise ProtectError("policy_expiry_timezone_required")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_money_to_cents(value: str) -> int:
    """Parse a human money value without ever passing through binary float."""
    if not isinstance(value, str) or not value.strip():
        raise ProtectError("money_value_required")
    raw = value.strip().replace(",", "")
    if raw.startswith("$"):
        raw = raw[1:]
    try:
        amount = Decimal(raw)
    except InvalidOperation as exc:
        raise ProtectError("money_value_invalid") from exc
    if not amount.is_finite() or amount < 0:
        raise ProtectError("money_value_invalid")
    cents = amount * 100
    if cents != cents.to_integral_value():
        raise ProtectError("money_value_must_have_at_most_two_decimals")
    return int(cents)


def _slug(value: str) -> str:
    candidate = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return candidate or "receiver"


@dataclass(frozen=True)
class RefundProtectionConfig:
    owner: str
    autonomous_limit_cents: int
    hard_limit_cents: int
    approval_max_age_seconds: int
    authorization_ttl_seconds: int
    expires_at: str
    agent_id: str = "refund-agent"
    tool: str = "process_refund"
    target: str = "refund://process"
    purpose: str = "customer refunds"
    currency: str = "USD"

    def validate(self, *, now: datetime | None = None) -> "RefundProtectionConfig":
        current = now or _utc_now()
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        current = current.astimezone(timezone.utc)
        if not self.owner.strip():
            raise ProtectError("owner_required")
        if not self.agent_id.strip():
            raise ProtectError("agent_id_required")
        if not self.tool.strip():
            raise ProtectError("tool_required")
        if not self.target.strip():
            raise ProtectError("target_required")
        if not self.purpose.strip():
            raise ProtectError("purpose_required")
        if self.currency != "USD":
            raise ProtectError("refund_template_currency_must_be_USD")
        if self.autonomous_limit_cents < 0:
            raise ProtectError("autonomous_limit_invalid")
        if self.hard_limit_cents <= 0:
            raise ProtectError("hard_limit_must_be_positive")
        if self.autonomous_limit_cents > self.hard_limit_cents:
            raise ProtectError("autonomous_limit_exceeds_hard_limit")
        if self.approval_max_age_seconds <= 0:
            raise ProtectError("approval_max_age_must_be_positive")
        if self.authorization_ttl_seconds <= 0:
            raise ProtectError("authorization_ttl_must_be_positive")
        if self.authorization_ttl_seconds > self.approval_max_age_seconds:
            raise ProtectError("authorization_ttl_exceeds_approval_freshness")
        expiry = _parse_rfc3339(self.expires_at)
        if expiry <= current:
            raise ProtectError("policy_expiry_must_be_in_future")
        return RefundProtectionConfig(
            owner=self.owner.strip(),
            autonomous_limit_cents=self.autonomous_limit_cents,
            hard_limit_cents=self.hard_limit_cents,
            approval_max_age_seconds=self.approval_max_age_seconds,
            authorization_ttl_seconds=self.authorization_ttl_seconds,
            expires_at=_iso(expiry),
            agent_id=self.agent_id.strip(),
            tool=self.tool.strip(),
            target=self.target.strip(),
            purpose=self.purpose.strip(),
            currency=self.currency,
        )


def build_refund_policy(config: RefundProtectionConfig) -> dict:
    config = config.validate()
    base = _slug(config.tool)
    return {
        "schema": "openline.authorized_tool_policy.v1",
        "mandate": {
            "profile": "principal_mandate/v1",
            "mandate_id": f"{base}-mandate",
            "principal_id": config.owner,
            "agent_id": config.agent_id,
            "purpose": config.purpose,
            "allowed_action_types": ["authorize_payment"],
            "allowed_targets": [config.target],
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": config.hard_limit_cents,
            "delegation_allowed": False,
            "expires_at": config.expires_at,
            "version": "1",
        },
        "permission_policy": {
            "profile": "decision_permission_policy/v1",
            "policy_id": f"{base}-permission",
            "version": "1",
            "routes": [
                {
                    "route_id": "refund",
                    "tool": config.tool,
                    "target": config.target,
                    "requirements": [
                        {
                            "requirement_id": "refund_authority",
                            "kind": "authority",
                            "accepted_issuers": ["refund_authority"],
                            "max_age_seconds": config.approval_max_age_seconds,
                            "independent_from_producer": True,
                        }
                    ],
                    "unknown_behavior": "QUARANTINE",
                    "max_authorization_ttl_seconds": config.authorization_ttl_seconds,
                }
            ],
        },
    }


def _render_guard(config: RefundProtectionConfig) -> str:
    return f'''"""Starter guard generated by ``olp-gate protect refund``.

The values in this file came from your answers. OpenLine did not choose who may
act, the dollar limits, or how long an approval remains usable.
"""
from __future__ import annotations

from pathlib import Path

from olp_gate import EvidenceAssertion, authorize, payment_semantics


AUTONOMOUS_LIMIT_CENTS = {config.autonomous_limit_cents}
APPROVAL_MAX_AGE_SECONDS = {config.approval_max_age_seconds}
POLICY = Path(__file__).with_name("refund_policy.json")


def current_refund_state(call):
    """Return receiver-owned facts that should be checked again before execution.

    Replace ``refund_enabled`` with your application's real state when this can
    change at runtime. Keep mutable safety facts here rather than in model text.
    """
    return {{
        "refund_enabled": True,
        "customer_id": call.arguments["customer_id"],
    }}


def trusted_high_value_approval(call):
    """Connect your real human/workflow approval source here.

    Returning ``None`` deliberately keeps larger refunds blocked. Do not replace
    this with model reasoning or caller-supplied text.
    """
    return None


def refund_authority(call):
    amount_cents = call.arguments["amount_cents"]
    if amount_cents <= AUTONOMOUS_LIMIT_CENTS:
        return EvidenceAssertion(
            payload={{
                "basis": "receiver_selected_autonomous_limit",
                "amount_cents": amount_cents,
                "customer_id": call.arguments["customer_id"],
            }},
            issuer_id="refund_authority",
            expires_in_seconds=APPROVAL_MAX_AGE_SECONDS,
        )
    return trusted_high_value_approval(call)


refund_guard = authorize(
    policy=POLICY,
    tool={config.tool!r},
    target={config.target!r},
    semantics=payment_semantics("amount_cents"),
    state_source=current_refund_state,
    evidence_sources={{"refund_authority": refund_authority}},
)

# Use it directly:
#
# @refund_guard
# def {config.tool}(amount_cents: int, customer_id: str):
#     return payment_api.refund(amount_cents, customer_id)
'''


def _render_readme(config: RefundProtectionConfig) -> str:
    auto = f"{config.autonomous_limit_cents / 100:.2f}"
    hard = f"{config.hard_limit_cents / 100:.2f}"
    return f"""# Refund protection starter

This folder was generated from rules you chose.

- The agent is acting for **{config.owner}**.
- Refunds up to **${auto}** can use the automatic rule you approved.
- Refunds above **${auto}** stay blocked until `trusted_high_value_approval()` is connected to a trusted approval source.
- Refunds above **${hard}** are denied by the policy even if an approval is presented.
- Approval evidence may be at most **{config.approval_max_age_seconds} seconds** old.
- A cleared action may wait at most **{config.authorization_ttl_seconds} seconds** before it must be checked again.
- This policy expires at **{config.expires_at}**.

## Wire it into your function

```python
from .refund_guard import refund_guard

@refund_guard
def {config.tool}(amount_cents: int, customer_id: str):
    return payment_api.refund(amount_cents, customer_id)
```

Keep money as integer cents at the function boundary. Before production use, replace the placeholder state and high-value approval functions in `refund_guard.py` with receiver-owned sources. If those sources are unavailable, leave them unavailable; do not substitute model output as approval.

`refund_policy.json` contains the machine-enforced ceiling and freshness rules. `answers.json` records exactly what you selected when this starter was generated.
"""


def _render_generated_test(config: RefundProtectionConfig) -> str:
    return f'''from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class GeneratedRefundPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "refund_policy.json").read_text(encoding="utf-8"))

    def test_hard_limit_is_exactly_what_was_selected(self):
        self.assertEqual(self.policy["mandate"]["max_payment_cents"], {config.hard_limit_cents})

    def test_unknown_approval_fails_closed(self):
        route = self.policy["permission_policy"]["routes"][0]
        self.assertEqual(route["unknown_behavior"], "QUARANTINE")
        self.assertEqual(route["requirements"][0]["requirement_id"], "refund_authority")

    def test_policy_is_bound_to_the_selected_function(self):
        route = self.policy["permission_policy"]["routes"][0]
        self.assertEqual(route["tool"], {config.tool!r})
        self.assertEqual(route["target"], {config.target!r})


if __name__ == "__main__":
    unittest.main()
'''


def write_refund_starter(
    config: RefundProtectionConfig,
    output: str | Path,
    *,
    force: bool = False,
) -> list[Path]:
    config = config.validate()
    root = Path(output)
    files = {
        root / "refund_policy.json": json.dumps(
            build_refund_policy(config), indent=2, sort_keys=False
        ) + "\n",
        root / "refund_guard.py": _render_guard(config),
        root / "README.md": _render_readme(config),
        root / "test_refund_policy.py": _render_generated_test(config),
        root / "answers.json": json.dumps(
            {
                "template": "refund",
                "owner": config.owner,
                "agent_id": config.agent_id,
                "tool": config.tool,
                "target": config.target,
                "purpose": config.purpose,
                "currency": config.currency,
                "autonomous_limit_cents": config.autonomous_limit_cents,
                "hard_limit_cents": config.hard_limit_cents,
                "approval_max_age_seconds": config.approval_max_age_seconds,
                "authorization_ttl_seconds": config.authorization_ttl_seconds,
                "expires_at": config.expires_at,
            },
            indent=2,
        ) + "\n",
    }
    existing = [path for path in files if path.exists()]
    if existing and not force:
        names = ",".join(str(path) for path in existing)
        raise ProtectError(f"output_exists:{names}")
    root.mkdir(parents=True, exist_ok=True)
    for path, content in files.items():
        path.write_text(content, encoding="utf-8")
    return list(files)


def _ask(
    label: str,
    current: str | None,
    *,
    default: str | None = None,
    input_fn: Callable[[str], str] = input,
) -> str:
    if current is not None:
        return current
    suffix = f" [{default}]" if default is not None else ""
    answer = input_fn(f"{label}{suffix}: ").strip()
    if answer:
        return answer
    if default is not None:
        return default
    raise ProtectError("answer_required")


def _config_from_args(
    ns: argparse.Namespace,
    *,
    input_fn: Callable[[str], str] = input,
) -> RefundProtectionConfig:
    if ns.non_interactive:
        required = {
            "--owner": ns.owner,
            "--autonomous-limit": ns.autonomous_limit,
            "--hard-limit": ns.hard_limit,
            "--approval-max-age": ns.approval_max_age,
            "--authorization-ttl": ns.authorization_ttl,
            "--expires-at": ns.expires_at,
        }
        missing = [flag for flag, value in required.items() if value is None]
        if missing:
            raise ProtectError("non_interactive_missing:" + ",".join(missing))
    owner = _ask("Who is the agent acting for", ns.owner, input_fn=input_fn)
    autonomous = _ask(
        "Largest refund the agent may issue without fresh human approval (USD)",
        ns.autonomous_limit,
        input_fn=input_fn,
    )
    hard = _ask(
        "Absolute maximum refund this function may issue (USD)",
        ns.hard_limit,
        input_fn=input_fn,
    )
    approval_age = _ask(
        "How many seconds may approval evidence remain fresh",
        None if ns.approval_max_age is None else str(ns.approval_max_age),
        default="300",
        input_fn=input_fn,
    )
    ttl = _ask(
        "How many seconds may a cleared refund wait before it must be checked again",
        None if ns.authorization_ttl is None else str(ns.authorization_ttl),
        default="120",
        input_fn=input_fn,
    )
    expires = _ask(
        "When should this policy expire (RFC3339 UTC)",
        ns.expires_at,
        input_fn=input_fn,
    )
    try:
        approval_seconds = int(approval_age)
        ttl_seconds = int(ttl)
    except ValueError as exc:
        raise ProtectError("seconds_value_invalid") from exc
    return RefundProtectionConfig(
        owner=owner,
        autonomous_limit_cents=parse_money_to_cents(autonomous),
        hard_limit_cents=parse_money_to_cents(hard),
        approval_max_age_seconds=approval_seconds,
        authorization_ttl_seconds=ttl_seconds,
        expires_at=expires,
        agent_id=ns.agent_id,
        tool=ns.tool,
        target=ns.target,
        purpose=ns.purpose,
        currency="USD",
    ).validate()


def _summary(config: RefundProtectionConfig, output: Path) -> str:
    return "\n".join(
        [
            "Protect this refund function with these rules:",
            f"  Acts for:              {config.owner}",
            f"  Function:              {config.tool}",
            f"  Automatic limit:       ${config.autonomous_limit_cents / 100:.2f}",
            f"  Absolute limit:        ${config.hard_limit_cents / 100:.2f}",
            f"  Approval freshness:    {config.approval_max_age_seconds}s",
            f"  Recheck window:        {config.authorization_ttl_seconds}s",
            f"  Policy expires:        {config.expires_at}",
            f"  Write starter to:      {output}",
        ]
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="olp-gate protect",
        description="Turn plain application rules into a fail-closed OpenLine starter.",
    )
    sub = parser.add_subparsers(dest="template", required=True)
    refund = sub.add_parser(
        "refund", description="Protect a refund function without learning OpenLine internals."
    )
    refund.add_argument("--owner", help="Person or organization the agent acts for")
    refund.add_argument("--autonomous-limit", help="USD amount allowed by the automatic rule")
    refund.add_argument("--hard-limit", help="Absolute USD ceiling for this function")
    refund.add_argument("--approval-max-age", type=int, help="Maximum age of approval evidence in seconds")
    refund.add_argument("--authorization-ttl", type=int, help="Maximum wait before a cleared action is rechecked")
    refund.add_argument("--expires-at", help="Policy expiry as timezone-aware RFC3339")
    refund.add_argument("--agent-id", default="refund-agent")
    refund.add_argument("--tool", default="process_refund")
    refund.add_argument("--target", default="refund://process")
    refund.add_argument("--purpose", default="customer refunds")
    refund.add_argument("--output", default=".openline/refund")
    refund.add_argument("--non-interactive", action="store_true")
    refund.add_argument("--yes", action="store_true", help="Write without the final confirmation prompt")
    refund.add_argument("--force", action="store_true", help="Replace an existing generated starter")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    input_fn: Callable[[str], str] = input,
    out=sys.stdout,
    err=sys.stderr,
) -> int:
    parser = _build_parser()
    ns = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if ns.template != "refund":
            raise ProtectError("template_unsupported")
        config = _config_from_args(ns, input_fn=input_fn)
        output = Path(ns.output)
        print(_summary(config, output), file=out)
        if ns.non_interactive and not ns.yes:
            raise ProtectError("non_interactive_requires_yes")
        if not ns.yes:
            confirmation = input_fn("Write these files? [y/N]: ").strip().lower()
            if confirmation not in {"y", "yes"}:
                print("No files written.", file=out)
                return 1
        written = write_refund_starter(config, output, force=ns.force)
    except ProtectError as exc:
        print(f"protect: {exc}", file=err)
        return 2
    print(f"Wrote {len(written)} files to {output}", file=out)
    print("Next: connect trusted_high_value_approval() before allowing larger refunds.", file=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
