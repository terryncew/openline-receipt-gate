"""Guided policy authoring for consequential tool boundaries.

`olp-gate protect` exposes small application-specific policy packs. Each pack
asks ordinary product questions, records the developer's answers, and compiles
them into the existing OpenLine authorization path. Packs do not create new
execution authority and do not let the generator choose consequential values
on the developer's behalf.
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
from typing import Any, Callable, Mapping, Sequence


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


def _validate_window(
    approval_max_age_seconds: int,
    authorization_ttl_seconds: int,
    expires_at: str,
    *,
    now: datetime | None = None,
) -> str:
    current = now or _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    if approval_max_age_seconds <= 0:
        raise ProtectError("approval_max_age_must_be_positive")
    if authorization_ttl_seconds <= 0:
        raise ProtectError("authorization_ttl_must_be_positive")
    if authorization_ttl_seconds > approval_max_age_seconds:
        raise ProtectError("authorization_ttl_exceeds_approval_freshness")
    expiry = _parse_rfc3339(expires_at)
    if expiry <= current:
        raise ProtectError("policy_expiry_must_be_in_future")
    return _iso(expiry)


def _validate_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtectError(f"{name}_required")
    return value.strip()


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


def _normalize_recipients(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted({item.strip() for item in values if item.strip()}))


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
        owner = _validate_text(self.owner, "owner")
        agent_id = _validate_text(self.agent_id, "agent_id")
        tool = _validate_text(self.tool, "tool")
        target = _validate_text(self.target, "target")
        purpose = _validate_text(self.purpose, "purpose")
        if self.currency != "USD":
            raise ProtectError("refund_template_currency_must_be_USD")
        if self.autonomous_limit_cents < 0:
            raise ProtectError("autonomous_limit_invalid")
        if self.hard_limit_cents <= 0:
            raise ProtectError("hard_limit_must_be_positive")
        if self.autonomous_limit_cents > self.hard_limit_cents:
            raise ProtectError("autonomous_limit_exceeds_hard_limit")
        expires_at = _validate_window(
            self.approval_max_age_seconds,
            self.authorization_ttl_seconds,
            self.expires_at,
            now=now,
        )
        return RefundProtectionConfig(
            owner=owner,
            autonomous_limit_cents=self.autonomous_limit_cents,
            hard_limit_cents=self.hard_limit_cents,
            approval_max_age_seconds=self.approval_max_age_seconds,
            authorization_ttl_seconds=self.authorization_ttl_seconds,
            expires_at=expires_at,
            agent_id=agent_id,
            tool=tool,
            target=target,
            purpose=purpose,
            currency=self.currency,
        )


@dataclass(frozen=True)
class SendMessageProtectionConfig:
    owner: str
    allowed_recipients: tuple[str, ...]
    content_mode: str
    approval_max_age_seconds: int
    authorization_ttl_seconds: int
    expires_at: str
    agent_id: str = "messaging-agent"
    tool: str = "send_message"
    target: str = "message://send"
    purpose: str = "send messages for the principal"
    disclosure_class: str = "message_content"

    def validate(self, *, now: datetime | None = None) -> "SendMessageProtectionConfig":
        owner = _validate_text(self.owner, "owner")
        agent_id = _validate_text(self.agent_id, "agent_id")
        tool = _validate_text(self.tool, "tool")
        target = _validate_text(self.target, "target")
        purpose = _validate_text(self.purpose, "purpose")
        disclosure_class = _validate_text(self.disclosure_class, "disclosure_class")
        recipients = _normalize_recipients(self.allowed_recipients)
        if self.content_mode not in {"exact-approval", "autonomous-for-listed"}:
            raise ProtectError("content_mode_invalid")
        if self.content_mode == "autonomous-for-listed" and not recipients:
            raise ProtectError("autonomous_content_requires_allowed_recipient")
        expires_at = _validate_window(
            self.approval_max_age_seconds,
            self.authorization_ttl_seconds,
            self.expires_at,
            now=now,
        )
        return SendMessageProtectionConfig(
            owner=owner,
            allowed_recipients=recipients,
            content_mode=self.content_mode,
            approval_max_age_seconds=self.approval_max_age_seconds,
            authorization_ttl_seconds=self.authorization_ttl_seconds,
            expires_at=expires_at,
            agent_id=agent_id,
            tool=tool,
            target=target,
            purpose=purpose,
            disclosure_class=disclosure_class,
        )


def _policy_bundle(
    *,
    owner: str,
    agent_id: str,
    purpose: str,
    action_type: str,
    target: str,
    disclosure_classes: Sequence[str],
    mandate_id: str,
    policy_id: str,
    route_id: str,
    tool: str,
    requirement_id: str,
    issuer_id: str,
    approval_max_age_seconds: int,
    authorization_ttl_seconds: int,
    expires_at: str,
    max_payment_cents: int = 0,
) -> dict[str, Any]:
    return {
        "schema": "openline.authorized_tool_policy.v1",
        "mandate": {
            "profile": "principal_mandate/v1",
            "mandate_id": mandate_id,
            "principal_id": owner,
            "agent_id": agent_id,
            "purpose": purpose,
            "allowed_action_types": [action_type],
            "allowed_targets": [target],
            "allowed_disclosure_classes": list(disclosure_classes),
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": max_payment_cents,
            "delegation_allowed": False,
            "expires_at": expires_at,
            "version": "1",
        },
        "permission_policy": {
            "profile": "decision_permission_policy/v1",
            "policy_id": policy_id,
            "version": "1",
            "routes": [
                {
                    "route_id": route_id,
                    "tool": tool,
                    "target": target,
                    "requirements": [
                        {
                            "requirement_id": requirement_id,
                            "kind": "authority",
                            "accepted_issuers": [issuer_id],
                            "max_age_seconds": approval_max_age_seconds,
                            "independent_from_producer": True,
                        }
                    ],
                    "unknown_behavior": "QUARANTINE",
                    "max_authorization_ttl_seconds": authorization_ttl_seconds,
                }
            ],
        },
    }


def build_refund_policy(config: RefundProtectionConfig) -> dict[str, Any]:
    config = config.validate()
    base = _slug(config.tool)
    return _policy_bundle(
        owner=config.owner,
        agent_id=config.agent_id,
        purpose=config.purpose,
        action_type="authorize_payment",
        target=config.target,
        disclosure_classes=(),
        mandate_id=f"{base}-mandate",
        policy_id=f"{base}-permission",
        route_id="refund",
        tool=config.tool,
        requirement_id="refund_authority",
        issuer_id="refund_authority",
        approval_max_age_seconds=config.approval_max_age_seconds,
        authorization_ttl_seconds=config.authorization_ttl_seconds,
        expires_at=config.expires_at,
        max_payment_cents=config.hard_limit_cents,
    )


def build_send_message_policy(config: SendMessageProtectionConfig) -> dict[str, Any]:
    config = config.validate()
    base = _slug(config.tool)
    return _policy_bundle(
        owner=config.owner,
        agent_id=config.agent_id,
        purpose=config.purpose,
        action_type="send",
        target=config.target,
        disclosure_classes=(config.disclosure_class,),
        mandate_id=f"{base}-mandate",
        policy_id=f"{base}-permission",
        route_id="send-message",
        tool=config.tool,
        requirement_id="message_authority",
        issuer_id="message_authority",
        approval_max_age_seconds=config.approval_max_age_seconds,
        authorization_ttl_seconds=config.authorization_ttl_seconds,
        expires_at=config.expires_at,
    )


def _write_files(files: Mapping[Path, str], *, force: bool) -> list[Path]:
    existing = [path for path in files if path.exists()]
    if existing and not force:
        names = ",".join(str(path) for path in existing)
        raise ProtectError(f"output_exists:{names}")
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return list(files)


def _render_refund_guard(config: RefundProtectionConfig) -> str:
    return f"""# Starter guard generated by `olp-gate protect refund`.
from __future__ import annotations

from pathlib import Path

from olp_gate import EvidenceAssertion, authorize, payment_semantics


AUTONOMOUS_LIMIT_CENTS = {config.autonomous_limit_cents}
APPROVAL_MAX_AGE_SECONDS = {config.approval_max_age_seconds}
POLICY = Path(__file__).with_name("refund_policy.json")


def current_refund_state(call):
    return {{
        "refund_enabled": True,
        "customer_id": call.arguments["customer_id"],
    }}


def trusted_high_value_approval(call):
    # Connect a receiver-owned human/workflow approval source here.
    # Returning None deliberately keeps larger refunds blocked.
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

# @refund_guard
# def {config.tool}(amount_cents: int, customer_id: str):
#     return payment_api.refund(amount_cents, customer_id)
"""


def _render_refund_readme(config: RefundProtectionConfig) -> str:
    auto = f"{config.autonomous_limit_cents / 100:.2f}"
    hard = f"{config.hard_limit_cents / 100:.2f}"
    return f"""# Refund protection starter

This folder was generated from rules you chose.

- The agent is acting for **{config.owner}**.
- Refunds up to **${auto}** can use the automatic rule you approved.
- Refunds above **${auto}** stay blocked until `trusted_high_value_approval()` is connected.
- Refunds above **${hard}** are denied even if an approval is presented.
- Approval evidence may be at most **{config.approval_max_age_seconds} seconds** old.
- A cleared action may wait at most **{config.authorization_ttl_seconds} seconds** before rechecking.
- This policy expires at **{config.expires_at}**.

Keep money as integer cents. Connect receiver-owned state and approval sources.
Do not substitute model output as approval.
"""


def _render_refund_generated_test(config: RefundProtectionConfig) -> str:
    return f"""from __future__ import annotations

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
"""


def write_refund_starter(
    config: RefundProtectionConfig,
    output: str | Path,
    *,
    force: bool = False,
) -> list[Path]:
    config = config.validate()
    root = Path(output)
    files = {
        root / "refund_policy.json": json.dumps(build_refund_policy(config), indent=2) + "\n",
        root / "refund_guard.py": _render_refund_guard(config),
        root / "README.md": _render_refund_readme(config),
        root / "test_refund_policy.py": _render_refund_generated_test(config),
        root / "answers.json": json.dumps(
            {
                "pack": "refund",
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
    return _write_files(files, force=force)


def _render_message_guard(config: SendMessageProtectionConfig) -> str:
    recipients = repr(tuple(config.allowed_recipients))
    return f"""# Starter guard generated by `olp-gate protect send-message`.
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from olp_gate import EvidenceAssertion, authorize


ALLOWED_RECIPIENTS = frozenset({recipients})
CONTENT_MODE = {config.content_mode!r}
APPROVAL_MAX_AGE_SECONDS = {config.approval_max_age_seconds}
DISCLOSURE_CLASS = {config.disclosure_class!r}
POLICY = Path(__file__).with_name("message_policy.json")


def message_approval_key(call):
    recipient = call.arguments.get("recipient")
    message = call.arguments.get("message")
    if not isinstance(recipient, str) or not recipient:
        raise ValueError("message_recipient_invalid")
    if not isinstance(message, str) or not message:
        raise ValueError("message_body_invalid")
    payload = json.dumps(
        {{"recipient": recipient, "message": message}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def current_message_state(call):
    return {{
        "messaging_enabled": True,
        "recipient": call.arguments["recipient"],
        "approval_key": message_approval_key(call),
    }}


def trusted_exact_message_approval(call):
    # Connect a receiver-owned approval store keyed by message_approval_key(call).
    # Returning None deliberately blocks the send.
    return None


def message_authority(call):
    recipient = call.arguments.get("recipient")
    if CONTENT_MODE == "autonomous-for-listed" and recipient in ALLOWED_RECIPIENTS:
        return EvidenceAssertion(
            payload={{
                "basis": "receiver_selected_recipient_autonomy",
                "recipient": recipient,
                "approval_key": message_approval_key(call),
            }},
            issuer_id="message_authority",
            expires_in_seconds=APPROVAL_MAX_AGE_SECONDS,
        )
    return trusted_exact_message_approval(call)


def message_semantics(call):
    message_approval_key(call)
    return {{
        "action_type": "send",
        "disclosures": [DISCLOSURE_CLASS],
        "value_cents": 0,
        "delegatee": None,
    }}


message_guard = authorize(
    policy=POLICY,
    tool={config.tool!r},
    target={config.target!r},
    semantics=message_semantics,
    state_source=current_message_state,
    evidence_sources={{"message_authority": message_authority}},
)

# @message_guard
# def {config.tool}(recipient: str, message: str):
#     return messaging_api.send(recipient, message)
"""


def _render_message_readme(config: SendMessageProtectionConfig) -> str:
    recipients = ", ".join(config.allowed_recipients) or "(none)"
    return f"""# Send-message protection starter

This folder was generated from rules you chose.

- The agent is acting for **{config.owner}**.
- Listed recipients: **{recipients}**.
- Content mode: **{config.content_mode}**.
- Approval evidence may be at most **{config.approval_max_age_seconds} seconds** old.
- A cleared send may wait at most **{config.authorization_ttl_seconds} seconds** before rechecking.
- This policy expires at **{config.expires_at}**.

`message_approval_key(call)` hashes the exact recipient and message body.
Connect `trusted_exact_message_approval()` to a receiver-owned approval store
using that key. If recipient or message changes, the key changes and the old
approval does not apply.

In `autonomous-for-listed` mode, listed recipients may receive new content
without exact human approval. Every other recipient still requires the trusted
approval hook. In `exact-approval` mode, every send requires trusted approval.

Do not substitute model output as approval.
"""


def _render_message_generated_test(config: SendMessageProtectionConfig) -> str:
    return f"""from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class GeneratedMessagePolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "message_policy.json").read_text(encoding="utf-8"))
        self.answers = json.loads((ROOT / "answers.json").read_text(encoding="utf-8"))

    def test_mandate_allows_send_not_payment(self):
        mandate = self.policy["mandate"]
        self.assertEqual(mandate["allowed_action_types"], ["send"])
        self.assertEqual(mandate["max_payment_cents"], 0)

    def test_message_disclosure_is_explicit(self):
        self.assertEqual(
            self.policy["mandate"]["allowed_disclosure_classes"],
            [{config.disclosure_class!r}],
        )

    def test_unknown_message_approval_fails_closed(self):
        route = self.policy["permission_policy"]["routes"][0]
        self.assertEqual(route["unknown_behavior"], "QUARANTINE")
        self.assertEqual(route["requirements"][0]["requirement_id"], "message_authority")

    def test_selected_content_mode_is_recorded(self):
        self.assertEqual(self.answers["content_mode"], {config.content_mode!r})


if __name__ == "__main__":
    unittest.main()
"""


def write_send_message_starter(
    config: SendMessageProtectionConfig,
    output: str | Path,
    *,
    force: bool = False,
) -> list[Path]:
    config = config.validate()
    root = Path(output)
    files = {
        root / "message_policy.json": json.dumps(build_send_message_policy(config), indent=2) + "\n",
        root / "message_guard.py": _render_message_guard(config),
        root / "README.md": _render_message_readme(config),
        root / "test_message_policy.py": _render_message_generated_test(config),
        root / "answers.json": json.dumps(
            {
                "pack": "send-message",
                "owner": config.owner,
                "agent_id": config.agent_id,
                "tool": config.tool,
                "target": config.target,
                "purpose": config.purpose,
                "disclosure_class": config.disclosure_class,
                "allowed_recipients": list(config.allowed_recipients),
                "content_mode": config.content_mode,
                "approval_max_age_seconds": config.approval_max_age_seconds,
                "authorization_ttl_seconds": config.authorization_ttl_seconds,
                "expires_at": config.expires_at,
            },
            indent=2,
        ) + "\n",
    }
    return _write_files(files, force=force)


def _ask(
    label: str,
    current: str | None,
    *,
    default: str | None = None,
    input_fn: Callable[[str], str] = input,
) -> str:
    if current is not None:
        return current
    suffix = f" [{default}]" if default not in (None, "") else ""
    answer = input_fn(f"{label}{suffix}: ").strip()
    if answer:
        return answer
    if default is not None:
        return default
    raise ProtectError("answer_required")


def _refund_config_from_args(
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
    autonomous = _ask("Largest refund allowed without fresh approval (USD)", ns.autonomous_limit, input_fn=input_fn)
    hard = _ask("Absolute maximum refund (USD)", ns.hard_limit, input_fn=input_fn)
    approval_age = _ask(
        "How many seconds may approval remain fresh",
        None if ns.approval_max_age is None else str(ns.approval_max_age),
        default="300",
        input_fn=input_fn,
    )
    ttl = _ask(
        "How many seconds may a cleared refund wait before rechecking",
        None if ns.authorization_ttl is None else str(ns.authorization_ttl),
        default="120",
        input_fn=input_fn,
    )
    expires = _ask("When should this policy expire (RFC3339 UTC)", ns.expires_at, input_fn=input_fn)
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
    ).validate()


def _message_config_from_args(
    ns: argparse.Namespace,
    *,
    input_fn: Callable[[str], str] = input,
) -> SendMessageProtectionConfig:
    if ns.non_interactive:
        required = {
            "--owner": ns.owner,
            "--content-mode": ns.content_mode,
            "--approval-max-age": ns.approval_max_age,
            "--authorization-ttl": ns.authorization_ttl,
            "--expires-at": ns.expires_at,
        }
        missing = [flag for flag, value in required.items() if value is None]
        if missing:
            raise ProtectError("non_interactive_missing:" + ",".join(missing))
    owner = _ask("Who is the agent acting for", ns.owner, input_fn=input_fn)
    if ns.allowed_recipient is None:
        raw = _ask(
            "Recipients to list (comma-separated; blank for none)",
            None,
            default="",
            input_fn=input_fn,
        )
        recipients = _normalize_recipients(raw.split(","))
    else:
        recipients = _normalize_recipients(ns.allowed_recipient)
    content_mode = _ask(
        "Content mode (exact-approval or autonomous-for-listed)",
        ns.content_mode,
        default="exact-approval",
        input_fn=input_fn,
    )
    approval_age = _ask(
        "How many seconds may message approval remain fresh",
        None if ns.approval_max_age is None else str(ns.approval_max_age),
        default="300",
        input_fn=input_fn,
    )
    ttl = _ask(
        "How many seconds may a cleared send wait before rechecking",
        None if ns.authorization_ttl is None else str(ns.authorization_ttl),
        default="120",
        input_fn=input_fn,
    )
    expires = _ask("When should this policy expire (RFC3339 UTC)", ns.expires_at, input_fn=input_fn)
    try:
        approval_seconds = int(approval_age)
        ttl_seconds = int(ttl)
    except ValueError as exc:
        raise ProtectError("seconds_value_invalid") from exc
    return SendMessageProtectionConfig(
        owner=owner,
        allowed_recipients=recipients,
        content_mode=content_mode,
        approval_max_age_seconds=approval_seconds,
        authorization_ttl_seconds=ttl_seconds,
        expires_at=expires,
        agent_id=ns.agent_id,
        tool=ns.tool,
        target=ns.target,
        purpose=ns.purpose,
        disclosure_class=ns.disclosure_class,
    ).validate()


def _refund_summary(config: RefundProtectionConfig, output: Path) -> str:
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


def _message_summary(config: SendMessageProtectionConfig, output: Path) -> str:
    recipients = ", ".join(config.allowed_recipients) or "(none)"
    return "\n".join(
        [
            "Protect this messaging function with these rules:",
            f"  Acts for:              {config.owner}",
            f"  Function:              {config.tool}",
            f"  Listed recipients:     {recipients}",
            f"  Content mode:          {config.content_mode}",
            f"  Approval freshness:    {config.approval_max_age_seconds}s",
            f"  Recheck window:        {config.authorization_ttl_seconds}s",
            f"  Policy expires:        {config.expires_at}",
            f"  Write starter to:      {output}",
        ]
    )


def _add_refund_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--owner", help="Person or organization the agent acts for")
    parser.add_argument("--autonomous-limit", help="USD amount allowed by the automatic rule")
    parser.add_argument("--hard-limit", help="Absolute USD ceiling")
    parser.add_argument("--approval-max-age", type=int)
    parser.add_argument("--authorization-ttl", type=int)
    parser.add_argument("--expires-at")
    parser.add_argument("--agent-id", default="refund-agent")
    parser.add_argument("--tool", default="process_refund")
    parser.add_argument("--target", default="refund://process")
    parser.add_argument("--purpose", default="customer refunds")
    parser.add_argument("--output", default=".openline/refund")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--force", action="store_true")


def _add_message_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--owner", help="Person or organization the agent acts for")
    parser.add_argument("--allowed-recipient", action="append")
    parser.add_argument(
        "--content-mode",
        choices=("exact-approval", "autonomous-for-listed"),
    )
    parser.add_argument("--approval-max-age", type=int)
    parser.add_argument("--authorization-ttl", type=int)
    parser.add_argument("--expires-at")
    parser.add_argument("--agent-id", default="messaging-agent")
    parser.add_argument("--tool", default="send_message")
    parser.add_argument("--target", default="message://send")
    parser.add_argument("--purpose", default="send messages for the principal")
    parser.add_argument("--disclosure-class", default="message_content")
    parser.add_argument("--output", default=".openline/send-message")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--force", action="store_true")


@dataclass(frozen=True)
class ProtectPack:
    name: str
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    config_from_args: Callable[..., Any]
    summary: Callable[[Any, Path], str]
    writer: Callable[..., list[Path]]
    next_step: str


PACKS: dict[str, ProtectPack] = {
    "refund": ProtectPack(
        name="refund",
        help="Protect a refund function.",
        add_arguments=_add_refund_arguments,
        config_from_args=_refund_config_from_args,
        summary=_refund_summary,
        writer=write_refund_starter,
        next_step="Next: connect trusted_high_value_approval() before allowing larger refunds.",
    ),
    "send-message": ProtectPack(
        name="send-message",
        help="Protect messaging and bind approval to the exact send.",
        add_arguments=_add_message_arguments,
        config_from_args=_message_config_from_args,
        summary=_message_summary,
        writer=write_send_message_starter,
        next_step="Next: connect trusted_exact_message_approval() to a receiver-owned approval source.",
    ),
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="olp-gate protect",
        description="Turn plain application rules into a fail-closed OpenLine starter.",
    )
    sub = parser.add_subparsers(dest="template", required=True)
    for name, pack in PACKS.items():
        item = sub.add_parser(name, description=pack.help, help=pack.help)
        pack.add_arguments(item)
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
        pack = PACKS.get(ns.template)
        if pack is None:
            raise ProtectError("template_unsupported")
        config = pack.config_from_args(ns, input_fn=input_fn)
        output = Path(ns.output)
        print(pack.summary(config, output), file=out)
        if ns.non_interactive and not ns.yes:
            raise ProtectError("non_interactive_requires_yes")
        if not ns.yes:
            confirmation = input_fn("Write these files? [y/N]: ").strip().lower()
            if confirmation not in {"y", "yes"}:
                print("No files written.", file=out)
                return 1
        written = pack.writer(config, output, force=ns.force)
    except ProtectError as exc:
        print(f"protect: {exc}", file=err)
        return 2
    print(f"Wrote {len(written)} files to {output}", file=out)
    print(pack.next_step, file=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
