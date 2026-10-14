#!/usr/bin/env python3
"""Receiver-local policy adapter over the frozen OpenLine Wallet ReferenceGate.

ReferenceGate.protect_action() tracks *carried recipient scopes* for route
checks. It is NOT a source-side receiver permission check. This bridge
checks receiver-required owner scopes separately, before returning ALLOWED.

This is a research reference adapter, not a production concurrency, custody,
durability, or cross-host revocation solution. Wire records remain Wallet's.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
from threading import RLock
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from openline_wallet import ReferenceGate, WalletError, create_presentation  # noqa: E402
from openline_wallet.crypto import record_hash  # noqa: E402


class WalletReceiver:
    """A receiver that owns its trust root list, signing key and action rules.

    Each action MUST be explicitly configured. Mandate scopes must include
    the exact action (checked by Wallet) AND all receiver-required scopes.
    The reference Gate's internal admitted timeline is read only while our
    local lock is held; this pins the bridge to the vendored Wallet version.
    """

    def __init__(
        self,
        gate_id: str,
        *,
        max_bundle_age_seconds: int = 300,
        challenge_ttl_seconds: int = 60,
        gate_key: Ed25519PrivateKey | None = None,
    ):
        self.gate = ReferenceGate(
            gate_id,
            gate_key=gate_key,
            max_bundle_age_seconds=max_bundle_age_seconds,
            challenge_ttl_seconds=challenge_ttl_seconds,
        )
        self._action_scopes: dict[str, frozenset[str]] = {}
        self._lock = RLock()

    @property
    def public_key(self) -> str:
        return self.gate.public_key

    def pin_owner(self, principal_id: str, root_public_key: str) -> None:
        with self._lock:
            self.gate.pin_principal(principal_id, root_public_key)

    def protect_action(self, action: str, required_scopes: list[str]) -> None:
        """Configure a local permission requirement; NOT carried-route state."""
        if not isinstance(action, str) or not action:
            raise WalletError("RECEIVER_ACTION_INVALID")
        if (
            not isinstance(required_scopes, list)
            or not required_scopes
            or any(not isinstance(v, str) or not v for v in required_scopes)
            or len(set(required_scopes)) != len(required_scopes)
        ):
            raise WalletError("RECEIVER_SCOPES_INVALID")
        required = frozenset(required_scopes)
        with self._lock:
            old = self._action_scopes.get(action)
            if old is not None and old != required:
                raise WalletError("RECEIVER_POLICY_CONFLICT")
            self._action_scopes[action] = required

    def admit_bundle(self, bundle: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            return self.gate.admit_bundle(bundle)

    def issue_challenge(self, principal_id: str, subject_id: str, action: str) -> str:
        with self._lock:
            return self.gate.issue_challenge(
                principal_id=principal_id, subject_id=subject_id, action=action
            )

    def _signed_stop(self, presentation: Mapping[str, Any], action: str, reason: str) -> dict[str, Any]:
        # The reference Gate has no public arbitrary-local-policy-deny API.
        # Reuse its EXISTING signed decision-receipt schema, never a new wire
        # format or an unsigned STOPPED dict. This private API is version-pinned.
        return self.gate._receipt(  # noqa: SLF001
            decision="STOPPED",
            reasons=[reason],
            principal_id=presentation["principal_id"],
            mandate_id=presentation.get("mandate_id"),
            subject_id=presentation.get("subject_id"),
            action=action,
            presentation_hash=record_hash(presentation),
            now=datetime.now(timezone.utc),
        )

    def authorize(self, presentation: Mapping[str, Any], action: str) -> dict[str, Any]:
        with self._lock:
            # Always evaluate to consume one-use challenge, even if local
            # policy will deny. Never expose this intermediate ALLOWED record.
            decision = self.gate.evaluate(presentation, expected_action=action)
            if decision.get("decision") != "ALLOWED":
                return decision
            required = self._action_scopes.get(action)
            if required is None:
                return self._signed_stop(presentation, action, "RECEIVER_ACTION_UNCONFIGURED")
            principal = presentation["principal_id"]
            mandate_id = presentation["mandate_id"]
            admitted = self.gate._admitted.get(principal)  # noqa: SLF001
            mandate = admitted.timeline.mandates.get(mandate_id) if admitted else None
            scopes = mandate.get("scopes") if isinstance(mandate, dict) else None
            if not isinstance(scopes, (list, tuple, set)) or not required.issubset(set(scopes)):
                return self._signed_stop(presentation, action, "RECEIVER_SCOPE_POLICY_UNMET")
            return decision


def worker_present(
    *,
    bundle: Mapping[str, Any],
    mandate_id: str,
    subject_id: str,
    subject_key: Ed25519PrivateKey,
    action: str,
    challenge: str,
) -> dict[str, Any]:
    return create_presentation(
        bundle=bundle,
        mandate_id=mandate_id,
        subject_id=subject_id,
        subject_key=subject_key,
        action=action,
        receiver_challenge=challenge,
    )
