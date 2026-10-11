#!/usr/bin/env python3
"""OPENLINE-RECEIVER-001 Priority 2: Wallet authority bridge.

Connects the real OpenLine Wallet to the Gateway receiver. The gateway
does NOT define a parallel authority format — it uses the Wallet's own
contracts (vendored in gateway/openline_wallet/):

- Owner side: Wallet.grant / Wallet.revoke / Wallet.export_bundle
- Receiver side: ReferenceGate.pin_principal / admit_bundle /
  issue_challenge / evaluate

The receiver operates with its own pinned trust rules: it pins the
owner's root key out-of-band and admits only bundles from pinned
principals. Revocation is checked against the freshness-bounded
admitted bundle — an old exported bundle does not contain live
revocation information.

Freshness bound: ReferenceGate enforces max_bundle_age_seconds (<=600s)
on admission, and evaluate() rejects presentations whose bundle_head_hash
does not match the currently admitted head (PRESENTATION_HEAD_STALE).
A revoked mandate is enforced when the receiver admits the bundle
containing the MANDATE_REVOKED event.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from openline_wallet import (  # noqa: E402
    ReferenceGate,
    WalletError,
    create_presentation,
)
from openline_wallet.crypto import public_key_hex  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)


class WalletReceiver:
    """A separately operated receiver that accepts portable Wallet authority.

    The receiver pins owner root keys (its own trust decision, made
    out-of-band) and admits signed authority bundles. Workers prove
    key ownership via challenge-bound presentations. The receiver never
    trusts the worker's word about its own authority — every decision
    is evaluated against the admitted bundle at consequence time.
    """

    def __init__(
        self,
        gate_id: str,
        *,
        max_bundle_age_seconds: int = 300,
        challenge_ttl_seconds: int = 60,
    ):
        self.gate = ReferenceGate(
            gate_id,
            max_bundle_age_seconds=max_bundle_age_seconds,
            challenge_ttl_seconds=challenge_ttl_seconds,
        )
        # action -> required Wallet scopes (receiver's policy, not the
        # worker's claim)
        self._action_scopes: dict[str, frozenset[str]] = {}

    @property
    def public_key(self) -> str:
        return self.gate.public_key

    def pin_owner(self, principal_id: str, root_public_key: str) -> None:
        """Pin an owner's root key. Out-of-band trust decision."""
        self.gate.pin_principal(principal_id, root_public_key)

    def protect_action(self, action: str, required_scopes: list[str]) -> None:
        """Declare what Wallet scopes an action requires (receiver policy)."""
        self._action_scopes[action] = frozenset(required_scopes)
        self.gate.protect_action(
            action, required_recipient_scopes=required_scopes
        )

    def admit_bundle(self, bundle: Mapping[str, Any]) -> dict[str, Any]:
        """Admit a signed authority bundle. Enforces freshness."""
        return self.gate.admit_bundle(bundle)

    def issue_challenge(
        self, principal_id: str, subject_id: str, action: str
    ) -> str:
        """Issue a one-use challenge for a worker to bind its presentation."""
        return self.gate.issue_challenge(
            principal_id=principal_id,
            subject_id=subject_id,
            action=action,
        )

    def authorize(
        self,
        presentation: Mapping[str, Any],
        action: str,
    ) -> dict[str, Any]:
        """Evaluate a worker's presentation. Returns the signed decision."""
        decision = self.gate.evaluate(presentation, expected_action=action)
        # Enforce the receiver's scope policy on top of the mandate check.
        if decision.get("decision") == "ALLOWED":
            required = self._action_scopes.get(action, frozenset())
            # The mandate's scopes were already checked by evaluate();
            # here we confirm the receiver's protected-action requirements
            # were recorded (carried_scopes is the conservative exposure).
            carried = self.gate.carried_scopes(
                presentation.get("principal_id", ""),
                presentation.get("subject_id", ""),
            )
            if required and not required.issubset(set(carried)):
                # Should not happen (evaluate records them), but fail
                # closed if the gate's bookkeeping disagrees.
                return {
                    "decision": "STOPPED",
                    "reasons": ["RECEIVER_SCOPE_POLICY_UNMET"],
                    "action": action,
                }
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
    """Worker side: bind the subject key to the receiver's challenge."""
    return create_presentation(
        bundle=bundle,
        mandate_id=mandate_id,
        subject_id=subject_id,
        subject_key=subject_key,
        action=action,
        receiver_challenge=challenge,
    )
