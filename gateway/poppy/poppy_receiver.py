#!/usr/bin/env python3
"""POPPY-PROOF-001: Receiving business with OpenLine authority extension.

The receiver is a Poppy company that ALSO verifies owner-controlled
authority before allowing a consequential operation:

1. Poppy layer (draft 0.1, standard): verify the session JWT —
   signature, expiry, DPoP binding. Establishes WHO (signed-in user)
   and COARSE SCOPE (read/write).
2. OpenLine layer (experimental extension): verify the owner-signed
   Wallet mandate matches the EXACT operation terms — merchant, line
   items, amounts, limits, expiry. Establishes AUTHORITY for THIS
   EXACT OPERATION.
3. Issue a signed decision receipt (ALLOWED/STOPPED + reason codes),
   independently verifiable with the receiver's public key.
4. The simulated business effect (ledger movement) happens only on
   ALLOWED.

Rejection cases (all demonstrated in tests):
- No mandate presented (agent claims approval, cannot prove it).
- Mandate signature invalid / principal not pinned.
- Operation terms differ from mandated terms (changed details).
- Mandate revoked (fresh bundle shows MANDATE_REVOKED).
- Presentation stale (bundle head moved past the presented head).
- Mandate expired.
- Worker key mismatch (wrong subject key).
- Poppy session invalid (bad signature, expired, DPoP mismatch,
  company-revoked).
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from poppy_session import PoppyCompany  # noqa: E402
from wallet_bridge import WalletReceiver, worker_present  # noqa: E402
from openline_wallet import Wallet  # noqa: E402
from openline_wallet.crypto import public_key_hex  # noqa: E402


def operation_terms_hash(operation: Mapping[str, Any]) -> str:
    """Canonical hash of the exact operation terms.

    The mandate's scope encodes this hash. Any change to the operation
    details (amount, merchant, items) changes the hash and fails the
    mandate match.
    """
    canonical = json.dumps(operation, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def mandate_scope_for_operation(operation: Mapping[str, Any]) -> str:
    """The Wallet scope that authorizes exactly this operation."""
    return f"poppy:op:{operation_terms_hash(operation)[:32]}"


class PoppyReceiver(PoppyCompany):
    """A Poppy company that enforces owner-signed exact-terms authority.

    Extends PoppyCompany (the Poppy-native session layer) with an
    OpenLine WalletReceiver (the authority layer). Both must pass.
    """

    def __init__(
        self,
        org_name: str,
        org_id: str,
        *,
        max_bundle_age_seconds: int = 300,
    ):
        super().__init__(org_name, org_id)
        self.authority = WalletReceiver(
            f"poppy-receiver-{org_id}",
            max_bundle_age_seconds=max_bundle_age_seconds,
        )
        self._receipt_key = Ed25519PrivateKey.generate()
        # Simulated business ledger: account -> balance (cents)
        self._ledger: dict[str, int] = {}
        # receipt_id -> receipt (for independent verification)
        self._receipts: dict[str, dict[str, Any]] = {}

    @property
    def receipt_public_key(self) -> str:
        return public_key_hex(self._receipt_key)

    # ---- Owner trust ----

    def pin_owner(self, principal_id: str, root_public_key: str) -> None:
        """Pin an owner's Wallet root key (out-of-band trust decision)."""
        self.authority.pin_owner(principal_id, root_public_key)

    def admit_authority_bundle(self, bundle: Mapping[str, Any]) -> dict[str, Any]:
        """Admit a signed Wallet authority bundle (freshness-enforced)."""
        return self.authority.admit_bundle(bundle)

    # ---- Ledger ----

    def fund(self, account: str, cents: int) -> None:
        self._ledger[account] = self._ledger.get(account, 0) + cents

    def balance(self, account: str) -> int:
        return self._ledger.get(account, 0)

    # ---- Decision ----

    def _sign_receipt(self, receipt: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        sig = self._receipt_key.sign(body)
        receipt["receiver_signature"] = sig.hex()
        receipt["receiver_public_key"] = self.receipt_public_key
        return receipt

    def decide(
        self,
        *,
        operation: Mapping[str, Any],
        session_token: str,
        dpop_public_key: str,
        presentation: Mapping[str, Any] | None,
        principal_id: str = "",
    ) -> dict[str, Any]:
        """Decide whether the operation may proceed.

        Returns a signed decision receipt. On ALLOWED, the business
        effect is applied to the simulated ledger.
        """
        now = datetime.now(timezone.utc)
        receipt_id = f"rcpt_{uuid.uuid4().hex[:16]}"

        def stopped(reasons: list[str]) -> dict[str, Any]:
            receipt = {
                "receipt_id": receipt_id,
                "decision": "STOPPED",
                "reason_codes": reasons,
                "operation_hash": operation_terms_hash(operation),
                "decided_at": now.isoformat(),
                "receiver": self.org_id,
            }
            self._sign_receipt(receipt)
            self._receipts[receipt_id] = receipt
            return receipt

        # Layer 1: Poppy session (draft 0.1 — identity + coarse scope).
        sess = self.verify_session(session_token, dpop_public_key, now=now)
        if not sess["valid"]:
            return stopped([f"POPPY_{sess['reason']}"])
        claims = sess["claims"]
        if claims.get("scope") != "write":
            return stopped(["POPPY_SCOPE_INSUFFICIENT"])

        # Layer 2: OpenLine mandate (experimental — exact-terms authority).
        # The action IS the operation's terms hash: the mandate authorizes
        # exactly this operation, nothing else.
        if presentation is None:
            return stopped(["AUTHORITY_NOT_PRESENTED"])
        op_action = mandate_scope_for_operation(operation)
        from openline_wallet.errors import WalletError  # noqa: E402
        try:
            self.authority.protect_action(op_action, [op_action])
        except WalletError:
            # Already protected with the same scope (idempotent for
            # hash-derived action names).
            pass
        decision = self.authority.authorize(presentation, op_action)
        if decision.get("decision") != "ALLOWED":
            reasons = decision.get("reason_codes") or decision.get("reasons") or ["AUTHORITY_DENIED"]
            return stopped([f"MANDATE_{r}" for r in reasons])

        # Both layers passed: apply the business effect.
        op_type = operation.get("type")
        if op_type == "charge":
            account = operation["account"]
            amount = int(operation["amount_cents"])
            if self._ledger.get(account, 0) < amount:
                return stopped(["INSUFFICIENT_FUNDS"])
            self._ledger[account] -= amount
            self._ledger[operation["merchant"]] = (
                self._ledger.get(operation["merchant"], 0) + amount
            )
        elif op_type == "refund":
            merchant = operation["merchant"]
            account = operation["account"]
            amount = int(operation["amount_cents"])
            self._ledger[merchant] -= amount
            self._ledger[account] = self._ledger.get(account, 0) + amount

        receipt = {
            "receipt_id": receipt_id,
            "decision": "ALLOWED",
            "reason_codes": ["POPPY_SESSION_VALID", "MANDATE_MATCHED_EXACT_TERMS"],
            "operation_hash": operation_terms_hash(operation),
            "operation": dict(operation),
            "decided_at": now.isoformat(),
            "receiver": self.org_id,
            "ledger_after": dict(self._ledger),
        }
        self._sign_receipt(receipt)
        self._receipts[receipt_id] = receipt
        return receipt

    def verify_receipt(self, receipt: Mapping[str, Any]) -> bool:
        """Independently verify a decision receipt's signature."""
        try:
            sig = bytes.fromhex(str(receipt["receiver_signature"]))
            pub = Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(self._receipt_key.private_bytes_raw().hex())
            ).public_key()
            # Reconstruct the signed body (receipt minus signature fields).
            body_dict = {k: v for k, v in receipt.items()
                         if k not in ("receiver_signature", "receiver_public_key")}
            body = json.dumps(body_dict, sort_keys=True, separators=(",", ":")).encode()
            pub.verify(sig, body)
            # Confirm the claimed public key matches ours.
            return receipt.get("receiver_public_key") == self.receipt_public_key
        except Exception:
            return False

    def get_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        return self._receipts.get(receipt_id)
