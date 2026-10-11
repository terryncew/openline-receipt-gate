#!/usr/bin/env python3
"""Lithic ASA Adapter — Offline Fixture Test.

Verifies the adapter logic for 6 scenarios without a network connection.
Uses synthetic fixtures. No Lithic API calls. No real funds.

Scenarios:
1. Valid mandate → APPROVE
2. Revoked mandate → DECLINE
3. Worker replacement → APPROVE (new worker)
4. Amount exceeds mandate → DECLINE
5. Duplicate delivery → DECLINE (second)
6. Invalid signature → DECLINE (fail closed)

Run: python3 test_lithic_adapter.py
"""

import json
import sys
from pathlib import Path

# The adapter uses the receiver package
sys.path.insert(0, str(Path(__file__).parent))

from openline_receiver.wallet_bridge import WalletReceiver, worker_present
from openline_receiver.openline_wallet.wallet import Wallet
from openline_receiver.openline_wallet.receiver import ReferenceGate
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class LithicAdapter:
    """Offline adapter: Lithic ASA request → OpenLine decision → Lithic response.
    
    In production, this would be a webhook endpoint. Here, it's a pure
    function for testing.
    """
    
    def __init__(self, receiver: WalletReceiver):
        self.receiver = receiver
        self.seen_challenges = set()  # For duplicate detection
    
    def decide(self, lithic_request: dict) -> dict:
        """Process a Lithic ASA authorization request.
        
        Returns: {"approved": bool, "openline_receipt": {...}, ...}
        """
        pres = lithic_request.get("openline_presentation", {})
        amount = lithic_request.get("amount", 0)
        
        # Check for duplicate (challenge replay)
        challenge = pres.get("receiver_challenge", "")
        if challenge in self.seen_challenges:
            return {
                "approved": False,
                "decline_reason": "CHALLENGE_REPLAY",
                "openline_receipt": self._receipt("DECLINED", "CHALLENGE_REPLAY", pres, amount),
            }
        
        # Verify the presentation via the receiver
        # (In real code, the receiver.decide() does this)
        # For the fixture test, we simulate the decision
        
        # Extract mandate info from presentation
        # (Real code would call receiver.decide(pres, action))
        decision = self._evaluate(pres, amount)
        
        if decision["allowed"]:
            self.seen_challenges.add(challenge)
            return {
                "approved": True,
                "openline_receipt": self._receipt("APPROVED", None, pres, amount),
            }
        else:
            return {
                "approved": False,
                "decline_reason": decision["reason"],
                "openline_receipt": self._receipt("DECLINED", decision["reason"], pres, amount),
            }
    
    def _evaluate(self, pres: dict, amount: int) -> dict:
        """Simulate receiver evaluation. In real code, this is receiver.decide()."""
        # This is a simplified simulation for the fixture test.
        # The real WalletReceiver.decide() does full cryptographic verification.
        
        # Check 1: Signature valid (simulated via fixture flag)
        if pres.get("_fixture_tampered"):
            return {"allowed": False, "reason": "PRESENTATION_SIGNATURE_INVALID"}
        
        # Check 2: Mandate not revoked (simulated via fixture flag)
        if pres.get("_fixture_revoked"):
            return {"allowed": False, "reason": "MANDATE_REVOKED"}
        
        # Check 3: Amount within limit (mandate limit $1.00 = 100 cents)
        if amount > 100:
            return {"allowed": False, "reason": "AMOUNT_EXCEEDS_MANDATE"}
        
        return {"allowed": True, "reason": None}
    
    def _receipt(self, decision: str, reason: str | None, pres: dict, amount: int) -> dict:
        """Create a signed receipt (simulated)."""
        return {
            "schema": "openline.receipt.v1",
            "decision": decision,
            "reason": reason,
            "principal_id": pres.get("principal_id", "unknown"),
            "mandate_id": pres.get("mandate_id", "unknown"),
            "amount_cents": amount,
            # In real code, this is signed by the receiver's key
            "receiver_signature": "simulated-signature",
        }


def make_fixture(overrides: dict | None = None) -> dict:
    """Create a valid Lithic ASA request fixture."""
    base = {
        "token": "lithic-auth-token-fixture",
        "card_token": "card_fixture123",
        "amount": 100,  # $1.00
        "currency": "USD",
        "merchant": {"name": "TEST MERCHANT", "mcc": "5999"},
        "openline_presentation": {
            "schema": "openline.presentation.v1",
            "principal_id": "terrynce-test-owner",
            "mandate_id": "mandate_fixture123",
            "subject_id": "test-agent-1",
            "action": "lithic:authorize",
            "receiver_challenge": "challenge-fixture-001",
            "issued_at": "2026-10-11T20:00:00Z",
        },
    }
    if overrides:
        # Deep merge for openline_presentation
        if "openline_presentation" in overrides:
            base["openline_presentation"].update(overrides.pop("openline_presentation"))
        base.update(overrides)
    return base


def test_scenarios():
    """Run the 6 scenarios."""
    receiver = WalletReceiver(gate_id="test-receiver")
    adapter = LithicAdapter(receiver)
    
    results = []
    
    # Scenario 1: Valid mandate → APPROVE
    req1 = make_fixture()
    res1 = adapter.decide(req1)
    ok1 = res1["approved"] is True and res1["openline_receipt"]["decision"] == "APPROVED"
    results.append(("1. Valid mandate → APPROVE", ok1, res1))
    
    # Scenario 2: Revoked mandate → DECLINE
    req2 = make_fixture({
        "openline_presentation": {
            "receiver_challenge": "challenge-fixture-002",
            "_fixture_revoked": True,
        }
    })
    res2 = adapter.decide(req2)
    ok2 = res2["approved"] is False and res2["decline_reason"] == "MANDATE_REVOKED"
    results.append(("2. Revoked mandate → DECLINE", ok2, res2))
    
    # Scenario 3: Worker replacement → APPROVE (new worker)
    req3 = make_fixture({
        "openline_presentation": {
            "subject_id": "test-agent-2",  # Successor
            "mandate_id": "mandate_fixture456",  # New mandate
            "receiver_challenge": "challenge-fixture-003",
        }
    })
    res3 = adapter.decide(req3)
    ok3 = res3["approved"] is True
    results.append(("3. Worker replacement → APPROVE", ok3, res3))
    
    # Scenario 4: Amount exceeds → DECLINE
    req4 = make_fixture({
        "amount": 500,  # $5.00, exceeds $1.00 limit
        "openline_presentation": {"receiver_challenge": "challenge-fixture-004"},
    })
    res4 = adapter.decide(req4)
    ok4 = res4["approved"] is False and res4["decline_reason"] == "AMOUNT_EXCEEDS_MANDATE"
    results.append(("4. Amount exceeds → DECLINE", ok4, res4))
    
    # Scenario 5: Duplicate delivery → DECLINE (second)
    req5a = make_fixture({
        "openline_presentation": {"receiver_challenge": "challenge-fixture-005"},
    })
    res5a = adapter.decide(req5a)  # First: APPROVE
    req5b = make_fixture({
        "openline_presentation": {"receiver_challenge": "challenge-fixture-005"},
    })
    res5b = adapter.decide(req5b)  # Second: DECLINE (replay)
    ok5 = res5a["approved"] is True and res5b["approved"] is False
    ok5 = ok5 and res5b["decline_reason"] == "CHALLENGE_REPLAY"
    results.append(("5. Duplicate → DECLINE (2nd)", ok5, res5b))
    
    # Scenario 6: Invalid signature → DECLINE (fail closed)
    req6 = make_fixture({
        "openline_presentation": {
            "receiver_challenge": "challenge-fixture-006",
            "_fixture_tampered": True,
        }
    })
    res6 = adapter.decide(req6)
    ok6 = res6["approved"] is False
    ok6 = ok6 and res6["decline_reason"] == "PRESENTATION_SIGNATURE_INVALID"
    results.append(("6. Invalid signature → DECLINE", ok6, res6))
    
    # Report
    print("Lithic ASA Adapter — Offline Fixture Test")
    print("=" * 50)
    passed = 0
    for name, ok, res in results:
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name}")
        if not ok:
            print(f"       Result: {json.dumps(res, indent=2)[:200]}")
        else:
            passed += 1
    
    print("=" * 50)
    print(f"{passed}/{len(results)} scenarios pass")
    
    # Note about limitations
    print("\nNote: This is a SIMULATED test. The _evaluate() method uses")
    print("fixture flags (_fixture_revoked, etc.) instead of real cryptographic")
    print("verification. A production adapter would call")
    print("receiver.decide(presentation, action) which does full verification.")
    print("The 6 scenarios document the EXPECTED behavior, not a proven implementation.")
    
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(test_scenarios())
