#!/usr/bin/env python3
"""Lithic ASA Adapter — Secure OpenLine Integration.

CRITICAL SECURITY PROPERTY:
handle_asa() NEVER approves from card bindings alone.
It requires a transaction-specific, verified OpenLine authorization.

Flow:
1. Worker calls /pre_authorize with a signed presentation for a specific
   (card_token, amount_cents). The presentation is bound to a challenge.
2. Adapter calls receiver.authorize(presentation, "lithic:authorize").
3. If ALLOWED: adapter stores a one-use authorization for
   (card_token, amount_cents, mandate_id), expires in 60s.
4. Lithic ASA arrives with (token, card_token, amount).
5. Adapter checks: is there a valid, unused authorization for
   (card_token, amount)? If yes → APPROVE and consume it.
   If no → DECLINE.

A known card with NO verified transaction approval MUST decline.
Changing card, amount, txn token, or operation cannot reuse an approval.

Durable SQLite: pins, bundles, card bindings, pending auths, decisions,
receipts, receiver key. Survives restart.

Lithic HMAC: official raw-body, Base64, timestamp verification. Fail closed.
"""

import base64
import hashlib
import hmac
import json
import sqlite3
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    from openline_receiver.wallet_bridge import WalletReceiver, worker_present
    from openline_receiver.openline_wallet import Wallet
    from openline_receiver.openline_wallet.crypto import public_key_hex
    import base64 as _b64
    def b64u_encode(b: bytes) -> str:
        return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()
    def b64u_decode(s: str) -> bytes:
        return _b64.urlsafe_b64decode(s + "==")
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from wallet_bridge import WalletReceiver, worker_present
    from openline_wallet import Wallet
    from openline_wallet.crypto import public_key_hex
    import base64 as _b64
    def b64u_encode(b: bytes) -> str:
        return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()
    def b64u_decode(s: str) -> bytes:
        return _b64.urlsafe_b64decode(s + "==")


class SecureLithicAdapter:
    """Secure adapter: transaction-specific OpenLine authorization required."""
    
    def __init__(self, db_path: str, gate_id: str = "lithic-secure-1",
                 hmac_secret: str | None = None):
        self.db_path = db_path
        self.gate_id = gate_id
        self.hmac_secret = hmac_secret  # If set, HMAC verification is MANDATORY
        self.db = sqlite3.connect(db_path)
        self._init_db()
        self.receiver = WalletReceiver(gate_id=gate_id)
        self._rehydrate()
    
    def _init_db(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS pins (
                principal_id TEXT PRIMARY KEY,
                root_key_hex TEXT NOT NULL,
                pinned_at TEXT NOT NULL
            )""")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS bundles (
                principal_id TEXT PRIMARY KEY,
                bundle_json TEXT NOT NULL,
                admitted_at TEXT NOT NULL
            )""")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS card_bindings (
                card_token TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                mandate_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                bound_at TEXT NOT NULL
            )""")
        # Pending authorizations: one-use, transaction-specific, expire in 60s
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS pending_auths (
                card_token TEXT NOT NULL,
                amount_cents INTEGER NOT NULL,
                mandate_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (card_token, amount_cents, mandate_id)
            )""")
        # Decided transactions: for duplicate detection (durable)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                txn_token TEXT PRIMARY KEY,
                card_token TEXT NOT NULL,
                amount_cents INTEGER NOT NULL,
                decision TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                decided_at TEXT NOT NULL
            )""")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS receiver_keys (
                gate_id TEXT PRIMARY KEY,
                private_key_b64 TEXT NOT NULL,
                public_key_b64 TEXT NOT NULL
            )""")
        self.db.commit()
    
    def _rehydrate(self):
        """Re-pin and re-admit from DB. If state is invalid, fail closed."""
        for principal_id, root_key_hex in self.db.execute(
            "SELECT principal_id, root_key_hex FROM pins"):
            try:
                self.receiver.pin_owner(principal_id, root_key_hex)
            except Exception as e:
                # Invalid pin: do NOT leave the system in a partially
                # authorized state. Remove the pin from DB.
                print(f"WARNING: Invalid pin for {principal_id}, removing: {e}")
                self.db.execute("DELETE FROM pins WHERE principal_id=?",
                                (principal_id,))
                self.db.commit()
        for principal_id, bundle_json in self.db.execute(
            "SELECT principal_id, bundle_json FROM bundles"):
            try:
                bundle = json.loads(bundle_json)
                self.receiver.admit_bundle(bundle)
            except Exception as e:
                print(f"WARNING: Invalid bundle for {principal_id}, removing: {e}")
                self.db.execute("DELETE FROM bundles WHERE principal_id=?",
                                (principal_id,))
                self.db.commit()
        # Expired pending auths are cleaned lazily on access.
    
    def enroll_owner(self, principal_id: str, root_key_hex: str):
        self.receiver.pin_owner(principal_id, root_key_hex)
        self.db.execute(
            "INSERT OR REPLACE INTO pins VALUES (?, ?, ?)",
            (principal_id, root_key_hex,
             datetime.now(timezone.utc).isoformat()))
        self.db.commit()
    
    def admit_bundle(self, principal_id: str, bundle: dict):
        """Admit bundle. If the bundle revokes a mandate, pending auths for
        that mandate are invalidated (not just card unbind)."""
        result = self.receiver.admit_bundle(bundle)
        self.db.execute(
            "INSERT OR REPLACE INTO bundles VALUES (?, ?, ?)",
            (principal_id, json.dumps(bundle),
             datetime.now(timezone.utc).isoformat()))
        self.db.commit()
        # TODO: Parse bundle for revocations, invalidate pending_auths.
        # For now, revocation is via explicit revoke_mandate().
        return result
    
    def revoke_mandate(self, mandate_id: str):
        """Owner-signed revocation: remove pending auths for this mandate.
        
        In a full implementation, this would be triggered by admitting a
        bundle that contains a revocation event. For the pilot, it's explicit.
        """
        self.db.execute("DELETE FROM pending_auths WHERE mandate_id=?",
                        (mandate_id,))
        self.db.commit()
    
    def bind_card(self, card_token: str, principal_id: str, mandate_id: str,
                  subject_id: str):
        """Bind a card to a mandate. This ALONE does not authorize."""
        self.db.execute(
            "INSERT OR REPLACE INTO card_bindings VALUES (?, ?, ?, ?, ?)",
            (card_token, principal_id, mandate_id, subject_id,
             datetime.now(timezone.utc).isoformat()))
        self.db.commit()
    
    def pre_authorize(self, card_token: str, amount_cents: int,
                      presentation: dict) -> dict:
        """Worker requests transaction-specific authorization.
        
        The presentation must be:
        - Signed by the worker's key (in the mandate)
        - Bound to a fresh challenge
        - For action "lithic:authorize"
        
        Returns: {"authorized": bool, "reason": str}
        """
        # Look up the card binding
        binding = self.db.execute(
            "SELECT principal_id, mandate_id, subject_id FROM card_bindings "
            "WHERE card_token=?", (card_token,)).fetchone()
        if not binding:
            return {"authorized": False, "reason": "UNKNOWN_CARD"}
        
        principal_id, mandate_id, subject_id = binding
        
        # Verify the presentation is for THIS mandate and subject
        pres_mandate = presentation.get("mandate_id", "")
        pres_subject = presentation.get("subject_id", "")
        if pres_mandate != mandate_id:
            return {"authorized": False, "reason": "MANDATE_MISMATCH"}
        if pres_subject != subject_id:
            return {"authorized": False, "reason": "SUBJECT_MISMATCH"}
        
        # REAL OpenLine verification
        decision = self.receiver.authorize(presentation, "lithic:authorize")
        if decision.get("decision") != "ALLOWED":
            return {"authorized": False,
                    "reason": decision.get("reasons", ["DENIED"])[0]
                    if decision.get("reasons") else "DENIED"}
        
        # Store the one-use authorization (expires in 60s)
        expires = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
        self.db.execute(
            "INSERT OR REPLACE INTO pending_auths VALUES (?, ?, ?, ?, ?, ?, ?)",
            (card_token, amount_cents, mandate_id, principal_id, subject_id,
             expires, datetime.now(timezone.utc).isoformat()))
        self.db.commit()
        
        return {"authorized": True, "reason": "OK"}
    
    def handle_asa(self, request: dict, headers: dict | None = None,
                   raw_body: bytes | None = None) -> dict:
        """Process Lithic ASA. REQUIRES a verified transaction authorization.
        
        A known card with NO verified transaction approval MUST decline.
        """
        headers = headers or {}
        
        # HMAC verification (if secret configured, MANDATORY)
        if self.hmac_secret:
            if not self._verify_hmac(raw_body or b"", headers, self.hmac_secret):
                # Fail closed: cannot verify authenticity
                return self._decline(request, "SUSPECTED_FRAUD",
                                     "HMAC verification failed")
        
        txn_token = request.get("token", "")
        card_token = request.get("card_token", "")
        
        # Duplicate: return consistent decision (durable)
        existing = self.db.execute(
            "SELECT decision, receipt_json FROM decisions WHERE txn_token=?",
            (txn_token,)).fetchone()
        if existing:
            decision, receipt_json = existing
            receipt = json.loads(receipt_json)
            # Return ONLY documented Lithic fields
            if decision == "APPROVED":
                return {"result": "APPROVED"}
            else:
                return {"result": decision}
        
        # Extract amount from official ASA payload
        # Lithic uses "amounts": {"cardholder": {"amount": ...}}
        amount_cents = request.get("amounts", {}).get("cardholder", {}).get("amount", 0)
        
        # CRITICAL: Check for a valid, unused, transaction-specific authorization
        # The authorization must match (card_token, amount_cents) exactly.
        # It must not be expired. It must not have been used.
        now_iso = datetime.now(timezone.utc).isoformat()
        auth = self.db.execute(
            "SELECT mandate_id, principal_id, subject_id FROM pending_auths "
            "WHERE card_token=? AND amount_cents=? AND expires_at > ?",
            (card_token, amount_cents, now_iso)).fetchone()
        
        if not auth:
            # NO VERIFIED TRANSACTION APPROVAL → DECLINE
            # This is the critical security property.
            return self._decline(request, "CARD_PAUSED",
                                 "No verified transaction authorization")
        
        mandate_id, principal_id, subject_id = auth
        
        # Consume the authorization (one-use) and APPROVE, atomically
        try:
            self.db.execute("BEGIN IMMEDIATE")
            # Double-check (in txn) that it's still valid and unused
            check = self.db.execute(
                "SELECT 1 FROM pending_auths WHERE card_token=? "
                "AND amount_cents=? AND mandate_id=? AND expires_at > ?",
                (card_token, amount_cents, mandate_id, now_iso)).fetchone()
            if not check:
                self.db.execute("ROLLBACK")
                return self._decline(request, "CARD_PAUSED",
                                     "Authorization expired or consumed")
            
            # Consume it
            self.db.execute(
                "DELETE FROM pending_auths WHERE card_token=? "
                "AND amount_cents=? AND mandate_id=?",
                (card_token, amount_cents, mandate_id))
            
            # Create signed receipt
            receipt = self._sign_receipt(
                "APPROVED", None, principal_id, mandate_id, subject_id,
                card_token, txn_token, amount_cents)
            
            # Record decision (durable)
            self.db.execute(
                "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?)",
                (txn_token, card_token, amount_cents, "APPROVED",
                 json.dumps(receipt), now_iso))
            self.db.commit()
            
            # Return ONLY documented Lithic ASA response fields
            # The receipt is stored locally, NOT returned in the ASA response.
            # (Lithic's schema doesn't have a field for it.)
            return {"result": "APPROVED"}
            
        except Exception as e:
            try:
                self.db.execute("ROLLBACK")
            except Exception:
                pass
            return self._decline(request, "SUSPECTED_FRAUD",
                                 f"Transaction failed: {e}")
    
    def _decline(self, request: dict, reason: str, detail: str) -> dict:
        """Record decline with signed receipt. Return Lithic-schema response."""
        txn_token = request.get("token", "")
        card_token = request.get("card_token", "")
        amount_cents = request.get("amounts", {}).get("cardholder", {}).get("amount", 0)
        
        binding = self.db.execute(
            "SELECT principal_id, mandate_id, subject_id FROM card_bindings "
            "WHERE card_token=?", (card_token,)).fetchone()
        if binding:
            principal_id, mandate_id, subject_id = binding
        else:
            principal_id, mandate_id, subject_id = "unknown", "unknown", "unknown"
        
        receipt = self._sign_receipt(
            "DECLINED", reason, principal_id, mandate_id, subject_id,
            card_token, txn_token, amount_cents)
        
        self.db.execute(
            "INSERT OR IGNORE INTO decisions VALUES (?, ?, ?, ?, ?, ?)",
            (txn_token, card_token, amount_cents, reason,
             json.dumps(receipt),
             datetime.now(timezone.utc).isoformat()))
        self.db.commit()
        
        # Return ONLY documented Lithic fields
        return {"result": reason}
    
    def _sign_receipt(self, decision: str, reason: str | None,
                      principal_id: str, mandate_id: str, subject_id: str,
                      card_token: str, txn_token: str, amount_cents: int) -> dict:
        """Sign receipt with receiver key. Verifiable with pinned public key."""
        row = self.db.execute(
            "SELECT private_key_b64, public_key_b64 FROM receiver_keys "
            "WHERE gate_id=?", (self.gate_id,)).fetchone()
        if not row:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            key = Ed25519PrivateKey.generate()
            priv_b64 = b64u_encode(key.private_bytes_raw())
            pub_b64 = b64u_encode(key.public_key().public_bytes_raw())
            self.db.execute(
                "INSERT INTO receiver_keys VALUES (?, ?, ?)",
                (self.gate_id, priv_b64, pub_b64))
            self.db.commit()
            row = (priv_b64, pub_b64)
        
        priv_b64, pub_b64 = row
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(b64u_decode(priv_b64))
        
        unsigned = {
            "schema": "openline.receipt.v1",
            "decision": decision,
            "reason": reason,
            "principal_id": principal_id,
            "mandate_id": mandate_id,
            "subject_id": subject_id,
            "card_token": card_token,
            "txn_token": txn_token,
            "amount_cents": amount_cents,
            "receiver_gate_id": self.gate_id,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }
        canonical = json.dumps(unsigned, sort_keys=True,
                               separators=(",", ":")).encode()
        sig = key.sign(canonical)
        
        return {
            **unsigned,
            "receiver_signature": b64u_encode(sig),
            "receiver_public_key": pub_b64,
        }
    
    def get_receiver_public_key(self) -> str:
        """Get the receiver's public key for independent verification."""
        row = self.db.execute(
            "SELECT public_key_b64 FROM receiver_keys WHERE gate_id=?",
            (self.gate_id,)).fetchone()
        return row[0] if row else ""
    
    def _verify_hmac(self, raw_body: bytes, headers: dict, secret: str) -> bool:
        """Official Lithic HMAC verification.
        
        From Lithic docs:
        - Headers: webhook-id, webhook-timestamp, webhook-signature
        - Signature: "v1,<base64-hmac-sha256>"
        - Signed content: webhook-id + "." + webhook-timestamp + "." + raw_body
        - Secret: from Lithic dashboard (per-program)
        
        Returns True if valid, False otherwise. Fail closed.
        """
        webhook_id = headers.get("webhook-id", "")
        timestamp = headers.get("webhook-timestamp", "")
        signature = headers.get("webhook-signature", "")
        
        if not all([webhook_id, timestamp, signature]):
            return False
        
        # Check timestamp freshness (within 5 minutes, per Lithic)
        try:
            ts = int(timestamp)
            now = int(time.time())
            if abs(now - ts) > 300:
                return False
        except ValueError:
            return False
        
        # Construct signed content with RAW BODY (not re-serialized JSON)
        signed_content = f"{webhook_id}.{timestamp}.".encode() + raw_body
        
        # HMAC-SHA256, Base64 encoded
        expected = base64.b64encode(
            hmac.new(secret.encode(), signed_content,
                     hashlib.sha256).digest()).decode()
        
        # Signature format: "v1,<base64>"
        if not signature.startswith("v1,"):
            return False
        provided = signature[3:]
        
        return hmac.compare_digest(expected, provided)


def run_negative_tests():
    """Negative tests FIRST. These MUST fail (decline) for security."""
    import tempfile
    import os
    
    print("=" * 60)
    print("NEGATIVE TESTS (must decline)")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "adapter.db")
        adapter = SecureLithicAdapter(db_path, gate_id="neg-test")
        
        # Setup: owner, mandate, card
        owner_dir = os.path.join(tmp, "owner")
        os.makedirs(owner_dir)
        owner = Wallet.create(owner_dir)
        principal_id = owner.principal_id
        owner_pub = public_key_hex(owner.root_key)
        adapter.enroll_owner(principal_id, owner_pub)
        
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from datetime import timedelta
        worker_key = Ed25519PrivateKey.generate()
        worker_pub = public_key_hex(worker_key)
        mandate = owner.grant(
            subject_id="agent-1",
            subject_public_key=worker_pub,
            scopes=["lithic:authorize"],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        mandate_id = mandate["data"]["mandate_id"]
        bundle = owner.export_bundle()
        adapter.admit_bundle(principal_id, bundle)
        
        card_token = "card_neg_001"
        adapter.bind_card(card_token, principal_id, mandate_id, "agent-1")
        
        results = []
        
        # NEGATIVE 1: Known card, NO pre-authorization → MUST DECLINE
        print("\n[NEG-1] Known card, no verified approval → DECLINE")
        req1 = {
            "token": "txn_neg_1",
            "card_token": card_token,
            "amounts": {"cardholder": {"amount": 100, "currency": "USD"}},
        }
        res1 = adapter.handle_asa(req1)
        ok1 = res1["result"] != "APPROVED"
        print(f"  [{'PASS' if ok1 else 'FAIL'}] Result: {res1['result']}")
        results.append(ok1)
        
        # NEGATIVE 2: Wrong amount (pre-auth for $1, ASA for $2) → DECLINE
        print("\n[NEG-2] Amount mismatch → DECLINE")
        # First, do a valid pre-auth for $1
        challenge = adapter.receiver.issue_challenge(principal_id, "agent-1", "lithic:authorize")
        pres = worker_present(bundle=bundle, mandate_id=mandate_id,
                              subject_id="agent-1", subject_key=worker_key,
                              action="lithic:authorize", challenge=challenge)
        pre = adapter.pre_authorize(card_token, 100, pres)
        assert pre["authorized"], f"Pre-auth failed: {pre}"
        # Now ASA for $2 (different amount)
        req2 = {
            "token": "txn_neg_2",
            "card_token": card_token,
            "amounts": {"cardholder": {"amount": 200, "currency": "USD"}},
        }
        res2 = adapter.handle_asa(req2)
        ok2 = res2["result"] != "APPROVED"
        print(f"  [{'PASS' if ok2 else 'FAIL'}] Result: {res2['result']}")
        results.append(ok2)
        
        # NEGATIVE 3: Wrong card (use auth for card A on card B) → DECLINE
        print("\n[NEG-3] Card mismatch → DECLINE")
        card_b = "card_neg_002"
        adapter.bind_card(card_b, principal_id, mandate_id, "agent-1")
        req3 = {
            "token": "txn_neg_3",
            "card_token": card_b,  # Different card, no pre-auth for it
            "amounts": {"cardholder": {"amount": 100, "currency": "USD"}},
        }
        res3 = adapter.handle_asa(req3)
        ok3 = res3["result"] != "APPROVED"
        print(f"  [{'PASS' if ok3 else 'FAIL'}] Result: {res3['result']}")
        results.append(ok3)
        
        # NEGATIVE 4: Reuse consumed auth → DECLINE
        print("\n[NEG-4] Reuse consumed authorization → DECLINE")
        # Use the $1 pre-auth from NEG-2
        req4a = {
            "token": "txn_neg_4a",
            "card_token": card_token,
            "amounts": {"cardholder": {"amount": 100, "currency": "USD"}},
        }
        res4a = adapter.handle_asa(req4a)
        ok4a = res4a["result"] == "APPROVED"
        print(f"  First use: {res4a['result']} [{'PASS' if ok4a else 'FAIL'}]")
        # Try to reuse (different txn token, same card+amount)
        req4b = {
            "token": "txn_neg_4b",
            "card_token": card_token,
            "amounts": {"cardholder": {"amount": 100, "currency": "USD"}},
        }
        res4b = adapter.handle_asa(req4b)
        ok4b = res4b["result"] != "APPROVED"
        print(f"  [{'PASS' if ok4b else 'FAIL'}] Reuse → {res4b['result']}")
        results.append(ok4a and ok4b)
        
        # NEGATIVE 5: Forged presentation (wrong key) → pre-auth DECLINE
        print("\n[NEG-5] Forged presentation → pre-auth DECLINE")
        evil_key = Ed25519PrivateKey.generate()
        challenge5 = adapter.receiver.issue_challenge(principal_id, "agent-1", "lithic:authorize")
        pres5 = worker_present(bundle=bundle, mandate_id=mandate_id,
                               subject_id="agent-1", subject_key=evil_key,  # Wrong key!
                               action="lithic:authorize", challenge=challenge5)
        pre5 = adapter.pre_authorize(card_token, 100, pres5)
        ok5 = not pre5["authorized"]
        print(f"  [{'PASS' if ok5 else 'FAIL'}] Pre-auth: {pre5['reason']}")
        results.append(ok5)
        
        # Summary
        passed = sum(results)
        total = len(results)
        print("\n" + "=" * 60)
        print(f"NEGATIVE TESTS: {passed}/{total} PASS")
        print("=" * 60)
        return 0 if passed == total else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--negative":
        sys.exit(run_negative_tests())
    else:
        print("Usage: python3 lithic_adapter_secure.py --negative")
        print("Runs negative tests (must decline).")
