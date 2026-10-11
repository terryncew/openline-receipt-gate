"""One-card, one-dollar ASA preflight. No settlement or provider API calls.

The durable boundary orders signed bundle admission and ASA decisions with
BEGIN IMMEDIATE. A worker's Wallet presentation grants authority; a separate
signed intent restricts its use to the next matching authorization, not a
transaction token that Lithic has not supplied yet.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
from typing import Mapping
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .wallet_bridge import WalletReceiver
from .openline_wallet.canonical import canonical_json, strict_json_loads
from .openline_wallet.clock import parse_time
from .openline_wallet.crypto import normalize_public_key, public_key_hex, record_hash, sign_record, verify_record
from .openline_wallet.errors import WalletError
from .openline_wallet.wallet import verify_bundle
from .lithic_hmac import decode_asa_secret, verify_lithic_hmac, LithicAuthenticationError

ACTION = "lithic:authorize"
INTENT_SCHEMA = "openline.lithic.payment_intent.v1"
RECEIPT_SCHEMA = "openline.lithic.asa_receipt.v1"
PENDING_TTL_SECONDS = 60


class ReceiverStateError(RuntimeError):
    """State cannot be trusted. No approval may be issued."""


class ReceiptAccessError(PermissionError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _uuid(value):
    if not isinstance(value, str):
        raise ValueError("UUID required")
    return str(uuid.UUID(value))


def payment_details(request: Mapping) -> dict:
    """Select real ASA operation fields; strict $1 USD purchase pilot only."""
    if request.get("event_type") != "card_authorization.approval_request":
        raise ValueError("Only ASA approval requests supported")
    card, amounts, merchant = request["card"], request["amounts"], request["merchant"]
    if card.get("type") != "VIRTUAL" or card.get("state") != "OPEN":
        raise ValueError("Pilot requires an open virtual card")
    cardholder, vendor = amounts["cardholder"], amounts["merchant"]
    for part in (cardholder, vendor):
        if type(part.get("amount")) is not int or part["amount"] != 100 or part.get("currency") != "USD":
            raise ValueError("Pilot permits exactly 100 USD cents")
    rate = cardholder.get("conversion_rate")
    try:
        valid_rate = isinstance(rate, str) and Decimal(rate).is_finite() and Decimal(rate) == 1
    except InvalidOperation:
        valid_rate = False
    if not valid_rate:
        raise ValueError("Pilot excludes currency conversion")
    if (request.get("status") != "AUTHORIZATION"
            or request.get("transaction_initiator") != "CARDHOLDER"
            or type(request.get("cash_amount")) is not int or request["cash_amount"] != 0
            or type(request.get("acquirer_fee")) is not int or request["acquirer_fee"] != 0):
        raise ValueError("Pilot excludes cash, fees, credits and other operations")
    required = {"acceptor_id", "acquiring_institution_id", "city", "country", "descriptor", "mcc", "state"}
    optional = {"phone_number", "postal_code", "street_address"}
    if (not required.issubset(merchant) or set(merchant) - required - optional
            or any(not isinstance(merchant[k], str) for k in required)
            or any(merchant[k] is not None and not isinstance(merchant[k], str) for k in optional & set(merchant))):
        raise ValueError("Complete merchant identity required")
    if not merchant["acceptor_id"] or not merchant["acquiring_institution_id"] or not merchant["descriptor"]:
        raise ValueError("Merchant identity must be populated")
    for name in ("hold", "settlement"):
        part = amounts.get(name)
        if part is not None and (part.get("amount") != 100 or part.get("currency") != "USD"):
            raise ValueError("Pilot excludes adjusted hold/settlement amounts")
    for name in ("amount", "authorization_amount", "merchant_amount"):
        if name in request and (type(request[name]) is not int or request[name] != 100):
            raise ValueError("Legacy and structured amounts must agree")
    for name in ("cardholder_currency", "merchant_currency"):
        if name in request and request[name] != "USD":
            raise ValueError("Legacy and structured currencies must agree")
    if request.get("settled_amount", 0) != 0:
        raise ValueError("Pilot does not authorize settled transactions")
    details = {"card_token": _uuid(card["token"]), "amounts": amounts,
               "merchant": merchant, "status": request["status"],
               "transaction_initiator": request["transaction_initiator"],
               "cash_amount": 0, "acquirer_fee": 0}
    for name in ("network", "pos", "account_type", "service_location", "cardholder_authentication", "token_info",
                 "avs", "name_validation", "network_risk_score", "network_specific_data", "fleet_info", "latest_challenge"):
        # Bind any supplied network/POS/operation context, including absence.
        details[name] = request.get(name)
    return json.loads(canonical_json(details))


def create_payment_intent(*, gate_id, details, presentation, subject_key):
    """Worker signs actual payment terms and the exact Wallet presentation."""
    return sign_record({"schema": INTENT_SCHEMA, "gate_id": gate_id,
                        "principal_id": presentation["principal_id"],
                        "mandate_id": presentation["mandate_id"],
                        "subject_id": presentation["subject_id"],
                        "presentation_hash": record_hash(presentation),
                        "details": details}, subject_key)


class SecureLithicAdapter:
    def __init__(self, db_path, *, gate_id="lithic-pilot-1", signing_secrets=(),
                 sandbox=True, initialize=False, expected_receiver_public_key=None):
        self.db_path, self.gate_id = Path(db_path), gate_id
        self.signing_secrets = (signing_secrets,) if isinstance(signing_secrets, str) else tuple(signing_secrets)
        self.sandbox = sandbox
        if sandbox and not self.signing_secrets:
            raise ValueError("Sandbox ASA authentication requires its ASA signing secret")
        for secret in self.signing_secrets:
            decode_asa_secret(secret)
        self._lock = threading.RLock()
        self._failed = False
        new = not self.db_path.exists()
        if new and not initialize:
            raise ReceiverStateError("Receiver state unavailable; explicit initialization required")
        if new:
            descriptor = os.open(self.db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        try:
            self.db = sqlite3.connect(str(self.db_path), timeout=1, check_same_thread=False, isolation_level=None)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            if new:
                self._initialize()
            self._validate_state()
            if expected_receiver_public_key is not None and self._public_key != normalize_public_key(expected_receiver_public_key):
                raise ReceiverStateError("Receiver key differs from independent pin")
        except Exception as error:
            if hasattr(self, "db"):
                self.db.close()
            raise ReceiverStateError("Receiver state initialization/verification failed") from error

    @contextmanager
    def _transaction(self):
        if not self._lock.acquire(timeout=1):
            raise ReceiverStateError("Receiver transaction queue unavailable")
        try:
            if self._failed or not self.db_path.exists():
                raise ReceiverStateError("Receiver state unavailable")
            try:
                self.db.execute("BEGIN IMMEDIATE")
                yield
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
        finally:
            self._lock.release()

    def _initialize(self):
        # Only explicit fresh initialization creates a key. Receipt signing
        # never creates keys, calls COMMIT, or changes transaction ownership.
        with self._transaction():
            self.db.execute("CREATE TABLE metadata(gate_id TEXT PRIMARY KEY, version INTEGER NOT NULL, private_key TEXT NOT NULL, public_key TEXT NOT NULL)")
            self.db.execute("CREATE TABLE pins(principal TEXT PRIMARY KEY, root TEXT NOT NULL)")
            self.db.execute("CREATE TABLE bundles(principal TEXT PRIMARY KEY REFERENCES pins(principal), body TEXT NOT NULL, sequence INTEGER NOT NULL, head TEXT, quarantined INTEGER NOT NULL DEFAULT 0)")
            self.db.execute("CREATE TABLE cards(card TEXT PRIMARY KEY, principal TEXT NOT NULL REFERENCES pins(principal), mandate TEXT NOT NULL, subject TEXT NOT NULL)")
            self.db.execute("CREATE TABLE challenges(token TEXT PRIMARY KEY, card TEXT NOT NULL REFERENCES cards(card), principal TEXT NOT NULL, subject TEXT NOT NULL, issued TEXT NOT NULL, expires TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
            self.db.execute("CREATE TABLE pending(card TEXT PRIMARY KEY REFERENCES cards(card), principal TEXT NOT NULL, mandate TEXT NOT NULL, subject TEXT NOT NULL, details TEXT NOT NULL, proof TEXT NOT NULL, expires TEXT NOT NULL)")
            self.db.execute("CREATE TABLE decisions(token TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, principal TEXT, result TEXT NOT NULL, receipt TEXT NOT NULL)")
            self.db.execute("CREATE TABLE integrators(identity TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, principal TEXT NOT NULL REFERENCES pins(principal))")
            key = Ed25519PrivateKey.generate()
            self.db.execute("INSERT INTO metadata VALUES (?,1,?,?)",
                            (self.gate_id, key.private_bytes_raw().hex(), public_key_hex(key)))

    def _validate_state(self):
        if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise ReceiverStateError("Receiver database corrupt")
        row = self.db.execute("SELECT gate_id,version,private_key,public_key FROM metadata").fetchall()
        if len(row) != 1 or row[0][:2] != (self.gate_id, 1):
            raise ReceiverStateError("Receiver metadata missing/mismatched")
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(row[0][2]))
        if public_key_hex(key) != row[0][3]:
            raise ReceiverStateError("Receiver signing identity corrupt")
        self._key, self._public_key = key, row[0][3]
        for principal, root in self.db.execute("SELECT principal,root FROM pins"):
            receiver = WalletReceiver(self.gate_id)
            receiver.pin_owner(principal, root)
        for (principal,) in self.db.execute("SELECT principal FROM bundles"):
            self._authority(principal, fresh=False)
        if self.db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ReceiverStateError("Receiver references corrupt")

    def _authority(self, principal, *, fresh=True):
        row = self.db.execute("SELECT b.body,b.sequence,b.head,b.quarantined,p.root FROM bundles b JOIN pins p USING(principal) WHERE principal=?", (principal,)).fetchone()
        if row is None:
            raise WalletError("BUNDLE_NOT_ADMITTED")
        bundle, sequence, head, quarantine, root = row
        verified, timeline = verify_bundle(strict_json_loads(bundle), require_fresh=fresh)
        if (verified["principal"]["principal_id"] != principal or verified["principal"]["root_public_key"] != root
                or timeline.head_sequence != sequence or timeline.head_hash != head):
            raise ReceiverStateError("Stored authority inconsistent")
        if quarantine and fresh:
            raise WalletError("PRINCIPAL_FORK_QUARANTINED")
        if fresh and (_now() - parse_time(verified["issued_at"])).total_seconds() > 300:
            raise WalletError("BUNDLE_OUTSIDE_GATE_FRESHNESS")
        return verified, timeline

    @staticmethod
    def _active(timeline, mandate_id, subject):
        mandate = timeline.mandates.get(mandate_id)
        return bool(mandate and mandate["status"] == "ACTIVE"
                    and mandate["subject_id"] == subject and ACTION in mandate["scopes"]
                    and parse_time(mandate["expires_at"]) > _now())

    def enroll_owner(self, principal_id, root_key_hex):
        receiver = WalletReceiver(self.gate_id)
        receiver.pin_owner(principal_id, root_key_hex)
        root = normalize_public_key(root_key_hex)
        with self._transaction():
            pins = self.db.execute("SELECT principal,root FROM pins").fetchall()
            if pins and pins != [(principal_id, root)]:
                raise ValueError("Pilot permits one pinned owner; no implicit root rotation")
            self.db.execute("INSERT OR IGNORE INTO pins VALUES (?,?)", (principal_id, root))

    def admit_bundle(self, principal_id, bundle):
        fork = False
        with self._transaction():
            verified, timeline = verify_bundle(bundle)
            pin = self.db.execute("SELECT root FROM pins WHERE principal=?", (principal_id,)).fetchone()
            if (not pin or verified["principal"]["principal_id"] != principal_id
                    or verified["principal"]["root_public_key"] != pin[0]):
                raise WalletError("ROOT_NOT_PINNED")
            # Use the real ReferenceGate to apply admission freshness policy.
            receiver = WalletReceiver(self.gate_id)
            receiver.pin_owner(principal_id, pin[0])
            result = receiver.admit_bundle(verified)
            previous = self.db.execute("SELECT body,sequence,head,quarantined FROM bundles WHERE principal=?", (principal_id,)).fetchone()
            if previous:
                old, old_timeline = self._authority(principal_id, fresh=False)
                if previous[3]:
                    raise WalletError("PRINCIPAL_FORK_QUARANTINED")
                if timeline.head_sequence < old_timeline.head_sequence:
                    raise WalletError("BUNDLE_HEAD_STALE")
                fork = (timeline.head_sequence == old_timeline.head_sequence and timeline.head_hash != old_timeline.head_hash)
                if timeline.head_sequence > old_timeline.head_sequence and old_timeline.head_sequence:
                    fork = record_hash(verified["events"][old_timeline.head_sequence - 1]) != old_timeline.head_hash
                if not fork and parse_time(verified["issued_at"]) < parse_time(old["issued_at"]):
                    raise WalletError("BUNDLE_REFRESH_STALE")
            if fork:
                self.db.execute("UPDATE bundles SET quarantined=1 WHERE principal=?", (principal_id,))
                self.db.execute("DELETE FROM pending WHERE principal=?", (principal_id,))
            else:
                self.db.execute("INSERT INTO bundles VALUES (?,?,?,?,0) ON CONFLICT(principal) DO UPDATE SET body=excluded.body,sequence=excluded.sequence,head=excluded.head",
                                (principal_id, canonical_json(verified).decode(), timeline.head_sequence, timeline.head_hash))
                for card, mandate, subject in self.db.execute("SELECT card,mandate,subject FROM pending WHERE principal=?", (principal_id,)).fetchall():
                    if not self._active(timeline, mandate, subject):
                        self.db.execute("DELETE FROM pending WHERE card=?", (card,))
        # Quarantine is durable, rather than rolled back by raising in the txn.
        if fork:
            raise WalletError("BUNDLE_FORK_QUARANTINED")
        return result

    def bind_card(self, card_token, principal_id, mandate_id, subject_id):
        card = _uuid(card_token)
        with self._transaction():
            _, timeline = self._authority(principal_id)
            if not self._active(timeline, mandate_id, subject_id):
                raise WalletError("MANDATE_INACTIVE")
            cards = self.db.execute("SELECT card FROM cards").fetchall()
            if cards and cards != [(card,)]:
                raise ValueError("Pilot permits one virtual card")
            self.db.execute("DELETE FROM pending WHERE card=?", (card,))
            self.db.execute("DELETE FROM challenges WHERE card=?", (card,))
            self.db.execute("INSERT INTO cards VALUES (?,?,?,?) ON CONFLICT(card) DO UPDATE SET principal=excluded.principal,mandate=excluded.mandate,subject=excluded.subject",
                            (card, principal_id, mandate_id, subject_id))

    def issue_challenge(self, card_token):
        card = _uuid(card_token)
        with self._transaction():
            binding = self.db.execute("SELECT principal,mandate,subject FROM cards WHERE card=?", (card,)).fetchone()
            if not binding:
                raise WalletError("UNKNOWN_CARD")
            _, timeline = self._authority(binding[0])
            if not self._active(timeline, binding[1], binding[2]):
                raise WalletError("MANDATE_INACTIVE")
            now = _now()
            token = "challenge_" + secrets.token_hex(16)
            self.db.execute("INSERT INTO challenges VALUES (?,?,?,?,?,?,0)",
                            (token, card, binding[0], binding[2], now.isoformat(),
                             (now + timedelta(seconds=60)).isoformat()))
            return token

    def pre_authorize(self, card_token, details, presentation, signed_intent):
        card = _uuid(card_token)
        with self._transaction():
            # Enforce the same narrow terms before claiming preauthorization.
            try:
                candidate = {"event_type": "card_authorization.approval_request",
                             "card": {"token": card, "type": "VIRTUAL", "state": "OPEN"},
                             **{k: v for k, v in details.items() if k != "card_token"}}
                if payment_details(candidate) != details:
                    raise ValueError("Intent terms are not normalized")
            except (ValueError, TypeError, KeyError, WalletError):
                return {"authorized": False, "reason": "OUTSIDE_NARROW_PILOT"}
            binding = self.db.execute("SELECT principal,mandate,subject FROM cards WHERE card=?", (card,)).fetchone()
            if not binding or (presentation.get("principal_id"), presentation.get("mandate_id"), presentation.get("subject_id")) != binding:
                return {"authorized": False, "reason": "IDENTITY_BINDING_MISMATCH"}
            bundle, timeline = self._authority(binding[0])
            if not self._active(timeline, binding[1], binding[2]):
                return {"authorized": False, "reason": "MANDATE_INACTIVE"}
            expected = {"schema": INTENT_SCHEMA, "gate_id": self.gate_id,
                        "principal_id": binding[0], "mandate_id": binding[1], "subject_id": binding[2],
                        "presentation_hash": record_hash(presentation), "details": details}
            if ({k: v for k, v in signed_intent.items() if k not in {"payload_hash", "signature"}} != expected
                    or details.get("card_token") != card
                    or not verify_record(signed_intent, expected_public_key=timeline.mandates[binding[1]]["subject_public_key"])[0]):
                return {"authorized": False, "reason": "SIGNED_INTENT_INVALID"}
            # Validation happens again against the authenticated ASA payload.
            canonical_json(details)
            token = presentation.get("receiver_challenge")
            row = self.db.execute("SELECT card,principal,subject,issued,expires,used FROM challenges WHERE token=?", (token,)).fetchone()
            if not row or row[0:3] != (card, binding[0], binding[2]) or row[5]:
                return {"authorized": False, "reason": "CHALLENGE_UNKNOWN_OR_USED"}
            receiver = WalletReceiver(self.gate_id)
            receiver.gate.gate_key = self._key
            receiver.pin_owner(binding[0], bundle["principal"]["root_public_key"])
            receiver.protect_action(ACTION, [ACTION])
            receiver.admit_bundle(bundle)
            # Restore only this durable receiver-issued challenge, never one
            # supplied by the worker. The real Gate verifies its signature.
            receiver.gate._challenges[token] = {"principal_id": row[1], "subject_id": row[2], "action": ACTION,
                                                "issued_at": parse_time(row[3]), "expires_at": parse_time(row[4]), "used": False}
            decision = receiver.authorize(presentation, ACTION)
            if receiver.gate._challenges[token]["used"]:
                self.db.execute("UPDATE challenges SET used=1 WHERE token=?", (token,))
            if decision["decision"] != "ALLOWED":
                return {"authorized": False, "reason": (decision.get("reason_codes") or ["DENIED"])[0]}
            if self.db.execute("SELECT 1 FROM pending WHERE card=? AND expires>?", (card, _now().isoformat())).fetchone():
                return {"authorized": False, "reason": "PENDING_AUTHORIZATION_EXISTS"}
            proof = {"wallet_decision": decision, "worker_intent": signed_intent}
            expires = min(parse_time(decision["decided_at"]) + timedelta(seconds=PENDING_TTL_SECONDS), parse_time(bundle["expires_at"]),
                          parse_time(timeline.mandates[binding[1]]["expires_at"]))
            self.db.execute("INSERT INTO pending VALUES (?,?,?,?,?,?,?) ON CONFLICT(card) DO UPDATE SET principal=excluded.principal,mandate=excluded.mandate,subject=excluded.subject,details=excluded.details,proof=excluded.proof,expires=excluded.expires",
                            (card, *binding, canonical_json(details).decode(), canonical_json(proof).decode(), expires.isoformat()))
            return {"authorized": True, "reason": "OK", "expires_at": expires.isoformat()}

    def _sign_receipt(self, body):
        # This operation must be pure with respect to SQLite.
        return sign_record(body, self._key)

    def _check_identity(self):
        row = self.db.execute("SELECT gate_id,version,private_key,public_key FROM metadata").fetchall()
        if row != [(self.gate_id, 1, self._key.private_bytes_raw().hex(), self._public_key)]:
            raise ReceiverStateError("Receiver signing identity changed")

    def _verify_pending_proof(self, pending, details, timeline):
        proof = strict_json_loads(pending[4])
        if not isinstance(proof, dict) or set(proof) != {"wallet_decision", "worker_intent"}:
            raise ReceiverStateError("Pending authority proof corrupt")
        decision, intent = proof["wallet_decision"], proof["worker_intent"]
        if not isinstance(decision, dict) or not isinstance(intent, dict):
            raise ReceiverStateError("Pending authority proof corrupt")
        expected = {"schema": INTENT_SCHEMA, "gate_id": self.gate_id,
                    "principal_id": pending[0], "mandate_id": pending[1], "subject_id": pending[2],
                    "presentation_hash": decision.get("presentation_hash"), "details": details}
        decided_at = parse_time(decision.get("decided_at"))
        if (decided_at > _now() + timedelta(seconds=5)
                or decided_at + timedelta(seconds=60) <= _now()
                or parse_time(pending[5]) > decided_at + timedelta(seconds=60)):
            raise ReceiverStateError("Pending authority lifetime corrupt")
        if (not verify_record(decision, expected_public_key=self._public_key)[0]
                or decision.get("gate_id") != self.gate_id or decision.get("gate_public_key") != self._public_key
                or decision.get("decision") != "ALLOWED" or decision.get("action") != ACTION
                or tuple(decision.get(k) for k in ("principal_id", "mandate_id", "subject_id")) != pending[:3]
                or {k: v for k, v in intent.items() if k not in {"payload_hash", "signature"}} != expected
                or not verify_record(intent, expected_public_key=timeline.mandates[pending[1]]["subject_public_key"])[0]):
            raise ReceiverStateError("Pending authority proof corrupt")
        return proof

    def _stored_decision(self, token):
        row = self.db.execute("SELECT fingerprint,result,principal,receipt FROM decisions WHERE token=?", (token,)).fetchone()
        if row is None:
            return None
        receipt = strict_json_loads(row[3])
        if (not verify_record(receipt, expected_public_key=self._public_key)[0]
                or receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("gate_id") != self.gate_id
                or (receipt.get("request_fingerprint"), receipt.get("result"), receipt.get("principal_id")) != row[:3]
                or receipt.get("txn_token") != token):
            raise ReceiverStateError("Stored signed decision corrupt")
        return row[:3], receipt

    def handle_asa(self, request=None, headers=None, raw_body=None):
        if self.sandbox or self.signing_secrets:
            if not isinstance(raw_body, bytes):
                raise LithicAuthenticationError("Original ASA request bytes required")
            verify_lithic_hmac(raw_body, headers or {}, self.signing_secrets)
        if raw_body is not None:
            parsed = strict_json_loads(raw_body.decode("utf-8"))
            if request is not None and request != parsed:
                raise ValueError("Supplied request differs from authenticated bytes")
            request = parsed
        if not isinstance(request, dict):
            raise ValueError("ASA JSON object required")
        token = _uuid(request.get("token"))
        # Fingerprint all authenticated JSON contents, not just selected terms.
        fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        try:
            with self._transaction():
                self._check_identity()
                # Historical signature/head validation also applies to retries.
                # Revoked-but-valid history preserves an immutable old decision;
                # corrupt authority state cannot yield any APPROVED response.
                for (owner,) in self.db.execute("SELECT principal FROM bundles").fetchall():
                    self._authority(owner, fresh=False)
                stored = self._stored_decision(token)
                existing = stored[0] if stored else None
                if existing:
                    if existing[0] != fingerprint:
                        return {"result": "SUSPECTED_FRAUD"}
                    return {"result": existing[1]}
                result, reason, principal, mandate, subject, proof = "CARD_PAUSED", "NO_PENDING_AUTHORIZATION", None, None, None, None
                try:
                    associated_card = _uuid(request["card"]["token"])
                    associated = self.db.execute("SELECT principal,mandate,subject FROM cards WHERE card=?", (associated_card,)).fetchone()
                    if associated:
                        principal, mandate, subject = associated
                except (ValueError, KeyError, TypeError):
                    pass
                try:
                    required = {"event_type", "token", "created", "card", "amounts", "merchant", "status",
                                "transaction_initiator", "cash_amount", "acquirer_fee", "amount", "authorization_amount",
                                "merchant_amount", "settled_amount", "cardholder_currency", "merchant_currency", "avs",
                                "name_validation", "service_location"}
                    if not required.issubset(request):
                        raise ValueError("Complete ASA request required")
                    parse_time(request["created"])
                    details = payment_details(request)
                except (ValueError, KeyError, TypeError, WalletError):
                    details = None
                    result, reason = "UNAUTHORIZED_MERCHANT", "OUTSIDE_NARROW_PILOT"
                if details:
                    binding = self.db.execute("SELECT principal,mandate,subject FROM cards WHERE card=?", (details["card_token"],)).fetchone()
                    if binding:
                        principal, mandate, subject = binding
                    pending = self.db.execute("SELECT principal,mandate,subject,details,proof,expires FROM pending WHERE card=?", (details["card_token"],)).fetchone()
                    if pending:
                        principal, mandate, subject = pending[:3]
                        if binding != pending[:3]:
                            raise ReceiverStateError("Pending card authority binding corrupt")
                        try:
                            bundle, timeline = self._authority(principal)
                            active = self._active(timeline, mandate, subject)
                        except WalletError:
                            active = False
                        if not active or parse_time(pending[5]) <= _now():
                            self.db.execute("DELETE FROM pending WHERE card=?", (details["card_token"],))
                            reason = "AUTHORITY_REVOKED_OR_EXPIRED"
                        elif strict_json_loads(pending[3]) != details:
                            result, reason = "UNAUTHORIZED_MERCHANT", "INTENT_MISMATCH"
                        else:
                            proof = self._verify_pending_proof(pending, details, timeline)
                            result, reason = "APPROVED", "VERIFIED_NEXT_MATCHING_AUTHORIZATION"
                            self.db.execute("DELETE FROM pending WHERE card=?", (details["card_token"],))
                receipt = self._sign_receipt({"schema": RECEIPT_SCHEMA, "gate_id": self.gate_id, "txn_token": token,
                    "request_fingerprint": fingerprint, "result": result, "reason": reason,
                    "principal_id": principal, "mandate_id": mandate, "subject_id": subject,
                    "payment_details": details, "authority_proof": proof, "decided_at": _now().isoformat(),
                    "authorization_semantics": "One use by next matching ASA purchase within 60s; transaction token bound only at ASA decision; no settlement claim"})
                self.db.execute("INSERT INTO decisions VALUES (?,?,?,?,?)",
                                (token, fingerprint, principal, result, canonical_json(receipt).decode()))
                return {"result": result}
        except (sqlite3.Error, ReceiverStateError, WalletError, ValueError, TypeError, RuntimeError) as error:
            # A processing failure is not a durable decline. The HTTP adapter
            # returns 503, which permits a retry without contradicting a prior
            # acknowledged decision. Never return an uncommitted approval or
            # pretend an unavailable receipt/state was persisted.
            raise ReceiverStateError("ASA decision unavailable; no decision acknowledged") from error

    def enroll_integrator(self, identity, bearer_token, principal_id):
        if not isinstance(bearer_token, str) or len(bearer_token) < 32:
            raise ValueError("Integrator bearer token must have at least 32 characters")
        with self._transaction():
            self.db.execute("INSERT INTO integrators VALUES (?,?,?)", (identity, hashlib.sha256(bearer_token.encode()).hexdigest(), principal_id))

    def retrieve_receipt(self, txn_token, bearer_token):
        if not isinstance(bearer_token, str) or not bearer_token:
            raise ReceiptAccessError("Authentication required")
        with self._lock:
            if self._failed or not self.db_path.exists():
                raise ReceiverStateError("Receiver state unavailable")
            token_hash = hashlib.sha256(bearer_token.encode()).hexdigest()
            principal = next((row[1] for row in self.db.execute("SELECT token_hash,principal FROM integrators")
                              if hmac.compare_digest(row[0], token_hash)), None)
            if principal is None:
                raise ReceiptAccessError("Authentication required")
            stored = self._stored_decision(_uuid(txn_token))
            if stored is None or stored[0][2] != principal:
                # Do not disclose whether an inaccessible transaction exists.
                raise ReceiptAccessError("Receipt unavailable")
            receipt = stored[1]
            self._check_identity()
            if not verify_record(receipt, expected_public_key=self._public_key)[0]:
                raise ReceiverStateError("Stored signed receipt corrupt")
            return receipt

    def get_receiver_public_key(self):
        return self._public_key

    def close(self):
        with self._lock:
            self.db.close()
