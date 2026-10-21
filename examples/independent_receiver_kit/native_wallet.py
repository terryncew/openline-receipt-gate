"""Native Wallet bundle -> independent receiver's *local* SQLite document gate.

No conversion to mandate_authorization: the original signed receiver_bundle.v1
is verified by Wallet itself, and kept byte-equivalent in the receiver history.
A separate worker-signed receiver-kit-call/v1 binds the exact document/effect.
This is an experimental local reference, not a production receiver.
"""
from __future__ import annotations
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openline_wallet import verify_bundle
from openline_wallet.errors import WalletError
from olp_gate.crypto import olp_canonical_json, sha256_hex, sign_olp_body, public_key_hex
from olp_gate.mandate import validate_effect
from .formats import decode_call

def canonical(x): return olp_canonical_json(x).decode("ascii")
def digest(x): return sha256_hex(olp_canonical_json(x))

class NativeWalletReceiver:
    """Only this trusted receiver may call admit/submit and mutate its database."""
    def __init__(self, db, config, outcome_key: Ed25519PrivateKey, clock=None):
        if public_key_hex(outcome_key) != config["outcome_key"]:
            raise ValueError("receiver_outcome_key_not_pinned")
        if not config["owner_id"] or not config["owner_key"]:
            raise ValueError("owner_root_missing")
        if config["policy"]["tool"] != "intake.submit":
            raise ValueError("unsupported_receiver_policy")
        self.db, self.config, self.key = Path(db), json.loads(canonical(config)), outcome_key
        self.clock = clock or (lambda: int(time.time()))
        self.db.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript("""
                CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY, head TEXT UNIQUE NOT NULL, bundle TEXT NOT NULL, admitted_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS consumed(nonce TEXT PRIMARY KEY, proof_hash TEXT UNIQUE NOT NULL);
                CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, body TEXT NOT NULL, proof_hash TEXT UNIQUE NOT NULL);
                CREATE TABLE IF NOT EXISTS decisions(seq INTEGER PRIMARY KEY, route TEXT NOT NULL, request TEXT NOT NULL, signed TEXT NOT NULL);
            """)
            c.execute("BEGIN IMMEDIATE")
            row=c.execute("SELECT json FROM settings WHERE id=1").fetchone()
            if row is None:
                c.execute("INSERT INTO settings VALUES(1,?)",(canonical(self.config),))
            elif row[0] != canonical(self.config):
                c.rollback()
                raise ValueError("receiver_config_changed")
            c.commit()

    def _connect(self):
        c=sqlite3.connect(self.db, isolation_level=None, timeout=10)
        c.row_factory=sqlite3.Row
        c.execute("PRAGMA synchronous=FULL")
        return c

    def _verify(self, bundle, now):
        verified, timeline=verify_bundle(bundle, now=datetime.fromtimestamp(now, timezone.utc))
        principal=verified["principal"]
        if principal["principal_id"] != self.config["owner_id"] or principal["root_public_key"] != self.config["owner_key"]:
            raise ValueError("untrusted_wallet_root")
        issued=datetime.fromisoformat(verified["issued_at"].replace("Z","+00:00")).timestamp()
        # Signed export age is bounded by receiver policy, not wallet's 600s maximum.
        if issued > now or not 0 <= now-issued < self.config["policy"]["freshness_seconds"]:
            raise ValueError("wallet_export_stale_or_future")
        if timeline.head_sequence < 1 or timeline.head_hash is None:
            raise ValueError("empty_wallet_authority")
        return verified, timeline

    def dispatch(self, route, request):
        request=json.loads(canonical(request))  # freeze caller-owned mutable input
        with closing(self._connect()) as c:
            c.execute("BEGIN IMMEDIATE")
            now=int(self.clock())
            history=c.execute("SELECT * FROM history ORDER BY seq").fetchall()
            before=c.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            verdict,reason,subject,at="DENY","unsupported_route",None,None
            c.execute("SAVEPOINT effect")
            try:
                if route=="/authority":
                    bundle, timeline=self._verify(request, now)  # native signed bundle, no conversion
                    seq, head=timeline.head_sequence, timeline.head_hash
                    if history:
                        old=history[-1]
                        if seq<old["seq"]:
                            raise ValueError("wallet_history_rollback")
                        if seq==old["seq"]:
                            if head!=old["head"]:
                                raise ValueError("wallet_history_fork")
                            verdict,reason="ACCEPT","duplicate_does_not_refresh"
                        else:
                            from openline_wallet.crypto import record_hash
                            if record_hash(bundle["events"][old["seq"]-1])!=old["head"]:
                                raise ValueError("wallet_history_fork")
                    if not history or seq>history[-1]["seq"]:
                        c.execute("INSERT INTO history VALUES(?,?,?,?)",(seq,head,canonical(request),now))
                        verdict,reason="ACCEPT","native_wallet_bundle_admitted"
                elif route=="/submit":
                    if set(request)!={"proof"}:
                        raise ValueError("submit_shape_invalid")
                    if not history:
                        raise ValueError("wallet_authority_missing")
                    current=history[-1]
                    bundle=json.loads(current["bundle"])
                    verified,timeline=self._verify(bundle,now)
                    if timeline.head_hash!=current["head"] or timeline.head_sequence!=current["seq"]:
                        raise ValueError("wallet_frontier_corrupt")
                    if now-current["admitted_at"]>=self.config["policy"]["freshness_seconds"]:
                        raise ValueError("admission_freshness_expired")
                    proof=request["proof"]
                    if not isinstance(proof,dict) or not isinstance(proof.get("signature"),dict):
                        raise ValueError("worker_proof_invalid")
                    claimed=proof["signature"].get("public_key")
                    claims=decode_call("openline",proof,claimed,self.config,now)
                    subject=claims["sub"]
                    if claims["head_hash"]!=timeline.head_hash:
                        raise ValueError("worker_head_stale")
                    if claims["policy_hash"]!=digest(self.config["policy"]):
                        raise ValueError("receiver_policy_changed")
                    matching=[m for m in timeline.current(datetime.fromtimestamp(now,timezone.utc))
                              if m["subject_public_key"]==subject and m["mandate_id"]==claims["effect"]["mandate_id"]]
                    if len(matching)!=1:
                        raise ValueError("wallet_mandate_missing_or_revoked")
                    mandate=matching[0]
                    if "intake.submit" not in mandate["scopes"]:
                        raise ValueError("wallet_mandate_scope_denied")
                    effect=validate_effect(claims["effect"])
                    document=claims["document"]
                    if (effect["principal_id"]!=self.config["owner_id"]
                            or effect["agent_id"]!=subject or effect["purpose"]!="submit local document"
                            or effect["action_type"]!="send" or effect["target"]!=self.config["policy"]["target"]
                            or effect["value_cents"]!=0 or effect["disclosures"] or effect["delegatee"] is not None
                            or effect["effect_id"]!=document["record_id"]):
                        raise ValueError("exact_protected_action_mismatch")
                    if len(document["text"])>self.config["policy"]["max_document_chars"]:
                        raise ValueError("document_outside_policy")
                    fresh=int(self.clock())
                    if fresh<now or fresh>=claims["exp"]:
                        raise ValueError("worker_proof_expired_before_effect")
                    self._verify(bundle,fresh)
                    at=fresh
                    c.execute("INSERT INTO consumed VALUES(?,?)",(claims["jti"],digest(request)))
                    c.execute("INSERT INTO documents VALUES(?,?,?)",(document["record_id"],canonical(document),digest(request)))
                    verdict,reason="ALLOW","local_document_committed"
                else:
                    raise ValueError("unsupported_route")
            except (ValueError,TypeError,KeyError,IndexError,AttributeError,WalletError,sqlite3.IntegrityError) as err:
                c.execute("ROLLBACK TO effect")
                verdict,reason,at="DENY",str(err) or type(err).__name__,None
            c.execute("RELEASE effect")
            after=c.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            seq=c.execute("SELECT COALESCE(MAX(seq),0)+1 FROM decisions").fetchone()[0]
            new_head=c.execute("SELECT * FROM history ORDER BY seq DESC LIMIT 1").fetchone()
            decision=sign_olp_body({
                "schema":"receiver-kit-native-wallet-decision/v1", "mode":"wallet",
                "seq":seq, "receiver_id":self.config["receiver_id"],
                "route":route, "verdict":verdict,"reason":reason,"subject":subject,
                "request_hash":digest(request), "policy_hash":digest(self.config["policy"]),
                "owner_head":new_head["head"] if new_head else None,
                "owner_sequence":new_head["seq"] if new_head else 0,
                "observed_at":now,"effect_at":at,
                "documents_before":before,"documents_after":after,
            },self.key)
            c.execute("INSERT INTO decisions VALUES(?,?,?,?)",
                      (seq,route,canonical(request),canonical(decision)))
            c.commit()
            return decision
