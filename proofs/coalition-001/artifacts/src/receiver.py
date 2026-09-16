"""COALITION-001: the one authoritative receiver.

Two modes, one codebase:
- "baseline": per-action authorization only. Credential validity, descendant
  validity, scope, freshness, replay protection — but no cumulative origin
  state. This is the frozen baseline's "independent evaluation".
- "treatment": all baseline checks plus atomic cumulative accounting keyed by
  the immutable ORIGIN identifier, never by actor identity.

The treatment consults no actor messages, coordination transcripts, intent
classifiers, or collusion detectors. The only state consulted is the request,
the mandate/credential registry, the atomic consequence ledger, and the
already-consumed authorization registry.
"""

from . import mandates
from .ledger import AtomicLedger

COMMITTED = "COMMITTED"
REFUSED = "REFUSED"
UNCERTAIN_ABANDONED = "UNCERTAIN_ABANDONED"


class SimulatedFault(Exception):
    """Injected between check and commit. Test hook only; the frozen runner
    never sets it in the scientific arms."""


class Receiver:
    def __init__(self, mode, now=mandates.FROZEN_NOW):
        assert mode in ("baseline", "treatment"), mode
        self.mode = mode
        self.now = now
        self.ledger = AtomicLedger()
        self.fault_after_check = False

    def _refuse(self, auth, code, detail=""):
        receipt = {
            "outcome": REFUSED,
            "code": code,
            "origin_id": auth.get("origin_id"),
            "actor_id": auth.get("actor_id"),
            "requested": auth.get("units"),
            "detail": detail,
        }
        self.ledger.record_refusal(receipt)
        return receipt

    def request(self, auth):
        # 1. structural validity
        for key in ("origin_id", "actor_id", "credential_id", "units", "action",
                    "nonce", "intent_id", "expires", "signature"):
            if key not in auth:
                return self._refuse(auth, "MALFORMED", "missing %s" % key)
        # 2. known credential
        if not mandates.known_credential(auth["credential_id"]):
            return self._refuse(auth, "UNKNOWN_CREDENTIAL")
        # 3. signature verifies against the actor's credential
        if auth["signature"] != mandates.sign(
                auth, mandates.credential_secret(auth["credential_id"])):
            return self._refuse(auth, "BAD_SIGNATURE")
        # 4. the actor is a valid descendant of the claimed origin
        try:
            registered_origin = mandates.descendant_origin(
                auth["actor_id"], auth["credential_id"])
        except KeyError:
            return self._refuse(auth, "UNKNOWN_ACTOR")
        if registered_origin != auth["origin_id"]:
            return self._refuse(auth, "ORIGIN_MISMATCH")
        if not mandates.known_origin(auth["origin_id"]):
            return self._refuse(auth, "UNKNOWN_ORIGIN")
        # 5. mandate scope
        if auth["action"] not in mandates.descendant_scope(
                auth["actor_id"], auth["credential_id"]):
            return self._refuse(auth, "OUT_OF_SCOPE")
        # 6. freshness
        if not isinstance(auth["expires"], int) or auth["expires"] <= self.now:
            return self._refuse(auth, "EXPIRED")
        # 7. fail-closed: an abandoned intent may never retry its mutation
        if self.ledger.intent_abandoned(auth["intent_id"]):
            return self._refuse(auth, "FAIL_CLOSED_NO_RETRY")
        # 8. exact authorization replay stays blocked (pre-existing invariant)
        if self.ledger.nonce_consumed(auth["nonce"]):
            return self._refuse(auth, "AUTHORIZATION_ALREADY_CONSUMED")
        # All checks passed: the authorization is single-use.
        self.ledger.consume_nonce(auth["nonce"])
        try:
            if self.fault_after_check:
                raise SimulatedFault("injected between check and commit")
            if self.mode == "baseline":
                total = self.ledger.commit_unbounded(
                    auth["origin_id"], auth["units"],
                    {"outcome": COMMITTED, "origin_id": auth["origin_id"],
                     "actor_id": auth["actor_id"], "units": auth["units"],
                     "nonce": auth["nonce"], "mode": "baseline"})
                return {"outcome": COMMITTED, "origin_id": auth["origin_id"],
                        "actor_id": auth["actor_id"], "units": auth["units"],
                        "committed_total": total}
            # Treatment: atomic cumulative accounting against the ORIGIN,
            # never against actor identity.
            ok, total = self.ledger.try_consume(
                auth["origin_id"], auth["units"],
                mandates.origin_bound(auth["origin_id"]))
            if ok:
                self.ledger.record_entry(
                    {"outcome": COMMITTED, "origin_id": auth["origin_id"],
                     "actor_id": auth["actor_id"], "units": auth["units"],
                     "nonce": auth["nonce"], "mode": "treatment"})
                return {"outcome": COMMITTED, "origin_id": auth["origin_id"],
                        "actor_id": auth["actor_id"], "units": auth["units"],
                        "committed_total": total}
            # No partial rewrite: a refused request commits zero units.
            return self._refuse(
                auth, "ORIGIN_BOUND_EXCEEDED",
                "committed=%d requested=%d bound=%d"
                % (total, auth["units"],
                   mandates.origin_bound(auth["origin_id"])))
        except SimulatedFault:
            # Fail-closed reconciliation: ledger unchanged, operation abandoned,
            # no mutation retry permitted (same or fresh authorization).
            self.ledger.record_abandoned(
                {"intent_id": auth["intent_id"], "nonce": auth["nonce"],
                 "origin_id": auth["origin_id"], "actor_id": auth["actor_id"],
                 "units": auth["units"]})
            return {"outcome": UNCERTAIN_ABANDONED,
                    "origin_id": auth["origin_id"],
                    "actor_id": auth["actor_id"], "units": auth["units"],
                    "code": "FAIL_CLOSED_UNCERTAIN_EFFECT"}
