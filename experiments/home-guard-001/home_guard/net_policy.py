"""Boundary 2 — receiver-controlled network policy (deterministic simulator).

The ContainmentLayer is independent of the assistant: the agent is never
asked to obey. A connection attempt is evaluated against a frozen policy
table owned by the receiver. ALLOW creates a route entry; DENY creates
nothing. "Blocked, not merely logged" is proven by asserting the absence of
a route entry together with a signed DENY decision — there is no other way
for simulated traffic to flow in this model.

Alternative-path handling is explicit:
  * alternate destination ports are evaluated by the same port-agnostic rule
    (policy binds device identity, not ports);
  * source spoofing fails because identity comes from the layer's own
    registration registry, not from the caller's claimed name;
  * relay/forwarding (tv -> X -> nvr) is NOT modeled: the layer has no
    forwarding rules, so such attempts return OUT_OF_SCOPE
    ("forwarding_not_modeled") with no route. A real LAN may forward; that
    is an explicit, recorded limitation of the simulator, never a claim of
    real packet isolation.

Every network decision is signed by the receiver key, reusing the OLP
signing contract from olp_gate.crypto.
"""
from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import sign_olp_body, verify_olp_signature

from . import keys
from .receiver import FixedClock

NET_DECISION_SCHEMA = "openline.home_guard.net_decision.v1"


class ContainmentLayer:
    """Deterministic, receiver-owned network policy simulator."""

    # Frozen policy table: (src, dst) -> (verdict, reason_code).
    # "*" matches any. Evaluated in order; first match wins; default DENY.
    POLICY: tuple[tuple[str, str, str, str], ...] = (
        ("tv", "*", "DENY", "device_quarantined"),
        ("thermostat", "hvac-gateway", "ALLOW", "legitimate_telemetry"),
        ("*", "*", "DENY", "default_deny"),
    )

    def __init__(self, clock: FixedClock | None = None):
        self.clock = clock or FixedClock()
        self._key: Ed25519PrivateKey = keys.private_key("receiver")
        self.registry: dict[str, dict[str, Any]] = {}  # device_id -> identity record
        self.routes: set[tuple[str, str]] = set()      # admitted (src, dst) routes
        self.decisions: list[Mapping[str, Any]] = []

    @property
    def public_key_hex(self) -> str:
        return keys.public_key_hex_of("receiver")

    def register_device(self, device_id: str, device_class: str,
                        compromised: bool = False) -> None:
        self.registry[device_id] = {
            "device_id": device_id,
            "device_class": device_class,
            "compromised": compromised,
        }

    def _policy_lookup(self, src: str, dst: str) -> tuple[str, str]:
        for p_src, p_dst, verdict, reason in self.POLICY:
            if (p_src == "*" or p_src == src) and (p_dst == "*" or p_dst == dst):
                return verdict, reason
        return "DENY", "default_deny"

    def attempt(
        self,
        src_id: str,
        dst_id: str,
        *,
        session_id: str | None = None,
        claimed_src: str | None = None,
        dst_port: int | None = None,
        via: str | None = None,
    ) -> Mapping[str, Any]:
        """Evaluate one connection attempt.

        session_id: the layer-established identity of the caller (simulates an
            authenticated device identity). Spoofing is attempted by passing a
            claimed_src that differs from session_id.
        via: a relay device. Forwarding is not modeled -> OUT_OF_SCOPE.
        """
        if dst_id not in self.registry:
            verdict, reason = "DENY", "unknown_destination"
        elif via is not None:
            verdict, reason = "OUT_OF_SCOPE", "forwarding_not_modeled"
        else:
            caller = session_id if session_id is not None else src_id
            if caller not in self.registry:
                verdict, reason = "DENY", "unknown_source"
            elif claimed_src is not None and claimed_src != caller:
                verdict, reason = "DENY", "identity_mismatch"
            else:
                verdict, reason = self._policy_lookup(caller, dst_id)
                if verdict == "ALLOW" and self.registry[caller].get("compromised"):
                    # Defense in depth: a compromised device is quarantined
                    # regardless of any ALLOW rule naming it.
                    verdict, reason = "DENY", "device_quarantined"

        decision = sign_olp_body(
            {
                "schema": NET_DECISION_SCHEMA,
                "verdict": verdict,
                "reason_code": reason,
                "src": src_id,
                "dst": dst_id,
                "dst_port": dst_port,
                "via": via,
                "route_created": False,
                "decided_at": self.clock.now(),
            },
            self._key,
        )
        if verdict == "ALLOW":
            self.routes.add((src_id, dst_id))
            decision = dict(decision)  # re-sign with route_created=true
            body = {k: v for k, v in decision.items()
                    if k not in ("signature", "payload_hash")}
            body["route_created"] = True
            decision = sign_olp_body(body, self._key)
        self.decisions.append(decision)
        return decision

    def route_exists(self, src: str, dst: str) -> bool:
        return (src, dst) in self.routes

    def verify_decision(self, receipt: Mapping[str, Any]) -> tuple[bool, str | None]:
        ok, reason = verify_olp_signature(receipt)
        if not ok:
            return False, reason
        if receipt.get("signature", {}).get("public_key") != self.public_key_hex:
            return False, "untrusted_signer"
        return True, None
