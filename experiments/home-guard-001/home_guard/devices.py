"""Simulated home devices and the receiver-controlled command route.

There is exactly one code path that can cause a device effect:
SimulatedDevice.apply() with a Receiver-signed ALLOW decision receipt bound
to the exact (device, action, params) triple and a fresh nonce.

DirectDeviceAPI models the device API surface the assistant can reach. It
holds the simulated "device credential" (the authority to route a command to
a device) and enforces the same receipt check on every call. Bypass attempts
(forged, missing, replayed, or wrong-action tokens) are rejected with zero
effect. This models the claim "the receiver controls the only credential and
command route" inside the simulation; it says nothing about real device
firmware, which is explicitly out of scope (see THREAT_MODEL.md).
"""
from __future__ import annotations

from typing import Any, Mapping

from olp_gate.crypto import verify_olp_signature
from olp_gate.receipts import sha256_json


class SimulatedDevice:
    def __init__(self, device_id: str, device_type: str):
        self.device_id = device_id
        self.device_type = device_type
        self.state: dict[str, Any] = {"power": "off", "locked": device_type == "lock"}
        self.effects: list[dict[str, Any]] = []  # the only observable effects
        self.executed_nonces: set[str] = set()

    def apply(
        self,
        decision: Mapping[str, Any],
        proposal: Mapping[str, Any],
        receiver_pub: str,
    ) -> tuple[bool, str]:
        """Apply the proposed action iff the decision receipt authorizes it.

        Returns (effect_applied, reason). Any failure -> (False, reason), zero
        state change.
        """
        ok, reason = verify_olp_signature(decision)
        if not ok:
            return False, f"bad_signature:{reason}"
        if decision.get("signature", {}).get("public_key") != receiver_pub:
            return False, "untrusted_signer"
        if decision.get("schema") != "openline.home_guard.decision.v1":
            return False, "wrong_schema"
        if decision.get("decision") != "ALLOW":
            return False, f"denied:{decision.get('reason_code')}"
        # Exact binding: the receipt must describe this exact proposed action.
        for field in ("device", "action", "nonce"):
            if decision.get(field) != proposal.get(field):
                return False, f"binding_mismatch:{field}"
        if decision.get("params_sha256") != sha256_json(proposal.get("params", {})):
            return False, "binding_mismatch:params"
        nonce = decision["nonce"]
        if nonce in self.executed_nonces:
            return False, "replay_rejected"
        # Effect.
        self._effect(proposal["action"], proposal.get("params", {}))
        self.executed_nonces.add(nonce)
        self.effects.append(
            {"device": self.device_id, "action": proposal["action"],
             "nonce": nonce}
        )
        return True, "effect_applied"

    def _effect(self, action: str, params: Mapping[str, Any]) -> None:
        if action == "light.turn_on":
            self.state["power"] = "on"
            self.state["brightness"] = params.get("brightness", 100)
        elif action == "light.turn_off":
            self.state["power"] = "off"
        elif action == "lock.unlock":
            self.state["locked"] = False
        elif action == "lock.lock":
            self.state["locked"] = True
        else:
            self.state[f"last_{action}"] = dict(params)


class DirectDeviceAPI:
    """The only command route to devices. Enforces the receipt check on raw calls.

    `raw_call(token, ...)` is the bypass surface: whatever the assistant (or an
    attacker holding the assistant's keys) presents must still pass the
    receiver-signed, exactly-bound, fresh-nonce check, or nothing happens.
    """

    def __init__(self, devices: dict[str, SimulatedDevice], receiver_pub: str):
        self.devices = devices
        self.receiver_pub = receiver_pub
        self.rejected_calls: list[dict[str, Any]] = []

    def raw_call(
        self,
        token: Mapping[str, Any] | None,
        device_id: str,
        action: str,
        params: Mapping[str, Any],
        nonce: str,
    ) -> tuple[bool, str]:
        proposal = {"device": device_id, "action": action,
                    "params": dict(params), "nonce": nonce}
        if token is None:
            self._log_reject(device_id, action, "missing_credential")
            return False, "missing_credential"
        device = self.devices.get(device_id)
        if device is None:
            self._log_reject(device_id, action, "unknown_device")
            return False, "unknown_device"
        applied, reason = device.apply(token, proposal, self.receiver_pub)
        if not applied:
            self._log_reject(device_id, action, reason)
        return applied, reason

    def _log_reject(self, device_id: str, action: str, reason: str) -> None:
        self.rejected_calls.append(
            {"device": device_id, "action": action, "reason": reason}
        )
