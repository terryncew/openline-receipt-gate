"""HOME-GUARD-001 frozen security tests (deterministic, stdlib unittest only).

These eight tests are the frozen test criteria for issue #110. They must not
be weakened to fit an implementation: Codex hardens against them as written.
Every test uses fixed keys (home_guard.keys) and a fixed clock, so results
are byte-reproducible.

Scope labels used in failure messages:
  SIM  - property of the offline simulator only.
  ENV  - infeasible in this environment (recorded, not asserted as real).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
REPO = EXP.parents[1]
if str(EXP) not in sys.path:
    sys.path.insert(0, str(EXP))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from home_guard import keys  # noqa: E402
from home_guard.receiver import FixedClock, HomeGuardReceiver, Mandate, Proposal  # noqa: E402
from home_guard.devices import DirectDeviceAPI, SimulatedDevice  # noqa: E402
from home_guard.net_policy import ContainmentLayer  # noqa: E402


def build_receiver() -> HomeGuardReceiver:
    r = HomeGuardReceiver(owner_pub=keys.public_key_hex_of("owner"),
                          clock=FixedClock())
    mandate = Mandate.issue(
        mandate_id="mandate-home-001",
        grantee_name="assistant",
        scope=[{"device": "kitchen-light", "action": "light.turn_on"}],
        issued_at=r.clock.now(),
        expires_at="2027-10-13T09:39:55-07:00",
    )
    r.admit_mandate(mandate.signed)
    return r


def build_devices(receiver_pub: str):
    devices = {
        "kitchen-light": SimulatedDevice("kitchen-light", "light"),
        "front-door-lock": SimulatedDevice("front-door-lock", "lock"),
    }
    return devices, DirectDeviceAPI(devices, receiver_pub)


def build_layer() -> ContainmentLayer:
    layer = ContainmentLayer(FixedClock())
    for dev_id, cls, comp in [
        ("tv", "display", True),
        ("nvr", "recorder", False),
        ("thermostat", "sensor", False),
        ("hvac-gateway", "gateway", False),
    ]:
        layer.register_device(dev_id, cls, compromised=comp)
    return layer


def proposal(device, action, params, nonce, mandate_id="mandate-home-001"):
    return Proposal(mandate_id, device, action, params, nonce, FixedClock().now())


class HomeGuardFrozenTests(unittest.TestCase):
    # -- Boundary 1: AI action authority ------------------------------------
    def test_01_allow_kitchen_light_executes_once_with_verifiable_receipt(self):
        r = build_receiver()
        devices, api = build_devices(r.public_key_hex)
        d = r.authorize(proposal("kitchen-light", "light.turn_on",
                                 {"brightness": 80}, "nonce-t01"))
        self.assertEqual(d["decision"], "ALLOW")
        ok, reason = r.verify_decision(d)
        self.assertTrue(ok, f"SIM receipt must verify independently: {reason}")
        applied, why = api.raw_call(d, "kitchen-light", "light.turn_on",
                                    {"brightness": 80}, "nonce-t01")
        self.assertTrue(applied, f"SIM authorized effect must apply: {why}")
        self.assertEqual(len(devices["kitchen-light"].effects), 1)
        # Exactly once: the same token cannot execute again.
        applied2, _ = api.raw_call(d, "kitchen-light", "light.turn_on",
                                   {"brightness": 80}, "nonce-t01")
        self.assertFalse(applied2)
        self.assertEqual(len(devices["kitchen-light"].effects), 1)

    def test_02_deny_front_door_unlock_zero_device_action(self):
        r = build_receiver()
        devices, api = build_devices(r.public_key_hex)
        d = r.authorize(proposal("front-door-lock", "lock.unlock", {}, "nonce-t02"))
        self.assertEqual(d["decision"], "DENY")
        self.assertEqual(d["reason_code"], "not_in_mandate_scope")
        applied, _ = api.raw_call(d, "front-door-lock", "lock.unlock", {}, "nonce-t02")
        self.assertFalse(applied)
        self.assertEqual(len(devices["front-door-lock"].effects), 0)
        self.assertTrue(devices["front-door-lock"].state["locked"])

    def test_03_revoke_rejects_reused_grant(self):
        r = build_receiver()
        devices, api = build_devices(r.public_key_hex)
        rev = r.revoke("mandate-home-001")
        self.assertEqual(rev["schema"], "openline.home_guard.revocation.v1")
        ok, reason = r.verify_decision(rev)
        self.assertTrue(ok, f"SIM revocation record must verify: {reason}")
        d = r.authorize(proposal("kitchen-light", "light.turn_on",
                                 {"brightness": 80}, "nonce-t03"))
        self.assertEqual(d["decision"], "DENY")
        self.assertEqual(d["reason_code"], "mandate_revoked")
        applied, _ = api.raw_call(d, "kitchen-light", "light.turn_on",
                                  {"brightness": 80}, "nonce-t03")
        self.assertFalse(applied)
        self.assertEqual(len(devices["kitchen-light"].effects), 0)

    def test_04_reject_stale_and_forged_requests(self):
        r = build_receiver()
        devices, api = build_devices(r.public_key_hex)
        # Stale: unknown mandate id.
        d = r.authorize(proposal("kitchen-light", "light.turn_on", {}, "nonce-t04a",
                                 mandate_id="mandate-nonexistent"))
        self.assertEqual((d["decision"], d["reason_code"]),
                         ("DENY", "unknown_mandate"))
        # Forged: attacker re-signs a decision-shaped body with its own key.
        from olp_gate.crypto import sign_olp_body
        forged = sign_olp_body(
            {"schema": "openline.home_guard.decision.v1", "decision": "ALLOW",
             "reason_code": "forged", "mandate_id": "mandate-home-001",
             "device": "front-door-lock", "action": "lock.unlock",
             "params_sha256": "00" * 32, "proposal_sha256": "00" * 32,
             "nonce": "nonce-t04b", "decided_at": FixedClock().now()},
            keys.private_key("attacker"),
        )
        applied, reason = api.raw_call(forged, "front-door-lock", "lock.unlock",
                                       {}, "nonce-t04b")
        self.assertFalse(applied, f"SIM forged token must not execute: {reason}")
        self.assertEqual(len(devices["front-door-lock"].effects), 0)
        # Tampered: flip one byte of a genuine receipt body.
        genuine = r.authorize(proposal("kitchen-light", "light.turn_on", {}, "nonce-t04c"))
        tampered = dict(genuine)
        tampered["device"] = "front-door-lock"
        applied2, reason2 = api.raw_call(tampered, "front-door-lock", "lock.unlock",
                                         {}, "nonce-t04c")
        self.assertFalse(applied2, f"SIM tampered receipt must not execute: {reason2}")

    # -- Boundary 2: device-to-device reachability ---------------------------
    def test_05_deny_tv_lateral_blocked_not_merely_logged(self):
        layer = build_layer()
        d = layer.attempt("tv", "nvr", session_id="tv")
        self.assertEqual(d["verdict"], "DENY")
        self.assertEqual(d["reason_code"], "device_quarantined")
        ok, reason = layer.verify_decision(d)
        self.assertTrue(ok, f"SIM net decision must verify: {reason}")
        # Blocked, not merely logged: no route entry exists in the layer.
        self.assertFalse(layer.route_exists("tv", "nvr"),
                         "SIM DENY must create no route entry")

    def test_06_bypass_ai_raw_credential_no_effect(self):
        r = build_receiver()
        devices, api = build_devices(r.public_key_hex)
        # (a) no credential at all
        a, ra = api.raw_call(None, "front-door-lock", "lock.unlock", {}, "nonce-b6a")
        # (b) attacker-signed token
        from olp_gate.crypto import sign_olp_body
        forged = sign_olp_body(
            {"schema": "openline.home_guard.decision.v1", "decision": "ALLOW",
             "reason_code": "x", "mandate_id": "mandate-home-001",
             "device": "front-door-lock", "action": "lock.unlock",
             "params_sha256": "00" * 32, "proposal_sha256": "00" * 32,
             "nonce": "nonce-b6b", "decided_at": FixedClock().now()},
            keys.private_key("attacker"),
        )
        b, rb = api.raw_call(forged, "front-door-lock", "lock.unlock", {}, "nonce-b6b")
        # (c) valid receiver token for a DIFFERENT action (binding check)
        genuine = r.authorize(proposal("kitchen-light", "light.turn_on", {}, "nonce-b6c"))
        c, rc = api.raw_call(genuine, "front-door-lock", "lock.unlock", {}, "nonce-b6c")
        # (d) replay of an already-executed token
        api.raw_call(genuine, "kitchen-light", "light.turn_on", {}, "nonce-b6c")
        d, rd = api.raw_call(genuine, "kitchen-light", "light.turn_on", {}, "nonce-b6c")
        for label, applied, reason in [("a", a, ra), ("b", b, rb),
                                       ("c", c, rc), ("d", d, rd)]:
            self.assertFalse(applied, f"SIM bypass {label} must fail: {reason}")
        self.assertEqual(len(devices["front-door-lock"].effects), 0)
        self.assertEqual(len(devices["kitchen-light"].effects), 1)  # only the (d) first call

    def test_07_bypass_tv_alternative_paths_explicit(self):
        layer = build_layer()
        # Alternate destination port: policy is port-agnostic -> DENY.
        p1 = layer.attempt("tv", "nvr", session_id="tv", dst_port=8080)
        self.assertEqual(p1["verdict"], "DENY")
        # Source spoofing: identity comes from the layer registry -> DENY.
        p2 = layer.attempt("tv", "nvr", session_id="tv", claimed_src="thermostat")
        self.assertEqual((p2["verdict"], p2["reason_code"]),
                         ("DENY", "identity_mismatch"))
        # Relay via another device: forwarding is not modeled -> OUT_OF_SCOPE,
        # explicitly recorded, never asserted as contained.
        p3 = layer.attempt("tv", "nvr", session_id="tv", via="thermostat")
        self.assertEqual((p3["verdict"], p3["reason_code"]),
                         ("OUT_OF_SCOPE", "forwarding_not_modeled"))
        # No alternative path created a route. If any had, this is FAIL.
        self.assertFalse(layer.route_exists("tv", "nvr"),
                         "SIM FAIL: an alternative path created a route")

    def test_08_overblocking_control_legitimate_connection_preserved(self):
        layer = build_layer()
        before = layer.attempt("thermostat", "hvac-gateway", session_id="thermostat")
        self.assertEqual(before["verdict"], "ALLOW")
        # Quarantine of tv must not disturb the control case.
        layer.attempt("tv", "nvr", session_id="tv")
        after = layer.attempt("thermostat", "hvac-gateway", session_id="thermostat")
        self.assertEqual(after["verdict"], "ALLOW")
        self.assertTrue(layer.route_exists("thermostat", "hvac-gateway"))
        # Overblocking measured in the supported scope: 0 of 1 control flows blocked.
        blocked = sum(1 for d in (before, after) if d["verdict"] != "ALLOW")
        self.assertEqual(blocked, 0)


if __name__ == "__main__":
    unittest.main()
