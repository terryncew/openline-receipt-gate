"""Post-freeze hardening tests: original eight cases are unchanged."""
from __future__ import annotations
import sys
import tempfile
from pathlib import Path
import unittest

EXP = Path(__file__).resolve().parents[1]
REPO = EXP.parents[1]
sys.path.insert(0, str(EXP))
sys.path.insert(0, str(REPO))

from home_guard import keys
from home_guard.receiver import HomeGuardReceiver, FixedClock, Mandate, Proposal
from home_guard.durable import DurableSafetyState
from home_guard.devices import SimulatedDevice, DirectDeviceAPI
from home_guard.net_policy import ContainmentLayer


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "guard.sqlite"

    def tearDown(self):
        self.temp.cleanup()

    def world(self, store):
        receiver = HomeGuardReceiver(keys.public_key_hex_of("owner"), FixedClock(),
                                     durable_state=store, require_authenticated_requester=True)
        mandate = Mandate.issue("hardening-001", "assistant",
                                [{"device": "kitchen-light", "action": "light.turn_on"}],
                                receiver.clock.now(), "2027-10-13T09:39:55-07:00")
        receiver.admit_mandate(mandate.signed)
        device = SimulatedDevice("kitchen-light", "light")
        api = DirectDeviceAPI({"kitchen-light": device}, receiver.public_key_hex,
                              durable_state=store, admitted_mandates=receiver.mandates)
        return receiver, device, api, mandate

    def test_missing_or_wrong_authenticated_requester_denied(self):
        store = DurableSafetyState(self.path)
        receiver, _, _, _ = self.world(store)
        for identity, expected in [(None, "requester_identity_missing"),
                                   (keys.public_key_hex_of("attacker"), "requester_identity_mismatch")]:
            p = Proposal("hardening-001", "kitchen-light", "light.turn_on", {},
                         "identity-" + str(identity), receiver.clock.now())
            d = receiver.authorize(p, authenticated_requester_pub=identity)
            self.assertEqual((d["decision"], d["reason_code"]), ("DENY", expected))
        store.close()

    def test_unused_allow_after_revocation_zero_effect(self):
        store = DurableSafetyState(self.path)
        receiver, device, api, _ = self.world(store)
        nonce = "unused-after-revoke"
        d = receiver.authorize(Proposal("hardening-001", "kitchen-light", "light.turn_on", {}, nonce,
                                        receiver.clock.now()),
                               authenticated_requester_pub=keys.public_key_hex_of("assistant"))
        self.assertEqual(d["decision"], "ALLOW")
        receiver.revoke("hardening-001")
        applied, reason = api.raw_call(d, "kitchen-light", "light.turn_on", {}, nonce)
        self.assertEqual((applied, reason), (False, "mandate_revoked"))
        self.assertEqual(device.effects, [])
        store.close()

    def test_restart_retains_revocation_and_prevents_readmission(self):
        store = DurableSafetyState(self.path)
        receiver, _, _, mandate = self.world(store)
        receiver.revoke("hardening-001")
        store.close()
        after = DurableSafetyState(self.path)
        r2 = HomeGuardReceiver(keys.public_key_hex_of("owner"), durable_state=after)
        with self.assertRaisesRegex(ValueError, "revoked"):
            r2.admit_mandate(mandate.signed)
        after.close()

    def test_restart_prevents_replay_of_spent_receipt(self):
        store = DurableSafetyState(self.path)
        receiver, device, api, mandate = self.world(store)
        nonce = "spent-one"
        d = receiver.authorize(Proposal("hardening-001", "kitchen-light", "light.turn_on", {}, nonce,
                                        receiver.clock.now()),
                               authenticated_requester_pub=keys.public_key_hex_of("assistant"))
        applied, _ = api.raw_call(d, "kitchen-light", "light.turn_on", {}, nonce)
        self.assertTrue(applied)
        self.assertEqual(len(device.effects), 1)
        store.close()
        after = DurableSafetyState(self.path)
        r2 = HomeGuardReceiver(keys.public_key_hex_of("owner"), durable_state=after,
                               require_authenticated_requester=True)
        r2.admit_mandate(mandate.signed)
        device2 = SimulatedDevice("kitchen-light", "light")
        api2 = DirectDeviceAPI({"kitchen-light": device2}, r2.public_key_hex,
                               durable_state=after, admitted_mandates=r2.mandates)
        applied2, why = api2.raw_call(d, "kitchen-light", "light.turn_on", {}, nonce)
        self.assertEqual((applied2, why), (False, "replay_rejected"))
        self.assertEqual(device2.effects, [])
        after.close()

    def test_source_identity_cannot_be_relabelled_using_session(self):
        layer = ContainmentLayer()
        for dev, kind, comp in (("tv", "display", True), ("thermostat", "sensor", False),
                                ("nvr", "recorder", False), ("hvac-gateway", "gateway", False)):
            layer.register_device(dev, kind, comp)
        bad = layer.attempt("tv", "hvac-gateway", session_id="thermostat")
        self.assertEqual((bad["verdict"], bad["reason_code"]), ("DENY", "identity_mismatch"))
        self.assertFalse(layer.route_exists("tv", "hvac-gateway"))
        control = layer.attempt("thermostat", "hvac-gateway", session_id="thermostat")
        self.assertEqual(control["verdict"], "ALLOW")

    def test_timezone_equivalent_expiry_rejected(self):
        r = HomeGuardReceiver(keys.public_key_hex_of("owner"))
        m = Mandate.issue("already-expired", "assistant",
                          [{"device": "kitchen-light", "action": "light.turn_on"}],
                          r.clock.now(), "2026-10-13T16:39:55Z")
        with self.assertRaisesRegex(ValueError, "expired"):
            r.admit_mandate(m.signed)

    def test_strict_mode_requires_registry_and_durable_state_together(self):
        st = DurableSafetyState(self.path)
        with self.assertRaisesRegex(ValueError, "registry"):
            DirectDeviceAPI({}, keys.public_key_hex_of("receiver"), durable_state=st)
        st.close()

if __name__ == "__main__":
    unittest.main()
