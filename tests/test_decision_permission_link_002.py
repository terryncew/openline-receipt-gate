from __future__ import annotations

from copy import deepcopy
import unittest

from olp_gate.authority_link import assess_permission, compile_link, compile_obligation
from benchmarks.decision_permission_link_002.capability_control import CapabilityLedger, assess_challenge, compile_challenge, mint_token
from benchmarks.decision_permission_link_002.scenario import H, NOW, POLICY, evidence_for, proposal

KEY = bytes.fromhex("71" * 32)


def norm(value: str) -> str:
    return "ALLOW" if value in {"COMMIT_ELIGIBLE", "ALLOW"} else "BLOCK"


class DPL002PermissionParityTests(unittest.TestCase):
    def compare(self, p, ev, *, state_hash=None, obligation=None, challenge=None):
        state = state_hash or p["state_hash"]
        if obligation is None:
            dpl = compile_link(POLICY, p, ev, now=NOW, current_state_hash=state)["assessment"]["decision"]
        else:
            dpl = assess_permission(POLICY, p, ev, now=NOW, current_state_hash=state, obligation=obligation)["decision"]
        if challenge is None:
            challenge = compile_challenge(POLICY, p)
        cap = assess_challenge(challenge, p, ev, now=NOW, current_state_hash=state)["decision"]
        self.assertEqual(norm(dpl), norm(cap))
        return dpl, cap

    def test_clean_tier1_allows_both(self):
        p = proposal(); dpl, cap = self.compare(p, evidence_for(p))
        self.assertEqual((dpl, cap), ("COMMIT_ELIGIBLE", "ALLOW"))

    def test_rationale_mutation_does_not_change_permission(self):
        a = proposal(advisory="rationale-a"); b = proposal(advisory="rationale-b")
        self.assertEqual(norm(self.compare(a, evidence_for(a))[0]), norm(self.compare(b, evidence_for(b))[0]))

    def test_model_swap_does_not_change_permission(self):
        a = proposal(producer="optimizer-A", model="model-A")
        b = proposal(producer="optimizer-B", model="model-B")
        self.assertEqual(norm(self.compare(a, evidence_for(a))[0]), norm(self.compare(b, evidence_for(b))[0]))

    def test_better_but_unauthorized_tier2_early_blocks_both(self):
        p = proposal(vendor="VENDOR-BETA", tier=2, advisory="avoid huge late fee")
        dpl, cap = self.compare(p, evidence_for(p, tier1=False))
        self.assertEqual((norm(dpl), norm(cap)), ("BLOCK", "BLOCK"))

    def test_self_granted_evidence_blocks_both(self):
        p = proposal(); dpl, cap = self.compare(p, evidence_for(p, self_granted=True))
        self.assertEqual((norm(dpl), norm(cap)), ("BLOCK", "BLOCK"))

    def test_stale_liquidity_blocks_both(self):
        p = proposal(); dpl, cap = self.compare(p, evidence_for(p, liquidity_age=61))
        self.assertEqual((norm(dpl), norm(cap)), ("BLOCK", "BLOCK"))

    def test_revoked_liquidity_blocks_both(self):
        p = proposal(); dpl, cap = self.compare(p, evidence_for(p, revoked_liquidity=True))
        self.assertEqual((norm(dpl), norm(cap)), ("BLOCK", "BLOCK"))

    def test_state_drift_blocks_both(self):
        p = proposal(state="s1")
        obligation = compile_obligation(POLICY, p)
        challenge = compile_challenge(POLICY, p)
        dpl, cap = self.compare(p, evidence_for(p), state_hash=H("s2"), obligation=obligation, challenge=challenge)
        self.assertEqual((norm(dpl), norm(cap)), ("BLOCK", "BLOCK"))

    def test_lower_ranked_authorized_net30_allows_both(self):
        p = proposal(vendor="VENDOR-BETA", tier=2, immediate=False, advisory="lower utility")
        dpl, cap = self.compare(p, evidence_for(p, tier1=False, liquidity=False))
        self.assertEqual((dpl, cap), ("COMMIT_ELIGIBLE", "ALLOW"))

    def test_capability_exact_action_hash_blocks_post_auth_mutation(self):
        p = proposal(); ev = evidence_for(p)
        c = compile_challenge(POLICY, p); a = assess_challenge(c, p, ev, now=NOW, current_state_hash=p["state_hash"])
        token = mint_token(c, a, receiver_key=KEY, now=NOW, nonce="ab"*32)
        mutated = deepcopy(p); mutated["settings"]["vendor_id"] = "VENDOR-EVIL"
        result = CapabilityLedger.empty().execute_once(token, mutated, receiver_key=KEY, current_state_hash=p["state_hash"], now=NOW)
        self.assertFalse(result["authorized"])
        self.assertIn("effect_hash_mismatch", result["reason_codes"])

    def test_capability_replay_blocks(self):
        p = proposal(); ev = evidence_for(p)
        c = compile_challenge(POLICY, p); a = assess_challenge(c, p, ev, now=NOW, current_state_hash=p["state_hash"])
        token = mint_token(c, a, receiver_key=KEY, now=NOW, nonce="cd"*32)
        ledger = CapabilityLedger.empty()
        self.assertTrue(ledger.execute_once(token, p, receiver_key=KEY, current_state_hash=p["state_hash"], now=NOW)["authorized"])
        replay = ledger.execute_once(token, p, receiver_key=KEY, current_state_hash=p["state_hash"], now=NOW)
        self.assertFalse(replay["authorized"])
        self.assertIn("token_replay", replay["reason_codes"])


if __name__ == "__main__":
    unittest.main()
