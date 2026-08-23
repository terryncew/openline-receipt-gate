from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import unittest

from olp_gate.authority_link import (
    AuthorityLinkError,
    EVIDENCE_PROFILE,
    POLICY_PROFILE,
    PROPOSAL_PROFILE,
    VERIFIED_COMMIT_SETTINGS_PROFILE,
    assess_permission,
    canonical_hash,
    compile_link,
    compile_obligation,
    compile_verified_commit_settings,
    effect_hash,
    policy_hash,
)

NOW = datetime(2026, 8, 23, 20, 0, tzinfo=timezone.utc)
H = lambda s: hashlib.sha256(s.encode()).hexdigest()


def policy():
    return {
        "profile": POLICY_PROFILE,
        "policy_id": "receiver.policy.payment",
        "version": "1",
        "routes": [{
            "route_id": "pay-vendor",
            "tool": "payments.transfer",
            "target": "vendor:acme",
            "requirements": [
                {
                    "requirement_id": "principal_mandate",
                    "kind": "authority",
                    "accepted_issuers": ["receiver-mandate"],
                    "max_age_seconds": 86400,
                    "independent_from_producer": True,
                },
                {
                    "requirement_id": "risk_check",
                    "kind": "evidence",
                    "accepted_issuers": ["risk-oracle"],
                    "max_age_seconds": 300,
                    "independent_from_producer": True,
                },
            ],
            "unknown_behavior": "QUARANTINE",
            "max_authorization_ttl_seconds": 60,
        }],
    }


def proposal(*, producer="optimizer-A", advisory="decision-A", amount=12500, state="state-1"):
    return {
        "profile": PROPOSAL_PROFILE,
        "proposal_id": f"proposal-{producer}-{advisory}",
        "producer_id": producer,
        "producer_model": producer,
        "objective": "pay approved invoice",
        "tool": "payments.transfer",
        "target": "vendor:acme",
        "settings": {"amount_cents": amount, "currency": "USD", "invoice_id": "INV-7"},
        "state_hash": H(state),
        "advisory_hash": H(advisory),
    }


def evidence_for(p, *, rid, kind, issuer, age=10, verified="VERIFIED", revoked=False, subject=None):
    from datetime import timedelta
    issued = NOW - timedelta(seconds=age)
    return {
        "profile": EVIDENCE_PROFILE,
        "requirement_id": rid,
        "kind": kind,
        "subject_hash": subject or effect_hash(p),
        "issuer_id": issuer,
        "issued_at": issued.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "artifact_hash": H(f"artifact:{rid}:{issuer}:{age}"),
        "verification_receipt_hash": H(f"verify:{rid}:{issuer}:{age}"),
        "receiver_verification_status": verified,
        "revoked": revoked,
    }


def full_evidence(p):
    return [
        evidence_for(p, rid="principal_mandate", kind="authority", issuer="receiver-mandate"),
        evidence_for(p, rid="risk_check", kind="evidence", issuer="risk-oracle"),
    ]


class AuthorityLinkTests(unittest.TestCase):
    def test_clean_path_is_commit_eligible_and_compiles_verified_commit_settings(self):
        p = proposal()
        linked = compile_link(policy(), p, full_evidence(p), now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(linked["assessment"]["decision"], "COMMIT_ELIGIBLE")
        self.assertEqual(linked["verified_commit_settings"]["profile"], VERIFIED_COMMIT_SETTINGS_PROFILE)
        self.assertEqual(linked["verified_commit_settings"]["effect_settings"]["amount_cents"], 12500)

    def test_optimizer_swap_does_not_change_permission_outcome(self):
        p1 = proposal(producer="optimizer-A", advisory="score-99")
        p2 = proposal(producer="optimizer-B", advisory="score-12")
        a1 = compile_link(policy(), p1, full_evidence(p1), now=NOW, current_state_hash=p1["state_hash"])
        a2 = compile_link(policy(), p2, full_evidence(p2), now=NOW, current_state_hash=p2["state_hash"])
        self.assertEqual(a1["assessment"]["decision"], "COMMIT_ELIGIBLE")
        self.assertEqual(a2["assessment"]["decision"], "COMMIT_ELIGIBLE")
        self.assertNotEqual(a1["assessment"]["proposal_hash"], a2["assessment"]["proposal_hash"])

    def test_missing_required_evidence_quarantines(self):
        p = proposal()
        ev = [evidence_for(p, rid="principal_mandate", kind="authority", issuer="receiver-mandate")]
        result = compile_link(policy(), p, ev, now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "QUARANTINE")
        self.assertIn("requirement_missing:risk_check", result["assessment"]["reason_codes"])

    def test_unverified_evidence_quarantines(self):
        p = proposal()
        ev = full_evidence(p)
        ev[1]["receiver_verification_status"] = "UNVERIFIED"
        result = compile_link(policy(), p, ev, now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "QUARANTINE")

    def test_stale_evidence_quarantines(self):
        p = proposal()
        ev = [
            evidence_for(p, rid="principal_mandate", kind="authority", issuer="receiver-mandate"),
            evidence_for(p, rid="risk_check", kind="evidence", issuer="risk-oracle", age=301),
        ]
        result = compile_link(policy(), p, ev, now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "QUARANTINE")
        self.assertIn("evidence_stale:risk_check", result["assessment"]["reason_codes"])

    def test_revoked_evidence_quarantines(self):
        p = proposal()
        ev = full_evidence(p)
        ev[1]["revoked"] = True
        result = compile_link(policy(), p, ev, now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "QUARANTINE")

    def test_wrong_subject_denies(self):
        p = proposal()
        ev = full_evidence(p)
        ev[1]["subject_hash"] = H("different-effect")
        result = compile_link(policy(), p, ev, now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "DENY")
        self.assertIn("subject_mismatch:risk_check", result["assessment"]["reason_codes"])

    def test_unaccepted_issuer_denies(self):
        p = proposal()
        ev = full_evidence(p)
        ev[1]["issuer_id"] = "optimizer-A"
        result = compile_link(policy(), p, ev, now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "DENY")

    def test_self_evidence_denies_even_when_producer_is_allowlisted(self):
        pol = policy()
        pol["routes"][0]["requirements"][1]["accepted_issuers"].append("optimizer-A")
        p = proposal()
        ev = full_evidence(p)
        ev[1]["issuer_id"] = "optimizer-A"
        result = compile_link(pol, p, ev, now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "DENY")
        self.assertIn("self_evidence_forbidden:risk_check", result["assessment"]["reason_codes"])

    def test_state_drift_denies_old_obligation(self):
        p = proposal()
        obligation = compile_obligation(policy(), p)
        result = assess_permission(
            policy(), p, full_evidence(p), now=NOW,
            current_state_hash=H("state-2"), obligation=obligation,
        )
        self.assertEqual(result["decision"], "DENY")
        self.assertIn("state_changed_since_proposal", result["reason_codes"])

    def test_policy_drift_denies_old_obligation(self):
        p = proposal()
        old_policy = policy()
        obligation = compile_obligation(old_policy, p)
        new_policy = deepcopy(old_policy)
        new_policy["version"] = "2"
        result = assess_permission(
            new_policy, p, full_evidence(p), now=NOW,
            current_state_hash=p["state_hash"], obligation=obligation,
        )
        self.assertEqual(result["decision"], "DENY")
        self.assertIn("policy_changed_since_obligation", result["reason_codes"])

    def test_action_mutation_denies_old_obligation(self):
        p = proposal()
        obligation = compile_obligation(policy(), p)
        mutated = deepcopy(p)
        mutated["settings"]["amount_cents"] = 999999
        result = assess_permission(
            policy(), mutated, full_evidence(mutated), now=NOW,
            current_state_hash=mutated["state_hash"], obligation=obligation,
        )
        self.assertEqual(result["decision"], "DENY")
        self.assertTrue(any("changed_since_obligation" in r for r in result["reason_codes"]))

    def test_unrouted_action_denies(self):
        p = proposal()
        p["target"] = "vendor:evil"
        result = compile_link(policy(), p, [], now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "DENY")
        self.assertIsNone(result["obligation"])

    def test_floats_forbidden_from_permission_settings(self):
        p = proposal()
        p["settings"]["amount"] = 12.5
        with self.assertRaisesRegex(AuthorityLinkError, "canonical_float_forbidden"):
            compile_obligation(policy(), p)

    def test_tampered_assessment_cannot_compile_settings(self):
        p = proposal()
        obligation = compile_obligation(policy(), p)
        assessment = assess_permission(
            policy(), p, full_evidence(p), now=NOW,
            current_state_hash=p["state_hash"], obligation=obligation,
        )
        tampered = dict(assessment)
        tampered["used_evidence_hashes"] = []
        with self.assertRaisesRegex(AuthorityLinkError, "assessment_hash_mismatch"):
            compile_verified_commit_settings(p, obligation, tampered)

    def test_advisory_hash_cannot_satisfy_missing_requirement(self):
        p = proposal(advisory="perfect-score")
        result = compile_link(policy(), p, [], now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(result["assessment"]["decision"], "QUARANTINE")
        self.assertEqual(len(result["assessment"]["used_evidence_hashes"]), 0)


if __name__ == "__main__":
    unittest.main()
