from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import public_key_hex
from olp_gate.field_tiers import (
    DEFAULT_PROJECTORS,
    FIELD_TIER_DEFINITION_PROFILE,
    FIELD_TIER_REQUEST_PROFILE,
    FieldTierAdmission,
    FieldTierError,
    admit_minimized_request,
    applied_tiers_hash,
    definition_hash,
    generate_definition_artifacts,
    generate_policy_schema,
    generate_wire_schema,
    issue_field_tier_receipt,
    minimize_parameters,
    normalize_definition,
    verify_field_tier_receipt,
)


GOLDEN_PARAMETERS = {
    "recipient": "Jane.Doe@Customer.COM",
    "subject": "patient 778812 discharge summary",
    "body_size_bytes": 2048,
    "attachment_hashes": ["a" * 64, "b" * 64],
    "internal_note": "never crosses",
}

GOLDEN_PARAMETER_HASH = "279b1741414065f1c9d24d6a34a1c3c4796c1318eb5f085fe41697b8bbbbabf4"
GOLDEN_DEFINITION_HASH = "403a7e1198a152cfe3a6f9f33135c61be93639df08ebeb44f9656f099b7b595e"
GOLDEN_TIERS_HASH = "70a3fda912a41a59c3c5c1d38fa8444f3c129991512c6f0f9327ebdad0485f0e"
ROOT = Path(__file__).resolve().parents[1]


def definition() -> dict:
    return {
        "profile": FIELD_TIER_DEFINITION_PROFILE,
        "definition_id": "send-email-disclosure",
        "version": "1",
        "action_type": "send_email",
        "fields": [
            {
                "field": "recipient",
                "tier": "derived",
                "type": "string",
                "optional": False,
                "projections": [
                    {
                        "attribute": "recipient_domain",
                        "projector": "recipient_domain/v1",
                        "type": "string",
                    }
                ],
            },
            {
                "field": "subject",
                "tier": "payload",
                "type": "string",
                "optional": False,
            },
            {
                "field": "body_size_bytes",
                "tier": "policy",
                "type": "integer",
                "optional": False,
                "attribute": "body_size_bytes",
            },
            {
                "field": "attachment_hashes",
                "tier": "derived",
                "type": "array",
                "optional": False,
                "projections": [
                    {
                        "attribute": "attachment_count",
                        "projector": "item_count/v1",
                        "type": "integer",
                    }
                ],
            },
        ],
    }


def retiered_definition() -> dict:
    value = definition()
    value["version"] = "2"
    for field in value["fields"]:
        if field["field"] == "subject":
            field.clear()
            field.update(
                {
                    "field": "subject",
                    "tier": "policy",
                    "type": "string",
                    "optional": False,
                    "attribute": "subject",
                }
            )
    return value


class FieldTierProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("44" * 32))
        self.trusted_key = public_key_hex(self.key)

    def request(self) -> dict:
        return minimize_parameters(GOLDEN_PARAMETERS, definition())

    def admission(self):
        return admit_minimized_request(
            self.request(), {"send_email": definition()}
        )

    def receipt(self) -> dict:
        return issue_field_tier_receipt(
            self.admission(),
            decision="COMMIT",
            receiver_decision_hash="11" * 32,
            policy_id="outbound-email-policy",
            issuer_id="openline-receiver",
            signing_key=self.key,
            now=datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
        )

    def test_golden_literals_pin_commitment_and_projection(self) -> None:
        request = self.request()
        self.assertEqual(
            request,
            {
                "profile": FIELD_TIER_REQUEST_PROFILE,
                "action_type": "send_email",
                "action_parameters_hash": GOLDEN_PARAMETER_HASH,
                "action_parameters_size_bytes": 293,
                "attributes": {
                    "attachment_count": 2,
                    "body_size_bytes": 2048,
                    "recipient_domain": "customer.com",
                },
                "applied_tiers_hash": GOLDEN_TIERS_HASH,
            },
        )
        self.assertEqual(definition_hash(definition()), GOLDEN_DEFINITION_HASH)
        self.assertEqual(applied_tiers_hash(definition()), GOLDEN_TIERS_HASH)

    def test_payload_unclassified_fields_and_identifiers_never_cross(self) -> None:
        serialized = json.dumps(self.request(), sort_keys=True)
        for forbidden in (
            "Jane.Doe",
            "patient 778812 discharge summary",
            "778812",
            "never crosses",
            "internal_note",
            "subject",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_hidden_parameter_change_changes_commitment(self) -> None:
        changed = dict(GOLDEN_PARAMETERS)
        changed["subject"] = "another hidden subject"
        before = self.request()
        after = minimize_parameters(changed, definition())
        self.assertNotEqual(
            before["action_parameters_hash"], after["action_parameters_hash"]
        )
        self.assertEqual(before["attributes"], after["attributes"])

    def test_reclassification_changes_disclosure_not_raw_commitment(self) -> None:
        original = self.request()
        changed = minimize_parameters(GOLDEN_PARAMETERS, retiered_definition())
        self.assertEqual(
            original["action_parameters_hash"], changed["action_parameters_hash"]
        )
        self.assertNotEqual(
            original["applied_tiers_hash"], changed["applied_tiers_hash"]
        )
        self.assertNotIn("subject", original["attributes"])
        self.assertEqual(
            changed["attributes"]["subject"], GOLDEN_PARAMETERS["subject"]
        )

    def test_one_definition_generates_three_consistent_artifacts(self) -> None:
        artifacts = generate_definition_artifacts(definition())
        self.assertEqual(artifacts["definition_hash"], GOLDEN_DEFINITION_HASH)
        self.assertEqual(artifacts["applied_tiers_hash"], GOLDEN_TIERS_HASH)
        self.assertEqual(
            artifacts["policy_schema"], generate_policy_schema(definition())
        )
        self.assertEqual(
            artifacts["wire_schema"], generate_wire_schema(definition())
        )
        self.assertEqual(
            set(artifacts["policy_schema"]["attributes"]),
            {"attachment_count", "body_size_bytes", "recipient_domain"},
        )

    def test_definition_rejects_unknown_keys_and_duplicate_attributes(self) -> None:
        unknown = definition()
        unknown["default_tier"] = "policy"
        with self.assertRaisesRegex(FieldTierError, "definition_shape_invalid"):
            normalize_definition(unknown)
        duplicate = definition()
        duplicate["fields"][0]["projections"][0]["attribute"] = "body_size_bytes"
        with self.assertRaisesRegex(FieldTierError, "definition_attribute_duplicate"):
            normalize_definition(duplicate)

    def test_definition_complexity_is_bounded(self) -> None:
        long_name = definition()
        long_name["definition_id"] = "d" * 129
        with self.assertRaisesRegex(FieldTierError, "definition_id_invalid"):
            normalize_definition(long_name)
        too_many = definition()
        too_many["fields"] = [
            {
                "field": f"field_{index}",
                "tier": "payload",
                "type": "string",
                "optional": True,
            }
            for index in range(129)
        ]
        with self.assertRaisesRegex(FieldTierError, "definition_fields_invalid"):
            normalize_definition(too_many)

    def test_unknown_projector_refuses_instead_of_approximating(self) -> None:
        value = definition()
        value["fields"][0]["projections"][0]["projector"] = "nearest-guess/v1"
        with self.assertRaisesRegex(FieldTierError, "projector_unavailable"):
            minimize_parameters(GOLDEN_PARAMETERS, value)

    def test_builtin_projectors_have_fail_closed_literal_outputs(self) -> None:
        self.assertEqual(
            DEFAULT_PROJECTORS["recipient_domain/v1"]("Nobody-At-Example"), ""
        )
        self.assertEqual(
            DEFAULT_PROJECTORS["endpoint_host/v1"]("API.Example.COM:443/v1/x"),
            "api.example.com",
        )
        self.assertEqual(DEFAULT_PROJECTORS["item_count/v1"](["a", "b"]), 2)

    def test_custom_projector_cannot_mutate_committed_input_or_leak_exception(self) -> None:
        value = definition()
        value["fields"][3]["projections"][0]["projector"] = "custom-count/v1"

        def mutating(items):
            items.append("attacker mutation")
            return len(items) - 1

        result = minimize_parameters(
            GOLDEN_PARAMETERS,
            value,
            projectors={
                "custom-count/v1": mutating,
                "recipient_domain/v1": lambda raw: raw.rsplit("@", 1)[-1].lower(),
            },
        )
        self.assertEqual(result["action_parameters_hash"], GOLDEN_PARAMETER_HASH)
        self.assertEqual(
            GOLDEN_PARAMETERS["attachment_hashes"], ["a" * 64, "b" * 64]
        )

        def exploding(_value):
            raise RuntimeError(GOLDEN_PARAMETERS["subject"])

        with self.assertRaisesRegex(
            FieldTierError, "projector_failed:custom-count/v1"
        ) as raised:
            minimize_parameters(
                GOLDEN_PARAMETERS,
                value,
                projectors={
                    "custom-count/v1": exploding,
                    "recipient_domain/v1": (
                        lambda raw: raw.rsplit("@", 1)[-1].lower()
                    ),
                },
            )
        self.assertNotIn(GOLDEN_PARAMETERS["subject"], str(raised.exception))

    def test_missing_required_parameter_fails_locally(self) -> None:
        parameters = dict(GOLDEN_PARAMETERS)
        parameters.pop("subject")
        with self.assertRaisesRegex(FieldTierError, "required_parameter_missing:subject"):
            minimize_parameters(parameters, definition())

    def test_receiver_rejects_client_supplied_definition(self) -> None:
        request = self.request()
        request["definition"] = definition()
        with self.assertRaisesRegex(FieldTierError, "minimized_request_shape_invalid"):
            admit_minimized_request(request, {"send_email": definition()})

    def test_receiver_rejects_stale_tier_view(self) -> None:
        request = self.request()
        request["applied_tiers_hash"] = "00" * 32
        with self.assertRaisesRegex(FieldTierError, "applied_tiers_mismatch"):
            admit_minimized_request(request, {"send_email": definition()})

    def test_receiver_rejects_unexpected_or_missing_attribute(self) -> None:
        unexpected = self.request()
        unexpected["attributes"]["subject"] = "leak"
        with self.assertRaisesRegex(FieldTierError, "minimized_attribute_unknown:subject"):
            admit_minimized_request(unexpected, {"send_email": definition()})
        missing = self.request()
        missing["attributes"].pop("recipient_domain")
        with self.assertRaisesRegex(
            FieldTierError, "minimized_attribute_missing:recipient_domain"
        ):
            admit_minimized_request(missing, {"send_email": definition()})

    def test_public_receipt_contains_commitments_without_values(self) -> None:
        receipt = self.receipt()
        serialized = json.dumps(receipt, sort_keys=True)
        self.assertEqual(receipt["action"]["parameters_hash"], GOLDEN_PARAMETER_HASH)
        self.assertFalse(receipt["disclosure"]["raw_parameters_stored"])
        self.assertFalse(receipt["disclosure"]["minimized_attributes_stored"])
        self.assertEqual(
            receipt["authority"],
            {
                "status": "EVIDENCE_ONLY",
                "portable_execution_authority": False,
            },
        )
        for forbidden in (
            "Jane.Doe",
            "customer.com",
            "patient 778812 discharge summary",
            "never crosses",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_receipt_issuer_revalidates_admission_hashes(self) -> None:
        admission = self.admission()
        forged = FieldTierAdmission(
            request=admission.request,
            definition=admission.definition,
            definition_hash=admission.definition_hash,
            attributes_hash="00" * 32,
        )
        with self.assertRaisesRegex(
            FieldTierError, "field_tier_admission_hash_mismatch"
        ):
            issue_field_tier_receipt(
                forged,
                decision="COMMIT",
                receiver_decision_hash="11" * 32,
                policy_id="outbound-email-policy",
                issuer_id="openline-receiver",
                signing_key=self.key,
            )

    def test_public_receipt_verifies_without_claiming_hidden_preimage(self) -> None:
        result = verify_field_tier_receipt(
            self.receipt(), [self.trusted_key]
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["public_integrity_valid"])
        self.assertEqual(result["candidate_parameters_status"], "NOT_PROVIDED")
        self.assertIsNone(result["candidate_parameters_match"])
        self.assertEqual(result["authority"], "EVIDENCE_ONLY")

    def test_candidate_parameter_preimage_can_be_checked_exactly(self) -> None:
        result = verify_field_tier_receipt(
            self.receipt(),
            [self.trusted_key],
            candidate_parameters=GOLDEN_PARAMETERS,
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["candidate_parameters_status"], "MATCH")
        self.assertTrue(result["candidate_parameters_match"])

    def test_wrong_candidate_does_not_match_receipt(self) -> None:
        candidate = dict(GOLDEN_PARAMETERS)
        candidate["subject"] = "wrong hidden subject"
        result = verify_field_tier_receipt(
            self.receipt(),
            [self.trusted_key],
            candidate_parameters=candidate,
        )
        self.assertFalse(result["valid"])
        self.assertTrue(result["public_integrity_valid"])
        self.assertEqual(result["candidate_parameters_status"], "MISMATCH")
        self.assertIn("candidate_parameters_hash_mismatch", result["candidate_errors"])

    def test_tamper_and_untrusted_signer_fail(self) -> None:
        tampered = copy.deepcopy(self.receipt())
        tampered["decision"]["value"] = "DENY"
        result = verify_field_tier_receipt(tampered, [self.trusted_key])
        self.assertFalse(result["valid"])
        self.assertIn("payload_hash_mismatch", result["errors"])
        untrusted = verify_field_tier_receipt(self.receipt(), ["00" * 32])
        self.assertFalse(untrusted["valid"])
        self.assertIn("gate_key_not_trusted", untrusted["errors"])

    def test_independent_node_verifier_matches_python_public_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "field-tier-receipt.json"
            path.write_text(
                json.dumps(self.receipt(), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "verify-field-tier-node.mjs"),
                    str(path),
                    "--gate-key",
                    self.trusted_key,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["valid"])
            self.assertEqual(result["authority"], "EVIDENCE_ONLY")

    def test_independent_node_verifier_rejects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "field-tier-receipt.json"
            receipt = self.receipt()
            receipt["decision"]["value"] = "DENY"
            path.write_text(
                json.dumps(receipt, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "verify-field-tier-node.mjs"),
                    str(path),
                    "--gate-key",
                    self.trusted_key,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertIn("payload_hash_mismatch", json.loads(completed.stdout)["errors"])

    def test_historical_receipt_survives_later_reclassification(self) -> None:
        historical = self.receipt()
        # A new definition exists, but no historical byte is rewritten.
        self.assertNotEqual(
            definition_hash(definition()), definition_hash(retiered_definition())
        )
        result = verify_field_tier_receipt(historical, [self.trusted_key])
        self.assertTrue(result["valid"])
        self.assertEqual(
            historical["disclosure"]["definition_hash"], GOLDEN_DEFINITION_HASH
        )

    def test_float_and_oversized_integer_refuse_canonical_commitment(self) -> None:
        floating = dict(GOLDEN_PARAMETERS)
        floating["body_size_bytes"] = 1.5
        with self.assertRaises(FieldTierError):
            minimize_parameters(floating, definition())
        oversized = dict(GOLDEN_PARAMETERS)
        oversized["body_size_bytes"] = (1 << 53) + 1
        with self.assertRaises(FieldTierError):
            minimize_parameters(oversized, definition())


if __name__ == "__main__":
    unittest.main()
