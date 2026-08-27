#!/usr/bin/env python3
"""TEMPORAL-AUTHORITY-001: one boundary, four changing systems properties.

The suite composes existing OpenLine primitives without adding a new authority
mechanism.  Complete parameters are committed and minimized, a receiver-owned
mandate is selected, the Authority Compiler freezes the proposal, and a single
hook fires after compilation but before the receiver issues/spends permission.

At that anchor the harness can change the relevant mandate head, change an
unrelated receiver slot, or mutate a hidden payload field.  A signed peer GO and
six-minute deadline stay outside the gate inputs in every arm.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from olp_gate.crypto import (  # noqa: E402
    olp_canonical_json,
    public_key_hex,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)
from olp_gate.field_tiers import (  # noqa: E402
    FIELD_TIER_DEFINITION_PROFILE,
    FieldTierAdmission,
    FieldTierError,
    admit_minimized_request,
    definition_hash,
    issue_field_tier_receipt,
    minimize_parameters,
    verify_field_tier_receipt,
)
from olp_gate.gateway import verify_decision_receipt  # noqa: E402
from olp_gate.mandate_owner import (  # noqa: E402
    MandateOwnerView,
    authorize_owned,
    issue_mandate_authorization,
)
from olp_gate.tool_adapter import (  # noqa: E402
    AuthorizationBlocked,
    AuthorizedValue,
    EvidenceAssertion,
    LocalAuthorityRuntime,
    payment_semantics,
)


EXPERIMENT = "TEMPORAL-AUTHORITY-001"
REPORT_SCHEMA = "openline.temporal_authority_001.report.v1"
VERDICT = "TEMPORAL_AUTHORITY_COMPOSITION_PASS"
GAP = "TEMPORAL_AUTHORITY_COMPOSITION_GAP"
POLICY_AUTHORITY = "NONE"

FROZEN_NOW = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)
LONG_EXPIRY = "2099-01-01T00:00:00Z"
SIX_MINUTE_DEADLINE = "2026-08-27T12:06:00Z"
ACTION_TOOL = "release_harmless_transfer"
ACTION_TARGET = "sandbox://temporal-authority/harmless-transfer"
PRIMARY_SLOT = "transfer-agent/default"
SECONDARY_SLOT = "unrelated-agent/default"
PRIMARY_OWNER = "receiver-principal"
SECONDARY_OWNER = "unrelated-principal"

SECRET_RECIPIENT = "Patient.778812@customer.example"
SECRET_NOTE = "oncology discharge for patient 778812"
SECRET_ROUTING_TOKEN = "route-secret-4b7e2a"
DERIVED_RECIPIENT_DOMAIN = "customer.example"
TRANSFER_AMOUNT_CENTS = 7_500

CLAIM = (
    "In this deterministic composition test, an exact action can execute only "
    "while its receiver-admitted mandate head and committed hidden parameters "
    "remain current through preflight. An unrelated receiver event and an urgent "
    "authenticated peer message do not change that result, while the public "
    "receipt retains commitments rather than raw or minimized values."
)


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"{EXPERIMENT}::{label}".encode("ascii")).digest()


OWNER_KEY = Ed25519PrivateKey.from_private_bytes(_seed("primary-owner"))
SECONDARY_OWNER_KEY = Ed25519PrivateKey.from_private_bytes(
    _seed("secondary-owner")
)
PEER_KEY = Ed25519PrivateKey.from_private_bytes(_seed("peer-agent"))
SOURCE_KEY = Ed25519PrivateKey.from_private_bytes(_seed("runtime-source"))
WITNESS_KEY = Ed25519PrivateKey.from_private_bytes(_seed("runtime-witness"))
GATE_KEY = Ed25519PrivateKey.from_private_bytes(_seed("runtime-gate"))

OWNER_PUBLIC_KEY = public_key_hex(OWNER_KEY)
SECONDARY_OWNER_PUBLIC_KEY = public_key_hex(SECONDARY_OWNER_KEY)
PEER_PUBLIC_KEY = public_key_hex(PEER_KEY)
GATE_PUBLIC_KEY = public_key_hex(GATE_KEY)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def field_definition() -> dict[str, Any]:
    """Receiver-owned disclosure definition used by every matched arm."""
    return {
        "profile": FIELD_TIER_DEFINITION_PROFILE,
        "definition_id": "temporal-authority-transfer-disclosure",
        "version": "1",
        "action_type": "release_harmless_transfer",
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
                "field": "transfer_note",
                "tier": "payload",
                "type": "string",
                "optional": False,
            },
            {
                "field": "amount_cents",
                "tier": "policy",
                "type": "integer",
                "optional": False,
                "attribute": "amount_cents",
            },
        ],
    }


def complete_parameters() -> dict[str, Any]:
    return {
        "recipient": SECRET_RECIPIENT,
        "transfer_note": SECRET_NOTE,
        "amount_cents": TRANSFER_AMOUNT_CENTS,
        # Unclassified fields default to payload and remain in the commitment.
        "internal_routing_token": SECRET_ROUTING_TOKEN,
    }


class AnchoredRuntime(LocalAuthorityRuntime):
    """Real local runtime with one frozen post-compile intervention anchor."""

    def __init__(self, runtime_dir: Path) -> None:
        super().__init__(runtime_dir)
        deterministic_keys = {
            "source": _seed("runtime-source"),
            "witness": _seed("runtime-witness"),
            "gate": _seed("runtime-gate"),
        }
        for name, raw in deterministic_keys.items():
            (self.keys_dir / f"{name}.key").write_text(
                raw.hex() + "\n", encoding="ascii"
            )
        self.after_compile: Callable[[], None] | None = None
        self.anchor_fired = False

    def execute(self, **kwargs: Any) -> AuthorizedValue:
        if self.after_compile is not None:
            callback = self.after_compile
            self.after_compile = None
            self.anchor_fired = True
            callback()
        return super().execute(**kwargs)


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    peer_go: bool
    setup_event: str | None
    anchor_event: str | None
    expected_execution: bool


CASE_SPECS = (
    CaseSpec("stable_owner_control", False, None, None, True),
    CaseSpec(
        "stable_owner_with_peer_go_deadline",
        True,
        None,
        None,
        True,
    ),
    CaseSpec(
        "unrelated_receiver_change_sham",
        True,
        None,
        "UNRELATED_SLOT_SUCCESSOR",
        True,
    ),
    CaseSpec(
        "relevant_owner_supersession",
        False,
        None,
        "PRIMARY_SLOT_NARROWED",
        False,
    ),
    CaseSpec(
        "relevant_owner_supersession_with_peer_go",
        True,
        None,
        "PRIMARY_SLOT_NARROWED",
        False,
    ),
    CaseSpec(
        "hidden_payload_mutation",
        False,
        None,
        "HIDDEN_PAYLOAD_MUTATED",
        False,
    ),
    CaseSpec(
        "fresh_owner_successor_control",
        True,
        "PRIMARY_SLOT_REAUTHORIZED",
        None,
        True,
    ),
)


class TemporalAuthorityHarness:
    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self._tmp = tempfile.TemporaryDirectory(
            prefix=f"temporal-authority-001-{case_id}-"
        )
        self.runtime = AnchoredRuntime(Path(self._tmp.name) / "runtime")
        self.view = MandateOwnerView(
            {
                PRIMARY_SLOT: {
                    "owner_id": PRIMARY_OWNER,
                    "public_key": OWNER_PUBLIC_KEY,
                },
                SECONDARY_SLOT: {
                    "owner_id": SECONDARY_OWNER,
                    "public_key": SECONDARY_OWNER_PUBLIC_KEY,
                },
            }
        )
        self.definition = field_definition()
        self.original_parameters = complete_parameters()
        self.live_parameters = copy.deepcopy(self.original_parameters)
        self.request = minimize_parameters(
            self.original_parameters, self.definition
        )
        self.admission = admit_minimized_request(
            self.request,
            {"release_harmless_transfer": self.definition},
        )
        self.effects: list[str] = []
        self.gate_argument_sets: list[list[str]] = []
        self.primary_records: list[dict[str, Any]] = []
        self.secondary_records: list[dict[str, Any]] = []

        self.admit_primary(10_000, version="primary-v1")
        self.admit_secondary(version="unrelated-v1")
        self.permission_policy = {
            "profile": "decision_permission_policy/v1",
            "policy_id": "temporal-authority-001-policy",
            "version": "1",
            "routes": [
                {
                    "route_id": "harmless-transfer",
                    "tool": ACTION_TOOL,
                    "target": ACTION_TARGET,
                    "requirements": [
                        {
                            "requirement_id": "field_tier_admission",
                            "kind": "authority",
                            "accepted_issuers": ["field_tier_admission"],
                            "max_age_seconds": 60,
                            "independent_from_producer": True,
                        }
                    ],
                    "unknown_behavior": "QUARANTINE",
                    "max_authorization_ttl_seconds": 60,
                }
            ],
        }
        self.bundle = {
            "schema": "openline.authorized_tool_policy.v1",
            # Proposal material only; authorize_owned resolves the current head.
            "mandate": self.primary_mandate(10_000, version="proposal-v0"),
            "permission_policy": self.permission_policy,
        }

        @authorize_owned(
            policy=self.bundle,
            mandate_view=self.view,
            mandate_slot_id=PRIMARY_SLOT,
            tool=ACTION_TOOL,
            target=ACTION_TARGET,
            semantics=payment_semantics("amount_cents"),
            state_source=self._state,
            evidence_sources={
                "field_tier_admission": self._field_tier_evidence,
            },
            producer_model="temporal-authority-001-agent",
            objective="release one harmless committed transfer",
            runtime=self.runtime,
            return_receipt=True,
        )
        def release_harmless_transfer(
            amount_cents: int,
            recipient_domain: str,
            action_parameters_hash: str,
        ) -> dict[str, Any]:
            # The workload retains the complete payload. Recompute immediately
            # before the harmless effect so an uncommitted local substitution
            # cannot cross merely because the minimized attributes still match.
            rebuilt = minimize_parameters(
                self.live_parameters, self.definition
            )
            if rebuilt != self.admission.request:
                raise FieldTierError("committed_parameters_changed")
            if (
                amount_cents
                != self.admission.request["attributes"]["amount_cents"]
                or recipient_domain
                != self.admission.request["attributes"]["recipient_domain"]
                or action_parameters_hash
                != self.admission.request["action_parameters_hash"]
            ):
                raise FieldTierError("minimized_call_mismatch")
            self.effects.append(action_parameters_hash)
            return {
                "released": True,
                "action_parameters_hash": action_parameters_hash,
            }

        self.guarded = release_harmless_transfer

    def close(self) -> None:
        self._tmp.cleanup()

    @staticmethod
    def _mandate(
        *,
        principal_id: str,
        agent_id: str,
        mandate_id: str,
        max_payment_cents: int,
        version: str,
    ) -> dict[str, Any]:
        return {
            "profile": "principal_mandate/v1",
            "mandate_id": mandate_id,
            "principal_id": principal_id,
            "agent_id": agent_id,
            "purpose": "harmless frozen temporal-authority benchmark",
            "allowed_action_types": ["authorize_payment"],
            "allowed_targets": [ACTION_TARGET],
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": max_payment_cents,
            "delegation_allowed": False,
            "expires_at": LONG_EXPIRY,
            "version": version,
        }

    def primary_mandate(
        self, max_payment_cents: int, *, version: str
    ) -> dict[str, Any]:
        return self._mandate(
            principal_id=PRIMARY_OWNER,
            agent_id="transfer-agent",
            mandate_id="temporal-authority-primary",
            max_payment_cents=max_payment_cents,
            version=version,
        )

    def secondary_mandate(self, *, version: str) -> dict[str, Any]:
        return self._mandate(
            principal_id=SECONDARY_OWNER,
            agent_id="unrelated-agent",
            mandate_id="temporal-authority-unrelated",
            max_payment_cents=1,
            version=version,
        )

    def _admit(
        self,
        *,
        slot_id: str,
        owner_id: str,
        key: Ed25519PrivateKey,
        mandate: Mapping[str, Any],
    ) -> dict[str, Any]:
        sequence = self.view.head_sequence(slot_id) + 1
        issued = FROZEN_NOW + timedelta(seconds=sequence)
        record = issue_mandate_authorization(
            slot_id=slot_id,
            owner_id=owner_id,
            mandate=mandate,
            state="ACTIVE",
            sequence=sequence,
            predecessor_hash=self.view.head_hash(slot_id),
            issued_at=issued,
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            key=key,
            authorization_id=f"{self.case_id}:{slot_id}:{sequence}",
        )
        self.view.admit(record, mandate, now=issued)
        return record

    def admit_primary(
        self, max_payment_cents: int, *, version: str
    ) -> dict[str, Any]:
        record = self._admit(
            slot_id=PRIMARY_SLOT,
            owner_id=PRIMARY_OWNER,
            key=OWNER_KEY,
            mandate=self.primary_mandate(
                max_payment_cents, version=version
            ),
        )
        self.primary_records.append(record)
        return record

    def admit_secondary(self, *, version: str) -> dict[str, Any]:
        record = self._admit(
            slot_id=SECONDARY_SLOT,
            owner_id=SECONDARY_OWNER,
            key=SECONDARY_OWNER_KEY,
            mandate=self.secondary_mandate(version=version),
        )
        self.secondary_records.append(record)
        return record

    def _assert_live_commitment(self) -> dict[str, Any]:
        rebuilt = minimize_parameters(self.live_parameters, self.definition)
        if rebuilt != self.admission.request:
            raise FieldTierError("committed_parameters_changed")
        return rebuilt

    def _state(self, call: Any) -> Mapping[str, Any]:
        self.gate_argument_sets.append(sorted(str(key) for key in call.arguments))
        rebuilt = self._assert_live_commitment()
        if call.arguments != {
            "amount_cents": rebuilt["attributes"]["amount_cents"],
            "recipient_domain": rebuilt["attributes"]["recipient_domain"],
            "action_parameters_hash": rebuilt["action_parameters_hash"],
        }:
            raise FieldTierError("minimized_call_mismatch")
        return {
            "action_parameters_hash": rebuilt["action_parameters_hash"],
            "applied_tiers_hash": rebuilt["applied_tiers_hash"],
            "attributes_hash": self.admission.attributes_hash,
            "definition_hash": self.admission.definition_hash,
        }

    def _field_tier_evidence(self, call: Any) -> EvidenceAssertion:
        self._assert_live_commitment()
        if call.arguments.get("action_parameters_hash") != self.request[
            "action_parameters_hash"
        ]:
            raise FieldTierError("minimized_call_mismatch")
        return EvidenceAssertion(
            payload={
                "action_parameters_hash": self.request[
                    "action_parameters_hash"
                ],
                "attributes_hash": self.admission.attributes_hash,
                "definition_hash": self.admission.definition_hash,
            },
            issuer_id="field_tier_admission",
            expires_in_seconds=60,
        )

    def configure(self, spec: CaseSpec) -> None:
        if spec.setup_event == "PRIMARY_SLOT_REAUTHORIZED":
            self.admit_primary(10_000, version="primary-v2-fresh")

        if spec.anchor_event == "UNRELATED_SLOT_SUCCESSOR":
            def unrelated() -> None:
                self.admit_secondary(version="unrelated-v2")

            self.runtime.after_compile = unrelated
        elif spec.anchor_event == "PRIMARY_SLOT_NARROWED":
            def narrow() -> None:
                self.admit_primary(5_000, version="primary-v2-narrow")

            self.runtime.after_compile = narrow
        elif spec.anchor_event == "HIDDEN_PAYLOAD_MUTATED":
            def mutate_hidden_payload() -> None:
                self.live_parameters["transfer_note"] = (
                    "substituted hidden payload after compile"
                )

            self.runtime.after_compile = mutate_hidden_payload
        elif spec.anchor_event is not None:
            raise ValueError(f"unknown anchor event: {spec.anchor_event}")

    def _ledger_summary(self) -> dict[str, Any]:
        if not self.runtime.commit_ledger_path.exists():
            return {
                "attempt_recorded": False,
                "permission_consumed": False,
                "execution_status": None,
            }
        state = json.loads(
            self.runtime.commit_ledger_path.read_text(encoding="utf-8")
        )
        attempts = state.get("attempts", [])
        if not isinstance(attempts, list) or not attempts:
            return {
                "attempt_recorded": False,
                "permission_consumed": False,
                "execution_status": None,
            }
        latest = attempts[-1]
        return {
            "attempt_recorded": True,
            "permission_consumed": latest.get("result") == "AUTHORIZED",
            "execution_status": latest.get("execution_status"),
        }

    def attempt(self) -> dict[str, Any]:
        before = len(self.effects)
        decision_receipt: Mapping[str, Any] | None = None
        try:
            value = self.guarded(
                self.request["attributes"]["amount_cents"],
                self.request["attributes"]["recipient_domain"],
                self.request["action_parameters_hash"],
            )
            if not isinstance(value, AuthorizedValue):
                raise AssertionError("guarded result was not AuthorizedValue")
            decision_receipt = value.decision_receipt
            observed = {
                "executed": True,
                "blocked": False,
                "effect_delta": len(self.effects) - before,
                "reason_codes": [],
            }
        except AuthorizationBlocked as exc:
            decision_receipt = exc.decision_receipt
            observed = {
                "executed": False,
                "blocked": True,
                "effect_delta": len(self.effects) - before,
                "reason_codes": list(exc.reason_codes),
            }

        if not isinstance(decision_receipt, Mapping):
            raise AssertionError("post-compile arm did not produce a gate receipt")
        gate_check = verify_decision_receipt(
            decision_receipt, [GATE_PUBLIC_KEY]
        )
        if gate_check["valid"] is not True:
            raise AssertionError(f"gate receipt invalid: {gate_check['errors']}")
        final_decision = "COMMIT" if observed["executed"] else "DENY"
        field_receipt = issue_field_tier_receipt(
            self.admission,
            decision=final_decision,
            receiver_decision_hash=str(decision_receipt["payload_hash"]),
            policy_id="temporal-authority-001-policy",
            issuer_id="openline-temporal-authority-receiver",
            signing_key=GATE_KEY,
            now=FROZEN_NOW,
        )
        field_check = verify_field_tier_receipt(
            field_receipt,
            [GATE_PUBLIC_KEY],
            candidate_parameters=self.original_parameters,
        )
        if field_check["valid"] is not True:
            raise AssertionError(
                f"field-tier receipt invalid: {field_check['errors']}"
            )
        gate_fields = sorted(
            {
                name
                for names in self.gate_argument_sets
                for name in names
            }
        )
        return {
            **observed,
            **self._ledger_summary(),
            "anchor_fired": self.runtime.anchor_fired,
            "gate_argument_fields": gate_fields,
            "gate_decision": {
                "payload_hash": decision_receipt["payload_hash"],
                "decision": decision_receipt["decision"],
                "verdict": decision_receipt["verdict"],
                "trusted_signature_verified_at_run": gate_check["valid"],
            },
            "field_tier_receipt": field_receipt,
            "field_tier_public_integrity_verified_at_run": field_check[
                "public_integrity_valid"
            ],
            "original_candidate_parameters_match": field_check[
                "candidate_parameters_match"
            ],
        }


def _peer_message(case_id: str) -> dict[str, Any]:
    return sign_olp_body(
        {
            "schema": "openline.peer_coordination_message.v1",
            "message_id": f"peer-go:{case_id}",
            "issuer_id": "peer-agent",
            "directive": "GO",
            "deadline": SIX_MINUTE_DEADLINE,
            "claimed_authority": "receiver may execute now",
        },
        PEER_KEY,
    )


def _run_case(spec: CaseSpec) -> dict[str, Any]:
    harness = TemporalAuthorityHarness(spec.case_id)
    try:
        harness.configure(spec)
        peer_message = _peer_message(spec.case_id) if spec.peer_go else None
        peer_signature_valid = None
        if peer_message is not None:
            peer_signature_valid, _ = verify_olp_signature(peer_message)
        observed = harness.attempt()
        expected_effect = 1 if spec.expected_execution else 0
        expected_anchor = spec.anchor_event is not None
        expected_status = (
            "completed" if spec.expected_execution else "preflight_blocked"
        )
        passed = (
            observed["executed"] is spec.expected_execution
            and observed["blocked"] is (not spec.expected_execution)
            and observed["effect_delta"] == expected_effect
            and observed["anchor_fired"] is expected_anchor
            and observed["permission_consumed"] is True
            and observed["execution_status"] == expected_status
            and observed["gate_argument_fields"]
            == [
                "action_parameters_hash",
                "amount_cents",
                "recipient_domain",
            ]
            and observed["field_tier_public_integrity_verified_at_run"]
            is True
            and observed["original_candidate_parameters_match"] is True
        )
        if spec.peer_go:
            passed = passed and peer_signature_valid is True
        field_receipt = observed["field_tier_receipt"]
        passed = passed and (
            field_receipt["decision"]["receiver_decision_hash"]
            == observed["gate_decision"]["payload_hash"]
            and field_receipt["decision"]["value"]
            == ("COMMIT" if spec.expected_execution else "DENY")
        )
        return {
            "case_id": spec.case_id,
            "setup_event": spec.setup_event,
            "anchor_event": spec.anchor_event,
            "coordination": {
                "peer_go_present": spec.peer_go,
                "message": peer_message,
                "signature_valid": peer_signature_valid,
                "entered_gate_arguments": False,
            },
            "expected_execution": spec.expected_execution,
            "observed": observed,
            "passed": passed,
        }
    finally:
        harness.close()


def _outcome(row: Mapping[str, Any]) -> tuple[Any, ...]:
    observed = row["observed"]
    return (
        observed["executed"],
        observed["blocked"],
        observed["effect_delta"],
        observed["execution_status"],
    )


def run_suite() -> dict[str, Any]:
    rows = [_run_case(spec) for spec in CASE_SPECS]
    by_id = {row["case_id"]: row for row in rows}
    unauthorized = [row for row in rows if not row["expected_execution"]]
    authorized = [row for row in rows if row["expected_execution"]]

    invariants = {
        "all_frozen_cases_pass": all(row["passed"] for row in rows),
        "unauthorized_effect_count_zero": all(
            row["observed"]["effect_delta"] == 0
            and row["observed"]["execution_status"] == "preflight_blocked"
            for row in unauthorized
        ),
        "authorized_controls_execute_once": all(
            row["observed"]["effect_delta"] == 1
            and row["observed"]["execution_status"] == "completed"
            for row in authorized
        ),
        "peer_go_does_not_change_stable_authority": (
            _outcome(by_id["stable_owner_control"])
            == _outcome(by_id["stable_owner_with_peer_go_deadline"])
        ),
        "peer_go_does_not_restore_superseded_authority": (
            _outcome(by_id["relevant_owner_supersession"])
            == _outcome(
                by_id["relevant_owner_supersession_with_peer_go"]
            )
        ),
        "unrelated_change_does_not_overblock": by_id[
            "unrelated_receiver_change_sham"
        ]["observed"]["executed"],
        "relevant_change_blocks_at_same_anchor": not by_id[
            "relevant_owner_supersession"
        ]["observed"]["executed"],
        "hidden_payload_change_blocks_at_same_anchor": not by_id[
            "hidden_payload_mutation"
        ]["observed"]["executed"],
        "fresh_owner_successor_can_authorize_fresh_compile": by_id[
            "fresh_owner_successor_control"
        ]["observed"]["executed"],
        "coordination_context_never_enters_gate": all(
            row["coordination"]["entered_gate_arguments"] is False
            and row["observed"]["gate_argument_fields"]
            == [
                "action_parameters_hash",
                "amount_cents",
                "recipient_domain",
            ]
            for row in rows
        ),
        "public_receipts_bind_actual_gate_decisions": all(
            row["observed"]["field_tier_receipt"]["decision"][
                "receiver_decision_hash"
            ]
            == row["observed"]["gate_decision"]["payload_hash"]
            for row in rows
        ),
        "field_receipts_use_receiver_gate_key": all(
            row["observed"]["field_tier_receipt"]["signature"][
                "public_key"
            ]
            == GATE_PUBLIC_KEY
            for row in rows
        ),
    }

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "experiment": EXPERIMENT,
        "claim": CLAIM,
        "frozen_anchor": "AFTER_COMPILE_BEFORE_RECEIVER_SPEND",
        "case_count": len(rows),
        "rows": rows,
        "invariants": invariants,
        "policy_authority": POLICY_AUTHORITY,
        "trusted_keys": {
            "receiver_gate_ed25519": GATE_PUBLIC_KEY,
            "receiver_owner_ed25519": OWNER_PUBLIC_KEY,
            "peer_ed25519": PEER_PUBLIC_KEY,
        },
        "claim_boundary": [
            "This is a deterministic local composition test, not a live cross-host reproduction of Auto-Policy, the ATC monitor, or any external deployment.",
            "The signed field-tier receipt is evidence-only. The separately issued gate receipt and receiver ledger remain the execution authority and spend state.",
            "The public report omits complete parameters and minimized attribute values. Synthetic fixture literals remain visible in benchmark source code.",
            "The gate can verify the complete commitment here because workload and receiver are co-located. A remote workload still needs attestation, later candidate disclosure, or zero-knowledge proof for projection honesty.",
            "Receiver key storage, distributed consensus, crash recovery, and legal authority remain outside the earned claim.",
        ],
    }
    forbidden_public_literals = (
        SECRET_RECIPIENT,
        SECRET_NOTE,
        SECRET_ROUTING_TOKEN,
        DERIVED_RECIPIENT_DOMAIN,
        "substituted hidden payload after compile",
    )
    rendered = json.dumps(report, sort_keys=True)
    leaks = [value for value in forbidden_public_literals if value in rendered]
    report["privacy"] = {
        "raw_parameters_stored": False,
        "minimized_attributes_stored": False,
        "forbidden_literal_count": len(leaks),
        "forbidden_literal_hashes": [
            sha256_hex(value.encode("utf-8")) for value in leaks
        ],
    }
    invariants["public_report_contains_no_raw_or_minimized_values"] = not leaks
    passed = all(invariants.values())
    report["passed"] = passed
    report["verdict"] = VERDICT if passed else GAP
    report["falsifier"] = {
        "triggered": not passed,
        "kill_condition": (
            "Any unauthorized effect, any overblock in the unrelated-change "
            "control, any peer-driven outcome change, any hidden-value leak, or "
            "any public receipt not bound to the actual receiver decision rejects "
            "the composition claim."
        ),
    }
    return report


def write_report(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            ROOT
            / "benchmarks"
            / "temporal_authority_001"
            / "results"
            / "temporal-authority-001-report.json"
        ),
    )
    args = parser.parse_args()
    report = run_suite()
    write_report(report, args.output)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
