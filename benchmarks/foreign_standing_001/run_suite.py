"""FOREIGN-STANDING-001: verified foreign evidence, source-neutral standing.

The benchmark deliberately composes existing OpenLine mechanisms:

* Microsoft ACS-style verdict + separately verifiable offline artifact
* AIREP v0.1 signed decision record
* source-specific integrity/authenticity verification
* source-erasing common support normalization
* the existing openline-claim-graph impact engine
* ReceiverStandingView + standing_requirement_source
* the existing Receipt Gate / AuthorityCompiler / Verified Commit execution path

The adapter is forbidden to decide standing. After normalization, the common
support object carries no source discriminator. The same graph and gate code run
unchanged for both source representations.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_claim_graph import (
    analyze_source_impact,
    build_source,
    create_claim,
    create_impact_policy,
    create_relation,
    create_snapshot,
    create_source_status_event,
    provenance_anchor,
)
from olp_gate.crypto import (
    jcs_integer_canonical_json,
    public_key_hex,
    sha256_hex,
    sign_olp_body,
)
from olp_gate.foreign_evidence import (
    ACS_TEST_ARTIFACT_SCHEMA,
    AIREP_INTEROP_PROFILE,
    ForeignEvidenceError,
    normalize_verified_evidence,
    verify_acs_offline_evidence,
    verify_airep_record,
    verify_normalized_support,
)
from olp_gate.standing import (
    ReceiverStandingView,
    STANDING_PROJECTION_SCHEMA,
    standing_action_hash,
    standing_action_hash_from_call,
    standing_requirement_source,
    support_receipt_hash,
)
from olp_gate.tool_adapter import (
    AuthorizationBlocked,
    AuthorizedValue,
    EvidenceAssertion,
    LocalAuthorityRuntime,
    authorize,
    payment_semantics,
)


VERDICT = "FOREIGN_GOVERNANCE_PROTOCOL_INDEPENDENCE"
FAIL = "FOREIGN_STANDING_PROTOCOL_INDEPENDENCE_NOT_ESTABLISHED"
POLICY_AUTHORITY = "NONE"
ACTOR = "foreign-standing-001:receiver"
GENESIS = "sha256:" + "0" * 64


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _common_semantics(action_hash: str) -> dict[str, Any]:
    return {
        "action_hash": action_hash,
        "evidence_key": "refund:C-1:7500:foreign-approval",
        "assertion": "The exact refund action passed the foreign governance evidence check.",
        "coverage": ["approval_basis", "exact_action_binding"],
        "policy_basis": ["refund-policy-v1"],
    }


def _make_acs_fixture(
    semantics: Mapping[str, Any],
    *,
    key: Ed25519PrivateKey,
    when: datetime,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    artifact = {"schema": ACS_TEST_ARTIFACT_SCHEMA, **dict(semantics)}
    raw = jcs_integer_canonical_json(artifact)
    digest = sha256_hex(raw)
    bundle = {
        "signature": key.sign(raw).hex(),
        "public_key": public_key_hex(key),
        "artifact_hash": digest,
        "timestamp": _iso(when),
        "signer_did": "did:example:acs-evidence-signer",
    }
    verdict = {
        "decision": "allow",
        "reason": "foreign-standing-001 fixture",
        "evidence": {
            "artefact": f"sha256:{digest}",
            "verification_pointers": {
                "issuer_pubkey": "https://example.invalid/acs-key.pem",
            },
        },
    }
    return verdict, artifact, bundle


def _airep_hash_body(record: Mapping[str, Any]) -> bytes:
    body = json.loads(json.dumps(record, sort_keys=True, separators=(",", ":")))
    body["integrity"].pop("current", None)
    body["integrity"].pop("signature", None)
    return jcs_integer_canonical_json(body)


def _make_airep_fixture(
    semantics: Mapping[str, Any],
    *,
    key: Ed25519PrivateKey,
    when: datetime,
    resolvable: bool = True,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "airep_version": "0.1",
        "subject": {
            "runtime": "foreign-standing-001",
            "producer": "airep-fixture-producer",
            "decision_index": 0,
            "timestamp_utc": _iso(when),
        },
        "input": {
            "input_ref": "urn:openline:foreign-standing-001:refund:C-1:7500",
            "governance_state": "policy:refund-policy-v1",
        },
        "claim": {
            "assertion": str(semantics["assertion"]),
            "basis": ["policy:refund-policy-v1"],
        },
        "output": {
            "result_ref": "urn:openline:foreign-standing-001:decision:release",
            "redacted": False,
        },
        "evidence": [
            {
                "type": "human_approval",
                "ref": "urn:approval:refund:C-1:7500",
                "resolvable": resolvable,
                "content_hash": "sha256:" + "1" * 64,
            }
        ],
        "directive": {
            "verb": "release",
            "policy_basis": ["refund-policy-v1"],
        },
        "scope": {
            "covers": list(semantics["coverage"]),
            "does_not_cover": ["future_actions", "unbound_recipients"],
        },
        "integrity": {
            "previous": GENESIS,
            "canonical_json": True,
        },
        "profiles": {
            AIREP_INTEROP_PROFILE: dict(semantics),
        },
    }
    current = "sha256:" + sha256_hex(_airep_hash_body(record))
    record["integrity"]["current"] = current
    record["integrity"]["signature"] = {
        "alg": "Ed25519",
        "value": key.sign(current.encode("utf-8")).hex(),
    }
    return record


def _quote_claim(source: Mapping[str, Any], text: str) -> dict[str, Any]:
    return create_claim(
        kind="SOURCE_ASSERTION",
        text=text,
        asserted_by=ACTOR,
        provenance=[provenance_anchor(source, text, mode="QUOTE", asserted_by=ACTOR)],
    )


def _unanchored(text: str, kind: str = "ASSUMPTION") -> dict[str, Any]:
    return create_claim(kind=kind, text=text, asserted_by=ACTOR)


def _edge(source: Mapping[str, Any], target: Mapping[str, Any], relation: str) -> dict[str, Any]:
    return create_relation(
        source_claim_id=source["claim_id"],
        target_claim_id=target["claim_id"],
        relation=relation,
        asserted_by=ACTOR,
    )


def _run_claim_graph(normalized_support: Mapping[str, Any]) -> dict[str, Any]:
    support_text = json.dumps(normalized_support, sort_keys=True, separators=(",", ":"))
    foreign_source = build_source(support_text, locator="openline:normalized-foreign-support")
    independent_text = "Independent receiver evidence still supports Decision B."
    independent_source = build_source(independent_text, locator="fixture:independent-support")
    notice_text = "Receiver-recognized revocation: the normalized foreign support loses standing."
    notice_source = build_source(notice_text, locator="fixture:foreign-support-revocation")

    foreign_claim = _quote_claim(foreign_source, support_text)
    independent_claim = _quote_claim(independent_source, independent_text)
    affected_decision = _unanchored("Finalize Decision A from the foreign support.")
    retained_decision = _unanchored("Finalize Decision B when at least one admitted support survives.")

    affected_edge = _edge(affected_decision, foreign_claim, "DEPENDS_ON")
    foreign_support_edge = _edge(foreign_claim, retained_decision, "SUPPORTS")
    independent_support_edge = _edge(independent_claim, retained_decision, "SUPPORTS")
    snapshot = create_snapshot(
        claims=[foreign_claim, independent_claim, affected_decision, retained_decision],
        relations=[affected_edge, foreign_support_edge, independent_support_edge],
    )
    sources = {
        item["source_id"]: item
        for item in (foreign_source, independent_source, notice_source)
    }
    event = create_source_status_event(
        status="REVOKED",
        affected=[{"source_id": foreign_source["source_id"]}],
        evidence=[provenance_anchor(notice_source, notice_text, mode="QUOTE", asserted_by=ACTOR)],
        asserted_by=ACTOR,
        effective_at="2026-08-25T19:00:00Z",
        reason="FOREIGN-STANDING-001 receiver-recognized standing revocation.",
    )
    policy = create_impact_policy(
        snapshot,
        hard_relation_ids=[
            affected_edge["relation_id"],
            foreign_support_edge["relation_id"],
            independent_support_edge["relation_id"],
        ],
        decision_claim_ids=[affected_decision["claim_id"], retained_decision["claim_id"]],
    )
    report = analyze_source_impact(snapshot, sources, event, policy)
    quarantine = {item["claim_id"] for item in report["classifications"]["quarantine"]}
    survives = {item["claim_id"] for item in report["classifications"]["survives"]}
    return {
        "report": report,
        "affected_decision_id": affected_decision["claim_id"],
        "retained_decision_id": retained_decision["claim_id"],
        "affected_disposition": "REOPEN" if affected_decision["claim_id"] in quarantine else "NOT_REOPENED",
        "retained_disposition": "RETAIN" if retained_decision["claim_id"] in survives else "NOT_RETAINED",
    }


class GateHarness:
    STANDING_ISSUER = "foreign-standing-001-projector"

    def __init__(
        self,
        *,
        normalized_support: Mapping[str, Any],
        normalization_public_key: str,
        action: tuple[int, str],
    ) -> None:
        self.action = action
        self.support = dict(normalized_support)
        self.normalization_public_key = normalization_public_key
        self.standing_key = Ed25519PrivateKey.generate()
        self.standing_view = ReceiverStandingView(
            {self.STANDING_ISSUER: public_key_hex(self.standing_key)}
        )
        self.projection: Mapping[str, Any] | None = None
        self.effects: list[tuple[int, str]] = []
        self._tmp = tempfile.TemporaryDirectory(prefix="foreign-standing-001-")
        self.runtime = LocalAuthorityRuntime(Path(self._tmp.name) / "runtime")

        now = _now()
        self.bundle = {
            "schema": "openline.authorized_tool_policy.v1",
            "mandate": {
                "profile": "principal_mandate/v1",
                "mandate_id": "foreign-standing-001-mandate",
                "principal_id": "interop-receiver",
                "agent_id": "foreign-agent",
                "purpose": "foreign evidence interoperability test",
                "allowed_action_types": ["authorize_payment"],
                "allowed_targets": ["refund://process"],
                "allowed_disclosure_classes": [],
                "forbidden_disclosure_classes": [],
                "max_settlement_cents": 0,
                "max_payment_cents": 100_000,
                "delegation_allowed": False,
                "expires_at": _iso(now + timedelta(days=1)),
                "version": "1",
            },
            "permission_policy": {
                "profile": "decision_permission_policy/v1",
                "policy_id": "foreign-standing-001-policy",
                "version": "1",
                "routes": [
                    {
                        "route_id": "refund",
                        "tool": "process_refund",
                        "target": "refund://process",
                        "requirements": [
                            {
                                "requirement_id": "foreign_authority",
                                "kind": "authority",
                                "accepted_issuers": ["foreign_verified"],
                                "max_age_seconds": 300,
                                "independent_from_producer": True,
                            },
                            {
                                "requirement_id": "foreign_standing",
                                "kind": "evidence",
                                "accepted_issuers": ["receiver_standing"],
                                "max_age_seconds": 300,
                                "independent_from_producer": True,
                            },
                        ],
                        "unknown_behavior": "QUARANTINE",
                        "max_authorization_ttl_seconds": 120,
                    }
                ],
            },
        }
        self.standing_source = standing_requirement_source(
            self.standing_view,
            support_source=self._support_source,
            projection_source=self._projection_source,
            action_hash_source=standing_action_hash_from_call,
            evidence_issuer_id="receiver_standing",
            max_assertion_ttl_seconds=60,
            now_source=_now,
        )

        @authorize(
            policy=self.bundle,
            tool="process_refund",
            target="refund://process",
            semantics=payment_semantics("amount_cents"),
            state_source=lambda call: {
                "customer_id": call.arguments["customer_id"],
                "foreign_support_hash": support_receipt_hash(self.support),
            },
            evidence_sources={
                "foreign_authority": self._foreign_authority,
                "foreign_standing": self.standing_source,
            },
            producer_model="foreign-standing-001-agent",
            runtime=self.runtime,
            return_receipt=True,
        )
        def process_refund(amount_cents: int, customer_id: str):
            self.effects.append((amount_cents, customer_id))
            return {"refunded_cents": amount_cents, "customer_id": customer_id}

        self.process_refund = process_refund

    def close(self) -> None:
        self._tmp.cleanup()

    def _support_source(self, call):
        if (call.arguments.get("amount_cents"), call.arguments.get("customer_id")) != self.action:
            return None
        return self.support

    def _projection_source(self, call):
        if (call.arguments.get("amount_cents"), call.arguments.get("customer_id")) != self.action:
            return None
        return self.projection

    def _foreign_authority(self, call):
        if (call.arguments.get("amount_cents"), call.arguments.get("customer_id")) != self.action:
            return None
        expected = standing_action_hash_from_call(call)
        try:
            verify_normalized_support(
                self.support,
                trusted_receiver_key=self.normalization_public_key,
                expected_action_hash=expected,
            )
        except ForeignEvidenceError:
            return None
        return EvidenceAssertion(
            payload={"normalized_support_hash": support_receipt_hash(self.support)},
            issuer_id="foreign_verified",
            expires_in_seconds=60,
        )

    def set_standing(self, standing: str, event_type: str) -> dict[str, Any]:
        support_hash = support_receipt_hash(self.support)
        action_hash = standing_action_hash(
            tool="process_refund",
            target="refund://process",
            arguments={"amount_cents": self.action[0], "customer_id": self.action[1]},
        )
        current = self.projection
        now = _now()
        projection = sign_olp_body(
            {
                "schema": STANDING_PROJECTION_SCHEMA,
                "projection_id": f"foreign-standing-001:{event_type.lower()}:{1 if current is None else int(current['sequence']) + 1}",
                "issuer_id": self.STANDING_ISSUER,
                "support_hash": support_hash,
                "action_hash": action_hash,
                "standing": standing,
                "event_type": event_type,
                "sequence": 1 if current is None else int(current["sequence"]) + 1,
                "predecessor_hash": self.standing_view.head_hash(support_hash, action_hash),
                "issued_at": _iso(now),
                "expires_at": _iso(now + timedelta(hours=1)),
            },
            self.standing_key,
        )
        self.standing_view.admit(projection, now=now)
        self.projection = projection
        return projection

    def attempt(self) -> dict[str, Any]:
        before = len(self.effects)
        try:
            result = self.process_refund(*self.action)
            assert isinstance(result, AuthorizedValue)
            return {
                "executed": True,
                "blocked": False,
                "effect_delta": len(self.effects) - before,
                "decision": result.decision_receipt.get("decision"),
                "verdict": result.decision_receipt.get("verdict"),
            }
        except AuthorizationBlocked as exc:
            return {
                "executed": False,
                "blocked": True,
                "effect_delta": len(self.effects) - before,
                "decision": exc.decision,
                "reason_codes": list(exc.reason_codes),
            }


def _negative_cases(
    *,
    semantics: Mapping[str, Any],
    acs_key: Ed25519PrivateKey,
    airep_key: Ed25519PrivateKey,
    when: datetime,
) -> dict[str, bool]:
    # ACS: the pointer and artifact signature are cryptographically good, but the
    # offline artifact does not carry the exact action binding required by the
    # normalizer/verifier. Authentic bytes are not sufficient evidence.
    incomplete = {
        "schema": ACS_TEST_ARTIFACT_SCHEMA,
        "evidence_key": semantics["evidence_key"],
        "assertion": semantics["assertion"],
        "coverage": semantics["coverage"],
        "policy_basis": semantics["policy_basis"],
    }
    raw = jcs_integer_canonical_json(incomplete)
    digest = sha256_hex(raw)
    acs_verdict = {"decision": "allow", "evidence": {"artefact": f"sha256:{digest}"}}
    acs_bundle = {
        "signature": acs_key.sign(raw).hex(),
        "public_key": public_key_hex(acs_key),
        "artifact_hash": digest,
        "timestamp": _iso(when),
        "signer_did": "did:example:acs",
    }
    acs_rejected = False
    try:
        verify_acs_offline_evidence(
            acs_verdict,
            incomplete,
            acs_bundle,
            trusted_public_key=public_key_hex(acs_key),
            now=when,
        )
    except ForeignEvidenceError:
        acs_rejected = True

    # AIREP: cryptographic integrity can be valid while all evidence is explicitly
    # non-resolvable. AIREP v0.1 says such pointers MUST NOT count as verified evidence.
    unresolved = _make_airep_fixture(semantics, key=airep_key, when=when, resolvable=False)
    airep_rejected = False
    try:
        verify_airep_record(
            unresolved,
            trusted_public_key=public_key_hex(airep_key),
            now=when,
        )
    except ForeignEvidenceError:
        airep_rejected = True
    return {
        "acs_authentic_but_semantically_unbound_rejected": acs_rejected,
        "airep_valid_but_unresolvable_evidence_rejected": airep_rejected,
    }


def run_suite() -> dict[str, Any]:
    when = datetime(2026, 8, 25, 19, 0, 0, tzinfo=timezone.utc)
    action = (7_500, "C-1")
    action_hash = standing_action_hash(
        tool="process_refund",
        target="refund://process",
        arguments={"amount_cents": action[0], "customer_id": action[1]},
    )
    semantics = _common_semantics(action_hash)

    acs_key = Ed25519PrivateKey.generate()
    airep_key = Ed25519PrivateKey.generate()
    receiver_key = Ed25519PrivateKey.generate()

    acs_verdict, acs_artifact, acs_bundle = _make_acs_fixture(semantics, key=acs_key, when=when)
    airep_record = _make_airep_fixture(semantics, key=airep_key, when=when)

    acs_verified = verify_acs_offline_evidence(
        acs_verdict,
        acs_artifact,
        acs_bundle,
        trusted_public_key=public_key_hex(acs_key),
        expected_action_hash=action_hash,
        now=when,
    )
    airep_verified = verify_airep_record(
        airep_record,
        trusted_public_key=public_key_hex(airep_key),
        expected_action_hash=action_hash,
        now=when,
    )

    normalized_acs = normalize_verified_evidence(acs_verified, receiver_key=receiver_key, normalized_at=when)
    normalized_airep = normalize_verified_evidence(airep_verified, receiver_key=receiver_key, normalized_at=when)
    acs_support = dict(normalized_acs.support_receipt)
    airep_support = dict(normalized_airep.support_receipt)
    normalization_equal = jcs_integer_canonical_json(acs_support) == jcs_integer_canonical_json(airep_support)
    no_source_discriminator = all(
        token not in json.dumps(acs_support, sort_keys=True).lower()
        for token in ("acs", "airep", "microsoft", "phionyx")
    )

    graph_acs = _run_claim_graph(acs_support)
    graph_airep = _run_claim_graph(airep_support)
    graph_same = (
        graph_acs["affected_disposition"] == graph_airep["affected_disposition"] == "REOPEN"
        and graph_acs["retained_disposition"] == graph_airep["retained_disposition"] == "RETAIN"
    )

    gate_results: dict[str, Any] = {}
    for label, support in (("ACS", acs_support), ("AIREP", airep_support)):
        h = GateHarness(
            normalized_support=support,
            normalization_public_key=public_key_hex(receiver_key),
            action=action,
        )
        try:
            h.set_standing("ACTIVE", "ADMIT")
            before = h.attempt()
            h.set_standing("INACTIVE", "REVOKE")
            after = h.attempt()
            gate_results[label] = {
                "before": before,
                "after": after,
                "passed": before["executed"] and after["blocked"] and after["effect_delta"] == 0,
            }
        finally:
            h.close()

    gate_same = (
        gate_results["ACS"]["passed"]
        and gate_results["AIREP"]["passed"]
        and gate_results["ACS"]["after"]["decision"] == gate_results["AIREP"]["after"]["decision"]
    )

    negatives = _negative_cases(
        semantics=semantics,
        acs_key=acs_key,
        airep_key=airep_key,
        when=when,
    )
    negative_pass = all(negatives.values())

    source_swap_pass = normalization_equal and no_source_discriminator and graph_same and gate_same
    passed = source_swap_pass and negative_pass

    return {
        "schema": "openline.foreign_standing_001.report.v1",
        "experiment": "FOREIGN-STANDING-001",
        "verdict": VERDICT if passed else FAIL,
        "passed": passed,
        "policy_authority": POLICY_AUTHORITY,
        "source_verification": {
            "acs": {
                "verified": True,
                "source_outcome": acs_verified.source_outcome,
                "artifact_hash": acs_verified.source_artifact_hash,
                "boundary": "ACS evidence pointer was not trusted by itself; the referenced artifact and pinned signature were verified separately.",
            },
            "airep": {
                "verified": True,
                "source_outcome": airep_verified.source_outcome,
                "artifact_hash": airep_verified.source_artifact_hash,
                "boundary": "AIREP core integrity plus pinned Ed25519 authorship and at least one resolvable evidence pointer were required.",
            },
        },
        "normalization": {
            "byte_identical_common_support": normalization_equal,
            "source_discriminator_absent": no_source_discriminator,
            "support_hash": support_receipt_hash(acs_support) if normalization_equal else None,
            "acs_verification_receipt_hash": support_receipt_hash(normalized_acs.verification_receipt),
            "airep_verification_receipt_hash": support_receipt_hash(normalized_airep.verification_receipt),
        },
        "same_openline_graph": {
            "acs": {
                "affected_finalized_decision": graph_acs["affected_disposition"],
                "independently_supported_decision": graph_acs["retained_disposition"],
            },
            "airep": {
                "affected_finalized_decision": graph_airep["affected_disposition"],
                "independently_supported_decision": graph_airep["retained_disposition"],
            },
            "same_result": graph_same,
        },
        "same_receipt_gate": {
            "acs": gate_results["ACS"],
            "airep": gate_results["AIREP"],
            "same_result": gate_same,
        },
        "source_swap_falsifier": {
            "rule": "After normalization, source identity must be unavailable to Claim Graph and Receipt Gate. Equivalent verified semantics must yield the same support bytes and the same downstream result.",
            "passed": source_swap_pass,
        },
        "authority_laundering_negatives": negatives,
        "claim_boundary": [
            "ACS does not define or validate the offline evidence payload used here. The ACS fixture uses the specification's opaque evidence pointer plus a separately verified AGT-style Ed25519 artifact signature.",
            "AIREP v0.1 is experimental, not a ratified standard. This benchmark verifies the integer/string subset needed by the fixture and does not replace AIREP's full published conformance kit.",
            "AIREP core does not define an OpenLine exact-action hash; the fixture carries that binding in a namespaced interop profile as permitted by AIREP v0.1.",
            "The adapters verify authenticity/integrity and translate representation only. They do not decide standing or mutate receiver policy.",
            "The source-specific verification receipts remain available for audit but are not presented to Claim Graph or Receipt Gate as standing inputs.",
            "Protocol independence is established only for these two verified representations and the frozen semantics exercised here; it is not universal-format compatibility.",
        ],
    }


def main() -> int:
    report = run_suite()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
