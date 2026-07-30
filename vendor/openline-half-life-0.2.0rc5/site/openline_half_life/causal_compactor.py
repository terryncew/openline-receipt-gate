from __future__ import annotations

import base64
import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .evidence import build_evidence_index, evidence_is_fresh
from .handoff import _packet
from .receipts import (
    EXPECTED_BUNDLE_ARTIFACTS,
    RECEIPT_SCHEMA,
    SIGNED_OUTPUT_ARTIFACTS,
    ReceiptSigner,
    chain_digest,
    create_extension_receipt,
    verify_chain,
    verify_extension_chain,
)
from .reference_replay import reference_receipt_gate_projection
from .schema import validate_turn
from .util import (
    canonical_json,
    load_json,
    resolve_safe_relative_path,
    sha256_bytes,
    sha256_file,
    write_json,
)
from .vendor.openline_endurance_gate import succession as canonical

COMPACTION_POLICY_SCHEMA = "openline.half-life.compaction-policy.v1"
CAUSAL_CAPSULE_SCHEMA = "openline.half-life.causal-capsule.v1"
EQUIVALENCE_SCHEMA = "openline.half-life.decision-equivalence.v1"
ARCHIVE_MANIFEST_PAYLOAD_SCHEMA = "openline.half-life.archive-manifest.v1"
COMPACTION_PAYLOAD_SCHEMA = "openline.half-life.causal-compaction.v2"
RECEIVER_APPROVAL_SCHEMA = "openline.half-life.receiver-compaction-approval.v1"
PUBLIC_KEY_HEX = re.compile(r"^[0-9a-f]{64}$")
HASH256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9._:-]+$")
ALLOWED_DISPOSITIONS = {"COMMIT", "QUARANTINE", "DENY"}
RECEIVER_APPROVAL = "APPROVE"
DEFAULT_REHYDRATION_CONDITIONS = [
    "mechanism_weakened_or_overturned",
    "constraint_changed",
    "evidence_revoked",
    "compaction_policy_changed",
    "trusted_key_changed",
    "unresolved_contradiction_changed",
    "successor_decision_mismatch",
]
REQUIRED_KEEP_RULES = {
    "currently_supported_claims",
    "admitted_mechanisms_and_evidence_pointers",
    "live_constraints_and_commitments",
    "unresolved_questions_and_contradictions",
    "tombstones",
    "policy_and_trusted_key_versions",
    "checkpoint_and_source_chain_hashes",
    "rehydration_conditions",
}
REQUIRED_MERGE_RULES = {
    "exact_duplicates",
    "repeated_observations_represented_by_admitted_state",
    "superseded_versions",
    "settled_intermediate_steps_that_cannot_change_policy_decisions",
}
ALLOWED_CAUSAL_RELATIONS = {"causes", "mechanism"}


class CompactionError(ValueError):
    pass


@dataclass(frozen=True)
class CompactionInputs:
    source_bundle: Mapping[str, Any]
    compaction_policy: Mapping[str, Any]
    trusted_policy_keys: set[str]
    checkpoint: Mapping[str, Any]
    replay_latency_micros: int
    receiver_approval: Mapping[str, Any]
    output_dir: Path


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CompactionError(message)


def _unsigned_body(value: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(value)
    body.pop("payload_hash", None)
    body.pop("signature", None)
    return body


def build_compaction_policy_body(
    *,
    trusted_source_receipt_signer_keys_b64: Sequence[str],
    trusted_receiver_approval_public_keys: Sequence[str],
    active_receipt_bytes_budget: int,
    replay_latency_micros_budget: int,
    archive_destination: str = "cold_archive/receipts",
    policy_version: str = "0.1",
    trusted_key_version: str = "receiver-compaction-key-v1",
) -> dict[str, Any]:
    """Build an unsigned receiver policy.

    Budgets are receiver declarations. This function intentionally supplies no
    universal threshold and performs no fitting or scoring.
    """

    _require(
        isinstance(active_receipt_bytes_budget, int)
        and not isinstance(active_receipt_bytes_budget, bool)
        and active_receipt_bytes_budget > 0,
        "active receipt budget must be a positive integer",
    )
    _require(
        isinstance(replay_latency_micros_budget, int)
        and not isinstance(replay_latency_micros_budget, bool)
        and replay_latency_micros_budget > 0,
        "replay latency budget must be a positive integer",
    )
    _safe_archive_destination(archive_destination)
    _require(bool(trusted_source_receipt_signer_keys_b64), "source receipt signer trust set cannot be empty")
    _require(bool(trusted_receiver_approval_public_keys), "receiver approval trust set cannot be empty")
    _require(
        all(PUBLIC_KEY_HEX.fullmatch(key) is not None for key in trusted_receiver_approval_public_keys),
        "receiver approval keys must be 32-byte lowercase hex",
    )
    return {
        "schema": COMPACTION_POLICY_SCHEMA,
        "policy_version": policy_version,
        "trusted_key_version": trusted_key_version,
        "receiver_approval_required": True,
        "self_approval_forbidden": True,
        "automatic_compaction_authorized": False,
        "automatic_retirement_authorized": False,
        "trigger": {
            "active_receipt_bytes_budget": active_receipt_bytes_budget,
            "replay_latency_micros_budget": replay_latency_micros_budget,
            "rule": "propose_when_either_receiver_budget_is_crossed",
        },
        "archive": {
            "destination": archive_destination,
            "hash_algorithm": "sha256",
            "signed_manifest_required": True,
            "source_receipt_deletion_authorized": False,
        },
        "trusted_source_receipt_signer_keys_b64": sorted(set(trusted_source_receipt_signer_keys_b64)),
        "trusted_receiver_approval_public_keys": sorted(set(trusted_receiver_approval_public_keys)),
        "keep": sorted(REQUIRED_KEEP_RULES),
        "merge": sorted(REQUIRED_MERGE_RULES),
        "causal_admission": {
            "allowed_relation_kinds": sorted(ALLOWED_CAUSAL_RELATIONS),
            "explicit_admission_required": True,
            "fresh_evidence_required": True,
            "repetition_or_correlation_is_not_causation": True,
        },
        "receipt_gate_dispositions": sorted(ALLOWED_DISPOSITIONS),
        "decision_equivalence_required": True,
        "rehydration_conditions": list(DEFAULT_REHYDRATION_CONDITIONS),
        "claim_boundary": (
            "Receiver-owned compaction policy. It declares memory and latency budgets, "
            "does not create a health score, does not infer causation, does not authorize "
            "automatic retirement, and cannot approve its own compaction."
        ),
    }


def sign_compaction_policy(body: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    return canonical._sign_envelope(dict(body), key)


def build_receiver_approval_body(
    *,
    run_id: str,
    checkpoint_hash: str,
    source_chain: Sequence[Mapping[str, Any]],
    compaction_policy: Mapping[str, Any],
    disposition: str,
) -> dict[str, Any]:
    """Build a one-run approval that the receiver signs independently."""

    _require(bool(source_chain), "receiver approval requires a source chain")
    _require(disposition in {"APPROVE", "DENY"}, "invalid receiver disposition")
    return {
        "schema": RECEIVER_APPROVAL_SCHEMA,
        "run_id": run_id,
        "checkpoint_hash": checkpoint_hash,
        "source_chain_count": len(source_chain),
        "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
        "source_chain_digest": chain_digest(list(source_chain)),
        "compaction_policy_hash": compaction_policy["payload_hash"],
        "archive_destination": compaction_policy["archive"]["destination"],
        "disposition": disposition,
        "automatic_compaction_authorized": False,
        "automatic_retirement_authorized": False,
    }


def sign_receiver_approval(
    body: Mapping[str, Any],
    key: Ed25519PrivateKey,
) -> dict[str, Any]:
    return canonical._sign_envelope(dict(body), key)


def verify_receiver_approval(
    approval: Mapping[str, Any],
    *,
    source_chain: Sequence[Mapping[str, Any]],
    checkpoint: Mapping[str, Any],
    compaction_policy: Mapping[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []
    expected_keys = set(compaction_policy.get("trusted_receiver_approval_public_keys", []))
    if approval.get("schema") != RECEIVER_APPROVAL_SCHEMA:
        reasons.append("receiver_approval_schema_mismatch")
    if not canonical._verify_envelope(approval):
        reasons.append("receiver_approval_signature_or_payload_hash_invalid")
    elif not expected_keys or not canonical._verify_envelope(approval, expected_keys):
        reasons.append("receiver_approval_signer_not_trusted")

    expected_fields = {
        "schema",
        "run_id",
        "checkpoint_hash",
        "source_chain_count",
        "source_chain_tail_hash",
        "source_chain_digest",
        "compaction_policy_hash",
        "archive_destination",
        "disposition",
        "automatic_compaction_authorized",
        "automatic_retirement_authorized",
    }
    body = _unsigned_body(approval)
    if set(body) != expected_fields:
        reasons.append("receiver_approval_field_mismatch")
    if not source_chain:
        reasons.append("receiver_approval_source_chain_missing")
    else:
        try:
            expected = {
                "run_id": checkpoint.get("run_id"),
                "checkpoint_hash": checkpoint.get("packet_hash"),
                "source_chain_count": len(source_chain),
                "source_chain_tail_hash": source_chain[-1].get("receipt_hash"),
                "source_chain_digest": chain_digest(list(source_chain)),
                "compaction_policy_hash": compaction_policy.get("payload_hash"),
                "archive_destination": compaction_policy.get("archive", {}).get("destination"),
            }
            for field, value in expected.items():
                if approval.get(field) != value:
                    reasons.append(f"receiver_approval_binding_mismatch:{field}")
            source_key_hex = base64.b64decode(
                str(source_chain[0].get("signer_public_key", "")), validate=True
            ).hex()
            if approval.get("signature", {}).get("public_key") == source_key_hex:
                reasons.append("receiver_self_approval_forbidden")
        except Exception:
            reasons.append("receiver_approval_binding_inputs_invalid")
    if approval.get("disposition") != RECEIVER_APPROVAL:
        reasons.append("receiver_approval_missing")
    if approval.get("automatic_compaction_authorized") is not False:
        reasons.append("receiver_approval_cannot_authorize_automatic_compaction")
    if approval.get("automatic_retirement_authorized") is not False:
        reasons.append("receiver_approval_cannot_authorize_automatic_retirement")
    return {
        "valid": not reasons,
        "reason_codes": reasons,
        "approval_hash": approval.get("payload_hash"),
        "public_key": approval.get("signature", {}).get("public_key"),
        "disposition": approval.get("disposition"),
    }


def verify_compaction_policy(
    policy: Mapping[str, Any],
    expected_public_keys: set[str] | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not expected_public_keys:
        reasons.append("trusted_compaction_policy_key_required")
    elif any(PUBLIC_KEY_HEX.fullmatch(key) is None for key in expected_public_keys):
        reasons.append("trusted_compaction_policy_key_invalid")
    if policy.get("schema") != COMPACTION_POLICY_SCHEMA:
        reasons.append("unsupported_compaction_policy_schema")
    if not canonical._verify_envelope(policy):
        reasons.append("compaction_policy_signature_or_payload_hash_invalid")
    elif expected_public_keys and not canonical._verify_envelope(policy, expected_public_keys):
        reasons.append("compaction_policy_signer_not_trusted")

    try:
        body = _unsigned_body(policy)
        required = {
            "schema",
            "policy_version",
            "trusted_key_version",
            "receiver_approval_required",
            "self_approval_forbidden",
            "automatic_compaction_authorized",
            "automatic_retirement_authorized",
            "trigger",
            "archive",
            "trusted_source_receipt_signer_keys_b64",
            "trusted_receiver_approval_public_keys",
            "keep",
            "merge",
            "causal_admission",
            "receipt_gate_dispositions",
            "decision_equivalence_required",
            "rehydration_conditions",
            "claim_boundary",
        }
        if set(body) != required:
            reasons.append("compaction_policy_field_mismatch")
        trigger = body["trigger"]
        if set(trigger) != {
            "active_receipt_bytes_budget",
            "replay_latency_micros_budget",
            "rule",
        }:
            reasons.append("compaction_trigger_field_mismatch")
        for name in ("active_receipt_bytes_budget", "replay_latency_micros_budget"):
            value = trigger[name]
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                reasons.append(f"invalid_{name}")
        if trigger.get("rule") != "propose_when_either_receiver_budget_is_crossed":
            reasons.append("compaction_trigger_rule_changed")
        archive = body["archive"]
        if set(archive) != {
            "destination",
            "hash_algorithm",
            "signed_manifest_required",
            "source_receipt_deletion_authorized",
        }:
            reasons.append("archive_policy_field_mismatch")
        _safe_archive_destination(archive["destination"])
        if archive.get("hash_algorithm") != "sha256":
            reasons.append("archive_hash_algorithm_changed")
        if archive.get("signed_manifest_required") is not True:
            reasons.append("signed_archive_manifest_required")
        if archive.get("source_receipt_deletion_authorized") is not False:
            reasons.append("source_receipt_deletion_must_remain_forbidden")
        if body.get("receiver_approval_required") is not True:
            reasons.append("receiver_approval_required")
        if body.get("self_approval_forbidden") is not True:
            reasons.append("self_approval_must_remain_forbidden")
        if body.get("automatic_compaction_authorized") is not False:
            reasons.append("automatic_compaction_must_remain_forbidden")
        if body.get("automatic_retirement_authorized") is not False:
            reasons.append("automatic_retirement_must_remain_forbidden")
        source_keys = body.get("trusted_source_receipt_signer_keys_b64")
        if not isinstance(source_keys, list) or not source_keys or not all(isinstance(item, str) and item for item in source_keys):
            reasons.append("trusted_source_receipt_signer_required")
        else:
            for key in source_keys:
                try:
                    if len(base64.b64decode(key, validate=True)) != 32:
                        raise ValueError
                except Exception:
                    reasons.append("trusted_source_receipt_signer_invalid")
                    break
        approval_keys = body.get("trusted_receiver_approval_public_keys")
        if (
            not isinstance(approval_keys, list)
            or not approval_keys
            or not all(isinstance(item, str) and PUBLIC_KEY_HEX.fullmatch(item) is not None for item in approval_keys)
        ):
            reasons.append("trusted_receiver_approval_signer_required")
        if set(body.get("keep", [])) != REQUIRED_KEEP_RULES:
            reasons.append("compaction_keep_rules_changed")
        if set(body.get("merge", [])) != REQUIRED_MERGE_RULES:
            reasons.append("compaction_merge_rules_changed")
        admission = body["causal_admission"]
        if set(admission) != {
            "allowed_relation_kinds",
            "explicit_admission_required",
            "fresh_evidence_required",
            "repetition_or_correlation_is_not_causation",
        }:
            reasons.append("causal_admission_field_mismatch")
        if set(admission.get("allowed_relation_kinds", [])) != ALLOWED_CAUSAL_RELATIONS:
            reasons.append("causal_relation_kinds_changed")
        if admission.get("explicit_admission_required") is not True:
            reasons.append("explicit_causal_admission_required")
        if admission.get("fresh_evidence_required") is not True:
            reasons.append("fresh_causal_evidence_required")
        if admission.get("repetition_or_correlation_is_not_causation") is not True:
            reasons.append("correlation_causation_boundary_changed")
        if set(body.get("receipt_gate_dispositions", [])) != ALLOWED_DISPOSITIONS:
            reasons.append("receipt_gate_disposition_set_changed")
        if body.get("decision_equivalence_required") is not True:
            reasons.append("decision_equivalence_required")
        if set(body.get("rehydration_conditions", [])) != set(DEFAULT_REHYDRATION_CONDITIONS):
            reasons.append("rehydration_conditions_changed")
        if not isinstance(body.get("policy_version"), str) or SAFE_VERSION.fullmatch(body["policy_version"]) is None:
            reasons.append("invalid_compaction_policy_version")
        if not isinstance(body.get("trusted_key_version"), str) or SAFE_VERSION.fullmatch(body["trusted_key_version"]) is None:
            reasons.append("invalid_trusted_key_version")
    except (KeyError, TypeError, CompactionError):
        reasons.append("invalid_compaction_policy_semantics")
    return {
        "valid": not reasons,
        "reason_codes": reasons,
        "policy_hash": policy.get("payload_hash"),
        "public_key": policy.get("signature", {}).get("public_key"),
    }


def load_trusted_compaction_policy_keys(path: Path) -> set[str]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except UnicodeError as exc:
        raise CompactionError("trusted compaction policy key file must be lowercase ASCII hex") from exc
    keys = {line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")}
    if not keys:
        raise CompactionError("trusted compaction policy key file contains no keys")
    if any(PUBLIC_KEY_HEX.fullmatch(key) is None for key in keys):
        raise CompactionError("trusted compaction policy keys must be 32-byte lowercase hex")
    return keys


def _safe_archive_destination(value: Any) -> str:
    _require(isinstance(value, str) and value, "archive destination must be non-empty")
    path = PurePosixPath(value)
    _require(not path.is_absolute(), "archive destination must be relative")
    _require(".." not in path.parts, "archive destination cannot escape the output directory")
    _require(path.parts and all(part not in {"", "."} for part in path.parts), "invalid archive destination")
    return value


def _checkpoint_body(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(checkpoint)
    body.pop("packet_hash", None)
    return body


def _capsule_body(capsule: Mapping[str, Any]) -> dict[str, Any]:
    body = copy.deepcopy(dict(capsule))
    body.pop("capsule_hash", None)
    return body


def verify_checkpoint(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if checkpoint.get("schema") not in {
        "openline.half-life.verified-residue-handoff.v1",
        "openline.half-life.verified-residue-handoff.v2",
    }:
        errors.append("unsupported_checkpoint_schema")
    packet_hash = checkpoint.get("packet_hash")
    computed = sha256_bytes(canonical_json(_checkpoint_body(checkpoint)))
    if packet_hash != computed:
        errors.append("checkpoint_packet_hash_mismatch")
    if checkpoint.get("handoff_type") != "verified_residue":
        errors.append("checkpoint_is_not_verified_residue")
    if checkpoint.get("automatic_retirement_authorized") is True:
        errors.append("checkpoint_automatic_retirement_forbidden")
    return {"valid": not errors, "errors": errors, "packet_hash": packet_hash}


def active_receipt_size_bytes(chain: Sequence[Mapping[str, Any]]) -> int:
    return len(canonical_json(list(chain)))


def evaluate_pressure(
    chain: Sequence[Mapping[str, Any]],
    replay_latency_micros: int,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    _require(
        isinstance(replay_latency_micros, int)
        and not isinstance(replay_latency_micros, bool)
        and replay_latency_micros >= 0,
        "replay latency must be a non-negative integer",
    )
    size = active_receipt_size_bytes(chain)
    trigger = policy["trigger"]
    reasons: list[str] = []
    if size > trigger["active_receipt_bytes_budget"]:
        reasons.append("ACTIVE_RECEIPT_BUDGET_EXCEEDED")
    if replay_latency_micros > trigger["replay_latency_micros_budget"]:
        reasons.append("REPLAY_LATENCY_BUDGET_EXCEEDED")
    return {
        "proposed": bool(reasons),
        "reason_codes": reasons,
        "active_receipt_bytes": size,
        "active_receipt_bytes_budget": trigger["active_receipt_bytes_budget"],
        "replay_latency_micros": replay_latency_micros,
        "replay_latency_micros_budget": trigger["replay_latency_micros_budget"],
    }


def _extract_turns(chain: Sequence[Mapping[str, Any]], run_id: str) -> list[dict[str, Any]]:
    turns: list[dict[str, Any]] = []
    for receipt in chain:
        if receipt.get("kind") != "trajectory_turn":
            continue
        payload = receipt.get("payload", {})
        _require(payload.get("run_id") == run_id, "trajectory receipt crosses run binding")
        turn_record = payload.get("turn_record")
        _require(isinstance(turn_record, Mapping), "trajectory receipt missing turn_record")
        turn = validate_turn(turn_record, expected_turn=len(turns) + 1)
        expected_hash = sha256_bytes(canonical_json(turn))
        _require(payload.get("turn_hash") == expected_hash, "trajectory turn hash mismatch")
        turns.append(turn)
    _require(bool(turns), "verified receipt chain contains no trajectory turns")
    return turns


def _fresh_refs(
    refs: Sequence[str],
    evidence_index: Mapping[str, Mapping[str, Any]],
    at_turn: int,
) -> bool:
    return bool(refs) and all(
        ref in evidence_index and evidence_is_fresh(evidence_index[ref], at_turn)
        for ref in refs
    )


def _semantic_key(value: Mapping[str, Any], fields: Sequence[str]) -> str:
    return sha256_bytes(canonical_json({field: value.get(field) for field in fields}))


def _receiver_admission_is_valid(
    payload: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> bool:
    approval = payload.get("receiver_admission")
    if not isinstance(approval, Mapping):
        return False
    expected = {
        "schema": "openline.half-life.receiver-mechanism-admission.v1",
        "run_id": payload.get("run_id"),
        "mechanism_id": payload.get("mechanism_id"),
        "relation_kind": payload.get("relation_kind"),
        "source_ids": payload.get("source_ids"),
        "target_id": payload.get("target_id"),
        "evidence_refs": payload.get("evidence_refs"),
        "status": "admitted",
    }
    body = _unsigned_body(approval)
    trusted = set(policy.get("trusted_receiver_approval_public_keys", []))
    return body == expected and bool(trusted) and canonical._verify_envelope(approval, trusted)


def _compact_tombstones(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = {}
    for item in items:
        if item.get("item_type") == "claim" and item.get("slot") is not None:
            key = (
                "claim",
                item.get("slot"),
                item.get("value_hash"),
                item.get("status"),
            )
        else:
            key = (
                item.get("item_type"),
                item.get("item_id"),
                item.get("status"),
            )
        grouped.setdefault(key, []).append(item)

    compact: list[dict[str, Any]] = []
    for key, group in sorted(grouped.items(), key=lambda pair: canonical_json(pair[0])):
        first = group[0]
        if first.get("item_type") == "claim":
            ids = sorted({str(item.get("item_id")) for item in group if item.get("item_id") is not None})
            identity = f"claim-state:{first.get('slot')}:{first.get('value_hash')}:{first.get('status')}"
            value = {
                "identity": identity,
                "item_type": "claim",
                "slot": first.get("slot"),
                "value_hash": first.get("value_hash"),
                "status": first.get("status"),
                "source_count": len(group),
                "source_ids_hash": sha256_bytes(canonical_json(ids)),
            }
            if first.get("status") in {"rejected", "unresolved", "quarantined"}:
                value["source_ids"] = ids
            compact.append(value)
        else:
            compact.append({
                "identity": f"{first.get('item_type')}:{first.get('item_id')}:{first.get('status')}",
                "item_type": first.get("item_type"),
                "item_id": first.get("item_id"),
                "status": first.get("status"),
                "source_count": len(group),
            })
    return compact


def _merge_summary(items: Sequence[Mapping[str, Any]], tombstones: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "repeated_observation_group_count": sum(
            1 for item in items if item.get("merge_type") == "repeated_observation"
        ),
        "superseded_state_count": sum(
            int(item.get("source_count", 1))
            for item in tombstones
            if item.get("status") == "superseded"
        ),
        "settled_intermediate_count": sum(
            int(item.get("source_count", 1))
            for item in tombstones
            if item.get("item_type") == "outcome" and item.get("status") == "superseded"
        ),
        "details_hash": sha256_bytes(canonical_json(list(items))),
    }


def derive_causal_state(
    turns: Sequence[Mapping[str, Any]],
    chain: Sequence[Mapping[str, Any]],
    checkpoint_turn: int,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    normalized = [validate_turn(turn, expected_turn=index) for index, turn in enumerate(turns, 1)]
    selected = [turn for turn in normalized if int(turn["turn"]) <= checkpoint_turn]
    _require(selected and int(selected[-1]["turn"]) == checkpoint_turn, "checkpoint turn is not present in source receipts")
    evidence_index = build_evidence_index(selected, through_turn=checkpoint_turn)

    claims_by_slot: dict[str, list[Mapping[str, Any]]] = {}
    for turn in selected:
        for claim in turn["claims"]:
            claims_by_slot.setdefault(str(claim["slot"]), []).append(claim)

    supported_claims: list[dict[str, Any]] = []
    tombstones: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    merged: list[dict[str, Any]] = []
    used_refs: set[str] = set()

    for slot, claims in sorted(claims_by_slot.items()):
        eligible: list[Mapping[str, Any]] = []
        for claim in claims:
            refs = claim["evidence_refs"]
            if claim["support_status"] != "supported":
                tombstones.append({
                    "identity": f"claim:{claim['id']}",
                    "item_type": "claim",
                    "item_id": claim["id"],
                    "slot": slot,
                    "value_hash": sha256_bytes(canonical_json(claim["value"])),
                    "status": "rejected" if claim["support_status"] == "unsupported" else "unresolved",
                    "reason": "support_status_not_supported",
                })
            elif not _fresh_refs(refs, evidence_index, checkpoint_turn):
                tombstones.append({
                    "identity": f"claim:{claim['id']}",
                    "item_type": "claim",
                    "item_id": claim["id"],
                    "slot": slot,
                    "value_hash": sha256_bytes(canonical_json(claim["value"])),
                    "status": "stale",
                    "reason": "evidence_missing_or_stale",
                })
            else:
                eligible.append(claim)

        if not eligible:
            continue
        latest_turn = max(int(item["last_verified_turn"]) for item in eligible)
        latest = [item for item in eligible if int(item["last_verified_turn"]) == latest_turn]
        distinct_values = {canonical_json(item["value"]) for item in latest}
        if len(distinct_values) > 1:
            contradictions.append({
                "id": f"claim-slot:{slot}:{latest_turn}",
                "kind": "conflicting_supported_claims",
                "slot": slot,
                "claim_ids": sorted(str(item["id"]) for item in latest),
                "value_hashes": sorted(sha256_bytes(value) for value in distinct_values),
                "status": "unresolved",
            })
            for item in latest:
                tombstones.append({
                    "identity": f"claim:{item['id']}",
                    "item_type": "claim",
                    "item_id": item["id"],
                    "slot": slot,
                    "value_hash": sha256_bytes(canonical_json(item["value"])),
                    "status": "quarantined",
                    "reason": "unresolved_conflict",
                })
            continue
        selected_claim = max(latest, key=lambda item: str(item["id"]))
        supported_claims.append(dict(selected_claim))
        used_refs.update(selected_claim["evidence_refs"])
        for item in eligible:
            if item is selected_claim:
                continue
            tombstones.append({
                "identity": f"claim:{item['id']}",
                "item_type": "claim",
                "item_id": item["id"],
                "slot": slot,
                "value_hash": sha256_bytes(canonical_json(item["value"])),
                "status": "superseded",
                "reason": "newer_verified_claim_retained",
            })
        semantic_groups: dict[str, list[str]] = {}
        for item in claims:
            key = _semantic_key(item, ("slot", "value", "support_status", "evidence_refs"))
            semantic_groups.setdefault(key, []).append(str(item["id"]))
        for semantic_hash, ids in semantic_groups.items():
            if len(ids) > 1:
                merged.append({
                    "merge_type": "repeated_observation",
                    "semantic_hash": semantic_hash,
                    "source_ids": sorted(ids),
                    "retained_id": selected_claim["id"] if selected_claim["id"] in ids else sorted(ids)[-1],
                    "reason": "same_claim_state_already_represented",
                })

    constraints_by_id: dict[str, list[Mapping[str, Any]]] = {}
    for turn in selected:
        for constraint in turn["constraints"]:
            constraints_by_id.setdefault(str(constraint["id"]), []).append(constraint)
    current_constraints: list[dict[str, Any]] = []
    for constraint_id, values in sorted(constraints_by_id.items()):
        latest_turn = max(int(item["last_verified_turn"]) for item in values)
        latest = max(
            (item for item in values if int(item["last_verified_turn"]) == latest_turn),
            key=lambda item: canonical_json(item),
        )
        if latest["active"] and _fresh_refs(latest["evidence_refs"], evidence_index, checkpoint_turn):
            current_constraints.append(dict(latest))
            used_refs.update(latest["evidence_refs"])
        else:
            tombstones.append({
                "identity": f"constraint:{constraint_id}",
                "item_type": "constraint",
                "item_id": constraint_id,
                "status": "revoked" if not latest["active"] else "stale",
                "reason": "latest_constraint_state_not_active_and_fresh",
            })
        for item in values:
            if item is not latest:
                tombstones.append({
                    "identity": f"constraint-version:{constraint_id}:{item['last_verified_turn']}",
                    "item_type": "constraint",
                    "item_id": constraint_id,
                    "status": "superseded",
                    "reason": "newer_constraint_state_retained",
                })

    outcomes_by_id: dict[str, list[tuple[int, Mapping[str, Any]]]] = {}
    for turn in selected:
        for outcome in turn["outcomes"]:
            outcomes_by_id.setdefault(str(outcome["id"]), []).append((int(turn["turn"]), outcome))
    commitments: list[dict[str, Any]] = []
    for outcome_id, observations in sorted(outcomes_by_id.items()):
        observed_turn, latest = observations[-1]
        if latest["confirmed"] and _fresh_refs(latest["evidence_refs"], evidence_index, checkpoint_turn):
            commitments.append(dict(latest))
            used_refs.update(latest["evidence_refs"])
        else:
            tombstones.append({
                "identity": f"outcome:{outcome_id}",
                "item_type": "outcome",
                "item_id": outcome_id,
                "status": "revoked" if not latest["confirmed"] else "stale",
                "reason": "latest_outcome_state_not_confirmed_and_fresh",
                "observed_turn": observed_turn,
            })
        for old_turn, _ in observations[:-1]:
            tombstones.append({
                "identity": f"outcome-version:{outcome_id}:{old_turn}",
                "item_type": "outcome",
                "item_id": outcome_id,
                "status": "superseded",
                "reason": "newer_outcome_state_retained",
                "observed_turn": old_turn,
            })

    unresolved_questions: list[str] = []
    for turn in selected:
        for question in turn["unresolved_questions"]:
            if question not in unresolved_questions:
                unresolved_questions.append(question)

    admitted_mechanisms: list[dict[str, Any]] = []
    unresolved_associations: list[dict[str, Any]] = []
    allowed_kinds = set(policy["causal_admission"]["allowed_relation_kinds"])
    for receipt in chain:
        if receipt.get("kind") not in {"mechanism_admission", "observation"}:
            continue
        payload = receipt.get("payload", {})
        if payload.get("run_id") != selected[0]["run_id"]:
            raise CompactionError("causal receipt crosses run binding")
        relation_kind = payload.get("relation_kind", "observation")
        refs = payload.get("evidence_refs", [])
        explicit = (
            receipt.get("kind") == "mechanism_admission"
            and payload.get("status") == "admitted"
            and _receiver_admission_is_valid(payload, policy)
        )
        if explicit and relation_kind in allowed_kinds and _fresh_refs(refs, evidence_index, checkpoint_turn):
            mechanism = {
                "mechanism_id": payload["mechanism_id"],
                "relation_kind": relation_kind,
                "source_ids": list(payload["source_ids"]),
                "target_id": payload["target_id"],
                "evidence_refs": list(refs),
                "admission_receipt_hash": receipt["receipt_hash"],
                "status": "admitted",
            }
            admitted_mechanisms.append(mechanism)
            used_refs.update(refs)
        else:
            unresolved_associations.append({
                "observation_id": payload.get("observation_id", payload.get("mechanism_id", receipt["receipt_hash"])),
                "relation_kind": relation_kind,
                "receipt_hash": receipt["receipt_hash"],
                "status": "observation_or_association_not_admitted_as_causal",
            })

    tombstones = _compact_tombstones(tombstones)

    evidence_references = sorted(
        (dict(evidence_index[ref]) for ref in used_refs if ref in evidence_index),
        key=lambda item: item["id"],
    )
    return {
        "run_id": selected[0]["run_id"],
        "checkpoint_turn": checkpoint_turn,
        "objective": selected[-1]["objective"],
        "supported_claims": sorted(supported_claims, key=lambda item: (item["slot"], item["id"])),
        "admitted_mechanisms": sorted(admitted_mechanisms, key=lambda item: item["mechanism_id"]),
        "current_constraints": sorted(current_constraints, key=lambda item: item["id"]),
        "commitments": sorted(commitments, key=lambda item: item["id"]),
        "unresolved_questions": unresolved_questions,
        "contradictions": sorted(contradictions, key=lambda item: item["id"]),
        "unresolved_associations": sorted(unresolved_associations, key=lambda item: item["observation_id"]),
        "tombstones": tombstones,
        "evidence_references": evidence_references,
        "merged_items": sorted(merged, key=lambda item: (item["merge_type"], item["semantic_hash"])),
        "merge_summary": _merge_summary(merged, tombstones),
    }


def receipt_gate_projection(state: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Project only decision-relevant state into COMMIT/QUARANTINE/DENY.

    This is not a score. It is a deterministic receiver decision table used to
    prove that active-memory compaction does not change decisions.
    """

    projection: dict[str, dict[str, Any]] = {}
    for claim in state.get("supported_claims", []):
        key = f"claim-slot:{claim['slot']}"
        projection[key] = {
            "disposition": "COMMIT",
            "state_hash": sha256_bytes(canonical_json({
                "value": claim["value"],
                "evidence_refs": claim["evidence_refs"],
                "last_verified_turn": claim["last_verified_turn"],
            })),
        }
    for mechanism in state.get("admitted_mechanisms", []):
        projection[f"mechanism:{mechanism['mechanism_id']}"] = {
            "disposition": "COMMIT",
            "state_hash": sha256_bytes(canonical_json(mechanism)),
        }
    for constraint in state.get("current_constraints", []):
        projection[f"constraint:{constraint['id']}"] = {
            "disposition": "COMMIT",
            "state_hash": sha256_bytes(canonical_json(constraint)),
        }
    for outcome in state.get("commitments", state.get("confirmed_outcomes", [])):
        projection[f"outcome:{outcome['id']}"] = {
            "disposition": "COMMIT",
            "state_hash": sha256_bytes(canonical_json(outcome)),
        }
    for question in state.get("unresolved_questions", []):
        digest = sha256_bytes(canonical_json(question))
        projection[f"question:{digest}"] = {"disposition": "QUARANTINE", "state_hash": digest}
    for contradiction in state.get("contradictions", []):
        projection[f"contradiction:{contradiction['id']}"] = {
            "disposition": "QUARANTINE",
            "state_hash": sha256_bytes(canonical_json(contradiction)),
        }
    for association in state.get("unresolved_associations", []):
        projection[f"association:{association['observation_id']}"] = {
            "disposition": "QUARANTINE",
            "state_hash": sha256_bytes(canonical_json(association)),
        }
    for tombstone in state.get("tombstones", []):
        projection[f"tombstone:{tombstone['identity']}"] = {
            "disposition": "DENY",
            "state_hash": sha256_bytes(canonical_json(tombstone)),
        }
    projection["automatic-retirement"] = {
        "disposition": "DENY",
        "state_hash": sha256_bytes(b"automatic-retirement-forbidden"),
    }
    return dict(sorted(projection.items()))


def build_causal_capsule(
    state: Mapping[str, Any],
    *,
    source_chain: Sequence[Mapping[str, Any]],
    source_anchor: Mapping[str, Any],
    succession_policy_hash: str,
    succession_policy_public_key: str,
    compaction_policy: Mapping[str, Any],
    checkpoint_hash: str,
    archive_destination: str,
    receiver_disposition: str,
) -> dict[str, Any]:
    body = {
        "schema": CAUSAL_CAPSULE_SCHEMA,
        "run_id": state["run_id"],
        "checkpoint_turn": state["checkpoint_turn"],
        "objective": state["objective"],
        "supported_claims": copy.deepcopy(state["supported_claims"]),
        "admitted_mechanisms": copy.deepcopy(state["admitted_mechanisms"]),
        "current_constraints": copy.deepcopy(state["current_constraints"]),
        "commitments": copy.deepcopy(state["commitments"]),
        "unresolved_questions": copy.deepcopy(state["unresolved_questions"]),
        "contradictions": copy.deepcopy(state["contradictions"]),
        "unresolved_associations": copy.deepcopy(state["unresolved_associations"]),
        "tombstones": copy.deepcopy(state["tombstones"]),
        "evidence_references": copy.deepcopy(state["evidence_references"]),
        "merge_summary": copy.deepcopy(state["merge_summary"]),
        "policy_binding": {
            "succession_policy_hash": succession_policy_hash,
            "succession_policy_public_key": succession_policy_public_key,
            "compaction_policy_hash": compaction_policy["payload_hash"],
            "compaction_policy_public_key": compaction_policy["signature"]["public_key"],
            "compaction_policy_version": compaction_policy["policy_version"],
            "trusted_key_version": compaction_policy["trusted_key_version"],
        },
        "source_binding": {
            "checkpoint_hash": checkpoint_hash,
            "source_chain_count": len(source_chain),
            "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
            "source_chain_digest": chain_digest(list(source_chain)),
            "source_anchor_hash": source_anchor["anchor_hash"],
            "source_signer_public_key": source_chain[0]["signer_public_key"],
        },
        "archive": {
            "destination": archive_destination,
            "source_receipts_permanently_deleted": False,
            "manifest_receipt_hash": None,
        },
        "rehydration_conditions": list(compaction_policy["rehydration_conditions"]),
        "receiver_disposition": receiver_disposition,
        "automatic_compaction_authorized": False,
        "automatic_retirement_authorized": False,
        "claim_boundary": (
            "The capsule preserves admitted decision-relevant state and tombstones. "
            "It does not infer causation from repetition or correlation and can be "
            "overturned only by receiver-governed rehydration from the cold archive."
        ),
    }
    return {**body, "capsule_hash": sha256_bytes(canonical_json(body))}


def decision_equivalence_report(
    full_history_projection: Mapping[str, Mapping[str, Any]],
    capsule: Mapping[str, Any],
    *,
    source_chain_size_bytes: int,
) -> dict[str, Any]:
    full_projection = dict(sorted(full_history_projection.items()))
    capsule_projection = receipt_gate_projection(capsule)
    keys = sorted(set(full_projection) | set(capsule_projection))
    mismatches = [
        {
            "decision_key": key,
            "full_history": full_projection.get(key),
            "causal_capsule": capsule_projection.get(key),
        }
        for key in keys
        if full_projection.get(key) != capsule_projection.get(key)
    ]
    capsule_bytes = len(canonical_json(capsule))
    body = {
        "schema": EQUIVALENCE_SCHEMA,
        "passed": not mismatches,
        "mismatches": mismatches,
        "full_history_decision_hash": sha256_bytes(canonical_json(full_projection)),
        "causal_capsule_decision_hash": sha256_bytes(canonical_json(capsule_projection)),
        "full_history_decision_count": len(full_projection),
        "causal_capsule_decision_count": len(capsule_projection),
        "source_chain_active_bytes": source_chain_size_bytes,
        "causal_capsule_active_bytes": capsule_bytes,
        "active_size_ratio_micros": (
            0 if source_chain_size_bytes == 0 else capsule_bytes * 1_000_000 // source_chain_size_bytes
        ),
        "automatic_retirement_authorized": False,
        "full_history_evaluator": "independent_reference_replay_v1",
        "claim_boundary": (
            "Decision equivalence is exact over the disclosed COMMIT, QUARANTINE, and DENY projection. "
            "It is not a similarity score."
        ),
    }
    return {**body, "report_hash": sha256_bytes(canonical_json(body))}


def _archive_receipts(
    output_dir: Path,
    source_chain: Sequence[Mapping[str, Any]],
    source_anchor: Mapping[str, Any],
    archive_destination: str,
) -> dict[str, Any]:
    archive_root = output_dir / archive_destination
    archive_root.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for receipt in source_chain:
        receipt_hash = str(receipt["receipt_hash"])
        path = archive_root / f"{receipt_hash}.json"
        write_json(path, receipt)
        entries.append({
            "index": receipt["index"],
            "kind": receipt["kind"],
            "receipt_hash": receipt_hash,
            "path": str(PurePosixPath(archive_destination) / path.name),
            "file_sha256": sha256_file(path),
        })
    anchor_path = output_dir / "cold_archive" / "source_anchor.json"
    write_json(anchor_path, source_anchor)
    return {
        "schema": ARCHIVE_MANIFEST_PAYLOAD_SCHEMA,
        "archive_destination": archive_destination,
        "hash_addressed": True,
        "source_receipts_permanently_deleted": False,
        "source_chain_count": len(source_chain),
        "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
        "source_chain_digest": chain_digest(list(source_chain)),
        "entries": entries,
        "source_anchor": {
            "path": "cold_archive/source_anchor.json",
            "file_sha256": sha256_file(anchor_path),
            "anchor_hash": source_anchor["anchor_hash"],
        },
        "recoverability_required": True,
    }


def bind_capsule_to_residue(
    checkpoint: Mapping[str, Any],
    capsule: Mapping[str, Any],
    archive_manifest_receipt: Mapping[str, Any],
    equivalence_report: Mapping[str, Any],
) -> dict[str, Any]:
    body = _checkpoint_body(checkpoint)
    body["schema"] = "openline.half-life.verified-residue-handoff.v2"
    body["causal_compaction"] = {
        "capsule_hash": capsule["capsule_hash"],
        "archive_manifest_receipt_hash": archive_manifest_receipt["receipt_hash"],
        "decision_equivalence_report_hash": equivalence_report["report_hash"],
        "decision_equivalence_passed": equivalence_report["passed"],
        "active_size_ratio_micros": equivalence_report["active_size_ratio_micros"],
        "archive_destination": capsule["archive"]["destination"],
        "rehydration_conditions": capsule["rehydration_conditions"],
    }
    body["automatic_retirement_authorized"] = False
    return _packet(body)


def _source_chain_checkpoint_binding(
    chain: Sequence[Mapping[str, Any]],
    checkpoint: Mapping[str, Any],
) -> bool:
    return any(
        receipt.get("kind") == "verified_residue_checkpoint"
        and receipt.get("payload", {}).get("packet_hash") == checkpoint.get("packet_hash")
        and receipt.get("payload", {}).get("run_id") == checkpoint.get("run_id")
        for receipt in chain
    )


def verify_compaction_inputs(inputs: CompactionInputs) -> dict[str, Any]:
    errors: list[str] = []
    policy_result = verify_compaction_policy(inputs.compaction_policy, inputs.trusted_policy_keys)
    errors.extend(f"compaction_policy:{reason}" for reason in policy_result["reason_codes"])
    source_chain = inputs.source_bundle.get("receipts", [])
    source_anchor = inputs.source_bundle.get("anchor", {})
    chain_result = verify_chain(source_chain, source_anchor)
    errors.extend(f"source_chain:{error}" for error in chain_result["errors"])
    checkpoint_result = verify_checkpoint(inputs.checkpoint)
    errors.extend(f"checkpoint:{error}" for error in checkpoint_result["errors"])

    if policy_result["valid"]:
        trusted_source = set(inputs.compaction_policy["trusted_source_receipt_signer_keys_b64"])
        if source_anchor.get("signer_public_key") not in trusted_source:
            errors.append("source_receipt_signer_not_trusted_by_compaction_policy")
        try:
            requested_destination = _safe_archive_destination(inputs.compaction_policy["archive"]["destination"])
            output_root = inputs.output_dir.resolve()
            candidate = (inputs.output_dir / requested_destination).resolve()
            if output_root not in candidate.parents and candidate != output_root:
                errors.append("archive_destination_escapes_output_directory")
        except CompactionError as exc:
            errors.append(f"archive_destination_invalid:{exc}")
    if source_chain and inputs.checkpoint:
        run_id = inputs.checkpoint.get("run_id")
        run_ids = {
            receipt.get("payload", {}).get("run_id")
            for receipt in source_chain
            if receipt.get("payload", {}).get("run_id") is not None
        }
        if any(value != run_id for value in run_ids):
            errors.append("source_chain_run_binding_mismatch")
        if not _source_chain_checkpoint_binding(source_chain, inputs.checkpoint):
            errors.append("checkpoint_not_bound_into_source_chain")
        if inputs.checkpoint.get("policy_hash") != inputs.source_bundle.get("policy_hash"):
            errors.append("checkpoint_succession_policy_hash_mismatch")
    approval_result = verify_receiver_approval(
        inputs.receiver_approval,
        source_chain=source_chain,
        checkpoint=inputs.checkpoint,
        compaction_policy=inputs.compaction_policy,
    )
    errors.extend(f"receiver_approval:{reason}" for reason in approval_result["reason_codes"])
    if inputs.compaction_policy.get("automatic_retirement_authorized") is not False:
        errors.append("automatic_retirement_authorized")
    pressure = (
        evaluate_pressure(source_chain, inputs.replay_latency_micros, inputs.compaction_policy)
        if policy_result["valid"] and source_chain
        else {"proposed": False, "reason_codes": []}
    )
    if not pressure.get("proposed"):
        errors.append("budget_trigger_not_met")
    return {
        "valid": not errors,
        "errors": errors,
        "policy": policy_result,
        "chain": chain_result,
        "checkpoint": checkpoint_result,
        "receiver_approval": approval_result,
        "pressure": pressure,
    }


def compact_verified_chain(
    inputs: CompactionInputs,
    signer: ReceiptSigner,
) -> dict[str, Any]:
    verification = verify_compaction_inputs(inputs)
    if not verification["valid"]:
        raise CompactionError("compaction input verification failed: " + ",".join(verification["errors"]))

    source_chain = list(inputs.source_bundle["receipts"])
    source_anchor = inputs.source_bundle["anchor"]
    _require(
        signer.public_b64 == source_chain[0].get("signer_public_key"),
        "compaction signer must match the verified source receipt signer",
    )
    run_id = str(inputs.checkpoint["run_id"])
    checkpoint_turn = int(inputs.checkpoint["retirement_turn"])
    turns = _extract_turns(source_chain, run_id)
    state = derive_causal_state(turns, source_chain, checkpoint_turn, inputs.compaction_policy)
    full_projection = reference_receipt_gate_projection(
        turns,
        source_chain,
        checkpoint_turn,
        inputs.compaction_policy,
    )
    archive_destination = inputs.compaction_policy["archive"]["destination"]
    capsule = build_causal_capsule(
        state,
        source_chain=source_chain,
        source_anchor=source_anchor,
        succession_policy_hash=str(inputs.source_bundle["policy_hash"]),
        succession_policy_public_key=str(inputs.source_bundle["policy_public_key"]),
        compaction_policy=inputs.compaction_policy,
        checkpoint_hash=str(inputs.checkpoint["packet_hash"]),
        archive_destination=archive_destination,
        receiver_disposition=str(inputs.receiver_approval["disposition"]),
    )
    equivalence = decision_equivalence_report(
        full_projection,
        capsule,
        source_chain_size_bytes=verification["pressure"]["active_receipt_bytes"],
    )
    if not equivalence["passed"]:
        raise CompactionError("decision equivalence failed")

    archive_payload = _archive_receipts(
        inputs.output_dir,
        source_chain,
        source_anchor,
        archive_destination,
    )
    archive_receipt = create_extension_receipt(
        "cold_archive_manifest",
        archive_payload,
        signer,
        index=len(source_chain),
        parent_hash=source_chain[-1]["receipt_hash"],
    )
    archive_extension = verify_extension_chain(
        [archive_receipt],
        expected_parent_hash=source_chain[-1]["receipt_hash"],
        expected_start_index=len(source_chain),
        expected_signer_public_key=source_chain[0]["signer_public_key"],
    )
    _require(
        archive_extension["valid"],
        "generated archive manifest does not validly extend the verified source chain",
    )
    capsule_body = _capsule_body(capsule)
    capsule_body["archive"]["manifest_receipt_hash"] = archive_receipt["receipt_hash"]
    capsule = {**capsule_body, "capsule_hash": sha256_bytes(canonical_json(capsule_body))}
    equivalence = decision_equivalence_report(
        full_projection,
        capsule,
        source_chain_size_bytes=verification["pressure"]["active_receipt_bytes"],
    )
    updated_residue = bind_capsule_to_residue(inputs.checkpoint, capsule, archive_receipt, equivalence)
    return {
        "verification": verification,
        "state": state,
        "capsule": capsule,
        "equivalence_report": equivalence,
        "archive_manifest_receipt": archive_receipt,
        "updated_verified_residue": updated_residue,
        "source_chain": source_chain,
        "source_anchor": source_anchor,
        "receiver_approval": dict(inputs.receiver_approval),
    }


def build_compaction_receipt(
    *,
    source_chain: Sequence[Mapping[str, Any]],
    archive_receipt: Mapping[str, Any],
    capsule: Mapping[str, Any],
    equivalence_report: Mapping[str, Any],
    updated_residue: Mapping[str, Any],
    comparison: Mapping[str, Any],
    share_card_sha256: str,
    artifact_hashes: Mapping[str, str],
    input_hashes: Mapping[str, str],
    compaction_policy: Mapping[str, Any],
    receiver_approval: Mapping[str, Any],
    pressure: Mapping[str, Any],
    receiver_disposition: str,
    signer: ReceiptSigner,
) -> dict[str, Any]:
    _require(bool(source_chain), "compaction receipt requires a source chain")
    _require(
        signer.public_b64 == source_chain[0].get("signer_public_key"),
        "compaction signer must match the verified source receipt signer",
    )
    archive_extension = verify_extension_chain(
        [archive_receipt],
        expected_parent_hash=str(source_chain[-1]["receipt_hash"]),
        expected_start_index=len(source_chain),
        expected_signer_public_key=str(source_chain[0]["signer_public_key"]),
    )
    _require(
        archive_extension["valid"],
        "archive manifest must validly extend the verified source chain",
    )
    _require(
        set(artifact_hashes) == SIGNED_OUTPUT_ARTIFACTS,
        "signed artifact manifest must cover the complete required artifact set",
    )
    _require(
        all(isinstance(value, str) and HASH256.fullmatch(value) is not None for value in artifact_hashes.values()),
        "signed artifact manifest contains an invalid hash",
    )
    _require(
        set(input_hashes) == {"trajectory_sha256", "exam_hash"},
        "signed input manifest must contain the trajectory and exam hashes",
    )
    _require(
        all(isinstance(value, str) and HASH256.fullmatch(value) is not None for value in input_hashes.values()),
        "signed input manifest contains an invalid hash",
    )
    _require(
        receiver_disposition == receiver_approval.get("disposition") == RECEIVER_APPROVAL,
        "compaction receipt requires the bound receiver approval",
    )
    payload = {
        "schema": COMPACTION_PAYLOAD_SCHEMA,
        "run_id": capsule["run_id"],
        "checkpoint_turn": capsule["checkpoint_turn"],
        "source_chain_count": len(source_chain),
        "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
        "source_chain_digest": chain_digest(list(source_chain)),
        "resulting_capsule_hash": capsule["capsule_hash"],
        "archive_manifest_receipt_hash": archive_receipt["receipt_hash"],
        "decision_equivalence_report_hash": equivalence_report["report_hash"],
        "updated_verified_residue_packet_hash": updated_residue["packet_hash"],
        "comparison_hash": comparison["comparison_hash"],
        "comparison_passed": comparison["passed"],
        "same_exam_verified": comparison["same_exam_verified"],
        "legitimate_task_completion_preserved": comparison["legitimate_task_completion_preserved"],
        "share_card_sha256": share_card_sha256,
        "artifact_hashes": dict(sorted(artifact_hashes.items())),
        "input_hashes": dict(sorted(input_hashes.items())),
        "policy_hash": compaction_policy["payload_hash"],
        "policy_public_key": compaction_policy["signature"]["public_key"],
        "policy_version": compaction_policy["policy_version"],
        "trusted_key_version": compaction_policy["trusted_key_version"],
        "trusted_source_receipt_signer_key": source_chain[0]["signer_public_key"],
        "receiver_approval_hash": receiver_approval["payload_hash"],
        "receiver_approval_public_key": receiver_approval["signature"]["public_key"],
        "kept": {
            "supported_claim_ids": [item["id"] for item in capsule["supported_claims"]],
            "admitted_mechanism_ids": [item["mechanism_id"] for item in capsule["admitted_mechanisms"]],
            "constraint_ids": [item["id"] for item in capsule["current_constraints"]],
            "commitment_ids": [item["id"] for item in capsule["commitments"]],
            "unresolved_question_count": len(capsule["unresolved_questions"]),
            "contradiction_ids": [item["id"] for item in capsule["contradictions"]],
            "tombstone_count": len(capsule["tombstones"]),
        },
        "merged": capsule["merge_summary"],
        "archived": {
            "receipt_count": archive_receipt["payload"]["source_chain_count"],
            "destination": archive_receipt["payload"]["archive_destination"],
            "source_receipts_permanently_deleted": False,
        },
        "decision_log": [
            *[
                {
                    "action": "keep",
                    "item_type": "claim",
                    "item_id": item["id"],
                    "allowed_by": "CURRENTLY_SUPPORTED_WITH_FRESH_EVIDENCE",
                    "evidence_refs": list(item["evidence_refs"]),
                }
                for item in capsule["supported_claims"]
            ],
            *[
                {
                    "action": "keep",
                    "item_type": "mechanism",
                    "item_id": item["mechanism_id"],
                    "allowed_by": "EXPLICIT_RECEIVER_ADMISSION_WITH_FRESH_EVIDENCE",
                    "evidence_refs": list(item["evidence_refs"]),
                }
                for item in capsule["admitted_mechanisms"]
            ],
            *[
                {
                    "action": "keep",
                    "item_type": "constraint",
                    "item_id": item["id"],
                    "allowed_by": "LATEST_ACTIVE_STATE_WITH_FRESH_EVIDENCE",
                    "evidence_refs": list(item["evidence_refs"]),
                }
                for item in capsule["current_constraints"]
            ],
            *[
                {
                    "action": "keep",
                    "item_type": "commitment",
                    "item_id": item["id"],
                    "allowed_by": "LATEST_CONFIRMED_OUTCOME_WITH_FRESH_EVIDENCE",
                    "evidence_refs": list(item["evidence_refs"]),
                }
                for item in capsule["commitments"]
            ],
            *[
                {
                    "action": "keep",
                    "item_type": "tombstone",
                    "item_id": item["identity"],
                    "allowed_by": "REPLAY_PREVENTION_REQUIRES_NEGATIVE_STATE_RETENTION",
                    "status": item["status"],
                }
                for item in capsule["tombstones"]
            ],
            {
                "action": "merge",
                "item_type": "receipt_state",
                "item_id": capsule["merge_summary"]["details_hash"],
                "allowed_by": "RECEIVER_POLICY_LIMITS_MERGE_TO_DUPLICATE_OR_SUPERSEDED_DECISION_EQUIVALENT_STATE",
                "summary": capsule["merge_summary"],
            },
            {
                "action": "archive",
                "item_type": "source_receipt_chain",
                "item_id": source_chain[-1]["receipt_hash"],
                "allowed_by": "HASH_ADDRESSED_SIGNED_MANIFEST_WITH_NO_SOURCE_DELETION",
                "receipt_count": archive_receipt["payload"]["source_chain_count"],
                "destination": archive_receipt["payload"]["archive_destination"],
            },
        ],
        "allowed_because": [
            *pressure["reason_codes"],
            "TRUSTED_POLICY_SIGNER_VERIFIED",
            "SOURCE_CHAIN_VERIFIED",
            "CHECKPOINT_VERIFIED_AND_BOUND",
            "ARCHIVE_DESTINATION_VERIFIED",
            "DECISION_EQUIVALENCE_PROVED",
            "RECEIVER_APPROVED",
        ],
        "rehydration_conditions": capsule["rehydration_conditions"],
        "receiver_disposition": receiver_disposition,
        "automatic_compaction_authorized": False,
        "automatic_retirement_authorized": False,
    }
    return create_extension_receipt(
        "causal_compaction",
        payload,
        signer,
        index=int(archive_receipt["index"]) + 1,
        parent_hash=str(archive_receipt["receipt_hash"]),
    )


def candidate_hits_tombstone(capsule: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
    item_type = candidate.get("item_type")
    item_id = candidate.get("item_id")
    slot = candidate.get("slot")
    value_hash = candidate.get("value_hash")
    for tombstone in capsule.get("tombstones", []):
        if tombstone.get("item_type") != item_type:
            continue
        if item_id is not None and (
            tombstone.get("item_id") == item_id
            or item_id in tombstone.get("source_ids", [])
        ):
            return True
        if slot is not None and tombstone.get("slot") == slot and (
            value_hash is None or tombstone.get("value_hash") == value_hash
        ):
            return True
    return False


def propose_rehydration(
    capsule: Mapping[str, Any],
    later_receipts: Sequence[Mapping[str, Any]],
    *,
    current_compaction_policy_hash: str,
    current_trusted_key_version: str,
    expected_parent_hash: str | None = None,
    expected_start_index: int | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    evidence_state_updates: list[dict[str, Any]] = []
    binding = capsule["policy_binding"]
    if current_compaction_policy_hash != binding["compaction_policy_hash"]:
        reasons.append("COMPACTION_POLICY_CHANGED")
    if current_trusted_key_version != binding["trusted_key_version"]:
        reasons.append("TRUSTED_KEY_CHANGED")
    kind_reasons = {
        "mechanism_outcome": "MECHANISM_WEAKENED_OR_OVERTURNED",
        "constraint_change": "CONSTRAINT_CHANGED",
        "evidence_revocation": "EVIDENCE_REVOKED",
        "policy_change": "COMPACTION_POLICY_CHANGED",
        "contradiction_update": "UNRESOLVED_CONTRADICTION_CHANGED",
        "decision_mismatch": "SUCCESSOR_DECISION_MISMATCH",
    }
    receipt_verification: dict[str, Any] = {"valid": True, "errors": [], "count": 0}
    if later_receipts:
        if expected_parent_hash is None or expected_start_index is None:
            raise CompactionError("signed later receipts require an expected parent hash and start index")
        signer_key = str(capsule["source_binding"]["source_signer_public_key"])
        receipt_verification = verify_extension_chain(
            list(later_receipts),
            expected_parent_hash=expected_parent_hash,
            expected_start_index=expected_start_index,
            expected_signer_public_key=signer_key,
        )
        if not receipt_verification["valid"]:
            raise CompactionError(
                "later receipt verification failed: " + ",".join(receipt_verification["errors"])
            )
    for receipt in later_receipts:
        kind = receipt.get("kind")
        payload = receipt.get("payload", {})
        if payload.get("run_id") != capsule.get("run_id"):
            raise CompactionError("later receipt crosses capsule run binding")
        if kind == "mechanism_outcome":
            result = payload.get("result")
            if result in {"confirmed", "weakened", "overturned"}:
                evidence_state_updates.append({
                    "mechanism_id": payload.get("mechanism_id"),
                    "result": result,
                    "outcome_receipt_hash": receipt.get("receipt_hash"),
                    "policy_changed": False,
                })
            if result not in {"weakened", "overturned"}:
                continue
        if kind in kind_reasons:
            reasons.append(kind_reasons[kind])
    reasons = sorted(set(reasons))
    return {
        "proposed": bool(reasons),
        "reason_codes": reasons,
        "evidence_state_updates": evidence_state_updates,
        "archive_destination": capsule["archive"]["destination"],
        "source_chain_tail_hash": capsule["source_binding"]["source_chain_tail_hash"],
        "policy_rewrite_authorized": False,
        "self_approval_authorized": False,
        "required_action": "REHYDRATE_AND_RECOMPUTE_FROM_ARCHIVED_RECEIPTS" if reasons else "NONE",
        "later_receipt_verification": receipt_verification,
    }


def verify_archive_manifest(
    output_dir: Path,
    archive_receipt: Mapping[str, Any],
    source_chain: Sequence[Mapping[str, Any]],
    source_anchor: Mapping[str, Any],
    *,
    expected_archive_destination: str,
) -> list[str]:
    errors: list[str] = []
    payload = archive_receipt.get("payload", {})
    if archive_receipt.get("schema") != RECEIPT_SCHEMA or archive_receipt.get("kind") != "cold_archive_manifest":
        errors.append("archive_manifest_receipt_shape_invalid")
        return errors
    if payload.get("schema") != ARCHIVE_MANIFEST_PAYLOAD_SCHEMA:
        errors.append("archive_manifest_payload_schema_mismatch")
    entries = payload.get("entries", [])
    if payload.get("archive_destination") != expected_archive_destination:
        errors.append("archive_manifest_destination_policy_mismatch")
    try:
        _safe_archive_destination(expected_archive_destination)
        expected_archive_root = resolve_safe_relative_path(output_dir, expected_archive_destination)
    except (CompactionError, ValueError):
        errors.append("archive_manifest_destination_invalid")
        return errors
    if not isinstance(entries, list):
        errors.append("archive_manifest_entries_invalid")
        return errors
    expected_hashes = [receipt["receipt_hash"] for receipt in source_chain]
    actual_hashes = [entry.get("receipt_hash") for entry in entries]
    if actual_hashes != expected_hashes:
        errors.append("archive_manifest_completeness_mismatch")
    if payload.get("source_chain_count") != len(source_chain):
        errors.append("archive_manifest_count_mismatch")
    if payload.get("source_chain_tail_hash") != source_chain[-1]["receipt_hash"]:
        errors.append("archive_manifest_tail_mismatch")
    if payload.get("source_chain_digest") != chain_digest(list(source_chain)):
        errors.append("archive_manifest_digest_mismatch")
    for entry, receipt in zip(entries, source_chain):
        expected_relative = str(
            PurePosixPath(expected_archive_destination) / f"{receipt['receipt_hash']}.json"
        )
        if entry.get("path") != expected_relative:
            errors.append(f"archived_receipt_path_mismatch:{receipt['receipt_hash']}")
            continue
        try:
            path = resolve_safe_relative_path(output_dir, entry.get("path"))
        except ValueError:
            errors.append(f"archived_receipt_path_invalid:{receipt['receipt_hash']}")
            continue
        if path.parent != expected_archive_root:
            errors.append(f"archived_receipt_path_outside_destination:{receipt['receipt_hash']}")
            continue
        if not path.exists():
            errors.append(f"archived_receipt_missing:{receipt['receipt_hash']}")
            continue
        if sha256_file(path) != entry.get("file_sha256"):
            errors.append(f"archived_receipt_file_hash_mismatch:{receipt['receipt_hash']}")
            continue
        try:
            archived = load_json(path)
        except Exception:
            errors.append(f"archived_receipt_invalid_json:{receipt['receipt_hash']}")
            continue
        if archived != receipt:
            errors.append(f"archived_receipt_content_mismatch:{receipt['receipt_hash']}")
    anchor_spec = payload.get("source_anchor", {})
    if anchor_spec.get("path") != "cold_archive/source_anchor.json":
        errors.append("archived_source_anchor_path_mismatch")
        return errors
    try:
        anchor_path = resolve_safe_relative_path(output_dir, anchor_spec.get("path"))
    except ValueError:
        errors.append("archived_source_anchor_path_invalid")
        return errors
    if not anchor_path.exists():
        errors.append("archived_source_anchor_missing")
    elif sha256_file(anchor_path) != anchor_spec.get("file_sha256"):
        errors.append("archived_source_anchor_file_hash_mismatch")
    else:
        try:
            archived_anchor = load_json(anchor_path)
            if archived_anchor != source_anchor:
                errors.append("archived_source_anchor_content_mismatch")
        except Exception:
            errors.append("archived_source_anchor_invalid_json")
    return errors


def rehydrate_archived_state(
    output_dir: Path,
    capsule: Mapping[str, Any],
    archive_receipt: Mapping[str, Any],
    compaction_policy: Mapping[str, Any],
    *,
    expected_compaction_policy_public_keys: set[str] | None,
) -> dict[str, Any]:
    """Restore, authenticate, and replay the cold source chain.

    Nothing from the archive is admitted until its path, file hash, receipt
    signatures, chain completeness, source trust, run binding, and manifest
    extension signature all verify.
    """

    policy_result = verify_compaction_policy(
        compaction_policy,
        expected_compaction_policy_public_keys,
    )
    _require(
        policy_result["valid"],
        "compaction policy verification failed: " + ",".join(policy_result["reason_codes"]),
    )
    _require(capsule.get("schema") == CAUSAL_CAPSULE_SCHEMA, "causal capsule schema mismatch")
    _require(
        capsule.get("capsule_hash") == sha256_bytes(canonical_json(_capsule_body(capsule))),
        "causal capsule hash mismatch",
    )
    policy_binding = capsule.get("policy_binding", {})
    _require(isinstance(policy_binding, Mapping), "causal capsule policy binding is invalid")
    expected_policy_binding = {
        "compaction_policy_hash": compaction_policy["payload_hash"],
        "compaction_policy_public_key": compaction_policy["signature"]["public_key"],
        "compaction_policy_version": compaction_policy["policy_version"],
        "trusted_key_version": compaction_policy["trusted_key_version"],
    }
    for field, expected in expected_policy_binding.items():
        _require(
            policy_binding.get(field) == expected,
            f"causal capsule policy binding mismatch: {field}",
        )

    destination = str(compaction_policy["archive"]["destination"])
    capsule_archive = capsule.get("archive", {})
    _require(isinstance(capsule_archive, Mapping), "causal capsule archive binding is invalid")
    _require(
        capsule_archive.get("destination") == destination,
        "causal capsule archive destination does not match the verified policy",
    )
    _require(
        capsule_archive.get("manifest_receipt_hash") == archive_receipt.get("receipt_hash"),
        "causal capsule is not bound to the supplied archive manifest",
    )
    payload = archive_receipt.get("payload", {})
    entries = payload.get("entries", [])
    _require(isinstance(entries, list) and bool(entries), "archive manifest has no entries")
    source_chain: list[dict[str, Any]] = []
    for entry in entries:
        receipt_hash = entry.get("receipt_hash")
        _require(
            isinstance(receipt_hash, str) and HASH256.fullmatch(receipt_hash) is not None,
            "archive manifest receipt hash is invalid",
        )
        expected_path = str(PurePosixPath(destination) / f"{receipt_hash}.json")
        _require(entry.get("path") == expected_path, "archive manifest receipt path is not hash addressed")
        path = resolve_safe_relative_path(output_dir, entry.get("path"))
        _require(sha256_file(path) == entry.get("file_sha256"), "archived receipt file hash mismatch")
        source_chain.append(load_json(path))
    anchor_path = resolve_safe_relative_path(output_dir, "cold_archive/source_anchor.json")
    source_anchor = load_json(anchor_path)

    manifest_errors = verify_archive_manifest(
        output_dir,
        archive_receipt,
        source_chain,
        source_anchor,
        expected_archive_destination=destination,
    )
    chain_result = verify_chain(source_chain, source_anchor)
    extension_result = verify_extension_chain(
        [archive_receipt],
        expected_parent_hash=source_chain[-1]["receipt_hash"],
        expected_start_index=len(source_chain),
        expected_signer_public_key=source_chain[0]["signer_public_key"],
    )
    trusted_source = set(compaction_policy["trusted_source_receipt_signer_keys_b64"])
    errors = [*manifest_errors]
    errors.extend(f"source_chain:{item}" for item in chain_result["errors"])
    errors.extend(f"archive_extension:{item}" for item in extension_result["errors"])
    if source_chain[0]["signer_public_key"] not in trusted_source:
        errors.append("source_receipt_signer_not_trusted_by_compaction_policy")
    source_binding = capsule.get("source_binding", {})
    if not isinstance(source_binding, Mapping):
        errors.append("causal_capsule_source_binding_invalid")
        source_binding = {}
    expected_source_binding = {
        "source_chain_count": len(source_chain),
        "source_chain_tail_hash": source_chain[-1]["receipt_hash"],
        "source_chain_digest": chain_digest(source_chain),
        "source_anchor_hash": source_anchor.get("anchor_hash"),
        "source_signer_public_key": source_chain[0]["signer_public_key"],
    }
    for field, expected in expected_source_binding.items():
        if source_binding.get(field) != expected:
            errors.append(f"causal_capsule_source_binding_mismatch:{field}")
    checkpoint_receipt = next(
        (item for item in source_chain if item.get("kind") == "verified_residue_checkpoint"),
        None,
    )
    if checkpoint_receipt is None:
        errors.append("verified_residue_checkpoint_missing")
    else:
        checkpoint_payload = checkpoint_receipt.get("payload", {})
        if checkpoint_payload.get("packet_hash") != source_binding.get("checkpoint_hash"):
            errors.append("causal_capsule_source_binding_mismatch:checkpoint_hash")
        if checkpoint_payload.get("retirement_turn") != capsule.get("checkpoint_turn"):
            errors.append("causal_capsule_checkpoint_turn_mismatch")
    if errors:
        raise CompactionError("archive rehydration failed: " + ",".join(errors))

    run_id = str(capsule["run_id"])
    checkpoint_turn = int(capsule["checkpoint_turn"])
    turns = _extract_turns(source_chain, run_id)
    state = derive_causal_state(turns, source_chain, checkpoint_turn, compaction_policy)
    projection = reference_receipt_gate_projection(
        turns, source_chain, checkpoint_turn, compaction_policy
    )
    return {
        "state": state,
        "decision_projection": projection,
        "source_chain": source_chain,
        "source_anchor": source_anchor,
        "source_chain_verified": True,
        "archive_manifest_verified": True,
        "compaction_policy_verified": True,
        "policy_rewrite_authorized": False,
        "self_approval_authorized": False,
    }


def verify_compaction_outputs(
    output_dir: Path,
    source_bundle: Mapping[str, Any],
    *,
    expected_compaction_policy_public_keys: set[str] | None,
) -> dict[str, Any]:
    errors: list[str] = []
    required = set(EXPECTED_BUNDLE_ARTIFACTS)
    missing = [name for name in sorted(required) if not (output_dir / name).exists()]
    errors.extend(f"compaction_artifact_missing:{name}" for name in missing)
    if missing:
        return {"valid": False, "errors": errors}
    try:
        artifact_paths = {
            name: resolve_safe_relative_path(output_dir, name) for name in required
        }
    except ValueError as exc:
        return {"valid": False, "errors": [f"compaction_artifact_path_invalid:{exc}"]}
    try:
        policy = load_json(artifact_paths["compaction_policy.json"])
        policy_result = verify_compaction_policy(policy, expected_compaction_policy_public_keys)
        capsule = load_json(artifact_paths["causal_capsule.json"])
        equivalence = load_json(artifact_paths["decision_equivalence_report.json"])
        archive_receipt = load_json(artifact_paths["archive_manifest.json"])
        compaction_receipt = load_json(artifact_paths["compaction_receipt.json"])
        updated_residue = load_json(artifact_paths["verified_residue_handoff.json"])
        receiver_approval = load_json(artifact_paths["receiver_approval.json"])
    except Exception as exc:
        return {"valid": False, "errors": [f"compaction_artifact_invalid:{exc}"]}
    errors.extend(f"compaction_policy:{reason}" for reason in policy_result["reason_codes"])

    full_chain = source_bundle.get("receipts", [])
    if len(full_chain) < 3:
        errors.append("full_receipt_chain_too_short_for_compaction")
        return {"valid": False, "errors": errors}
    if full_chain[-2] != archive_receipt:
        errors.append("archive_manifest_not_bound_as_penultimate_receipt")
    if full_chain[-1] != compaction_receipt:
        errors.append("compaction_receipt_not_bound_as_chain_tail")
    source_chain = full_chain[:-2]
    try:
        source_anchor_path = resolve_safe_relative_path(output_dir, "cold_archive/source_anchor.json")
        source_anchor = load_json(source_anchor_path) if source_anchor_path.exists() else {}
    except ValueError:
        source_anchor = {}
        errors.append("archived_source_anchor_path_invalid")
    source_chain_result = verify_chain(source_chain, source_anchor)
    errors.extend(f"archived_source_chain:{error}" for error in source_chain_result["errors"])
    trusted_source = set(policy.get("trusted_source_receipt_signer_keys_b64", []))
    source_signer_trusted = bool(source_chain) and source_chain[0].get("signer_public_key") in trusted_source
    if not source_signer_trusted:
        errors.append("source_receipt_signer_not_trusted_by_compaction_policy")
    extension_result = verify_extension_chain(
        [archive_receipt, compaction_receipt],
        expected_parent_hash=source_chain[-1]["receipt_hash"],
        expected_start_index=len(source_chain),
        expected_signer_public_key=source_chain[0]["signer_public_key"],
    )
    errors.extend(f"compaction_extension:{error}" for error in extension_result["errors"])
    checkpoint_receipt = next(
        (item for item in source_chain if item.get("kind") == "verified_residue_checkpoint"),
        {},
    )
    checkpoint_binding = {
        "run_id": checkpoint_receipt.get("payload", {}).get("run_id"),
        "packet_hash": checkpoint_receipt.get("payload", {}).get("packet_hash"),
    }
    approval_result = verify_receiver_approval(
        receiver_approval,
        source_chain=source_chain,
        checkpoint=checkpoint_binding,
        compaction_policy=policy,
    )
    errors.extend(f"receiver_approval:{reason}" for reason in approval_result["reason_codes"])
    if source_chain_result["valid"] and extension_result["valid"] and source_signer_trusted:
        errors.extend(
            verify_archive_manifest(
                output_dir,
                archive_receipt,
                source_chain,
                source_anchor,
                expected_archive_destination=str(policy.get("archive", {}).get("destination", "")),
            )
        )

    if capsule.get("schema") != CAUSAL_CAPSULE_SCHEMA:
        errors.append("causal_capsule_schema_mismatch")
    capsule_body = _capsule_body(capsule)
    if capsule.get("capsule_hash") != sha256_bytes(canonical_json(capsule_body)):
        errors.append("causal_capsule_hash_mismatch")
    if equivalence.get("schema") != EQUIVALENCE_SCHEMA:
        errors.append("decision_equivalence_schema_mismatch")
    equivalence_body = dict(equivalence)
    equivalence_body.pop("report_hash", None)
    if equivalence.get("report_hash") != sha256_bytes(canonical_json(equivalence_body)):
        errors.append("decision_equivalence_report_hash_mismatch")
    if equivalence.get("passed") is not True:
        errors.append("decision_equivalence_not_proved")
    if receipt_gate_projection(capsule) and (
        sha256_bytes(canonical_json(receipt_gate_projection(capsule)))
        != equivalence.get("causal_capsule_decision_hash")
    ):
        errors.append("capsule_decision_projection_mismatch")
    try:
        source_turns = _extract_turns(source_chain, str(capsule.get("run_id")))
        full_projection = reference_receipt_gate_projection(
            source_turns, source_chain, int(capsule.get("checkpoint_turn")), policy
        )
        recomputed = decision_equivalence_report(
            full_projection,
            capsule,
            source_chain_size_bytes=active_receipt_size_bytes(source_chain),
        )
        if recomputed != equivalence:
            errors.append("decision_equivalence_semantic_mismatch")
    except (CompactionError, KeyError, TypeError, ValueError) as exc:
        errors.append(f"decision_equivalence_recomputation_failed:{exc}")
    if updated_residue.get("causal_compaction", {}).get("capsule_hash") != capsule.get("capsule_hash"):
        errors.append("updated_residue_capsule_binding_mismatch")
    if updated_residue.get("causal_compaction", {}).get("archive_manifest_receipt_hash") != archive_receipt.get("receipt_hash"):
        errors.append("updated_residue_archive_binding_mismatch")
    if updated_residue.get("causal_compaction", {}).get("decision_equivalence_report_hash") != equivalence.get("report_hash"):
        errors.append("updated_residue_equivalence_binding_mismatch")
    if updated_residue.get("packet_hash") != sha256_bytes(canonical_json(_checkpoint_body(updated_residue))):
        errors.append("updated_residue_packet_hash_mismatch")
    payload = compaction_receipt.get("payload", {})
    if payload.get("schema") != COMPACTION_PAYLOAD_SCHEMA:
        errors.append("compaction_receipt_payload_schema_mismatch")
    signed_artifact_hashes = payload.get("artifact_hashes")
    if not isinstance(signed_artifact_hashes, Mapping):
        errors.append("signed_artifact_manifest_invalid")
        signed_artifact_hashes = {}
    if set(signed_artifact_hashes) != SIGNED_OUTPUT_ARTIFACTS:
        errors.append("signed_artifact_manifest_coverage_mismatch")
    signed_input_hashes = payload.get("input_hashes")
    if not isinstance(signed_input_hashes, Mapping):
        errors.append("signed_input_manifest_invalid")
        signed_input_hashes = {}
    if set(signed_input_hashes) != {"trajectory_sha256", "exam_hash"}:
        errors.append("signed_input_manifest_coverage_mismatch")
    for name in ("trajectory_sha256", "exam_hash"):
        value = signed_input_hashes.get(name)
        if not isinstance(value, str) or HASH256.fullmatch(value) is None:
            errors.append(f"signed_input_hash_invalid:{name}")
    bundle_artifact_hashes = source_bundle.get("artifact_hashes")
    if not isinstance(bundle_artifact_hashes, Mapping):
        errors.append("receipt_bundle_artifact_manifest_invalid")
        bundle_artifact_hashes = {}
    if set(bundle_artifact_hashes) != EXPECTED_BUNDLE_ARTIFACTS:
        errors.append("receipt_bundle_artifact_manifest_coverage_mismatch")
    for name in sorted(SIGNED_OUTPUT_ARTIFACTS):
        signed_hash = signed_artifact_hashes.get(name)
        if not isinstance(signed_hash, str) or HASH256.fullmatch(signed_hash) is None:
            errors.append(f"signed_artifact_hash_invalid:{name}")
            continue
        if sha256_file(artifact_paths[name]) != signed_hash:
            errors.append(f"signed_artifact_hash_mismatch:{name}")
        if bundle_artifact_hashes.get(name) != signed_hash:
            errors.append(f"artifact_manifest_binding_mismatch:{name}")
    compaction_receipt_file_hash = sha256_file(artifact_paths["compaction_receipt.json"])
    if bundle_artifact_hashes.get("compaction_receipt.json") != compaction_receipt_file_hash:
        errors.append("artifact_manifest_binding_mismatch:compaction_receipt.json")
    comparison = load_json(artifact_paths["comparison.json"])
    bundle_input_hashes = source_bundle.get("input_hashes")
    if not isinstance(bundle_input_hashes, Mapping):
        errors.append("receipt_bundle_input_manifest_invalid")
        bundle_input_hashes = {}
    if set(bundle_input_hashes) != {"trajectory_sha256", "exam_hash"}:
        errors.append("receipt_bundle_input_manifest_coverage_mismatch")
    for name in ("trajectory_sha256", "exam_hash"):
        if bundle_input_hashes.get(name) != signed_input_hashes.get(name):
            errors.append(f"input_manifest_binding_mismatch:{name}")
    if signed_input_hashes.get("exam_hash") != comparison.get("exam_hash"):
        errors.append("input_manifest_exam_binding_mismatch")
    expected_bindings = {
        "resulting_capsule_hash": capsule.get("capsule_hash"),
        "archive_manifest_receipt_hash": archive_receipt.get("receipt_hash"),
        "decision_equivalence_report_hash": equivalence.get("report_hash"),
        "updated_verified_residue_packet_hash": updated_residue.get("packet_hash"),
        "comparison_hash": comparison.get("comparison_hash"),
        "policy_hash": policy.get("payload_hash"),
        "policy_public_key": policy.get("signature", {}).get("public_key"),
        "receiver_approval_hash": receiver_approval.get("payload_hash"),
        "receiver_approval_public_key": receiver_approval.get("signature", {}).get("public_key"),
    }
    for field, expected in expected_bindings.items():
        if payload.get(field) != expected:
            errors.append(f"compaction_receipt_binding_mismatch:{field}")
    bundle_compaction = source_bundle.get("compaction")
    expected_bundle_compaction = {
        "policy_hash": policy.get("payload_hash"),
        "policy_public_key": policy.get("signature", {}).get("public_key"),
        "policy_version": policy.get("policy_version"),
        "trusted_key_version": policy.get("trusted_key_version"),
        "source_chain_count": len(source_chain),
        "archive_manifest_receipt_hash": archive_receipt.get("receipt_hash"),
        "compaction_receipt_hash": compaction_receipt.get("receipt_hash"),
        "causal_capsule_hash": capsule.get("capsule_hash"),
        "decision_equivalence_report_hash": equivalence.get("report_hash"),
        "decision_equivalence_passed": equivalence.get("passed"),
        "active_size_ratio_micros": equivalence.get("active_size_ratio_micros"),
        "receiver_approval_hash": receiver_approval.get("payload_hash"),
        "receiver_approval_public_key": receiver_approval.get("signature", {}).get("public_key"),
        "receiver_disposition": RECEIVER_APPROVAL,
        "automatic_retirement_authorized": False,
    }
    if not isinstance(bundle_compaction, Mapping):
        errors.append("receipt_bundle_compaction_invalid")
        bundle_compaction = {}
    if set(bundle_compaction) != set(expected_bundle_compaction):
        errors.append("receipt_bundle_compaction_field_mismatch")
    for field, expected in expected_bundle_compaction.items():
        if bundle_compaction.get(field) != expected:
            errors.append(f"receipt_bundle_compaction_binding_mismatch:{field}")
    if capsule.get("automatic_retirement_authorized") is not False:
        errors.append("capsule_automatic_retirement_forbidden")
    if payload.get("automatic_retirement_authorized") is not False:
        errors.append("compaction_receipt_automatic_retirement_forbidden")
    if payload.get("share_card_sha256") != sha256_file(artifact_paths["share_card.html"]):
        errors.append("compaction_receipt_binding_mismatch:share_card_sha256")
    if payload.get("comparison_passed") is not comparison.get("passed"):
        errors.append("compaction_receipt_binding_mismatch:comparison_passed")
    if payload.get("same_exam_verified") is not comparison.get("same_exam_verified"):
        errors.append("compaction_receipt_binding_mismatch:same_exam_verified")
    if payload.get("legitimate_task_completion_preserved") is not comparison.get("legitimate_task_completion_preserved"):
        errors.append("compaction_receipt_binding_mismatch:legitimate_task_completion_preserved")
    if payload.get("receiver_disposition") != RECEIVER_APPROVAL:
        errors.append("compaction_receipt_receiver_approval_missing")
    if capsule.get("receiver_disposition") != RECEIVER_APPROVAL:
        errors.append("capsule_receiver_approval_missing")
    if capsule.get("archive", {}).get("destination") != policy.get("archive", {}).get("destination"):
        errors.append("capsule_archive_destination_policy_mismatch")
    if capsule.get("source_binding", {}).get("source_signer_public_key") != source_chain[0].get("signer_public_key"):
        errors.append("capsule_source_signer_binding_mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "source_chain": source_chain_result,
        "extension": extension_result,
        "active_size_ratio_micros": equivalence.get("active_size_ratio_micros"),
        "decision_equivalence_passed": equivalence.get("passed"),
        "archive_receipt_count": archive_receipt.get("payload", {}).get("source_chain_count"),
    }
