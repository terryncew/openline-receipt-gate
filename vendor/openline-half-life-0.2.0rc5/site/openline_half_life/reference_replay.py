"""Independent full-history decision replay for compaction verification.

This module intentionally does not import the causal compactor.  It computes
the receiver decision table straight from verified source turns so a defect in
the compactor cannot certify a copy of its own defective output.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .evidence import build_evidence_index, evidence_is_fresh
from .util import canonical_json, sha256_bytes
from .vendor.openline_endurance_gate import succession as canonical


def _fresh(
    refs: Sequence[str],
    evidence: Mapping[str, Mapping[str, Any]],
    at_turn: int,
) -> bool:
    return bool(refs) and all(
        ref in evidence and evidence_is_fresh(evidence[ref], at_turn) for ref in refs
    )


def _compact_tombstones(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = {}
    for item in items:
        if item.get("item_type") == "claim" and item.get("slot") is not None:
            key = ("claim", item.get("slot"), item.get("value_hash"), item.get("status"))
        else:
            key = (item.get("item_type"), item.get("item_id"), item.get("status"))
        groups.setdefault(key, []).append(item)

    compact: list[dict[str, Any]] = []
    for key, group in sorted(groups.items(), key=lambda pair: canonical_json(pair[0])):
        first = group[0]
        if first.get("item_type") == "claim":
            ids = sorted(
                {str(item.get("item_id")) for item in group if item.get("item_id") is not None}
            )
            value: dict[str, Any] = {
                "identity": (
                    f"claim-state:{first.get('slot')}:{first.get('value_hash')}:"
                    f"{first.get('status')}"
                ),
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
            compact.append(
                {
                    "identity": (
                        f"{first.get('item_type')}:{first.get('item_id')}:"
                        f"{first.get('status')}"
                    ),
                    "item_type": first.get("item_type"),
                    "item_id": first.get("item_id"),
                    "status": first.get("status"),
                    "source_count": len(group),
                }
            )
    return compact


def _receiver_admitted(payload: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
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
    body = dict(approval)
    body.pop("payload_hash", None)
    body.pop("signature", None)
    trusted = set(policy.get("trusted_receiver_approval_public_keys", []))
    return body == expected and bool(trusted) and canonical._verify_envelope(approval, trusted)


def reference_receipt_gate_projection(
    turns: Sequence[Mapping[str, Any]],
    chain: Sequence[Mapping[str, Any]],
    checkpoint_turn: int,
    policy: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Replay raw history into the exact receiver decision table."""

    selected = [turn for turn in turns if int(turn["turn"]) <= checkpoint_turn]
    if not selected or int(selected[-1]["turn"]) != checkpoint_turn:
        raise ValueError("checkpoint turn is not present in source history")
    run_id = selected[0]["run_id"]
    evidence = build_evidence_index(selected, through_turn=checkpoint_turn)
    projection: dict[str, dict[str, Any]] = {}
    tombstones: list[dict[str, Any]] = []

    claims_by_slot: dict[str, list[Mapping[str, Any]]] = {}
    for turn in selected:
        for claim in turn["claims"]:
            claims_by_slot.setdefault(str(claim["slot"]), []).append(claim)
    for slot, claims in sorted(claims_by_slot.items()):
        eligible: list[Mapping[str, Any]] = []
        for claim in claims:
            if claim["support_status"] != "supported":
                tombstones.append(
                    {
                        "item_type": "claim",
                        "item_id": claim["id"],
                        "slot": slot,
                        "value_hash": sha256_bytes(canonical_json(claim["value"])),
                        "status": (
                            "rejected" if claim["support_status"] == "unsupported" else "unresolved"
                        ),
                    }
                )
            elif not _fresh(claim["evidence_refs"], evidence, checkpoint_turn):
                tombstones.append(
                    {
                        "item_type": "claim",
                        "item_id": claim["id"],
                        "slot": slot,
                        "value_hash": sha256_bytes(canonical_json(claim["value"])),
                        "status": "stale",
                    }
                )
            else:
                eligible.append(claim)
        if not eligible:
            continue
        latest_turn = max(int(item["last_verified_turn"]) for item in eligible)
        latest = [item for item in eligible if int(item["last_verified_turn"]) == latest_turn]
        values = {canonical_json(item["value"]) for item in latest}
        if len(values) > 1:
            contradiction = {
                "id": f"claim-slot:{slot}:{latest_turn}",
                "kind": "conflicting_supported_claims",
                "slot": slot,
                "claim_ids": sorted(str(item["id"]) for item in latest),
                "value_hashes": sorted(sha256_bytes(value) for value in values),
                "status": "unresolved",
            }
            projection[f"contradiction:{contradiction['id']}"] = {
                "disposition": "QUARANTINE",
                "state_hash": sha256_bytes(canonical_json(contradiction)),
            }
            for item in latest:
                tombstones.append(
                    {
                        "item_type": "claim",
                        "item_id": item["id"],
                        "slot": slot,
                        "value_hash": sha256_bytes(canonical_json(item["value"])),
                        "status": "quarantined",
                    }
                )
            continue
        winner = max(latest, key=lambda item: str(item["id"]))
        projection[f"claim-slot:{slot}"] = {
            "disposition": "COMMIT",
            "state_hash": sha256_bytes(
                canonical_json(
                    {
                        "value": winner["value"],
                        "evidence_refs": winner["evidence_refs"],
                        "last_verified_turn": winner["last_verified_turn"],
                    }
                )
            ),
        }
        for item in eligible:
            if item is not winner:
                tombstones.append(
                    {
                        "item_type": "claim",
                        "item_id": item["id"],
                        "slot": slot,
                        "value_hash": sha256_bytes(canonical_json(item["value"])),
                        "status": "superseded",
                    }
                )

    constraints: dict[str, list[Mapping[str, Any]]] = {}
    for turn in selected:
        for item in turn["constraints"]:
            constraints.setdefault(str(item["id"]), []).append(item)
    for item_id, versions in sorted(constraints.items()):
        latest_turn = max(int(item["last_verified_turn"]) for item in versions)
        latest = max(
            (item for item in versions if int(item["last_verified_turn"]) == latest_turn),
            key=canonical_json,
        )
        if latest["active"] and _fresh(latest["evidence_refs"], evidence, checkpoint_turn):
            projection[f"constraint:{item_id}"] = {
                "disposition": "COMMIT",
                "state_hash": sha256_bytes(canonical_json(latest)),
            }
        else:
            tombstones.append(
                {
                    "item_type": "constraint",
                    "item_id": item_id,
                    "status": "revoked" if not latest["active"] else "stale",
                }
            )
        for version in versions:
            if version is not latest:
                tombstones.append(
                    {"item_type": "constraint", "item_id": item_id, "status": "superseded"}
                )

    outcomes: dict[str, list[tuple[int, Mapping[str, Any]]]] = {}
    for turn in selected:
        for item in turn["outcomes"]:
            outcomes.setdefault(str(item["id"]), []).append((int(turn["turn"]), item))
    for item_id, versions in sorted(outcomes.items()):
        _, latest = versions[-1]
        if latest["confirmed"] and _fresh(latest["evidence_refs"], evidence, checkpoint_turn):
            projection[f"outcome:{item_id}"] = {
                "disposition": "COMMIT",
                "state_hash": sha256_bytes(canonical_json(latest)),
            }
        else:
            tombstones.append(
                {
                    "item_type": "outcome",
                    "item_id": item_id,
                    "status": "revoked" if not latest["confirmed"] else "stale",
                }
            )
        for _ in versions[:-1]:
            tombstones.append(
                {"item_type": "outcome", "item_id": item_id, "status": "superseded"}
            )

    questions: list[str] = []
    for turn in selected:
        for question in turn["unresolved_questions"]:
            if question not in questions:
                questions.append(question)
    for question in questions:
        digest = sha256_bytes(canonical_json(question))
        projection[f"question:{digest}"] = {"disposition": "QUARANTINE", "state_hash": digest}

    allowed = set(policy["causal_admission"]["allowed_relation_kinds"])
    for receipt in chain:
        if receipt.get("kind") not in {"mechanism_admission", "observation"}:
            continue
        payload = receipt.get("payload", {})
        if payload.get("run_id") != run_id:
            raise ValueError("causal receipt crosses run binding")
        relation = payload.get("relation_kind", "observation")
        refs = payload.get("evidence_refs", [])
        explicit = (
            receipt.get("kind") == "mechanism_admission"
            and payload.get("status") == "admitted"
            and _receiver_admitted(payload, policy)
        )
        if explicit and relation in allowed and _fresh(refs, evidence, checkpoint_turn):
            mechanism = {
                "mechanism_id": payload["mechanism_id"],
                "relation_kind": relation,
                "source_ids": list(payload["source_ids"]),
                "target_id": payload["target_id"],
                "evidence_refs": list(refs),
                "admission_receipt_hash": receipt["receipt_hash"],
                "status": "admitted",
            }
            projection[f"mechanism:{mechanism['mechanism_id']}"] = {
                "disposition": "COMMIT",
                "state_hash": sha256_bytes(canonical_json(mechanism)),
            }
        else:
            association = {
                "observation_id": payload.get(
                    "observation_id", payload.get("mechanism_id", receipt["receipt_hash"])
                ),
                "relation_kind": relation,
                "receipt_hash": receipt["receipt_hash"],
                "status": "observation_or_association_not_admitted_as_causal",
            }
            projection[f"association:{association['observation_id']}"] = {
                "disposition": "QUARANTINE",
                "state_hash": sha256_bytes(canonical_json(association)),
            }

    for tombstone in _compact_tombstones(tombstones):
        projection[f"tombstone:{tombstone['identity']}"] = {
            "disposition": "DENY",
            "state_hash": sha256_bytes(canonical_json(tombstone)),
        }
    projection["automatic-retirement"] = {
        "disposition": "DENY",
        "state_hash": sha256_bytes(b"automatic-retirement-forbidden"),
    }
    return dict(sorted(projection.items()))
