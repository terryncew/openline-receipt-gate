"""Evidence binding and orthogonal outcome verification."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapters import Check, FAIL, PASS, UNAVAILABLE, TrustStore, parse_timestamp
from .crypto import olp_canonical_json, sha256_hex, sign_olp_body, strict_json_loads, verify_olp_signature


def normalize_hash(value: str | None) -> str | None:
    if value is None:
        return None
    return value.removeprefix("sha256:").lower()


def object_path(value: Any, dotted_path: str) -> Any:
    current = value
    for component in dotted_path.split("."):
        if not component:
            continue
        if isinstance(current, Mapping):
            if component not in current:
                raise KeyError(dotted_path)
            current = current[component]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            current = current[int(component)]
        else:
            raise KeyError(dotted_path)
    return current


def _artifact_bytes(
    item: Mapping[str, Any],
    base_dir: str | Path | None,
    max_evidence_bytes: int,
) -> bytes | None:
    if "artifact_path" in item:
        path = Path(str(item["artifact_path"]))
        root = Path(base_dir or ".").resolve()
        if not path.is_absolute():
            path = root / path
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise ValueError("evidence artifact escapes base directory")
        if resolved.stat().st_size > max_evidence_bytes:
            raise ValueError("evidence artifact exceeds policy size limit")
        return resolved.read_bytes()
    if "content" in item:
        content = item["content"]
        if not isinstance(content, str):
            raise ValueError("inline evidence content must be a string")
        data = content.encode("utf-8")
        if len(data) > max_evidence_bytes:
            raise ValueError("inline evidence exceeds policy size limit")
        return data
    if "json_value" in item:
        data = olp_canonical_json(item["json_value"])
        if len(data) > max_evidence_bytes:
            raise ValueError("JSON evidence exceeds policy size limit")
        return data
    return None


def _artifact_json(item: Mapping[str, Any], data: bytes) -> Any:
    if "json_value" in item:
        return item["json_value"]
    return strict_json_loads(data.decode("utf-8"))


def _graph_from_disclosure(
    source_receipts: Sequence[Mapping[str, Any]],
    disclosure: Mapping[str, Any] | None,
) -> tuple[Mapping[str, Any] | None, list[str]]:
    if disclosure is None:
        return None, []
    errors: list[str] = []
    if not source_receipts:
        return None, ["disclosure_without_source"]
    source = source_receipts[0]
    if source.get("kind") != "coherence_input_receipt":
        return None, ["disclosure_source_kind_mismatch"]
    graph = disclosure.get("semantic_graph")
    if not isinstance(graph, Mapping):
        return None, ["semantic_graph_missing"]
    try:
        graph_hash = sha256_hex(olp_canonical_json(graph))
    except ValueError:
        return None, ["semantic_graph_canonicalization_failed"]
    if graph_hash != source.get("semantic_graph_hash"):
        errors.append("semantic_graph_commitment_mismatch")
    if disclosure.get("trace_id") != source.get("trace_id"):
        errors.append("disclosure_trace_mismatch")
    signals = disclosure.get("signals", [])
    if not isinstance(signals, list):
        errors.append("disclosure_signals_invalid")
    else:
        values: list[int] = []
        for expected_sequence, signal in enumerate(signals):
            if not isinstance(signal, Mapping) or signal.get("sequence") != expected_sequence:
                errors.append("disclosure_signal_sequence_invalid")
                break
            values.append(signal.get("value_micros"))
        if values != source.get("signal_points_micros"):
            errors.append("disclosure_signal_commitment_mismatch")
    return graph, errors


def assess_evidence(
    *,
    source_receipts: Sequence[Mapping[str, Any]],
    source_receipt_hashes: Sequence[str],
    source_format: str,
    evidence_items: Sequence[Mapping[str, Any]],
    required_evidence_ids: Sequence[str],
    required_claim_ids: Sequence[str],
    require_source_binding: bool,
    assertions: Sequence[Mapping[str, Any]],
    disclosure: Mapping[str, Any] | None = None,
    base_dir: str | Path | None = None,
    max_evidence_bytes: int = 10_000_000,
) -> Check:
    """Check artifact integrity, source binding, claim links, and policy predicates.

    This function never infers semantic relevance from a hash.  A policy must
    identify the required evidence and, where content matters, declare a
    deterministic assertion over the disclosed artifact.
    """

    items = {str(item.get("id")): item for item in evidence_items if isinstance(item, Mapping)}
    errors: list[str] = []
    unavailable: list[str] = []
    artifact_hashes: dict[str, str] = {}
    artifact_json: dict[str, Any] = {}
    bound_ids: set[str] = set()

    graph, disclosure_errors = _graph_from_disclosure(source_receipts, disclosure)
    errors.extend(disclosure_errors)
    graph_evidence: dict[str, Mapping[str, Any]] = {}
    graph_support: dict[str, set[str]] = {}
    material_claims: set[str] = set()
    if graph is not None:
        claims = graph.get("claims", [])
        evidence = graph.get("evidence", [])
        relations = graph.get("relations", [])
        if not all(isinstance(group, list) for group in (claims, evidence, relations)):
            errors.append("semantic_graph_shape_invalid")
        else:
            for claim in claims:
                if isinstance(claim, Mapping) and claim.get("material") is True:
                    material_claims.add(str(claim.get("id")))
            graph_evidence = {
                str(entry.get("id")): entry for entry in evidence if isinstance(entry, Mapping)
            }
            for relation in relations:
                if isinstance(relation, Mapping) and relation.get("relation_type") == "supports":
                    graph_support.setdefault(str(relation.get("dst")), set()).add(str(relation.get("src")))

    claims_needed = set(str(value) for value in required_claim_ids) or material_claims
    ids_needed = set(str(value) for value in required_evidence_ids)

    for evidence_id in ids_needed:
        if evidence_id not in items:
            unavailable.append(f"required_evidence_missing:{evidence_id}")

    for evidence_id, item in items.items():
        try:
            data = _artifact_bytes(item, base_dir, max_evidence_bytes)
        except (OSError, UnicodeError, ValueError):
            errors.append(f"evidence_artifact_unreadable:{evidence_id}")
            continue
        if data is None:
            unavailable.append(f"evidence_artifact_unavailable:{evidence_id}")
            continue
        actual_hash = sha256_hex(data)
        artifact_hashes[evidence_id] = actual_hash
        declared_hash = normalize_hash(str(item.get("content_hash", "")))
        if declared_hash != actual_hash:
            errors.append(f"evidence_hash_mismatch:{evidence_id}")
            continue

        graph_entry = graph_evidence.get(evidence_id)
        if graph_entry is not None:
            if normalize_hash(str(graph_entry.get("content_hash", ""))) != actual_hash:
                errors.append(f"semantic_evidence_hash_mismatch:{evidence_id}")
            else:
                bound_ids.add(evidence_id)

        commitment_path = item.get("source_commitment_path")
        if source_format == "agent_receipts":
            fixed_path = "credentialSubject.outcome.response_hash"
            if commitment_path is not None and commitment_path != fixed_path:
                errors.append(f"source_commitment_path_invalid:{evidence_id}")
            commitment_path = fixed_path
        if commitment_path:
            if not source_receipts:
                unavailable.append(f"source_commitment_missing:{evidence_id}")
            else:
                try:
                    committed = object_path(source_receipts[-1], str(commitment_path))
                except (KeyError, ValueError, IndexError):
                    unavailable.append(f"source_commitment_missing:{evidence_id}")
                else:
                    if normalize_hash(str(committed)) != actual_hash:
                        errors.append(f"source_commitment_mismatch:{evidence_id}")
                    else:
                        bound_ids.add(evidence_id)

        if item.get("source_receipt_hash"):
            declared_source = normalize_hash(str(item.get("source_receipt_hash")))
            source_hashes = {
                normalize_hash(str(receipt.get("payload_hash") or receipt.get("receipt_hash") or ""))
                for receipt in source_receipts
            }
            source_hashes.update(normalize_hash(value) for value in source_receipt_hashes)
            if declared_source not in source_hashes:
                errors.append(f"source_receipt_binding_mismatch:{evidence_id}")
            else:
                bound_ids.add(evidence_id)

        # Claim support must come from either the source-committed OLP graph or
        # the external policy's required evidence/claim sets.  A request cannot
        # grant its own evidence semantic authority with a ``supports`` field.
        if graph is None and evidence_id in ids_needed and evidence_id in bound_ids:
            for claim_id in claims_needed:
                graph_support.setdefault(claim_id, set()).add(evidence_id)

        try:
            artifact_json[evidence_id] = _artifact_json(item, data)
        except (UnicodeError, json.JSONDecodeError, ValueError):
            pass

    if require_source_binding:
        for evidence_id in ids_needed or set(items):
            if evidence_id not in bound_ids:
                unavailable.append(f"evidence_not_bound_to_source:{evidence_id}")

    for claim_id in claims_needed:
        supporting = graph_support.get(claim_id, set()) & set(items)
        if not supporting:
            unavailable.append(f"claim_support_missing:{claim_id}")

    for assertion in assertions:
        evidence_id = str(assertion.get("evidence_id", ""))
        if evidence_id not in artifact_json:
            unavailable.append(f"assertion_artifact_unavailable:{evidence_id}")
            continue
        try:
            actual = object_path(artifact_json[evidence_id], str(assertion["path"]))
        except (KeyError, ValueError, IndexError):
            errors.append(f"assertion_path_missing:{evidence_id}:{assertion.get('path')}")
            continue
        operation = assertion.get("op", "equals")
        expected = assertion.get("value")
        passed = False
        if operation == "equals":
            passed = actual == expected
        elif operation == "in":
            passed = actual in expected if isinstance(expected, list) else False
        elif operation == "gte":
            passed = (
                isinstance(actual, (int, float))
                and not isinstance(actual, bool)
                and isinstance(expected, (int, float))
                and not isinstance(expected, bool)
                and actual >= expected
            )
        elif operation == "lte":
            passed = (
                isinstance(actual, (int, float))
                and not isinstance(actual, bool)
                and isinstance(expected, (int, float))
                and not isinstance(expected, bool)
                and actual <= expected
            )
        else:
            errors.append(f"assertion_operator_unsupported:{operation}")
            continue
        if not passed:
            errors.append(f"evidence_assertion_failed:{evidence_id}:{assertion.get('path')}")

    details = {
        "artifact_hashes": artifact_hashes,
        "bound_evidence_ids": sorted(bound_ids),
        "required_evidence_ids": sorted(ids_needed),
        "required_claim_ids": sorted(claims_needed),
        "raw_evidence_stored_in_decision": False,
        "scope": "policy-declared evidence binding and predicates; no general truth inference",
    }
    if errors:
        return Check(FAIL, errors, details)
    if unavailable:
        return Check(UNAVAILABLE, unavailable, details)
    return Check(PASS, [], details)


def issue_outcome_receipt(
    *,
    source_receipt_hash: str,
    outcome_status: str,
    harmful: bool,
    evidence_hash: str,
    witness_id: str,
    rollback_supported: bool,
    key: Ed25519PrivateKey,
    observed_at: str | None = None,
) -> dict[str, Any]:
    body = {
        "kind": "witness_outcome_receipt",
        "receipt_version": "0.2",
        "algorithm_id": "openline-orthogonal-outcome-0.2",
        "canonicalization_id": "olp-canonical-json-int-v1",
        "spec_uri": "https://github.com/terryncew/openline-receipt-gate",
        "source_receipt_hash": normalize_hash(source_receipt_hash),
        "outcome": {
            "status": outcome_status,
            "harmful": harmful,
            "rollback_supported": rollback_supported,
        },
        "evidence_hash": normalize_hash(evidence_hash),
        "witness_id": witness_id,
        "observed_at": observed_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    return sign_olp_body(body, key)


def assess_outcome(
    *,
    outcome_receipt: Mapping[str, Any] | None,
    source_hash: str | None,
    trust_store: TrustStore,
) -> Check:
    if outcome_receipt is None:
        return Check(UNAVAILABLE, ["trusted_outcome_missing"])
    valid, reason = verify_olp_signature(outcome_receipt)
    if not valid:
        return Check(FAIL, [reason or "outcome_signature_invalid"])
    if outcome_receipt.get("kind") != "witness_outcome_receipt":
        return Check(FAIL, ["outcome_profile_invalid"])
    if (
        outcome_receipt.get("receipt_version") != "0.2"
        or outcome_receipt.get("canonicalization_id") != "olp-canonical-json-int-v1"
        or outcome_receipt.get("algorithm_id") != "openline-orthogonal-outcome-0.2"
    ):
        return Check(FAIL, ["outcome_profile_invalid"])
    outcome = outcome_receipt.get("outcome")
    if (
        not isinstance(outcome, Mapping)
        or not isinstance(outcome.get("status"), str)
        or not isinstance(outcome.get("harmful"), bool)
        or not isinstance(outcome.get("rollback_supported"), bool)
        or not outcome_receipt.get("witness_id")
        or parse_timestamp(outcome_receipt.get("observed_at")) is None
    ):
        return Check(FAIL, ["outcome_fields_invalid"])
    for field_name in ("source_receipt_hash", "evidence_hash"):
        value = normalize_hash(str(outcome_receipt.get(field_name, "")))
        if value is None or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            return Check(FAIL, [f"{field_name}_invalid"])
    if normalize_hash(str(outcome_receipt.get("source_receipt_hash", ""))) != normalize_hash(source_hash):
        return Check(FAIL, ["outcome_source_binding_mismatch"])
    signature = outcome_receipt.get("signature", {})
    key_id = str(signature.get("public_key", "")) if isinstance(signature, Mapping) else ""
    record = trust_store.get(key_id)
    if record is None or "outcome" not in record.roles:
        return Check(UNAVAILABLE, ["outcome_witness_not_trusted"], {"witness_key": key_id})
    if record.independence not in {"orthogonal", "receiver", "independent"}:
        return Check(
            UNAVAILABLE,
            ["outcome_witness_not_independent"],
            {"witness_key": key_id, "independence": record.independence},
        )
    return Check(
        PASS,
        [],
        {
            "witness_key": key_id,
            "witness_id": outcome_receipt.get("witness_id"),
            "independence": record.independence,
            "status": outcome.get("status") if isinstance(outcome, Mapping) else None,
            "harmful": outcome.get("harmful") if isinstance(outcome, Mapping) else None,
            "rollback_supported": outcome.get("rollback_supported") if isinstance(outcome, Mapping) else None,
            "evidence_hash": outcome_receipt.get("evidence_hash"),
        },
    )
