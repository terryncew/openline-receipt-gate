"""Receiver-side reference replay for OpenLine Handoff Check.

This module deliberately does not import the capsule builder.  It reconstructs
the full-history reference state with a separate traversal and validator so a
capsule-extraction defect cannot certify the same defect during comparison.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any


REFERENCE_SCHEMA = "openline.handoff.reference-replay.v2"
SEMANTIC_KINDS = {
    "decision",
    "evidence",
    "constraint",
    "assumption",
    "open_question",
    "rejected_path",
    "artifact",
}
SEMANTIC_STATUSES = {"active", "resolved", "superseded", "rejected"}
CURRENT_KINDS = set(SEMANTIC_KINDS)
SUPPORT_REQUIRED = {"decision", "assumption"}
ACTION_SCOPED_KINDS = {"decision", "assumption", "artifact", "evidence"}
GENERIC_ACTION_WORDS = {
    "build",
    "change",
    "changes",
    "continue",
    "continuation",
    "feature",
    "fix",
    "implement",
    "implementation",
    "modify",
    "modification",
    "refactor",
    "refactoring",
    "rollout",
    "ship",
    "task",
    "update",
    "updates",
    "work",
}
UNSAFE_SEMANTIC_CHARS = (
    frozenset(chr(code) for code in range(0, 32) if code not in (9, 10, 13))
    | {
        chr(127),
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)
SEMANTIC_FIELDS = {
    "kind",
    "item_id",
    "key",
    "statement",
    "status",
    "evidence_ids",
    "relevant_actions",
}


class ReferenceReplayError(ValueError):
    """Raised when the canonical replay input itself is not usable."""


def _json_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _safe_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReferenceReplayError(f"{label}_invalid")
    if any(character in UNSAFE_SEMANTIC_CHARS for character in value):
        raise ReferenceReplayError(f"{label}_contains_unsafe_control_characters")
    return value.strip()


def _string_list(value: Any, *, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ReferenceReplayError(f"{label}_invalid")
    result = [
        _safe_text(item, label=f"{label}_{index}")
        for index, item in enumerate(value)
    ]
    if len(result) != len(set(result)):
        raise ReferenceReplayError(f"{label}_duplicates")
    return result


def _words(text: str) -> set[str]:
    result: set[str] = set()
    token: list[str] = []
    for character in text.lower():
        if character.isalnum() or character in {"_", "-", "/", "."}:
            token.append(character)
            continue
        if token:
            value = "".join(token).strip("._-/")
            if len(value) >= 3:
                result.add(value)
            token = []
    if token:
        value = "".join(token).strip("._-/")
        if len(value) >= 3:
            result.add(value)
    return result


def _action_matches(scopes: Sequence[str], next_action: str) -> bool:
    if not scopes:
        return True
    action_words = _words(next_action) - GENERIC_ACTION_WORDS
    if not action_words:
        return False
    for scope in scopes:
        scope_words = _words(scope) - GENERIC_ACTION_WORDS
        if scope_words and scope_words.issubset(action_words):
            return True
    return False


def _semantic(raw: Any, *, event_id: str, sequence: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ReferenceReplayError("semantic_not_object")
    unknown = set(raw) - SEMANTIC_FIELDS
    if unknown:
        raise ReferenceReplayError(f"semantic_unknown_fields:{sorted(unknown)}")
    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in SEMANTIC_KINDS:
        raise ReferenceReplayError("semantic_kind_invalid")
    statement = _safe_text(raw.get("statement"), label="semantic_statement")
    key_value = raw.get("key")
    if key_value is None:
        key_value = (
            f"{kind}:"
            f"{hashlib.sha256(statement.encode('utf-8')).hexdigest()[:20]}"
        )
    key = _safe_text(key_value, label="semantic_key")
    item_id_value = raw.get("item_id")
    if item_id_value is None:
        item_id_value = key
    item_id = _safe_text(item_id_value, label="semantic_item_id")
    status = raw.get("status", "active")
    if not isinstance(status, str) or status not in SEMANTIC_STATUSES:
        raise ReferenceReplayError("semantic_status_invalid")
    return {
        "item_id": item_id,
        "key": key,
        "kind": kind,
        "statement": statement,
        "status": status,
        "evidence_ids": _string_list(
            raw.get("evidence_ids"),
            label="semantic_evidence_ids",
        ),
        "relevant_actions": _string_list(
            raw.get("relevant_actions"),
            label="semantic_relevant_actions",
        ),
        "source_event_ids": [event_id],
        "source_sequence": sequence,
    }


def _changed_fields(previous: Mapping[str, Any], current: Mapping[str, Any]) -> list[str]:
    return [
        field
        for field in (
            "item_id",
            "statement",
            "status",
            "evidence_ids",
            "relevant_actions",
        )
        if previous.get(field) != current.get(field)
    ]


def reconstruct_reference(
    history: Mapping[str, Any],
    *,
    next_action: str,
) -> dict[str, Any]:
    """Reconstruct explicit current state from the full canonical history."""

    if not isinstance(history, Mapping) or not isinstance(history.get("events"), list):
        raise ReferenceReplayError("canonical_history_invalid")
    next_action = _safe_text(next_action, label="next_action")
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    item_id_owners: dict[str, tuple[str, str]] = {}
    changes: list[dict[str, Any]] = []
    semantic_errors: list[str] = []
    seen_event_ids: set[str] = set()

    for expected_sequence, event in enumerate(history["events"]):
        if not isinstance(event, Mapping):
            semantic_errors.append("canonical_event_not_object")
            continue
        event_id = event.get("event_id")
        sequence = event.get("sequence")
        if not isinstance(event_id, str) or not event_id:
            semantic_errors.append("canonical_event_id_invalid")
            continue
        if event_id in seen_event_ids:
            semantic_errors.append(f"canonical_event_id_duplicate:{event_id}")
            continue
        seen_event_ids.add(event_id)
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence != expected_sequence
        ):
            semantic_errors.append(
                f"canonical_event_sequence_invalid:{event_id}"
            )
            continue
        attributes = event.get("attributes")
        raw_semantic = (
            attributes.get("semantic")
            if isinstance(attributes, Mapping)
            else None
        )
        if raw_semantic is None:
            continue
        try:
            item = _semantic(
                raw_semantic,
                event_id=event_id,
                sequence=sequence,
            )
        except (ReferenceReplayError, TypeError, ValueError) as exc:
            semantic_errors.append(str(exc))
            continue
        identity = (item["kind"], item["key"])
        owner = item_id_owners.get(item["item_id"])
        if owner is not None and owner != identity:
            semantic_errors.append(
                f"semantic_item_id_collision:{item['item_id']}"
            )
            continue
        item_id_owners[item["item_id"]] = identity
        previous = latest.get(identity)
        if previous is not None:
            changed_fields = _changed_fields(previous, item)
            if changed_fields:
                changes.append(
                    {
                        "kind": item["kind"],
                        "key": item["key"],
                        "changed_fields": changed_fields,
                        "from": previous["statement"],
                        "to": item["statement"],
                        "from_status": previous["status"],
                        "to_status": item["status"],
                        "from_event_ids": previous["source_event_ids"],
                        "to_event_ids": item["source_event_ids"],
                    }
                )
        latest[identity] = item

    all_items = sorted(
        latest.values(),
        key=lambda item: (
            item["source_sequence"],
            item["kind"],
            item["key"],
        ),
    )
    active_evidence: dict[str, dict[str, Any]] = {}
    for item in all_items:
        if item["kind"] == "evidence" and item["status"] == "active":
            active_evidence[item["item_id"]] = item
            active_evidence[item["key"]] = item

    relevant: list[dict[str, Any]] = []
    missing_support: list[dict[str, Any]] = []
    for item in all_items:
        if item["status"] != "active" or item["kind"] not in CURRENT_KINDS:
            continue
        if (
            item["kind"] in ACTION_SCOPED_KINDS
            and not _action_matches(item["relevant_actions"], next_action)
        ):
            continue
        missing_ids: list[str] = []
        incompatible_ids: list[str] = []
        if item["kind"] in SUPPORT_REQUIRED:
            if not item["evidence_ids"]:
                missing_ids = ["<explicit-evidence-reference-required>"]
            else:
                for evidence_id in item["evidence_ids"]:
                    supporting = active_evidence.get(evidence_id)
                    if supporting is None:
                        missing_ids.append(evidence_id)
                    elif not _action_matches(
                        supporting["relevant_actions"],
                        next_action,
                    ):
                        incompatible_ids.append(evidence_id)
        supported = not missing_ids and not incompatible_ids
        enriched = {
            **item,
            "support_complete": supported,
            "missing_evidence_ids": missing_ids,
            "incompatible_evidence_ids": incompatible_ids,
        }
        relevant.append(enriched)
        if not supported:
            missing_support.append(
                {
                    "item_id": item["item_id"],
                    "kind": item["kind"],
                    "key": item["key"],
                    "missing_evidence_ids": missing_ids,
                    "incompatible_evidence_ids": incompatible_ids,
                }
            )

    reference_body = {
        "source_history_sha256": history.get("source_sha256"),
        "next_action": next_action,
        "relevant_state": relevant,
        "decision_changes_observed": changes,
        "missing_support": missing_support,
        "semantic_errors": semantic_errors,
    }
    return {
        "schema": REFERENCE_SCHEMA,
        "source_history_sha256": history.get("source_sha256"),
        "next_action": next_action,
        "next_action_sha256": hashlib.sha256(
            next_action.encode("utf-8")
        ).hexdigest(),
        "semantic_item_count": len(all_items),
        "relevant_item_count": len(relevant),
        "relevant_state": relevant,
        "decision_changes_observed": changes,
        "missing_support": missing_support,
        "semantic_errors": semantic_errors,
        "reference_sha256": _json_hash(reference_body),
    }
