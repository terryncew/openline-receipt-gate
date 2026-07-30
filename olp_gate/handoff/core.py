"""OpenLine Handoff Check.

A handoff capsule may propose inherited state.  It may never certify its own
fidelity.  The receiving side independently replays the canonical source
history and compares the capsule with that reference before returning a
continuation disposition.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import stat
import subprocess
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import olp_canonical_json, sha256_hex, sign_olp_body, strict_json_load
from .adapters import HandoffAdapterError, load_history
from .reference_replay import REFERENCE_SCHEMA, reconstruct_reference


CAPSULE_SCHEMA = "openline.handoff.capsule.v2"
REPORT_SCHEMA = "openline.handoff.report.v2"
RECEIPT_SCHEMA = "openline.handoff.receipt.v2"
ARCHIVE_INDEX_SCHEMA = "openline.handoff.archive-index.v2"
RESTORE_SCHEMA = "openline.handoff.restore.v2"

DISPOSITIONS = {
    "SAFE_TO_CONTINUE",
    "DECISION_CHANGED",
    "EVIDENCE_MISSING",
    "UNDECIDABLE",
}
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
CURRENT_KINDS = {"decision", "constraint", "assumption", "open_question", "rejected_path", "artifact", "evidence"}
SUPPORT_REQUIRED = {"decision", "assumption"}
ACTION_SCOPED_KINDS = {"decision", "assumption", "artifact", "evidence"}
OPERATIONAL_KINDS = {"read", "search", "edit", "test", "command", "error", "tool_result", "compaction"}
MAX_OPERATIONAL_ITEMS = 250
UNSAFE_SEMANTIC_CHARS = frozenset(chr(code) for code in range(0, 32) if code not in (9, 10, 13)) | {chr(127), "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}
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
EXTRACTION_BOUNDARY = (
    "Only explicit OLP semantic markers or structured semantic objects are "
    "treated as decisions, evidence, constraints, assumptions, open "
    "questions, rejected paths, or artifacts. Ordinary prose is never "
    "upgraded into semantic state."
)


class HandoffCheckError(ValueError):
    """Raised for malformed Handoff Check inputs or unsafe state."""


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _json_hash(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _normalize_words(text: str) -> set[str]:
    token = []
    words: set[str] = set()
    for char in text.lower():
        if char.isalnum() or char in {"_", "-", "/", "."}:
            token.append(char)
        elif token:
            value = "".join(token).strip("._-/")
            if len(value) >= 3:
                words.add(value)
            token = []
    if token:
        value = "".join(token).strip("._-/")
        if len(value) >= 3:
            words.add(value)
    return words


def _action_matches(scopes: Sequence[str], next_action: str) -> bool:
    if not scopes:
        return True
    action_words = _normalize_words(next_action) - GENERIC_ACTION_WORDS
    if not action_words:
        return False
    for scope in scopes:
        if not isinstance(scope, str):
            continue
        scope_words = _normalize_words(scope) - GENERIC_ACTION_WORDS
        if scope_words and scope_words.issubset(action_words):
            return True
    return False


def _require_safe_semantic_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HandoffCheckError(f"{label}_invalid")
    if any(character in UNSAFE_SEMANTIC_CHARS for character in value):
        raise HandoffCheckError(f"{label}_contains_unsafe_control_characters")
    return value.strip()


def _string_list(value: Any, *, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise HandoffCheckError(f"{label}_invalid")
    cleaned: list[str] = []
    for index, item in enumerate(value):
        cleaned.append(_require_safe_semantic_text(item, label=f"{label}_{index}"))
    if len(cleaned) != len(set(cleaned)):
        raise HandoffCheckError(f"{label}_duplicates")
    return cleaned


def _validate_semantic(raw: Any, *, event_id: str, sequence: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise HandoffCheckError("semantic_not_object")
    allowed = {
        "kind",
        "item_id",
        "key",
        "statement",
        "status",
        "evidence_ids",
        "relevant_actions",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise HandoffCheckError(f"semantic_unknown_fields:{sorted(unknown)}")
    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in SEMANTIC_KINDS:
        raise HandoffCheckError("semantic_kind_invalid")
    statement = _require_safe_semantic_text(raw.get("statement"), label="semantic_statement")
    key_value = raw.get("key")
    if key_value is None:
        key_value = f"{kind}:{hashlib.sha256(statement.encode('utf-8')).hexdigest()[:20]}"
    key = _require_safe_semantic_text(key_value, label="semantic_key")
    item_id_value = raw.get("item_id")
    if item_id_value is None:
        item_id_value = key
    item_id = _require_safe_semantic_text(item_id_value, label="semantic_item_id")
    status = raw.get("status", "active")
    if not isinstance(status, str) or status not in SEMANTIC_STATUSES:
        raise HandoffCheckError("semantic_status_invalid")
    evidence_ids = _string_list(raw.get("evidence_ids"), label="semantic_evidence_ids")
    relevant_actions = _string_list(raw.get("relevant_actions"), label="semantic_relevant_actions")
    return {
        "item_id": item_id,
        "key": key,
        "kind": kind,
        "statement": statement,
        "status": status,
        "evidence_ids": evidence_ids,
        "relevant_actions": relevant_actions,
        "source_event_ids": [event_id],
        "source_sequence": sequence,
    }


def _extract_capsule_state(
    history: Mapping[str, Any],
    *,
    next_action: str,
) -> list[dict[str, Any]]:
    """Build the candidate capsule state without calling reference replay."""

    if not isinstance(history, Mapping) or not isinstance(history.get("events"), list):
        raise HandoffCheckError("canonical_history_invalid")
    next_action = _require_safe_semantic_text(next_action, label="next_action")
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for event in reversed(history["events"]):
        if not isinstance(event, Mapping):
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
            item = _validate_semantic(
                raw_semantic,
                event_id=str(event.get("event_id")),
                sequence=int(event.get("sequence")),
            )
        except (HandoffCheckError, TypeError, ValueError):
            continue
        identity = (item["kind"], item["key"])
        if identity not in latest:
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
        relevant.append(
            {
                **item,
                "support_complete": not missing_ids and not incompatible_ids,
                "missing_evidence_ids": missing_ids,
                "incompatible_evidence_ids": incompatible_ids,
            }
        )
    return relevant


def _build_archive_index(
    history: Mapping[str, Any],
    *,
    operational_event_ids: Sequence[str],
    operational_stats: Mapping[str, int],
) -> dict[str, Any]:
    """Derive the restoration index from every explicit semantic source event."""

    items: dict[str, dict[str, Any]] = {}
    semantic_errors: list[str] = []
    for event in history.get("events", []):
        if not isinstance(event, Mapping):
            semantic_errors.append("canonical_event_not_object")
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
            item = _validate_semantic(
                raw_semantic,
                event_id=str(event.get("event_id")),
                sequence=int(event.get("sequence")),
            )
        except (HandoffCheckError, TypeError, ValueError) as exc:
            semantic_errors.append(str(exc))
            continue
        identity = (item["kind"], item["key"])
        entry = items.get(item["item_id"])
        if entry is not None and (entry["kind"], entry["key"]) != identity:
            semantic_errors.append(
                f"semantic_item_id_collision:{item['item_id']}"
            )
            continue
        if entry is None:
            entry = {
                "kind": item["kind"],
                "key": item["key"],
                "event_ids": [],
                "latest_semantic_sha256": None,
            }
            items[item["item_id"]] = entry
        entry["event_ids"].extend(item["source_event_ids"])
        entry["latest_semantic_sha256"] = _json_hash(
            {
                key: item[key]
                for key in (
                    "item_id",
                    "key",
                    "kind",
                    "statement",
                    "status",
                    "evidence_ids",
                    "relevant_actions",
                )
            }
        )

    archive_index: dict[str, Any] = {
        "schema": ARCHIVE_INDEX_SCHEMA,
        "source_history_sha256": history.get("source_sha256"),
        "items": items,
        "operational_event_ids": list(operational_event_ids),
        "restorable_from_source_history": True,
        "operational_stats": dict(operational_stats),
        "semantic_errors": semantic_errors,
    }
    archive_index["archive_index_sha256"] = _json_hash(archive_index)
    return archive_index


def _operational_state(history: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    occurrences: Counter[tuple[str, str]] = Counter()
    for event in history.get("events", []):
        if not isinstance(event, Mapping):
            continue
        kind = event.get("kind")
        if kind not in OPERATIONAL_KINDS:
            continue
        target = event.get("target")
        tool = event.get("tool")
        identity_target = str(target or tool or "<unscoped>")
        identity = (str(kind), identity_target)
        occurrences[identity] += 1
        latest[identity] = {
            "kind": kind,
            "tool": tool if isinstance(tool, str) else None,
            "target": target if isinstance(target, str) else None,
            "event_id": str(event.get("event_id")),
            "sequence": int(event.get("sequence", 0)),
            "content_sha256": event.get("content_sha256"),
        }
    items = sorted(latest.values(), key=lambda item: item["sequence"])
    if len(items) > MAX_OPERATIONAL_ITEMS:
        items = items[-MAX_OPERATIONAL_ITEMS:]
    repeated_reads_searches = sum(
        count - 1
        for (kind, _target), count in occurrences.items()
        if kind in {"read", "search"} and count > 1
    )
    repeated_operations = sum(count - 1 for count in occurrences.values() if count > 1)
    return items, {
        "repeated_reads_or_searches": repeated_reads_searches,
        "repeated_operations": repeated_operations,
        "unique_operational_states": len(latest),
    }


def _repo_state(repo: str | Path | None) -> dict[str, Any]:
    if repo is None:
        return {"status": "NOT_BOUND", "path": None, "head": None, "worktree_sha256": None}
    path = Path(repo).expanduser().resolve()
    if not path.is_dir():
        raise HandoffCheckError("repo_not_directory")
    try:
        head = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status_output = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            check=True,
            capture_output=True,
        ).stdout
        tracked_diff = subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "diff",
                "--binary",
                "--full-index",
                "--no-ext-diff",
                "HEAD",
                "--",
            ],
            check=True,
            capture_output=True,
        ).stdout
        untracked_output = subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            check=True,
            capture_output=True,
        ).stdout
        worktree_digest = hashlib.sha256()
        for label, payload in (
            (b"status\0", status_output),
            (b"tracked-diff\0", tracked_diff),
            (b"untracked-list\0", untracked_output),
        ):
            worktree_digest.update(label)
            worktree_digest.update(len(payload).to_bytes(8, "big"))
            worktree_digest.update(payload)
        for raw_relative in sorted(
            item for item in untracked_output.split(b"\0") if item
        ):
            relative = os.fsdecode(raw_relative)
            untracked_path = path / relative
            file_stat = untracked_path.lstat()
            worktree_digest.update(b"untracked-entry\0")
            worktree_digest.update(len(raw_relative).to_bytes(8, "big"))
            worktree_digest.update(raw_relative)
            worktree_digest.update(file_stat.st_mode.to_bytes(8, "big"))
            if stat.S_ISREG(file_stat.st_mode):
                with untracked_path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        worktree_digest.update(chunk)
            elif stat.S_ISLNK(file_stat.st_mode):
                target = os.fsencode(os.readlink(untracked_path))
                worktree_digest.update(len(target).to_bytes(8, "big"))
                worktree_digest.update(target)
        return {
            "status": "BOUND",
            "path": str(path),
            "head": head,
            "worktree_sha256": worktree_digest.hexdigest(),
        }
    except (OSError, subprocess.CalledProcessError) as exc:
        raise HandoffCheckError("repo_git_state_unavailable") from exc


def build_capsule(
    history: Mapping[str, Any],
    *,
    next_action: str,
    repo_state: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    next_action = _require_safe_semantic_text(next_action, label="next_action")
    operational, operational_stats = _operational_state(history)
    semantic_state = _extract_capsule_state(
        history,
        next_action=next_action,
    )
    capsule: dict[str, Any] = {
        "schema": CAPSULE_SCHEMA,
        "source": history.get("source"),
        "source_history_sha256": history.get("source_sha256"),
        "source_event_count": history.get("event_count"),
        "next_action": next_action,
        "next_action_sha256": sha256_hex(next_action.encode("utf-8")),
        "repo_state": dict(repo_state),
        "semantic_state": semantic_state,
        "operational_state": operational,
        "extraction_boundary": EXTRACTION_BOUNDARY,
    }
    capsule["capsule_sha256"] = _json_hash({key: value for key, value in capsule.items() if key != "capsule_sha256"})
    archive_index = _build_archive_index(
        history,
        operational_event_ids=[item["event_id"] for item in operational],
        operational_stats=operational_stats,
    )
    return capsule, archive_index


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_capsule_semantic_item(
    raw: Any,
    *,
    index: int,
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise HandoffCheckError(f"capsule_semantic_item_not_object:{index}")
    expected = {
        "item_id",
        "key",
        "kind",
        "statement",
        "status",
        "evidence_ids",
        "relevant_actions",
        "source_event_ids",
        "source_sequence",
        "support_complete",
        "missing_evidence_ids",
        "incompatible_evidence_ids",
    }
    if set(raw) != expected:
        raise HandoffCheckError(f"capsule_semantic_item_shape_invalid:{index}")
    validated = _validate_semantic(
        {
            key: raw[key]
            for key in (
                "item_id",
                "key",
                "kind",
                "statement",
                "status",
                "evidence_ids",
                "relevant_actions",
            )
        },
        event_id="<capsule-validation>",
        sequence=0,
    )
    for key in (
        "item_id",
        "key",
        "kind",
        "statement",
        "status",
        "evidence_ids",
        "relevant_actions",
    ):
        if raw.get(key) != validated[key]:
            raise HandoffCheckError(
                f"capsule_semantic_item_not_canonical:{index}:{key}"
            )
    source_event_ids = _string_list(
        raw.get("source_event_ids"),
        label=f"capsule_source_event_ids_{index}",
    )
    if not source_event_ids:
        raise HandoffCheckError(
            f"capsule_source_event_ids_empty:{index}"
        )
    source_sequence = raw.get("source_sequence")
    if (
        not isinstance(source_sequence, int)
        or isinstance(source_sequence, bool)
        or source_sequence < 0
    ):
        raise HandoffCheckError(
            f"capsule_source_sequence_invalid:{index}"
        )
    if not isinstance(raw.get("support_complete"), bool):
        raise HandoffCheckError(
            f"capsule_support_complete_invalid:{index}"
        )
    missing = _string_list(
        raw.get("missing_evidence_ids"),
        label=f"capsule_missing_evidence_ids_{index}",
    )
    incompatible = _string_list(
        raw.get("incompatible_evidence_ids"),
        label=f"capsule_incompatible_evidence_ids_{index}",
    )
    return {
        **{
            key: validated[key]
            for key in (
                "item_id",
                "key",
                "kind",
                "statement",
                "status",
                "evidence_ids",
                "relevant_actions",
            )
        },
        "source_event_ids": source_event_ids,
        "source_sequence": source_sequence,
        "support_complete": raw["support_complete"],
        "missing_evidence_ids": missing,
        "incompatible_evidence_ids": incompatible,
    }


def _validate_capsule(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HandoffCheckError("capsule_not_object")
    capsule = dict(value)
    expected = {
        "schema",
        "source",
        "source_history_sha256",
        "source_event_count",
        "next_action",
        "next_action_sha256",
        "repo_state",
        "semantic_state",
        "operational_state",
        "extraction_boundary",
        "capsule_sha256",
    }
    if set(capsule) != expected:
        raise HandoffCheckError("capsule_shape_invalid")
    if capsule.get("schema") != CAPSULE_SCHEMA:
        raise HandoffCheckError("capsule_schema_invalid")
    expected_hash = _json_hash(
        {
            key: value
            for key, value in capsule.items()
            if key != "capsule_sha256"
        }
    )
    if capsule.get("capsule_sha256") != expected_hash:
        raise HandoffCheckError("capsule_hash_mismatch")
    if not _is_sha256(capsule.get("source_history_sha256")):
        raise HandoffCheckError("capsule_source_history_hash_invalid")
    source_event_count = capsule.get("source_event_count")
    if (
        not isinstance(source_event_count, int)
        or isinstance(source_event_count, bool)
        or source_event_count < 0
    ):
        raise HandoffCheckError("capsule_source_event_count_invalid")
    next_action = _require_safe_semantic_text(
        capsule.get("next_action"),
        label="next_action",
    )
    if capsule.get("next_action_sha256") != sha256_hex(
        next_action.encode("utf-8")
    ):
        raise HandoffCheckError("capsule_next_action_hash_invalid")
    if capsule.get("extraction_boundary") != EXTRACTION_BOUNDARY:
        raise HandoffCheckError("capsule_extraction_boundary_invalid")
    repo_state = capsule.get("repo_state")
    if not isinstance(repo_state, Mapping) or set(repo_state) != {
        "status",
        "path",
        "head",
        "worktree_sha256",
    }:
        raise HandoffCheckError("capsule_repo_state_invalid")
    if repo_state.get("status") not in {"BOUND", "NOT_BOUND"}:
        raise HandoffCheckError("capsule_repo_status_invalid")
    if not isinstance(capsule.get("semantic_state"), list):
        raise HandoffCheckError("capsule_semantic_state_invalid")
    semantic_state: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    item_ids: set[str] = set()
    for index, item in enumerate(capsule["semantic_state"]):
        validated_item = _validate_capsule_semantic_item(
            item,
            index=index,
        )
        identity = (
            validated_item["kind"],
            validated_item["key"],
        )
        if identity in identities:
            raise HandoffCheckError(
                f"capsule_semantic_identity_duplicate:{index}"
            )
        if validated_item["item_id"] in item_ids:
            raise HandoffCheckError(
                f"capsule_semantic_item_id_duplicate:{index}"
            )
        identities.add(identity)
        item_ids.add(validated_item["item_id"])
        semantic_state.append(validated_item)
    if not isinstance(capsule.get("operational_state"), list):
        raise HandoffCheckError("capsule_operational_state_invalid")
    capsule["semantic_state"] = semantic_state
    capsule["repo_state"] = dict(repo_state)
    return capsule


def compare_capsule_to_reference(
    capsule_value: Mapping[str, Any],
    history: Mapping[str, Any],
    *,
    repo_state: Mapping[str, Any],
    expected_next_action: str | None = None,
) -> dict[str, Any]:
    capsule = _validate_capsule(capsule_value)
    capsule_next_action = _require_safe_semantic_text(
        capsule.get("next_action"),
        label="next_action",
    )
    blockers: list[str] = []
    if expected_next_action is None:
        next_action = capsule_next_action
        blockers.append("next_action_not_receiver_pinned")
    else:
        next_action = _require_safe_semantic_text(
            expected_next_action,
            label="expected_next_action",
        )
        if next_action != capsule_next_action:
            blockers.append("next_action_changed_since_capsule")
    reference = reconstruct_reference(history, next_action=next_action)
    changed: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []

    source_changed = (
        history.get("source_sha256")
        != capsule.get("source_history_sha256")
    )
    if source_changed:
        # A changed history is allowed for inspection, but the reference must
        # then decide whether the inherited state has changed.
        blockers.append("source_history_changed_since_capsule")
    if history.get("source") != capsule.get("source"):
        blockers.append("capsule_source_adapter_mismatch")
    if not source_changed and history.get("event_count") != capsule.get(
        "source_event_count"
    ):
        blockers.append("source_event_count_mismatch")
    if reference["next_action_sha256"] != capsule.get("next_action_sha256"):
        blockers.append("next_action_hash_mismatch")
    if dict(capsule["repo_state"]) != dict(repo_state):
        blockers.append("repo_state_changed_since_capsule")

    expected_operational_state, _ = _operational_state(history)
    if capsule.get("operational_state") != expected_operational_state:
        blockers.append(
            "operational_state_changed_since_capsule"
            if source_changed
            else "operational_state_mismatch"
        )

    ref_by_identity = {
        (item["kind"], item["key"]): item for item in reference["relevant_state"]
    }
    cap_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for item in capsule["semantic_state"]:
        cap_by_identity[(item["kind"], item["key"])] = item

    for identity, reference_item in ref_by_identity.items():
        capsule_item = cap_by_identity.get(identity)
        if capsule_item is None:
            missing.append(
                {
                    "kind": reference_item["kind"],
                    "key": reference_item["key"],
                    "reason": "continuation_item_missing_from_capsule",
                }
            )
            continue
        if capsule_item == reference_item:
            continue
        changed_fields = sorted(
            key
            for key in set(capsule_item) | set(reference_item)
            if capsule_item.get(key) != reference_item.get(key)
        )
        if any(
            field in changed_fields
            for field in ("statement", "status")
        ):
            changed.append(
                {
                    "kind": reference_item["kind"],
                    "key": reference_item["key"],
                    "capsule_statement": capsule_item.get("statement"),
                    "reference_statement": reference_item.get("statement"),
                    "capsule_status": capsule_item.get("status"),
                    "reference_status": reference_item.get("status"),
                    "changed_fields": changed_fields,
                }
            )
        else:
            missing.append(
                {
                    "kind": reference_item["kind"],
                    "key": reference_item["key"],
                    "reason": "semantic_boundary_changed",
                    "changed_fields": changed_fields,
                }
            )

    for identity, capsule_item in cap_by_identity.items():
        if identity in ref_by_identity:
            continue
        history_change = next(
            (
                item
                for item in reversed(reference["decision_changes_observed"])
                if item["kind"] == identity[0]
                and item["key"] == identity[1]
                and item["from"] == capsule_item.get("statement")
            ),
            None,
        )
        if history_change:
            changed.append(
                {
                    "kind": identity[0],
                    "key": identity[1],
                    "capsule_statement": capsule_item.get("statement"),
                    "reference_statement": history_change["to"],
                    "capsule_status": capsule_item.get("status"),
                    "reference_status": history_change["to_status"],
                    "changed_fields": history_change["changed_fields"],
                }
            )
        else:
            missing.append(
                {
                    "kind": identity[0],
                    "key": identity[1],
                    "reason": "capsule_item_no_longer_established",
                }
            )

    missing.extend(reference["missing_support"])
    if not reference["relevant_state"]:
        missing.append(
            {
                "reason": "no_explicit_decision_evidence_in_history",
                "boundary": "ordinary_prose_not_promoted_to_semantic_state",
            }
        )

    parse_errors = history.get("parse_errors") or []
    if parse_errors:
        blockers.append("history_contains_unparsed_records")
    blockers.extend(f"semantic_error:{error}" for error in reference["semantic_errors"])
    if history.get("adapter_confidence") == "low" and history.get("source") == "generic":
        blockers.append("generic_adapter_auto_detection_low_confidence")

    informational_blockers = {
        "source_history_changed_since_capsule",
        "operational_state_changed_since_capsule",
    }
    hard_blockers = [
        item
        for item in blockers
        if item not in informational_blockers
    ]
    if hard_blockers:
        disposition = "UNDECIDABLE"
    elif changed:
        disposition = "DECISION_CHANGED"
    elif missing:
        disposition = "EVIDENCE_MISSING"
    elif any(item in informational_blockers for item in blockers):
        # The source changed but all inherited state still matches.  We cannot
        # certify exact history identity, so stay fail-closed.
        disposition = "UNDECIDABLE"
    else:
        disposition = "SAFE_TO_CONTINUE"

    return {
        "disposition": disposition,
        "reference": reference,
        "decision_changes": changed,
        "evidence_missing": missing,
        "blockers": blockers,
    }


def _metrics(history: Mapping[str, Any], capsule: Mapping[str, Any], archive_index: Mapping[str, Any]) -> dict[str, Any]:
    source_bytes = int(history.get("source_bytes") or 0)
    capsule_bytes = len(_json_bytes(capsule))
    if source_bytes <= 0:
        excluded_bp = 0
    else:
        included_bp = min(10000, (capsule_bytes * 10000) // source_bytes)
        excluded_bp = max(0, 10000 - included_bp)
    stats = archive_index.get("operational_stats") if isinstance(archive_index.get("operational_stats"), Mapping) else {}
    return {
        "source_bytes": source_bytes,
        "capsule_bytes": capsule_bytes,
        "context_excluded_basis_points": excluded_bp,
        "source_events": int(history.get("event_count") or 0),
        "capsule_semantic_items": len(capsule.get("semantic_state", [])),
        "capsule_operational_items": len(capsule.get("operational_state", [])),
        "repeated_reads_or_searches_observed": int(stats.get("repeated_reads_or_searches", 0)),
        "repeated_operations_observed": int(stats.get("repeated_operations", 0)),
        "restorable_item_count": len(archive_index.get("items", {})) if isinstance(archive_index.get("items"), Mapping) else 0,
        "restorable_from_source_history": True,
    }


def _capsule_markdown(capsule: Mapping[str, Any], report: Mapping[str, Any]) -> str:
    lines = [
        "# OpenLine Verified Handoff Capsule",
        "",
        f"Disposition: **{report['disposition'].replace('_', ' ')}**",
        "",
        "## Next action",
        str(capsule["next_action"]),
        "",
        "## Inherited state",
    ]
    semantic = capsule.get("semantic_state", [])
    if not semantic:
        lines.append("No explicit decision/evidence state was established. Do not infer missing rationale from this capsule.")
    else:
        for item in semantic:
            evidence = item.get("evidence_ids") or []
            suffix = f" [evidence: {', '.join(evidence)}]" if evidence else ""
            lines.append(f"- {str(item.get('kind')).upper()} `{item.get('key')}`: {item.get('statement')}{suffix}")
    lines.extend(
        [
            "",
            "## Operational state",
        ]
    )
    operational = capsule.get("operational_state", [])
    if not operational:
        lines.append("No bounded operational state recorded.")
    else:
        for item in operational:
            target = item.get("target") or item.get("tool") or "unscoped"
            lines.append(f"- {str(item.get('kind')).upper()}: {target} @ event `{item.get('event_id')}`")
    lines.extend(
        [
            "",
            "## Boundary",
            str(capsule.get("extraction_boundary")),
            "",
            f"Source history SHA-256: `{capsule.get('source_history_sha256')}`",
            f"Capsule SHA-256: `{capsule.get('capsule_sha256')}`",
            "",
        ]
    )
    return "\n".join(lines)


def _proof_html(capsule: Mapping[str, Any], report: Mapping[str, Any]) -> str:
    metrics = report["metrics"]
    percent = metrics["context_excluded_basis_points"] / 100
    disposition = str(report["disposition"]).replace("_", " ")
    source = html.escape(str(capsule.get("source")))
    next_action = html.escape(str(capsule.get("next_action")))
    return f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>OpenLine Handoff Check</title>
<style>body{{font-family:system-ui,-apple-system,sans-serif;max-width:760px;margin:48px auto;padding:0 22px;line-height:1.45}}.status{{font-size:2rem;font-weight:800;margin:.2em 0 1em}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}.card{{border:1px solid #bbb;border-radius:12px;padding:14px}}code{{overflow-wrap:anywhere}}small{{color:#555}}</style></head>
<body><small>OPENLINE HANDOFF CHECK</small><div class=\"status\">{html.escape(disposition)}</div>
<div class=\"card\"><strong>{source} → fresh agent</strong><p><small>NEXT ACTION</small><br>{next_action}</p></div>
<div class=\"grid\"><div class=\"card\"><strong>{metrics['capsule_semantic_items']}</strong><br>semantic items preserved</div><div class=\"card\"><strong>{metrics['repeated_reads_or_searches_observed']}</strong><br>repeated reads/searches observed</div><div class=\"card\"><strong>{percent:.2f}%</strong><br>source bytes left outside capsule</div><div class=\"card\"><strong>{metrics['restorable_item_count']}</strong><br>indexed items restorable</div></div>
<p><small>SOURCE HISTORY SHA-256</small><br><code>{html.escape(str(capsule.get('source_history_sha256')))}</code></p>
<p><small>CAPSULE SHA-256</small><br><code>{html.escape(str(capsule.get('capsule_sha256')))}</code></p>
<p><strong>Change the agent without losing why the work was done.</strong></p>
</body></html>\n"""


def _receipt_body(capsule: Mapping[str, Any], report: Mapping[str, Any], artifact_hashes: Mapping[str, str]) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "disposition": report["disposition"],
        "source": capsule.get("source"),
        "source_history_sha256": capsule.get("source_history_sha256"),
        "capsule_sha256": capsule.get("capsule_sha256"),
        "next_action_sha256": capsule.get("next_action_sha256"),
        "repo_state": capsule.get("repo_state"),
        "metrics": report["metrics"],
        "decision_change_count": len(report.get("decision_changes", [])),
        "evidence_missing_count": len(report.get("evidence_missing", [])),
        "blocker_count": len(report.get("blockers", [])),
        "artifact_hashes": dict(artifact_hashes),
        "claim_boundary": "The receipt certifies deterministic comparison against the supplied local history only. It does not prove the history is complete, truthful, or sufficient for real-world task success.",
    }


def write_handoff_outputs(
    history_path: str | Path,
    output_dir: str | Path,
    *,
    next_action: str,
    source: str = "auto",
    repo: str | Path | None = None,
    signing_key: Ed25519PrivateKey | None = None,
) -> dict[str, Any]:
    history = load_history(history_path, source=source)
    capsule_repo_state = _repo_state(repo)
    capsule, archive_index = build_capsule(
        history,
        next_action=next_action,
        repo_state=capsule_repo_state,
    )
    receiver_repo_state = _repo_state(repo)
    comparison = compare_capsule_to_reference(
        capsule,
        history,
        repo_state=receiver_repo_state,
        expected_next_action=next_action,
    )
    metrics = _metrics(history, capsule, archive_index)
    report = {
        "schema": REPORT_SCHEMA,
        "disposition": comparison["disposition"],
        "source": history.get("source"),
        "detected_source": history.get("detected_source"),
        "adapter_confidence": history.get("adapter_confidence"),
        "source_history_sha256": history.get("source_sha256"),
        "next_action": next_action,
        "capsule_sha256": capsule["capsule_sha256"],
        "reference_sha256": comparison["reference"]["reference_sha256"],
        "decision_changes": comparison["decision_changes"],
        "evidence_missing": comparison["evidence_missing"],
        "blockers": comparison["blockers"],
        "metrics": metrics,
        "boundary": "The capsule cannot approve itself; the report is computed from an independent replay of the full canonicalized source history.",
    }
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    _write_json(output / "capsule.json", capsule)
    _write_json(output / "reference_replay.json", comparison["reference"])
    _write_json(output / "archive_index.json", archive_index)
    _write_json(output / "handoff_report.json", report)
    (output / "capsule.md").write_text(_capsule_markdown(capsule, report), encoding="utf-8")
    (output / "proof-card.html").write_text(_proof_html(capsule, report), encoding="utf-8")

    artifact_hashes = {
        name: hashlib.sha256((output / name).read_bytes()).hexdigest()
        for name in ("capsule.json", "reference_replay.json", "archive_index.json", "handoff_report.json", "capsule.md", "proof-card.html")
    }
    receipt_body = _receipt_body(capsule, report, artifact_hashes)
    if signing_key is not None:
        signed_body = {**receipt_body, "proof_mode": "SIGNED_ED25519"}
        receipt: dict[str, Any] = sign_olp_body(signed_body, signing_key)
    else:
        unsigned_body = {**receipt_body, "proof_mode": "UNSIGNED_LOCAL_HASH_BOUND"}
        receipt = {
            **unsigned_body,
            "body_sha256": sha256_hex(olp_canonical_json(unsigned_body)),
        }
    _write_json(output / "continuation_receipt.json", receipt)

    return {
        "disposition": report["disposition"],
        "output": str(output),
        "source": history.get("source"),
        "source_history_sha256": history.get("source_sha256"),
        "capsule_sha256": capsule["capsule_sha256"],
        "receipt_sha256": hashlib.sha256((output / "continuation_receipt.json").read_bytes()).hexdigest(),
        "metrics": metrics,
        "decision_change_count": len(report["decision_changes"]),
        "evidence_missing_count": len(report["evidence_missing"]),
        "blocker_count": len(report["blockers"]),
    }


def inspect_handoff(
    history_path: str | Path,
    capsule_path: str | Path,
    *,
    next_action: str | None = None,
    source: str = "auto",
    repo: str | Path | None = None,
) -> dict[str, Any]:
    history = load_history(history_path, source=source)
    capsule = strict_json_load(capsule_path)
    repo_state_before = _repo_state(repo)
    comparison = compare_capsule_to_reference(
        capsule,
        history,
        repo_state=repo_state_before,
        expected_next_action=next_action,
    )
    repo_state_after = _repo_state(repo)
    if repo_state_after != repo_state_before:
        comparison["blockers"].append(
            "repo_state_changed_during_inspection"
        )
        comparison["disposition"] = "UNDECIDABLE"
    return {
        "disposition": comparison["disposition"],
        "source_history_sha256": history.get("source_sha256"),
        "capsule_sha256": capsule.get("capsule_sha256") if isinstance(capsule, Mapping) else None,
        "decision_changes": comparison["decision_changes"],
        "evidence_missing": comparison["evidence_missing"],
        "blockers": comparison["blockers"],
        "reference_sha256": comparison["reference"]["reference_sha256"],
    }


def restore_items(
    handoff_dir: str | Path,
    history_path: str | Path,
    item_ids: Sequence[str],
    *,
    source: str = "auto",
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    if (
        isinstance(item_ids, (str, bytes, bytearray))
        or not isinstance(item_ids, Sequence)
        or not item_ids
        or not all(isinstance(item, str) and item for item in item_ids)
        or len(item_ids) != len(set(item_ids))
    ):
        raise HandoffCheckError("restore_item_ids_invalid")
    handoff = Path(handoff_dir).expanduser().resolve()
    archive_index = strict_json_load(handoff / "archive_index.json")
    if not isinstance(archive_index, Mapping) or archive_index.get("schema") != ARCHIVE_INDEX_SCHEMA:
        raise HandoffCheckError("archive_index_invalid")
    history = load_history(history_path, source=source)
    if history.get("source_sha256") != archive_index.get("source_history_sha256"):
        raise HandoffCheckError("restore_history_hash_mismatch")
    if history.get("parse_errors"):
        raise HandoffCheckError("restore_history_uninterpretable")
    operational, operational_stats = _operational_state(history)
    expected_archive_index = _build_archive_index(
        history,
        operational_event_ids=[
            item["event_id"]
            for item in operational
        ],
        operational_stats=operational_stats,
    )
    if dict(archive_index) != expected_archive_index:
        raise HandoffCheckError("archive_index_mismatch")
    if archive_index.get("semantic_errors"):
        raise HandoffCheckError("restore_semantic_state_uninterpretable")
    items = archive_index.get("items")
    if not isinstance(items, Mapping):
        raise HandoffCheckError("archive_index_items_invalid")
    wanted_event_ids: list[str] = []
    missing_item_ids: list[str] = []
    for item_id in item_ids:
        entry = items.get(item_id)
        event_ids = (
            entry.get("event_ids")
            if isinstance(entry, Mapping)
            else None
        )
        if (
            not isinstance(event_ids, list)
            or not event_ids
            or not all(
                isinstance(event_id, str) and event_id
                for event_id in event_ids
            )
        ):
            missing_item_ids.append(item_id)
            continue
        wanted_event_ids.extend(event_ids)
    event_map = {
        str(event.get("event_id")): event
        for event in history.get("events", [])
        if isinstance(event, Mapping)
    }
    absent_event_ids = [
        event_id
        for event_id in wanted_event_ids
        if event_id not in event_map
    ]
    if absent_event_ids:
        raise HandoffCheckError("archive_index_event_missing")
    restored_events = [
        event_map[event_id]
        for event_id in wanted_event_ids
    ]
    result = {
        "schema": RESTORE_SCHEMA,
        "source_history_sha256": history.get("source_sha256"),
        "requested_item_ids": list(item_ids),
        "missing_item_ids": missing_item_ids,
        "restored_event_count": len(restored_events),
        "events": restored_events,
    }
    result["restoration_sha256"] = _json_hash(result)
    if output_path is not None:
        _write_json(Path(output_path).expanduser().resolve(), result)
    return result
