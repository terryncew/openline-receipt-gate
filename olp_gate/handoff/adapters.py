"""Local, fail-closed adapters for OpenLine Handoff Check.

The adapter boundary converts vendor histories into a small observable event
stream.  It deliberately does not infer decisions from ordinary prose.  A
history can carry explicit semantic state either as a generic ``semantic``
object or as an ``OLP_*`` marker in visible text.  Everything else remains
operational telemetry.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..crypto import strict_json_loads


CANONICAL_EVENT_SCHEMA = "openline.handoff.canonical-event.v1"
HISTORY_SCHEMA = "openline.handoff.canonical-history.v1"
SUPPORTED_SOURCES = {"auto", "claude-code", "codex", "generic"}
MAX_PREVIEW_CHARS = 4000
MAX_JSON_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_JSONL_LINE_BYTES = 8 * 1024 * 1024

_SEMANTIC_MARKER = re.compile(
    r"^OLP_(DECISION|EVIDENCE|CONSTRAINT|ASSUMPTION|OPEN_QUESTION|REJECTED_PATH)"
    r"(?:\[([A-Za-z0-9._:/-]{1,160})\])?:\s*(.+?)\s*$"
)
_CONTROL_DISPLAY = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x1b]")
_BIDI_DISPLAY = re.compile(r"[\u202a-\u202e\u2066-\u2069]")


class HandoffAdapterError(ValueError):
    """Raised when a history cannot be safely adapted."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_value(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _clean_display(value: Any, *, limit: int = MAX_PREVIEW_CHARS) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            text = repr(value)
    else:
        text = str(value)
    text = _CONTROL_DISPLAY.sub("�", text)
    text = _BIDI_DISPLAY.sub("�", text)
    if len(text) > limit:
        return text[:limit] + "…"
    return text


def _extract_text(value: Any) -> str | None:
    if isinstance(value, str):
        return _clean_display(value)
    if isinstance(value, Mapping):
        for key in ("text", "content", "message", "output", "result"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return _clean_display(candidate)
        return _clean_display(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        pieces: list[str] = []
        for item in value:
            if isinstance(item, str):
                pieces.append(item)
            elif isinstance(item, Mapping):
                candidate = item.get("text")
                if isinstance(candidate, str):
                    pieces.append(candidate)
        if pieces:
            return _clean_display("\n".join(pieces))
    return None


def _target_from_mapping(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    for key in (
        "file_path",
        "path",
        "target",
        "uri",
        "url",
        "query",
        "pattern",
        "command",
        "cmd",
    ):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate:
            return _clean_display(candidate, limit=512)
    return None


def _tool_kind(name: str | None, payload: Any = None) -> str:
    lowered = (name or "").lower()
    if any(token in lowered for token in ("read", "cat", "open_file", "view")):
        return "read"
    if any(token in lowered for token in ("grep", "search", "find", "glob", "rg")):
        return "search"
    if any(token in lowered for token in ("edit", "write", "patch", "replace", "apply")):
        return "edit"
    if any(token in lowered for token in ("test", "pytest", "unittest")):
        return "test"
    if any(token in lowered for token in ("bash", "shell", "exec", "command", "terminal")):
        command = _target_from_mapping(payload)
        if command and any(token in command.lower() for token in ("pytest", "unittest", "npm test", "cargo test", "go test")):
            return "test"
        return "command"
    return "tool_call"


def _semantic_from_text(text: str | None) -> dict[str, Any] | None:
    if not text:
        return None
    for line in text.splitlines():
        match = _SEMANTIC_MARKER.match(line.strip())
        if not match:
            continue
        kind = match.group(1).lower()
        key = match.group(2)
        remainder = match.group(3)
        statement, sep, metadata = remainder.partition(" || ")
        semantic: dict[str, Any] = {
            "kind": kind,
            "key": key or f"marker:{hashlib.sha256(statement.encode('utf-8')).hexdigest()[:16]}",
            "statement": statement.strip(),
            "status": "active",
            "evidence_ids": [],
            "relevant_actions": [],
        }
        if sep:
            for part in metadata.split(";"):
                name, equals, value = part.strip().partition("=")
                if not equals:
                    continue
                values = [item.strip() for item in value.split(",") if item.strip()]
                if name == "evidence":
                    semantic["evidence_ids"] = values
                elif name == "action":
                    semantic["relevant_actions"] = values
        return semantic
    return None


def _semantic_from_generic(record: Mapping[str, Any]) -> dict[str, Any] | None:
    semantic = record.get("semantic")
    if not isinstance(semantic, Mapping):
        return None
    return dict(semantic)


def _event(
    *,
    sequence: int,
    event_id: str,
    timestamp: Any,
    actor: str,
    kind: str,
    tool: str | None = None,
    target: str | None = None,
    text: str | None = None,
    content: Any = None,
    attributes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": CANONICAL_EVENT_SCHEMA,
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": timestamp if isinstance(timestamp, str) and timestamp else None,
        "actor": actor,
        "kind": kind,
        "tool": tool,
        "target": target,
        "text": _clean_display(text),
        "content_sha256": _hash_value(content if content is not None else {"kind": kind, "text": text}),
        "attributes": dict(attributes or {}),
    }


def _claude_events(record: Mapping[str, Any], record_index: int, start: int) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    record_type = record.get("type")
    base_id = str(record.get("uuid") or f"claude-{record_index}")
    timestamp = record.get("timestamp")
    message = record.get("message")
    content = message.get("content") if isinstance(message, Mapping) else None

    common = {
        "source_record_index": record_index,
        "session_id": record.get("sessionId"),
        "cwd": _clean_display(record.get("cwd"), limit=512),
        "git_branch": _clean_display(record.get("gitBranch"), limit=256),
    }

    if record_type in {"assistant", "user"} and isinstance(content, list):
        for block_index, block in enumerate(content):
            if not isinstance(block, Mapping):
                continue
            block_type = block.get("type")
            event_id = f"{base_id}:{block_index}"
            if block_type in {"text", "thinking"}:
                text = _extract_text(block)
                attributes = dict(common)
                semantic = _semantic_from_text(text)
                if semantic:
                    attributes["semantic"] = semantic
                events.append(
                    _event(
                        sequence=start + len(events),
                        event_id=event_id,
                        timestamp=timestamp,
                        actor=str(record_type),
                        kind="message" if block_type == "text" else "reasoning_summary",
                        text=text,
                        content=block,
                        attributes=attributes,
                    )
                )
            elif block_type == "tool_use":
                name = block.get("name") if isinstance(block.get("name"), str) else None
                tool_input = block.get("input")
                events.append(
                    _event(
                        sequence=start + len(events),
                        event_id=event_id,
                        timestamp=timestamp,
                        actor="assistant",
                        kind=_tool_kind(name, tool_input),
                        tool=name,
                        target=_target_from_mapping(tool_input),
                        text=None,
                        content=block,
                        attributes={**common, "tool_use_id": block.get("id")},
                    )
                )
            elif block_type == "tool_result":
                text = _extract_text(block.get("content"))
                is_error = block.get("is_error") is True
                events.append(
                    _event(
                        sequence=start + len(events),
                        event_id=event_id,
                        timestamp=timestamp,
                        actor="tool",
                        kind="error" if is_error else "tool_result",
                        text=text,
                        content=block,
                        attributes={**common, "tool_use_id": block.get("tool_use_id")},
                    )
                )
        return events

    if record_type in {"assistant", "user"}:
        text = _extract_text(content if content is not None else message)
        attributes = dict(common)
        semantic = _semantic_from_text(text)
        if semantic:
            attributes["semantic"] = semantic
        events.append(
            _event(
                sequence=start,
                event_id=base_id,
                timestamp=timestamp,
                actor=str(record_type),
                kind="message",
                text=text,
                content=record,
                attributes=attributes,
            )
        )
        return events

    events.append(
        _event(
            sequence=start,
            event_id=base_id,
            timestamp=timestamp,
            actor="system",
            kind="compaction" if record_type in {"summary", "compact", "compacted"} else "other",
            text=_extract_text(record.get("summary") or record.get("content")),
            content=record,
            attributes=common,
        )
    )
    return events


def _codex_text_from_content(content: Any) -> str | None:
    if isinstance(content, str):
        return _clean_display(content)
    if isinstance(content, list):
        pieces: list[str] = []
        for block in content:
            if isinstance(block, Mapping):
                for key in ("text", "input_text", "output_text"):
                    value = block.get(key)
                    if isinstance(value, str):
                        pieces.append(value)
                        break
        if pieces:
            return _clean_display("\n".join(pieces))
    return None


def _codex_events(record: Mapping[str, Any], record_index: int, start: int) -> list[dict[str, Any]]:
    top_type = record.get("type")
    payload = record.get("payload")
    timestamp = record.get("timestamp")
    base_id = str(record.get("id") or f"codex-{record_index}")
    common = {"source_record_index": record_index, "top_type": top_type}
    if not isinstance(payload, Mapping):
        return [
            _event(
                sequence=start,
                event_id=base_id,
                timestamp=timestamp,
                actor="system",
                kind="compaction" if top_type == "compacted" else "other",
                text=None,
                content=record,
                attributes=common,
            )
        ]

    payload_type = payload.get("type")
    if top_type == "response_item":
        if payload_type == "message":
            role = payload.get("role") if isinstance(payload.get("role"), str) else "assistant"
            text = _codex_text_from_content(payload.get("content"))
            attributes = dict(common)
            semantic = _semantic_from_text(text)
            if semantic:
                attributes["semantic"] = semantic
            return [
                _event(
                    sequence=start,
                    event_id=str(payload.get("id") or base_id),
                    timestamp=timestamp,
                    actor=role,
                    kind="message",
                    text=text,
                    content=payload,
                    attributes=attributes,
                )
            ]
        if payload_type == "function_call":
            name = payload.get("name") if isinstance(payload.get("name"), str) else None
            arguments = payload.get("arguments")
            parsed_arguments: Any = arguments
            if isinstance(arguments, str):
                try:
                    parsed_arguments = strict_json_loads(arguments)
                except (ValueError, TypeError):
                    parsed_arguments = {"command": arguments}
            return [
                _event(
                    sequence=start,
                    event_id=str(payload.get("call_id") or payload.get("id") or base_id),
                    timestamp=timestamp,
                    actor="assistant",
                    kind=_tool_kind(name, parsed_arguments),
                    tool=name,
                    target=_target_from_mapping(parsed_arguments),
                    content=payload,
                    attributes=common,
                )
            ]
        if payload_type == "function_call_output":
            text = _extract_text(payload.get("output"))
            return [
                _event(
                    sequence=start,
                    event_id=str(payload.get("call_id") or base_id),
                    timestamp=timestamp,
                    actor="tool",
                    kind="tool_result",
                    text=text,
                    content=payload,
                    attributes=common,
                )
            ]
        if payload_type in {"reasoning", "reasoning_summary"}:
            text = _extract_text(payload.get("summary"))
            return [
                _event(
                    sequence=start,
                    event_id=str(payload.get("id") or base_id),
                    timestamp=timestamp,
                    actor="assistant",
                    kind="reasoning_summary",
                    text=text,
                    content={"type": payload_type, "summary": payload.get("summary")},
                    attributes=common,
                )
            ]

    if top_type == "event_msg":
        if payload_type in {"user_message", "agent_message", "agent_reasoning"}:
            text = _extract_text(payload.get("message") or payload.get("text"))
            actor = "user" if payload_type == "user_message" else "assistant"
            attributes = dict(common)
            semantic = _semantic_from_text(text)
            if semantic:
                attributes["semantic"] = semantic
            return [
                _event(
                    sequence=start,
                    event_id=base_id,
                    timestamp=timestamp,
                    actor=actor,
                    kind="reasoning_summary" if payload_type == "agent_reasoning" else "message",
                    text=text,
                    content=payload,
                    attributes=attributes,
                )
            ]
        if payload_type in {"context_compacted", "compacted"}:
            return [
                _event(
                    sequence=start,
                    event_id=base_id,
                    timestamp=timestamp,
                    actor="system",
                    kind="compaction",
                    content={"type": payload_type},
                    attributes=common,
                )
            ]
        if payload_type in {"turn_aborted", "error"}:
            return [
                _event(
                    sequence=start,
                    event_id=base_id,
                    timestamp=timestamp,
                    actor="system",
                    kind="error",
                    text=_extract_text(payload),
                    content=payload,
                    attributes=common,
                )
            ]
        if payload_type in {"task_started", "task_complete", "token_count"}:
            return [
                _event(
                    sequence=start,
                    event_id=base_id,
                    timestamp=timestamp,
                    actor="system",
                    kind="other",
                    content={"type": payload_type},
                    attributes=common,
                )
            ]

    if top_type == "compacted":
        return [
            _event(
                sequence=start,
                event_id=base_id,
                timestamp=timestamp,
                actor="system",
                kind="compaction",
                content={"type": "compacted"},
                attributes=common,
            )
        ]

    return [
        _event(
            sequence=start,
            event_id=base_id,
            timestamp=timestamp,
            actor="system",
            kind="other",
            text=None,
            content={"top_type": top_type, "payload_type": payload_type},
            attributes=common,
        )
    ]


def _generic_events(record: Mapping[str, Any], record_index: int, start: int) -> list[dict[str, Any]]:
    event_id = str(record.get("event_id") or record.get("id") or record.get("uuid") or f"generic-{record_index}")
    timestamp = record.get("timestamp")
    actor = record.get("actor") or record.get("role") or "unknown"
    actor = str(actor) if isinstance(actor, str) else "unknown"
    kind_value = record.get("kind") or record.get("type") or "other"
    kind = str(kind_value) if isinstance(kind_value, str) else "other"
    tool_value = record.get("tool") or record.get("name")
    tool = str(tool_value) if isinstance(tool_value, str) and tool_value else None
    payload = record.get("input") if isinstance(record.get("input"), Mapping) else record
    target = _target_from_mapping(payload)
    text = _extract_text(record.get("text") or record.get("content") or record.get("message"))
    semantic = _semantic_from_generic(record) or _semantic_from_text(text)
    attributes: dict[str, Any] = {"source_record_index": record_index}
    if semantic is not None:
        attributes["semantic"] = semantic
        kind = str(semantic.get("kind") or kind)
    elif tool:
        kind = _tool_kind(tool, payload)
    return [
        _event(
            sequence=start,
            event_id=event_id,
            timestamp=timestamp,
            actor=actor,
            kind=kind,
            tool=tool,
            target=target,
            text=text,
            content=record,
            attributes=attributes,
        )
    ]


def _looks_like_nonsemantic_oversized_codex(prefix: bytes) -> bool:
    lowered = prefix[:65536].lower()
    markers = (
        b'"type":"image_generation_end"',
        b'"type": "image_generation_end"',
        b'"type":"image_generation_call"',
        b'"type": "image_generation_call"',
    )
    return any(marker in lowered for marker in markers)


def _iter_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        index = 0
        while True:
            prefix = handle.readline(MAX_JSONL_LINE_BYTES + 1)
            if not prefix:
                break
            raw = prefix
            oversized = len(prefix) > MAX_JSONL_LINE_BYTES and not prefix.endswith(b"\n")
            if oversized:
                digest = hashlib.sha256(prefix)
                total = len(prefix)
                preview = prefix[:65536]
                while True:
                    chunk = handle.readline(MAX_JSONL_LINE_BYTES + 1)
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
                    if chunk.endswith(b"\n"):
                        break
                records.append(
                    {
                        "__opaque_line__": True,
                        "record_index": index,
                        "bytes": total,
                        "sha256": digest.hexdigest(),
                        "known_nonsemantic": _looks_like_nonsemantic_oversized_codex(preview),
                    }
                )
                index += 1
                continue
            raw = raw.rstrip(b"\r\n")
            if not raw.strip():
                index += 1
                continue
            try:
                text = raw.decode("utf-8")
                parsed = strict_json_loads(text)
            except (UnicodeDecodeError, ValueError, TypeError) as exc:
                records.append(
                    {
                        "__parse_error__": True,
                        "record_index": index,
                        "error": type(exc).__name__,
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
                index += 1
                continue
            if isinstance(parsed, Mapping):
                records.append(dict(parsed))
            else:
                records.append(
                    {
                        "__parse_error__": True,
                        "record_index": index,
                        "error": "jsonl_record_not_object",
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
            index += 1
    return records


def _load_records(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return _iter_jsonl(path)
    size = path.stat().st_size
    if size > MAX_JSON_DOCUMENT_BYTES:
        raise HandoffAdapterError(
            "json_document_too_large_use_jsonl"
        )
    raw = path.read_text(encoding="utf-8")
    try:
        parsed = strict_json_loads(raw)
    except (ValueError, TypeError) as exc:
        # A file without a JSONL extension may still be a line-oriented export.
        if "\n" in raw:
            return _iter_jsonl(path)
        raise HandoffAdapterError(f"history_json_invalid:{type(exc).__name__}") from exc
    if isinstance(parsed, list):
        if not all(isinstance(item, Mapping) for item in parsed):
            raise HandoffAdapterError("history_array_must_contain_objects")
        return [dict(item) for item in parsed]
    if isinstance(parsed, Mapping):
        events = parsed.get("events")
        if isinstance(events, list) and all(isinstance(item, Mapping) for item in events):
            return [dict(item) for item in events]
        return [dict(parsed)]
    raise HandoffAdapterError("history_root_must_be_object_or_array")


def _detect_source(records: list[dict[str, Any]]) -> tuple[str, str]:
    sample = [record for record in records[:40] if not any(key.startswith("__") for key in record)]
    claude_hits = sum(
        1
        for record in sample
        if record.get("type") in {"user", "assistant", "system", "summary"}
        and ("sessionId" in record or "parentUuid" in record or "message" in record)
    )
    codex_hits = sum(
        1
        for record in sample
        if record.get("type") in {"session_meta", "response_item", "event_msg", "turn_context", "compacted"}
        and ("payload" in record or record.get("type") == "compacted")
    )
    if claude_hits and claude_hits >= codex_hits:
        return "claude-code", "high" if claude_hits >= 2 else "medium"
    if codex_hits:
        return "codex", "high" if codex_hits >= 2 else "medium"
    generic_semantic_hits = sum(
        1 for record in sample if isinstance(record.get("semantic"), Mapping)
    )
    if generic_semantic_hits:
        return "generic", "high"
    return "generic", "low"


def load_history(path: str | Path, *, source: str = "auto") -> dict[str, Any]:
    """Load a local history into the canonical observable event stream."""

    if source not in SUPPORTED_SOURCES:
        raise HandoffAdapterError(f"unsupported_source:{source}")
    history_path = Path(path).expanduser().resolve()
    if not history_path.is_file():
        raise HandoffAdapterError("history_file_not_found")
    source_sha256 = _sha256_file(history_path)
    source_bytes = history_path.stat().st_size
    records = _load_records(history_path)
    if (
        history_path.stat().st_size != source_bytes
        or _sha256_file(history_path) != source_sha256
    ):
        raise HandoffAdapterError("history_changed_during_read")
    detected, confidence = _detect_source(records)
    selected = detected if source == "auto" else source
    if source != "auto":
        confidence = "explicit"

    events: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []
    opaque_lines: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if record.get("__parse_error__"):
            parse_errors.append(record)
            continue
        if record.get("__opaque_line__"):
            opaque_lines.append(record)
            parse_errors.append(
                {
                    "record_index": record.get("record_index"),
                    "error": "oversized_unparsed_record",
                    "sha256": record.get("sha256"),
                }
            )
            continue
        if selected == "claude-code":
            produced = _claude_events(record, index, len(events))
        elif selected == "codex":
            produced = _codex_events(record, index, len(events))
        else:
            produced = _generic_events(record, index, len(events))
        events.extend(produced)

    # Re-number after block expansion to make sequence an invariant independent
    # of vendor message/block boundaries.
    for sequence, event in enumerate(events):
        event["sequence"] = sequence
    seen_event_ids: set[str] = set()
    for event in events:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            parse_errors.append(
                {
                    "record_index": event.get("sequence"),
                    "error": "canonical_event_id_invalid",
                }
            )
            continue
        if event_id in seen_event_ids:
            parse_errors.append(
                {
                    "record_index": event.get("sequence"),
                    "error": "canonical_event_id_duplicate",
                    "event_id": event_id,
                }
            )
        seen_event_ids.add(event_id)

    return {
        "schema": HISTORY_SCHEMA,
        "source": selected,
        "detected_source": detected,
        "adapter_confidence": confidence,
        "source_path": str(history_path),
        "source_sha256": source_sha256,
        "source_bytes": source_bytes,
        "record_count": len(records),
        "event_count": len(events),
        "parse_errors": parse_errors,
        "opaque_record_count": len(opaque_lines),
        "events": events,
    }
