from __future__ import annotations
from typing import Any, Mapping
from .common import ENTITIES, SKILLS, historical_hash, preserve_all, unresolved_all

def _explicit_sources(state: Mapping[str, Any]) -> dict[str, tuple[str, ...]] | None:
    patterns = state.get("wiki", {}).get("patterns", {})
    result: dict[str, tuple[str, ...]] = {}
    for pattern in ENTITIES:
        record = patterns.get(pattern)
        if not isinstance(record, Mapping):
            return None
        refs = record.get("source_trace_ids")
        if not isinstance(refs, list) or not refs or not all(isinstance(x, str) and x for x in refs):
            return None
        result[pattern] = tuple(refs)
    return result

def evaluate(state: Mapping[str, Any], standing_event: Mapping[str, Any]) -> dict[str, Any]:
    before = historical_hash(state)
    if standing_event.get("new_standing") != "INVALIDATED" or standing_event.get("trace_id") is None:
        return {"disposition":"NO_CHANGE","outcome":preserve_all(),"historical_before":before,"historical_after":before}
    refs = _explicit_sources(state)
    if refs is None:
        return {"disposition":"UNRESOLVED_PROVENANCE","outcome":unresolved_all(),"historical_before":before,"historical_after":before}
    invalid = str(standing_event["trace_id"])
    patterns = {p:("REOPEN" if invalid in refs[p] else "PRESERVE") for p in ENTITIES}
    skills = {s:"PRESERVE" for s in SKILLS}
    skill_records = state.get("skills", {})
    for skill in SKILLS:
        purpose = skill_records.get(skill, {}).get("PURPOSE.md", {})
        addressed = purpose.get("patterns_addressed", []) if isinstance(purpose, Mapping) else []
        if any(patterns.get(p) == "REOPEN" for p in addressed):
            skills[skill] = "REOPEN"
    return {"disposition":"RESOLVED_FROM_EXPLICIT_SOURCE_REFS","outcome":{"patterns":patterns,"skills":skills},"historical_before":before,"historical_after":before}
