from __future__ import annotations
from typing import Any, Mapping
from .common import ENTITIES, SKILLS, historical_hash, preserve_all

def evaluate(state: Mapping[str, Any], standing_event: Mapping[str, Any], support_graph: Mapping[str, Any]) -> dict[str, Any]:
    before = historical_hash(state)
    if standing_event.get("new_standing") != "INVALIDATED" or standing_event.get("trace_id") is None:
        return {"disposition":"NO_CHANGE","outcome":preserve_all(),"historical_before":before,"historical_after":before}
    invalid = str(standing_event["trace_id"])
    trace_to_patterns = support_graph.get("trace_to_patterns", {})
    pattern_to_skills = support_graph.get("pattern_to_skills", {})
    affected_patterns = set(trace_to_patterns.get(invalid, []))
    patterns = {p:("REOPEN" if p in affected_patterns else "PRESERVE") for p in ENTITIES}
    affected_skills = {s for p in affected_patterns for s in pattern_to_skills.get(p, [])}
    skills = {s:("REOPEN" if s in affected_skills else "PRESERVE") for s in SKILLS}
    return {"disposition":"SELECTIVE_STANDING_PROPAGATED","outcome":{"patterns":patterns,"skills":skills},"historical_before":before,"historical_after":before}
