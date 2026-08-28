from __future__ import annotations
from typing import Any, Mapping
from .common import historical_hash, preserve_all, reopen_all

def evaluate(state: Mapping[str, Any], standing_event: Mapping[str, Any]) -> dict[str, Any]:
    changed = standing_event.get("new_standing") == "INVALIDATED" and standing_event.get("trace_id") is not None
    return {
        "disposition":"BROAD_RECALL" if changed else "NO_CHANGE",
        "outcome":reopen_all() if changed else preserve_all(),
        "historical_before":historical_hash(state),
        "historical_after":historical_hash(state),
    }
