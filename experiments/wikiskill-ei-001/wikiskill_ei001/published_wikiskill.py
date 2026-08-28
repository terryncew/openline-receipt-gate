from __future__ import annotations
from typing import Any, Mapping
from .common import historical_hash

def evaluate(state: Mapping[str, Any], standing_event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "disposition":"OUT_OF_SCOPE_POST_HOC_EXPERIENCE_INVALIDATION",
        "scored":False,
        "standing_event_applied":False,
        "historical_before":historical_hash(state),
        "historical_after":historical_hash(state),
    }
