"""Published SARA scope boundary after task termination."""

from __future__ import annotations

from typing import Any, Mapping

from .common import digest, historical_snapshot


def evaluate_published_sara(
    fixture: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    del event
    if fixture.get("task", {}).get("status") != "TERMINATED":
        raise ValueError("published_sara_requires_terminated_task")
    before = digest(historical_snapshot(fixture))
    after = digest(historical_snapshot(fixture))
    return {
        "scope_status": "OUT_OF_SCOPE_AFTER_TASK_END",
        "scored": False,
        "runtime_state_after_task": "CLEARED",
        "dispositions": {
            decision["decision_id"]: "UNASSESSED"
            for decision in fixture["decisions"]
        },
        "historical_evidence": "UNCHANGED" if before == after else "CHANGED",
        "historical_hash_before": before,
        "historical_hash_after": after,
    }
