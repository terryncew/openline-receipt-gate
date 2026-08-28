"""Broad post-task invalidation baseline."""

from __future__ import annotations

from typing import Any, Mapping

from .common import digest, historical_snapshot


def evaluate_broad_recall(
    fixture: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    before = digest(historical_snapshot(fixture))
    disposition = "REOPEN" if event.get("event_type") == "REVOKE" else "PRESERVE"
    after = digest(historical_snapshot(fixture))
    return {
        "scope_status": "ASSESSED",
        "scored": True,
        "dispositions": {
            decision["decision_id"]: disposition
            for decision in fixture["decisions"]
        },
        "historical_evidence": "UNCHANGED" if before == after else "CHANGED",
        "historical_hash_before": before,
        "historical_hash_after": after,
        "mechanism": "REOPEN_ALL_DECISIONS_ON_ANY_REVOKE",
    }
