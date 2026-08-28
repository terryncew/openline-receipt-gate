"""OpenLine selective recall arm with persisted support relations."""

from __future__ import annotations

from collections import deque
from typing import Any, Mapping

from .common import (
    call_matches_contract,
    digest,
    historical_snapshot,
    history_entry_is_admitted,
    scalar_strings,
)


def _capture_support_relations(fixture: Mapping[str, Any]) -> list[tuple[str, str]]:
    relations: set[tuple[str, str]] = set()
    for entry in fixture["H"]:
        if not history_entry_is_admitted(entry):
            continue
        call = entry["call"]
        call_id = call["call_id"]
        for contract in fixture["K"]:
            if call_matches_contract(call, contract):
                relations.add((contract["contract_item_id"], call_id))
        observation_values = scalar_strings(entry["observation"])
        for decision in fixture["decisions"]:
            if observation_values.intersection(scalar_strings(decision)):
                relations.add((call_id, decision["decision_id"]))
    return sorted(relations)


def _descendants(start: str, relations: list[tuple[str, str]]) -> set[str]:
    children: dict[str, set[str]] = {}
    for parent, child in relations:
        children.setdefault(parent, set()).add(child)
    seen: set[str] = set()
    pending: deque[str] = deque([start])
    while pending:
        current = pending.popleft()
        for child in sorted(children.get(current, set())):
            if child not in seen:
                seen.add(child)
                pending.append(child)
    return seen


def evaluate_openline_recall(
    fixture: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    before = digest(historical_snapshot(fixture))
    relations = _capture_support_relations(fixture)
    affected: set[str] = set()
    if (
        event.get("event_type") == "REVOKE"
        and event.get("standing") == "REVOKED"
    ):
        affected = _descendants(str(event.get("contract_item_id")), relations)
    dispositions = {
        decision["decision_id"]: (
            "REOPEN" if decision["decision_id"] in affected else "PRESERVE"
        )
        for decision in fixture["decisions"]
    }
    after = digest(historical_snapshot(fixture))
    return {
        "scope_status": "ASSESSED",
        "scored": True,
        "dispositions": dispositions,
        "historical_evidence": "UNCHANGED" if before == after else "CHANGED",
        "historical_hash_before": before,
        "historical_hash_after": after,
        "persisted_support_relations": [list(item) for item in relations],
        "mechanism": "PERSIST_SUPPORT_RELATIONS_AND_TRAVERSE_LOST_STANDING_DESCENDANTS",
    }
