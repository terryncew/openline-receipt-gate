"""Faithful persistence/revocation extension over published K/F/H state.

The function performs a full query-time scan over the raw calls and
observations already present in H. It creates no durable derived state and
returns no decision-to-history mapping.
"""

from __future__ import annotations

from typing import Any, Mapping

from .common import (
    call_matches_contract,
    digest,
    historical_snapshot,
    history_entry_is_admitted,
    json_copy,
    scalar_strings,
)


def evaluate_minimal_sara(
    fixture: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    if fixture.get("task", {}).get("status") != "TERMINATED":
        raise ValueError("minimal_extension_requires_terminated_task")

    before = digest(historical_snapshot(fixture))
    persisted_state = {
        "K": json_copy(fixture["K"]),
        "F": json_copy(fixture["F"]),
        "H": json_copy(fixture["H"]),
    }
    extension_state = {"standing_updates": [json_copy(event)]}
    target = event.get("contract_item_id")
    revoked = (
        event.get("event_type") == "REVOKE"
        and event.get("standing") == "REVOKED"
    )

    dispositions: dict[str, str] = {}
    scan_count = 0
    for decision in fixture["decisions"]:
        affected = False
        decision_values = scalar_strings(decision)
        if revoked:
            for entry in persisted_state["H"]:
                scan_count += 1
                if not history_entry_is_admitted(entry):
                    continue
                if not decision_values.intersection(
                    scalar_strings(entry.get("observation", {}))
                ):
                    continue
                call = entry.get("call", {})
                for contract in persisted_state["K"]:
                    if (
                        contract.get("contract_item_id") == target
                        and call_matches_contract(call, contract)
                    ):
                        affected = True
        dispositions[decision["decision_id"]] = (
            "REOPEN" if affected else "PRESERVE"
        )

    after = digest(historical_snapshot(fixture))
    return {
        "scope_status": "ASSESSED",
        "scored": True,
        "dispositions": dispositions,
        "historical_evidence": "UNCHANGED" if before == after else "CHANGED",
        "historical_hash_before": before,
        "historical_hash_after": after,
        "state_shape": {
            "persisted_keys": sorted(persisted_state),
            "extension_keys": sorted(extension_state),
            "new_persistent_structure_count": 0,
            "returns_derived_relationships": False,
        },
        "query_time_history_rows_scanned": scan_count,
        "persisted_state_sha256": digest(persisted_state),
        "extension_state_sha256": digest(extension_state),
    }
