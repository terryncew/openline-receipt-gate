"""Shared, representation-neutral helpers for the frozen SARA fixture."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Mapping


def json_copy(value: Any) -> Any:
    return copy.deepcopy(value)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def historical_snapshot(fixture: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "K": json_copy(fixture["K"]),
        "F": json_copy(fixture["F"]),
        "H": json_copy(fixture["H"]),
        "decisions": json_copy(fixture["decisions"]),
    }


def scalar_strings(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.add(value)
    elif isinstance(value, Mapping):
        for child in value.values():
            found.update(scalar_strings(child))
    elif isinstance(value, list):
        for child in value:
            found.update(scalar_strings(child))
    return found


def call_matches_contract(
    call: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> bool:
    if call.get("tool") != contract.get("operation"):
        return False
    arguments = call.get("arguments")
    static_arguments = contract.get("static_arguments")
    if not isinstance(arguments, Mapping) or not isinstance(static_arguments, Mapping):
        return False
    if arguments.get("source_uri") != contract.get("scope"):
        return False
    return all(arguments.get(key) == value for key, value in static_arguments.items())


def history_entry_is_admitted(entry: Mapping[str, Any]) -> bool:
    return entry.get("allowed") is True and entry.get("success") is True
