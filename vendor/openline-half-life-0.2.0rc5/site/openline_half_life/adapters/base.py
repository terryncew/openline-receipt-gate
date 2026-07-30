from __future__ import annotations

from typing import Any, Mapping, Protocol


class SuccessorAdapter(Protocol):
    """Optional provider adapters must implement this deterministic boundary."""

    def run_exam(self, packet: Mapping[str, Any], exam: Mapping[str, Any]) -> dict[str, Any]:
        ...
