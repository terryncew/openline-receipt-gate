"""Holder method ``receiver-held-v1``.

Our model has no presenter: the capability receipt is held by the
enforcement point itself, and holder proof is composed from mandate
admission (the existing verifier), not from a challenge. The receipt is
therefore loaded from the store's own bytes — a caller-presented receipt
is never accepted as authority.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

HOLDER_METHOD = "receiver-held-v1"


class HolderError(ValueError):
    """Raised when no store-held receipt exists for a digest."""


def load_receipt(conn: sqlite3.Connection, receipt_digest: str) -> dict[str, Any]:
    """Return the enforcement point's own stored receipt bytes."""
    cur = conn.execute(
        "SELECT receipt_json FROM capabilities WHERE receipt_digest = ?",
        (receipt_digest,),
    )
    found = cur.fetchone()
    if found is None:
        raise HolderError("receipt_not_held")
    return json.loads(found[0])
