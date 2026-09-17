"""Durable atomic state domain for bounded capabilities (draft §11).

One SQLite database is one authoritative atomic state domain. Every state
transition in :mod:`olp_gate.capability_lifecycle` runs inside exactly one
``BEGIN IMMEDIATE`` transaction here; the single writer serializes
concurrent executors. The store never interprets authority — it persists
rows and enforces uniqueness. Deployment assumption: a single
enforcement-service process on durable storage (WAL mode).
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

_SCHEMA = """
CREATE TABLE IF NOT EXISTS capabilities(
  capability_id       TEXT PRIMARY KEY,
  receipt_digest      TEXT NOT NULL UNIQUE,
  receipt_json        TEXT NOT NULL,
  issuer_owner_id     TEXT NOT NULL,
  issuer_pubkey       TEXT NOT NULL,
  amount              INTEGER NOT NULL,
  unit                TEXT NOT NULL,
  scale               INTEGER NOT NULL,
  scope_profile       TEXT NOT NULL,
  holder_method       TEXT NOT NULL,
  expires_at          INTEGER NOT NULL,
  issuance_auth_digest TEXT NOT NULL UNIQUE,
  revoked             INTEGER NOT NULL DEFAULT 0,
  created_at          INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS operations(
  capability_id          TEXT NOT NULL REFERENCES capabilities(capability_id),
  op_id                  TEXT NOT NULL,
  receipt_digest         TEXT NOT NULL,
  state                  TEXT NOT NULL,
  amount                 INTEGER NOT NULL,
  exercise_action_digest TEXT NOT NULL,
  mandate_hash           TEXT NOT NULL,
  token_hash             TEXT,
  entry_deadline         INTEGER,
  effect_evidence_digest TEXT,
  resolution_note        TEXT,
  created_at             INTEGER NOT NULL,
  updated_at             INTEGER NOT NULL,
  PRIMARY KEY (capability_id, op_id),
  UNIQUE (receipt_digest, op_id)
);
CREATE INDEX IF NOT EXISTS ops_state ON operations(capability_id, state);
CREATE INDEX IF NOT EXISTS ops_action ON operations(capability_id, exercise_action_digest);
"""


class StoreError(ValueError):
    """Raised for registration and persistence failures (fail-closed)."""


def open_store(path: str | Path) -> sqlite3.Connection:
    """Open (creating) the state-domain database."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """One atomic transition: BEGIN IMMEDIATE .. COMMIT/ROLLBACK."""
    conn.execute("BEGIN IMMEDIATE;")
    try:
        yield conn
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        raise


def _row(conn: sqlite3.Connection, capability_id: str) -> dict[str, Any] | None:
    cur = conn.execute(
        "SELECT capability_id, receipt_digest, receipt_json, issuer_owner_id,"
        " issuer_pubkey, amount, unit, scale, scope_profile, holder_method,"
        " expires_at, issuance_auth_digest, revoked, created_at"
        " FROM capabilities WHERE capability_id = ?",
        (capability_id,),
    )
    found = cur.fetchone()
    if found is None:
        return None
    keys = [d[0] for d in cur.description]
    return dict(zip(keys, found))


def register_capability(
    conn: sqlite3.Connection,
    parsed: Mapping[str, Any],
    issuance_auth_digest: str,
    now_unix: int,
) -> dict[str, Any]:
    """Idempotent registration. Raises :class:`StoreError` on conflict.

    At most one non-terminal capability per (domain, issuer_owner_id):
    registering a second while one is active is refused — no capability
    sets, no selection policy (frozen narrow rule).
    """
    with transaction(conn):
        existing = _row(conn, parsed["capability_id"])
        if existing is not None:
            if existing["receipt_digest"] != parsed["receipt_digest"]:
                raise StoreError("capability_id_conflict")
            return existing  # idempotent: identical retry
        cur = conn.execute(
            "SELECT capability_id FROM capabilities"
            " WHERE issuer_owner_id = ? AND revoked = 0 AND expires_at > ?",
            (parsed["issuer_owner_id"], now_unix),
        )
        if cur.fetchone() is not None:
            raise StoreError("principal_capability_already_active")
        cur = conn.execute(
            "SELECT capability_id FROM capabilities WHERE issuance_auth_digest = ?",
            (issuance_auth_digest,),
        )
        if cur.fetchone() is not None:
            raise StoreError("issuance_auth_already_consumed")
        expires = int(datetime_to_unix(parsed["expires_at"]))
        conn.execute(
            "INSERT INTO capabilities(capability_id, receipt_digest, receipt_json,"
            " issuer_owner_id, issuer_pubkey, amount, unit, scale, scope_profile,"
            " holder_method, expires_at, issuance_auth_digest, revoked, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,?)",
            (
                parsed["capability_id"], parsed["receipt_digest"], parsed["receipt_json"],
                parsed["issuer_owner_id"], parsed["issuer_public_key"], parsed["amount"],
                parsed["unit"], parsed["scale"], parsed["scope_profile"],
                parsed["holder_method"], expires, issuance_auth_digest, now_unix,
            ),
        )
        row = _row(conn, parsed["capability_id"])
        assert row is not None
        return row


def get_capability(conn: sqlite3.Connection, capability_id: str) -> dict[str, Any] | None:
    return _row(conn, capability_id)


def active_capability_for(
    conn: sqlite3.Connection, owner_id: str, now_unix: int
) -> dict[str, Any] | None:
    """The principal's one active capability, or None (opt-in layer)."""
    cur = conn.execute(
        "SELECT capability_id FROM capabilities"
        " WHERE issuer_owner_id = ? AND revoked = 0 AND expires_at > ?",
        (owner_id, now_unix),
    )
    found = cur.fetchone()
    return _row(conn, found[0]) if found else None


def revoke_capability(conn: sqlite3.Connection, capability_id: str, now_unix: int) -> None:
    """Direct revocation (caller authenticates; the draft leaves
    distribution to the receiver)."""
    with transaction(conn):
        cur = conn.execute(
            "UPDATE capabilities SET revoked = 1 WHERE capability_id = ? AND revoked = 0",
            (capability_id,),
        )
        if cur.rowcount == 0:
            raise StoreError("capability_revoke_failed")


def datetime_to_unix(iso: str) -> int:
    from datetime import datetime, timezone

    candidate = iso[:-1] + "+00:00" if iso.endswith("Z") else iso
    return int(datetime.fromisoformat(candidate).astimezone(timezone.utc).timestamp())
