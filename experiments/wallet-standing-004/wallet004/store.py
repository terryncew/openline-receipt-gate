"""Durable per-Gate SQLite state store.

Each Gate gets its own database path. There is no shared database or state file.
ACKs are emitted only after ``commit()`` returns under ``synchronous=FULL``.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time
from typing import Any


class DurableStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS gate_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), state_json TEXT NOT NULL, revision INTEGER NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS admissions (revision INTEGER PRIMARY KEY, kind TEXT NOT NULL, event_hash TEXT, receipt_json TEXT NOT NULL, commit_started_ns INTEGER NOT NULL)"
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def load(self) -> tuple[dict[str, Any] | None, int]:
        row = self.conn.execute(
            "SELECT state_json, revision FROM gate_state WHERE singleton=1"
        ).fetchone()
        if row is None:
            return None, 0
        return json.loads(row[0]), int(row[1])

    def initialize(self, state: dict[str, Any]) -> None:
        current, _revision = self.load()
        if current is not None:
            return
        payload = json.dumps(state, sort_keys=True, separators=(",", ":"))
        with self.conn:
            self.conn.execute(
                "INSERT INTO gate_state(singleton,state_json,revision) VALUES(1,?,0)",
                (payload,),
            )

    def commit_state(
        self,
        *,
        state: dict[str, Any],
        kind: str,
        event_hash: str | None,
        receipt: dict[str, Any],
    ) -> dict[str, int]:
        current, revision = self.load()
        if current is None:
            raise RuntimeError("store_not_initialized")
        next_revision = revision + 1
        state_json = json.dumps(state, sort_keys=True, separators=(",", ":"))
        receipt_json = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        commit_started_ns = time.time_ns()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute(
                "UPDATE gate_state SET state_json=?, revision=? WHERE singleton=1",
                (state_json, next_revision),
            )
            self.conn.execute(
                "INSERT INTO admissions(revision,kind,event_hash,receipt_json,commit_started_ns) VALUES(?,?,?,?,?)",
                (next_revision, kind, event_hash, receipt_json, commit_started_ns),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        # This is the first local timestamp after SQLite reports FULL commit complete.
        commit_complete_ns = time.time_ns()
        return {
            "revision": next_revision,
            "commit_started_ns": commit_started_ns,
            "commit_complete_ns": commit_complete_ns,
        }

    def revision(self) -> int:
        _state, revision = self.load()
        return revision
