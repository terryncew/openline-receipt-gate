"""Opt-in SQLite replay/revocation ledger for HOME-GUARD-001 simulation.

A nonce is committed before any effect: an interrupted action may fail to
execute, but cannot be executed twice after a process restart.
"""
from __future__ import annotations

from pathlib import Path
import sqlite3


class DurableSafetyState:
    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise ValueError("persistent file path required")
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS revoked (mandate_id TEXT PRIMARY KEY)")
        self.db.execute("CREATE TABLE IF NOT EXISTS consumed "
                        "(nonce TEXT PRIMARY KEY, mandate_id TEXT NOT NULL)")

    def is_revoked(self, mandate_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM revoked WHERE mandate_id=?", (mandate_id,)).fetchone() is not None

    def is_consumed(self, nonce: str) -> bool:
        return self.db.execute("SELECT 1 FROM consumed WHERE nonce=?", (nonce,)).fetchone() is not None

    def revoke(self, mandate_id: str) -> None:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("INSERT OR IGNORE INTO revoked (mandate_id) VALUES (?)", (mandate_id,))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def consume(self, mandate_id: str, nonce: str) -> tuple[bool, str]:
        """Atomic across processes sharing the database; errors fail closed."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            if self.db.execute("SELECT 1 FROM revoked WHERE mandate_id=?", (mandate_id,)).fetchone():
                self.db.execute("ROLLBACK")
                return False, "mandate_revoked"
            try:
                self.db.execute("INSERT INTO consumed (nonce, mandate_id) VALUES (?, ?)",
                                (nonce, mandate_id))
            except sqlite3.IntegrityError:
                self.db.execute("ROLLBACK")
                return False, "replay_rejected"
            self.db.execute("COMMIT")
            return True, "consumed"
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self.db.close()
