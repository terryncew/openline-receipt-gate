"""Durable monotonic head frontier for receiver admission state.

Receiver views (standing, mandate-owner) keep the *admitted head* — the
receiver's own policy act of recognizing a projection/authorization as
current — in memory. Process restart wipes that memory, and a superseded
projection can then be re-admitted as a fresh head: restart widens authority
(RECEIVER-ROLLBACK-001).

This module persists exactly the head frontier, nothing more. It reuses the
repo's existing ledger pattern: JSON file, fcntl lock, tempfile + fsync +
atomic os.replace (see verified_commit.py, session.py).

Design notes:
- Explicit opt-in. Views take `durable_path=None`; without it behavior is
  unchanged (legacy in-memory).
- Fail closed on open. A missing, corrupt, schema-mismatched, or
  identity-mismatched file raises at construction. First boot goes through
  the documented `DurableHeadStore.create()`; the view never auto-creates.
- Identity binding. The file pins the trust configuration it was created
  under (normalized issuers/slots, supplied by the owning view). Opening a
  file created under different trust raises: a head frontier is only
  meaningful relative to the trust root that admitted it.
- Persistence-before-decision. `read_modify_write` runs the caller's
  transition against freshly-loaded heads inside the lock and commits
  atomically; only then does the view update its in-memory state.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
from typing import Any, Callable, Mapping

SCHEMA = "durable_head_store/v1"


class DurableHeadStoreError(Exception):
    """Raised when the durable head file is missing, corrupt, or untrusted."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _deep_copy(value: Any) -> Any:
    return json.loads(_canonical_json(value))


class DurableHeadStore:
    """Atomic, lock-guarded JSON store for a receiver's admitted-head frontier."""

    def __init__(self, path: str, identity: Mapping[str, Any]) -> None:
        self._path = str(path)
        self._identity = _deep_copy(dict(identity))
        self._lock = threading.Lock()
        # Fail closed: any problem with the file raises here, before the view
        # can admit anything against an unknown frontier.
        self._load_locked()

    @classmethod
    def create(cls, path: str, identity: Mapping[str, Any]) -> "DurableHeadStore":
        """First boot: create the head file. Refuses to clobber an existing one."""
        path = str(path)
        payload = _canonical_json(
            {"schema": SCHEMA, "identity": dict(identity), "heads": {}}
        )
        try:
            handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise DurableHeadStoreError("durable_head_store_already_exists")
        try:
            with os.fdopen(handle, "w") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        return cls(path, identity)

    @property
    def path(self) -> str:
        return self._path

    def _parse(self, raw: str) -> dict[str, Any]:
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            raise DurableHeadStoreError("durable_head_store_corrupt")
        if not isinstance(payload, dict):
            raise DurableHeadStoreError("durable_head_store_corrupt")
        if payload.get("schema") != SCHEMA:
            raise DurableHeadStoreError("durable_head_store_schema_mismatch")
        if payload.get("identity") != self._identity:
            raise DurableHeadStoreError("durable_head_store_identity_mismatch")
        heads = payload.get("heads")
        if not isinstance(heads, dict):
            raise DurableHeadStoreError("durable_head_store_corrupt")
        return _deep_copy(heads)

    def _read_file(self) -> dict[str, Any]:
        try:
            stream = open(self._path, "r")
        except FileNotFoundError:
            raise DurableHeadStoreError("durable_head_store_missing")
        with stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            return self._parse(stream.read())

    def _load_locked(self) -> dict[str, Any]:
        with self._lock:
            return self._read_file()

    def load(self) -> dict[str, Any]:
        """Return a copy of the current persisted heads."""
        return self._load_locked()

    def read_modify_write(
        self, transition: Callable[[dict[str, Any]], dict[str, Any]]
    ) -> dict[str, Any]:
        """Apply `transition` to freshly-loaded heads and commit atomically.

        The transition runs inside the store lock against the heads as they
        exist on disk right now (not a stale in-memory copy). If it raises,
        nothing is written. The new heads are serialized, fsynced to a temp
        file in the same directory, and atomically renamed over the store.
        Returns the committed heads.
        """
        with self._lock:
            # Open, lock, then verify the fd still names the current path.
            # A concurrent writer may have atomically replaced the file
            # between our open() and our lock acquisition; then the fd
            # points at the old inode and we must reopen, or we would
            # read-modify-write stale heads. No writer can replace while
            # we hold LOCK_EX (all writers lock first), so one check
            # after acquisition is sufficient.
            while True:
                try:
                    stream = open(self._path, "r")
                except FileNotFoundError:
                    raise DurableHeadStoreError("durable_head_store_missing")
                with stream:
                    # Exclusive lock across the whole read-modify-write.
                    # Separate opens (threads, processes) serialize here:
                    # the second writer sees the first writer's heads.
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                    try:
                        current = os.stat(self._path)
                    except FileNotFoundError:
                        raise DurableHeadStoreError("durable_head_store_missing")
                    if not os.path.samestat(os.fstat(stream.fileno()), current):
                        continue
                    fresh = self._parse(stream.read())
                    new_heads = transition(_deep_copy(fresh))
                    if not isinstance(new_heads, dict):
                        raise DurableHeadStoreError(
                            "durable_head_store_transition_invalid"
                        )
                    raw = _canonical_json(
                        {
                            "schema": SCHEMA,
                            "identity": self._identity,
                            "heads": new_heads,
                        }
                    )
                    directory = os.path.dirname(os.path.abspath(self._path)) or "."
                    fd, tmp_path = tempfile.mkstemp(
                        dir=directory, prefix=".heads-", suffix=".tmp"
                    )
                    try:
                        with os.fdopen(fd, "w") as out:
                            out.write(raw)
                            out.flush()
                            os.fsync(out.fileno())
                        os.replace(tmp_path, self._path)
                    except BaseException:
                        try:
                            os.unlink(tmp_path)
                        except OSError:
                            pass
                        raise
                return _deep_copy(new_heads)
