"""Durable receiver state: monotonic head frontier and ancestry op log.

Receiver views keep admission state in memory. Process restart wipes that
memory. RECEIVER-ROLLBACK-001 persists the admitted-head frontier
(`DurableHeadStore`); RECEIVER-ROLLBACK-002 persists the ancestry
operation log (`DurableOpLog`) so upstream-standing-loss consequences
survive restart too.

Both stores reuse the same mechanics: JSON file, fcntl lock, tempfile +
fsync + atomic os.replace (see verified_commit.py, session.py).

Design notes (shared):
- Explicit opt-in. Views take `durable_path=None`; without it behavior is
  unchanged (legacy in-memory).
- Fail closed on open. A missing, corrupt, schema-mismatched, or
  identity-mismatched file raises at construction. First boot goes through
  the documented `create()`; the view never auto-creates.
- Identity binding. The file pins the trust configuration it was created
  under (normalized, supplied by the owning view). Opening a file created
  under different trust raises.
- Persistence-before-decision. `read_modify_write` runs the caller's
  transition against freshly-loaded state inside the lock and commits
  atomically; only then does the view update its in-memory state.
"""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
from typing import Any, Callable, Mapping

HEAD_SCHEMA = "durable_head_store/v1"
OPLOG_SCHEMA = "durable_ancestry_log/v1"

_HEX = frozenset("0123456789abcdef")


class DurableHeadStoreError(Exception):
    """Raised when the durable head file is missing, corrupt, or untrusted."""


class DurableOpLogError(Exception):
    """Raised when the durable ancestry log is missing, corrupt, or untrusted."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _deep_copy(value: Any) -> Any:
    return json.loads(_canonical_json(value))


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


class _AtomicJsonFile:
    """fcntl-guarded atomic JSON file with identity binding.

    Subclasses fix the schema, error type/prefix, and the domain payload
    shape via the `_extract` / `_check_result` / `_wrap_state` hooks.
    """

    _SCHEMA = "durable_state/v0"
    _ERROR: type[Exception] = Exception
    _PREFIX = "durable_state"

    def __init__(self, path: str, identity: Mapping[str, Any]) -> None:
        self._path = str(path)
        self._identity = _deep_copy(dict(identity))
        self._lock = threading.Lock()
        # Fail closed: any problem with the file raises here, before the view
        # can admit anything against unknown durable state.
        self._load_locked()

    @classmethod
    def _blank_state(cls) -> dict[str, Any]:
        raise NotImplementedError

    @classmethod
    def _extract(cls, payload: Any) -> Any:
        """Validate a parsed file payload; return a deep copy of the domain state."""
        raise NotImplementedError

    @classmethod
    def _check_result(cls, state: Any) -> Any:
        """Validate a transition's returned domain state."""
        raise NotImplementedError

    @classmethod
    def _wrap_state(cls, state: Any) -> dict[str, Any]:
        raise NotImplementedError

    def _fail(self, code: str) -> Any:
        raise self._ERROR(f"{self._PREFIX}_{code}")

    @classmethod
    def create(cls, path: str, identity: Mapping[str, Any]) -> "_AtomicJsonFile":
        """First boot: create the file. Refuses to clobber an existing one."""
        path = str(path)
        payload = _canonical_json(
            {
                "schema": cls._SCHEMA,
                "identity": dict(identity),
                **cls._blank_state(),
            }
        )
        try:
            handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise cls._ERROR(f"{cls._PREFIX}_already_exists")
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

    def _parse(self, raw: str) -> Any:
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            self._fail("corrupt")
        if not isinstance(payload, dict):
            self._fail("corrupt")
        if payload.get("schema") != self._SCHEMA:
            self._fail("schema_mismatch")
        if payload.get("identity") != self._identity:
            self._fail("identity_mismatch")
        return self._extract(payload)

    def _read_file(self) -> Any:
        try:
            stream = open(self._path, "r")
        except FileNotFoundError:
            self._fail("missing")
        with stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            return self._parse(stream.read())

    def _load_locked(self) -> Any:
        with self._lock:
            return self._read_file()

    def load(self) -> Any:
        """Return a copy of the current persisted domain state."""
        return self._load_locked()

    def read_modify_write(
        self, transition: Callable[[Any], Any]
    ) -> Any:
        """Apply `transition` to freshly-loaded state and commit atomically.

        The transition runs inside the store lock against the state as it
        exists on disk right now (not a stale in-memory copy). If it raises,
        nothing is written. The new state is serialized, fsynced to a temp
        file in the same directory, and atomically renamed over the store.
        Returns the committed state.
        """
        with self._lock:
            # Open, lock, then verify the fd still names the current path.
            # A concurrent writer may have atomically replaced the file
            # between our open() and our lock acquisition; then the fd
            # points at the old inode and we must reopen, or we would
            # read-modify-write stale state. No writer can replace while
            # we hold LOCK_EX (all writers lock first), so one check
            # after acquisition is sufficient.
            while True:
                try:
                    stream = open(self._path, "r")
                except FileNotFoundError:
                    self._fail("missing")
                with stream:
                    # Exclusive lock across the whole read-modify-write.
                    # Separate opens (threads, processes) serialize here:
                    # the second writer sees the first writer's state.
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                    try:
                        current = os.stat(self._path)
                    except FileNotFoundError:
                        self._fail("missing")
                    if not os.path.samestat(os.fstat(stream.fileno()), current):
                        continue
                    fresh = self._parse(stream.read())
                    new_state = transition(_deep_copy(fresh))
                    checked = self._check_result(new_state)
                    raw = _canonical_json(
                        {
                            "schema": self._SCHEMA,
                            "identity": self._identity,
                            **self._wrap_state(checked),
                        }
                    )
                    directory = os.path.dirname(os.path.abspath(self._path)) or "."
                    fd, tmp_path = tempfile.mkstemp(
                        dir=directory, prefix=".durable-", suffix=".tmp"
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
                return _deep_copy(checked)


class DurableHeadStore(_AtomicJsonFile):
    """Atomic, lock-guarded JSON store for a receiver's admitted-head frontier."""

    _SCHEMA = HEAD_SCHEMA
    _ERROR = DurableHeadStoreError
    _PREFIX = "durable_head_store"

    @classmethod
    def _blank_state(cls) -> dict[str, Any]:
        return {"heads": {}}

    @classmethod
    def _extract(cls, payload: Any) -> Any:
        if not isinstance(payload, dict):
            raise cls._ERROR(f"{cls._PREFIX}_corrupt")
        heads = payload.get("heads")
        if not isinstance(heads, dict):
            raise cls._ERROR(f"{cls._PREFIX}_corrupt")
        return _deep_copy(heads)

    @classmethod
    def _check_result(cls, state: Any) -> Any:
        if not isinstance(state, dict):
            raise cls._ERROR(f"{cls._PREFIX}_transition_invalid")
        return _deep_copy(state)

    @classmethod
    def _wrap_state(cls, state: Any) -> dict[str, Any]:
        return {"heads": state}


def _check_op_shape(op: Any) -> dict[str, Any]:
    """Validate one ancestry op; raise DurableOpLogError on any problem."""
    fail = DurableOpLogError
    if not isinstance(op, dict):
        raise fail("durable_ancestry_log_op_invalid")
    tag = op.get("op")
    if tag == "edge":
        if not isinstance(op.get("decision_id"), str) or not op["decision_id"]:
            raise fail("durable_ancestry_log_op_invalid")
        if not _is_hash(op.get("support_hash")):
            raise fail("durable_ancestry_log_op_invalid")
        if not _is_hash(op.get("derived_receipt_hash")):
            raise fail("durable_ancestry_log_op_invalid")
        sequence = op.get("sequence")
    elif tag == "loss":
        if not _is_hash(op.get("support_hash")):
            raise fail("durable_ancestry_log_op_invalid")
        if (
            not isinstance(op.get("standing_event_id"), str)
            or not op["standing_event_id"]
        ):
            raise fail("durable_ancestry_log_op_invalid")
        sequence = op.get("standing_event_sequence")
    else:
        raise fail("durable_ancestry_log_op_invalid")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence <= 0
    ):
        raise fail("durable_ancestry_log_op_invalid")
    return {
        key: op[key]
        for key in (
            ("op", "decision_id", "support_hash", "derived_receipt_hash", "sequence")
            if tag == "edge"
            else ("op", "support_hash", "standing_event_id", "standing_event_sequence")
        )
    }


class DurableOpLog(_AtomicJsonFile):
    """Atomic, lock-guarded append-only log of ancestry operations.

    Holds the authoritative ancestry facts (lineage edges, standing-loss
    events) in admission order. Derived closure state is recomputed by
    replay, never persisted.
    """

    _SCHEMA = OPLOG_SCHEMA
    _ERROR = DurableOpLogError
    _PREFIX = "durable_ancestry_log"

    @classmethod
    def _blank_state(cls) -> dict[str, Any]:
        return {"ops": []}

    @classmethod
    def _extract(cls, payload: Any) -> Any:
        if not isinstance(payload, dict):
            raise cls._ERROR(f"{cls._PREFIX}_corrupt")
        ops = payload.get("ops")
        if not isinstance(ops, list):
            raise cls._ERROR(f"{cls._PREFIX}_corrupt")
        # Fail the whole open on any malformed entry: no partial replay.
        return [_check_op_shape(op) for op in ops]

    @classmethod
    def _check_result(cls, state: Any) -> Any:
        if not isinstance(state, list):
            raise cls._ERROR(f"{cls._PREFIX}_transition_invalid")
        return [_check_op_shape(op) for op in state]

    @classmethod
    def _wrap_state(cls, state: Any) -> dict[str, Any]:
        return {"ops": state}

    def load_ops(self) -> list[dict[str, Any]]:
        """Return the validated op list in log order."""
        return self.load()

    def append(self, op: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Atomically append one validated op; returns the committed log."""
        checked = _check_op_shape(dict(op))

        def _add(ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [*ops, checked]

        return self.read_modify_write(_add)
