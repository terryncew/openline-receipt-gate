"""Persistent challenge and replay protection for decision gates."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

import fcntl

from .adapters import Check, FAIL, PASS
from .crypto import strict_json_loads


SESSION_SCHEMA = "openline.proof_to_policy.sessions.v0.2"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class SessionLedger:
    """One-time challenges bound to run, session, sequence, parent, and source."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def _empty(self) -> dict[str, Any]:
        return {"schema": SESSION_SCHEMA, "sessions": {}, "consumed_nonces": {}}

    @contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            if self.path.exists():
                state = strict_json_loads(self.path.read_text(encoding="utf-8"))
            else:
                state = self._empty()
            if state.get("schema") != SESSION_SCHEMA:
                raise ValueError("unsupported session ledger schema")
            yield state
            descriptor, temp_name = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(state, handle, sort_keys=True, indent=2)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, self.path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _session_key(run_id: str, session_id: str) -> str:
        return f"{run_id}\x1f{session_id}"

    def issue_challenge(
        self,
        *,
        run_id: str,
        session_id: str,
        expected_source_hash: str,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        now = _utc_now()
        nonce = secrets.token_hex(16)
        session_key = self._session_key(run_id, session_id)
        with self._locked() as state:
            session = state["sessions"].setdefault(
                session_key,
                {
                    "run_id": run_id,
                    "session_id": session_id,
                    "next_sequence": 1,
                    "parent_decision_hash": None,
                    "pending": {},
                    "seen_source_hashes": [],
                },
            )
            if session["run_id"] != run_id or session["session_id"] != session_id:
                raise ValueError("session identity collision")
            # One outstanding challenge per accepted decision chain prevents
            # two valid nonces from racing at the same sequence/parent.
            expired = []
            for pending_nonce, pending in session.get("pending", {}).items():
                try:
                    if now > _parse(str(pending["expires_at"])):
                        expired.append(pending_nonce)
                except (KeyError, ValueError):
                    expired.append(pending_nonce)
            for pending_nonce in expired:
                session["pending"].pop(pending_nonce, None)
            if session.get("pending"):
                raise ValueError("session already has a pending challenge")
            session["pending"][nonce] = {
                "expected_source_hash": expected_source_hash,
                "sequence": session["next_sequence"],
                "parent_decision_hash": session["parent_decision_hash"],
                "issued_at": _iso(now),
                "expires_at": _iso(now + timedelta(seconds=ttl_seconds)),
            }
            return {
                "run_id": run_id,
                "session_id": session_id,
                "sequence": session["next_sequence"],
                "challenge_nonce": nonce,
                "parent_decision_hash": session["parent_decision_hash"],
                "expected_source_hash": expected_source_hash,
                "challenge_expires_at": _iso(now + timedelta(seconds=ttl_seconds)),
            }

    def check(
        self,
        binding: Mapping[str, Any],
        *,
        source_hash: str | None,
        now: datetime | None = None,
    ) -> Check:
        now = now or _utc_now()
        run_id = str(binding.get("run_id", ""))
        session_id = str(binding.get("session_id", ""))
        nonce = str(binding.get("challenge_nonce", ""))
        if not run_id or not session_id or not nonce:
            return Check(FAIL, ["binding_fields_missing"])
        session_key = self._session_key(run_id, session_id)
        with self._locked() as state:
            if nonce in state.get("consumed_nonces", {}):
                return Check(FAIL, ["challenge_replay"])
            session = state.get("sessions", {}).get(session_key)
            if session is None:
                return Check(FAIL, ["session_unknown"])
            challenge = session.get("pending", {}).get(nonce)
            if challenge is None:
                return Check(FAIL, ["challenge_unknown"])
            errors: list[str] = []
            if binding.get("sequence") != challenge.get("sequence"):
                errors.append("decision_sequence_mismatch")
            if binding.get("parent_decision_hash") != challenge.get("parent_decision_hash"):
                errors.append("decision_parent_mismatch")
            if binding.get("expected_source_hash") != challenge.get("expected_source_hash"):
                errors.append("binding_source_hash_mismatch")
            if source_hash != challenge.get("expected_source_hash"):
                errors.append("actual_source_hash_mismatch")
            if source_hash in session.get("seen_source_hashes", []):
                errors.append("source_receipt_replay")
            if challenge.get("sequence") != session.get("next_sequence"):
                errors.append("challenge_sequence_stale")
            if challenge.get("parent_decision_hash") != session.get("parent_decision_hash"):
                errors.append("challenge_parent_stale")
            try:
                if now > _parse(str(challenge["expires_at"])):
                    errors.append("challenge_expired")
            except (KeyError, ValueError):
                errors.append("challenge_expiry_invalid")
            if errors:
                return Check(FAIL, errors)
            return Check(PASS, [], {"challenge_issued_at": challenge.get("issued_at")})

    def consume(
        self,
        binding: Mapping[str, Any],
        *,
        source_hash: str,
        decision_hash: str,
    ) -> None:
        run_id = str(binding["run_id"])
        session_id = str(binding["session_id"])
        nonce = str(binding["challenge_nonce"])
        session_key = self._session_key(run_id, session_id)
        with self._locked() as state:
            session = state["sessions"].get(session_key)
            if session is None or nonce not in session.get("pending", {}):
                raise ValueError("challenge cannot be consumed")
            challenge = session["pending"][nonce]
            if (
                challenge.get("sequence") != session.get("next_sequence")
                or challenge.get("parent_decision_hash") != session.get("parent_decision_hash")
                or challenge.get("expected_source_hash") != source_hash
            ):
                raise ValueError("stale challenge cannot be consumed")
            session["pending"].pop(nonce)
            state["consumed_nonces"][nonce] = {
                "run_id": run_id,
                "session_id": session_id,
                "sequence": challenge["sequence"],
                "source_hash": source_hash,
                "decision_hash": decision_hash,
                "consumed_at": _iso(_utc_now()),
            }
            session["seen_source_hashes"].append(source_hash)
            session["parent_decision_hash"] = decision_hash
            session["next_sequence"] = int(challenge["sequence"]) + 1
