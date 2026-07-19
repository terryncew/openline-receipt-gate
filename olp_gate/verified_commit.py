"""Receiver-owned, single-use enforcement for signed COMMIT decisions.

Verified Commit does not define another receipt family.  The proof-to-policy
gate optionally places an exact-action authorization inside its existing
``proof_to_policy_decision_receipt``.  A receiver-controlled tool entry point
verifies that receipt, compares the attempted action byte-for-byte through the
declared canonical hashes, and atomically spends the authorization before it
invokes the tool.

The local execution ledger is enforcement state, not a portable receipt and
not an independent witness.  Its purpose is to make replay and concurrent
double use fail closed at the receiver boundary.
"""

from __future__ import annotations

import fcntl
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapters import Check, FAIL, PASS, parse_timestamp
from .crypto import (
    UnsupportedCanonicalValue,
    olp_canonical_json,
    public_key_hex,
    sha256_hex,
    strict_json_load,
    strict_json_loads,
)


VERIFIED_COMMIT_PROFILE = "verified_commit/v1"
COMMIT_LEDGER_SCHEMA = "openline.proof_to_policy.commit-ledger.v1"

COMMIT_REQUEST_KEYS = {
    "tool",
    "target",
    "settings",
    "run_id",
    "capsule_hash",
    "evidence_hashes",
    "policy_hash",
    "expires_at",
    "one_use_code",
}
COMMIT_POLICY_KEYS = {
    "required",
    "tool",
    "target",
    "settings_hash",
    "run_id",
    "capsule_hash",
    "evidence_hashes",
    "max_ttl_seconds",
}
EXECUTION_ACTION_KEYS = {
    "tool",
    "target",
    "settings",
    "run_id",
    "capsule_hash",
    "evidence_hashes",
    "policy_hash",
}
AUTHORIZATION_KEYS = {
    "profile",
    "tool",
    "target",
    "settings_hash",
    "run_id",
    "capsule_hash",
    "evidence_hashes",
    "policy_hash",
    "expires_at",
    "one_use_code_hash",
    "action_hash",
    "authorization_hash",
}
ACTION_BINDING_KEYS = {
    "tool",
    "target",
    "settings_hash",
    "run_id",
    "capsule_hash",
    "evidence_hashes",
    "policy_hash",
}

_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_CODE_DOMAIN = b"openline-verified-commit-v1\x00"
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, threading.RLock] = {}
T = TypeVar("T")


class VerifiedCommitError(ValueError):
    """Raised when a commit request or authorization has an invalid shape."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and _HEX_256.fullmatch(value) is not None


def _normalized_hashes(value: Any) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [], ["evidence_hashes_invalid"]
    hashes: list[str] = []
    errors: list[str] = []
    for item in value:
        normalized = str(item).removeprefix("sha256:").lower()
        if not _is_hash(normalized):
            errors.append("evidence_hashes_invalid")
        else:
            hashes.append(normalized)
    if len(set(hashes)) != len(hashes):
        errors.append("evidence_hashes_duplicate")
    return sorted(hashes), sorted(set(errors))


def issue_one_use_code() -> str:
    """Return a receiver-held 256-bit code suitable for one authorization."""

    return secrets.token_hex(32)


def one_use_code_hash(code: str) -> str:
    if not isinstance(code, str) or _HEX_256.fullmatch(code) is None:
        raise VerifiedCommitError("one_use_code_invalid")
    return sha256_hex(_CODE_DOMAIN + code.encode("ascii"))


def settings_hash(settings: Mapping[str, Any]) -> str:
    if not isinstance(settings, Mapping):
        raise VerifiedCommitError("settings_invalid")
    try:
        return sha256_hex(olp_canonical_json(dict(settings)))
    except UnsupportedCanonicalValue as exc:
        raise VerifiedCommitError("settings_canonicalization_unsupported") from exc


def _action_binding(
    *,
    tool: str,
    target: str,
    settings_digest: str,
    run_id: str,
    capsule_hash: str,
    evidence_hashes: Sequence[str],
    policy_hash: str,
) -> dict[str, Any]:
    return {
        "tool": tool,
        "target": target,
        "settings_hash": settings_digest,
        "run_id": run_id,
        "capsule_hash": capsule_hash,
        "evidence_hashes": sorted(evidence_hashes),
        "policy_hash": policy_hash,
    }


def _action_hash(binding: Mapping[str, Any]) -> str:
    return sha256_hex(olp_canonical_json(dict(binding)))


def _authorization_from_fields(
    *,
    action_binding: Mapping[str, Any],
    expires_at: str,
    code_hash: str,
) -> dict[str, Any]:
    body = {
        "profile": VERIFIED_COMMIT_PROFILE,
        **dict(action_binding),
        "expires_at": expires_at,
        "one_use_code_hash": code_hash,
        "action_hash": _action_hash(action_binding),
    }
    return {
        **body,
        "authorization_hash": sha256_hex(olp_canonical_json(body)),
    }


def _validated_policy(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(value, Mapping):
        return None, ["verified_commit_policy_missing"]
    policy = dict(value)
    errors: list[str] = []
    if set(policy) != COMMIT_POLICY_KEYS:
        errors.append("verified_commit_policy_shape_invalid")
    if policy.get("required") is not True:
        errors.append("verified_commit_policy_not_required")
    for name in ("tool", "target", "run_id"):
        if not isinstance(policy.get(name), str) or not policy.get(name):
            errors.append(f"verified_commit_policy_{name}_invalid")
    for name in ("settings_hash", "capsule_hash"):
        if not _is_hash(policy.get(name)):
            errors.append(f"verified_commit_policy_{name}_invalid")
    policy_evidence, evidence_errors = _normalized_hashes(
        policy.get("evidence_hashes")
    )
    errors.extend(f"verified_commit_policy_{error}" for error in evidence_errors)
    policy["evidence_hashes"] = policy_evidence
    ttl = policy.get("max_ttl_seconds")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        errors.append("verified_commit_policy_ttl_invalid")
    return policy, sorted(set(errors))


def assess_verified_commit(
    request: Mapping[str, Any],
    *,
    policy_metadata: Mapping[str, Any],
    policy_hash: str,
    binding: Mapping[str, Any],
    evidence_check: Check,
    now: datetime,
) -> Check:
    """Validate an optional exact-action request against receiver policy.

    The raw one-use code and raw settings never enter the signed decision.
    Only their domain-separated/canonical hashes are carried forward.
    """

    raw_request = request.get("commit_request")
    raw_policy = policy_metadata.get("verified_commit")
    if raw_request is None and raw_policy is None:
        return Check(
            PASS,
            [],
            {
                "required": False,
                "profile": VERIFIED_COMMIT_PROFILE,
                "scope": "no portable tool permission requested",
            },
        )

    policy, errors = _validated_policy(raw_policy)
    if raw_request is None:
        errors.append("verified_commit_request_missing")
        return Check(
            FAIL,
            sorted(set(errors)),
            {"required": True, "profile": VERIFIED_COMMIT_PROFILE},
        )
    if not isinstance(raw_request, Mapping):
        errors.append("verified_commit_request_invalid")
        return Check(
            FAIL,
            sorted(set(errors)),
            {"required": True, "profile": VERIFIED_COMMIT_PROFILE},
        )
    commit_request = dict(raw_request)
    if set(commit_request) != COMMIT_REQUEST_KEYS:
        errors.append("verified_commit_request_shape_invalid")

    for name in ("tool", "target", "run_id"):
        if not isinstance(commit_request.get(name), str) or not commit_request.get(name):
            errors.append(f"verified_commit_{name}_invalid")
    if not _is_hash(commit_request.get("capsule_hash")):
        errors.append("verified_commit_capsule_hash_invalid")
    if not _is_hash(commit_request.get("policy_hash")):
        errors.append("verified_commit_policy_hash_invalid")
    request_evidence, evidence_errors = _normalized_hashes(
        commit_request.get("evidence_hashes")
    )
    errors.extend(f"verified_commit_{error}" for error in evidence_errors)
    try:
        request_settings_hash = settings_hash(commit_request.get("settings"))
    except VerifiedCommitError as exc:
        request_settings_hash = ""
        errors.append(str(exc))
    try:
        code_hash = one_use_code_hash(str(commit_request.get("one_use_code", "")))
    except VerifiedCommitError as exc:
        code_hash = ""
        errors.append(str(exc))

    expires_at = commit_request.get("expires_at")
    expiry = parse_timestamp(expires_at)
    if expiry is None:
        errors.append("verified_commit_expiry_invalid")
    elif expiry <= now:
        errors.append("verified_commit_expired_at_issue")

    artifact_hashes = evidence_check.details.get("artifact_hashes", {})
    if evidence_check.status != PASS or not isinstance(artifact_hashes, Mapping):
        actual_evidence: list[str] = []
        errors.append("verified_commit_evidence_not_verified")
    else:
        actual_evidence, actual_errors = _normalized_hashes(
            list(artifact_hashes.values())
        )
        errors.extend(f"verified_commit_actual_{error}" for error in actual_errors)

    if commit_request.get("policy_hash") != policy_hash:
        errors.append("verified_commit_policy_hash_mismatch")
    if commit_request.get("run_id") != binding.get("run_id"):
        errors.append("verified_commit_binding_run_mismatch")
    if request_evidence != actual_evidence:
        errors.append("verified_commit_evidence_binding_mismatch")

    if policy is not None:
        comparisons = {
            "tool": commit_request.get("tool"),
            "target": commit_request.get("target"),
            "settings_hash": request_settings_hash,
            "run_id": commit_request.get("run_id"),
            "capsule_hash": commit_request.get("capsule_hash"),
            "evidence_hashes": request_evidence,
        }
        for name, observed in comparisons.items():
            if observed != policy.get(name):
                errors.append(f"verified_commit_policy_{name}_mismatch")
        if expiry is not None and isinstance(policy.get("max_ttl_seconds"), int):
            if (expiry - now).total_seconds() > policy["max_ttl_seconds"]:
                errors.append("verified_commit_ttl_exceeds_policy")

    if errors:
        return Check(
            FAIL,
            sorted(set(errors)),
            {
                "required": True,
                "profile": VERIFIED_COMMIT_PROFILE,
                "raw_settings_stored": False,
                "raw_one_use_code_stored": False,
            },
        )

    action_binding = _action_binding(
        tool=str(commit_request["tool"]),
        target=str(commit_request["target"]),
        settings_digest=request_settings_hash,
        run_id=str(commit_request["run_id"]),
        capsule_hash=str(commit_request["capsule_hash"]),
        evidence_hashes=request_evidence,
        policy_hash=policy_hash,
    )
    authorization = _authorization_from_fields(
        action_binding=action_binding,
        expires_at=str(expires_at),
        code_hash=code_hash,
    )
    return Check(
        PASS,
        [],
        {
            "required": True,
            "profile": VERIFIED_COMMIT_PROFILE,
            "authorization": authorization,
            "raw_settings_stored": False,
            "raw_one_use_code_stored": False,
        },
    )


def commit_authorization_from_check(check: Check, decision: str) -> dict[str, Any] | None:
    if decision != "COMMIT" or check.status != PASS or check.details.get("required") is not True:
        return None
    value = check.details.get("authorization")
    if not isinstance(value, Mapping):
        raise VerifiedCommitError("verified_commit_authorization_missing")
    return dict(value)


def validate_commit_authorization(receipt: Mapping[str, Any]) -> list[str]:
    """Recompute the optional authorization from signed decision inputs."""

    errors: list[str] = []
    assessments = receipt.get("assessments")
    if not isinstance(assessments, Mapping):
        assessments = {}
    assessment = assessments.get("verified_commit", {})
    details = assessment.get("details", {}) if isinstance(assessment, Mapping) else {}
    if not isinstance(details, Mapping):
        details = {}
    required = details.get("required") is True
    authorization = receipt.get("commit_authorization")
    if not required:
        if authorization is not None:
            errors.append("unexpected_commit_authorization")
        return errors
    if receipt.get("decision") != "COMMIT" or receipt.get("verdict") != "VERIFIED":
        if authorization is not None:
            errors.append("noncommit_authorization_present")
        return errors
    if not isinstance(authorization, Mapping):
        return ["commit_authorization_missing"]
    value = dict(authorization)
    if set(value) != AUTHORIZATION_KEYS:
        errors.append("commit_authorization_shape_invalid")
    if value.get("profile") != VERIFIED_COMMIT_PROFILE:
        errors.append("commit_authorization_profile_invalid")
    for name in ("tool", "target", "run_id"):
        if not isinstance(value.get(name), str) or not value.get(name):
            errors.append(f"commit_authorization_{name}_invalid")
    for name in (
        "settings_hash",
        "capsule_hash",
        "policy_hash",
        "one_use_code_hash",
        "action_hash",
        "authorization_hash",
    ):
        if not _is_hash(value.get(name)):
            errors.append(f"commit_authorization_{name}_invalid")
    evidence_hashes, evidence_errors = _normalized_hashes(value.get("evidence_hashes"))
    errors.extend(f"commit_authorization_{error}" for error in evidence_errors)

    policy_value = receipt.get("policy")
    if not isinstance(policy_value, Mapping):
        policy_value = {}
    binding_value = receipt.get("binding")
    if not isinstance(binding_value, Mapping):
        binding_value = {}
    policy_hash = policy_value.get("hash")
    binding_run = binding_value.get("run_id")
    if value.get("policy_hash") != policy_hash:
        errors.append("commit_authorization_policy_mismatch")
    if value.get("run_id") != binding_run:
        errors.append("commit_authorization_run_mismatch")
    evidence_assessment = assessments.get("evidence")
    evidence_details = (
        evidence_assessment.get("details", {})
        if isinstance(evidence_assessment, Mapping)
        else {}
    )
    if not isinstance(evidence_details, Mapping):
        evidence_details = {}
    artifact_hashes = evidence_details.get("artifact_hashes", {})
    actual_evidence, actual_errors = _normalized_hashes(
        list(artifact_hashes.values()) if isinstance(artifact_hashes, Mapping) else []
    )
    errors.extend(f"commit_authorization_actual_{error}" for error in actual_errors)
    if evidence_hashes != actual_evidence:
        errors.append("commit_authorization_evidence_mismatch")

    policy_snapshot = policy_value.get("snapshot")
    if not isinstance(policy_snapshot, Mapping):
        policy_snapshot = {}
    policy_metadata = policy_snapshot.get("metadata", {})
    verified_policy, policy_errors = _validated_policy(
        policy_metadata.get("verified_commit") if isinstance(policy_metadata, Mapping) else None
    )
    errors.extend(policy_errors)
    if verified_policy is not None:
        for name in (
            "tool",
            "target",
            "settings_hash",
            "run_id",
            "capsule_hash",
            "evidence_hashes",
        ):
            if value.get(name) != verified_policy.get(name):
                errors.append(f"commit_authorization_policy_{name}_mismatch")

    action_binding = {name: value.get(name) for name in ACTION_BINDING_KEYS}
    try:
        if value.get("action_hash") != _action_hash(action_binding):
            errors.append("commit_authorization_action_hash_mismatch")
        body = dict(value)
        observed_authorization_hash = body.pop("authorization_hash", None)
        if observed_authorization_hash != sha256_hex(olp_canonical_json(body)):
            errors.append("commit_authorization_hash_mismatch")
    except UnsupportedCanonicalValue:
        errors.append("commit_authorization_canonicalization_unsupported")

    expiry = parse_timestamp(value.get("expires_at"))
    created = parse_timestamp(receipt.get("created_at"))
    if expiry is None:
        errors.append("commit_authorization_expiry_invalid")
    elif created is None or expiry <= created:
        errors.append("commit_authorization_expiry_not_after_issue")
    elif verified_policy is not None and isinstance(
        verified_policy.get("max_ttl_seconds"), int
    ):
        if (expiry - created).total_seconds() > verified_policy["max_ttl_seconds"]:
            errors.append("commit_authorization_ttl_exceeds_policy")

    expected = details.get("authorization")
    if not isinstance(expected, Mapping) or dict(expected) != value:
        errors.append("commit_authorization_assessment_mismatch")
    if details.get("raw_settings_stored") is not False:
        errors.append("commit_authorization_settings_privacy_invalid")
    if details.get("raw_one_use_code_stored") is not False:
        errors.append("commit_authorization_code_privacy_invalid")
    return sorted(set(errors))


def execution_action_from_authorization(
    receipt: Mapping[str, Any],
    *,
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    authorization = receipt.get("commit_authorization")
    if not isinstance(authorization, Mapping):
        raise VerifiedCommitError("commit_authorization_missing")
    return {
        "tool": authorization.get("tool"),
        "target": authorization.get("target"),
        "settings": dict(settings),
        "run_id": authorization.get("run_id"),
        "capsule_hash": authorization.get("capsule_hash"),
        "evidence_hashes": list(authorization.get("evidence_hashes", [])),
        "policy_hash": authorization.get("policy_hash"),
    }


def _normalize_execution_action(value: Any) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(value, Mapping):
        return None, ["execution_action_invalid"]
    action = dict(value)
    errors: list[str] = []
    if set(action) != EXECUTION_ACTION_KEYS:
        errors.append("execution_action_shape_invalid")
    for name in ("tool", "target", "run_id"):
        if not isinstance(action.get(name), str) or not action.get(name):
            errors.append(f"execution_{name}_invalid")
    for name in ("capsule_hash", "policy_hash"):
        if not _is_hash(action.get(name)):
            errors.append(f"execution_{name}_invalid")
    evidence_hashes, evidence_errors = _normalized_hashes(action.get("evidence_hashes"))
    errors.extend(f"execution_{error}" for error in evidence_errors)
    try:
        digest = settings_hash(action.get("settings"))
    except VerifiedCommitError as exc:
        digest = ""
        errors.append(f"execution_{exc}")
    if errors:
        return None, sorted(set(errors))
    return _action_binding(
        tool=str(action["tool"]),
        target=str(action["target"]),
        settings_digest=digest,
        run_id=str(action["run_id"]),
        capsule_hash=str(action["capsule_hash"]),
        evidence_hashes=evidence_hashes,
        policy_hash=str(action["policy_hash"]),
    ), []


def _path_lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.RLock())


class VerifiedCommitLedger:
    """Atomic receiver-side consumption state for portable COMMIT permission."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._thread_lock = _path_lock(self.lock_path)

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "schema": COMMIT_LEDGER_SCHEMA,
            "consumed_decisions": {},
            "consumed_codes": {},
            "attempts": [],
        }

    @contextmanager
    def _locked(self) -> Iterator[dict[str, Any]]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self._thread_lock:
            with self.lock_path.open("a+", encoding="utf-8") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                if self.path.exists():
                    state = strict_json_loads(self.path.read_text(encoding="utf-8"))
                else:
                    state = self._empty()
                if not isinstance(state, dict) or state.get("schema") != COMMIT_LEDGER_SCHEMA:
                    raise VerifiedCommitError("commit_ledger_schema_invalid")
                yield state
                descriptor, temp_name = tempfile.mkstemp(
                    prefix=self.path.name + ".",
                    dir=self.path.parent,
                )
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

    def check_and_consume(
        self,
        receipt: Mapping[str, Any],
        action: Mapping[str, Any],
        *,
        one_use_code: str,
        trusted_gate_keys: Sequence[str],
        now: datetime | None = None,
        attempt_label: str | None = None,
    ) -> dict[str, Any]:
        """Verify and atomically spend permission before any tool side effect."""

        check_time = now or _utc_now()
        with self._locked() as state:
            errors: list[str] = []
            # Local import avoids a module cycle: gateway uses the pure
            # authorization helpers above while the tool boundary verifies the
            # complete signed decision.
            from .gateway import verify_decision_receipt

            decision_check = verify_decision_receipt(receipt, trusted_gate_keys)
            errors.extend(
                f"decision_receipt_invalid:{error}"
                for error in decision_check.get("errors", [])
            )
            if receipt.get("decision") != "COMMIT" or receipt.get("verdict") != "VERIFIED":
                errors.append("decision_not_commit")
            authorization = receipt.get("commit_authorization")
            if not isinstance(authorization, Mapping):
                errors.append("commit_authorization_missing")
                authorization = {}

            attempted_binding, action_errors = _normalize_execution_action(action)
            errors.extend(action_errors)
            if attempted_binding is not None and authorization:
                comparisons = {
                    "tool": "tool_mismatch",
                    "target": "target_mismatch",
                    "settings_hash": "settings_mismatch",
                    "run_id": "run_mismatch",
                    "capsule_hash": "capsule_mismatch",
                    "evidence_hashes": "evidence_mismatch",
                    "policy_hash": "policy_mismatch",
                }
                for name, reason in comparisons.items():
                    if attempted_binding.get(name) != authorization.get(name):
                        errors.append(reason)
                attempted_hash = _action_hash(attempted_binding)
                if attempted_hash != authorization.get("action_hash"):
                    errors.append("action_hash_mismatch")
            else:
                attempted_hash = None

            try:
                supplied_code_hash = one_use_code_hash(one_use_code)
            except VerifiedCommitError:
                supplied_code_hash = None
                errors.append("one_use_code_invalid")
            expected_code_hash = authorization.get("one_use_code_hash")
            if (
                supplied_code_hash is not None
                and isinstance(expected_code_hash, str)
                and not hmac.compare_digest(supplied_code_hash, expected_code_hash)
            ):
                errors.append("one_use_code_mismatch")

            expiry = parse_timestamp(authorization.get("expires_at"))
            if expiry is None:
                errors.append("authorization_expiry_invalid")
            elif check_time >= expiry:
                errors.append("authorization_expired")

            decision_hash = receipt.get("payload_hash")
            if not _is_hash(decision_hash):
                errors.append("decision_payload_hash_invalid")
            if decision_hash in state["consumed_decisions"]:
                errors.append("authorization_replay")
            if (
                isinstance(expected_code_hash, str)
                and expected_code_hash in state["consumed_codes"]
            ):
                errors.append("one_use_code_replay")

            authorized = not errors
            attempt_id = secrets.token_hex(12)
            record = {
                "attempt_id": attempt_id,
                "attempt_label": attempt_label,
                "checked_at": _iso(check_time),
                "decision_payload_hash": decision_hash,
                "authorization_hash": authorization.get("authorization_hash"),
                "attempt_action_hash": attempted_hash,
                "result": "AUTHORIZED" if authorized else "BLOCKED",
                "reason_codes": sorted(set(errors)),
                "execution_status": "permitted" if authorized else "not_started",
                "tool_result_hash": None,
            }
            state["attempts"].append(record)
            if authorized:
                state["consumed_decisions"][decision_hash] = {
                    "authorization_hash": authorization["authorization_hash"],
                    "one_use_code_hash": expected_code_hash,
                    "action_hash": attempted_hash,
                    "consumed_at": _iso(check_time),
                    "attempt_id": attempt_id,
                }
                state["consumed_codes"][expected_code_hash] = {
                    "decision_payload_hash": decision_hash,
                    "consumed_at": _iso(check_time),
                    "attempt_id": attempt_id,
                }
            return {
                "authorized": authorized,
                "reason_codes": record["reason_codes"],
                "attempt_id": attempt_id,
                "decision_payload_hash": decision_hash,
                "authorization_hash": authorization.get("authorization_hash"),
                "action_hash": attempted_hash,
            }

    def _record_execution(
        self,
        attempt_id: str,
        *,
        status: str,
        tool_result_hash: str | None = None,
        error_type: str | None = None,
    ) -> None:
        with self._locked() as state:
            for attempt in state["attempts"]:
                if attempt.get("attempt_id") == attempt_id:
                    if attempt.get("result") != "AUTHORIZED":
                        raise VerifiedCommitError("blocked_attempt_cannot_execute")
                    attempt["execution_status"] = status
                    attempt["tool_result_hash"] = tool_result_hash
                    if error_type is not None:
                        attempt["execution_error_type"] = error_type
                    attempt["execution_updated_at"] = _iso(_utc_now())
                    return
            raise VerifiedCommitError("commit_attempt_unknown")

    def execute_once(
        self,
        receipt: Mapping[str, Any],
        action: Mapping[str, Any],
        *,
        one_use_code: str,
        trusted_gate_keys: Sequence[str],
        executor: Callable[[], T],
        now: datetime | None = None,
        attempt_label: str | None = None,
    ) -> dict[str, Any]:
        """Spend permission, then and only then invoke ``executor`` once."""

        result = self.check_and_consume(
            receipt,
            action,
            one_use_code=one_use_code,
            trusted_gate_keys=trusted_gate_keys,
            now=now,
            attempt_label=attempt_label,
        )
        if not result["authorized"]:
            return result
        self._record_execution(result["attempt_id"], status="started")
        try:
            tool_result = executor()
        except BaseException as exc:
            self._record_execution(
                result["attempt_id"],
                status="failed",
                error_type=type(exc).__name__,
            )
            raise
        try:
            result_hash = sha256_hex(olp_canonical_json(tool_result))
            status = "completed"
        except UnsupportedCanonicalValue:
            result_hash = None
            status = "completed_result_unhashable"
        self._record_execution(
            result["attempt_id"],
            status=status,
            tool_result_hash=result_hash,
        )
        return {
            **result,
            "tool_result": tool_result,
            "tool_result_hash": result_hash,
            "execution_status": status,
        }

    def read_state(self) -> dict[str, Any]:
        with self._locked() as state:
            return json.loads(json.dumps(state, sort_keys=True))


VERIFIED_COMMIT_SUMMARY_SCHEMA = "openline.verified-commit.demo-summary.v1"
EXECUTED_ACTION_FORMAT = "openline.verified-commit.executed-action.v1"


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _copy_json(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))


def run_verified_commit_demo(
    half_life_output: str | Path,
    output_dir: str | Path,
    *,
    succession_policy_public_key_path: str | Path,
    compaction_policy_public_key_path: str | Path,
    source_model: str,
    target_model: str,
    source_signing_key: Ed25519PrivateKey,
    grader_signing_key: Ed25519PrivateKey,
    gate_signing_key: Ed25519PrivateKey,
    gate_issuer: str,
    source_adapter: str = "offline-deterministic-source-v1",
    target_adapter: str = "offline-deterministic-target-v1",
    trial_id: str = "verified-commit-demo",
) -> dict[str, Any]:
    """Run Model A -> Model B and spend one exact action authorization."""

    from .model_swap import run_verified_model_swap

    output = Path(output_dir)
    action_core = {
        "tool": "filesystem.write",
        "target": "artifact://approved_action.json",
        "settings": {
            "content": "portable permission spent once",
            "encoding": "utf-8",
            "mode": "create_new",
        },
    }
    code = issue_one_use_code()
    swap = run_verified_model_swap(
        half_life_output,
        output,
        succession_policy_public_key_path=succession_policy_public_key_path,
        compaction_policy_public_key_path=compaction_policy_public_key_path,
        source_model=source_model,
        target_model=target_model,
        source_signing_key=source_signing_key,
        grader_signing_key=grader_signing_key,
        gate_signing_key=gate_signing_key,
        gate_issuer=gate_issuer,
        source_adapter=source_adapter,
        target_adapter=target_adapter,
        trial_id=trial_id,
        commit_action=action_core,
        commit_one_use_code=code,
        commit_ttl_seconds=300,
    )
    decision_text = (output / "decision_receipts.jsonl").read_text(
        encoding="utf-8"
    ).strip()
    decision = strict_json_loads(decision_text)
    if not isinstance(decision, Mapping):
        raise VerifiedCommitError("verified_commit_decision_invalid")
    authorization = decision.get("commit_authorization")
    if not isinstance(authorization, Mapping):
        raise VerifiedCommitError("verified_commit_authorization_missing")
    exact_action = execution_action_from_authorization(
        decision,
        settings=action_core["settings"],
    )
    gate_key = public_key_hex(gate_signing_key)
    ledger = VerifiedCommitLedger(output / "verified_commit_ledger.json")
    forbidden_executions: list[str] = []

    def blocked_executor(label: str) -> Callable[[], dict[str, Any]]:
        def execute() -> dict[str, Any]:
            forbidden_executions.append(label)
            return {"unexpected_execution": label}

        return execute

    mutations: list[tuple[str, dict[str, Any], str, str | None, datetime | None]] = []
    changed = _copy_json(exact_action)
    changed["tool"] = "filesystem.delete"
    mutations.append(("changed_tool", changed, code, "tool_mismatch", None))
    changed = _copy_json(exact_action)
    changed["target"] = "artifact://wrong-target.json"
    mutations.append(("wrong_target", changed, code, "target_mismatch", None))
    changed = _copy_json(exact_action)
    changed["settings"]["mode"] = "overwrite"
    mutations.append(("changed_settings", changed, code, "settings_mismatch", None))
    changed = _copy_json(exact_action)
    changed["run_id"] = "other-run"
    mutations.append(("changed_run", changed, code, "run_mismatch", None))
    changed = _copy_json(exact_action)
    changed["capsule_hash"] = "00" * 32
    mutations.append(("changed_capsule", changed, code, "capsule_mismatch", None))
    changed = _copy_json(exact_action)
    changed["evidence_hashes"] = ["00" * 32]
    mutations.append(("changed_evidence", changed, code, "evidence_mismatch", None))
    changed = _copy_json(exact_action)
    changed["policy_hash"] = "00" * 32
    mutations.append(("changed_policy", changed, code, "policy_mismatch", None))
    mutations.append(
        ("wrong_code", _copy_json(exact_action), "00" * 32, "one_use_code_mismatch", None)
    )
    expiry = parse_timestamp(authorization.get("expires_at"))
    if expiry is None:
        raise VerifiedCommitError("verified_commit_expiry_invalid")
    mutations.append(
        (
            "expired",
            _copy_json(exact_action),
            code,
            "authorization_expired",
            expiry + timedelta(seconds=1),
        )
    )

    mutation_results: list[dict[str, Any]] = []
    for label, attempted, attempted_code, expected_reason, attempted_now in mutations:
        result = ledger.execute_once(
            decision,
            attempted,
            one_use_code=attempted_code,
            trusted_gate_keys=[gate_key],
            executor=blocked_executor(label),
            now=attempted_now,
            attempt_label=label,
        )
        mutation_results.append(
            {
                "label": label,
                "authorized": result["authorized"],
                "expected_reason": expected_reason,
                "observed_reasons": result["reason_codes"],
                "blocked_before_execution": (
                    not result["authorized"]
                    and expected_reason in result["reason_codes"]
                    and label not in forbidden_executions
                ),
            }
        )

    executed_path = output / "approved_action.json"

    def execute_approved_action() -> dict[str, Any]:
        value = {
            "format": EXECUTED_ACTION_FORMAT,
            "decision_payload_hash": decision["payload_hash"],
            "authorization_hash": authorization["authorization_hash"],
            "tool": exact_action["tool"],
            "target": exact_action["target"],
            "settings_hash": settings_hash(exact_action["settings"]),
            "run_id": exact_action["run_id"],
            "capsule_hash": exact_action["capsule_hash"],
            "evidence_hashes": exact_action["evidence_hashes"],
            "policy_hash": exact_action["policy_hash"],
        }
        with executed_path.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return value

    barrier = threading.Barrier(2)

    def concurrent_use(index: int) -> dict[str, Any]:
        barrier.wait()
        return ledger.execute_once(
            decision,
            exact_action,
            one_use_code=code,
            trusted_gate_keys=[gate_key],
            executor=execute_approved_action,
            attempt_label=f"simultaneous_use_{index}",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        concurrent_results = list(pool.map(concurrent_use, (1, 2)))

    replay = ledger.execute_once(
        decision,
        exact_action,
        one_use_code=code,
        trusted_gate_keys=[gate_key],
        executor=blocked_executor("sequential_replay"),
        attempt_label="sequential_replay",
    )
    state = ledger.read_state()
    authorized_concurrent = sum(
        result["authorized"] is True for result in concurrent_results
    )
    blocked_concurrent = sum(
        result["authorized"] is False for result in concurrent_results
    )
    approved_file_hash = (
        sha256_hex(executed_path.read_bytes()) if executed_path.exists() else None
    )
    summary = {
        "schema": VERIFIED_COMMIT_SUMMARY_SCHEMA,
        "claim": "Proof travels; permission belongs to the receiver.",
        "model_swap": {
            "source": source_model,
            "target": target_model,
            "provider_execution_attested": False,
            "decision": swap["decision"],
            "capsule_matches_oracle": swap["capsule_matches_oracle"],
            "archive_matches_oracle": swap["archive_matches_oracle"],
        },
        "authorization": {
            "decision_payload_hash": decision["payload_hash"],
            "authorization_hash": authorization["authorization_hash"],
            "action_hash": authorization["action_hash"],
            "expires_at": authorization["expires_at"],
            "raw_one_use_code_stored": False,
        },
        "hostile_checks": mutation_results,
        "simultaneous_use": {
            "attempts": 2,
            "authorized": authorized_concurrent,
            "blocked": blocked_concurrent,
            "at_most_one_execution": authorized_concurrent == 1,
        },
        "replay": {
            "authorized": replay["authorized"],
            "reason_codes": replay["reason_codes"],
            "blocked_before_execution": (
                not replay["authorized"]
                and "authorization_replay" in replay["reason_codes"]
                and "sequential_replay" not in forbidden_executions
            ),
        },
        "execution": {
            "approved_action_file": executed_path.name,
            "approved_action_file_sha256": approved_file_hash,
            "authorized_attempts": sum(
                attempt.get("result") == "AUTHORIZED"
                for attempt in state["attempts"]
            ),
            "completed_attempts": sum(
                attempt.get("execution_status") == "completed"
                for attempt in state["attempts"]
            ),
            "forbidden_executor_calls": forbidden_executions,
        },
        "claim_boundary": (
            "This proves receiver-side exactly-once authorization for the disclosed "
            "action and local atomic ledger. It does not prove live vendor-model "
            "execution, global coordination across independent ledgers, successful "
            "rollback, or safety of a tool that bypasses this checker."
        ),
    }
    summary["passed"] = bool(
        swap["passed"]
        and all(item["blocked_before_execution"] for item in mutation_results)
        and authorized_concurrent == 1
        and blocked_concurrent == 1
        and summary["replay"]["blocked_before_execution"]
        and approved_file_hash is not None
        and summary["execution"]["authorized_attempts"] == 1
        and summary["execution"]["completed_attempts"] == 1
        and not forbidden_executions
    )
    _write_json(output / "verified_commit_summary.json", summary)
    verification = verify_verified_commit_output(
        output,
        trusted_gate_keys=[gate_key],
        half_life_output=half_life_output,
        succession_policy_public_key_path=succession_policy_public_key_path,
        compaction_policy_public_key_path=compaction_policy_public_key_path,
    )
    if not verification["valid"]:
        raise VerifiedCommitError(
            "new Verified Commit output failed verification: "
            + ",".join(verification["errors"])
        )
    return {
        "passed": summary["passed"] and verification["valid"],
        "decision": swap["decision"],
        "verdict": swap["verdict"],
        "gate_public_key": gate_key,
        "authorization_hash": authorization["authorization_hash"],
        "action_hash": authorization["action_hash"],
        "mutation_count": len(mutation_results),
        "mutations_blocked_before_execution": sum(
            item["blocked_before_execution"] for item in mutation_results
        ),
        "simultaneous_authorized": authorized_concurrent,
        "simultaneous_blocked": blocked_concurrent,
        "replay_blocked": summary["replay"]["blocked_before_execution"],
        "approved_action_file_sha256": approved_file_hash,
        "output_dir": str(output),
        "verification": verification,
    }


def verify_verified_commit_output(
    output_dir: str | Path,
    *,
    trusted_gate_keys: Sequence[str],
    half_life_output: str | Path,
    succession_policy_public_key_path: str | Path,
    compaction_policy_public_key_path: str | Path,
) -> dict[str, Any]:
    """Independently inspect the signed permission and local execution state."""

    from .model_swap import verify_model_swap_output

    output = Path(output_dir)
    errors: list[str] = []
    model_swap = verify_model_swap_output(
        output,
        trusted_gate_keys=trusted_gate_keys,
        half_life_output=half_life_output,
        succession_policy_public_key_path=succession_policy_public_key_path,
        compaction_policy_public_key_path=compaction_policy_public_key_path,
    )
    if not model_swap["valid"]:
        errors.extend(f"model_swap:{error}" for error in model_swap["errors"])
    try:
        decision_text = (output / "decision_receipts.jsonl").read_text(
            encoding="utf-8"
        ).strip()
        decision = strict_json_loads(decision_text)
        ledger = strict_json_load(output / "verified_commit_ledger.json")
        summary = strict_json_load(output / "verified_commit_summary.json")
        executed = strict_json_load(output / "approved_action.json")
    except (OSError, ValueError) as exc:
        return {
            "valid": False,
            "errors": [f"verified_commit_output_unreadable:{exc}"],
            "model_swap": model_swap,
        }
    if not isinstance(decision, Mapping):
        return {
            "valid": False,
            "errors": ["verified_commit_decision_invalid"],
            "model_swap": model_swap,
        }
    authorization = decision.get("commit_authorization")
    if not isinstance(authorization, Mapping):
        errors.append("commit_authorization_missing")
        authorization = {}
    if ledger.get("schema") != COMMIT_LEDGER_SCHEMA:
        errors.append("commit_ledger_schema_invalid")
    attempts = ledger.get("attempts")
    if not isinstance(attempts, list) or not all(
        isinstance(item, Mapping) for item in attempts
    ):
        attempts = []
        errors.append("commit_attempts_invalid")
    authorized = [item for item in attempts if item.get("result") == "AUTHORIZED"]
    blocked = [item for item in attempts if item.get("result") == "BLOCKED"]
    completed = [
        item for item in authorized if item.get("execution_status") == "completed"
    ]
    if len(authorized) != 1:
        errors.append("authorized_attempt_count_invalid")
    if len(completed) != 1:
        errors.append("completed_attempt_count_invalid")
    if any(item.get("execution_status") != "not_started" for item in blocked):
        errors.append("blocked_attempt_reached_execution")
    observed_reasons = {
        reason
        for item in blocked
        for reason in item.get("reason_codes", [])
        if isinstance(reason, str)
    }
    required_reasons = {
        "tool_mismatch",
        "target_mismatch",
        "settings_mismatch",
        "run_mismatch",
        "capsule_mismatch",
        "evidence_mismatch",
        "policy_mismatch",
        "one_use_code_mismatch",
        "authorization_expired",
        "authorization_replay",
    }
    missing_reasons = sorted(required_reasons - observed_reasons)
    if missing_reasons:
        errors.extend(f"blocked_reason_missing:{reason}" for reason in missing_reasons)

    decision_hash = decision.get("payload_hash")
    code_hash = authorization.get("one_use_code_hash")
    if set(ledger.get("consumed_decisions", {})) != {decision_hash}:
        errors.append("consumed_decision_state_invalid")
    if set(ledger.get("consumed_codes", {})) != {code_hash}:
        errors.append("consumed_code_state_invalid")
    if executed.get("format") != EXECUTED_ACTION_FORMAT:
        errors.append("executed_action_format_invalid")
    comparisons = {
        "decision_payload_hash": decision_hash,
        "authorization_hash": authorization.get("authorization_hash"),
        "tool": authorization.get("tool"),
        "target": authorization.get("target"),
        "settings_hash": authorization.get("settings_hash"),
        "run_id": authorization.get("run_id"),
        "capsule_hash": authorization.get("capsule_hash"),
        "evidence_hashes": authorization.get("evidence_hashes"),
        "policy_hash": authorization.get("policy_hash"),
    }
    for name, expected in comparisons.items():
        if executed.get(name) != expected:
            errors.append(f"executed_action_{name}_mismatch")
    executed_file_hash = sha256_hex((output / "approved_action.json").read_bytes())
    canonical_result_hash = sha256_hex(olp_canonical_json(executed))
    if completed and completed[0].get("tool_result_hash") != canonical_result_hash:
        errors.append("executed_result_hash_mismatch")

    if summary.get("schema") != VERIFIED_COMMIT_SUMMARY_SCHEMA:
        errors.append("verified_commit_summary_schema_invalid")
    if summary.get("passed") is not True:
        errors.append("verified_commit_summary_not_passed")
    if (
        summary.get("authorization", {}).get("decision_payload_hash")
        != decision_hash
    ):
        errors.append("summary_decision_hash_mismatch")
    if (
        summary.get("authorization", {}).get("authorization_hash")
        != authorization.get("authorization_hash")
    ):
        errors.append("summary_authorization_hash_mismatch")
    if (
        summary.get("execution", {}).get("approved_action_file_sha256")
        != executed_file_hash
    ):
        errors.append("summary_executed_file_hash_mismatch")
    if summary.get("execution", {}).get("forbidden_executor_calls") != []:
        errors.append("summary_forbidden_execution_detected")
    if summary.get("simultaneous_use", {}).get("authorized") != 1:
        errors.append("summary_simultaneous_authorized_invalid")
    if summary.get("simultaneous_use", {}).get("blocked") != 1:
        errors.append("summary_simultaneous_blocked_invalid")
    if summary.get("replay", {}).get("blocked_before_execution") is not True:
        errors.append("summary_replay_not_blocked")

    sensitive_paths = (
        output / "gate_request.json",
        output / "decision_receipts.jsonl",
        output / "verified_commit_ledger.json",
        output / "verified_commit_summary.json",
    )
    if any(
        '"one_use_code":' in path.read_text(encoding="utf-8").replace(" ", "")
        for path in sensitive_paths
    ):
        errors.append("raw_one_use_code_persisted")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "model_swap": model_swap,
        "decision_payload_hash": decision_hash,
        "authorization_hash": authorization.get("authorization_hash"),
        "authorized_attempts": len(authorized),
        "blocked_attempts": len(blocked),
        "completed_attempts": len(completed),
        "executed_action_file_sha256": executed_file_hash,
    }
