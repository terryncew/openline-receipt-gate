"""Receiver-owned mandate authority over developer-authored policy proposals.

A policy bundle may contain a syntactically valid mandate proposal. That does
not make the proposal governing authority.

This module adds a separate receiver-owned lifecycle:

    draft mandate proposal
        -> owner-signed authorization
        -> receiver admission for one configured slot
        -> current mandate supplied to the ordinary Authority Compiler

The root of trust is deliberately outside the mandate object. Each mandate slot
is configured by the receiver with a pinned owner identifier and Ed25519 public
key. The mandate cannot name or promote its own trusted signer.

This is an experimental layer. It does not establish legal authority, identity,
or fiduciary duty, and it does not solve trust-root regress in general.
"""
from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import sign_olp_body, verify_olp_signature
from .mandate import MandateSpec
from .tool_adapter import (
    AuthorizationBlocked,
    LocalAuthorityRuntime,
    ToolCallContext,
    authorize,
)


MANDATE_AUTHORIZATION_SCHEMA = "openline.mandate_owner_authorization.v1"
POLICY_BUNDLE_SCHEMA = "openline.authorized_tool_policy.v1"
_ALLOWED_STATES = {"ACTIVE", "REVOKED"}
_HEX = frozenset("0123456789abcdef")


class MandateAuthorityError(ValueError):
    """Raised when mandate-owner authority cannot be admitted or used."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise MandateAuthorityError("mandate_authorization_timestamp_timezone_required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise MandateAuthorityError("mandate_authorization_timestamp_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise MandateAuthorityError("mandate_authorization_timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise MandateAuthorityError("mandate_authorization_timestamp_timezone_required")
    return parsed.astimezone(timezone.utc)


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError) as exc:
        raise MandateAuthorityError("mandate_authority_json_invalid") from exc


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


def _normalized_mandate(value: Mapping[str, Any]) -> tuple[dict[str, Any], MandateSpec]:
    if not isinstance(value, Mapping):
        raise MandateAuthorityError("mandate_proposal_invalid")
    try:
        spec = MandateSpec.from_mapping(_json_copy(dict(value)))
    except (TypeError, ValueError) as exc:
        raise MandateAuthorityError(f"mandate_proposal_invalid:{exc}") from exc
    return spec.as_dict(), spec


def issue_mandate_authorization(
    *,
    slot_id: str,
    owner_id: str,
    mandate: Mapping[str, Any],
    state: str,
    sequence: int,
    predecessor_hash: str | None,
    issued_at: datetime,
    expires_at: datetime,
    key: Ed25519PrivateKey,
    authorization_id: str | None = None,
) -> dict[str, Any]:
    """Sign one proposed mandate lifecycle record.

    Signing is only authorship. A receiver still has to admit this record against
    its out-of-band slot configuration before the mandate can govern anything.
    """
    if not isinstance(slot_id, str) or not slot_id:
        raise MandateAuthorityError("mandate_slot_id_invalid")
    if not isinstance(owner_id, str) or not owner_id:
        raise MandateAuthorityError("mandate_owner_id_invalid")
    if state not in _ALLOWED_STATES:
        raise MandateAuthorityError("mandate_authorization_state_invalid")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
        raise MandateAuthorityError("mandate_authorization_sequence_invalid")
    if predecessor_hash is not None and not _is_hash(predecessor_hash):
        raise MandateAuthorityError("mandate_authorization_predecessor_invalid")
    _mandate_dict, spec = _normalized_mandate(mandate)
    issued = issued_at.astimezone(timezone.utc) if issued_at.tzinfo else None
    expires = expires_at.astimezone(timezone.utc) if expires_at.tzinfo else None
    if issued is None or expires is None:
        raise MandateAuthorityError("mandate_authorization_timestamp_timezone_required")
    if expires <= issued:
        raise MandateAuthorityError("mandate_authorization_lifetime_invalid")
    body = {
        "schema": MANDATE_AUTHORIZATION_SCHEMA,
        "authorization_id": authorization_id or f"{slot_id}:{sequence}",
        "slot_id": slot_id,
        "owner_id": owner_id,
        "mandate_hash": spec.mandate_hash,
        "state": state,
        "sequence": sequence,
        "predecessor_hash": predecessor_hash,
        "issued_at": _iso(issued),
        "expires_at": _iso(expires),
    }
    # Keep the exact mandate validation above even though only its hash is signed.
    # The receiver will independently bind this record to the supplied mandate.
    return sign_olp_body(body, key)


def validate_mandate_authorization(
    authorization: Mapping[str, Any],
    *,
    expected_slot_id: str,
    expected_owner_id: str,
    expected_public_key: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify one owner authorization against receiver-pinned slot authority."""
    if not isinstance(authorization, Mapping):
        raise MandateAuthorityError("mandate_authorization_invalid")
    item = _json_copy(dict(authorization))
    required = {
        "schema",
        "authorization_id",
        "slot_id",
        "owner_id",
        "mandate_hash",
        "state",
        "sequence",
        "predecessor_hash",
        "issued_at",
        "expires_at",
        "payload_hash",
        "signature",
    }
    if set(item) != required:
        raise MandateAuthorityError("mandate_authorization_shape_invalid")
    if item.get("schema") != MANDATE_AUTHORIZATION_SCHEMA:
        raise MandateAuthorityError("mandate_authorization_schema_invalid")
    for name in ("authorization_id", "slot_id", "owner_id"):
        if not isinstance(item.get(name), str) or not item[name]:
            raise MandateAuthorityError(f"mandate_authorization_{name}_invalid")
    if item["slot_id"] != expected_slot_id:
        raise MandateAuthorityError("mandate_authorization_slot_mismatch")
    if item["owner_id"] != expected_owner_id:
        raise MandateAuthorityError("mandate_authorization_owner_mismatch")
    if not _is_hash(item.get("mandate_hash")):
        raise MandateAuthorityError("mandate_authorization_mandate_hash_invalid")
    if item.get("state") not in _ALLOWED_STATES:
        raise MandateAuthorityError("mandate_authorization_state_invalid")
    sequence = item.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
        raise MandateAuthorityError("mandate_authorization_sequence_invalid")
    predecessor = item.get("predecessor_hash")
    if predecessor is not None and not _is_hash(predecessor):
        raise MandateAuthorityError("mandate_authorization_predecessor_invalid")
    if not _is_hash(item.get("payload_hash")):
        raise MandateAuthorityError("mandate_authorization_payload_hash_invalid")

    issued_at = _parse_time(item["issued_at"])
    expires_at = _parse_time(item["expires_at"])
    current = now or _utc_now()
    if current.tzinfo is None:
        raise MandateAuthorityError("mandate_authorization_now_timezone_required")
    current = current.astimezone(timezone.utc)
    if issued_at > current:
        raise MandateAuthorityError("mandate_authorization_from_future")
    if expires_at <= issued_at:
        raise MandateAuthorityError("mandate_authorization_lifetime_invalid")
    if expires_at <= current:
        raise MandateAuthorityError("mandate_authorization_expired")

    valid, reason = verify_olp_signature(item)
    if valid is not True:
        raise MandateAuthorityError(
            f"mandate_authorization_signature_invalid:{reason or 'unknown'}"
        )
    signature = item.get("signature")
    if not isinstance(signature, Mapping):
        raise MandateAuthorityError("mandate_authorization_signature_shape_invalid")
    observed_key = str(signature.get("public_key", "")).lower()
    expected_key = str(expected_public_key).lower()
    if len(expected_key) != 64 or any(char not in _HEX for char in expected_key):
        raise MandateAuthorityError("mandate_owner_public_key_invalid")
    if observed_key != expected_key:
        raise MandateAuthorityError("mandate_authorization_owner_key_mismatch")
    return item


class MandateOwnerView:
    """Receiver-owned current mandate heads keyed by out-of-band slots.

    ``slots`` is receiver configuration, not mandate data. Example::

        {
            "refund-agent/default": {
                "owner_id": "alice",
                "public_key": "<64 hex chars>",
            }
        }

    A mandate proposal becomes governing authority only after ``admit`` accepts
    an owner-signed record for the configured slot. Exactly one monotonic head is
    current per slot.
    """

    def __init__(self, slots: Mapping[str, Mapping[str, str]]) -> None:
        if not isinstance(slots, Mapping) or not slots:
            raise MandateAuthorityError("mandate_owner_slots_required")
        normalized: dict[str, dict[str, str]] = {}
        for slot_id, raw in slots.items():
            if not isinstance(slot_id, str) or not slot_id:
                raise MandateAuthorityError("mandate_slot_id_invalid")
            if not isinstance(raw, Mapping) or set(raw) != {"owner_id", "public_key"}:
                raise MandateAuthorityError("mandate_owner_slot_config_invalid")
            owner_id = raw.get("owner_id")
            key = str(raw.get("public_key", "")).lower()
            if not isinstance(owner_id, str) or not owner_id:
                raise MandateAuthorityError("mandate_owner_id_invalid")
            if len(key) != 64 or any(char not in _HEX for char in key):
                raise MandateAuthorityError("mandate_owner_public_key_invalid")
            normalized[slot_id] = {"owner_id": owner_id, "public_key": key}
        self._slots = normalized
        self._heads: dict[str, dict[str, Any]] = {}

    def _slot(self, slot_id: str) -> dict[str, str]:
        slot = self._slots.get(slot_id)
        if slot is None:
            raise MandateAuthorityError("mandate_owner_slot_unknown")
        return slot

    def head_hash(self, slot_id: str) -> str | None:
        self._slot(slot_id)
        current = self._heads.get(slot_id)
        if current is None:
            return None
        return str(current["authorization"]["payload_hash"])

    def head_sequence(self, slot_id: str) -> int:
        self._slot(slot_id)
        current = self._heads.get(slot_id)
        return 0 if current is None else int(current["authorization"]["sequence"])

    def status(self, slot_id: str, *, now: datetime | None = None) -> str:
        self._slot(slot_id)
        current = self._heads.get(slot_id)
        if current is None:
            return "MISSING"
        check_time = now or _utc_now()
        if check_time.tzinfo is None:
            raise MandateAuthorityError("mandate_authorization_now_timezone_required")
        check_time = check_time.astimezone(timezone.utc)
        authorization = current["authorization"]
        if _parse_time(authorization["expires_at"]) <= check_time:
            return "AUTHORIZATION_EXPIRED"
        if authorization["state"] != "ACTIVE":
            return "REVOKED"
        mandate = MandateSpec.from_mapping(current["mandate"])
        # Mandate expiry is an independent ceiling on owner authorization.
        mandate_expiry = _parse_time(mandate.expires_at)
        if mandate_expiry <= check_time:
            return "MANDATE_EXPIRED"
        return "ACTIVE"

    def current_mandate(
        self,
        slot_id: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        if self.status(slot_id, now=now) != "ACTIVE":
            return None
        return _json_copy(self._heads[slot_id]["mandate"])

    def current_authorization(
        self,
        slot_id: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        if self.status(slot_id, now=now) != "ACTIVE":
            return None
        return _json_copy(self._heads[slot_id]["authorization"])

    def require_current(
        self,
        slot_id: str,
        *,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], str]:
        status = self.status(slot_id, now=now)
        if status != "ACTIVE":
            raise MandateAuthorityError(f"mandate_owner_authority_{status.lower()}")
        head = self.head_hash(slot_id)
        if head is None:
            raise MandateAuthorityError("mandate_owner_authority_missing")
        return _json_copy(self._heads[slot_id]["mandate"]), head

    def admit(
        self,
        authorization: Mapping[str, Any],
        mandate: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Admit one owner-authorized successor as the slot's current head."""
        if not isinstance(authorization, Mapping):
            raise MandateAuthorityError("mandate_authorization_invalid")
        slot_id = str(authorization.get("slot_id", ""))
        slot = self._slot(slot_id)
        checked = validate_mandate_authorization(
            authorization,
            expected_slot_id=slot_id,
            expected_owner_id=slot["owner_id"],
            expected_public_key=slot["public_key"],
            now=now,
        )
        mandate_dict, spec = _normalized_mandate(mandate)
        if spec.mandate_hash != checked["mandate_hash"]:
            raise MandateAuthorityError("mandate_authorization_hash_mismatch")
        # MANDATE-OWNER-001 intentionally uses a non-delegated ownership model:
        # the out-of-band slot owner must be the principal named by the mandate.
        if spec.principal_id != slot["owner_id"]:
            raise MandateAuthorityError("mandate_principal_owner_mismatch")

        current = self._heads.get(slot_id)
        if current is None:
            if checked["state"] != "ACTIVE":
                raise MandateAuthorityError("mandate_authorization_initial_state_invalid")
            if checked["sequence"] != 1:
                raise MandateAuthorityError("mandate_authorization_initial_sequence_invalid")
            if checked["predecessor_hash"] is not None:
                raise MandateAuthorityError("mandate_authorization_initial_predecessor_forbidden")
        else:
            current_auth = current["authorization"]
            if checked["sequence"] != int(current_auth["sequence"]) + 1:
                raise MandateAuthorityError("mandate_authorization_successor_sequence_invalid")
            if checked["predecessor_hash"] != current_auth["payload_hash"]:
                raise MandateAuthorityError("mandate_authorization_successor_predecessor_mismatch")
            if (
                checked["state"] == "REVOKED"
                and checked["mandate_hash"] != current_auth["mandate_hash"]
            ):
                raise MandateAuthorityError("mandate_revocation_target_mismatch")

        self._heads[slot_id] = {
            "authorization": checked,
            "mandate": mandate_dict,
        }
        return {
            "admitted": True,
            "slot_id": slot_id,
            "owner_id": slot["owner_id"],
            "state": checked["state"],
            "sequence": checked["sequence"],
            "head_hash": checked["payload_hash"],
            "mandate_hash": checked["mandate_hash"],
        }

    def assess(
        self,
        authorization: Mapping[str, Any],
        mandate: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Assess historical authenticity separately from current authority."""
        slot_id = str(authorization.get("slot_id", "")) if isinstance(authorization, Mapping) else ""
        try:
            slot = self._slot(slot_id)
            checked = validate_mandate_authorization(
                authorization,
                expected_slot_id=slot_id,
                expected_owner_id=slot["owner_id"],
                expected_public_key=slot["public_key"],
                now=now,
            )
            _mandate_dict, spec = _normalized_mandate(mandate)
            if spec.mandate_hash != checked["mandate_hash"]:
                raise MandateAuthorityError("mandate_authorization_hash_mismatch")
            if spec.principal_id != slot["owner_id"]:
                raise MandateAuthorityError("mandate_principal_owner_mismatch")
        except MandateAuthorityError as exc:
            return {
                "verified": False,
                "current": False,
                "reason_codes": [str(exc)],
                "authorization_hash": (
                    str(authorization.get("payload_hash"))
                    if isinstance(authorization, Mapping)
                    else None
                ),
            }
        current_head = self.head_hash(slot_id)
        is_current = current_head == checked["payload_hash"]
        return {
            "verified": True,
            "current": is_current,
            "state": checked["state"],
            "reason_codes": [] if is_current else ["mandate_authorization_head_mismatch"],
            "authorization_hash": checked["payload_hash"],
            "current_head_hash": current_head,
            "mandate_hash": checked["mandate_hash"],
            "sequence": checked["sequence"],
        }


def _load_policy_proposal(value: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Mapping):
        bundle = _json_copy(dict(value))
    else:
        path = Path(value)
        try:
            bundle = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MandateAuthorityError(f"mandate_policy_bundle_unreadable:{path}") from exc
    if not isinstance(bundle, dict):
        raise MandateAuthorityError("mandate_policy_bundle_invalid")
    if bundle.get("schema") != POLICY_BUNDLE_SCHEMA:
        raise MandateAuthorityError("mandate_policy_bundle_schema_invalid")
    if set(bundle) != {"schema", "mandate", "permission_policy"}:
        raise MandateAuthorityError("mandate_policy_bundle_shape_invalid")
    if not isinstance(bundle.get("permission_policy"), Mapping):
        raise MandateAuthorityError("mandate_permission_policy_invalid")
    # Validate the authored mandate as a proposal, but do not grant it authority.
    _normalized_mandate(bundle.get("mandate", {}))
    return bundle


def authorize_owned(
    *,
    policy: str | Path | Mapping[str, Any],
    mandate_view: MandateOwnerView,
    mandate_slot_id: str,
    target: str | Callable[[ToolCallContext], str],
    semantics: Callable[[ToolCallContext], Mapping[str, Any]],
    state_source: Callable[[ToolCallContext], Mapping[str, Any] | str],
    evidence_sources: Mapping[str, Callable[[ToolCallContext], Any]],
    tool: str | None = None,
    producer_model: str = "untrusted-agent",
    objective: str = "execute the requested tool call",
    runtime: Any | None = None,
    runtime_dir: str | Path = ".openline/runtime",
    return_receipt: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Guard a function using only the receiver-admitted current mandate.

    ``policy['mandate']`` remains developer-authored proposal material. It is
    never passed to the Authority Compiler as governing authority. Each call
    resolves the receiver's current mandate head for ``mandate_slot_id`` and
    injects that admitted mandate into the existing ``authorize`` path.

    The selected head is also bound into receiver state. If the mandate head
    changes after selection but before execution preflight, the call fails
    closed rather than spending authority from the stale head.
    """
    if not isinstance(mandate_view, MandateOwnerView):
        raise MandateAuthorityError("mandate_owner_view_invalid")
    if not isinstance(mandate_slot_id, str) or not mandate_slot_id:
        raise MandateAuthorityError("mandate_slot_id_invalid")
    if not callable(state_source):
        raise MandateAuthorityError("mandate_state_source_not_callable")
    proposal_bundle = _load_policy_proposal(policy)
    permission_policy = _json_copy(proposal_bundle["permission_policy"])

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        active_runtime = runtime or LocalAuthorityRuntime(runtime_dir)

        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            selected_at = _utc_now()
            try:
                current_mandate, selected_head_hash = mandate_view.require_current(
                    mandate_slot_id,
                    now=selected_at,
                )
            except MandateAuthorityError as exc:
                raise AuthorizationBlocked("DENY", [str(exc)]) from exc

            active_bundle = {
                "schema": POLICY_BUNDLE_SCHEMA,
                "mandate": current_mandate,
                "permission_policy": permission_policy,
            }

            def owner_bound_state(call: ToolCallContext) -> Mapping[str, Any]:
                observed_status = mandate_view.status(mandate_slot_id, now=_utc_now())
                observed_head = mandate_view.head_hash(mandate_slot_id)
                if observed_status != "ACTIVE":
                    raise MandateAuthorityError(
                        f"mandate_owner_authority_{observed_status.lower()}"
                    )
                if observed_head != selected_head_hash:
                    raise MandateAuthorityError("mandate_owner_head_changed")
                application_state = state_source(call)
                if isinstance(application_state, Mapping):
                    frozen_application_state: Any = {
                        "kind": "mapping",
                        "value": _json_copy(dict(application_state)),
                    }
                elif isinstance(application_state, str):
                    frozen_application_state = {
                        "kind": "string",
                        "value": application_state,
                    }
                else:
                    raise MandateAuthorityError("mandate_state_source_result_invalid")
                return {
                    "application_state": frozen_application_state,
                    "mandate_slot_id": mandate_slot_id,
                    "mandate_head_hash": selected_head_hash,
                }

            guarded = authorize(
                policy=active_bundle,
                target=target,
                semantics=semantics,
                state_source=owner_bound_state,
                evidence_sources=evidence_sources,
                tool=tool,
                producer_model=producer_model,
                objective=objective,
                runtime=active_runtime,
                runtime_dir=runtime_dir,
                return_receipt=return_receipt,
            )(function)
            return guarded(*args, **kwargs)

        wrapped.__openline_guarded__ = True  # type: ignore[attr-defined]
        wrapped.__openline_mandate_owner__ = True  # type: ignore[attr-defined]
        wrapped.openline_mandate_slot_id = mandate_slot_id  # type: ignore[attr-defined]
        wrapped.openline_mandate_owner_view = mandate_view  # type: ignore[attr-defined]
        wrapped.openline_policy_proposal = _json_copy(proposal_bundle)  # type: ignore[attr-defined]
        return wrapped

    return decorate
