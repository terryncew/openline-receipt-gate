"""Bounded wallet standing protocol used by WALLET-STANDING-001.

This is an experiment kernel, not a production wallet or witness network. It
tests five separations:

* a pinned principal root certifies replaceable wallet epoch keys;
* an epoch key signs a subject-bound, expiring mandate;
* independently salted Merkle leaves permit selective field disclosure;
* a receiver applies its own freshness policy to a signed standing witness;
* a subject proves possession for one receiver challenge, preventing a copied
  mandate projection from becoming a bearer credential.

The kernel intentionally supports only top-level JSON fields under OpenLine's
integer-only canonical JSON profile. Root recovery and witness distribution are
outside WALLET-STANDING-001.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
from typing import Any, Callable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import (
    MAX_SAFE_INTEGER,
    olp_canonical_json,
    public_key_hex,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)


EPOCH_CERTIFICATE_SCHEMA = "openline.wallet_epoch_certificate.v1"
MANDATE_SCHEMA = "openline.wallet_merkle_mandate.v1"
PROJECTION_SCHEMA = "openline.wallet_mandate_projection.v1"
HOLDER_PROOF_SCHEMA = "openline.wallet_holder_proof.v1"
STANDING_WITNESS_SCHEMA = "openline.wallet_standing_witness.v1"
BUNDLE_SCHEMA = "openline.wallet_presentation_bundle.v1"
LEAF_DOMAIN = "OLP-MANDATE-LEAF-v1"
NODE_DOMAIN = b"OLP-MANDATE-NODE-v1\x00"

_HEX = frozenset("0123456789abcdef")
_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:/-]{0,127}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_RISK_TIERS = frozenset({"HIGH", "LOW"})
_STANDING_VALUES = frozenset({"ACTIVE", "REVOKED"})
_MAX_FIELDS = 64


class WalletProtocolError(ValueError):
    """Fail-closed protocol error carrying a stable reason code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AdmissionPolicy:
    """Receiver-owned acceptance policy for one wallet presentation."""

    high_risk_max_witness_age_seconds: int
    low_risk_max_offline_ttl_seconds: int
    required_fields: tuple[str, ...]
    forbid_extra_disclosures: bool = True

    def __post_init__(self) -> None:
        if (
            isinstance(self.high_risk_max_witness_age_seconds, bool)
            or self.high_risk_max_witness_age_seconds <= 0
        ):
            raise WalletProtocolError("policy_witness_age_invalid")
        if (
            isinstance(self.low_risk_max_offline_ttl_seconds, bool)
            or self.low_risk_max_offline_ttl_seconds <= 0
        ):
            raise WalletProtocolError("policy_offline_ttl_invalid")
        if not self.required_fields or len(set(self.required_fields)) != len(
            self.required_fields
        ):
            raise WalletProtocolError("policy_required_fields_invalid")
        for field in self.required_fields:
            _field_name(field)


@dataclass(frozen=True)
class IssuedMandate:
    """Private wallet state plus the portable signed mandate."""

    epoch_certificate: Mapping[str, Any]
    mandate: Mapping[str, Any]
    fields: Mapping[str, Any]
    salts: Mapping[str, str]
    proofs: Mapping[str, tuple[Mapping[str, str], ...]]


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise WalletProtocolError(f"{label}_invalid")
    return value


def _field_name(value: Any) -> str:
    if not isinstance(value, str) or not _FIELD.fullmatch(value):
        raise WalletProtocolError("field_name_invalid")
    return value


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(olp_canonical_json(value).decode("ascii"))
    except (TypeError, ValueError) as exc:
        raise WalletProtocolError("canonical_json_invalid") from exc


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise WalletProtocolError("timestamp_timezone_required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise WalletProtocolError(f"{label}_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise WalletProtocolError(f"{label}_invalid") from exc
    if parsed.tzinfo is None:
        raise WalletProtocolError(f"{label}_timezone_required")
    return parsed.astimezone(timezone.utc)


def _seconds(delta) -> int:
    return int(delta.total_seconds())


def _signed_body(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, Mapping):
        raise WalletProtocolError("signed_record_invalid")
    body = dict(receipt)
    body.pop("payload_hash", None)
    body.pop("signature", None)
    return body


def _verify_signature(
    receipt: Mapping[str, Any],
    *,
    expected_public_key: str,
    schema: str,
    label: str,
) -> None:
    if not isinstance(receipt, Mapping) or receipt.get("schema") != schema:
        raise WalletProtocolError(f"{label}_schema_invalid")
    valid, _reason = verify_olp_signature(receipt)
    if valid is not True:
        raise WalletProtocolError(f"{label}_signature_invalid")
    signature = receipt.get("signature")
    if (
        not isinstance(signature, Mapping)
        or str(signature.get("public_key", "")).lower()
        != str(expected_public_key).lower()
    ):
        raise WalletProtocolError(f"{label}_signer_mismatch")


def issue_epoch_certificate(
    root_key: Ed25519PrivateKey,
    epoch_key: Ed25519PrivateKey,
    *,
    principal_id: str,
    epoch_id: str,
    sequence: int,
    issued_at: datetime,
    expires_at: datetime,
    predecessor_epoch_id: str | None = None,
    branch: str = "operational",
) -> dict[str, Any]:
    """Have the pinned principal root certify one replaceable epoch key."""
    principal = _identifier(principal_id, "principal_id")
    epoch = _identifier(epoch_id, "epoch_id")
    branch_value = _identifier(branch, "epoch_branch")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise WalletProtocolError("epoch_sequence_invalid")
    if predecessor_epoch_id is not None:
        _identifier(predecessor_epoch_id, "predecessor_epoch_id")
    issued = _parse_time(_iso(issued_at), "epoch_issued_at")
    expires = _parse_time(_iso(expires_at), "epoch_expires_at")
    if expires <= issued:
        raise WalletProtocolError("epoch_lifetime_invalid")
    return sign_olp_body(
        {
            "schema": EPOCH_CERTIFICATE_SCHEMA,
            "principal_id": principal,
            "epoch_id": epoch,
            "sequence": sequence,
            "branch": branch_value,
            "epoch_public_key": public_key_hex(epoch_key),
            "predecessor_epoch_id": predecessor_epoch_id,
            "issued_at": _iso(issued),
            "expires_at": _iso(expires),
        },
        root_key,
    )


def _validate_field_value(value: Any) -> Any:
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise WalletProtocolError("field_integer_out_of_range")
    return _json_copy(value)


def merkle_leaf_commitment(
    *,
    mandate_id: str,
    field_path: str,
    salt_hex: str,
    value: Any,
) -> str:
    """Commit one field with mandate and path domain separation."""
    mandate = _identifier(mandate_id, "mandate_id")
    path = _field_name(field_path)
    if (
        not isinstance(salt_hex, str)
        or len(salt_hex) != 64
        or any(character not in _HEX for character in salt_hex)
    ):
        raise WalletProtocolError("field_salt_invalid")
    body = {
        "domain": LEAF_DOMAIN,
        "mandate_id": mandate,
        "field_path": path,
        "salt": salt_hex,
        "value": _validate_field_value(value),
    }
    return sha256_hex(olp_canonical_json(body))


def _node_hash(left: str, right: str) -> str:
    if not _is_hash(left) or not _is_hash(right):
        raise WalletProtocolError("merkle_node_invalid")
    return hashlib.sha256(
        NODE_DOMAIN + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


def _build_merkle(
    leaves: Sequence[tuple[str, str]],
) -> tuple[str, dict[str, tuple[dict[str, str], ...]]]:
    if not leaves:
        raise WalletProtocolError("mandate_fields_empty")
    ordered = sorted(leaves, key=lambda item: item[0])
    paths = [item[0] for item in ordered]
    if len(paths) != len(set(paths)):
        raise WalletProtocolError("mandate_field_duplicate")
    level = [item[1] for item in ordered]
    proof_lists: list[list[dict[str, str]]] = [[] for _ in ordered]
    memberships = [[index] for index in range(len(ordered))]

    while len(level) > 1:
        next_level: list[str] = []
        next_memberships: list[list[int]] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            left_members = memberships[index]
            right_members = (
                memberships[index + 1]
                if index + 1 < len(memberships)
                else memberships[index]
            )
            for member in left_members:
                proof_lists[member].append({"side": "RIGHT", "hash": right})
            if index + 1 < len(level):
                for member in right_members:
                    proof_lists[member].append({"side": "LEFT", "hash": left})
            next_level.append(_node_hash(left, right))
            next_memberships.append(sorted(set(left_members + right_members)))
        level = next_level
        memberships = next_memberships

    proofs = {
        path: tuple(proof_lists[index]) for index, path in enumerate(paths)
    }
    return level[0], proofs


def _verify_merkle_proof(leaf: str, proof: Sequence[Mapping[str, Any]], root: str) -> bool:
    if not _is_hash(leaf) or not _is_hash(root):
        return False
    current = leaf
    for step in proof:
        if not isinstance(step, Mapping) or set(step) != {"side", "hash"}:
            return False
        sibling = step.get("hash")
        side = step.get("side")
        if not _is_hash(sibling) or side not in {"LEFT", "RIGHT"}:
            return False
        current = (
            _node_hash(str(sibling), current)
            if side == "LEFT"
            else _node_hash(current, str(sibling))
        )
    return current == root


def issue_mandate(
    epoch_key: Ed25519PrivateKey,
    epoch_certificate: Mapping[str, Any],
    *,
    mandate_id: str,
    subject_key: Ed25519PrivateKey,
    risk_tier: str,
    fields: Mapping[str, Any],
    issued_at: datetime,
    expires_at: datetime,
    epoch_salt_registry: set[str],
    salt_source: Callable[[int], bytes] = secrets.token_bytes,
) -> IssuedMandate:
    """Issue a subject-bound mandate with independently salted field leaves."""
    mandate = _identifier(mandate_id, "mandate_id")
    if risk_tier not in _RISK_TIERS:
        raise WalletProtocolError("risk_tier_invalid")
    if not isinstance(fields, Mapping) or not fields or len(fields) > _MAX_FIELDS:
        raise WalletProtocolError("mandate_fields_invalid")
    if not callable(salt_source):
        raise WalletProtocolError("salt_source_invalid")
    if not isinstance(epoch_salt_registry, set) or any(
        not isinstance(value, str) for value in epoch_salt_registry
    ):
        raise WalletProtocolError("epoch_salt_registry_invalid")
    epoch_body = _signed_body(epoch_certificate)
    if epoch_body.get("schema") != EPOCH_CERTIFICATE_SCHEMA:
        raise WalletProtocolError("epoch_certificate_schema_invalid")
    if epoch_body.get("epoch_public_key") != public_key_hex(epoch_key):
        raise WalletProtocolError("epoch_key_mismatch")

    issued = _parse_time(_iso(issued_at), "mandate_issued_at")
    expires = _parse_time(_iso(expires_at), "mandate_expires_at")
    if expires <= issued:
        raise WalletProtocolError("mandate_lifetime_invalid")
    epoch_issued = _parse_time(epoch_body.get("issued_at"), "epoch_issued_at")
    epoch_expires = _parse_time(epoch_body.get("expires_at"), "epoch_expires_at")
    if issued < epoch_issued or expires > epoch_expires:
        raise WalletProtocolError("mandate_outside_epoch_lifetime")

    copied_fields: dict[str, Any] = {}
    salts: dict[str, str] = {}
    leaves: list[tuple[str, str]] = []
    used_salts: set[str] = set()
    for raw_path, raw_value in sorted(fields.items()):
        path = _field_name(raw_path)
        value = _validate_field_value(raw_value)
        raw_salt = salt_source(32)
        if not isinstance(raw_salt, bytes) or len(raw_salt) != 32:
            raise WalletProtocolError("salt_source_output_invalid")
        salt = raw_salt.hex()
        if salt in used_salts or salt in epoch_salt_registry:
            raise WalletProtocolError("salt_reuse_detected")
        used_salts.add(salt)
        copied_fields[path] = value
        salts[path] = salt
        leaves.append(
            (
                path,
                merkle_leaf_commitment(
                    mandate_id=mandate,
                    field_path=path,
                    salt_hex=salt,
                    value=value,
                ),
            )
        )
    merkle_root, proofs = _build_merkle(leaves)
    epoch_salt_registry.update(used_salts)
    signed = sign_olp_body(
        {
            "schema": MANDATE_SCHEMA,
            "mandate_id": mandate,
            "principal_id": epoch_body["principal_id"],
            "issuer_epoch_id": epoch_body["epoch_id"],
            "issuer_epoch_certificate_hash": epoch_certificate["payload_hash"],
            "subject_public_key": public_key_hex(subject_key),
            "risk_tier": risk_tier,
            "issued_at": _iso(issued),
            "expires_at": _iso(expires),
            "field_count": len(copied_fields),
            "merkle_root": merkle_root,
            "salt_profile": "independent-random-32-byte/v1",
        },
        epoch_key,
    )
    return IssuedMandate(
        epoch_certificate=_json_copy(epoch_certificate),
        mandate=_json_copy(signed),
        fields=_json_copy(copied_fields),
        salts=_json_copy(salts),
        proofs={
            path: tuple(_json_copy(step) for step in path_proof)
            for path, path_proof in proofs.items()
        },
    )


def issue_standing_witness(
    root_key: Ed25519PrivateKey,
    epoch_certificate: Mapping[str, Any],
    *,
    standing: str,
    sequence: int,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Create the controlled root-signed witness consumed by the frozen Gate."""
    if standing not in _STANDING_VALUES:
        raise WalletProtocolError("standing_value_invalid")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise WalletProtocolError("standing_sequence_invalid")
    epoch_body = _signed_body(epoch_certificate)
    if epoch_body.get("schema") != EPOCH_CERTIFICATE_SCHEMA:
        raise WalletProtocolError("epoch_certificate_schema_invalid")
    issued = _parse_time(_iso(issued_at), "witness_issued_at")
    expires = _parse_time(_iso(expires_at), "witness_expires_at")
    if expires <= issued:
        raise WalletProtocolError("witness_lifetime_invalid")
    return sign_olp_body(
        {
            "schema": STANDING_WITNESS_SCHEMA,
            "principal_id": epoch_body["principal_id"],
            "epoch_id": epoch_body["epoch_id"],
            "epoch_certificate_hash": epoch_certificate["payload_hash"],
            "standing": standing,
            "sequence": sequence,
            "issued_at": _iso(issued),
            "expires_at": _iso(expires),
        },
        root_key,
    )


def _projection_hash(projection: Mapping[str, Any]) -> str:
    return sha256_hex(olp_canonical_json(projection))


def build_presentation_bundle(
    issued: IssuedMandate,
    *,
    disclose_fields: Sequence[str],
    subject_key: Ed25519PrivateKey,
    receiver_challenge: str,
    standing_witness: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Project selected fields and bind them to one holder challenge."""
    if not isinstance(issued, IssuedMandate):
        raise WalletProtocolError("issued_mandate_required")
    challenge = _identifier(receiver_challenge, "receiver_challenge")
    mandate = dict(issued.mandate)
    if mandate.get("subject_public_key") != public_key_hex(subject_key):
        raise WalletProtocolError("subject_key_mismatch")
    paths = [_field_name(item) for item in disclose_fields]
    if not paths or len(paths) != len(set(paths)):
        raise WalletProtocolError("projection_fields_invalid")
    entries: list[dict[str, Any]] = []
    for path in sorted(paths):
        if path not in issued.fields:
            raise WalletProtocolError("projection_field_unknown")
        entries.append(
            {
                "field_path": path,
                "value": _json_copy(issued.fields[path]),
                "salt": issued.salts[path],
                "proof": [_json_copy(step) for step in issued.proofs[path]],
            }
        )
    projection = {
        "schema": PROJECTION_SCHEMA,
        "mandate_id": mandate["mandate_id"],
        "merkle_root": mandate["merkle_root"],
        "disclosures": entries,
    }
    holder = sign_olp_body(
        {
            "schema": HOLDER_PROOF_SCHEMA,
            "subject_public_key": mandate["subject_public_key"],
            "receiver_challenge": challenge,
            "epoch_certificate_hash": issued.epoch_certificate["payload_hash"],
            "mandate_hash": mandate["payload_hash"],
            "projection_hash": _projection_hash(projection),
        },
        subject_key,
    )
    return {
        "schema": BUNDLE_SCHEMA,
        "epoch_certificate": _json_copy(issued.epoch_certificate),
        "mandate": _json_copy(mandate),
        "projection": _json_copy(projection),
        "holder_proof": _json_copy(holder),
        "standing_witness": (
            None if standing_witness is None else _json_copy(standing_witness)
        ),
    }


def _validate_epoch(
    certificate: Mapping[str, Any],
    *,
    trusted_root_public_key: str,
    now: datetime,
) -> dict[str, Any]:
    required = {
        "schema",
        "principal_id",
        "epoch_id",
        "sequence",
        "branch",
        "epoch_public_key",
        "predecessor_epoch_id",
        "issued_at",
        "expires_at",
        "payload_hash",
        "signature",
    }
    if not isinstance(certificate, Mapping) or set(certificate) != required:
        raise WalletProtocolError("epoch_certificate_shape_invalid")
    _verify_signature(
        certificate,
        expected_public_key=trusted_root_public_key,
        schema=EPOCH_CERTIFICATE_SCHEMA,
        label="epoch_certificate",
    )
    _identifier(certificate.get("principal_id"), "principal_id")
    _identifier(certificate.get("epoch_id"), "epoch_id")
    _identifier(certificate.get("branch"), "epoch_branch")
    key = certificate.get("epoch_public_key")
    if not _is_hash(key):
        raise WalletProtocolError("epoch_public_key_invalid")
    issued = _parse_time(certificate.get("issued_at"), "epoch_issued_at")
    expires = _parse_time(certificate.get("expires_at"), "epoch_expires_at")
    if issued > now:
        raise WalletProtocolError("epoch_from_future")
    if expires <= now:
        raise WalletProtocolError("epoch_expired")
    if expires <= issued:
        raise WalletProtocolError("epoch_lifetime_invalid")
    return dict(certificate)


def _validate_mandate(
    mandate: Mapping[str, Any],
    epoch: Mapping[str, Any],
    *,
    now: datetime,
) -> tuple[dict[str, Any], datetime, datetime]:
    required = {
        "schema",
        "mandate_id",
        "principal_id",
        "issuer_epoch_id",
        "issuer_epoch_certificate_hash",
        "subject_public_key",
        "risk_tier",
        "issued_at",
        "expires_at",
        "field_count",
        "merkle_root",
        "salt_profile",
        "payload_hash",
        "signature",
    }
    if not isinstance(mandate, Mapping) or set(mandate) != required:
        raise WalletProtocolError("mandate_shape_invalid")
    _verify_signature(
        mandate,
        expected_public_key=str(epoch["epoch_public_key"]),
        schema=MANDATE_SCHEMA,
        label="mandate",
    )
    if mandate.get("principal_id") != epoch.get("principal_id"):
        raise WalletProtocolError("mandate_principal_mismatch")
    if mandate.get("issuer_epoch_id") != epoch.get("epoch_id"):
        raise WalletProtocolError("mandate_epoch_mismatch")
    if mandate.get("issuer_epoch_certificate_hash") != epoch.get("payload_hash"):
        raise WalletProtocolError("mandate_epoch_binding_mismatch")
    if mandate.get("risk_tier") not in _RISK_TIERS:
        raise WalletProtocolError("risk_tier_invalid")
    if not _is_hash(mandate.get("subject_public_key")):
        raise WalletProtocolError("subject_public_key_invalid")
    if not _is_hash(mandate.get("merkle_root")):
        raise WalletProtocolError("mandate_merkle_root_invalid")
    if mandate.get("salt_profile") != "independent-random-32-byte/v1":
        raise WalletProtocolError("mandate_salt_profile_invalid")
    field_count = mandate.get("field_count")
    if (
        isinstance(field_count, bool)
        or not isinstance(field_count, int)
        or field_count <= 0
        or field_count > _MAX_FIELDS
    ):
        raise WalletProtocolError("mandate_field_count_invalid")
    issued = _parse_time(mandate.get("issued_at"), "mandate_issued_at")
    expires = _parse_time(mandate.get("expires_at"), "mandate_expires_at")
    if issued > now:
        raise WalletProtocolError("mandate_from_future")
    if expires <= now:
        raise WalletProtocolError("mandate_expired")
    if expires <= issued:
        raise WalletProtocolError("mandate_lifetime_invalid")
    return dict(mandate), issued, expires


def _validate_projection(
    projection: Mapping[str, Any],
    mandate: Mapping[str, Any],
    *,
    expected_action: Mapping[str, Any],
    policy: AdmissionPolicy,
) -> dict[str, Any]:
    if not isinstance(projection, Mapping) or set(projection) != {
        "schema",
        "mandate_id",
        "merkle_root",
        "disclosures",
    }:
        raise WalletProtocolError("projection_shape_invalid")
    if projection.get("schema") != PROJECTION_SCHEMA:
        raise WalletProtocolError("projection_schema_invalid")
    if projection.get("mandate_id") != mandate.get("mandate_id"):
        raise WalletProtocolError("projection_mandate_mismatch")
    if projection.get("merkle_root") != mandate.get("merkle_root"):
        raise WalletProtocolError("projection_root_mismatch")
    disclosures = projection.get("disclosures")
    if not isinstance(disclosures, list) or not disclosures:
        raise WalletProtocolError("projection_disclosures_invalid")
    observed: dict[str, Any] = {}
    for entry in disclosures:
        if not isinstance(entry, Mapping) or set(entry) != {
            "field_path",
            "value",
            "salt",
            "proof",
        }:
            raise WalletProtocolError("projection_entry_shape_invalid")
        path = _field_name(entry.get("field_path"))
        if path in observed:
            raise WalletProtocolError("projection_field_duplicate")
        proof = entry.get("proof")
        if not isinstance(proof, list):
            raise WalletProtocolError("projection_proof_invalid")
        try:
            leaf = merkle_leaf_commitment(
                mandate_id=str(mandate["mandate_id"]),
                field_path=path,
                salt_hex=str(entry.get("salt", "")),
                value=entry.get("value"),
            )
        except WalletProtocolError as exc:
            raise WalletProtocolError("merkle_proof_invalid") from exc
        if not _verify_merkle_proof(leaf, proof, str(mandate["merkle_root"])):
            raise WalletProtocolError("merkle_proof_invalid")
        observed[path] = _json_copy(entry.get("value"))
    required = set(policy.required_fields)
    present = set(observed)
    if not required <= present:
        raise WalletProtocolError("required_disclosure_missing")
    if policy.forbid_extra_disclosures and present != required:
        raise WalletProtocolError("unexpected_disclosure")
    expected = _json_copy(dict(expected_action))
    if set(expected) != required:
        raise WalletProtocolError("expected_action_shape_invalid")
    if observed != expected:
        raise WalletProtocolError("action_binding_mismatch")
    return observed


def _validate_holder(
    holder: Mapping[str, Any],
    *,
    mandate: Mapping[str, Any],
    epoch: Mapping[str, Any],
    projection: Mapping[str, Any],
    receiver_challenge: str,
) -> None:
    required = {
        "schema",
        "subject_public_key",
        "receiver_challenge",
        "epoch_certificate_hash",
        "mandate_hash",
        "projection_hash",
        "payload_hash",
        "signature",
    }
    if not isinstance(holder, Mapping) or set(holder) != required:
        raise WalletProtocolError("holder_proof_shape_invalid")
    if holder.get("subject_public_key") != mandate.get("subject_public_key"):
        raise WalletProtocolError("subject_binding_mismatch")
    _verify_signature(
        holder,
        expected_public_key=str(mandate["subject_public_key"]),
        schema=HOLDER_PROOF_SCHEMA,
        label="holder_proof",
    )
    if holder.get("receiver_challenge") != receiver_challenge:
        raise WalletProtocolError("holder_challenge_mismatch")
    if holder.get("epoch_certificate_hash") != epoch.get("payload_hash"):
        raise WalletProtocolError("holder_epoch_binding_mismatch")
    if holder.get("mandate_hash") != mandate.get("payload_hash"):
        raise WalletProtocolError("holder_mandate_binding_mismatch")
    if holder.get("projection_hash") != _projection_hash(projection):
        raise WalletProtocolError("holder_projection_binding_mismatch")


def _validate_witness(
    witness: Mapping[str, Any],
    *,
    epoch: Mapping[str, Any],
    trusted_root_public_key: str,
    now: datetime,
    max_age_seconds: int | None,
) -> str:
    required = {
        "schema",
        "principal_id",
        "epoch_id",
        "epoch_certificate_hash",
        "standing",
        "sequence",
        "issued_at",
        "expires_at",
        "payload_hash",
        "signature",
    }
    if not isinstance(witness, Mapping) or set(witness) != required:
        raise WalletProtocolError("standing_witness_shape_invalid")
    _verify_signature(
        witness,
        expected_public_key=trusted_root_public_key,
        schema=STANDING_WITNESS_SCHEMA,
        label="standing_witness",
    )
    if witness.get("principal_id") != epoch.get("principal_id"):
        raise WalletProtocolError("witness_principal_mismatch")
    if witness.get("epoch_id") != epoch.get("epoch_id"):
        raise WalletProtocolError("witness_epoch_mismatch")
    if witness.get("epoch_certificate_hash") != epoch.get("payload_hash"):
        raise WalletProtocolError("witness_epoch_binding_mismatch")
    if witness.get("standing") not in _STANDING_VALUES:
        raise WalletProtocolError("standing_value_invalid")
    issued = _parse_time(witness.get("issued_at"), "witness_issued_at")
    expires = _parse_time(witness.get("expires_at"), "witness_expires_at")
    if issued > now:
        raise WalletProtocolError("witness_from_future")
    if expires <= now:
        raise WalletProtocolError("freshness_required")
    if max_age_seconds is not None and _seconds(now - issued) > max_age_seconds:
        raise WalletProtocolError("freshness_required")
    return str(witness["standing"])


def _evaluate_bundle(
    bundle: Mapping[str, Any],
    *,
    trusted_root_public_key: str,
    expected_action: Mapping[str, Any],
    receiver_challenge: str,
    now: datetime,
    policy: AdmissionPolicy,
) -> dict[str, Any]:
    if now.tzinfo is None:
        raise WalletProtocolError("gate_time_timezone_required")
    current = now.astimezone(timezone.utc)
    if not _is_hash(trusted_root_public_key):
        raise WalletProtocolError("trusted_root_key_invalid")
    challenge = _identifier(receiver_challenge, "receiver_challenge")
    if not isinstance(bundle, Mapping) or set(bundle) != {
        "schema",
        "epoch_certificate",
        "mandate",
        "projection",
        "holder_proof",
        "standing_witness",
    }:
        raise WalletProtocolError("bundle_shape_invalid")
    if bundle.get("schema") != BUNDLE_SCHEMA:
        raise WalletProtocolError("bundle_schema_invalid")
    epoch = _validate_epoch(
        bundle["epoch_certificate"],
        trusted_root_public_key=trusted_root_public_key,
        now=current,
    )
    mandate, issued, expires = _validate_mandate(
        bundle["mandate"], epoch, now=current
    )
    disclosed = _validate_projection(
        bundle["projection"],
        mandate,
        expected_action=expected_action,
        policy=policy,
    )
    _validate_holder(
        bundle["holder_proof"],
        mandate=mandate,
        epoch=epoch,
        projection=bundle["projection"],
        receiver_challenge=challenge,
    )

    witness = bundle.get("standing_witness")
    risk_tier = str(mandate["risk_tier"])
    standing_mode: str
    if risk_tier == "HIGH":
        if witness is None:
            raise WalletProtocolError("freshness_required")
        standing = _validate_witness(
            witness,
            epoch=epoch,
            trusted_root_public_key=trusted_root_public_key,
            now=current,
            max_age_seconds=policy.high_risk_max_witness_age_seconds,
        )
        if standing == "REVOKED":
            raise WalletProtocolError("epoch_revoked")
        standing_mode = "FRESH_WITNESS"
    else:
        lifetime = _seconds(expires - issued)
        if lifetime > policy.low_risk_max_offline_ttl_seconds:
            raise WalletProtocolError("offline_ttl_exceeds_policy")
        if witness is not None:
            standing = _validate_witness(
                witness,
                epoch=epoch,
                trusted_root_public_key=trusted_root_public_key,
                now=current,
                max_age_seconds=None,
            )
            if standing == "REVOKED":
                raise WalletProtocolError("epoch_revoked")
            standing_mode = "OPTIONAL_WITNESS"
        else:
            standing_mode = "EXPIRY_ONLY"

    return {
        "decision": "PASS",
        "reason_codes": [],
        "executed": True,
        "effect_delta": 1,
        "principal_id": mandate["principal_id"],
        "epoch_id": mandate["issuer_epoch_id"],
        "mandate_id": mandate["mandate_id"],
        "risk_tier": risk_tier,
        "standing_mode": standing_mode,
        "disclosed_fields": sorted(disclosed),
        "wallet_policy_authority": "NONE",
        "decision_authority": "RECEIVER_GATE",
    }


def evaluate_bundle(
    bundle: Mapping[str, Any],
    *,
    trusted_root_public_key: str,
    expected_action: Mapping[str, Any],
    receiver_challenge: str,
    now: datetime,
    policy: AdmissionPolicy,
) -> dict[str, Any]:
    """Fail-closed receiver boundary for a wallet presentation bundle."""
    try:
        return _evaluate_bundle(
            bundle,
            trusted_root_public_key=trusted_root_public_key,
            expected_action=expected_action,
            receiver_challenge=receiver_challenge,
            now=now,
            policy=policy,
        )
    except WalletProtocolError as exc:
        public_code = exc.code.upper()
        return {
            "decision": "BLOCK",
            "reason_codes": [public_code],
            "executed": False,
            "effect_delta": 0,
            "wallet_policy_authority": "NONE",
            "decision_authority": "RECEIVER_GATE",
        }
    except Exception:
        return {
            "decision": "BLOCK",
            "reason_codes": ["WALLET_VERIFICATION_ERROR"],
            "executed": False,
            "effect_delta": 0,
            "wallet_policy_authority": "NONE",
            "decision_authority": "RECEIVER_GATE",
        }
