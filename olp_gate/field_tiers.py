"""Receiver-owned field-tier minimization and portable audit receipts.

The raw action parameters are committed before any disclosure rule runs.  A
receiver-owned definition then decides which top-level fields may cross raw,
which may cross only through a named projection, and which stay inside the
workload.  The public receipt stores commitments, the receiver's definition,
and a binding to an existing gate decision.  It never becomes execution
authority.

This module deliberately implements a bounded v1 surface:

* JSON objects with top-level field declarations;
* the repository's integer-only canonical JSON profile;
* explicit, receiver-installed projection functions; and
* signatures using the existing OpenLine Ed25519 receipt profile.

Nested values may be committed or passed as a declared policy value, but v1
does not classify nested paths independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import (
    MAX_SAFE_INTEGER,
    olp_canonical_json,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)


FIELD_TIER_DEFINITION_PROFILE = "openline.field_tier_definition/v1"
FIELD_TIER_VIEW_PROFILE = "openline.applied_field_tiers/v1"
FIELD_TIER_REQUEST_PROFILE = "openline.minimized_action_request/v1"
FIELD_TIER_RECEIPT_KIND = "openline_field_tier_receipt"
FIELD_TIER_RECEIPT_VERSION = "1"
FIELD_TIER_CANONICALIZATION = "olp-canonical-json-int-v1"

_TIERS = frozenset({"policy", "derived", "payload"})
_VALUE_TYPES = frozenset({"string", "integer", "boolean", "array", "object"})
_DECISIONS = frozenset({"COMMIT", "QUARANTINE", "DENY"})
_HEX = frozenset("0123456789abcdef")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:/-]*$")
_OMIT = object()
_MAX_NAME_LENGTH = 128
_MAX_FIELDS = 128
_MAX_PROJECTIONS_PER_FIELD = 16


class FieldTierError(ValueError):
    """Raised when disclosure rules or minimized requests fail closed."""


Projector = Callable[[Any], Any]


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise FieldTierError("timestamp_timezone_required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


def _name(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_NAME_LENGTH
        or not _NAME.fullmatch(value)
    ):
        raise FieldTierError(f"{label}_invalid")
    return value


def _version(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise FieldTierError("definition_version_invalid")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value):
        raise FieldTierError("definition_version_invalid")
    return value


def _json_copy(value: Any) -> Any:
    """Return a detached JSON value under the OpenLine canonical profile."""
    try:
        canonical = olp_canonical_json(value)
        return json.loads(canonical.decode("ascii"))
    except (TypeError, ValueError) as exc:
        raise FieldTierError("canonical_json_invalid") from exc


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and abs(value) <= MAX_SAFE_INTEGER
        )
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, Mapping)
    return False


def _recipient_domain(value: Any) -> str:
    if not isinstance(value, str):
        raise FieldTierError("projector_input_type_invalid:recipient_domain/v1")
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1].lower()


def _item_count(value: Any) -> int:
    if not isinstance(value, list):
        raise FieldTierError("projector_input_type_invalid:item_count/v1")
    return len(value)


def _endpoint_host(value: Any) -> str:
    if not isinstance(value, str):
        raise FieldTierError("projector_input_type_invalid:endpoint_host/v1")
    candidate = value if "://" in value else "//" + value
    parsed = urlsplit(candidate)
    return (parsed.hostname or "").lower()


DEFAULT_PROJECTORS: Mapping[str, Projector] = MappingProxyType(
    {
        "recipient_domain/v1": _recipient_domain,
        "item_count/v1": _item_count,
        "endpoint_host/v1": _endpoint_host,
    }
)


def normalize_definition(definition: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize the one receiver-owned field declaration."""
    if not isinstance(definition, Mapping):
        raise FieldTierError("definition_invalid")
    expected_keys = {
        "profile",
        "definition_id",
        "version",
        "action_type",
        "fields",
    }
    if set(definition) != expected_keys:
        raise FieldTierError("definition_shape_invalid")
    if definition.get("profile") != FIELD_TIER_DEFINITION_PROFILE:
        raise FieldTierError("definition_profile_invalid")
    definition_id = _name(definition.get("definition_id"), "definition_id")
    version = _version(definition.get("version"))
    action_type = _name(definition.get("action_type"), "action_type")
    raw_fields = definition.get("fields")
    if not isinstance(raw_fields, list) or len(raw_fields) > _MAX_FIELDS:
        raise FieldTierError("definition_fields_invalid")

    fields: list[dict[str, Any]] = []
    field_names: set[str] = set()
    attribute_names: set[str] = set()
    for raw in raw_fields:
        if not isinstance(raw, Mapping):
            raise FieldTierError("definition_field_invalid")
        tier = raw.get("tier")
        if tier not in _TIERS:
            raise FieldTierError("definition_field_tier_invalid")
        base_keys = {"field", "tier", "type", "optional"}
        expected = set(base_keys)
        if tier == "policy":
            expected.add("attribute")
        elif tier == "derived":
            expected.add("projections")
        if set(raw) != expected:
            raise FieldTierError(f"definition_field_shape_invalid:{tier}")
        field = _name(raw.get("field"), "field_name")
        if field in field_names:
            raise FieldTierError(f"definition_field_duplicate:{field}")
        field_names.add(field)
        value_type = raw.get("type")
        if value_type not in _VALUE_TYPES:
            raise FieldTierError(f"definition_field_type_invalid:{field}")
        optional = raw.get("optional")
        if not isinstance(optional, bool):
            raise FieldTierError(f"definition_optional_invalid:{field}")
        normalized: dict[str, Any] = {
            "field": field,
            "tier": tier,
            "type": value_type,
            "optional": optional,
        }
        if tier == "policy":
            attribute = _name(raw.get("attribute"), "attribute_name")
            if attribute in attribute_names:
                raise FieldTierError(f"definition_attribute_duplicate:{attribute}")
            attribute_names.add(attribute)
            normalized["attribute"] = attribute
        elif tier == "derived":
            projections = raw.get("projections")
            if (
                not isinstance(projections, list)
                or not projections
                or len(projections) > _MAX_PROJECTIONS_PER_FIELD
            ):
                raise FieldTierError(f"definition_projections_invalid:{field}")
            projected: list[dict[str, str]] = []
            for item in projections:
                if not isinstance(item, Mapping) or set(item) != {
                    "attribute",
                    "projector",
                    "type",
                }:
                    raise FieldTierError(f"definition_projection_shape_invalid:{field}")
                attribute = _name(item.get("attribute"), "attribute_name")
                projector = _name(item.get("projector"), "projector_name")
                output_type = item.get("type")
                if output_type not in _VALUE_TYPES:
                    raise FieldTierError(
                        f"definition_projection_type_invalid:{attribute}"
                    )
                if attribute in attribute_names:
                    raise FieldTierError(f"definition_attribute_duplicate:{attribute}")
                attribute_names.add(attribute)
                projected.append(
                    {
                        "attribute": attribute,
                        "projector": projector,
                        "type": str(output_type),
                    }
                )
            normalized["projections"] = sorted(
                projected, key=lambda value: value["attribute"]
            )
        fields.append(normalized)

    return {
        "profile": FIELD_TIER_DEFINITION_PROFILE,
        "definition_id": definition_id,
        "version": version,
        "action_type": action_type,
        "fields": sorted(fields, key=lambda value: value["field"]),
    }


def applied_tiers_view(definition: Mapping[str, Any]) -> dict[str, Any]:
    """Rebuild the narrow view whose hash attests the disclosure rules."""
    checked = normalize_definition(definition)
    fields: list[dict[str, Any]] = []
    for rule in checked["fields"]:
        names: list[str] = []
        if rule["tier"] == "derived":
            names = sorted(item["projector"] for item in rule["projections"])
        fields.append(
            {
                "field": rule["field"],
                "tier": rule["tier"],
                "optional": rule["optional"],
                "projections": names,
            }
        )
    return {
        "profile": FIELD_TIER_VIEW_PROFILE,
        "action_type": checked["action_type"],
        "fields": fields,
    }


def applied_tiers_hash(definition: Mapping[str, Any]) -> str:
    return sha256_hex(olp_canonical_json(applied_tiers_view(definition)))


def definition_hash(definition: Mapping[str, Any]) -> str:
    return sha256_hex(olp_canonical_json(normalize_definition(definition)))


def generate_policy_schema(definition: Mapping[str, Any]) -> dict[str, Any]:
    """Generate the attributes a policy is allowed to reference."""
    checked = normalize_definition(definition)
    attributes: dict[str, dict[str, Any]] = {}
    for rule in checked["fields"]:
        if rule["tier"] == "policy":
            attributes[rule["attribute"]] = {
                "type": rule["type"],
                "required": not rule["optional"],
            }
        elif rule["tier"] == "derived":
            for projection in rule["projections"]:
                attributes[projection["attribute"]] = {
                    "type": projection["type"],
                    "required": not rule["optional"],
                }
    return {
        "profile": "openline.field_tier_policy_schema/v1",
        "definition_id": checked["definition_id"],
        "version": checked["version"],
        "action_type": checked["action_type"],
        "attributes": dict(sorted(attributes.items())),
        "additional_attributes": False,
    }


def generate_wire_schema(definition: Mapping[str, Any]) -> dict[str, Any]:
    """Generate the strict minimized-request schema from the same definition."""
    policy_schema = generate_policy_schema(definition)
    return {
        "profile": "openline.field_tier_wire_schema/v1",
        "action_type": policy_schema["action_type"],
        "request_keys": [
            "action_parameters_hash",
            "action_parameters_size_bytes",
            "action_type",
            "applied_tiers_hash",
            "attributes",
            "profile",
        ],
        "attribute_schema": policy_schema["attributes"],
        "additional_request_keys": False,
        "additional_attributes": False,
    }


def generate_definition_artifacts(definition: Mapping[str, Any]) -> dict[str, Any]:
    """Return the tier view, policy schema, and wire schema from one source."""
    checked = normalize_definition(definition)
    return {
        "definition": checked,
        "definition_hash": definition_hash(checked),
        "applied_tiers_view": applied_tiers_view(checked),
        "applied_tiers_hash": applied_tiers_hash(checked),
        "policy_schema": generate_policy_schema(checked),
        "wire_schema": generate_wire_schema(checked),
    }


def minimize_parameters(
    parameters: Mapping[str, Any],
    definition: Mapping[str, Any],
    *,
    projectors: Mapping[str, Projector] = DEFAULT_PROJECTORS,
) -> dict[str, Any]:
    """Commit raw parameters first, then produce the bounded mediator view."""
    if not isinstance(parameters, Mapping):
        raise FieldTierError("action_parameters_invalid")
    checked_parameters = _json_copy(dict(parameters))
    canonical = olp_canonical_json(checked_parameters)
    checked = normalize_definition(definition)
    attributes: dict[str, Any] = {}

    for rule in checked["fields"]:
        field = rule["field"]
        if field not in checked_parameters:
            if rule["optional"]:
                continue
            raise FieldTierError(f"required_parameter_missing:{field}")
        value = checked_parameters[field]
        if not _matches_type(value, rule["type"]):
            raise FieldTierError(f"parameter_type_invalid:{field}")
        if rule["tier"] == "payload":
            continue
        if rule["tier"] == "policy":
            attributes[rule["attribute"]] = value
            continue
        for projection in rule["projections"]:
            name = projection["projector"]
            projector = projectors.get(name)
            if projector is None or not callable(projector):
                raise FieldTierError(f"projector_unavailable:{name}")
            try:
                projected = projector(_json_copy(value))
            except FieldTierError:
                raise
            except Exception as exc:
                raise FieldTierError(f"projector_failed:{name}") from exc
            if projected is _OMIT:
                if not rule["optional"]:
                    raise FieldTierError(
                        f"required_projection_omitted:{projection['attribute']}"
                    )
                continue
            if not _matches_type(projected, projection["type"]):
                raise FieldTierError(
                    f"projection_type_invalid:{projection['attribute']}"
                )
            attributes[projection["attribute"]] = _json_copy(projected)

    minimized = {
        "profile": FIELD_TIER_REQUEST_PROFILE,
        "action_type": checked["action_type"],
        "action_parameters_hash": sha256_hex(canonical),
        "action_parameters_size_bytes": len(canonical),
        "attributes": dict(sorted(attributes.items())),
        "applied_tiers_hash": applied_tiers_hash(checked),
    }
    _json_copy(minimized)
    return minimized


@dataclass(frozen=True)
class FieldTierAdmission:
    """Receiver-side validation result for a minimized action request."""

    request: Mapping[str, Any]
    definition: Mapping[str, Any]
    definition_hash: str
    attributes_hash: str


def admit_minimized_request(
    request: Mapping[str, Any],
    receiver_definitions: Mapping[str, Mapping[str, Any]],
) -> FieldTierAdmission:
    """Validate a client view against the receiver's own definition registry.

    This establishes schema and tier-table agreement.  It cannot establish
    that a remote client honestly computed the digest or projections from its
    hidden parameters; candidate parameters can be checked later by the public
    verifier.
    """
    if not isinstance(request, Mapping):
        raise FieldTierError("minimized_request_invalid")
    required_keys = {
        "profile",
        "action_type",
        "action_parameters_hash",
        "action_parameters_size_bytes",
        "attributes",
        "applied_tiers_hash",
    }
    if set(request) != required_keys:
        raise FieldTierError("minimized_request_shape_invalid")
    if request.get("profile") != FIELD_TIER_REQUEST_PROFILE:
        raise FieldTierError("minimized_request_profile_invalid")
    action_type = _name(request.get("action_type"), "action_type")
    definition = receiver_definitions.get(action_type)
    if not isinstance(definition, Mapping):
        raise FieldTierError("receiver_definition_missing")
    checked_definition = normalize_definition(definition)
    if checked_definition["action_type"] != action_type:
        raise FieldTierError("receiver_definition_action_mismatch")
    if not _is_hash(request.get("action_parameters_hash")):
        raise FieldTierError("action_parameters_hash_invalid")
    size = request.get("action_parameters_size_bytes")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 2
        or size > MAX_SAFE_INTEGER
    ):
        raise FieldTierError("action_parameters_size_invalid")
    if request.get("applied_tiers_hash") != applied_tiers_hash(checked_definition):
        raise FieldTierError("applied_tiers_mismatch")
    attributes = request.get("attributes")
    if not isinstance(attributes, Mapping):
        raise FieldTierError("minimized_attributes_invalid")
    checked_attributes = _json_copy(dict(attributes))
    schema = generate_policy_schema(checked_definition)["attributes"]
    unknown = set(checked_attributes) - set(schema)
    if unknown:
        raise FieldTierError(
            "minimized_attribute_unknown:" + ",".join(sorted(unknown))
        )
    for name, spec in schema.items():
        if spec["required"] and name not in checked_attributes:
            raise FieldTierError(f"minimized_attribute_missing:{name}")
        if name in checked_attributes and not _matches_type(
            checked_attributes[name], spec["type"]
        ):
            raise FieldTierError(f"minimized_attribute_type_invalid:{name}")
    checked_request = {
        "profile": FIELD_TIER_REQUEST_PROFILE,
        "action_type": action_type,
        "action_parameters_hash": str(request["action_parameters_hash"]),
        "action_parameters_size_bytes": int(size),
        "attributes": dict(sorted(checked_attributes.items())),
        "applied_tiers_hash": str(request["applied_tiers_hash"]),
    }
    return FieldTierAdmission(
        request=checked_request,
        definition=checked_definition,
        definition_hash=definition_hash(checked_definition),
        attributes_hash=sha256_hex(
            olp_canonical_json(checked_request["attributes"])
        ),
    )


def issue_field_tier_receipt(
    admission: FieldTierAdmission,
    *,
    decision: str,
    receiver_decision_hash: str,
    policy_id: str,
    issuer_id: str,
    signing_key: Ed25519PrivateKey,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Issue a public receipt without retaining raw or minimized values."""
    if not isinstance(admission, FieldTierAdmission):
        raise FieldTierError("field_tier_admission_required")
    try:
        action_type = str(admission.request["action_type"])
    except (KeyError, TypeError) as exc:
        raise FieldTierError("field_tier_admission_invalid") from exc
    checked_admission = admit_minimized_request(
        admission.request,
        {action_type: admission.definition},
    )
    if (
        checked_admission.definition_hash != admission.definition_hash
        or checked_admission.attributes_hash != admission.attributes_hash
    ):
        raise FieldTierError("field_tier_admission_hash_mismatch")
    if decision not in _DECISIONS:
        raise FieldTierError("field_tier_decision_invalid")
    if not _is_hash(receiver_decision_hash):
        raise FieldTierError("receiver_decision_hash_invalid")
    policy = _name(policy_id, "policy_id")
    issuer = _name(issuer_id, "issuer_id")
    current = now or datetime.now(timezone.utc)
    request = checked_admission.request
    body = {
        "kind": FIELD_TIER_RECEIPT_KIND,
        "receipt_version": FIELD_TIER_RECEIPT_VERSION,
        "canonicalization_id": FIELD_TIER_CANONICALIZATION,
        "issuer": {"id": issuer},
        "created_at": _iso(current),
        "action": {
            "type": request["action_type"],
            "parameters_hash": request["action_parameters_hash"],
            "parameters_size_bytes": request["action_parameters_size_bytes"],
        },
        "disclosure": {
            "definition": dict(checked_admission.definition),
            "definition_hash": checked_admission.definition_hash,
            "applied_tiers_hash": request["applied_tiers_hash"],
            "attributes_hash": checked_admission.attributes_hash,
            "raw_parameters_stored": False,
            "minimized_attributes_stored": False,
        },
        "decision": {
            "value": decision,
            "policy_id": policy,
            "receiver_decision_hash": receiver_decision_hash,
        },
        "authority": {
            "status": "EVIDENCE_ONLY",
            "portable_execution_authority": False,
        },
    }
    return sign_olp_body(body, signing_key)


def verify_field_tier_receipt(
    receipt: Mapping[str, Any],
    trusted_gate_keys: Sequence[str],
    *,
    candidate_parameters: Mapping[str, Any] | None = None,
    projectors: Mapping[str, Projector] = DEFAULT_PROJECTORS,
) -> dict[str, Any]:
    """Verify public integrity and, when supplied, an exact parameter preimage."""
    errors: list[str] = []
    candidate_errors: list[str] = []
    valid_signature, signature_reason = verify_olp_signature(receipt)
    if not valid_signature:
        errors.append(signature_reason or "signature_invalid")
    signature = receipt.get("signature")
    embedded_key = (
        signature.get("public_key") if isinstance(signature, Mapping) else None
    )
    trusted = {str(value).removeprefix("ed25519:") for value in trusted_gate_keys}
    if not trusted or embedded_key not in trusted:
        errors.append("gate_key_not_trusted")
    required_keys = {
        "kind",
        "receipt_version",
        "canonicalization_id",
        "issuer",
        "created_at",
        "action",
        "disclosure",
        "decision",
        "authority",
        "payload_hash",
        "signature",
    }
    if set(receipt) != required_keys:
        errors.append("field_tier_receipt_shape_invalid")
    if receipt.get("kind") != FIELD_TIER_RECEIPT_KIND:
        errors.append("field_tier_receipt_kind_invalid")
    if receipt.get("receipt_version") != FIELD_TIER_RECEIPT_VERSION:
        errors.append("field_tier_receipt_version_invalid")
    if receipt.get("canonicalization_id") != FIELD_TIER_CANONICALIZATION:
        errors.append("field_tier_canonicalization_invalid")
    if _parse_time(receipt.get("created_at")) is None:
        errors.append("field_tier_timestamp_invalid")
    issuer = receipt.get("issuer")
    if (
        not isinstance(issuer, Mapping)
        or set(issuer) != {"id"}
        or not isinstance(issuer.get("id"), str)
        or not issuer.get("id")
    ):
        errors.append("field_tier_issuer_invalid")

    action = receipt.get("action")
    disclosure = receipt.get("disclosure")
    decision = receipt.get("decision")
    authority = receipt.get("authority")
    checked_definition: dict[str, Any] | None = None
    if not isinstance(action, Mapping) or set(action) != {
        "type",
        "parameters_hash",
        "parameters_size_bytes",
    }:
        errors.append("field_tier_action_invalid")
    else:
        try:
            _name(action.get("type"), "action_type")
        except FieldTierError:
            errors.append("field_tier_action_type_invalid")
        if not _is_hash(action.get("parameters_hash")):
            errors.append("field_tier_parameters_hash_invalid")
        size = action.get("parameters_size_bytes")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 2
            or size > MAX_SAFE_INTEGER
        ):
            errors.append("field_tier_parameters_size_invalid")
    if not isinstance(disclosure, Mapping) or set(disclosure) != {
        "definition",
        "definition_hash",
        "applied_tiers_hash",
        "attributes_hash",
        "raw_parameters_stored",
        "minimized_attributes_stored",
    }:
        errors.append("field_tier_disclosure_invalid")
    else:
        if disclosure.get("raw_parameters_stored") is not False:
            errors.append("raw_parameters_retained")
        if disclosure.get("minimized_attributes_stored") is not False:
            errors.append("minimized_attributes_retained")
        for name in ("definition_hash", "applied_tiers_hash", "attributes_hash"):
            if not _is_hash(disclosure.get(name)):
                errors.append(f"field_tier_{name}_invalid")
        try:
            raw_definition = disclosure.get("definition")
            if not isinstance(raw_definition, Mapping):
                raise FieldTierError("definition_invalid")
            checked_definition = normalize_definition(raw_definition)
            if definition_hash(checked_definition) != disclosure.get("definition_hash"):
                errors.append("field_tier_definition_hash_mismatch")
            if applied_tiers_hash(checked_definition) != disclosure.get(
                "applied_tiers_hash"
            ):
                errors.append("field_tier_applied_tiers_hash_mismatch")
            if (
                isinstance(action, Mapping)
                and checked_definition["action_type"] != action.get("type")
            ):
                errors.append("field_tier_definition_action_mismatch")
        except FieldTierError as exc:
            errors.append(f"field_tier_definition_invalid:{exc}")
    if not isinstance(decision, Mapping) or set(decision) != {
        "value",
        "policy_id",
        "receiver_decision_hash",
    }:
        errors.append("field_tier_decision_binding_invalid")
    else:
        if decision.get("value") not in _DECISIONS:
            errors.append("field_tier_decision_invalid")
        try:
            _name(decision.get("policy_id"), "policy_id")
        except FieldTierError:
            errors.append("field_tier_policy_id_invalid")
        if not _is_hash(decision.get("receiver_decision_hash")):
            errors.append("field_tier_receiver_decision_hash_invalid")
    if authority != {
        "status": "EVIDENCE_ONLY",
        "portable_execution_authority": False,
    }:
        errors.append("field_tier_authority_boundary_invalid")

    candidate_status = "NOT_PROVIDED"
    if candidate_parameters is not None:
        candidate_status = "UNVERIFIABLE"
        if checked_definition is None or not isinstance(action, Mapping) or not isinstance(
            disclosure, Mapping
        ):
            candidate_errors.append("candidate_receipt_inputs_invalid")
        else:
            try:
                rebuilt = minimize_parameters(
                    candidate_parameters,
                    checked_definition,
                    projectors=projectors,
                )
                comparisons = {
                    "candidate_parameters_hash_mismatch": (
                        rebuilt["action_parameters_hash"],
                        action.get("parameters_hash"),
                    ),
                    "candidate_parameters_size_mismatch": (
                        rebuilt["action_parameters_size_bytes"],
                        action.get("parameters_size_bytes"),
                    ),
                    "candidate_applied_tiers_mismatch": (
                        rebuilt["applied_tiers_hash"],
                        disclosure.get("applied_tiers_hash"),
                    ),
                    "candidate_attributes_hash_mismatch": (
                        sha256_hex(olp_canonical_json(rebuilt["attributes"])),
                        disclosure.get("attributes_hash"),
                    ),
                }
                for code, (observed, expected) in comparisons.items():
                    if observed != expected:
                        candidate_errors.append(code)
                candidate_status = "MATCH" if not candidate_errors else "MISMATCH"
            except FieldTierError as exc:
                candidate_errors.append(f"candidate_unverifiable:{exc}")

    public_integrity_valid = not errors
    candidate_match = (
        None
        if candidate_parameters is None
        else candidate_status == "MATCH"
    )
    return {
        "valid": public_integrity_valid and candidate_match is not False,
        "public_integrity_valid": public_integrity_valid,
        "candidate_parameters_status": candidate_status,
        "candidate_parameters_match": candidate_match,
        "errors": sorted(set(errors)),
        "candidate_errors": sorted(set(candidate_errors)),
        "payload_hash": receipt.get("payload_hash"),
        "gate_public_key": embedded_key,
        "gate_key_trusted": embedded_key in trusted,
        "authority": "EVIDENCE_ONLY",
    }


__all__ = [
    "DEFAULT_PROJECTORS",
    "FIELD_TIER_CANONICALIZATION",
    "FIELD_TIER_DEFINITION_PROFILE",
    "FIELD_TIER_RECEIPT_KIND",
    "FIELD_TIER_REQUEST_PROFILE",
    "FIELD_TIER_VIEW_PROFILE",
    "FieldTierAdmission",
    "FieldTierError",
    "admit_minimized_request",
    "applied_tiers_hash",
    "applied_tiers_view",
    "definition_hash",
    "generate_definition_artifacts",
    "generate_policy_schema",
    "generate_wire_schema",
    "issue_field_tier_receipt",
    "minimize_parameters",
    "normalize_definition",
    "verify_field_tier_receipt",
]
