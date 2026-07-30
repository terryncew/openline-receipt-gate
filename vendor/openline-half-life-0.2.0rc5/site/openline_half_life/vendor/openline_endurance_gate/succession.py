"""Receiver-owned calibration and advisory succession for COLE measurements.

This module deliberately keeps three questions separate:

* COLE measures a bounded checkpoint.
* A labeled corpus calibrates an agent- and task-specific succession policy.
* The advisory says whether the evidence supports continued observation,
  handoff preparation, or a receiver-reviewed succession candidate.

It never authorizes automatic retirement.  A fresh runtime must receive and
verify a handoff before the source runtime can be retired by its owner.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from fractions import Fraction
from importlib import import_module
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


COLE_ALGORITHM_ID = "cole-portable-core-2.1-draft"
MEASUREMENT_REQUEST_SCHEMA = "openline.succession.measurement-request.v1"
MEASUREMENT_BUNDLE_SCHEMA = "openline.succession.measurement-bundle.v1"
LABELED_OBSERVATION_SCHEMA = "openline.succession.labeled-observation.v1"
CALIBRATION_POLICY_SCHEMA = "openline.succession.calibration-policy.v1"
ASSESSMENT_SCHEMA = "openline.succession.assessment.v1"
CANONICALIZATION_ID = "openline-canonical-json-int-v1"
MAX_SAFE_INTEGER = (1 << 53) - 1
SCALE = 1_000_000
MINIMUM_COLE_CALIBRATION_SAMPLES = 500
MINIMUM_LABELS_PER_SPLIT = 20
MINIMUM_RUNS_PER_LABEL_PER_SPLIT = 5
DEFAULT_CRITICAL_SPECIFICITY_MICROS = 950_000
DEFAULT_MINIMUM_HOLDOUT_BALANCED_ACCURACY_MICROS = 600_000
DEFAULT_MINIMUM_HOLDOUT_SPECIFICITY_MICROS = 950_000
DEFAULT_MINIMUM_HOLDOUT_SENSITIVITY_MICROS = 500_000
DEFAULT_MAX_PERSISTENCE_WINDOW = 5
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_JSONL_BYTES = 1024 * 1024 * 1024
MAX_JSON_DEPTH = 64

SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
HASH256 = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_KEY = re.compile(r"^[0-9a-f]{64}$")

METRICS: dict[str, str] = {
    "kappa_micros": "high",
    "epsilon_micros": "high",
    "delta_hol_micros": "high",
    "phi_star_micros": "low",
}

CONTRACT_FIELDS = (
    "signal_schema_id",
    "smoothing_window",
    "epsilon_window",
    "i_c_micros",
    "alpha_k_micros",
    "alpha_e_micros",
    "stability_delta_micros",
    "dhol_claim_weight_micros",
    "dhol_evidence_weight_micros",
    "dhol_relation_weight_micros",
)


class SuccessionError(ValueError):
    """An invalid or unsupported succession artifact."""


def _validate_json_value(value: Any, *, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Validate canonical integer JSON iteratively to bound hostile nesting."""

    stack: list[tuple[Any, int, str]] = [(value, 0, "$")]
    while stack:
        current, depth, path = stack.pop()
        if depth > max_depth:
            raise SuccessionError(f"{path}: JSON nesting exceeds {max_depth}")
        if current is None or isinstance(current, (str, bool)):
            continue
        if isinstance(current, int):
            if isinstance(current, bool) or abs(current) > MAX_SAFE_INTEGER:
                raise SuccessionError(f"{path}: integer outside interoperable range")
            continue
        if isinstance(current, float):
            raise SuccessionError(f"{path}: floats are forbidden")
        if isinstance(current, (list, tuple)):
            for index, item in enumerate(current):
                stack.append((item, depth + 1, f"{path}[{index}]"))
            continue
        if isinstance(current, Mapping):
            for key, item in current.items():
                if not isinstance(key, str) or not key.isascii():
                    raise SuccessionError(f"{path}: keys must be ASCII strings")
                stack.append((item, depth + 1, f"{path}.{key}"))
            continue
        raise SuccessionError(f"{path}: unsupported value type {type(current).__name__}")


def canonical_json(value: Any) -> bytes:
    _validate_json_value(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SuccessionError(f"duplicate object key: {key}")
        result[key] = value
    return result


def parse_json_strict(text: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=lambda _: (_ for _ in ()).throw(SuccessionError("floats are forbidden")),
            parse_constant=lambda _: (_ for _ in ()).throw(SuccessionError("non-finite values are forbidden")),
        )
    except RecursionError as exc:
        raise SuccessionError("JSON nesting exceeds parser capacity") from exc
    except json.JSONDecodeError as exc:
        raise SuccessionError(f"invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}") from exc
    _validate_json_value(value)
    return value


def load_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    size = path.stat().st_size
    if size > max_bytes:
        raise SuccessionError(f"JSON artifact exceeds {max_bytes} bytes: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise SuccessionError(f"JSON artifact is not valid UTF-8: {path}") from exc
    return parse_json_strict(text)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.stat().st_size > MAX_JSONL_BYTES:
        raise SuccessionError(f"JSONL corpus exceeds {MAX_JSONL_BYTES} bytes: {path}")
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                if len(line.encode("utf-8")) > MAX_JSON_BYTES:
                    raise SuccessionError(f"line {line_number} exceeds {MAX_JSON_BYTES} bytes")
                value = parse_json_strict(line)
                if not isinstance(value, dict):
                    raise SuccessionError(f"line {line_number} must be a JSON object")
                rows.append(value)
    except UnicodeError as exc:
        raise SuccessionError(f"JSONL corpus is not valid UTF-8: {path}") from exc
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, value: Mapping[str, Any]) -> None:
    """Append one canonical object as one physical JSONL record."""

    encoded = canonical_json(value)
    if len(encoded) > MAX_JSON_BYTES:
        raise SuccessionError(f"JSONL record exceeds {MAX_JSON_BYTES} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as handle:
        handle.write(encoded + b"\n")


def _exact(value: Mapping[str, Any], fields: set[str], name: str) -> None:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise SuccessionError(f"{name} field mismatch: expected={sorted(fields)} actual={actual}")


def _safe_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise SuccessionError(f"{name} must match {SAFE_ID.pattern}")
    return value


def _micros(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= SCALE:
        raise SuccessionError(f"{name} must be an integer in [0, {SCALE}]")
    return value


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        text = path.read_text(encoding="ascii").strip()
    except UnicodeError as exc:
        raise SuccessionError("private key file must be lowercase ASCII hex") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise SuccessionError("private key file must contain exactly 32 lowercase-hex bytes")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text))


def generate_keypair(private_path: Path, public_path: Path, *, force: bool = False) -> dict[str, str]:
    if not force and (private_path.exists() or public_path.exists()):
        raise SuccessionError("refusing to overwrite an existing key; pass force=True explicitly")
    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_hex = key.private_bytes_raw().hex()
    public_hex = key.public_key().public_bytes_raw().hex()
    private_path.write_text(private_hex + "\n", encoding="ascii")
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    public_path.write_text(public_hex + "\n", encoding="ascii")
    return {"private_key_path": str(private_path), "public_key_path": str(public_path), "public_key": public_hex}


def _sign_envelope(body: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    if "payload_hash" in body or "signature" in body:
        raise SuccessionError("unsigned body contains reserved envelope fields")
    payload = canonical_json(body)
    return {
        **body,
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "signature": {
            "algorithm": "Ed25519",
            "public_key": key.public_key().public_bytes_raw().hex(),
            "value": key.sign(payload).hex(),
        },
    }


def _verify_envelope(value: Mapping[str, Any], expected_public_keys: set[str] | None = None) -> bool:
    try:
        _validate_json_value(value)
        body = dict(value)
        signature = body.pop("signature")
        payload_hash = body.pop("payload_hash")
        if not isinstance(signature, Mapping) or set(signature) != {"algorithm", "public_key", "value"}:
            return False
        if signature["algorithm"] != "Ed25519" or not PUBLIC_KEY.fullmatch(signature["public_key"]):
            return False
        if not isinstance(signature["value"], str) or not re.fullmatch(r"[0-9a-f]{128}", signature["value"]):
            return False
        if not isinstance(payload_hash, str) or not HASH256.fullmatch(payload_hash):
            return False
        if expected_public_keys is not None and signature["public_key"] not in expected_public_keys:
            return False
        payload = canonical_json(body)
        if hashlib.sha256(payload).hexdigest() != payload_hash:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature["public_key"])).verify(
            bytes.fromhex(signature["value"]), payload
        )
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError, SuccessionError, RecursionError):
        return False


def _cole_api() -> dict[str, Any]:
    try:
        package = import_module("cole_portable_core")
        core = import_module("cole_portable_core.core")
        receipt = import_module("cole_portable_core.receipt")
    except ImportError as exc:
        raise SuccessionError(
            "COLE Portable Core is required for succession measurement. "
            "Install this project with the 'succession' extra."
        ) from exc
    if getattr(package, "ALGORITHM_ID", None) != COLE_ALGORITHM_ID:
        raise SuccessionError(
            f"unsupported COLE algorithm: {getattr(package, 'ALGORITHM_ID', None)!r}; "
            f"expected {COLE_ALGORITHM_ID!r}"
        )
    return {
        "issue": package.issue_measurement_receipt,
        "verify": package.verify_measurement_receipt,
        "reference_profile": package.reference_profile,
        "validate_profile": core.validate_profile,
        "validate_measurement_profile": receipt.validate_measurement_profile,
    }


PAIR_FIELDS = {"receipt", "disclosure"}
REQUEST_FIELDS = {"schema", "run_id", "sequence", "current", "previous", "checkpoint_anchor", "profile"}
BUNDLE_BODY_FIELDS = {"schema", "run_id", "sequence", "current", "previous", "checkpoint_anchor", "measurement_receipt"}


def _validate_pair(value: Any, name: str, *, optional: bool = False) -> Mapping[str, Any] | None:
    if value is None and optional:
        return None
    if not isinstance(value, Mapping):
        raise SuccessionError(f"{name} must be an object")
    _exact(value, PAIR_FIELDS, name)
    if not isinstance(value["receipt"], Mapping) or not isinstance(value["disclosure"], Mapping):
        raise SuccessionError(f"{name} receipt and disclosure must be objects")
    return value


def issue_measurement_bundle(request: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    """Issue an official COLE receipt and bind it to run/sequence metadata."""

    _validate_json_value(request)
    _exact(request, REQUEST_FIELDS, "measurement request")
    if request["schema"] != MEASUREMENT_REQUEST_SCHEMA:
        raise SuccessionError("unsupported measurement request schema")
    run_id = _safe_id(request["run_id"], "run_id")
    sequence = request["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise SuccessionError("sequence must be a nonnegative integer")
    current = _validate_pair(request["current"], "current")
    previous = _validate_pair(request["previous"], "previous", optional=True)
    anchor = _validate_pair(request["checkpoint_anchor"], "checkpoint_anchor", optional=True)
    if not isinstance(request["profile"], Mapping):
        raise SuccessionError("profile must be an object")

    cole = _cole_api()
    profile = dict(request["profile"])
    try:
        cole["validate_profile"](profile)
        derived = cole["issue"](
            current["receipt"],
            current["disclosure"],
            key,
            previous_input_receipt=None if previous is None else previous["receipt"],
            previous_disclosure=None if previous is None else previous["disclosure"],
            checkpoint_anchor_input_receipt=None if anchor is None else anchor["receipt"],
            checkpoint_anchor_disclosure=None if anchor is None else anchor["disclosure"],
            profile=profile,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SuccessionError(f"COLE measurement issuance failed: {exc}") from exc

    body = {
        "schema": MEASUREMENT_BUNDLE_SCHEMA,
        "run_id": run_id,
        "sequence": sequence,
        "current": dict(current),
        "previous": None if previous is None else dict(previous),
        "checkpoint_anchor": None if anchor is None else dict(anchor),
        "measurement_receipt": derived,
    }
    bundle = _sign_envelope(body, key)
    verification = verify_measurement_bundle(
        bundle,
        expected_public_keys={key.public_key().public_bytes_raw().hex()},
    )
    if not verification["valid"]:
        raise SuccessionError(f"newly issued bundle failed self-verification: {verification['reason_codes']}")
    return bundle


def verify_measurement_bundle(
    bundle: Mapping[str, Any],
    *,
    expected_public_keys: set[str] | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    try:
        _validate_json_value(bundle)
        if not isinstance(bundle, Mapping) or set(bundle) != BUNDLE_BODY_FIELDS | {"payload_hash", "signature"}:
            raise SuccessionError("measurement bundle field mismatch")
        if bundle["schema"] != MEASUREMENT_BUNDLE_SCHEMA:
            raise SuccessionError("unsupported measurement bundle schema")
        _safe_id(bundle["run_id"], "run_id")
        sequence = bundle["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise SuccessionError("sequence must be a nonnegative integer")
        current = _validate_pair(bundle["current"], "current")
        previous = _validate_pair(bundle["previous"], "previous", optional=True)
        anchor = _validate_pair(bundle["checkpoint_anchor"], "checkpoint_anchor", optional=True)
        if not _verify_envelope(bundle, expected_public_keys):
            reasons.append("bundle_signature_or_hash_invalid")
            return {"valid": False, "reason_codes": reasons}

        signer = bundle["signature"]["public_key"]
        derived = bundle["measurement_receipt"]
        if not isinstance(derived, Mapping):
            raise SuccessionError("measurement_receipt must be an object")
        if derived.get("algorithm_id") != COLE_ALGORITHM_ID:
            raise SuccessionError("measurement receipt uses an unsupported COLE algorithm")
        derived_signature = derived.get("signature")
        if not isinstance(derived_signature, Mapping) or derived_signature.get("public_key") != signer:
            reasons.append("bundle_and_measurement_signer_mismatch")
            return {"valid": False, "reason_codes": reasons}

        cole = _cole_api()
        valid = cole["verify"](
            derived,
            current["receipt"],
            current["disclosure"],
            previous_input_receipt=None if previous is None else previous["receipt"],
            previous_disclosure=None if previous is None else previous["disclosure"],
            checkpoint_anchor_input_receipt=None if anchor is None else anchor["receipt"],
            checkpoint_anchor_disclosure=None if anchor is None else anchor["disclosure"],
            expected_public_key=signer,
        )
        if not valid:
            reasons.append("cole_measurement_recomputation_failed")
        return {
            "valid": valid,
            "reason_codes": reasons,
            "run_id": bundle["run_id"],
            "sequence": bundle["sequence"],
            "measurement_public_key": signer,
            "measurement": derived.get("measurement") if valid else None,
            "profile": derived.get("profile") if valid else None,
            "measurement_receipt_hash": derived.get("payload_hash") if valid else None,
            "bundle_hash": bundle.get("payload_hash") if valid else None,
        }
    except (KeyError, TypeError, ValueError, SuccessionError, RecursionError) as exc:
        reasons.append(f"invalid_bundle:{exc}")
        return {"valid": False, "reason_codes": reasons}


OBSERVATION_FIELDS = {"schema", "sample_id", "label", "label_source", "outcome", "bundle"}
OUTCOME_FIELDS = {
    "continued_quality_micros",
    "successor_quality_micros",
    "benefit_margin_micros",
    "review_reference_hash",
}


def make_labeled_observation(
    bundle: Mapping[str, Any],
    *,
    sample_id: str,
    label: str,
    label_source: str,
    continued_quality_micros: int | None = None,
    successor_quality_micros: int | None = None,
    benefit_margin_micros: int | None = None,
    review_reference_hash: str | None = None,
) -> dict[str, Any]:
    observation = {
        "schema": LABELED_OBSERVATION_SCHEMA,
        "sample_id": sample_id,
        "label": label,
        "label_source": label_source,
        "outcome": {
            "continued_quality_micros": continued_quality_micros,
            "successor_quality_micros": successor_quality_micros,
            "benefit_margin_micros": benefit_margin_micros,
            "review_reference_hash": review_reference_hash,
        },
        "bundle": dict(bundle),
    }
    # Refuse malformed labels at collection time instead of letting an operator
    # discover the mistake only after a large corpus reaches calibration.
    _validate_label(observation)
    return observation


def _validate_label(value: Mapping[str, Any]) -> tuple[str, str]:
    _exact(value, OBSERVATION_FIELDS, "labeled observation")
    if value["schema"] != LABELED_OBSERVATION_SCHEMA:
        raise SuccessionError("unsupported labeled observation schema")
    sample_id = _safe_id(value["sample_id"], "sample_id")
    label = value["label"]
    if label not in {"continue", "succession_beneficial"}:
        raise SuccessionError("label must be 'continue' or 'succession_beneficial'")
    source = value["label_source"]
    if source not in {"paired_run", "review"}:
        raise SuccessionError("label_source must be 'paired_run' or 'review'")
    outcome = value["outcome"]
    if not isinstance(outcome, Mapping):
        raise SuccessionError("outcome must be an object")
    _exact(outcome, OUTCOME_FIELDS, "outcome")
    if source == "paired_run":
        continued = _micros(outcome["continued_quality_micros"], "continued_quality_micros")
        successor = _micros(outcome["successor_quality_micros"], "successor_quality_micros")
        margin = _micros(outcome["benefit_margin_micros"], "benefit_margin_micros")
        if outcome["review_reference_hash"] is not None:
            raise SuccessionError("paired_run must not include review_reference_hash")
        expected = "succession_beneficial" if successor - continued >= margin else "continue"
        if label != expected:
            raise SuccessionError(f"label disagrees with paired outcomes; expected {expected}")
    else:
        if any(outcome[name] is not None for name in (
            "continued_quality_micros", "successor_quality_micros", "benefit_margin_micros"
        )):
            raise SuccessionError("review labels must not invent paired-run outcomes")
        reference = outcome["review_reference_hash"]
        if not isinstance(reference, str) or not HASH256.fullmatch(reference):
            raise SuccessionError("review labels require a lowercase SHA-256 review reference")
    return sample_id, label


def _measurement_contract(profile: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return {name: profile[name] for name in CONTRACT_FIELDS}
    except KeyError as exc:
        raise SuccessionError(f"profile is missing contract field {exc.args[0]}") from exc


def _extract_row(
    observation: Mapping[str, Any],
    *,
    expected_public_keys: set[str] | None,
) -> dict[str, Any]:
    sample_id, label = _validate_label(observation)
    verification = verify_measurement_bundle(observation["bundle"], expected_public_keys=expected_public_keys)
    if not verification["valid"]:
        raise SuccessionError("measurement bundle failed: " + ",".join(verification["reason_codes"]))
    if verification["profile"]["calibration_status"] == "synthetic_conformance":
        raise SuccessionError("the synthetic COLE conformance profile is inadmissible for agent calibration")
    measurement = verification["measurement"]
    digest = measurement["digest"]
    support = measurement["support"]
    if support["claim_count"] < 1:
        raise SuccessionError("no material claim was available to support the calibration observation")
    if support["unsupported_claim_count"] != 0 or support["ucr_micros"] != 0:
        raise SuccessionError("unsupported material claims make the observation inadmissible")
    values: dict[str, int] = {}
    for metric in METRICS:
        value = digest.get(metric)
        if not isinstance(value, int) or isinstance(value, bool):
            raise SuccessionError(f"{metric} is unavailable; collect a warm checkpoint with previous state")
        if abs(value) > MAX_SAFE_INTEGER:
            raise SuccessionError(f"{metric} exceeds the interoperable integer range")
        values[metric] = value
    bundle = observation["bundle"]
    return {
        "sample_id": sample_id,
        "run_id": bundle["run_id"],
        "sequence": bundle["sequence"],
        "label": label,
        "label_source": observation["label_source"],
        "values": values,
        "measurement_receipt_hash": verification["measurement_receipt_hash"],
        "bundle_hash": verification["bundle_hash"],
        "measurement_public_key": verification["measurement_public_key"],
        "profile": verification["profile"],
        "contract": _measurement_contract(verification["profile"]),
    }


def _split(rows: Sequence[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    run_ids = sorted(
        {row["run_id"] for row in rows},
        key=lambda run_id: (hashlib.sha256(run_id.encode("ascii")).hexdigest(), run_id),
    )
    holdout_run_count = (len(run_ids) + 4) // 5
    holdout_run_ids = set(run_ids[:holdout_run_count])
    train: list[dict[str, Any]] = []
    holdout: list[dict[str, Any]] = []
    for row in rows:
        (holdout if row["run_id"] in holdout_run_ids else train).append(row)
    return train, holdout


def _predict_metric(value: int, threshold: int, direction: str) -> bool:
    return value >= threshold if direction == "high" else value < threshold


def _confusion(labels: Iterable[str], predictions: Iterable[bool]) -> dict[str, int]:
    result = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    for label, predicted in zip(labels, predictions, strict=True):
        positive = label == "succession_beneficial"
        if positive and predicted:
            result["true_positive"] += 1
        elif positive:
            result["false_negative"] += 1
        elif predicted:
            result["false_positive"] += 1
        else:
            result["true_negative"] += 1
    return result


def _ratio_micros(numerator: int, denominator: int) -> int | None:
    return None if denominator == 0 else numerator * SCALE // denominator


def _performance(confusion: Mapping[str, int]) -> dict[str, Any]:
    tp = confusion["true_positive"]
    fp = confusion["false_positive"]
    tn = confusion["true_negative"]
    fn = confusion["false_negative"]
    sensitivity = _ratio_micros(tp, tp + fn)
    specificity = _ratio_micros(tn, tn + fp)
    precision = _ratio_micros(tp, tp + fp)
    accuracy = _ratio_micros(tp + tn, tp + tn + fp + fn)
    balanced = None if sensitivity is None or specificity is None else (sensitivity + specificity) // 2
    return {
        "confusion": dict(confusion),
        "sensitivity_micros": sensitivity,
        "specificity_micros": specificity,
        "precision_micros": precision,
        "accuracy_micros": accuracy,
        "balanced_accuracy_micros": balanced,
    }


def _candidate_thresholds(values: Sequence[int], direction: str) -> list[int]:
    unique = sorted(set(values))
    if direction == "high":
        return unique + [min(MAX_SAFE_INTEGER, unique[-1] + 1)]
    return [0] + unique


def _balanced_fraction(confusion: Mapping[str, int]) -> Fraction:
    tp, fn = confusion["true_positive"], confusion["false_negative"]
    tn, fp = confusion["true_negative"], confusion["false_positive"]
    if tp + fn == 0 or tn + fp == 0:
        return Fraction(-1, 1)
    return (Fraction(tp, tp + fn) + Fraction(tn, tn + fp)) / 2


def _fit_threshold(rows: Sequence[dict[str, Any]], metric: str, direction: str) -> dict[str, Any]:
    values = [row["values"][metric] for row in rows]
    best: tuple[tuple[Any, ...], int, dict[str, int]] | None = None
    for threshold in _candidate_thresholds(values, direction):
        confusion = _confusion(
            (row["label"] for row in rows),
            (_predict_metric(row["values"][metric], threshold, direction) for row in rows),
        )
        specificity = Fraction(
            confusion["true_negative"],
            confusion["true_negative"] + confusion["false_positive"],
        )
        conservative = threshold if direction == "high" else -threshold
        key = (_balanced_fraction(confusion), specificity, conservative)
        if best is None or key > best[0]:
            best = (key, threshold, confusion)
    assert best is not None
    return {
        "metric": metric,
        "direction": direction,
        "threshold_micros": best[1],
        "selection": "maximum_train_balanced_accuracy_then_specificity_then_conservative_threshold",
        "train": _performance(best[2]),
    }


def _fit_critical_threshold(
    rows: Sequence[dict[str, Any]],
    metric: str,
    direction: str,
    specificity_floor_micros: int,
) -> dict[str, Any]:
    values = [row["values"][metric] for row in rows]
    eligible: list[tuple[tuple[Any, ...], int, dict[str, int]]] = []
    for threshold in _candidate_thresholds(values, direction):
        confusion = _confusion(
            (row["label"] for row in rows),
            (_predict_metric(row["values"][metric], threshold, direction) for row in rows),
        )
        performance = _performance(confusion)
        specificity = performance["specificity_micros"]
        if specificity is None or specificity < specificity_floor_micros:
            continue
        sensitivity = performance["sensitivity_micros"] or 0
        conservative = threshold if direction == "high" else -threshold
        eligible.append(((sensitivity, specificity, conservative), threshold, confusion))
    if not eligible:
        raise SuccessionError(f"no {metric} threshold met the declared specificity floor")
    _, threshold, confusion = max(eligible, key=lambda item: item[0])
    return {
        "metric": metric,
        "direction": direction,
        "threshold_micros": threshold,
        "specificity_floor_micros": specificity_floor_micros,
        "selection": "maximum_train_sensitivity_subject_to_specificity_floor",
        "train": _performance(confusion),
    }


def _metric_votes(row: Mapping[str, Any], thresholds: Mapping[str, Mapping[str, Any]]) -> dict[str, bool]:
    return {
        metric: _predict_metric(row["values"][metric], spec["threshold_micros"], spec["direction"])
        for metric, spec in thresholds.items()
    }


def _policy_predictions(
    rows: Sequence[dict[str, Any]],
    thresholds: Mapping[str, Mapping[str, Any]],
    *,
    minimum_metric_breaches: int,
    persistence_window: int,
    persistence_required: int,
) -> list[bool]:
    by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_run[row["run_id"]].append(row)
    predictions_by_id: dict[str, bool] = {}
    for run_rows in by_run.values():
        ordered = sorted(run_rows, key=lambda item: item["sequence"])
        flags: list[bool] = []
        for row in ordered:
            votes = _metric_votes(row, thresholds)
            flags.append(sum(votes.values()) >= minimum_metric_breaches)
            recent = flags[-persistence_window:]
            predictions_by_id[row["sample_id"]] = (
                len(recent) == persistence_window and sum(recent) >= persistence_required
            )
    return [predictions_by_id[row["sample_id"]] for row in rows]


def _fit_persistence_rule(
    rows: Sequence[dict[str, Any]],
    thresholds: Mapping[str, Mapping[str, Any]],
    *,
    max_window: int,
) -> dict[str, Any]:
    best: tuple[tuple[Any, ...], dict[str, int], dict[str, int]] | None = None
    for minimum_breaches in range(1, len(thresholds) + 1):
        for window in range(1, max_window + 1):
            for required in range(1, window + 1):
                config = {
                    "minimum_metric_breaches": minimum_breaches,
                    "persistence_window": window,
                    "persistence_required": required,
                }
                predictions = _policy_predictions(rows, thresholds, **config)
                confusion = _confusion((row["label"] for row in rows), predictions)
                specificity = Fraction(
                    confusion["true_negative"],
                    confusion["true_negative"] + confusion["false_positive"],
                )
                sensitivity = Fraction(
                    confusion["true_positive"],
                    confusion["true_positive"] + confusion["false_negative"],
                )
                key = (
                    _balanced_fraction(confusion),
                    specificity,
                    sensitivity,
                    minimum_breaches,
                    -window,
                    required,
                )
                if best is None or key > best[0]:
                    best = (key, config, confusion)
    assert best is not None
    return {
        **best[1],
        "selection": (
            "maximum_train_balanced_accuracy_then_specificity_then_sensitivity_"
            "then_metric_consensus_then_shortest_sufficient_window"
        ),
        "train": _performance(best[2]),
    }


def _evaluate_rule(
    rows: Sequence[dict[str, Any]],
    thresholds: Mapping[str, Mapping[str, Any]],
    persistence: Mapping[str, Any],
) -> dict[str, Any]:
    predictions = _policy_predictions(
        rows,
        thresholds,
        minimum_metric_breaches=persistence["minimum_metric_breaches"],
        persistence_window=persistence["persistence_window"],
        persistence_required=persistence["persistence_required"],
    )
    return _performance(_confusion((row["label"] for row in rows), predictions))


def _counts(rows: Sequence[dict[str, Any]]) -> dict[str, int]:
    values = Counter(row["label"] for row in rows)
    return {"continue": values["continue"], "succession_beneficial": values["succession_beneficial"]}


def _calibrated_profile(
    source_profile: Mapping[str, Any],
    *,
    corpus_hash: str,
    sample_count: int,
    thresholds: Mapping[str, Mapping[str, Any]],
    critical: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    profile = dict(source_profile)
    profile.update(
        {
            "profile_id": f"cole-succession-{corpus_hash[:16]}",
            "calibration_status": "calibrated",
            "calibration_corpus_hash": corpus_hash,
            "calibration_sample_count": sample_count,
            "amber_kappa_micros": thresholds["kappa_micros"]["threshold_micros"],
            "amber_epsilon_micros": thresholds["epsilon_micros"]["threshold_micros"],
            "amber_dhol_micros": thresholds["delta_hol_micros"]["threshold_micros"],
            "kappa_critical_micros": critical["kappa_micros"]["threshold_micros"],
            "phi_min_micros": critical["phi_star_micros"]["threshold_micros"],
        }
    )
    _cole_api()["validate_profile"](profile)
    return profile


def calibrate_succession(
    observations: Sequence[Mapping[str, Any]],
    policy_signing_key: Ed25519PrivateKey,
    *,
    expected_measurement_public_keys: set[str] | None,
    critical_specificity_micros: int = DEFAULT_CRITICAL_SPECIFICITY_MICROS,
    minimum_holdout_balanced_accuracy_micros: int = DEFAULT_MINIMUM_HOLDOUT_BALANCED_ACCURACY_MICROS,
    minimum_holdout_specificity_micros: int = DEFAULT_MINIMUM_HOLDOUT_SPECIFICITY_MICROS,
    minimum_holdout_sensitivity_micros: int = DEFAULT_MINIMUM_HOLDOUT_SENSITIVITY_MICROS,
    max_persistence_window: int = DEFAULT_MAX_PERSISTENCE_WINDOW,
) -> dict[str, Any]:
    """Fit a deterministic advisory policy from verified labeled checkpoints."""

    _micros(critical_specificity_micros, "critical_specificity_micros")
    _micros(
        minimum_holdout_balanced_accuracy_micros,
        "minimum_holdout_balanced_accuracy_micros",
    )
    _micros(minimum_holdout_specificity_micros, "minimum_holdout_specificity_micros")
    _micros(minimum_holdout_sensitivity_micros, "minimum_holdout_sensitivity_micros")
    if not isinstance(max_persistence_window, int) or isinstance(max_persistence_window, bool) or not 1 <= max_persistence_window <= 20:
        raise SuccessionError("max_persistence_window must be an integer in [1, 20]")
    pinned = None if expected_measurement_public_keys is None else set(expected_measurement_public_keys)
    if pinned is not None and any(not PUBLIC_KEY.fullmatch(value) for value in pinned):
        raise SuccessionError("expected measurement keys must be lowercase Ed25519 public-key hex")

    admitted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen_samples: set[str] = set()
    seen_positions: set[tuple[str, int]] = set()
    profile_hash: str | None = None
    contract: dict[str, Any] | None = None
    source_profile: dict[str, Any] | None = None
    canonical_rows: list[Mapping[str, Any]] = []
    admitted_canonical_rows: list[Mapping[str, Any]] = []

    for index, observation in enumerate(observations):
        try:
            if not isinstance(observation, Mapping):
                raise SuccessionError("observation must be an object")
            canonical_rows.append(observation)
            row = _extract_row(observation, expected_public_keys=pinned)
            if row["sample_id"] in seen_samples:
                raise SuccessionError("duplicate sample_id")
            position = (row["run_id"], row["sequence"])
            if position in seen_positions:
                raise SuccessionError("duplicate run_id/sequence checkpoint")
            current_profile_hash = canonical_hash(row["profile"])
            if profile_hash is not None and current_profile_hash != profile_hash:
                raise SuccessionError("mixed COLE measurement profiles are not calibratable together")
            if contract is not None and row["contract"] != contract:
                raise SuccessionError("mixed measurement contracts are not calibratable together")
            profile_hash = current_profile_hash
            contract = row["contract"]
            source_profile = dict(row["profile"])
            seen_samples.add(row["sample_id"])
            seen_positions.add(position)
            admitted.append(row)
            admitted_canonical_rows.append(observation)
        except (KeyError, TypeError, ValueError, SuccessionError) as exc:
            rejected.append({"index": index, "sample_id": observation.get("sample_id") if isinstance(observation, Mapping) else None, "reason": str(exc)})

    # The corpus hash binds every submitted row, including rejected evidence,
    # so deleting, reordering, or hiding a hostile row changes policy identity.
    submitted_corpus_hash = hashlib.sha256(
        b"".join(canonical_json(row) + b"\n" for row in canonical_rows)
    ).hexdigest()
    admitted_corpus_hash = hashlib.sha256(
        b"".join(canonical_json(row) + b"\n" for row in admitted_canonical_rows)
    ).hexdigest()

    train, holdout = _split(admitted)
    eligibility_reasons: list[str] = []
    if len(admitted) < MINIMUM_COLE_CALIBRATION_SAMPLES:
        eligibility_reasons.append(
            f"need_at_least_{MINIMUM_COLE_CALIBRATION_SAMPLES}_admitted_labeled_samples"
        )
    if rejected:
        eligibility_reasons.append("rejected_observations_present")
    if not pinned:
        eligibility_reasons.append("measurement_signer_keys_not_pinned")
    if not admitted:
        eligibility_reasons.append("no_admitted_observations")
    for name, rows in (("train", train), ("holdout", holdout)):
        counts = _counts(rows)
        if counts["continue"] == 0 or counts["succession_beneficial"] == 0:
            eligibility_reasons.append(f"{name}_split_missing_a_label_class")
        for label in ("continue", "succession_beneficial"):
            if counts[label] < MINIMUM_LABELS_PER_SPLIT:
                eligibility_reasons.append(f"{name}_{label}_below_minimum_label_count")
            run_count = len({row["run_id"] for row in rows if row["label"] == label})
            if run_count < MINIMUM_RUNS_PER_LABEL_PER_SPLIT:
                eligibility_reasons.append(f"{name}_{label}_below_minimum_run_count")
    if len({row["run_id"] for row in train} & {row["run_id"] for row in holdout}) != 0:
        eligibility_reasons.append("run_group_leakage_detected")

    thresholds: dict[str, dict[str, Any]] = {}
    critical: dict[str, dict[str, Any]] = {}
    persistence: dict[str, Any] | None = None
    validation: dict[str, Any] | None = None
    fit_ready = all(_counts(train)[label] > 0 for label in ("continue", "succession_beneficial"))
    if fit_ready:
        thresholds = {
            metric: _fit_threshold(train, metric, direction)
            for metric, direction in METRICS.items()
        }
        critical = {
            "kappa_micros": _fit_critical_threshold(
                train, "kappa_micros", "high", critical_specificity_micros
            ),
            "phi_star_micros": _fit_critical_threshold(
                train, "phi_star_micros", "low", critical_specificity_micros
            ),
        }
        persistence = _fit_persistence_rule(train, thresholds, max_window=max_persistence_window)
        validation = _evaluate_rule(holdout, thresholds, persistence) if holdout else None
    else:
        eligibility_reasons.append("threshold_fit_unavailable")

    validation_requirements = {
        "minimum_balanced_accuracy_micros": minimum_holdout_balanced_accuracy_micros,
        "minimum_specificity_micros": minimum_holdout_specificity_micros,
        "minimum_sensitivity_micros": minimum_holdout_sensitivity_micros,
    }
    if validation is None:
        eligibility_reasons.append("holdout_validation_unavailable")
    else:
        for metric, floor in (
            ("balanced_accuracy_micros", minimum_holdout_balanced_accuracy_micros),
            ("specificity_micros", minimum_holdout_specificity_micros),
            ("sensitivity_micros", minimum_holdout_sensitivity_micros),
        ):
            observed = validation.get(metric)
            if not isinstance(observed, int) or isinstance(observed, bool) or observed < floor:
                eligibility_reasons.append(f"holdout_{metric}_below_declared_floor")

    activated = not eligibility_reasons and source_profile is not None and persistence is not None
    calibrated_profile = None
    if activated:
        calibrated_profile = _calibrated_profile(
            source_profile,
            corpus_hash=admitted_corpus_hash,
            sample_count=len(admitted),
            thresholds=thresholds,
            critical=critical,
        )

    body = {
        "schema": CALIBRATION_POLICY_SCHEMA,
        "policy_version": "0.1",
        "cole_algorithm_id": COLE_ALGORITHM_ID,
        "mode": "calibrated_advisory" if activated else "observe_only",
        "automatic_retirement_authorized": False,
        "corpus": {
            "submitted_hash_algorithm": "submitted-order-canonical-jsonl-sha256-v1",
            "submitted_corpus_hash": submitted_corpus_hash,
            "admitted_hash_algorithm": "admitted-order-canonical-jsonl-sha256-v1",
            "admitted_corpus_hash": admitted_corpus_hash,
            "submitted_sample_count": len(observations),
            "admitted_sample_count": len(admitted),
            "rejected_sample_count": len(rejected),
            "minimum_activation_sample_count": MINIMUM_COLE_CALIBRATION_SAMPLES,
            "minimum_labels_per_split": MINIMUM_LABELS_PER_SPLIT,
            "minimum_runs_per_label_per_split": MINIMUM_RUNS_PER_LABEL_PER_SPLIT,
            "label_counts": _counts(admitted),
            "label_source_counts": dict(sorted(Counter(row["label_source"] for row in admitted).items())),
            "pinned_measurement_public_keys": sorted(pinned or set()),
            "source_profile_hash": profile_hash,
        },
        "measurement_contract": contract,
        "split": {
            "method": "sha256-sorted-run-id-first-fifth-holdout-v1",
            "grouping": "run_id",
            "train_sample_count": len(train),
            "holdout_sample_count": len(holdout),
            "train_run_count": len({row["run_id"] for row in train}),
            "holdout_run_count": len({row["run_id"] for row in holdout}),
            "train_label_counts": _counts(train),
            "holdout_label_counts": _counts(holdout),
        },
        "thresholds": thresholds,
        "critical_thresholds": critical,
        "persistence": persistence,
        "holdout_validation": validation,
        "validation_requirements": validation_requirements,
        "cole_profile": calibrated_profile,
        "eligibility": {
            "activated": activated,
            "reason_codes": sorted(set(eligibility_reasons)),
            "rejected_observations": rejected,
        },
        "claim_boundary": (
            "This receiver-owned policy is calibrated only for the admitted agent, task, signal schema, "
            "and label process. It is advisory, does not prove semantic truth, and never authorizes "
            "automatic retirement. A successor must verify a handoff before source retirement."
        ),
    }
    return _sign_envelope(body, policy_signing_key)


POLICY_BODY_FIELDS = {
    "schema", "policy_version", "cole_algorithm_id", "mode", "automatic_retirement_authorized",
    "corpus", "measurement_contract", "split", "thresholds", "critical_thresholds", "persistence",
    "holdout_validation", "validation_requirements", "cole_profile", "eligibility", "claim_boundary",
}

CORPUS_FIELDS = {
    "submitted_hash_algorithm", "submitted_corpus_hash", "admitted_hash_algorithm",
    "admitted_corpus_hash", "submitted_sample_count", "admitted_sample_count",
    "rejected_sample_count", "minimum_activation_sample_count", "minimum_labels_per_split",
    "minimum_runs_per_label_per_split", "label_counts", "label_source_counts",
    "pinned_measurement_public_keys", "source_profile_hash",
}
SPLIT_FIELDS = {
    "method", "grouping", "train_sample_count", "holdout_sample_count", "train_run_count",
    "holdout_run_count", "train_label_counts", "holdout_label_counts",
}
ELIGIBILITY_FIELDS = {"activated", "reason_codes", "rejected_observations"}
VALIDATION_REQUIREMENT_FIELDS = {
    "minimum_balanced_accuracy_micros", "minimum_specificity_micros",
    "minimum_sensitivity_micros",
}
PERFORMANCE_FIELDS = {
    "confusion", "sensitivity_micros", "specificity_micros", "precision_micros",
    "accuracy_micros", "balanced_accuracy_micros",
}
CONFUSION_FIELDS = {"true_positive", "false_positive", "true_negative", "false_negative"}
THRESHOLD_FIELDS = {"metric", "direction", "threshold_micros", "selection", "train"}
PERSISTENCE_FIELDS = {
    "minimum_metric_breaches", "persistence_window", "persistence_required", "selection", "train",
}


def _validate_policy_semantics(policy: Mapping[str, Any]) -> None:
    _exact(policy["corpus"], CORPUS_FIELDS, "policy corpus")
    corpus = policy["corpus"]
    if corpus["submitted_hash_algorithm"] != "submitted-order-canonical-jsonl-sha256-v1":
        raise SuccessionError("unsupported submitted-corpus hash method")
    if corpus["admitted_hash_algorithm"] != "admitted-order-canonical-jsonl-sha256-v1":
        raise SuccessionError("unsupported admitted-corpus hash method")
    for field in ("submitted_corpus_hash", "admitted_corpus_hash"):
        if not isinstance(corpus[field], str) or not HASH256.fullmatch(corpus[field]):
            raise SuccessionError(f"invalid {field}")
    for field in (
        "submitted_sample_count", "admitted_sample_count", "rejected_sample_count",
        "minimum_activation_sample_count", "minimum_labels_per_split",
        "minimum_runs_per_label_per_split",
    ):
        if not isinstance(corpus[field], int) or isinstance(corpus[field], bool) or corpus[field] < 0:
            raise SuccessionError(f"invalid corpus {field}")
    if corpus["minimum_activation_sample_count"] != MINIMUM_COLE_CALIBRATION_SAMPLES:
        raise SuccessionError("policy changes the minimum COLE calibration sample count")
    if corpus["minimum_labels_per_split"] != MINIMUM_LABELS_PER_SPLIT:
        raise SuccessionError("policy changes minimum labels per split")
    if corpus["minimum_runs_per_label_per_split"] != MINIMUM_RUNS_PER_LABEL_PER_SPLIT:
        raise SuccessionError("policy changes minimum runs per label per split")
    pins = corpus["pinned_measurement_public_keys"]
    if not isinstance(pins, list) or pins != sorted(set(pins)) or any(
        not isinstance(item, str) or not PUBLIC_KEY.fullmatch(item) for item in pins
    ):
        raise SuccessionError("invalid pinned measurement public keys")
    source_hash = corpus["source_profile_hash"]
    if source_hash is not None and (not isinstance(source_hash, str) or not HASH256.fullmatch(source_hash)):
        raise SuccessionError("invalid source profile hash")

    contract = policy["measurement_contract"]
    if contract is not None:
        _exact(contract, set(CONTRACT_FIELDS), "measurement contract")

    _exact(policy["split"], SPLIT_FIELDS, "policy split")
    if policy["split"]["method"] != "sha256-sorted-run-id-first-fifth-holdout-v1" or policy["split"]["grouping"] != "run_id":
        raise SuccessionError("unsupported policy split")
    _exact(policy["eligibility"], ELIGIBILITY_FIELDS, "policy eligibility")
    if not isinstance(policy["eligibility"]["activated"], bool):
        raise SuccessionError("eligibility activated must be boolean")
    if not isinstance(policy["eligibility"]["reason_codes"], list) or any(
        not isinstance(item, str) for item in policy["eligibility"]["reason_codes"]
    ):
        raise SuccessionError("invalid eligibility reason codes")

    requirements = policy["validation_requirements"]
    _exact(requirements, VALIDATION_REQUIREMENT_FIELDS, "validation requirements")
    for field in VALIDATION_REQUIREMENT_FIELDS:
        _micros(requirements[field], field)

    validation = policy["holdout_validation"]
    if validation is not None:
        _exact(validation, PERFORMANCE_FIELDS, "holdout validation")
        _exact(validation["confusion"], CONFUSION_FIELDS, "holdout confusion")
        for field in CONFUSION_FIELDS:
            value = validation["confusion"][field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise SuccessionError(f"invalid holdout confusion {field}")
        for field in PERFORMANCE_FIELDS - {"confusion"}:
            value = validation[field]
            if value is not None:
                _micros(value, f"holdout {field}")

    thresholds = policy["thresholds"]
    if not isinstance(thresholds, Mapping) or (thresholds and set(thresholds) != set(METRICS)):
        raise SuccessionError("policy thresholds must be empty or cover every declared metric")
    for metric, spec in thresholds.items():
        _exact(spec, THRESHOLD_FIELDS, f"threshold {metric}")
        if spec["metric"] != metric or spec["direction"] != METRICS[metric]:
            raise SuccessionError(f"threshold contract mismatch for {metric}")
        if not isinstance(spec["threshold_micros"], int) or isinstance(spec["threshold_micros"], bool):
            raise SuccessionError(f"invalid threshold for {metric}")

    critical = policy["critical_thresholds"]
    if not isinstance(critical, Mapping) or (
        critical and set(critical) != {"kappa_micros", "phi_star_micros"}
    ):
        raise SuccessionError("critical thresholds have an invalid metric set")
    for metric, spec in critical.items():
        _exact(spec, THRESHOLD_FIELDS | {"specificity_floor_micros"}, f"critical threshold {metric}")
        if spec["metric"] != metric or spec["direction"] != METRICS[metric]:
            raise SuccessionError(f"critical threshold contract mismatch for {metric}")
        _micros(spec["specificity_floor_micros"], f"{metric} specificity floor")

    persistence = policy["persistence"]
    if persistence is not None:
        _exact(persistence, PERSISTENCE_FIELDS, "persistence policy")
        minimum = persistence["minimum_metric_breaches"]
        window = persistence["persistence_window"]
        required = persistence["persistence_required"]
        if not isinstance(minimum, int) or isinstance(minimum, bool) or not 1 <= minimum <= len(METRICS):
            raise SuccessionError("invalid minimum metric breaches")
        if not isinstance(window, int) or isinstance(window, bool) or not 1 <= window <= 20:
            raise SuccessionError("invalid persistence window")
        if not isinstance(required, int) or isinstance(required, bool) or not 1 <= required <= window:
            raise SuccessionError("invalid persistence requirement")

    if policy["mode"] == "observe_only":
        if policy["cole_profile"] is not None:
            raise SuccessionError("observe-only policy cannot publish an activated COLE profile")
        if policy["eligibility"]["activated"]:
            raise SuccessionError("observe-only policy cannot claim activation")
    else:
        if not thresholds or not critical or persistence is None or contract is None:
            raise SuccessionError("calibrated advisory is missing its measurement rule")
        if validation is None:
            raise SuccessionError("calibrated advisory is missing holdout validation")
        floor_pairs = (
            ("balanced_accuracy_micros", "minimum_balanced_accuracy_micros"),
            ("specificity_micros", "minimum_specificity_micros"),
            ("sensitivity_micros", "minimum_sensitivity_micros"),
        )
        for observed_field, requirement_field in floor_pairs:
            observed = validation[observed_field]
            if observed is None or observed < requirements[requirement_field]:
                raise SuccessionError(f"calibrated advisory fails {observed_field} floor")


def verify_calibration_policy(
    policy: Mapping[str, Any],
    *,
    expected_public_key: str | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    expected = None if expected_public_key is None else {expected_public_key}
    try:
        if not isinstance(policy, Mapping) or set(policy) != POLICY_BODY_FIELDS | {"payload_hash", "signature"}:
            raise SuccessionError("calibration policy field mismatch")
        if policy["schema"] != CALIBRATION_POLICY_SCHEMA or policy["policy_version"] != "0.1":
            raise SuccessionError("unsupported calibration policy")
        if policy["cole_algorithm_id"] != COLE_ALGORITHM_ID:
            raise SuccessionError("calibration policy uses an unsupported COLE algorithm")
        if policy["mode"] not in {"observe_only", "calibrated_advisory"}:
            raise SuccessionError("invalid policy mode")
        if policy["automatic_retirement_authorized"] is not False:
            raise SuccessionError("automatic retirement is forbidden")
        if not _verify_envelope(policy, expected):
            reasons.append("policy_signature_or_hash_invalid")
            return {"valid": False, "reason_codes": reasons}
        _validate_policy_semantics(policy)
        if policy["mode"] == "calibrated_advisory":
            if not policy["eligibility"].get("activated") or policy["eligibility"].get("reason_codes"):
                raise SuccessionError("advisory mode lacks a clean activation gate")
            if policy["corpus"]["admitted_sample_count"] < MINIMUM_COLE_CALIBRATION_SAMPLES:
                raise SuccessionError("advisory mode has too few samples")
            if not policy["corpus"]["pinned_measurement_public_keys"]:
                raise SuccessionError("advisory mode lacks pinned measurement keys")
            _cole_api()["validate_profile"](policy["cole_profile"])
        return {
            "valid": True,
            "reason_codes": [],
            "policy_hash": policy["payload_hash"],
            "policy_public_key": policy["signature"]["public_key"],
            "mode": policy["mode"],
        }
    except (KeyError, TypeError, ValueError, SuccessionError, RecursionError) as exc:
        reasons.append(f"invalid_policy:{exc}")
        return {"valid": False, "reason_codes": reasons}


def _support_complete(bundle_verification: Mapping[str, Any]) -> bool:
    support = bundle_verification["measurement"]["support"]
    return (
        support["claim_count"] > 0
        and support["unsupported_claim_count"] == 0
        and support["ucr_micros"] == 0
    )


def _assessment_row(verification: Mapping[str, Any]) -> dict[str, Any]:
    digest = verification["measurement"]["digest"]
    values = {metric: digest.get(metric) for metric in METRICS}
    return {
        "sample_id": verification["bundle_hash"],
        "run_id": verification["run_id"],
        "sequence": verification["sequence"],
        "label": "continue",  # ignored by assessment predictions
        "values": values,
    }


def assess_succession(
    current_bundle: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    history: Sequence[Mapping[str, Any]] = (),
    expected_policy_public_key: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic advisory; never return an automatic retire command."""

    if expected_policy_public_key is None:
        raise SuccessionError("expected_policy_public_key is required for receiver-owned assessment")
    policy_verification = verify_calibration_policy(policy, expected_public_key=expected_policy_public_key)
    if not policy_verification["valid"]:
        raise SuccessionError("calibration policy failed: " + ",".join(policy_verification["reason_codes"]))
    measurement_keys = set(policy["corpus"]["pinned_measurement_public_keys"])
    expected_keys = measurement_keys or None
    bundles = [*history, current_bundle]
    verified: list[dict[str, Any]] = []
    for bundle in bundles:
        result = verify_measurement_bundle(bundle, expected_public_keys=expected_keys)
        if not result["valid"]:
            raise SuccessionError("measurement history failed: " + ",".join(result["reason_codes"]))
        verified.append(result)

    current = verified[-1]
    if any(item["run_id"] != current["run_id"] for item in verified):
        raise SuccessionError("history crosses run_id boundaries")
    sequences = [item["sequence"] for item in verified]
    if sequences != sorted(set(sequences)):
        raise SuccessionError("history sequences must be unique and strictly increasing")
    contract = policy["measurement_contract"]
    if contract is not None and any(_measurement_contract(item["profile"]) != contract for item in verified):
        raise SuccessionError("measurement contract does not match the calibrated policy")

    thresholds = policy["thresholds"]
    current_row = _assessment_row(current)
    metric_report: dict[str, Any] = {}
    if thresholds:
        for metric, direction in METRICS.items():
            value = current_row["values"][metric]
            spec = thresholds[metric]
            metric_report[metric] = {
                "value_micros": value,
                "threshold_micros": spec["threshold_micros"],
                "direction": direction,
                "breached": None if value is None else _predict_metric(value, spec["threshold_micros"], direction),
            }
    else:
        for metric, direction in METRICS.items():
            metric_report[metric] = {
                "value_micros": current_row["values"][metric],
                "threshold_micros": None,
                "direction": direction,
                "breached": None,
            }

    reasons: list[str] = []
    disposition = "observe_only"
    recent_window: list[dict[str, Any]] = []
    persistence_observed = 0
    if policy["mode"] != "calibrated_advisory" or not thresholds or policy["persistence"] is None:
        reasons.append("calibration_not_activated")
    elif not all(_support_complete(item) for item in verified):
        disposition = "insufficient_evidence"
        reasons.append("unsupported_or_absent_material_claims")
    elif any(any(value is None for value in _assessment_row(item)["values"].values()) for item in verified):
        disposition = "insufficient_evidence"
        reasons.append("incomplete_cole_measurement")
    else:
        persistence = policy["persistence"]
        window = persistence["persistence_window"]
        required = persistence["persistence_required"]
        minimum = persistence["minimum_metric_breaches"]
        all_rows = [_assessment_row(item) for item in verified]
        for row in all_rows[-window:]:
            votes = _metric_votes(row, thresholds)
            recent_window.append(
                {
                    "sequence": row["sequence"],
                    "metric_breaches": sum(votes.values()),
                    "checkpoint_signal": sum(votes.values()) >= minimum,
                }
            )
        persistence_observed = sum(int(item["checkpoint_signal"]) for item in recent_window)
        current_signal = bool(recent_window and recent_window[-1]["checkpoint_signal"])
        if len(recent_window) == window and persistence_observed >= required:
            disposition = "succession_candidate"
            reasons.append("calibrated_persistence_rule_met")
        elif current_signal:
            disposition = "prepare_handoff"
            reasons.append("checkpoint_signal_without_required_persistence")
        else:
            disposition = "continue_observation"
            reasons.append("calibrated_persistence_rule_not_met")

    support = current["measurement"]["support"]
    body = {
        "schema": ASSESSMENT_SCHEMA,
        "policy_hash": policy["payload_hash"],
        "measurement_bundle_hash": current["bundle_hash"],
        "measurement_receipt_hash": current["measurement_receipt_hash"],
        "run_id": current["run_id"],
        "sequence": current["sequence"],
        "policy_mode": policy["mode"],
        "metrics": metric_report,
        "support": support,
        "persistence": {
            "recent": recent_window,
            "observed_checkpoint_signals": persistence_observed,
            "required_checkpoint_signals": None if policy["persistence"] is None else policy["persistence"]["persistence_required"],
            "window": None if policy["persistence"] is None else policy["persistence"]["persistence_window"],
        },
        "disposition": disposition,
        "reason_codes": reasons,
        "automatic_retirement_authorized": False,
        "receiver_approval_required": True,
        "handoff": {
            "required_before_source_retirement": disposition in {"prepare_handoff", "succession_candidate"},
            "required_bindings": [
                "run_id", "parent_hash", "generation_index", "objective", "constraints",
                "unresolved_work", "evidence_hashes", "policy_hash",
            ],
            "instruction": (
                "Create and verify a receiver-bound handoff in the fresh runtime before the owner retires the source runtime."
            ),
        },
        "attestation": "local_recomputation_unsigned",
    }
    return {**body, "assessment_hash": canonical_hash(body)}


def initialize_workspace(root: Path, *, force: bool = False) -> dict[str, Any]:
    """Create a guided local workspace without writing any agent data."""

    paths = [
        root / "measurement.private.hex",
        root / "measurement.public.hex",
        root / "policy.private.hex",
        root / "policy.public.hex",
        root / "observations.jsonl",
        root / "measurement-request.template.json",
        root / "README.md",
    ]
    if not force and any(path.exists() for path in paths):
        raise SuccessionError("refusing to partially overwrite an existing calibration workspace")
    root.mkdir(parents=True, exist_ok=True)
    measurement = generate_keypair(root / "measurement.private.hex", root / "measurement.public.hex", force=force)
    policy = generate_keypair(root / "policy.private.hex", root / "policy.public.hex", force=force)
    observations = root / "observations.jsonl"
    observations.write_text("", encoding="utf-8")
    template = {
        "schema": MEASUREMENT_REQUEST_SCHEMA,
        "run_id": "replace-with-your-run-id",
        "sequence": 0,
        "current": {"receipt": None, "disclosure": None},
        "previous": {"receipt": None, "disclosure": None},
        "checkpoint_anchor": None,
        "profile": {"replace": "use cole_portable_core.reference_profile(signal_schema_id)"},
    }
    write_json(root / "measurement-request.template.json", template)
    guide = """# Succession calibration workspace

1. Instrument the agent with OLP Wire Canon checkpoints and a declared normalized signal schema.
2. Create warm COLE measurement bundles with `succession-measure`; keep the same metric-affecting profile.
3. At sampled checkpoints, run matched arms: continue the current agent and start a fresh runtime from the same verified handoff.
4. Score both arms with the same bounded evaluator. Add a `paired_run` label only after declaring the benefit margin.
5. Collect at least 500 admitted samples across enough independent run IDs for a run-grouped holdout.
6. Run `succession-calibrate` while pinning every admitted measurement public key.
7. Use `succession-assess` as advice. It never authorizes automatic retirement.

Keep both `.private.hex` files private. Commit only public keys, policies, fixtures cleared for release, and redacted evidence.
"""
    (root / "README.md").write_text(guide, encoding="utf-8")
    return {
        "workspace": str(root),
        "measurement_public_key": measurement["public_key"],
        "policy_public_key": policy["public_key"],
        "next_step": "replace the template with a valid Wire Canon request, then run succession-measure",
    }
