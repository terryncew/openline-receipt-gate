"""OpenLine Jev Witness (Vercel): Jev judgments via Vercel AI Gateway as signed evidence.

Jev (TypeSafe AI's System One evaluation model) is reached here through Vercel
AI Gateway's evaluation-model endpoint, not through TypeSafe's own API. One
Jev judgment is bound to the exact evaluation request, the typed
question/options, the gateway response, and the exact proposed consequential
action; receiver-owned authority and policy then decide the disposition.

Core invariant (frozen):

    A Jev judgment is evidence. It is never permission by itself.

This module composes existing OpenLine machinery and reimplements none of it:

- canonical serialization: :mod:`olp_gate.crypto` (``olp_canonical_json``)
- receipt signing/verification: :mod:`olp_gate.crypto`
  (``sign_olp_body`` / ``verify_olp_signature``)
- current-standing / revocation checks: :mod:`olp_gate.standing` and
  :mod:`olp_gate.stop_standing` (supplied by the caller as an authority check;
  this module never assumes authority)
- the protected-effect path and its one-use semantics live in the caller; this
  module supplies the evidence verification the caller gates on

Gateway surface facts used here were verified against primary sources on
2026-09-20 (published ``ai`` 7.0.107 / ``@ai-sdk/gateway`` 4.0.87 /
``@ai-sdk/provider`` 4.0.17 package sources, plus the live gateway):

- endpoint: ``POST https://ai-gateway.vercel.sh/v4/ai/evaluation-model``
- headers: ``ai-gateway-protocol-version: 0.0.1``,
  ``ai-evaluation-model-specification-version: 4``, ``ai-model-id: <model>``
- body: ``{"state": <input>, "questions": {<id>: <v4 question>}}``
- v4 questions: ``boolean`` / ``choice`` / ``score`` with ``instructions`` and
  optional ``criteria``
- v4 answers: ``boolean`` -> ``probability`` (P(true) in [0,1]);
  ``choice`` -> ``choice`` + optional ``probabilities``;
  ``score`` -> ``score`` + optional ``probabilities``
- response envelope: ``answers`` / ``usage`` (optional) / ``warnings`` /
  ``rounding`` / ``providerMetadata``; response headers are available
- Jev model slug on the gateway: ``typesafe-ai/jev`` (type ``evaluation``;
  zero-data-retention and no-training apply to all requests per the live
  model listing; input $0.042/M tokens, output free)

Provenance actually exposed (verified, not assumed):

- AVAILABLE: the exact request we sent (caller-retained copy); the exact
  response body (answers/usage/warnings/rounding/providerMetadata); response
  headers (a request id is recorded only when an allowlisted id header is
  present, else null, never invented).
- NOT AVAILABLE: a provider-resolved model version distinct from the requested
  id (the gateway echoes the requested ``ai-model-id``; it is recorded as
  ``model_reported`` and never presented as a resolved version id); provider
  timestamps; signatures; content hashes.
- The witness timestamp is recorded as ``witness_clock`` and never presented
  as a Jev or gateway timestamp.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..crypto import (
    olp_canonical_json,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)


JEV_VERCEL_EVIDENCE_SCHEMA = "openline.jev_vercel_evidence.v1"
JEV_VERCEL_DECISION_SCHEMA = "openline.jev_vercel_decision.v1"

GATEWAY_HOST = "ai-gateway.vercel.sh"
GATEWAY_EVALUATE_PATH = "/v4/ai/evaluation-model"
GATEWAY_PROTOCOL_VERSION = "0.0.1"
EVAL_SPEC_VERSION = "4"
JEV_MODEL_ID = "typesafe-ai/jev"

# Response headers that may carry a request/judgment identifier. The value is
# recorded when present and null when absent; nothing is ever invented.
_REQUEST_ID_HEADERS = frozenset(
    {
        "x-typesafe-request-id",
        "x-request-id",
        "x-vercel-id",
    }
)

_QUESTION_TYPES = ("boolean", "choice", "score")
_HEX = frozenset("0123456789abcdef")


class JevVercelEvidenceError(ValueError):
    """Raised when Jev-Vercel evidence cannot be built, verified, or decided."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise JevVercelEvidenceError("jev_vercel_time_invalid")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise JevVercelEvidenceError("jev_vercel_time_invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_jev_value(value: Any, path: str = "$") -> Any:
    """Recursively normalize Jev-derived values to canonical-JSON-safe form.

    Frozen rule: every float becomes its ``repr()`` string (exact round-trip,
    deterministic). Non-finite floats, non-ASCII object keys, and non-JSON
    values are refused rather than mangled. Python object identity and
    ``repr()`` of objects are never bound.
    """
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise JevVercelEvidenceError(f"jev_vercel_non_finite_float:{path}")
        return repr(value)
    if isinstance(value, Mapping):
        items: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise JevVercelEvidenceError(f"jev_vercel_object_key_not_string:{path}")
            if not key.isascii():
                raise JevVercelEvidenceError(f"jev_vercel_object_key_not_ascii:{path}")
            items[key] = _normalize_jev_value(item, f"{path}.{key}")
        return items
    if isinstance(value, (list, tuple)):
        return [_normalize_jev_value(item, f"{path}[{i}]") for i, item in enumerate(value)]
    raise JevVercelEvidenceError(f"jev_vercel_unsupported_value:{path}:{type(value).__name__}")


def canonical_action_hash(action: Mapping[str, Any]) -> str:
    """Exact-action binding: sha256 over the canonicalized action bytes."""
    if not isinstance(action, Mapping) or not action:
        raise JevVercelEvidenceError("jev_vercel_action_invalid")
    return sha256_hex(olp_canonical_json(_normalize_jev_value(action)))


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise JevVercelEvidenceError(f"jev_vercel_{name}_invalid")
    return value


def _validate_probability(value: Any, name: str) -> None:
    try:
        number = float(value) if isinstance(value, str) else float(value)
    except (TypeError, ValueError) as exc:
        raise JevVercelEvidenceError(f"jev_vercel_probability_not_numeric:{name}") from exc
    if not 0.0 <= number <= 1.0:
        raise JevVercelEvidenceError(f"jev_vercel_probability_out_of_range:{name}")


def _validate_questions_shape(questions: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the v4 evaluation questions shape; refuse what is uninterpretable."""
    if not isinstance(questions, Mapping) or not questions:
        raise JevVercelEvidenceError("jev_vercel_questions_invalid")
    normalized: dict[str, Any] = {}
    for name, question in questions.items():
        if not isinstance(name, str) or not name:
            raise JevVercelEvidenceError("jev_vercel_question_name_invalid")
        if not isinstance(question, Mapping):
            raise JevVercelEvidenceError(f"jev_vercel_question_invalid:{name}")
        qtype = question.get("type")
        if qtype not in _QUESTION_TYPES:
            raise JevVercelEvidenceError(f"jev_vercel_question_type_unsupported:{name}:{qtype}")
        if "instructions" not in question:
            raise JevVercelEvidenceError(f"jev_vercel_question_instructions_missing:{name}")
        criteria = question.get("criteria")
        if qtype == "choice":
            if not isinstance(criteria, Mapping) or not criteria:
                raise JevVercelEvidenceError(f"jev_vercel_question_criteria_invalid:{name}")
        elif qtype == "score":
            if not isinstance(criteria, (list, tuple)) or len(criteria) < 2:
                raise JevVercelEvidenceError(f"jev_vercel_question_criteria_invalid:{name}")
        elif criteria is not None and not isinstance(criteria, Mapping):
            raise JevVercelEvidenceError(f"jev_vercel_question_criteria_invalid:{name}")
        normalized[name] = _normalize_jev_value(dict(question), f"$.questions.{name}")
    return normalized


def _validate_response_shape(response: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the gateway evaluation response body; refuse what is uninterpretable."""
    if not isinstance(response, Mapping):
        raise JevVercelEvidenceError("jev_vercel_response_invalid")
    answers = response.get("answers")
    if not isinstance(answers, Mapping) or not answers:
        raise JevVercelEvidenceError("jev_vercel_response_answers_invalid")
    normalized_answers: dict[str, Any] = {}
    for name, answer in answers.items():
        if not isinstance(name, str) or not name:
            raise JevVercelEvidenceError("jev_vercel_answer_name_invalid")
        if not isinstance(answer, Mapping):
            raise JevVercelEvidenceError(f"jev_vercel_answer_invalid:{name}")
        answer_type = answer.get("type")
        if answer_type == "boolean":
            _validate_probability(answer.get("probability"), f"{name}.probability")
        elif answer_type == "choice":
            _require_str(answer.get("choice"), f"answer_choice:{name}")
            probabilities = answer.get("probabilities")
            if probabilities is not None:
                if not isinstance(probabilities, Mapping):
                    raise JevVercelEvidenceError(f"jev_vercel_answer_probabilities_invalid:{name}")
                for option, prob in probabilities.items():
                    _validate_probability(prob, f"{name}.probabilities.{option}")
        elif answer_type == "score":
            try:
                float(answer.get("score"))
            except (TypeError, ValueError) as exc:
                raise JevVercelEvidenceError(f"jev_vercel_answer_score_invalid:{name}") from exc
            probabilities = answer.get("probabilities")
            if probabilities is not None:
                if not isinstance(probabilities, Mapping):
                    raise JevVercelEvidenceError(f"jev_vercel_answer_probabilities_invalid:{name}")
                for level, prob in probabilities.items():
                    _validate_probability(prob, f"{name}.probabilities.{level}")
        else:
            raise JevVercelEvidenceError(f"jev_vercel_answer_type_unsupported:{name}:{answer_type}")
        normalized_answers[name] = _normalize_jev_value(dict(answer), f"$.answers.{name}")
    normalized_usage: dict[str, Any] | None = None
    usage = response.get("usage")
    if usage is not None:
        if not isinstance(usage, Mapping):
            raise JevVercelEvidenceError("jev_vercel_response_usage_invalid")
        normalized_usage = {}
        for key in ("inputTokens", "outputTokens", "totalTokens"):
            tokens = usage.get(key)
            if tokens is None:
                continue
            if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0:
                raise JevVercelEvidenceError(f"jev_vercel_response_usage_{key}_invalid")
            normalized_usage[key] = tokens
    warnings = response.get("warnings")
    if warnings is not None and not isinstance(warnings, list):
        raise JevVercelEvidenceError("jev_vercel_response_warnings_invalid")
    rounding = response.get("rounding")
    if rounding is not None and not isinstance(rounding, Mapping):
        raise JevVercelEvidenceError("jev_vercel_response_rounding_invalid")
    provider_metadata = response.get("providerMetadata")
    if provider_metadata is not None and not isinstance(provider_metadata, Mapping):
        raise JevVercelEvidenceError("jev_vercel_response_provider_metadata_invalid")
    return {
        "answers": normalized_answers,
        "usage": (
            _normalize_jev_value(normalized_usage, "$.usage") if normalized_usage else None
        ),
        "warnings": (
            _normalize_jev_value(warnings, "$.warnings") if warnings is not None else None
        ),
        "rounding": (
            _normalize_jev_value(rounding, "$.rounding") if rounding is not None else None
        ),
        "provider_metadata": (
            _normalize_jev_value(provider_metadata, "$.providerMetadata")
            if provider_metadata is not None
            else None
        ),
    }


def extract_request_id(response_headers: Mapping[str, Any] | None) -> str | None:
    """Extract a request identifier from gateway response headers, if exposed.

    Returns the value when an allowlisted id header is present, else None.
    Never invented.
    """
    if not isinstance(response_headers, Mapping):
        return None
    for name, value in response_headers.items():
        if not isinstance(name, str):
            continue
        if name.lower() in _REQUEST_ID_HEADERS and isinstance(value, str) and value:
            return value
    return None


def extract_jev_signal(
    response: Mapping[str, Any],
    question_name: str,
    *,
    signal_option: str | None = None,
) -> float:
    """Frozen signal rule: boolean -> probability; choice -> probabilities[signal_option].

    ``score`` answers are refused: this demo freezes no score-to-signal mapping
    rather than inventing one. The signal is the receiver's policy input. It is
    NOT a permission.
    """
    answers = response.get("answers")
    if not isinstance(answers, Mapping) or question_name not in answers:
        raise JevVercelEvidenceError(f"jev_vercel_signal_question_missing:{question_name}")
    answer = answers[question_name]
    if not isinstance(answer, Mapping):
        raise JevVercelEvidenceError(f"jev_vercel_signal_answer_invalid:{question_name}")
    answer_type = answer.get("type")
    if answer_type == "boolean":
        raw = answer.get("probability")
    elif answer_type == "choice":
        if not signal_option:
            raise JevVercelEvidenceError(
                f"jev_vercel_signal_option_required:{question_name}"
            )
        probabilities = answer.get("probabilities")
        if not isinstance(probabilities, Mapping) or signal_option not in probabilities:
            raise JevVercelEvidenceError(
                f"jev_vercel_signal_option_missing:{question_name}:{signal_option}"
            )
        raw = probabilities[signal_option]
    else:
        raise JevVercelEvidenceError(
            f"jev_vercel_signal_type_unsupported:{question_name}:{answer_type}"
        )
    # Answers were normalized with floats stringified; accept both forms.
    try:
        signal = float(raw) if isinstance(raw, str) else float(raw)
    except (TypeError, ValueError) as exc:
        raise JevVercelEvidenceError(f"jev_vercel_signal_not_numeric:{question_name}") from exc
    if not 0.0 <= signal <= 1.0:
        raise JevVercelEvidenceError(f"jev_vercel_signal_out_of_range:{question_name}")
    return signal

def build_jev_vercel_evidence(
    *,
    state: Any,
    questions: Mapping[str, Any],
    response: Mapping[str, Any],
    response_headers: Mapping[str, Any] | None = None,
    action: Mapping[str, Any],
    witness_key: Ed25519PrivateKey,
    model_requested: str = JEV_MODEL_ID,
    model_reported: str | None = None,
    request_id: str | None = None,
    evidence_id: str | None = None,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    """Bind one gateway Jev judgment to its exact request/response/action.

    ``response`` is the gateway evaluation response body (``answers`` /
    ``usage`` / ``warnings`` / ``rounding`` / ``providerMetadata``);
    ``request_id`` is extracted from allowlisted response headers by the
    caller (``extract_request_id``) and recorded null when absent, never
    invented. ``model_reported`` is the gateway/SDK-echoed model id; it is
    recorded as reported, never as a resolved version id. The returned mapping
    is the signed OpenLine Jev-Vercel evidence receipt.
    """
    if not isinstance(witness_key, Ed25519PrivateKey):
        raise JevVercelEvidenceError("jev_vercel_witness_key_invalid")
    validated_response = _validate_response_shape(response)
    validated_questions = _validate_questions_shape(questions)
    normalized_state = _normalize_jev_value(state, "$.state")
    normalized_action = _normalize_jev_value(action, "$.action")
    action_hash = sha256_hex(olp_canonical_json(normalized_action))
    model_requested = _require_str(model_requested, "model_requested")
    if model_reported is not None:
        model_reported = _require_str(model_reported, "model_reported")
    if request_id is not None and (not isinstance(request_id, str) or not request_id):
        raise JevVercelEvidenceError("jev_vercel_request_id_invalid")
    chosen_evidence_id = evidence_id or secrets.token_hex(16)
    if (
        not isinstance(chosen_evidence_id, str)
        or len(chosen_evidence_id) != 32
        or any(ch not in _HEX for ch in chosen_evidence_id.lower())
    ):
        raise JevVercelEvidenceError("jev_vercel_evidence_id_invalid")
    when = evaluated_at or _utc_now()
    payload = {
        "schema": JEV_VERCEL_EVIDENCE_SCHEMA,
        "schema_version": 1,
        "evidence_id": chosen_evidence_id.lower(),
        "action_hash": action_hash,
        "action": normalized_action,
        "jev": {
            "surface": "vercel-ai-gateway",
            "gateway_host": GATEWAY_HOST,
            "evaluate_path": GATEWAY_EVALUATE_PATH,
            "gateway_protocol_version": GATEWAY_PROTOCOL_VERSION,
            "eval_spec_version": EVAL_SPEC_VERSION,
            "model_requested": model_requested,
            # The gateway echoes the requested ai-model-id; no distinct
            # provider-resolved version id is exposed. Recorded as reported.
            "model_reported": model_reported,
            "request_id": request_id,
            "state": normalized_state,
            "questions": validated_questions,
            "response": validated_response,
            "evaluated_at": _iso(when),
            "evaluated_at_source": "witness_clock",
        },
    }
    return sign_olp_body(payload, witness_key)


@dataclass(frozen=True)
class JevVercelWitnessPolicy:
    """Frozen receiver policy for the JEV-WITNESS-VERCEL-001 demo.

    Threshold logic belongs to the receiver. The adapter merely presents
    verified Jev evidence; Jev does not set OpenLine policy.
    """

    policy_id: str = "jev-witness-vercel-001-demo-policy-v1"
    signal_question: str = "proceed"
    signal_option: str | None = None
    commit_threshold: float = 0.95
    review_band_low: float = 0.80
    max_evidence_age_seconds: int = 300

    def decide_signal(self, signal: float) -> str:
        if signal >= self.commit_threshold:
            return "COMMIT"
        if signal >= self.review_band_low:
            return "QUARANTINE"
        return "DENY"


class JevVercelEvidenceLedger:
    """One-use tracking for Jev-Vercel evidence ids on the protected-effect path.

    Minimal apparatus storage (JSONL + file lock). The one-use semantic is the
    demo path's own frozen rule, not a claim about existing Receipt Gate
    machinery: the existing gate enforces action nonces separately.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def is_consumed(self, evidence_id: str) -> bool:
        with self.lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                if not self.path.exists():
                    return False
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if record.get("evidence_id") == evidence_id:
                        return True
                return False
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def consume(self, evidence_id: str, *, decision_hash: str) -> bool:
        """Record one consumption. Returns False if already consumed."""
        with self.lock_path.open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                if self.path.exists():
                    for line in self.path.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                        except ValueError:
                            continue
                        if record.get("evidence_id") == evidence_id:
                            return False
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(
                            {
                                "evidence_id": evidence_id,
                                "decision_hash": decision_hash,
                                "consumed_at": _iso(_utc_now()),
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                return True
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _append_decision_log(path: str | Path, value: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_suffix(target.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            payload = (
                json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            descriptor = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                remaining = memoryview(payload)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError("short write while appending Jev-Vercel decision receipt")
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def verify_jev_vercel_evidence(
    receipt: Mapping[str, Any],
    *,
    expected_action: Mapping[str, Any],
    trusted_witness_key: str,
    max_evidence_age_seconds: int = 300,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a signed Jev-Vercel evidence receipt. Fail closed on any mismatch.

    Checks, in order: schema, witness signature, exact-action binding, expiry.
    Replay (evidence_id one-use) is enforced by the caller on the
    protected-effect path via :class:`JevVercelEvidenceLedger`, not here, so
    that historical re-verification stays possible after consumption.
    """
    if not isinstance(receipt, Mapping) or receipt.get("schema") != JEV_VERCEL_EVIDENCE_SCHEMA:
        raise JevVercelEvidenceError("jev_vercel_evidence_schema_invalid")
    valid, reason = verify_olp_signature(receipt)
    if valid is not True:
        raise JevVercelEvidenceError(f"jev_vercel_evidence_signature_invalid:{reason or 'unknown'}")
    signature = receipt.get("signature")
    if not isinstance(signature, Mapping):
        raise JevVercelEvidenceError("jev_vercel_evidence_signature_shape_invalid")
    observed_key = str(signature.get("public_key", "")).lower()
    expected_key = str(trusted_witness_key).lower()
    if len(expected_key) != 64 or any(ch not in _HEX for ch in expected_key):
        raise JevVercelEvidenceError("jev_vercel_trusted_witness_key_invalid")
    if observed_key != expected_key:
        raise JevVercelEvidenceError("jev_vercel_evidence_witness_key_mismatch")

    observed_action_hash = receipt.get("action_hash")
    if not isinstance(observed_action_hash, str):
        raise JevVercelEvidenceError("jev_vercel_evidence_action_hash_invalid")
    recomputed = canonical_action_hash(expected_action)
    if observed_action_hash.lower() != recomputed:
        raise JevVercelEvidenceError("jev_vercel_evidence_action_binding_mismatch")

    jev = receipt.get("jev")
    if not isinstance(jev, Mapping):
        raise JevVercelEvidenceError("jev_vercel_evidence_payload_invalid")
    evaluated_at = _parse_time(jev.get("evaluated_at"))
    current = now or _utc_now()
    age = (current - evaluated_at).total_seconds()
    if age < -5:
        raise JevVercelEvidenceError("jev_vercel_evidence_timestamp_in_future")
    if age > max_evidence_age_seconds:
        raise JevVercelEvidenceError("jev_vercel_evidence_expired")

    return dict(receipt)


def evaluate_jev_vercel_witness(
    *,
    action: Mapping[str, Any],
    evidence_receipt: Mapping[str, Any],
    policy: JevVercelWitnessPolicy,
    authority_check: Callable[[], Mapping[str, Any]],
    witness_key: Ed25519PrivateKey,
    trusted_witness_key: str,
    decision_path: str | Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Receiver decision over verified Jev-Vercel evidence: COMMIT / QUARANTINE / DENY.

    Order of checks (fail closed): evidence verification, authority currency,
    then receiver policy over the Jev signal. A high-confidence Jev result
    never authorizes anything by itself.
    """
    if not isinstance(policy, JevVercelWitnessPolicy):
        raise JevVercelEvidenceError("jev_vercel_policy_invalid")
    if not callable(authority_check):
        raise JevVercelEvidenceError("jev_vercel_authority_check_missing")
    current = now or _utc_now()
    reason_codes: list[str] = []
    signal: float | None = None

    try:
        verified = verify_jev_vercel_evidence(
            evidence_receipt,
            expected_action=action,
            trusted_witness_key=trusted_witness_key,
            max_evidence_age_seconds=policy.max_evidence_age_seconds,
            now=current,
        )
    except JevVercelEvidenceError as exc:
        reason_codes.append(str(exc))
        verified = None

    authority: Mapping[str, Any] | None = None
    if verified is not None:
        try:
            authority = authority_check()
        except Exception as exc:  # fail closed on authority-check errors
            reason_codes.append(f"jev_vercel_authority_check_error:{type(exc).__name__}")
            authority = None
        if authority is not None and authority.get("allowed") is not True:
            reason_codes.extend(
                f"authority:{code}" for code in authority.get("reason_codes", [])
            )
            authority = None

    if verified is not None and authority is not None:
        try:
            signal = extract_jev_signal(
                verified["jev"]["response"],
                policy.signal_question,
                signal_option=policy.signal_option,
            )
        except JevVercelEvidenceError as exc:
            reason_codes.append(str(exc))
            signal = None

    if reason_codes:
        decision = "DENY"
    else:
        assert signal is not None
        decision = policy.decide_signal(signal)
        reason_codes.append(f"policy:{decision.lower()}_band")

    receipt_body = {
        "schema": JEV_VERCEL_DECISION_SCHEMA,
        "schema_version": 1,
        "decision": decision,
        "policy_id": policy.policy_id,
        "signal_question": policy.signal_question,
        # Frozen float rule applies to decision receipts too: the signal is
        # bound as its repr() string, never as a float.
        "signal": repr(signal) if signal is not None else None,
        "action_hash": (
            verified["action_hash"] if verified is not None else canonical_action_hash(action)
        ),
        "evidence_id": (
            verified.get("evidence_id") if isinstance(verified, Mapping) else None
        ),
        "evidence_hash": (
            verified.get("payload_hash") if isinstance(verified, Mapping) else None
        ),
        "authority_observation": (
            {
                "standing": authority.get("standing"),
                "terminal": authority.get("terminal"),
                "reason_codes": list(authority.get("reason_codes", [])),
            }
            if isinstance(authority, Mapping)
            else None
        ),
        "reason_codes": sorted(set(reason_codes)),
        "decided_at": _iso(current),
    }
    signed = sign_olp_body(receipt_body, witness_key)
    _append_decision_log(decision_path, signed)
    return signed


__all__ = [
    "EVAL_SPEC_VERSION",
    "GATEWAY_EVALUATE_PATH",
    "GATEWAY_HOST",
    "GATEWAY_PROTOCOL_VERSION",
    "JEV_MODEL_ID",
    "JEV_VERCEL_DECISION_SCHEMA",
    "JEV_VERCEL_EVIDENCE_SCHEMA",
    "JevVercelEvidenceError",
    "JevVercelEvidenceLedger",
    "JevVercelWitnessPolicy",
    "build_jev_vercel_evidence",
    "canonical_action_hash",
    "evaluate_jev_vercel_witness",
    "extract_jev_signal",
    "extract_request_id",
    "verify_jev_vercel_evidence",
]
