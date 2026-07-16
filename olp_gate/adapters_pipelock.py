"""Pipelock ActionReceipt v1 adapter.

Cryptographic and chain verification is delegated to the official
``pipelock_verify`` package.  This module only maps its result into Receipt
Gate's separate integrity, provenance, coverage, profile, and source-signal
assessments.  It never treats a Pipelock ``allow`` as an OLP ``COMMIT``.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .adapters import (
    FAIL,
    PARTIAL,
    PASS,
    UNAVAILABLE,
    Check,
    SourceAssessment,
    TrustStore,
    _trusted_provenance,
)


PIPELOCK_ACTION_RECEIPT_V1 = "pipelock_action_receipt_v1"
PIPELOCK_EVIDENCE_RECEIPT_V2 = "pipelock_evidence_receipt_v2"


class PipelockFormatUnsupported(ValueError):
    """A real Pipelock format exists but this adapter phase does not handle it."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def detect_pipelock_format(receipt: Mapping[str, Any]) -> str | None:
    """Detect the actual current Pipelock envelopes.

    Stock ActionReceipt v1 objects omit ``record_type``.  The official Python
    verifier also routes an explicit ``action_receipt_v1`` marker to v1, so the
    adapter accepts it for routing and lets the native verifier decide validity.
    """

    record_type = receipt.get("record_type")
    if record_type == "evidence_receipt_v2":
        return PIPELOCK_EVIDENCE_RECEIPT_V2
    if record_type not in (None, "action_receipt_v1"):
        return None
    if (
        receipt.get("version") == 1
        and isinstance(receipt.get("action_record"), Mapping)
        and "signature" in receipt
        and "signer_key" in receipt
    ):
        return PIPELOCK_ACTION_RECEIPT_V1
    return None


def _unsupported_v2_assessment(receipts: Sequence[Mapping[str, Any]]) -> SourceAssessment:
    first = receipts[0] if receipts else {}
    event_id = first.get("event_id")
    timestamp = first.get("timestamp")
    reason = "pipelock_evidence_receipt_v2_phase1_unsupported"
    return SourceAssessment(
        source_format=PIPELOCK_EVIDENCE_RECEIPT_V2,
        receipt_hashes=[],
        primary_hash=None,
        source_key_ids=[],
        source_binding={
            "run_id": None,
            "session_id": None,
            "source_sequence": first.get("chain_seq"),
            "action_id": event_id,
            "native_verdict": None,
        },
        source_timestamp=str(timestamp) if timestamp is not None else None,
        integrity=Check(UNAVAILABLE, ["canonicalization_unsupported"], {"format": "EvidenceReceipt v2"}),
        provenance=Check(UNAVAILABLE, ["source_key_unavailable"]),
        coverage=Check(UNAVAILABLE, [reason]),
        profile=Check(FAIL, [reason], {"phase": 1, "native_format_recognized": True}),
        source_signal=Check(UNAVAILABLE, [reason]),
    )


def assess_unsupported_pipelock_v2(
    receipts: Sequence[Mapping[str, Any]],
) -> SourceAssessment:
    return _unsupported_v2_assessment(receipts)


def _load_native_verifier() -> tuple[Any, Any, Any, str]:
    try:
        import pipelock_verify
        from pipelock_verify._verify import _compute_receipt_hash
    except ImportError as exc:
        raise RuntimeError("pipelock_verifier_unavailable") from exc
    version = str(getattr(pipelock_verify, "__version__", "unknown"))
    if not version.startswith("0.2."):
        raise RuntimeError(f"pipelock_verifier_version_unsupported:{version}")
    return pipelock_verify.verify, pipelock_verify.verify_chain, _compute_receipt_hash, version


def _pinned_key(keys: Sequence[str], trust_store: TrustStore) -> str | None:
    if not keys:
        return None
    candidate = keys[0]
    record = trust_store.get(candidate)
    if record is None or "source" not in record.roles:
        return None
    declared = (record.public_key or candidate).removeprefix("ed25519:")
    return candidate if declared == candidate else None


def _profile_error(error: str | None) -> bool:
    if not error:
        return False
    return error.startswith(
        (
            "unsupported receipt version",
            "missing or invalid action_record",
            "invalid action record",
            "unmarshal receipt",
            "unknown record_type",
            "parsing receipt",
            "receipt must be",
            "unrecognized JSONL line",
        )
    )


def _source_signal(
    *,
    verdict: str | None,
    integrity: Check,
    profile: Check,
) -> Check:
    if integrity.status != PASS or profile.status != PASS:
        return Check(
            UNAVAILABLE,
            ["pipelock_source_verdict_untrusted"],
            {"native_verdict": verdict},
        )
    normalized = verdict.lower() if isinstance(verdict, str) else ""
    if normalized in {"allow", "forward"}:
        return Check(PASS, [], {"native_verdict": normalized, "mapping": "advisory_input_only"})
    if normalized == "block":
        return Check(
            FAIL,
            ["pipelock_source_verdict_block"],
            {"native_verdict": normalized, "mapping": "must_not_commit"},
        )
    if normalized in {"warn", "ask", "strip", "redirect", "defer"}:
        return Check(
            PARTIAL,
            ["pipelock_source_verdict_requires_review"],
            {"native_verdict": normalized, "mapping": "must_not_commit_without_policy_review"},
        )
    return Check(
        FAIL,
        ["pipelock_source_verdict_unknown"],
        {"native_verdict": verdict, "mapping": "fail_closed"},
    )


def assess_pipelock_v1(
    receipts: Sequence[Mapping[str, Any]],
    trust_store: TrustStore,
) -> SourceAssessment:
    """Verify and map one ActionReceipt v1 sequence.

    The official verifier receives the externally pinned public key whenever it
    is present in the Receipt Gate trust store.  Without that pin, signature
    mathematics can still pass, while provenance remains explicitly unavailable.
    """

    if not receipts:
        raise ValueError("Pipelock receipt bundle is empty")
    formats = [detect_pipelock_format(receipt) for receipt in receipts]
    if PIPELOCK_EVIDENCE_RECEIPT_V2 in formats:
        raise PipelockFormatUnsupported("pipelock_evidence_receipt_v2_phase1_unsupported")
    if any(value != PIPELOCK_ACTION_RECEIPT_V1 for value in formats):
        raise PipelockFormatUnsupported("pipelock_record_type_unsupported")

    keys = sorted(
        {
            str(receipt.get("signer_key"))
            for receipt in receipts
            if isinstance(receipt.get("signer_key"), str) and receipt.get("signer_key")
        }
    )
    pin = _pinned_key(keys, trust_store)

    try:
        verify_one, verify_chain, compute_hash, verifier_version = _load_native_verifier()
    except RuntimeError as exc:
        reason = str(exc)
        return SourceAssessment(
            source_format=PIPELOCK_ACTION_RECEIPT_V1,
            receipt_hashes=[],
            primary_hash=None,
            source_key_ids=keys,
            source_binding={},
            source_timestamp=None,
            integrity=Check(UNAVAILABLE, [reason]),
            provenance=Check(UNAVAILABLE, [reason]),
            coverage=Check(UNAVAILABLE, [reason]),
            profile=Check(UNAVAILABLE, [reason]),
            source_signal=Check(UNAVAILABLE, [reason]),
        )

    individual_results = [verify_one(dict(receipt), public_key_hex=pin) for receipt in receipts]
    with tempfile.TemporaryDirectory(prefix="olp-pipelock-chain-") as temporary:
        chain_path = Path(temporary) / "receipts.jsonl"
        chain_path.write_text(
            "".join(
                json.dumps(dict(receipt), ensure_ascii=False, separators=(",", ":")) + "\n"
                for receipt in receipts
            ),
            encoding="utf-8",
        )
        chain_result = verify_chain(chain_path, public_key_hex=pin)

    receipt_hashes: list[str] = []
    hash_errors: list[str] = []
    for index, receipt in enumerate(receipts):
        try:
            receipt_hashes.append(str(compute_hash(dict(receipt))))
        except (KeyError, TypeError, ValueError) as exc:
            hash_errors.append(f"receipt_{index}:{type(exc).__name__}")

    native_errors = [
        {"index": index, "error": result.error}
        for index, result in enumerate(individual_results)
        if not result.valid
    ]
    integrity_reasons: list[str] = []
    if native_errors:
        integrity_reasons.append("pipelock_receipt_invalid")
    if not chain_result.valid:
        integrity_reasons.append("pipelock_chain_invalid")
    if hash_errors:
        integrity_reasons.append("pipelock_receipt_hash_unavailable")
    integrity_details = {
        "native_verifier": "pipelock_verify",
        "native_verifier_version": verifier_version,
        "trusted_key_pinned": pin is not None,
        "signature_math_verified": all(result.valid for result in individual_results),
        "signatures_verified": pin is not None and all(result.valid for result in individual_results),
        "individual_errors": native_errors,
        "chain_error": chain_result.error,
        "chain_broken_at_seq": chain_result.broken_at_seq,
        "receipt_count": len(receipts),
        "hash_errors": hash_errors,
    }
    integrity = Check(FAIL, integrity_reasons, integrity_details) if integrity_reasons else Check(PASS, [], integrity_details)

    profile_reasons = sorted(
        {
            "pipelock_profile_invalid"
            for result in individual_results
            if not result.valid and _profile_error(result.error)
        }
    )
    last_record = receipts[-1].get("action_record", {})
    verdict = str(last_record.get("verdict")) if isinstance(last_record, Mapping) and last_record.get("verdict") is not None else None
    known_verdicts = {"allow", "block", "warn", "ask", "strip", "forward", "redirect", "defer"}
    if verdict is not None and verdict.lower() not in known_verdicts:
        profile_reasons.append("pipelock_verdict_vocabulary_unsupported")
    profile = (
        Check(FAIL, profile_reasons, {"native_errors": native_errors})
        if profile_reasons
        else Check(PASS, [], {"record_type": "action_receipt_v1", "record_type_was_implicit": receipts[0].get("record_type") is None})
    )

    if chain_result.valid:
        coverage = Check(
            PARTIAL,
            ["pipelock_action_chain_tail_completeness_unproved"],
            {
                "claim": "present ActionReceipt v1 sequence and linkage verified",
                "receipt_count": chain_result.receipt_count,
                "root_hash": chain_result.root_hash,
                "action_omission_proved_absent": False,
            },
        )
    else:
        coverage = Check(
            FAIL,
            ["pipelock_chain_invalid"],
            {"error": chain_result.error, "broken_at_seq": chain_result.broken_at_seq},
        )

    signatures_verified = pin is not None and all(result.valid for result in individual_results)
    provenance = _trusted_provenance(keys, trust_store)
    provenance_details = {
        **provenance.details,
        "signatures_verified": signatures_verified,
        "trusted_key_pinned": pin is not None,
        "embedded_key_self_consistency_only": pin is None,
    }
    if not signatures_verified:
        provenance = Check(
            UNAVAILABLE,
            sorted(set(provenance.reason_codes + ["pipelock_provenance_not_established"])),
            provenance_details,
        )
    else:
        provenance.details.update(provenance_details)

    action_record = last_record if isinstance(last_record, Mapping) else {}
    run_nonce = action_record.get("run_nonce")
    session_id = action_record.get("session_id")
    timestamp = action_record.get("timestamp")
    source_signal = _source_signal(verdict=verdict, integrity=integrity, profile=profile)

    return SourceAssessment(
        source_format=PIPELOCK_ACTION_RECEIPT_V1,
        receipt_hashes=receipt_hashes,
        primary_hash=receipt_hashes[-1] if receipt_hashes else None,
        source_key_ids=keys,
        source_binding={
            "run_id": run_nonce,
            "session_id": session_id,
            "source_sequence": action_record.get("chain_seq"),
            "action_id": action_record.get("action_id"),
            "native_verdict": verdict,
            "target": action_record.get("target"),
            "transport": action_record.get("transport"),
            "policy_hash": action_record.get("policy_hash"),
        },
        source_timestamp=str(timestamp) if timestamp is not None else None,
        integrity=integrity,
        provenance=provenance,
        coverage=coverage,
        profile=profile,
        source_signal=source_signal,
    )
