"""OpenLine's ECT-001 t1-only standing adapter.

This module deliberately contains no ECT certificate verifier and no closed replay.
It accepts only an already author-verified t0 attestation and evaluates whether a
t1 standing event intersects the certificate's admitted dependency basis.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EXPECTED_SOURCE = "arxiv:2608.23623v1"


class AuthorAttestationError(ValueError):
    """Raised when the t0 author-authority boundary is not satisfied."""


def _admit_author_t0(attestation: Mapping[str, Any]) -> frozenset[str]:
    if attestation.get("source_pin") != _EXPECTED_SOURCE:
        raise AuthorAttestationError("unexpected_source_pin")
    if attestation.get("verifier_authority") != "AUTHOR":
        raise AuthorAttestationError("t0_verifier_authority_must_be_author")
    if attestation.get("verifier_result") != "PASS":
        raise AuthorAttestationError("author_verifier_did_not_pass")

    digest = attestation.get("certificate_sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise AuthorAttestationError("invalid_certificate_digest")

    basis = attestation.get("admitted_dependency_basis")
    if not isinstance(basis, list) or not basis or any(not isinstance(x, str) or not x for x in basis):
        raise AuthorAttestationError("missing_or_invalid_dependency_basis")
    if len(set(basis)) != len(basis):
        raise AuthorAttestationError("duplicate_dependency_basis")
    return frozenset(basis)


def evaluate_t1_standing(
    author_t0_attestation: Mapping[str, Any],
    t1_event: Mapping[str, Any],
) -> dict[str, Any]:
    """Return REOPEN iff the later lost-standing set intersects admitted t0 basis.

    This function does not examine ECT claims, tool traces, scope rules, or replay.
    """

    basis = _admit_author_t0(author_t0_attestation)
    lost = t1_event.get("lost_standing_basis")
    if not isinstance(lost, list) or any(not isinstance(x, str) or not x for x in lost):
        raise ValueError("invalid_t1_lost_standing_basis")

    affected = sorted(basis.intersection(lost))
    return {
        "schema": "openline.ect001.t1-result.v1",
        "t0_certificate_sha256": author_t0_attestation["certificate_sha256"],
        "disposition": "REOPEN" if affected else "NO_REOPEN",
        "affected_basis": affected,
        "t0_reverified_by_openline": False,
        "authority": "OPENLINE_T1_STANDING_ONLY"
    }
