from __future__ import annotations

from typing import Mapping, Sequence


class EvidenceIdentityError(ValueError):
    """Raised when an evidence identifier is rebound to different content."""


def build_evidence_index(
    turns: Sequence[Mapping[str, object]],
    *,
    through_turn: int | None = None,
) -> dict[str, Mapping[str, object]]:
    """Build the latest observation index while enforcing immutable ID→hash binding.

    An evidence ID may be re-observed later only when it resolves to the same
    SHA-256 content. A later observation refreshes freshness metadata; it may not
    silently replace the underlying evidence artifact.
    """

    index: dict[str, Mapping[str, object]] = {}
    bound_hashes: dict[str, str] = {}
    for turn in turns:
        turn_number = int(turn["turn"])
        if through_turn is not None and turn_number > through_turn:
            break
        for raw in turn["evidence"]:  # type: ignore[index]
            evidence = raw  # type: ignore[assignment]
            evidence_id = str(evidence["id"])
            evidence_hash = str(evidence["sha256"])
            prior_hash = bound_hashes.get(evidence_id)
            if prior_hash is not None and prior_hash != evidence_hash:
                raise EvidenceIdentityError(
                    f"evidence_id_rebound:{evidence_id}:{prior_hash}:{evidence_hash}"
                )
            bound_hashes[evidence_id] = evidence_hash
            current = index.get(evidence_id)
            if current is None or int(evidence["observed_turn"]) >= int(current["observed_turn"]):
                index[evidence_id] = evidence
    return index


def evidence_is_fresh(evidence: Mapping[str, object], at_turn: int) -> bool:
    return at_turn - int(evidence["observed_turn"]) <= int(evidence["expires_after_turns"])
