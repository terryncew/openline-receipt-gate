"""Verified Model Swap orchestration.

The candidate models and the Half-Life compactor do not grade this trial.  A
receiver process replays the raw verified history, compares each candidate
lane with that replay, authenticates the cold archive, and then asks the
existing proof-to-policy gate whether the resulting evidence may continue.

This module defines a proof-card artifact, not a new receipt family.  The final
authorization remains a ``proof_to_policy_decision_receipt``.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from importlib import metadata
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapters import PASS, TrustStore, assess_source_bundle
from .crypto import (
    jcs_integer_canonical_json,
    public_key_hex,
    sha256_hex,
    strict_json_load,
)
from .evidence import assess_outcome, issue_outcome_receipt
from .gateway import evaluate_request, verify_decision_log
from .policy import PolicySpec
from .session import SessionLedger
from .verified_commit import VerifiedCommitError, one_use_code_hash, settings_hash


PROOF_CARD_SCHEMA = "openline.verified-model-swap.proof-card.v1"
SUMMARY_SCHEMA = "openline.verified-model-swap.ordinary-summary.v1"
DSM_PROJECTION_SCHEMA = "openline.verified-model-swap.dsm-projection.v1"
ACTION_TYPE = "verified_model_swap"
EVIDENCE_ID = "model_swap_proof_card"
ALLOWED_DISPOSITIONS = {"COMMIT", "QUARANTINE", "DENY"}
CLAIM = "Change the model without losing receiver-relevant continuity."
CLAIM_BOUNDARY = (
    "This trial proves exact receiver-decision equivalence only for the disclosed "
    "Half-Life history, candidate lane outputs, policy pins, and deterministic "
    "projection. Model identifiers are caller declarations, not proof that a "
    "commercial provider executed the trial. It does not establish legal ownership, "
    "universal model portability, controller independence, or semantic truth beyond "
    "the verified evidence. Distinct signing keys prove key separation, not who "
    "ultimately controls their custody."
)


class ModelSwapError(ValueError):
    """Raised when the swap evidence cannot be verified or safely graded."""


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_hash(value: Any) -> str:
    return sha256_hex(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _load_half_life_api() -> dict[str, Any]:
    try:
        from openline_half_life.causal_compactor import (
            receipt_gate_projection,
            rehydrate_archived_state,
        )
        from openline_half_life.causal_compactor import (
            load_trusted_compaction_policy_keys,
        )
        from openline_half_life.policy import load_trusted_policy_keys
        from openline_half_life.receipts import verify_output_directory
        from openline_half_life.reference_replay import (
            reference_receipt_gate_projection,
        )
        from openline_half_life.util import load_json
    except ImportError as exc:
        raise ModelSwapError(
            "Verified Model Swap requires the pinned OpenLine Half-Life integration; "
            "install requirements-model-swap.txt"
        ) from exc
    try:
        version = metadata.version("openline-half-life")
    except metadata.PackageNotFoundError:
        version = "source-tree"
    return {
        "version": version,
        "receipt_gate_projection": receipt_gate_projection,
        "rehydrate_archived_state": rehydrate_archived_state,
        "load_trusted_compaction_policy_keys": load_trusted_compaction_policy_keys,
        "load_trusted_policy_keys": load_trusted_policy_keys,
        "verify_output_directory": verify_output_directory,
        "reference_receipt_gate_projection": reference_receipt_gate_projection,
        "load_json": load_json,
    }


def _validate_projection(
    value: Mapping[str, Any],
    *,
    lane_id: str,
) -> dict[str, dict[str, str]]:
    projection: dict[str, dict[str, str]] = {}
    for key, raw in value.items():
        if not isinstance(key, str) or not key:
            raise ModelSwapError(f"{lane_id}: decision key must be a nonempty string")
        if not isinstance(raw, Mapping):
            raise ModelSwapError(f"{lane_id}: decision {key} must be an object")
        if set(raw) != {"disposition", "state_hash"}:
            raise ModelSwapError(f"{lane_id}: decision {key} has an invalid shape")
        disposition = raw.get("disposition")
        state_hash = raw.get("state_hash")
        if disposition not in ALLOWED_DISPOSITIONS:
            raise ModelSwapError(f"{lane_id}: decision {key} has an invalid disposition")
        if (
            not isinstance(state_hash, str)
            or len(state_hash) != 64
            or any(char not in "0123456789abcdef" for char in state_hash)
        ):
            raise ModelSwapError(f"{lane_id}: decision {key} has an invalid state hash")
        projection[key] = {
            "disposition": str(disposition),
            "state_hash": state_hash,
        }
    return dict(sorted(projection.items()))


def build_ordinary_summary(capsule: Mapping[str, Any]) -> dict[str, Any]:
    """Build a disclosed success-state summary baseline.

    The baseline preserves active claims, constraints, commitments, and open
    questions.  It deliberately does not pretend that a prose-style summary
    normally carries tombstones, archive custody, or policy/key bindings.
    """

    body = {
        "schema": SUMMARY_SCHEMA,
        "summary_rule": "active_state_without_negative_history_or_archive_custody",
        "run_id": capsule.get("run_id"),
        "objective": capsule.get("objective"),
        "supported_claims": list(capsule.get("supported_claims", [])),
        "current_constraints": list(capsule.get("current_constraints", [])),
        "commitments": list(capsule.get("commitments", [])),
        "unresolved_questions": list(capsule.get("unresolved_questions", [])),
        "omitted_by_rule": [
            "admitted_mechanisms",
            "contradictions",
            "unresolved_associations",
            "tombstones",
            "evidence_references",
            "policy_binding",
            "source_binding",
            "archive",
            "rehydration_conditions",
        ],
        "claim_boundary": (
            "This deterministic baseline is not claimed to represent every model "
            "summary. It exposes exactly which negative-history and custody fields "
            "are absent so the receiver can grade the loss rather than infer it."
        ),
    }
    return {**body, "summary_hash": _json_hash(body)}


def _grade_lane(
    *,
    lane_id: str,
    input_artifact: Mapping[str, Any],
    oracle: Mapping[str, Mapping[str, str]],
    candidate: Mapping[str, Mapping[str, str]],
    adapter_id: str,
) -> dict[str, Any]:
    expected = _validate_projection(oracle, lane_id="independent_oracle")
    observed = _validate_projection(candidate, lane_id=lane_id)
    keys = sorted(set(expected) | set(observed))
    mismatches = []
    survived = []
    lost = []
    changed = []
    introduced = []
    for key in keys:
        expected_value = expected.get(key)
        observed_value = observed.get(key)
        if expected_value == observed_value:
            survived.append(key)
            continue
        mismatches.append(
            {
                "decision_key": key,
                "oracle": expected_value,
                "candidate": observed_value,
            }
        )
        if expected_value is None:
            introduced.append(key)
        elif observed_value is None:
            lost.append(key)
        else:
            changed.append(key)
    commit_survivors = [
        key
        for key in survived
        if expected[key]["disposition"] == "COMMIT"
    ]
    boundary_survivors = [
        key
        for key in survived
        if expected[key]["disposition"] in {"QUARANTINE", "DENY"}
    ]
    return {
        "lane_id": lane_id,
        "adapter_id": adapter_id,
        "input_hash": _json_hash(input_artifact),
        "input_bytes": len(
            json.dumps(
                input_artifact,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ),
        "projection": observed,
        "decision_hash": _json_hash(observed),
        "decision_count": len(observed),
        "matches_oracle": not mismatches,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "commitments_survived": commit_survivors,
        "boundaries_survived": boundary_survivors,
        "lost_decisions": lost,
        "changed_decisions": changed,
        "introduced_decisions": introduced,
    }


def _evaluate_half_life_artifacts(
    half_life_output: Path,
    *,
    succession_policy_public_key_path: Path,
    compaction_policy_public_key_path: Path,
) -> dict[str, Any]:
    api = _load_half_life_api()
    root = half_life_output.resolve(strict=True)
    succession_keys = api["load_trusted_policy_keys"](
        succession_policy_public_key_path.resolve(strict=True)
    )
    compaction_keys = api["load_trusted_compaction_policy_keys"](
        compaction_policy_public_key_path.resolve(strict=True)
    )
    verification = api["verify_output_directory"](
        root,
        expected_policy_public_keys=succession_keys,
        expected_compaction_policy_public_keys=compaction_keys,
    )
    if not verification.get("valid"):
        errors = verification.get("errors", [])
        raise ModelSwapError(
            "Half-Life output failed receiver verification: " + ",".join(errors)
        )

    load_json = api["load_json"]
    bundle = load_json(root / "half_life_receipt.json")
    full_handoff = load_json(root / "full_history_handoff.json")
    capsule = load_json(root / "causal_capsule.json")
    compaction_policy = load_json(root / "compaction_policy.json")
    archive_receipt = load_json(root / "archive_manifest.json")
    equivalence = load_json(root / "decision_equivalence_report.json")
    source_count = int(bundle["compaction"]["source_chain_count"])
    source_chain = list(bundle["receipts"][:source_count])
    checkpoint_turn = int(capsule["checkpoint_turn"])

    oracle = api["reference_receipt_gate_projection"](
        full_handoff["turns"],
        source_chain,
        checkpoint_turn,
        compaction_policy,
    )
    capsule_projection = api["receipt_gate_projection"](capsule)
    rehydrated = api["rehydrate_archived_state"](
        root,
        capsule,
        archive_receipt,
        compaction_policy,
        expected_compaction_policy_public_keys=compaction_keys,
    )
    rehydrated_projection = rehydrated["decision_projection"]
    ordinary_summary = build_ordinary_summary(capsule)
    summary_projection = api["receipt_gate_projection"](ordinary_summary)

    expected_hash = _json_hash(oracle)
    observed_checks = {
        "stored_full_history_hash_matches": (
            equivalence.get("full_history_decision_hash") == expected_hash
        ),
        "stored_capsule_hash_matches": (
            equivalence.get("causal_capsule_decision_hash")
            == _json_hash(capsule_projection)
        ),
        "stored_equivalence_passed": equivalence.get("passed") is True,
        "capsule_matches_oracle": capsule_projection == oracle,
        "archive_matches_oracle": rehydrated_projection == oracle,
    }
    if not all(observed_checks.values()):
        failed = sorted(name for name, passed in observed_checks.items() if not passed)
        raise ModelSwapError(
            "Half-Life semantic replay failed: " + ",".join(failed)
        )
    return {
        "api_version": api["version"],
        "root": root,
        "verification": verification,
        "bundle": bundle,
        "full_handoff": full_handoff,
        "capsule": capsule,
        "ordinary_summary": ordinary_summary,
        "archive_receipt": archive_receipt,
        "equivalence": equivalence,
        "oracle": _validate_projection(oracle, lane_id="independent_oracle"),
        "default_projections": {
            "full_history": _validate_projection(oracle, lane_id="full_history"),
            "ordinary_summary": _validate_projection(
                summary_projection, lane_id="ordinary_summary"
            ),
            "verified_capsule": _validate_projection(
                capsule_projection, lane_id="verified_capsule"
            ),
        },
        "rehydrated_projection": _validate_projection(
            rehydrated_projection, lane_id="rehydrated_archive"
        ),
        "semantic_checks": observed_checks,
    }


def build_model_swap_proof(
    half_life_output: str | Path,
    *,
    succession_policy_public_key_path: str | Path,
    compaction_policy_public_key_path: str | Path,
    source_model: str,
    target_model: str,
    source_adapter: str = "offline-deterministic-source-v1",
    target_adapter: str = "offline-deterministic-target-v1",
    candidate_lane_projections: Mapping[
        str, Mapping[str, Mapping[str, str]]
    ] | None = None,
    trial_id: str = "verified-model-swap-demo",
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not source_model or not target_model:
        raise ModelSwapError("source and target model identifiers are required")
    if source_model == target_model:
        raise ModelSwapError("a model swap requires different source and target identifiers")
    if not trial_id:
        raise ModelSwapError("trial_id is required")

    evaluated = _evaluate_half_life_artifacts(
        Path(half_life_output),
        succession_policy_public_key_path=Path(succession_policy_public_key_path),
        compaction_policy_public_key_path=Path(compaction_policy_public_key_path),
    )
    projections = dict(evaluated["default_projections"])
    if candidate_lane_projections is not None:
        if set(candidate_lane_projections) != {
            "full_history",
            "ordinary_summary",
            "verified_capsule",
        }:
            raise ModelSwapError("candidate projections must provide exactly three lanes")
        projections = {
            lane: _validate_projection(value, lane_id=lane)
            for lane, value in candidate_lane_projections.items()
        }

    inputs = {
        "full_history": evaluated["full_handoff"],
        "ordinary_summary": evaluated["ordinary_summary"],
        "verified_capsule": evaluated["capsule"],
    }
    lanes = {
        lane_id: _grade_lane(
            lane_id=lane_id,
            input_artifact=inputs[lane_id],
            oracle=evaluated["oracle"],
            candidate=projections[lane_id],
            adapter_id=target_adapter,
        )
        for lane_id in ("full_history", "ordinary_summary", "verified_capsule")
    }
    summary_missing = lanes["ordinary_summary"]["lost_decisions"]
    restored = [
        key
        for key in summary_missing
        if evaluated["rehydrated_projection"].get(key)
        == evaluated["oracle"].get(key)
    ]
    archive_payload = evaluated["archive_receipt"].get("payload", {})
    entries = archive_payload.get("entries", [])
    body = {
        "schema": PROOF_CARD_SCHEMA,
        "profile": "verified_model_swap/v1",
        "trial_id": trial_id,
        "generated_at": generated_at or _iso_now(),
        "claim": CLAIM,
        "models": {
            "source": source_model,
            "target": target_model,
            "source_adapter": source_adapter,
            "target_adapter": target_adapter,
            "provider_execution_attested": False,
        },
        "authority": {
            "grader": "receiver-independent-reference-replay-v1",
            "candidate_self_grading_allowed": False,
            "compactor_self_grading_allowed": False,
            "dsm_grading_allowed": False,
        },
        "half_life_verification": {
            "valid": True,
            "version": evaluated["api_version"],
            "bundle_schema": evaluated["bundle"].get("schema"),
            "bundle_chain_valid": evaluated["verification"]["chain"]["valid"],
            "compaction_valid": evaluated["verification"]["compaction"]["valid"],
            "receipt_count": evaluated["verification"]["chain"]["count"],
            "decision_equivalence_report_hash": evaluated["equivalence"]["report_hash"],
            "decision_equivalence_exact": True,
            "semantic_checks": evaluated["semantic_checks"],
        },
        "oracle": {
            "evaluator": "independent_reference_replay_v1",
            "decision_hash": _json_hash(evaluated["oracle"]),
            "decision_count": len(evaluated["oracle"]),
        },
        "lanes": lanes,
        "continuity": {
            "capsule_commitments_survived": lanes["verified_capsule"][
                "commitments_survived"
            ],
            "capsule_boundaries_survived": lanes["verified_capsule"][
                "boundaries_survived"
            ],
            "summary_lost": summary_missing,
            "summary_changed": lanes["ordinary_summary"]["changed_decisions"],
            "archive_receipt_count": len(entries),
            "archive_manifest_receipt_hash": evaluated["archive_receipt"].get(
                "receipt_hash"
            ),
            "archive_rehydration_verified": True,
            "had_to_return_from_archive": restored,
        },
        "independent_grade": {
            "passed": bool(
                lanes["full_history"]["matches_oracle"]
                and lanes["verified_capsule"]["matches_oracle"]
                and evaluated["rehydrated_projection"] == evaluated["oracle"]
            ),
            "full_history_matches_oracle": lanes["full_history"]["matches_oracle"],
            "summary_matches_oracle": lanes["ordinary_summary"]["matches_oracle"],
            "capsule_matches_oracle": lanes["verified_capsule"]["matches_oracle"],
            "archive_matches_oracle": (
                evaluated["rehydrated_projection"] == evaluated["oracle"]
            ),
            "summary_loss_is_required_for_pass": False,
        },
        "receiver_controls": {
            "succession_policy_hash": evaluated["bundle"].get("policy_hash"),
            "compaction_policy_hash": evaluated["bundle"]
            .get("compaction", {})
            .get("policy_hash"),
            "trusted_key_version": evaluated["capsule"]
            .get("policy_binding", {})
            .get("trusted_key_version"),
            "automatic_compaction_authorized": False,
            "automatic_retirement_authorized": False,
        },
        "display": {
            "headline": "Change the model without losing the agent.",
            "subhead": "The capsule kept the receiver decisions the ordinary summary dropped.",
            "disposition": (
                "ELIGIBLE_FOR_RECEIVER_GATE"
                if lanes["verified_capsule"]["matches_oracle"]
                else "HOLD"
            ),
        },
        "claim_boundary": CLAIM_BOUNDARY,
    }
    return {**body, "proof_hash": _json_hash(body)}


def _u64(value: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _issue_agent_receipt(
    *,
    key: Ed25519PrivateKey,
    method: str,
    trial_id: str,
    artifact_hash: str,
    created_at: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentreceipts.ai/context/v2",
        ],
        "id": f"urn:receipt:{trial_id}",
        "type": ["VerifiableCredential", "AgentReceipt"],
        "version": "0.5.0",
        "issuer": {
            "id": "did:example:verified-model-swap-orchestrator",
            "type": "AIAgent",
            "session_id": trial_id,
        },
        "issuanceDate": created_at,
        "credentialSubject": {
            "principal": {
                "id": "did:example:receiver",
                "type": "HumanPrincipal",
            },
            "action": {
                "id": trial_id,
                "type": ACTION_TYPE,
                "risk_level": "high",
                "timestamp": created_at,
            },
            "outcome": {
                "status": "success",
                "reversible": True,
                "response_hash": "sha256:" + artifact_hash,
            },
            "chain": {
                "sequence": 1,
                "previous_receipt_hash": None,
                "chain_id": trial_id,
                "terminal": True,
                "status": "complete",
            },
        },
    }
    return {
        **body,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": created_at,
            "verificationMethod": method,
            "proofPurpose": "assertionMethod",
            "proofValue": _u64(key.sign(jcs_integer_canonical_json(body))),
        },
    }


def _agent_source_hash(receipt: Mapping[str, Any]) -> str:
    body = dict(receipt)
    body.pop("proof", None)
    return sha256_hex(jcs_integer_canonical_json(body))


def run_verified_model_swap(
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
    candidate_lane_projections: Mapping[
        str, Mapping[str, Mapping[str, str]]
    ] | None = None,
    trial_id: str = "verified-model-swap-demo",
    commit_action: Mapping[str, Any] | None = None,
    commit_one_use_code: str | None = None,
    commit_ttl_seconds: int = 120,
) -> dict[str, Any]:
    """Build, gate, and verify one model-swap proof bundle."""

    public_keys = {
        public_key_hex(source_signing_key),
        public_key_hex(grader_signing_key),
        public_key_hex(gate_signing_key),
    }
    if len(public_keys) != 3:
        raise ModelSwapError("source, independent grader, and gate keys must differ")

    output = Path(output_dir)
    guarded_names = {
        "proof_card.json",
        "decision_receipts.jsonl",
        "verified_model_swap.latest.json",
    }
    if any((output / name).exists() for name in guarded_names):
        raise ModelSwapError("refusing to overwrite an existing model-swap proof bundle")
    output.mkdir(parents=True, exist_ok=True)

    created_at = _iso_now()
    proof = build_model_swap_proof(
        half_life_output,
        succession_policy_public_key_path=succession_policy_public_key_path,
        compaction_policy_public_key_path=compaction_policy_public_key_path,
        source_model=source_model,
        target_model=target_model,
        source_adapter=source_adapter,
        target_adapter=target_adapter,
        candidate_lane_projections=candidate_lane_projections,
        trial_id=trial_id,
        generated_at=created_at,
    )
    proof_path = output / "proof_card.json"
    _write_json(proof_path, proof)
    proof_file_hash = sha256_hex(proof_path.read_bytes())

    source_method = "did:example:verified-model-swap-orchestrator#key-1"
    source_receipt = _issue_agent_receipt(
        key=source_signing_key,
        method=source_method,
        trial_id=trial_id,
        artifact_hash=proof_file_hash,
        created_at=created_at,
    )
    source_hash = _agent_source_hash(source_receipt)
    grader_public = public_key_hex(grader_signing_key)
    trust_value = {
        "keys": {
            source_method: {
                "public_key": public_key_hex(source_signing_key),
                "roles": ["source"],
                "independence": "operator",
                "controller": "model-swap-orchestrator",
            },
            grader_public: {
                "public_key": grader_public,
                "roles": ["outcome"],
                "independence": "receiver",
                "controller": "receiver-independent-grader",
            },
        }
    }
    trust = TrustStore.from_mapping(trust_value)
    ledger = SessionLedger(output / "session_ledger.json")
    binding = ledger.issue_challenge(
        run_id=trial_id,
        session_id=trial_id,
        expected_source_hash=source_hash,
    )
    outcome = issue_outcome_receipt(
        source_receipt_hash=source_hash,
        outcome_status=("pass" if proof["independent_grade"]["passed"] else "fail"),
        harmful=False,
        evidence_hash=proof_file_hash,
        witness_id="receiver-independent-grader",
        rollback_supported=True,
        key=grader_signing_key,
    )
    policy_metadata: dict[str, Any] = {
        "profile": "verified_model_swap/v1",
        "irreversible_action_gate": True,
    }
    commit_settings: dict[str, Any] | None = None
    if commit_action is not None:
        if set(commit_action) != {"tool", "target", "settings"}:
            raise ModelSwapError(
                "commit_action must contain exactly tool, target, and settings"
            )
        if (
            not isinstance(commit_action.get("tool"), str)
            or not commit_action.get("tool")
            or not isinstance(commit_action.get("target"), str)
            or not commit_action.get("target")
            or not isinstance(commit_action.get("settings"), Mapping)
        ):
            raise ModelSwapError("commit_action fields are invalid")
        if commit_one_use_code is None:
            raise ModelSwapError("commit_one_use_code is required with commit_action")
        if (
            not isinstance(commit_ttl_seconds, int)
            or isinstance(commit_ttl_seconds, bool)
            or commit_ttl_seconds <= 0
        ):
            raise ModelSwapError("commit_ttl_seconds must be positive")
        # Validate the receiver-held code before any decision is emitted.  The
        # raw value is never written to the bundle.
        one_use_code_hash(commit_one_use_code)
        commit_settings = dict(commit_action["settings"])
        policy_metadata["verified_commit"] = {
            "required": True,
            "tool": str(commit_action["tool"]),
            "target": str(commit_action["target"]),
            "settings_hash": settings_hash(commit_settings),
            "run_id": trial_id,
            "capsule_hash": proof["lanes"]["verified_capsule"]["input_hash"],
            "evidence_hashes": [proof_file_hash],
            "max_ttl_seconds": commit_ttl_seconds,
        }
    elif commit_one_use_code is not None:
        raise ModelSwapError("commit_action is required with commit_one_use_code")

    policy = PolicySpec.from_mapping(
        {
            "policy_id": "verified-model-swap.receiver-policy",
            "version": "1",
            "require_declared_coverage": True,
            "require_outcome_witness": True,
            "required_evidence_ids": [EVIDENCE_ID],
            "required_claim_ids": [trial_id],
            "evidence_assertions": [
                {
                    "evidence_id": EVIDENCE_ID,
                    "path": "authority.candidate_self_grading_allowed",
                    "op": "equals",
                    "value": False,
                },
                {
                    "evidence_id": EVIDENCE_ID,
                    "path": "half_life_verification.valid",
                    "op": "equals",
                    "value": True,
                },
                {
                    "evidence_id": EVIDENCE_ID,
                    "path": "independent_grade.capsule_matches_oracle",
                    "op": "equals",
                    "value": True,
                },
                {
                    "evidence_id": EVIDENCE_ID,
                    "path": "independent_grade.archive_matches_oracle",
                    "op": "equals",
                    "value": True,
                },
                {
                    "evidence_id": EVIDENCE_ID,
                    "path": "independent_grade.passed",
                    "op": "equals",
                    "value": True,
                },
            ],
            "metadata": policy_metadata,
        }
    )
    request = {
        "schema": "openline.proof_to_policy.request.v0.2",
        "request_id": f"{trial_id}-receiver-decision",
        "action_type": ACTION_TYPE,
        "claim": CLAIM,
        "source_receipts": [source_receipt],
        "binding": binding,
        "evidence": [
            {
                "id": EVIDENCE_ID,
                "artifact_path": proof_path.name,
                "content_hash": proof_file_hash,
                "source_commitment_path": "credentialSubject.outcome.response_hash",
            }
        ],
        "outcome_receipt": outcome,
    }
    if commit_action is not None and commit_settings is not None:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        request["commit_request"] = {
            "tool": str(commit_action["tool"]),
            "target": str(commit_action["target"]),
            "settings": commit_settings,
            "run_id": trial_id,
            "capsule_hash": proof["lanes"]["verified_capsule"]["input_hash"],
            "evidence_hashes": [proof_file_hash],
            "policy_hash": policy.policy_hash,
            "expires_at": (
                created + timedelta(seconds=commit_ttl_seconds)
            ).isoformat().replace("+00:00", "Z"),
            "one_use_code": commit_one_use_code,
        }
    decision_path = output / "decision_receipts.jsonl"
    decision = evaluate_request(
        request,
        policy=policy,
        trust_store=trust,
        signing_key=gate_signing_key,
        issuer_id=gate_issuer,
        decision_path=decision_path,
        session_ledger=ledger,
        base_dir=output,
    )
    _write_json(output / "source_receipt.json", source_receipt)
    _write_json(output / "outcome_receipt.json", outcome)
    saved_request = json.loads(json.dumps(request))
    if isinstance(saved_request.get("commit_request"), dict):
        raw_code = saved_request["commit_request"].pop("one_use_code")
        saved_request["commit_request"]["one_use_code_hash"] = one_use_code_hash(
            raw_code
        )
        saved_request["commit_request"]["one_use_code_redacted"] = True
    _write_json(output / "gate_request.json", saved_request)
    _write_json(output / "gate_policy.json", policy.as_dict())
    _write_json(output / "gate_trust.json", trust_value)

    projection = {
        "schema": DSM_PROJECTION_SCHEMA,
        "display_only": True,
        "grading_authority": "receipt-gate-output; DSM must not recompute",
        "proof_card": proof,
        "gate_decision": decision,
        "integrity": {
            "proof_card_file_sha256": proof_file_hash,
            "decision_receipt_payload_hash": decision["payload_hash"],
        },
        "claim_boundary": (
            "This projection is a bounded display artifact. Verify the proof card, "
            "Half-Life evidence, receiver policy, and signed decision outside DSM."
        ),
    }
    projection_path = output / "verified_model_swap.latest.json"
    _write_json(projection_path, projection)
    verification = verify_model_swap_output(
        output,
        trusted_gate_keys=[public_key_hex(gate_signing_key)],
        half_life_output=half_life_output,
        succession_policy_public_key_path=succession_policy_public_key_path,
        compaction_policy_public_key_path=compaction_policy_public_key_path,
    )
    if not verification["valid"]:
        raise ModelSwapError(
            "new model-swap output failed verification: "
            + ",".join(verification["errors"])
        )
    return {
        "passed": decision["decision"] == "COMMIT" and verification["valid"],
        "decision": decision["decision"],
        "verdict": decision["verdict"],
        "gate_public_key": public_key_hex(gate_signing_key),
        "proof_hash": proof["proof_hash"],
        "proof_card_sha256": proof_file_hash,
        "summary_lost_count": len(proof["continuity"]["summary_lost"]),
        "capsule_matches_oracle": proof["independent_grade"][
            "capsule_matches_oracle"
        ],
        "archive_matches_oracle": proof["independent_grade"][
            "archive_matches_oracle"
        ],
        "output_dir": str(output),
        "verification": verification,
        "verified_commit": {
            "requested": commit_action is not None,
            "authorized": decision.get("commit_authorization") is not None,
            "authorization_hash": (
                decision.get("commit_authorization", {}).get("authorization_hash")
                if isinstance(decision.get("commit_authorization"), Mapping)
                else None
            ),
            "expires_at": (
                decision.get("commit_authorization", {}).get("expires_at")
                if isinstance(decision.get("commit_authorization"), Mapping)
                else None
            ),
        },
    }


def verify_model_swap_output(
    output_dir: str | Path,
    *,
    trusted_gate_keys: Sequence[str],
    half_life_output: str | Path,
    succession_policy_public_key_path: str | Path,
    compaction_policy_public_key_path: str | Path,
) -> dict[str, Any]:
    """Verify the proof, policy decision, bindings, and independent replay."""

    errors: list[str] = []
    output = Path(output_dir)
    try:
        proof = strict_json_load(output / "proof_card.json")
        request = strict_json_load(output / "gate_request.json")
        source_receipt = strict_json_load(output / "source_receipt.json")
        outcome_receipt = strict_json_load(output / "outcome_receipt.json")
        policy_value = strict_json_load(output / "gate_policy.json")
        trust_value = strict_json_load(output / "gate_trust.json")
        projection = strict_json_load(output / "verified_model_swap.latest.json")
    except (OSError, ValueError) as exc:
        return {"valid": False, "errors": [f"output_unreadable:{exc}"]}

    if proof.get("schema") != PROOF_CARD_SCHEMA:
        errors.append("proof_card_schema_invalid")
    proof_body = dict(proof)
    proof_hash = proof_body.pop("proof_hash", None)
    if proof_hash != _json_hash(proof_body):
        errors.append("proof_card_hash_mismatch")
    proof_file_hash = sha256_hex((output / "proof_card.json").read_bytes())

    try:
        recomputed = build_model_swap_proof(
            half_life_output,
            succession_policy_public_key_path=succession_policy_public_key_path,
            compaction_policy_public_key_path=compaction_policy_public_key_path,
            source_model=str(proof["models"]["source"]),
            target_model=str(proof["models"]["target"]),
            source_adapter=str(proof["models"]["source_adapter"]),
            target_adapter=str(proof["models"]["target_adapter"]),
            candidate_lane_projections={
                lane: proof["lanes"][lane]["projection"]
                for lane in (
                    "full_history",
                    "ordinary_summary",
                    "verified_capsule",
                )
            },
            trial_id=str(proof["trial_id"]),
            generated_at=str(proof["generated_at"]),
        )
        if recomputed != proof:
            errors.append("independent_regrade_mismatch")
    except (KeyError, TypeError, ModelSwapError) as exc:
        errors.append(f"independent_regrade_failed:{exc}")

    decision_result = verify_decision_log(
        output / "decision_receipts.jsonl", trusted_gate_keys
    )
    if not decision_result["valid"]:
        errors.extend(
            f"decision_log:{item}" for item in decision_result.get("errors", [])
        )
    try:
        line = (output / "decision_receipts.jsonl").read_text(encoding="utf-8").strip()
        decision = json.loads(line)
    except (OSError, json.JSONDecodeError):
        decision = {}
        errors.append("decision_receipt_unreadable")
    if decision.get("decision") != "COMMIT" or decision.get("verdict") != "VERIFIED":
        errors.append("receiver_gate_did_not_commit")
    try:
        trust = TrustStore.from_mapping(trust_value)
        source_assessment = assess_source_bundle([source_receipt], trust)
    except (TypeError, ValueError) as exc:
        source_assessment = None
        errors.append(f"saved_trust_invalid:{exc}")
    if source_assessment is not None:
        for name in ("integrity", "provenance", "coverage", "profile"):
            if getattr(source_assessment, name).status != PASS:
                errors.append(f"source_receipt_{name}_invalid")
        if source_assessment.primary_hash != decision.get("source", {}).get(
            "primary_hash"
        ):
            errors.append("source_receipt_decision_binding_mismatch")
        outcome_check = assess_outcome(
            outcome_receipt=outcome_receipt,
            source_hash=source_assessment.primary_hash,
            trust_store=trust,
        )
        if outcome_check.status != PASS:
            errors.append("outcome_receipt_invalid")
    request_binding = request.get("binding", {})
    decision_binding = decision.get("binding", {})
    if (
        not isinstance(request_binding, Mapping)
        or not isinstance(decision_binding, Mapping)
        or {
            key: request_binding.get(key)
            for key in decision_binding
        }
        != decision_binding
    ):
        errors.append("saved_request_binding_mismatch")
    if policy_value != decision.get("policy", {}).get("snapshot"):
        errors.append("saved_policy_decision_mismatch")
    artifact_hashes = (
        decision.get("assessments", {}).get("evidence", {}).get("details", {}).get(
            "artifact_hashes", {}
        )
    )
    if artifact_hashes.get(EVIDENCE_ID) != proof_file_hash:
        errors.append("decision_evidence_hash_binding_mismatch")
    if (
        source_receipt.get("credentialSubject", {})
        .get("outcome", {})
        .get("response_hash")
        != "sha256:" + proof_file_hash
    ):
        errors.append("source_proof_card_binding_mismatch")
    if outcome_receipt.get("evidence_hash") != proof_file_hash:
        errors.append("grader_proof_card_binding_mismatch")
    if request.get("source_receipts") != [source_receipt]:
        errors.append("saved_request_source_mismatch")
    if request.get("outcome_receipt") != outcome_receipt:
        errors.append("saved_request_outcome_mismatch")
    evidence_items = request.get("evidence", [])
    if (
        not isinstance(evidence_items, list)
        or len(evidence_items) != 1
        or not isinstance(evidence_items[0], Mapping)
        or evidence_items[0].get("content_hash") != proof_file_hash
    ):
        errors.append("saved_request_evidence_mismatch")
    authorization = decision.get("commit_authorization")
    saved_commit = request.get("commit_request")
    if authorization is None:
        if saved_commit is not None:
            errors.append("saved_commit_request_without_authorization")
    elif not isinstance(authorization, Mapping) or not isinstance(
        saved_commit, Mapping
    ):
        errors.append("saved_commit_request_missing")
    else:
        expected_saved_keys = {
            "tool",
            "target",
            "settings",
            "run_id",
            "capsule_hash",
            "evidence_hashes",
            "policy_hash",
            "expires_at",
            "one_use_code_hash",
            "one_use_code_redacted",
        }
        if set(saved_commit) != expected_saved_keys:
            errors.append("saved_commit_request_shape_invalid")
        if "one_use_code" in saved_commit:
            errors.append("saved_commit_request_leaks_code")
        if saved_commit.get("one_use_code_redacted") is not True:
            errors.append("saved_commit_request_not_redacted")
        for name in (
            "tool",
            "target",
            "run_id",
            "capsule_hash",
            "evidence_hashes",
            "policy_hash",
            "expires_at",
            "one_use_code_hash",
        ):
            if saved_commit.get(name) != authorization.get(name):
                errors.append(f"saved_commit_{name}_mismatch")
        try:
            if settings_hash(saved_commit.get("settings")) != authorization.get(
                "settings_hash"
            ):
                errors.append("saved_commit_settings_mismatch")
        except (TypeError, VerifiedCommitError):
            errors.append("saved_commit_settings_invalid")
    if projection.get("schema") != DSM_PROJECTION_SCHEMA:
        errors.append("dsm_projection_schema_invalid")
    if projection.get("display_only") is not True:
        errors.append("dsm_projection_not_display_only")
    if projection.get("grading_authority") != "receipt-gate-output; DSM must not recompute":
        errors.append("dsm_projection_authority_invalid")
    if projection.get("proof_card") != proof:
        errors.append("dsm_projection_proof_mismatch")
    if projection.get("gate_decision") != decision:
        errors.append("dsm_projection_decision_mismatch")
    if (
        projection.get("integrity", {}).get("proof_card_file_sha256")
        != proof_file_hash
    ):
        errors.append("dsm_projection_proof_hash_mismatch")
    if (
        projection.get("integrity", {}).get("decision_receipt_payload_hash")
        != decision.get("payload_hash")
    ):
        errors.append("dsm_projection_decision_hash_mismatch")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "decision_log": decision_result,
        "proof_card_sha256": proof_file_hash,
        "decision": decision.get("decision"),
        "verdict": decision.get("verdict"),
        "independent_grade_passed": proof.get("independent_grade", {}).get(
            "passed"
        ),
    }
