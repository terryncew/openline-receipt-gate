from __future__ import annotations

from pathlib import Path
from typing import Any

from .assessment import assess_trajectory, first_retirement_turn
from .causal_compactor import (
    CompactionInputs,
    build_compaction_receipt,
    build_receiver_approval_body,
    compact_verified_chain,
    load_trusted_compaction_policy_keys,
    sign_receiver_approval,
)
from .comparison import compare_results
from .exam import load_exam, run_same_exam
from .handoff import build_full_history_handoff, build_verified_residue_handoff
from .policy import load_policy, load_trusted_policy_keys
from .receipts import (
    EXPECTED_BUNDLE_ARTIFACTS,
    SIGNED_OUTPUT_ARTIFACTS,
    ReceiptSigner,
    build_receipt_bundle,
    create_anchor,
    create_chain,
    verify_output_directory,
)
from .schema import load_trajectory
from .share_card import describe_share_card, render_share_card
from .util import canonical_json, load_json, sha256_bytes, sha256_file, write_json

REQUIRED_ARTIFACTS = sorted(EXPECTED_BUNDLE_ARTIFACTS)


def _trajectory_receipt_items(turns: list[dict[str, Any]], retirement_turn: int) -> list[tuple[str, dict[str, Any]]]:
    items: list[tuple[str, dict[str, Any]]] = []
    for turn in turns:
        if int(turn["turn"]) > retirement_turn:
            break
        items.append(
            (
                "trajectory_turn",
                {
                    "run_id": turn["run_id"],
                    "turn_number": turn["turn"],
                    "turn_hash": sha256_bytes(canonical_json(turn)),
                    "turn_record": turn,
                },
            )
        )
    return items


def run_pipeline(
    trajectory_path: Path,
    exam_path: Path,
    policy_path: Path,
    policy_public_key_path: Path,
    signing_key_path: Path,
    output_dir: Path,
    *,
    compaction_policy_path: Path,
    compaction_policy_public_key_path: Path,
    replay_latency_micros: int,
    receiver_approval_signing_key_path: Path,
    receiver_disposition: str = "APPROVE",
) -> dict[str, Any]:
    trusted_policy_keys = load_trusted_policy_keys(policy_public_key_path)
    trusted_compaction_policy_keys = load_trusted_compaction_policy_keys(
        compaction_policy_public_key_path
    )
    turns = load_trajectory(trajectory_path)
    policy = load_policy(policy_path, trusted_policy_keys)
    compaction_policy = load_json(compaction_policy_path)
    exam = load_exam(exam_path)
    assessments = assess_trajectory(
        turns,
        policy,
        expected_policy_public_keys=trusted_policy_keys,
    )
    retirement_turn = first_retirement_turn(assessments)
    if retirement_turn is None:
        raise ValueError("trajectory has no defensible retirement point under the pinned policy")

    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "calibrator_policy.json", policy)
    write_json(output_dir / "compaction_policy.json", compaction_policy)
    write_json(
        output_dir / "turn_assessments.json",
        {
            "schema": "openline.half-life.turn-assessments.v1",
            "policy_hash": policy["payload_hash"],
            "policy_public_key": policy["signature"]["public_key"],
            "assessments": assessments,
        },
    )

    full = build_full_history_handoff(turns, retirement_turn, policy["payload_hash"])
    checkpoint = build_verified_residue_handoff(turns, retirement_turn, policy["payload_hash"])
    write_json(output_dir / "full_history_handoff.json", full)

    signer = ReceiptSigner.from_hex_file(signing_key_path)
    retirement_assessment = assessments[retirement_turn - 1]
    source_items = _trajectory_receipt_items(turns, retirement_turn)
    source_items.extend(
        [
            (
                "calibrator_policy",
                {
                    "run_id": turns[0]["run_id"],
                    "policy_hash": policy["payload_hash"],
                    "policy_public_key": policy["signature"]["public_key"],
                    "receiver_pin_verified": True,
                },
            ),
            (
                "retirement_assessment",
                {
                    "run_id": turns[0]["run_id"],
                    "retirement_turn": retirement_turn,
                    "assessment_hash": retirement_assessment["assessment_hash"],
                    "mark": retirement_assessment["mark"],
                    "automatic_retirement_authorized": False,
                    "receiver_approval_required": True,
                },
            ),
            (
                "full_history_handoff",
                {
                    "run_id": turns[0]["run_id"],
                    "packet_hash": full["packet_hash"],
                    "artifact_sha256": sha256_file(output_dir / "full_history_handoff.json"),
                },
            ),
            (
                "verified_residue_checkpoint",
                {
                    "run_id": turns[0]["run_id"],
                    "retirement_turn": retirement_turn,
                    "packet_hash": checkpoint["packet_hash"],
                    "policy_hash": policy["payload_hash"],
                    "automatic_retirement_authorized": False,
                },
            ),
        ]
    )
    source_chain = create_chain(source_items, signer)
    source_anchor = create_anchor(source_chain, signer)
    receiver_approval_key = ReceiptSigner.from_hex_file(
        receiver_approval_signing_key_path
    ).private_key
    receiver_approval = sign_receiver_approval(
        build_receiver_approval_body(
            run_id=str(checkpoint["run_id"]),
            checkpoint_hash=str(checkpoint["packet_hash"]),
            source_chain=source_chain,
            compaction_policy=compaction_policy,
            disposition=receiver_disposition,
        ),
        receiver_approval_key,
    )
    write_json(output_dir / "receiver_approval.json", receiver_approval)
    provisional_bundle = build_receipt_bundle(
        chain=source_chain,
        anchor=source_anchor,
        artifact_hashes={},
        policy_hash=policy["payload_hash"],
        policy_public_key=policy["signature"]["public_key"],
        retirement_turn=retirement_turn,
    )

    compaction = compact_verified_chain(
        CompactionInputs(
            source_bundle=provisional_bundle,
            compaction_policy=compaction_policy,
            trusted_policy_keys=trusted_compaction_policy_keys,
            checkpoint=checkpoint,
            replay_latency_micros=replay_latency_micros,
            receiver_approval=receiver_approval,
            output_dir=output_dir,
        ),
        signer,
    )
    capsule = compaction["capsule"]
    equivalence = compaction["equivalence_report"]
    archive_receipt = compaction["archive_manifest_receipt"]
    updated_residue = compaction["updated_verified_residue"]

    write_json(output_dir / "causal_capsule.json", capsule)
    write_json(output_dir / "decision_equivalence_report.json", equivalence)
    write_json(output_dir / "archive_manifest.json", archive_receipt)
    write_json(output_dir / "verified_residue_handoff.json", updated_residue)

    full_result, residue_result = run_same_exam(full, updated_residue, exam)
    comparison = compare_results(full_result, residue_result)
    write_json(output_dir / "comparison.json", comparison)
    card_description = describe_share_card(retirement_turn, comparison)
    render_share_card(
        output_dir / "share_card.html",
        retirement_turn,
        comparison,
        equivalence,
    )
    signed_artifact_hashes = {
        name: sha256_file(output_dir / name)
        for name in sorted(SIGNED_OUTPUT_ARTIFACTS)
    }
    input_hashes = {
        "trajectory_sha256": sha256_file(trajectory_path),
        "exam_hash": sha256_bytes(canonical_json(exam)),
    }

    compaction_receipt = build_compaction_receipt(
        source_chain=source_chain,
        archive_receipt=archive_receipt,
        capsule=capsule,
        equivalence_report=equivalence,
        updated_residue=updated_residue,
        comparison=comparison,
        share_card_sha256=sha256_file(output_dir / "share_card.html"),
        artifact_hashes=signed_artifact_hashes,
        input_hashes=input_hashes,
        compaction_policy=compaction_policy,
        receiver_approval=receiver_approval,
        pressure=compaction["verification"]["pressure"],
        receiver_disposition=receiver_disposition,
        signer=signer,
    )
    write_json(output_dir / "compaction_receipt.json", compaction_receipt)

    full_chain = [*source_chain, archive_receipt, compaction_receipt]
    final_anchor = create_anchor(full_chain, signer)
    artifact_hashes = {name: sha256_file(output_dir / name) for name in REQUIRED_ARTIFACTS}
    bundle = build_receipt_bundle(
        chain=full_chain,
        anchor=final_anchor,
        artifact_hashes=artifact_hashes,
        policy_hash=policy["payload_hash"],
        policy_public_key=policy["signature"]["public_key"],
        retirement_turn=retirement_turn,
    )
    bundle["compaction"] = {
        "policy_hash": compaction_policy["payload_hash"],
        "policy_public_key": compaction_policy["signature"]["public_key"],
        "policy_version": compaction_policy["policy_version"],
        "trusted_key_version": compaction_policy["trusted_key_version"],
        "source_chain_count": len(source_chain),
        "archive_manifest_receipt_hash": archive_receipt["receipt_hash"],
        "compaction_receipt_hash": compaction_receipt["receipt_hash"],
        "causal_capsule_hash": capsule["capsule_hash"],
        "decision_equivalence_report_hash": equivalence["report_hash"],
        "decision_equivalence_passed": equivalence["passed"],
        "active_size_ratio_micros": equivalence["active_size_ratio_micros"],
        "receiver_disposition": receiver_disposition,
        "receiver_approval_hash": receiver_approval["payload_hash"],
        "receiver_approval_public_key": receiver_approval["signature"]["public_key"],
        "automatic_retirement_authorized": False,
    }
    bundle["input_hashes"] = input_hashes
    write_json(output_dir / "half_life_receipt.json", bundle)

    verification = verify_output_directory(
        output_dir,
        expected_policy_public_keys=trusted_policy_keys,
        expected_compaction_policy_public_keys=trusted_compaction_policy_keys,
    )
    if not verification["valid"]:
        raise AssertionError(
            "newly written output failed verification: " + ",".join(verification["errors"])
        )
    return {
        "passed": bool(
            comparison["passed"]
            and equivalence["passed"]
            and verification["valid"]
        ),
        "retirement_turn": retirement_turn,
        "comparison": comparison,
        "compaction": {
            "decision_equivalence_passed": equivalence["passed"],
            "active_size_ratio_micros": equivalence["active_size_ratio_micros"],
            "archived_receipt_count": archive_receipt["payload"]["source_chain_count"],
            "trigger_reason_codes": compaction["verification"]["pressure"]["reason_codes"],
        },
        "verification": verification,
        "output_dir": str(output_dir),
        "share_card": card_description,
    }
