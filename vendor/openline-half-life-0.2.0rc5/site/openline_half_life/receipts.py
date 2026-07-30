from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .comparison import compare_results
from .policy import verify_policy
from .share_card import describe_share_card
from .util import canonical_json, load_json, resolve_safe_relative_path, sha256_bytes, sha256_file

RECEIPT_SCHEMA = "openline.endurance.receipt.v1"
ANCHOR_SCHEMA = "openline.endurance.anchor.v1"
BUNDLE_SCHEMA = "openline.half-life.receipt-bundle.v3"

# These files exist before the terminal compaction receipt is created, so their
# hashes can be bound inside that signed receipt without creating a self-hash.
SIGNED_OUTPUT_ARTIFACTS = frozenset({
    "calibrator_policy.json",
    "compaction_policy.json",
    "receiver_approval.json",
    "turn_assessments.json",
    "full_history_handoff.json",
    "verified_residue_handoff.json",
    "comparison.json",
    "causal_capsule.json",
    "archive_manifest.json",
    "decision_equivalence_report.json",
    "share_card.html",
})
EXPECTED_BUNDLE_ARTIFACTS = SIGNED_OUTPUT_ARTIFACTS | {"compaction_receipt.json"}
BUNDLE_CLAIM_BOUNDARY = (
    "The receipt bundle proves local artifact integrity, receiver-pinned succession and compaction "
    "policies, same-exam execution, exact decision-equivalence checks, and hash-addressed archive "
    "custody under the disclosed harness. It does not prove universal successor benefit, infer "
    "causation, authorize automatic compaction, or authorize automatic retirement."
)


@dataclass(frozen=True)
class ReceiptSigner:
    private_key: Ed25519PrivateKey

    @classmethod
    def from_hex_file(cls, path: Path) -> "ReceiptSigner":
        value = path.read_text(encoding="ascii").strip()
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("signing key must contain exactly 32 lowercase-hex bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value)))

    @property
    def public_b64(self) -> str:
        raw = self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def sign_hash(self, digest_hex: str) -> str:
        return base64.b64encode(self.private_key.sign(bytes.fromhex(digest_hex))).decode("ascii")


def _receipt_body(kind: str, index: int, parent_hash: str | None, payload: dict[str, Any], public_key: str) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "index": index,
        "kind": kind,
        "parent_hash": parent_hash,
        "signer_public_key": public_key,
        "payload": payload,
    }


def create_chain(items: list[tuple[str, dict[str, Any]]], signer: ReceiptSigner) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    parent: str | None = None
    for index, (kind, payload) in enumerate(items):
        body = _receipt_body(kind, index, parent, payload, signer.public_b64)
        receipt_hash = sha256_bytes(canonical_json(body))
        receipt = {**body, "receipt_hash": receipt_hash, "signature": signer.sign_hash(receipt_hash)}
        chain.append(receipt)
        parent = receipt_hash
    return chain


def create_extension_receipt(
    kind: str,
    payload: dict[str, Any],
    signer: ReceiptSigner,
    *,
    index: int,
    parent_hash: str,
) -> dict[str, Any]:
    """Create one receipt that extends an already verified chain."""

    body = _receipt_body(kind, index, parent_hash, payload, signer.public_b64)
    receipt_hash = sha256_bytes(canonical_json(body))
    return {**body, "receipt_hash": receipt_hash, "signature": signer.sign_hash(receipt_hash)}


def verify_extension_chain(
    receipts: list[Mapping[str, Any]],
    *,
    expected_parent_hash: str,
    expected_start_index: int,
    expected_signer_public_key: str,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(expected_signer_public_key))
    except Exception as exc:
        return {"valid": False, "errors": [f"invalid_extension_public_key:{exc}"]}
    parent = expected_parent_hash
    for offset, receipt in enumerate(receipts):
        expected_index = expected_start_index + offset
        try:
            body = {
                key: receipt[key]
                for key in ("schema", "index", "kind", "parent_hash", "signer_public_key", "payload")
            }
            computed_hash = sha256_bytes(canonical_json(body))
            if receipt["schema"] != RECEIPT_SCHEMA:
                errors.append(f"schema_mismatch:{expected_index}")
            if receipt["index"] != expected_index:
                errors.append(f"index_mismatch:{expected_index}")
            if receipt["parent_hash"] != parent:
                errors.append(f"parent_mismatch:{expected_index}")
            if receipt["signer_public_key"] != expected_signer_public_key:
                errors.append(f"signer_mismatch:{expected_index}")
            if receipt["receipt_hash"] != computed_hash:
                errors.append(f"hash_mismatch:{expected_index}")
            public.verify(base64.b64decode(receipt["signature"]), bytes.fromhex(computed_hash))
            parent = computed_hash
        except Exception:
            errors.append(f"signature_or_shape_invalid:{expected_index}")
    return {
        "valid": not errors,
        "errors": errors,
        "count": len(receipts),
        "tail_hash": parent if receipts else expected_parent_hash,
    }


def chain_digest(chain: list[Mapping[str, Any]]) -> str:
    return sha256_bytes("".join(str(item["receipt_hash"]) for item in chain).encode("ascii"))


def create_anchor(chain: list[dict[str, Any]], signer: ReceiptSigner) -> dict[str, Any]:
    body = {
        "schema": ANCHOR_SCHEMA,
        "expected_count": len(chain),
        "expected_tail_hash": chain[-1]["receipt_hash"] if chain else None,
        "chain_digest": chain_digest(chain),
        "signer_public_key": signer.public_b64,
    }
    anchor_hash = sha256_bytes(canonical_json(body))
    return {**body, "anchor_hash": anchor_hash, "signature": signer.sign_hash(anchor_hash)}


def verify_chain(chain: list[Mapping[str, Any]], anchor: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(anchor["signer_public_key"]))
    except Exception as exc:
        return {"valid": False, "errors": [f"invalid_anchor_public_key:{exc}"]}
    expected_parent = None
    for expected_index, receipt in enumerate(chain):
        try:
            body = {key: receipt[key] for key in ("schema", "index", "kind", "parent_hash", "signer_public_key", "payload")}
            computed_hash = sha256_bytes(canonical_json(body))
            if receipt["schema"] != RECEIPT_SCHEMA:
                errors.append(f"schema_mismatch:{expected_index}")
            if receipt["index"] != expected_index:
                errors.append(f"index_mismatch:{expected_index}")
            if receipt["parent_hash"] != expected_parent:
                errors.append(f"parent_mismatch:{expected_index}")
            if receipt["receipt_hash"] != computed_hash:
                errors.append(f"hash_mismatch:{expected_index}")
            if receipt["signer_public_key"] != anchor["signer_public_key"]:
                errors.append(f"signer_mismatch:{expected_index}")
            public.verify(base64.b64decode(receipt["signature"]), bytes.fromhex(computed_hash))
            expected_parent = computed_hash
        except Exception:
            errors.append(f"signature_or_shape_invalid:{expected_index}")
    try:
        anchor_body = {
            key: anchor[key]
            for key in ("schema", "expected_count", "expected_tail_hash", "chain_digest", "signer_public_key")
        }
        computed_anchor_hash = sha256_bytes(canonical_json(anchor_body))
        if anchor.get("schema") != ANCHOR_SCHEMA:
            errors.append("anchor_schema_mismatch")
        if anchor.get("anchor_hash") != computed_anchor_hash:
            errors.append("anchor_hash_mismatch")
        public.verify(base64.b64decode(anchor["signature"]), bytes.fromhex(computed_anchor_hash))
    except Exception:
        errors.append("anchor_signature_or_shape_invalid")
    tail = chain[-1]["receipt_hash"] if chain else None
    if anchor.get("expected_count") != len(chain):
        errors.append("completeness_count_mismatch")
    if anchor.get("expected_tail_hash") != tail:
        errors.append("completeness_tail_mismatch")
    if anchor.get("chain_digest") != chain_digest(chain):
        errors.append("completeness_digest_mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "count": len(chain),
        "tail_hash": tail,
        "chain_digest": chain_digest(chain),
    }


def build_receipt_bundle(
    *,
    chain: list[dict[str, Any]],
    anchor: dict[str, Any],
    artifact_hashes: dict[str, str],
    policy_hash: str,
    policy_public_key: str,
    retirement_turn: int,
) -> dict[str, Any]:
    return {
        "schema": BUNDLE_SCHEMA,
        "policy_hash": policy_hash,
        "policy_public_key": policy_public_key,
        "retirement_turn": retirement_turn,
        "artifact_hashes": dict(sorted(artifact_hashes.items())),
        "receipts": chain,
        "anchor": anchor,
        "claim_boundary": BUNDLE_CLAIM_BOUNDARY,
    }


def _verify_bound_policy(
    output_dir: Path,
    bundle: Mapping[str, Any],
    expected_policy_public_keys: set[str] | None,
) -> list[str]:
    errors: list[str] = []
    if not expected_policy_public_keys:
        return ["trusted_policy_key_required"]
    try:
        policy_path = resolve_safe_relative_path(output_dir, "calibrator_policy.json")
    except ValueError:
        return ["calibrator_policy_path_invalid"]
    if not policy_path.exists():
        return ["calibrator_policy_missing"]
    try:
        policy = load_json(policy_path)
        result = verify_policy(policy, expected_policy_public_keys)
    except Exception as exc:
        return [f"calibrator_policy_invalid:{exc}"]
    if not result["valid"]:
        errors.extend(f"calibrator_policy:{reason}" for reason in result["reason_codes"])
    if policy.get("payload_hash") != bundle.get("policy_hash"):
        errors.append("policy_hash_binding_mismatch")
    if policy.get("signature", {}).get("public_key") != bundle.get("policy_public_key"):
        errors.append("policy_public_key_binding_mismatch")
    return errors



def _verify_comparison_semantics(output_dir: Path) -> list[str]:
    try:
        comparison_path = resolve_safe_relative_path(output_dir, "comparison.json")
        full_path = resolve_safe_relative_path(output_dir, "full_history_handoff.json")
        residue_path = resolve_safe_relative_path(output_dir, "verified_residue_handoff.json")
    except ValueError:
        return ["comparison_artifact_path_invalid"]
    if not comparison_path.exists():
        return []
    try:
        comparison = load_json(comparison_path)
        recomputed = compare_results(comparison["full_history"], comparison["verified_residue"])
        full_packet = load_json(full_path)
        residue_packet = load_json(residue_path)
    except Exception as exc:
        return [f"comparison_semantic_check_failed:{exc}"]
    errors: list[str] = []
    if recomputed != comparison:
        errors.append("comparison_semantic_mismatch")
    if comparison["full_history"].get("packet_hash") != full_packet.get("packet_hash"):
        errors.append("comparison_full_history_packet_binding_mismatch")
    if comparison["verified_residue"].get("packet_hash") != residue_packet.get("packet_hash"):
        errors.append("comparison_verified_residue_packet_binding_mismatch")
    return errors

def _verify_share_card_semantics(output_dir: Path, bundle: Mapping[str, Any]) -> list[str]:
    try:
        comparison_path = resolve_safe_relative_path(output_dir, "comparison.json")
        card_path = resolve_safe_relative_path(output_dir, "share_card.html")
        equivalence_path = resolve_safe_relative_path(output_dir, "decision_equivalence_report.json")
    except ValueError:
        return ["share_card_artifact_path_invalid"]
    if not comparison_path.exists() or not card_path.exists():
        return []  # Missing artifacts are reported by artifact verification.
    try:
        comparison = load_json(comparison_path)
        description = describe_share_card(int(bundle["retirement_turn"]), comparison)
        card = card_path.read_text(encoding="utf-8")
    except Exception as exc:
        return [f"share_card_semantic_check_failed:{exc}"]
    errors: list[str] = []
    for field in ("status", "headline", "subhead"):
        if description[field] not in card:
            errors.append(f"share_card_{field}_mismatch")
    if equivalence_path.exists():
        try:
            equivalence = load_json(equivalence_path)
            ratio = (abs(int(equivalence["active_size_ratio_micros"])) + 5_000) // 10_000
            expected = (
                f"Causal capsule preserved exact receiver decisions at {ratio}% of active receipt size."
                if equivalence.get("passed") is True
                else "Causal compaction not admitted: decision equivalence failed."
            )
            if expected not in card:
                errors.append("share_card_compaction_statement_mismatch")
        except Exception as exc:
            errors.append(f"share_card_compaction_semantic_check_failed:{exc}")
    return errors


def verify_output_directory(
    output_dir: Path,
    *,
    expected_policy_public_keys: set[str] | None = None,
    expected_compaction_policy_public_keys: set[str] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        receipt_path = resolve_safe_relative_path(output_dir, "half_life_receipt.json")
    except ValueError:
        return {"valid": False, "errors": ["half_life_receipt_path_invalid"]}
    if not receipt_path.exists():
        return {"valid": False, "errors": ["half_life_receipt_missing"]}
    try:
        bundle = load_json(receipt_path)
    except Exception as exc:
        return {"valid": False, "errors": [f"half_life_receipt_invalid:{exc}"]}
    if not isinstance(bundle, Mapping):
        return {"valid": False, "errors": ["half_life_receipt_must_be_an_object"]}
    expected_bundle_fields = {
        "schema",
        "policy_hash",
        "policy_public_key",
        "retirement_turn",
        "artifact_hashes",
        "receipts",
        "anchor",
        "claim_boundary",
        "compaction",
        "input_hashes",
    }
    if set(bundle) != expected_bundle_fields:
        errors.append("receipt_bundle_field_mismatch")
    if bundle.get("schema") != BUNDLE_SCHEMA:
        errors.append("receipt_bundle_schema_mismatch")
    if bundle.get("claim_boundary") != BUNDLE_CLAIM_BOUNDARY:
        errors.append("receipt_bundle_claim_boundary_mismatch")
    chain_result = verify_chain(bundle.get("receipts", []), bundle.get("anchor", {}))
    errors.extend(chain_result["errors"])
    artifact_hashes = bundle.get("artifact_hashes")
    if not isinstance(artifact_hashes, Mapping):
        errors.append("artifact_manifest_invalid")
        artifact_hashes = {}
    artifact_names = set(artifact_hashes)
    if artifact_names != EXPECTED_BUNDLE_ARTIFACTS:
        errors.append("artifact_manifest_coverage_mismatch")
        errors.extend(
            f"artifact_manifest_missing:{name}"
            for name in sorted(EXPECTED_BUNDLE_ARTIFACTS - artifact_names)
        )
        errors.extend(
            f"artifact_manifest_unexpected:{name}"
            for name in sorted(artifact_names - EXPECTED_BUNDLE_ARTIFACTS)
        )
    for relative in sorted(EXPECTED_BUNDLE_ARTIFACTS):
        expected_hash = artifact_hashes.get(relative)
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            errors.append(f"artifact_hash_invalid:{relative}")
            continue
        try:
            path = resolve_safe_relative_path(output_dir, relative)
        except ValueError:
            errors.append(f"artifact_path_invalid:{relative}")
            continue
        if not path.exists():
            errors.append(f"artifact_missing:{relative}")
        elif sha256_file(path) != expected_hash:
            errors.append(f"artifact_hash_mismatch:{relative}")
    errors.extend(_verify_bound_policy(output_dir, bundle, expected_policy_public_keys))
    errors.extend(_verify_comparison_semantics(output_dir))
    errors.extend(_verify_share_card_semantics(output_dir, bundle))
    if (output_dir / "compaction_receipt.json").exists() or bundle.get("compaction") is not None:
        from .causal_compactor import verify_compaction_outputs

        compaction_result = verify_compaction_outputs(
            output_dir,
            bundle,
            expected_compaction_policy_public_keys=expected_compaction_policy_public_keys,
        )
        errors.extend(f"compaction:{error}" for error in compaction_result["errors"])
    else:
        compaction_result = None
    return {
        "valid": not errors,
        "errors": errors,
        "chain": chain_result,
        "retirement_turn": bundle.get("retirement_turn"),
        "policy_hash": bundle.get("policy_hash"),
        "policy_public_key": bundle.get("policy_public_key"),
        "compaction": compaction_result,
    }
