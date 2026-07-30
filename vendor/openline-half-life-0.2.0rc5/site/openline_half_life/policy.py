from __future__ import annotations

import copy
import json
import re
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from .util import load_json, sha256_file, write_json
from .vendor.openline_endurance_gate import succession as canonical

CANONICAL_REPOSITORY = "https://github.com/terryncew/openline-endurance-gate"
CANONICAL_VERSION = "0.10.0"
CANONICAL_COMMIT = "6c6f740"
CANONICAL_SOURCE_SHA256 = "0fd92bdfed08107a6826f03131fe6f076744deaad2785b4177c56f484cb35d12"
POLICY_SCHEMA = "openline.half-life.calibrator-policy.v1"
# Release public key only. The corresponding private key is not distributed.
DEMO_POLICY_PUBLIC_KEY_HEX = "d810f13ea0d000c1c3a201cc568c1774b60f240a709f2f5220fec474254015af"
PUBLIC_KEY_HEX = re.compile(r"^[0-9a-f]{64}$")

LOW_VALUES = {
    "kappa_micros": 0,
    "epsilon_micros": 0,
    "delta_hol_micros": 0,
    "phi_star_micros": 990_099,
}
HIGH_VALUES = {
    "kappa_micros": 707_107,
    "epsilon_micros": 500_000,
    "delta_hol_micros": 577_350,
    "phi_star_micros": 660_697,
}


def _calibration_rows() -> list[dict[str, Any]]:
    pattern = [
        (False, False),
        (True, False),
        (False, False),
        (True, False),
        (True, True),
    ]
    rows: list[dict[str, Any]] = []
    for run in range(100):
        for sequence, (high, beneficial) in enumerate(pattern):
            rows.append(
                {
                    "sample_id": f"sample-{run:03d}-{sequence}",
                    "run_id": f"run-{run:03d}",
                    "sequence": sequence,
                    "label": "succession_beneficial" if beneficial else "continue",
                    "values": dict(HIGH_VALUES if high else LOW_VALUES),
                }
            )
    return rows


def _build_demo_policy_body() -> dict[str, Any]:
    """Recompute the exact unsigned policy body with the v0.10.0 fitter."""

    rows = _calibration_rows()
    train, holdout = canonical._split(rows)
    thresholds = {
        metric: canonical._fit_threshold(train, metric, direction)
        for metric, direction in canonical.METRICS.items()
    }
    critical = {
        "kappa_micros": canonical._fit_critical_threshold(
            train,
            "kappa_micros",
            "high",
            canonical.DEFAULT_CRITICAL_SPECIFICITY_MICROS,
        ),
        "phi_star_micros": canonical._fit_critical_threshold(
            train,
            "phi_star_micros",
            "low",
            canonical.DEFAULT_CRITICAL_SPECIFICITY_MICROS,
        ),
    }
    persistence = canonical._fit_persistence_rule(
        train,
        thresholds,
        max_window=canonical.DEFAULT_MAX_PERSISTENCE_WINDOW,
    )
    holdout_validation = canonical._evaluate_rule(holdout, thresholds, persistence)
    return {
        "schema": POLICY_SCHEMA,
        "policy_version": "0.1",
        "canonical_source": {
            "repository": CANONICAL_REPOSITORY,
            "version": CANONICAL_VERSION,
            "commit": CANONICAL_COMMIT,
            "vendored_source_sha256": CANONICAL_SOURCE_SHA256,
            "fitter_functions": [
                "_fit_threshold",
                "_fit_critical_threshold",
                "_fit_persistence_rule",
                "_evaluate_rule",
            ],
        },
        "cole_algorithm_id": canonical.COLE_ALGORITHM_ID,
        "mode": "calibrated_advisory",
        "automatic_retirement_authorized": False,
        "receiver_approval_required": True,
        "metric_directions": copy.deepcopy(canonical.METRICS),
        "thresholds": thresholds,
        "critical_thresholds": critical,
        "persistence": persistence,
        "evidence_sufficiency": {
            "metric": "ucr_micros",
            "required_value_micros": 0,
            "role": "separate_evidence_gate_not_health_score",
        },
        "calibration": {
            "type": "synthetic_mechanism_fixture",
            "submitted_sample_count": len(rows),
            "train_sample_count": len(train),
            "holdout_sample_count": len(holdout),
            "low_values": LOW_VALUES,
            "high_values": HIGH_VALUES,
        },
        "holdout_validation": holdout_validation,
        "claim_boundary": (
            "Synthetic mechanism policy only. It preserves separate COLE metrics, "
            "does not establish universal model support, and never authorizes automatic retirement."
        ),
    }


def _unsigned_body(policy: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(policy)
    body.pop("payload_hash", None)
    body.pop("signature", None)
    return body


def build_demo_policy() -> dict[str, Any]:
    """Load the release-signed policy and verify its body is reproducible.

    The release private key is deliberately absent. Reproducibility comes from
    recomputing the unsigned fitter output, not from distributing signing power.
    """

    text = resources.files("openline_half_life").joinpath(
        "data", "policy", "succession_policy.json"
    ).read_text(encoding="utf-8")
    policy = json.loads(text)
    if _unsigned_body(policy) != _build_demo_policy_body():
        raise ValueError("packaged demo policy body does not match canonical fitter output")
    return policy


def load_trusted_policy_keys(path: Path) -> set[str]:
    """Load receiver-owned policy signer pins from an external trust file."""

    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except UnicodeError as exc:
        raise ValueError("trusted policy key file must be lowercase ASCII hex") from exc
    keys = {line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")}
    if not keys:
        raise ValueError("trusted policy key file contains no keys")
    if any(PUBLIC_KEY_HEX.fullmatch(key) is None for key in keys):
        raise ValueError("trusted policy keys must be 32-byte lowercase hex")
    return keys


def verify_policy(
    policy: Mapping[str, Any],
    expected_public_keys: set[str] | None = None,
) -> dict[str, Any]:
    """Verify fitter provenance, signature, and receiver-owned signer pin."""

    reasons: list[str] = []
    if not expected_public_keys:
        reasons.append("trusted_policy_key_required")
    elif any(PUBLIC_KEY_HEX.fullmatch(key) is None for key in expected_public_keys):
        reasons.append("trusted_policy_key_invalid")

    if policy.get("schema") != POLICY_SCHEMA:
        reasons.append("unsupported_policy_schema")
    if _unsigned_body(policy) != _build_demo_policy_body():
        reasons.append("canonical_fitter_output_mismatch")
    if not canonical._verify_envelope(policy):
        reasons.append("policy_signature_or_payload_hash_invalid")
    elif expected_public_keys and not canonical._verify_envelope(policy, expected_public_keys):
        reasons.append("policy_signer_not_trusted")

    source = policy.get("canonical_source", {})
    if source.get("vendored_source_sha256") != CANONICAL_SOURCE_SHA256:
        reasons.append("canonical_source_hash_mismatch")
    if policy.get("automatic_retirement_authorized") is not False:
        reasons.append("automatic_retirement_must_remain_forbidden")
    if policy.get("evidence_sufficiency", {}).get("role") != "separate_evidence_gate_not_health_score":
        reasons.append("ucr_role_changed")
    expected_metrics = set(canonical.METRICS)
    if set(policy.get("thresholds", {})) != expected_metrics:
        reasons.append("metric_threshold_set_mismatch")
    return {
        "valid": not reasons,
        "reason_codes": reasons,
        "policy_hash": policy.get("payload_hash"),
        "public_key": policy.get("signature", {}).get("public_key"),
    }


def write_demo_policy(path: Path) -> dict[str, Any]:
    policy = build_demo_policy()
    write_json(path, policy)
    return policy


def load_policy(path: Path, expected_public_keys: set[str] | None = None) -> dict[str, Any]:
    policy = load_json(path)
    result = verify_policy(policy, expected_public_keys)
    if not result["valid"]:
        raise ValueError("policy verification failed: " + ",".join(result["reason_codes"]))
    return policy


def verify_vendored_source(path: Path) -> bool:
    return sha256_file(path) == CANONICAL_SOURCE_SHA256
