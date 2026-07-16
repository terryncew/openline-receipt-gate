#!/usr/bin/env python3
"""Prepare the frozen fixture metadata without scoring either system.

The five source receipts are copied byte-for-byte from agent-egress-bench.
This script only creates the receiver-side evidence artifact, AARP companion
assertions, and a hash manifest.  It deliberately does not call a verifier.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
UPSTREAM = FIXTURES / "upstream"
AARP = FIXTURES / "aarp"
EVIDENCE = FIXTURES / "evidence"
REQUESTS = FIXTURES / "requests"
REQUEST_EVIDENCE = REQUESTS / "evidence"

PIPELOCK_COMMIT = "371893f0084ed693c1f69adf6da81c269e84aeff"
PIPELOCK_VERIFY_COMMIT = "329f1c76fdfa5fc5b165a3794f7c62906a076c03"
AGENT_EGRESS_BENCH_COMMIT = "1a0d386f3d3d9370dbb6f9c86c92c403fb529cb4"
OLP_BASE_COMMIT = "2d8474f821df1ea4ffdd300f78f039b686811912"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Any, *, compact: bool = False) -> None:
    if compact:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    else:
        payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(payload, encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def make_aarp_companion(
    receipt: dict[str, Any],
    *,
    claims: list[str],
    evidence_refs: list[str],
    test_keys: dict[str, Any],
    canonicalize_action_record: Any,
    canonicalize_receipt: Any,
    unmarshal: Any,
    protected_header_type: Any,
    signing_input: Any,
) -> dict[str, Any]:
    action_hash = sha256_bytes(canonicalize_action_record(receipt["action_record"]))
    receipt_hash = sha256_bytes(canonicalize_receipt(receipt))
    body: dict[str, Any] = {
        "profile": "aarp/v0.1",
        "subject": {
            "action_record_sha256": action_hash,
            "receipt_envelope_sha256": receipt_hash,
            "receipt_signer_key": receipt["signer_key"],
            "receipt_type": "action_receipt_v1",
        },
        "assertion": {
            "claimed": claims,
            "mediator_id": "mediator.example",
            "complete_mediation": False,
            "issued_at": "2026-07-15T20:00:00Z",
        },
        "signatures": [],
        "crit_ext": [],
        "ext": {
            "benchmark_origin": "OLP-authored AARP companion; public conformance test key only"
        },
    }
    if evidence_refs:
        body["assertion"]["evidence_refs"] = evidence_refs
    header = {
        "profile": "aarp/v0.1",
        "canon": "jcs-rfc8785-nfc",
        "alg": "ed25519",
        "key_type": "ed25519",
        "key_id": "k-signer",
        "signer_role": "mediator",
    }
    body["signatures"] = [{"protected": header, "sig": ""}]
    envelope = unmarshal(json.dumps(body, ensure_ascii=False).encode("utf-8"))
    payload_digest = envelope.payload_digest()
    protected = protected_header_type(header)
    message = signing_input(payload_digest, protected)
    seed = bytes.fromhex(test_keys["keys"]["k-signer"]["seed_hex"])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    body["signatures"][0]["sig"] = "ed25519:" + base64.standard_b64encode(signature).decode("ascii")
    return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipelock-verify-source", type=Path, required=True)
    parser.add_argument("--pipelock-source", type=Path, required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(args.pipelock_verify_source.resolve()))
    sys.path.insert(0, str((args.pipelock_source / "sdk/verifiers/python/src").resolve()))
    from pipelock_verify._canonical import canonicalize_action_record, canonicalize_receipt
    from pipelock_aarp_verify.envelope import ProtectedHeader, signing_input, unmarshal

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    AARP.mkdir(parents=True, exist_ok=True)
    REQUESTS.mkdir(parents=True, exist_ok=True)
    REQUEST_EVIDENCE.mkdir(parents=True, exist_ok=True)

    evidence_value = {
        "action_id": "conformance-00000",
        "claim": "The downstream result artifact was supplied to the receiver.",
        "status": "complete",
    }
    evidence_path = EVIDENCE / "case-01-downstream-evidence.json"
    write_json(evidence_path, evidence_value)
    write_json(REQUEST_EVIDENCE / evidence_path.name, evidence_value)
    evidence_hash = sha256_bytes(evidence_path.read_bytes())

    aarp_keys = load_json(AARP / "pipelock-aarp-test-keys.json")
    companion_specs = {
        "case-01-clean-allow": {
            "receipt": "case-01-clean-allow.json",
            "claims": ["mediated"],
            "evidence_refs": [f"sha256:{evidence_hash}"],
        },
        "case-02-allow-missing-evidence": {
            "receipt": "case-02-allow-missing-evidence.json",
            "claims": ["mediated", "downstream_claim_evidence_sufficient"],
            "evidence_refs": [],
        },
        "case-04-native-block": {
            "receipt": "case-04-native-block.json",
            "claims": ["mediated"],
            "evidence_refs": [],
        },
    }
    for case_id, spec in companion_specs.items():
        receipt = load_json(UPSTREAM / spec["receipt"])
        envelope = make_aarp_companion(
            receipt,
            claims=spec["claims"],
            evidence_refs=spec["evidence_refs"],
            test_keys=aarp_keys,
            canonicalize_action_record=canonicalize_action_record,
            canonicalize_receipt=canonicalize_receipt,
            unmarshal=unmarshal,
            protected_header_type=ProtectedHeader,
            signing_input=signing_input,
        )
        write_json(AARP / f"{case_id}.aarp.json", envelope, compact=True)

    cases = {
        "schema": "openline.pipelock_benchmark_cases.v0.1",
        "policy": {
            "policy_id": "pipelock-head-to-head-v1",
            "version": "frozen-2026-07-15",
            "require_trusted_source": True,
            "require_independent_source": False,
            "require_declared_coverage": False,
            "require_replay_guard": False,
            "require_evidence": True,
            "require_source_bound_evidence": True,
            "require_outcome_witness": False,
            "required_evidence_ids": ["downstream-result"],
            "required_claim_ids": ["conformance-00000"],
            "evidence_assertions": [
                {
                    "evidence_id": "downstream-result",
                    "path": "status",
                    "op": "equals",
                    "value": "complete",
                }
            ],
            "max_source_age_seconds": None,
            "max_evidence_bytes": 1000000,
            "no_badge_action_types": ["eval_score_claim"],
            "deny_risk_levels": [],
            "rollback_on_harm": True,
            "metadata": {
                "purpose": "isolate receiver-side evidence sufficiency from Pipelock mediation"
            },
        },
        "pipelock_signer_key": "890726e93f89e773fb3b4298271245a69c1884fd1003846c3358b8b65a2288fa",
        "cases": [
            {
                "case_id": "case-01-clean-allow",
                "fixture": "upstream/case-01-clean-allow.json",
                "input_mode": "single",
                "aarp_fixture": "aarp/case-01-clean-allow.aarp.json",
                "native_expected": {"valid": True, "action_verdict": "allow"},
                "aarp_expected": {
                    "assertion_signed": True,
                    "verified_claims_include": ["mediator_key_pinned", "receipt_signature_valid"],
                    "claimed_unverified_include": [],
                },
                "olp_expected": {"verdict": "VERIFIED", "decision": "COMMIT"},
                "evidence": [
                    {
                        "id": "downstream-result",
                        "artifact_path": "evidence/case-01-downstream-evidence.json",
                        "content_hash": evidence_hash,
                        "source_receipt_hash": "34f2780dcb510c03f55fc31387c993066fad23e328a2bf5f64b630b8d58a0dfb",
                    }
                ],
            },
            {
                "case_id": "case-02-allow-missing-evidence",
                "fixture": "upstream/case-02-allow-missing-evidence.json",
                "input_mode": "single",
                "aarp_fixture": "aarp/case-02-allow-missing-evidence.aarp.json",
                "native_expected": {"valid": True, "action_verdict": "allow"},
                "aarp_expected": {
                    "assertion_signed": True,
                    "verified_claims_include": ["mediator_key_pinned", "receipt_signature_valid"],
                    "claimed_unverified_include": ["downstream_claim_evidence_sufficient"],
                },
                "olp_expected": {"verdict": "UNDECIDABLE", "decision": "QUARANTINE"},
                "evidence": [],
            },
            {
                "case_id": "case-03-broken-chain",
                "fixture": "upstream/case-03-broken-chain.jsonl",
                "input_mode": "chain",
                "aarp_fixture": None,
                "native_expected": {"valid": False, "action_verdict": None},
                "aarp_expected": {"not_applicable": "native receipt chain rejected"},
                "olp_expected": {"verdict": "REJECTED", "decision": "DENY"},
                "evidence": [],
            },
            {
                "case_id": "case-04-native-block",
                "fixture": "upstream/case-04-native-block.json",
                "input_mode": "single",
                "aarp_fixture": "aarp/case-04-native-block.aarp.json",
                "native_expected": {"valid": True, "action_verdict": "block"},
                "aarp_expected": {
                    "assertion_signed": True,
                    "verified_claims_include": ["mediator_key_pinned", "receipt_signature_valid"],
                    "claimed_unverified_include": [],
                },
                "olp_expected": {"verdict": "REJECTED", "decision": "DENY"},
                "evidence": [],
            },
            {
                "case_id": "case-05-malformed-v1",
                "fixture": "upstream/case-05-malformed-v1.json",
                "input_mode": "single",
                "aarp_fixture": None,
                "native_expected": {"valid": False, "action_verdict": None},
                "aarp_expected": {"not_applicable": "native receipt rejected"},
                "olp_expected": {"verdict": "REJECTED", "decision": "DENY"},
                "evidence": [],
            },
        ],
    }
    write_json(HERE / "CASES.json", cases)

    write_json(FIXTURES / "olp-policy.json", cases["policy"])
    write_json(
        FIXTURES / "olp-trust.json",
        {
            "keys": {
                cases["pipelock_signer_key"]: {
                    "public_key": cases["pipelock_signer_key"],
                    "roles": ["source"],
                    "independence": "mediator",
                    "controller": "agent-egress-bench public conformance key",
                }
            }
        },
    )
    for case in cases["cases"]:
        fixture_path = FIXTURES / case["fixture"]
        if case["input_mode"] == "chain":
            source_receipts = [
                json.loads(line)
                for line in fixture_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        else:
            source_receipts = [load_json(fixture_path)]
        action_record = source_receipts[-1].get("action_record", {})
        evidence_items = []
        for item in case["evidence"]:
            cli_item = dict(item)
            evidence_items.append(cli_item)
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": case["case_id"],
            "action_type": str(action_record.get("action_type", "unknown")),
            "claim": "Receiver may use the downstream claim only when the frozen evidence policy passes.",
            "source_receipts": source_receipts,
            "binding": {},
            "evidence": evidence_items,
        }
        write_json(REQUESTS / f"{case['case_id']}.request.json", request)

    origin = {
        "case-01-clean-allow.json": "receipts/v0/conformance/golden/01-allow-clean-get.json",
        "case-01-clean-allow.upstream-expect.json": "receipts/v0/conformance/golden/01-allow-clean-get.expect.json",
        "case-02-allow-missing-evidence.json": "receipts/v0/conformance/golden/02-allow-suppressed-allowlist.json",
        "case-02-allow-missing-evidence.upstream-expect.json": "receipts/v0/conformance/golden/02-allow-suppressed-allowlist.expect.json",
        "case-03-broken-chain.jsonl": "receipts/v0/conformance/malicious/m08-tampered-chain-prev-hash.jsonl",
        "case-03-broken-chain.upstream-expect.json": "receipts/v0/conformance/malicious/m08-tampered-chain-prev-hash.expect.json",
        "case-04-native-block.json": "receipts/v0/conformance/golden/03-block-dlp-aws-key.json",
        "case-04-native-block.upstream-expect.json": "receipts/v0/conformance/golden/03-block-dlp-aws-key.expect.json",
        "case-05-malformed-v1.json": "receipts/v0/conformance/malicious/m06-missing-required-verdict.json",
        "case-05-malformed-v1.upstream-expect.json": "receipts/v0/conformance/malicious/m06-missing-required-verdict.expect.json",
        "pipelock-conformance-test-key.json": "receipts/v0/conformance/_generator/test-key.json",
    }
    files: list[dict[str, Any]] = []
    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(FIXTURES).as_posix()
        entry: dict[str, Any] = {
            "path": relative,
            "sha256": sha256_bytes(path.read_bytes()),
            "bytes": path.stat().st_size,
            "origin": "OLP-authored benchmark companion",
        }
        if path.parent == UPSTREAM:
            entry["origin"] = "agent-egress-bench byte-for-byte copy"
            entry["upstream_path"] = origin[path.name]
            entry["upstream_commit"] = AGENT_EGRESS_BENCH_COMMIT
        elif path.name in {"pipelock-aarp-test-keys.json", "pipelock-aarp-trust.json"}:
            entry["origin"] = "Pipelock AARP conformance corpus byte-for-byte copy"
            entry["upstream_commit"] = PIPELOCK_COMMIT
        files.append(entry)

    manifest = {
        "schema": "openline.pipelock_fixture_manifest.v0.1",
        "prepared_without_scoring": True,
        "source_commits": {
            "openline_receipt_gate_base": OLP_BASE_COMMIT,
            "pipelock": PIPELOCK_COMMIT,
            "pipelock_verify_python": PIPELOCK_VERIFY_COMMIT,
            "agent_egress_bench": AGENT_EGRESS_BENCH_COMMIT,
        },
        "files": files,
        "cases_sha256": sha256_bytes((HERE / "CASES.json").read_bytes()),
    }
    write_json(HERE / "FIXTURE_MANIFEST.json", manifest)
    print(json.dumps({"prepared": True, "fixture_count": len(files)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
