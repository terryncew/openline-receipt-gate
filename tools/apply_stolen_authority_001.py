#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "3ae2918d59125e13cf8f58147e482ebb940b6da6"


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one patch anchor, found {count}")
    target.write_text(text.replace(old, new), encoding="utf-8")


# verified_commit.py: define a privacy-preserving stable-subject binding.
replace_once(
    "olp_gate/verified_commit.py",
    '''_HEX_256 = re.compile(r"^[0-9a-f]{64}$")\n_CODE_DOMAIN = b"openline-verified-commit-v1\\x00"\n_LOCAL_LOCKS_GUARD = threading.Lock()\n''',
    '''_HEX_256 = re.compile(r"^[0-9a-f]{64}$")\n_CODE_DOMAIN = b"openline-verified-commit-v1\\x00"\n_AUTHORITY_SUBJECT_DOMAIN = b"openline-authority-subject-v1\\x00"\nAUTHORITY_SUBJECT_PROFILE = "openline.authority-subject/v1"\nAUTHORITY_SUBJECT_KEYS = {"profile", "subject_hash"}\n_LOCAL_LOCKS_GUARD = threading.Lock()\n''',
)

replace_once(
    "olp_gate/verified_commit.py",
    '''def one_use_code_hash(code: str) -> str:\n    if not isinstance(code, str) or _HEX_256.fullmatch(code) is None:\n        raise VerifiedCommitError("one_use_code_invalid")\n    return sha256_hex(_CODE_DOMAIN + code.encode("ascii"))\n\n\ndef settings_hash(settings: Mapping[str, Any]) -> str:\n''',
    '''def one_use_code_hash(code: str) -> str:\n    if not isinstance(code, str) or _HEX_256.fullmatch(code) is None:\n        raise VerifiedCommitError("one_use_code_invalid")\n    return sha256_hex(_CODE_DOMAIN + code.encode("ascii"))\n\n\ndef authority_subject_hash(subject_id: str) -> str:\n    """Hash a receiver-observed stable authority subject without storing it raw."""\n\n    if not isinstance(subject_id, str) or not subject_id:\n        raise VerifiedCommitError("authority_subject_id_invalid")\n    return sha256_hex(_AUTHORITY_SUBJECT_DOMAIN + subject_id.encode("utf-8"))\n\n\ndef authority_subject_policy(subject_id: str) -> dict[str, str]:\n    """Return receiver-owned policy metadata binding spend to one subject."""\n\n    return {\n        "profile": AUTHORITY_SUBJECT_PROFILE,\n        "subject_hash": authority_subject_hash(subject_id),\n    }\n\n\ndef settings_hash(settings: Mapping[str, Any]) -> str:\n''',
)

replace_once(
    "olp_gate/verified_commit.py",
    '''        one_use_code: str,\n        trusted_gate_keys: Sequence[str],\n        replay_scope_hash: str | None = None,\n        now: datetime | None = None,\n        attempt_label: str | None = None,\n''',
    '''        one_use_code: str,\n        trusted_gate_keys: Sequence[str],\n        observed_subject_id: str | None = None,\n        replay_scope_hash: str | None = None,\n        now: datetime | None = None,\n        attempt_label: str | None = None,\n''',
)

replace_once(
    "olp_gate/verified_commit.py",
    '''            expiry = parse_timestamp(authorization.get("expires_at"))\n            if expiry is None:\n                errors.append("authorization_expiry_invalid")\n            elif check_time >= expiry:\n                errors.append("authorization_expired")\n\n            decision_hash = receipt.get("payload_hash")\n''',
    '''            expiry = parse_timestamp(authorization.get("expires_at"))\n            if expiry is None:\n                errors.append("authorization_expiry_invalid")\n            elif check_time >= expiry:\n                errors.append("authorization_expired")\n\n            # Subject authority is receiver policy, never a producer claim.\n            # The low-level ledger accepts an observed subject only from the\n            # receiver-owned boundary that invokes it.  LocalAuthorityRuntime\n            # supplies the stable mandate agent slot, deliberately not a model\n            # or provider identity, so model swaps preserve valid authority.\n            observed_subject_hash: str | None = None\n            policy_value = receipt.get("policy")\n            policy_snapshot = (\n                policy_value.get("snapshot")\n                if isinstance(policy_value, Mapping)\n                else None\n            )\n            policy_metadata = (\n                policy_snapshot.get("metadata", {})\n                if isinstance(policy_snapshot, Mapping)\n                else {}\n            )\n            raw_subject_binding = (\n                policy_metadata.get("authority_subject")\n                if isinstance(policy_metadata, Mapping)\n                else None\n            )\n            if raw_subject_binding is not None:\n                expected_subject_hash: str | None = None\n                if not isinstance(raw_subject_binding, Mapping):\n                    errors.append("authority_subject_binding_invalid")\n                else:\n                    subject_binding = dict(raw_subject_binding)\n                    if set(subject_binding) != AUTHORITY_SUBJECT_KEYS:\n                        errors.append("authority_subject_binding_invalid")\n                    if subject_binding.get("profile") != AUTHORITY_SUBJECT_PROFILE:\n                        errors.append("authority_subject_binding_invalid")\n                    candidate_subject_hash = subject_binding.get("subject_hash")\n                    if not _is_hash(candidate_subject_hash):\n                        errors.append("authority_subject_binding_invalid")\n                    else:\n                        expected_subject_hash = candidate_subject_hash\n                if observed_subject_id is None:\n                    errors.append("authority_subject_missing")\n                else:\n                    try:\n                        observed_subject_hash = authority_subject_hash(\n                            observed_subject_id\n                        )\n                    except VerifiedCommitError:\n                        errors.append("authority_subject_observation_invalid")\n                    if (\n                        expected_subject_hash is not None\n                        and observed_subject_hash is not None\n                        and not hmac.compare_digest(\n                            observed_subject_hash, expected_subject_hash\n                        )\n                    ):\n                        errors.append("authority_subject_mismatch")\n\n            decision_hash = receipt.get("payload_hash")\n''',
)

replace_once(
    "olp_gate/verified_commit.py",
    '''                "attempt_action_hash": attempted_hash,\n                "replay_scope_hash": replay_scope_hash,\n                "result": "AUTHORIZED" if authorized else "BLOCKED",\n''',
    '''                "attempt_action_hash": attempted_hash,\n                "observed_subject_hash": observed_subject_hash,\n                "replay_scope_hash": replay_scope_hash,\n                "result": "AUTHORIZED" if authorized else "BLOCKED",\n''',
)

# The second matching parameter block is execute_once; target a larger unique anchor.
replace_once(
    "olp_gate/verified_commit.py",
    '''        trusted_gate_keys: Sequence[str],\n        executor: Callable[[], T],\n        preflight: Callable[[], Mapping[str, Any]] | None = None,\n        replay_scope_hash: str | None = None,\n''',
    '''        trusted_gate_keys: Sequence[str],\n        executor: Callable[[], T],\n        preflight: Callable[[], Mapping[str, Any]] | None = None,\n        observed_subject_id: str | None = None,\n        replay_scope_hash: str | None = None,\n''',
)

replace_once(
    "olp_gate/verified_commit.py",
    '''            one_use_code=one_use_code,\n            trusted_gate_keys=trusted_gate_keys,\n            replay_scope_hash=replay_scope_hash,\n            now=now,\n''',
    '''            one_use_code=one_use_code,\n            trusted_gate_keys=trusted_gate_keys,\n            observed_subject_id=observed_subject_id,\n            replay_scope_hash=replay_scope_hash,\n            now=now,\n''',
)

# authority_compiler.py: forward the receiver observation without changing model-swap semantics.
replace_once(
    "olp_gate/authority_compiler.py",
    '''        one_use_code: str,\n        trusted_gate_keys: Sequence[str],\n        executor: Callable[[str, str, Mapping[str, Any]], Any],\n        replay_scope_hash: str | None = None,\n''',
    '''        one_use_code: str,\n        trusted_gate_keys: Sequence[str],\n        executor: Callable[[str, str, Mapping[str, Any]], Any],\n        observed_subject_id: str | None = None,\n        replay_scope_hash: str | None = None,\n''',
)

replace_once(
    "olp_gate/authority_compiler.py",
    '''            one_use_code=one_use_code,\n            trusted_gate_keys=trusted_gate_keys,\n            executor=lambda: executor(\n''',
    '''            one_use_code=one_use_code,\n            trusted_gate_keys=trusted_gate_keys,\n            observed_subject_id=observed_subject_id,\n            executor=lambda: executor(\n''',
)

# tool_adapter.py: receiver creates the binding from its stable mandate subject and observes the same slot at spend.
replace_once(
    "olp_gate/tool_adapter.py",
    '''        from .verified_commit import (\n            VerifiedCommitLedger,\n            issue_one_use_code,\n            settings_hash,\n        )\n''',
    '''        from .verified_commit import (\n            VerifiedCommitLedger,\n            authority_subject_policy,\n            issue_one_use_code,\n            settings_hash,\n        )\n''',
)

replace_once(
    "olp_gate/tool_adapter.py",
    '''                    "verified_commit": {\n                        "required": True,\n                        "tool": action["tool"],\n                        "target": action["target"],\n                        "settings_hash": settings_hash(action["settings"]),\n                        "run_id": run_id,\n                        "capsule_hash": action["capsule_hash"],\n                        "evidence_hashes": action["evidence_hashes"],\n                        "max_ttl_seconds": ttl,\n                    }\n''',
    '''                    "verified_commit": {\n                        "required": True,\n                        "tool": action["tool"],\n                        "target": action["target"],\n                        "settings_hash": settings_hash(action["settings"]),\n                        "run_id": run_id,\n                        "capsule_hash": action["capsule_hash"],\n                        "evidence_hashes": action["evidence_hashes"],\n                        "max_ttl_seconds": ttl,\n                    },\n                    "authority_subject": authority_subject_policy(\n                        compiler.mandate.agent_id\n                    ),\n''',
)

replace_once(
    "olp_gate/tool_adapter.py",
    '''            one_use_code=one_use_code,\n            trusted_gate_keys=[public_key_hex(gate_key)],\n            executor=lambda _tool, _target, _settings: executor(),\n            now=now,\n''',
    '''            one_use_code=one_use_code,\n            trusted_gate_keys=[public_key_hex(gate_key)],\n            observed_subject_id=compiler.mandate.agent_id,\n            executor=lambda _tool, _target, _settings: executor(),\n            now=now,\n''',
)

# Focused hostile fixture. It deliberately presents B with A's exact receipt/action/code.
test_path = ROOT / "tests/test_stolen_authority_001.py"
if test_path.exists():
    raise SystemExit("tests/test_stolen_authority_001.py already exists")
test_path.write_text(r'''from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.adapters import TrustStore
from olp_gate.crypto import public_key_hex, sha256_hex
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.verified_commit import (
    VerifiedCommitLedger,
    authority_subject_policy,
    settings_hash,
)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class StolenAuthority001Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="stolen-authority-001-")
        self.root = Path(self.temp.name)
        self.source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("71" * 32))
        self.witness_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("72" * 32))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("73" * 32))
        self.source_method = "did:example:stolen-authority-source#key-1"
        self.gate_public_key = public_key_hex(self.gate_key)
        self.store = TrustStore.from_mapping(
            {
                "keys": {
                    self.source_method: {
                        "public_key": public_key_hex(self.source_key),
                        "roles": ["source"],
                        "independence": "operator",
                        "controller": "stolen-authority-source",
                    },
                    public_key_hex(self.witness_key): {
                        "public_key": public_key_hex(self.witness_key),
                        "roles": ["outcome"],
                        "independence": "receiver",
                        "controller": "stolen-authority-receiver",
                    },
                }
            }
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def issue(self, case: str, subject_id: str) -> tuple[dict, dict, str]:
        now = datetime.now(timezone.utc)
        artifact = self.root / f"{case}.json"
        artifact.write_text('{"approved":true,"status":"complete"}\n', encoding="utf-8")
        artifact_hash = sha256_hex(artifact.read_bytes())
        run_id = f"run-{case}"
        source = _agent_receipt(
            key=self.source_key,
            method=self.source_method,
            chain_id=run_id,
            session_id=f"session-{case}",
            action_id=f"action-{case}",
            action_type="tool_call",
            response_hash=artifact_hash,
            timestamp=_iso(now),
        )
        source_hash = _source_hash(source)
        session = SessionLedger(self.root / f"{case}-sessions.json")
        binding = session.issue_challenge(
            run_id=run_id,
            session_id=f"session-{case}",
            expected_source_hash=source_hash,
        )
        outcome = issue_outcome_receipt(
            source_receipt_hash=source_hash,
            outcome_status="pass",
            harmful=False,
            evidence_hash=artifact_hash,
            witness_id="stolen-authority-receiver",
            rollback_supported=True,
            key=self.witness_key,
        )
        settings = {"content_sha256": sha256_hex(b"approved payload"), "mode": "create_new"}
        action = {
            "tool": "filesystem.write",
            "target": "artifact://approved.json",
            "settings": settings,
            "run_id": run_id,
            "capsule_hash": sha256_hex(f"capsule:{case}".encode("utf-8")),
            "evidence_hashes": [artifact_hash],
        }
        policy = PolicySpec.from_mapping(
            {
                "policy_id": "stolen-authority.receiver-policy",
                "version": "1",
                "require_declared_coverage": True,
                "require_outcome_witness": True,
                "required_evidence_ids": ["result"],
                "evidence_assertions": [
                    {"evidence_id": "result", "path": "approved", "op": "equals", "value": True}
                ],
                "metadata": {
                    "verified_commit": {
                        "required": True,
                        "tool": action["tool"],
                        "target": action["target"],
                        "settings_hash": settings_hash(settings),
                        "run_id": run_id,
                        "capsule_hash": action["capsule_hash"],
                        "evidence_hashes": action["evidence_hashes"],
                        "max_ttl_seconds": 120,
                    },
                    "authority_subject": authority_subject_policy(subject_id),
                },
            }
        )
        code = "cd" * 32
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": f"request-{case}",
            "action_type": "tool_call",
            "claim": "The receiver-bound subject may execute this exact action once.",
            "source_receipts": [source],
            "binding": binding,
            "evidence": [
                {
                    "id": "result",
                    "artifact_path": artifact.name,
                    "content_hash": artifact_hash,
                    "source_commitment_path": "credentialSubject.outcome.response_hash",
                }
            ],
            "outcome_receipt": outcome,
            "commit_request": {
                **action,
                "policy_hash": policy.policy_hash,
                "expires_at": _iso(now + timedelta(seconds=60)),
                "one_use_code": code,
            },
        }
        receipt = evaluate_request(
            request,
            policy=policy,
            trust_store=self.store,
            signing_key=self.gate_key,
            issuer_id="stolen-authority-test-gate",
            decision_path=self.root / f"{case}-decisions.jsonl",
            session_ledger=session,
            base_dir=self.root,
            now=now,
        )
        self.assertEqual((receipt["verdict"], receipt["decision"]), ("VERIFIED", "COMMIT"))
        action["policy_hash"] = policy.policy_hash
        return receipt, action, code

    def test_thief_with_exact_artifacts_is_denied_without_burning_owner_permission(self) -> None:
        receipt, action, code = self.issue("stolen", "agent-a")
        ledger = VerifiedCommitLedger(self.root / "stolen-ledger.json")
        effects: list[str] = []

        thief = ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            observed_subject_id="agent-b",
            executor=lambda: effects.append("thief"),
            attempt_label="agent-b-stolen-first",
        )
        self.assertFalse(thief["authorized"])
        self.assertIn("authority_subject_mismatch", thief["reason_codes"])
        self.assertEqual(effects, [])

        owner = ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            observed_subject_id="agent-a",
            executor=lambda: effects.append("owner") or {"ok": True},
            attempt_label="agent-a-owner",
        )
        self.assertTrue(owner["authorized"])
        self.assertEqual(effects, ["owner"])

        replay = ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            observed_subject_id="agent-a",
            executor=lambda: effects.append("replay"),
            attempt_label="agent-a-replay",
        )
        self.assertFalse(replay["authorized"])
        self.assertIn("authorization_replay", replay["reason_codes"])
        self.assertEqual(effects, ["owner"])

    def test_bound_permission_fails_closed_without_receiver_observation(self) -> None:
        receipt, action, code = self.issue("missing-subject", "agent-a")
        ledger = VerifiedCommitLedger(self.root / "missing-subject-ledger.json")
        effects: list[str] = []

        missing = ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            executor=lambda: effects.append("missing"),
        )
        self.assertFalse(missing["authorized"])
        self.assertIn("authority_subject_missing", missing["reason_codes"])
        self.assertEqual(effects, [])

        owner = ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            observed_subject_id="agent-a",
            executor=lambda: effects.append("owner") or {"ok": True},
        )
        self.assertTrue(owner["authorized"])
        self.assertEqual(effects, ["owner"])

    def test_subject_is_stable_authority_slot_not_provider_model(self) -> None:
        receipt, action, code = self.issue("model-swap", "stable-agent-slot")
        effects: list[str] = []
        result = VerifiedCommitLedger(self.root / "model-swap-ledger.json").execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            observed_subject_id="stable-agent-slot",
            executor=lambda: effects.append("replacement-model") or {"ok": True},
            attempt_label="provider-model-2-same-subject",
        )
        self.assertTrue(result["authorized"])
        self.assertEqual(effects, ["replacement-model"])


if __name__ == "__main__":
    unittest.main()
''', encoding="utf-8")

print("STOLEN-AUTHORITY-001 patch applied")
