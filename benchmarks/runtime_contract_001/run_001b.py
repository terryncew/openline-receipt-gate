#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import public_key_hex, sign_olp_body, verify_olp_signature
from olp_gate.gate import gate
from olp_gate.receipts import sha256_json, verify_chain
from olp_gate.standing import (
    ReceiverStandingView,
    STANDING_PROJECTION_SCHEMA,
    standing_action_hash,
    standing_action_hash_from_call,
    standing_requirement_source,
    support_receipt_hash,
)
from olp_gate.tool_adapter import (
    AuthorizationBlocked,
    AuthorizedValue,
    EvidenceAssertion,
    authorize,
)


BASE_SHA = "6c01bfcfe6f1226ec1483a0000817401cc937814"
FREEZE_SCHEMA = "openline.runtime-contract-001b.freeze.v1"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(value), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()


class FakeRuntime:
    """Exercise the real compiler/preflight path while keeping effects harmless."""

    def __init__(self) -> None:
        self.executions: list[tuple[Mapping[str, Any], Any]] = []
        self.compilations: list[Mapping[str, Any]] = []

    def record_compilation(self, value: Mapping[str, Any]) -> None:
        self.compilations.append(dict(value))

    def execute(self, *, compiler, proposal, compilation, executor, now):
        preflight = compiler.preflight(compilation, proposal, now=now)
        if not preflight["allowed"]:
            raise AuthorizationBlocked(
                "DENY",
                preflight["reason_codes"],
                compilation=compilation,
            )
        value = executor()
        self.executions.append((dict(proposal), value))
        return AuthorizedValue(
            value=value,
            decision_receipt={"decision": "COMMIT", "verdict": "VERIFIED"},
            compilation=compilation,
            execution={"authorized": True, "execution_status": "completed"},
        )


class RuntimeContractHarness:
    def __init__(self, receipt_path: Path) -> None:
        self.now = datetime.now(timezone.utc)
        self.source_key = Ed25519PrivateKey.generate()
        self.standing_key = Ed25519PrivateKey.generate()
        self.standing_issuer = "runtime-contract-standing-projector"
        self.view = ReceiverStandingView(
            {self.standing_issuer: public_key_hex(self.standing_key)}
        )
        self.runtime = FakeRuntime()
        self.effects: list[str] = []
        self.supports: dict[str, dict[str, Any]] = {}
        self.projections: dict[tuple[str, str], dict[str, Any]] = {}
        self.presented: dict[tuple[str, str], dict[str, Any]] = {}
        self.receipt_path = receipt_path

        self.bundle = {
            "schema": "openline.authorized_tool_policy.v1",
            "mandate": {
                "profile": "principal_mandate/v1",
                "mandate_id": "runtime-contract-001b-mandate",
                "principal_id": "receiver-owner",
                "agent_id": "runtime-contract-agent",
                "purpose": "exercise transitive standing without external effects",
                "allowed_action_types": ["apply_decision"],
                "allowed_targets": ["runtime://decision"],
                "allowed_disclosure_classes": [],
                "forbidden_disclosure_classes": [],
                "max_settlement_cents": 0,
                "max_payment_cents": 0,
                "delegation_allowed": False,
                "expires_at": _iso(self.now + timedelta(days=1)),
                "version": "1",
            },
            "permission_policy": {
                "profile": "decision_permission_policy/v1",
                "policy_id": "runtime-contract-001b-policy",
                "version": "1",
                "routes": [
                    {
                        "route_id": "apply-decision",
                        "tool": "apply_decision",
                        "target": "runtime://decision",
                        "requirements": [
                            {
                                "requirement_id": "decision_authority",
                                "kind": "authority",
                                "accepted_issuers": ["decision_authority"],
                                "max_age_seconds": 300,
                                "independent_from_producer": True,
                            },
                            {
                                "requirement_id": "decision_standing",
                                "kind": "evidence",
                                "accepted_issuers": ["receiver_standing"],
                                "max_age_seconds": 300,
                                "independent_from_producer": True,
                            },
                        ],
                        "unknown_behavior": "QUARANTINE",
                        "max_authorization_ttl_seconds": 120,
                    }
                ],
            },
        }

        self._standing_provider = standing_requirement_source(
            self.view,
            support_source=self._support_for_call,
            projection_source=self._projection_for_call,
            action_hash_source=standing_action_hash_from_call,
            evidence_issuer_id="receiver_standing",
            max_assertion_ttl_seconds=60,
            now_source=lambda: datetime.now(timezone.utc),
        )

        @authorize(
            policy=self.bundle,
            tool="apply_decision",
            target="runtime://decision",
            semantics=self._semantics,
            state_source=self._state,
            evidence_sources={
                "decision_authority": self._authority_for_call,
                "decision_standing": self._standing_provider,
            },
            producer_model="runtime-contract-fixture",
            runtime=self.runtime,
        )
        def apply_decision(decision_id: str, payload: str):
            self.effects.append(decision_id)
            return {
                "applied": True,
                "decision_id": decision_id,
                "payload": payload,
            }

        self.apply_decision = apply_decision

    @staticmethod
    def _semantics(call):
        return {
            "action_type": "apply_decision",
            "disclosures": [],
            "value_cents": 0,
            "delegatee": None,
        }

    @staticmethod
    def _state(call):
        return {
            "decision_id": call.arguments["decision_id"],
            "payload": call.arguments["payload"],
        }

    @staticmethod
    def action_hash(decision_id: str, payload: str) -> str:
        return standing_action_hash(
            tool="apply_decision",
            target="runtime://decision",
            arguments={"decision_id": decision_id, "payload": payload},
        )

    def _support_for_call(self, call):
        return self.supports.get(str(call.arguments.get("decision_id")))

    def _projection_for_call(self, call):
        support = self._support_for_call(call)
        if support is None:
            return None
        key = (support_receipt_hash(support), standing_action_hash_from_call(call))
        return self.presented.get(key)

    def _support_valid(self, support: Mapping[str, Any]) -> bool:
        schema = support.get("schema")
        if schema == "openline.runtime-contract-basis.v1":
            valid, _reason = verify_olp_signature(support)
            if valid is not True:
                return False
            signature = support.get("signature")
            return (
                isinstance(signature, Mapping)
                and signature.get("public_key") == public_key_hex(self.source_key)
            )

        if schema == "openline.receipt_gate.v0.1.1":
            observed = support.get("receipt_hash")
            if not isinstance(observed, str):
                return False
            body = {key: value for key, value in support.items() if key != "receipt_hash"}
            return (
                observed == sha256_json(body)
                and support.get("decision") == "COMMIT"
                and support.get("status") == "committed"
            )
        return False

    def _authority_for_call(self, call):
        support = self._support_for_call(call)
        if support is None or not self._support_valid(support):
            return None
        return EvidenceAssertion(
            payload={"support_hash": support_receipt_hash(support)},
            issuer_id="decision_authority",
            expires_in_seconds=60,
        )

    def external_basis(self, basis_id: str) -> dict[str, Any]:
        return sign_olp_body(
            {
                "schema": "openline.runtime-contract-basis.v1",
                "basis_id": basis_id,
                "issuer_id": "fixture-source",
                "issued_at": _iso(self.now),
                "expires_at": _iso(self.now + timedelta(hours=1)),
            },
            self.source_key,
        )

    def set_support(self, decision_id: str, support: Mapping[str, Any]) -> None:
        self.supports[decision_id] = json.loads(
            json.dumps(dict(support), sort_keys=True)
        )

    def _projection(
        self,
        decision_id: str,
        payload: str,
        *,
        standing: str,
        event_type: str,
    ) -> dict[str, Any]:
        support = self.supports[decision_id]
        support_hash = support_receipt_hash(support)
        action_hash = self.action_hash(decision_id, payload)
        key = (support_hash, action_hash)
        current = self.projections.get(key)
        sequence = 1 if current is None else int(current["sequence"]) + 1
        predecessor = self.view.head_hash(support_hash, action_hash)
        return sign_olp_body(
            {
                "schema": STANDING_PROJECTION_SCHEMA,
                "projection_id": f"{decision_id}:{event_type.lower()}:{sequence}",
                "issuer_id": self.standing_issuer,
                "support_hash": support_hash,
                "action_hash": action_hash,
                "standing": standing,
                "event_type": event_type,
                "sequence": sequence,
                "predecessor_hash": predecessor,
                "issued_at": _iso(datetime.now(timezone.utc)),
                "expires_at": _iso(datetime.now(timezone.utc) + timedelta(hours=1)),
            },
            self.standing_key,
        )

    def admit(
        self,
        decision_id: str,
        payload: str,
        *,
        standing: str,
        event_type: str,
    ) -> dict[str, Any]:
        projection = self._projection(
            decision_id,
            payload,
            standing=standing,
            event_type=event_type,
        )
        self.view.admit(projection, now=datetime.now(timezone.utc))
        support = self.supports[decision_id]
        key = (support_receipt_hash(support), self.action_hash(decision_id, payload))
        self.projections[key] = projection
        self.presented[key] = projection
        return projection

    def try_apply(self, decision_id: str, payload: str) -> dict[str, Any]:
        before = len(self.effects)
        try:
            value = self.apply_decision(decision_id, payload)
            return {
                "executed": True,
                "blocked": False,
                "decision": "COMMIT",
                "reasons": [],
                "effect_delta": len(self.effects) - before,
                "value": value.value if isinstance(value, AuthorizedValue) else value,
            }
        except AuthorizationBlocked as exc:
            return {
                "executed": False,
                "blocked": True,
                "decision": exc.decision,
                "reasons": list(exc.reason_codes),
                "effect_delta": len(self.effects) - before,
            }

    def make_a_receipt(
        self,
        *,
        basis_support_hash: str,
        a_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        with gate(
            action_type="runtime_contract_decision",
            claim="Decision A executed under current standing",
            evidence_required=True,
            store_raw_evidence=True,
            receipt_path=str(self.receipt_path),
            metadata={
                "decision_id": "A",
                "runtime_contract_role": "upstream_decision",
            },
        ) as receipt_gate:
            return receipt_gate.commit(
                dict(a_result),
                evidence={
                    "basis_support_hash": basis_support_hash,
                },
            )


def execute(repo: Path, out: Path) -> dict[str, Any]:
    freeze_path = repo / "benchmarks/runtime_contract_001/001b-freeze.json"
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    if freeze.get("schema") != FREEZE_SCHEMA:
        raise RuntimeError("runtime-contract-001b freeze schema mismatch")
    if freeze.get("base_sha") != BASE_SHA:
        raise RuntimeError("runtime-contract-001b base SHA mismatch")

    base_tree = _git(repo, "rev-parse", f"{BASE_SHA}:olp_gate")
    head_tree = _git(repo, "rev-parse", "HEAD:olp_gate")
    if base_tree != head_tree:
        raise RuntimeError(
            "olp_gate changed after preregistration; 001B must test current runtime "
            "before a remedy"
        )

    receipt_path = out / "runtime-contract-receipts.jsonl"
    h = RuntimeContractHarness(receipt_path)

    payload_a = "apply-A"
    payload_b = "apply-B-from-A"
    payload_c = "apply-independent-C"

    basis_x = h.external_basis("X")
    basis_c = h.external_basis("CONTROL-C")
    h.set_support("A", basis_x)
    h.set_support("C", basis_c)

    h.admit("A", payload_a, standing="ACTIVE", event_type="ADMIT")
    h.admit("C", payload_c, standing="ACTIVE", event_type="ADMIT")

    a_initial = h.try_apply("A", payload_a)
    if not a_initial["executed"]:
        raise RuntimeError(f"fixture invalid: A did not execute initially: {a_initial!r}")

    x_hash = support_receipt_hash(basis_x)
    a_receipt = h.make_a_receipt(
        basis_support_hash=x_hash,
        a_result={"decision_id": "A", "protected_effect": "completed"},
    )
    if a_receipt.get("decision") != "COMMIT":
        raise RuntimeError(f"fixture invalid: A receipt not committed: {a_receipt!r}")
    if not verify_chain(receipt_path)["valid"]:
        raise RuntimeError("fixture invalid: A receipt chain failed verification")

    h.set_support("B", a_receipt)
    h.admit("B", payload_b, standing="ACTIVE", event_type="ADMIT")

    b_initial = h.try_apply("B", payload_b)
    c_initial = h.try_apply("C", payload_c)
    if not b_initial["executed"] or not c_initial["executed"]:
        raise RuntimeError(
            f"fixture invalid: B/C controls did not execute: "
            f"B={b_initial!r} C={c_initial!r}"
        )

    raw_evidence = (
        a_receipt.get("metadata", {})
        .get("evidence", {})
    )
    ancestry_encoded = (
        raw_evidence.get("basis_support_hash") == x_hash
        and support_receipt_hash(h.supports["B"]) == support_receipt_hash(a_receipt)
    )
    if not ancestry_encoded:
        raise RuntimeError("fixture invalid: frozen X -> A -> B ancestry is not encoded")

    # The only T1 event: receiver admits X as no longer standing for A.
    h.admit("A", payload_a, standing="INACTIVE", event_type="REVOKE")

    a_after = h.try_apply("A", payload_a)
    b_after = h.try_apply("B", payload_b)
    c_after = h.try_apply("C", payload_c)

    if not a_after["blocked"] or a_after["effect_delta"] != 0:
        raise RuntimeError(
            f"fixture invalid: direct standing no longer blocks A: {a_after!r}"
        )
    if not c_after["executed"] or c_after["effect_delta"] != 1:
        raise RuntimeError(
            f"fixture invalid: unrelated control C did not survive: {c_after!r}"
        )

    if b_after["blocked"] and b_after["effect_delta"] == 0:
        verdict = "TRANSITIVE_CONSEQUENCE_ALREADY_ENFORCED"
    elif b_after["executed"] and b_after["effect_delta"] == 1:
        verdict = "TRANSITIVE_CONSEQUENCE_NOT_DISCOVERED"
    else:
        raise RuntimeError(
            f"scientific outcome ambiguous: downstream B state is {b_after!r}"
        )

    result = {
        "schema": "openline.runtime-contract-001b.result.v1",
        "experiment": "RUNTIME-CONTRACT-001B",
        "verdict": verdict,
        "git_head": _git(repo, "rev-parse", "HEAD"),
        "preregistered_base_sha": BASE_SHA,
        "source_guard": {
            "base_olp_gate_tree": base_tree,
            "head_olp_gate_tree": head_tree,
            "unchanged": base_tree == head_tree,
        },
        "freeze_sha256": _sha(freeze_path),
        "claim_graph_runtime_dependency": False,
        "ancestry": {
            "x_support_hash": x_hash,
            "a_receipt_hash": a_receipt["receipt_hash"],
            "a_receipt_records_x_basis": ancestry_encoded,
            "b_direct_support_is_a_receipt": True,
            "explicit_x_to_b_update_after_revoke": False,
        },
        "before_standing_loss": {
            "A": a_initial,
            "B": b_initial,
            "C": c_initial,
        },
        "standing_change": {
            "support": "X",
            "direct_decision": "A",
            "event_type": "REVOKE",
            "new_standing": "INACTIVE",
        },
        "after_standing_loss": {
            "A": a_after,
            "B": b_after,
            "C": c_after,
        },
        "receipt_chain": verify_chain(receipt_path),
        "claim_boundary": [
            "Direct standing enforcement is a fixture prerequisite, not the claim under test.",
            "The experiment tests X -> A -> B transitive consequence discovery.",
            "No Claim Graph or dependency remedy is imported or implemented.",
            "A FAIL shows the current runtime lacks this transitive discovery path.",
        ],
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    repo = args.repo.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    result = execute(repo, out)
    result_path = out / "RUNTIME_CONTRACT_001B_RESULT.json"
    _write(result_path, result)
    result_sha = _sha(result_path)
    (out / "RUNTIME_CONTRACT_001B_RESULT.sha256").write_text(
        result_sha + "\n",
        encoding="utf-8",
    )

    print(result["verdict"])
    print(
        "before: "
        f"A={result['before_standing_loss']['A']['executed']} "
        f"B={result['before_standing_loss']['B']['executed']} "
        f"C={result['before_standing_loss']['C']['executed']}"
    )
    print(
        "after X revoke: "
        f"A_blocked={result['after_standing_loss']['A']['blocked']} "
        f"B_blocked={result['after_standing_loss']['B']['blocked']} "
        f"C_executed={result['after_standing_loss']['C']['executed']}"
    )
    print(f"result_sha256={result_sha}")

    # Both frozen verdicts are valid scientific completion.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
