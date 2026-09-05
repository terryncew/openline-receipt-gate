#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import traceback
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.ancestry import (
    AncestryClosureError,
    ClosureAwareStandingView,
    ReceiverAncestryClosureView,
    closure_aware_standing_requirement_source,
)
from olp_gate.crypto import public_key_hex, sign_olp_body, verify_olp_signature
from olp_gate.standing import (
    STANDING_PROJECTION_SCHEMA,
    standing_action_hash,
    standing_action_hash_from_call,
    support_receipt_hash,
)
from olp_gate.tool_adapter import (
    AuthorizationBlocked,
    AuthorizedValue,
    EvidenceAssertion,
    authorize,
)


IMPLEMENTATION_BASE_SHA = "37004d71860b603a85657c8c0ee6f0ae16356ba4"
CONTRACT_BASE_SHA = "3f7874dde7e0e1b7918ceac00eee0f251c452b94"
CONTRACT_GIT_BLOB_SHA = "0d8ca58d86c108d2a7d1365b4986aa9fba474403"
CONTRACT_SCHEMA = "openline.runtime-contract-002.contract.v1"


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


def _signature_matches(
    value: Mapping[str, Any],
    expected_public_key: str,
) -> bool:
    valid, _reason = verify_olp_signature(value)
    if valid is not True:
        return False
    signature = value.get("signature")
    return (
        isinstance(signature, Mapping)
        and str(signature.get("public_key", "")).lower()
        == expected_public_key.lower()
    )


class FakeRuntime:
    """Use the real compiler/preflight path with harmless local effects."""

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


class RuntimeContract002Harness:
    def __init__(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.basis_key = Ed25519PrivateKey.generate()
        self.decision_receipt_key = Ed25519PrivateKey.generate()
        self.standing_key = Ed25519PrivateKey.generate()
        self.standing_issuer = "runtime-contract-002-standing-projector"

        self.closure = ReceiverAncestryClosureView()
        self.view = ClosureAwareStandingView(
            {self.standing_issuer: public_key_hex(self.standing_key)},
            closure_view=self.closure,
        )
        self.runtime = FakeRuntime()
        self.effects: list[str] = []
        self.supports: dict[str, dict[str, Any]] = {}
        self.projections: dict[tuple[str, str], dict[str, Any]] = {}
        self.presented: dict[tuple[str, str], dict[str, Any]] = {}

        self.bundle = {
            "schema": "openline.authorized_tool_policy.v1",
            "mandate": {
                "profile": "principal_mandate/v1",
                "mandate_id": "runtime-contract-002-mandate",
                "principal_id": "receiver-owner",
                "agent_id": "runtime-contract-agent",
                "purpose": "exercise receiver-owned ancestry closure",
                "allowed_action_types": ["inspect"],
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
                "policy_id": "runtime-contract-002-policy",
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

        self._standing_provider = closure_aware_standing_requirement_source(
            self.view,
            closure_view=self.closure,
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
            producer_model="runtime-contract-002-fixture",
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
            "action_type": "inspect",
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
        key = (
            support_receipt_hash(support),
            standing_action_hash_from_call(call),
        )
        return self.presented.get(key)

    def _support_valid(self, support: Mapping[str, Any]) -> bool:
        schema = support.get("schema")
        if schema == "openline.runtime-contract-basis.v1":
            return _signature_matches(
                support,
                public_key_hex(self.basis_key),
            )
        if schema == "openline.runtime-contract-decision-receipt.v2":
            return (
                support.get("decision") == "COMMIT"
                and support.get("status") == "committed"
                and _signature_matches(
                    support,
                    public_key_hex(self.decision_receipt_key),
                )
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
            self.basis_key,
        )

    def make_receipt(
        self,
        decision_id: str,
        *,
        basis_support_hash: str,
        result: Mapping[str, Any],
        claimed_basis_support_hash: str | None = None,
    ) -> dict[str, Any]:
        return sign_olp_body(
            {
                "schema": "openline.runtime-contract-decision-receipt.v2",
                "receipt_id": f"decision-{decision_id}-receipt",
                "issuer_id": "runtime-contract-receiver",
                "decision_id": decision_id,
                "decision": "COMMIT",
                "status": "committed",
                "basis_support_hash": (
                    claimed_basis_support_hash
                    if claimed_basis_support_hash is not None
                    else basis_support_hash
                ),
                "result_hash": hashlib.sha256(
                    json.dumps(
                        dict(result),
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
                "issued_at": _iso(datetime.now(timezone.utc)),
                "expires_at": _iso(
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ),
            },
            self.decision_receipt_key,
        )

    def commit_receipt(
        self,
        decision_id: str,
        *,
        accepted_support: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        support_hash = support_receipt_hash(accepted_support)
        receipt = self.make_receipt(
            decision_id,
            basis_support_hash=support_hash,
            result=result,
        )
        if not self._support_valid(receipt):
            raise RuntimeError(
                f"fixture invalid: {decision_id} receipt failed signature verification"
            )
        admission = self.closure.record_commit(
            decision_id=decision_id,
            derived_receipt=receipt,
            accepted_supports=[accepted_support],
        )
        return receipt, admission

    def set_support(
        self,
        decision_id: str,
        support: Mapping[str, Any],
    ) -> None:
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
                "projection_id": (
                    f"{decision_id}:{event_type.lower()}:{sequence}"
                ),
                "issuer_id": self.standing_issuer,
                "support_hash": support_hash,
                "action_hash": action_hash,
                "standing": standing,
                "event_type": event_type,
                "sequence": sequence,
                "predecessor_hash": predecessor,
                "issued_at": _iso(datetime.now(timezone.utc)),
                "expires_at": _iso(
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ),
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
        admission = self.view.admit(
            projection,
            now=datetime.now(timezone.utc),
        )
        support = self.supports[decision_id]
        key = (
            support_receipt_hash(support),
            self.action_hash(decision_id, payload),
        )
        self.projections[key] = projection
        self.presented[key] = projection
        return {
            "projection": projection,
            "admission": admission,
        }

    def try_apply(
        self,
        decision_id: str,
        payload: str,
    ) -> dict[str, Any]:
        before = len(self.effects)
        try:
            value = self.apply_decision(decision_id, payload)
            return {
                "executed": True,
                "blocked": False,
                "decision": "COMMIT",
                "reasons": [],
                "effect_delta": len(self.effects) - before,
                "value": (
                    value.value
                    if isinstance(value, AuthorizedValue)
                    else value
                ),
            }
        except AuthorizationBlocked as exc:
            return {
                "executed": False,
                "blocked": True,
                "decision": exc.decision,
                "reasons": list(exc.reason_codes),
                "effect_delta": len(self.effects) - before,
            }


def execute(repo: Path, out: Path) -> dict[str, Any]:
    contract_path = repo / "benchmarks/runtime_contract_002/contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))

    if contract.get("schema") != CONTRACT_SCHEMA:
        raise RuntimeError("runtime-contract-002 contract schema mismatch")
    if contract.get("status") != "FROZEN_BEFORE_REMEDY_IMPLEMENTATION":
        raise RuntimeError("runtime-contract-002 contract is not frozen")
    if contract.get("base_sha") != CONTRACT_BASE_SHA:
        raise RuntimeError("runtime-contract-002 contract base mismatch")

    observed_blob = _git(repo, "hash-object", str(contract_path))
    if observed_blob != CONTRACT_GIT_BLOB_SHA:
        raise RuntimeError(
            "runtime-contract-002 contract changed after freeze"
        )

    h = RuntimeContract002Harness()

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
        raise RuntimeError(f"fixture invalid: A did not execute: {a_initial!r}")
    a_receipt, edge_a = h.commit_receipt(
        "A",
        accepted_support=basis_x,
        result={"decision_id": "A", "protected_effect": "completed"},
    )

    h.set_support("B", a_receipt)
    b_admit = h.admit(
        "B",
        payload_b,
        standing="ACTIVE",
        event_type="ADMIT",
    )
    b_head_before = b_admit["admission"]["head_hash"]

    b_initial = h.try_apply("B", payload_b)
    if not b_initial["executed"]:
        raise RuntimeError(f"fixture invalid: B did not execute: {b_initial!r}")
    b_receipt, edge_b = h.commit_receipt(
        "B",
        accepted_support=a_receipt,
        result={"decision_id": "B", "protected_effect": "completed"},
    )

    c_initial = h.try_apply("C", payload_c)
    if not c_initial["executed"]:
        raise RuntimeError(f"fixture invalid: C did not execute: {c_initial!r}")
    c_receipt, edge_c = h.commit_receipt(
        "C",
        accepted_support=basis_c,
        result={"decision_id": "C", "protected_effect": "completed"},
    )

    x_hash = support_receipt_hash(basis_x)
    a_hash = support_receipt_hash(a_receipt)
    b_hash = support_receipt_hash(b_receipt)
    c_hash = support_receipt_hash(c_receipt)

    # Adversarial 1: producer-supplied edge material has no admission path.
    forged_edge = {
        "relationship": "BASIS_FOR",
        "support_hash": x_hash,
        "derived_receipt_hash": support_receipt_hash(
            h.make_receipt(
                "P",
                basis_support_hash=support_receipt_hash(basis_c),
                claimed_basis_support_hash=x_hash,
                result={"decision_id": "P"},
            )
        ),
        "producer": "untrusted",
    }
    before_untrusted = h.closure.snapshot()
    untrusted_decision = h.closure.assess_untrusted_edge(forged_edge)
    producer_forged_edge_pass = (
        untrusted_decision["admitted"] is False
        and untrusted_decision["reason"]
        == "ancestry_external_edge_forbidden"
        and h.closure.snapshot() == before_untrusted
    )

    # Adversarial 2: B -> X would close X -> A -> B -> X.
    before_cycle = h.closure.snapshot()
    cycle_error = None
    try:
        h.closure.record_commit(
            decision_id="cycle",
            derived_receipt=basis_x,
            accepted_supports=[b_receipt],
        )
    except AncestryClosureError as exc:
        cycle_error = str(exc)
    cycle_edge_pass = (
        cycle_error == "ancestry_cycle_forbidden"
        and h.closure.snapshot() == before_cycle
    )

    a_hash_before = support_receipt_hash(a_receipt)
    b_hash_before = support_receipt_hash(b_receipt)
    a_sig_before = h._support_valid(a_receipt)
    b_sig_before = h._support_valid(b_receipt)

    revoke = h.admit(
        "A",
        payload_a,
        standing="INACTIVE",
        event_type="REVOKE",
    )
    closure_result = revoke["admission"].get("closure")
    if not isinstance(closure_result, Mapping):
        raise RuntimeError("fixture invalid: standing loss produced no closure")

    closure_after_first = h.closure.snapshot()

    a_after = h.try_apply("A", payload_a)
    b_after = h.try_apply("B", payload_b)
    c_after = h.try_apply("C", payload_c)

    b_head_after = h.view.head_hash(
        a_hash,
        h.action_hash("B", payload_b),
    )

    # Adversarial 3: replay exact receiver standing-loss event.
    replay = h.closure.apply_standing_loss(
        support_hash=x_hash,
        standing_event_id=str(closure_result["standing_event_id"]),
        standing_event_sequence=int(
            closure_result["standing_event_sequence"]
        ),
    )
    closure_after_replay = h.closure.snapshot()
    standing_event_replay_pass = (
        replay["replayed"] is True
        and closure_after_replay["closure_event_sequence"]
        == closure_after_first["closure_event_sequence"]
        and closure_after_replay["affected"]
        == closure_after_first["affected"]
    )

    a_sig_after = h._support_valid(a_receipt)
    b_sig_after = h._support_valid(b_receipt)
    historical_authenticity_pass = (
        a_sig_before
        and b_sig_before
        and a_sig_after
        and b_sig_after
        and support_receipt_hash(a_receipt) == a_hash_before
        and support_receipt_hash(b_receipt) == b_hash_before
    )

    affected = closure_after_first["affected"]
    exact_closure_pass = set(affected) == {a_hash, b_hash}
    causal_path_pass = (
        affected[b_hash]["causal_path"] == [x_hash, a_hash, b_hash]
    )
    unrelated_control_pass = (
        c_hash not in affected
        and c_after["executed"] is True
        and c_after["effect_delta"] == 1
    )
    no_manual_x_to_b_pass = (
        b_head_before == b_head_after
        and h.presented[
            (a_hash, h.action_hash("B", payload_b))
        ]["payload_hash"]
        == b_head_before
    )
    gate_integration_pass = (
        a_after["blocked"] is True
        and a_after["effect_delta"] == 0
        and b_after["blocked"] is True
        and b_after["effect_delta"] == 0
        and c_after["executed"] is True
    )

    adversarial = {
        "producer_forged_edge": producer_forged_edge_pass,
        "cycle_edge": cycle_edge_pass,
        "standing_event_replay": standing_event_replay_pass,
        "unrelated_control": unrelated_control_pass,
        "historical_authenticity": historical_authenticity_pass,
    }

    pass_checks = {
        "contract_blob_unchanged": observed_blob == CONTRACT_GIT_BLOB_SHA,
        "receiver_edges_admitted_before_revoke": (
            edge_a["created"]
            and edge_b["created"]
            and edge_c["created"]
        ),
        "before_A_B_C_execute": (
            a_initial["executed"]
            and b_initial["executed"]
            and c_initial["executed"]
        ),
        "exact_affected_closure_A_B": exact_closure_pass,
        "causal_path_X_A_B": causal_path_pass,
        "no_explicit_X_to_B_update": no_manual_x_to_b_pass,
        "gate_blocks_A_and_B_but_allows_C": gate_integration_pass,
        "historical_authenticity_preserved": historical_authenticity_pass,
        "all_adversarial_checks": all(adversarial.values()),
        "multi_basis_not_exercised": True,
    }

    verdict = (
        "TRANSITIVE_CONSEQUENCE_CLOSURE_ENFORCED"
        if all(pass_checks.values())
        else "TRANSITIVE_CONSEQUENCE_CLOSURE_STILL_ESCAPABLE"
    )

    result = {
        "schema": "openline.runtime-contract-002.result.v1",
        "experiment": "RUNTIME-CONTRACT-002",
        "verdict": verdict,
        "git_head": _git(repo, "rev-parse", "HEAD"),
        "implementation_base_sha": IMPLEMENTATION_BASE_SHA,
        "contract": {
            "schema": CONTRACT_SCHEMA,
            "base_sha": CONTRACT_BASE_SHA,
            "git_blob_sha": observed_blob,
            "sha256": _sha(contract_path),
        },
        "ancestry_module_sha256": _sha(repo / "olp_gate/ancestry.py"),
        "graph": {
            "X": x_hash,
            "A_receipt": a_hash,
            "B_receipt": b_hash,
            "CONTROL_C_receipt": c_hash,
            "snapshot_after_revoke": closure_after_first,
        },
        "standing_loss": {
            "support_hash": x_hash,
            "event_type": "REVOKE",
            "standing": "INACTIVE",
            "closure": closure_result,
        },
        "before_standing_loss": {
            "A": a_initial,
            "B": b_initial,
            "C": c_initial,
        },
        "after_standing_loss": {
            "A": a_after,
            "B": b_after,
            "C": c_after,
        },
        "adversarial": adversarial,
        "pass_checks": pass_checks,
        "claim_boundary": [
            "One accepted basis per committed receipt only.",
            "Receiver-owned local ancestry closure only.",
            "No automatic undo of historical effects.",
            "No cross-receiver propagation or distributed consistency claim.",
            "Historical receipts remain authentic; closure changes current standing.",
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

    _write(
        out / "run-start.json",
        {
            "schema": "openline.runtime-contract-002.run-start.v1",
            "status": "STARTED",
            "implementation_base_sha": IMPLEMENTATION_BASE_SHA,
        },
    )

    try:
        result = execute(repo, out)
    except Exception as exc:
        _write(
            out / "RUNTIME_CONTRACT_002_INFRA_FAILURE.json",
            {
                "schema": "openline.runtime-contract-002.infra-failure.v1",
                "status": "INFRASTRUCTURE_FAILURE",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            },
        )
        raise

    result_path = out / "RUNTIME_CONTRACT_002_RESULT.json"
    _write(result_path, result)
    result_sha = _sha(result_path)
    (out / "RUNTIME_CONTRACT_002_RESULT.sha256").write_text(
        result_sha + "\n",
        encoding="utf-8",
    )

    print(result["verdict"])
    print(
        "after X revoke: "
        f"A_blocked={result['after_standing_loss']['A']['blocked']} "
        f"B_blocked={result['after_standing_loss']['B']['blocked']} "
        f"C_executed={result['after_standing_loss']['C']['executed']}"
    )
    print(
        "adversarial="
        f"{sum(1 for value in result['adversarial'].values() if value)}/"
        f"{len(result['adversarial'])}"
    )
    print(f"result_sha256={result_sha}")

    # Both scientific outcomes are valid completed experiments.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
