"""DISTRIBUTED-STOP-001 receiver worker.

One OS process = one independent receiver. Holds its own
MandateOwnerView (durable heads), VerifiedCommitLedger, and effect dir.
Receives owner-signed records via its own file inbox; receives commands
via command files; reports via result files. Harness only.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate._durable_heads import DurableHeadStore
from olp_gate.adapters import TrustStore
from olp_gate.crypto import public_key_hex, sha256_hex
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request
from olp_gate.mandate_owner import MandateOwnerView
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.stop_standing import owner_mandate_stop_check
from olp_gate.verified_commit import VerifiedCommitLedger, settings_hash


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _mandate(owner_id: str, now: datetime) -> dict:
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": "distributed-stop-mandate",
        "principal_id": owner_id,
        "agent_id": "distributed-stop-agent",
        "purpose": "distributed stop experiment",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["payments://ledger"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": 10_000,
        "delegation_allowed": False,
        "expires_at": _iso(now + timedelta(days=1)),
        "version": "v1",
    }


class Worker:
    def __init__(self, args) -> None:
        self.args = args
        self.state = Path(args.state_dir)
        self.inbox = Path(args.inbox_dir)
        self.cmd_dir = Path(args.cmd_dir)
        self.res_dir = Path(args.res_dir)
        for d in (self.state, self.inbox, self.cmd_dir, self.res_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.effects = self.state / "effects"
        self.effects.mkdir(exist_ok=True)

        self.slot = args.slot
        self.owner_id = args.owner_id
        self.mandate = _mandate(args.owner_id, _now())

        heads_path = str(self.state / "owner_heads.json")
        if args.init:
            DurableHeadStore.create(
                heads_path,
                {
                    "view": "mandate_owner/v1",
                    "slots": {
                        self.slot: {
                            "owner_id": self.owner_id,
                            "public_key": args.owner_pubkey,
                        }
                    },
                },
            )
        self.view = MandateOwnerView(
            {
                self.slot: {
                    "owner_id": self.owner_id,
                    "public_key": args.owner_pubkey,
                }
            },
            durable_path=heads_path,
        )
        self.ledger = VerifiedCommitLedger(self.state / "commit_ledger.json")

        # Fresh test keys per worker process (receipt-minting only).
        self.gate_key = Ed25519PrivateKey.generate()
        self.source_key = Ed25519PrivateKey.generate()
        self.witness_key = Ed25519PrivateKey.generate()
        self.source_method = "did:example:distributed-stop-source#key-1"
        self.store = TrustStore.from_mapping(
            {
                "keys": {
                    self.source_method: {
                        "public_key": public_key_hex(self.source_key),
                        "roles": ["source"],
                        "independence": "operator",
                        "controller": "distributed-stop-source",
                    },
                    public_key_hex(self.witness_key): {
                        "public_key": public_key_hex(self.witness_key),
                        "roles": ["outcome"],
                        "independence": "receiver",
                        "controller": "distributed-stop-receiver",
                    },
                }
            }
        )
        self.admissions_path = self.state / "admissions.jsonl"

    # -- inbox ----------------------------------------------------------

    def cmd_poll(self, payload: dict) -> dict:
        outcomes = []
        for path in sorted(self.inbox.glob("*.json")):
            record = json.loads(path.read_text(encoding="utf-8"))
            now = _now()
            try:
                admission = self.view.admit(record, self.mandate, now=now)
                outcome = {
                    "file": path.name,
                    "admitted": True,
                    "state": admission.get("state"),
                    "sequence": admission.get("sequence"),
                }
                with self.admissions_path.open("a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "file": path.name,
                                "state": admission.get("state"),
                                "sequence": admission.get("sequence"),
                                "payload_hash": admission.get("head_hash"),
                                "admitted_at": _iso(now),
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
            except Exception as exc:  # harness: record, do not crash
                outcome = {
                    "file": path.name,
                    "admitted": False,
                    "error": f"{type(exc).__name__}:{exc}",
                }
            outcomes.append(outcome)
            path.unlink()
        return {"outcomes": outcomes}

    # -- receipt issuance (mirrors tests/test_stop_standing_integration) --

    def _issue(self, case: str):
        now = _now()
        root = self.state
        artifact = root / f"{case}.json"
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
        session = SessionLedger(root / f"{case}-sessions.json")
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
            witness_id="distributed-stop-receiver",
            rollback_supported=True,
            key=self.witness_key,
        )
        settings = {
            "content_sha256": sha256_hex(b"approved payload"),
            "mode": "create_new",
        }
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
                "policy_id": "distributed-stop.receiver-policy",
                "version": "1",
                "require_declared_coverage": True,
                "require_outcome_witness": True,
                "required_evidence_ids": ["result"],
                "evidence_assertions": [
                    {
                        "evidence_id": "result",
                        "path": "approved",
                        "op": "equals",
                        "value": True,
                    }
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
                    }
                },
            }
        )
        code = sha256_hex(f"one-use:{case}".encode("utf-8"))[:64]
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": f"request-{case}",
            "action_type": "tool_call",
            "claim": "The exact receiver-approved action may execute once.",
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
            issuer_id="distributed-stop-test-gate",
            decision_path=root / f"{case}-decisions.jsonl",
            session_ledger=session,
            base_dir=root,
            now=now,
        )
        action["policy_hash"] = policy.policy_hash
        return receipt, action, code

    def cmd_attempt(self, payload: dict) -> dict:
        case = str(payload["case"])
        now = _now()
        receipt, action, code = self._issue(case)
        marker = self.effects / f"{case}.json"

        def executor():
            marker.write_text(
                json.dumps({"case": case, "committed": True}, sort_keys=True),
                encoding="utf-8",
            )
            return {"effect": case}

        result = self.ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[public_key_hex(self.gate_key)],
            executor=executor,
            now=now,
            attempt_label=case,
            final_authority_check=owner_mandate_stop_check(
                self.view, self.slot, now=now
            ),
        )
        state = self.ledger.read_state()
        attempt = state["attempts"][-1]
        final = attempt.get("standing_final_check_v1") or {}
        return {
            "case": case,
            "authorized": result["authorized"],
            "reason_codes": result.get("reason_codes", []),
            "execution_status": result.get("execution_status"),
            "effect_observed": marker.exists(),
            "commit_seq": attempt.get("commit_seq"),
            "attempt_result": attempt.get("result"),
            "standing": final.get("standing"),
            "terminal": final.get("terminal"),
            "head_seq": final.get("head_seq"),
            "stop_effective_seq": attempt.get("stop_effective_seq"),
            "path_verdict": (attempt.get("path_verdict_v1") or {}).get("verdict"),
            "path_ordering": (attempt.get("path_verdict_v1") or {}).get("ordering"),
        }

    def cmd_status(self, payload: dict) -> dict:
        now = _now()
        return {
            "status": self.view.status(self.slot, now=now),
            "head_seq": self.view.head_sequence(self.slot),
            "head_hash": self.view.head_hash(self.slot),
        }

    def run(self) -> None:
        (self.res_dir / "ready").write_text("ready\n", encoding="utf-8")
        seen: set[str] = set()
        handlers = {
            "poll": self.cmd_poll,
            "attempt": self.cmd_attempt,
            "status": self.cmd_status,
        }
        while True:
            progressed = False
            for path in sorted(self.cmd_dir.glob("cmd_*.json")):
                if path.name in seen:
                    continue
                seen.add(path.name)
                progressed = True
                cmd = json.loads(path.read_text(encoding="utf-8"))
                name = str(cmd.get("cmd"))
                if name == "shutdown":
                    (self.res_dir / path.name.replace("cmd_", "res_")).write_text(
                        json.dumps({"ok": True, "shutdown": True}) + "\n",
                        encoding="utf-8",
                    )
                    return
                try:
                    result = handlers[name](cmd)
                    result = {"ok": True, **result}
                except Exception as exc:
                    result = {"ok": False, "error": f"{type(exc).__name__}:{exc}"}
                (self.res_dir / path.name.replace("cmd_", "res_")).write_text(
                    json.dumps(result, sort_keys=True) + "\n", encoding="utf-8"
                )
            if not progressed:
                time.sleep(0.05)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--inbox-dir", required=True)
    parser.add_argument("--cmd-dir", required=True)
    parser.add_argument("--res-dir", required=True)
    parser.add_argument("--slot", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--owner-pubkey", required=True)
    parser.add_argument("--init", action="store_true")
    args = parser.parse_args()
    Worker(args).run()


if __name__ == "__main__":
    main()
