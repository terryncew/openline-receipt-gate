"""Independently replay signed receiver evidence against one read-only snapshot.

This verifier imports codecs, never the Receiver or its dispatch implementation.
It requires externally trusted public roots, checks each successful authorization
and protected mutation, then compares the reconstructed state with SQLite rows.
Denial reasons are signed receiver testimony, not a complete semantic proof.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from olp_gate.crypto import (
    olp_canonical_json,
    sha256_hex,
    strict_json_loads,
    verify_olp_signature,
)

from examples.independent_receiver_kit import formats


_ROOTS = ("owner_id", "owner_key", "slot_id", "receiver_id", "outcome_key")
_TABLES = ("settings", "history", "documents", "consumed", "decisions")
_DECISION_FIELDS = {
    "schema", "seq", "mode", "receiver_id", "verdict", "reason", "subject",
    "request_hash", "policy_hash", "owner_head", "owner_sequence", "observed_at",
    "effect_at", "policy", "documents_before", "documents_after", "payload_hash",
    "signature",
}


def _canonical(value: Any) -> str:
    return olp_canonical_json(value).decode("ascii")


def _digest(value: Any) -> str:
    return sha256_hex(olp_canonical_json(value))


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _integer(value: Any, reason: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, reason)
    return value


def _snapshot(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Read all evidence from the same SQLite snapshot without creating a DB."""
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as database:
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only=ON")
        database.execute("BEGIN")
        rows = {
            table: [dict(row) for row in database.execute(f"SELECT * FROM {table}")]
            for table in _TABLES
        }
        database.execute("COMMIT")
        return rows


def _policy(value: Any) -> dict[str, Any]:
    _require(isinstance(value, dict), "decision_policy_not_object")
    _require(set(value) == {
        "version", "tool", "target", "max_document_chars", "freshness_seconds",
    }, "decision_policy_shape_invalid")
    _integer(value["version"], "policy_version_invalid")
    _require(isinstance(value["tool"], str) and bool(value["tool"]), "policy_tool_invalid")
    _require(isinstance(value["target"], str) and bool(value["target"]), "policy_target_invalid")
    _integer(value["max_document_chars"], "policy_document_limit_invalid")
    _integer(value["freshness_seconds"], "policy_freshness_invalid")
    return value


def verify(state: str | Path, config: Mapping[str, Any], mode: str, codec=None) -> dict[str, Any]:
    """Return a machine-readable verdict; no private key or receiver import."""
    codec = codec or formats
    counts = {"decisions": 0, "allows": 0, "denies": 0, "authority_accepts": 0,
              "history": 0, "documents": 0, "consumed": 0}
    result: dict[str, Any] = {
        "valid": False, "errors": [], "mode": mode, "counts": counts,
        "trust_assumptions": [
            "External configuration pins the owner and receiver public roots.",
            "Receiver signatures attest its local clock and policy snapshots.",
            "The captured SQLite snapshot is the database being evaluated.",
            "Whole-database rollback and omitted suffixes need an external checkpoint.",
            "Denial reasons are signed testimony; successful effects are replayed.",
        ],
    }
    try:
        codec._mode(mode)
        rows = _snapshot(state)
        _require(len(rows["settings"]) == 1, "settings_row_count_invalid")
        settings = rows["settings"][0]
        _require(settings["id"] == 1 and settings["mode"] == mode, "settings_mode_invalid")
        saved_config = strict_json_loads(settings["body"])
        _require(isinstance(saved_config, dict), "settings_config_invalid")
        for name in _ROOTS:
            _require(saved_config[name] == config[name], f"settings_root_mismatch:{name}")
        # Local administration may have changed policy after the last request.
        _policy(saved_config["policy"])

        quarantined = False
        history: list[dict[str, Any]] = []
        documents: dict[str, dict[str, str]] = {}
        consumed: dict[str, dict[str, str]] = {}
        head: dict[str, Any] | None = None
        packet: dict[str, Any] | None = None
        decisions = sorted(rows["decisions"], key=lambda row: row["seq"])
        for expected_sequence, row in enumerate(decisions, start=1):
            decision = strict_json_loads(row["body"])
            _require(isinstance(decision, dict) and set(decision) == _DECISION_FIELDS,
                     "decision_shape_invalid")
            signature = decision["signature"]
            _require(isinstance(signature, dict)
                     and signature.get("public_key") == config["outcome_key"],
                     "decision_receiver_key_not_pinned")
            valid, reason = verify_olp_signature(decision)
            _require(valid, f"decision_signature_invalid:{reason}")
            for name in ("seq", "owner_sequence", "documents_before", "documents_after"):
                _integer(decision[name], f"decision_{name}_invalid")
            _require(row["seq"] == expected_sequence == decision["seq"], "decision_sequence_gap")
            _require(decision["schema"] == "receiver-kit-decision/v1", "decision_schema_invalid")
            _require(decision["mode"] == mode, "decision_mode_mismatch")
            _require(decision["receiver_id"] == config["receiver_id"], "decision_receiver_mismatch")
            envelope = strict_json_loads(row["request"])
            _require(isinstance(envelope, dict) and set(envelope) == {"path", "request"},
                     "recorded_request_shape_invalid")
            route, request = envelope["path"], envelope["request"]
            request_hash = _digest(request)
            _require(decision["request_hash"] == request_hash, "decision_request_hash_mismatch")
            policy = _policy(decision["policy"])
            _require(decision["policy_hash"] == _digest(policy), "decision_policy_hash_mismatch")
            historical_config = {**config, "policy": policy}
            at = _integer(decision["observed_at"], "decision_time_invalid")
            _require(decision["documents_before"] == len(documents), "decision_before_count_mismatch")
            verdict = decision["verdict"]

            if verdict in {"ACCEPT","ALLOW"}:
                _require(not quarantined,"admission_after_fork_quarantine")
            if verdict == "ACCEPT":
                _require(route == "/authority", "authority_accept_route_invalid")
                parsed = codec.parse_head(mode, request, historical_config, at)
                if head is not None and parsed["hash"] == head["hash"]:
                    _require(decision["reason"] == "authority_duplicate_no_refresh",
                             "authority_duplicate_reason_mismatch")
                    # A repeated credential never changes accepted_at or expiry.
                else:
                    if hasattr(codec,"transition"):
                        codec.transition(head,parsed)
                    else:
                        _require(parsed["seq"] == (head["seq"] + 1 if head else 1),
                                 "authority_sequence_invalid")
                        _require(parsed["prev"] == (head["hash"] if head else None),
                                 "authority_predecessor_invalid")
                        _require(head is not None or parsed["state"] == "ACTIVE",
                                 "initial_authority_not_active")
                        if parsed["state"] == "REVOKED" and head is not None:
                            _require(parsed["mandate_hash"] == head["mandate_hash"],
                                     "revocation_target_mismatch")
                    _require(decision["reason"] == "authority_admitted", "authority_reason_mismatch")
                    head, packet = parsed, request
                    history.append({"seq": parsed["seq"], "hash": parsed["hash"],
                                    "packet": _canonical(request), "accepted_at": at})
                _require(decision["effect_at"] is None, "authority_effect_time_invalid")
                counts["authority_accepts"] += 1

            elif verdict == "ALLOW":
                _require(route == "/submit", "allow_route_invalid")
                _require(policy["tool"] == "intake.submit", "allow_policy_disallows_operation")
                _require(isinstance(request, dict) and set(request) == {"proof"},
                         "submit_request_shape_invalid")
                _require(head is not None and packet is not None, "allow_without_authority")
                _require(head["state"] == "ACTIVE", "allow_after_revocation")
                _require(0 <= at - head["issued"] < policy["freshness_seconds"]
                         and at < head["expires"], "allow_with_stale_authority")
                claims = codec.decode_call(mode, request["proof"], head["subject"], historical_config, at)
                _require(claims["head_hash"] == head["hash"], "allow_head_hash_mismatch")
                _require(claims["policy_hash"] == _digest(policy), "allow_policy_hash_mismatch")
                effect, document = claims["effect"], claims["document"]
                _require(not codec.assess(mode, packet, effect, at), "allow_effect_outside_mandate")
                _require(isinstance(document, dict) and set(document) == {"record_id", "text"},
                         "allow_document_shape_invalid")
                record_id = document["record_id"]
                _require(isinstance(record_id, str) and bool(record_id), "allow_record_id_invalid")
                _require(isinstance(document["text"], str)
                         and len(document["text"]) <= policy["max_document_chars"],
                         "allow_document_outside_policy")
                _require(effect["value_cents"] == 0 and effect["disclosures"] == []
                         and effect["delegatee"] is None
                         and effect["effect_id"] == record_id and effect["action_type"] == "send"
                         and effect["target"] == policy["target"], "allow_protected_action_mismatch")
                effect_at = _integer(decision["effect_at"], "allow_effect_time_invalid")
                _require(at <= effect_at < claims["exp"] and effect_at < head["expires"]
                         and effect_at - head["issued"] < policy["freshness_seconds"],
                         "allow_expired_before_effect")
                nonce = claims["jti"]
                _require(nonce not in consumed and record_id not in documents,
                         "allow_replays_consumed_authorization_or_record")
                _require(all(item["proof_hash"] != request_hash for item in consumed.values()),
                         "allow_duplicate_proof")
                _require(decision["subject"] == claims["sub"], "allow_subject_mismatch")
                _require(decision["reason"] == "local_document_committed", "allow_reason_mismatch")
                consumed[nonce] = {"nonce": nonce, "proof_hash": request_hash}
                documents[record_id] = {"id": record_id, "body": _canonical(document),
                                        "request_hash": request_hash}
                counts["allows"] += 1

            elif verdict == "DENY":
                _require(decision["effect_at"] is None, "denial_effect_time_invalid")
                if hasattr(codec,"transition") and decision["reason"]=="authority_fork_quarantined":
                    if not quarantined:
                        candidate=codec.parse_head(mode,request,historical_config,at)
                        try:
                            codec.transition(head,candidate)
                        except ValueError as exc:
                            _require(str(exc)=="authority_fork_quarantined","invalid_quarantine_reason")
                        else:
                            raise ValueError("quarantine_without_fork")
                    quarantined=True
                counts["denies"] += 1
            else:
                raise ValueError("decision_verdict_invalid")

            _require(decision["owner_head"] == (head["hash"] if head else None)
                     and decision["owner_sequence"] == (head["seq"] if head else 0),
                     "decision_owner_frontier_mismatch")
            _require(decision["documents_after"] == len(documents), "decision_after_count_mismatch")
            counts["decisions"] += 1

        _require(bool(saved_config.get("_quarantined",False))==quarantined,"quarantine_state_mismatch")
        _require(sorted(rows["history"], key=lambda row: row["seq"]) == history,
                 "durable_history_differs_from_signed_replay")
        _require(sorted(rows["documents"], key=lambda row: row["id"])
                 == sorted(documents.values(), key=lambda row: row["id"]),
                 "durable_documents_differ_from_signed_replay")
        _require(sorted(rows["consumed"], key=lambda row: row["nonce"])
                 == sorted(consumed.values(), key=lambda row: row["nonce"]),
                 "durable_consumption_differs_from_signed_replay")
        counts.update(history=len(history), documents=len(documents), consumed=len(consumed))
        result["valid"] = True
    except (ValueError, TypeError, KeyError, AttributeError, sqlite3.Error, OSError) as exc:
        result["errors"].append(str(exc) or type(exc).__name__)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True,
                        help="externally trusted public receiver configuration")
    parser.add_argument("--mode", choices=["openline", "conventional"], required=True)
    args = parser.parse_args()
    try:
        config = strict_json_loads(args.config.read_text(encoding="utf-8"))
        result = verify(args.state, config, args.mode)
    except (ValueError, TypeError, OSError) as exc:
        result = {"valid": False, "errors": [str(exc) or type(exc).__name__], "mode": args.mode}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
