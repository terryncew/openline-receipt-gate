from __future__ import annotations

import hashlib
import json
import time
import uuid
from json import JSONDecodeError
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_any(value: Any) -> str:
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    if isinstance(value, str):
        return sha256_text(value)
    return sha256_json(value)


def _parse_receipts(path: str | Path) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], bool, bool]:
    """Parse JSONL receipts without throwing.

    Returns:
      receipts, errors, missing, empty
    """
    p = Path(path)
    if not p.exists():
        return [], [{"reason": "missing_receipt_file", "line_number": None}], True, False

    text = p.read_text(encoding="utf-8")
    if not text.strip():
        return [], [{"reason": "empty_receipt_chain", "line_number": None}], False, True

    receipts: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except JSONDecodeError as exc:
            errors.append({
                "reason": "json_parse_error",
                "line_number": line_number,
                "message": exc.msg,
                "position": exc.pos,
            })
            continue

        if not isinstance(item, dict):
            errors.append({
                "reason": "json_receipt_not_object",
                "line_number": line_number,
            })
            continue

        receipts.append(item)

    if not receipts and not errors:
        errors.append({"reason": "empty_receipt_chain", "line_number": None})
        return [], errors, False, True

    return receipts, errors, False, False


def load_receipts(path: str | Path) -> List[Dict[str, Any]]:
    """Load valid JSONL receipt objects.

    Malformed lines are omitted here. Use verify_chain() to detect parse errors.
    """
    receipts, _errors, _missing, _empty = _parse_receipts(path)
    return receipts


def last_hash(path: str | Path) -> Optional[str]:
    chain = verify_chain(path)
    if not chain["valid"]:
        return None
    receipts = load_receipts(path)
    return receipts[-1].get("receipt_hash") if receipts else None


def make_receipt(
    *,
    path: str | Path,
    action_type: str,
    claim: str,
    evidence_hash: Optional[str],
    result_hash: Optional[str],
    status: str,
    decision: str,
    policy_flags: List[str],
    next_use_note: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    parent_hash = last_hash(path)
    receipt = {
        "schema": "openline.receipt_gate.v0.1.1",
        "receipt_id": str(uuid.uuid4()),
        "parent_hash": parent_hash,
        "timestamp": time.time(),
        "action_type": action_type,
        "claim": claim,
        "evidence_hash": evidence_hash,
        "result_hash": result_hash,
        "status": status,
        "decision": decision,
        "policy_flags": policy_flags,
        "next_use_note": next_use_note,
        "metadata": metadata or {},
    }
    receipt["receipt_hash"] = sha256_json({k: v for k, v in receipt.items() if k != "receipt_hash"})
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(receipt, sort_keys=True, ensure_ascii=False) + "\n")
    return receipt


def verify_chain(path: str | Path) -> Dict[str, Any]:
    receipts, parse_errors, missing, empty = _parse_receipts(path)
    errors: List[Dict[str, Any]] = list(parse_errors)

    prev = None
    if not parse_errors:
        for i, r in enumerate(receipts):
            if r.get("parent_hash") != prev:
                errors.append({
                    "index": i,
                    "receipt_id": r.get("receipt_id"),
                    "reason": "parent_hash_mismatch",
                })
            expected = sha256_json({k: v for k, v in r.items() if k != "receipt_hash"})
            if r.get("receipt_hash") != expected:
                errors.append({
                    "index": i,
                    "receipt_id": r.get("receipt_id"),
                    "reason": "receipt_hash_mismatch",
                })
            prev = r.get("receipt_hash")

    return {
        "path": str(path),
        "valid": not errors,
        "count": len(receipts),
        "errors": errors,
        "missing": missing,
        "empty": empty,
        "last_hash": prev if not errors else None,
    }


def summarize_badge(path: str | Path) -> Dict[str, Any]:
    chain = verify_chain(path)

    if chain["missing"] or chain["empty"]:
        return {
            "path": str(path),
            "badge": "NO_BADGE",
            "review_required": True,
            "reason": "empty_or_missing_receipt_chain",
            "counts": {"COMMIT": 0, "QUARANTINE": 0, "NO_BADGE": 0},
            "policy_flags": {},
            "chain": chain,
        }

    if not chain["valid"]:
        return {
            "path": str(path),
            "badge": "INVALID_CHAIN",
            "review_required": True,
            "reason": "receipt chain failed verification",
            "counts": {"COMMIT": 0, "QUARANTINE": 0, "NO_BADGE": 0},
            "policy_flags": {},
            "chain": chain,
        }

    receipts = load_receipts(path)
    counts = {"COMMIT": 0, "QUARANTINE": 0, "NO_BADGE": 0}
    flags: Dict[str, int] = {}
    for r in receipts:
        d = r.get("decision")
        if d in counts:
            counts[d] += 1
        for flag in r.get("policy_flags", []):
            flags[flag] = flags.get(flag, 0) + 1

    if counts["NO_BADGE"] > 0:
        badge = "NO_BADGE"
        review_required = True
        reason = "one or more actions lacked required proof"
    elif counts["QUARANTINE"] > 0:
        badge = "REVIEW"
        review_required = True
        reason = "one or more actions were quarantined"
    elif counts["COMMIT"] > 0:
        badge = "PASS"
        review_required = False
        reason = "all gated actions committed with required proof"
    else:
        badge = "NO_BADGE"
        review_required = True
        reason = "empty_or_missing_receipt_chain"

    return {
        "path": str(path),
        "badge": badge,
        "review_required": review_required,
        "reason": reason,
        "counts": counts,
        "policy_flags": flags,
        "chain": chain,
    }


def review_packet(path: str | Path) -> Dict[str, Any]:
    badge = summarize_badge(path)

    if badge["badge"] in {"INVALID_CHAIN", "NO_BADGE"} and badge["chain"]["count"] == 0:
        return {
            "badge": badge,
            "review_items": [{
                "receipt_id": None,
                "action_type": None,
                "claim": None,
                "decision": badge["badge"],
                "status": "review_required",
                "policy_flags": [badge["reason"]],
                "receipt_hash": None,
                "next_use_note": "No trusted receipt chain is available. Do not badge this run.",
            }],
        }

    receipts = load_receipts(path)
    review_items = [
        {
            "receipt_id": r.get("receipt_id"),
            "action_type": r.get("action_type"),
            "claim": r.get("claim"),
            "decision": r.get("decision"),
            "status": r.get("status"),
            "policy_flags": r.get("policy_flags", []),
            "receipt_hash": r.get("receipt_hash"),
            "next_use_note": r.get("next_use_note"),
        }
        for r in receipts
        if r.get("decision") in {"QUARANTINE", "NO_BADGE"}
    ]

    if badge["badge"] == "INVALID_CHAIN":
        review_items.insert(0, {
            "receipt_id": None,
            "action_type": None,
            "claim": None,
            "decision": "INVALID_CHAIN",
            "status": "review_required",
            "policy_flags": [e["reason"] for e in badge["chain"]["errors"]],
            "receipt_hash": None,
            "next_use_note": "Receipt file failed verification. Treat downstream badge as invalid.",
        })

    return {
        "badge": badge,
        "review_items": review_items,
    }
