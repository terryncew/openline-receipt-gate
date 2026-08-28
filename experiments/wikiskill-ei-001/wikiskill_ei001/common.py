from __future__ import annotations
import copy, hashlib, json
from typing import Any, Mapping

ENTITIES = ("pattern-left", "pattern-right")
SKILLS = ("skill-left", "skill-right")

def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

def clone(value: Any) -> Any:
    return copy.deepcopy(value)

def preserve_all() -> dict[str, dict[str, str]]:
    return {"patterns": {p:"PRESERVE" for p in ENTITIES}, "skills": {s:"PRESERVE" for s in SKILLS}}

def unresolved_all() -> dict[str, dict[str, str]]:
    return {"patterns": {p:"UNRESOLVED_PROVENANCE" for p in ENTITIES}, "skills": {s:"UNRESOLVED_PROVENANCE" for s in SKILLS}}

def reopen_all() -> dict[str, dict[str, str]]:
    return {"patterns": {p:"REOPEN" for p in ENTITIES}, "skills": {s:"REOPEN" for s in SKILLS}}

def historical_hash(state: Mapping[str, Any]) -> str:
    return sha256_json(state)
