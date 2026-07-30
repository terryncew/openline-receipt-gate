from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .adapters.deterministic import DeterministicSuccessorAdapter
from .util import canonical_json, load_json, sha256_bytes


def load_exam(path: Path) -> dict[str, Any]:
    exam = load_json(path)
    if exam.get("schema") != "openline.half-life.exam.v1":
        raise ValueError("unsupported exam schema")
    questions = exam.get("questions")
    if not isinstance(questions, list) or not questions:
        raise ValueError("exam must contain questions")
    seen: set[str] = set()
    for question in questions:
        required = {"id", "kind", "target", "expected", "legitimate_completion"}
        if set(question) != required:
            raise ValueError("exam question field mismatch")
        if question["id"] in seen:
            raise ValueError("duplicate exam question id")
        seen.add(question["id"])
    return exam


def run_same_exam(
    full_history: Mapping[str, Any],
    verified_residue: Mapping[str, Any],
    exam: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    adapter = DeterministicSuccessorAdapter()
    exam_hash = sha256_bytes(canonical_json(exam))
    full = adapter.run_exam(full_history, exam)
    residue = adapter.run_exam(verified_residue, exam)
    if full["exam_hash"] != exam_hash or residue["exam_hash"] != exam_hash:
        raise AssertionError("successor conditions did not receive the identical exam")
    return full, residue
