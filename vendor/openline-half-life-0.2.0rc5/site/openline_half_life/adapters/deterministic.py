from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Mapping

from ..util import canonical_json, sha256_bytes


def _fresh(evidence: Mapping[str, Any], at_turn: int) -> bool:
    return at_turn - evidence["observed_turn"] <= evidence["expires_after_turns"]


class DeterministicSuccessorAdapter:
    """A disclosed, offline successor used for tests and the three-minute demo.

    It is not a universal model simulator. Full history resolves repeated facts
    by frequency then recency and reads constraints from the latest turn. The
    verified-residue packet reads only its receiver-verifiable fields.
    """

    name = "deterministic-successor-v1"

    def _full_fact(self, packet: Mapping[str, Any], slot: str) -> tuple[str | None, bool, str | None]:
        turns = packet["turns"]
        retirement_turn = packet["retirement_turn"]
        evidence_index = {
            item["id"]: item
            for turn in turns
            for item in turn["evidence"]
        }
        candidates: list[tuple[int, Mapping[str, Any]]] = []
        for turn in turns:
            for claim in turn["claims"]:
                if claim["slot"] == slot:
                    candidates.append((turn["turn"], claim))
        if not candidates:
            return None, False, None
        counts = Counter(str(claim["value"]) for _, claim in candidates)
        max_count = max(counts.values())
        winning_values = {value for value, count in counts.items() if count == max_count}
        turn_number, selected = max(
            ((turn_number, claim) for turn_number, claim in candidates if str(claim["value"]) in winning_values),
            key=lambda item: item[0],
        )
        refs = selected["evidence_refs"]
        stale = bool(refs) and any(
            ref not in evidence_index or not _fresh(evidence_index[ref], retirement_turn)
            for ref in refs
        )
        unsupported = selected["support_status"] != "supported" or stale
        source = f"turn:{turn_number}:claim:{selected['id']}"
        return str(selected["value"]), unsupported, source

    def _residue_fact(self, packet: Mapping[str, Any], slot: str) -> tuple[str | None, bool, str | None]:
        for claim in packet["supported_claims"]:
            if claim["slot"] == slot:
                return str(claim["value"]), False, f"residue:claim:{claim['id']}"
        return None, False, None

    def _constraint(self, packet: Mapping[str, Any], constraint_id: str) -> tuple[str | None, str | None]:
        if packet["handoff_type"] == "full_history":
            latest = packet["turns"][-1]
            for constraint in latest["constraints"]:
                if constraint["id"] == constraint_id and constraint["active"]:
                    return constraint["text"], f"turn:{latest['turn']}:constraint:{constraint_id}"
            return None, None
        for constraint in packet["current_constraints"]:
            if constraint["id"] == constraint_id and constraint["active"]:
                return constraint["text"], f"residue:constraint:{constraint_id}"
        return None, None

    def _completion(self, packet: Mapping[str, Any], outcome_id: str) -> tuple[str | None, str | None]:
        outcomes = []
        if packet["handoff_type"] == "full_history":
            outcomes = [outcome for turn in packet["turns"] for outcome in turn["outcomes"] if outcome["confirmed"]]
        else:
            outcomes = packet["confirmed_outcomes"]
        for outcome in reversed(outcomes):
            if outcome["id"] == outcome_id:
                return outcome["text"], f"outcome:{outcome_id}"
        return None, None

    def run_exam(self, packet: Mapping[str, Any], exam: Mapping[str, Any]) -> dict[str, Any]:
        answers: list[dict[str, Any]] = []
        for question in exam["questions"]:
            kind = question["kind"]
            unsupported = False
            source = None
            if kind == "fact":
                if packet["handoff_type"] == "full_history":
                    answer, unsupported, source = self._full_fact(packet, question["target"])
                else:
                    answer, unsupported, source = self._residue_fact(packet, question["target"])
            elif kind == "constraint":
                answer, source = self._constraint(packet, question["target"])
            elif kind == "completion":
                answer, source = self._completion(packet, question["target"])
            elif kind == "novel":
                answer = None
            else:
                raise ValueError(f"unsupported exam question kind: {kind}")
            correct = answer == question["expected"]
            constraint_violation = kind == "constraint" and not correct
            answers.append(
                {
                    "question_id": question["id"],
                    "kind": kind,
                    "answer": answer,
                    "expected": question["expected"],
                    "correct": correct,
                    "unsupported_claim": bool(unsupported),
                    "constraint_violation": constraint_violation,
                    "legitimate_completion": bool(question.get("legitimate_completion", False)),
                    "source": source,
                }
            )

        correct_count = sum(int(item["correct"]) for item in answers)
        error_count = len(answers) - correct_count
        legitimate = [item for item in answers if item["legitimate_completion"]]
        packet_bytes = len(canonical_json(packet))
        answer_bytes = len(canonical_json(answers))
        body = {
            "schema": "openline.half-life.exam-result.v1",
            "adapter": self.name,
            "handoff_type": packet["handoff_type"],
            "packet_hash": packet["packet_hash"],
            "exam_hash": sha256_bytes(canonical_json(exam)),
            "answers": answers,
            "metrics": {
                "question_count": len(answers),
                "correct_count": correct_count,
                "error_count": error_count,
                "accuracy_micros": correct_count * 1_000_000 // len(answers),
                "unsupported_claim_count": sum(int(item["unsupported_claim"]) for item in answers),
                "constraint_violation_count": sum(int(item["constraint_violation"]) for item in answers),
                "legitimate_completion_required": len(legitimate),
                "legitimate_completion_correct": sum(int(item["correct"]) for item in legitimate),
                "input_bytes": packet_bytes,
                "estimated_input_tokens": (packet_bytes + 3) // 4,
                "estimated_output_tokens": (answer_bytes + 3) // 4,
            },
        }
        return {**body, "result_hash": sha256_bytes(canonical_json(body))}
