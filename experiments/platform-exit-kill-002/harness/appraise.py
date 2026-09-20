"""PLATFORM-EXIT-KILL-002 independent appraiser.

Reads ONLY the frozen run/ evidence. Re-derives every preregistered
expectation without trusting the driver: signature validity, admission
journal consistency, path verdicts (via olp_gate.stop_standing.
derive_path_verdicts), snapshot prefix-preservation, effect marker
presence/absence, worker attestations, historical verification via
MandateOwnerView.assess(), and the receipt-distinction table.

Exit 0 with zero VIOLATIONs = appraiser pass. Any violation -> exit 1.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HARNESS = Path(__file__).resolve().parent
EXP = REPO / "experiments" / "platform-exit-kill-002"
for _p in (str(REPO), str(HARNESS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from olp_gate.crypto import verify_olp_signature  # noqa: E402
from olp_gate.gateway import verify_decision_receipt  # noqa: E402
from olp_gate.mandate_owner import MandateOwnerView  # noqa: E402
from olp_gate.stop_standing import derive_path_verdict  # noqa: E402
import gate_path as gp  # noqa: E402

RUN = EXP / "run"
SLOT_A = "agent-a/platform-exit-job"
SLOT_B = "agent-b/platform-exit-job"

EXPECTED = {
    # attempt_id: (case, agent_id, authorized_expected, slot, head_seq_or_None)
    "c1-a1": ("case_1", "agent-a", True, SLOT_A, 1),
    "c1-a2": ("case_1", "agent-a", True, SLOT_A, 1),
    "c3-a1": ("case_3", "agent-a", False, SLOT_A, 2),
    "c3-a2": ("case_3", "agent-a", False, SLOT_A, 2),
    "c3-a3": ("case_3", "agent-a", False, SLOT_A, 2),
    "c4-b1": ("case_4", "agent-b", True, SLOT_B, 1),
    "c4-b2": ("case_4", "agent-b", True, SLOT_B, 1),
    "c5-a1": ("case_5", "agent-a", False, SLOT_A, 2),
    "c5-a2": ("case_5", "agent-a", False, SLOT_A, 2),
}
ORDER = list(EXPECTED)


class Appraiser:
    def __init__(self) -> None:
        self.violations: list[str] = []
        self.checks = 0
        self.run_now = None

    def check(self, cond: bool, label: str) -> None:
        self.checks += 1
        if not cond:
            self.violations.append(label)

    def load(self) -> dict:
        d: dict = {}
        d["keys"] = json.loads((RUN / "keys.json").read_text(encoding="utf-8"))
        d["mandates"] = json.loads((RUN / "mandates.json").read_text(encoding="utf-8"))
        d["slots"] = json.loads((RUN / "slots.json").read_text(encoding="utf-8"))
        d["admissions"] = json.loads(
            (RUN / "admissions.jsonl").read_text(encoding="utf-8")
        )["admissions"]
        d["case_results"] = json.loads(
            (RUN / "case_results.json").read_text(encoding="utf-8")
        )
        state_dir = RUN / "receiver_state"
        d["ledger"] = json.loads(
            (state_dir / "commit_ledger.json").read_text(encoding="utf-8")
        )
        d["outcomes"] = {}
        for p in sorted((RUN / "worker_outcomes").glob("*.json")):
            d["outcomes"][p.stem] = json.loads(p.read_text(encoding="utf-8"))
        d["snapshots"] = {}
        for p in sorted((RUN / "snapshots").glob("snapshot_*.json")):
            d["snapshots"][p.stem.replace("snapshot_", "")] = json.loads(
                p.read_text(encoding="utf-8")
            )
        d["issued"] = {}
        for p in sorted((RUN / "issued").glob("*.json")):
            d["issued"][p.stem] = json.loads(p.read_text(encoding="utf-8"))
        d["state_dir"] = state_dir
        return d

    # -- sections -----------------------------------------------------

    def check_owner_records(self, d: dict) -> None:
        owner_pub = d["keys"]["owner"]
        for name, record in d["issued"].items():
            valid, reason = verify_olp_signature(record)
            self.check(valid is True, f"SIGNATURE_VALID failed for issued/{name}: {reason}")
            signer = (record.get("signature") or {}).get("public_key", "")
            self.check(signer.lower() == owner_pub.lower(),
                       f"issued/{name} not signed by owner O")
        # Expected admission records exist.
        names = set(d["issued"])
        self.check(names == {"a_active_seq1", "a_revoked_seq2", "b_active_seq1"},
                   f"issued record set wrong: {sorted(names)}")

    def check_admission_journal(self, d: dict) -> None:
        adm = d["admissions"]
        by_slot: dict[str, list[dict]] = {}
        for entry in adm:
            by_slot.setdefault(entry["slot"], []).append(entry)
        self.check(set(by_slot) == {SLOT_A, SLOT_B},
                   f"admission slots wrong: {sorted(by_slot)}")
        exp_seq = {SLOT_A: [1, 2], SLOT_B: [1]}
        exp_state = {SLOT_A: ["ACTIVE", "REVOKED"], SLOT_B: ["ACTIVE"]}
        prev_hash: dict[str, str | None] = {}
        for slot, entries in by_slot.items():
            seqs = [e["sequence"] for e in entries]
            self.check(seqs == exp_seq[slot], f"{slot} sequences {seqs}")
            states = [e["state"] for e in entries]
            self.check(states == exp_state[slot], f"{slot} states {states}")
            for e in entries:
                issued_name = {"a_active_seq1", "a_revoked_seq2", "b_active_seq1"}
                # predecessor chain
                rec = None
                for name, record in d["issued"].items():
                    if record["payload_hash"] == e["payload_hash"]:
                        rec = record
                self.check(rec is not None, f"admission {e} has no issued record")
                if rec is not None:
                    self.check(rec.get("predecessor_hash") == prev_hash.get(slot),
                               f"{slot} seq {e['sequence']} predecessor break")
                    self.check(rec["slot_id"] == slot, f"slot mismatch in {e}")
                    prev_hash[slot] = rec["payload_hash"]
                    # mandate binding: the admitted mandate hash must equal the
                    # mandate for that slot's agent.
                    agent = "agent-a" if slot == SLOT_A else "agent-b"
                    want = d["mandates"]["mandate_a" if agent == "agent-a" else "mandate_b"]
                    from olp_gate.mandate import MandateSpec
                    self.check(
                        rec["mandate_hash"] == MandateSpec.from_mapping(want).mandate_hash,
                        f"{slot} mandate binding wrong",
                    )
                    self.check(e["signer"].lower() == d["keys"]["owner"].lower(),
                               f"{slot} admission signer not O")

    def check_no_succession(self, d: dict) -> None:
        view = MandateOwnerView(d["slots"],
                                durable_path=str(d["state_dir"] / "owner_heads.json"))
        for slot in (SLOT_A, SLOT_B):
            self.check(view.succession_sequence(slot) == 0,
                       f"{slot} succession_sequence != 0")
            self.check(len(view.key_schedule(slot)) == 1,
                       f"{slot} key schedule length != 1")
            self.check(view.current_owner(slot)["public_key"].lower()
                       == d["keys"]["owner"].lower(),
                       f"{slot} current owner is not O")
        # No succession schema anywhere in the frozen evidence.
        hits = []
        for p in sorted(RUN.rglob("*.json")) + sorted(RUN.rglob("*.jsonl")):
            try:
                text = p.read_text(encoding="utf-8")
            except Exception:
                continue
            if "owner_trust_root_succession" in text:
                hits.append(str(p.relative_to(RUN)))
        self.check(not hits, f"succession schema present in: {hits}")

    def check_ledger_and_verdicts(self, d: dict) -> dict:
        attempts = d["ledger"].get("attempts", [])
        self.check([a.get("commit_seq") for a in attempts] == list(range(1, 10)),
                   "commit_seq not 1..9 in order")
        self.check([a.get("attempt_label") for a in attempts] == ORDER,
                   "attempt order wrong")
        by_label = {a["attempt_label"]: a for a in attempts}
        # Per-slot re-derivation: the STOP lived on slot A; slot B's
        # admissions must not leak into B-era verdicts (and vice versa).
        slot_admissions: dict[str, list[dict]] = {SLOT_A: [], SLOT_B: []}
        for entry in d["admissions"]:
            slot_admissions[entry["slot"]].append(entry)
        for label in ORDER:
            _case, _agent, _auth, slot, _seq = EXPECTED[label]
            item = derive_path_verdict(by_label[label], slot_admissions[slot])
            stored = by_label[label].get("path_verdict_v1")
            if stored is None:
                # Observation-time verdict covers refusals only; a committed
                # attempt must re-derive to verdict None (PRE_STOP_COMMIT /
                # NO_STOP_ADMITTED is the appraiser's ordering classification).
                self.check(item["verdict"] is None,
                           f"{label}: derived verdict {item} for committed attempt")
            else:
                self.check(
                    stored.get("verdict") == item["verdict"]
                    and stored.get("ordering") == item["ordering"]
                    and stored.get("stop_effective_seq") == item["stop_effective_seq"],
                    f"{label}: stored verdict {stored} != derived {item}",
                )
        # Per-attempt expectations.
        for label, (case, agent, authorized, slot, head_seq) in EXPECTED.items():
            a = by_label[label]
            final = a.get("standing_final_check_v1") or {}
            self.check((a.get("result") == "AUTHORIZED") == authorized,
                       f"{label}: authorized mismatch")
            if authorized:
                self.check(a.get("execution_status") == "completed",
                           f"{label}: not completed")
                self.check(final.get("allowed") is True
                           and final.get("standing") == "ACTIVE",
                           f"{label}: final check {final}")
            else:
                self.check(a.get("execution_status") == "not_started",
                           f"{label}: executed despite refusal")
                self.check("owner_standing_revoked" in (a.get("reason_codes") or []),
                           f"{label}: reasons {a.get('reason_codes')}")
                self.check(final.get("allowed") is False
                           and final.get("standing") == "REVOKED",
                           f"{label}: final check {final}")
                self.check(final.get("terminal") is True,
                           f"{label}: not terminal")
                v = a.get("path_verdict_v1") or {}
                self.check(v.get("verdict") == "STOPPED"
                           and v.get("ordering") == "STOP_FIRST"
                           and v.get("stop_effective_seq") == 2,
                           f"{label}: path verdict {v}")
            self.check(final.get("head_seq") == head_seq,
                       f"{label}: head_seq {final.get('head_seq')} != {head_seq}")
        return by_label

    def check_snapshots(self, d: dict, by_label: dict) -> None:
        final_attempts = d["ledger"]["attempts"]
        for name, snap in d["snapshots"].items():
            prefix = final_attempts[: len(snap["attempts"])]
            self.check(snap["attempts"] == prefix,
                       f"snapshot {name} is not a byte-equal prefix of final journal")
        s1 = d["snapshots"].get("case1", {})
        self.check(s1.get("slot_status", {}).get(SLOT_A) == "ACTIVE",
                   "case1 snapshot: slot A not ACTIVE")
        s2 = d["snapshots"].get("case2", {})
        self.check(s2.get("slot_status", {}).get(SLOT_A) == "REVOKED",
                   "case2 snapshot: slot A not REVOKED")
        s5 = d["snapshots"].get("case5", {})
        self.check(s5.get("head_seq", {}).get(SLOT_A) == 2
                   and s5.get("head_seq", {}).get(SLOT_B) == 1,
                   "case5 snapshot: head moved")

    def check_markers(self, d: dict) -> None:
        effects = d["state_dir"] / "effects"
        for label, (case, agent, authorized, _slot, _seq) in EXPECTED.items():
            marker = effects / f"{label}.json"
            if authorized:
                self.check(marker.exists(), f"{label}: marker missing")
                if marker.exists():
                    body = json.loads(marker.read_text(encoding="utf-8"))
                    self.check(body.get("agent_id") == agent
                               and body.get("committed") is True,
                               f"{label}: marker attribution wrong: {body}")
            else:
                self.check(not marker.exists(), f"{label}: marker exists despite refusal")

    def check_outcomes_and_attestations(self, d: dict, by_label: dict) -> None:
        seen: dict[str, dict] = {}
        for plan_name, bundle in d["outcomes"].items():
            for outcome in bundle["outcomes"]:
                label = outcome["attempt_id"]
                self.check(label in EXPECTED, f"unexpected outcome {label}")
                seen[label] = outcome
                case, agent, authorized, slot, _seq = EXPECTED[label]
                self.check(outcome.get("agent_id") == agent,
                           f"{label}: outcome agent {outcome.get('agent_id')}")
                self.check(outcome.get("slot") == slot, f"{label}: outcome slot")
                self.check(outcome.get("worker_error") is None,
                           f"{label}: worker_error {outcome.get('worker_error')}")
                self.check(outcome.get("preflight_allowed") is True,
                           f"{label}: preflight not allowed {outcome.get('preflight_reasons')}")
                journal = by_label[label]
                self.check(outcome.get("commit_seq") == journal.get("commit_seq"),
                           f"{label}: outcome/journal commit_seq mismatch")
                # Attestation under the agent's own public key.
                key_name = "worker_a" if agent == "agent-a" else "worker_b"
                ok, reason = gp.check_attestation(
                    outcome.get("attestation") or {},
                    agent,
                    d["keys"][key_name],
                    outcome.get("effect_hash"),
                )
                self.check(ok, f"{label}: attestation bad: {reason}")
        self.check(set(seen) == set(EXPECTED), "outcome coverage incomplete")
        # Agent key separation.
        self.check(d["keys"]["worker_a"] != d["keys"]["worker_b"],
                   "worker keys not distinct")
        self.check(d["keys"]["source_a"] != d["keys"]["source_b"],
                   "source keys not distinct")
        # The replay attempt really re-presented the pre-STOP payload.
        r1 = seen["c5-a2"].get("effect_hash")
        r0 = seen["c1-a1"].get("effect_hash")
        self.check(r1 == r0 and r1 is not None,
                   "c5-a2 is not a genuine replay of the c1-a1 payload")

    def check_decision_receipts(self, d: dict) -> None:
        gate_pub = d["keys"]["gate"]
        for label in ORDER:
            p = d["state_dir"] / "decisions" / f"{label}.jsonl"
            self.check(p.exists(), f"{label}: decision receipt missing")
            if p.exists():
                receipt = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
                res = verify_decision_receipt(receipt, [gate_pub])
                self.check(res.get("errors") == [], f"{label}: decision receipt errors {res}")

    def check_historical_verification(self, d: dict) -> dict:
        view = MandateOwnerView(d["slots"],
                                durable_path=str(d["state_dir"] / "owner_heads.json"))
        seq1 = d["issued"]["a_active_seq1"]
        assessment = view.assess(seq1, d["mandates"]["mandate_a"])
        self.check(assessment["verified"] is True, "seq1 not verified")
        self.check(assessment["current"] is False, "seq1 assessed as current")
        self.check(view.status(SLOT_A) == "REVOKED",
                   "historical verification moved slot A off REVOKED")
        self.check(view.status(SLOT_B) == "ACTIVE", "slot B not ACTIVE")
        # A-era and B-era head records verify as historical/current facts.
        return {
            "a_seq1_assessment": assessment,
            "slot_a_status": view.status(SLOT_A),
            "slot_b_status": view.status(SLOT_B),
        }

    def distinctions_table(self, d: dict, by_label: dict) -> list[dict]:
        rows = []
        for label, (case, agent, authorized, slot, _seq) in EXPECTED.items():
            a = by_label[label]
            final = a.get("standing_final_check_v1") or {}
            rows.append({
                "attempt": label,
                "case": case,
                "agent": agent,
                "SIGNATURE_VALID": True,  # decision receipt verified in check_decision_receipts
                "HISTORICALLY_VALID": "n/a (effect attempt, not an authorization)",
                "CURRENT_AUTHORITY": final.get("standing"),
                "AUTHORIZED_FOR_THIS_ACTION": final.get("allowed"),
                "ACCEPTED": a.get("result") == "AUTHORIZED",
                "EFFECTED": a.get("execution_status") == "completed",
            })
        return rows

    def run(self) -> dict:
        d = self.load()
        self.check(d["case_results"].get("failure") in (None, False),
                   f"driver reported failure: {d['case_results'].get('failure')}")
        for case_entry in d["case_results"].get("case_results", []):
            self.check(case_entry["case"].startswith("case_"),
                       f"case result malformed: {case_entry}")
        self.check_owner_records(d)
        self.check_admission_journal(d)
        self.check_no_succession(d)
        by_label = self.check_ledger_and_verdicts(d)
        self.check_snapshots(d, by_label)
        self.check_markers(d)
        self.check_outcomes_and_attestations(d, by_label)
        self.check_decision_receipts(d)
        hist = self.check_historical_verification(d)
        report = {
            "experiment": "PLATFORM-EXIT-KILL-002",
            "checks": self.checks,
            "violations": self.violations,
            "passed": not self.violations,
            "historical_verification": hist,
            "receipt_distinctions": self.distinctions_table(d, by_label),
        }
        (RUN / "appraise_report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return report


def main() -> None:
    if not RUN.exists():
        raise SystemExit(f"no run dir: {RUN}")
    app = Appraiser()
    report = app.run()
    print(f"appraiser: {report['checks']} checks, "
          f"{len(report['violations'])} violations")
    for v in report["violations"]:
        print(f"VIOLATION: {v}")
    if report["violations"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
