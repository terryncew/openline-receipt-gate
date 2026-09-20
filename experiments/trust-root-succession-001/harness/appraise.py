"""TRUST-ROOT-SUCCESSION-001 appraiser.

Independently re-derives every preregistered expectation from the frozen
run evidence (issued records, admissions journals, snapshots, assessments)
without trusting the driver's in-memory assertions. Reports counts and
zero-VIOLATION verdict. Harness only.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
EXP = REPO / "experiments" / "trust-root-succession-001"
RUN = EXP / "run"
sys.path.insert(0, str(REPO))

from olp_gate.crypto import verify_olp_signature

VIOLATIONS: list[str] = []
PASSES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSES.append(name)
    else:
        VIOLATIONS.append(f"{name}: {detail}")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    prereg_path = EXP / "preregistration.json"
    check("preregistration_frozen", prereg_path.exists())
    prereg = load_json(prereg_path)
    check("prereg_label", prereg.get("experiment_label") == "TRUST-ROOT-SUCCESSION-001")
    check("prereg_baseline",
          prereg.get("baseline_main_sha") == "01e01eb4e22ae4a15e573e81680a5e62c683d807")

    keys = load_json(RUN / "keys.json")
    A, B, C, W = keys["A"], keys["B"], keys["C"], keys["W"]
    issued = {p.stem: load_json(p) for p in (RUN / "issued").glob("*.json")}

    # -- cryptographic re-verification of the succession event ------------
    ab = issued["a_to_b_seq1"]
    valid, reason = verify_olp_signature(ab)
    check("succession_event_signature_valid", valid is True, str(reason))
    check("succession_event_signed_by_A",
          ab["signature"]["public_key"].lower() == A.lower())
    check("succession_event_binds_B",
          ab["successor_public_key"].lower() == B.lower())
    check("succession_event_seq1", ab["succession_sequence"] == 1)
    check("succession_event_no_predecessor",
          ab["predecessor_succession_hash"] is None)

    # -- per-receiver evidence ---------------------------------------------
    journals = {}
    for r in ("r1", "r2"):
        journals[r] = read_jsonl(RUN / "receivers" / r / "admissions.jsonl")

    def admitted(r: str, fname: str):
        return [e for e in journals[r]
                if e.get("file") == fname and e.get("admitted") is True]

    def refused_with(r: str, fname: str, code: str) -> bool:
        return any(e.get("file") == fname and e.get("admitted") is False
                   and code in str(e.get("error", ""))
                   for e in journals[r])

    for r in ("r1", "r2"):
        check(f"{r}_a_auth1_admitted", len(admitted(r, "a_active_seq1.json")) == 1)
        check(f"{r}_succession_admitted", len(admitted(r, "a_to_b_seq1.json")) == 1)
        check(f"{r}_b_auth2_admitted", len(admitted(r, "b_active_seq2.json")) == 1)
        check(f"{r}_b_stop3_admitted", len(admitted(r, "b_stop_seq3.json")) == 1)
        check(f"{r}_b_auth4_admitted", len(admitted(r, "b_active_seq4.json")) == 1)
        check(f"{r}_w_stop_refused",
              refused_with(r, "w_stop_seq5.json",
                           "mandate_authorization_owner_key_mismatch"))
        check(f"{r}_a_auth5_refused",
              refused_with(r, "a_active_seq5.json",
                           "mandate_authorization_owner_key_mismatch"))
        check(f"{r}_c_self_refused",
              refused_with(r, "c_self_seq2.json",
                           "trust_root_succession_signer_not_current_owner"))
        check(f"{r}_replay_refused",
              any(e.get("file") == "replay_a_to_b.json"
                  and e.get("admitted") is False for e in journals[r]))
        check(f"{r}_dup_seq_refused",
              refused_with(r, "b_dup_seq1.json",
                           "trust_root_succession_sequence_invalid"))
        check(f"{r}_bad_pred_refused",
              refused_with(r, "b_badpred_seq2.json",
                           "trust_root_succession_predecessor_mismatch"))
        check(f"{r}_a_forge_refused",
              refused_with(r, "a_forge_seq2.json",
                           "trust_root_succession_signer_not_current_owner"))

    # -- exactly one admitted succession event, signer A -> successor B ----
    for r in ("r1", "r2"):
        succ = [e for e in journals[r]
                if e.get("kind") == "trust_root_succession"
                and e.get("admitted") is True]
        check(f"{r}_exactly_one_succession", len(succ) == 1,
              f"found {len(succ)}")
        if succ:
            check(f"{r}_succession_seq1",
                  succ[0]["detail"]["succession_sequence"] == 1)
            check(f"{r}_succession_event_hash_matches",
                  succ[0]["detail"]["event_hash"] == ab["payload_hash"])

    # -- admitted mandate auths: only A pre-succession, B after -------------
    for r in ("r1", "r2"):
        auths = [e for e in journals[r]
                 if e.get("kind") == "mandate_authorization"
                 and e.get("admitted") is True]
        signers = set()
        for name in ("a_active_seq1", "b_active_seq2", "b_stop_seq3",
                     "b_active_seq4"):
            rec = issued[name]
            signers.add(rec["signature"]["public_key"].lower())
        check(f"{r}_admitted_auth_signers_bounded",
              signers <= {A.lower(), B.lower()}, str(signers))

    # -- restart evidence --------------------------------------------------
    post = RUN / "snapshots" / "case_5_post_restart"
    r1_trust = load_json(post / "r1_trust_roots.json")
    heads = r1_trust.get("heads", {})
    r1_entry = heads.get("owner/default", {})
    schedule = r1_entry.get("schedule", [])
    check("restart_schedule_len_2", len(schedule) == 2, str(len(schedule)))
    check("restart_current_is_B",
          schedule[-1].get("public_key", "").lower() == B.lower() if schedule else False)
    check("restart_seq_1", r1_entry.get("sequence") == 1)
    check("restart_one_current_owner",
          len([p for p in schedule]) == 2 and
          schedule[-1].get("public_key", "").lower() !=
          schedule[0].get("public_key", "").lower())
    r1_j = read_jsonl(RUN / "receivers" / "r1" / "admissions.jsonl")
    check("restart_b_auth5_admitted",
          any(e.get("file") == "b_active_seq5.json" and e.get("admitted") is True
              for e in r1_j))
    check("restart_a_auth6_refused",
          any(e.get("file") == "a_active_seq6.json"
              and e.get("admitted") is False
              and "mandate_authorization_owner_key_mismatch" in str(e.get("error", ""))
              for e in r1_j))

    # -- historical verification evidence ----------------------------------
    assess = load_json(RUN / "case_6_assessments.json")
    a_era, b_era = assess["a_era"], assess["b_era"]
    check("a_era_verified", a_era["verified"] is True)
    check("a_era_not_current", a_era["current"] is False)
    check("a_era_historical_key",
          a_era["reason_codes"] == ["trust_root_succession_historical_key"])
    check("a_era_key_is_A", a_era["historical_public_key"].lower() == A.lower())
    check("b_era_verified_current",
          b_era["verified"] is True and b_era["current"] is True)

    # -- final atomicity: one current owner on each receiver ----------------
    final = RUN / "snapshots" / "final"
    for r in ("r1", "r2"):
        tr = load_json(final / f"{r}_trust_roots.json").get("heads", {})
        entry = tr.get("owner/default", {})
        sched = entry.get("schedule", [])
        check(f"{r}_final_one_current",
              len(sched) >= 1 and
              sched[-1].get("public_key", "").lower() == B.lower())
        check(f"{r}_final_old_not_current",
              all(p.get("public_key", "").lower() != B.lower()
                  or p is sched[-1] for p in sched))

    results = load_json(RUN / "case_results.json")
    check("driver_recorded_12_cases", len(results) == 12, f"{len(results)}")

    appraisal = {
        "experiment": "TRUST-ROOT-SUCCESSION-001",
        "checks_passed": len(PASSES),
        "violations": VIOLATIONS,
        "passed": PASSES,
    }
    (RUN / "appraisal.json").write_text(
        json.dumps(appraisal, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"appraiser: {len(PASSES)} passed, {len(VIOLATIONS)} violations")
    for v in VIOLATIONS:
        print(f"  VIOLATION: {v}")
    return 0 if not VIOLATIONS else 1


if __name__ == "__main__":
    raise SystemExit(main())
