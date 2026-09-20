"""OWNER-CONTROL-002 appraiser.

Independently re-derives every preregistered expectation from the frozen
run evidence (issued records, admissions journals, snapshots, assessments)
without trusting the driver's in-memory assertions. Reports counts and
zero-VIOLATION verdict. Harness only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
EXP = REPO / "experiments" / "owner-control-002"
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
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def main() -> int:
    prereg_path = EXP / "preregistration.json"
    check("preregistration_frozen", prereg_path.exists())
    prereg = load_json(prereg_path)
    check("prereg_label", prereg.get("experiment_label") == "OWNER-CONTROL-002")
    check("prereg_baseline",
          prereg.get("baseline_main_sha") == "41631b7c09f1d5c319d3a2e98685577fa99e52ef")

    keys = load_json(RUN / "keys.json")
    A, B, C, W = keys["A"], keys["B"], keys["C"], keys["W"]
    issued = {p.stem: load_json(p) for p in (RUN / "issued").glob("*.json")}

    # -- case 1: owner authority works ------------------------------------
    for name, signer, state, seq in (
        ("a_active_seq1", "A", "ACTIVE", 1),
        ("a_stop_seq2", "A", "REVOKED", 2),
    ):
        rec = issued[name]
        valid, reason = verify_olp_signature(rec)
        check(f"case1_{name}_signature_valid", valid is True, str(reason))
        check(f"case1_{name}_signed_by_A",
              rec["signature"]["public_key"].lower() == A.lower())
        check(f"case1_{name}_state", rec["state"] == state)
        check(f"case1_{name}_sequence", rec["sequence"] == seq)
    check("case1_stop_chains_auth",
          issued["a_stop_seq2"]["predecessor_hash"] == issued["a_active_seq1"]["payload_hash"])

    journals = {r: read_jsonl(RUN / "receivers" / r / "admissions.jsonl")
                for r in ("r1", "r2")}

    def admitted(r: str, fname: str):
        return [e for e in journals[r]
                if e.get("file") == fname and e.get("admitted") is True]

    def refused_with(r: str, fname: str, code: str) -> bool:
        return any(e.get("file") == fname and e.get("admitted") is False
                   and code in str(e.get("error", ""))
                   for e in journals[r])

    for r in ("r1", "r2"):
        check(f"{r}_a_auth1_admitted", len(admitted(r, "a_active_seq1.json")) == 1)
        check(f"{r}_a_stop2_admitted", len(admitted(r, "a_stop_seq2.json")) == 1)
        o = admitted(r, "a_stop_seq2.json")[0] if admitted(r, "a_stop_seq2.json") else {}
        check(f"{r}_stop_state_revoked", o.get("detail", {}).get("state") == "REVOKED")

    # -- case 2: worker cannot self-elevate --------------------------------
    w_stop = issued["w_stop_seq3"]
    valid, reason = verify_olp_signature(w_stop)
    check("case2_w_signature_valid", valid is True, str(reason))
    check("case2_w_signed_by_W",
          w_stop["signature"]["public_key"].lower() == W.lower())
    check("case2_w_names_owner", w_stop["owner_id"] == "owner")
    check("case2_w_is_stop", w_stop["state"] == "REVOKED")
    check("case2_w_chains_head",
          w_stop["predecessor_hash"] == issued["a_stop_seq2"]["payload_hash"])
    for r in ("r1", "r2"):
        check(f"{r}_w_stop_refused",
              refused_with(r, "w_stop_seq3.json",
                           "mandate_authorization_owner_key_mismatch"))
    # ordered admitted mandate-authorization sequence per receiver: the
    # refusal must leave no trace in the admitted sequence (no head
    # movement), and W's attempt must precede the succession admission.
    expected_r2 = ["a_active_seq1.json", "a_stop_seq2.json",
                  "b_active_seq3.json", "b_stop_seq4.json",
                  "b_active_seq5.json"]
    expected_r1 = expected_r2 + ["b_active_seq6.json"]
    for r, expected in (("r1", expected_r1), ("r2", expected_r2)):
        auths = [e for e in journals[r]
                 if e.get("kind") == "mandate_authorization"
                 and e.get("admitted") is True]
        files = [e.get("file") for e in auths]
        check(f"{r}_admitted_auth_order", files == expected, str(files))
        w_idx = next((i for i, e in enumerate(journals[r])
                      if e.get("file") == "w_stop_seq3.json"), None)
        s_idx = next((i for i, e in enumerate(journals[r])
                      if e.get("file") == "a_to_b_seq1.json"
                      and e.get("admitted") is True), None)
        check(f"{r}_worker_attempt_pre_succession",
              w_idx is not None and s_idx is not None and w_idx < s_idx)

    # -- case 3: succession ------------------------------------------------
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
    for r in ("r1", "r2"):
        succ = [e for e in journals[r]
                if e.get("kind") == "trust_root_succession"
                and e.get("admitted") is True]
        check(f"{r}_exactly_one_succession", len(succ) == 1, f"found {len(succ)}")
        if succ:
            check(f"{r}_succession_seq1",
                  succ[0]["detail"]["succession_sequence"] == 1)
            check(f"{r}_succession_event_hash_matches",
                  succ[0]["detail"]["event_hash"] == ab["payload_hash"])
    post3 = RUN / "snapshots" / "case_3_post_succession"
    for r in ("r1", "r2"):
        tr = load_json(post3 / f"{r}_trust_roots.json").get("heads", {})
        entry = tr.get("owner/default", {})
        sched = entry.get("schedule", [])
        check(f"{r}_post3_schedule_len_2", len(sched) == 2, str(len(sched)))
        check(f"{r}_post3_current_is_B",
              sched[-1].get("public_key", "").lower() == B.lower() if sched else False)
        check(f"{r}_post3_genesis_is_A",
              sched[0].get("public_key", "").lower() == A.lower() if sched else False)

    # -- case 4: successor can act -----------------------------------------
    for name, state, seq in (
        ("b_active_seq3", "ACTIVE", 3),
        ("b_stop_seq4", "REVOKED", 4),
        ("b_active_seq5", "ACTIVE", 5),
    ):
        rec = issued[name]
        valid, reason = verify_olp_signature(rec)
        check(f"case4_{name}_signature_valid", valid is True, str(reason))
        check(f"case4_{name}_signed_by_B",
              rec["signature"]["public_key"].lower() == B.lower())
        for r in ("r1", "r2"):
            got = admitted(r, f"{name}.json")
            check(f"{r}_{name}_admitted", len(got) == 1)
            if got:
                check(f"{r}_{name}_state", got[0]["detail"]["state"] == state)
                check(f"{r}_{name}_sequence", got[0]["detail"]["sequence"] == seq)

    # -- case 5: superseded owner cannot return ----------------------------
    a_stop6 = issued["a_stop_seq6"]
    valid, reason = verify_olp_signature(a_stop6)
    check("case5_a_stop6_signature_valid", valid is True, str(reason),
          "SIGNATURE_VALID must hold even as standing fails")
    check("case5_a_stop6_signed_by_A",
          a_stop6["signature"]["public_key"].lower() == A.lower())
    for r in ("r1", "r2"):
        check(f"{r}_a_stop6_refused",
              refused_with(r, "a_stop_seq6.json",
                           "mandate_authorization_owner_key_mismatch"))
    # case-5 no-head-movement is already covered by the ordered admitted
    # sequence checks above (the refused a_stop_seq6 leaves no trace).

    # -- case 6: restart ---------------------------------------------------
    pre6 = RUN / "snapshots" / "case_6_pre_restart"
    post6 = RUN / "snapshots" / "case_6_post_restart"
    r1_post_tr = load_json(post6 / "r1_trust_roots.json").get("heads", {})
    entry = r1_post_tr.get("owner/default", {})
    sched = entry.get("schedule", [])
    check("restart_schedule_len_2", len(sched) == 2, str(len(sched)))
    check("restart_current_is_B",
          sched[-1].get("public_key", "").lower() == B.lower() if sched else False)
    check("restart_genesis_is_A",
          sched[0].get("public_key", "").lower() == A.lower() if sched else False)
    check("restart_seq_1", entry.get("sequence") == 1)
    check("restart_pre_post_same_schedule",
          load_json(pre6 / "r1_trust_roots.json").get("heads", {}).get(
              "owner/default", {}).get("schedule") == sched)
    r1_j = journals["r1"]
    check("restart_b_auth6_admitted",
          any(e.get("file") == "b_active_seq6.json" and e.get("admitted") is True
              for e in r1_j))
    check("restart_a_auth7_refused",
          any(e.get("file") == "a_active_seq7.json"
              and e.get("admitted") is False
              and "mandate_authorization_owner_key_mismatch" in str(e.get("error", ""))
              for e in r1_j))
    b6 = issued["b_active_seq6"]
    check("restart_b6_signed_by_B",
          b6["signature"]["public_key"].lower() == B.lower())

    # -- case 7: history survives ------------------------------------------
    assess = load_json(RUN / "case_7_assessments.json")
    a_era, b_era = assess["a_era"], assess["b_era"]
    check("a_era_verified", a_era["verified"] is True)
    check("a_era_not_current", a_era["current"] is False)
    check("a_era_historical_key",
          a_era["reason_codes"] == ["trust_root_succession_historical_key"])
    check("a_era_key_is_A", a_era["historical_public_key"].lower() == A.lower())
    check("b_era_verified_current",
          b_era["verified"] is True and b_era["current"] is True)

    # -- final atomicity ----------------------------------------------------
    final = RUN / "snapshots" / "final"
    for r in ("r1", "r2"):
        tr = load_json(final / f"{r}_trust_roots.json").get("heads", {})
        entry = tr.get("owner/default", {})
        sched = entry.get("schedule", [])
        check(f"{r}_final_one_current",
              len(sched) >= 1 and
              sched[-1].get("public_key", "").lower() == B.lower())
        check(f"{r}_final_no_second_current",
              len([p for p in sched
                   if p.get("public_key", "").lower() == B.lower()]) == 1)

    results = load_json(RUN / "case_results.json")
    check("driver_recorded_7_cases", len(results) == 7, f"{len(results)}")

    appraisal = {
        "experiment": "OWNER-CONTROL-002",
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
