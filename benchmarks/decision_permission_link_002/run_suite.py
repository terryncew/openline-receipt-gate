from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from olp_gate.authority_link import assess_permission, compile_link, compile_obligation, effect_hash
from benchmarks.decision_permission_link_002.capability_control import (
    CapabilityLedger, assess_challenge, compile_challenge, mint_token,
)
from benchmarks.decision_permission_link_002.scenario import H, NOW, POLICY, evidence_for, proposal

RECEIVER_KEY = bytes.fromhex("71" * 32)


def dpl_decision(p, ev, *, state_hash=None, obligation=None):
    if obligation is None:
        result = compile_link(POLICY, p, ev, now=NOW, current_state_hash=state_hash or p["state_hash"])
        return result["assessment"]["decision"], result
    assessment = assess_permission(
        POLICY, p, ev, now=NOW, current_state_hash=state_hash or p["state_hash"], obligation=obligation,
    )
    return assessment["decision"], {"obligation": obligation, "assessment": assessment, "verified_commit_settings": None}


def cap_decision(p, ev, *, state_hash=None, challenge=None):
    challenge = challenge or compile_challenge(POLICY, p)
    result = assess_challenge(challenge, p, ev, now=NOW, current_state_hash=state_hash or p["state_hash"])
    return result["decision"], {"challenge": challenge, "assessment": result}


def normalized(value: str) -> str:
    return "ALLOW" if value in {"COMMIT_ELIGIBLE", "ALLOW"} else "BLOCK"


def compare_case(case_id, p, ev, *, state_hash=None, old_obligation=None, old_challenge=None):
    dpl, dpl_art = dpl_decision(p, ev, state_hash=state_hash, obligation=old_obligation)
    try:
        cap, cap_art = cap_decision(p, ev, state_hash=state_hash, challenge=old_challenge)
    except PermissionError:
        cap, cap_art = "BLOCK", {"assessment": {"reason_codes": ["capability_route_not_authorized"]}}
    return {
        "case_id": case_id,
        "dpl_decision": dpl,
        "capability_decision": cap,
        "normalized_dpl": normalized(dpl),
        "normalized_capability": normalized(cap),
        "parity": normalized(dpl) == normalized(cap),
        "dpl_reasons": dpl_art["assessment"]["reason_codes"],
        "capability_reasons": cap_art["assessment"]["reason_codes"],
    }


def main() -> int:
    cases = []
    clean = proposal()
    clean_ev = evidence_for(clean)
    cases.append(compare_case("clean_tier1_immediate", clean, clean_ev))

    rationale = proposal(advisory="completely-different-rationale")
    cases.append(compare_case("rationale_mutation_same_effect", rationale, evidence_for(rationale)))

    swapped = proposal(producer="optimizer-B", model="local-quantized-model", advisory="utility-01")
    cases.append(compare_case("model_swap_same_effect", swapped, evidence_for(swapped)))

    tier2 = proposal(vendor="VENDOR-BETA", tier=2, advisory="avoid-18000-late-fee")
    cases.append(compare_case("better_but_unauthorized_tier2_early", tier2, evidence_for(tier2, tier1=False)))

    self_grant = proposal()
    cases.append(compare_case("self_granted_tier1_evidence", self_grant, evidence_for(self_grant, self_granted=True)))

    stale = proposal()
    cases.append(compare_case("stale_liquidity", stale, evidence_for(stale, liquidity_age=61)))

    revoked = proposal()
    cases.append(compare_case("revoked_liquidity", revoked, evidence_for(revoked, revoked_liquidity=True)))

    original = proposal(state="state-1")
    old_obligation = compile_obligation(POLICY, original)
    old_challenge = compile_challenge(POLICY, original)
    cases.append(compare_case(
        "state_drift_after_compilation", original, evidence_for(original),
        state_hash=H("state-2"), old_obligation=old_obligation, old_challenge=old_challenge,
    ))

    downgrade = proposal(vendor="VENDOR-BETA", tier=2, immediate=False, advisory="lower-ranked-safe-choice")
    cases.append(compare_case("lower_ranked_authorized_net30", downgrade, evidence_for(downgrade, tier1=False, liquidity=False)))

    wrong_target = proposal()
    wrong_target["target"] = "account:attacker"
    cases.append(compare_case("unauthorized_target", wrong_target, []))

    # Post-authorization mutation and replay are tested on the strong capability
    # baseline here and on actual Verified Commit in the repo integration test.
    cap_challenge = compile_challenge(POLICY, clean)
    cap_assessment = assess_challenge(cap_challenge, clean, clean_ev, now=NOW, current_state_hash=clean["state_hash"])
    token = mint_token(cap_challenge, cap_assessment, receiver_key=RECEIVER_KEY, now=NOW, nonce="ab"*32)
    ledger = CapabilityLedger.empty()
    mutated = deepcopy(clean)
    mutated["settings"]["vendor_id"] = "VENDOR-EVIL"
    mutation = ledger.execute_once(token, mutated, receiver_key=RECEIVER_KEY, current_state_hash=clean["state_hash"], now=NOW)
    first = ledger.execute_once(token, clean, receiver_key=RECEIVER_KEY, current_state_hash=clean["state_hash"], now=NOW)
    replay = ledger.execute_once(token, clean, receiver_key=RECEIVER_KEY, current_state_hash=clean["state_hash"], now=NOW)

    parity_count = sum(1 for case in cases if case["parity"])
    control_parity = parity_count == len(cases)
    integration_path = Path(__file__).resolve().parent / "results" / "verified_commit_integration.json"
    if integration_path.exists():
        integration = json.loads(integration_path.read_text(encoding="utf-8"))
    else:
        integration = {"passed": False, "status": "PENDING_CI"}
    execution_parity = all({
        "cap_mutation": mutation["authorized"] is False,
        "cap_once": first["authorized"] is True,
        "cap_replay": replay["authorized"] is False,
    }.values()) and integration.get("passed") is True
    if control_parity and execution_parity:
        final_status = "CAPABILITY_PARITY"
    elif integration.get("status") == "PENDING_CI":
        final_status = "PENDING_ACTUAL_VERIFIED_COMMIT_CI"
    else:
        final_status = "DPL_DISTINCT_SEAM_FOUND"
    report = {
        "schema": "openline.dpl002.comparison.v1",
        "experiment_id": "DPL-002",
        "title": "End-to-End Authority Acquisition Falsifier",
        "workflow": "B2B invoice settlement and liquidity routing",
        "baseline": "receiver-issued caveated bearer capability with exact-effect hash, state binding, expiry, one-use replay protection, and third-party discharge-style evidence",
        "cases": cases,
        "permission_stage_parity": {"matched": parity_count, "total": len(cases), "all_match": control_parity},
        "capability_execution_attacks": {
            "post_authorization_mutation_blocked": mutation["authorized"] is False,
            "exact_action_executes_once": first["authorized"] is True,
            "replay_blocked": replay["authorized"] is False,
        },
        "actual_verified_commit_integration": integration,
        "strong_falsifier": {
            "condition": "A standard caveated capability plus exact-action hashing/state/evidence caveats matches DPL on every permission and execution seam.",
            "permission_stage_triggered": control_parity,
            "final_status": final_status,
        },
        "interpretation_if_final_parity": "DPL is not a novel authorization primitive. Its remaining value is a receipt-native, receiver-owned application profile for compiling optimizer proposals into evidence-conditioned capability issuance and exact execution authorization.",
        "interpretation_if_dpl_separates": "Investigate the separating seam and show it cannot be reproduced with ordinary capability caveats before claiming a new primitive.",
    }
    out = Path(__file__).resolve().parent / "results" / "comparison.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if all(case["parity"] for case in cases) and all(report["capability_execution_attacks"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
