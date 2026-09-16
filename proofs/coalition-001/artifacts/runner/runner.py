#!/usr/bin/env python3
"""COALITION-001 frozen outcome-producing runner.

Invoke exactly once, after the contract and all artifacts are sealed.
Scientific contact begins with this invocation. After contact there is no
seed swap, bound change, actor substitution, easier action sequence, altered
negative control, receiver-topology change, threshold movement, or rescue
rerun.

The runner is fully deterministic: frozen logical time, fixed identifiers,
fixed nonces, no randomness.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)  # so `src` and `tests` import as packages

from src import mandates
from src.receiver import Receiver, COMMITTED, REFUSED
from tests import protected_tests

PASS = "PASS_COALITION_001_MANDATE_SCOPED_BOUND_ENFORCED"
FAIL = "FAIL_COALITION_001_SPLIT_CONSEQUENCE_BYPASS"
INCONCLUSIVE = "INCONCLUSIVE_COALITION_001_EXECUTION_FAILURE"

MAX_EARNED_CLAIM = ("Within the controlled receiver set, splitting one "
                    "originating bounded authority across the two frozen actor "
                    "authorities did not increase the cumulative authority "
                    "available under that origin.")

SEALED_ARTIFACTS = [
    "frozen/COALITION-001-contract.md",
    "src/__init__.py",
    "src/mandates.py",
    "src/ledger.py",
    "src/receiver.py",
    "runner/runner.py",
    "tests/protected_tests.py",
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_baseline_arm():
    """Frozen baseline: the same two valid actions evaluated independently
    under per-action authorization with no cumulative origin state."""
    r = Receiver("baseline")
    auth_a = mandates.mint_authorization("actor-A", "cred-A", 60,
                                         "compute.dispatch", "base-nA1", "base-iA1")
    auth_b = mandates.mint_authorization("actor-B", "cred-B", 60,
                                         "compute.dispatch", "base-nB1", "base-iB1")
    out_a = r.request(auth_a)
    out_b = r.request(auth_b)
    snap = r.ledger.snapshot()
    return {
        "a_outcome": out_a["outcome"],
        "b_outcome": out_b["outcome"],
        "committed_O": snap["committed"].get(mandates.ORIGIN_O, 0),
        "entries": snap["entries"],
    }


def run_treatment_arm():
    """Frozen treatment: atomic cumulative accounting against origin O."""
    r = Receiver("treatment")
    auth_a = mandates.mint_authorization("actor-A", "cred-A", 60,
                                         "compute.dispatch", "treat-nA1", "treat-iA1")
    auth_b = mandates.mint_authorization("actor-B", "cred-B", 60,
                                         "compute.dispatch", "treat-nB1", "treat-iB1")
    out_a = r.request(auth_a)
    out_b = r.request(auth_b)  # must be refused: 60 + 60 > 100, no partial rewrite
    snap = r.ledger.snapshot()
    entries_o = [e for e in snap["entries"]
                 if e["origin_id"] == mandates.ORIGIN_O]
    return {
        "receiver": r,
        "a_outcome": out_a["outcome"],
        "b_outcome": out_b["outcome"],
        "b_code": out_b.get("code"),
        "b_refusal_receipt_recorded": any(
            x.get("code") == "ORIGIN_BOUND_EXCEEDED"
            and x.get("actor_id") == "actor-B" for x in snap["refusals"]),
        "committed_O": snap["committed"].get(mandates.ORIGIN_O, 0),
        "entries_O": entries_o,
        "auth_a_for_replay": auth_a,
    }


def run_o2_control(receiver):
    """Mandatory negative control: O2 keeps its own 100-unit bound."""
    auth_o2 = mandates.mint_authorization("actor-O2-1", "cred-O2-1", 60,
                                          "compute.dispatch", "treat-nO2", "treat-iO2")
    out = receiver.request(auth_o2)
    snap = receiver.ledger.snapshot()
    committed_o = snap["committed"].get(mandates.ORIGIN_O, 0)
    committed_o2 = snap["committed"].get(mandates.ORIGIN_O2, 0)
    return {
        "o2_outcome": out["outcome"],
        "committed_O": committed_o,
        "committed_O2": committed_o2,
        "o2_available": mandates.BOUND - committed_o2,
    }


def run_replay_probe(receiver, auth_a):
    """Observational: exact replay of A's consumed authorization must stay
    blocked and must not move the ledger."""
    before = receiver.ledger.snapshot()["committed"].get(mandates.ORIGIN_O, 0)
    out = receiver.request(auth_a)
    after = receiver.ledger.snapshot()["committed"].get(mandates.ORIGIN_O, 0)
    return {
        "replay_outcome": out["outcome"],
        "replay_code": out.get("code"),
        "committed_O_before": before,
        "committed_O_after": after,
        "ledger_unchanged": before == after,
    }


def assign_verdict(obs):
    # Rule 1: completed run and all protected tests green.
    if not obs["completed"]:
        return INCONCLUSIVE, "rule-1: runner did not complete"
    failed = [t for t in obs["protected_tests"] if not t["passed"]]
    if failed:
        return INCONCLUSIVE, "rule-1: protected tests failed: %s" % (
            ",".join(t["name"] for t in failed))
    # Rule 2: the frozen baseline must demonstrate the split-consequence
    # exposure (both 60-unit effects commit independently -> 120).
    b = obs["arms"]["baseline"]
    if not (b["a_outcome"] == COMMITTED and b["b_outcome"] == COMMITTED
            and b["committed_O"] == 120):
        return INCONCLUSIVE, ("rule-2: baseline did not demonstrate the "
                              "split-consequence exposure")
    # Integrity: the replay probe must show the pre-existing invariant held.
    rp = obs["arms"]["replay_probe"]
    if not (rp["replay_outcome"] == REFUSED and rp["ledger_unchanged"]
            and rp["committed_O_after"] == 60):
        return INCONCLUSIVE, ("integrity: replay probe failed; apparatus "
                              "invariant broken, observations cannot "
                              "establish the property")
    t = obs["arms"]["treatment"]
    # Rule 3: treatment must keep O at or below 100.
    if t["committed_O"] > mandates.BOUND:
        return FAIL, "rule-3: treatment committed %d > bound 100 for O" % (
            t["committed_O"],)
    # Rule 4: the frozen success condition, exactly.
    if t["committed_O"] != 60:
        return FAIL, "rule-4: treatment committed_O=%d, expected exactly 60" % (
            t["committed_O"],)
    if t["b_outcome"] != REFUSED or t["b_code"] != "ORIGIN_BOUND_EXCEEDED" \
            or not t["b_refusal_receipt_recorded"]:
        return FAIL, "rule-4: B's request was not refused with a refusal receipt"
    if any(e["units"] != 60 for e in t["entries_O"]):
        return FAIL, "rule-4: partial (non-60) commit detected"
    # Rule 5: the independent O2 control must remain unaffected.
    c = obs["arms"]["control_O2"]
    if c["o2_outcome"] != COMMITTED or c["committed_O2"] != 60:
        return FAIL, "rule-5: O2 control did not commit its 60 units"
    if c["o2_available"] != 40 or c["committed_O"] != 60:
        return FAIL, "rule-5: O consumption leaked into O2's authority"
    # Rule 6: everything held.
    return PASS, "rule-6: all frozen conditions met"


def main():
    artifact_hashes = {p: sha256_file(os.path.join(BASE, p))
                       for p in SEALED_ARTIFACTS}
    obs = {
        "experiment": "COALITION-001",
        "question": ("Given one receiver-recognized originating authority O "
                     "with cumulative bound B, can multiple distinct "
                     "authorities derived from O cause committed mechanically "
                     "observable consequence whose sum exceeds B?"),
        "run_utc": datetime.now(timezone.utc).isoformat(),
        "contract_sha256": artifact_hashes["frozen/COALITION-001-contract.md"],
        "artifact_hashes": artifact_hashes,
        "frozen_parameters": {
            "origin_O": mandates.ORIGIN_O,
            "origin_O2": mandates.ORIGIN_O2,
            "bound_B": mandates.BOUND,
            "a_units": 60, "b_units": 60, "o2_units": 60,
            "no_partial_rewrite": True,
        },
        "actor_condition": {
            "a_and_b_distinct_credentials": mandates.actor_credentials_distinct(),
            "note": ("A and B are distinct authority-bearing descendants of O "
                     "(distinct actor ids, credentials, secrets); the "
                     "treatment ledger keys on origin O only."),
        },
        "completed": False,
    }
    try:
        baseline = run_baseline_arm()
        treatment = run_treatment_arm()
        control_o2 = run_o2_control(treatment["receiver"])
        replay_probe = run_replay_probe(treatment["receiver"],
                                        treatment["auth_a_for_replay"])
        obs["arms"] = {
            "baseline": baseline,
            "treatment": {k: v for k, v in treatment.items()
                          if k not in ("receiver", "auth_a_for_replay")},
            "control_O2": control_o2,
            "replay_probe": replay_probe,
        }
        obs["protected_tests"] = protected_tests.run_all()
        obs["completed"] = True
    except Exception as exc:  # noqa: BLE001 - any crash -> INCONCLUSIVE
        obs["error"] = "%s: %s" % (type(exc).__name__, exc)

    verdict, reason = assign_verdict(obs)
    obs["verdict"] = verdict
    obs["verdict_reason"] = reason
    if verdict == PASS:
        obs["max_earned_claim"] = MAX_EARNED_CLAIM

    out_path = os.path.join(BASE, "evidence", "COALITION-001-observations.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(obs, f, indent=2, sort_keys=True)
    print("verdict: %s" % verdict)
    print("reason: %s" % reason)
    print("observations: %s" % out_path)
    print("baseline committed_O: %s" % obs["arms"]["baseline"]["committed_O"])
    print("treatment committed_O: %s" % obs["arms"]["treatment"]["committed_O"])
    print("treatment B outcome: %s (%s)"
          % (obs["arms"]["treatment"]["b_outcome"],
             obs["arms"]["treatment"]["b_code"]))
    print("O2 committed: %s available: %s"
          % (obs["arms"]["control_O2"]["committed_O2"],
             obs["arms"]["control_O2"]["o2_available"]))
    print("protected tests: %d/%d green"
          % (sum(1 for t in obs["protected_tests"] if t["passed"]),
             len(obs["protected_tests"])))


if __name__ == "__main__":
    main()
