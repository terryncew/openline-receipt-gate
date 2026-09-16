"""COALITION-001 protected existing tests.

These test pre-existing receiver behavior the treatment must not break.
All must be green for PASS_COALITION_001_MANDATE_SCOPED_BOUND_ENFORCED.
Each returns (name, passed, detail).
"""

from src import mandates
from src.receiver import Receiver, COMMITTED, REFUSED, UNCERTAIN_ABANDONED


def _auth(actor, cred, units, nonce, intent, action="compute.dispatch", **kw):
    return mandates.mint_authorization(actor, cred, units, action, nonce, intent, **kw)


def test_valid_single_action_commits():
    r = Receiver("treatment")
    out = r.request(_auth("actor-A", "cred-A", 60, "pt1-n1", "pt1-i1"))
    snap = r.ledger.snapshot()
    passed = (out["outcome"] == COMMITTED
              and snap["committed"].get(mandates.ORIGIN_O) == 60)
    return ("valid_single_action_commits", passed,
            "outcome=%s committed_O=%s" % (out["outcome"],
             snap["committed"].get(mandates.ORIGIN_O)))


def test_out_of_scope_refused():
    r = Receiver("treatment")
    out = r.request(_auth("actor-A", "cred-A", 60, "pt2-n1", "pt2-i1",
                          action="db.drop"))
    snap = r.ledger.snapshot()
    passed = (out["outcome"] == REFUSED and out["code"] == "OUT_OF_SCOPE"
              and snap["committed"].get(mandates.ORIGIN_O, 0) == 0)
    return ("out_of_scope_refused", passed,
            "outcome=%s code=%s committed_O=%s"
            % (out["outcome"], out.get("code"),
               snap["committed"].get(mandates.ORIGIN_O, 0)))


def test_exact_replay_blocked():
    r = Receiver("treatment")
    auth = _auth("actor-A", "cred-A", 60, "pt3-n1", "pt3-i1")
    first = r.request(auth)
    second = r.request(auth)  # exact replay
    snap = r.ledger.snapshot()
    passed = (first["outcome"] == COMMITTED
              and second["outcome"] == REFUSED
              and second["code"] == "AUTHORIZATION_ALREADY_CONSUMED"
              and snap["committed"].get(mandates.ORIGIN_O) == 60)
    return ("exact_replay_blocked", passed,
            "first=%s replay_code=%s committed_O=%s"
            % (first["outcome"], second.get("code"),
               snap["committed"].get(mandates.ORIGIN_O)))


def test_uncertain_effect_fail_closed_no_retry():
    r = Receiver("treatment")
    r.fault_after_check = True  # injected only here, never in scientific arms
    auth = _auth("actor-A", "cred-A", 60, "pt4-n1", "pt4-i1")
    out = r.request(auth)
    snap = r.ledger.snapshot()
    retry_same = r.request(auth)
    retry_fresh = r.request(_auth("actor-A", "cred-A", 60, "pt4-n2", "pt4-i1"))
    snap2 = r.ledger.snapshot()
    passed = (out["outcome"] == UNCERTAIN_ABANDONED
              and snap["committed"].get(mandates.ORIGIN_O, 0) == 0
              and retry_same["outcome"] == REFUSED
              and retry_fresh["outcome"] == REFUSED
              and retry_fresh["code"] == "FAIL_CLOSED_NO_RETRY"
              and snap2["committed"].get(mandates.ORIGIN_O, 0) == 0)
    return ("uncertain_effect_fail_closed_no_retry", passed,
            "outcome=%s retry_same=%s retry_fresh_code=%s committed_O=%s"
            % (out["outcome"], retry_same["outcome"],
               retry_fresh.get("code"),
               snap2["committed"].get(mandates.ORIGIN_O, 0)))


def test_o2_independent_of_o():
    r = Receiver("treatment")
    r.request(_auth("actor-A", "cred-A", 60, "pt5-n1", "pt5-i1"))
    o2 = r.request(_auth("actor-O2-1", "cred-O2-1", 60, "pt5-n2", "pt5-i2"))
    snap = r.ledger.snapshot()
    committed_o = snap["committed"].get(mandates.ORIGIN_O, 0)
    committed_o2 = snap["committed"].get(mandates.ORIGIN_O2, 0)
    passed = (o2["outcome"] == COMMITTED
              and committed_o == 60 and committed_o2 == 60
              and (mandates.BOUND - committed_o2) == 40)
    return ("o2_independent_of_o", passed,
            "o2_outcome=%s committed_O=%s committed_O2=%s o2_available=%s"
            % (o2["outcome"], committed_o, committed_o2,
               mandates.BOUND - committed_o2))


ALL = [test_valid_single_action_commits,
       test_out_of_scope_refused,
       test_exact_replay_blocked,
       test_uncertain_effect_fail_closed_no_retry,
       test_o2_independent_of_o]


def run_all():
    results = []
    for fn in ALL:
        name, passed, detail = fn()
        results.append({"name": name, "passed": bool(passed), "detail": detail})
    return results
