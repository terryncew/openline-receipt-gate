# HOME-GUARD-001 reproduction

Prerequisites: Python 3.12, the `cryptography` package, a clone of
openline-receipt-gate at branch `study/home-guard-001`. No network access,
no paid APIs, no devices needed.

## 1. Run the frozen security tests

From the repo root:

    python -m unittest discover -s experiments/home-guard-001/tests -v

Expected: `Ran 8 tests ... OK`. Verify the collection count matches the
source count:

    grep -c "def test_" experiments/home-guard-001/tests/test_home_guard_001.py
    # must print 8

The tests are stdlib `unittest` only (no pytest import) and use fixed keys
and a fixed clock: results are deterministic.

## 2. Run the executable demo

From the repo root:

    python experiments/home-guard-001/home_guard/demo.py

Expected: seven scenario lines (ALLOW / DENY / REVOKE / NET DENY /
BYPASS blocked / BYPASS alt paths / CONTROL ALLOW), then:

    Wrote .../results/receipts.jsonl (9 receipts) and run.json

## 3. Verify byte-reproducibility

Run the demo twice; the receipts file hash must be identical:

    sha256sum experiments/home-guard-001/results/receipts.jsonl
    python experiments/home-guard-001/home_guard/demo.py > /dev/null
    sha256sum experiments/home-guard-001/results/receipts.jsonl

Evidence-run hash: `3bc49332c75315a305d84e2afcf55cde6acf546e6f265f5c6fb04e40e31e49aa`
(recorded in `results/run.json` and `EVIDENCE.md`).

## 4. Independently verify a receipt

```python
import json, sys
sys.path.insert(0, "experiments/home-guard-001")  # for home_guard keys
sys.path.insert(0, ".")                            # for olp_gate
from olp_gate.crypto import verify_olp_signature
from home_guard import keys

receipts = [json.loads(l) for l in
            open("experiments/home-guard-001/results/receipts.jsonl")]
for r in receipts:
    ok, reason = verify_olp_signature(r)
    assert ok, reason
    assert r["signature"]["public_key"] == keys.public_key_hex_of("receiver")
print(f"{len(receipts)} receipts verify against the receiver key")
```

## 5. Test matrix

| # | Scenario | Layer | Expected | Status |
|---|---|---|---|---|
| 1 | ALLOW kitchen light, exact effect once, receipt verifies | sim | PASS | PASS |
| 2 | DENY front-door unlock, zero device action | sim | PASS | PASS |
| 3 | Revoke; reused grant rejected | sim | PASS | PASS |
| 4 | Stale/forged/tampered requests rejected | sim | PASS | PASS |
| 5 | DENY tv->nvr, no route created (blocked, not logged) | sim | PASS | PASS |
| 6 | AI raw-credential bypass attempts, zero effect | sim | PASS | PASS |
| 7 | TV alternative paths: DENY/DENY/OUT_OF_SCOPE, no route | sim | PASS | PASS |
| 8 | Control case preserved, overblocking measured | sim | PASS | PASS |
| 9 | Linux netns packet-isolation verification | env | infeasible here | NOT RUN (`setns: Operation not permitted`) |
| 10 | Real-home / real-device claims | real | out of scope | NOT TESTED |

`sim` = property of the offline simulator only. Nothing in rows 1-8 is a
claim about real packets, real firmware, or a real home.
