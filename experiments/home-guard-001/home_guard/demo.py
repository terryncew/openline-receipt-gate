"""HOME-GUARD-001 executable local demo (offline, $0 spend).

Runs the full scenario walk once, prints a concise line per scenario, and
writes results/receipts.jsonl (every signed decision) and results/run.json
(tool versions, git SHA, timings, revocation observation).

Usage (from repo root):
    python experiments/home-guard-001/home_guard/demo.py
"""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
RESULTS = EXP / "results"
sys.path.insert(0, str(EXP))

from home_guard import keys  # noqa: E402
from home_guard.receiver import FixedClock, HomeGuardReceiver, Mandate, Proposal  # noqa: E402
from home_guard.devices import DirectDeviceAPI, SimulatedDevice  # noqa: E402
from home_guard.net_policy import ContainmentLayer  # noqa: E402


def git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=EXP.parents[1], text=True
        ).strip()
    except Exception:
        return "unknown"


def build_world():
    clock = FixedClock()
    receiver = HomeGuardReceiver(owner_pub=keys.public_key_hex_of("owner"), clock=clock)
    devices = {
        "kitchen-light": SimulatedDevice("kitchen-light", "light"),
        "front-door-lock": SimulatedDevice("front-door-lock", "lock"),
    }
    api = DirectDeviceAPI(devices, receiver.public_key_hex)
    layer = ContainmentLayer(clock)
    for dev_id, cls, comp in [
        ("tv", "display", True),
        ("nvr", "recorder", False),
        ("thermostat", "sensor", False),
        ("hvac-gateway", "gateway", False),
    ]:
        layer.register_device(dev_id, cls, compromised=comp)
    mandate = Mandate.issue(
        mandate_id="mandate-home-001",
        grantee_name="assistant",
        scope=[{"device": "kitchen-light", "action": "light.turn_on"}],
        issued_at=clock.now(),
        expires_at="2027-10-13T09:39:55-07:00",
    )
    receiver.admit_mandate(mandate.signed)
    return receiver, api, layer, mandate


def main() -> int:
    t0 = time.time()
    receiver, api, layer, mandate = build_world()
    receipts: list[dict] = []
    lines: list[str] = []

    def note(text: str) -> None:
        lines.append(text)
        print(text, flush=True)

    # 1. ALLOW kitchen light.
    p1 = Proposal(mandate.mandate_id, "kitchen-light", "light.turn_on",
                  {"brightness": 80}, "nonce-0001", receiver.clock.now())
    d1 = receiver.authorize(p1)
    applied, _ = api.raw_call(d1, "kitchen-light", "light.turn_on",
                              {"brightness": 80}, "nonce-0001")
    receipts.append(d1)
    note(f"1. ALLOW kitchen-light light.turn_on -> effect={applied} "
         f"effects={len(api.devices['kitchen-light'].effects)}")

    # 2. DENY front-door unlock (not in scope).
    p2 = Proposal(mandate.mandate_id, "front-door-lock", "lock.unlock",
                  {}, "nonce-0002", receiver.clock.now())
    d2 = receiver.authorize(p2)
    applied2, r2 = api.raw_call(d2, "front-door-lock", "lock.unlock", {}, "nonce-0002")
    receipts.append(d2)
    note(f"2. DENY front-door-lock lock.unlock -> reason={d2['reason_code']} "
         f"effect={applied2} effects={len(api.devices['front-door-lock'].effects)}")

    # 3. Revoke; reused grant rejected.
    rev = receiver.revoke(mandate.mandate_id)
    t_revoke = time.time()
    p3 = Proposal(mandate.mandate_id, "kitchen-light", "light.turn_on",
                  {"brightness": 80}, "nonce-0003", receiver.clock.now())
    d3 = receiver.authorize(p3)
    applied3, _ = api.raw_call(d3, "kitchen-light", "light.turn_on",
                               {"brightness": 80}, "nonce-0003")
    t_deny_after_revoke = time.time()
    receipts.extend([rev, d3])
    note(f"3. REVOKE mandate-home-001 -> re-attempt reason={d3['reason_code']} "
         f"effect={applied3} "
         f"revocation_to_deny={(t_deny_after_revoke - t_revoke) * 1000:.2f}ms (in-process)")

    # 4. TV -> NVR lateral blocked by containment layer (not merely logged).
    n1 = layer.attempt("tv", "nvr", session_id="tv")
    receipts.append(n1)
    note(f"4. NET tv->nvr -> verdict={n1['verdict']} reason={n1['reason_code']} "
         f"route_exists={layer.route_exists('tv', 'nvr')}")

    # 5. Bypass: AI raw credential attempts.
    forged = dict(d1)
    forged["signature"] = {"algorithm": "Ed25519",
                           "public_key": keys.public_key_hex_of("attacker"),
                           "value": "00" * 64}
    bypass_results = []
    bypass_results.append(api.raw_call(None, "front-door-lock", "lock.unlock", {}, "nonce-b1"))
    bypass_results.append(api.raw_call(forged, "front-door-lock", "lock.unlock", {}, "nonce-b2"))
    bypass_results.append(api.raw_call(d1, "front-door-lock", "lock.unlock", {}, "nonce-0001"))
    bypass_results.append(api.raw_call(d1, "kitchen-light", "light.turn_on",
                                       {"brightness": 80}, "nonce-0001"))  # replay
    all_blocked = all(not ok for ok, _ in bypass_results)
    note(f"5. BYPASS raw-credential attempts blocked: {all_blocked} "
         f"({[r for _, r in bypass_results]})")

    # 6. Bypass: TV alternative paths.
    alt = [
        layer.attempt("tv", "nvr", session_id="tv", dst_port=8080),
        layer.attempt("tv", "nvr", session_id="tv", claimed_src="thermostat"),
        layer.attempt("tv", "nvr", session_id="tv", via="thermostat"),
    ]
    receipts.extend(alt)
    note(f"6. BYPASS tv alt paths -> {[(a['verdict'], a['reason_code']) for a in alt]} "
         f"route_exists={layer.route_exists('tv', 'nvr')}")

    # 7. Control case: legitimate connection preserved (overblocking check).
    c1 = layer.attempt("thermostat", "hvac-gateway", session_id="thermostat")
    receipts.append(c1)
    note(f"7. CONTROL thermostat->hvac-gateway -> verdict={c1['verdict']} "
         f"route_exists={layer.route_exists('thermostat', 'hvac-gateway')}")

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "receipts.jsonl", "w", encoding="utf-8") as f:
        for r in receipts:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    run = {
        "experiment": "HOME-GUARD-001",
        "git_sha": git_sha(),
        "branch": "study/home-guard-001",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cryptography": __import__("cryptography").__version__,
        "wall_start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)),
        "elapsed_s": round(time.time() - t0, 3),
        "revocation_to_deny_ms_in_process": round((t_deny_after_revoke - t_revoke) * 1000, 3),
        "receipts_sha256": hashlib.sha256(
            (RESULTS / "receipts.jsonl").read_bytes()).hexdigest(),
        "scenario_outcomes": lines,
    }
    (RESULTS / "run.json").write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {RESULTS / 'receipts.jsonl'} ({len(receipts)} receipts) and run.json",
          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
