#!/usr/bin/env python3
"""POPPY-PROOF-001 benchmark: latency and operational complexity baseline.

Measures (no premature optimization):
1. Poppy-native decision latency (session verify + company policy).
2. Poppy+OpenLine decision latency (session verify + mandate verify + receipt).
3. The delta: what the exact-terms authority check costs.
4. Operational complexity: component/step counts for each approach.

All measurements are local, single-process, no network. The absolute
numbers are not production claims — the DELTA and the shape matter.
"""

from __future__ import annotations

import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from openline_wallet import Wallet  # noqa: E402
from openline_wallet.crypto import public_key_hex  # noqa: E402
from poppy_session import PoppyAgent  # noqa: E402
from poppy_receiver import PoppyReceiver, mandate_scope_for_operation  # noqa: E402
from poppy_native_baseline import PoppyNativeReceiver  # noqa: E402
from wallet_bridge import worker_present  # noqa: E402

N = 50


def bench_native() -> list[float]:
    rx = PoppyNativeReceiver("Manzanita Supply", "manzanita")
    rx.fund("owner-checking", 10_000_000)
    agent = PoppyAgent("atlas")
    sess = agent.open_session(rx, user_id="user_123", access_choice="write")
    op = {"type": "charge", "merchant": "manzanita-supply",
          "account": "owner-checking", "amount_cents": 4250, "currency": "USD",
          "items": [], "order_ref": "bench"}
    lat = []
    for _ in range(N):
        t0 = time.perf_counter()
        rx.decide_native(operation=op, session_token=sess["session_token"],
                         dpop_public_key=agent.dpop_public_key)
        lat.append((time.perf_counter() - t0) * 1000)
    return lat


def bench_extended() -> tuple[list[float], list[float], list[float]]:
    """Returns (total, poppy_layer, mandate_layer) latencies in ms."""
    tmp = tempfile.TemporaryDirectory()
    now = datetime.now(timezone.utc)
    wallet = Wallet.create(tmp.name)
    pid = wallet.principal_id
    rx = PoppyReceiver("Manzanita Supply", "manzanita")
    rx.pin_owner(pid, wallet.root_public_key)
    rx.fund("owner-checking", 10_000_000)
    agent = PoppyAgent("atlas")
    sess = agent.open_session(rx, user_id="user_123", access_choice="write")
    op = {"type": "charge", "merchant": "manzanita-supply",
          "account": "owner-checking", "amount_cents": 4250, "currency": "USD",
          "items": [], "order_ref": "bench"}
    scope = mandate_scope_for_operation(op)
    key = Ed25519PrivateKey.generate()
    wallet.grant(subject_id="agent-1", subject_public_key=public_key_hex(key),
                 scopes=[scope], expires_at=now + timedelta(hours=1))
    bundle = wallet.export_bundle(ttl_seconds=300)
    rx.admit_authority_bundle(bundle)

    total, poppy_layer, mandate_layer = [], [], []
    for _ in range(N):
        ch = rx.authority.issue_challenge(pid, "agent-1", scope)
        pres = worker_present(bundle=bundle,
                              mandate_id=wallet.timeline().active_by_subject.get("agent-1"),
                              subject_id="agent-1", subject_key=key,
                              action=scope, challenge=ch)
        # Time the Poppy layer alone.
        t0 = time.perf_counter()
        rx.verify_session(sess["session_token"], agent.dpop_public_key)
        poppy_layer.append((time.perf_counter() - t0) * 1000)
        # Time the mandate layer alone.
        t0 = time.perf_counter()
        rx.authority.protect_action(scope, [scope])
        rx.authority.authorize(pres, scope)
        mandate_layer.append((time.perf_counter() - t0) * 1000)
        # Time the full decide (fresh challenge + presentation each time).
        ch2 = rx.authority.issue_challenge(pid, "agent-1", scope)
        pres2 = worker_present(bundle=bundle,
                               mandate_id=wallet.timeline().active_by_subject.get("agent-1"),
                               subject_id="agent-1", subject_key=key,
                               action=scope, challenge=ch2)
        t0 = time.perf_counter()
        rx.decide(operation=op, session_token=sess["session_token"],
                  dpop_public_key=agent.dpop_public_key,
                  presentation=pres2, principal_id=pid)
        total.append((time.perf_counter() - t0) * 1000)
    tmp.cleanup()
    return total, poppy_layer, mandate_layer


def pct(data: list[float], p: float) -> float:
    s = sorted(data)
    return s[min(int(len(s) * p / 100), len(s) - 1)]


def main() -> int:
    print(f"POPPY-PROOF-001 latency baseline (n={N}, local, single-process)\n")
    native = bench_native()
    total, poppy_l, mandate_l = bench_extended()

    def row(name: str, d: list[float]) -> None:
        print(f"{name:28s} p50 {statistics.median(d):7.2f} ms   "
              f"p95 {pct(d, 95):7.2f} ms   mean {statistics.mean(d):7.2f} ms")

    row("poppy-native decide", native)
    row("poppy layer (session verify)", poppy_l)
    row("mandate layer (verify+receipt)", mandate_l)
    row("extended decide (full)", total)
    delta = statistics.median(total) - statistics.median(native)
    print(f"\nmedian added latency of exact-terms authority: {delta:.2f} ms")
    print("mandate layer share of extended decide: "
          f"{statistics.median(mandate_l) / statistics.median(total) * 100:.0f}%")

    print("\nOperational complexity (components / steps):")
    print("  poppy-native : poppy.json + OAuth sign-in + session JWT verify")
    print("                 + company policy check  (4 moving parts)")
    print("  extended     : above + owner Wallet (grant/revoke) + bundle")
    print("                 admission + challenge/presentation + signed receipt")
    print("                 (8 moving parts; +4 over native)")
    print("\nNote: absolute numbers are local-process only, not production")
    print("claims. Optimization explicitly deferred (Codex phase).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
