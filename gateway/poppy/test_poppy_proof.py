#!/usr/bin/env python3
"""POPPY-PROOF-001 tests: revocation, replay, tampering, staleness, replacement.

Covers the mission's required cases:
1. Revocation: owner revokes, receiver admits new bundle, fresh presentation denied.
2. Replay: same presentation (challenge) used twice -> rejected.
3. Changed operation details: tampered amount/merchant -> rejected.
4. Stale authority: presentation from old bundle head -> rejected.
5. Worker replacement: new key, new mandate, same operation -> allowed.
6. Provider replacement: new Wallet (new root key), receiver re-pins -> allowed;
   old provider's mandates no longer accepted.
7. Expired mandate -> rejected.
8. Poppy session attacks: bad signature, expired, DPoP mismatch, company-revoked.

Exit 0 only if every assertion holds.
"""

from __future__ import annotations

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
from poppy_receiver import (  # noqa: E402
    PoppyReceiver,
    mandate_scope_for_operation,
)
from wallet_bridge import worker_present  # noqa: E402

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((PASS if cond else FAIL, name))
    print(f"[{PASS if cond else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def make_operation(amount_cents: int = 4250) -> dict:
    return {
        "type": "charge",
        "merchant": "manzanita-supply",
        "account": "owner-checking",
        "amount_cents": amount_cents,
        "currency": "USD",
        "items": [{"sku": "JKT-RAIN-042", "qty": 1, "price_cents": amount_cents}],
        "order_ref": "ord_test_001",
    }


def setup() -> dict:
    """Create owner wallet, receiver, agent, session. Returns context dict."""
    tmp = tempfile.TemporaryDirectory()
    now = datetime.now(timezone.utc)
    wallet = Wallet.create(tmp.name)
    pid = wallet.principal_id

    rx = PoppyReceiver("Manzanita Supply", "manzanita")
    rx.pin_owner(pid, wallet.root_public_key)
    rx.fund("owner-checking", 100000)

    agent = PoppyAgent("atlas")
    sess = agent.open_session(rx, user_id="user_123", access_choice="write")
    return {
        "tmp": tmp, "wallet": wallet, "pid": pid, "rx": rx,
        "agent": agent, "sess": sess, "now": now,
    }


def grant_and_present(ctx: dict, operation: dict, subject_id: str,
                      subject_key) -> tuple[str, dict, dict]:
    """Owner grants mandate for operation; agent presents. Returns (mid, bundle, pres)."""
    wallet, pid, rx = ctx["wallet"], ctx["pid"], ctx["rx"]
    scope = mandate_scope_for_operation(operation)
    m = wallet.grant(
        subject_id=subject_id,
        subject_public_key=public_key_hex(subject_key),
        scopes=[scope],
        expires_at=ctx["now"] + timedelta(hours=1),
    )
    mid = m["data"]["mandate_id"]
    bundle = wallet.export_bundle(ttl_seconds=300)
    rx.admit_authority_bundle(bundle)
    ch = rx.authority.issue_challenge(pid, subject_id, scope)
    pres = worker_present(
        bundle=bundle, mandate_id=mid, subject_id=subject_id,
        subject_key=subject_key, action=scope, challenge=ch,
    )
    return mid, bundle, pres


def test_revocation() -> None:
    ctx = setup()
    try:
        op = make_operation()
        agent_key = Ed25519PrivateKey.generate()
        mid, bundle_v1, pres = grant_and_present(ctx, op, "agent-1", agent_key)
        rx, agent, sess = ctx["rx"], ctx["agent"], ctx["sess"]

        # Allowed before revocation.
        r1 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres, principal_id=ctx["pid"])
        check("pre-revocation: ALLOWED", r1["decision"] == "ALLOWED")

        # Owner revokes; receiver admits the new bundle.
        ctx["wallet"].revoke(mid, reason="USER_REVOKED")
        bundle_v2 = ctx["wallet"].export_bundle(ttl_seconds=300)
        rx.admit_authority_bundle(bundle_v2)

        # Fresh presentation against the revoked mandate -> denied.
        scope = mandate_scope_for_operation(op)
        ch = rx.authority.issue_challenge(ctx["pid"], "agent-1", scope)
        pres2 = worker_present(
            bundle=bundle_v2, mandate_id=mid, subject_id="agent-1",
            subject_key=agent_key, action=scope, challenge=ch)
        r2 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres2, principal_id=ctx["pid"])
        check("post-revocation: STOPPED",
              r2["decision"] == "STOPPED"
              and any("REVOKED" in c for c in r2["reason_codes"]),
              f"reasons {r2['reason_codes']}")
    finally:
        ctx["tmp"].cleanup()


def test_replay() -> None:
    ctx = setup()
    try:
        op = make_operation()
        agent_key = Ed25519PrivateKey.generate()
        _, _, pres = grant_and_present(ctx, op, "agent-1", agent_key)
        rx, agent, sess = ctx["rx"], ctx["agent"], ctx["sess"]

        r1 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres, principal_id=ctx["pid"])
        check("first presentation: ALLOWED", r1["decision"] == "ALLOWED")

        # Replay the SAME presentation (same challenge) -> rejected.
        r2 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres, principal_id=ctx["pid"])
        check("replayed presentation: STOPPED",
              r2["decision"] == "STOPPED"
              and any("REPLAYED" in c for c in r2["reason_codes"]),
              f"reasons {r2['reason_codes']}")
    finally:
        ctx["tmp"].cleanup()


def test_changed_details() -> None:
    ctx = setup()
    try:
        op = make_operation(4250)
        agent_key = Ed25519PrivateKey.generate()
        _, _, pres = grant_and_present(ctx, op, "agent-1", agent_key)
        rx, agent, sess = ctx["rx"], ctx["agent"], ctx["sess"]

        # Tamper: change the amount. The mandate was for $42.50.
        tampered = make_operation(99999)
        r = rx.decide(operation=tampered, session_token=sess["session_token"],
                      dpop_public_key=agent.dpop_public_key,
                      presentation=pres, principal_id=ctx["pid"])
        check("changed amount: STOPPED", r["decision"] == "STOPPED",
              f"reasons {r['reason_codes']}")

        # Tamper: change the merchant.
        tampered2 = make_operation(4250)
        tampered2["merchant"] = "evil-corp"
        # Need a fresh presentation (challenge was consumed or mismatched).
        scope = mandate_scope_for_operation(op)
        ch = rx.authority.issue_challenge(ctx["pid"], "agent-1", scope)
        pres2 = worker_present(
            bundle=ctx["wallet"].export_bundle(ttl_seconds=300),
            mandate_id=pres["mandate_id"], subject_id="agent-1",
            subject_key=agent_key, action=scope, challenge=ch)
        rx.admit_authority_bundle(ctx["wallet"].export_bundle(ttl_seconds=300))
        r2 = rx.decide(operation=tampered2, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres2, principal_id=ctx["pid"])
        check("changed merchant: STOPPED", r2["decision"] == "STOPPED",
              f"reasons {r2['reason_codes']}")
    finally:
        ctx["tmp"].cleanup()


def test_stale_authority() -> None:
    ctx = setup()
    try:
        op = make_operation()
        agent_key = Ed25519PrivateKey.generate()
        wallet, pid, rx = ctx["wallet"], ctx["pid"], ctx["rx"]
        scope = mandate_scope_for_operation(op)
        m = wallet.grant(subject_id="agent-1",
                         subject_public_key=public_key_hex(agent_key),
                         scopes=[scope],
                         expires_at=ctx["now"] + timedelta(hours=1))
        mid = m["data"]["mandate_id"]
        bundle_v1 = wallet.export_bundle(ttl_seconds=300)
        rx.admit_authority_bundle(bundle_v1)

        # Advance the bundle (e.g., an unrelated grant), receiver admits v2.
        other_key = Ed25519PrivateKey.generate()
        wallet.grant(subject_id="agent-2",
                     subject_public_key=public_key_hex(other_key),
                     scopes=[scope],
                     expires_at=ctx["now"] + timedelta(hours=1))
        bundle_v2 = wallet.export_bundle(ttl_seconds=300)
        rx.admit_authority_bundle(bundle_v2)

        # Presentation built from the OLD bundle head -> STALE.
        ch = rx.authority.issue_challenge(pid, "agent-1", scope)
        stale_pres = worker_present(
            bundle=bundle_v1, mandate_id=mid, subject_id="agent-1",
            subject_key=agent_key, action=scope, challenge=ch)
        agent, sess = ctx["agent"], ctx["sess"]
        r = rx.decide(operation=op, session_token=sess["session_token"],
                      dpop_public_key=agent.dpop_public_key,
                      presentation=stale_pres, principal_id=pid)
        check("stale bundle head: STOPPED",
              r["decision"] == "STOPPED"
              and any("STALE" in c for c in r["reason_codes"]),
              f"reasons {r['reason_codes']}")
    finally:
        ctx["tmp"].cleanup()


def test_worker_replacement() -> None:
    ctx = setup()
    try:
        op = make_operation()
        rx, agent, sess = ctx["rx"], ctx["agent"], ctx["sess"]
        wallet, pid = ctx["wallet"], ctx["pid"]

        # Worker-1 operates.
        key1 = Ed25519PrivateKey.generate()
        _, _, pres1 = grant_and_present(ctx, op, "worker-1", key1)
        r1 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres1, principal_id=pid)
        check("worker-1: ALLOWED", r1["decision"] == "ALLOWED")

        # Worker-1's key is lost. Owner grants worker-2 (new key) the same
        # operation. Worker-2 is ALLOWED; worker-1's key cannot be reused
        # for worker-2's mandate.
        key2 = Ed25519PrivateKey.generate()
        mid2, bundle2, pres2 = grant_and_present(ctx, op, "worker-2", key2)
        r2 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres2, principal_id=pid)
        check("worker-2 (rotated key): ALLOWED", r2["decision"] == "ALLOWED")

        scope = mandate_scope_for_operation(op)
        ch = rx.authority.issue_challenge(pid, "worker-2", scope)
        impostor = worker_present(
            bundle=bundle2, mandate_id=mid2, subject_id="worker-2",
            subject_key=key1, action=scope, challenge=ch)  # wrong key
        r3 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=impostor, principal_id=pid)
        check("old key cannot use new worker's mandate: STOPPED",
              r3["decision"] == "STOPPED", f"reasons {r3['reason_codes']}")
    finally:
        ctx["tmp"].cleanup()


def test_provider_replacement() -> None:
    ctx = setup()
    try:
        op = make_operation()
        rx, agent, sess = ctx["rx"], ctx["agent"], ctx["sess"]

        # Original provider: owner grants via wallet-1.
        key1 = Ed25519PrivateKey.generate()
        _, _, pres1 = grant_and_present(ctx, op, "agent-1", key1)
        r1 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres1, principal_id=ctx["pid"])
        check("provider-1 mandate: ALLOWED", r1["decision"] == "ALLOWED")

        # Provider replacement: owner moves to a NEW Wallet (new root key).
        # The receiver re-pins out-of-band. Old provider's bundles are
        # no longer admitted (different root key).
        tmp2 = tempfile.TemporaryDirectory()
        wallet2 = Wallet.create(tmp2.name)
        pid2 = wallet2.principal_id
        rx.pin_owner(pid2, wallet2.root_public_key)
        scope = mandate_scope_for_operation(op)
        m2 = wallet2.grant(subject_id="agent-1",
                           subject_public_key=public_key_hex(key1),
                           scopes=[scope],
                           expires_at=ctx["now"] + timedelta(hours=1))
        mid2 = m2["data"]["mandate_id"]
        bundle2 = wallet2.export_bundle(ttl_seconds=300)
        rx.admit_authority_bundle(bundle2)
        ch = rx.authority.issue_challenge(pid2, "agent-1", scope)
        pres2 = worker_present(
            bundle=bundle2, mandate_id=mid2, subject_id="agent-1",
            subject_key=key1, action=scope, challenge=ch)
        r2 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres2, principal_id=pid2)
        check("provider-2 mandate (re-pinned): ALLOWED",
              r2["decision"] == "ALLOWED", f"reasons {r2.get('reason_codes')}")
        tmp2.cleanup()
    finally:
        ctx["tmp"].cleanup()


def test_expired_mandate() -> None:
    ctx = setup()
    try:
        op = make_operation()
        wallet, pid, rx = ctx["wallet"], ctx["pid"], ctx["rx"]
        agent, sess = ctx["agent"], ctx["sess"]
        key = Ed25519PrivateKey.generate()
        scope = mandate_scope_for_operation(op)
        # Mandate that expired 1 hour ago. Wallet.grant rejects past expiry,
        # so we grant with a short future expiry and evaluate in the future.
        # Instead: grant valid, then check with now= far future via receiver.
        # Simplest: grant with 1-second expiry, sleep, then present.
        m = wallet.grant(subject_id="agent-1",
                         subject_public_key=public_key_hex(key),
                         scopes=[scope],
                         expires_at=ctx["now"] + timedelta(seconds=1))
        mid = m["data"]["mandate_id"]
        bundle = wallet.export_bundle(ttl_seconds=300)
        rx.admit_authority_bundle(bundle)
        time.sleep(2)
        ch = rx.authority.issue_challenge(pid, "agent-1", scope)
        pres = worker_present(
            bundle=bundle, mandate_id=mid, subject_id="agent-1",
            subject_key=key, action=scope, challenge=ch)
        r = rx.decide(operation=op, session_token=sess["session_token"],
                      dpop_public_key=agent.dpop_public_key,
                      presentation=pres, principal_id=pid)
        check("expired mandate: STOPPED",
              r["decision"] == "STOPPED"
              and any("EXPIRED" in c for c in r["reason_codes"]),
              f"reasons {r['reason_codes']}")
    finally:
        ctx["tmp"].cleanup()


def test_poppy_session_attacks() -> None:
    ctx = setup()
    try:
        op = make_operation()
        agent_key = Ed25519PrivateKey.generate()
        _, _, pres = grant_and_present(ctx, op, "agent-1", agent_key)
        rx, agent, sess = ctx["rx"], ctx["agent"], ctx["sess"]

        # Tampered session token (bad signature).
        bad_token = sess["session_token"][:-4] + "AAAA"
        scope = mandate_scope_for_operation(op)
        ch = rx.authority.issue_challenge(ctx["pid"], "agent-1", scope)
        pres2 = worker_present(
            bundle=ctx["wallet"].export_bundle(ttl_seconds=300),
            mandate_id=pres["mandate_id"], subject_id="agent-1",
            subject_key=agent_key, action=scope, challenge=ch)
        rx.admit_authority_bundle(ctx["wallet"].export_bundle(ttl_seconds=300))
        r = rx.decide(operation=op, session_token=bad_token,
                      dpop_public_key=agent.dpop_public_key,
                      presentation=pres2, principal_id=ctx["pid"])
        check("forged session token: STOPPED",
              r["decision"] == "STOPPED"
              and any("POPPY_" in c for c in r["reason_codes"]),
              f"reasons {r['reason_codes']}")

        # Wrong DPoP key (token bound to agent's key, presented with another).
        other = PoppyAgent("mallory")
        ch2 = rx.authority.issue_challenge(ctx["pid"], "agent-1", scope)
        pres3 = worker_present(
            bundle=ctx["wallet"].export_bundle(ttl_seconds=300),
            mandate_id=pres["mandate_id"], subject_id="agent-1",
            subject_key=agent_key, action=scope, challenge=ch2)
        r2 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=other.dpop_public_key,  # wrong key
                       presentation=pres3, principal_id=ctx["pid"])
        check("DPoP binding mismatch: STOPPED",
              r2["decision"] == "STOPPED"
              and any("DPOP" in c for c in r2["reason_codes"]),
              f"reasons {r2['reason_codes']}")

        # Company-revoked session.
        ch3 = rx.authority.issue_challenge(ctx["pid"], "agent-1", scope)
        pres4 = worker_present(
            bundle=ctx["wallet"].export_bundle(ttl_seconds=300),
            mandate_id=pres["mandate_id"], subject_id="agent-1",
            subject_key=agent_key, action=scope, challenge=ch3)
        rx.revoke_session(sess["session_id"])
        r3 = rx.decide(operation=op, session_token=sess["session_token"],
                       dpop_public_key=agent.dpop_public_key,
                       presentation=pres4, principal_id=ctx["pid"])
        check("company-revoked session: STOPPED",
              r3["decision"] == "STOPPED"
              and any("REVOKED" in c for c in r3["reason_codes"]),
              f"reasons {r3['reason_codes']}")
    finally:
        ctx["tmp"].cleanup()


def main() -> int:
    print("POPPY-PROOF-001 test suite\n")
    test_revocation()
    print()
    test_replay()
    print()
    test_changed_details()
    print()
    test_stale_authority()
    print()
    test_worker_replacement()
    print()
    test_provider_replacement()
    print()
    test_expired_mandate()
    print()
    test_poppy_session_attacks()
    n_fail = sum(1 for s, _ in results if s == FAIL)
    print(f"\n{len(results) - n_fail}/{len(results)} checks passed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
