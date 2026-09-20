#!/usr/bin/env python3
"""Jev through Vercel AI Gateway, witnessed by OpenLine. One-command demo.

Usage:
    AI_GATEWAY_API_KEY=... python3 demo.py

What it does, in one run:
  1. asks the real Jev model (typesafe-ai/jev) through Vercel AI Gateway
     whether a harmless marker-file write should proceed;
  2. binds that judgment as signed OpenLine evidence to the exact action;
  3. lets the receiver decide from CURRENT authority + its own policy;
  4. executes the harmless effect only on COMMIT;
  5. revokes authority and shows the SAME judgment can no longer authorize;
  6. shows action substitution, evidence mutation, and replay are refused.

Jev is evidence here, never permission. The receiver owns the threshold.
No new authority primitive is introduced; everything composes the existing
olp_gate machinery (signing, canonicalization, standing, exact-action
binding, one-use ledger).

Data hygiene: the example sends only synthetic, non-sensitive fixture data
and does NOT request Vercel's Zero Data Retention control (it sends
disallowPromptTraining instead). It does not establish a ZDR execution path.

Needs: Python 3.10+, the `cryptography` package, this repository on
sys.path (run from the repo root or from this directory).
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from olp_gate.crypto import public_key_hex, sign_olp_body  # noqa: E402
from olp_gate.standing import ReceiverStandingView, STANDING_PROJECTION_SCHEMA  # noqa: E402
from olp_gate.stop_standing import receiver_action_stop_check  # noqa: E402
from olp_gate.integrations.jev_vercel_v3 import (  # noqa: E402
    GATEWAY_EVALUATE_URL,
    JEV_MODEL_ID,
    JevVercelEvidenceError,
    JevVercelEvidenceLedger,
    JevVercelWitnessPolicy,
    build_jev_vercel_evidence,
    evaluate_jev_vercel_witness,
    extract_jev_signal,
    extract_request_id,
    extract_request_id_v2,
    verify_jev_vercel_evidence,
)

GATEWAY_URL = GATEWAY_EVALUATE_URL
ACTION = {
    "kind": "write_marker_file",
    "filename": "marker-v1.txt",
    "content": "jev-witness-vercel-002 marker",
}
ACTION_SUBSTITUTED = {
    "kind": "write_marker_file",
    "filename": "marker-substituted.txt",
    "content": "jev-witness-vercel-002 marker",
}
POLICY = JevVercelWitnessPolicy()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def call_jev(api_key: str, request_body: dict) -> tuple[dict, dict]:
    """One real Jev evaluation through Vercel AI Gateway. No reruns.

    Public route: POST {GATEWAY_URL} with the body
    {"model": "typesafe-ai/jev", "state": ..., "questions": ...,
    "providerOptions": {"gateway": {"disallowPromptTraining": true}}}.
    """
    req = urllib.request.Request(
        GATEWAY_URL,
        data=json.dumps(request_body).encode("utf-8"),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            headers = {k.lower(): v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as exc:
        sys.exit(f"gateway HTTP {exc.code}: {exc.read()[:300].decode('utf-8', 'replace')}")
    return body, headers


def admit(view, body, issuer_key):
    return view.admit(sign_olp_body(body, issuer_key))


def main() -> int:
    api_key = os.environ.get("AI_GATEWAY_API_KEY")
    if not api_key:
        print(
            "Set AI_GATEWAY_API_KEY to a Vercel AI Gateway key, then re-run.\n"
            "The key is used for this demo call only; it is never printed or stored.",
            file=sys.stderr,
        )
        return 2

    frozen = json.loads(
        (REPO_ROOT / "experiments/jev-witness-vercel-003/harness/frozen_request.json")
        .read_text(encoding="utf-8")
    )
    demo_dir = Path(tempfile.mkdtemp(prefix="jev-vercel-demo-"))
    ledger = JevVercelEvidenceLedger(demo_dir / "consumed.jsonl")
    decision_log = demo_dir / "decisions.jsonl"

    witness_key = Ed25519PrivateKey.generate()
    trusted = public_key_hex(witness_key.public_key())
    operator_key = Ed25519PrivateKey.generate()
    view = ReceiverStandingView({"operator": public_key_hex(operator_key.public_key())})

    # --- 1-2. real Jev judgment ------------------------------------------------
    resp_body, resp_headers = call_jev(api_key, frozen)
    signal = extract_jev_signal(resp_body, POLICY.signal_question)
    print(f"Action: write marker file {ACTION['filename']} (fixed content) in demo workspace")
    print(f"Jev judgment: PROCEED {signal:.2f}  (model {JEV_MODEL_ID} via Vercel AI Gateway)")

    # --- 3-5. bind as evidence; receiver decides --------------------------------
    evidence = build_jev_vercel_evidence(
        state=frozen["state"],
        questions=frozen["questions"],
        response=resp_body,
        response_headers=resp_headers,
        action=ACTION,
        witness_key=witness_key,
        model_requested=JEV_MODEL_ID,
        model_reported=resp_body.get("model")
        if isinstance(resp_body.get("model"), str)
        else None,
        request_id=extract_request_id_v2(resp_body) or extract_request_id(resp_headers),
        # Frozen 003 request: disallowPromptTraining sent, ZDR not sent.
        zero_data_retention_requested=False,
        disallow_prompt_training_requested=True,
    )
    support, action_hash = evidence["payload_hash"], evidence["action_hash"]
    admit(
        view,
        {
            "schema": STANDING_PROJECTION_SCHEMA,
            "projection_id": "demo/active",
            "issuer_id": "operator",
            "support_hash": support,
            "action_hash": action_hash,
            "standing": "ACTIVE",
            "event_type": "ADMIT",
            "sequence": 1,
            "predecessor_hash": None,
            "issued_at": _iso(_utc_now()),
            "expires_at": _iso(_utc_now() + timedelta(hours=1)),
        },
        operator_key,
    )
    authority = receiver_action_stop_check(view, support, action_hash)
    decision = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=evidence,
        policy=POLICY,
        authority_check=authority,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=decision_log,
    )
    print(f"Current authority: ACTIVE")
    print(f"Result: {decision['decision']}")
    executed = False
    if decision["decision"] == "COMMIT" and ledger.consume(
        evidence["evidence_id"], decision_hash=decision["payload_hash"]
    ):
        (demo_dir / ACTION["filename"]).write_text(ACTION["content"], encoding="utf-8")
        executed = True
    print(f"Effect: {'EXECUTED' if executed else 'NOT EXECUTED'}")

    # --- 6-8. owner revocation; same judgment reused ---------------------------
    print("\nOwner STOP issued.")
    admit(
        view,
        {
            "schema": STANDING_PROJECTION_SCHEMA,
            "projection_id": "demo/revoke",
            "issuer_id": "operator",
            "support_hash": support,
            "action_hash": action_hash,
            "standing": "INACTIVE",
            "event_type": "REVOKE",
            "sequence": 2,
            "predecessor_hash": view.head(support, action_hash)["payload_hash"],
            "issued_at": _iso(_utc_now()),
            "expires_at": _iso(_utc_now() + timedelta(hours=1)),
        },
        operator_key,
    )
    authority_revoked = receiver_action_stop_check(view, support, action_hash)
    verify_jev_vercel_evidence(evidence, expected_action=ACTION, trusted_witness_key=trusted)
    print(f"Same Jev judgment: PROCEED {signal:.2f} (receipt still verifies: historical, authentic)")
    decision2 = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=evidence,
        policy=POLICY,
        authority_check=authority_revoked,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=decision_log,
    )
    print("Current authority: REVOKED")
    print(f"Result: {decision2['decision']}")
    print("Effect: NOT EXECUTED")

    # --- 9. action substitution --------------------------------------------------
    decision3 = evaluate_jev_vercel_witness(
        action=ACTION_SUBSTITUTED,
        evidence_receipt=evidence,
        policy=POLICY,
        authority_check=authority,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=decision_log,
    )
    print(f"\nAction substitution ({ACTION_SUBSTITUTED['filename']}): {decision3['decision']}")

    # --- evidence mutation -------------------------------------------------------
    mutated = copy.deepcopy(evidence)
    mutated["jev"]["state"] = {"action": "MUTATED"}
    try:
        verify_jev_vercel_evidence(mutated, expected_action=ACTION, trusted_witness_key=trusted)
        print("Evidence mutation: UNEXPECTEDLY VERIFIED")
    except JevVercelEvidenceError:
        print("Evidence mutation: verification failed -> DENY")

    # --- replay ------------------------------------------------------------------
    if executed:
        admit(
            view,
            {
                "schema": STANDING_PROJECTION_SCHEMA,
                "projection_id": "demo/restore",
                "issuer_id": "operator",
                "support_hash": support,
                "action_hash": action_hash,
                "standing": "ACTIVE",
                "event_type": "ADMIT",
                "sequence": 3,
                "predecessor_hash": view.head(support, action_hash)["payload_hash"],
                "issued_at": _iso(_utc_now()),
                "expires_at": _iso(_utc_now() + timedelta(hours=1)),
            },
            operator_key,
        )
        decision5 = evaluate_jev_vercel_witness(
            action=ACTION,
            evidence_receipt=evidence,
            policy=POLICY,
            authority_check=receiver_action_stop_check(view, support, action_hash),
            witness_key=witness_key,
            trusted_witness_key=trusted,
            decision_path=decision_log,
        )
        replay_allowed = (
            decision5["decision"] == "COMMIT"
            and ledger.consume(evidence["evidence_id"], decision_hash=decision5["payload_hash"])
        )
        print(f"Receipt replay: {'EXECUTED (BAD)' if replay_allowed else 'DENY (evidence_replay)'}")
    else:
        print("Receipt replay: n/a (no committed receipt to replay)")

    print(f"\nDemo artifacts: {demo_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
