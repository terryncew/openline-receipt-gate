#!/usr/bin/env python3
"""Jev through Vercel AI Gateway, witnessed by OpenLine. Product demo: JEV-WITNESS-DEMO-001.

Usage:
    AI_GATEWAY_API_KEY=... python3 demo.py

One run, one real Jev call:

  Jev: proceed, 0.xx
  Receiver policy: COMMIT
  Effect: executed

  Owner revoked the agent.

  Same Jev judgment. Same action.
  Receiver: DENY
  Effect: not executed

What this shows: a receiver can choose what confidence earns for a
particular consequence. Jev supplies the judgment. OpenLine binds it to the
exact action and current authority. The protected action is trivial and
reversible: the literal text "jev-ok" written into a temporary marker file.

The >= 0.80 commit threshold is illustrative receiver policy for this
low-risk/reversible risk class -- NOT a claim about Jev calibration or
safety. TypeSafe's own public framing is that the surrounding code chooses
the confidence thresholds for autonomous action versus review; they
prescribe no universal cutoff.

The demo makes exactly one live Jev call. It never reruns the call to chase
a threshold: if Jev returns below 0.80, the receiver's frozen policy DENYs
and the demo shows that instead.

No new authority primitive is introduced; everything composes the existing
olp_gate machinery (signing, canonicalization, standing, exact-action
binding, one-use ledger).

Data hygiene: the example uses synthetic, non-sensitive data only and does
NOT request Vercel's Zero Data Retention control (it sends
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

ACTION = {
    "kind": "write_marker_file",
    "filename": "jev-ok.txt",
    "content": "jev-ok",
}
ACTION_SUBSTITUTED = {
    "kind": "write_marker_file",
    "filename": "jev-ok-substituted.txt",
    "content": "jev-ok",
}
# Illustrative receiver policy for the low-risk/reversible risk class:
# COMMIT >= 0.80. Not a calibration or safety claim.
POLICY = JevVercelWitnessPolicy(
    policy_id="jev-witness-demo-001-product-demo-policy-v1",
    signal_question="proceed",
    commit_threshold=0.80,
    review_band_low=0.80,
    max_evidence_age_seconds=300,
)
FROZEN_REQUEST = json.loads(
    (REPO_ROOT / "experiments/jev-witness-demo-001/harness/frozen_request.json")
    .read_text(encoding="utf-8")
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def call_jev(api_key: str, request_body: dict) -> tuple[dict, dict]:
    """One real Jev evaluation through Vercel AI Gateway. No reruns."""
    req = urllib.request.Request(
        GATEWAY_EVALUATE_URL,
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

    demo_dir = Path(tempfile.mkdtemp(prefix="jev-demo-001-"))
    ledger = JevVercelEvidenceLedger(demo_dir / "consumed.jsonl")
    decision_log = demo_dir / "decisions.jsonl"

    witness_key = Ed25519PrivateKey.generate()
    trusted = public_key_hex(witness_key.public_key())
    operator_key = Ed25519PrivateKey.generate()
    view = ReceiverStandingView({"operator": public_key_hex(operator_key.public_key())})

    # --- one real Jev judgment; bind as evidence ------------------------------
    resp_body, resp_headers = call_jev(api_key, FROZEN_REQUEST)
    signal = extract_jev_signal(resp_body, POLICY.signal_question)
    evidence = build_jev_vercel_evidence(
        state=FROZEN_REQUEST["state"],
        questions=FROZEN_REQUEST["questions"],
        response=resp_body,
        response_headers=resp_headers,
        action=ACTION,
        witness_key=witness_key,
        model_requested=JEV_MODEL_ID,
        model_reported=resp_body.get("model")
        if isinstance(resp_body.get("model"), str)
        else None,
        request_id=extract_request_id_v2(resp_body) or extract_request_id(resp_headers),
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

    # --- receiver decides; protected effect only on COMMIT --------------------
    decision = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=evidence,
        policy=POLICY,
        authority_check=authority,
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=decision_log,
    )
    print(f"Jev: proceed, {signal:.2f}")
    print(f"Receiver policy: {decision['decision']}")
    executed = False
    if decision["decision"] == "COMMIT" and ledger.consume(
        evidence["evidence_id"], decision_hash=decision["payload_hash"]
    ):
        (demo_dir / ACTION["filename"]).write_text(ACTION["content"], encoding="utf-8")
        executed = True
    print(f"Effect: {'executed' if executed else 'not executed'}")
    print("")
    print("Owner revoked the agent.")
    print("")

    # --- same judgment after revocation ---------------------------------------
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
    verify_jev_vercel_evidence(evidence, expected_action=ACTION, trusted_witness_key=trusted)
    decision2 = evaluate_jev_vercel_witness(
        action=ACTION,
        evidence_receipt=evidence,
        policy=POLICY,
        authority_check=receiver_action_stop_check(view, support, action_hash),
        witness_key=witness_key,
        trusted_witness_key=trusted,
        decision_path=decision_log,
    )
    print("Same Jev judgment. Same action.")
    print(f"Receiver: {decision2['decision']}")
    # The revoked path never executes the protected effect; the marker from
    # the committed run (if any) is untouched by design.
    print("Effect: not executed")

    # --- substitution, mutation, replay -----------------------------------------
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

    mutated = copy.deepcopy(evidence)
    mutated["jev"]["state"] = {"action": "MUTATED"}
    try:
        verify_jev_vercel_evidence(mutated, expected_action=ACTION, trusted_witness_key=trusted)
        print("Evidence mutation: UNEXPECTEDLY VERIFIED")
    except JevVercelEvidenceError:
        print("Evidence mutation: verification failed -> DENY")

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
