"""JEV-WITNESS-DEMO-001 frozen acceptance cases V1-V5.

FRESH PRODUCT DEMO LABEL, not a rescue of VERCEL-003. VERCEL-003 stays frozen
(BELOW_RECEIVER_THRESHOLD @ 9ec76ba): do NOT lower 0.95 there, do NOT rerun
its question here.

The sole intentional apparatus delta from VERCEL-003 is a second,
pre-contact-frozen receiver policy for the low-consequence/reversible risk
class: COMMIT >= 0.80. The 0.80 threshold is explicitly illustrative
receiver policy (frozen before the call), NOT a claim about Jev calibration
or safety -- per TypeSafe's own public framing, the surrounding code chooses
the confidence thresholds for autonomous action versus review.

The protected action is trivial and reversible: write the literal text
"jev-ok" into a temporary marker file in the run's isolated
protected_workspace directory.

DATA HYGIENE (frozen): because provider-level Zero Data Retention is not
requested, this label uses ONLY synthetic, non-sensitive fixture data. This
run does NOT establish a ZDR execution path.

Scientific contact gate: the live Jev call goes through the Secure Vault
connector custom.vercel-ai-gateway via the authd surrogate exchange, using
the sanctioned dynamic_credentials helpers exactly as the vercel-ai-gateway
skill does. The raw key never enters this process. If the credential is
unavailable, add_surrogate_to_request raises before any network call: the
harness prints an honest gate message, performs NO network calls, and exits 2.

Transport: POST https://ai-gateway.vercel.sh/v1/evaluate (the documented
public route) with body {"model": "typesafe-ai/jev", "state": ...,
"questions": ..., "providerOptions": {"gateway": {"disallowPromptTraining":
true}}}. ``zeroDataRetention`` is deliberately NOT sent. Request id from
providerMetadata.gateway.generationId when present.

What this harness does, per case:
  V1  one real Jev evaluation through Vercel AI Gateway (frozen boolean
      question). If signal >= 0.80 and all checks hold: COMMIT and exactly
      one effect (positive control: "jev-ok" written to the marker file).
      If signal < 0.80: do NOT rerun; freeze the observation and STOP
      (terminal BELOW_DEMO_THRESHOLD).
  V2  admit owner revocation (INACTIVE successor) -> same authentic evidence
      must DENY, no second effect; the receipt must still verify (historical
      authenticity).
  V3  evidence built for action A presented for action B -> DENY via
      action-binding mismatch, before any effect.
  V4  mutated evidence bytes -> verification failure -> DENY.
  V5  replay V1's exact receipt on the protected-effect path -> second effect
      refused (evidence_replay), effect count unchanged. Only applicable when
      V1 committed; otherwise recorded NOT_APPLICABLE.

run_sequence() is factored so that pre-contact stub qualification can drive
it with synthetic v1/evaluate-shaped fixtures without any network call.
"""
from __future__ import annotations

import copy
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

def _credential_helpers():
    """Import the authd surrogate-exchange helpers lazily.

    Imported at live-call time, not at module import, so the frozen
    harness (including its stub-qualified acceptance path) loads in
    environments without the Secure Vault skill path, e.g. CI or a
    stranger's machine. The credential gate in the live-call function
    still fires before any network call when the connector is
    unavailable.
    """
    sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
    from dynamic_credentials import (  # noqa: E402
        add_surrogate_to_request,
        read_json_response,
    )
    return add_surrogate_to_request, read_json_response

from olp_gate.crypto import public_key_hex, sign_olp_body  # noqa: E402
from olp_gate.standing import ReceiverStandingView, STANDING_PROJECTION_SCHEMA  # noqa: E402
from olp_gate.stop_standing import receiver_action_stop_check  # noqa: E402
from olp_gate.integrations.jev_vercel_v3 import (  # noqa: E402
    GATEWAY_EVALUATE_URL,
    GATEWAY_HOST,
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

CREDENTIAL_NAME = "custom.vercel-ai-gateway"
LABEL = "JEV-WITNESS-DEMO-001"

HERE = Path(__file__).resolve().parent
PREREG = json.loads((HERE.parent / "preregistration.json").read_text(encoding="utf-8"))
POLICY = JevVercelWitnessPolicy(
    policy_id=PREREG["receiver_policy_frozen"]["policy_id"],
    signal_question=PREREG["receiver_policy_frozen"]["signal_question"],
    commit_threshold=0.80,
    review_band_low=0.80,
    max_evidence_age_seconds=300,
)
FROZEN_REQUEST = json.loads((HERE / "frozen_request.json").read_text(encoding="utf-8"))
ACTION_V1 = dict(PREREG["protected_action_frozen"]["action"])
ACTION_B = dict(PREREG["protected_action_frozen"]["action_b"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def live_jev_judgment(request_body: dict) -> tuple[dict, dict]:
    """Call live Jev once via POST /v1/evaluate with the frozen request body.

    Returns (response_body, response_headers). The credential lives in the
    Secure Vault and reaches the gateway only through the authd surrogate
    exchange; this process never sees the raw key.
    Raises SystemExit(2) on the credential gate, RuntimeError on provider
    failure.
    """
    req = urllib.request.Request(
        GATEWAY_EVALUATE_URL,
        data=json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    try:
        add_surrogate_to_request, read_json_response = _credential_helpers()
        add_surrogate_to_request(req, CREDENTIAL_NAME, allowed_hosts=[GATEWAY_HOST])
    except Exception as exc:
        print(
            f"{LABEL} acceptance requires the Vercel AI Gateway "
            "credential (Secure Vault connector custom.vercel-ai-gateway).\n"
            f"The credential is unavailable in this environment ({type(exc).__name__}). "
            "Per the work order this is a human gate: the harness does not ask "
            "for, fabricate, or substitute a key. No network calls were made. "
            "To resume: connect the credential and re-run this exact frozen "
            "harness.",
            file=sys.stderr,
        )
        sys.exit(2)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            response_body = read_json_response(resp)
            headers = {name.lower(): value for name, value in resp.getheaders()}
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:2000].decode("utf-8", "replace")
        raise RuntimeError(
            f"gateway HTTP {exc.code}: {detail}"
        )
    except Exception as exc:
        raise RuntimeError(f"transport error: {type(exc).__name__}: {exc}")
    return response_body, headers


def admit_projection(view: ReceiverStandingView, body: dict, issuer_key: Ed25519PrivateKey) -> dict:
    signed = sign_olp_body(body, issuer_key)
    return view.admit(signed)


def expected_band_disposition(signal: float) -> str:
    # Demo risk class: COMMIT >= 0.80, no quarantine band.
    return "COMMIT" if signal >= 0.80 else "DENY"


def run_sequence(
    resp_body: dict,
    resp_headers: dict,
    run_dir: Path,
    *,
    verbose: bool = True,
) -> dict:
    """Drive frozen V1-V5 over one judgment (live or synthetic fixture).

    Returns the run summary dict (also written to run_dir/results.json).
    Synthetic fixtures must be v1/evaluate-shaped and are NEVER substituted
    for the live observation; this exists for pre-contact stub qualification
    and unit tests only.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    workspace = run_dir / "protected_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    ledger = JevVercelEvidenceLedger(run_dir / "consumed_evidence.jsonl")
    decision_log = run_dir / "decision_receipts.jsonl"

    witness_key = Ed25519PrivateKey.generate()
    trusted_witness = public_key_hex(witness_key.public_key())
    operator_key = Ed25519PrivateKey.generate()
    operator_pub = public_key_hex(operator_key.public_key())
    view = ReceiverStandingView({"operator": operator_pub})

    results: dict[str, dict] = {}
    public_lines: list[str] = []
    effect_count = 0

    def emit(line: str) -> None:
        public_lines.append(line)
        if verbose:
            print(line, flush=True)

    def record(case: str, verdict: str, detail: str, extra: dict | None = None) -> None:
        entry = {"case": case, "verdict": verdict, "detail": detail}
        if extra:
            entry.update(extra)
        results[case] = entry
        if verbose:
            print(f"{case}: {verdict} -- {detail}", flush=True)

    def protected_path(action: dict, evidence: dict, authority_fn) -> tuple[dict, bool]:
        """One protected-effect traversal. Returns (decision, effect_executed)."""
        nonlocal effect_count
        decision = evaluate_jev_vercel_witness(
            action=action,
            evidence_receipt=evidence,
            policy=POLICY,
            authority_check=authority_fn,
            witness_key=witness_key,
            trusted_witness_key=trusted_witness,
            decision_path=decision_log,
        )
        executed = False
        if decision["decision"] == "COMMIT":
            if ledger.consume(evidence["evidence_id"], decision_hash=decision["payload_hash"]):
                marker = workspace / action["filename"]
                marker.write_text(action["content"], encoding="utf-8")
                effect_count += 1
                executed = True
            else:
                decision = dict(decision)
                decision["decision"] = "DENY"
                decision["reason_codes"] = sorted(
                    set(decision.get("reason_codes", [])) | {"evidence_replay"}
                )
        return decision, executed

    # ---------------- V1: judgment + current authority ----------------------
    request_id = extract_request_id_v2(resp_body) or extract_request_id(resp_headers)
    model_reported = resp_body.get("model") if isinstance(resp_body.get("model"), str) else None
    evidence_v1 = build_jev_vercel_evidence(
        state=FROZEN_REQUEST["state"],
        questions=FROZEN_REQUEST["questions"],
        response=resp_body,
        response_headers=resp_headers,
        action=ACTION_V1,
        witness_key=witness_key,
        model_requested=JEV_MODEL_ID,
        model_reported=model_reported,
        request_id=request_id,
        # Demo frozen request: disallowPromptTraining sent, ZDR not sent.
        zero_data_retention_requested=False,
        disallow_prompt_training_requested=True,
    )
    support_v1 = evidence_v1["payload_hash"]
    action_hash_v1 = evidence_v1["action_hash"]
    admit_projection(
        view,
        {
            "schema": STANDING_PROJECTION_SCHEMA,
            "projection_id": "jev-witness-demo-001/v1/active",
            "issuer_id": "operator",
            "support_hash": support_v1,
            "action_hash": action_hash_v1,
            "standing": "ACTIVE",
            "event_type": "ADMIT",
            "sequence": 1,
            "predecessor_hash": None,
            "issued_at": _iso(_utc_now()),
            "expires_at": _iso(_utc_now() + timedelta(hours=1)),
        },
        operator_key,
    )
    authority_v1 = receiver_action_stop_check(view, support_v1, action_hash_v1)
    signal_v1 = extract_jev_signal(resp_body, POLICY.signal_question)

    emit(f"Jev: proceed, {signal_v1:.2f}")
    decision_v1, executed_v1 = protected_path(ACTION_V1, evidence_v1, authority_v1)
    verdict_v1 = decision_v1["decision"]
    emit(f"Receiver policy: {verdict_v1}")
    emit(f"Effect: {'executed' if executed_v1 else 'not executed'}")
    emit("")
    if signal_v1 >= 0.80:
        ok = verdict_v1 == "COMMIT" and executed_v1 and effect_count == 1
        record(
            "V1",
            "PASS" if ok else "FAIL",
            f"signal={signal_v1:.4f}; decision={verdict_v1}; effects={effect_count}; "
            f"reasons={decision_v1['reason_codes']}",
        )
    else:
        expected = expected_band_disposition(signal_v1)
        ok = verdict_v1 == expected and effect_count == 0
        record(
            "V1",
            "PASS" if ok else "FAIL",
            f"PRECONDITION MISS (signal={signal_v1:.4f} < 0.80); policy mapping for "
            f"actual band: expected={expected}, got={verdict_v1}; effects={effect_count}",
            {"precondition_miss": True, "signal": signal_v1},
        )
    v1_committed = verdict_v1 == "COMMIT" and executed_v1
    below_demo_threshold = signal_v1 < 0.80

    # ---------------- V2: owner revocation -> DENY --------------------------
    admit_projection(
        view,
        {
            "schema": STANDING_PROJECTION_SCHEMA,
            "projection_id": "jev-witness-demo-001/v1/revoke",
            "issuer_id": "operator",
            "support_hash": support_v1,
            "action_hash": action_hash_v1,
            "standing": "INACTIVE",
            "event_type": "REVOKE",
            "sequence": 2,
            "predecessor_hash": view.head(support_v1, action_hash_v1)["payload_hash"],
            "issued_at": _iso(_utc_now()),
            "expires_at": _iso(_utc_now() + timedelta(hours=1)),
        },
        operator_key,
    )
    authority_revoked = receiver_action_stop_check(view, support_v1, action_hash_v1)
    try:
        verify_jev_vercel_evidence(
            evidence_v1, expected_action=ACTION_V1, trusted_witness_key=trusted_witness
        )
        historical_ok = True
    except JevVercelEvidenceError:
        historical_ok = False
    emit("Owner revoked the agent.")
    emit("")
    decision_v2 = evaluate_jev_vercel_witness(
        action=ACTION_V1,
        evidence_receipt=evidence_v1,
        policy=POLICY,
        authority_check=authority_revoked,
        witness_key=witness_key,
        trusted_witness_key=trusted_witness,
        decision_path=decision_log,
    )
    marker_v1 = workspace / ACTION_V1["filename"]
    if v1_committed:
        marker_content_unchanged = (
            marker_v1.exists() and marker_v1.read_text(encoding="utf-8") == ACTION_V1["content"]
        )
        second_effect_ok = effect_count == 1 and marker_content_unchanged
    else:
        second_effect_ok = effect_count == 0 and not marker_v1.exists()
    ok_v2 = decision_v2["decision"] == "DENY" and historical_ok and second_effect_ok
    emit("Same Jev judgment. Same action.")
    emit(f"Receiver: {decision_v2['decision']}")
    emit(f"Effect: {'executed' if not second_effect_ok else 'not executed'}")
    record(
        "V2",
        "PASS" if ok_v2 else "FAIL",
        f"decision={decision_v2['decision']}; receipt_still_verifies={historical_ok}; "
        f"effects={effect_count}; reasons={decision_v2['reason_codes']}",
    )

    # ---------------- V3: action substitution -> DENY -----------------------
    decision_v3 = evaluate_jev_vercel_witness(
        action=ACTION_B,
        evidence_receipt=evidence_v1,
        policy=POLICY,
        authority_check=authority_v1,
        witness_key=witness_key,
        trusted_witness_key=trusted_witness,
        decision_path=decision_log,
    )
    substituted_marker = workspace / ACTION_B["filename"]
    ok_v3 = (
        decision_v3["decision"] == "DENY"
        and "jev_vercel_evidence_action_binding_mismatch" in decision_v3["reason_codes"]
        and not substituted_marker.exists()
    )
    record(
        "V3",
        "PASS" if ok_v3 else "FAIL",
        f"decision={decision_v3['decision']}; substituted_effect_absent={not substituted_marker.exists()}; "
        f"reasons={decision_v3['reason_codes']}",
    )

    # ---------------- V4: evidence mutation -> verification failure ---------
    mutated = copy.deepcopy(evidence_v1)
    mutated["jev"]["state"] = {"action": "MUTATED"}
    try:
        verify_jev_vercel_evidence(
            mutated, expected_action=ACTION_V1, trusted_witness_key=trusted_witness
        )
        mutation_ok = False
    except JevVercelEvidenceError:
        mutation_ok = True
    decision_v4 = evaluate_jev_vercel_witness(
        action=ACTION_V1,
        evidence_receipt=mutated,
        policy=POLICY,
        authority_check=authority_v1,
        witness_key=witness_key,
        trusted_witness_key=trusted_witness,
        decision_path=decision_log,
    )
    ok_v4 = mutation_ok and decision_v4["decision"] == "DENY"
    record(
        "V4",
        "PASS" if ok_v4 else "FAIL",
        f"verification_failed={mutation_ok}; decision={decision_v4['decision']}; "
        f"reasons={decision_v4['reason_codes']}",
    )

    # ---------------- V5: receipt replay -> second effect refused -----------
    # Authority is restored first (ADMIT successor, sequence 3) so that the
    # DENY comes from the replay rule, not from the V2 revocation.
    if v1_committed:
        admit_projection(
            view,
            {
                "schema": STANDING_PROJECTION_SCHEMA,
                "projection_id": "jev-witness-demo-001/v1/restore",
                "issuer_id": "operator",
                "support_hash": support_v1,
                "action_hash": action_hash_v1,
                "standing": "ACTIVE",
                "event_type": "ADMIT",
                "sequence": 3,
                "predecessor_hash": view.head(support_v1, action_hash_v1)["payload_hash"],
                "issued_at": _iso(_utc_now()),
                "expires_at": _iso(_utc_now() + timedelta(hours=1)),
            },
            operator_key,
        )
        decision_v5, executed_v5 = protected_path(ACTION_V1, evidence_v1, authority_v1)
        ok_v5 = (
            decision_v5["decision"] == "DENY"
            and "evidence_replay" in decision_v5["reason_codes"]
            and not executed_v5
            and effect_count == 1
        )
        record(
            "V5",
            "PASS" if ok_v5 else "FAIL",
            f"decision={decision_v5['decision']}; effects={effect_count}; "
            f"reasons={decision_v5['reason_codes']}",
        )
    else:
        record(
            "V5",
            "NOT_APPLICABLE",
            "V1 did not COMMIT, so no receipt was consumed on the protected-effect "
            "path; nothing exists to replay. One-use ledger semantics are covered "
            "by pre-contact unit tests.",
            {"not_applicable": True},
        )
        ok_v5 = True

    case_ok = {
        "V1": results["V1"]["verdict"] == "PASS",
        "V2": ok_v2,
        "V3": ok_v3,
        "V4": ok_v4,
        "V5": ok_v5,
    }
    if all(case_ok.values()):
        terminal = (
            "PASS_JEV_WITNESS_DEMO_001"
            if not below_demo_threshold
            else "BELOW_DEMO_THRESHOLD"
        )
    elif not case_ok["V1"] and results["V1"]["verdict"] == "INCONCLUSIVE":
        terminal = "INCONCLUSIVE_PROVIDER_RUNTIME"
    elif not case_ok["V3"]:
        terminal = "FAIL_ACTION_BINDING"
    elif not case_ok["V2"]:
        terminal = "FAIL_STANDING_ENFORCEMENT"
    elif not case_ok["V4"]:
        terminal = "FAIL_EVIDENCE_INTEGRITY"
    else:
        terminal = "FAIL_REPLAY"

    summary = {
        "label": LABEL,
        "terminal": terminal,
        "signal_v1": signal_v1,
        "below_demo_threshold": below_demo_threshold,
        "effect_count": effect_count,
        "public_output": public_lines,
        "cases": results,
    }
    (run_dir / "results.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    (run_dir / "terminal_output.txt").write_text(
        "\n".join(public_lines) + "\n", encoding="utf-8"
    )
    if verbose:
        print(f"TERMINAL: {terminal}", flush=True)
        print(f"signal_v1={signal_v1:.4f} effects={effect_count}", flush=True)
    return summary


def main() -> int:
    stamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    run_dir = HERE.parent / "run" / stamp
    run_dir.mkdir(parents=True, exist_ok=True)

    # The exact frozen request is preserved with the run before contact.
    (run_dir / "frozen_request.json").write_text(
        json.dumps(FROZEN_REQUEST, indent=2, sort_keys=True), encoding="utf-8"
    )

    try:
        resp_body, resp_headers = live_jev_judgment(FROZEN_REQUEST)
    except RuntimeError as exc:
        results = {
            "label": LABEL,
            "terminal": "INCONCLUSIVE_PROVIDER_RUNTIME",
            "cases": {"V1": {"case": "V1", "verdict": "INCONCLUSIVE",
                             "detail": f"provider/transport failure before any judgment: {exc}"}},
        }
        (run_dir / "results.json").write_text(
            json.dumps(results, indent=2), encoding="utf-8"
        )
        print(f"V1: INCONCLUSIVE -- provider/transport failure before any judgment: {exc}", flush=True)
        print("TERMINAL: INCONCLUSIVE_PROVIDER_RUNTIME", flush=True)
        return 4
    (run_dir / "gateway_response.json").write_text(
        json.dumps({"body": resp_body, "headers": resp_headers}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    summary = run_sequence(resp_body, resp_headers, run_dir, verbose=True)
    terminal = summary["terminal"]
    return 0 if terminal in ("PASS_JEV_WITNESS_DEMO_001", "BELOW_DEMO_THRESHOLD") else 1


if __name__ == "__main__":
    sys.exit(main())
