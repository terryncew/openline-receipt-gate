"""PLATFORM-EXIT-KILL-001 worker agent subprocess.

One OS process = one agent lifetime. The driver spawns this per phase
(A-era, A-restart, B-era, A-post-handoff) with ONLY that agent's key file,
mandate, and slot. The worker builds its proof-to-policy decision receipt
through the existing gate path and executes the mandated consequence via
execute_mandated_once against the shared durable receiver state.

Exit code is always 0; per-attempt outcomes (including refusals) are
written to --out for the driver/appraiser. A crash is therefore
distinguishable from a refusal.
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HARNESS = Path(__file__).resolve().parent
for _p in (str(REPO), str(HARNESS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gate_path as gp  # noqa: E402
from olp_gate.crypto import public_key_hex  # noqa: E402
from olp_gate.mandate import MandateSpec  # noqa: E402
from olp_gate.mandate_owner import MandateOwnerView  # noqa: E402
from olp_gate.verified_commit import VerifiedCommitLedger  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--agent", required=True, choices=("a", "b"))
    p.add_argument("--state-dir", required=True)
    p.add_argument("--agent-key-file", required=True)
    p.add_argument("--mandate-file", required=True)
    p.add_argument("--slot", required=True)
    p.add_argument("--gate-key-file", required=True)
    p.add_argument("--witness-key-file", required=True)
    p.add_argument("--source-key-file", required=True)
    p.add_argument("--slots-file", required=True)
    p.add_argument("--owner-pubkey", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--plan", required=True)
    p.add_argument("--run-now", required=True)
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    run_now = datetime.fromisoformat(args.run_now.replace("Z", "+00:00"))
    if run_now.tzinfo is None:
        run_now = run_now.replace(tzinfo=timezone.utc)
    state_dir = Path(args.state_dir)
    effects_dir = state_dir / "effects"

    agent_id = f"agent-{args.agent}"
    worker_key = gp.load_private_key(args.agent_key_file)
    mandate_dict = json.loads(Path(args.mandate_file).read_text(encoding="utf-8"))
    spec = MandateSpec.from_mapping(mandate_dict)
    slots = json.loads(Path(args.slots_file).read_text(encoding="utf-8"))
    gate_key = gp.load_private_key(args.gate_key_file)
    witness_key = gp.load_private_key(args.witness_key_file)
    source_key = gp.load_private_key(args.source_key_file)
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))

    gate = gp.GatePath(
        root=state_dir,
        run_now=run_now,
        gate_key=gate_key,
        witness_key=witness_key,
        source_key=source_key,
        source_method=f"did:example:platform-exit-source-{args.agent}#key-1",
    )
    gate_pub = public_key_hex(gate_key)

    outcomes: list[dict] = []
    for item in plan:
        attempt_id = item["attempt_id"]
        case = item["case"]
        effect_id = item["effect_id"]
        value_cents = int(item.get("value_cents", 60))
        record: dict = {
            "attempt_id": attempt_id,
            "case": case,
            "agent_id": agent_id,
            "slot": args.slot,
        }
        try:
            effect = gp.build_effect(mandate_dict, effect_id, value_cents)
            settings = gp.compile_verified_commit_settings(
                spec, effect, now=run_now
            )
            # Separate mandate-fit computation: proves a later refusal is a
            # standing failure, not a format failure.
            preflight = gp.mandate_preflight(mandate_dict, settings, now=run_now)
            record["preflight_allowed"] = preflight["allowed"] is True
            record["preflight_reasons"] = preflight["reason_codes"]
            record["effect_hash"] = preflight["evidence"]["effect_hash"]

            receipt, action, code = gate.issue_decision_receipt(
                attempt_id, settings
            )
            view = MandateOwnerView(slots, durable_path=str(state_dir / "owner_heads.json"))
            ledger = VerifiedCommitLedger(state_dir / "commit_ledger.json")
            marker, executor = gp.make_executor(
                effects_dir, agent_id, case, attempt_id, effect_id
            )
            result = gp.execute_mandated_once(
                ledger,
                receipt,
                action,
                mandate=spec,
                one_use_code=code,
                trusted_gate_keys=[gate_pub],
                executor=executor,
                now=run_now,
                attempt_label=attempt_id,
                mandate_owner_view=view,
                mandate_slot_id=args.slot,
            )
            record["authorized"] = result["authorized"] is True
            record["reason_codes"] = result.get("reason_codes", [])
            record["execution_status"] = result.get("execution_status")
            record["marker_exists"] = marker.exists()
            # The authoritative observation, read back from the journal.
            state = ledger.read_state()
            journal_hit = None
            for attempt in state.get("attempts", []):
                if attempt.get("attempt_label") == attempt_id:
                    journal_hit = attempt
            if journal_hit is None:
                record["journal_error"] = "attempt_not_in_journal"
            else:
                record["journal_result"] = journal_hit.get("result")
                record["journal_execution_status"] = journal_hit.get(
                    "execution_status"
                )
                record["commit_seq"] = journal_hit.get("commit_seq")
                record["standing_final_check"] = journal_hit.get(
                    "standing_final_check_v1"
                )
                record["path_verdict"] = journal_hit.get("path_verdict_v1")
                record["stop_effective_seq"] = journal_hit.get("stop_effective_seq")
            record["attestation"] = gp.attest_attempt(
                worker_key, agent_id, attempt_id, record["effect_hash"]
            )
        except Exception as exc:  # harness-level: record, do not crash the batch
            record["worker_error"] = f"{type(exc).__name__}:{exc}"
            record["worker_traceback"] = traceback.format_exc(limit=5)
        outcomes.append(record)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            {
                "agent": agent_id,
                "slot": args.slot,
                "outcomes": outcomes,
                "worker_pubkey": public_key_hex(worker_key),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
