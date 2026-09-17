"""Crash-test driver for the BOUND-AUTHORITY-TEST-001 falsifier (T4).

Reserves through the real gate path (real mandate admission), marks the
effect boundary, signals readiness on stdout, then waits to be SIGKILLed
by the parent. Never commits. Usage: crash_child.py <args.json>.
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from olp_gate import capability_gate as gate  # noqa: E402
from olp_gate import capability_store as store  # noqa: E402
from olp_gate.mandate import (  # noqa: E402
    MandateSpec,
    compile_verified_commit_settings,
    validate_effect,
)
from olp_gate.mandate_gate import mandate_preflight  # noqa: E402


def main() -> None:
    args = json.loads(Path(sys.argv[1]).read_text())
    conn = store.open_store(args["db_path"])
    now = datetime.now(timezone.utc)
    mandate = MandateSpec.from_mapping(args["mandate"])
    effect = validate_effect(args["effect"])
    settings = compile_verified_commit_settings(mandate, effect, now=now)
    preflight = mandate_preflight(mandate, settings, now=now)
    assert preflight["allowed"] is True, preflight["reason_codes"]
    res = gate.reserve_for_effect(
        conn, preflight, effect,
        op_id=args["op_id"], now_unix=args["now_unix"],
        entry_ttl=args["entry_ttl"],
    )
    assert res["allowed"] is True, res
    token = res["reservation"]["token"]
    assert token, "no reservation token issued"
    gate.note_entry_for(conn, res["reservation"], args["capability_id"], token, args["now_unix"])
    print("BOUNDARY_MARKED", flush=True)
    time.sleep(600)


main()
