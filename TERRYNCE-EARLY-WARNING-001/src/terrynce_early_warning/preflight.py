from __future__ import annotations
from pathlib import Path
import hashlib, json
from .protocol import project_root, protocol_sha256
from .inventory import inventory

def preflight(root: Path | None = None) -> dict:
    root = root or project_root()
    acq_path = root / "artifacts" / "acquisition_receipt.json"
    if not acq_path.exists():
        raise FileNotFoundError("run acquire first")
    acq = json.loads(acq_path.read_text())
    if acq.get("status") != "PASS" or not all(x.get("verified") for x in acq.get("files", [])):
        raise ValueError("acquisition receipt is not verified")

    inv = inventory(root)
    checks = []
    checks.append({
        "id": "required_tables_present",
        "status": "PASS" if not inv["missing_required"] else "FAIL",
        "detail": inv["missing_required"],
    })
    checks.append({
        "id": "author_code_present",
        "status": "PASS" if inv["author_code"]["files"] else "FAIL",
        "detail": {"files": inv["author_code"]["files"][:20]},
    })
    f = inv["author_code"]["findings"]
    checks.append({
        "id": "recovery_logic_visible",
        "status": "PASS" if f["recovery"] and f["twsa"] else "REVIEW",
        "detail": {"recovery_hits": len(f["recovery"]), "twsa_hits": len(f["twsa"]), "threshold95_hits": len(f["threshold_95"])},
    })

    # We deliberately do NOT guess the causal join here. The receipt exposes headers and
    # author-code lines so the next commit can freeze exact episode/relief/outcome mappings.
    hard_fail = any(c["status"] == "FAIL" for c in checks)
    report = {
        "experiment_id": "TERRYNCE-EARLY-WARNING-001",
        "stage": "DATA_PREFLIGHT",
        "status": "FAIL" if hard_fail else "PASS_DATA_PREFLIGHT",
        "protocol_sha256": protocol_sha256(root),
        "checks": checks,
        "science_lock_ready": False,
        "next_gate": "Freeze exact basin-id, t0 relief timestamp, 24-month TWSA recovery outcome, and <=t0 feature mapping from this receipt. No holdout scoring before that lock.",
        "boundary": "A green workflow proves data availability/schema inspection only. It is not evidence for Recoverability Margin.",
    }
    p = root / "artifacts" / "preflight_report.json"
    p.write_text(json.dumps(report, indent=2) + "\n")
    (root / "artifacts" / "preflight_report.sha256").write_text(
        hashlib.sha256(p.read_bytes()).hexdigest() + "  preflight_report.json\n"
    )
    if hard_fail:
        raise SystemExit(2)
    return report
