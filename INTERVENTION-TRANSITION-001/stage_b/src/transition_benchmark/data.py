from __future__ import annotations
from pathlib import Path
import csv


def load_cells(path: Path, label_contexts: set[str] | None):
    """Load transition metadata; labels are parsed only for explicitly allowed contexts.

    A holdout row may contain an invalid label and this function must still succeed when
    that context is outside label_contexts. This is the Stage B calibration barrier.
    """
    rows=[]
    with path.open(newline="") as f:
        for r in csv.DictReader(f):
            cid=r["context_id"]
            y=None
            if label_contexts is not None and cid in label_contexts:
                y_fail=1-int(r["outcome_success"])
                if y_fail not in (0,1):
                    raise ValueError("Outcome must be binary")
                y=y_fail
            rows.append({
                "context_id":cid,
                "action_id":r["action_id"],
                "lag":int(float(r["lag"])),
                "y_fail":y,
            })
    return rows
