from __future__ import annotations
from .margin import PreReliefState, recoverability_margin

def smoke_receipt() -> dict:
    easy = PreReliefState(0.5, 0.01, 0.2, 2.0, 0.08)
    hard = PreReliefState(1.5, 0.06, 1.0, 8.0, 0.03)
    a = recoverability_margin(easy)
    b = recoverability_margin(hard)
    if not a > b:
        raise AssertionError("margin should shrink as burden/lag rise and capacity falls")
    return {
        "status": "PASS",
        "higher_recoverability_example": a,
        "lower_recoverability_example": b,
        "note": "Synthetic smoke test only; no scientific evidence."
    }
