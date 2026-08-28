"""Measurement-only clock calibration.

Calibration values are never passed into wallet003 admission functions. They
exist only to report transport timing after the receiver has made and durably
committed its local decision.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import time
from typing import Any

from .wire import send_json


@dataclass(frozen=True)
class Calibration:
    gate_id: str
    offset_ns: int  # gate_clock - emitter_clock
    uncertainty_ns: int
    rtt_ns: int
    sample_count: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def calibrate_gate(host: str, port: int, gate_id: str, *, samples: int = 7) -> Calibration:
    if samples < 3:
        raise ValueError("samples_must_be_at_least_3")
    rows: list[tuple[int, int]] = []
    for _ in range(samples):
        t0 = time.time_ns()
        response = send_json(host, port, {"op": "CALIBRATE", "client_send_ns": t0})
        t3 = time.time_ns()
        if response.get("ok") is not True or response.get("gate_id") != gate_id:
            raise RuntimeError("calibration_failed")
        t1 = int(response["gate_receive_ns"])
        t2 = int(response["gate_send_ns"])
        rtt = max(0, (t3 - t0) - max(0, t2 - t1))
        offset = ((t1 - t0) + (t2 - t3)) // 2
        rows.append((rtt, offset))
    rtt, offset = min(rows, key=lambda row: row[0])
    return Calibration(
        gate_id=gate_id,
        offset_ns=offset,
        uncertainty_ns=max(1, rtt // 2),
        rtt_ns=rtt,
        sample_count=samples,
    )


def tau_measurement(
    *,
    emitted_ns: int,
    commit_complete_ns: int | None,
    calibration: Calibration,
) -> dict[str, Any]:
    if commit_complete_ns is None:
        return {
            "status": "CENSORED_UNDELIVERED",
            "raw_ns": None,
            "offset_corrected_ns": None,
            "uncertainty_ns": calibration.uncertainty_ns,
            "display": "undefined/censored",
        }
    raw = int(commit_complete_ns) - int(emitted_ns)
    corrected = raw - int(calibration.offset_ns)
    if abs(corrected) <= calibration.uncertainty_ns:
        display = "<= clock resolution"
    else:
        display = f"{corrected / 1_000_000:.3f} ms"
    return {
        "status": "MEASURED",
        "raw_ns": raw,
        "offset_corrected_ns": corrected,
        "uncertainty_ns": calibration.uncertainty_ns,
        "display": display,
    }
