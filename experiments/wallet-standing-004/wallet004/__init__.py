"""Transport substrate for WALLET-STANDING-004.

This package does not implement wallet authority. It transports opaque 003
artifacts between isolated receiver processes and records durable local
admission timing.
"""

from .clock import Calibration, calibrate_gate, tau_measurement
from .wire import recv_json, send_json

__all__ = [
    "Calibration",
    "calibrate_gate",
    "tau_measurement",
    "recv_json",
    "send_json",
]
