from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class PreReliefState:
    state_deficit: float
    adverse_momentum: float
    drought_burden: float
    response_lag_months: float
    historical_recovery_capacity_per_month: float
    horizon_months: float = 24.0

def recoverability_margin(x: PreReliefState) -> float:
    if x.horizon_months <= 0 or x.response_lag_months < 0:
        raise ValueError("invalid horizon/lag")
    future_burden = (
        x.state_deficit
        + max(0.0, x.adverse_momentum) * x.response_lag_months
        + x.drought_burden
    )
    available_window = max(0.0, x.horizon_months - x.response_lag_months)
    available_recovery = x.historical_recovery_capacity_per_month * available_window
    return available_recovery - future_burden
