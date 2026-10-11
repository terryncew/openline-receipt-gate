#!/usr/bin/env python3
"""Measured construction: Gateway security/state machinery + OPA mandate policy.

This is a benchmark comparator, not a standalone equivalent OPA product.
It reuses exactly the Gateway service, including schema validation, signatures,
durable state, revocation reads, receipts, decision binding and standing.
Only mandate fit assessment is delegated to the real OPA process.
"""
from __future__ import annotations

import os
import sys
from datetime import timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from gateway.latency001.opa_shim import OpaClient
from olp_gate import mandate as mandate_module
from olp_gate import mandate_gate as mandate_gate_module

CLIENT = OpaClient(os.environ.get(
    "LATENCY_OPA_URL", "http://opa:8181/v1/data/gateway_mandate/decision"))


def assess_effect(mandate_value, effect_value, *, now):
    mandate = (mandate_value if isinstance(mandate_value, mandate_module.MandateSpec)
               else mandate_module.MandateSpec.from_mapping(mandate_value))
    effect = mandate_module.validate_effect(effect_value)
    result = CLIENT.query({
        "mandate": mandate.as_dict(), "effect": effect,
        "now_seconds": now.astimezone(timezone.utc).timestamp(),
        "expires_at_seconds": mandate_module._parse_time(mandate.expires_at).timestamp(),
    })
    allowed, reasons = result.get("allowed"), result.get("reason_codes")
    if (not isinstance(allowed, bool) or not isinstance(reasons, list)
            or not all(isinstance(reason, str) for reason in reasons)
            or allowed != (not reasons)):
        raise ValueError("invalid OPA assessment")
    return {
        "schema": "openline.principal_mandate.assessment.v1",
        "allowed": allowed,
        "decision": "COMMIT_ELIGIBLE" if allowed else "DENY",
        "reason_codes": sorted(set(reasons)),
        "mandate_hash": mandate.mandate_hash,
        "effect_hash": mandate_module._canonical_hash(effect),
        "policy_authority": "NONE",
    }


def install_policy_engine():
    # Both modules have an assess_effect reference. Install before importing
    # authz_server so its compiler/preflight imports cannot retain old aliases.
    mandate_module.assess_effect = assess_effect
    mandate_gate_module.assess_effect = assess_effect


if __name__ == "__main__":
    install_policy_engine()
    import authz_server
    authz_server.serve(int(sys.argv[1]) if len(sys.argv) > 1 else 50051)
