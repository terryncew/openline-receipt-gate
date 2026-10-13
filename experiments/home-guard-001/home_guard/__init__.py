"""HOME-GUARD-001 — bounded offline OpenLine Home Guard prototype.

Two independent, receiver-controlled boundaries, fully simulated:

  Boundary 1 (AI action authority): home_guard.receiver
  Boundary 2 (device-to-device reachability): home_guard.net_policy

No real devices, no network changes, no paid APIs. See THREAT_MODEL.md.
"""
from __future__ import annotations

import sys
from pathlib import Path


def _ensure_repo_root_on_path() -> None:
    # experiments/home-guard-001/home_guard/__init__.py -> parents[3] is repo root.
    repo_root = Path(__file__).resolve().parents[3]
    try:
        import olp_gate  # noqa: F401
    except ImportError:
        sys.path.insert(0, str(repo_root))


_ensure_repo_root_on_path()

__all__ = ["receiver", "devices", "net_policy", "keys", "demo"]
