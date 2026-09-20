# pytest collection mirror of the unittest discovery rule in
# tests/__init__.py: byte-frozen historical test modules are excluded from
# current-development runs.  Their historical verification runs via
# `python scripts/freeze_governance.py verify-all` against reconstructed
# frozen snapshot roots.  The canonical list lives in
# scripts/freeze_governance.py FROZEN_TEST_MODULES; the two must match
# (enforced by tests/test_freeze_governance.py).
collect_ignore = [
    "tests/test_x402_freeze.py",
    "tests/test_temporal_authority_001.py",
    "tests/test_peer_authority_001.py",
    "tests/test_role_confusion_freeze.py",
]
