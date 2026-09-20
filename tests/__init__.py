"""tests package.

Byte-frozen historical test modules (see FROZEN_TEST_MODULES in
scripts/freeze_governance.py) are excluded from current-development
discovery: their source-closure assertions ("current HEAD must equal
historical source") go obsolete the moment production legitimately
evolves.  Their historical verification still runs -- via
``python scripts/freeze_governance.py verify-all``, which reconstructs
the exact frozen bytes from repository history and runs the original
verifiers against that snapshot root.

Drift between current source and a frozen closure is reported by the
governance harness; it is not a test failure.

NOTE: discovery must run with an explicit top-level directory above
tests/, e.g. ``python -m unittest discover -s tests -t .``.  With
``-s tests`` alone, unittest treats the start directory as its own top
level and never consults this package's load_tests hook.
"""

from __future__ import annotations

import pkgutil
import unittest

from scripts.freeze_governance import FROZEN_TEST_MODULES


def load_tests(loader, tests, ignore):
    suite = unittest.TestSuite()
    for module_info in pkgutil.iter_modules(__path__):
        name = module_info.name
        if not name.startswith("test_"):
            continue
        if name in FROZEN_TEST_MODULES:
            continue
        suite.addTests(loader.loadTestsFromName(f"tests.{name}"))
    return suite
