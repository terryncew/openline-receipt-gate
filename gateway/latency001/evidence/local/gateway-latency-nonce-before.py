from pathlib import Path
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

root = Path('/workspace/openline-receipt-gate')
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / 'gateway'))
sys.path.insert(0, str(root / 'gateway' / 'tests'))
from test_latency_regressions import LatencySecurityRegressions

revision = '9461188'
source = subprocess.run(
    ['git', 'show', revision + ':gateway/authz_server.py'], cwd=root,
    check=True, capture_output=True, text=True).stdout
print('Frozen source: ' + revision + ':gateway/authz_server.py', flush=True)
print('Controlled schedule: 8 verified contenders; serialize writes only; '
      'require exactly 1 authorization.', flush=True)
with tempfile.TemporaryDirectory(prefix='nonce-frozen-source-') as temporary:
    module_path = Path(temporary) / 'authz_server.py'
    module_path.write_text(source)
    spec = importlib.util.spec_from_file_location('frozen_authz', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with mock.patch.dict(sys.modules, {'authz_server': module}):
        suite = unittest.TestSuite([LatencySecurityRegressions(
            'test_simultaneous_nonce_claim_mints_exactly_one_token')])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
