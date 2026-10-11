import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path('/workspace/openline-receipt-gate/gateway/receiver-package')))
from test_lithic_atomicity import AtomicityTests
from openline_receiver.lithic_adapter import SecureLithicAdapter

results = []
for kind in ('replace-corrupt', 'replace-empty', 'overwrite-header', 'truncate-main'):
    test = AtomicityTests(methodName='test_database_corruption_is_not_reinitialized')
    test.setUp()
    adapter = test.adapter
    checkpoint = list(adapter.db.execute('PRAGMA wal_checkpoint(TRUNCATE)'))
    before = test.db_path.stat()
    if kind.startswith('replace-'):
        replacement = test.directory / 'replacement.sqlite3'
        replacement.write_bytes(b'CORRUPT STATE' if kind == 'replace-corrupt' else b'')
        os.replace(replacement, test.db_path)
    elif kind == 'overwrite-header':
        with test.db_path.open('r+b') as file:
            file.write(b'CORRUPT STATE    ')
            file.flush()
            os.fsync(file.fileno())
    else:
        with test.db_path.open('wb') as file:
            file.write(b'CORRUPT STATE')
            file.flush()
            os.fsync(file.fileno())
    after = test.db_path.stat()
    row = {'case': kind, 'checkpoint': checkpoint, 'inode_changed': before.st_ino != after.st_ino,
           'size_before': before.st_size, 'size_after': after.st_size}
    try:
        row['response'] = adapter.handle_asa(test.request)
        row['live_decisions'] = adapter.db.execute('SELECT count(*) FROM decisions').fetchone()[0]
    except Exception as error:
        row['error'] = type(error).__name__
        row['cause'] = type(error.__cause__).__name__ if error.__cause__ else None
        row['cause_message'] = str(error.__cause__) if error.__cause__ else None
    test._close_adapter()
    try:
        reopened = SecureLithicAdapter(test.db_path, sandbox=False, expected_receiver_public_key=test.pinned_key)
        row['restart_response'] = reopened.handle_asa(test.request)
        reopened.close()
    except Exception as error:
        row['restart_error'] = type(error).__name__
        row['restart_cause'] = str(error.__cause__) if error.__cause__ else None
    results.append(row)
    test.doCleanups()
print(json.dumps(results, indent=2))
