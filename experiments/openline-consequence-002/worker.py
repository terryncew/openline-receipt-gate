"""Disposable offline worker. All keys/identity/clock are public TEST fixtures."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from fixtures import NOW, SUBJECT, key
from olp_gate.sqlite_consequence import SQLiteConsequence

if __name__ == '__main__':
    directory, implementation, stage = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    f = json.loads((directory/'fixture.json').read_text())
    adapter = SQLiteConsequence(directory/'state.sqlite3', roots=f['roots'],
        subject_source=lambda: SUBJECT, signing_key=key('74'), clock=lambda: NOW,
        implementation=implementation)
    def fault(point):
        if point == stage:
            os._exit(81 if point == 'before_commit' else 82)
    result = adapter.commission(f['receipt'], f['action'], one_use_code=f['code'], fault=fault)
    print(json.dumps(result), flush=True)
