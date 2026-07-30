#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from olp_gate.crypto import strict_json_load
from olp_gate.role_confusion import run_case_matrix
HERE=Path(__file__).resolve().parent
policy=strict_json_load(HERE/'receiver-policy.json')
cases=strict_json_load(HERE/'cases.json')
summary=run_case_matrix(cases,policy)
out=HERE/'results'/'hostile_report.json'
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k!='rows'},indent=2,sort_keys=True))
raise SystemExit(0 if summary['passed'] else 2)
