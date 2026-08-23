
from pathlib import Path
import sys,json,hashlib
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from iac002.generator import generate
from iac002.core import evaluate
p=json.loads((ROOT/"preregistration.json").read_text())
cases=generate(p)
(ROOT/"ground_truth_trials.json").write_text(json.dumps(cases,sort_keys=True,separators=(",",":"))+"\n")
res=evaluate(cases,p)
res["preregistration_sha256"]=hashlib.sha256((ROOT/"preregistration.json").read_bytes()).hexdigest()
res["ground_truth_sha256"]=hashlib.sha256((ROOT/"ground_truth_trials.json").read_bytes()).hexdigest()
(ROOT/"result.json").write_text(json.dumps(res,indent=2,sort_keys=True)+"\n")
print(json.dumps(res,indent=2,sort_keys=True))
