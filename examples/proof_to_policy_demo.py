from pathlib import Path
import json

from olp_gate.demo import run_demo


if __name__ == "__main__":
    result = run_demo(Path("results/proof_to_policy_demo"))
    print(json.dumps(result, indent=2))
