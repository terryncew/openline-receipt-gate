from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from jain_design import load_json, run_confirmatory


def main() -> int:
    parser = argparse.ArgumentParser(description="Run frozen CPG-001 Jain confirmatory replay on a normalized, source-bound artifact.")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    normalized = load_json(args.data)
    thresholds = load_json(HERE / "JAIN_2017_THRESHOLDS.json")
    design_lock = load_json(HERE / "JAIN_2017_DESIGN_LOCK.json")
    result = run_confirmatory(normalized, thresholds, design_lock)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
