from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from gdpa1_replay import run


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--source", default=str(HERE / "SOURCE.json"))
    parser.add_argument("--policy", default=str(HERE / "promotion-policy.json"))
    args = parser.parse_args()
    receipt, score, verdict = run(Path(args.csv), Path(args.source), Path(args.policy))
    out = Path(args.out_dir)
    dump(out / "source-receipt.json", receipt)
    dump(out / "score.json", score)
    dump(out / "verdict.json", verdict)
    print(verdict["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
