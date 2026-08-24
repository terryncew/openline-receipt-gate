from __future__ import annotations

import argparse
import json
from pathlib import Path

from external_selector import HERE, REPO, run_external


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--config", type=Path, default=HERE / "CONFIG.json")
    p.add_argument(
        "--source-contract",
        type=Path,
        default=REPO / "benchmarks/candidate_promotion/gdpa1_002/SOURCE.json",
    )
    p.add_argument(
        "--policy",
        type=Path,
        default=REPO / "benchmarks/candidate_promotion/gdpa1_002/promotion-policy.json",
    )
    p.add_argument(
        "--jain-cohort",
        type=Path,
        default=REPO
        / "benchmarks/candidate_promotion/results/jain_canonical_01/JAIN_2017_CANONICAL_COHORT.json",
    )
    args = p.parse_args()

    receipt, result, verdict = run_external(
        csv_path=args.csv,
        config_path=args.config,
        source_contract_path=args.source_contract,
        policy_path=args.policy,
        jain_cohort_path=args.jain_cohort,
    )
    dump(args.out_dir / "source-receipt.json", receipt)
    dump(args.out_dir / "external-result.json", result)
    dump(args.out_dir / "verdict.json", verdict)
    print(verdict["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
