#!/usr/bin/env python3
"""Export a static scientific plot of a completed strict Docker matrix.

Requires matplotlib; this optional presentation tool never runs workloads.
"""
import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", "/tmp/gateway-latency-matplotlib")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    matrix = json.loads(args.matrix.read_text())
    if not matrix["passed"]:
        raise SystemExit("A passing required matrix is needed for this plot")
    cases = {c["plan"]["name"]: c for c in matrix["cases"]}

    def measured(name):
        case = cases[name]
        if not case["passed"]:
            raise ValueError("Cannot plot a failed row as a valid latency result: " + name)
        return case["benchmark"]["cases"][0]["successful_latency"]

    names = ["original-c1", "optimized-c1", "native-opa-a-c1",
             "native-opa-b-c1", "stateful-opa-c1", "envoy-floor-c1"]
    labels = ["Original", "Optimized", "Basic OPA", "OPA + revocation data",
              "Gateway wrapper + OPA", "Protected execution floor"]
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8), layout="constrained")
    for metric, marker, color in [("p50_ms", "o", "#126a92"),
                                   ("p95_ms", "^", "#b06215"),
                                   ("p99_ms", "s", "#814698")]:
        axes[0].scatter([measured(n)[metric] for n in names], range(len(names)),
                        marker=marker, color=color, label=metric[:3], s=44)
    axes[0].set_yticks(range(len(names)), labels)
    axes[0].invert_yaxis()
    axes[0].set(xlabel="Complete transfer response latency (ms)",
                title="Serial, 1,000 successful transfers per row", xlim=(0, None))
    axes[0].legend(frameon=False)
    concurrency = sorted(c["plan"]["concurrency"] for c in matrix["cases"]
                         if c["plan"]["name"].startswith("optimized-c"))
    extra = [measured(f"optimized-c{n}")["p50_ms"] -
             measured(f"envoy-floor-c{n}")["p50_ms"] for n in concurrency]
    axes[1].plot(concurrency, extra, "o-", color="#126a92")
    axes[1].axhline(25, color="#a83d3d", linestyle="--", label="25 ms target")
    axes[1].set(xticks=concurrency, xlabel="Concurrent closed-loop clients",
                ylabel="Difference of matched medians (ms)",
                title="Additional Gateway authorization cost\nStanding ON in Gateway and floor")
    axes[1].legend(frameon=False)
    for ax in axes:
        ax.grid(axis="x" if ax is axes[0] else "y", alpha=.2)
        ax.spines[["top", "right"]].set_visible(False)
    fig.suptitle("Linux Docker · FULL ledger writes · Envoy workers = 2")
    fig.supxlabel("OPA A/B have fewer security controls. Median differences are not paired-request percentiles.", fontsize=9)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output.with_suffix(".svg"))
    fig.savefig(args.output.with_suffix(".png"), dpi=180)


if __name__ == "__main__":
    main()
