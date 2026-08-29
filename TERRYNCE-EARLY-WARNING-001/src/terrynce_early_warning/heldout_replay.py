from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import csv, hashlib, json, math, random, statistics

from .episode_lock import (
    _parse_date, _read_csv, _find_one, _direct_outcome, _author_expected_outcome,
    _twsa_observed_series
)
from .inventory import inventory
from .modeling import metrics, auroc
from .protocol import project_root


MODEL_NAMES = [
    "recoverability_margin",
    "state_only",
    "trend_only",
    "drought_severity_duration",
    "critical_slowing",
    "history_persistence",
    "best_single",
    "conventional_multivariable",
    "rm_augmented_conventional",
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _key(row: dict) -> tuple[str, str, str]:
    return (str(row["ID"]).strip(), str(row["group"]).strip(), str(row["relief_t0"]).strip())


def _pct(xs: list[float], q: float) -> float:
    if not xs:
        raise ValueError("empty percentile input")
    ys = sorted(xs)
    if len(ys) == 1:
        return ys[0]
    pos = (len(ys) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return ys[lo]
    frac = pos - lo
    return ys[lo] * (1 - frac) + ys[hi] * frac


def _brier_delta(rows: list[dict]) -> float:
    n = len(rows)
    if n == 0:
        raise ValueError("no rows")
    conv = sum((r["y"] - r["conventional_multivariable_probability"]) ** 2 for r in rows) / n
    aug = sum((r["y"] - r["rm_augmented_conventional_probability"]) ** 2 for r in rows) / n
    return conv - aug


def _cluster_bootstrap(rows: list[dict], reps: int, seed: int) -> dict:
    by_id = defaultdict(list)
    for r in rows:
        by_id[str(r["ID"])].append(r)
    clusters = sorted(by_id)
    if len(clusters) < 2:
        raise ValueError("need at least two basin clusters")
    rng = random.Random(seed)
    vals = []
    for _ in range(reps):
        sample = []
        for _j in range(len(clusters)):
            cid = rng.choice(clusters)
            sample.extend(by_id[cid])
        vals.append(_brier_delta(sample))
    return {
        "cluster": "ID",
        "unique_basins": len(clusters),
        "replicates": reps,
        "seed": seed,
        "lower_2_5": _pct(vals, 0.025),
        "median": _pct(vals, 0.50),
        "upper_97_5": _pct(vals, 0.975),
        "fraction_positive": sum(v > 0 for v in vals) / len(vals),
    }


def _warning_metrics(y_recovery: list[int], warn: list[int]) -> dict:
    y_fail = [1 - y for y in y_recovery]
    tp = sum(1 for y, w in zip(y_fail, warn) if y == 1 and w == 1)
    fn = sum(1 for y, w in zip(y_fail, warn) if y == 1 and w == 0)
    fp = sum(1 for y, w in zip(y_fail, warn) if y == 0 and w == 1)
    tn = sum(1 for y, w in zip(y_fail, warn) if y == 0 and w == 0)
    return {
        "warning_count": sum(warn),
        "sensitivity": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
    }


def replay(root: Path | None = None) -> dict:
    root = root or project_root()
    proto = json.loads((root / "config" / "heldout_replay_protocol.frozen.json").read_text())

    # Verify the exact pre-outcome artifacts before touching outcomes.
    frozen = root / "frozen"
    for name, expected in proto["pinned_sha256"].items():
        file_map = {
            "calibration_lock": "calibration.lock.json",
            "holdout_predictions": "holdout_predictions.lock.csv",
            "holdout_probabilities": "holdout_probabilities.lock.csv",
            "episode_definition": "episode_definition.lock.json",
        }
        got = _sha256(frozen / file_map[name])
        if got != expected:
            raise ValueError(f"pinned {name} hash mismatch: expected {expected} got {got}")

    cal = json.loads((frozen / "calibration.lock.json").read_text())
    if cal["holdout_labels_constructed"] is not False:
        raise ValueError("source calibration did not preserve closed holdout")
    if cal["holdout_probabilities_sha256"] != proto["pinned_sha256"]["holdout_probabilities"]:
        raise ValueError("calibration probability hash does not match replay protocol")

    preds = _read_csv(frozen / "holdout_predictions.lock.csv")
    if len(preds) != proto["holdout"]["expected_prediction_rows"]:
        raise ValueError(f"unexpected frozen prediction count: {len(preds)}")
    pred_idx = {_key(r): r for r in preds}
    if len(pred_idx) != len(preds):
        raise ValueError("duplicate frozen prediction keys")

    # Only now do we open the outcome-side data.
    inventory(root)
    data_root = root / "data" / "work" / "data_bundle"
    severe = _read_csv(_find_one(data_root, "severe_drought_events_ensemble.csv"))
    recovery = _read_csv(_find_one(data_root, "TWSA_recovery_one_95.csv"))
    _, twsa_outcome = _twsa_observed_series(_find_one(data_root, "data_TWSA_all_filled_stl.csv"))

    severe_idx = {
        (str(r["ID"]).strip(), str(r["group"]).strip(), _parse_date(r["EndDate"]).isoformat()): r
        for r in severe
    }
    rec_idx = {(str(r["ID"]).strip(), str(r["group"]).strip()): r for r in recovery}

    scored = []
    author_agree = 0
    reconstruction_n = 0

    for key, p in pred_idx.items():
        iid, group, t0s = key
        ev = severe_idx.get(key)
        rr = rec_idx.get((iid, group))
        if ev is None or rr is None:
            raise ValueError(f"missing outcome join for frozen prediction {key}")
        t0 = _parse_date(t0s)
        y, detail = _direct_outcome(
            t0, rr, twsa_outcome.get(iid, {}),
            proto["holdout"]["outcome_horizon_months"]
        )
        if y is None:
            raise ValueError(f"could not reconstruct holdout outcome {key}")
        expected = _author_expected_outcome(
            t0, rr, proto["holdout"]["outcome_horizon_months"]
        )
        reconstruction_n += 1
        author_agree += int(y == expected)

        row = {
            "ID": iid,
            "group": group,
            "relief_t0": t0s,
            "y": int(y),
            "author_expected_y": int(expected),
            "label_first_crossing": detail["first_crossing"],
            "recoverability_margin_raw": float(p["recoverability_margin_raw"]),
        }
        for name in MODEL_NAMES:
            row[f"{name}_probability"] = float(p[f"{name}_probability"])
            row[f"{name}_failure_risk"] = float(p[f"{name}_failure_risk"])
            row[f"{name}_warn"] = int(p[f"{name}_warn"])
        scored.append(row)

    agreement = author_agree / reconstruction_n if reconstruction_n else 0.0
    if agreement < proto["holdout"]["outcome_reconstruction_integrity_min_agreement"]:
        verdict = {
            "status": "OUTCOME_RECONSTRUCTION_FAILURE",
            "claim_survives": None,
            "reason": f"author/reconstructed outcome agreement {agreement:.6f} below frozen minimum",
        }
    else:
        y = [r["y"] for r in scored]
        if len(set(y)) < 2:
            verdict = {
                "status": "HOLDOUT_CLASS_DEGENERACY",
                "claim_survives": None,
                "reason": "held-out outcome contains only one class",
            }
        else:
            model_metrics = {}
            warning = {}
            for name in MODEL_NAMES:
                pr = [r[f"{name}_probability"] for r in scored]
                model_metrics[name] = metrics(y, pr)
                warning[name] = _warning_metrics(y, [r[f"{name}_warn"] for r in scored])

            recovered_rm = [r["recoverability_margin_raw"] for r in scored if r["y"] == 1]
            failed_rm = [r["recoverability_margin_raw"] for r in scored if r["y"] == 0]
            raw_rm_auc = auroc(y, [r["recoverability_margin_raw"] for r in scored])
            direction = {
                "mean_rm_recovered": statistics.fmean(recovered_rm),
                "mean_rm_nonrecovered": statistics.fmean(failed_rm),
                "auroc_raw_rm_for_recovery": raw_rm_auc,
            }
            direction["pass"] = (
                direction["mean_rm_recovered"] > direction["mean_rm_nonrecovered"]
                and raw_rm_auc is not None and raw_rm_auc > 0.5
            )

            delta = (
                model_metrics["conventional_multivariable"]["brier"]
                - model_metrics["rm_augmented_conventional"]["brier"]
            )
            boot_cfg = proto["primary_success"]["basin_cluster_bootstrap"]
            boot = _cluster_bootstrap(
                scored, int(boot_cfg["replicates"]), int(boot_cfg["seed"])
            )
            point_pass = delta > 0
            ci_pass = boot["lower_2_5"] > 0
            all_pass = direction["pass"] and point_pass and ci_pass

            verdict = {
                "status": "SURVIVES_HELDOUT" if all_pass else "FAILS_HELDOUT_RECOVERABILITY_CLAIM",
                "claim_survives": all_pass,
                "conditions": {
                    "rm_direction": direction["pass"],
                    "incremental_brier_positive": point_pass,
                    "cluster_bootstrap_95ci_excludes_zero_on_positive_side": ci_pass,
                },
                "incremental_brier": delta,
                "cluster_bootstrap": boot,
                "direction": direction,
            }

    # Write full score table and final receipt.
    outdir = root / "artifacts"
    outdir.mkdir(exist_ok=True)

    score_path = outdir / "heldout_scored.csv"
    fields = list(scored[0].keys()) if scored else []
    with score_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(scored)

    y = [r["y"] for r in scored]
    model_metrics = {}
    warning = {}
    if scored and len(set(y)) == 2:
        for name in MODEL_NAMES:
            model_metrics[name] = metrics(y, [r[f"{name}_probability"] for r in scored])
            warning[name] = _warning_metrics(y, [r[f"{name}_warn"] for r in scored])

    report = {
        "experiment_id": proto["experiment_id"],
        "stage": proto["stage"],
        "status": "COMPLETE",
        "source_green_calibration": proto["source_green_calibration"],
        "pinned_sha256": proto["pinned_sha256"],
        "holdout_rows": len(scored),
        "holdout_recovered": sum(y),
        "holdout_nonrecovered": len(y) - sum(y),
        "outcome_reconstruction_author_agreement": agreement,
        "model_metrics": model_metrics,
        "warning_metrics": warning,
        "primary_verdict": verdict,
        "limitation": proto["limitation_to_record"],
        "boundary": (
            "This result is frozen for TERRYNCE-EARLY-WARNING-001. "
            "No post-holdout tuning may overwrite it; any revised RM construction requires a new experiment ID and fresh holdout."
        ),
    }
    rp = outdir / "heldout_report.json"
    rp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    report_sha = _sha256(rp)
    (outdir / "heldout_report.sha256").write_text(report_sha + "  heldout_report.json\n")
    (outdir / "heldout_scored.sha256").write_text(_sha256(score_path) + "  heldout_scored.csv\n")

    return report
