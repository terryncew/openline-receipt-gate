from __future__ import annotations

from collections import defaultdict
from datetime import date
from pathlib import Path
import csv, hashlib, json, math, statistics

from .inventory import inventory
from .protocol import project_root, load_protocol, protocol_sha256


OBS_COLS = ("CSR", "GSFC", "JPL")
STATIC_COLS = ("AI", "pIRR", "pSNOW", "MAP", "MAT", "area_log", "fReser_MAP")


def _parse_date(s: str) -> date:
    s = str(s).strip().replace("/", "-")
    p = [int(x) for x in s.split("-")[:3]]
    if len(p) == 2:
        p.append(1)
    return date(p[0], p[1], p[2])


def _month_index(d: date) -> int:
    return d.year * 12 + d.month - 1


def _add_months(d: date, n: int) -> date:
    x = _month_index(d) + n
    return date(x // 12, x % 12 + 1, 1)


def _months_between(a: date, b: date) -> int:
    return _month_index(b) - _month_index(a)


def _num(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except Exception:
        return None


def _median(xs):
    ys = [x for x in xs if x is not None and math.isfinite(x)]
    return statistics.median(ys) if ys else None


def _mean(xs):
    ys = [x for x in xs if x is not None and math.isfinite(x)]
    return statistics.fmean(ys) if ys else None


def _variance(xs):
    ys = [x for x in xs if x is not None and math.isfinite(x)]
    return statistics.variance(ys) if len(ys) >= 2 else None


def _slope(points):
    # x is month index; y is observed TWSA.
    if len(points) < 2:
        return None
    xs = [float(_month_index(d)) for d, _ in points]
    ys = [float(y) for _, y in points]
    xm, ym = statistics.fmean(xs), statistics.fmean(ys)
    den = sum((x - xm) ** 2 for x in xs)
    if den == 0:
        return None
    return sum((x - xm) * (y - ym) for x, y in zip(xs, ys)) / den


def _ar1(points):
    ys = [float(y) for _, y in points]
    if len(ys) < 3:
        return None
    a, b = ys[:-1], ys[1:]
    am, bm = statistics.fmean(a), statistics.fmean(b)
    den = math.sqrt(sum((x-am)**2 for x in a) * sum((x-bm)**2 for x in b))
    if den == 0:
        return 0.0
    return sum((x-am)*(x-bm) for x, y in zip(a, b)) / den


def _read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def _find_one(root: Path, basename: str) -> Path:
    xs = list(root.rglob(basename))
    if len(xs) != 1:
        raise ValueError(f"expected one {basename}, found {len(xs)}")
    return xs[0]


def _split_name(d: date, proto: dict) -> str | None:
    ym = f"{d.year:04d}-{d.month:02d}"
    for name in ("train", "validation", "holdout"):
        lo, hi = proto["split"][name]
        if lo <= ym <= hi:
            return name
    return None


def _canonical_hash(obj) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(b).hexdigest()


def _twsa_observed_series(path: Path):
    by_id = defaultdict(list)
    outcome = defaultdict(dict)
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        rd = csv.DictReader(f)
        for r in rd:
            iid = str(r["ID"]).strip()
            d = _parse_date(r["Date"])
            obs = _median([_num(r.get(c)) for c in OBS_COLS])
            if obs is not None:
                by_id[iid].append((d, obs))
            y = _num(r.get("TWSA_deseason_mov"))
            if y is not None:
                outcome[iid][d] = y
    for iid in by_id:
        by_id[iid].sort()
    return by_id, outcome


def _feature_row(event: dict, series: list[tuple[date, float]], drought_rows: list[dict], static: dict) -> tuple[dict | None, str | None]:
    start = _parse_date(event["StartDate"])
    t0 = _parse_date(event["EndDate"])

    # Fixed baseline: 24 calendar months ending immediately before meteorological drought onset.
    b0 = _add_months(start, -24)
    baseline_pts = [(d, y) for d, y in series if b0 <= d < start]
    if len(baseline_pts) < 6:
        return None, "baseline_obs"

    baseline = _median([y for _, y in baseline_pts])

    past = [(d, y) for d, y in series if d <= t0]
    if not past:
        return None, "no_pre_t0_twsa"
    current_d, current = past[-1]
    if _months_between(current_d, t0) > 3:
        return None, "stale_current_twsa"

    trend_candidates = [(d, y) for d, y in past if _add_months(t0, -12) <= d <= t0][-6:]
    if len(trend_candidates) < 4:
        return None, "trend_obs"
    trend = _slope(trend_candidates)
    if trend is None:
        return None, "trend_degenerate"

    resilience_pts = [(d, y) for d, y in past if _add_months(t0, -24) <= d <= t0][-12:]
    if len(resilience_pts) < 8:
        return None, "resilience_obs"
    ar1 = _ar1(resilience_pts)
    var = _variance([y for _, y in resilience_pts])
    if ar1 is None or var is None:
        return None, "resilience_degenerate"

    drought_in_event = []
    for r in drought_rows:
        d = _parse_date(r["Date"])
        if start <= d <= t0:
            drought_in_event.append(r)
    if not drought_in_event:
        return None, "drought_series_missing"
    mean_pd = _mean([_num(r.get("p_drought")) for r in drought_in_event])
    peak_pe = max([x for x in (_num(r.get("p_extreme")) for r in drought_in_event) if x is not None], default=None)
    if mean_pd is None or peak_pe is None:
        return None, "drought_values_missing"

    static_vals = {c: _num(static.get(c)) for c in STATIC_COLS}
    if any(v is None for v in static_vals.values()):
        return None, "static_missing"

    row = {
        "ID": str(event["ID"]).strip(),
        "group": str(event["group"]).strip(),
        "drought_start": start.isoformat(),
        "relief_t0": t0.isoformat(),
        "state_baseline": baseline,
        "state_current": current,
        "state_current_date": current_d.isoformat(),
        "state_deficit": baseline - current,
        "pre_relief_slope": trend,
        "adverse_momentum": max(0.0, -trend),
        "pre_relief_ar1": ar1,
        "pre_relief_variance": var,
        "duration_months": _num(event.get("Duration")),
        "extreme_duration_months": _num(event.get("Duration_Extreme")),
        "mean_p_drought": mean_pd,
        "peak_p_extreme": peak_pe,
        **{f"static_{k}": v for k, v in static_vals.items()},
    }
    if row["duration_months"] is None or row["extreme_duration_months"] is None:
        return None, "event_duration_missing"
    return row, None


def _direct_outcome(t0: date, rr: dict, outcome_series: dict[date, float], horizon_months: int = 24) -> tuple[int | None, dict]:
    init = _num(rr.get("init_TWSA"))
    minv = _num(rr.get("min_TWSA"))
    if init is None or minv is None or not rr.get("min_TWSA_Date"):
        return None, {"reason": "label_fields_missing"}
    min_d = _parse_date(rr["min_TWSA_Date"])
    threshold = minv + 0.90 * (init - minv)
    end = _add_months(t0, horizon_months)
    search_start = max(t0, min_d)

    hit = None
    for d in sorted(outcome_series):
        if search_start <= d <= end and outcome_series[d] >= threshold:
            hit = d
            break
    y = 1 if hit is not None else 0
    return y, {
        "threshold": threshold,
        "search_start": search_start.isoformat(),
        "search_end": end.isoformat(),
        "first_crossing": hit.isoformat() if hit else None,
    }


def _author_expected_outcome(t0: date, rr: dict, horizon_months: int = 24) -> int:
    recovered = str(rr.get("recovered", "")).strip().upper() == "TRUE"
    if not recovered or not rr.get("EndDate_dgt"):
        return 0
    return int(_parse_date(rr["EndDate_dgt"]) <= _add_months(t0, horizon_months))


def build_episode_lock(root: Path | None = None) -> dict:
    root = root or project_root()
    proto = load_protocol(root)
    lock = json.loads((root / "config" / "science_lock.frozen.json").read_text())
    inventory(root)
    data_root = root / "data" / "work" / "data_bundle"

    severe = _read_csv(_find_one(data_root, "severe_drought_events_ensemble.csv"))
    recovery = _read_csv(_find_one(data_root, "TWSA_recovery_one_95.csv"))
    basin_attr = _read_csv(_find_one(data_root, "basin_attr.csv"))
    spei = _read_csv(_find_one(data_root, "basin_ensemble_spei06.csv"))
    twsa_obs, twsa_outcome = _twsa_observed_series(_find_one(data_root, "data_TWSA_all_filled_stl.csv"))

    rec_idx = {(str(r["ID"]).strip(), str(r["group"]).strip()): r for r in recovery}
    attr_idx = {str(r["ID"]).strip(): r for r in basin_attr}
    spei_idx = defaultdict(list)
    for r in spei:
        spei_idx[str(r["ID"]).strip()].append(r)

    tv_rows = []
    holdout_hash_rows = []
    feature_counts = {"train": 0, "validation": 0, "holdout": 0}
    raw_counts = {"train": 0, "validation": 0, "holdout": 0, "outside": 0}
    missing = defaultdict(lambda: defaultdict(int))
    label_checks = {"train": {"n": 0, "agree": 0, "positive": 0},
                    "validation": {"n": 0, "agree": 0, "positive": 0}}
    holdout_keys = []

    for ev in severe:
        iid = str(ev["ID"]).strip()
        k = (iid, str(ev["group"]).strip())
        t0 = _parse_date(ev["EndDate"])
        split = _split_name(t0, proto)
        raw_counts[split or "outside"] += 1
        if split not in ("train", "validation", "holdout"):
            continue
        rr = rec_idx.get(k)
        if rr is None:
            missing[split]["recovery_join"] += 1
            continue
        static = attr_idx.get(iid)
        if static is None:
            missing[split]["basin_attr"] += 1
            continue

        feat, reason = _feature_row(ev, twsa_obs.get(iid, []), spei_idx.get(iid, []), static)
        if feat is None:
            missing[split][reason or "feature_unknown"] += 1
            continue
        feat["split"] = split
        feature_counts[split] += 1

        if split in ("train", "validation"):
            y, detail = _direct_outcome(t0, rr, twsa_outcome.get(iid, {}), lock["outcome"]["horizon_months"])
            if y is None:
                missing[split]["label_missing"] += 1
                feature_counts[split] -= 1
                continue
            expected = _author_expected_outcome(t0, rr, lock["outcome"]["horizon_months"])
            c = label_checks[split]
            c["n"] += 1
            c["agree"] += int(y == expected)
            c["positive"] += y
            feat["recovered_within_24m"] = y
            feat["label_threshold"] = detail["threshold"]
            feat["label_first_crossing"] = detail["first_crossing"]
            tv_rows.append(feat)
        else:
            # Holdout labels are deliberately not constructed here.
            visible = {
                "ID": feat["ID"],
                "group": feat["group"],
                "relief_t0": feat["relief_t0"],
                "feature_sha256": _canonical_hash(feat),
            }
            holdout_hash_rows.append(visible)
            holdout_keys.append((feat["ID"], feat["group"], feat["relief_t0"]))

    for s in ("train", "validation"):
        c = label_checks[s]
        c["agreement_fraction"] = c["agree"] / c["n"] if c["n"] else 0.0
        c["positive_fraction"] = c["positive"] / c["n"] if c["n"] else None

    label_agreement_ok = all(label_checks[s]["agreement_fraction"] >= 0.98 for s in ("train", "validation"))
    sample_size_ok = feature_counts["train"] >= 80 and feature_counts["validation"] >= 30 and feature_counts["holdout"] >= 30

    episode_definition = {
        "experiment_id": proto["experiment_id"],
        "science_lock_receipt_sha256": lock["science_lock_receipt_sha256"],
        "episode_key": ["ID", "group"],
        "relief_t0": "severe_drought_events_ensemble.EndDate",
        "primary_outcome": {
            "name": "TWSA recovery within 24 months after relief_t0",
            "label_series": "TWSA_deseason_mov",
            "recovery_fraction": 0.90,
            "threshold": "min_TWSA + 0.90 * (init_TWSA - min_TWSA)",
            "crossing_window": "max(relief_t0, min_TWSA_Date) through relief_t0 + 24 months",
            "label_only_fields": lock["outcome"]["label_only_columns"],
        },
        "predictor_boundary": {
            "timestamp": "<= relief_t0",
            "observed_twsa": {
                "columns": list(OBS_COLS),
                "monthly_value": "median of available nonmissing center observations",
                "no_fill_or_stl_predictors": True,
            },
            "state_baseline": "median observed TWSA in 24 calendar months before meteorological drought onset; >=6 observations",
            "state_current": "latest observed TWSA <= relief_t0 and no more than 3 months old",
            "trend": "OLS slope of last 6 observed TWSA values in trailing 12 months; >=4 observations",
            "critical_slowing": "AR(1) and variance of last 12 observed TWSA values in trailing 24 months; >=8 observations",
            "drought": "Duration, Duration_Extreme, mean p_drought, peak p_extreme over the severe-drought event",
            "static_basin": list(STATIC_COLS),
        },
        "common_complete_case": True,
        "split": proto["split"],
        "holdout_rule": "2019-01 through 2022-12 labels remain unopened until final replay",
        "no_post_holdout_retuning": True,
    }

    outdir = root / "artifacts"
    outdir.mkdir(exist_ok=True)

    # Training + validation only: readable episode table.
    fieldnames = []
    for r in tv_rows:
        for k in r:
            if k not in fieldnames:
                fieldnames.append(k)
    with (outdir / "episode_lock_train_validation.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(tv_rows)

    (outdir / "holdout_feature_hashes.json").write_text(json.dumps({
        "count": len(holdout_hash_rows),
        "rows": holdout_hash_rows,
        "labels_constructed": False,
    }, indent=2) + "\n")

    ep_path = outdir / "episode_definition.lock.json"
    ep_path.write_text(json.dumps(episode_definition, indent=2) + "\n")
    ep_sha = hashlib.sha256(ep_path.read_bytes()).hexdigest()
    (outdir / "episode_definition.lock.sha256").write_text(ep_sha + "  episode_definition.lock.json\n")

    checks = [
        {
            "id": "outcome_reproduction_train_validation",
            "status": "PASS" if label_agreement_ok else "FAIL",
            "detail": label_checks,
        },
        {
            "id": "common_complete_case_size",
            "status": "PASS" if sample_size_ok else "FAIL",
            "detail": feature_counts,
        },
        {
            "id": "holdout_labels_still_closed",
            "status": "PASS",
            "detail": {"holdout_feature_rows_hashed": len(holdout_hash_rows), "labels_constructed": False},
        },
        {
            "id": "quarantined_preprocessing_excluded",
            "status": "PASS",
            "detail": lock["quarantined_predictor_material"],
        },
    ]
    hard_fail = any(c["status"] == "FAIL" for c in checks)

    report = {
        "experiment_id": proto["experiment_id"],
        "stage": "EPISODE_LOCK",
        "status": "FAIL" if hard_fail else "PASS_EPISODE_LOCK",
        "protocol_sha256": protocol_sha256(root),
        "science_lock_receipt_sha256": lock["science_lock_receipt_sha256"],
        "episode_definition_sha256": ep_sha,
        "raw_split_counts": raw_counts,
        "common_complete_case_counts": feature_counts,
        "missing_feature_reasons": {s: dict(v) for s, v in missing.items()},
        "train_validation_label_reproduction": label_checks,
        "checks": checks,
        "next_gate": "Training-only RM/baseline fit plus validation-only model/threshold freeze. Holdout remains unopened.",
        "boundary": "Green means episode/outcome/predictor definitions are frozen and reproducible. It is not evidence that Recoverability Margin works.",
    }
    rp = outdir / "episode_lock_report.json"
    rp.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "episode_lock_report.sha256").write_text(
        hashlib.sha256(rp.read_bytes()).hexdigest() + "  episode_lock_report.json\n"
    )

    if hard_fail:
        raise SystemExit(2)
    return report
