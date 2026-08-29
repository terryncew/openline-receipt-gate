from __future__ import annotations

from collections import defaultdict
from datetime import date
from pathlib import Path
import csv, hashlib, json, math, statistics

from .inventory import inventory
from .protocol import project_root, load_protocol, protocol_sha256


def _parse_date(s: str) -> date:
    s = s.strip().replace("/", "-")
    parts = [int(x) for x in s.split("-")[:3]]
    if len(parts) == 2:
        parts.append(1)
    return date(parts[0], parts[1], parts[2])


def _month_index(d: date) -> int:
    return d.year * 12 + d.month - 1


def _month_delta(a: date, b: date) -> int:
    """Whole calendar months from a to b."""
    return _month_index(b) - _month_index(a)


def _key(row: dict) -> tuple[str, str]:
    return (str(row["ID"]).strip(), str(row["group"]).strip())


def _read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def _find_one(root: Path, basename: str) -> Path:
    xs = list(root.rglob(basename))
    if len(xs) != 1:
        raise ValueError(f"expected exactly one {basename}, found {len(xs)}")
    return xs[0]


def _unique_index(rows: list[dict], label: str) -> dict[tuple[str, str], dict]:
    out = {}
    dup = []
    for r in rows:
        k = _key(r)
        if k in out:
            dup.append(k)
        out[k] = r
    if dup:
        raise ValueError(f"{label} has duplicate (ID,group) keys; first={dup[:10]}")
    return out


def _split_name(d: date, proto: dict) -> str | None:
    ym = f"{d.year:04d}-{d.month:02d}"
    for name in ("train", "validation", "holdout"):
        lo, hi = proto["split"][name]
        if lo <= ym <= hi:
            return name
    return None


def _numeric(v: str | None) -> float | None:
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except Exception:
        return None


def _candidate_twsa_match(stl_path: Path, recovery_rows: list[dict]) -> dict:
    """Find which released TWSA column most closely reproduces author init/min values.

    Only rows at the author-provided StartDate_dgt and min_TWSA_Date are retained.
    This is a schema/reproduction diagnostic; these outcome-side dates are forbidden
    as causal predictor inputs.
    """
    targets: dict[tuple[str, date], list[tuple[str, float]]] = defaultdict(list)
    for r in recovery_rows:
        iid = str(r["ID"]).strip()
        iv = _numeric(r.get("init_TWSA"))
        mv = _numeric(r.get("min_TWSA"))
        if iv is not None and r.get("StartDate_dgt"):
            targets[(iid, _parse_date(r["StartDate_dgt"]))].append(("init", iv))
        if mv is not None and r.get("min_TWSA_Date"):
            targets[(iid, _parse_date(r["min_TWSA_Date"]))].append(("min", mv))

    errors: dict[str, list[float]] = defaultdict(list)
    hits = 0
    with stl_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        rd = csv.DictReader(f)
        numeric_cols = [c for c in (rd.fieldnames or []) if c not in {"ID", "Date"}]
        for row in rd:
            k = (str(row["ID"]).strip(), _parse_date(row["Date"]))
            if k not in targets:
                continue
            hits += 1
            vals = {c: _numeric(row.get(c)) for c in numeric_cols}
            for _, target in targets[k]:
                for c, v in vals.items():
                    if v is not None:
                        errors[c].append(abs(v - target))

    ranked = []
    for c, es in errors.items():
        if not es:
            continue
        ranked.append({
            "column": c,
            "n": len(es),
            "median_abs_error": statistics.median(es),
            "mean_abs_error": statistics.fmean(es),
            "within_0_01_fraction": sum(e <= 0.01 for e in es) / len(es),
            "within_0_05_fraction": sum(e <= 0.05 for e in es) / len(es),
        })
    ranked.sort(key=lambda x: (x["median_abs_error"], x["mean_abs_error"]))
    return {"target_dates_found": hits, "ranked_columns": ranked[:12]}


def diagnose_science_lock(root: Path | None = None) -> dict:
    root = root or project_root()
    proto = load_protocol(root)
    inv = inventory(root)
    data_root = root / "data" / "work" / "data_bundle"

    severe_path = _find_one(data_root, "severe_drought_events_ensemble.csv")
    recovery_path = _find_one(data_root, "TWSA_recovery_one_95.csv")
    stl_path = _find_one(data_root, "data_TWSA_all_filled_stl.csv")

    severe = _read_csv(severe_path)
    recovery = _read_csv(recovery_path)
    sidx = _unique_index(severe, "severe_drought_events_ensemble")
    ridx = _unique_index(recovery, "TWSA_recovery_one_95")

    joined = []
    for k, s in sidx.items():
        r = ridx.get(k)
        if r is not None:
            joined.append((k, s, r))

    severe_coverage = len(joined) / len(sidx) if sidx else 0.0
    recovery_coverage = len(joined) / len(ridx) if ridx else 0.0

    # Test whether recovery-table EndDate_dgt is mechanically tied to the
    # post-loss recovery_time. If so, it is outcome-derived and cannot be t0.
    rec_consistency = []
    t0_vs_author_end = []
    min_vs_t0 = []
    rows = []
    split_counts = {"train": 0, "validation": 0, "holdout": 0, "outside": 0}
    followup_counts = {"train": 0, "validation": 0, "holdout": 0}

    for k, s, r in joined:
        t0 = _parse_date(s["EndDate"])
        split = _split_name(t0, proto)
        split_counts[split or "outside"] += 1

        # Dataset ends 2024-12. This is a t0-based equal 24-month follow-up gate.
        if split and _month_index(t0) <= _month_index(date(2022, 12, 1)):
            followup_counts[split] += 1

        amin = _parse_date(r["min_TWSA_Date"]) if r.get("min_TWSA_Date") else None
        aend = _parse_date(r["EndDate_dgt"]) if r.get("EndDate_dgt") else None
        rtime = _numeric(r.get("recovery_time"))
        recovered = str(r.get("recovered", "")).upper() == "TRUE"

        consistency_error = None
        if recovered and amin and aend and rtime is not None:
            consistency_error = abs(_month_delta(amin, aend) - rtime)
            rec_consistency.append(consistency_error)
        if aend:
            t0_vs_author_end.append(_month_delta(t0, aend))
        if amin:
            min_vs_t0.append(_month_delta(t0, amin))

        rows.append({
            "ID": k[0],
            "group": k[1],
            "severe_drought_start": s["StartDate"],
            "relief_t0": s["EndDate"],
            "split": split or "outside",
            "author_StartDate_dgt": r.get("StartDate_dgt"),
            "author_EndDate_dgt": r.get("EndDate_dgt"),
            "author_min_TWSA_Date": r.get("min_TWSA_Date"),
            "author_recovered": r.get("recovered"),
            "author_recovery_time": r.get("recovery_time"),
            "author_end_minus_t0_months": _month_delta(t0, aend) if aend else None,
            "author_min_minus_t0_months": _month_delta(t0, amin) if amin else None,
            "author_end_minus_min_minus_recovery_time_abs": consistency_error,
        })

    consistency_fraction = (
        sum(x <= 1.0 for x in rec_consistency) / len(rec_consistency)
        if rec_consistency else 0.0
    )
    outcome_derived_end = consistency_fraction >= 0.90

    twsa_match = _candidate_twsa_match(stl_path, recovery)
    best = twsa_match["ranked_columns"][0] if twsa_match["ranked_columns"] else None

    checks = [
        {
            "id": "episode_key_unique",
            "status": "PASS",
            "detail": {"severe_rows": len(sidx), "recovery_rows": len(ridx)},
        },
        {
            "id": "episode_join_coverage",
            "status": "PASS" if severe_coverage >= 0.90 and recovery_coverage >= 0.90 else "REVIEW",
            "detail": {
                "joined": len(joined),
                "severe_coverage": severe_coverage,
                "recovery_coverage": recovery_coverage,
            },
        },
        {
            "id": "author_EndDate_dgt_is_outcome_derived",
            "status": "PASS" if outcome_derived_end else "REVIEW",
            "detail": {
                "recovered_rows_checked": len(rec_consistency),
                "fraction_EndDate_minus_min_matches_recovery_time_within_1_month": consistency_fraction,
                "median_abs_month_error": statistics.median(rec_consistency) if rec_consistency else None,
            },
        },
        {
            "id": "twsa_series_reproduction_candidate",
            "status": "PASS" if best and best["within_0_05_fraction"] >= 0.80 else "REVIEW",
            "detail": best,
        },
        {
            "id": "chronological_split_has_episodes",
            "status": "PASS" if all(split_counts[x] > 0 for x in ("train", "validation", "holdout")) else "FAIL",
            "detail": {"split_counts": split_counts, "eligible_24m_followup": followup_counts},
        },
    ]

    hard_fail = any(c["status"] == "FAIL" for c in checks)
    needs_review = any(c["status"] == "REVIEW" for c in checks)

    lock_candidate = {
        "episode_key": ["ID", "group"],
        "relief_t0": {
            "table": "severe_drought_events_ensemble.csv",
            "column": "EndDate",
            "rationale": "Meteorological severe-drought episode end; independent of later TWS recovery.",
        },
        "forbidden_as_predictor_time_or_feature": [
            "TWSA_recovery_one_95.EndDate_dgt",
            "TWSA_recovery_one_95.min_TWSA_Date",
            "TWSA_recovery_one_95.recovered",
            "TWSA_recovery_one_95.recovery_time",
            "TWSA_recovery_one_95.recovery_ratio",
            "TWSA_recovery_one_95.max_rev_TWSA",
            "TWSA_recovery_one_95.recovery_rate",
            "TWSA_recovery_one_95.recovery_speed",
            "all measurements with Date > relief_t0",
        ],
        "predictor_preprocessing_boundary": {
            "allow": [
                "raw observed values timestamped <= relief_t0",
                "strictly trailing/cumulative transforms using only dates <= relief_t0",
                "static basin attributes",
                "history from earlier episodes only",
            ],
            "quarantine_until_causality_proven": [
                "STL-derived predictor columns",
                "gap-filled predictor columns",
                "centered smoothers",
                "whole-record normalizations",
            ],
        },
        "outcome_reconstruction_status": "PENDING_EXACT_COLUMN_LOCK",
        "best_twsa_reproduction_candidate": best,
    }

    report = {
        "experiment_id": proto["experiment_id"],
        "stage": "SCIENCE_LOCK_DIAGNOSTIC",
        "status": "FAIL" if hard_fail else ("REVIEW" if needs_review else "PASS_LOCK_DIAGNOSTIC"),
        "protocol_sha256": protocol_sha256(root),
        "checks": checks,
        "split_counts": split_counts,
        "eligible_24m_followup": followup_counts,
        "join_coverage": {
            "severe_events": len(sidx),
            "recovery_rows": len(ridx),
            "joined": len(joined),
            "severe_coverage": severe_coverage,
            "recovery_coverage": recovery_coverage,
        },
        "date_relationships": {
            "author_end_minus_relief_t0_months_median": statistics.median(t0_vs_author_end) if t0_vs_author_end else None,
            "author_min_minus_relief_t0_months_median": statistics.median(min_vs_t0) if min_vs_t0 else None,
            "author_end_is_outcome_derived": outcome_derived_end,
        },
        "twsa_match": twsa_match,
        "lock_candidate": lock_candidate,
        "boundary": (
            "This stage may freeze the causal episode key and relief t0, but it does not "
            "score Recoverability Margin. Outcome reconstruction must be locked from this receipt first."
        ),
    }

    outdir = root / "artifacts"
    outdir.mkdir(exist_ok=True)
    rp = outdir / "science_lock_diagnostic.json"
    rp.write_text(json.dumps(report, indent=2) + "\n")
    (outdir / "science_lock_diagnostic.sha256").write_text(
        hashlib.sha256(rp.read_bytes()).hexdigest() + "  science_lock_diagnostic.json\n"
    )

    ep = outdir / "science_lock_episode_sample.json"
    ep.write_text(json.dumps(rows[:100], indent=2) + "\n")

    if hard_fail:
        raise SystemExit(2)
    return report
