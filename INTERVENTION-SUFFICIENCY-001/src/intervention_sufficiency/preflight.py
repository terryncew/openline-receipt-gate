from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import csv, hashlib, json, math

REQUIRED_BASE = ("context_id", "action_id", "lag", "target_id", "constraint_set_id")

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def _read_json(path: Path) -> dict:
    return json.loads(path.read_text())

def _read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def _float(v, name: str) -> float:
    try:
        x = float(v)
    except Exception as e:
        raise ValueError(f"{name} is not numeric: {v!r}") from e
    if not math.isfinite(x):
        raise ValueError(f"{name} must be finite")
    return x

def _validate_manifest(manifest: dict, gate: dict) -> None:
    required = [
        "candidate_id", "domain", "evidence_mode", "dataset_receipt_sha256",
        "context_definition", "matching_procedure",
        "matching_frozen_before_outcome_analysis", "target_definition",
        "constraint_definition", "lag_unit", "action_definition"
    ]
    missing = [k for k in required if k not in manifest]
    if missing:
        raise ValueError(f"manifest missing: {missing}")
    mode = manifest["evidence_mode"]
    if mode not in gate["evidence_modes"]:
        raise ValueError(f"unsupported evidence_mode: {mode}")
    if not manifest["matching_frozen_before_outcome_analysis"]:
        raise ValueError("matching procedure was not frozen before outcome analysis")
    if not str(manifest["matching_procedure"]).strip():
        raise ValueError("matching_procedure must be explicit")
    if mode == "validated_dynamics_model":
        v = manifest.get("model_validation_receipt_sha256")
        if not v or len(str(v).replace("sha256:", "")) != 64:
            raise ValueError("validated_dynamics_model requires model_validation_receipt_sha256")

def _aggregate(rows: list[dict], mode: str, gate: dict) -> list[dict]:
    value_col = gate["evidence_modes"][mode]["required_value_column"]
    missing_cols = [c for c in REQUIRED_BASE + (value_col,) if c not in rows[0]]
    if missing_cols:
        raise ValueError(f"dataset missing required columns: {missing_cols}")

    grouped = defaultdict(list)
    for i, r in enumerate(rows):
        context = str(r["context_id"]).strip()
        action = str(r["action_id"]).strip()
        target = str(r["target_id"]).strip()
        constraints = str(r["constraint_set_id"]).strip()
        if not all([context, action, target, constraints]):
            raise ValueError(f"row {i+2}: blank identity field")
        lag = _float(r["lag"], "lag")
        if lag < 0:
            raise ValueError(f"row {i+2}: lag must be >= 0")

        score = _float(r[value_col], value_col)
        if mode in ("deterministic_rollout", "stochastic_rollout"):
            if score not in (0.0, 1.0):
                raise ValueError(f"row {i+2}: outcome_success must be 0 or 1")
        elif not 0.0 <= score <= 1.0:
            raise ValueError(f"row {i+2}: success_probability must be in [0,1]")
        grouped[(context, action, lag, target, constraints)].append(score)

    min_trials = int(gate["evidence_modes"][mode]["min_trials_per_cell"])
    cells = []
    for key, vals in grouped.items():
        if len(vals) < min_trials:
            continue
        context, action, lag, target, constraints = key
        cells.append({
            "context_id": context,
            "action_id": action,
            "lag": lag,
            "target_id": target,
            "constraint_set_id": constraints,
            "n": len(vals),
            "success_score": sum(vals) / len(vals),
        })
    return cells

def _inventory(cells: list[dict], gate: dict) -> dict:
    feasible = float(gate["contrast_thresholds"]["feasible_score"])
    infeasible = float(gate["contrast_thresholds"]["infeasible_score"])

    contexts = {c["context_id"] for c in cells}
    actions = {c["action_id"] for c in cells}
    lags = {c["lag"] for c in cells}

    by_context_lag = defaultdict(list)
    by_context_action = defaultdict(list)
    for c in cells:
        by_context_lag[(c["context_id"], c["lag"], c["target_id"], c["constraint_set_id"])].append(c)
        by_context_action[(c["context_id"], c["action_id"], c["target_id"], c["constraint_set_id"])].append(c)

    action_tested = 0
    remedy_divergent = 0
    remedy_examples = []
    for key, group in by_context_lag.items():
        if len({x["action_id"] for x in group}) >= 2:
            action_tested += 1
            hi = [x for x in group if x["success_score"] >= feasible]
            lo = [x for x in group if x["success_score"] <= infeasible]
            if hi and lo:
                remedy_divergent += 1
                if len(remedy_examples) < 10:
                    remedy_examples.append({
                        "context_id": key[0], "lag": key[1],
                        "target_id": key[2], "constraint_set_id": key[3],
                        "feasible_actions": sorted({x["action_id"] for x in hi}),
                        "infeasible_actions": sorted({x["action_id"] for x in lo}),
                    })

    lag_tested = 0
    lag_contractions = 0
    contraction_examples = []
    for key, group in by_context_action.items():
        vals = sorted(group, key=lambda x: x["lag"])
        if len({x["lag"] for x in vals}) >= 2:
            lag_tested += 1
            contraction = None
            for early in vals:
                if early["success_score"] < feasible:
                    continue
                for late in vals:
                    if late["lag"] > early["lag"] and late["success_score"] <= infeasible:
                        contraction = (early, late)
                        break
                if contraction:
                    break
            if contraction:
                lag_contractions += 1
                if len(contraction_examples) < 10:
                    e, l = contraction
                    contraction_examples.append({
                        "context_id": key[0], "action_id": key[1],
                        "target_id": key[2], "constraint_set_id": key[3],
                        "early_lag": e["lag"], "early_success_score": e["success_score"],
                        "late_lag": l["lag"], "late_success_score": l["success_score"],
                    })

    return {
        "unique_contexts": len(contexts),
        "transition_cells": len(cells),
        "unique_actions": len(actions),
        "unique_lags": len(lags),
        "action_tested_context_lag_groups": action_tested,
        "remedy_divergent_context_lag_groups": remedy_divergent,
        "lag_tested_context_action_groups": lag_tested,
        "lag_contraction_context_action_groups": lag_contractions,
        "success_like_cells": sum(c["success_score"] >= feasible for c in cells),
        "failure_like_cells": sum(c["success_score"] <= infeasible for c in cells),
        "remedy_divergence_examples": remedy_examples,
        "lag_contraction_examples": contraction_examples,
    }

def run_preflight(dataset_path: Path, manifest_path: Path, gate_path: Path, outdir: Path) -> dict:
    gate = _read_json(gate_path)
    manifest = _read_json(manifest_path)
    _validate_manifest(manifest, gate)

    actual_sha = _sha256(dataset_path)
    expected_sha = str(manifest["dataset_receipt_sha256"]).replace("sha256:", "")
    if actual_sha != expected_sha:
        raise ValueError(f"dataset SHA-256 mismatch: expected {expected_sha} got {actual_sha}")

    rows = _read_csv(dataset_path)
    if not rows:
        raise ValueError("dataset has no rows")
    cells = _aggregate(rows, manifest["evidence_mode"], gate)
    inv = _inventory(cells, gate)

    checks = []
    for name, minimum in gate["minimums"].items():
        actual = inv[name]
        checks.append({
            "id": name, "minimum": minimum, "actual": actual,
            "status": "PASS" if actual >= minimum else "FAIL",
        })

    failures = [c["id"] for c in checks if c["status"] == "FAIL"]
    status = gate["decision"]["pass"] if not failures else gate["decision"]["fail"]

    receipt = {
        "experiment_id": gate["experiment_id"],
        "candidate_id": manifest["candidate_id"],
        "domain": manifest["domain"],
        "evidence_mode": manifest["evidence_mode"],
        "status": status,
        "dataset_sha256": actual_sha,
        "gate_sha256": _sha256(gate_path),
        "manifest_sha256": _sha256(manifest_path),
        "inventory": inv,
        "checks": checks,
        "failure_reasons": failures,
        "next_step": (
            "Build and benchmark a direct action-conditioned transition model before any margin/scalar."
            if status == gate["decision"]["pass"]
            else "Reject this substrate for recoverability claims. Do not fit a margin or recovery scalar."
        ),
        "boundary": gate["decision"]["meaning"],
    }

    outdir.mkdir(parents=True, exist_ok=True)
    rp = outdir / "intervention_sufficiency_receipt.json"
    rp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    (outdir / "intervention_sufficiency_receipt.sha256").write_text(
        _sha256(rp) + "  intervention_sufficiency_receipt.json\n"
    )

    cp = outdir / "transition_cell_inventory.csv"
    fields = ["context_id","action_id","lag","target_id","constraint_set_id","n","success_score"]
    with cp.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(cells)
    (outdir / "transition_cell_inventory.sha256").write_text(
        _sha256(cp) + "  transition_cell_inventory.csv\n"
    )
    return receipt
