from __future__ import annotations
from pathlib import Path
import hashlib, json, random
import numpy as np
from .common import load_lock, sha256_file, canonical_sha256


def _flatten_tensor(t):
    if t is None:
        return np.empty(0, dtype=np.float64)
    return t.detach().cpu().numpy().astype(np.float64, copy=False).ravel()


def reconstruct_features(unitree_root: Path, stage_a_dir: Path, outdir: Path, project_root: Path) -> dict:
    from intervention_transition.adapter import UnitreeG1Adapter
    from intervention_transition.common import load_protocol

    lock = load_lock(project_root)
    protocol_root = project_root.parents[0]  # INTERVENTION-TRANSITION-001
    p = load_protocol(protocol_root)
    a = UnitreeG1Adapter(unitree_root, p)
    expected = {x["context_id"]: x for x in json.loads((stage_a_dir / "context_receipts.json").read_text())}
    if set(expected) != {f"g1-{i:03d}" for i in range(50)}:
        raise RuntimeError("Unexpected Stage A context set")

    cg = p["context_generation"]
    rng = random.Random(int(cg["seed"]))
    body = a.root_body_id()
    push_steps = int(round(float(cg["push_duration_seconds"]) / a.dt))
    warm_base = int(round(float(cg["warmup_seconds"]) / a.dt))

    context_ids, vectors, checks = [], [], []
    for i in range(int(cg["count"])):
        d = a.new_data(); w = a.new_wrapper()
        phase = float(cg["phase_offsets_seconds"][i % len(cg["phase_offsets_seconds"])])
        a.step_n(d, w, warm_base + int(round(phase / a.dt)))
        mag = float(rng.choice(cg["force_magnitudes_newtons"]))
        torque = float(rng.choice(cg["torque_magnitudes_nm"]))
        dx, dy = rng.choice(cg["force_directions_xy"])
        torque_sign = -1.0 if (i % 2) else 1.0
        d.xfrc_applied[body, :] = 0.0
        d.xfrc_applied[body, 0] = mag * float(dx)
        d.xfrc_applied[body, 1] = mag * float(dy)
        d.xfrc_applied[body, 4] = torque_sign * torque
        a.step_n(d, w, push_steps)
        d.xfrc_applied[body, :] = 0.0
        a.mujoco.mj_forward(a.model, d)
        snap = a.snapshot(d, w)
        cid = f"g1-{i:03d}"
        exp = expected[cid]
        integration_sha = hashlib.sha256(snap["integration"].tobytes()).hexdigest()
        wrapper_obj = {
            "action": [float(x) for x in snap["wrapper"].action],
            "target_dof_pos": [float(x) for x in snap["wrapper"].target_dof_pos],
            "obs": [float(x) for x in snap["wrapper"].obs],
            "counter": int(snap["wrapper"].counter),
            "cmd": [float(x) for x in snap["wrapper"].cmd],
            "policy_state": a.policy_state_hashes(snap["wrapper"]),
        }
        wrapper_sha = canonical_sha256(wrapper_obj)
        if integration_sha != exp["integration_state_sha256"] or wrapper_sha != exp["wrapper_state_sha256"]:
            raise RuntimeError(f"Context reproduction mismatch for {cid}")

        sw = snap["wrapper"]
        vec = np.concatenate([
            snap["integration"].astype(np.float64, copy=False).ravel(),
            np.asarray(sw.action, dtype=np.float64).ravel(),
            np.asarray(sw.target_dof_pos, dtype=np.float64).ravel(),
            np.asarray(sw.obs, dtype=np.float64).ravel(),
            np.asarray(sw.cmd, dtype=np.float64).ravel(),
            np.asarray([float(sw.counter)], dtype=np.float64),
            _flatten_tensor(sw.policy_hidden_state),
            _flatten_tensor(sw.policy_cell_state),
        ])
        if not np.all(np.isfinite(vec)):
            raise RuntimeError(f"Non-finite state feature for {cid}")
        context_ids.append(cid); vectors.append(vec)
        checks.append({"context_id": cid, "integration_state_sha256": integration_sha, "wrapper_state_sha256": wrapper_sha})

    dims = {len(v) for v in vectors}
    if len(dims) != 1:
        raise RuntimeError(f"Inconsistent feature dimensions: {dims}")
    X = np.stack(vectors)
    outdir.mkdir(parents=True, exist_ok=True)
    npz = outdir / "state_features.npz"
    np.savez_compressed(npz, context_ids=np.asarray(context_ids), X=X)
    receipt = {
        "experiment_id": lock["experiment_id"],
        "stage": "STAGE_B_FEATURE_RECONSTRUCTION",
        "status": "PASS_CONTEXT_REPRODUCTION",
        "contexts": len(context_ids),
        "feature_dimension": int(X.shape[1]),
        "feature_definition": [
            "mjSTATE_INTEGRATION",
            "previous policy action",
            "target joint positions",
            "observation vector",
            "command",
            "controller counter",
            "recurrent hidden state",
            "recurrent cell state",
        ],
        "outcome_columns_used": False,
        "state_features_sha256": sha256_file(npz),
        "context_checks": checks,
    }
    rp = outdir / "feature_receipt.json"
    rp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    (outdir / "feature_receipt.sha256").write_text(sha256_file(rp) + "  feature_receipt.json\n")
    return receipt
