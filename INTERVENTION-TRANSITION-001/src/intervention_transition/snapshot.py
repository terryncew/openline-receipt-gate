from __future__ import annotations
from pathlib import Path
import json
from .common import load_protocol, sha256_file

def _max_abs(np,a,b):
    if a.shape!=b.shape:
        return float("inf")
    if a.size==0:
        return 0.0
    return float(np.max(np.abs(a-b)))

def run_snapshot_fidelity(unitree_root: Path, outdir: Path, project_root: Path|None=None) -> dict:
    from .adapter import UnitreeG1Adapter
    project_root=project_root or Path.cwd()
    p=load_protocol(project_root)
    a=UnitreeG1Adapter(unitree_root,p)
    d=a.new_data(); w=a.new_wrapper()

    warm_steps=int(round(float(p["context_generation"]["warmup_seconds"])/a.dt))
    a.step_n(d,w,warm_steps)
    snap=a.snapshot(d,w)

    d1,w1=a.restore(snap)
    d2,w2=a.restore(snap)
    steps=int(p["snapshot"]["fidelity_steps"])

    max_state=0.0
    max_action=0.0
    max_target=0.0
    max_obs=0.0
    counter_match=True
    cmd_match=True

    for _ in range(steps):
        a.step(d1,w1); a.step(d2,w2)
        max_state=max(max_state,_max_abs(a.np,a.integration_state(d1),a.integration_state(d2)))
        max_action=max(max_action,_max_abs(a.np,w1.action,w2.action))
        max_target=max(max_target,_max_abs(a.np,w1.target_dof_pos,w2.target_dof_pos))
        max_obs=max(max_obs,_max_abs(a.np,w1.obs,w2.obs))
        counter_match=counter_match and (w1.counter==w2.counter)
        cmd_match=cmd_match and bool(a.np.array_equal(w1.cmd,w2.cmd))

    tol=float(p["snapshot"]["max_abs_state_error"])
    wtol=float(p["snapshot"]["max_abs_wrapper_error"])
    passed=(max_state<=tol and max_action<=wtol and max_target<=wtol and
            max_obs<=wtol and counter_match and cmd_match)
    r={
        "experiment_id":p["experiment_id"],
        "stage":"SNAPSHOT_FIDELITY",
        "status":"PASS_SNAPSHOT_FIDELITY" if passed else "FAIL_SNAPSHOT_FIDELITY",
        "steps":steps,
        "mujoco_state_spec":p["snapshot"]["mujoco_state_spec"],
        "max_abs_integration_state_error":max_state,
        "max_abs_action_error":max_action,
        "max_abs_target_dof_pos_error":max_target,
        "max_abs_obs_error":max_obs,
        "counter_match":counter_match,
        "cmd_match":cmd_match,
        "state_tolerance":tol,
        "wrapper_tolerance":wtol,
        "boundary":"PASS proves repeatable cloning for identical future controls. It does not prove intervention sufficiency."
    }
    outdir.mkdir(parents=True,exist_ok=True)
    rp=outdir/"snapshot_fidelity.json"
    rp.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
    (outdir/"snapshot_fidelity.sha256").write_text(sha256_file(rp)+"  snapshot_fidelity.json\n")
    if not passed:
        raise SystemExit(2)
    return r
