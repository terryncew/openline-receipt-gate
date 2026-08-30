from __future__ import annotations
from pathlib import Path
import csv, hashlib, json, math, random, statistics
from .common import load_protocol, sha256_file, canonical_sha256

def _median(xs):
    return statistics.median(xs) if xs else None

def _manifest_sha(path:Path)->str:
    return sha256_file(path)

def run_oracle(unitree_root:Path,outdir:Path,project_root:Path|None=None)->dict:
    from .adapter import UnitreeG1Adapter
    project_root=project_root or Path.cwd()
    p=load_protocol(project_root)
    a=UnitreeG1Adapter(unitree_root,p)
    cg=p["context_generation"]
    actions=p["actions"]
    lags=[int(x) for x in p["lags_ms"]]
    rng=random.Random(int(cg["seed"]))
    body=a.root_body_id()

    rollout_steps=int(round(float(p["rollout"]["horizon_seconds"])/a.dt))
    final_window_steps=int(round(0.30/a.dt))
    push_steps=int(round(float(cg["push_duration_seconds"])/a.dt))
    warm_base=int(round(float(cg["warmup_seconds"])/a.dt))

    transitions=[]
    contexts=[]
    failures_by_reason={}
    for i in range(int(cg["count"])):
        d=a.new_data(); w=a.new_wrapper()

        phase=float(cg["phase_offsets_seconds"][i%len(cg["phase_offsets_seconds"])])
        a.step_n(d,w,warm_base+int(round(phase/a.dt)))

        mag=float(rng.choice(cg["force_magnitudes_newtons"]))
        torque=float(rng.choice(cg["torque_magnitudes_nm"]))
        dx,dy=rng.choice(cg["force_directions_xy"])
        torque_sign=-1.0 if (i%2) else 1.0

        # Apply the same physically realized perturbation once; snapshot after release.
        d.xfrc_applied[body,:]=0.0
        d.xfrc_applied[body,0]=mag*float(dx)
        d.xfrc_applied[body,1]=mag*float(dy)
        d.xfrc_applied[body,4]=torque_sign*torque
        a.step_n(d,w,push_steps)
        d.xfrc_applied[body,:]=0.0
        a.mujoco.mj_forward(a.model,d)

        snap=a.snapshot(d,w)
        context_id=f"g1-{i:03d}"
        context_sha=hashlib.sha256(snap["integration"].tobytes()).hexdigest()
        wrapper_obj={
            "action":[float(x) for x in snap["wrapper"].action],
            "target_dof_pos":[float(x) for x in snap["wrapper"].target_dof_pos],
            "obs":[float(x) for x in snap["wrapper"].obs],
            "counter":int(snap["wrapper"].counter),
            "cmd":[float(x) for x in snap["wrapper"].cmd],
            "policy_state":a.policy_state_hashes(snap["wrapper"]),
        }
        wrapper_sha=canonical_sha256(wrapper_obj)
        health=a.state_health(d)
        contexts.append({
            "context_id":context_id,
            "integration_state_sha256":context_sha,
            "wrapper_state_sha256":wrapper_sha,
            "phase_offset_seconds":phase,
            "push_force_newtons":mag,
            "push_direction_x":float(dx),
            "push_direction_y":float(dy),
            "push_pitch_torque_nm":torque_sign*torque,
            "snapshot_health":health,
        })

        for action_id,cmd in actions.items():
            for lag_ms in lags:
                bd,bw=a.restore(snap)
                original_cmd=bw.cmd.copy()
                requested_switch_step=int(math.ceil((lag_ms/1000.0)/a.dt))
                # Policy only consumes command at 50 Hz update; change the command
                # once wall-simulation lag has elapsed, then the next policy update uses it.
                switched=False
                failed=False
                failure_reason=None
                heights=[]; gh=[]
                intervention_active_step=None
                for step in range(rollout_steps):
                    if (not switched) and step>=requested_switch_step:
                        bw.cmd[:]=a.np.asarray(cmd,dtype=a.np.float64)
                        switched=True
                        intervention_active_step=step
                    a.step(bd,bw)
                    h=a.state_health(bd)
                    heights.append(h["height"])
                    gh.append(h["gravity_horizontal_norm"])
                    if switched:
                        if not h["finite"]:
                            failed=True; failure_reason="nonfinite"; break
                        if h["height"]<0.45:
                            failed=True; failure_reason="base_height"; break
                        if h["gravity_z"]>-0.35:
                            failed=True; failure_reason="orientation"; break
                if failed:
                    outcome=0
                    failures_by_reason[failure_reason]=failures_by_reason.get(failure_reason,0)+1
                else:
                    tail_h=heights[-final_window_steps:] if len(heights)>=final_window_steps else heights
                    tail_g=gh[-final_window_steps:] if len(gh)>=final_window_steps else gh
                    outcome=int(
                        bool(tail_h) and bool(tail_g) and
                        _median(tail_h)>=0.60 and _median(tail_g)<=0.45
                    )
                    if outcome==0:
                        failures_by_reason["terminal_target"]=failures_by_reason.get("terminal_target",0)+1

                transitions.append({
                    "context_id":context_id,
                    "action_id":action_id,
                    "lag":lag_ms,
                    "target_id":p["rollout"]["target_id"],
                    "constraint_set_id":p["rollout"]["constraint_set_id"],
                    "trial_id":f"{context_id}:{action_id}:{lag_ms}",
                    "outcome_success":outcome,
                    "requested_lag_ms":lag_ms,
                    "intervention_switch_step":intervention_active_step,
                    "effective_switch_ms":None if intervention_active_step is None else intervention_active_step*a.dt*1000.0,
                    "snapshot_integration_sha256":context_sha,
                    "snapshot_wrapper_sha256":wrapper_sha,
                })

    outdir.mkdir(parents=True,exist_ok=True)
    full=outdir/"oracle_transitions_full.csv"
    fields=list(transitions[0].keys())
    with full.open("w",newline="") as f:
        wri=csv.DictWriter(f,fieldnames=fields); wri.writeheader(); wri.writerows(transitions)

    # Canonical input to INTERVENTION-SUFFICIENCY-001.
    canonical=outdir/"intervention_sufficiency_input.csv"
    canon_fields=["context_id","action_id","lag","target_id","constraint_set_id","trial_id","outcome_success"]
    with canonical.open("w",newline="") as f:
        wri=csv.DictWriter(f,fieldnames=canon_fields); wri.writeheader()
        wri.writerows([{k:r[k] for k in canon_fields} for r in transitions])

    cp=outdir/"context_receipts.json"
    cp.write_text(json.dumps(contexts,indent=2,sort_keys=True)+"\n")

    manifest={
        "candidate_id":p["experiment_id"],
        "domain":"Unitree G1 / MuJoCo / released locomotion controller",
        "evidence_mode":"deterministic_rollout",
        "dataset_receipt_sha256":sha256_file(canonical),
        "context_definition":"Exact full MuJoCo integration state plus released deployment-loop mutable state and branch-local recurrent LSTM hidden/cell state after a frozen physical perturbation.",
        "matching_procedure":"Exact context_id identity; every action×lag arm restores the same integration-state and wrapper-state hashes.",
        "matching_frozen_before_outcome_analysis":True,
        "target_definition":p["rollout"]["target_id"],
        "constraint_definition":p["rollout"]["constraint_set_id"],
        "lag_unit":"milliseconds",
        "action_definition":"Frozen command-level interventions in config/protocol.frozen.json.",
        "model_validation_receipt_sha256":None,
    }
    mp=outdir/"intervention_sufficiency_manifest.json"
    mp.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")

    successes=sum(int(r["outcome_success"]) for r in transitions)
    r={
        "experiment_id":p["experiment_id"],
        "stage":"COUNTERFACTUAL_ORACLE",
        "status":"COMPLETE_ORACLE_READY_FOR_SUFFICIENCY_GATE",
        "contexts":len(contexts),
        "actions":len(actions),
        "lags":len(lags),
        "transition_cells":len(transitions),
        "success_cells":successes,
        "failure_cells":len(transitions)-successes,
        "failure_reasons":failures_by_reason,
        "canonical_dataset_sha256":sha256_file(canonical),
        "context_receipts_sha256":sha256_file(cp),
        "manifest_sha256":sha256_file(mp),
        "boundary":"This is deterministic counterfactual evidence under one frozen controller. It is not a physical viability claim and no learned probability is produced."
    }
    rp=outdir/"oracle_receipt.json"
    rp.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
    (outdir/"oracle_receipt.sha256").write_text(sha256_file(rp)+"  oracle_receipt.json\n")
    return r
