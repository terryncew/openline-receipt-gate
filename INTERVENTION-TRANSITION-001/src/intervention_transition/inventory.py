from __future__ import annotations
from pathlib import Path
import json, subprocess, sys
from .common import sha256_file, load_protocol

def _git(repo: Path,*args:str)->str:
    return subprocess.check_output(["git","-C",str(repo),*args],text=True).strip()

def inventory(unitree_root: Path, outdir: Path, project_root: Path|None=None) -> dict:
    project_root=project_root or Path.cwd()
    p=load_protocol(project_root)
    exp=p["upstream"]["unitree_rl_gym"]
    actual_commit=_git(unitree_root,"rev-parse","HEAD")
    if actual_commit!=exp["commit"]:
        raise ValueError(f"Unitree commit mismatch: {actual_commit} != {exp['commit']}")
    files={}
    for key in ("deploy_script","config","policy","xml"):
        path=unitree_root/exp[key]
        if not path.is_file():
            raise FileNotFoundError(path)
        files[key]={
            "path":exp[key],
            "bytes":path.stat().st_size,
            "sha256":sha256_file(path),
        }
    receipt={
        "experiment_id":p["experiment_id"],
        "stage":"CONTROLLER_INVENTORY",
        "status":"PASS_CONTROLLER_INVENTORY",
        "unitree_commit":actual_commit,
        "mujoco_version_required":p["upstream"]["mujoco"]["version"],
        "files":files,
        "mutable_python_wrapper_state":p["controller"]["snapshot_python_state"],
        "constant_controller_state":p["controller"]["constant_controller_state"],
        "release_contract": {
            "simulation_dt_seconds":p["controller"]["simulation_dt_seconds"],
            "control_decimation":p["controller"]["control_decimation"],
            "policy_update_hz":p["controller"]["policy_update_hz"],
        },
        "boundary":"Inventory establishes the exact controller artifact and snapshot contract. It is not intervention evidence."
    }
    outdir.mkdir(parents=True,exist_ok=True)
    rp=outdir/"controller_inventory.json"
    rp.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    (outdir/"controller_inventory.sha256").write_text(sha256_file(rp)+"  controller_inventory.json\n")
    return receipt
