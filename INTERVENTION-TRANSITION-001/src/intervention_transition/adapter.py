from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import copy, json, math

@dataclass
class WrapperSnapshot:
    action: object
    target_dof_pos: object
    obs: object
    counter: int
    cmd: object

class UnitreeG1Adapter:
    """Headless reproduction of the released deploy_mujoco.py loop.

    Imports heavy dependencies lazily so unit tests for receipt logic stay stdlib-only.
    """
    def __init__(self, unitree_root: Path, protocol: dict):
        import mujoco, numpy as np, torch, yaml
        self.mujoco=mujoco
        self.np=np
        self.torch=torch
        self.protocol=protocol
        cfg_path=unitree_root/protocol["upstream"]["unitree_rl_gym"]["config"]
        with cfg_path.open() as f:
            c=yaml.safe_load(f)
        expand=lambda s: s.replace("{LEGGED_GYM_ROOT_DIR}",str(unitree_root))
        self.policy_path=Path(expand(c["policy_path"]))
        self.xml_path=Path(expand(c["xml_path"]))
        self.dt=float(c["simulation_dt"])
        self.decimation=int(c["control_decimation"])
        self.kps=np.asarray(c["kps"],dtype=np.float64)
        self.kds=np.asarray(c["kds"],dtype=np.float64)
        self.default=np.asarray(c["default_angles"],dtype=np.float64)
        self.ang_vel_scale=float(c["ang_vel_scale"])
        self.dof_pos_scale=float(c["dof_pos_scale"])
        self.dof_vel_scale=float(c["dof_vel_scale"])
        self.action_scale=float(c["action_scale"])
        self.cmd_scale=np.asarray(c["cmd_scale"],dtype=np.float64)
        self.num_actions=int(c["num_actions"])
        self.num_obs=int(c["num_obs"])
        self.initial_cmd=np.asarray(c["cmd_init"],dtype=np.float64)

        self.model=mujoco.MjModel.from_xml_path(str(self.xml_path))
        self.model.opt.timestep=self.dt
        self.policy=torch.jit.load(str(self.policy_path),map_location="cpu")
        self.policy.eval()
        torch.set_num_threads(1)
        try:
            torch.use_deterministic_algorithms(True)
        except Exception:
            pass

    def new_data(self):
        return self.mujoco.MjData(self.model)

    def new_wrapper(self):
        np=self.np
        return WrapperSnapshot(
            action=np.zeros(self.num_actions,dtype=np.float64),
            target_dof_pos=self.default.copy(),
            obs=np.zeros(self.num_obs,dtype=np.float64),
            counter=0,
            cmd=self.initial_cmd.copy(),
        )

    def gravity_orientation(self,q):
        np=self.np
        qw,qx,qy,qz=[float(x) for x in q]
        return np.asarray([
            2*(-qz*qx+qw*qy),
            -2*(qz*qy+qw*qx),
            1-2*(qw*qw+qz*qz)
        ],dtype=np.float64)

    def integration_state(self,data):
        n=self.mujoco.mj_stateSize(self.model,self.mujoco.mjtState.mjSTATE_INTEGRATION)
        x=self.np.empty(n,dtype=self.np.float64)
        self.mujoco.mj_getState(self.model,data,x,self.mujoco.mjtState.mjSTATE_INTEGRATION)
        return x

    def set_integration_state(self,data,x):
        self.mujoco.mj_setState(self.model,data,x,self.mujoco.mjtState.mjSTATE_INTEGRATION)
        self.mujoco.mj_forward(self.model,data)

    def copy_data(self,src):
        """Full in-memory MuJoCo branch copy.

        mjSTATE_INTEGRATION remains the portable state digest, but exact branching
        uses mj_copyData so engine-side state outside the portable state vector
        cannot silently differ between counterfactual arms.
        """
        dest=self.new_data()
        self.mujoco.mj_copyData(dest,self.model,src)
        return dest

    def snapshot(self,data,w):
        return {
            "data":self.copy_data(data),
            "integration":self.integration_state(data).copy(),
            "wrapper":WrapperSnapshot(
                action=w.action.copy(),
                target_dof_pos=w.target_dof_pos.copy(),
                obs=w.obs.copy(),
                counter=int(w.counter),
                cmd=w.cmd.copy(),
            ),
        }

    def restore(self,snap):
        d=self.copy_data(snap["data"])
        sw=snap["wrapper"]
        w=WrapperSnapshot(
            action=sw.action.copy(),target_dof_pos=sw.target_dof_pos.copy(),
            obs=sw.obs.copy(),counter=int(sw.counter),cmd=sw.cmd.copy()
        )
        return d,w

    def _policy_update(self,d,w):
        np=self.np
        qj=(d.qpos[7:]-self.default)*self.dof_pos_scale
        dqj=d.qvel[6:]*self.dof_vel_scale
        quat=d.qpos[3:7]
        omega=d.qvel[3:6]*self.ang_vel_scale
        gravity=self.gravity_orientation(quat)
        period=0.8
        count=w.counter*self.dt
        phase=count%period/period
        w.obs[:3]=omega
        w.obs[3:6]=gravity
        w.obs[6:9]=w.cmd*self.cmd_scale
        n=self.num_actions
        w.obs[9:9+n]=qj
        w.obs[9+n:9+2*n]=dqj
        w.obs[9+2*n:9+3*n]=w.action
        w.obs[9+3*n:9+3*n+2]=np.asarray([np.sin(2*np.pi*phase),np.cos(2*np.pi*phase)])
        t=self.torch.from_numpy(w.obs.astype(np.float32)).unsqueeze(0)
        with self.torch.no_grad():
            a=self.policy(t).detach().cpu().numpy().squeeze()
        w.action=a.astype(np.float64)
        w.target_dof_pos=w.action*self.action_scale+self.default

    def step(self,d,w):
        tau=(w.target_dof_pos-d.qpos[7:])*self.kps+(0.0-d.qvel[6:])*self.kds
        d.ctrl[:]=tau
        self.mujoco.mj_step(self.model,d)
        w.counter+=1
        if w.counter%self.decimation==0:
            self._policy_update(d,w)

    def step_n(self,d,w,n):
        for _ in range(int(n)):
            self.step(d,w)

    def root_body_id(self):
        # Prefer the free-joint root body; fallback to body 1.
        for name in ("pelvis","torso","base"):
            try:
                bid=self.mujoco.mj_name2id(self.model,self.mujoco.mjtObj.mjOBJ_BODY,name)
                if bid>=0:
                    return bid
            except Exception:
                pass
        return 1

    def state_health(self,d):
        g=self.gravity_orientation(d.qpos[3:7])
        return {
            "height":float(d.qpos[2]),
            "gravity_x":float(g[0]),
            "gravity_y":float(g[1]),
            "gravity_z":float(g[2]),
            "gravity_horizontal_norm":float(math.sqrt(float(g[0])**2+float(g[1])**2)),
            "finite":bool(self.np.all(self.np.isfinite(self.integration_state(d)))),
        }
