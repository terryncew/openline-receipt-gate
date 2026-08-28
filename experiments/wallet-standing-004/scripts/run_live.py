#!/usr/bin/env python3
"""Run WALLET-STANDING-004 over isolated TCP Gate processes.

The protocol surface from WALLET-STANDING-001/002/003 is imported unchanged.
004 changes only the epistemic substrate: process isolation, per-Gate SQLite
state, socket transport, adversarial relay schedules, and measurement-only
clock calibration.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EXPERIMENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EXPERIMENT_ROOT.parents[1]
W1 = REPO_ROOT / "experiments" / "wallet-standing-001"
W2 = REPO_ROOT / "experiments" / "wallet-standing-002"
W3 = REPO_ROOT / "experiments" / "wallet-standing-003"
for path in (REPO_ROOT, W1, W2, W3, EXPERIMENT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from olp_gate.crypto import public_key_hex  # noqa: E402
from wallet001 import (  # noqa: E402
    AdmissionPolicy,
    build_presentation_bundle,
    issue_epoch_certificate,
    issue_mandate,
    issue_standing_witness,
)
from wallet002 import create_recovery_policy, create_root_succession_event  # noqa: E402
from wallet003 import (  # noqa: E402
    create_guardian_freeze,
    create_root_checkpoint,
    ingest_root_succession,
    initialize_distributed_gate,
)
from wallet004.clock import calibrate_gate, tau_measurement  # noqa: E402
from wallet004.envelope import create_envelope  # noqa: E402
from wallet004.wire import send_json  # noqa: E402

VERDICT = "LIVE_TRANSPORT_CONTINUITY_ENFORCED_WITH_MEASURED_PROPAGATION_LAG"
FAIL = "LIVE_TRANSPORT_CONTINUITY_BOUNDARY_NOT_ESTABLISHED"
CHALLENGE = "wallet-standing-004-gate"
REQUIRED_FIELDS = ("action", "amount_cents", "recipient")
RESULT_PATH = EXPERIMENT_ROOT / "live_result.json"


def _key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"wallet-standing-004:{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


class FrozenSaltSource:
    def __init__(self, label: str) -> None:
        self.label = label
        self.index = 0

    def __call__(self, size: int) -> bytes:
        if size != 32:
            raise ValueError("salt_size")
        raw = hashlib.sha256(f"wallet-standing-004:salt:{self.label}:{self.index}".encode()).digest()
        self.index += 1
        return raw


def _action(recipient: str, amount_cents: int) -> dict[str, Any]:
    return {"action": "transfer", "amount_cents": amount_cents, "recipient": recipient}


def _admission_policy_dict() -> dict[str, Any]:
    return {
        "high_risk_max_witness_age_seconds": 60,
        "low_risk_max_offline_ttl_seconds": 600,
        "required_fields": list(REQUIRED_FIELDS),
        "forbid_extra_disclosures": True,
    }


def _issue_bundle(
    root_key: Ed25519PrivateKey,
    subject_key: Ed25519PrivateKey,
    *,
    principal_id: str,
    epoch_id: str,
    mandate_id: str,
    action: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    epoch_key = _key(f"epoch:{epoch_id}")
    cert = issue_epoch_certificate(
        root_key,
        epoch_key,
        principal_id=principal_id,
        epoch_id=epoch_id,
        sequence=1,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=10),
    )
    mandate = issue_mandate(
        epoch_key,
        cert,
        mandate_id=mandate_id,
        subject_key=subject_key,
        risk_tier="HIGH",
        fields={**dict(action), "private_purpose": f"private:{mandate_id}"},
        issued_at=now - timedelta(milliseconds=500),
        expires_at=now + timedelta(minutes=5),
        epoch_salt_registry=set(),
        salt_source=FrozenSaltSource(mandate_id),
    )
    witness = issue_standing_witness(
        root_key,
        cert,
        standing="ACTIVE",
        sequence=1,
        issued_at=now - timedelta(milliseconds=250),
        expires_at=now + timedelta(minutes=2),
    )
    bundle = build_presentation_bundle(
        mandate,
        disclose_fields=REQUIRED_FIELDS,
        subject_key=subject_key,
        receiver_challenge=CHALLENGE,
        standing_witness=witness,
    )
    return {"bundle": bundle, "action": dict(action)}


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return int(port)


def _wait_port(port: int, timeout: float = 5.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError(f"port_not_ready:{port}")


def _pythonpath() -> str:
    roots = [REPO_ROOT, W1, W2, W3, EXPERIMENT_ROOT]
    existing = os.environ.get("PYTHONPATH")
    if existing:
        roots.append(Path(existing))
    return os.pathsep.join(str(p) for p in roots)


class Cluster:
    def __init__(self, root: Path, policy: Mapping[str, Any], policy_hash: str, measurement_pub: str) -> None:
        self.root = root
        self.policy = dict(policy)
        self.policy_hash = policy_hash
        self.measurement_pub = measurement_pub
        self.relay_port = _free_port()
        self.gate_ports = {name: _free_port() for name in ("gate-a", "gate-b", "gate-c")}
        self.procs: dict[str, subprocess.Popen] = {}
        self.calibration = {}
        env = os.environ.copy()
        env["PYTHONPATH"] = _pythonpath()
        self.env = env
        self._start_relay()
        self._start_gate("gate-a", False)
        self._start_gate("gate-b", False)
        self._start_gate("gate-c", True)
        for name, port in self.gate_ports.items():
            self.calibration[name] = calibrate_gate("127.0.0.1", port, name, samples=7)

    def _start_relay(self) -> None:
        cmd = [sys.executable, "-m", "wallet004.relay_server", "--port", str(self.relay_port)]
        self.procs["relay"] = subprocess.Popen(cmd, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        _wait_port(self.relay_port)

    def _start_gate(self, gate_id: str, virgin: bool) -> None:
        policy_b64 = base64.urlsafe_b64encode(json.dumps(self.policy, sort_keys=True).encode()).decode()
        cmd = [
            sys.executable,
            "-m",
            "wallet004.gate_server",
            "--gate-id",
            gate_id,
            "--db",
            str(self.root / f"{gate_id}.sqlite"),
            "--port",
            str(self.gate_ports[gate_id]),
            "--policy-b64",
            policy_b64,
            "--policy-hash",
            self.policy_hash,
            "--measurement-public-key",
            self.measurement_pub,
        ]
        if virgin:
            cmd.append("--requires-checkpoint")
        self.procs[gate_id] = subprocess.Popen(cmd, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        _wait_port(self.gate_ports[gate_id])

    def restart_gate(self, gate_id: str) -> None:
        proc = self.procs[gate_id]
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(timeout=2)
        self._start_gate(gate_id, gate_id == "gate-c")

    def forward(self, gate_id: str, message: Mapping[str, Any], *, delay_ms: int = 0, duplicates: int = 1, drop: bool = False, timeout: float = 5.0) -> dict[str, Any]:
        return send_json(
            "127.0.0.1",
            self.relay_port,
            {
                "op": "FORWARD",
                "target_host": "127.0.0.1",
                "target_port": self.gate_ports[gate_id],
                "message": dict(message),
                "delay_ms": delay_ms,
                "duplicates": duplicates,
                "drop": drop,
                "timeout": timeout,
            },
            timeout=max(timeout + delay_ms / 1000.0 + 1.0, 2.0),
        )

    def ingest(self, gate_id: str, envelope: Mapping[str, Any], **relay_kwargs) -> dict[str, Any]:
        outer = self.forward(gate_id, {"op": "INGEST", "envelope": dict(envelope)}, **relay_kwargs)
        responses = outer.get("responses", [])
        return responses[-1] if responses else {"ok": False, "dropped": True}

    def evaluate(self, gate_id: str, fixture: Mapping[str, Any]) -> dict[str, Any]:
        outer = self.forward(
            gate_id,
            {
                "op": "EVALUATE",
                "bundle": fixture["bundle"],
                "expected_action": fixture["action"],
                "receiver_challenge": CHALLENGE,
                "admission_policy": _admission_policy_dict(),
            },
        )
        return outer["responses"][-1]

    def state(self, gate_id: str) -> dict[str, Any]:
        outer = self.forward(gate_id, {"op": "STATE"})
        return outer["responses"][-1]

    def close(self) -> None:
        for gate_id in ("gate-a", "gate-b", "gate-c"):
            proc = self.procs.get(gate_id)
            if proc and proc.poll() is None:
                try:
                    send_json("127.0.0.1", self.gate_ports[gate_id], {"op": "SHUTDOWN"}, timeout=1)
                except Exception:
                    pass
        relay = self.procs.get("relay")
        if relay and relay.poll() is None:
            try:
                send_json("127.0.0.1", self.relay_port, {"op": "SHUTDOWN"}, timeout=1)
            except Exception:
                pass
        for proc in self.procs.values():
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def _fixture() -> dict[str, Any]:
    old_root = _key("principal-root-old")
    root2 = _key("principal-root-2")
    root3 = _key("principal-root-3")
    fork_x = _key("principal-root-fork-x")
    fork_y = _key("principal-root-fork-y")
    subject = _key("principal-subject")
    measurement = _key("measurement-only")
    guardians = {f"guardian-{i}": _key(f"guardian-{i}") for i in (1, 2, 3)}
    now = datetime.now(timezone.utc)
    policy = create_recovery_policy(
        old_root,
        guardians,
        policy_id="wallet-recovery-policy-live-transport",
        principal_id="principal-terrynce",
        threshold=2,
        issued_at=now - timedelta(seconds=2),
    )
    return {
        "old_root": old_root,
        "root2": root2,
        "root3": root3,
        "fork_x": fork_x,
        "fork_y": fork_y,
        "subject": subject,
        "measurement": measurement,
        "guardians": guardians,
        "policy": policy,
        "policy_hash": policy["policy_hash"],
    }


def _freeze(fx, event_id: str = "freeze-live"):
    view = initialize_distributed_gate(fx["policy"], trusted_policy_hash=fx["policy_hash"], gate_id="emitter-template").root_view
    now = datetime.now(timezone.utc)
    return create_guardian_freeze(
        fx["policy"], fx["guardians"]["guardian-1"], view,
        event_id=event_id, guardian_id="guardian-1", reason="SUSPECTED_COMPROMISE",
        issued_at=now, expires_at=now + timedelta(seconds=600),
    )


def _succession(fx, successor_key, event_id: str, *, prior_root_key=None, prior_generation: int = 1, successor_generation: int = 2, guardians=("guardian-1", "guardian-2")):
    if prior_root_key is None:
        prior_root_key = fx["old_root"]
    now = datetime.now(timezone.utc)
    return create_root_succession_event(
        fx["policy"],
        {gid: fx["guardians"][gid] for gid in guardians},
        event_id=event_id,
        prior_root_public_key=public_key_hex(prior_root_key),
        prior_generation=prior_generation,
        successor_root_public_key=public_key_hex(successor_key),
        successor_generation=successor_generation,
        reason="COMPROMISED",
        effective_at=now,
    )


def _envelope(fx, inner: Mapping[str, Any], kind: str):
    emitted = time.time_ns()
    return create_envelope(inner, kind=kind, emitted_ns=emitted, measurement_key=fx["measurement"])


def _measure(ack: Mapping[str, Any], calibration) -> dict[str, Any]:
    emitted = ack.get("emitted_ns")
    commit = ack.get("commit_complete_ns")
    if emitted is None:
        return {"status": "NO_MEASUREMENT"}
    tau = tau_measurement(emitted_ns=int(emitted), commit_complete_ns=int(commit) if commit is not None else None, calibration=calibration)
    receive = ack.get("gate_receive_ns")
    if receive is not None:
        transport_raw = int(receive) - int(emitted)
        tau["transport_raw_ns"] = transport_raw
        tau["transport_offset_corrected_ns"] = transport_raw - calibration.offset_ns
        if commit is not None:
            tau["admission_ns"] = int(commit) - int(receive)
    return tau


def _is_pass(response: Mapping[str, Any]) -> bool:
    return response.get("receipt", {}).get("decision") == "PASS"


def _is_block(response: Mapping[str, Any], reason: str | None = None) -> bool:
    receipt = response.get("receipt", {})
    if receipt.get("decision") != "BLOCK":
        return False
    return reason is None or reason in receipt.get("reason_codes", [])


def _scenario_race_to_window(root: Path, fx) -> dict[str, Any]:
    cluster = Cluster(root, fx["policy"], fx["policy_hash"], public_key_hex(fx["measurement"]))
    try:
        now = datetime.now(timezone.utc)
        old = _issue_bundle(fx["old_root"], fx["subject"], principal_id="principal-terrynce", epoch_id="race-old", mandate_id="race-old", action=_action("attacker.example", 9900), now=now)
        freeze = _envelope(fx, _freeze(fx, "freeze-race"), "FREEZE")
        before = cluster.evaluate("gate-b", old)
        ack = cluster.ingest("gate-b", freeze, delay_ms=150)
        after = cluster.evaluate("gate-b", old)
        return {
            "name": "race_to_window",
            "pre_delivery_effect": _is_pass(before),
            "post_admission_block": _is_block(after, "GUARDIAN_FREEZE_ACTIVE"),
            "tau": _measure(ack, cluster.calibration["gate-b"]),
            "passed": _is_pass(before) and _is_block(after, "GUARDIAN_FREEZE_ACTIVE") and ack.get("admitted") is True,
        }
    finally:
        cluster.close()


def _scenario_split_brain(root: Path, fx) -> dict[str, Any]:
    cluster = Cluster(root, fx["policy"], fx["policy_hash"], public_key_hex(fx["measurement"]))
    try:
        now = datetime.now(timezone.utc)
        old = _issue_bundle(fx["old_root"], fx["subject"], principal_id="principal-terrynce", epoch_id="split-old", mandate_id="split-old", action=_action("split.example", 9800), now=now)
        env = _envelope(fx, _freeze(fx, "freeze-split"), "FREEZE")
        dropped = cluster.ingest("gate-b", env, drop=True)
        edge = cluster.evaluate("gate-b", old)
        ack = cluster.ingest("gate-b", env)
        after = cluster.evaluate("gate-b", old)
        return {
            "name": "split_brain_delivery",
            "partition_drop_visible": dropped.get("dropped") is True,
            "pre_reconnect_effect": _is_pass(edge),
            "post_reconnect_block": _is_block(after, "GUARDIAN_FREEZE_ACTIVE"),
            "tau": _measure(ack, cluster.calibration["gate-b"]),
            "passed": dropped.get("dropped") is True and _is_pass(edge) and _is_block(after, "GUARDIAN_FREEZE_ACTIVE"),
        }
    finally:
        cluster.close()


def _scenario_successor_race(root: Path, fx) -> dict[str, Any]:
    cluster = Cluster(root, fx["policy"], fx["policy_hash"], public_key_hex(fx["measurement"]))
    try:
        x = _succession(fx, fx["fork_x"], "fork-x", guardians=("guardian-1", "guardian-2"))
        y = _succession(fx, fx["fork_y"], "fork-y", guardians=("guardian-2", "guardian-3"))
        ax = cluster.ingest("gate-a", _envelope(fx, x, "SUCCESSION"))
        by = cluster.ingest("gate-b", _envelope(fx, y, "SUCCESSION"))
        now = datetime.now(timezone.utc)
        bx = _issue_bundle(fx["fork_x"], fx["subject"], principal_id="principal-terrynce", epoch_id="fork-x", mandate_id="fork-x", action=_action("fork-x.example", 3100), now=now)
        byb = _issue_bundle(fx["fork_y"], fx["subject"], principal_id="principal-terrynce", epoch_id="fork-y", mandate_id="fork-y", action=_action("fork-y.example", 3200), now=now)
        pre_a = cluster.evaluate("gate-a", bx)
        pre_b = cluster.evaluate("gate-b", byb)
        ay = cluster.ingest("gate-a", _envelope(fx, y, "SUCCESSION"))
        bxack = cluster.ingest("gate-b", _envelope(fx, x, "SUCCESSION"))
        post_a = cluster.evaluate("gate-a", bx)
        post_b = cluster.evaluate("gate-b", byb)
        fork_a = ay.get("receipt", {}).get("decision") == "FORK_DETECTED"
        fork_b = bxack.get("receipt", {}).get("decision") == "FORK_DETECTED"
        return {
            "name": "successor_race",
            "partitioned_branch_effects": int(_is_pass(pre_a)) + int(_is_pass(pre_b)),
            "fork_detected": fork_a and fork_b,
            "post_discovery_effects": int(_is_pass(post_a)) + int(_is_pass(post_b)),
            "passed": ax.get("admitted") is True and by.get("admitted") is True and _is_pass(pre_a) and _is_pass(pre_b) and fork_a and fork_b and _is_block(post_a, "ROOT_FORK_QUARANTINED") and _is_block(post_b, "ROOT_FORK_QUARANTINED"),
        }
    finally:
        cluster.close()


def _scenario_cold_start(root: Path, fx) -> dict[str, Any]:
    cluster = Cluster(root, fx["policy"], fx["policy_hash"], public_key_hex(fx["measurement"]))
    try:
        succession = _succession(fx, fx["root2"], "cold-successor")
        now = datetime.now(timezone.utc)
        successor = _issue_bundle(fx["root2"], fx["subject"], principal_id="principal-terrynce", epoch_id="cold-2", mandate_id="cold-2", action=_action("merchant.example", 2500), now=now)
        before = cluster.evaluate("gate-c", successor)
        dropped = cluster.ingest("gate-c", _envelope(fx, succession, "SUCCESSION"), drop=True)
        still = cluster.evaluate("gate-c", successor)
        succ_ack = cluster.ingest("gate-c", _envelope(fx, succession, "SUCCESSION"))
        after_lineage = cluster.evaluate("gate-c", successor)

        # Build a checkpoint for the exact succession view without sharing Gate C state.
        emitter_view = initialize_distributed_gate(fx["policy"], trusted_policy_hash=fx["policy_hash"], gate_id="checkpoint-emitter", requires_checkpoint=True)
        emitter_view, r = ingest_root_succession(emitter_view, fx["policy"], succession, now=datetime.now(timezone.utc))
        if r.get("accepted") is not True:
            raise RuntimeError("emitter_lineage_failed")
        checkpoint = create_root_checkpoint(
            fx["policy"],
            {"guardian-1": fx["guardians"]["guardian-1"], "guardian-2": fx["guardians"]["guardian-2"]},
            emitter_view.root_view,
            checkpoint_id="cold-checkpoint",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=120),
        )
        cp_ack = cluster.ingest("gate-c", _envelope(fx, checkpoint, "CHECKPOINT"))
        after_both = cluster.evaluate("gate-c", successor)
        return {
            "name": "cold_start_starvation",
            "blocked_without_lineage": _is_block(before, "CURRENT_ROOT_CHECKPOINT_REQUIRED"),
            "drop_visible": dropped.get("dropped") is True,
            "blocked_after_lineage_without_checkpoint": _is_block(after_lineage, "CURRENT_ROOT_CHECKPOINT_REQUIRED"),
            "passes_after_lineage_and_checkpoint": _is_pass(after_both),
            "succession_tau": _measure(succ_ack, cluster.calibration["gate-c"]),
            "checkpoint_tau": _measure(cp_ack, cluster.calibration["gate-c"]),
            "passed": _is_block(before, "CURRENT_ROOT_CHECKPOINT_REQUIRED") and _is_block(still, "CURRENT_ROOT_CHECKPOINT_REQUIRED") and _is_block(after_lineage, "CURRENT_ROOT_CHECKPOINT_REQUIRED") and _is_pass(after_both),
        }
    finally:
        cluster.close()


def _scenario_duplicate_storm(root: Path, fx) -> dict[str, Any]:
    cluster = Cluster(root, fx["policy"], fx["policy_hash"], public_key_hex(fx["measurement"]))
    try:
        now = datetime.now(timezone.utc)
        old = _issue_bundle(fx["old_root"], fx["subject"], principal_id="principal-terrynce", epoch_id="dup-old", mandate_id="dup-old", action=_action("duplicate.example", 9700), now=now)
        env = _envelope(fx, _freeze(fx, "freeze-duplicate"), "FREEZE")
        first = cluster.ingest("gate-a", env)
        storm = cluster.forward("gate-a", {"op": "INGEST", "envelope": env}, duplicates=50, timeout=10.0)
        responses = storm.get("responses", [])
        after = cluster.evaluate("gate-a", old)
        state = cluster.state("gate-a")
        rejected = sum(1 for row in responses if row.get("receipt", {}).get("decision") == "REJECT_FREEZE")
        return {
            "name": "duplicate_storm_replay",
            "duplicates_sent": 50,
            "duplicates_rejected": rejected,
            "revision": state.get("revision"),
            "still_blocked": _is_block(after, "GUARDIAN_FREEZE_ACTIVE"),
            "passed": first.get("admitted") is True and rejected == 50 and state.get("revision") == 1 and _is_block(after, "GUARDIAN_FREEZE_ACTIVE"),
        }
    finally:
        cluster.close()


def _scenario_cross_epoch_reorder(root: Path, fx) -> dict[str, Any]:
    cluster = Cluster(root, fx["policy"], fx["policy_hash"], public_key_hex(fx["measurement"]))
    try:
        s12 = _succession(fx, fx["root2"], "succession-1-2")
        # Build a gen2->gen3 event directly from the same frozen quorum policy.
        s23 = _succession(fx, fx["root3"], "succession-2-3", prior_root_key=fx["root2"], prior_generation=2, successor_generation=3)
        later_first = cluster.ingest("gate-a", _envelope(fx, s23, "SUCCESSION"))
        first = cluster.ingest("gate-a", _envelope(fx, s12, "SUCCESSION"))
        later_second = cluster.ingest("gate-a", _envelope(fx, s23, "SUCCESSION"))
        state = cluster.state("gate-a")
        generation = state.get("state", {}).get("root_view", {}).get("current_generation")
        return {
            "name": "cross_epoch_reorder",
            "later_first_admitted": later_first.get("admitted"),
            "generation_after_ordered_replay": generation,
            "passed": later_first.get("admitted") is False and first.get("admitted") is True and later_second.get("admitted") is True and generation == 3,
        }
    finally:
        cluster.close()


def _durability_preflight(root: Path, fx) -> dict[str, Any]:
    cluster = Cluster(root, fx["policy"], fx["policy_hash"], public_key_hex(fx["measurement"]))
    try:
        env = _envelope(fx, _freeze(fx, "freeze-crash-before-commit"), "FREEZE")
        outer = cluster.forward("gate-a", {"op": "INGEST", "envelope": env, "crash_before_commit": True}, timeout=2.0)
        crashed_response = outer.get("responses", [{}])[-1]
        time.sleep(0.1)
        cluster.restart_gate("gate-a")
        state = cluster.state("gate-a")
        ack = cluster.ingest("gate-a", env)
        return {
            "name": "crash_before_commit",
            "first_ack_received": crashed_response.get("ok") is True and not crashed_response.get("transport_error"),
            "revision_after_restart": state.get("revision"),
            "redelivery_admitted": ack.get("admitted") is True,
            "passed": bool(crashed_response.get("transport_error")) and state.get("revision") == 0 and ack.get("admitted") is True,
        }
    finally:
        cluster.close()


def run() -> dict[str, Any]:
    fx = _fixture()
    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with tempfile.TemporaryDirectory(prefix="wallet004-") as tmp:
        base = Path(tmp)
        durability = _durability_preflight(base / "durability", fx)
        scenarios = [
            _scenario_race_to_window(base / "race", fx),
            _scenario_split_brain(base / "split", fx),
            _scenario_successor_race(base / "successor", fx),
            _scenario_cold_start(base / "cold", fx),
            _scenario_duplicate_storm(base / "duplicate", fx),
            _scenario_cross_epoch_reorder(base / "reorder", fx),
        ]
    passed = durability["passed"] and all(row["passed"] for row in scenarios)
    result = {
        "schema": "openline.wallet_standing_004.live_result.v1",
        "experiment_id": "WALLET-STANDING-004",
        "base_commit": "9278b6238bf4f04e56184135913f4a7859db66bf",
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verdict": VERDICT if passed else FAIL,
        "passed": passed,
        "authority": {
            "wallet_policy_authority": "NONE",
            "measurement_authority": "NONE",
            "relay_authority": "NONE",
            "decision_authority": "RECEIVER_GATE",
        },
        "clock_model": {
            "mode": "PRE_RUN_NTP_STYLE_CALIBRATION_MEASUREMENT_ONLY",
            "admission_uses_calibration": False,
            "tau_stop_definition": "FIRST_TIMESTAMP_AFTER_SQLITE_SYNCHRONOUS_FULL_COMMIT_RETURNS",
        },
        "durability_preflight": durability,
        "scenarios": scenarios,
    }
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


if __name__ == "__main__":
    outcome = run()
    raise SystemExit(0 if outcome["passed"] else 1)
