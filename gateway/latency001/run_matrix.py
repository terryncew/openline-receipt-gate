#!/usr/bin/env python3
"""Reproduce the latency comparison on Linux with real Docker, sequentially.

Requires Docker Compose >= 2.24.4, Git history containing both pinned
baseline commits, and the benchmark's pinned Python dependencies.
Run from any directory; all Compose paths are absolute. Every case gets
a fresh, uniquely named project and volumes. Only that project is removed.
Original concurrent failures remain FAIL evidence but do not suppress the
optimized/native OPA/stateful/floor cases. Every required case must pass.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

import benchmark

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = ROOT / "gateway" / "compose" / "docker-compose.yml"
ORIGINAL_REF = "9461188"
PROFILE_REF = "51ef1df"
IMAGES = {"original": "gateway-latency-original:9461188",
          "profile-original": "gateway-latency-profile-original:51ef1df",
          "optimized": "gateway-latency-optimized:local"}


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT).decode().strip()


@contextmanager
def experiment_environment(values):
    # Experiments are sequential. The imported benchmark Compose helper
    # inherits these exact values, and the caller's environment is restored.
    previous = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def command(arguments, log, *, env=None, cwd=ROOT, timeout=600):
    with Path(log).open("w") as output:
        result = subprocess.run(arguments, cwd=cwd, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=timeout)
    return {"command": arguments, "exit_code": result.returncode,
            "log": str(log)}


def archive_source(ref, destination):
    archive = destination.parent / (destination.name + ".tar")
    with archive.open("wb") as output:
        subprocess.run(["git", "archive", "--format=tar", ref], cwd=ROOT,
                       stdout=output, check=True)
    destination.mkdir()
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")
    archive.unlink()


def current_source(destination):
    """Copy public source, including current edits, without ignored keys/runtime."""
    destination.mkdir()
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
         "--", "gateway", "olp_gate"], cwd=ROOT).decode().split("\0")
    digest = hashlib.sha256()
    for name in sorted(set(filter(None, names))):
        source = ROOT / name
        if not source.exists() and not source.is_symlink():
            continue  # A tracked deletion is part of the current checkout.
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            link = os.readlink(source)
            target.symlink_to(link)
            content = link.encode()
        else:
            shutil.copy2(source, target)
            content = source.read_bytes()
        digest.update(name.encode() + b"\0" + content + b"\0")
    return digest.hexdigest()


def make_plan(args):
    plans = []

    def add(name, image, mode, concurrency, *, required=True, profile=False,
            historical=False, variant=None):
        plans.append({"name": name, "image": image, "mode": mode,
                      "concurrency": concurrency, "required": required,
                      "profile": profile, "historical": historical,
                      "opa_variant": variant,
                      "samples": 500 if historical else args.profile_samples if profile else args.samples,
                      "amount": 100 if historical else 1,
                      "clients": ["close", "persistent"] if historical else ["persistent"]})

    if args.historical:
        add("historical-original", "original", "openline", 1,
            required=False, historical=True)
        add("historical-native-opa-a", "optimized", "opa-a", 1,
            historical=True, variant="a")
    for concurrency in args.concurrency:
        # The frozen exact baseline listens for standing on loopback only.
        # Its instrumentation-only successor adds an environment-selected
        # bind address needed for a working same-topology standing-ON run.
        # Profiling remains OFF in these primary comparisons.
        add(f"original-c{concurrency}", "profile-original", "openline", concurrency, required=False)
    for concurrency in args.profile_concurrency:
        add(f"profile-original-c{concurrency}", "profile-original", "openline", concurrency,
            required=False, profile=True)
    for concurrency in args.concurrency:
        add(f"optimized-c{concurrency}", "optimized", "openline", concurrency)
    for concurrency in args.profile_concurrency:
        add(f"profile-optimized-c{concurrency}", "optimized", "openline", concurrency, profile=True)
    for variant in ("a", "b"):
        for concurrency in args.concurrency:
            add(f"native-opa-{variant}-c{concurrency}", "optimized", f"opa-{variant}",
                concurrency, variant=variant)
    for concurrency in args.concurrency:
        add(f"stateful-opa-c{concurrency}", "optimized", "opa-stateful", concurrency)
    for concurrency in args.concurrency:
        add(f"envoy-floor-c{concurrency}", "optimized", benchmark.FLOOR_MODE, concurrency)
    return plans


def compose_setup(plan, directory, project, port):
    opa = plan["opa_variant"] is not None
    files = ([HERE / "compose-opa.yaml", HERE / "compose-opa-native.yaml"] if opa
             else [BASE] + ([] if plan["historical"] else [HERE / "compose-openline.yaml"]))
    if plan["mode"] == "opa-stateful":
        files.append(HERE / "compose-stateful.yaml")
    if plan["mode"] == benchmark.FLOOR_MODE:
        files.append(HERE / "compose-floor.yaml")
    # The runtime overlay lives outside the repository and only pins image
    # selection and a loopback port; historical tracked files stay unchanged.
    overlay = directory / "runtime.yaml"
    lines = ["services:", "  envoy:", "    ports: !override",
             f'      - "127.0.0.1:{port}:8080"', "  mockapi:",
             f'    image: "{IMAGES[plan["image"]]}"']
    if not opa:
        lines.extend(["  authz:", f'    image: "{IMAGES[plan["image"]]}"'])
    overlay.write_text("\n".join(lines) + "\n")
    files.append(overlay)
    values = {"COMPOSE_FILE": os.pathsep.join(map(str, files)),
              "COMPOSE_PROJECT_NAME": project, "LATENCY_PORT": str(port),
              "LATENCY_IMAGE": IMAGES[plan["image"]],
              "AUTH_MODE": "openline", "OPA_VARIANT": plan["opa_variant"] or "a",
              "LATENCY_STANDING_CHECK": "1",
              "LATENCY_AUTHZ_PROFILE": "/tmp/authz.jsonl" if plan["profile"] else "",
              "LATENCY_API_PROFILE": "/tmp/api.jsonl" if plan["profile"] else ""}
    profile = "" if opa else "openline"
    values["COMPOSE_PROFILES"] = profile
    compose = ["docker", "compose"] + (["--profile", profile] if profile else [])
    return values, profile, compose


def functional_readiness(plan, compose, url, timeout):
    """Observe a real authorized one-cent effect, not just Envoy /health."""
    deadline = time.monotonic() + timeout
    attempts, agent = [], None
    agent_id = "matrix-ready-" + uuid.uuid4().hex[:12]
    signed = plan["mode"] in benchmark.SIGNED_MODES
    floor = plan["mode"] == benchmark.FLOOR_MODE
    while time.monotonic() < deadline:
        transport = benchmark.HttpTransport(url, "close", min(5, timeout))
        observation = {"attempt": len(attempts) + 1, "status": None, "passed": False}
        try:
            if (signed or floor) and agent is None:
                agent = compose.provision(agent_id, 1_000_000)
            before = compose.ledger_snapshot()
            if signed:
                headers = agent.headers_for("authorize_payment", value_cents=1)
            elif floor:
                headers = {"x-ol-decision": compose.mint_floor_decisions(agent_id, 1, 1)["tokens"][0]}
            else:
                headers = {"Authorization": "Bearer opaline-token-001"}
            status, payload, latency, _, _ = transport.request(
                "POST", "/api/transfer", headers, b'{"to":"vendor","cents":1}')
            error, effect = benchmark.validate_response(status, payload, "transfer", 1,
                                                        signed or floor, "http", 0)
            observation.update({"status": status, "latency_ms": latency, "error": error})
            if not error:
                after = compose.ledger_snapshot()
                observation["passed"] = (
                    before["balances"]["treasury"] - after["balances"]["treasury"] == 1
                    and after["balances"].get("vendor", 0) - before["balances"].get("vendor", 0) == 1
                    and after["effects"] - before["effects"] == 1 and bool(effect))
        except Exception as error:
            observation["error"] = type(error).__name__
        finally:
            transport.close()
        attempts.append(observation)
        if observation["passed"]:
            return {"passed": True, "attempts": attempts}
        time.sleep(.5)
    return {"passed": False, "attempts": attempts}


def sqlite_observation(compose, service):
    code = """import json,os,sqlite3
d=sqlite3.connect(os.environ['GATEWAY_DB'])
print(json.dumps({'sqlite_version':sqlite3.sqlite_version,
'journal_mode':d.execute('PRAGMA journal_mode').fetchone()[0],
'snapshot_connection_synchronous':d.execute('PRAGMA synchronous').fetchone()[0],
'note':'synchronous is connection-local; this new read-only-observation connection does not prove the running writer setting'}))
"""
    return json.loads(compose.exec(service, code))


def container_observations(arguments, env):
    identifiers = subprocess.check_output(arguments + ["ps", "--all", "-q"],
                                          cwd=ROOT, env=env, text=True).split()
    if not identifiers:
        return []
    template = ('{"name":{{json .Name}},"image_id":{{json .Image}},'
                '"image_tag":{{json .Config.Image}},"running":{{json .State.Running}},'
                '"exit_code":{{json .State.ExitCode}},"started_at":{{json .State.StartedAt}}}')
    output = subprocess.check_output(["docker", "inspect", "--format", template, *identifiers],
                                     cwd=ROOT, env=env, text=True)
    return [json.loads(line) for line in output.splitlines()]


def export_receipts(compose, directory):
    # Only the public key and already signed receipts leave the container.
    code = """import os
from pathlib import Path
from gateway.gateway_admin import b64u_decode,b64u_encode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k=Ed25519PrivateKey.from_private_bytes(b64u_decode((Path(os.environ['GATEWAY_CONFIG'])/'receiver.key').read_text().strip()))
print(b64u_encode(k.public_key().public_bytes_raw()))
"""
    public = directory / "receiver.pubkey"
    receipts = directory / "receipts.jsonl"
    public.write_text(compose.exec("authz", code))
    receipts.write_text(compose.exec("authz", "import os,sqlite3; "
                                    "d=sqlite3.connect(os.environ['GATEWAY_DB']); "
                                    "print('\\n'.join(r[0] for r in d.execute('SELECT body FROM receipts ORDER BY ts,receipt_id')))") )
    return command([sys.executable, str(ROOT / "gateway" / "ci" / "verify_receipt_export.py"),
                    "--public-key", str(public), "--receipts", str(receipts)],
                   directory / "independent-receipt-verification.json", timeout=120)


def run_case(args, plan, output, prefix):
    directory = output / plan["name"]
    directory.mkdir()
    project = prefix + "-" + plan["name"]
    values, profile, compose_arguments = compose_setup(plan, directory, project, args.port)
    env = {**os.environ, **values}
    result = {"plan": plan, "project": project, "compose": values,
              "passed": False, "commands": [], "benchmark": None}
    with experiment_environment(values):
        compose = benchmark.Compose(ROOT / "gateway" / "compose", profile)
        try:
            up = command(compose_arguments + ["up", "-d", "--no-build"],
                         directory / "startup.log", env=env, timeout=300)
            result["commands"].append(up)
            if up["exit_code"]:
                raise RuntimeError("compose startup failed")
            result["readiness"] = functional_readiness(
                plan, compose, f"http://127.0.0.1:{args.port}", args.readiness_timeout)
            (directory / "readiness.json").write_text(json.dumps(result["readiness"], indent=2) + "\n")
            if not result["readiness"]["passed"]:
                raise RuntimeError("functional readiness failed")
            result["containers"] = container_observations(compose_arguments, env)
            result["runtime_flags"] = {"mockapi": compose.runtime_flags("mockapi")}
            result["sqlite"] = {"mockapi": sqlite_observation(compose, "mockapi")}
            if plan["opa_variant"] is None:
                result["runtime_flags"]["authz"] = compose.runtime_flags("authz")
                result["sqlite"]["authz"] = sqlite_observation(compose, "authz")
            arguments = [sys.executable, str(HERE / "benchmark.py"), "--mode", plan["mode"],
                         "--url", f"http://127.0.0.1:{args.port}", "--profile", profile,
                         "--samples", str(plan["samples"]), "--concurrency", str(plan["concurrency"]),
                         "--clients", *plan["clients"], "--workloads", "transfer",
                         "--amount", str(plan["amount"]), "--warmup", str(args.warmup),
                         "--output", str(directory / "benchmark"), "--label", plan["name"]]
            if plan["profile"]:
                arguments.extend(["--profile-file", "authz:/tmp/authz.jsonl",
                                  "--profile-file", "mockapi:/tmp/api.jsonl"])
            measured = command(arguments, directory / "benchmark.stdout.json", env=env,
                               timeout=args.case_timeout)
            result["commands"].append(measured)
            report_path = directory / "benchmark" / "report.json"
            if report_path.exists():
                result["benchmark"] = json.loads(report_path.read_text())
            receipt_ok = True
            if plan["mode"] in benchmark.SIGNED_MODES:
                receipt_check = export_receipts(compose, directory)
                result["commands"].append(receipt_check)
                receipt_ok = receipt_check["exit_code"] == 0
            profile_ok = True
            if plan["profile"]:
                observations = []
                for case in (result["benchmark"] or {}).get("cases", []):
                    count = case["successful_latency"]["n"]
                    counts = case["profiling"]["record_counts"]
                    observations.append({"successful_requests": count,
                                         "authz_records": counts.get("authz.request", 0),
                                         "api_records": counts.get("api.request", 0),
                                         "malformed_lines": case["profile_malformed_lines"]})
                profile_ok = bool(observations) and all(
                    row["malformed_lines"] == 0
                    and row["authz_records"] == row["successful_requests"]
                    and row["api_records"] == row["successful_requests"]
                    for row in observations)
                result["profile_validation"] = {"passed": profile_ok, "observations": observations}
            result["passed"] = measured["exit_code"] == 0 and bool(
                result["benchmark"] and result["benchmark"]["passed"]) and receipt_ok and profile_ok
            # An expected original failure still needs a completed benchmark
            # report. Build/startup/receipt integrity failures remain blockers.
            result["allowed_original_failure"] = (
                not plan["required"] and result["benchmark"] is not None
                and bool(result["benchmark"].get("cases")) and receipt_ok and profile_ok)
        except Exception as error:
            result["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        finally:
            for suffix, arguments in (
                    ("containers.log", compose_arguments + ["ps", "--all"]),
                    ("compose.log", compose_arguments + ["logs", "--no-color"]),
                    ("cleanup.log", compose_arguments + ["down", "--volumes", "--remove-orphans"])):
                try:
                    operation = command(arguments, directory / suffix, env=env, timeout=180)
                    result["commands"].append(operation)
                    if suffix == "cleanup.log" and operation["exit_code"]:
                        result["cleanup_failed"] = True
                        result["passed"] = False
                        result["allowed_original_failure"] = False
                except Exception as error:
                    result[suffix + "_error"] = type(error).__name__
                    if suffix == "cleanup.log":
                        result["cleanup_failed"] = True
                        result["passed"] = False
                        result["allowed_original_failure"] = False
    (directory / "case.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--profile-samples", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8, 32])
    parser.add_argument("--profile-concurrency", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--readiness-timeout", type=float, default=60)
    parser.add_argument("--case-timeout", type=int, default=600)
    parser.add_argument("--historical", action="store_true")
    parser.add_argument("--skip-build", action="store_true", help="reuse the three explicitly named local image tags")
    parser.add_argument("--dry-run", action="store_true", help="save the exact plan without running Docker")
    args = parser.parse_args(argv)
    if min(args.samples, args.profile_samples, *args.concurrency, *args.profile_concurrency) <= 0:
        parser.error("sample counts and concurrency must be positive")
    if max(args.concurrency) > args.samples or max(args.profile_concurrency) > args.profile_samples:
        parser.error("sample count must cover every concurrent worker")
    if args.warmup < 0 or not 1 <= args.port <= 65535:
        parser.error("warmup >= 0 and valid port required")
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("output must be empty; preserve existing evidence and choose a fresh directory")
    output.mkdir(parents=True, exist_ok=True)
    plans = make_plan(args)
    refs = {"original": git("rev-parse", ORIGINAL_REF),
            "profile-original": git("rev-parse", PROFILE_REF),
            "optimized_head": git("rev-parse", "HEAD")}
    report = {"passed": False, "refs": refs, "images": IMAGES, "plan": plans,
              "command": sys.argv, "platform": platform.platform(),
              "cpu_count": os.cpu_count(), "python": platform.python_version(),
              "host_sqlite_version": sqlite3.sqlite_version,
              "optimized_worktree_status": git("status", "--short"),
              "builds": [], "cases": [],
              "method": "fresh project and volumes per case; standing ON and Envoy 2 workers for matched Gateway runs; 1-cent identical successful effects; unprofiled primary comparisons; separately profiled diagnostics; original failures retained; historical exact Gateway uses default original topology and standing OFF; historical native OPA uses the earlier 500x100-cent workload but a different native topology and is not a reproduction of the old shim deployment",
              "fair_original_note": "Fair original uses instrumentation-only 51ef1df with profiling OFF, allowing standing to bind 0.0.0.0 in Docker; exact 9461188's standing endpoint is hardcoded loopback. Authorization/transaction behavior is otherwise original. Exact 9461188 is retained for historical standing-OFF reproduction."}
    if args.dry_run:
        report["planned_only"] = True
        (output / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Planned {len(plans)} cases; no Docker operations. {output / 'matrix.json'}")
        return 0
    prefix = "latency-matrix-" + uuid.uuid4().hex[:8]
    try:
        report["docker_version"] = subprocess.check_output(
            ["docker", "version", "--format", "{{.Server.Version}}"], text=True).strip()
        report["compose_version"] = subprocess.check_output(
            ["docker", "compose", "version", "--short"], text=True).strip()
        with tempfile.TemporaryDirectory(prefix="gateway-latency-build-") as temporary:
            directory = Path(temporary)
            for kind in ("original", "profile-original", "optimized"):
                if not args.skip_build:
                    context = directory / kind
                    if kind == "optimized":
                        report["optimized_source_sha256"] = current_source(context)
                    else:
                        archive_source(refs[kind], context)
                    build = command(["docker", "build", "--progress=plain", "--tag", IMAGES[kind],
                                     "--file", str(context / "gateway" / "compose" / "Dockerfile.gateway"),
                                     str(context)], output / f"build-{kind}.log", timeout=1200)
                    report["builds"].append(build)
                    if build["exit_code"]:
                        raise RuntimeError(f"image build failed: {kind}")
                report.setdefault("image_ids", {})[kind] = subprocess.check_output(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", IMAGES[kind]], text=True).strip()
            for plan in plans:
                case = run_case(args, plan, output, prefix)
                report["cases"].append(case)
                # Write after every case so interruption cannot erase earlier evidence.
                (output / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
                tag = "PASS" if case["passed"] else "FAIL"
                note = " (original failure retained)" if case.get("allowed_original_failure") and not case["passed"] else ""
                print(f"{tag} {plan['name']}{note}", flush=True)
            report["passed"] = all(case["passed"] or case.get("allowed_original_failure", False)
                                   for case in report["cases"])
    except Exception as error:
        report["fatal_error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    (output / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Required matrix {'PASS' if report['passed'] else 'FAIL'}; evidence: {output / 'matrix.json'}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
