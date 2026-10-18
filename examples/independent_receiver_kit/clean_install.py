"""Measure an internal clean-source/venv run on the existing host.

Run from the repository root after committing the version to be measured:
    python examples/independent_receiver_kit/clean_install.py --output /tmp/FRESH

This is not a fresh operating system, a cold external user test, or evidence of
independent organizational adoption. Existing host/network infrastructure and
package registries remain in use. Every application command runs from the
exported committed source, with a new venv and no inherited user site packages.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import time


def extract_source(archive, destination):
    """Extract regular Git archive entries without links or path traversal."""
    with tarfile.open(archive, "r:") as bundle:
        members = bundle.getmembers()
        names = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or member.name in names or not (member.isdir() or member.isfile())):
                raise ValueError("unsafe or unsupported archive entry: " + member.name)
            names.add(member.name)
        destination.mkdir()
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(member.mode & 0o777)


def run(output):
    started = time.perf_counter()
    repository = Path.cwd().resolve()
    output = output.resolve()
    # Exclusive creation also refuses an existing empty directory or symlink.
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    environment = os.environ.copy()
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "__PYVENV_LAUNCHER__",
                 "PIP_TARGET", "PIP_PREFIX", "PIP_USER"):
        environment.pop(name, None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PIP_CONFIG_FILE"] = os.devnull
    summary = {
        "schema": "openline_internal_clean_install/v1",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Internal isolated committed source and new venv on existing host",
        "fresh_operating_system": False,
        "external_cold_user_test": False,
        "independent_organizational_adoption": False,
        "package_download_cache_disabled": True,
        "host_python": sys.version,
        "host_platform": platform.platform(),
        "source_repository": str(repository),
        "output": str(output),
        "stages": [],
        "first_successful_end_to_end_seconds": None,
        "status": "running",
    }

    def save():
        summary["elapsed_seconds"] = time.perf_counter() - started
        pending = output / "summary.json.tmp"
        pending.write_text(json.dumps(summary, indent=2) + "\n")
        pending.replace(output / "summary.json")

    def command(name, arguments, cwd, extra_environment=None):
        stage_start = time.perf_counter()
        stage = {"name": name, "command": [str(a) for a in arguments],
                 "cwd": str(cwd), "started_after_seconds": stage_start - started,
                 "log": name + ".log"}
        summary["stages"].append(stage)
        save()
        child_environment = environment.copy()
        child_environment.update(extra_environment or {})
        try:
            with (output / stage["log"]).open("w", encoding="utf-8") as log:
                log.write(json.dumps({"command": stage["command"], "cwd": str(cwd)}) + "\n")
                log.flush()
                result = subprocess.run(stage["command"], cwd=cwd, env=child_environment,
                                        stdout=log, stderr=subprocess.STDOUT, check=False)
                stage["exit_status"] = result.returncode
                log.write("\n" + json.dumps({"exit_status": result.returncode}) + "\n")
        except Exception as error:
            stage["exit_status"] = None
            stage["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            stage["elapsed_seconds"] = time.perf_counter() - stage_start
            stage["finished_after_seconds"] = time.perf_counter() - started
            save()
        return result.returncode

    def finish(status, exit_status):
        summary["status"] = status
        summary["exit_status"] = exit_status
        save()
        print(json.dumps(summary, indent=2))
        # Keep the exact subprocess status above; map signals for this CLI's exit.
        return exit_status if exit_status >= 0 else 128 - exit_status

    save()
    try:
        root = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=repository,
                              env=environment, text=True, capture_output=True, check=True)
        if Path(root.stdout.strip()).resolve() != repository:
            raise ValueError("invoke clean_install.py from the repository root")
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository,
                                  env=environment, text=True, capture_output=True, check=True)
        summary["source_commit"] = revision.stdout.strip()
        archive = output / "source.tar"
        status = command("archive", ["git", "archive", "--format=tar", "--output",
                                      archive, summary["source_commit"]], repository)
        if status:
            return finish("archive_failed", status)
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        summary["source_archive_sha256"] = digest.hexdigest()
        extraction_start = time.perf_counter()
        extract_source(archive, source)
        summary["stages"].append({"name": "extract", "elapsed_seconds": time.perf_counter() - extraction_start,
                                   "started_after_seconds": extraction_start - started,
                                   "finished_after_seconds": time.perf_counter() - started,
                                   "exit_status": 0})
        if not (source / "examples/independent_receiver_kit/clean_install.py").is_file():
            raise ValueError("commit the kit, including this harness, before measuring HEAD")
        save()

        venv = output / "venv"
        status = command("venv", [sys.executable, "-m", "venv", venv], source)
        if status:
            return finish("venv_failed", status)
        # venv defaults to ensurepip and excludes inherited site packages.
        configuration = (venv / "pyvenv.cfg").read_text()
        if "include-system-site-packages = false" not in configuration.lower():
            raise ValueError("new venv unexpectedly includes system site packages")
        (output / "pyvenv.cfg").write_text(configuration)
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        status = command("install", [python, "-m", "pip", "install", "--no-cache-dir", "-e", ".",
                                      "-r", "examples/independent_receiver_kit/requirements.txt"], source)
        if status:
            return finish("install_failed", status)

        inventory = (
            "import importlib.metadata,json,platform,site,sys; "
            "from pathlib import Path; "
            "data={'python':sys.version,'executable':sys.executable,"
            "'platform':platform.platform(),'prefix':sys.prefix,'base_prefix':sys.base_prefix,"
            "'enable_user_site':site.ENABLE_USER_SITE,"
            "'packages':sorted([{'name':d.metadata['Name'],'version':d.version} "
            "for d in importlib.metadata.distributions()],key=lambda d:d['name'].lower())}; "
            "Path(sys.argv[1]).write_text(json.dumps(data,indent=2)+'\\n'); "
            "print(json.dumps(data,indent=2))"
        )
        status = command("versions", [python, "-c", inventory, output / "versions.json"], source)
        if status:
            return finish("inventory_failed", status)
        demo_status = command("demo", [python, "-m", "examples.independent_receiver_kit.demo",
                                        "--output", output / "demo"], source)
        if demo_status == 0:
            summary["first_successful_end_to_end_seconds"] = time.perf_counter() - started
            summary["first_successful_end_to_end_includes"] = [
                "source metadata", "git archive", "extraction", "venv with ensurepip",
                "dependency installation", "version inventory", "complete demo and independent verifiers"]
        save()
        tests_status = command("tests", [python, "-m", "unittest",
                                          "examples.independent_receiver_kit.test_receiver", "-v"], source,
                               {"RECEIVER_KIT_EVIDENCE": str(output / "tests")})
        return finish("passed" if demo_status == tests_status == 0 else "validation_failed",
                      demo_status or tests_status)
    except Exception as error:
        summary["error"] = type(error).__name__ + ": " + str(error)
        return finish("harness_failed", 1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="fresh output path; an existing path is refused")
    arguments = parser.parse_args()
    try:
        sys.exit(run(arguments.output))
    except FileExistsError:
        parser.exit(2, "output path already exists; choose a fresh path\n")
