"""$0 scripted Claude->Codex continuation in disposable Git workspace.

No real model, paid API, production filesystem or outside effect.
An ordinary Git+notes+tests control receives exactly the same task/checks.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from olp_gate.handoff.adoption import main as cli

def run(*args,cwd=None):
    r=subprocess.run(args,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if r.returncode:raise RuntimeError(f"{args!r}: {r.stderr}")
    return r.stdout.strip()

def main():
    started=time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="openline-adoption-001-") as tmp:
        root=Path(tmp);repo=root/"synthetic-repo";repo.mkdir()
        run("git","init","-q",str(repo))
        run("git","config","user.email","demo@example.invalid",cwd=repo)
        run("git","config","user.name","Scripted Agent",cwd=repo)
        (repo/"calculator.py").write_text("def total(items):\n    items.sort()\n    return sum(items)\n")
        (repo/"test_calc.py").write_text(
            "import unittest\nfrom calculator import total\n"
            "class Ordinary(unittest.TestCase):\n"
            " def test_total(self):self.assertEqual(total([3,1,2]),6)\n"
            "class NoMutation(unittest.TestCase):\n"
            " def test_unchanged(self):\n"
            "  x=[3,1,2];total(x);self.assertEqual(x,[3,1,2])\n")
        run("git","add",".",cwd=repo)
        run("git","commit","-qm","scripted Claude partial work",cwd=repo)
        checkpoint=run("git","rev-parse","HEAD",cwd=repo)
        approval=root/"owner-approved.json"
        approval.write_text(json.dumps({
            "schema":"openline.approved_job.v1","task_id":"fix-pure-sum",
            "requirements":["Return correct sum","Never mutate the caller's list"],
            "tests":[{"name":"ordinary","argv":["python3","-m","unittest","test_calc.Ordinary"]},
                     {"name":"no-mutation","argv":["python3","-m","unittest","test_calc.NoMutation"]}],
            "unfinished":["Approved no-mutation acceptance still fails"],
            "notes":["Claude says complete — unverified agent statement"]}))
        control=root/"receiver-state"
        if cli(["handoff","prepare","--repo",str(repo),"--control",str(control),"--approval",str(approval)]):
            raise RuntimeError("prepare_failed")
        if cli(["handoff","continue","--repo",str(repo),"--control",str(control),"--agent","codex"]):
            raise RuntimeError("continue_failed")
        packet=json.loads((control/"continuation-codex.json").read_text())
        assert [t["exit_code"] for t in packet["observed_test_exit_codes"]]==[0,1]
        assert packet["runtime_permission"]=="NONE"
        # Simulated worker B: read the packet first; no Claude chat or API keys.
        (repo/"calculator.py").write_text("def total(items):\n    return sum(items)\n")
        run("git","add","calculator.py",cwd=repo)
        run("git","commit","-qm","scripted Codex continuation",cwd=repo)
        run("git","merge-base","--is-ancestor",checkpoint,"HEAD",cwd=repo)
        test=run("python3","-m","unittest","test_calc.Ordinary","test_calc.NoMutation",cwd=repo)
        successor=run("git","rev-parse","HEAD",cwd=repo)
        # Competent conventional control on the same synthetic checkout:
        # Git and the same tests see the same checkpoints, and notes are notes.
        baseline_start=time.perf_counter()
        baseline_head=run("git","rev-parse","HEAD",cwd=repo)
        run("git","status","--porcelain",cwd=repo)
        run("git","merge-base","--is-ancestor",checkpoint,baseline_head,cwd=repo)
        run("python3","-m","unittest","test_calc.Ordinary","test_calc.NoMutation",cwd=repo)
        result={
            "verdict":"SCRIPTED_HANDOFF_PASS","model_calls":0,"external_effects":0,
            "checkpoint":checkpoint,"successor_commit":successor,
            "receiver_verified_predecessor_tests":{"ordinary":"PASS","no_mutation":"FAIL"},
            "successor_tests":{"ordinary":"PASS","no_mutation":"PASS"},
            "notes_promoted_to_verified":False,
            "successor_used_prior_chat":False,"successor_launched_by_cli":False,
            "shell_enforcement":"NONE",
            "baseline":"manual notes + git status/history + same unittest commands",
            "baseline_result":"SAME_CORRECT_CONTINUATION_WITH_DILIGENT_RECHECKS",
            "baseline_check_ms":round((time.perf_counter()-baseline_start)*1000),
            "total_script_seconds":round(time.perf_counter()-started,3),
            "ten_minute_target_met_in_ci_script":(time.perf_counter()-started)<600,
            "ten_minute_outsider_installation":"NOT_MEASURED"}
        print(json.dumps(result,sort_keys=True,indent=2))
        return result
if __name__=="__main__":main()
