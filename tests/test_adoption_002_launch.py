"""ADOPTION-002: reproduce old same-UID break, then verify Linux owner UID isolation.

$0 scripted processes only. Tests require root, otherwise explicitly SKIP/BLOCKED.
"""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import pwd
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from olp_gate.handoff.adoption import prepare,continue_to,load
from olp_gate.handoff.isolated_launch import (owner_init,revoke,launch,
                                              verify_receipt,digest)

def git(*args,cwd):
    return subprocess.run(["git",*args],cwd=cwd,capture_output=True,
                          check=True).stdout.decode().strip()

class LegacyStandingAttack(unittest.TestCase):
    def test_legacy_same_uid_unsigned_revocation_can_be_reset(self):
        with tempfile.TemporaryDirectory(prefix="adoption002-legacy-") as tmp:
            base=Path(tmp);repo=base/"repo";repo.mkdir()
            git("init","-q",cwd=repo)
            git("config","user.email","test@example.invalid",cwd=repo)
            git("config","user.name","Test",cwd=repo)
            (repo/"code.py").write_text("answer=42\n")
            (repo/"test_code.py").write_text(
                "import unittest\nclass T(unittest.TestCase):\n"
                " def test_something(self):self.assertEqual(42,42)\n")
            git("add",".",cwd=repo);git("commit","-qm","fixed",cwd=repo)
            approval=base/"approval.json"
            approval.write_text(json.dumps({
                "schema":"openline.approved_job.v1","task_id":"legacy",
                "requirements":["do task"],"tests":[{"name":"t","argv":["python3","-m","unittest","test_code.T"]}],
                "unfinished":[],"notes":[]}))
            ctl=base/"legacy-control"
            prepare(repo,ctl,approval)
            (ctl/"standing.json").write_text(json.dumps(
                {"revoked":True,"sequence":1,"reason":"owner revoked"}))
            (ctl/"standing.json").write_text(json.dumps(
                {"revoked":False,"sequence":0,"reason":None}))
            # Historical failure reproduced: a worker with owner UID can
            # rewrite unsigned state, then get a continuation INFORMATION packet.
            outcome=continue_to(repo,ctl,"codex")
            self.assertEqual(outcome["verdict"],"CONTINUATION_PACKET_VERIFIED")
            self.assertFalse(outcome["agent_invoked"])
            self.assertFalse(outcome["runtime_enforcement"])
            # The old packet is NEVER accepted by the v2 successor launcher.
            self.assertNotIn("checkpoint_sha256",load(ctl/"continuation-codex.json"))

@unittest.skipUnless(sys.platform=="linux" and os.geteuid()==0,
                     "BLOCKED: trusted root-owned OS separation unavailable")
class ProtectedLaunch(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix="adoption002-secure-")
        self.addCleanup(self.t.cleanup)
        self.base=Path(self.t.name)
        self.base.chmod(0o700)
        self.repo=self.base/"repo";self.repo.mkdir()
        git("init","-q",cwd=self.repo)
        git("config","user.email","test@example.invalid",cwd=self.repo)
        git("config","user.name","Test",cwd=self.repo)
        (self.repo/"calculator.py").write_text("def total(items):\n    items.sort()\n    return sum(items)\n")
        (self.repo/"test_code.py").write_text(
            "import unittest\nfrom calculator import total\n"
            "class Ordinary(unittest.TestCase):\n"
            " def test_total(self):self.assertEqual(total([3,1,2]),6)\n"
            "class NoMutation(unittest.TestCase):\n"
            " def test_unchanged(self):\n"
            "  values=[3,1,2];total(values);self.assertEqual(values,[3,1,2])\n")
        git("add",".",cwd=self.repo);git("commit","-qm","checkpoint",cwd=self.repo)
        self.approval=self.base/"approved.json"
        self.approval.write_text(json.dumps({
            "schema":"openline.approved_job.v1","task_id":"safe",
            "requirements":["Sum the items, without modifying them"],
            "tests":[{"name":"ordinary","argv":["python3","-m","unittest","test_code.Ordinary"]},
                     {"name":"no_mutation","argv":["python3","-m","unittest","test_code.NoMutation"]}],
            "unfinished":["NoMutation test fails at the partial checkpoint"],"notes":["Previous agent asserts all tests passed: FALSE"]}))
        self.ctl=self.base/"owner-control"
        self.pin=self.base/"owner-pin.json"
        self.uid=pwd.getpwnam("nobody").pw_uid
        self.assertNotEqual(self.uid,0)
        self.created=owner_init(self.repo,self.approval,self.ctl,self.pin,self.uid)
        self.assertEqual(self.created["decision"],"OWNER_INITIALIZED")
    def last_receipt(self):
        files=sorted((self.ctl/"receipts").glob("*.json"))
        self.assertTrue(files)
        r=load(files[-1])
        self.assertTrue(verify_receipt(r,self.pin))
        return r

    def test_observed_partial_tests_are_signed_not_promoted_from_notes(self):
        packet=load(self.ctl/"checkpoint.json")
        self.assertEqual([t["exit_code"] for t in packet["receiver_observed_tests"]],[0,1])
        self.assertEqual(packet["notes_unverified"],["Previous agent asserts all tests passed: FALSE"])
        self.assertEqual(launch(self.repo,self.ctl,self.pin,self.uid)["decision"],"LAUNCHED")
        tampered=dict(packet)
        tampered["receiver_observed_tests"]=[{**packet["receiver_observed_tests"][1],"exit_code":0}]
        (self.ctl/"checkpoint.json").write_text(json.dumps(tampered))
        refused=launch(self.repo,self.ctl,self.pin,self.uid)
        self.assertEqual(refused["decision"],"REFUSED")
        self.assertEqual(self.last_receipt()["decision"],"REFUSED")

    def test_valid_launch_real_distinct_worker_and_protected_control(self):
        v=launch(self.repo,self.ctl,self.pin,self.uid)
        self.assertEqual(v["decision"],"LAUNCHED",v)
        self.assertEqual(v["worker_exit"],0)
        r=self.last_receipt()
        self.assertEqual(r["decision"],"LAUNCHED")
        self.assertTrue(r["facts"]["worker_control_write_blocked"])
        self.assertEqual(r["facts"]["worker_uid"],self.uid)
        self.assertEqual((self.ctl/"authority.jsonl").stat().st_uid,0)

    def test_revoked_standing_denies_pre_spawn_and_old_checkpoint(self):
        old=load(self.ctl/"checkpoint.json")
        revoke(self.ctl,self.pin)
        self.assertEqual(launch(self.repo,self.ctl,self.pin,self.uid)["decision"],"REFUSED")
        self.assertEqual(self.last_receipt()["decision"],"REFUSED")
        self.assertEqual(load(self.ctl/"checkpoint.json"),old)
        self.assertEqual(launch(self.repo,self.ctl,self.pin,self.uid)["decision"],"REFUSED")

    def test_worker_cannot_touch_root_keys_or_authority_via_real_uid(self):
        # The actual launched worker tries the direct signed authority write.
        self.assertEqual(launch(self.repo,self.ctl,self.pin,self.uid)["decision"],"LAUNCHED")
        trial=subprocess.run([sys.executable,"-c",
             "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('hacked')",
             str(self.ctl/"owner-key.hex")],
             preexec_fn=lambda:(os.setgroups([]),os.setgid(pwd.getpwuid(self.uid).pw_gid),os.setuid(self.uid)),
             capture_output=True)
        self.assertNotEqual(trial.returncode,0)
        self.assertEqual(len(list((self.ctl/"receipts").glob("*.json"))),1)

    def test_old_checkpoint_is_rejected_even_if_new_signed_file_replaced(self):
        old=load(self.ctl/"checkpoint.json")
        (self.ctl/"checkpoint.json").write_text(json.dumps(
            {**old,"git_commit":"0"*40}))
        v=launch(self.repo,self.ctl,self.pin,self.uid)
        self.assertEqual(v["decision"],"REFUSED")
        self.assertIn("signature",v["reason"])

    def test_worker_uid_cannot_replace_any_owner_authority_file(self):
        identity=pwd.getpwuid(self.uid)
        for protected in (self.pin, self.ctl/"owner-key.hex",
                          self.ctl/"checkpoint.json", self.ctl/"authority.jsonl",
                          self.ctl/"frontier.json", self.ctl/"controller.lock"):
            original=protected.read_bytes()
            attacker=subprocess.run([sys.executable,"-c",
                  "import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b'worker-rollback')",
                  str(protected)],
                  preexec_fn=lambda:(os.setgroups([]),os.setgid(identity.pw_gid),
                                     os.setuid(identity.pw_uid)),
                  stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertNotEqual(attacker.returncode,0,protected)
            self.assertEqual(protected.read_bytes(),original,protected)
        self.assertEqual(launch(self.repo,self.ctl,self.pin,self.uid)["decision"],"LAUNCHED")

    def test_bad_legacy_trusted_receiver_is_never_launch_trust_root(self):
        # The old unpinned trust file is ignored entirely by the v2 controller.
        (self.base/"trusted-receiver.json").write_text('{"public_key":"00"}')
        self.assertEqual(launch(self.repo,self.ctl,self.pin,self.uid)["decision"],"LAUNCHED")

    def test_controller_pin_or_key_replacement_fails(self):
        owner=load(self.pin)
        (self.pin).write_text(json.dumps({"schema":owner["schema"],"owner_public_key":"00"*32}))
        with self.assertRaises(ValueError):
            launch(self.repo,self.ctl,self.pin,self.uid)

    def test_rollback_to_old_valid_signed_event_rejected(self):
        old=(self.ctl/"authority.jsonl").read_bytes()
        revoke(self.ctl,self.pin)
        (self.ctl/"authority.jsonl").write_bytes(old)
        v=launch(self.repo,self.ctl,self.pin,self.uid)
        self.assertEqual(v["decision"],"REFUSED")
        self.assertIn("rollback",v["reason"])

    def test_prelaunch_checkpoint_mutation_race_refuses(self):
        def race():
            (self.repo/"calculator.py").write_text("def total(items):return 0\n")
        v=launch(self.repo,self.ctl,self.pin,self.uid,before_spawn=race)
        self.assertEqual(v["decision"],"REFUSED")
        self.assertIn("checkpoint",v["reason"])
        self.assertEqual(self.last_receipt()["decision"],"REFUSED")

    def test_unrelated_control_is_still_permitted(self):
        v=launch(self.repo,self.ctl,self.pin,self.uid)
        self.assertEqual(v["decision"],"LAUNCHED")
        # A separate signed permission state for another owner-controlled
        # task would not be invalidated by changing this task's authority.
        # This independent control is the conventional OS permission baseline.
        other_dir=self.base/"another-control"
        other_pin=self.base/"another-pin.json"
        owner_init(self.repo,self.approval,other_dir,other_pin,self.uid)
        revoke(self.ctl,self.pin)
        self.assertEqual(launch(self.repo,self.ctl,self.pin,self.uid)["decision"],"REFUSED")
        self.assertEqual(launch(self.repo,other_dir,other_pin,self.uid)["decision"],"LAUNCHED")

    def test_conventional_same_OS_isolation_baseline_parity(self):
        v=launch(self.repo,self.ctl,self.pin,self.uid,mode="conventional")
        self.assertEqual(v["decision"],"LAUNCHED")
        self.assertEqual(self.last_receipt()["facts"]["mode"],"conventional")
        revoke(self.ctl,self.pin)
        self.assertEqual(launch(self.repo,self.ctl,self.pin,self.uid,mode="conventional")["decision"],"REFUSED")

    def test_non_root_controller_must_refuse(self):
        script="from olp_gate.handoff.isolated_launch import launch; import sys; print(launch(*sys.argv[1:4],int(sys.argv[4])))"
        p=pwd.getpwuid(self.uid)
        cmd=[sys.executable,"-c",script,str(self.repo),str(self.ctl),str(self.pin),str(self.uid)]
        out=subprocess.run(cmd,preexec_fn=lambda:(os.setgroups([]),os.setgid(p.pw_gid),os.setuid(p.pw_uid)),
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertNotEqual(out.returncode,0)

if __name__=="__main__":unittest.main()
