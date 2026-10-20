"""No-model, no-API, disposable Git-repository adversarial continuation tests."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from olp_gate.handoff.adoption import prepare,continue_to,load,write_new

def shell(*args,cwd=None):
    return subprocess.run(args,cwd=cwd,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout

class HandoffAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name)
        self.repo=self.home/"code"
        self.repo.mkdir()
        shell("git","init","-q",str(self.repo))
        shell("git","config","user.email","dev@example.invalid",cwd=self.repo)
        shell("git","config","user.name","Scripted Worker",cwd=self.repo)
        (self.repo/"calculator.py").write_text("def total(items):\n    items.sort()\n    return sum(items)\n")
        (self.repo/"test_calc.py").write_text(
            "import unittest\nfrom calculator import total\n"
            "class Ordinary(unittest.TestCase):\n"
            " def test_total(self): self.assertEqual(total([3,1,2]),6)\n"
            "class NoMutation(unittest.TestCase):\n"
            " def test_unchanged(self):\n"
            "  values=[3,1,2];total(values);self.assertEqual(values,[3,1,2])\n")
        shell("git","add","calculator.py","test_calc.py",cwd=self.repo)
        shell("git","commit","-qm","scripted Claude partial checkpoint",cwd=self.repo)
        self.approval=self.home/"approved.json"
        self.approval.write_text(json.dumps({
            "schema":"openline.approved_job.v1",
            "task_id":"correct-total-without-mutating",
            "requirements":["Return the total","Never mutate the caller's list"],
            "tests":[{"name":"ordinary","argv":["python3","-m","unittest","test_calc.Ordinary"]},
                     {"name":"no_mutation","argv":["python3","-m","unittest","test_calc.NoMutation"]}],
            "unfinished":["NoMutation fails; correct calculator.py without resetting to base"],
            "notes":["Worker claims all tests passed (unverified and false)"]},sort_keys=True))
        self.control=self.home/"receiver-control"
    def prepared(self):
        return prepare(self.repo,self.control,self.approval)
    def test_partial_handoff_is_signed_and_preserves_actual_failed_check(self):
        report=self.prepared()
        self.assertEqual(report["verdict"],"PREPARED")
        packet=load(self.control/"handoff.json")
        self.assertEqual([x["exit_code"] for x in packet["receiver_executed_tests"]],[0,1])
        self.assertIn("unverified and false",packet["notes_unverified"][0])
        result=continue_to(self.repo,self.control,"codex")
        self.assertEqual(result["verdict"],"CONTINUATION_PACKET_VERIFIED")
        continuation=load(self.control/"continuation-codex.json")
        self.assertFalse(continuation["runtime_permission"]!="NONE")
        self.assertFalse(result["agent_invoked"])
        self.assertEqual([x["exit_code"] for x in continuation["observed_test_exit_codes"]],[0,1])
    def test_modified_checkpoint_rejected(self):
        self.prepared()
        (self.repo/"calculator.py").write_text("def total(items): return 0\n")
        with self.assertRaisesRegex(ValueError,"dirty_checkpoint"):
            continue_to(self.repo,self.control,"codex")
        self.assertFalse((self.control/"continuation-codex.json").exists())
    def test_new_commit_after_prepared_checkpoint_refused(self):
        self.prepared()
        (self.repo/"calculator.py").write_text("def total(items): return sum(items)\n")
        shell("git","add","calculator.py",cwd=self.repo)
        shell("git","commit","-qm","advance after checkpoint",cwd=self.repo)
        with self.assertRaisesRegex(ValueError,"git_checkpoint_mismatch"):
            continue_to(self.repo,self.control,"codex")
    def test_revocation_blocks_packet(self):
        self.prepared()
        (self.control/"standing.json").write_text(json.dumps({"revoked":True,"sequence":1,"reason":"owner revoked"}))
        with self.assertRaisesRegex(ValueError,"permission_revoked"):
            continue_to(self.repo,self.control,"codex")
        self.assertFalse((self.control/"continuation-codex.json").exists())
    def test_unsigned_note_cannot_be_promoted(self):
        self.prepared()
        packet=load(self.control/"handoff.json")
        packet["receiver_executed_tests"][1]["exit_code"]=0
        (self.control/"handoff.json").write_text(json.dumps(packet))
        with self.assertRaisesRegex(ValueError,"signed_handoff_invalid"):
            continue_to(self.repo,self.control,"codex")
    def test_missing_signed_evidence_refuses(self):
        self.prepared()
        (self.control/"handoff.json").unlink()
        with self.assertRaises(FileNotFoundError):
            continue_to(self.repo,self.control,"codex")
    def test_forged_public_key_refuses(self):
        self.prepared()
        (self.control/"trusted-receiver.json").write_text(json.dumps({"public_key":"00"*32}))
        with self.assertRaisesRegex(ValueError,"untrusted_checkpoint_signer"):
            continue_to(self.repo,self.control,"codex")
    def test_control_inside_repo_refuses(self):
        with self.assertRaisesRegex(ValueError,"control_must_be_outside"):
            prepare(self.repo,self.repo/"control",self.approval)
    def test_owner_approval_missing_or_malformed_refuses(self):
        self.approval.write_text(json.dumps({"notes":["make up passed test results"]}))
        with self.assertRaisesRegex(ValueError,"approved_job_shape_invalid"):
            self.prepared()
    def test_asserted_permissions_do_not_authorize_real_shell(self):
        self.prepared()
        continue_to(self.repo,self.control,"codex")
        c=load(self.control/"continuation-codex.json")
        self.assertEqual(c["runtime_permission"],"NONE")
        self.assertIn("unrestricted",c["warning"])
        self.assertTrue((self.repo/"calculator.py").exists())

if __name__=="__main__":
    unittest.main()
