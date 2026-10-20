"""$0 no-model, adversarial end-to-end tests. Not frozen release autodiscovery."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from .run import build
from .verify import verify, MODES

def sha(x):return hashlib.sha256(x).hexdigest()
def reseal(root):
    """An attacker who can rewrite the *untrusted* manifest is not the owner."""
    m=root/"MANIFEST.json"
    current=json.loads(m.read_text())
    for rel in current["files"]:
        p=root/rel
        current["files"][rel]={"sha256":sha(p.read_bytes()),"bytes":p.stat().st_size}
    m.write_text(json.dumps(current,indent=2,sort_keys=True)+"\n")

class FireDrill(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="fire-drill-tests-")
        cls.base=Path(cls.temp.name)
        cls.original=cls.base/"original"
        cls.manifest=build(cls.original)
        cls.checked=verify(cls.original,cls.manifest)
        if cls.checked["verdict"]!="PASS_SCOPED_EVIDENCE":
            raise AssertionError(cls.checked)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def clone(self):
        base=Path(tempfile.mkdtemp(dir=self.base,prefix="mutated-"))
        root=base/"bundle"
        shutil.copytree(self.original,root)
        return root
    def test_fair_competent_baseline_and_openline_both_stop_protected_effect(self):
        report=self.checked["modes"]
        self.assertEqual(report["conventional"]["protected_unauthorized_effects"],0)
        self.assertEqual(report["openline"]["protected_unauthorized_effects"],0)
        self.assertEqual(report["conventional"]["protected_denied_old_agent_attempts"],4)
        self.assertEqual(report["openline"]["protected_denied_old_agent_attempts"],4)
    def test_deliberately_weak_fixture_is_a_real_local_failure_not_vendor_claim(self):
        weak=self.checked["modes"]["intentionally_weak"]
        self.assertEqual(weak["protected_unauthorized_effects"],4)
        self.assertEqual(weak["receiver_cryptographic_evidence"],"NOT_AVAILABLE_UNSIGNED_WEAK_TEACHING_FIXTURE")
    def test_approved_successor_and_unrelated_authority_survive_in_each_mode(self):
        for mode in MODES:
            r=self.checked["modes"][mode]
            self.assertTrue(r["retained_original_work"])
            self.assertTrue(r["successor_work"])
            self.assertEqual(r["unrelated_slot_effects"],1)
    def test_outside_receiver_write_survives_in_every_mode(self):
        for mode in MODES:
            self.assertEqual(self.checked["modes"][mode]["outside_receiver_effects"],1)
    def test_bundle_has_self_contained_40_second_playback(self):
        page=(self.original/"fire-drill-40s.html").read_text()
        self.assertIn("elapsed/5",page)
        self.assertIn("Math.min(40",page)
        self.assertIn("Intentionally weak: 4 post-revocation A effects",page)
        self.assertIn("Proper JWT: 0. OpenLine: 0.",page)
        self.assertNotIn("__DATA__",page)
        self.assertNotIn("real Claude API",page)
    def test_verifier_accepts_original_pinned_bundle(self):
        self.assertEqual(self.checked["verdict"],"PASS_SCOPED_EVIDENCE")
        self.assertEqual(self.checked["manifest_sha256"],self.manifest)
    def test_manifest_pin_refuses_wholesale_replacement(self):
        root=self.clone()
        doc=json.loads((root/"MANIFEST.json").read_text())
        doc["source"]="attacker rewrites manifest"
        (root/"MANIFEST.json").write_text(json.dumps(doc))
        self.assertEqual(verify(root,self.manifest)["verdict"],"BLOCKED")
        self.assertIn("out_of_band_manifest_hash_mismatch",verify(root,self.manifest)["errors"])
    def test_single_file_tamper_refused(self):
        root=self.clone()
        path=root/"conventional"/"events.jsonl"
        path.write_text(path.read_text()+"\n")
        self.assertEqual(verify(root)["verdict"],"BLOCKED")
    def test_missing_evidence_refused(self):
        root=self.clone()
        (root/"openline"/"events.jsonl").unlink()
        self.assertEqual(verify(root)["verdict"],"BLOCKED")
    def test_extra_unlisted_evidence_refused(self):
        root=self.clone()
        (root/"attacker_override.json").write_text('{"allow":true}')
        self.assertEqual(verify(root)["verdict"],"BLOCKED")
    def test_forged_signed_receipt_refused_even_after_attacker_rehashes_manifest(self):
        root=self.clone()
        path=root/"openline"/"state.sqlite3"
        with sqlite3.connect(path) as c:
            raw=c.execute("SELECT body FROM decisions WHERE seq=4").fetchone()[0]
            value=json.loads(raw)
            value["verdict"]="ALLOW"
            c.execute("UPDATE decisions SET body=? WHERE seq=4",(json.dumps(value),))
        reseal(root)
        report=verify(root)
        self.assertEqual(report["verdict"],"BLOCKED")
        self.assertTrue(any("reported_decision" in str(x) or "signed_receiver" in str(x)
                            for x in report["errors"]))
    def test_hidden_external_write_cannot_be_erased_and_resealed(self):
        root=self.clone()
        path=root/"conventional"/"unprotected.sqlite3"
        with sqlite3.connect(path) as c:c.execute("DELETE FROM effects")
        reseal(root)
        self.assertEqual(verify(root)["verdict"],"BLOCKED")
    def test_runner_summary_cannot_substitute_missing_signed_evidence(self):
        root=self.clone()
        (root/"openline"/"state.sqlite3").unlink()
        reseal(root)
        self.assertEqual(verify(root)["verdict"],"BLOCKED")
    def test_malformed_case_claim_rejected_despite_valid_untrusted_manifest(self):
        root=self.clone()
        path=root/"intentionally_weak"/"events.jsonl"
        items=[json.loads(l) for l in path.read_text().splitlines()]
        items[3]["decision"]["verdict"]="DENY"
        path.write_text("".join(json.dumps(i)+"\n" for i in items))
        reseal(root)
        self.assertEqual(verify(root)["verdict"],"BLOCKED")

if __name__=="__main__":unittest.main()
