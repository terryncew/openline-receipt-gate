import asyncio,json,sys,unittest
from pathlib import Path
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R))
from atomic_receiver import AtomicReceiver

class Tests(unittest.IsolatedAsyncioTestCase):
    async def test_post_correction_taint_blocks(self):
        r=AtomicReceiver(clean=set(),tainted={"x"},unknown=set(),arm="ATOMIC_RECEIVER_GATE")
        await r.apply_correction()
        e=await r.atomic_commit("x")
        self.assertEqual(e["kind"],"BLOCK")
        self.assertGreater(e["sequence"],r.correction_sequence)

    async def test_clean_survives_after_correction(self):
        r=AtomicReceiver(clean={"c"},tainted=set(),unknown=set(),arm="ATOMIC_RECEIVER_GATE")
        await r.apply_correction()
        e=await r.atomic_commit("c")
        self.assertEqual(e["kind"],"COMMIT")

    async def test_unknown_quarantines(self):
        r=AtomicReceiver(clean=set(),tainted=set(),unknown={"u"},arm="ATOMIC_RECEIVER_GATE")
        await r.apply_correction()
        e=await r.atomic_commit("u")
        self.assertEqual(e["kind"],"QUARANTINE")

    async def test_stale_precheck_can_launder(self):
        r=AtomicReceiver(clean=set(),tainted={"x"},unknown=set(),arm="STALE_PRECHECK")
        d=await r.precheck("x")
        self.assertEqual(d,"ALLOW")
        await r.apply_correction()
        e=await r.stale_commit(d,"x")
        self.assertEqual(e["kind"],"COMMIT")

    async def test_receiver_sequence_linearizes_correction(self):
        r=AtomicReceiver(clean=set(),tainted={"x"},unknown=set(),arm="ATOMIC_RECEIVER_GATE")
        await r.apply_correction()
        e=await r.atomic_commit("x")
        self.assertEqual(r.correction_sequence+1,e["sequence"])

class FreezeTests(unittest.TestCase):
    def test_runtime_unaware(self):
        f=json.loads((R/"FREEZE.json").read_text())
        self.assertFalse(f["runtime"]["scheduler_openline_awareness"])
    def test_dispatch_is_before_detection(self):
        f=json.loads((R/"FREEZE.json").read_text())
        self.assertTrue(f["race"]["dispatch_before_detection"])
    def test_authority_none(self):
        self.assertEqual(json.loads((R/"FREEZE.json").read_text())["policy_authority"],"NONE")

if __name__=="__main__":
    unittest.main()
