import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]))
from src.contestability_001.core import ContestabilityReceiver,sign_event
KEY=b"contestability-001-fixture-key"
BASE={"schema":"foreign.contestability.fixture.v1","authorization_id":"auth-001","action_digest":"sha256:action-001","forum":"forum.example/review","standing_policy_digest":"sha256:standing-policy-v1","effect_policy_digest":"sha256:effect-policy-v1"}
def ev(i,state,**extra): return sign_event(dict(BASE,event_id=i,state=state,**extra),KEY)
class T(unittest.TestCase):
    def test_filed_no_effect(self): self.assertEqual(ContestabilityReceiver(KEY).ingest(ev('1','filed',requested_local_consequence='REOPEN_ALL'))['consequences'],{"D1":"PRESERVE","D1A":"PRESERVE","D2":"PRESERVE"})
    def test_accepted(self): self.assertEqual(ContestabilityReceiver(KEY).ingest(ev('2','accepted'))['consequences'],{"D1":"QUARANTINE","D1A":"QUARANTINE","D2":"PRESERVE"})
    def test_applied(self): self.assertEqual(ContestabilityReceiver(KEY).ingest(ev('3','applied'))['consequences'],{"D1":"REOPEN","D1A":"REOPEN","D2":"PRESERVE"})
    def test_tamper(self):
        x=ev('4','applied'); x['state']='filed'; self.assertEqual(ContestabilityReceiver(KEY).ingest(x)['reason'],'INVALID_SIGNATURE')
    def test_replay(self):
        r=ContestabilityReceiver(KEY); x=ev('5','accepted'); r.ingest(x); self.assertEqual(r.ingest(x)['reason'],'REPLAY')
    def test_order(self):
        r=ContestabilityReceiver(KEY); r.ingest(ev('6a','applied')); self.assertEqual(r.ingest(ev('6b','filed'))['reason'],'ORDERING_REGRESSION')
    def test_forum(self): self.assertEqual(ContestabilityReceiver(KEY).ingest(ev('7','applied',forum='bad.example'))['reason'],'UNRECOGNIZED_FORUM')
    def test_auth(self): self.assertEqual(ContestabilityReceiver(KEY).ingest(ev('8','applied',authorization_id='auth-other'))['reason'],'AUTHORIZATION_MISMATCH')
if __name__=='__main__': unittest.main()
