"""Native, unmodified Wallet export exercised at independent receiver. Test keys only."""
from __future__ import annotations
import copy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openline_wallet import Wallet
from olp_gate.crypto import public_key_hex
from .fixtures import A,B,OUTCOME,T0
from .formats import encode_call
from .native_wallet import NativeWalletReceiver,digest
from .verify_native_wallet import verify
from .receiver import make_server
from .demo import post

def when(seconds):
    return datetime.fromtimestamp(T0+seconds,timezone.utc)

class NativeWalletKitTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)
        self.wallet=Wallet.create(self.path/"wallet",now=when(0))
        self.wallet.grant(subject_id="agent-a",subject_public_key=public_key_hex(A),
                          scopes=["intake.submit"],expires_at=when(300),now=when(0),
                          mandate_id="mandate-a")
        self.now=T0+1
        self.config={"owner_id":self.wallet.principal_id,
                     "owner_key":self.wallet.root_public_key,
                     "receiver_id":"receiver:local-lab",
                     "outcome_key":public_key_hex(OUTCOME),
                     "policy":{"version":1,"tool":"intake.submit",
                               "target":"records://local-lab/intake",
                               "max_document_chars":128,"freshness_seconds":60}}
        self.db=self.path/"receiver.sqlite3"
        self.gate=NativeWalletReceiver(self.db,self.config,OUTCOME,clock=lambda:self.now)
        self.bundle=self.wallet.export_bundle(now=when(1))
    def admit(self,bundle=None):
        return self.gate.dispatch("/authority",bundle if bundle is not None else self.bundle)
    def proof(self,key=A,mandate="mandate-a",record="record-a",nonce="nonce-a",at=None):
        t=self.now if at is None else at
        pub=public_key_hex(key)
        body={"iss":pub,"sub":pub,"aud":self.config["receiver_id"],
              "iat":t,"nbf":t,"exp":t+30,"jti":nonce,
              "policy_hash":digest(self.config["policy"]),
              "head_hash":self.bundle["head"]["event_hash"],
              "effect":{"profile":"principal_effect/v1","effect_id":record,
                        "mandate_id":mandate,"principal_id":self.wallet.principal_id,
                        "agent_id":pub,"purpose":"submit local document",
                        "action_type":"send","target":self.config["policy"]["target"],
                        "disclosures":[],"value_cents":0,"delegatee":None,
                        "producer_model":"scripted-provider"},
              "document":{"record_id":record,"text":"hello"}}
        return encode_call("openline",body,key)
    def submit(self,proof=None):
        return self.gate.dispatch("/submit",{"proof":self.proof() if proof is None else proof})
    def nrows(self):
        with sqlite3.connect(self.db) as c:
            return c.execute("SELECT COUNT(*) FROM documents").fetchone()[0]

    def test_native_export_unchanged_and_exact_effect(self):
        snapshot=json.dumps(self.bundle,sort_keys=True)
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.assertEqual(self.submit()["verdict"],"ALLOW")
        self.assertEqual(self.nrows(),1)
        self.assertEqual(json.dumps(self.bundle,sort_keys=True),snapshot)
        self.assertEqual(self.submit()["verdict"],"DENY") # durable replay
        self.assertEqual(self.nrows(),1)
    def test_wrong_owner_and_tampered_scope_refused(self):
        wrong=copy.deepcopy(self.bundle)
        wrong["principal"]["root_public_key"]="00"*32
        self.assertEqual(self.admit(wrong)["verdict"],"DENY")
        forged=copy.deepcopy(self.bundle)
        forged["events"][0]["data"]["scopes"]=["intake.submit","send:money"]
        self.assertEqual(self.admit(forged)["verdict"],"DENY")
        self.assertEqual(self.nrows(),0)
    def test_stale_export_does_not_refresh_from_duplicate(self):
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.now=T0+31
        duplicate=self.wallet.export_bundle(now=when(31))
        self.assertEqual(self.admit(duplicate)["reason"],"duplicate_does_not_refresh")
        self.now=T0+62
        self.assertEqual(self.submit()["verdict"],"DENY")
    def test_worker_binding_signature_exact_params_and_replay(self):
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.assertEqual(self.submit(self.proof(key=B))["verdict"],"DENY")
        p=self.proof()
        p["document"]["text"]="attacker mutated"
        self.assertEqual(self.submit(p)["verdict"],"DENY")
        good=self.proof()
        self.assertEqual(self.submit(good)["verdict"],"ALLOW")
        self.assertEqual(self.submit(good)["verdict"],"DENY")
        self.assertEqual(self.nrows(),1)
    def test_revocation_and_successor(self):
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.assertEqual(self.submit(self.proof(record="first",nonce="first"))["verdict"],"ALLOW")
        self.now=T0+10
        self.wallet.revoke("agent-a",now=when(10))
        self.bundle=self.wallet.export_bundle(now=when(10))
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.assertEqual(self.submit(self.proof(record="denied",nonce="denied"))["verdict"],"DENY")
        self.now=T0+20
        self.wallet.grant(subject_id="agent-b",subject_public_key=public_key_hex(B),
                          scopes=["intake.submit"],expires_at=when(300),now=when(20),
                          mandate_id="mandate-b")
        self.bundle=self.wallet.export_bundle(now=when(20))
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.assertEqual(self.submit(self.proof(key=B,mandate="mandate-b",
                         record="second",nonce="second"))["verdict"],"ALLOW")
        self.assertEqual(self.submit(self.proof(record="old",nonce="old"))["verdict"],"DENY")
        self.assertEqual(self.nrows(),2)
    def test_rollback_restart_and_no_alternate_effect_route(self):
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.now=T0+10; self.wallet.revoke("agent-a",now=when(10))
        self.bundle=self.wallet.export_bundle(now=when(10))
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.assertEqual(self.gate.dispatch("/authority",self.wallet.export_bundle(now=when(10)))["verdict"],"ACCEPT")
        self.assertEqual(self.gate.dispatch("/escape",{"x":1})["verdict"],"DENY")
        self.gate=NativeWalletReceiver(self.db,self.config,OUTCOME,clock=lambda:self.now)
        self.assertEqual(self.submit()["verdict"],"DENY")
        self.assertEqual(self.nrows(),0)
    def test_readonly_independent_verifier_and_tampered_sqlite_detected(self):
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        self.assertEqual(self.submit()["verdict"],"ALLOW")
        self.assertTrue(verify(self.db,self.config)["valid"])
        with sqlite3.connect(self.db) as c:
            c.execute("UPDATE documents SET body=? WHERE id=?",('{"record_id":"changed","text":"forged"}',"record-a"))
            c.commit()
        self.assertFalse(verify(self.db,self.config)["valid"])

    def test_http_receiver_enforces_before_local_effect(self):
        from .demo import post
        from .receiver import make_server
        server=make_server(self.gate)
        worker=threading.Thread(target=server.serve_forever,kwargs={"poll_interval":0.01},daemon=True)
        worker.start()
        try:
            port=server.server_address[1]
            self.assertEqual(post(port,"/authority",self.bundle)["verdict"],"ACCEPT")
            self.assertEqual(post(port,"/submit",{"proof":self.proof()})["verdict"],"ALLOW")
            self.assertEqual(post(port,"/submit",{"proof":self.proof()})["verdict"],"DENY")
            self.assertEqual(self.nrows(),1)
            self.assertTrue(verify(self.db,self.config)["valid"])
        finally:
            server.shutdown();worker.join(timeout=5);server.server_close()

    def test_invalid_scope_and_receiver_policy(self):
        self.assertEqual(self.admit()["verdict"],"ACCEPT")
        p=self.proof();p["effect"]["target"]="records://another-service"
        self.assertEqual(self.submit(p)["verdict"],"DENY")
        self.assertEqual(self.nrows(),0)

if __name__=="__main__":
    unittest.main()
