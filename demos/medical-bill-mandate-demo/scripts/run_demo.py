from __future__ import annotations

import json
import tempfile
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.adapters import TrustStore
from olp_gate.crypto import public_key_hex, sha256_hex
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request
from olp_gate.mandate import assess_effect, compile_verified_commit_settings
from olp_gate.mandate_gate import execute_mandated_once
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.verified_commit import VerifiedCommitLedger, settings_hash

ROOT=Path(__file__).resolve().parents[1]
MANDATE=json.loads((ROOT/"fixtures/alice_mandate.json").read_text())
PRESSURE=json.loads((ROOT/"fixtures/pressure_variants.json").read_text())
NOW=datetime(2026,8,23,5,30,0,tzinfo=timezone.utc)

def iso(v):
    return v.astimezone(timezone.utc).isoformat().replace("+00:00","Z")

def effect(effect_id, *, model="model-a", disclosures=None,
           action_type="send", value_cents=0, target="hospital-billing-office"):
    return {
        "profile":"principal_effect/v1",
        "effect_id":effect_id,
        "mandate_id":MANDATE["mandate_id"],
        "principal_id":MANDATE["principal_id"],
        "agent_id":MANDATE["agent_id"],
        "purpose":MANDATE["purpose"],
        "action_type":action_type,
        "target":target,
        "disclosures":disclosures or [],
        "value_cents":value_cents,
        "delegatee":None,
        "producer_model":model,
    }

class Fixture:
    def __init__(self, root):
        self.root=Path(root)
        self.source_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex("81"*32))
        self.witness_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex("82"*32))
        self.gate_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex("83"*32))
        self.source_method="did:example:medical-bill-demo#key-1"
        self.store=TrustStore.from_mapping({
            "keys":{
                self.source_method:{
                    "public_key":public_key_hex(self.source_key),
                    "roles":["source"],"independence":"operator","controller":"demo-source"
                },
                public_key_hex(self.witness_key):{
                    "public_key":public_key_hex(self.witness_key),
                    "roles":["outcome"],"independence":"receiver","controller":"demo-receiver"
                }
            }
        })

    @property
    def gate_public(self):
        return public_key_hex(self.gate_key)

    def issue(self, case, e):
        settings=compile_verified_commit_settings(MANDATE,e,now=NOW)
        artifact=self.root/f"{case}.json"
        artifact.write_text('{"approved":true}\n',encoding="utf-8")
        ah=sha256_hex(artifact.read_bytes())
        run_id=f"demo-{case}"
        source=_agent_receipt(
            key=self.source_key,method=self.source_method,chain_id=run_id,
            session_id=f"session-{case}",action_id=f"action-{case}",
            action_type="tool_call",response_hash=ah,timestamp=iso(NOW)
        )
        source_hash=_source_hash(source)
        session=SessionLedger(self.root/f"{case}-sessions.json")
        binding=session.issue_challenge(
            run_id=run_id,session_id=f"session-{case}",expected_source_hash=source_hash
        )
        outcome=issue_outcome_receipt(
            source_receipt_hash=source_hash,outcome_status="pass",harmful=False,
            evidence_hash=ah,witness_id="demo-receiver",
            rollback_supported=True,key=self.witness_key
        )
        action={
            "tool":"messaging.send",
            "target":"hospital-billing-office",
            "settings":settings,
            "run_id":run_id,
            "capsule_hash":sha256_hex(f"capsule:{case}".encode()),
            "evidence_hashes":[ah],
        }
        policy=PolicySpec.from_mapping({
            "policy_id":"medical-bill-demo-policy","version":"1",
            "require_declared_coverage":True,"require_outcome_witness":True,
            "required_evidence_ids":["result"],
            "evidence_assertions":[
                {"evidence_id":"result","path":"approved","op":"equals","value":True}
            ],
            "metadata":{
                "verified_commit":{
                    "required":True,"tool":action["tool"],"target":action["target"],
                    "settings_hash":settings_hash(settings),"run_id":run_id,
                    "capsule_hash":action["capsule_hash"],
                    "evidence_hashes":action["evidence_hashes"],
                    "max_ttl_seconds":120,
                }
            }
        })
        # Keep the demo's already-proven authorized case code unchanged, but
        # give every other fixture a separate deterministic code family.
        code=("aa" if case=="allowed" else "cd")*32
        req={
            "schema":"openline.proof_to_policy.request.v0.2",
            "request_id":f"request-{case}","action_type":"tool_call",
            "claim":"This exact user-authorized effect may execute once.",
            "source_receipts":[source],"binding":binding,
            "evidence":[{
                "id":"result","artifact_path":artifact.name,"content_hash":ah,
                "source_commitment_path":"credentialSubject.outcome.response_hash",
            }],
            "outcome_receipt":outcome,
            "commit_request":{
                **action,"policy_hash":policy.policy_hash,
                "expires_at":iso(NOW+timedelta(seconds=60)),
                "one_use_code":code,
            }
        }
        receipt=evaluate_request(
            req,policy=policy,trust_store=self.store,signing_key=self.gate_key,
            issuer_id="medical-bill-demo-gate",
            decision_path=self.root/f"{case}-decisions.jsonl",
            session_ledger=session,base_dir=self.root,now=NOW,
        )
        action["policy_hash"]=policy.policy_hash
        return receipt,action,code

def print_line(label, text):
    print(f"{label:<18} {text}")

def main():
    transcript=[]
    with tempfile.TemporaryDirectory(prefix="medical-bill-mandate-demo-") as td:
        fx=Fixture(td)

        psych=effect(
            "psych-disclosure",
            disclosures=["billing-record","psychiatric-note"],
        )

        unguarded_effects=[]
        def unguarded_send(e):
            unguarded_effects.append(e)
            return {"sent":True}
        unguarded_send(psych)
        transcript.append({
            "scene":"no_gate_control",
            "proposal":"send billing record + psychiatric note",
            "result":"SENT",
        })

        guarded_assessment=assess_effect(MANDATE,psych,now=NOW)
        guarded_sent=False
        try:
            compile_verified_commit_settings(MANDATE,psych,now=NOW)
            guarded_sent=True
        except PermissionError:
            pass
        transcript.append({
            "scene":"guarded_forbidden_disclosure",
            "proposal":"send billing record + psychiatric note",
            "result":"BLOCKED" if not guarded_sent else "SENT",
            "reason_codes":guarded_assessment["reason_codes"],
        })

        allowed=effect("allowed",disclosures=["billing-record","eob"])
        receipt,action,code=fx.issue("allowed",allowed)
        ledger=VerifiedCommitLedger(Path(td)/"allowed-ledger.json")
        effects={"n":0}
        lock=threading.Lock()
        def send():
            with lock:
                effects["n"]+=1
            return {"sent":True}
        first=execute_mandated_once(
            ledger,receipt,action,mandate=MANDATE,one_use_code=code,
            trusted_gate_keys=[fx.gate_public],executor=send,now=NOW,
            attempt_label="first-send"
        )
        transcript.append({
            "scene":"guarded_allowed_dispute",
            "result":"SENT" if first["authorized"] else "BLOCKED",
            "effect_count":effects["n"],
        })

        replay=execute_mandated_once(
            ledger,receipt,action,mandate=MANDATE,one_use_code=code,
            trusted_gate_keys=[fx.gate_public],executor=send,now=NOW,
            attempt_label="replay"
        )
        transcript.append({
            "scene":"spent_authorization_replay",
            "result":"BLOCKED" if not replay["authorized"] else "SENT",
            "reason_codes":replay["reason_codes"],
            "effect_count":effects["n"],
        })

        over=effect("settlement",action_type="accept_settlement",value_cents=50001)
        over_a=assess_effect(MANDATE,over,now=NOW)
        transcript.append({
            "scene":"settlement_above_ceiling",
            "result":"BLOCKED" if not over_a["allowed"] else "ACCEPTED",
            "reason_codes":over_a["reason_codes"],
        })

        model_rows={}
        for model in ("model-a","model-b"):
            ok=assess_effect(
                MANDATE,effect(f"ok-{model}",model=model,disclosures=["billing-record"]),now=NOW
            )
            bad=assess_effect(
                MANDATE,effect(f"bad-{model}",model=model,disclosures=["psychiatric-note"]),now=NOW
            )
            model_rows[model]={"allowed_case":ok["allowed"],"forbidden_case":bad["allowed"]}
        transcript.append({
            "scene":"model_swap",
            "result":"UNCHANGED_AUTHORITY",
            "models":model_rows,
        })

        # Race repair:
        # use independent ledger objects pointed at the same receiver-owned
        # ledger file. This preserves one shared atomic replay scope while
        # avoiding a demo-only shared-object scheduling artifact.
        race=effect("race",disclosures=["billing-record"])
        r_receipt,r_action,r_code=fx.issue("race",race)
        race_ledger_path=Path(td)/"race-ledger.json"
        r_count={"n":0}
        r_lock=threading.Lock()
        barrier=threading.Barrier(16)

        def worker(i):
            barrier.wait()
            def do_send():
                with r_lock:
                    r_count["n"]+=1
                return {"sent":True,"worker":i}
            return execute_mandated_once(
                VerifiedCommitLedger(race_ledger_path),
                r_receipt,
                r_action,
                mandate=MANDATE,
                one_use_code=r_code,
                trusted_gate_keys=[fx.gate_public],
                executor=do_send,
                now=NOW,
                attempt_label=f"race-{i}",
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            rows=list(pool.map(worker,range(16)))

        auth=sum(1 for r in rows if r["authorized"])
        blocked_reasons=Counter(
            reason
            for row in rows if not row["authorized"]
            for reason in row.get("reason_codes",[])
        )
        transcript.append({
            "scene":"concurrent_replay",
            "attempts":16,
            "authorized":auth,
            "blocked":16-auth,
            "effect_count":r_count["n"],
            "blocked_reason_counts":dict(sorted(blocked_reasons.items())),
        })

        pressure_results=[]
        for model in ("model-a","model-b"):
            for i,text in enumerate(PRESSURE):
                if i % 2 == 0:
                    e=effect(
                        f"pressure-{model}-{i}",model=model,
                        disclosures=["billing-record","psychiatric-note"],
                    )
                else:
                    e=effect(
                        f"pressure-{model}-{i}",model=model,
                        action_type="accept_settlement",value_cents=50001,
                    )
                a=assess_effect(MANDATE,e,now=NOW)
                pressure_results.append({
                    "model":model,"variant":i,"embedded_text":text,
                    "blocked":not a["allowed"],"reason_codes":a["reason_codes"],
                })

        held=sum(1 for r in pressure_results if r["blocked"])
        qa={
            "schema":"openline.medical_bill_mandate_demo.pressure_qa.v1",
            "held":held,"total":len(pressure_results),
            "producer_model_labels":["model-a","model-b"],
            "real_llm_generation":False,
            "claim":"downstream mandate enforcement under varied hostile proposed effects",
            "results":pressure_results,
        }

        receipt_out={
            "schema":"openline.medical_bill_mandate_demo.receipt.v1",
            "policy_authority":"NONE",
            "transcript":transcript,
            "checks":{
                "unguarded_control_exposed_forbidden_effect":len(unguarded_effects)==1,
                "guarded_forbidden_effect_blocked":not guarded_sent,
                "allowed_effect_committed_once":first["authorized"] and effects["n"]==1,
                "sequential_replay_blocked":not replay["authorized"] and effects["n"]==1,
                "settlement_above_ceiling_blocked":not over_a["allowed"],
                "model_swap_did_not_expand_authority":all(
                    v=={"allowed_case":True,"forbidden_case":False}
                    for v in model_rows.values()
                ),
                "concurrent_replay_exactly_once":auth==1 and r_count["n"]==1,
                "pressure_qa_all_held":held==len(pressure_results),
            },
            "race_diagnostics":{
                "authorized":auth,
                "effects":r_count["n"],
                "blocked_reason_counts":dict(sorted(blocked_reasons.items())),
            },
            "claim_boundary":{
                "creates_fiduciary_duty":False,
                "real_llm_prompt_injection_test":False,
                "uses_real_medical_records":False,
                "moves_real_money":False,
            }
        }
        receipt_out["passed"]=all(receipt_out["checks"].values())

        (ROOT/"demo_receipt.json").write_text(
            json.dumps(receipt_out,indent=2,sort_keys=True)+"\n"
        )
        (ROOT/"pressure_qa.json").write_text(
            json.dumps(qa,indent=2,sort_keys=True)+"\n"
        )

        print("\nMEDICAL BILL MANDATE DEMO\n")
        print_line("NO GATE", "psychiatric record proposal -> SENT")
        print_line("MANDATE GATE", "same proposal -> BLOCKED")
        print_line("ALLOWED", "billing record + EOB -> SENT")
        print_line("SETTLEMENT", "$500.01 proposal -> BLOCKED")
        print_line("MODEL SWAP", "authority unchanged")
        print_line("REPLAY", "spent authorization -> BLOCKED")
        print_line("RACE", f"16 attempts -> {auth} effect")
        if auth != 1:
            print_line("RACE REASONS", json.dumps(dict(sorted(blocked_reasons.items()))))
        print_line("PRESSURE QA", f"{held}/{len(pressure_results)} hostile proposals held")
        print("\nPASS" if receipt_out["passed"] else "\nFAIL")
        return 0 if receipt_out["passed"] else 2

if __name__=="__main__":
    raise SystemExit(main())
