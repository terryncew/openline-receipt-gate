"""Out-of-process independent read-only audit of native Wallet kit's signed state."""
from __future__ import annotations
from contextlib import closing
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3

from openline_wallet import verify_bundle
from openline_wallet.crypto import record_hash
from olp_gate.crypto import olp_canonical_json,verify_olp_signature,sha256_hex
from .formats import decode_call

def canonical(x):return olp_canonical_json(x).decode("ascii")
def digest(x):return sha256_hex(olp_canonical_json(x))

def verify(db,config):
    result={"valid":False,"errors":[],"authority":0,"allows":0,"denies":0,"documents":0,
            "caveats":["Source keys/config are externally trusted test fixtures",
                       "Signer and SQLite operator are trusted; this is not external effect control"]}
    try:
        uri=Path(db).resolve().as_uri()+"?mode=ro"
        with closing(sqlite3.connect(uri,uri=True)) as c:
            c.row_factory=sqlite3.Row
            c.execute("PRAGMA query_only=ON");c.execute("BEGIN")
            rows={table:[dict(x) for x in c.execute("SELECT * FROM "+table)]
                  for table in ("settings","history","decisions","documents","consumed")}
            c.execute("COMMIT")
        if len(rows["settings"])!=1 or rows["settings"][0]["json"]!=canonical(config):
            raise ValueError("receiver_config_changed")
        accepted=[]
        previous=None
        documents={}
        consumed={}
        for n,row in enumerate(sorted(rows["decisions"],key=lambda x:x["seq"]),start=1):
            if row["seq"]!=n:raise ValueError("decision_sequence_gap")
            decision=json.loads(row["signed"]);request=json.loads(row["request"])
            if decision.get("schema")!="receiver-kit-native-wallet-decision/v1":
                raise ValueError("decision_schema_invalid")
            signature=decision.get("signature")
            if not isinstance(signature,dict) or signature.get("public_key")!=config["outcome_key"]:
                raise ValueError("decision_receiver_key_not_pinned")
            ok,reason=verify_olp_signature(decision)
            if not ok:raise ValueError("invalid_decision_signature:"+str(reason))
            if (decision["seq"]!=n or decision["route"]!=row["route"]
                    or decision["receiver_id"]!=config["receiver_id"]
                    or decision["request_hash"]!=digest(request)
                    or decision["policy_hash"]!=digest(config["policy"])):
                raise ValueError("decision_binding_invalid")
            if decision["documents_before"]!=len(documents):
                raise ValueError("documents_before_mismatch")
            at=decision["observed_at"]
            verdict=decision["verdict"]
            if verdict=="ACCEPT":
                if row["route"]!="/authority":raise ValueError("admission_route_invalid")
                bundle,timeline=verify_bundle(request,now=datetime.fromtimestamp(at,timezone.utc))
                principal=bundle["principal"]
                if principal["principal_id"]!=config["owner_id"] or principal["root_public_key"]!=config["owner_key"]:
                    raise ValueError("wallet_root_invalid")
                issued=datetime.fromisoformat(bundle["issued_at"].replace("Z","+00:00")).timestamp()
                if not 0<=at-issued<config["policy"]["freshness_seconds"]:
                    raise ValueError("wallet_age_invalid")
                if previous and timeline.head_sequence<previous["seq"]:
                    raise ValueError("history_rollback")
                if previous and timeline.head_sequence==previous["seq"]:
                    if timeline.head_hash!=previous["head"] or decision["reason"]!="duplicate_does_not_refresh":
                        raise ValueError("duplicate_frontier_invalid")
                else:
                    if previous and record_hash(bundle["events"][previous["seq"]-1])!=previous["head"]:
                        raise ValueError("history_ancestor_mismatch")
                    if decision["reason"]!="native_wallet_bundle_admitted":
                        raise ValueError("admission_reason_invalid")
                    previous={"seq":timeline.head_sequence,"head":timeline.head_hash,
                              "bundle":canonical(request),"admitted_at":at}
                    accepted.append(previous)
                if decision["effect_at"] is not None:raise ValueError("admission_has_effect")
                result["authority"]+=1
            elif verdict=="ALLOW":
                if row["route"]!="/submit" or set(request)!={"proof"} or not previous:
                    raise ValueError("allow_route_invalid")
                bundle=json.loads(previous["bundle"])
                _,timeline=verify_bundle(bundle,now=datetime.fromtimestamp(at,timezone.utc))
                if timeline.head_hash!=previous["head"] or at-previous["admitted_at"]>=config["policy"]["freshness_seconds"]:
                    raise ValueError("allow_stale_history")
                proof=request["proof"]
                subject=proof["signature"]["public_key"]
                claims=decode_call("openline",proof,subject,config,at)
                if claims["head_hash"]!=timeline.head_hash or claims["policy_hash"]!=digest(config["policy"]):
                    raise ValueError("allow_broken_binding")
                active=[m for m in timeline.current(datetime.fromtimestamp(at,timezone.utc))
                        if m["subject_public_key"]==subject and m["mandate_id"]==claims["effect"]["mandate_id"]]
                if len(active)!=1 or "intake.submit" not in active[0]["scopes"]:
                    raise ValueError("allow_outside_wallet_mandate")
                effect,document=claims["effect"],claims["document"]
                if (effect["principal_id"]!=config["owner_id"] or effect["agent_id"]!=subject
                        or effect["purpose"]!="submit local document" or effect["action_type"]!="send"
                        or effect["target"]!=config["policy"]["target"] or effect["value_cents"]!=0
                        or effect["disclosures"] or effect["delegatee"] is not None
                        or effect["effect_id"]!=document["record_id"]
                        or len(document["text"])>config["policy"]["max_document_chars"]):
                    raise ValueError("allow_effect_invalid")
                if claims["jti"] in consumed or document["record_id"] in documents:
                    raise ValueError("allow_replay")
                if not isinstance(decision["effect_at"],int) or not at<=decision["effect_at"]<claims["exp"]:
                    raise ValueError("allow_effect_time_invalid")
                consumed[claims["jti"]]={"nonce":claims["jti"],"proof_hash":digest(request)}
                documents[document["record_id"]]={"id":document["record_id"],
                                                   "body":canonical(document),"proof_hash":digest(request)}
                result["allows"]+=1
            elif verdict=="DENY":
                if decision["effect_at"] is not None:raise ValueError("deny_has_effect")
                result["denies"]+=1
            else:raise ValueError("unsupported_decision")
            if (decision["owner_head"]!=(previous["head"] if previous else None)
                    or decision["owner_sequence"]!=(previous["seq"] if previous else 0)
                    or decision["documents_after"]!=len(documents)):
                raise ValueError("frontier_or_effect_count_mismatch")
        if rows["history"] != accepted:
            raise ValueError("history_differs_from_signed_replay")
        if sorted(rows["documents"],key=lambda x:x["id"])!=sorted(documents.values(),key=lambda x:x["id"]):
            raise ValueError("document_effects_diff")
        if sorted(rows["consumed"],key=lambda x:x["nonce"])!=sorted(consumed.values(),key=lambda x:x["nonce"]):
            raise ValueError("consumed_replay_diff")
        result["documents"]=len(documents)
        result["valid"]=True
    except (OSError,ValueError,KeyError,IndexError,TypeError,AttributeError,sqlite3.Error) as exc:
        result["errors"].append(str(exc) or type(exc).__name__)
    return result
