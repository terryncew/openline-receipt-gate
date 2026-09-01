from __future__ import annotations
from dataclasses import dataclass
import hashlib, hmac, json
STATE_RANK={"filed":1,"accepted":2,"applied":3}
def canonical(obj): return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sign_event(event,key):
    body=dict(event); body.pop("signature",None)
    body["signature"]=hmac.new(key,canonical(body),hashlib.sha256).hexdigest(); return body
def verify_event(event,key):
    sig=event.get("signature",""); body=dict(event); body.pop("signature",None)
    return hmac.compare_digest(sig,hmac.new(key,canonical(body),hashlib.sha256).hexdigest())
@dataclass(frozen=True)
class ReceiverPolicy:
    authorization_id:str="auth-001"
    action_digest:str="sha256:action-001"
    recognized_forum:str="forum.example/review"
class ContestabilityReceiver:
    def __init__(self,key,policy=None):
        self.key=key; self.policy=policy or ReceiverPolicy(); self.seen=set(); self.highest=0
        self.graph={"D1":{"auth-001"},"D1A":{"D1"},"D2":{"auth-independent"}}
    def closure(self):
        affected={self.policy.authorization_id}; changed=True
        while changed:
            changed=False
            for d,deps in self.graph.items():
                if d not in affected and deps & affected: affected.add(d); changed=True
        affected.discard(self.policy.authorization_id); return affected
    def ingest(self,event):
        out={"event_id":event.get("event_id"),"foreign_state":event.get("state"),"evidence_status":"REJECT","standing":"UNCHANGED","consequences":{"D1":"PRESERVE","D1A":"PRESERVE","D2":"PRESERVE"},"reason":None}
        if not verify_event(event,self.key): out["reason"]="INVALID_SIGNATURE"; return out
        if event.get("authorization_id")!=self.policy.authorization_id: out["reason"]="AUTHORIZATION_MISMATCH"; return out
        if event.get("action_digest")!=self.policy.action_digest: out["reason"]="ACTION_MISMATCH"; return out
        if event.get("forum")!=self.policy.recognized_forum: out["reason"]="UNRECOGNIZED_FORUM"; return out
        state=event.get("state")
        if state not in STATE_RANK: out["reason"]="UNKNOWN_STATE"; return out
        eid=event.get("event_id")
        if not eid or eid in self.seen: out["reason"]="REPLAY"; return out
        rank=STATE_RANK[state]
        if rank<self.highest: out["reason"]="ORDERING_REGRESSION"; return out
        self.seen.add(eid); self.highest=max(self.highest,rank); out["evidence_status"]="ADMIT"; out["reason"]="VALID_FOREIGN_EVIDENCE"
        dep=self.closure()
        if state=="accepted":
            out["standing"]="CONTESTED"
            for d in dep: out["consequences"][d]="QUARANTINE"
        elif state=="applied":
            out["standing"]="LOST"
            for d in dep: out["consequences"][d]="REOPEN"
        return out
