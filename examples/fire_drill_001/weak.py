"""Deliberately weak shared-token teaching fixture. NEVER a competitor baseline.

A valid old bearer can still write after advisory revocation. Actual SQLite
effects, not pretend terminal text. No signatures, no worker-specific grants.
"""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import sqlite3
import sys

from olp_gate.crypto import olp_canonical_json,strict_json_loads
TOKEN="PUBLIC_DISPOSABLE_SHARED_CREDENTIAL"
def canon(x):return olp_canonical_json(x).decode("ascii")

class WeakReceiver:
    mode="intentionally_weak"
    def __init__(self,db):
        self.db=Path(db)
        with sqlite3.connect(self.db) as c:
            c.execute("CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, body TEXT NOT NULL, actor TEXT NOT NULL, route TEXT NOT NULL)")
            c.execute("CREATE TABLE IF NOT EXISTS decisions(seq INTEGER PRIMARY KEY, route TEXT NOT NULL, request TEXT NOT NULL, body TEXT NOT NULL)")
    def dispatch(self,route,request):
        with sqlite3.connect(self.db) as c:
            before=c.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            decision={"mode":self.mode,"route":route,"verdict":"DENY","reason":"no_shared_credential",
                      "documents_before":before,"actor":request.get("actor") if isinstance(request,dict) else None}
            if isinstance(request,dict) and route=="/authority":
                # This is deliberately *advisory*. No revocation state is
                # enforced, unlike the two real secure receiver modes.
                decision.update(verdict="ACCEPT",reason="advisory_only_not_enforced")
            elif (isinstance(request,dict) and route in ("/submit","/raw-write")
                  and request.get("shared_credential")==TOKEN
                  and isinstance(request.get("document"),dict)
                  and set(request["document"])=={"record_id","text"}
                  and isinstance(request["document"]["record_id"],str)
                  and isinstance(request["document"]["text"],str)
                  and request["document"]["record_id"]
                  and len(request["document"]["text"])<=128):
                item=request["document"]
                try:
                    c.execute("INSERT INTO documents VALUES(?,?,?,?)",
                              (item["record_id"],canon(item),str(request.get("actor","unattributed")),route))
                    decision.update(verdict="ALLOW",reason="shared_bearer_accepted")
                except sqlite3.IntegrityError:
                    decision.update(reason="duplicate_document_id")
            elif isinstance(request,dict) and route in ("/submit","/raw-write"):
                decision.update(reason="invalid_shared_bearer_or_document")
            else:
                decision.update(reason="unsupported_route")
            decision["documents_after"]=c.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            seq=c.execute("SELECT COALESCE(MAX(seq),0)+1 FROM decisions").fetchone()[0]
            decision["seq"]=seq
            c.execute("INSERT INTO decisions VALUES(?,?,?,?)",(seq,route,canon(request),canon(decision)))
            c.commit()
            return decision

def serve(db):
    receiver=WeakReceiver(db)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            try:
                n=int(self.headers.get("Content-Length","0"))
                if not 0<n<=65536:raise ValueError("invalid_length")
                request=strict_json_loads(self.rfile.read(n).decode("utf-8"))
                result=receiver.dispatch(self.path,request)
                data=canon(result).encode()
                self.send_response(200)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (ValueError,TypeError,UnicodeError):
                self.send_error(400,"invalid_disposable_request")
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    print(json.dumps({"port":server.server_address[1],"mode":receiver.mode}),flush=True)
    try:server.serve_forever()
    finally:server.server_close()

if __name__=="__main__":
    if len(sys.argv)!=2:raise SystemExit("Usage: python -m examples.fire_drill_001.weak STATE")
    serve(sys.argv[1])
