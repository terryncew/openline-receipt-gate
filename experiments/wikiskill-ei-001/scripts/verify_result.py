#!/usr/bin/env python3
"""Independent verifier. Imports neither experiment runner nor candidate arms."""
from __future__ import annotations
import ast, hashlib, json
from pathlib import Path
EXP=Path(__file__).resolve().parents[1]

def load(p): return json.loads((EXP/p).read_text(encoding="utf-8"))
def canon(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
def h(v): return hashlib.sha256(canon(v)).hexdigest()
def filehash(p): return hashlib.sha256((EXP/p).read_bytes()).hexdigest()
def fail(msg): raise SystemExit("WIKISKILL_EI_001_VERIFY_FAIL: "+msg)

scenario=load("fixtures/scenario.json"); oracle=load("oracle.json"); result=load("result.json"); lock=load("DESIGN_LOCK.json")
for rel, expected in lock["files"].items():
    if filehash(rel)!=expected: fail("design lock mismatch: "+rel)
if result.get("passed") is not True: fail("result did not pass frozen rule")
state=scenario["public_state"]; event=scenario["standing_event"]
if result.get("public_state_sha256")!=h(state) or result.get("standing_event_sha256")!=h(event): fail("public input hash mismatch")
if oracle["event_case"]["world-A"]==oracle["event_case"]["world-B"]: fail("oracle does not discriminate worlds")
if result["indistinguishability"]!={"world_count":2,"published_state_identical":True,"standing_event_identical":True,"oracle_answers_differ":True}: fail("indistinguishability receipt mismatch")
rows=result.get("rows",[])
if len(rows)!=12: fail(f"expected 12 rows, got {len(rows)}")
for row in rows:
    obs=row["observed"]
    if obs.get("historical_before")!=obs.get("historical_after"): fail("historical mutation")
    if row.get("historical_unchanged") is not True: fail("historical unchanged flag false")
for world in ("world-A","world-B"):
    subset={r["arm"]:r for r in rows if r["world"]==world and r["case"]=="trace-A-invalidated"}
    if subset["published_wikiskill"]["observed"].get("disposition")!="OUT_OF_SCOPE_POST_HOC_EXPERIENCE_INVALIDATION": fail("published arm scope")
    if subset["published_wikiskill"].get("scored") is not False: fail("published arm scored")
    if subset["minimal_wikiskill_extension"]["observed"].get("disposition")!="UNRESOLVED_PROVENANCE": fail("minimal did not fail closed")
    if subset["minimal_wikiskill_extension"].get("exact_oracle_match") is not False: fail("minimal unexpectedly matches")
    if subset["openline_selective_standing"].get("exact_oracle_match") is not True: fail("openline mismatch")
    if subset["broad_recall"].get("exact_oracle_match") is not False: fail("broad recall unexpectedly selective")
noops=[r for r in rows if r["case"]=="no-op"]
if len(noops)!=4: fail("no-op row count")
for row in noops:
    if row["arm"]=="published_wikiskill":
        if row.get("scored") is not False or row["observed"].get("disposition")!="OUT_OF_SCOPE_POST_HOC_EXPERIENCE_INVALIDATION": fail("published no-op scope")
    elif row.get("exact_oracle_match") is not True:
        fail("no-op mismatch")
pc=result.get("provenance_control",{})
if pc.get("exact_oracle_match") is not True or pc.get("observed",{}).get("disposition")!="RESOLVED_FROM_EXPLICIT_SOURCE_REFS": fail("positive provenance control failed")
minimal_event=[r for r in rows if r["case"]=="trace-A-invalidated" and r["arm"]=="minimal_wikiskill_extension"]
openline_event=[r for r in rows if r["case"]=="trace-A-invalidated" and r["arm"]=="openline_selective_standing"]
broad_event=[r for r in rows if r["case"]=="trace-A-invalidated" and r["arm"]=="broad_recall"]
scored_noops=[r for r in noops if r["scored"]]
parity=all(r["exact_oracle_match"] for r in minimal_event) and all(r["exact_oracle_match"] for r in scored_noops)
gap=(all(r["observed"].get("disposition")=="UNRESOLVED_PROVENANCE" and not r["exact_oracle_match"] for r in minimal_event)
     and all(r["exact_oracle_match"] for r in openline_event)
     and all(not r["exact_oracle_match"] for r in broad_event)
     and all(r["exact_oracle_match"] for r in scored_noops)
     and pc["exact_oracle_match"] and all(r["historical_unchanged"] for r in rows))
expected_verdict="WIKISKILL_EXTENSION_PARITY" if parity else ("WIKISKILL_POST_HOC_PROVENANCE_GAP" if gap else "WIKISKILL_EI_BOUNDARY_NOT_ESTABLISHED")
if result.get("verdict")!=expected_verdict: fail("verdict does not follow frozen scoring rule")
# Source audit: minimal arm may use explicit serialized refs but may not access sealed truth / OpenLine support graph or inference machinery.
minimal=(EXP/"wikiskill_ei001/minimal_extension.py").read_text(encoding="utf-8")
for forbidden in ("sealed_worlds","derivation_truth","support_graph","trace_to_patterns","openline_recall","subprocess","requests","openai","anthropic"):
    if forbidden in minimal: fail("minimal forbidden dependency: "+forbidden)
ast.parse(minimal)
print("WIKISKILL_EI_001_RESULT_OK: 12 rows; indistinguishability, design lock, source boundary, no-op, and provenance control verified")
