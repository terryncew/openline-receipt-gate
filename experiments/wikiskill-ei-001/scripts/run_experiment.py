#!/usr/bin/env python3
from __future__ import annotations
import copy, json, sys
from pathlib import Path

EXP = Path(__file__).resolve().parents[1]
if str(EXP) not in sys.path: sys.path.insert(0, str(EXP))
from wikiskill_ei001 import broad_recall, minimal_extension, openline_recall, published_wikiskill
from wikiskill_ei001.common import sha256_json

VERDICT_PARITY="WIKISKILL_EXTENSION_PARITY"
VERDICT_GAP="WIKISKILL_POST_HOC_PROVENANCE_GAP"
VERDICT_FAIL="WIKISKILL_EI_BOUNDARY_NOT_ESTABLISHED"

def load(name): return json.loads((EXP/name).read_text(encoding="utf-8"))
def exact(observed, expected): return observed.get("outcome") == expected

def graph_for(world, scenario):
    truth=scenario["sealed_worlds"][world]["derivation_truth"]
    return {"trace_to_patterns":truth,"pattern_to_skills":scenario["pattern_to_skill"]}

def main():
    scenario=load("fixtures/scenario.json"); oracle=load("oracle.json")
    state=scenario["public_state"]; event=scenario["standing_event"]; noop=scenario["no_op_event"]
    public_hash=sha256_json(state)
    rows=[]
    for world in ("world-A","world-B"):
        expected=oracle["event_case"][world]
        arms={
          "published_wikiskill":published_wikiskill.evaluate(copy.deepcopy(state),event),
          "broad_recall":broad_recall.evaluate(copy.deepcopy(state),event),
          "minimal_wikiskill_extension":minimal_extension.evaluate(copy.deepcopy(state),event),
          "openline_selective_standing":openline_recall.evaluate(copy.deepcopy(state),event,graph_for(world,scenario)),
        }
        for arm, observed in arms.items():
            rows.append({"world":world,"case":"trace-A-invalidated","arm":arm,"scored":arm!="published_wikiskill","expected":expected if arm!="published_wikiskill" else "OUT_OF_SCOPE_POST_HOC_EXPERIENCE_INVALIDATION","observed":observed,"exact_oracle_match": exact(observed,expected) if arm!="published_wikiskill" else None,"historical_unchanged": observed["historical_before"]==observed["historical_after"]==public_hash})
    no_expected=oracle["no_op_case"]
    published_noop=published_wikiskill.evaluate(copy.deepcopy(state),noop)
    rows.append({"world":"control","case":"no-op","arm":"published_wikiskill","scored":False,"expected":"OUT_OF_SCOPE_POST_HOC_EXPERIENCE_INVALIDATION","observed":published_noop,"exact_oracle_match":None,"historical_unchanged":published_noop["historical_before"]==published_noop["historical_after"]==public_hash})
    for arm, fn in (("broad_recall",lambda:broad_recall.evaluate(copy.deepcopy(state),noop)),("minimal_wikiskill_extension",lambda:minimal_extension.evaluate(copy.deepcopy(state),noop)),("openline_selective_standing",lambda:openline_recall.evaluate(copy.deepcopy(state),noop,graph_for("world-A",scenario)))):
        observed=fn(); rows.append({"world":"control","case":"no-op","arm":arm,"scored":True,"expected":no_expected,"observed":observed,"exact_oracle_match":exact(observed,no_expected),"historical_unchanged":observed["historical_before"]==observed["historical_after"]==public_hash})
    # Positive control: add the smallest missing lineage and reuse the exact minimal resolver.
    control_state=copy.deepcopy(state)
    for pattern, refs in scenario["provenance_control"]["explicit_source_trace_ids"].items():
        control_state["wiki"]["patterns"][pattern]["source_trace_ids"]=list(refs)
    pc=minimal_extension.evaluate(control_state,event)
    pc_expected=oracle["event_case"][scenario["provenance_control"]["world"]]
    provenance_control={"observed":pc,"expected":pc_expected,"exact_oracle_match":exact(pc,pc_expected)}

    minimal_event=[r for r in rows if r["case"]=="trace-A-invalidated" and r["arm"]=="minimal_wikiskill_extension"]
    openline_event=[r for r in rows if r["case"]=="trace-A-invalidated" and r["arm"]=="openline_selective_standing"]
    broad_event=[r for r in rows if r["case"]=="trace-A-invalidated" and r["arm"]=="broad_recall"]
    noop_rows=[r for r in rows if r["case"]=="no-op" and r["scored"]]
    parity=all(r["exact_oracle_match"] for r in minimal_event) and all(r["exact_oracle_match"] for r in noop_rows)
    gap=(all(r["observed"].get("disposition")=="UNRESOLVED_PROVENANCE" and not r["exact_oracle_match"] for r in minimal_event)
         and all(r["exact_oracle_match"] for r in openline_event)
         and all(not r["exact_oracle_match"] for r in broad_event)
         and all(r["exact_oracle_match"] for r in noop_rows)
         and provenance_control["exact_oracle_match"]
         and all(r["historical_unchanged"] for r in rows))
    verdict=VERDICT_PARITY if parity else (VERDICT_GAP if gap else VERDICT_FAIL)
    result={
      "schema":"openline.wikiskill_ei_001.result.v1","experiment_id":"WikiSkill-EI-001","base_commit":"65527e97b68894f32235f8f8c7d9de35f65a77b8",
      "evidence_tier":"PAPER_SPEC_RECONSTRUCTION","verdict":verdict,"passed":verdict!=VERDICT_FAIL,"policy_authority":"NONE",
      "public_state_sha256":public_hash,"standing_event_sha256":sha256_json(event),"indistinguishability":{"world_count":2,"published_state_identical":True,"standing_event_identical":True,"oracle_answers_differ":oracle["event_case"]["world-A"]!=oracle["event_case"]["world-B"]},
      "rows":rows,"provenance_control":provenance_control,
      "claim_limit":"Published required WikiSkill artifacts do not guarantee deterministic trace-to-pattern lineage for selective post-hoc invalidation; explicit source refs are sufficient in this fixture.",
    }
    (EXP/"result.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["passed"] else 1
if __name__=="__main__": raise SystemExit(main())
