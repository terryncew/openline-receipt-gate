from __future__ import annotations
import asyncio, hashlib, json, random, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import runtime_unaware
from atomic_receiver import AtomicReceiver

F=json.loads((ROOT/"FREEZE.json").read_text())

def make_trial(rnd, trial_id):
    n=F["tasks_per_trial"]
    ids=[f"trial{trial_id}_task{i}" for i in range(n)]
    tainted_n=int(n*F["tainted_fraction"])
    unknown_n=max(1,int(n*F["unknown_fraction"]))
    tainted=set(ids[:tainted_n])
    unknown=set(ids[tainted_n:tainted_n+unknown_n])
    clean=set(ids[tainted_n+unknown_n:])

    r=F["race"]
    tasks=[]
    for a in ids:
        before=rnd.uniform(r["pre_effect_delay_ms_min"],r["pre_effect_delay_ms_max"])/1000
        after=rnd.uniform(r["post_precheck_delay_ms_min"],r["post_precheck_delay_ms_max"])/1000
        tasks.append({"authority":a,"before":before,"after":after})
    detection=rnd.uniform(r["detection_delay_ms_min"],r["detection_delay_ms_max"])/1000
    return {"tainted":tainted,"unknown":unknown,"clean":clean,"tasks":tasks,"detection":detection}

async def run_trial(arm, spec):
    receiver=AtomicReceiver(
        clean=set(spec["clean"]), tainted=set(spec["tainted"]),
        unknown=set(spec["unknown"]), arm=arm
    )

    scheduled=[]
    # All downstream work is scheduled before correction.
    for t in spec["tasks"]:
        if arm=="STALE_PRECHECK":
            scheduled.append(asyncio.create_task(
                runtime_unaware.stale_dispatch(
                    t["before"],t["after"],receiver.precheck,receiver.stale_commit,t["authority"]
                )
            ))
        else:
            scheduled.append(asyncio.create_task(
                runtime_unaware.dispatch(t["before"],receiver.atomic_commit,t["authority"])
            ))

    async def detector():
        await asyncio.sleep(spec["detection"])
        await receiver.apply_correction()

    detection_task=asyncio.create_task(detector())
    await asyncio.gather(*scheduled,detection_task)
    return {
        "events":receiver.events,
        "correction_sequence":receiver.correction_sequence,
        "tainted":sorted(spec["tainted"]),
        "unknown":sorted(spec["unknown"]),
        "clean":sorted(spec["clean"])
    }

def summarize(results):
    totals={}
    for arm,trials in results.items():
        tainted_post=unknown_post=tainted_post_commits=unknown_post_commits=0
        clean_commits=clean_effects=0
        post_clean_blocked=0
        for tr in trials:
            cseq=tr["correction_sequence"]
            tainted=set(tr["tainted"]); unknown=set(tr["unknown"]); clean=set(tr["clean"])
            for e in tr["events"]:
                if e["kind"] in {"PRECHECK","APPLY_CORRECTION"}:
                    continue
                auth=e["authority"]
                post=e["sequence"]>cseq
                if auth in tainted and post:
                    tainted_post += 1
                    tainted_post_commits += int(e["kind"]=="COMMIT")
                if auth in unknown and post:
                    unknown_post += 1
                    unknown_post_commits += int(e["kind"]=="COMMIT")
                if auth in clean:
                    clean_effects += 1
                    clean_commits += int(e["kind"]=="COMMIT")
                    if post and e["kind"]!="COMMIT":
                        post_clean_blocked += 1
        totals[arm]={
            "post_detection_tainted_escape_rate":
                tainted_post_commits/tainted_post if tainted_post else 0.0,
            "post_detection_unknown_escape_rate":
                unknown_post_commits/unknown_post if unknown_post else 0.0,
            "clean_commit_rate":
                clean_commits/clean_effects if clean_effects else 1.0,
            "post_detection_clean_blocked":post_clean_blocked,
            "post_detection_tainted_opportunities":tainted_post,
            "post_detection_tainted_commits":tainted_post_commits
        }
    return totals

def grade(metrics):
    a=metrics["ATOMIC_RECEIVER_GATE"]
    stale=metrics["STALE_PRECHECK"]
    no=metrics["NO_PROPAGATION"]
    glob=metrics["GLOBAL_KILL"]
    b=F["pass_bar"]
    checks={
        "atomic_zero_tainted_escape":
            a["post_detection_tainted_escape_rate"]<=b["post_detection_tainted_escape_rate_max"],
        "atomic_zero_unknown_escape":
            a["post_detection_unknown_escape_rate"]<=b["post_detection_unknown_escape_rate_max"],
        "atomic_preserves_clean":
            a["clean_commit_rate"]>=b["clean_commit_rate_min"],
        "beats_stale_precheck":
            stale["post_detection_tainted_escape_rate"]>a["post_detection_tainted_escape_rate"],
        "no_propagation_demonstrates_escape":
            no["post_detection_tainted_commits"]>0,
        "global_kill_demonstrates_clean_loss":
            glob["post_detection_clean_blocked"]>0
    }
    passed=all(checks.values())
    return {
        "schema":"openline.receipt_gate.iac004.result.v2",
        "standing":F["maximum_standing"] if passed else F["failure_standing"],
        "policy_authority":"NONE",
        "checks":checks,
        "metrics":metrics,
        "claims":{
            "universal_runtime_portability":False,
            "preempts_effects_before_receiver_boundary":False,
            "undoes_pre_correction_commits":False,
            "revokes_external_credentials":False
        }
    }

async def main_async():
    rnd=random.Random(F["seed"])
    specs=[make_trial(rnd,i) for i in range(F["trials"])]
    results={}
    for arm in F["arms"]:
        results[arm]=[]
        for spec in specs:
            results[arm].append(await run_trial(arm,spec))
    metrics=summarize(results)
    result=grade(metrics)
    result["freeze_sha256"]=hashlib.sha256((ROOT/"FREEZE.json").read_bytes()).hexdigest()
    result["runtime_sha256"]=hashlib.sha256((ROOT/"runtime_unaware.py").read_bytes()).hexdigest()
    result["receiver_sha256"]=hashlib.sha256((ROOT/"atomic_receiver.py").read_bytes()).hexdigest()
    (ROOT/"result.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    # Full event corpus separately, so result stays readable.
    (ROOT/"race_events.json").write_text(json.dumps(results,sort_keys=True,separators=(",",":"))+"\n")
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=="__main__":
    asyncio.run(main_async())
