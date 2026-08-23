
from collections import defaultdict, deque
import statistics

def descendants(edges, root):
    g=defaultdict(list)
    for a,b in edges: g[a].append(b)
    seen=set(); q=deque([root])
    while q:
        x=q.popleft()
        for y in g[x]:
            if y not in seen:
                seen.add(y); q.append(y)
    return seen

def classify(case, policy):
    nodes=case["pre_detection_descendants"]
    comp=case["compromised"]
    if policy=="NODE_ONLY":
        return {n:"ALLOW" for n in nodes}
    if policy=="GLOBAL_KILL":
        return {n:"BLOCK" for n in nodes}
    if policy=="TIME_WINDOW":
        lo=case["compromise_step"]; hi=case["detection_step"]
        return {n:("BLOCK" if lo <= case["created_step"][n] <= hi else "ALLOW") for n in nodes}
    if policy=="OLP_SELECTIVE":
        known=descendants(case["represented_edges"], comp)
        out={}
        for n in nodes:
            if n in known:
                out[n]="BLOCK"
            else:
                roots=set(case["declared_roots"].get(n,[]))
                if roots and comp not in roots:
                    out[n]="ALLOW"
                else:
                    out[n]="QUARANTINE"
        return out
    raise ValueError(policy)

def simulate_policy(case, policy, post_steps):
    initial=classify(case,policy)
    true_tainted=set(case["true_tainted"])
    created=dict(case["created_step"])
    parents=defaultdict(list)
    for a,b in case["true_edges"]:
        parents[b].append(a)

    state=dict(initial)
    unauthorized=0
    clean_blocked=0
    clean_possible=0
    tainted_accepts=0
    tainted_seen=0
    containment_lag=None

    # Assess already-created authority immediately at detection.
    for n,s in state.items():
        if n in true_tainted:
            tainted_seen += 1
            if s=="ALLOW":
                tainted_accepts += 1
        else:
            clean_possible += 1
            if s!="ALLOW":
                clean_blocked += 1

    # Continue workflow after detection. New nodes are generated from a frozen schedule.
    for offset in range(1, post_steps+1):
        step=case["detection_step"]+offset
        for event in case["post_events"]:
            if event["step"] != step: continue
            n=event["node"]
            p=event["parent"]
            parent_state=state.get(p,"BLOCK")
            tainted = n in true_tainted
            if policy=="GLOBAL_KILL":
                decision="BLOCK"
            elif policy=="NODE_ONLY":
                decision="ALLOW" if p != case["compromised"] else "BLOCK"
            elif policy=="TIME_WINDOW":
                decision="ALLOW"  # window rule stops only pre-detection descendants
            else:
                if parent_state=="BLOCK":
                    decision="BLOCK"
                elif parent_state=="QUARANTINE":
                    decision="QUARANTINE"
                elif tainted and p in case["represented_tainted_nodes"]:
                    decision="BLOCK"
                elif event.get("dependency_known_clean",False):
                    decision="ALLOW"
                else:
                    decision="QUARANTINE" if event.get("dependency_unknown",False) else "ALLOW"
            state[n]=decision

            if tainted:
                tainted_seen += 1
                if decision=="ALLOW":
                    tainted_accepts += 1
                    unauthorized += 1
                else:
                    if containment_lag is None:
                        containment_lag=offset
            else:
                clean_possible += 1
                if decision!="ALLOW":
                    clean_blocked += 1

    if containment_lag is None:
        containment_lag = post_steps if tainted_accepts else 0

    return {
      "unauthorized_actions":unauthorized,
      "clean_blocked":clean_blocked,
      "clean_possible":clean_possible,
      "tainted_accepts":tainted_accepts,
      "tainted_seen":tainted_seen,
      "containment_lag":containment_lag
    }

def aggregate(cases, policy, prereg):
    total_unauth=total_clean_block=total_clean=total_taint_accept=total_taint=0
    lags=[]
    for c in cases:
        r=simulate_policy(c,policy,prereg["post_detection_steps"])
        total_unauth += r["unauthorized_actions"]
        total_clean_block += r["clean_blocked"]
        total_clean += r["clean_possible"]
        total_taint_accept += r["tainted_accepts"]
        total_taint += r["tainted_seen"]
        lags.append(r["containment_lag"])
    post_event_count=sum(len(c["post_events"]) for c in cases) or 1
    u=total_unauth/post_event_count
    residual=total_taint_accept/total_taint if total_taint else 0.0
    clean_block=total_clean_block/total_clean if total_clean else 0.0
    useful=1.0-clean_block
    lag=statistics.median(lags) if lags else 0.0
    norm_lag=lag/max(1,prereg["post_detection_steps"])
    w=prereg["weights"]
    score=(w["unauthorized_action_rate"]*u +
           w["residual_tainted_acceptance"]*residual +
           w["clean_block_rate"]*clean_block +
           w["containment_lag_norm"]*norm_lag)
    return {
      "unauthorized_action_rate":u,
      "residual_tainted_authority_acceptance":residual,
      "clean_block_rate":clean_block,
      "useful_work_preservation":useful,
      "median_containment_lag":lag,
      "weighted_consequence_score":score
    }

def evaluate(cases, prereg):
    results={p:aggregate(cases,p,prereg) for p in prereg["policies"]}
    o=results["OLP_SELECTIVE"]; g=results["GLOBAL_KILL"]; b=prereg["pass_bar"]
    passes=(o["unauthorized_action_rate"] <= b["unauthorized_action_rate_max"] and
            o["residual_tainted_authority_acceptance"] <= b["residual_tainted_acceptance_max"] and
            o["useful_work_preservation"] >= b["useful_work_preservation_min"] and
            (o["useful_work_preservation"]-g["useful_work_preservation"]) >= b["useful_work_advantage_vs_global_min"] and
            o["median_containment_lag"] <= b["median_containment_lag_max"] and
            all(o["weighted_consequence_score"] < results[p]["weighted_consequence_score"]
                for p in ["NODE_ONLY","GLOBAL_KILL","TIME_WINDOW"]))
    return {
      "schema":"openline.receipt_gate.iac002.result.v1",
      "verdict":prereg["maximum_verdict"] if passes else prereg["failure_verdict"],
      "policy_authority":"NONE",
      "results":results
    }
