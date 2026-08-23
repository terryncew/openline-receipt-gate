
import random
from iac002.core import descendants

def generate(prereg):
    rnd=random.Random(prereg["seed"])
    cases=[]
    for ti in range(prereg["trials"]):
        n=prereg["nodes_per_trial"]
        nodes=[f"t{ti}n{i}" for i in range(n)]
        comp=nodes[0]
        clean_root=nodes[1]
        true_edges=[]
        roots={comp:[comp], clean_root:[clean_root]}
        created={comp:0, clean_root:0}

        # create pre-detection DAG
        detection=rnd.randint(prereg["detection_lag_min"],prereg["detection_lag_max"])
        for i in range(2,n):
            created[nodes[i]]=rnd.randint(1,detection)
            if rnd.random()<0.55:
                ta=[x for x in nodes[:i] if comp in roots.get(x,[])] or [comp]
                p=rnd.choice(ta)
            else:
                cl=[x for x in nodes[1:i] if comp not in roots.get(x,[])] or [clean_root]
                p=rnd.choice(cl)
            true_edges.append((p,nodes[i]))
            roots[nodes[i]]=list(roots.get(p,[p]))

        truth=descendants(true_edges,comp)
        represented=[e for e in true_edges if rnd.random()>=prereg["edge_drop_probability"]]
        represented_tainted=descendants(represented,comp)

        # clean provenance is often explicit; tainted provenance is never used to falsely retain.
        declared={}
        for node in nodes[1:]:
            if node not in truth and rnd.random()<0.88:
                declared[node]=roots[node]

        # freeze a post-detection schedule. Half events extend tainted family, half clean.
        events=[]
        next_idx=n
        available=list(nodes)
        for offset in range(1,prereg["post_detection_steps"]+1):
            for _ in range(2):
                want_taint=rnd.random()<0.50
                if want_taint:
                    ta=[x for x in available if x in truth or x==comp]
                    parent=rnd.choice(ta) if ta else comp
                else:
                    cl=[x for x in available if x not in truth and x!=comp]
                    parent=rnd.choice(cl) if cl else clean_root
                node=f"t{ti}n{next_idx}"; next_idx+=1
                is_taint=(parent in truth or parent==comp)
                if is_taint: truth.add(node)
                available.append(node)
                # For OLP, post-detection receipts make tainted parent status explicit whenever parent is already known tainted.
                dependency_unknown = (rnd.random()<0.12)
                known_clean = (not is_taint and not dependency_unknown)
                events.append({"step":detection+offset,"node":node,"parent":parent,
                               "dependency_unknown":dependency_unknown,
                               "dependency_known_clean":known_clean})
        cases.append({
          "trial_id":ti,
          "compromised":comp,
          "compromise_step":0,
          "detection_step":detection,
          "pre_detection_descendants":nodes[1:],
          "true_edges":true_edges,
          "represented_edges":represented,
          "true_tainted":sorted(truth),
          "represented_tainted_nodes":sorted(represented_tainted),
          "declared_roots":declared,
          "created_step":created,
          "post_events":events
        })
    return cases
