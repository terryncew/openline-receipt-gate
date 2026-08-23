from collections import defaultdict, deque


def descendants(edges, root):
    graph = defaultdict(list)
    for a, b in edges:
        graph[a].append(b)
    seen = set()
    q = deque([root])
    while q:
        x = q.popleft()
        for y in graph[x]:
            if y not in seen:
                seen.add(y)
                q.append(y)
    return seen


def classify_olp(case):
    known_tainted = descendants(case["represented_edges"], case["compromised"])
    out = {}
    for node in case["descendant_nodes"]:
        if node in known_tainted:
            out[node] = "REVOKE"
            continue
        roots = set(case["declared_roots"].get(node, []))
        if roots and case["compromised"] not in roots:
            out[node] = "RETAIN"
        else:
            out[node] = "UNKNOWN"
    return out


def classify(case, policy):
    nodes = case["descendant_nodes"]
    if policy == "NODE_ONLY":
        return {n: "RETAIN" for n in nodes}
    if policy == "GLOBAL_REACHABLE":
        reach = descendants(case["represented_edges"], case["compromised"])
        return {n: ("REVOKE" if n in reach else "QUARANTINE") for n in nodes}
    if policy == "TIME_WINDOW":
        c, d = case["compromise_time"], case["detection_time"]
        return {n: ("REVOKE" if c <= case["created_at"][n] <= d else "RETAIN") for n in nodes}
    if policy == "OLP_SELECTIVE":
        raw = classify_olp(case)
        return {n: ("QUARANTINE" if s == "UNKNOWN" else s) for n, s in raw.items()}
    raise ValueError(policy)


def metrics(cases, policy, weights):
    tp = missed = clean_quarantine = false_revoke = retained = retained_clean = tainted_total = clean_total = 0
    for case in cases:
        pred = classify(case, policy)
        truth = set(case["true_tainted"])
        for node, state in pred.items():
            tainted = node in truth
            tainted_total += int(tainted)
            clean_total += int(not tainted)
            stopped = state in {"REVOKE", "QUARANTINE"}
            if tainted and stopped:
                tp += 1
            if tainted and state == "RETAIN":
                missed += 1
            if not tainted and state == "QUARANTINE":
                clean_quarantine += 1
            if not tainted and state == "REVOKE":
                false_revoke += 1
            if state == "RETAIN":
                retained += 1
                retained_clean += int(not tainted)
    recall = tp / tainted_total if tainted_total else 1.0
    retain_precision = retained_clean / retained if retained else 1.0
    false_quarantine = clean_quarantine / clean_total if clean_total else 0.0
    missed_rate = missed / tainted_total if tainted_total else 0.0
    false_revoke_rate = false_revoke / clean_total if clean_total else 0.0
    harm = weights["missed_taint"] * missed_rate + weights["false_quarantine"] * false_quarantine + weights["false_revoke"] * false_revoke_rate
    return {
        "taint_recall": recall,
        "retain_precision": retain_precision,
        "false_quarantine_rate": false_quarantine,
        "missed_taint_rate": missed_rate,
        "false_revoke_rate": false_revoke_rate,
        "weighted_harm": harm,
    }


def evaluate(cases, prereg):
    results = {p: metrics(cases, p, prereg["weights"]) for p in prereg["policies"]}
    o = results["OLP_SELECTIVE"]
    g = results["GLOBAL_REACHABLE"]
    b = prereg["pass_bar"]
    passed = (
        o["taint_recall"] >= b["taint_recall_min"]
        and o["retain_precision"] >= b["retain_precision_min"]
        and o["missed_taint_rate"] <= b["missed_taint_rate_max"]
        and (g["false_quarantine_rate"] - o["false_quarantine_rate"]) >= b["false_quarantine_improvement_vs_global_min"]
        and all(o["weighted_harm"] < results[p]["weighted_harm"] for p in ["NODE_ONLY", "GLOBAL_REACHABLE", "TIME_WINDOW"])
    )
    return {
        "schema": "openline.receipt_gate.iac001.result.v1",
        "verdict": prereg["maximum_verdict"] if passed else prereg["failure_verdict"],
        "policy_authority": "NONE",
        "results": results,
    }
