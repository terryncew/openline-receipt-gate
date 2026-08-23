import random
from .core import descendants


def generate(prereg):
    rnd = random.Random(prereg["seed"])
    cases = []
    for gi in range(prereg["graphs"]):
        n = prereg["nodes_per_graph"]
        nodes = [f"g{gi}n{i}" for i in range(n)]
        compromised, clean_root = nodes[0], nodes[1]
        edges = []
        roots = {compromised: [compromised], clean_root: [clean_root]}
        created = {node: i for i, node in enumerate(nodes)}
        for i in range(2, n):
            r = rnd.random()
            if r < 0.55:
                candidates = [x for x in nodes[:i] if compromised in roots.get(x, [])] or [compromised]
                parent = rnd.choice(candidates)
                edges.append((parent, nodes[i]))
                roots[nodes[i]] = list(set(roots.get(parent, [parent])))
            elif r < 0.90:
                candidates = [x for x in nodes[1:i] if compromised not in roots.get(x, [])] or [clean_root]
                parent = rnd.choice(candidates)
                edges.append((parent, nodes[i]))
                roots[nodes[i]] = list(set(roots.get(parent, [parent])))
            else:
                tainted = [x for x in nodes[:i] if compromised in roots.get(x, [])] or [compromised]
                clean = [x for x in nodes[1:i] if compromised not in roots.get(x, [])] or [clean_root]
                a, b = rnd.choice(tainted), rnd.choice(clean)
                edges.extend([(a, nodes[i]), (b, nodes[i])])
                roots[nodes[i]] = list(set(roots.get(a, [a]) + roots.get(b, [b])))
        truth = descendants(edges, compromised)
        represented = [e for e in edges if rnd.random() >= prereg["edge_drop_probability"]]
        declared = {node: roots[node] for node in nodes[1:] if rnd.random() < 0.75}
        cases.append({
            "graph_id": gi,
            "compromised": compromised,
            "descendant_nodes": nodes[1:],
            "true_edges": edges,
            "represented_edges": represented,
            "true_tainted": sorted(truth),
            "declared_roots": declared,
            "created_at": created,
            "compromise_time": 0,
            "detection_time": max(3, n // 3),
        })
    return cases
