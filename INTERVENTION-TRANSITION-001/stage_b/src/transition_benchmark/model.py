from __future__ import annotations
from collections import defaultdict
import numpy as np

MODELS=("state_only","state_plus_lag","state_plus_action","direct_action_lag")


def build_outcome_index(rows, train_contexts):
    by_context=defaultdict(list)
    exact={}
    by_lag=defaultdict(lambda: defaultdict(list))
    by_action=defaultdict(lambda: defaultdict(list))
    global_action_lag=defaultdict(list)
    for r in rows:
        cid=r["context_id"]
        if cid not in train_contexts: continue
        y=r["y_fail"]
        if y is None: raise RuntimeError("Training label missing")
        a=r["action_id"]; lag=r["lag"]
        by_context[cid].append(y)
        exact[(cid,a,lag)]=y
        by_lag[cid][lag].append(y)
        by_action[cid][a].append(y)
        global_action_lag[(a,lag)].append(y)
    return {
        "context_mean":{c:float(np.mean(v)) for c,v in by_context.items()},
        "exact":exact,
        "lag_mean":{c:{k:float(np.mean(v)) for k,v in d.items()} for c,d in by_lag.items()},
        "action_mean":{c:{k:float(np.mean(v)) for k,v in d.items()} for c,d in by_action.items()},
        "global_action_lag":{k:float(np.mean(v)) for k,v in global_action_lag.items()},
    }


def fit_state_embedding(context_ids, X, train_ids, max_components=12):
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    pos={c:i for i,c in enumerate(context_ids)}
    train_idx=[pos[c] for c in train_ids]
    scaler=StandardScaler().fit(X[train_idx])
    Xs=scaler.transform(X)
    n=min(int(max_components),len(train_idx)-1,X.shape[1])
    pca=PCA(n_components=n,svd_solver="full").fit(Xs[train_idx])
    Z=pca.transform(Xs)
    return Z, scaler, pca


def _neighbor_weights(query_z, train_z, train_ids, k):
    d=np.linalg.norm(train_z-query_z[None,:],axis=1)
    order=np.argsort(d,kind="stable")[:k]
    dd=d[order]
    w=1.0/(dd+1e-6)
    w=w/w.sum()
    return [(train_ids[int(i)],float(ww)) for i,ww in zip(order,w)]


def predict_one(model_name, query_z, action, lag, train_z, train_ids, index, k):
    if model_name=="action_lag_global":
        return float(index["global_action_lag"][(action,lag)])
    neigh=_neighbor_weights(query_z,train_z,train_ids,k)
    vals=[]; weights=[]
    for cid,w in neigh:
        if model_name=="state_only": val=index["context_mean"][cid]
        elif model_name=="state_plus_lag": val=index["lag_mean"][cid][lag]
        elif model_name=="state_plus_action": val=index["action_mean"][cid][action]
        elif model_name=="direct_action_lag": val=index["exact"][(cid,action,lag)]
        else: raise KeyError(model_name)
        vals.append(val); weights.append(w)
    return float(np.dot(vals,weights))
