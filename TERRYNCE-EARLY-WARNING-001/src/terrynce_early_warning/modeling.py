from __future__ import annotations

import math
import statistics
from typing import Iterable


def sigmoid(z: float) -> float:
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


def _solve_linear(a: list[list[float]], b: list[float]) -> list[float]:
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(m[r][col]))
        if abs(m[pivot][col]) < 1e-12:
            m[pivot][col] += 1e-8
        m[col], m[pivot] = m[pivot], m[col]
        d = m[col][col]
        if abs(d) < 1e-15:
            raise ValueError("singular linear system")
        for j in range(col, n + 1):
            m[col][j] /= d
        for r in range(n):
            if r == col:
                continue
            f = m[r][col]
            if f == 0:
                continue
            for j in range(col, n + 1):
                m[r][j] -= f * m[col][j]
    return [m[i][n] for i in range(n)]


def _standardize_fit(rows: list[dict], features: list[str]) -> tuple[dict, list[list[float]]]:
    means, stds = {}, {}
    for f in features:
        vals = [float(r[f]) for r in rows]
        mu = statistics.fmean(vals)
        sd = statistics.pstdev(vals)
        if not math.isfinite(sd) or sd < 1e-12:
            sd = 1.0
        means[f], stds[f] = mu, sd
    x = [[(float(r[f]) - means[f]) / stds[f] for f in features] for r in rows]
    return {"means": means, "stds": stds}, x


def _standardize_apply(rows: list[dict], features: list[str], scaler: dict) -> list[list[float]]:
    return [[(float(r[f]) - scaler["means"][f]) / scaler["stds"][f] for f in features] for r in rows]


def fit_logistic(rows: list[dict], features: list[str], target: str, l2: float = 0.1,
                 max_iter: int = 200, tol: float = 1e-9) -> dict:
    if not rows:
        raise ValueError("no rows")
    ys = [int(r[target]) for r in rows]
    if len(set(ys)) < 2:
        raise ValueError("target requires both classes")

    scaler, xs0 = _standardize_fit(rows, features)
    xs = [[1.0] + x for x in xs0]
    p = len(xs[0])
    beta = [0.0] * p
    prevalence = min(max(sum(ys) / len(ys), 1e-6), 1 - 1e-6)
    beta[0] = math.log(prevalence / (1 - prevalence))

    for _ in range(max_iter):
        probs = [sigmoid(sum(b * x for b, x in zip(beta, row))) for row in xs]
        grad = [0.0] * p
        h = [[0.0] * p for _ in range(p)]
        for x, y, pr in zip(xs, ys, probs):
            err = pr - y
            w = max(pr * (1 - pr), 1e-8)
            for j in range(p):
                grad[j] += err * x[j]
                for k in range(p):
                    h[j][k] += w * x[j] * x[k]
        for j in range(1, p):
            grad[j] += l2 * beta[j]
            h[j][j] += l2
        try:
            step = _solve_linear(h, grad)
        except ValueError:
            for j in range(p):
                h[j][j] += 1e-6
            step = _solve_linear(h, grad)
        nxt = [b - s for b, s in zip(beta, step)]
        if max(abs(a-b) for a, b in zip(nxt, beta)) < tol:
            beta = nxt
            break
        beta = nxt

    return {
        "features": list(features),
        "beta": beta,
        "scaler": scaler,
        "l2": float(l2),
        "family": "l2_logistic",
    }


def predict_logistic(model: dict, rows: list[dict]) -> list[float]:
    xs0 = _standardize_apply(rows, model["features"], model["scaler"])
    out = []
    for x0 in xs0:
        x = [1.0] + x0
        out.append(sigmoid(sum(b * v for b, v in zip(model["beta"], x))))
    return out


def brier(y: list[int], p: list[float]) -> float:
    return sum((a-b)**2 for a, b in zip(y, p)) / len(y)


def auroc(y: list[int], p: list[float]) -> float | None:
    pos = [x for x, yy in zip(p, y) if yy == 1]
    neg = [x for x, yy in zip(p, y) if yy == 0]
    if not pos or not neg:
        return None
    wins = 0.0
    for a in pos:
        for b in neg:
            wins += 1.0 if a > b else 0.5 if a == b else 0.0
    return wins / (len(pos) * len(neg))


def auprc(y: list[int], p: list[float]) -> float | None:
    total_pos = sum(y)
    if total_pos == 0:
        return None
    order = sorted(range(len(y)), key=lambda i: (-p[i], i))
    tp = 0
    fp = 0
    ap = 0.0
    for i in order:
        if y[i] == 1:
            tp += 1
            ap += tp / (tp + fp)
        else:
            fp += 1
    return ap / total_pos


def metrics(y: list[int], p: list[float]) -> dict:
    return {"brier": brier(y, p), "auroc": auroc(y, p), "auprc": auprc(y, p)}


def threshold_at_fpr(y: list[int], p: list[float], budget: float = 0.10) -> dict:
    neg = sum(1 for a in y if a == 0)
    pos = sum(1 for a in y if a == 1)
    if neg == 0 or pos == 0:
        raise ValueError("threshold selection requires both classes")
    thresholds = sorted(set(p), reverse=True)
    thresholds = [1.0 + 1e-12] + thresholds + [-1e-12]
    best = None
    for t in thresholds:
        pred = [int(x >= t) for x in p]
        fp = sum(1 for a, q in zip(y, pred) if a == 0 and q == 1)
        tp = sum(1 for a, q in zip(y, pred) if a == 1 and q == 1)
        fpr = fp / neg
        tpr = tp / pos
        if fpr <= budget + 1e-12:
            cand = (tpr, t, fpr)
            if best is None or cand[0] > best[0] or (cand[0] == best[0] and cand[1] > best[1]):
                best = cand
    if best is None:
        raise RuntimeError("no feasible threshold")
    return {"threshold": best[1], "validation_sensitivity": best[0], "validation_fpr": best[2], "budget": budget}


def chronological_cv_brier(rows: list[dict], feature: str, target: str, blocks: int = 5, l2: float = 0.1) -> float:
    n = len(rows)
    if n < blocks * 4:
        raise ValueError("too few rows for blocked CV")
    scores = []
    for k in range(blocks):
        lo = (n * k) // blocks
        hi = (n * (k + 1)) // blocks
        test = rows[lo:hi]
        train = rows[:lo] + rows[hi:]
        if len(set(int(r[target]) for r in train)) < 2 or not test:
            continue
        m = fit_logistic(train, [feature], target, l2=l2)
        pr = predict_logistic(m, test)
        scores.extend((int(r[target]) - q) ** 2 for r, q in zip(test, pr))
    if not scores:
        raise ValueError("no CV scores")
    return sum(scores) / len(scores)
