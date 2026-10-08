"""inference - techniques a threat probably also uses, from MITRE CTID's Technique Inference Engine (TIE).

TIE (https://github.com/center-for-threat-informed-defense/technique-inference-engine) is a model trained on
published CTI reports: given the techniques seen in an intrusion, it ranks the techniques most likely to also be
present. yadda uses the trained model TIE publishes for its web app (src/tie-web-interface/public/app.trained.model.zip)
and the same prediction (WalsRecommender.predictNewEntity, ported below).

Inferred techniques are a hint for where to look next. They are labelled "inferred" and never counted in coverage,
priorities or the funnel.
"""
from __future__ import annotations

from delib.config import TOOLS

MODEL = TOOLS / "tie" / "app.trained.model.zip"
_model = None


def model():
    """(technique ids, V, c, regularization coefficient) from TIE's trained model; None when it isn't installed."""
    global _model
    if _model is None:
        if not MODEL.exists():
            return None
        import numpy as np
        z = np.load(MODEL)
        h = z["hyperparameters"][0]
        _model = ([str(t) for t in z["technique_ids"]], z["V"].astype(np.float64), float(h["c"]),
                  float(h["regularization_coefficient"]))
    return _model


def predict(observed: set) -> list[tuple[str, float]]:
    """[(technique, score)] for every technique TIE knows, best first, without the observed ones (as in TIE).
    Techniques TIE was not trained on are ignored, as TIE's web app rejects them."""
    import numpy as np
    m = model()
    if m is None or not observed:
        return []
    ids, V, c, rc = m
    index = {t: i for i, t in enumerate(ids)}
    P = np.zeros(len(ids))
    for t in observed:
        if t in index:
            P[index[t]] = 1.0
    if not P.any():
        return []
    # WalsRecommender.predictNewEntity / updateFactor with one entity (q = 1):
    alpha = (1 / c) - 1
    C = np.where(P > 0, alpha + 1, 1)
    k = V.shape[1]
    vtciv = np.zeros((k, k))
    for i in np.nonzero(C - 1)[0]:                       # V_T_C_I_V: sum of v_i v_i^T over the observed items
        vtciv += np.outer(V[i], V[i])
    inv = np.linalg.solve(V.T @ V + vtciv + rc * np.identity(k), np.identity(k))
    u = inv @ V.T @ P
    scores = V @ u
    res = [(t, float(scores[i])) for t, i in index.items() if t not in observed]
    return sorted(res, key=lambda x: -x[1])


def for_threats(threats: list, limit: int = 10) -> list[dict]:
    """Per threat: the top `limit` techniques TIE infers from the techniques ATT&CK lists for it.
    threats: [(label, id, techniques)] (priorities._threat_list)."""
    out = []
    for label, _, ts in threats:
        known = {t for t in ts if model() and t in set(model()[0])}
        for rank, (t, score) in enumerate(predict(set(ts))[:limit], 1):
            out.append({"threat": label, "rank": rank, "technique": t, "score": round(score, 4),
                        "from": len(known)})
    return out
