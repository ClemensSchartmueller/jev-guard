"""Sensitivity check: same model, but half of the benign tool-output corpus (deduplicated and split by content hash)
is added to the training negatives as 2000-char windows. False-block rate is measured on the other half only.
This is the most favourable setup for the n-gram idea: the model has seen in-domain benign text.

usage: python -I evaluate_adapted.py INDIRECT.jsonl BENIGN_DIR OUT_DIR
"""
import hashlib
import json
import os
import sys
import warnings

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

warnings.simplefilter("ignore")
ROWS, BENIGN, OUT = sys.argv[1:4]
WIN, STRIDE = 2000, 1000


def windows(t):
    return [t] if len(t) <= WIN else [t[i:i + WIN] for i in range(0, len(t) - WIN // 2, STRIDE)]


rows = [json.loads(l) for l in open(ROWS)]
tr = [r for r in rows if r["split"] == "train"]
te = [r for r in rows if r["split"] == "test"]
benign, seen_b = [], set()   # deduplicated by content
for cat in sorted(os.listdir(BENIGN)):
    for f in sorted(os.listdir(os.path.join(BENIGN, cat))):
        t = open(os.path.join(BENIGN, cat, f), encoding="utf-8", errors="replace").read()
        ch = hashlib.sha256(" ".join(t.split()).encode()).hexdigest()   # split by content, not by file name
        if t.strip() and ch not in seen_b:
            seen_b.add(ch)
            benign.append((cat, f, t, int(ch, 16) % 2))
fit_b = [w for c, f, t, h in benign if h == 0 for w in windows(t)]
held = [(c, f, t) for c, f, t, h in benign if h == 1]

res = {"n_benign_fit_docs": sum(h == 0 for *_, h in benign), "n_benign_fit_windows": len(fit_b),
       "n_benign_heldout_docs": len(held), "runs": []}
X = [r["text"] for r in tr] + fit_b
y = np.array([r["label"] for r in tr] + [0] * len(fit_b))
for c in (1.0, 10.0, 100.0):
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=200000)
    m = LogisticRegression(C=c, solver="liblinear", class_weight="balanced", max_iter=2000).fit(v.fit_transform(X), y)
    sc = lambda ts: m.predict_proba(v.transform(ts))[:, 1]
    yte = np.array([r["label"] for r in te])
    ste = sc([r["text"] for r in te])
    att = np.sort(ste[yte == 1])
    allw = [windows(t) for _, _, t in held]
    flat = sc([w for ws in allw for w in ws])
    mx, k = [], 0
    for ws in allw:
        mx.append(float(flat[k:k + len(ws)].max()))
        k += len(ws)
    mx = np.array(mx)
    first = sc([t[:WIN] for _, _, t in held])
    run = {"C": c, "test_auroc": round(float(roc_auc_score(yte, ste)), 3), "sweep": []}
    for rate in (0.5, 0.7, 0.8, 0.9):
        t = float(att[int(np.floor((1 - rate) * len(att)))])
        cats = sorted({x[0] for x in held})
        run["sweep"].append({"catch": rate, "thr": round(t, 3), "test_fbr": round(float((ste[yte == 0] >= t).mean()), 3),
                             "heldout_fbr_first2k": round(float((first >= t).mean()), 3),
                             "heldout_fbr_maxwin": round(float((mx >= t).mean()), 3),
                             "by_cat_maxwin": {ct: f"{int(sum(mx[i] >= t for i, x in enumerate(held) if x[0] == ct))}/"
                                                   f"{sum(x[0] == ct for x in held)}" for ct in cats}})
    t3 = float(np.quantile(mx, 0.97, method="higher")) + 1e-9
    run["catch_at_3pct_heldout_fbr"] = round(float((att >= t3).mean()), 3)
    res["runs"].append(run)
json.dump(res, open(os.path.join(OUT, "results_adapted.json"), "w"), indent=1)
print(json.dumps(res, indent=1))
