"""Fit raxIT's char_ngram_logreg on indirect rows, pick the threshold at 80% catch rate on held-out attack families,
and measure the false-block rate on a benign tool-output corpus.

Model (verbatim settings from e2_prompt_attacks_shortcuts.py):
  TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=200000)
  LogisticRegression(C, solver="liblinear", class_weight="balanced", max_iter=2000), C by grouped inner CV (AUROC)

usage: python -I evaluate.py INDIRECT.jsonl BENIGN_DIR OUT_DIR
"""
import json
import os
import sys
import warnings
from collections import defaultdict

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold

warnings.simplefilter("ignore")
ROWS, BENIGN, OUT = sys.argv[1:4]
C_GRID = (0.01, 0.1, 1.0, 10.0, 100.0)
WIN, STRIDE = 2000, 1000


def vec():
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=200000)


def clf(c):
    return LogisticRegression(C=c, solver="liblinear", class_weight="balanced", max_iter=2000)


rows = [json.loads(l) for l in open(ROWS)]
tr = [r for r in rows if r["split"] == "train"]
te = [r for r in rows if r["split"] == "test"]
Xtr, ytr, gtr = [r["text"] for r in tr], np.array([r["label"] for r in tr]), [r["group"] for r in tr]

per = defaultdict(list)
for a, b in GroupKFold(5).split(Xtr, ytr, gtr):
    v = vec()
    xa = v.fit_transform([Xtr[i] for i in a])
    xb = v.transform([Xtr[i] for i in b])
    for c in C_GRID:
        per[c].append(roc_auc_score(ytr[b], clf(c).fit(xa, ytr[a]).decision_function(xb)))
best_c = max(sorted(per), key=lambda c: (np.mean(per[c]), -c))
v = vec()
m = clf(best_c).fit(v.fit_transform(Xtr), ytr)


def score(texts):
    return m.predict_proba(v.transform(texts))[:, 1]


yte = np.array([r["label"] for r in te])
ste = score([r["text"] for r in te])
att = np.sort(ste[yte == 1])


def thr_at_catch(rate):
    # smallest threshold that still blocks `rate` of held-out attacks (score >= thr blocks)
    return float(att[int(np.floor((1 - rate) * len(att)))])


def windows(t):
    if len(t) <= WIN:
        return [t]
    return [t[i:i + WIN] for i in range(0, len(t) - WIN // 2, STRIDE)]


benign = []
for cat in sorted(os.listdir(BENIGN)):
    for f in sorted(os.listdir(os.path.join(BENIGN, cat))):
        t = open(os.path.join(BENIGN, cat, f), encoding="utf-8", errors="replace").read()
        if t.strip():
            benign.append((cat, f, t))
first = score([t[:WIN] for _, _, t in benign])
allw = [windows(t) for _, _, t in benign]
flat = score([w for ws in allw for w in ws])
mx, k = [], 0
for ws in allw:
    mx.append(float(flat[k:k + len(ws)].max()))
    k += len(ws)
mx = np.array(mx)

res = {"C": best_c, "inner_cv_auroc": {str(c): round(float(np.mean(s)), 3) for c, s in per.items()},
       "n_train": len(tr), "n_test": len(te), "n_test_attacks": int(yte.sum()), "n_benign_docs": len(benign),
       "n_benign_windows": int(len(flat)),
       "test_auroc": round(float(roc_auc_score(yte, ste)), 3), "sweep": []}
for rate in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
    t = thr_at_catch(rate)
    row = {"catch": rate, "thr": round(t, 3),
           "test_fbr": round(float((ste[yte == 0] >= t).mean()), 3),
           "benign_fbr_first2k": round(float((first >= t).mean()), 3),
           "benign_fbr_maxwin": round(float((mx >= t).mean()), 3),
           "benign_fbr_window": round(float((flat >= t).mean()), 3),
           "by_cat_maxwin": {}}
    cats = sorted({c for c, _, _ in benign})
    for c in cats:
        idx = [i for i, b in enumerate(benign) if b[0] == c]
        row["by_cat_maxwin"][c] = f"{int((mx[idx] >= t).sum())}/{len(idx)}"
    res["sweep"].append(row)
for t in (0.5, 0.7, 0.9):
    res.setdefault("fixed", []).append({"thr": t, "catch": round(float((att >= t).mean()), 3),
                                        "test_fbr": round(float((ste[yte == 0] >= t).mean()), 3),
                                        "benign_fbr_maxwin": round(float((mx >= t).mean()), 3)})
for fbr in (0.01, 0.03, 0.05, 0.10):
    t = float(np.quantile(mx, 1 - fbr, method="higher")) + 1e-9   # block only above the benign (1-fbr) quantile
    res.setdefault("at_benign_fbr", []).append({"benign_fbr_max": fbr, "thr": round(t, 4),
                                                "benign_fbr": round(float((mx >= t).mean()), 3),
                                                "catch": round(float((att >= t).mean()), 3)})
top = sorted(range(len(benign)), key=lambda i: -mx[i])[:15]
res["top_benign"] = [{"cat": benign[i][0], "file": benign[i][1], "score": round(float(mx[i]), 3)} for i in top]
names = v.get_feature_names_out()
co = m.coef_[0]
res["top_attack_ngrams"] = [repr(names[i]) for i in np.argsort(-co)[:40]]
res["nnz_weights"] = int((np.abs(co) > 1e-6).sum())
json.dump(res, open(os.path.join(OUT, "results.json"), "w"), indent=1)
print(json.dumps({k: res[k] for k in res if k not in ("top_attack_ngrams",)}, indent=1))
print("top attack n-grams:", " ".join(res["top_attack_ngrams"]))
