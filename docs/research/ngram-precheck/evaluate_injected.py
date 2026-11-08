"""Fairest check for the go/no-go: the domain-adapted model (evaluate_adapted.py setup), but the 80% catch threshold
is calibrated on attacks *inside tool outputs*: each held-out benign doc gets one held-out payload (SEP probe or BIPIA
attack whose canonical family is in the test split, read from build_indirect.py's payload file) inserted at a
random line break. False-block rate is measured on the same held-out docs without the payload (paired twins).

usage: python -I evaluate_injected.py INDIRECT.jsonl BENIGN_DIR OUT_DIR   (reads INDIRECT.jsonl.payloads.jsonl)
"""
import hashlib
import json
import os
import random
import sys
import warnings

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

warnings.simplefilter("ignore")
ROWS, BENIGN, OUT = sys.argv[1:4]
WIN, STRIDE = 2000, 1000
rng = random.Random(62)


def windows(t):
    return [t] if len(t) <= WIN else [t[i:i + WIN] for i in range(0, len(t) - WIN // 2, STRIDE)]


# held-out payloads: SEP and BIPIA payloads whose canonical family is in the test split, taken from the builder's
# payload file so setup C uses exactly the same family mapping and split as the rows
payloads = [json.loads(line) for line in open(ROWS + ".payloads.jsonl")]
pay = list(dict.fromkeys((p["src"], p["text"]) for p in payloads if p["split"] == "test" and p["src"] in ("sep", "bipia")))
train_pay = [" ".join(p["text"].lower().split()) for p in payloads if p["split"] == "train"]
assert not any(" ".join(t.lower().split()) in q for _, t in pay for q in train_pay), "held-out payload in training"

benign, seen_b = [], set()   # deduplicated by content, same split as evaluate_adapted.py
for cat in sorted(os.listdir(BENIGN)):
    for f in sorted(os.listdir(os.path.join(BENIGN, cat))):
        t = open(os.path.join(BENIGN, cat, f), encoding="utf-8", errors="replace").read()
        ch = hashlib.sha256(" ".join(t.split()).encode()).hexdigest()   # split by content, not by file name
        if t.strip() and ch not in seen_b:
            seen_b.add(ch)
            benign.append((cat, f, t, int(ch, 16) % 2))
fit_b = [w for c, f, t, s in benign if s == 0 for w in windows(t)]
held = [(c, t) for c, f, t, s in benign if s == 1]


def inject(t, p):
    cuts = [i for i in range(len(t)) if t.startswith("\n", i)] or [len(t)]
    k = rng.choice(cuts)
    return t[:k] + "\n\n" + p + "\n\n" + t[k:]


inj = [(c, inject(t, rng.choice(pay)[1])) for c, t in held]

rows = [json.loads(l) for l in open(ROWS)]
tr, te = [r for r in rows if r["split"] == "train"], [r for r in rows if r["split"] == "test"]
X = [r["text"] for r in tr] + fit_b
y = np.array([r["label"] for r in tr] + [0] * len(fit_b))
res = {"n_heldout_payloads": len(pay), "n_heldout_docs": len(held), "runs": []}
for c in (1.0, 10.0, 100.0):
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=200000)
    m = LogisticRegression(C=c, solver="liblinear", class_weight="balanced", max_iter=2000).fit(v.fit_transform(X), y)

    def maxwin(texts):
        allw = [windows(t) for t in texts]
        flat = m.predict_proba(v.transform([w for ws in allw for w in ws]))[:, 1]
        out, k = [], 0
        for ws in allw:
            out.append(float(flat[k:k + len(ws)].max()))
            k += len(ws)
        return np.array(out)

    sb, si = maxwin([t for _, t in held]), maxwin([t for _, t in inj])
    yte = np.array([r["label"] for r in te])
    ste = m.predict_proba(v.transform([r["text"] for r in te]))[:, 1]
    att_email = np.sort(ste[yte == 1])
    run = {"C": c, "auroc_tool_output": round(float(roc_auc_score([0] * len(sb) + [1] * len(si), np.r_[sb, si])), 3),
           "sweep": []}
    att = np.sort(si)
    for rate in (0.5, 0.6, 0.7, 0.8, 0.9):
        t = float(att[int(np.floor((1 - rate) * len(att)))])
        run["sweep"].append({"catch_tool_output": rate, "thr": round(t, 4),
                             "fbr_tool_output": round(float((sb >= t).mean()), 3),
                             "catch_email_test": round(float((att_email >= t).mean()), 3)})
    # threshold fixed by 80% catch on the email/passage test split (as in the main run)
    t = float(att_email[int(np.floor(0.2 * len(att_email)))])
    run["at_email_thr80"] = {"thr": round(t, 4), "catch_tool_output": round(float((si >= t).mean()), 3),
                             "fbr_tool_output": round(float((sb >= t).mean()), 3)}
    res["runs"].append(run)
json.dump(res, open(os.path.join(OUT, "results_injected.json"), "w"), indent=1)
print(json.dumps(res, indent=1))
