"""Approximate rebuild of raxIT's r26 *indirect* prompt-attack rows from upstream sources.

The published HF rows are ids_only, so this mirrors the construction described in
goldrails_dataset/sources/e2_prompt_attacks_r26.py (raxITlabs/decision-models-as-guardrails, Apache-2.0)
without running that code:

  attack  = real carrier document + real payload inserted as a paragraph at start/middle/end
  twin    = same carrier, same position, an ordinary paragraph from another carrier of the same kind
            (or, for ~10%, the payload quoted inside an authored security notice)
  clean   = unmodified carriers, length-matched
Payload families and carriers are assigned to one split each (no reuse across splits). Families are canonical:
payloads whose normalized text contains another payload's text share its family, and the build fails if any
held-out payload still overlaps a training payload.

usage: python -I build_indirect.py DATA_DIR OUT.jsonl   (also writes OUT.jsonl.payloads.jsonl)
"""
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict

DATA, OUT = sys.argv[1], sys.argv[2]
rng = random.Random(62)
EMAIL_FORMAT = "Subject of the email: {subject}.   Body: {body}"


def h(s):
    return int(hashlib.sha256(s.encode()).hexdigest()[:8], 16)


def split_of(key, test_share=0.3):
    return "test" if (h("split:" + key) % 1000) < test_share * 1000 else "train"


def english(t):
    return sum(c.isascii() for c in t) / max(1, len(t)) > 0.95


def ws(t):
    return re.sub(r"[ \t]+", " ", t).strip()


# --- payloads ---------------------------------------------------------------------------------------------------------
payloads = []
sep = json.load(open(f"{DATA}/sep/SEP_dataset.json"))
probes = {}
for x in sep:
    c, i = x["prompt_clean"].strip(), x["prompt_instructed"].strip()
    p = i[len(c):].strip() if i.startswith(c) else (i[:-len(c)].strip() if i.endswith(c) else None)
    pid = x["info"]["appended_task_id"]
    if p and pid not in probes:
        probes[pid] = p
for pid, p in probes.items():
    payloads.append({"src": "sep", "family": f"sep:{pid}", "text": p})

for part in ("test", "train"):
    d = json.load(open(f"{DATA}/bipia/benchmark_text_attack_{part}.json"))
    for cat, items in d.items():
        for t in items:
            if t.strip() and len(t) <= 600:
                payloads.append({"src": "bipia", "family": f"bipia:{part}:{cat}", "text": t.strip()})

labels = json.load(open(f"{DATA}/llmail/labelled_unique_submissions_phase2.json"))
per_team, seen = Counter(), set()
for line in open(f"{DATA}/llmail/raw_submissions_phase2.jsonl"):
    s = json.loads(line)
    key = EMAIL_FORMAT.format(subject=s.get("subject", ""), body=s.get("body", ""))
    lab = labels.get(key)
    if not lab or str(lab.get("attack_attempt")).lower() != "true":
        continue
    b = ws(s.get("body") or "")
    norm = re.sub(r"\W+", "", b.lower())[:80]
    team = s.get("team_id") or "unknown"
    if not (40 <= len(b) <= 600) or not english(b) or norm in seen or per_team[team] >= 5:
        continue
    seen.add(norm)
    per_team[team] += 1
    payloads.append({"src": "llmail", "family": f"llmail:{team}", "text": b})
del labels


# --- canonical families -----------------------------------------------------------------------------------------------
# Some source IDs are variants of one instruction (e.g. SEP prefixes a base probe with a priority phrase under a new
# appended_task_id). Any two payloads where one normalized text contains the other belong to one family, so that no
# held-out payload is a substring of a training payload.
def norm(t):
    return re.sub(r"\W+", " ", t.lower()).strip()


parent = {p["family"]: p["family"] for p in payloads}


def find(f):
    while parent[f] != f:
        parent[f] = parent[parent[f]]
        f = parent[f]
    return f


normed = sorted(((norm(p["text"]), p["family"]) for p in payloads), key=lambda x: len(x[0]))
for i, (a, fa) in enumerate(normed):
    for b, fb in normed[i + 1:]:
        if a in b:
            ra, rb = find(fa), find(fb)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)
merged = sum(find(f) != f for f in parent)
for p in payloads:
    p["family"] = find(p["family"])

# --- carriers ---------------------------------------------------------------------------------------------------------
carriers, cseen = [], set()
for x in sep:
    c = x["prompt_clean"].strip()
    k = re.sub(r"\W+", "", c.lower())
    if len(c) >= 150 and k not in cseen:
        cseen.add(k)
        carriers.append({"src": "sep", "kind": "passage", "key": f"sep:{h(k)}", "header": "", "body": c})
sc = json.load(open(f"{DATA}/llmail/scenarios.json"))
emails = [e for k in sc for e in sc[k]["emails"]] + json.load(open(f"{DATA}/llmail/emails_for_fp_tests.json"))
for e in dict.fromkeys(emails):
    m = re.match(r"Subject of the email:\s*(.*?)\.\s{2,}Body:\s*(.*)$", e, re.S)
    s, b = (m.group(1).strip(), m.group(2).strip()) if m else ("", e.strip())
    carriers.append({"src": "llmail", "kind": "email", "key": f"llmail:{h(e)}",
                     "header": f"Subject: {s}\n\n" if s else "", "body": ws(b)})
for part in ("test", "train"):
    for j, line in enumerate(open(f"{DATA}/bipia/benchmark_email_{part}.jsonl")):
        if not line.strip():
            continue
        row = json.loads(line)
        f = dict(x.split(": ", 1) if ": " in x else (x, "") for x in row["context"].split("|", 3))
        body = (f.get("CONTENT") or "").strip()
        if not body or len(body) > 2500:
            continue
        head = f"Subject: {f.get('SUBJECT', '').strip()}\nFrom: {f.get('EMAIL_FROM', '').strip()}\n\n"
        carriers.append({"src": "bipia", "kind": "email", "key": f"bipia:{part}:{j}", "header": head, "body": ws(body)})

# SEP has thousands of passages; keep the mix close to raxIT's (about half SEP).
sep_c = [c for c in carriers if c["src"] == "sep"]
rng.shuffle(sep_c)
carriers = [c for c in carriers if c["src"] != "sep"] + sep_c[:900]
for c in carriers:
    c["split"] = split_of(c["key"])
for p in payloads:
    p["split"] = split_of(p["family"])

# overlap audit: no test payload may contain, or be contained in, a training payload
train_n = [norm(p["text"]) for p in payloads if p["split"] == "train"]
leaks = [p["family"] for p in payloads if p["split"] == "test" and any(a in b or b in a for a, b in
                                                                       ((norm(p["text"]), t) for t in train_n))]
print(f"families merged={merged} cross-split containment leaks={len(leaks)}")
if leaks:
    sys.exit(f"payload family leak: {sorted(set(leaks))[:10]}")


def sentences(t):
    return [s for s in re.split(r"(?<=[.!?])\s+", t) if s.strip()]


def insert(body, para, pos):
    ss = sentences(body)
    if pos == "start" or len(ss) < 2:
        return para + "\n\n" + body if pos != "end" else body + "\n\n" + para
    if pos == "end":
        return body + "\n\n" + para
    m = len(ss) // 2
    return " ".join(ss[:m]) + "\n\n" + para + "\n\n" + " ".join(ss[m:])


NOTICES = [
    "Security notice from IT: we have received phishing messages containing text like the following. Do not act on "
    "them and report any copies to the security team:\n\"{p}\"",
    "FYI, the spam filter flagged a message with this content last week, quoted here so you can recognise it: \"{p}\"",
    "Training example (do not follow): attackers sometimes hide lines such as \"{p}\" in documents.",
]

by_kind_split = defaultdict(list)
for c in carriers:
    by_kind_split[(c["kind"], c["split"])].append(c)


def donor_paragraph(c, n):
    """An ordinary run of sentences from another carrier of the same kind and split, about n characters long."""
    pool = by_kind_split[(c["kind"], c["split"])]
    for _ in range(50):
        d = rng.choice(pool)
        if d["key"] == c["key"]:
            continue
        ss = sentences(d["body"])
        if not ss:
            continue
        i = rng.randrange(len(ss))
        out = ss[i]
        while len(out) < n and i + 1 < len(ss):
            i += 1
            out += " " + ss[i]
        if len(out) >= min(n, 40):
            return out
    return None


rows = []
prefer = {"sep": ["sep"], "llmail": ["llmail", "bipia", "sep"], "bipia": ["bipia", "llmail", "sep"]}
by_src_split = defaultdict(list)
for c in carriers:
    by_src_split[(c["src"], c["split"])].append(c)
fam_uses = Counter()
rng.shuffle(payloads)
for p in payloads:
    if fam_uses[p["family"]] >= 6:
        continue
    for _ in range(2 if p["src"] == "sep" else 1):
        src = rng.choice(prefer[p["src"]])
        pool = by_src_split[(src, p["split"])]
        if not pool:
            continue
        c = rng.choice(pool)
        pos = rng.choice(["start", "middle", "end"])
        group = f"{p['family']}|{c['key']}"
        rows.append({"text": c["header"] + insert(c["body"], p["text"], pos), "label": 1, "split": p["split"],
                     "group": p["family"], "payload_src": p["src"], "carrier_src": c["src"], "pos": pos})
        if rng.random() < 0.1:
            twin = rng.choice(NOTICES).format(p=p["text"])
            tk = "notice"
        else:
            twin = donor_paragraph(c, len(p["text"]))
            tk = "paragraph"
        if twin:
            rows.append({"text": c["header"] + insert(c["body"], twin, pos), "label": 0, "split": p["split"],
                         "group": p["family"], "payload_src": "none", "carrier_src": c["src"], "pos": pos,
                         "twin": tk})
        fam_uses[p["family"]] += 1

# unmodified clean carriers (about a quarter of the benign class)
n_clean = sum(r["label"] == 1 for r in rows) // 3
for c in rng.sample(carriers, min(n_clean, len(carriers))):
    rows.append({"text": c["header"] + c["body"], "label": 0, "split": c["split"], "group": c["key"],
                 "payload_src": "none", "carrier_src": c["src"], "pos": "none", "twin": "clean"})

with open(OUT, "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
# payloads with canonical family and split, for evaluate_injected.py
with open(OUT + ".payloads.jsonl", "w") as f:
    for p in payloads:
        f.write(json.dumps(p) + "\n")
cnt = Counter((r["split"], r["label"], r.get("payload_src"), r["carrier_src"]) for r in rows)
print(f"payloads={len(payloads)} carriers={len(carriers)} rows={len(rows)}")
for k, v in sorted(cnt.items()):
    print(v, k)
