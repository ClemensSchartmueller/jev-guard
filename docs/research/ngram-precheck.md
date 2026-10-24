# Research: local n-gram prompt-attack pre-check (#62)

**Question.** Could a local character n-gram logistic regression act as a stricter-only "suspicious tool output" signal? Go/no-go bar from #62: at 80% catch rate on held-out attacks, the false-block rate on real benign tool output must be at most about 3%.

**Answer: reject the tested recipe.** At 80% catch the false-block rate on 502 real benign tool outputs is **76.3%** with max-window scoring. It is 50.0% if only the first 2,000 characters are scored, and 39.8% if each output is scored as one whole text. When we give the model in-domain benign text, the false blocks disappear, but then it catches only **0.4–1.2%** of attacks hidden inside tool outputs. In these experiments the model separates the genre of the text, not attacks. No setting tested gets close to the bar.

Experiment run 2026-10-24 (run 4, after review), Python 3.14.4, scikit-learn 1.9.1, numpy 2.5.4. Scripts are in [`ngram-precheck/`](ngram-precheck/). No data, weights or third-party text are committed.

## Method

### Model

This is raxIT's `char_ngram_logreg` shortcut model, with settings copied from `dataset/goldrails_dataset/sources/e2_prompt_attacks_shortcuts.py` (raxITlabs/decision-models-as-guardrails, Apache-2.0):

```
TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=200000)
LogisticRegression(C, solver="liblinear", class_weight="balanced", max_iter=2000)
```

`C` is chosen from {0.01, 0.1, 1, 10, 100} by 5-fold `GroupKFold` AUROC, grouped by canonical payload family. `C = 100` won with inner-CV AUROC 0.925. The adapted runs below report C = 1, 10 and 100.

### Attack data: indirect prompt-attack rows (rebuilt; see Limitations)

The HF dataset `raxITLabs/decision-models-as-guardrails` has 1,282 `indirect` prompt-attack rows: dev 245, test 1,037. By source they are SEP 946, LLMail-Inject 237, BIPIA 56 and AgentDojo 43. **All 1,282 are `redistribution: ids_only`.** Across the whole prompt-attack suite, 3,845 of 3,892 rows have no text. Their `RECONSTRUCT.md` rebuilds the text by cloning the repo, running `uv sync` and running their rehydrate pipeline, which downloads every source. We did not do that: it means executing third-party code and dependencies, and it does not fit the time box.

Instead, `build_indirect.py` rebuilds rows the same way `e2_prompt_attacks_r26.py` builds them (we read that code but did not run it), from the same upstream sources. The inputs are pinned by sha256 in [`inputs.sha256`](ngram-precheck/inputs.sha256).

- **Attack:** a real carrier document (an SEP passage, an LLMail scenario email or a BIPIA email) with a real payload (an SEP probe, a BIPIA text attack, or an LLMail phase-2 submission labelled `attack_attempt`) inserted as a paragraph at the start, middle or end.
- **Twin (benign):** the same carrier and position with an ordinary paragraph from another carrier of the same kind. About 10% of twins instead quote the payload inside an authored "do not follow this" security notice.
- **Clean (benign):** unmodified carriers.
- **Split:** by canonical payload family and by carrier. 30% of families are held out as test. A family is canonical when every payload whose normalized text contains another payload's text is merged into that payload's family. This matters for SEP, where probes 50–99 are probes 0–49 with a fixed "priority question" prefix. The merge joined 59 source IDs (50 SEP, 9 BIPIA/LLMail). The build then checks that no held-out payload contains, or is contained in, a training payload, and fails if one does.

Result: 1,575 rows (train 1,118, test 457), of which 675 are attacks and 198 are test attacks (72 SEP, 76 LLMail, 50 BIPIA payloads). The negatives are 622 paragraph twins, 53 notice twins and 225 clean carriers. Held-out test AUROC is 0.950. On this in-distribution measure our rows are **easier** than raxIT's: their shortcut gate removes rows until this model scores BA ≤ 0.70 or AUROC ≤ 0.75. How the model would transfer to tool output after training on their published rows is unknown.

### Benign tool-output corpus (502 documents)

Collected with `collect_benign.sh` and `collect_benign_extra.sh`. Each item is the raw text an agent would see as a tool result. The 514 collected files are deduplicated by content (sha256 of the whitespace-normalized text), which leaves 502.

| Category | Docs | What it is |
|---|---:|---|
| `gh_json` | 145 | `gh api` JSON for 25 popular repos: repo, issues, closed PRs, releases, commits, raw README (one is a 404 error body) |
| `doc_usr_share` | 70 | `/usr/share/doc` READMEs, NEWS and Markdown (Debian packages) |
| `readme_npm` | 63 | READMEs of npm packages in the local npx cache, plus Go toolchain READMEs |
| `man` | 57 | `man -P cat` output for 57 everyday commands |
| `go_doc_mcp` | 43 | `go doc -all <pkg>` wrapped as an MCP `tools/call` result |
| `mcp_fs_read` | 40 | Go stdlib source files wrapped as MCP filesystem `read_file` results |
| `gh_docs_pages` | 37 | CONTRIBUTING, SECURITY, AGENTS and CLAUDE files from 20 public repos via `gh api` |
| `gh_readme_security` | 29 | READMEs and issues of LLM-security projects (garak, llm-guard, PyRIT, BIPIA, AgentDojo, …): hard negatives that discuss prompt injection |
| `repo_docs` | 18 | Markdown docs in local project checkouts, including agent instruction files |

Long outputs are scored in 2,000-character windows with a 1,000-character stride, 4,868 windows in total. A document counts as blocked if **any** window reaches the threshold ("max-window"). This is one reasonable protocol for a screen over long tool output. We also report scoring only the first 2,000 characters, scoring each whole document as one text, and the per-window rate. Every held-out test attack is shorter than 2,000 characters, so its score is the same under all of these protocols.

The threshold is the score that blocks 80% of held-out test attacks. It is chosen from the test attacks themselves, so the catch column is a descriptive operating point, not an independent estimate of future catch.

## Results

### A. raxIT model trained on indirect rows only (the experiment #62 asked for)

| Catch (held-out attacks) | Threshold | In-distribution benign FBR | **Tool-output FBR (max-window)** | Tool-output FBR (first 2,000 chars) | Tool-output FBR (whole doc) | Per-window FBR |
|---:|---:|---:|---:|---:|---:|---:|
| 50% | 0.939 | 2.3% | 24.3% | 7.2% | 4.0% | 5.8% |
| 60% | 0.877 | 3.5% | 38.6% | 15.1% | 9.8% | 12.9% |
| 70% | 0.740 | 5.0% | 58.2% | 29.7% | 25.9% | 28.2% |
| **80%** | **0.578** | 6.6% | **76.3%** | 50.0% | 39.8% | 49.0% |
| 90% | 0.311 | 12.0% | 90.6% | 76.5% | 67.5% | 75.0% |
| 95% | 0.182 | 20.5% | 94.0% | 83.7% | 80.1% | 83.4% |

At 80% catch, blocked documents by category (max-window): `gh_json` 139/145, `man` 49/57, `gh_readme_security` 25/29, `readme_npm` 49/63, `repo_docs` 14/18, `mcp_fs_read` 26/40, `go_doc_mcp` 25/43, `gh_docs_pages` 21/37, `doc_usr_share` 35/70.

Reading the table the other way: holding the tool-output false-block rate (max-window) at 3% leaves a catch rate of 39%, and at 1% it leaves 35%.

The strongest attack-side n-grams are `name`, `? `, `what`, `your`, `how`, `answer`, `response`, `state`, `end`. These mark question and request style ("what is your name", "answer", "state the …"), not attacks, and ordinary docs and issue threads are full of them.

### B. Sensitivity: give the model in-domain benign text

One objection to result A is that the model never saw tool-style text. `evaluate_adapted.py` adds half of the deduplicated benign corpus to the training negatives: 249 documents, split by content hash, 2,414 windows. It then measures on the other 253 documents. Held-out false blocks drop to **0.0%** at 80% catch (on the email/passage test split) for C = 1, 10 and 100, and stay at 0.0% at 90% catch.

That looks like a pass, but it is the shortcut raxIT's gate warns about. Every training attack is an email or passage, so "looks like a README, man page or JSON" becomes "benign".

### C. Attacks hidden inside tool output

`evaluate_injected.py` keeps setup B but inserts one held-out payload into each held-out benign document. There are 86 payloads (SEP probes and BIPIA attacks), all from test-split canonical families, read from the builder's payload file. Each goes in at a random line break, and the clean and injected documents form 253 pairs.

| C | AUROC (clean vs injected tool output) | Catch at the email-calibrated 80% threshold | Tool-output FBR at 80% catch on injected tool output |
|---:|---:|---:|---:|
| 1 | 0.617 | 0.4% | 68.4% |
| 10 | 0.671 | 0.4% | 63.2% |
| 100 | 0.703 | 1.2% | 57.7% |

With the threshold set for 80% catch on email-style attacks, the adapted model misses about 99% of the same kind of payloads placed inside a README, man page or `gh` JSON. With the threshold calibrated on tool output instead, more than half of clean tool outputs are blocked. An AUROC of 0.62–0.70 is weak separation. The model separates genres, not attacks.

## Recommendation: reject the tested recipe

- Against the #62 bar, the result is 76.3% false blocks at 80% catch (A, max-window), about 25× the 3% limit. Scoring whole documents instead still gives 39.8%, about 13× the limit.
- Training on in-domain benign text (B) removes the false blocks only by giving up detection of in-domain attacks (C). Either outcome makes this signal useless. In the first case most tool outputs become an ASK, and #62 already names that prompt fatigue as the main risk. In the second case the flag almost never fires on a real injection.
- These results are for our rebuilt rows. How a model trained on raxIT's published rows would do on tool output was not measured.
- Use (b) from #62, a flag on PreToolUse shell commands, has a larger domain gap still (commands and paths against prose) and was not tested.

We recommend closing #62 as "won't do" for the recipe it proposed: an n-gram model trained on email- and passage-style prompt attacks. This report does not rule out a screen trained on tool-output-shaped data on both sides, with injections inside READMEs, issue bodies, JSON and MCP results as positives and the same genres as negatives. B and C trained only the negatives in-domain, so that experiment is still open. Other model families are also possible future work if a local untrusted-text screen is needed (for example the offline fallback in #60).

## Review

A review of the first version (runs 1–3) found three problems. All are fixed in run 4, which replaces every number above.

- **Family leakage (R1).** SEP probes 50–99 are probes 0–49 with a priority prefix, but each had its own family ID. As a result, 13 held-out probe texts appeared inside training attacks, affecting 26 of 197 test attacks and also setup C's payloads. Families are now canonical (containment merge), the builder fails on any cross-split containment, and setup C reads the builder's family and split assignment instead of recomputing it. Effect at 80% catch: tool-output FBR 80.9% → 76.3%, first 2,000 chars 54.5% → 50.0%, test AUROC 0.951 → 0.950.
- **Benign duplicates (R2).** B and C split the benign corpus by random file name, so seven byte-identical documents sat on both sides. The corpus is now deduplicated by content (514 → 502 documents) and split by content hash. B and C conclusions are unchanged.
- **Overreaching claims (R3).** The first version said the upstream rows "would do worse" and that a future screen would "need a different model family". Neither was measured. The recommendation above now covers only the tested recipe.
- The reviewer reproduced run 1 exactly, and also scored whole documents (48.1% FBR in run 1). That column is now part of the table (39.8% in run 4).

## Limitations and what was not done

- **The upstream rows were not used.** The indirect rows are ids-only, and running raxIT's rehydrate pipeline was out of scope. The rebuild follows their method but has a different mix: 100 SEP payloads (50 canonical families) of 604, against 74% SEP upstream, and no AgentDojo rows (no AgentDojo data was downloaded).
- **The LLMail raw submissions** (`raw_submissions_phase2.jsonl` and `labelled_unique_submissions_phase2.json`) were re-downloaded for run 4 and match the hashes in `inputs.sha256`. Setup C still uses only SEP and BIPIA payloads, to stay comparable with the first version.
- **One seed, one split, no confidence intervals.** The margins (76% against 3%, and about 1% against 80%) are far larger than plausible split variance. Other seeds were not run.
- **Not tried:** smaller windows or sentence-level scoring, word n-grams, other classifiers, hashed features (the proposed Go form), and training on attacks embedded in tool output. B and C suggest that genre is the dominant signal for this feature set, but these variants were not measured.
- **Some benign items were picked by hand** (the security READMEs and AGENTS/CLAUDE files are deliberately hard negatives). Even without them, `man`, `gh_json` and `doc_usr_share` block 50–96% of their documents at 80% catch.
- **Near-duplicate benign documents** (for example the same README with different wrapping) are only merged when their whitespace-normalized text is identical.

## Licensing and attribution if weights were ever shipped

Not needed now that the result is a reject. Recorded for any future attempt:

- **Benchmark code and method:** raxITlabs/decision-models-as-guardrails, Apache-2.0. Copying their model settings is fine with attribution. Shipping anything derived from their files requires carrying their LICENSE and NOTICE.
- **Training sources used here** (per their `SOURCES.md` at `4232719`):
  - SEP (Zverev et al., ICLR 2025), MIT, text generated by the authors with GPT-4.
  - BIPIA (Yi et al., 2023), MIT, Copyright Microsoft. Its NOTICE lists the OpenAI Evals email data.
  - LLMail-Inject (Abdelnabi et al., 2025), MIT per the HF card and the GitHub repo.
  - raxIT mark the licence review for all three as "not finished". That is why their HF rows are ids-only.
- **Weights as a derivative work:** this is legally unsettled. At minimum, a release would need a third-party notices file with the MIT copyright lines of SEP, BIPIA and LLMail, plus the Apache-2.0 LICENSE and NOTICE if raxIT-derived artifacts are included. jev-guard is MIT, so these would be additional notices, not a relicence. Review this before shipping any embedded weights.
- **The benign corpus** (npm and Debian docs, man pages, GitHub content) has mixed licences. It was used only for local evaluation and is not committed. Setup B's fit is throwaway.

## How it would have plugged into #60 (for the record)

If a future screen passes the bar, it should be a one-way signal attached after the gate decision, never an input to it:

- **PostToolUse (use a, needs #60):** score the tool output with max-window scoring. Above the threshold, set the session taint that #60 introduces, exactly as a TypeSafe "untrusted" verdict would. The local score is only consulted when TypeSafe is unreachable or as an extra OR-term. It never clears a taint.
- **PreToolUse:** in `traceGateEvaluation` (`main.go:173`), apply the signal after `trace.Final` is set on both the fast-path branch (`main.go:188`) and the evaluator branch (`main.go:206`). Then compute `final = max(final, ASK)` if the flag is set. Because the fast path can return `fastpath_trusted` ALLOW, the signal must be applied after that early return, not inside the filter.
- **Invariants:** it can only raise ALLOW to ASK, or ASK to BLOCK if ever configured, never lower a decision. It never produces ALLOW. Its absence (missing model, error, timeout) is a no-op, not a failsafe ASK. The audit log records it with its own `Source`, for example `local_ngram`.

No Go code was written, because the tested recipe is a clear reject.

## Reproducing

```
python3 -I build_indirect.py DATA_DIR indirect.jsonl            # DATA_DIR/{sep,bipia,llmail}/… (see inputs.sha256); also writes indirect.jsonl.payloads.jsonl
bash collect_benign.sh BENIGN_DIR /path/to/jev-guard            # needs gh auth, go, man, npx cache
bash collect_benign_extra.sh BENIGN_DIR
python3 -I evaluate.py indirect.jsonl BENIGN_DIR OUT_A          # result A
python3 -I evaluate_adapted.py indirect.jsonl BENIGN_DIR OUT_B  # result B
python3 -I evaluate_injected.py indirect.jsonl BENIGN_DIR OUT_C  # result C
```

Keep each download in its own directory, run the scripts from outside the data directories, and treat everything downloaded as untrusted.
