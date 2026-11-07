# M11 design note

Written and committed before any M11 metric was computed. Nothing here has run. Choices marked **OPEN** are the user's. Definitions are §10.1, §10.2, §10.7, D17, D56, D61 and D62; this note changes none of them, and no target moves.

Inputs read while writing it: file schemas, the `answers` table of `llm.sqlite` (read-only, for its structure and for whether drafts can be recovered), window and line counts without labels, and raw-text matching on russellmitchell only. No santos, `wardbeck` or `harrison` metric was computed.

## 1. Inventory

| Module | State | Holds |
|---|---|---|
| `eval/metrics.py` | real | `window_truth`, `with_truth`, `window_metrics`, `detected_phases`, `phase_recall`, `phase_credit`, `incident_phases`, `candidate_recall`, gold mapping |
| `eval/detection.py` | real | `truth_context`, `evaluate`, `dev_candidate_recall` (dev only) |
| `eval/baselines.py` | partial | alert loading, rates, budget check. No host, no alert text, no grouping, no phase recall |
| `eval/extra_testbeds.py` | real | `targets_extra.md`, denominators, D28 exposure |
| `eval/ablations.py`, `eval/human_eval.py`, `eval/report.py` | one-line stubs | nothing |
| `agents/prompts/reporter_examples.md` | missing | `few_shot` fails loudly until it exists (D48) |
| `cli.evaluate` | stub | out of scope this session |

| §10.2 / §10.3 item | Exists | Lacks |
|---|---|---|
| Window P/R/F1, PR-AUC | `window_metrics` | a table across testbeds; a `pooled_without_dns` row |
| Phase recall | `phase_recall`, `phase_credit` | the all-parsed variant, pooled sums |
| Alert reduction | raw alert rates | anomalous windows per day, grouped alerts, reductions |
| Verdict | nothing | incident truth, confusion matrix, F1, D17 secondary, D62 pooling |
| ATT&CK top-1/top-3 | gold mapping, `incident_phases` | hit logic, strict and lenient |
| Faithfulness (primary) | nothing | sample, sheet, import: needs people |
| Faithfulness (auto) | Verifier answers in `llm.sqlite` | a reader. Needs no LLM call, but it is not in this session's list, so it is left for the next one |
| Hallucinated citations | `draft_*` fields in report meta | the table |
| Cost/latency | `agents_<testbed>.csv` | the table, the peak note |
| Human evaluation | nothing | sheet, import, κ |
| IDS baseline | rates only | phase recall |
| ML-only baseline | incidents | the table |
| LLM-only baseline | nothing | sampler, prompt, runner |
| Supervised reference | `supervised_*.csv`, final | nothing: read as saved |
| Ablations | switches in the graph, condition in the cache key | a runner that can write elsewhere, a guard, a cache-only mode |

## 2. Metrics of this session

Everything reads saved files only, through a new `eval/tables.py`, which calls no detect, scoring, supervised or fit code. A test checks that. All files are under `reports/results/`. `group` is `dev`, `test` or `pooled`; russellmitchell is only ever `dev`, and pooled means santos, `wardbeck` and `harrison`.

| Metric | Inputs | Scope | Primary | Secondary | Output |
|---|---|---|---|---|---|
| Window P/R/F1, PR-AUC | `scores.parquet`, labels through `eval.duckdb` | dev, each test testbed. **Never pooled** | label-ambiguous windows left out | included as normal (D17) | `eval_windows.csv` |
| Phase recall | same | dev, each test testbed, pooled sum/sum | baseline-capable denominator | all parsed; without `dnsteal_exfil` | `eval_phase_recall.csv`, `eval_phase_credit.csv` |
| Unclipped DNS secondary | `status.md`, quoted, never recomputed | dev, santos only (D61) | | as M5 recorded it | row in `eval_phase_recall.csv` with `source` |
| Incidents/day, alert reduction | incidents, scores, AIT-ADS | dev, each test testbed. **Never pooled** | incidents vs raw alerts | vs anomalous windows, vs grouped alerts | `eval_alert_reduction.csv` |
| IDS phase recall | AIT-ADS, labels, phases | dev, each test testbed, pooled | event-based label | time-based label | `eval_ids_recall.csv`, `eval_ids_phases.csv` |
| ML-only baseline | incidents, truth | same as verdict | verdict `malicious` for all | D17 | `eval_verdict.csv`, `method` column |
| Verdict | reports, truth | dev, each test testbed, pooled (D62) | ambiguous incidents left out | included as benign | `eval_verdict.csv` |
| ATT&CK top-1/top-3 | reports, truth, gold | dev, each test testbed, pooled | strict | lenient | `eval_attack.csv`, `eval_attack_incidents.csv` |
| Hallucinated citations | report meta | dev, each test testbed, pooled | claims of first drafts | | `eval_citations.csv` |
| Cost, latency, tokens | report meta | dev, each test testbed | as logged | same tokens at off-peak rates, because M8 reports are at peak | `eval_cost.csv` |

Rules fixed here, because the definitions leave them open:

- **Event-based IDS label.** AIT-ADS has no per-alert label: a recursive search of the alert files finds none, and `labels.csv` holds only time intervals. So the label is derived: an alert carries a phase if its log text (`full_log` of Wazuh, any line of `RawLogData` of AMiner) equals the raw text of a labeled line of that phase in the evaluation period. Suricata alerts (`eve.json`, `fast.log`) have no labeled source log, so they can never carry an event label. Text is compared without the host, so an alert on `inet-dns` can match the identical labeled line of `inet-firewall`. On dev the text of Wazuh and AMiner alerts equals the raw lines exactly.
- **Time-based IDS label.** An alert carries a phase if `start_utc <= ts <= end_utc` of its row in the phases file, without the ±60 s of §5.3.
- **Alert host.** `agent.name` is `wazuh-client` on every alert. The host is `agent.ip` for Wazuh and `AMiner.ID` for AMiner: one address space, one address per host.
- **Grouped alerts.** Two alerts link if `|Δt| <= ml.gap_minutes` (30, the tuned value) and they have the same host. Each component is one group. All raw alerts of the evaluation period, mirrored files included, as in `targets.md`.
- **Alert reduction.** `1 - incidents_per_day / other_per_day`.
- **Verdict F1.** Positive = true malicious. Predicted positive = `malicious` or `uncertain`.
- **Lenient match.** The IDs before the dot are equal, for predicted and gold alike.
- **Top-k.** The first k techniques of the report, in order. No technique is a miss.
- **p90.** `numpy.percentile`, linear, as in `status.md`.
- **`dns` separately.** `pooled` keeps all five log types, as in M5 and as "also reported separately" reads; the `dns` row is shown apart. `pooled_without_dns` is added for the other reading.

## 3. Proposals, nothing run

### 3a. Ablations on santos (§10.4)

Santos has 3 incidents, so all 3 run. Four conditions:

| Condition | Switches | Run name | Spends |
|---|---|---|---|
| `base` | verifier, RAG on, few-shot off | `verifier1-rag1-few_shot0-8853cca7` | 0, replay |
| `verifier0` | Verifier off | `verifier0-rag1-few_shot0-8853cca7` | yes |
| `rag0` | RAG off: `mapper-no-rag-1`, no `attack_search` (D48) | `verifier1-rag0-few_shot0-8853cca7` | yes |
| `few_shot1` | examples on | `verifier1-rag1-few_shot1-<new hash>` | yes |

**Guards stay as they are.** `investigate` is not used and `--rerun-reason` is never passed, so the once-only guard on santos `investigate` is untouched.

- New command `logtriage ablate --condition <name> --reason <text>`, santos only.
- Order of checks: `check_container` first (D53, whatever the reason given), then the testbed must be santos (§10.7), `agents.prompts_frozen` must hold, and `--reason` must not be empty.
- Each condition is its own ledger stage, `ablation:<name>`, in `test_runs.csv`, written with its reason before it starts, so a crash counts as a run. A second run of a condition is refused, with no override. `guards.check_run` compares the stage exactly, so these rows neither open nor block `investigate`.
- The condition goes into a copy of the settings in memory. `configs/default.yaml` does not change.
- Reports go to `data/processed/santos/ablations/<name>/` and tables to `reports/results/ablation_<name>.csv`, so `reports/` and `agents_santos.csv` cannot be overwritten. `run_incidents` needs an output directory and a table path for that.
- Answers stay apart through the condition in `cache_key`, and memory through the run name (D42). `base` does not write to the incident store.

**Proof that `base` replays at 0 cost.** `LLMClient` gets a `cache_only` mode that raises on any miss, and `base` runs with a backend that raises if invoked and with no API key. Then:

1. `spend` has 367 rows and 0.4645 USD before and after.
2. Each report has `cached_calls == llm_calls` and `spent_usd == 0`.
3. Each report equals the saved one after dropping `spent_usd`, `cached_calls` and `latency_s`.
4. The sha256 of the saved reports is unchanged.

A miss stops the run at no cost and is reported. It can happen: `ca1a8d3` (chat) touched `tools.py` and `graph.py` after the santos run. D49 says M8 keys still match, but that was never tested on santos. If it misses, `base` cannot be replayed and the saved reports stand as the Verifier-on condition; a paid `base` is not an option, because it would be a second santos run.

**Limit to state.** Each condition has its own cache keys, as §10.4 requires, so each re-runs the Investigator, and the model is not bit-exact at temperature 0 (Recorded facts). With 3 incidents, a difference between conditions mixes the switch with run-to-run variation. Results are descriptive only.

`system_fingerprint` is compared after the first call, and the run stops if it differs from `bc19ba97cbe016479903222bb1578db6` (D44). Conditions run off-peak.

**Cost.** Santos took 143,690 input tokens (48,256 cached) and 12,216 output, so 0.0218 USD off-peak per condition. No cache hits at all and more rewrites give 0.04 at most. Three conditions: **about 0.07 USD, at most 0.13 off-peak**, twice that at peak.

### 3b. `prompts/reporter_examples.md`

- **Content.** 2 short examples, about 700 tokens, each an input excerpt and the JSON of `ReportDraft`. `prompt_version: reporter-examples-1`, the word json, no `labels` or `phases` (the §5.2 scan reads prompts).
- **Invented, not adapted.** Hosts `host-a`, `host-b`; addresses from RFC 5737 only; users `user1`, `user2`; domains under `.example`.
- **No answers given away.** Scenarios outside the attack chain of these testbeds and no technique ID from the gold mapping. Proposed: a backup job read as `benign`, and a mail relay misconfiguration read as `uncertain`, with one technique outside the gold set or none.
- **Who writes them.** Not this session: to learn the schema it printed parts of `santos-0001` and `harrison-0001`. A fresh agent, given only `reporter.md`, `schemas.py`, §5.7 and this section, with no access to `data/` or `reports/`. Or the user. **OPEN**, recommendation: the fresh agent, then the user reads them.
- **How it is checked.** A `@pytest.mark.data` test fails if the file holds any address, host, user or domain of any testbed, any gold ID, or any 6-word sequence found in the text of a test-testbed report or a raw line of its incident windows. A `tests/` unit test checks the format and that addresses are RFC 5737. Then the user's reading, the file's sha256 in `status.md`, and the commit, all before `few_shot1` runs. The examples are never changed after its reports are seen.

### 3c. LLM-only baseline (§10.3)

Module `eval/llm_baseline.py`, prompt `agents/prompts/llm_only.md`, `llm-only-1`, outside `ROLES` like `chat-1`, so run names do not move. The rule below is committed here; the draw happens after that.

**Population.** Santos evaluation windows that have a row in `scores.parquet`, so the five baseline-capable log types, without label-ambiguous windows (D17). Attack = at least 1 labeled line. Normal = none.

**Draw**, `numpy.random.default_rng(42)`, one generator, this order:

1. Sort the population by `(window_start, host, log_type)`.
2. Attack, 20: one pool per phase of the primary denominator, in the time order of the phases file. Each pool holds the attack windows with that phase and is shuffled once. Take from the pools in turn, one per turn, skipping a window already taken and any empty pool, until 20. So rare phases are in the sample at all; a plain draw would be nearly all `dnsteal_exfil`.
3. Normal, 20: one pool per log type, in alphabetical order, shuffled once, 4 from each. If a pool is short, the rest go to the next pool in turn. Scores are not used.
4. Shuffle the 40 and write `reports/results/llm_only_sample.csv`, committed before any call.

**Lines.** `parse_ok` lines of the window by `(ts, line_no)`, the first 300 if there are more. This is the literal "≤ 300, chronological". It can drop every labeled line of a long window, so the sample file records lines kept and labeled lines kept, and the window stays in its stratum.

**Prompt.** Host, log type and raw lines through `wrap_untrusted`; asks for JSON with a verdict and the top 3 techniques. No score, no label, no phase, no stratum. The caller reads only the key columns of the sample file. Same model, `temperature=0`, thinking off, own condition `{"llm_only": true}` in the cache key, ledger stage `llm_only`, once, santos only, refused in the container.

**Reported on the sample.** Verdict matrix and F1 (attack = malicious), ATT&CK top-1 and top-3 strict and lenient on the 20 attack windows against the gold sets of their phases, cost, latency, tokens.

**Cost.** Estimated at 3 characters per token. Means per line: `apache_access` 266 characters, `dns` 113, `audit` 206, `auth` 99, `vpn` 97. Attack windows run to 11,000–27,000 tokens at the cap and normal windows about 1,500. So 230,000–570,000 input tokens and about 12,000 output: **0.04–0.10 USD off-peak**, 0.17 at the extreme of 40 full `apache_access` windows.

**Extrapolated full-period cost**, computed after the run. From the 40 calls, measure input tokens per line by log type, fixed prompt tokens per call and output tokens per call. Calls for the full period = `Σ ceil(n_lines / 300)` over all 16,336 evaluation windows. Cost = (tokens per line × 549,000 evaluation lines by log type + fixed tokens × calls) at the input rate + output tokens × calls at the output rate, at both rates, with no cached-input discount. Before any run, a rough figure is 8 USD off-peak for 2.7 days.

### 3d. Faithfulness sample (§10.2, §10.7): **OPEN**

Final reports hold 367 claims: santos 45 (11 summary, 30 timeline, 4 technique), `wardbeck` 195 (55, 133, 7), `harrison` 127 (36, 87, 4).

**Verifier-on sample, the same in every option, 120 claims.** All 45 of santos, so the santos reading has no sampling error, and 75 of the others in proportion: 45 `wardbeck`, 30 `harrison`. Within a testbed: at least 1 claim per report, then allocate by claim type in proportion. `default_rng(42)`. The pooled rate is weighted by each testbed's claims, and the raw rate is shown beside it.

**The conflict.** The target needs "higher than without". Two facts make that hard:

- A Verifier-off report can be a new run only on santos (D56), about 45 claims. But on santos the Verifier changed nothing in the saved run: 0 rewrites, 0 removed, so every final claim is its first draft. A santos on/off gap therefore cannot show a Verifier effect: it can only show two different runs.
- The Verifier did act elsewhere: 9 rewrites on 8 reports (`wardbeck` 3, `harrison` 5). Their first drafts are still in `llm.sqlite`. All 34 reports were traced back to their Reporter answers, by reading only. Those 8 reports have 117 draft claims: 15 exist only in the draft, 13 only in the final report, the rest are the same. A first draft is what the graph with `verifier: false` would return from the same evidence (D48).

| | Option 1: santos run | Option 2: cached drafts | Option 3: both |
|---|---|---|---|
| Off arm | Verifier-off run, about 45 claims | 15 draft-only claims; the 13 final-only claims join the on arm | both |
| Claims to rate | about 165 | about 148 | about 193 |
| Rater time at 1 min per claim, an assumption | 2.8 h | 2.5 h | 3.2 h |
| Extra USD | 0 (§10.4 runs it anyway) | 0 | 0 |
| Respects D56 | yes | yes: no new run or report on any testbed; it reads saved answers | yes |
| Lets `results.md` say | rate with and without on santos, n about 45 each. Not attributable to the Verifier | on the 8 reports where the Verifier acted, how many changed claims were supported before and after, on the same evidence. Over all 367 claims, the rate with and without differs only through those claims | both, labeled apart |
| Cannot say | that the Verifier caused the gap | anything for santos: there, with and without are equal by construction, so "higher" does not hold there | |
| Main risk | a gap, either way, read as an effect | the 8 reports are the ones the Verifier flagged, so this is its effect where it fired, and it rests on about 28 claims | |

**Recommendation: Option 3**, with the reading fixed now, before any rating. The target's "higher than without" is read on the santos run comparison, as §10.2 and the santos-primary rule say, and is stated as confounded. The paired drafts are the secondary reading that actually isolates the Verifier. It costs about 45 more ratings than Option 2 and nobody can say the favourable reading was picked afterwards.

**Blinding, all options.** One row per distinct claim: random id, claim text (a timeline claim with its time), the raw text of its cited lines, and a rating. Nothing else: no report, verdict, technique rank, run name or condition. Testbed names in text are masked as `<org>`. A claim with the same text and cited lines in both arms is rated once and counts in both. Rows are shuffled with seed 42. The key (id to testbed, report, arm) goes to `data/cache/`, never committed, and is regenerated from the seed at import. Rating: `supported` only if the cited lines show every fact in the claim, otherwise `not_supported`. Absence claims are `not_supported` unless a line shows them. Raters try 10 dev claims first, to settle the rule; those do not count. This session writes nothing here: the rater names and the double rating are the user's. Recommendation: 2 raters on all claims, disagreements settled together, κ reported.

### 3e. Human evaluation (§10.2)

**Which reports. OPEN.** Recommendation: **all 27** Verifier-on test-testbed reports (3 santos, 14 `wardbeck`, 10 `harrison`), which meets ≥ 20 and removes any selection. The alternative is 21: all 3 santos, all 4 other `malicious` verdicts, and 14 `uncertain` by `default_rng(42)`, 8 `wardbeck` and 6 `harrison`. It saves about 22% of the time but drops some of the 7 near-identical `dns`-only `harrison` reports by chance. At 4 minutes per report, an assumption: 1.8 h or 1.4 h per rater.

**Sheet.** `reports/human_eval/sheet.csv`: `sheet_id`, report text as a reader sees it (summary, timeline, techniques, verdict, confidence, actions, cited lines), `usefulness` and `readability` 1–5, `rater`. One copy per rater, in an order shuffled with seed 42 plus the rater's number, and at least 2 raters.

**Blinding.** `sheet_id` is random. No incident id, testbed name (masked as `<org>`), score, cost, Verifier data, phase, label or ground-truth verdict. The key goes to `data/cache/`, as above. Raters do not see each other's scores. All 27 share one condition, so there is no condition to hide. Limit: raters from the team know these testbeds, so blinding to testbed and to the truth is only partial, and `results.md` says so.

**Agreement.** Cohen's κ per dimension on scores binarized at ≥ 4, as §10.2 leaves the cut open, with the mean per dimension. With more than 2 raters, mean pairwise κ.

## 4. Cost of the next session

Ablations at most 0.13 and LLM-only at most 0.17 USD off-peak, so at most 0.30, or 0.60 at peak. Ledger today 0.4645, about 0.50 with the unledgered part, against the 10 USD stop.
