# v2 plan: detection improvement on dev, measured once on shaw

Written 2026-11-08 on branch `m12-v2` (D74), **before any candidate was implemented or measured**. Everything below that is a number comes from saved russellmitchell files and in-memory computation on russellmitchell: nothing was fit, scored or written under `data/processed`, and the sha256 of all 311 files under `data/processed` and `reports/results` were identical before and after. No LLM call (ledger 485 calls, 0.54517 USD). Nothing ran on santos, `wardbeck` or `harrison`, and shaw was not downloaded. Santos numbers quoted here come from `reports/audit_incident_count.md` and `reports/results.md`, which were already written, and none of them supports a candidate.

## 1. Protocol (fixed by D74)

- Development and selection happen on russellmitchell (dev) only.
- v1's results on santos, `wardbeck` and `harrison` stay the official v1 results. Those testbeds have been seen, so a v2 number on them could only be a secondary "seen data" figure. M12 produces none.
- The clean measure is **shaw**, the next unseen testbed in the committed seed-42 order of D55 (wardbeck, harrison, **shaw**, wheeler, fox, wilson). v1 and v2 each run once there.
- **wheeler** joins shaw as a second unseen test testbed, under the same protocol (changed: see status.md D77, decided before any shaw or wheeler data was seen; §5 to §7). **fox replaces wheeler**, which fails the D55 criteria (changed: see status.md D84, D85).
- The agents stay as in v1: frozen prompts, retrieval and `deepseek-flash`. Only detection changes.

## 2. Diagnosis on dev

Dev has 10 phases with traces. v1 detects 6 at `q` 0.999 and gap 30 (7 incidents, 3.73 per day). In the table:
- **Windows** counts the scored eval windows holding a labeled line of the phase. `apache_error` lines are listed, but that type has no baseline (D19), so they are never scored.
- **Percentiles** are `pct_if / pct_lof / pct_pca` of the best window.
- **Rank** counts the windows of the same log type that score strictly higher, plus one.

| Phase | Labeled eval lines (type, host) | Windows | Best window | Score | Percentiles | Rank | Passed `q` | Result, limit |
|---|---|---|---|---:|---|---|---:|---|
| `service_scans` | `apache_access` intranet_server 12; `dns` inet-firewall 443 | 4 (`apache_access` 2, `dns` 2) | `apache_access` 01-24 03:57 | 1.000000 | 1 / 1 / 1 | 1 of 3,458 | 1 | detected |
| `dirb` | `apache_access` intranet_server 4,462; `apache_error` 23; `dns` 8 | 2 (1, 1) | `apache_access` 03:57 (the same window) | 1.000000 | 1 / 1 / 1 | 1 | 1 | detected |
| `wpscan` | `apache_access` intranet_server 3,186; `apache_error` 13; `dns` 8 | 3 (2, 1) | `apache_access` 03:57 | 1.000000 | 1 / 1 / 1 | 1 | 2 | detected |
| `webshell` | `apache_access` intranet_server 31 | 2 | `apache_access` 03:58 | 1.000000 | 1 / 1 / 1 | 1 | 2 | detected |
| `cracking` | `apache_access` intranet_server 4; `dns` 12 | 2 (1, 1) | `apache_access` 03:59 | 0.999736 | 0.999209 / 1 / 1 | 4 | 1 | detected |
| `privilege_escalation` | `audit` intranet_server 9; `auth` intranet_server 8 | 4 (`audit` 2, `auth` 2) | `audit` 04:37 | 1.000000 | 1 / 1 / 1 | 1 of 1,514 | 1 | detected. The best `auth` window, 0.998775 (0.996324 / 1 / 1), sits one calib window under `q` on IF: with `N` 272, `q` 0.999 allows no lost rank |
| `service_stop` | `audit` internal_share 2; `dns` inet-firewall 10 | 2 (`audit` 1, `dns` 1) | `audit` 01-24 13:50 | 0.995215 | 0.990431 / 1 / 0.995215 | 5 of 1,514, tied with 80 | 0 | **missed: the features.** The window's feature row is identical to 79 other eval windows on 7 hosts, and to 54 fit and 10 calib windows, so no threshold or calibration can separate it. Its 2 labeled lines are systemd `SERVICE_START` and `SERVICE_STOP` for `unit=put`. Templates 7 and 8 mask the unit, and they are common (522 and 461 fit lines on 7 hosts). No feature carries the unit name. Its `dns` window is a low score, 0.346 |
| `network_scans` | `dns` inet-firewall 510 (PTR and random-name queries from the tunnel address); `vpn` vpn 28 (the attacker's connection) | 4 (`dns` 3, `vpn` 1) | `vpn` 01-24 03:01 | 0.941725 | 1 / **0.825175** / 1 | 4 of 157 | 0 | **missed: the D28 reference, on LOF.** The window's raw LOF is 0.9837: 0 of the 24 calib scores lie above it, against 25 of the 119 OOF scores. Calib alone would give it `pct_lof` 1.0, while D28 gives 118/143. This is not a ceiling, since dev `vpn` reaches 1.0 on all three models. Its best `dns` window is a low score, 0.879826, rank 397 of 4,855 |
| `dnsteal_exfil` | `dns` inet-firewall 21,399 | 2,090 | `dns` 01-24 11:56 | 0.987493 | 1 / 0.962480 / 1 | 21 of 4,855 | 0 | **missed: a low score, from a contaminated baseline (D16).** The tunnel runs through every training hour, so it is the normal state. 23 of the 613 calib windows of the stream lie above it on LOF. The D29 clip is not the limit: without it, dev flags 17 `dns` windows, none of them true (M5) |
| `dnsteal` | `dns` inet-firewall 38 | 3 | `dns` 01-24 13:51 | 0.977162 | 0.977162 / 0.980424 / 0.973899 | 80 of 4,855 | 0 | **missed: a low score**, for the same reason as `dnsteal_exfil`. Its lines are the last tunnel queries before the service stops. The clip is not the limit, for the same reason |

Limits that decide **no** dev miss:
- **Baseline capability:** every missed phase has lines in a capable type.
- **Grouping:** every flagged eval window belongs to an incident, so grouping cannot lose a phase.
- **The calibration stream:** no missed phase fails only by the per-host or per-type choice.
- **A dropped constant feature:** D25 drops only the `n_execve*` features, which `SERVICE_*` records do not touch.

**How `q` interacts with the misses.** A window passes `q` if the rank steps it loses over the three models number at most `(1 - q) · 3N`. With `N` < 334 that is 0, so `q` 0.999 requires all three percentiles at 1.0 (audit C1). On v1 scores no `q` in (0.995, 0.999) can add a dev phase. Phase sets only grow as `q` falls, because every flagged eval window joins an incident. At 0.995 dev detects exactly one more phase, `service_stop`, whose best window is 0.995215. So `q` must be at most 0.995215 to add it, and at that level 122 eval windows pass (84 of them `audit`). This is the reason candidate (b) is tested only alongside the others.

### D28 ceiling per log type, dev

| Log type | Reference | `N` | Thin | Max `pct` in eval, IF / LOF / PCA | Ceiling | Best eval score |
|---|---|---:|---|---|---:|---:|
| `apache_access` | per host (`cloud_share`, `webserver`); `intranet_server` per type | 613; 1,264 | no | 1 / 1 / 1 | 1.0 | 1.000000 |
| `audit` | per type | 209 | no, by 9 windows | 1 / 1 / 1 | 1.0 | 1.000000 |
| `auth` | per type | 272 | no | 1 / 1 / 1 | 1.0 | 1.000000 |
| `dns` | per host | 613 | no | 1 / 1 / 1 | 1.0 | 0.990756 |
| `vpn` | per type + OOF | 24 + 119 | **yes** | 1 / 1 / 1 | 1.0 | 1.000000 |

On dev only `vpn` uses D28, and its OOF maxima stay below the final models' maxima (IF 0.6230 against 0.8033, LOF 1.1562 against 1.2933, PCA 0.6186 against 7.3599). So **dev has no D28 ceiling**. The mixing still decides one dev phase, `network_scans`, through the 25 OOF LOF scores above its window. The real ceilings appear on the test testbeds, which are already reported: santos `auth` 0.998848 and `vpn` 0.992063, `wardbeck` `vpn` 0.991031, `harrison` `vpn` 0.995318.

A recomputation of dev `vpn` in memory reproduces the saved raw scores exactly (difference 0 on all three models).

### How D28's mixing creates the ceiling

For model `m`, a window's percentile is `pct_m(x) = #{r ∈ R : r ≤ s_m(x)} / N`. Under D28 a thin type's reference `R` holds two kinds of scores:
- **calib scores** of the final model `s_m`, fit on all fit windows;
- **OOF scores** `s_m^(k)(j)` of the fit windows `j` in block `k`, from five other models, each fit on the other four blocks.

Every scored window, calib and eval, is then scored by the final model alone. The two kinds of score come from different functions on different scales.

The OOF scores run high for three reasons:
- **LOF and IF:** a row that occurs only in block `k` is new to fold model `k`, but the final model has seen it. Quiet windows repeat a few rows: dev `vpn` has 119 fit windows and only 9 distinct rows.
- **PCA:** a direction of variance that exists only in one block is missing from that fold's components, so its rows get a large reconstruction error. The final PCA includes that direction.
- **IF's subsample:** it is `min(256, n)` rows (119 for the final dev `vpn` model, about 95 for a fold model), so its normalization differs.

So the top of `R` can hold OOF scores that **no final-model score reaches**. If `k_m` reference scores lie above the highest score the final model gives any window, then `pct_m ≤ 1 - k_m/N` for every window, and the ensemble score is at most `1 - (k_if + k_lof + k_pca) / (3N)`. That bound is the ceiling. `q` 0.999 is out of reach once `Σ k_m > 0.003 · N`, which is any `k_m` ≥ 1 below `N` 334.

On santos `auth`, 3 OOF scores sit above the IF maximum that the final model gives 27 windows, 0.8136. So `pct_if` stops at 0.996544 and the ceiling is 0.998848. On dev the same mechanism stops short of a ceiling, because the final models' eval maxima happen to exceed every OOF score. It still lowers individual windows: the `network_scans` window above has a final LOF score at the calib maximum, yet 25 OOF scores outrank it. D28's premise was that OOF scores behave like scores of unseen windows. The saved data contradicts it: on dev `vpn`, 21.0% of OOF LOF scores pass the calib maximum, against 5.1% of eval windows, and eval holds the attack.

## 3. Candidates

Each candidate is label-free, sits in the detection code (`data/features.py` or `ml/`), and is the same rule on every testbed.

**(a) Cross-fitted calibration for thin log types; it replaces D28's mixed reference.** Reason: section 2, the D28 mechanism (the dev `network_scans` window) and the known ceilings. The trigger stays D28's: a log type with fewer than `ml.min_calib_windows` calib windows. Its fit windows are cut into the same `ml.oof_folds` contiguous blocks, and fold model `M_k` is fit on the other blocks.
- **Reference:** for each model `m` and fold `k`, `R_k = M_k` scores of block `k` ∪ `M_k` scores of the type's calib windows.
- **Calib and eval windows:** `pct_m(x) = mean over k of ECDF(R_k, M_k(x))`.
- **Fit windows in block `k`:** they use fold `k` only.

Every percentile is then measured against scores of the same function, on data that function did not see, so no structural cap remains. The final all-fit models no longer score thin types. Their raw `score_<m>` columns become the mean of the fold scores, and the report says so. Streams and types with at least 200 calib windows keep v1's calib-only reference unchanged. On dev this touches `vpn` only.

**(b) A finer `q` grid: {0.95, 0.97, 0.98, 0.99, 0.995, 0.996, 0.997, 0.998, 0.999}** under the §6.5 rule. Reason: with small `N`, `q` 0.999 acts as an AND of the three models (section 2, audit C1). Dev uses 15% of the incident budget. The v1 grid jumps from 133 windows at 0.995 to 24 at 0.999. On v1 scores alone (b) cannot add a dev phase (section 2), so its only possible value is with (a) or (d).

**(c) DNS: no change.** No DNS change is principled without labels:
- The tunnel is in every training hour (D16), so any detector relative to the baseline sees exfiltration as normal.
- Cleaning the baseline needs labels or attacker information (§5.2).
- An absolute rule ("entropy above X") would be a signature fitted to labeled dev windows, not anomaly detection.
- Dropping the clip (D29) gives 17 dev `dns` flags with 0 true.

`dnsteal_exfil` and `dnsteal` therefore stay out of reach by design, and the best dev result v2 can reach is 8 of 10.

**(d) An unseen systemd unit feature for `audit`: `n_unseen_units`.** It counts the distinct `unit=` values of `SERVICE_START` and `SERVICE_STOP` records in a window that are not in the fit vocabulary of the testbed. It is built, gated and dropped like the other `n_unseen_*` features (§6.3, D15, D25), and it joins the `audit` feature list. Reason: section 2. The `service_stop` window is identical to 79 other eval windows, and the only thing that tells it apart, the unit name, is masked by the template. This is the same idea as `n_unseen_exe`.

Label-free count on dev, by unit name only: two eval units are not in the fit vocabulary, `put` (2 lines, 1 host) and `fstrim` (12 lines, 6 hosts, a weekly timer). `fstrim` will produce false positives. **Disclosed:** (d) was found by reading the labeled lines of a missed dev phase, so its dev result is optimistic, and only shaw can say whether it generalizes. On a new testbed the service may have another name, or start inside the fit period.

### Rejected ideas

| Idea | Why not |
|---|---|
| Drop D28 and use calib only for thin types | D28's own reason holds: santos `vpn` has 7 calib windows, so steps of 1/7, and a score at the calib maximum gets 1.0. It would also be chosen on the strength of santos and `harrison` ceilings |
| Keep the final models and add their in-sample fit scores to the reference | In-sample scores are biased low, so eval windows would look more extreme than they are. This is the bias D28 was meant to avoid |
| Extend the D29 clip to `mean_template_rarity` | Its only support is `harrison`'s 42 post-tunnel `dns` flags and santos' post-tunnel ties, all test testbeds. D29 already chose to leave it alone |
| Lower `q` or add a rule to catch santos `cracking` (0.997737) | Support is a test-testbed miss only. Dev detects `cracking` |
| A PTR-query or random-name feature for `network_scans` in `dns` | It would credit the phase through `dns` alone, the credit D29 flags as suspect, and the tunnel's random names already sit in the baseline. Dev's own `vpn` limit is the D28 one, which (a) addresses |
| Treat `::1` as host-local in linking (audit B2) | A real bug, but grouping cannot lose a phase. The fix only adds incidents (dev 7 either way at the chosen setting). Left as a known limitation |
| Fix `reference_size` in `detect_report.json` (audit B3) | Reporting only. It would break the byte-identity check of v1 mode on `detect_report.json`. Left for later |
| Anything for `service_stop`, `network_scans` or `cracking` on santos, `wardbeck` or `harrison` | All three miss these phases, but that is test-testbed evidence and supports nothing here. (d) and (a) rest on dev only |
| DeepLog, memory evaluation | Dropped by D74 |

## 4. Selection rule (dev only, measured once)

- **Configurations:** v1, a, b, d, a+b, a+d, b+d, a+b+d. Each runs once on russellmitchell through `logtriage.eval.tuning`, over its `q` grid (the v1 grid, or the grid of (b) when b is included) × gap {5, 10, 15, 30}.
- **Output:** all rows go to `reports/results/v2_dev_selection.csv`, committed.
- **v1 check:** the v1 rows must equal `reports/results/tuning_dev.csv` exactly, or the session stops.
- **Rule:** the §6.5 rule, unchanged, over all rows of all configurations. Take the highest dev phase recall with incidents per day ≤ 25; ties go to fewer incidents. Remaining ties go to fewer candidates (v1 first), then to the existing order (higher `q`, smaller gap).
- **v2 is the chosen row.** If that row is v1 itself, v2 did not help on dev. M12 then stops after dev with that result, and neither shaw nor wheeler is downloaded, because there would be nothing to compare (changed: see status.md D77).
- **Nothing else:** no candidate is tuned. Fold count, the 200 trigger, the unit regex and the grid points are fixed above, and a failed candidate is reported, not repaired.

## 5. Shaw and fox protocol (changed: see status.md D77, D85)

shaw and fox, the next two unseen testbeds of the D55 order, are both test testbeds. fox is third in that order; it replaces wheeler, which fails the D55 criteria (D84, D85). Every step below applies to each of them, separately, and nothing is pooled before evaluation.

1. **Before downloading:**
   - Log the decision.
   - Add shaw and fox to `test_testbeds`, `download.sources` and the AIT-ADS extraction, so every guard of D57 covers both. That includes `prompts_frozen`, the container marker and the once-only ledger.
   - Check the feasibility of each by the D55 criteria, from the zip directory and the `labels.csv` row count only: `dataset.yaml`, 8 label files, the six log families, 10 phase rows.
   - If either is infeasible, the next unchecked testbed in the order (fox, then wilson) takes its place, with no other change. Feasibility failure as D55 defines it, or a download that cannot fit on disk, is the only reason to replace a testbed: never a result, never anything seen in detection (changed: see status.md D80).
2. **Prepare** each: download, extract, `inventory` and `prepare` with the v2 code. Windows then hold the (d) column, and v1 mode ignores it.
3. **Freeze before any detection** on either testbed. Write the following to `reports/targets_shaw.md` and `reports/targets_fox.md`, then commit both and record their sha256 in status.md:
   - EDA, periods and gap (any fallback logged as in D58);
   - phases with traces and the three denominators;
   - the budget of 25 per day × eval days;
   - IDS alerts per day;
   - the D28 exposure from counts.

   The targets and definitions are those of `reports/targets.md`, unchanged.
4. **v1 runs once on each testbed, each step through `guards.py` with its own row in `reports/results/test_runs.csv` before it starts:**
   - `detect`, with v1's `configs/default.yaml` in v1 mode;
   - the supervised test stage, with the frozen v1 models;
   - `investigate`, into the official memory.

   Before either testbed, v1 mode must reproduce dev's saved `scores.parquet` and `incidents.parquet` byte for byte.
5. **v2 runs once on each testbed:**
   - `detect` with `configs/v2.yaml`;
   - `investigate`, both under their own stage names (`detect:v2`, `investigate:v2`) with ledger rows;
   - outputs under `data/processed/<testbed>/v2/` and their own Chroma store, as for the ablations (D65), so v2 never touches v1's files or memory.

   A v2 incident identical to a v1 one may hit the LLM cache. That is the same request, and the cache counts it as such.
6. **Evaluate** from saved outputs: phase recall (primary, all parsed, without exfiltration, with per-type credit), incidents per day, alert reduction, ATT&CK top-3 and verdicts, for v1 and v2 side by side, per testbed and as the sum over shaw and fox (phase recall as detected over denominators summed; incidents per day per testbed only).
   - AI-annotated faithfulness is not run on shaw or fox, since the agents are unchanged.
   - No second run of any stage. A failed paid stage follows D69, and a failed `detect` or `investigate` stops.

## 6. Cost estimate

- **LLM:**
  - Per incident, from M11: mean 0.0067–0.0073 USD and p90 0.0094 off-peak, about double at peak.
  - v1 on each of shaw and fox: v1 gave 3, 14 and 10 incidents on the test testbeds, so about 3–15 incidents and ≤ 0.15 USD off-peak per testbed, ≤ 0.30 for both.
  - v2 at most fills the budget: 25 per day × about 1.7–3.3 eval days is ≤ 83 incidents per testbed, ≤ 0.78 USD at the off-peak p90, ≤ 1.56 at peak; for both testbeds ≤ 1.56 off-peak, ≤ 3.12 at peak (changed: see status.md D77).
  - Dev selection makes no LLM call.
  - **Stop for M12: 2.00 USD of new ledger spend.** The cumulative 10 USD stop also holds (now 0.5452).
  - **Before any paid call of session 3B**, the cost is re-estimated from the real incident counts per testbed and mode (v1, v2; shaw, fox). If the projected total would pass the stop, stop and ask (changed: see status.md D82).
  - Paid shaw and fox runs go off-peak. The worst case of both testbeds off-peak, about 1.86 USD (0.30 + 1.56), stays under the 2.00 stop; at peak it would not, which is one more reason for off-peak.
- **Data:** each zip is about 17 GB, if like `wardbeck` and `harrison`, about 34 GB for both, with about 3–4 h of download each at the speed seen in M10b. Expect about 0.2–0.5 GB extracted and 0.4–0.5 GB processed per testbed, against 628 GB free. Each size is checked by a range request before downloading.
- **Compute:** about one dev scoring pass per configuration. The 5 fold fits of (a) apply to thin types only, so each pass takes minutes.

## 7. What counts as v2 helping (fixed now; changed: see status.md D77)

The comparison is on shaw and fox only, v2 against v1, with the frozen definitions and the primary denominator. The verdict reads the **sum over shaw and fox**, and the per-testbed numbers are always shown beside it.
- **Helps:** all of
  - v2 credits more phases than v1 in total over shaw and fox;
  - at least one extra phase is credited through a log type other than `dns`;
  - v2 stays within 25 incidents per day on each testbed.
- **Does not help:** the same number of phases in total, or a total gain that comes only through `dns` credit.
- **Hurts:** fewer phases than v1 in total, or more than 25 incidents per day on either testbed.
- **Always reported:**
  - any phase v1 detects that v2 loses, on either testbed, even when the total is equal or higher;
  - the frozen ≥ 80% target for both, per testbed;
  - phase recall without exfiltration;
  - incidents per day, ATT&CK top-3 and cost, per testbed.
- **Expected outcome, written before any shaw, wheeler or fox data exists:** the dev gain rests on one phase (`service_stop`) caught at a single `q` step, with 6 `fstrim` false positives, and (d) was found on dev labels. A null or negative result is therefore an expected and acceptable outcome, and is reported as such (changed: see status.md D81).
- **Limits:** these are two testbeds with about 9 phases each and one run each, so a difference of one or two phases is an observation, not a statistical result. Dev numbers are the selection metric and optimistic by construction. They are never presented as evidence that v2 helps.
- **The verdict changes no setting.** `configs/default.yaml` stays v1, the official version, and v2 is merged as `configs/v2.yaml` with its code, whatever shaw and fox show.

## 8. Not sure

- Dev can exercise (a) only through `vpn`, a single type with `N` 143, where D28 caps no model. Dev `audit` misses the thin rule by 9 windows. The selection of (a) therefore rests on one dev phase at most, while its main effect on test testbeds, four thin types on santos, is invisible on dev.
- (a) changes the user's wording "so the final models can reach `q`". Under any honest larger reference, the final all-fit models of a thin type cannot be calibrated, because the only windows they did not see are the calib windows. So (a) replaces them with the fold models for those types.
- (d) comes from one dev event of 2 lines, so its value on shaw is a real unknown, and `fstrim`-like timers can add false positives.
- The plan runs v1 on shaw as v2 code in v1 mode, checked byte for byte on dev, not as a checkout of tag `v1.0`, because the `v1.0` code has no guard for shaw.
- Shaw's feasibility and zip size are unknown until checked.
