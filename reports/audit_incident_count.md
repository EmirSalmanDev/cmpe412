# Audit: why santos has only 3 incidents

Read-only, 2026-11-06, on `main` at `4527529` (tag `m9-done`). Nothing was fit, re-scored or re-calibrated. No `detect`, `prepare`, `investigate`, LLM call or notebook run. No config, threshold, feature or evaluation definition changed. Santos numbers here are **description only**: none of them is a basis for choosing `q`, the gap or any setting.

## Verdict

**There is no logic error between the saved windows and the incidents.** Every correctness check passes (Q6), and `tuning_dev.csv` reproduces exactly from saved scores (24 rows, 9 columns, 0 mismatches). The count of 3 comes from a design choice and a data limit, plus one real flaw in the D28 calibration reference whose effect on the count could not be measured here.

1. **The attack is compact.** If every attack window on santos were flagged, §6.6 would give only 5 incidents at gap 30, or 4 without exfiltration-only windows. 3 is low against a budget of 67, not against what the data holds.
2. **Both testbeds have exactly 2 incidents with a labeled line.** The whole 7 vs 3 difference is incidents with no labeled line: 5 on russellmitchell, 1 on santos.
3. **Nearly all the drop is at the threshold.** 16,336 scored windows become 5 flagged windows, a factor of 3,267. Grouping only takes 5 to 3, and the gap does not matter: 3 incidents at 5, 10, 15 and 30 minutes.
4. **`q` 0.999 does not mean the same thing on both testbeds.** It was chosen where 4 of 5 log types calibrate on calib windows only. On santos 4 of 5 log types use a reference that is 80–96% out-of-fold scores.

Terms used below:
- **Reference**: the scores a window's percentile is measured against (§6.5).
- **OOF**: out-of-fold scores of fit windows, added to a thin log type's reference by D28.
- **Rank step**: one reference score, worth `1/(3N)` of ensemble score with a reference of size `N`.
- **Ceiling**: the highest score a log type could show, if the highest percentile of each model in its eval windows fell on one window.

## Findings

### Bug leads

| # | Finding | Evidence | Effect on the count |
|---|---|---|---|
| B1 | **D28 mixes scores from different models in one reference, and that puts `auth` and `vpn` on santos out of reach of `q` 0.999.** The code does what D28 says, so the flaw is in the rule, not the implementation. The final models are compared with OOF scores from five other models, on a scale they do not reach. | Santos `auth`: 3 OOF scores sit above the highest IF score the final model gives any of the 2,666 `auth` windows (0.8136, reached by 27), so `pct_if` stops at 0.996544 and the ceiling is **0.998848**. Santos `vpn`: 2 OOF scores sit above the top PCA score, so `pct_pca` stops at 0.976190 and the ceiling is **0.992063**, while `vpn` needs all three models at 1.0. No calib window is above those tops, so these scores are OOF by elimination. OOF scores also do not behave like scores of unseen windows, which is what D28 assumes: 20.1% of santos `auth` OOF scores pass the calib LOF maximum against 0.6% of eval windows, and eval holds the attack. OOF is the higher share on 11 of 12 santos rows (Q4). D28 rejected a cap *because* `vpn` "could never reach any `q` in the grid"; on santos `vpn` still cannot reach 0.995 or 0.999. Dev could not show this: only `vpn` is thin there, and it reaches 1.0 on all three models. | **Not measured.** It needs a re-calibration, which this audit forbids. It is probably not the main cause: the top `auth` windows also have 2 calib windows above them on IF, and with calib alone (`N` 176) one rank costs more than `q` allows. |
| B2 | **`::1` counts as a shared entity across hosts.** Loopback on one host is not the same source as loopback on another, but it is under the 50% rule (10.8% of russellmitchell `apache_access` fit windows, 34.6% of santos). | Components without `::1` at gap 30, russellmitchell: 94, 100, 105, 119 against 91, 94, 96, 116 for `q` 0.95–0.99. Santos: 46, 64, 69 against 44, 62, 68 for `q` 0.95–0.98. | **None** at the chosen setting: 7 and 3 either way. Dev selection is unchanged too, since those rows are over budget in both forms. |
| B3 | **`reference_size` in `detect_report.json` is wrong for streams calibrated per host.** It reports the log type's calib count, not the stream's. | Santos `dns` says 750, each host uses 375. Russellmitchell `dns` says 1,226, each host uses 613; `apache_access` says 1,264, `cloud_share` and `webserver` use 613. | **None.** Reporting only; scores are not affected. Anyone reading that field gets the wrong size. |

### Design choices

| # | Finding | Evidence |
|---|---|---|
| C1 | **`q` 0.999 works close to an AND of the three models.** With three percentiles averaged, a window may lose at most `floor(0.003 N)` rank steps in total. Below `N` 334 it may lose none, so `q` 0.999 means exactly 1.0. | Allowed steps: 0 for `N` 84–272, 1 for 375 and 613, 2 for 868, 3 for 1,157 and 1,264, 5 for 1,915. All three must be at 1.0 on 18 of 23 russellmitchell streams (2,920 of 11,233 eval windows) and 1 of 23 santos streams (227 of 16,336). |
| C2 | **`q` was chosen under one kind of reference and applied under another.** On dev, 0.999 mostly means "beyond the top of a small calib slice", and the training period itself passes that test. Santos has fit-period extremes in the reference. | Fit windows flagged, scored in-sample: **russellmitchell 18 of 11,716, santos 0 of 6,596**. Flag rate without `dns`, per 1,000 eval windows: 3.76 against 0.48. Eval windows at exactly 1.0: 22 of 24 against 0 of 5. Thin types: `vpn` only on dev, four of five on santos, and dev `audit` missed the rule by 9 windows (209 against 200). This fits the difference in no-labeled-line incidents, but the cause is not proven without a re-calibration. |
| C3 | **The `q` grid jumps from 0.995 to 0.999.** Already logged (`q` decision); the size of the jump is new. | Santos: 198 windows at 0.995, 5 at 0.999. Russellmitchell: 133 and 24. 180 of the 198 santos windows are `dns`, which leads to C4. |
| C4 | **Santos `dns` sits one rank step under `q`, in one tie.** These are not attack detections: they are the D29 known limitation. | 98 windows tie at 0.998222, with percentiles (1, 0.99467, 1), only 2 distinct score triples, 2 lines and 1 query each, all from 07:28 on 01-16 onward, after the tunnel stops. None holds a labeled line. 2 calib windows are above them on LOF and `N` 375 allows 1. 292 of 293 `dns` windows at or above 0.99 come after the tunnel stops. |
| C5 | **The D29 clip removes `dns` windows, but not santos incidents.** | From saved outputs of `03_ml_models.ipynb`, not re-run: `dns` flags 0 clipped and 1,012 unclipped on santos, 0 and 17 on russellmitchell. Incidents per day 1.11 and 1.11 on santos, 3.73 and 7.47 on russellmitchell (Q6). |
| C6 | **The linking rules changed almost nothing at the chosen setting.** No window is ever dropped. | Santos: time alone also gives 3. The only common entity is `root` in `auth`, and removing the exclusion gives 7 and 3 again. The address found in every `dns` window of its host sits at exactly 50.0% (1,501 of 3,002 on santos), so `> 0.5` misses what look like the DNS forwarders §6.6 names as its example. That is harmless: each appears on one host, so the same-host rule links those windows anyway. |

### Data limits

| # | Finding | Evidence |
|---|---|---|
| L1 | **Few separate attack episodes exist.** | Attack windows grouped by §6.6 at gap 30, as if all were flagged: santos 5, russellmitchell 4; without exfiltration-only windows 4 and 6. Santos has 13 windows that are not exfiltration-only. 12 of them lie between 11:15 and 11:59 on 01-17; the other is `service_stop` on 01-16. |
| L2 | **The santos calib slice is short and quiet.** This is what makes four types thin (D27, D28). | 6.25 h at night: 83 `apache_access`, 164 `audit`, 176 `auth`, 7 `vpn` windows. Russellmitchell has 10.2 h and 1,264, 209, 272, 24. |
| L3 | **Exfiltration runs through the baseline** (D16), so it cannot score high. | Best `dnsteal_exfil` window: rank 306 of 5,949 on santos, 21 of 4,855 on russellmitchell. |
| L4 | **Some phases leave almost nothing to find.** | Santos `service_stop` has 2 labeled lines; its best window scores 0.770959 and ties with 123 others. |

### What this audit cannot say

How many santos windows D28 itself removes or adds. Answering that means re-calibrating santos, which is out of scope and would be a test-set look at a design change. D28 also works in both directions: it adds high OOF scores, but it also makes rank steps finer. Without it, santos `apache_access` would have `N` 83, where a single calib window above costs 0.004 of score.

**If a change looks justified,** D28 is the only candidate, and it must be studied and selected on russellmitchell only, with a logged decision (§14.3). Santos has already been seen, so any later santos result is a disclosed exploratory pass, not the frozen run. Nothing here argues for a new `q` or gap.

## Q1. Funnel, evaluation period

Parsed lines are the sum of `n_lines` over eval windows, so a window crossing the boundary counts whole (D24). "Incidents touched" adds up to more than the total, because an incident can hold several log types.

| log type | RM lines | RM windows | RM flagged | RM incidents touched | santos lines | santos windows | santos flagged | santos incidents touched |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `apache_access` | 55,187 | 3,458 | 5 | 2 | 157,319 | 5,632 | 3 | 1 |
| `audit` | 8,984 | 1,514 | 3 | 2 | 17,085 | 2,730 | 2 | 2 |
| `auth` | 2,492 | 1,249 | 14 | 5 | 3,587 | 1,798 | 0 | 0 |
| `dns` | 236,651 | 4,855 | 0 | 0 | 366,878 | 5,949 | 0 | 0 |
| `vpn` | 2,807 | 157 | 2 | 1 | 4,080 | 227 | 0 | 0 |
| `apache_error` (no baseline) | 82 | 11 | not scored | – | 66 | 9 | not scored | – |

RM = russellmitchell.

| stage | russellmitchell | factor | santos | factor |
|---|---:|---:|---:|---:|
| parsed lines | 306,203 | | 549,015 | |
| windows | 11,244 | 27× | 16,345 | 34× |
| scored windows | 11,233 | 1× | 16,336 | 1× |
| flagged windows at `q` 0.999 | 24 | **468×** | 5 | **3,267×** |
| incidents at gap 30 | 7 | 3.4× | 3 | 1.7× |

**The largest drop on both testbeds is windows to flagged windows.** Incidents with a labeled line: 2 of 7 and 2 of 3. `auth` is the largest single difference between testbeds, 14 against 0, and none of those 14 windows holds a labeled line.

## Q2. Grouping

Components at `q` 0.999, gap 30, with parts of the linking rule switched off, using `link_windows` itself:

| rule | russellmitchell (24 windows) | santos (5 windows) |
|---|---:|---:|
| **full rule** | **7** | **3** |
| time only, every window linkable | 6 | 3 |
| same host only | 16 | 4 |
| shared `src_ip` only | 10 | 3 |
| shared user only | 21 | 5 |
| host + `src_ip` | 7 | 3 |
| host + user | 15 | 4 |
| full rule, no common-entity exclusion | 7 | 3 |
| full rule, without `::1` | 7 | 3 |

| window pairs within 30 min | russellmitchell | santos |
|---|---:|---:|
| all pairs | 96 | 3 |
| linked by host only | 3 | 0 |
| linked by host and entity | 8 | 1 |
| linked by entity only | 33 | 2 |
| not directly linked | 52 | 0 |
| shared entity removed by the common rule | 0 | 0 |

- **Merged:** `src_ip` does nearly all the work. On santos, `172.21.128.119` joins `cloud_share` and `intranet_server` into `santos-0002`. On russellmitchell, `192.168.230.122` and `172.19.131.174` join 13 windows on 9 hosts into `russellmitchell-0004`, and the two groups meet on one host, `webserver`, whose `apache_access` window holds the first address and whose `auth` window holds the second.
- **Separated:** on santos, time alone separates all three incidents. `santos-0001` is about 27 h from the rest, and the last window of `santos-0002` starts 36 minutes before `santos-0003`, just past the gap, although both are on `intranet_server`. On russellmitchell the rule splits one window from time-only grouping: `russellmitchell-0005`, `auth` on `vpn` from `10.9.0.10`.
- **Dropped windows: none, and the code cannot drop any.** Every node enters the union-find, and a window with no link becomes its own incident. Windows in incidents: 24 of 24 and 5 of 5. No flagged window has empty entities, and none reaches the top-10 cut on `src_ips` or `users`.

## Q3. Sensitivity (description only)

Counted from saved scores, regrouped with `group_incidents`. **Check:** the russellmitchell grid matches `reports/results/tuning_dev.csv` on all 24 rows and all 9 columns, including phases and `missed`, so there is no bug lead here.

Russellmitchell:

| `q` | windows | `apache_access` | `audit` | `auth` | `dns` | `vpn` | gap 5 | gap 10 | gap 15 | gap 30 | per day at 30 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.95 | 993 | 555 | 87 | 213 | 135 | 3 | 443 | 305 | 130 | 91 | 48.55 |
| 0.97 | 763 | 375 | 86 | 213 | 86 | 3 | 419 | 316 | 136 | 94 | 50.15 |
| 0.98 | 556 | 177 | 86 | 213 | 77 | 3 | 371 | 308 | 136 | 96 | 51.22 |
| 0.99 | 181 | 58 | 84 | 35 | 1 | 3 | 144 | 137 | 135 | 116 | 61.89 |
| 0.995 | 133 | 14 | 84 | 32 | 0 | 3 | 106 | 106 | 105 | 99 | 52.82 |
| **0.999** | **24** | 5 | 3 | 14 | 0 | 2 | 9 | 8 | 8 | **7** | 3.73 |

Santos:

| `q` | windows | `apache_access` | `audit` | `auth` | `dns` | `vpn` | gap 5 | gap 10 | gap 15 | gap 30 | per day at 30 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.95 | 892 | 87 | 8 | 11 | 783 | 3 | 388 | 200 | 119 | 44 | 16.31 |
| 0.97 | 575 | 48 | 7 | 11 | 506 | 3 | 327 | 224 | 156 | 62 | 22.99 |
| 0.98 | 397 | 33 | 6 | 11 | 344 | 3 | 236 | 182 | 147 | 68 | 25.21 |
| 0.99 | 316 | 8 | 3 | 11 | 293 | 1 | 176 | 131 | 100 | 30 | 11.12 |
| 0.995 | 198 | 6 | 3 | 9 | 180 | 0 | 127 | 109 | 96 | 33 | 12.24 |
| **0.999** | **5** | 3 | 2 | 0 | 0 | 0 | 3 | 3 | 3 | **3** | 1.11 |

- Several santos rows are under 25 per day, and that is not a basis for selection. `q` was fixed on dev, where only 0.999 fits (0.995 gives 52.82–56.55 per day). Below 0.999 most santos windows are post-tunnel `dns` (C4), not more detection.
- At gap 30 the count is not monotonic in `q` on either testbed, because more windows also chain into fewer components.

## Q4. Score health

`score` over eval windows:

| testbed | log type | windows | max | p99.9 | p99 | at max | at 1.0 | ≥ `q` | per 1,000 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| RM | `apache_access` | 3,458 | 1.000000 | 0.999736 | 0.991843 | 3 | 3 | 5 | 1.45 |
| RM | `audit` | 1,514 | 1.000000 | 1.000000 | 0.995215 | 3 | 3 | 3 | 1.98 |
| RM | `auth` | 1,249 | 1.000000 | 1.000000 | 1.000000 | 14 | 14 | 14 | 11.21 |
| RM | `dns` | 4,855 | 0.990756 | 0.989668 | 0.986406 | 1 | 0 | 0 | 0 |
| RM | `vpn` | 157 | 1.000000 | 1.000000 | 0.998695 | 2 | 2 | 2 | 12.74 |
| santos | `apache_access` | 5,632 | 0.999826 | 0.994598 | 0.968614 | 2 | 0 | 3 | 0.53 |
| santos | `audit` | 2,730 | 0.999712 | 0.989720 | 0.874964 | 1 | 0 | 2 | 0.73 |
| santos | `auth` | 1,798 | 0.997696 | 0.997696 | 0.941628 | 6 | 0 | 0 | 0 |
| santos | `dns` | 5,949 | 0.998222 | 0.998222 | 0.998222 | 98 | 0 | 0 | 0 |
| santos | `vpn` | 227 | 0.992063 | 0.989373 | 0.943016 | 1 | 0 | 0 | 0 |

Reference per stream:

| testbed | log type | streams | source | `N` (calib + OOF) | rank step | steps allowed at `q` | `q` means 1.0 |
|---|---|---|---|---:|---:|---:|---|
| RM | `apache_access` | `cloud_share`, `webserver` | host | 613 + 0 | 0.000544 | 1 | no |
| RM | `apache_access` | `intranet_server` (38 own) | log type | 1,264 + 0 | 0.000264 | 3 | no |
| RM | `audit` | 7 hosts | log type | 209 + 0 | 0.001595 | 0 | **yes** |
| RM | `auth` | 10 hosts | log type | 272 + 0 | 0.001225 | 0 | **yes** |
| RM | `dns` | 2 hosts | host | 613 + 0 | 0.000544 | 1 | no |
| RM | `vpn` | 1 host | log type + OOF | 24 + 119 | 0.002331 | 0 | **yes** |
| santos | `apache_access` | 3 hosts | log type + OOF | 83 + 1,832 | 0.000174 | 5 | no |
| santos | `audit` | 7 hosts | log type + OOF | 164 + 993 | 0.000288 | 3 | no |
| santos | `auth` | 10 hosts | log type + OOF | 176 + 692 | 0.000384 | 2 | no |
| santos | `dns` | 2 hosts | host | 375 + 0 | 0.000889 | 1 | no |
| santos | `vpn` | 1 host | log type + OOF | 7 + 77 | 0.003968 | 0 | **yes** |

Ceilings. Russellmitchell reaches 1.0 on every model of every log type, so its ceiling is 1.0 throughout. Santos:

| log type | max `pct_if` | max `pct_lof` | max `pct_pca` | ceiling | best score | can reach `q` 0.999 |
|---|---:|---:|---:|---:|---:|---|
| `apache_access` | 1.000000 | 0.999478 | 1.000000 | 0.999826 | 0.999826 | yes |
| `audit` | 1.000000 | 1.000000 | 0.999136 | 0.999712 | 0.999712 | yes |
| `auth` | **0.996544** | 1.000000 | 1.000000 | **0.998848** | 0.997696 | **no** |
| `dns` | 1.000000 | 1.000000 | 1.000000 | 1.000000 | 0.998222 | yes |
| `vpn` | 1.000000 | 1.000000 | **0.976190** | **0.992063** | 0.992063 | **no** |

The `auth` and `vpn` limits hold over all periods, not just eval. This is a statement about the saved windows: PCA error has no upper bound, so a stranger window could in principle pass.

Top of the reference for thin log types. A reference score above the calib maximum can only be OOF. This reads ranks from saved `pct` and raw scores, and makes no new score.

| testbed | log type | model | `N` | calib max | reference scores above it | highest in-sample fit score | reference scores above that | eval max |
|---|---|---|---:|---:|---:|---:|---:|---:|
| RM | `vpn` | IF | 143 | 0.7274 | 0 | 0.8033 | 0 | 0.8033 |
| RM | `vpn` | LOF | 143 | 0.9837 | 25 | 0.9837 | 25 | 1.2933 |
| RM | `vpn` | PCA | 143 | 0.1817 | 4 | 0.5148 | 1 | 7.3599 |
| santos | `apache_access` | IF | 1,915 | 0.6574 | 4 | 0.6574 | 4 | 0.7487 |
| santos | `apache_access` | LOF | 1,915 | 1.9966 | 22 | 11.0301 | 0 | 9.4342 |
| santos | `apache_access` | PCA | 1,915 | 2.1022 | 14 | 7.3849 | 1 | 120.8617 |
| santos | `audit` | IF | 1,157 | 0.6837 | 33 | 0.7339 | 2 | 0.7474 |
| santos | `audit` | LOF | 1,157 | 1.0291 | 1 | 1.8723 | 0 | 2.2422 |
| santos | `audit` | PCA | 1,157 | 0.1737 | 51 | 2.1139 | 2 | 16.3246 |
| santos | `auth` | IF | 868 | 0.8136 | **3** | 0.8136 | 3 | 0.8136 |
| santos | `auth` | LOF | 868 | 0.9914 | **139** | 0.9885 | (below calib max) | 1.2870 |
| santos | `auth` | PCA | 868 | 1.3136 | 10 | 5.4032 | 1 | 22.9453 |
| santos | `vpn` | IF | 84 | 0.4067 | 64 | 0.7668 | 0 | 0.7406 |
| santos | `vpn` | LOF | 84 | 0.9838 | 32 | 0.9838 | 32 | 1.0722 |
| santos | `vpn` | PCA | 84 | 0.7676 | 51 | 15.2358 | **2** | 15.2358 |

Do OOF scores behave like scores of unseen windows? Share of each group above the calib maximum, for the thin log types. If they did, the two shares would be close. Eval holds the attack, so if anything its share should be the higher one.

| testbed | log type | model | OOF above | OOF share | eval above | eval share |
|---|---|---|---:|---:|---:|---:|
| RM | `vpn` | IF | 0 of 119 | 0.0% | 7 of 157 | 4.5% |
| RM | `vpn` | LOF | 25 of 119 | 21.0% | 8 of 157 | 5.1% |
| RM | `vpn` | PCA | 4 of 119 | 3.4% | 9 of 157 | 5.7% |
| santos | `apache_access` | IF | 4 of 1,832 | 0.2% | 3 of 5,632 | 0.1% |
| santos | `apache_access` | LOF | 22 of 1,832 | 1.2% | 24 of 5,632 | 0.4% |
| santos | `apache_access` | PCA | 14 of 1,832 | 0.8% | 37 of 5,632 | 0.7% |
| santos | `audit` | IF | 33 of 993 | 3.3% | 49 of 2,730 | 1.8% |
| santos | `audit` | LOF | 1 of 993 | 0.1% | 6 of 2,730 | 0.2% |
| santos | `audit` | PCA | 51 of 993 | 5.1% | 39 of 2,730 | 1.4% |
| santos | `auth` | IF | 3 of 692 | 0.4% | 0 of 1,798 | 0.0% |
| santos | `auth` | LOF | **139 of 692** | **20.1%** | 11 of 1,798 | **0.6%** |
| santos | `auth` | PCA | 10 of 692 | 1.4% | 13 of 1,798 | 0.7% |
| santos | `vpn` | IF | 64 of 77 | 83.1% | 120 of 227 | 52.9% |
| santos | `vpn` | LOF | 32 of 77 | 41.6% | 3 of 227 | 1.3% |
| santos | `vpn` | PCA | 51 of 77 | 66.2% | 64 of 227 | 28.2% |

OOF is the higher share on 11 of 12 santos rows. A likely reason, not tested here: quiet windows repeat a few distinct rows (D31), so holding out a contiguous block makes ordinary rows look new to the fold's models. The `vpn` calib slice is only 7 windows, so its maximum is a weak yardstick.

**Does saturation limit what `q` can separate? Yes, in both directions.**
- Russellmitchell saturates at the top: 22 of 24 flagged windows tie at exactly 1.0, flagged windows hold only 2 distinct scores, and `q` cannot rank them. `audit` goes from 84 at 0.995 to 3 at 0.999 because 80 of the 81 windows between tie at 0.995215.
- Santos saturates under `q`: 98 `dns` windows at 0.998222 and 6 `auth` windows at 0.997696.
- Only 30 distinct scores exist at or above 0.99 on russellmitchell, and 21 on santos. `q` moves across a short ladder, not a continuous scale.

## Q5. Phase view, through `logtriage.eval` (descriptive)

Best window of each counted phase, on any baseline-capable log type. Rank counts windows of that log type scoring strictly higher, plus one. "Tied" counts windows at that same score, including the phase's own.

Santos:

| phase | log type | scored attack windows | best score | below `q` | rank | tied | result |
|---|---|---:|---:|---:|---:|---:|---|
| `service_scans` | `apache_access` | 2 | 0.999826 | passes | 1 of 5,632 | 2 | detected, `santos-0002` |
| `dirb` | `apache_access` | 1 | 0.999826 | passes | 1 of 5,632 | 2 | detected, `santos-0002` |
| `wpscan` | `apache_access` | 2 | 0.999826 | passes | 1 of 5,632 | 2 | detected, `santos-0002` |
| `webshell` | `apache_access` | 3 | 0.999826 | passes | 1 of 5,632 | 2 | detected, `santos-0002` |
| `privilege_escalation` | `audit` | 2 | 0.999712 | passes | 1 of 2,730 | 1 | detected, `santos-0003` |
| `cracking` | `apache_access` | 2 | 0.997737 | 0.001263 | 4 of 5,632 | 2 | **low score** |
| `network_scans` | `dns` | 4 | 0.994667 | 0.004333 | 181 of 5,949 | 75 | **low score** |
| `dnsteal_exfil` | `dns` | 1,441 | 0.986667 | 0.012333 | 306 of 5,949 | 4 | **low score** |
| `service_stop` | `audit` | 1 | 0.770959 | 0.228041 | 67 of 2,730 | 124 | **low score** |

Russellmitchell:

| phase | log type | scored attack windows | best score | below `q` | rank | tied | result |
|---|---|---:|---:|---:|---:|---:|---|
| `service_scans` | `apache_access` | 4 | 1.000000 | passes | 1 of 3,458 | 3 | detected, `russellmitchell-0004` |
| `dirb` | `apache_access` | 2 | 1.000000 | passes | 1 of 3,458 | 3 | detected, `russellmitchell-0004` |
| `wpscan` | `apache_access` | 3 | 1.000000 | passes | 1 of 3,458 | 3 | detected, `russellmitchell-0004` |
| `webshell` | `apache_access` | 2 | 1.000000 | passes | 1 of 3,458 | 3 | detected, `russellmitchell-0004` |
| `privilege_escalation` | `audit` | 4 | 1.000000 | passes | 1 of 1,514 | 3 | detected, `russellmitchell-0006` |
| `cracking` | `apache_access` | 2 | 0.999736 | passes | 4 of 3,458 | 2 | detected, `russellmitchell-0004` |
| `service_stop` | `audit` | 2 | 0.995215 | 0.003785 | 5 of 1,514 | 80 | **low score** |
| `dnsteal_exfil` | `dns` | 2,090 | 0.987493 | 0.011507 | 21 of 4,855 | 11 | **low score** |
| `dnsteal` | `dns` | 3 | 0.977162 | 0.021838 | 80 of 4,855 | 1 | **low score** |
| `network_scans` | `vpn` | 4 | 0.941725 | 0.057275 | 4 of 157 | 2 | **low score** |

Why the missed phases were missed:

| reason | santos | russellmitchell |
|---|---:|---:|
| low score | 4 of 4 | 4 of 4 |
| no window exists | 0 | 0 |
| grouping | 0 | 0 |

- Every flagged eval window belongs to an incident, so grouping cannot lose a phase. Attack windows with no scored window are `apache_error` only (santos 1, russellmitchell 2), and their phases `dirb` and `wpscan` also appear in `apache_access`.
- `cracking` on santos is the near miss. Its window at 11:24 has 12 reference scores above it on IF, 11 of them OOF, and 1 on LOF, where 5 are allowed. That is not evidence against D28: with calib alone, the 1 calib window above it on IF would already cost more than `q` allows. It would also add no incident: it is 2 minutes from `santos-0002`, on the same host.
- The second-best `network_scans` window on santos is `vpn`, rank 4 of 227, score 0.837302. The `vpn` ceiling did not decide this one, since its `pct_lof` is only 0.6190.
- The santos `auth` windows at 11:21 match the 1-line, unseen-template windows flagged at 03:56–03:57 on russellmitchell. There they reach 1.0, here 0.997696. None of them holds a labeled line on either testbed. Four of the five share `172.21.128.119` with `santos-0002`, so those four would join it rather than add incidents.

## Q6. Correctness checks

| check | russellmitchell | santos | result |
|---|---|---|---|
| Period rule D24, recomputed from `periods.json` for every window | 0 of 25,960 differ | 0 of 24,124 differ | pass |
| `scores` and `windows` keys and periods match, no duplicates | 25,944 of 25,944 | 24,112 of 24,112 | pass |
| Fit or calib window in an incident (D30) | 0 of 24 | 0 of 5 | pass |
| Flagged fit or calib windows kept out of incidents | 18 fit, 0 calib, none in an incident | 0, 0 | pass |
| `window_start` type: UTC in `windows`, `scores`, `incidents`, truth | `datetime64[us, UTC]` | `datetime64[us, UTC]` | pass |
| `window_start` on the minute and inside the simulation | 0 off | 0 off | pass |
| Eval truth windows that match a window key | 2,104 of 2,104 | 1,455 of 1,455 | pass |
| `is_anomalous` equals `score >= q`, all rows | 0 differ | 0 differ | pass |
| Scores within 1e-6 of `q`, where rounding could flip a flag | 0 | 0 | pass |
| `score` equals the mean of the three percentiles | max difference 0 | max difference 0 | pass |
| Regrouping saved windows gives `incidents.parquet` | identical | identical | pass |
| `window_keys` equal the flagged eval windows | 24 of 24 | 5 of 5 | pass |
| Grouping shortcut against all pairs, 3 settings per testbed | same partitions | same partitions | pass |
| Common entities recomputed from fit windows | same (`root` in `auth`) | same (`root` in `auth`) | pass |
| Incidents per day | 7 / 1.874 = 3.73 | 3 / 2.697 = 1.11 | pass |

**D29 clip on `dns`.** The unclipped rows are saved outputs of cell 13 of `03_ml_models.ipynb`, read and not executed. Clip shares come from `FeatureScaler.transform` on saved windows, which fits nothing and scores nothing.

| | russellmitchell | santos |
|---|---:|---:|
| `dns` flagged, clipped (primary) | 0 | 0 |
| `dns` flagged, unclipped | 17 | 1,012 |
| of those with a labeled line | 0 | 5 |
| incidents per day, clipped | 3.73 | 1.11 |
| incidents per day, unclipped | 7.47 | 1.11 |
| phases, clipped | 6 of 10 | 5 of 9 |
| phases, unclipped | 6 of 10 | 7 of 9, 2 through `dns` alone |
| fit windows with a clipped value | 3,755 of 4,896 | 2,274 of 3,002 |
| calib windows with a clipped value | 787 of 1,226 | 481 of 750 |
| eval windows with a clipped value | 3,822 of 4,855 | 5,356 of 5,949 |

On santos the tunnel stops at `first_attack`, and all 3,067 `dns` windows after it have a clipped value, against 2,289 of 2,882 before it. The clip does what D29 intended and is not why santos has few incidents.

## Method

Throwaway scripts outside `src/`, not committed. They read `scores.parquet`, `incidents.parquet`, `windows_*.parquet`, `periods.json`, `detect_report.json`, the DNS scaler and `reports/results/tuning_dev.csv`. Labels were read only through `logtriage.eval` (`window_truth`, `with_truth`, `evaluate`, `counted_phases`), with `eval.duckdb` opened read-only. Grouping used `link_windows` and `group_incidents` unchanged. The notebook was read as JSON. No Python file changed, so ruff and pytest were not run. `scores.parquet`, `incidents.parquet` and `eval.duckdb` keep their timestamps from before this audit.

Two santos counts were deliberately not made, because each would be a re-calibration: eval windows above the calib maximum on all three models, and any score against a calib-only reference. Q4 and Q5 read ranks and counts of existing reference scores only, for the top windows.
