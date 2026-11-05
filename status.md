# Status

Keep this file short and current. Update it at the end of every session and at every milestone merge.
Format rules: newest entries first in the logs; numbers with their testbed; link plan sections as §N.

## Now
- **Current milestone:** M4 — Windows and features (in progress)
- **Branch:** `m4-features`
- **Next step:** Create branch `m4-features`. Before writing any M4 code, extend the §5.2 isolation scan to cover `logtriage.eval`, `logtriage.prepare`, `label_report` and `first_attack` references. Then: exclude `parse_ok=False` lines from windows and features (D14); drop vocabulary and "unseen" features per D15; run `SET TimeZone='UTC'` on every DuckDB connection; add DNS qname features, because `is_unseen_template` has no DNS signal (only 2 unseen DNS lines per testbed).
- **Blockers:** none

## Milestones
- [x] M0 Bootstrap
- [x] M1 Data acquisition and inventory
- [x] M2 Parsing, Drain3, labels
- [x] M3 EDA and frozen targets
- [ ] M4 Windows and features
- [ ] M5 Anomaly detection and incidents
- [ ] M6 Supervised reference
- [ ] M7 ATT&CK index and agent tools (may start after M2)
- [ ] M8 Agent graph
- [ ] M9 Chat, dashboard, replay
- [ ] M10 Docker
- [ ] M11 Evaluation
- [ ] M12 Stretch (optional)
- [ ] M13 Finalize

## Recorded facts
Fill these in when they are known; they are referenced by plan §7.1, §8.1 and §15.
- LLM model string (verified): —
- LLM prices per 1M tokens (verified, date): —
- ATT&CK version used: 20.1 (`data/raw/attack/enterprise-attack.json`, sha256 `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`, downloaded 2026-11-05 from `attack-stix-data` master; M7 should reuse this file)
- Simulation periods (`dataset.yaml`, naive timestamps; dnsmasq lines line up with them as UTC): russellmitchell 2022-01-21 to 2022-01-25, santos 2022-01-14 to 2022-01-18
- §4.3 boundaries (UTC, gap 24h, from `periods.json`): russellmitchell first_attack 2022-01-24 03:01:00, training 51.0h, fit to 01-22 16:48:48, calib to 01-23 03:01:00, eval to 01-25 00:00; santos first_attack 2022-01-16 07:16:17, training 31.3h, fit to 01-15 01:01:01.6, calib to 01-15 07:16:17, eval to 01-18 00:00
- Label line base: 1-based, like `line_no`, on both testbeds. Labeled auth lines start at `Successful su for ...` and VPN lines at `TLS: Initial packet`; under 0-based they would skip those lines and include an unrelated CRON line
- Drain3 throughput (both miners together): russellmitchell 67,222 lines/s (636,526 lines, 9.5 s), santos 68,889 lines/s (776,637 lines, 11.3 s). Slowest types (`apache_access`, `apache_error`, `audit`) run at about 35,000–41,000 lines/s; no log type comes near the 1 hour limit
- Processed data: russellmitchell 44 MB, santos 57 MB; `prepare` takes about 20 s per testbed
- Chosen hyperparameters (q, gap_minutes, LOF k, ...): —
- Disk usage of raw data: 17 GB in `data/raw` (zips 16 GB; extracted russellmitchell 113 MB, santos 148 MB, ait_ads 189 MB). Archives hold 15.0 GB and 17.7 GB unpacked; extraction takes 127 of 14,911 and 121 of 14,908 members
- Real paths: `dataset.yaml` (keys `name`, `start`, `end`); labels at `labels/<host>/logs/<path>`, one per log at `gather/<host>/logs/<path>`; phases in `data/raw/ait_ads/labels.csv`; alerts in `data/raw/ait_ads/<testbed>_{aminer,wazuh}.json`
- Labeled files (8 per testbed): `inet-firewall/logs/dnsmasq.log`, `intranet_server/logs/auth.log`, `intranet_server/logs/audit/audit.log`, `internal_share/logs/audit/audit.log`, `vpn/logs/openvpn.log`, `intranet_server/logs/apache2/intranet.smith.<testbed>.com-{access,error}.log` (with suffix `.2` on russellmitchell, none on santos), `monitoring/logs/logstash/intranet-server/<date>-system.cpu.log`
- Git remote: origin, https://github.com/EmirSalmanDev/cmpe412.git
- Frozen targets: the reference is tag `targets-frozen` (`3684424`), not `m3-done`; M11 must repeat the freeze reference note from the Decision log in `reports/results.md`

## Key results
(Add headline numbers per milestone, e.g. "M5 santos: phase recall 7/9, 18 incidents/day".)
- M1 russellmitchell: 118 files, 710,583 lines, 61,862 labeled lines, 53,056 of them `dnsteal`
- M1 santos: 112 files, 860,215 lines, 47,367 labeled lines, 38,563 of them `dnsteal`
- M2 parse rate: 100% of log records in every file (russellmitchell 82 files, santos 74). Left out of the rate (D12): 4,757 and 4,717 stderr lines, 6 blank lines each
- M2 lines kept in the simulation interval: russellmitchell 641,289 of 680,172; santos 781,360 of 818,897
- M2 labels: 100% resolve to a parsed line (russellmitchell 61,813, santos 47,323; 49 and 44 `system.cpu` labels skipped as out of scope). 100% in a phase using the committed rows, on every labeled file
- M2 labeled lines per phase, russellmitchell: dnsteal_exfil 53,006, dirb 4,493, wpscan 3,207, network_scans 538, service_scans 455, dnsteal 38, webshell 31, privilege_escalation 17, cracking 16, service_stop 12
- M2 labeled lines per phase, santos: dnsteal_exfil 38,561, dirb 4,485, wpscan 3,314, network_scans 558, service_scans 327, privilege_escalation 31, webshell 29, cracking 16, service_stop 2
- M2 templates, frozen/online: russellmitchell apache_access 19/27, apache_error 8/15, audit 14/16, auth 15/23, dns 11/12, vpn 25/29; santos 17/27, 0/16, 12/15, 5/24, 10/11, 27/29
- M1 phases: AIT-ADS starts match `attacks.log` within 3 s for the eight foothold-to-escalation phases on both testbeds
- M3 frozen targets (`reports/targets.md`, santos evaluation period): phase recall ≥ 80% (≥ 8 of 9 phases), ≤ 25 incidents/day (≤ 67 in 2.697 days) and ≥ 90% fewer than raw IDS alerts, ATT&CK top-3 strict ≥ 70%, manual faithfulness ≥ 90% and higher than without the Verifier. All unchanged from §10.5
- M3 phases with traces: russellmitchell 10, santos 9 (primary, equal to the all-parsed variant; without `dnsteal_exfil` 9 and 8). Excluded: `reverse_shell` on both, `dnsteal` on santos. No phase depends only on a log type without a baseline
- M3 baseline-capable: every log type except `apache_error`, on both testbeds
- M3 attack share of parsed lines, evaluation period: russellmitchell 9.86%, santos 4.65%; without exfiltration 3.09% and 1.65% (31 and 60 normal lines per attack line)
- M3 label gap: unlabeled exfiltration on `inet-dns` 53,052 and 38,559 lines; unlabeled attacker-address lines inside phase windows 50–513 and 2–625 (low: external address, high: adds the shared tunnel address); unlabeled attacker stderr lines 3,847 on each testbed
- M3 DNS contamination of training: 21.6% and 26.0% of `inet-firewall` DNS lines (hourly up to 45.5% and 90.2%), in every training hour
- M3 IDS alerts/day in the evaluation period: russellmitchell 15,704, santos 30,774. Budget 25 incidents/day, so a reduction of 99.84% and 99.92%
- M2 audit: 7 of 9 items passed; item 8 (1 missing plan marker) and item 9 (2 parser bugs) failed and are fixed; 193 tests pass; `line_no` right on all 1,422,649 rows; see `reports/audit_m2.md`

## Decision log
Format: `YYYY-MM-DD · Dxx · what changed · why · evidence`. D1–D7 are the approved design decisions in plan §2.
- 2026-11-05 · M4 · D22 · The §5.2 scan also rejects references to `logtriage.eval`, `logtriage.prepare` (including `from logtriage import eval` and relative imports), `label_report` and `first_attack`; §5.2 updated · These reach ground truth or attack timing without using the words `labels` or `phases`: `Periods.first_attack` is one attribute away in any module that reads `periods.json` · `tests/test_isolation.py`; no scanned module had such a reference
- 2026-11-05 · M3 · Freeze reference clarified · The freeze is the content of `reports/targets.md` at `3684424`. Commit `0ae17bf` changed only line 3 (`PENDING` replaced by the hash); no target number or definition changed. Tag `m3-done` is on merge commit `cad7b1f`, which contains the freeze but does not point at it. New tag `targets-frozen` points at `3684424` · `git diff 3684424 m3-done -- reports/targets.md` shows one line
- 2026-11-05 · M3 · D17 · Windows of log type `dns` on host `inet-dns` are label-ambiguous, and so is an incident with such a window and no attack window. Primary window-level and incident-level metrics (false positives, verdict confusion matrix) leave them out, a secondary number includes them, and phase recall is unaffected; §10.1 and §10.2 updated · That host holds the same exfiltration with no labels, so true detections there would count as false positives · By domain match, 53,052 and 38,559 unlabeled exfiltration lines on `inet-dns`; the same match on `inet-firewall` agrees with the labels exactly (0 false matches, 0 misses)
- 2026-11-05 · M3 · D21 · All preliminary targets of §10.5 are kept and frozen in `reports/targets.md`; §10.5 updated · The EDA found no target that cannot be measured: every counted phase has labeled lines in a baseline-capable log type, and IDS data covers both evaluation periods · Smallest counted phases: santos `service_stop` 2 lines, `cracking` 16
- 2026-11-05 · M3 · D20 · The incidents/day budget stays at 25, in `ml.incidents_per_day_budget`; §10.5 updated · "≥ 90% fewer" needs incidents/day ≤ 0.1 × alerts/day, and 25 is far below that, so the evidence gives no reason to move the default. No detection result was used · Raw alerts in the evaluation period: russellmitchell 29,435 in 1.874 days = 15,704 per day (limit 1,570), santos 82,998 in 2.697 days = 30,774 per day (limit 3,077). Even AMiner alone allows 195 and 139
- 2026-11-05 · M3 · "Phases with traces" counts labeled lines in the evaluation period, not the whole simulation · §10 scores the evaluation period, so a phase seen only in training could not be detected · Same result either way today: 10 and 9 phases
- 2026-11-05 · M3 · Incidents/day and alert reduction count label-ambiguous incidents · An analyst still reads them, and D17 names only false positives and the verdict matrix · `reports/targets.md`
- 2026-11-05 · M3 · The label-gap estimate has a low and a high end · The tunnel address comes from the VPN pool: it has 39,147 and 38,795 unlabeled lines outside phase windows, so it also serves ordinary users; only the attacker's external address is specific · `01_eda.ipynb` §6.2
- 2026-11-05 · M3 · Downloaded `enterprise-attack.json` to `data/raw/attack/`, ahead of M7 · The gold IDs had to be checked before the freeze · ATT&CK 20.1, sha256 `539a843a...b910b5`
- 2026-11-05 · M3 · D16 · Training is not cleaned with labels or attacker information (§5.2); §4.3 stays as computed and the contamination is a documented limitation. DNS results are reported separately in M5 and M11, and phase recall also in a secondary variant without `dnsteal_exfil`. The primary definition in §10.2 is unchanged; §4.3 and §10.2 updated · Cleaning would need labels, and no exfil-free span of 24 h exists · Exfiltration share of `inet-firewall` DNS lines in training: russellmitchell 21.6% (hourly 7.1–45.5%, 52 of 52 hours), santos 26.0% (hourly 8.6–90.2%, 32 of 32 hours); calib is worse than fit, 31.1% and 47.8%
- 2026-11-05 · M3 · D18 · `configs/gold_attack_mapping.yaml` written: `dnsteal_exfil` takes the set of `dnsteal` (T1048.003, T1048, T1071.004), and `vpn_access` is dropped. Phases with no labeled line in the counted log types are left out of the recall denominator and named in `reports/targets.md`; §11 updated · Exfiltration holds almost all `dnsteal` lines but had no gold set. `vpn_access` is not in the phases files, because §5.3 adds it only for unassigned VPN lines · 0 unassigned lines on both testbeds; all 16 gold IDs exist and are neither revoked nor deprecated in ATT&CK 20.1
- 2026-11-05 · M3 · The 28 attacker VPN lines per testbed stay in `network_scans`, whose gold set stays T1046, T1018 without T1133 or T1078 · Adding them would make the frozen ATT&CK target easier without new evidence · A VPN-only incident is scored against `network_scans`, stated in `reports/targets.md`
- 2026-11-05 · M3 · D19 · Extends D15. A `(testbed, log_type)` is baseline-capable only with at least `min_fit_lines` (200) parsed fit lines and `min_calib_lines` (50, new in `configs/default.yaml`) parsed calib lines; other types are left out of ensemble and incidents as "no baseline, not detectable" and stay in parsed data and agent tools. The D7 denominator uses baseline-capable log types; §6.4 and §10.1 updated · D15 covered only zero fit-period windows, so russellmitchell `apache_error` could be fit but never calibrated · Full table from the data: every log type passes on both testbeds except `apache_error` (russellmitchell 13 fit, 0 calib; santos 0 fit, 10 calib); the next lowest calib count is 147 (santos `vpn`)
- 2026-11-05 · M3 · `CLAUDE.md` is versioned with `git add -f`, because `~/.gitignore_global` ignores it · §12 lists it and a fresh clone needs it; checked first for secrets and personal paths · `a8c96f8`
- 2026-11-05 · M2 audit · Fixed: `status.md` said `apache_access` is the slowest Drain3 type; corrected in Recorded facts · The claim did not match the report · `prepare_report.json`: `audit` 36,193 lines/s on russellmitchell, `apache_error` 34,797 on santos
- 2026-11-05 · M2 audit · Fixed: §4.3 lacked the D9 marker that §14.3 requires · D9 names §4.2 and §4.3 · `cb2a524`
- 2026-11-05 · M2 audit · Fixed: Apache error microseconds were truncated by float arithmetic · §5.1 keeps the event time · `44f48e4`; 1 santos line moved by 1 µs, everything else identical, santos regenerated
- 2026-11-05 · M2 audit · Fixed: impossible timestamps raised in the Apache, OpenVPN and audit parsers and aborted `prepare`; such lines are now `parse_ok=False` · §6.1 keeps unparseable lines · `a1cfbe6`; no line in either testbed triggers it, so data did not change
- 2026-11-05 · M2 audit · D15 · Vocabulary, rarity and "unseen" features are dropped for a `(testbed, log_type)` with fewer than `min_fit_lines` (200, `configs/default.yaml`) parsed fit-period lines. With zero fit-period windows no anomaly model is fit: the type is left out of ensemble and incidents, reported as "no baseline, not detectable", and kept in parsed data and agent tools. The D7 "phases with traces" denominator is computed over log types with a fitted baseline, excluded phases are listed in `reports/targets.md`, and the variant over all parsed log types is secondary; §6.3, §6.4 and §10.1 updated · A vocabulary from almost no lines marks nearly everything unseen, and an empty frozen miner gives `template_rarity` = inf · Below 200 today: russellmitchell `apache_error` 13 lines, santos `apache_error` 0 (76 of 76 lines unseen, rarity inf). No phase depends only on santos `apache_error`: its `dirb` and `wpscan` lines also appear in `apache_access`
- 2026-11-05 · M2 audit · D14 · Lines with `parse_ok=False` stay in `lines_*.parquet` but are excluded from windows and features (M4). M7 `log_search` must not surface those whose `ts` was inherited, or must clearly mark them; §5.1, §5.4, §6.3 and M7 in §13 updated · Their timestamps are unreliable, and counting them would create a false spike · russellmitchell 4,763 such lines carry only 3 distinct `ts`, santos 4,723 carry 4; 3,853 lines of intranet_server `error.log.2` share 01-23 06:25:03 though they hold attacker output stamped 01-24 03:59:22
- 2026-11-05 · M2 · D13 · For lines labeled `dnsteal`, `dnsteal_exfil` is tried first, but an interval containing `ts` always beats the ±60 s tolerance; §5.3 updated · D11 left the order open. Applying the tolerance to the exfil row first took the `exfiltration-service` audit lines away from `service_stop`, leaving that phase empty · `service_stop` had 0 labeled lines, now 12 on russellmitchell and 2 on santos
- 2026-11-05 · M2 · D12 · Parse rate counts log records only: blank lines and Apache error log text not starting with `[` stay `parse_ok=False` but are counted separately; their template columns are null; §5.1 and §6.1 updated · That text is process stderr with no timestamp, not an Apache record, and it is most of 7 error log files (rates 0.05–1.2% otherwise). A line starting with `[` that fails still counts against the rate, so format errors are not hidden · `prepare_report.json`; intranet_server `error.log.2` has 3,847 such lines in 3,856
- 2026-11-05 · M2 · `src/logtriage/prepare.py` runs the pipeline and `parsers/common.py` holds shared parser code; §12 updated · `prepare` must call `labels.py`, and a module under `data/` that did would fail the §5.2 scan · plan §5.2
- 2026-11-05 · M2 · `build_eval_db` lives in `labels.py`, while `store.py` only builds `agent.duckdb` · Keeps every reference to ground truth inside an allowed module · `tests/test_isolation.py`
- 2026-11-05 · M2 · Added `pytz` · DuckDB needs it to return `TIMESTAMPTZ` values to Python, so any reader of `ts` would crash · ModuleNotFoundError when fetching `ts`
- 2026-11-05 · M2 · `labels.parquet` holds the six processed log types only · `system.cpu` lines are not parsed, so their labels cannot resolve to a `line_id` · `skipped_files` in `label_report.json`
- 2026-11-05 · M2 · Period settings (`gap_hours`, `min_training_hours`, `fallback_gap_hours`, `fit_fraction`) are in `configs/default.yaml` · M3 may need to change them without code edits · plan §4.3
- 2026-11-05 · M2 · Drain3 uses `full_search_strategy="fallback"` for frozen matching, and miners start empty on every run · Otherwise fit lines could be reported as unseen, and old state could change ids · 0 unseen fit lines; same template digests across three runs of each testbed
- 2026-11-05 · M1 · D11 · Phases files keep the AIT-ADS rows as published and add a `dnsteal_exfil` row from `dnsteal.log`, which applies only to lines labeled `dnsteal`; `first_attack` ignores that row, so §4.3 boundaries are the same as with the published rows; §4.3 and §5.3 updated · The published `dnsteal` interval misses the exfiltration, and with the row in `first_attack` the training period would be empty because exfiltration starts before sim start · Labeled DNS lines inside a phase ±60 s: russellmitchell 3.8% published, 100% with the row; santos 2.2%, 100%. Attacker received data 2022-01-20 12:48 to 01-24 13:50 and 2022-01-13 13:20 to 01-16 07:16
- 2026-11-05 · M1 · D10 · `inventory.py` may report aggregate label counts through `labels.py`, and `download.py` may name `labels/` paths; §5.2 updated · M1 requires label counts in the inventory and extraction of label files, which the §5.2 source scan would otherwise reject · plan §13 M1
- 2026-11-05 · M1 · D9 · The metadata file is `dataset.yaml`, not `dataset.yml`; §4.2 and §4.3 updated · Name used as it is in the archive · zip listings of both testbeds
- 2026-11-05 · M1 · D8 · Phase intervals are in `labels.csv`, a separate file in Zenodo record 8263181, not inside `ait_ads.zip`; §4.1 and §5.3 updated · The zip holds only alert files · Zenodo API and zip listing
- 2026-11-05 · M1 · Cross-check compares `service_stop` with the last chunk received as well as with `dnsteal_stop` · `dnsteal_stop` is the attacker's listener shutting down, not the victim stopping: santos is 26.5h away from `service_stop`, the last chunk 12 s; both rows stay in the report · `reports/inventory_santos.md`
- 2026-11-05 · M1 · `logtriage inventory` also writes the phases file instead of a ninth command · §9.3 lists eight commands and inventory already reads the same inputs · plan §9.3
- 2026-11-05 · M1 · Only the russellmitchell and santos alert files are extracted from `ait_ads.zip`, and `traffic.json` is skipped on attacker_0 · The zip holds all eight scenarios (2.9 GB unpacked); `traffic.json` is up to 545 MB and not needed for phase timing · zip listings
- 2026-11-05 · M1 · `logstash/*system.auth.log` on monitoring is left out of `auth` · It is a forwarded copy of host logs and is not labeled · zip listings
- 2026-11-05 · M1 · Added `certifi` and verify TLS against it · This Python build has no CA store, so Zenodo requests failed with CERTIFICATE_VERIFY_FAILED; verification stays on · first download attempt
- 2026-11-05 · M0 · Ruff excludes `*.md` · ruff 0.17 formats Python blocks in Markdown, so `ruff format .` rewrote the §5.7 block in plan.md; the change was restored before any commit and plan.md is unchanged
- 2026-11-05 · M0 · `.gitignore` adds `!src/logtriage/data/` after the required `data/` entry · `data/` matches at any depth and would have ignored the package from §12
- 2026-11-05 · M0 · Added `pydantic-settings`, which is not in the §3 list · The config loader needs Pydantic settings with `.env` support
- 2026-11-05 · M0 · Precedence is environment, `.env`, YAML, defaults; overrides use `LOGTRIAGE_` with `__` for nesting; `load_settings` drops any API key found in YAML · §3 asks for env overrides but sets no naming; the key must come only from env
- 2026-11-05 · M0 · CLI defaults are `--testbed russellmitchell` and `--config configs/default.yaml`, relative to the repo root · Dev testbed is the safe default
- 2026-11-05 · D1–D7 · Approved before development (window key, VPN, calibrated ensemble, gap grouping, Drain3 + line_id + UTC, deterministic supervisor + validated LLM outputs, gold mapping sets + metric definitions) · Proposal review · plan §2

## Open questions
(Things that need a human decision. Keep working on other parts meanwhile.)
- M7, label isolation: a read-only connection to `agent.duckdb` can still read `labels.parquet` and `phases_*.csv` with `read_parquet` and `read_csv` (61,813 and 47,323 rows returned). The planned SQL guard list does not stop a plain `SELECT` from a table function. Nothing leaks yet because no agent exists. Decide the guard before M7 tools are written, e.g. block file-reading functions or allow only the views.
- M5, calibration: the santos calib period is 01:01–07:16 UTC, so it holds quiet hours only: `apache_access` 253 lines/h against 2,430 in eval, `dns` 2,862 against 5,668. Percentiles calibrated there may flag normal daytime traffic. Decide in M5 whether the §4.3 split stands, without using labels.
- M10: DuckDB views use paths relative to the repository root, so Docker and the app must run from there or rebuild the views.
- Other labeled log types: only `monitoring/logs/logstash/intranet-server/<date>-system.cpu.log` (49 labeled lines on russellmitchell, 44 on santos, raw labels include `crack_passwords` and `escalate`), left unprocessed. Syslog and Suricata files exist but have no label files.

## Session log
Format: `YYYY-MM-DD · milestone · what was done · next`.
- 2026-11-05 · M3 · `01_eda.ipynb`, `logtriage.eval` EDA and IDS code, gold mapping and `reports/targets.md` done; budget fixed at 25; targets frozen; plan changed by D16–D21; `CLAUDE.md` versioned · Start M4 on `m4-features`
- 2026-11-05 · M2 audit · Audited M1 and M2 (`reports/audit_m2.md`), fixed 2 parser bugs, a plan marker and a status claim, recorded D14–D15, added 6 open questions · Start M3 on `m3-eda`
- 2026-11-05 · M2 · Periods, parsers, Drain3, `labels.parquet`, DuckDB files and `prepare` done for both testbeds; plan changed by D12–D13 · Start M3 on `m3-eda`
- 2026-11-05 · M1 · Download, selective extraction, inventory, `sources.yaml` and phases files done for both testbeds; plan changed by D8–D11 · Start M2 on `m2-parse`
- 2026-11-05 · M0 · Project config, package skeleton, config loader, CLI stubs, smoke tests, CI, README done; ruff clean, 12 tests pass · Start M1 on `m1-data`
- 2026-11-05 · — · Plan, CLAUDE.md and status.md written · Start M0
