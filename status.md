# Status

Keep this file short and current. Update it at the end of every session and at every milestone merge.
Format rules: newest entries first in the logs; numbers with their testbed; link plan sections as §N.

## Now
- **Current milestone:** M3 — EDA and frozen targets (not started)
- **Branch:** —
- **Next step:** Create branch `m3-eda`, do the M3 tasks in plan §13, and resolve the contaminated-baseline open question there, before targets freeze.
- **Blockers:** none

## Milestones
- [x] M0 Bootstrap
- [x] M1 Data acquisition and inventory
- [x] M2 Parsing, Drain3, labels
- [ ] M3 EDA and frozen targets
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
- ATT&CK version used: —
- Simulation periods (`dataset.yaml`, naive timestamps; dnsmasq lines line up with them as UTC): russellmitchell 2022-01-21 to 2022-01-25, santos 2022-01-14 to 2022-01-18
- §4.3 boundaries (UTC, gap 24h, from `periods.json`): russellmitchell first_attack 2022-01-24 03:01:00, training 51.0h, fit to 01-22 16:48:48, calib to 01-23 03:01:00, eval to 01-25 00:00; santos first_attack 2022-01-16 07:16:17, training 31.3h, fit to 01-15 01:01:01.6, calib to 01-15 07:16:17, eval to 01-18 00:00
- Label line base: 1-based, like `line_no`, on both testbeds. Labeled auth lines start at `Successful su for ...` and VPN lines at `TLS: Initial packet`; under 0-based they would skip those lines and include an unrelated CRON line
- Drain3 throughput (both miners together): russellmitchell 67,222 lines/s (636,526 lines, 9.5 s), santos 68,889 lines/s (776,637 lines, 11.3 s). Slowest type is apache_access at about 37,000–40,000 lines/s; no log type comes near the 1 hour limit
- Processed data: russellmitchell 44 MB, santos 57 MB; `prepare` takes about 20 s per testbed
- Chosen hyperparameters (q, gap_minutes, LOF k, ...): —
- Disk usage of raw data: 17 GB in `data/raw` (zips 16 GB; extracted russellmitchell 113 MB, santos 148 MB, ait_ads 189 MB). Archives hold 15.0 GB and 17.7 GB unpacked; extraction takes 127 of 14,911 and 121 of 14,908 members
- Real paths: `dataset.yaml` (keys `name`, `start`, `end`); labels at `labels/<host>/logs/<path>`, one per log at `gather/<host>/logs/<path>`; phases in `data/raw/ait_ads/labels.csv`; alerts in `data/raw/ait_ads/<testbed>_{aminer,wazuh}.json`
- Labeled files (8 per testbed): `inet-firewall/logs/dnsmasq.log`, `intranet_server/logs/auth.log`, `intranet_server/logs/audit/audit.log`, `internal_share/logs/audit/audit.log`, `vpn/logs/openvpn.log`, `intranet_server/logs/apache2/intranet.smith.<testbed>.com-{access,error}.log` (with suffix `.2` on russellmitchell, none on santos), `monitoring/logs/logstash/intranet-server/<date>-system.cpu.log`
- Git remote: origin, https://github.com/EmirSalmanDev/cmpe412.git

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

## Decision log
Format: `YYYY-MM-DD · Dxx · what changed · why · evidence`. D1–D7 are the approved design decisions in plan §2.
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
- CLAUDE.md is listed in §12 but `~/.gitignore_global` ignores it, so it is not committed and a fresh clone will not have it. It was not force-added. Should it be versioned?
- The §4.3 clean baseline does not exist. DNS exfiltration is in every training hour (russellmitchell 52 of 52 hours, 21.6% of inet-firewall DNS lines; santos 32 of 32, 26.0%), and there is no exfil-free span of at least 24h before the main attack on russellmitchell. Removing it would need labels, so the training period stays as computed. Models will likely learn exfiltration as normal, which may make the dnsteal phase undetectable on the dns family. Decide before targets freeze in M3: accept and report it, or change the DNS approach.
- Exfiltration is only labeled on `inet-firewall/logs/dnsmasq.log`. `inet-dns/logs/dnsmasq.log` holds a similar volume of the same queries (20,009 and 15,345 exfil-shaped queries) with no labels, so true detections there would count as false positives. Decide how M3 and §10 treat that host.
- Gold mapping gap: §11 maps `dnsteal` but not `dnsteal_exfil`, which now holds almost all exfiltration lines. On santos `dnsteal` has no labeled lines, so under D7 it drops out of the recall denominator, and `dnsteal_exfil` has no gold techniques. Decide in M3 how the phase is scored. §10 and §11 were not changed.
- `is_unseen_template` carries no signal for DNS: exfiltration queries match the ordinary `query[A] <*> from <IP>` template, and only 2 DNS lines are unseen on each testbed. This adds to the baseline question; DNS detection will need qname features in M4.
- Stderr lines in Apache error logs have unreliable timestamps. All 3,853 `parse_ok=False` lines of russellmitchell `intranet_server` `error.log.2` carry 01-23 06:25:03 from the line before them, though they hold attacker output such as a `wget` stamped 01-24 03:59:22. Counting them in M4 windows would create a false spike, so M4 should exclude `parse_ok=False` lines. They are also unlabeled, which M3 should cover in its label gap analysis.
- santos `apache_error` has no fit-period lines (first record 01-15 06:25, fit ends 01-15 01:01), so its frozen miner is empty and all 76 lines count as unseen. M4 needs a rule for this before it uses the feature.
- Other labeled log types: only `monitoring/logs/logstash/intranet-server/<date>-system.cpu.log` (49 labeled lines on russellmitchell, 44 on santos, raw labels include `crack_passwords` and `escalate`), left unprocessed. Syslog and Suricata files exist but have no label files.

## Session log
Format: `YYYY-MM-DD · milestone · what was done · next`.
- 2026-11-05 · M2 · Periods, parsers, Drain3, `labels.parquet`, DuckDB files and `prepare` done for both testbeds; plan changed by D12–D13 · Start M3 on `m3-eda`
- 2026-11-05 · M1 · Download, selective extraction, inventory, `sources.yaml` and phases files done for both testbeds; plan changed by D8–D11 · Start M2 on `m2-parse`
- 2026-11-05 · M0 · Project config, package skeleton, config loader, CLI stubs, smoke tests, CI, README done; ruff clean, 12 tests pass · Start M1 on `m1-data`
- 2026-11-05 · — · Plan, CLAUDE.md and status.md written · Start M0
