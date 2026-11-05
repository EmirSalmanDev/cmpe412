# Status

Keep this file short and current. Update it at the end of every session and at every milestone merge.
Format rules: newest entries first in the logs; numbers with their testbed; link plan sections as §N.

## Now
- **Current milestone:** M2 — Parsing, Drain3, labels (not started)
- **Branch:** —
- **Next step:** Create branch `m2-parse` and do the M2 tasks in plan §13. Read the D11 entry first: it changes how phases and `first_attack` work.
- **Blockers:** none

## Milestones
- [x] M0 Bootstrap
- [x] M1 Data acquisition and inventory
- [ ] M2 Parsing, Drain3, labels
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
- Expected §4.3 boundaries, to confirm in M2: russellmitchell first_attack 2022-01-24 03:01:00, training 51.0h; santos first_attack 2022-01-16 07:16:17, training 31.3h. Fit/calib split not computed yet
- Chosen hyperparameters (q, gap_minutes, LOF k, ...): —
- Disk usage of raw data: 17 GB in `data/raw` (zips 16 GB; extracted russellmitchell 113 MB, santos 148 MB, ait_ads 189 MB). Archives hold 15.0 GB and 17.7 GB unpacked; extraction takes 127 of 14,911 and 121 of 14,908 members
- Real paths: `dataset.yaml` (keys `name`, `start`, `end`); labels at `labels/<host>/logs/<path>`, one per log at `gather/<host>/logs/<path>`; phases in `data/raw/ait_ads/labels.csv`; alerts in `data/raw/ait_ads/<testbed>_{aminer,wazuh}.json`
- Labeled files (8 per testbed): `inet-firewall/logs/dnsmasq.log`, `intranet_server/logs/auth.log`, `intranet_server/logs/audit/audit.log`, `internal_share/logs/audit/audit.log`, `vpn/logs/openvpn.log`, `intranet_server/logs/apache2/intranet.smith.<testbed>.com-{access,error}.log` (with suffix `.2` on russellmitchell, none on santos), `monitoring/logs/logstash/intranet-server/<date>-system.cpu.log`
- Git remote: origin, https://github.com/EmirSalmanDev/cmpe412.git

## Key results
(Add headline numbers per milestone, e.g. "M5 santos: phase recall 7/9, 18 incidents/day".)
- M1 russellmitchell: 118 files, 710,583 lines, 61,862 labeled lines, 53,056 of them `dnsteal`
- M1 santos: 112 files, 860,215 lines, 47,367 labeled lines, 38,563 of them `dnsteal`
- M1 phases: AIT-ADS starts match `attacks.log` within 3 s for the eight foothold-to-escalation phases on both testbeds

## Decision log
Format: `YYYY-MM-DD · Dxx · what changed · why · evidence`. D1–D7 are the approved design decisions in plan §2.
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
- Other labeled log types: only `monitoring/logs/logstash/intranet-server/<date>-system.cpu.log` (49 labeled lines on russellmitchell, 44 on santos, raw labels include `crack_passwords` and `escalate`), left unprocessed. Syslog and Suricata files exist but have no label files.

## Session log
Format: `YYYY-MM-DD · milestone · what was done · next`.
- 2026-11-05 · M1 · Download, selective extraction, inventory, `sources.yaml` and phases files done for both testbeds; plan changed by D8–D11 · Start M2 on `m2-parse`
- 2026-11-05 · M0 · Project config, package skeleton, config loader, CLI stubs, smoke tests, CI, README done; ruff clean, 12 tests pass · Start M1 on `m1-data`
- 2026-11-05 · — · Plan, CLAUDE.md and status.md written · Start M0
