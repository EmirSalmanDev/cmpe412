# Audit of M1 and M2

Date: 2026-11-05. Audited: `main` at `1216a0d` (tag `m2-done`). Final numbers were re-measured on branch `m2-audit` after the fixes below.

Everything here was recomputed from the raw files, `lines_*.parquet` and the label files, not read from `status.md` or `prepare_report.json`. Phase assignment and parse rates were written again from the plan text, so they do not reuse the code under audit. The frozen miner check does reuse `make_miner`, because it has to build the same miner.

Scope note: of plan §13, only the M7 entry was read, because decision A edits it. Item 4 checks the list in the audit request, not the M2 entry of §13.

## Summary

| # | Item | Result |
|---|---|---|
| 1 | Tests, ruff, CLI | PASS |
| 2 | Git hygiene | PASS |
| 3 | M1 outputs | PASS |
| 4 | M2 acceptance | PASS (with D12; 7 files are below 99% without it) |
| 5 | Determinism | PASS |
| 6 | Label isolation | PASS as specified; see risk R1 |
| 7 | Frozen miner and split | PASS |
| 8 | Plan changes D8–D13 | FAIL, 1 missing marker, fixed |
| 9 | Other risks | FAIL, 2 code bugs fixed, 1 wrong status claim corrected, 6 risks open |

7 passed, 2 failed. Both failures are fixed; the open risks are in `status.md` under Open questions.

## 1. Tests, ruff, CLI: PASS

| Command | On `main` | After fixes |
|---|---|---|
| `uv run pytest -m "not live"` | 184 passed | 193 passed |
| `uv run ruff check .` | clean | clean |
| `uv run ruff format --check .` | 58 files formatted | 58 files formatted |
| `uv run logtriage --help` | exit 0, 8 commands | same |

26 of the 184 tests are marked `data`, and they ran. CI uses `-m "not live and not data"`, which is right for a runner without `data/`.

## 2. Git hygiene: PASS

- Tags `m0-done` (`e63018e`), `m1-done` (`6aba23b`), `m2-done` (`1216a0d`) exist locally and on `origin`.
- `main` was clean and equal to `origin/main` by `git ls-remote`.
- Largest blob in all history: `uv.lock`, 438,672 bytes. Blobs over 5 MB: 0.
- Nothing under `data/` (other than the `src/logtriage/data/` package), no `.env`, `*.parquet`, `*.duckdb`, `*.sqlite` or `*.zip`, in the tree or in any commit.
- Secret patterns (`sk-`, AWS, GitHub, Slack, private keys, quoted `api_key`/`token`/`password` values): no hit in the tree or in any commit. `.env` is ignored and was not opened.
- `CLAUDE.md` is not tracked, because `~/.gitignore_global` ignores it. This is the known open question.

## 3. M1: PASS

- `reports/inventory_russellmitchell.md` and `reports/inventory_santos.md` exist: 118 files, 710,583 lines, 61,862 labeled; 112 files, 860,215 lines, 47,367 labeled. Both match `status.md`, as does the 53,056 and 38,563 `dnsteal` count.
- Coverage: all 8 label files per testbed map to a log family or to `other_labeled`, none is unmapped, and each has its log on disk. All 82 and 74 family files in the zips are extracted, none is compressed, and none is under `attacker_0`.
- Family-like names outside `sources.yaml`: 18 per testbed, all unlabeled: `horde-*` application logs and the `logstash/*system.auth.log` copies (the latter a logged M1 decision).
- Phases: the 10 published rows per testbed equal `labels.csv` exactly. The `dnsteal_exfil` row equals the first and last `Received data` event in `dnsteal.log`. Phase starts are within 2.4 s of `attacks.log` for the eight foothold-to-escalation phases on both testbeds. `service_stop` is 12.0 s after the last chunk on santos and 34.8 s on russellmitchell. The santos `dnsteal_stop` mismatch (-95,505 s) is explained in the inventory: it is the attacker's listener.
- MD5: `parse_record`, `md5_file`, `is_valid_download` and `download_file` exist, and a mismatch raises `ChecksumError`. Tests cover the bad checksum and the skip of a valid copy. The zips were not hashed again.
- Selective extraction: `select_members` gives 127 of 14,911 and 121 of 14,908 members, as logged.

## 4. M2 acceptance: PASS

| Check | russellmitchell | santos |
|---|---|---|
| Rows in `lines_*.parquet` | 641,289 of 680,172 | 781,360 of 818,897 |
| Files processed / with rows | 82 / 69 | 74 / 67 |
| Lowest parse rate with D12 | 100% | 100% |
| Files below 99% without D12 | 3 | 4 |
| Left out by D12: stderr / blank | 4,757 / 6 | 4,717 / 6 |
| Other failed lines (log types other than `apache_error`, or starting with `[`) | 0 | 0 |
| Labels in scope | 61,813 | 47,323 |
| Labels resolved to a parsed line | 100% | 100% |
| Labeled lines with `parse_ok=False` | 0 | 0 |
| `labels.parquet` rows differing from the recomputation | 0 | 0 |
| Inside a phase, strict interval | 61,803 (99.98%) | 47,323 (100%) |
| Inside a phase, ±60 s | 100% | 100% |
| Inside a published phase ±60 s, without the D11 row | 15.9% | 18.5% |
| `line_no` wrong, every row against the raw file | 0 of 641,289 | 0 of 781,360 |
| `sed` spot checks | 72 of 72 (12 per log type) | 72 of 72 |
| `sed` spot checks after a blank line | 12 of 12 | 12 of 12 |
| Rows outside `[sim_start, sim_end)` | 0 | 0 |
| Null or non-UTC `ts` | 0 | 0 |

- **Parse rate.** The 13 and 7 files without rows are empty files. Without D12 the rate falls to 0.05–1.24% on these 7 files, which hold almost only stderr; the appendix has every file. The rate is the same on whole files, including lines outside the simulation.
- **D12 was not hiding format errors.** No line starting with `[` failed, and the 6 stderr lines per testbed with a time-like string are `wget` and password-cracking output, not records.
- **Phase check.** The ≥95% target is met only because of the D11 row, since most labeled lines are exfiltration. This is as D11 describes.
- **Line base.** Labels are 1-based. No label has line 0 or runs past the file end. The attacker's IP is on 100% of labeled lines of the Apache and VPN files as 1-based, and on 96.4–99.97% as 0-based. Under 0-based, one russellmitchell Apache error label would point past the file end. Labeled runs start at `Successful su for ...` and `TLS: Initial packet`, as `status.md` says.
- **File with empty lines.** `intranet_server` `error.log.2` (russellmitchell) and `error.log` (santos), blank at lines 16, 1102, 1104, 1110, 3844, 3846.
- **Time zones.** `auth` agrees with `audit` epochs at offset 0 on all 7 hosts with both, per testbed. All Apache access offsets are `+0000`. `apache_error` and `vpn` share too few seconds with `audit` for that test, so they rest on the phase check, which they pass at 100%.

## 5. Determinism: PASS

`prepare` ran twice into scratch directories for each testbed, with `PYTHONHASHSEED` 101 and 202. `template_digest` and a hash over `line_id`, `template_id`, `template`, `is_unseen_template` and `template_rarity` were equal between the runs and equal to the stored data, for all six log types.

## 6. Label isolation: PASS

- `agent.duckdb` holds 7 views (`lines` and six `lines_*`), no tables. No name or view SQL mentions labels, phases or eval, and the 17 columns are those of §5.1. `eval.duckdb` adds `labels` and `phases`.
- The test scans `data`, `ml`, `agents`, `rag`, `app`, with the §5.2 exceptions. 21 planted references (3 patterns in `data/`, `data/parsers/`, `ml/`, `agents/`, `rag/`, `app/` and an `agents/*.md` prompt) all made it fail. Probe files were removed and `git status` was clean.
- `periods.py` reads only `dataset.yaml` and the phases passed to it, and uses only the `start` of rows with source `ait_ads:labels.csv`. `prepare.py` gives it `read_phases_csv` output. No label file is read.

The checks asked for pass, but the isolation is weaker than they suggest. See R1 and R2.

## 7. Frozen miner and split: PASS

- Code: `add_templates` trains the frozen miner only on rows with `ts < fit_end`, and matches with `match()`, which does not update it.
- Sample: each miner was rebuilt from fit rows alone, then every parsed row of all 12 `(testbed, log_type)` pairs was compared: 0 differences in `is_unseen_template`, 0 in `template_rarity`. `N_fit` in the miner equals the fit row count, and 0 fit lines are unseen.
- Split: fit share of training is 0.8 on both testbeds, by time (russellmitchell 40.8 h + 10.2 h, santos 25.0 h + 6.3 h). `first_attack`, `eval_start` and `train_end` match a recomputation from `dataset.yaml` and the phases.
- Calibration sees unseen lines as designed: russellmitchell `apache_access` has 4 in calib and 7,738 in eval.

| Parsed lines fit/calib/eval | russellmitchell | santos |
|---|---|---|
| apache_access | 40,217 / 7,933 / 55,187 | 51,221 / 1,581 / 157,319 |
| apache_error | 13 / 0 / 82 | 0 / 10 / 66 |
| audit | 8,372 / 1,384 / 8,984 | 5,956 / 1,001 / 17,085 |
| auth | 2,283 / 544 / 2,492 | 1,375 / 352 / 3,587 |
| dns | 231,943 / 34,904 / 236,651 | 146,692 / 17,898 / 366,872 |
| vpn | 2,291 / 439 / 2,807 | 1,395 / 147 / 4,080 |

## 8. Plan changes D8–D13: FAIL, fixed

All six are in the Decision log and the code matches the text: D8 `intervals_file`; D9 `dataset.yaml`; D10 the allow list, with `inventory.py` using `labels.py` only; D11 the `published_source` filter and the exfil row; D12 `blank`, `foreign` and null template columns; D13 `assign_phase`.

| Decision | Sections it names | Marker |
|---|---|---|
| D8 | §4.1, §5.3 | present |
| D9 | §4.2, §4.3 | **§4.3 missing, added in `cb2a524`** |
| D10 | §5.2 | present |
| D11 | §4.3, §5.3 | present |
| D12 | §5.1, §6.1 | present |
| D13 | §5.3 | present |

No stale `dataset.yml` remains outside the D9 log entry.

## 9. Other findings: FAIL, fixed where clear

### Fixed

1. **`a1cfbe6`: an impossible timestamp aborted `prepare`.** The Apache, OpenVPN and audit parsers raised on dates that fit the line shape but do not exist, such as `[99/Jan/2022:...`. §6.1 keeps such lines as `parse_ok=False`, and `auth` and `dns` already did. No line in either testbed triggers it, so data did not change. 8 test cases added.
2. **`44f48e4`: Apache error microseconds were truncated.** `float(".500624") * 1e6` gives 500623. One santos line was 1 µs early. A scratch rebuild showed exactly that one `ts` changing, every other column and `labels.parquet` identical. santos was regenerated. 1 test added.
3. **`status.md`: wrong throughput claim.** It said `apache_access` is the slowest type. `prepare_report.json` shows `audit` at 36,193 lines/s on russellmitchell and `apache_error` at 34,797 on santos, with `apache_access` at 37,319 and 40,007. Corrected. All other M1 and M2 numbers in `status.md` that were checked are right, including the 21.6% and 26.0% exfiltration share.

### Clean

No duplicate `line_id`, no `attacker_0` rows, no raw text repeated across rotated files of a host, no compressed files, no U+FFFD. One backward time step over 60 s in a file (santos `apache_access`) and none over 1 h. Hosts without rows have no in-scope logs: client hosts, `attacker_0`, and `monitoring`, which holds forwarded copies.

### Open risks, in `status.md`

- **R1, high, M7: the read-only agent connection can read the labels.** On `agent.duckdb`, `read_parquet('data/processed/<testbed>/labels.parquet')` returned all 61,813 and 47,323 rows, and `read_csv` all 11 phase rows. The M7 SQL guard list (INSERT, UPDATE, DELETE, ATTACH, COPY, PRAGMA, CREATE, multiple statements) does not stop a plain `SELECT` from a table function. No agent exists yet, so nothing leaks today.
- **R2, medium, M4–M7: the §5.2 scan has gaps.** The test matches the plan's patterns, but `import logtriage.eval.metrics`, `from logtriage.prepare import run_prepare`, `open('label_report.json')` and `periods.first_attack` all pass it. `periods.json` holds `first_attack`, which is attack timing and must not reach the agent context.
- **R3, medium, M4: DuckDB uses the session time zone.** Here that is `Europe/Istanbul`, so `ts` comes back as +03 and `date_trunc('day', ts)` gives 1,199 lines on the first day of russellmitchell `auth` against 1,355 in UTC. The stored instants are right, but §6.3 computes in DuckDB, and Docker would use another zone. Connections need `SET TimeZone='UTC'`.
- **R4, medium, M5: calibration is not representative on santos.** The calib period is 01:01–07:16 UTC. `apache_access` runs at 253 lines/h there against 2,430 in eval, active in 3 of 7 hours; `dns` 2,862 against 5,668; `vpn` 24 against 63. On russellmitchell the `apache_access` gap is 778 against 1,227. Percentiles calibrated on quiet hours may flag normal daytime traffic.
- **R5, medium, M5: D15 leaves a gap on russellmitchell `apache_error`.** It has 13 fit lines and **0 calib lines**, so a model can be fit but not calibrated, and `LocalOutlierFactor(n_neighbors=35)` would see at most 13 windows. D15 covers only zero fit-period windows.
- **R6, low, M10: DuckDB views use relative paths.** `read_parquet('data/processed/...')` only resolves from the repository root. The `store.py` docstring says so, but Docker and the app must run from there or rebuild the views.

## Decisions recorded

- **D14** (decision A): §5.1, §5.4, §6.3, M7 in §13.
- **D15** (decision B): `ml.min_fit_lines: 200` in `configs/default.yaml`, §6.3, §6.4, §10.1. It sits under `ml` because `Settings` ignores unknown top-level keys, and it counts parsed lines, in line with D14. It applies today to russellmitchell `apache_error` (13) and santos `apache_error` (0). On current data no phase depends only on santos `apache_error`, because its `dirb` and `wpscan` lines also appear in `apache_access`, so the two denominators should agree. M3 fixes the numbers.

## Appendix: parse rate per file

Computed from `lines_*.parquet`, so it covers lines inside the simulation. With D12, blank and stderr lines are left out; without it they count as failures.

### russellmitchell

| file | type | kept | parsed | blank | stderr | with D12 | without D12 |
|---|---|---|---|---|---|---|---|
| `cloud_share/logs/apache2/error.log.1` | apache_error | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/error.log.2` | apache_error | 241 | 3 | 0 | 238 | 100.00% | 1.24% |
| `cloud_share/logs/apache2/error.log.3` | apache_error | 675 | 3 | 0 | 672 | 100.00% | 0.44% |
| `cloud_share/logs/apache2/error.log.4` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/other_vhosts_access.log.1` | apache_access | 5546 | 5546 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/other_vhosts_access.log.2` | apache_access | 6954 | 6954 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/other_vhosts_access.log.3` | apache_access | 7591 | 7591 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/other_vhosts_access.log.4` | apache_access | 7409 | 7409 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/audit/audit.log` | audit | 4588 | 4588 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/auth.log` | auth | 592 | 592 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/auth.log.1` | auth | 784 | 784 | 0 | 0 | 100.00% | 100.00% |
| `davey_mail/logs/auth.log` | auth | 264 | 264 | 0 | 0 | 100.00% | 100.00% |
| `davey_mail/logs/auth.log.1` | auth | 347 | 347 | 0 | 0 | 100.00% | 100.00% |
| `inet-dns/logs/auth.log` | auth | 92 | 92 | 0 | 0 | 100.00% | 100.00% |
| `inet-dns/logs/auth.log.1` | auth | 124 | 124 | 0 | 0 | 100.00% | 100.00% |
| `inet-dns/logs/dnsmasq.log` | dns | 227598 | 227598 | 0 | 0 | 100.00% | 100.00% |
| `inet-firewall/logs/audit/audit.log` | audit | 726 | 726 | 0 | 0 | 100.00% | 100.00% |
| `inet-firewall/logs/auth.log` | auth | 92 | 92 | 0 | 0 | 100.00% | 100.00% |
| `inet-firewall/logs/auth.log.1` | auth | 124 | 124 | 0 | 0 | 100.00% | 100.00% |
| `inet-firewall/logs/dnsmasq.log` | dns | 275900 | 275900 | 0 | 0 | 100.00% | 100.00% |
| `internal_share/logs/audit/audit.log` | audit | 732 | 732 | 0 | 0 | 100.00% | 100.00% |
| `internal_share/logs/auth.log` | auth | 92 | 92 | 0 | 0 | 100.00% | 100.00% |
| `internal_share/logs/auth.log.1` | auth | 124 | 124 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/error.log.1` | apache_error | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/error.log.2` | apache_error | 3856 | 3 | 6 | 3847 | 100.00% | 0.08% |
| `intranet_server/logs/apache2/error.log.3` | apache_error | 3 | 3 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/error.log.4` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.1` | apache_access | 601 | 601 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2` | apache_access | 8530 | 8530 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.3` | apache_access | 933 | 933 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.4` | apache_access | 1120 | 1120 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.russellmitchell.com-error.log.1` | apache_error | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.russellmitchell.com-error.log.2` | apache_error | 36 | 36 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.russellmitchell.com-error.log.3` | apache_error | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/audit/audit.log` | audit | 2316 | 2316 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/auth.log` | auth | 272 | 272 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/auth.log.1` | auth | 356 | 356 | 0 | 0 | 100.00% | 100.00% |
| `mail/logs/audit/audit.log` | audit | 7388 | 7388 | 0 | 0 | 100.00% | 100.00% |
| `mail/logs/auth.log` | auth | 275 | 275 | 0 | 0 | 100.00% | 100.00% |
| `mail/logs/auth.log.1` | auth | 360 | 360 | 0 | 0 | 100.00% | 100.00% |
| `morris_mail/logs/auth.log` | auth | 263 | 263 | 0 | 0 | 100.00% | 100.00% |
| `morris_mail/logs/auth.log.1` | auth | 342 | 342 | 0 | 0 | 100.00% | 100.00% |
| `vpn/logs/audit/audit.log` | audit | 726 | 726 | 0 | 0 | 100.00% | 100.00% |
| `vpn/logs/auth.log` | auth | 92 | 92 | 0 | 0 | 100.00% | 100.00% |
| `vpn/logs/auth.log.1` | auth | 124 | 124 | 0 | 0 | 100.00% | 100.00% |
| `vpn/logs/openvpn.log` | vpn | 5537 | 5537 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.russellmitchell.com-access.log.1` | apache_access | 5515 | 5515 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.russellmitchell.com-access.log.2` | apache_access | 6869 | 6869 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.russellmitchell.com-access.log.3` | apache_access | 7541 | 7541 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.russellmitchell.com-access.log.4` | apache_access | 7366 | 7366 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.russellmitchell.com-error.log.1` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/error.log.1` | apache_error | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/error.log.2` | apache_error | 3 | 3 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/error.log.3` | apache_error | 3 | 3 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/error.log.4` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/mail.smith.russellmitchell.com-access.log.1` | apache_access | 9488 | 9488 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/mail.smith.russellmitchell.com-access.log.2` | apache_access | 8783 | 8783 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/mail.smith.russellmitchell.com-access.log.3` | apache_access | 8025 | 8025 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/mail.smith.russellmitchell.com-access.log.4` | apache_access | 8215 | 8215 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-access.log.1` | apache_access | 772 | 772 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-access.log.2` | apache_access | 818 | 818 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-access.log.3` | apache_access | 653 | 653 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-access.log.4` | apache_access | 608 | 608 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-error.log.1` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-error.log.2` | apache_error | 25 | 25 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-error.log.3` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/audit/audit.log` | audit | 2264 | 2264 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/auth.log` | auth | 258 | 258 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/auth.log.1` | auth | 342 | 342 | 0 | 0 | 100.00% | 100.00% |

### santos

| file | type | kept | parsed | blank | stderr | with D12 | without D12 |
|---|---|---|---|---|---|---|---|
| `cloud_share/logs/apache2/error.log` | apache_error | 268 | 2 | 0 | 266 | 100.00% | 0.75% |
| `cloud_share/logs/apache2/error.log.1` | apache_error | 333 | 3 | 0 | 330 | 100.00% | 0.90% |
| `cloud_share/logs/apache2/error.log.2` | apache_error | 277 | 3 | 0 | 274 | 100.00% | 1.08% |
| `cloud_share/logs/apache2/error.log.3` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/other_vhosts_access.log` | apache_access | 9664 | 9664 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/other_vhosts_access.log.1` | apache_access | 11971 | 11971 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/other_vhosts_access.log.2` | apache_access | 10659 | 10659 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/apache2/other_vhosts_access.log.3` | apache_access | 11950 | 11950 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/audit/audit.log` | audit | 4572 | 4572 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/auth.log` | auth | 592 | 592 | 0 | 0 | 100.00% | 100.00% |
| `cloud_share/logs/auth.log.1` | auth | 784 | 784 | 0 | 0 | 100.00% | 100.00% |
| `hayes_mail/logs/auth.log` | auth | 274 | 274 | 0 | 0 | 100.00% | 100.00% |
| `hayes_mail/logs/auth.log.1` | auth | 345 | 345 | 0 | 0 | 100.00% | 100.00% |
| `inet-dns/logs/auth.log` | auth | 92 | 92 | 0 | 0 | 100.00% | 100.00% |
| `inet-dns/logs/auth.log.1` | auth | 124 | 124 | 0 | 0 | 100.00% | 100.00% |
| `inet-dns/logs/dnsmasq.log` | dns | 255795 | 255795 | 0 | 0 | 100.00% | 100.00% |
| `inet-firewall/logs/audit/audit.log` | audit | 708 | 708 | 0 | 0 | 100.00% | 100.00% |
| `inet-firewall/logs/auth.log` | auth | 91 | 91 | 0 | 0 | 100.00% | 100.00% |
| `inet-firewall/logs/auth.log.1` | auth | 124 | 124 | 0 | 0 | 100.00% | 100.00% |
| `inet-firewall/logs/dnsmasq.log` | dns | 275667 | 275667 | 0 | 0 | 100.00% | 100.00% |
| `internal_share/logs/audit/audit.log` | audit | 728 | 728 | 0 | 0 | 100.00% | 100.00% |
| `internal_share/logs/auth.log` | auth | 92 | 92 | 0 | 0 | 100.00% | 100.00% |
| `internal_share/logs/auth.log.1` | auth | 124 | 124 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/error.log` | apache_error | 3855 | 2 | 6 | 3847 | 100.00% | 0.05% |
| `intranet_server/logs/apache2/error.log.1` | apache_error | 3 | 3 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/error.log.2` | apache_error | 3 | 3 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/error.log.3` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.santos.com-access.log` | apache_access | 9462 | 9462 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.santos.com-access.log.1` | apache_access | 2228 | 2228 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.santos.com-access.log.2` | apache_access | 1706 | 1706 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.santos.com-access.log.3` | apache_access | 2388 | 2388 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.santos.com-error.log` | apache_error | 44 | 44 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/apache2/intranet.smith.santos.com-error.log.1` | apache_error | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/audit/audit.log` | audit | 2263 | 2263 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/auth.log` | auth | 270 | 270 | 0 | 0 | 100.00% | 100.00% |
| `intranet_server/logs/auth.log.1` | auth | 342 | 342 | 0 | 0 | 100.00% | 100.00% |
| `mail/logs/audit/audit.log` | audit | 12817 | 12817 | 0 | 0 | 100.00% | 100.00% |
| `mail/logs/auth.log` | auth | 287 | 287 | 0 | 0 | 100.00% | 100.00% |
| `mail/logs/auth.log.1` | auth | 352 | 352 | 0 | 0 | 100.00% | 100.00% |
| `rogersturnbull_mail/logs/auth.log` | auth | 263 | 263 | 0 | 0 | 100.00% | 100.00% |
| `rogersturnbull_mail/logs/auth.log.1` | auth | 344 | 344 | 0 | 0 | 100.00% | 100.00% |
| `vpn/logs/audit/audit.log` | audit | 710 | 710 | 0 | 0 | 100.00% | 100.00% |
| `vpn/logs/auth.log` | auth | 91 | 91 | 0 | 0 | 100.00% | 100.00% |
| `vpn/logs/auth.log.1` | auth | 124 | 124 | 0 | 0 | 100.00% | 100.00% |
| `vpn/logs/openvpn.log` | vpn | 5622 | 5622 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.santos.com-access.log` | apache_access | 9570 | 9570 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.santos.com-access.log.1` | apache_access | 11858 | 11858 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.santos.com-access.log.2` | apache_access | 10525 | 10525 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/cloud.smith.santos.com-access.log.3` | apache_access | 11796 | 11796 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/error.log` | apache_error | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/error.log.1` | apache_error | 3 | 3 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/error.log.2` | apache_error | 3 | 3 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/error.log.3` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/mail.smith.santos.com-access.log` | apache_access | 21901 | 21901 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/mail.smith.santos.com-access.log.1` | apache_access | 23989 | 23989 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/mail.smith.santos.com-access.log.2` | apache_access | 26294 | 26294 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/mail.smith.santos.com-access.log.3` | apache_access | 23443 | 23443 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-access.log` | apache_access | 2208 | 2208 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-access.log.1` | apache_access | 2815 | 2815 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-access.log.2` | apache_access | 3089 | 3089 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-access.log.3` | apache_access | 2605 | 2605 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-error.log` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-error.log.1` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/apache2/proxy-error.log.2` | apache_error | 1 | 1 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/audit/audit.log` | audit | 2244 | 2244 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/auth.log` | auth | 257 | 257 | 0 | 0 | 100.00% | 100.00% |
| `webserver/logs/auth.log.1` | auth | 342 | 342 | 0 | 0 | 100.00% | 100.00% |

