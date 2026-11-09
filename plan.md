# LogTriage Agent — Implementation Plan

This is the single source of truth for design, data contracts and milestones.
`status.md` tracks progress; `CLAUDE.md` holds the always-on rules.
If something here proves wrong once you see the real data, follow §14.3 (change it, log it, never deviate silently).

---

## 0. How to use this document

- At the start of a session, read `status.md`, then only the sections of this plan that the current milestone (§13) points to.
- Section numbers are stable; refer to them in commits and in `status.md` (e.g. "per §5.4").
- "MUST" = required for acceptance. "SHOULD" = default; deviate only with a logged reason.

---

## 1. Project summary

LogTriage Agent finds attacks in security logs and explains them with evidence.

1. **Data layer**: parse raw Linux logs from the AIT Log Data Set V2.0 (AIT-LDS), template them with Drain3, aggregate into 1-minute windows with features, store as Parquet + DuckDB.
2. **ML layer**: unsupervised anomaly detection (Isolation Forest, LOF, PCA reconstruction) per log type, percentile-calibrated ensemble, then grouping of anomalous windows into a small number of **incidents**.
3. **Agent layer** (LangGraph): for each incident, an Investigator gathers evidence lines with tools, a Mapper proposes MITRE ATT&CK techniques via RAG, a Reporter writes a structured report in which every claim cites evidence, and a Verifier rejects unsupported claims (max 2 rewrite rounds).
4. **Interface**: Streamlit dashboard (incident list, timeline, scores, report, chat with the agent) with a replay mode, started via Docker Compose.
5. **Evaluation**: window-level, attack-phase-level, alert reduction, verdict, ATT&CK mapping, faithfulness, cost/latency, against IDS (AIT-ADS), ML-only, LLM-only and supervised baselines, plus ablations.

Course constraint: each CRISP-DM phase has a notebook (`notebooks/01..05`). Logic lives in the `logtriage` package; notebooks only call it and show results.

Project language: code, comments, prompts, reports and notebooks in English.

---

## 2. Fixed design decisions

These were approved before development. Section references point to the full specification.

| ID | Decision | Spec |
|----|----------|------|
| D1 | Window key = `(testbed, host, log_type, window_start)`, 1-minute windows. One anomaly model **per log type** (pooled across hosts). Source IPs/users are window *attributes*, not part of the key. | §6.3, §6.4 |
| D2 | VPN logs are a first-class log type (features + `ip_profile` maps VPN-internal IPs to external IPs). The attacker enters via stolen VPN credentials. | §6.3, §7.3 |
| D3 | Model scores are converted to percentiles against a held-out calibration slice of the normal period, then averaged. The threshold on this ensemble score is chosen on the dev testbed. LOF uses `novelty=True`. Unsupervised models are fit on each testbed's own normal period; the dev testbed is used only to choose hyperparameters. | §6.4, §6.5 |
| D4 | Incidents are built by time-gap grouping with entity linking (union-find), not DBSCAN on mixed features. | §6.6 |
| D5 | Drain3 is trained on the normal period and frozen for "unseen template" features; every line carries `line_id = host|file|line_no` from parsing to the report; logs are filtered to the simulation interval; all timestamps are UTC. | §5.1, §6.1, §6.2 |
| D6 | Supervisor is a deterministic LangGraph router (not an LLM). Mapper is one RAG + LLM call. All LLM outputs are validated with Pydantic (retry on failure). Tool outputs are deduplicated and capped. One model name from config. | §7 |
| D7 | Gold ATT&CK mapping uses acceptable-technique *sets* per phase (corrected IDs, §11). Phase recall denominator = phases with ≥1 labeled line in processed log types. Faithfulness is measured on a manually annotated sample, not only by the Verifier. The supervised model is called "supervised reference". | §10, §11 |

Further fixed choices:

- Dev testbed: `russellmitchell`. Test testbed: `santos`. Tuning only on dev.
- Extra test testbeds: `wardbeck` and `harrison`, drawn before any result was seen. All test testbeds are in `test_testbeds` in `configs/default.yaml`. They reuse the frozen config, prompts and retrieval, and each runs once (changed: see status.md D55, D56).
- LLM: DeepSeek V4 Flash (`deepseek-v4-flash`) for every LLM role during development and evaluation (§7.1).
- Labels are isolated from everything except evaluation and the supervised reference (§5.2).

---

## 3. Environment and tooling

- Python 3.11, managed with **uv** (`uv sync`, `uv run ...`). If uv is missing: `pip install uv`.
- Packaging: `pyproject.toml`, package `logtriage` in `src/logtriage/`, CLI entry point `logtriage` (Typer).
- Core libs: pandas, pyarrow, duckdb, drain3, scikit-learn, xgboost, matplotlib, plotly, langgraph, langgraph-checkpoint-sqlite (changed: see status.md D49), langchain-core, langchain-openai, chromadb, sentence-transformers, pydantic v2, pyyaml, python-dotenv, streamlit, typer, tqdm.
  Dev: pytest, ruff, nbstripout (optional), jupyter. torch is a direct dependency, CPU-only on Linux, so that uv can pick its wheel; sentence-transformers needs it anyway (changed: see status.md D54).
- Lint/format: ruff (line length 100). Type hints everywhere; no mypy gate.
- Config: `configs/default.yaml` loaded by `logtriage.config` into a Pydantic settings object; env overrides via `.env` (see `.env.example`).
- Secrets: only `DEEPSEEK_API_KEY` in `.env` (gitignored). Never print or log it.
- Pytest markers (register in `pyproject.toml`):
  - `live`: calls the real LLM API.
  - `data`: needs `data/` (downloaded/processed datasets) or downloaded models.
  Unit tests use tiny fixtures in `tests/fixtures/` and have no marker.
- Local merge gate: `uv run pytest -m "not live"` (unit + data tests). CI: `pytest -m "not live and not data"`.
- CI: GitHub Actions workflow `.github/workflows/ci.yml` running `uv sync`, `ruff check`, `ruff format --check` and the CI pytest selection on push/PR. If the repo has no GitHub remote, keep the file anyway.
- Seeds: global seed 42 in config; pass `random_state` everywhere.

---

## 4. Data

### 4.1 Sources

| Dataset | Where | Use |
|---|---|---|
| AIT-LDS V2.0 | Zenodo record 5789064 (`https://zenodo.org/records/5789064`), one zip per testbed, e.g. `russellmitchell.zip` | Logs + line labels |
| AIT-ADS | Zenodo record 8263181: `ait_ads.zip` (~96 MB) for alerts, `labels.csv` beside it for phases (changed: see status.md D8) | IDS baseline alerts (Wazuh, Suricata, AMiner) and attack phase time intervals |
| MITRE ATT&CK Enterprise (STIX 2.1) | `https://github.com/mitre-attack/attack-stix-data` (`enterprise-attack/enterprise-attack.json`) | RAG index and gold-ID validation |

Licenses: AIT data is CC BY-NC-SA 4.0 (non-commercial, attribution). Cite in README and report.

### 4.2 Download and selective extraction (M1)

- Get exact file names, URLs and MD5 checksums from the Zenodo API (`https://zenodo.org/api/records/5789064`, `.../8263181`). Verify MD5 after download.
- Download to `data/raw/zips/`. Check free disk space first. Each testbed is several GB compressed and much larger unpacked.
- **Do not unzip everything.** First `unzip -l` to list contents, then extract only:
  - `dataset.yaml` (simulation start and end; changed: see status.md D9),
  - `labels/**` (all label files),
  - for every label file, the matching log file under `gather/**`,
  - the remaining `gather/<host>/logs/**` files of the five log families (§4.4), even if unlabeled,
  - `gather/attacker_0/logs/**` (attack execution logs, used only for phase timing),
  - skip pcap and other large unrelated files.
- Target layout: `data/raw/<testbed>/{dataset.yaml, gather/..., labels/...}`, `data/raw/ait_ads/...`.
- The download script MUST be idempotent (skip if checksum matches) and runnable as `logtriage download --testbed russellmitchell`.

### 4.3 Testbeds and periods

For each testbed, from `dataset.yaml` (changed: see status.md D9) and the attack phases (§5.3):

- `sim_start`, `sim_end`: simulation interval. Drop all lines outside it.
- `first_attack` = earliest start among the phases with source `ait_ads:labels.csv`, so `dnsteal_exfil` does not count (changed: see status.md D11).
- **Training period** = `[sim_start, first_attack - 24h)`. Documented assumption: the analyst knows a clean baseline period. This is the **only** use of attack timing outside evaluation (allowed exception to §5.2). It MUST be ≥ 24h; if not, log it in status.md and use `[sim_start, first_attack - 6h)`. Known limitation: the baseline is not clean, because DNS exfiltration runs through all of it on both testbeds (changed: see status.md D11). It is not cleaned with labels or attacker information, which §5.2 forbids; the definition stays as computed, and the contamination is quantified in `01_eda.ipynb` (changed: see status.md D16).
- The training period is split by time into:
  - **fit** = first 80%. Drain3 frozen miner, all "unseen"/rarity vocabularies, scalers and anomaly models are fit **only** here.
  - **calib** = last 20%. Not used for fitting anything; used for percentile calibration (§6.5), so calibration sees "unseen" features the same way the eval period does.
- **Evaluation period** = `[first_attack - 24h, sim_end)`. It contains normal traffic before the attack, so false positives can be measured.
- `logtriage/data/periods.py` computes these boundaries once and writes `data/processed/<testbed>/periods.json`. All other code reads periods from this file and never from phases or labels.

**Extra test testbeds (changed: see status.md D55, D56).** `wardbeck` and `harrison` follow this section unchanged. Periods, scalers, vocabularies and models are computed per testbed: results are combined across testbeds (§10.7), data never is. Nothing is tuned on them.

### 4.4 Log families in scope

| log_type | Typical source (confirm in M1) |
|---|---|
| `apache_access` | Apache access logs on web/intranet servers |
| `apache_error` | Apache error logs |
| `auth` | `auth.log` on all hosts |
| `dns` | DNS server logs (dnsmasq or similar) |
| `audit` | `audit.log` (auditd) |
| `vpn` | OpenVPN server logs |

The exact path patterns → log_type mapping lives in `configs/sources.yaml` and is written in M1 from the actual file inventory. If other *labeled* log types exist (e.g. syslog, Suricata), list them in status.md "Open questions" and do not process them unless a later decision adds them.

---

## 5. Data contracts

All tables are Parquet under `data/processed/<testbed>/`. `data/processed/<testbed>/agent.duckdb` (agent-facing, **no label tables**) holds them as tables, without the column `period` and with no reference to any file; `eval.duckdb` (everything) exposes them through views (changed: see status.md D41).

### 5.1 `lines_<log_type>.parquet`

| column | type | notes |
|---|---|---|
| `line_id` | str | `"{host}|{file}|{line_no}"`, globally unique within a testbed |
| `testbed` | str | |
| `host` | str | directory name under `gather/` |
| `log_type` | str | §4.4 |
| `file` | str | path relative to `gather/<host>/`, e.g. `logs/audit/audit.log` |
| `line_no` | int | **1-based line number in the original file**, counted before any filtering |
| `ts` | timestamp[UTC] | parsed event time |
| `raw` | str | original line (decoded utf-8, `errors="replace"`) |
| `message` | str | part after the syslog/apache prefix that is fed to Drain3 |
| `template_id` | int | from the online Drain3 miner (§6.2); this and the other template columns are null when `parse_ok` is false (changed: see status.md D12) |
| `template` | str | |
| `is_unseen_template` | bool | frozen fit-period miner found no match (§6.2) |
| `template_rarity` | float | `-log((count_fit + 1) / (N_fit + V))`, from fit-period counts of the frozen miner's templates (unseen → count 0) |
| `src_ip` | str? | when present |
| `user` | str? | when present |
| `fields` | str (JSON) | log-type-specific parsed fields (status, method, path, user agent, qname, exe, uid, ...) |
| `parse_ok` | bool | false → line kept with `raw` only, and left out of windows and features (changed: see status.md D14) |

Reading rules: read files in binary, split on `b"\n"` only, keep empty lines in the count, decode per line. Stream in chunks; never load a multi-GB file at once.

### 5.2 `labels.parquet` (evaluation only)

| column | type |
|---|---|
| `line_id` | str |
| `labels` | list[str] (raw AIT labels) |
| `rules` | str (JSON) |
| `phase` | str (§5.3, or `"unassigned"`) |

Built from `labels/**` JSON Lines (`{"line": N, "labels": [...], "rules": {...}}`), joined by `(host, file, line)`.
**Line base check (M2):** confirm whether the label `line` numbers are 0- or 1-based. Check that labeled lines look like attack lines (attacker IP, timestamps inside phase intervals) under each assumption. If they are 0-based, convert once in `labels.py`; `line_no` stays 1-based everywhere else. Log the finding in status.md.

**Isolation rule:** this table and anything derived from it (window labels, phases, `data_meta/phases_*.csv`) MUST NOT be readable from feature code, unsupervised models, agent tools, prompts or the UI's agent/chat context. Allowed readers: `logtriage.eval` (incl. `eval/tuning.py`, which picks hyperparameters on the dev testbed), `logtriage.ml.supervised`, `logtriage.data.labels`, `logtriage.data.periods` (period boundaries only, §4.3), `logtriage.data.inventory` (aggregate counts for the inventory report, through `logtriage.data.labels` only; changed: see status.md D10), the EDA notebook, and the optional evaluation page of the UI, which may only call functions from `logtriage.eval`.
Enforce with a test that scans the source of `data/` (except `labels.py`, `periods.py`, `inventory.py`, and `download.py`, which only names the `labels/` paths to extract), `ml/` (except `supervised.py`), `agents/`, `rag/` and `app/` (except the evaluation page) for references to `labels`, `phases`, `eval.duckdb`, `logtriage.eval`, `logtriage.prepare`, `label_report` or `first_attack` (changed: see status.md D22).

### 5.3 `data_meta/phases_<testbed>.csv` (committed, small)

`testbed, phase, start_utc, end_utc, source`

- Primary source: the attack-phase intervals shipped with AIT-ADS in `labels.csv` (per scenario: phase name with epoch start/end, e.g. `network_scans, service_scans, dirb, wpscan, webshell, cracking, reverse_shell, privilege_escalation, service_stop, dnsteal`; changed: see status.md D8). These rows are kept as published, with source `ait_ads:labels.csv`. Cross-check against `gather/attacker_0/logs/attacks.log` of the testbed.
- The published `dnsteal` interval starts as the exfiltration ends, so each file also has a `dnsteal_exfil` row: first to last `Received data` event in `gather/attacker_0/logs/dnsteal.log`, with source `attacker_0:dnsteal.log`. It overlaps the other phases, so it applies only to lines whose raw labels include `dnsteal`; all other lines ignore it (changed: see status.md D11). For those lines it is tried first. An interval containing `ts` always beats the ±60 s tolerance, so `service_stop` keeps its lines (changed: see status.md D13).
- Phase names and order can differ per testbed. Use what the data says.
- A labeled line's `phase` = the phase whose interval contains its `ts` (±60 s tolerance), else `"unassigned"`.
- If the `unassigned` lines are mostly VPN login/session lines of the attacker, add a phase `vpn_access` spanning those lines and log the decision.
- **Timezone check (M2 acceptance):** ≥95% of labeled lines MUST fall inside some phase interval after UTC normalization. If not, investigate the time offset and fix it before going on.

### 5.4 `windows_<log_type>.parquet`

Key `(testbed, host, log_type, window_start)`; only non-empty windows. Windows hold only lines with `parse_ok=True` (changed: see status.md D14).
Columns: key, `n_lines`, feature columns (§6.3), `src_ips` (list[str], top 10 by count), `users` (list[str], top 10), `period` ∈ {`fit`, `calib`, `eval`}.
A window takes the period in which it ends, so one that crosses a boundary goes to the later period and a `fit` window holds only fit lines (changed: see status.md D24).

### 5.5 `scores.parquet`

Key + `score_if`, `score_lof`, `score_pca` (raw), `pct_if`, `pct_lof`, `pct_pca` (calibrated percentiles in [0,1]), `score` (ensemble mean), `is_anomalous` (bool).

### 5.6 `incidents.parquet`

| column | notes |
|---|---|
| `incident_id` | `"{testbed}-{NNNN}"`, ordered by start time |
| `start`, `end` | UTC |
| `hosts`, `log_types`, `src_ips`, `users` | list[str] |
| `n_windows` | |
| `max_score`, `mean_score` | |
| `priority` | §6.6 |
| `window_keys` | list of window keys (JSON) |

### 5.7 Report (`data/processed/<testbed>/reports/<incident_id>.json`)

Pydantic models in `logtriage/agents/schemas.py`:

```python
class Evidence(BaseModel):
    eid: str            # short id shown to the LLM: "E1", "E2", ...
    line_id: str        # resolved real id
    ts: datetime
    host: str
    log_type: str
    raw: str            # truncated to 500 chars
    note: str           # why the Investigator picked it

class Claim(BaseModel):
    text: str
    evidence: list[str] # eids, at least 1

class TimelineItem(BaseModel):
    ts: datetime
    claim: Claim

class TechniqueChoice(BaseModel):
    technique_id: str   # e.g. "T1046" or "T1548.003"
    name: str
    justification: Claim

class IncidentReport(BaseModel):
    incident_id: str
    summary: list[Claim]            # 1-4 claims
    timeline: list[TimelineItem]
    techniques: list[TechniqueChoice]  # ranked, max 3
    verdict: Literal["malicious", "benign", "uncertain"]
    confidence: float               # 0-1
    recommended_actions: list[str]  # recommendations only, no automated action
    evidence: list[Evidence]
    verifier_rounds: int
    unsupported_claims_removed: list[str]
    meta: dict                      # model, prompt_version, tokens_in/out, cost_usd, latency_s, ablation flags
```

The LLM only ever sees and cites `eid`s. Code resolves `eid → line_id`. A claim citing an unknown eid is unsupported by definition.

---

## 6. Data and ML pipeline

### 6.1 Parsing (`logtriage/data/parsers/`)

- One parser module per log type, each exposing `parse_line(raw: str, ctx) -> ParsedLine`.
- Timestamps: syslog-style lines have no year. Take the year from `sim_start`; handle the year boundary. Audit lines use `msg=audit(<epoch>.<ms>:<serial>)`. Apache uses `[%d/%b/%Y:%H:%M:%S %z]`. Normalize everything to tz-aware UTC. Confirm the source timezone with the phase check (§5.3).
- Unparseable lines: `parse_ok=False`, keep `raw`, `ts` = previous line's ts in the same file, or the next one at the start of a file (log the count). Parse rate MUST be ≥ 99% per file. The rate counts log records only: blank lines, and text in Apache error logs that does not start with `[` (process stderr, no timestamp), stay `parse_ok=False` but are counted separately and left out of the rate (changed: see status.md D12).
- Drop lines with `ts` outside `[sim_start, sim_end)` *after* assigning `line_no`.

### 6.2 Drain3 templating (`logtriage/data/drain.py`)

- Masking (Drain3 `MaskingInstruction`): IPv4, IPv6, hex ids, numbers, UUIDs, long base32/64-like tokens (≥ 20 chars), file paths are **not** masked.
- Per `(testbed, log_type)`:
  1. **Frozen miner**: train on fit-period `message`s, then save its state to `data/processed/<testbed>/drain/<log_type>.frozen.bin`. For every line, `match()` against it (no update) → `is_unseen_template = (match is None)`. Template frequencies from the fit period give `template_rarity`.
  2. **Online miner**: process *all* lines in chronological order with `add_log_message` → `template_id`, `template` (used for grouping and dedup in agent tools).
- Persist both states; results MUST be reproducible across runs (same input → same ids).
- Drain3 is the slowest step. Measure lines/second in M2 and log it in status.md. If a log type would take more than ~1 hour, record it as an open question before optimizing.

### 6.3 Features (`logtriage/data/features.py`)

Compute with DuckDB SQL over `lines_*.parquet` grouped by window key. Vocabulary-based features ("unseen X") use vocabularies built **only from the fit period** of the same testbed.

Lines with `parse_ok=False` stay in `lines_*.parquet` but are excluded from windows and features, because their `ts` is inherited from another line and is unreliable (changed: see status.md D14).

Common (all log types): `n_lines`, `n_unseen_templates`, `ratio_unseen_templates`, `mean_template_rarity`, `max_template_rarity`, `n_unique_templates`.

| log_type | Specific features |
|---|---|
| `apache_access` | `n_req`, `ratio_4xx`, `ratio_404`, `ratio_5xx`, `ratio_post`, `n_unique_paths`, `ratio_unseen_paths`, `mean_path_len`, `max_path_len`, `n_unique_ua`, `ratio_unseen_ua`, `n_unique_src_ip`, `n_unseen_src_ip` |
| `apache_error` | `n_errors`, `n_unique_clients` (if present) |
| `auth` | `n_failed_login`, `n_success_login`, `n_session_open`, `n_sudo`, `n_su`, `n_unique_users`, `n_unseen_users`, `n_events_by_web_user` (uid 33 / `www-data`) |
| `dns` | `n_queries`, `mean_qname_len`, `max_label_len`, `mean_label_entropy`, `max_label_entropy`, `ratio_unique_qnames`, `top_domain_share` (share of queries to the most-queried registered domain), `n_unique_clients`, `n_unseen_domains` |
| `audit` | `n_execve`, `n_execve_web_user`, `n_unique_exe`, `n_unseen_exe`, `n_user_auth_events` (USER_AUTH, USER_START, CRED_ACQ, USER_CMD), `n_root_execve` |
| `vpn` | `n_auth_success`, `n_auth_fail`, `n_new_sessions`, `n_unique_src_ip`, `n_unseen_src_ip`, `n_unseen_users` |

DNS definitions (changed: see status.md D23). Only `query` lines count, because dnsmasq repeats each name in its forwarded, reply and cached lines; a window without one has 0 in these features. The registered domain is the public suffix plus one part, lowercased; the suffix is the last part, or the last two when the TLD has two letters and the second-level name is in `features.second_level_suffixes` (`thesun.co.uk`). A name without a dot, such as `mail`, is its own domain. `*_label_*` features use the parts left of the public suffix, with case kept; entropy is Shannon entropy in bits over the characters of one part, and `mean_label_entropy` averages over all parts of all queries in the window. `ratio_unique_qnames` compares names without case or trailing dot.

Other definitions (changed: see status.md D25). `*_paths` features use the path without its query string, and `mean_path_len` and `max_path_len` use the full request target. `n_errors` counts lines at level `error` or above. `n_unseen_X` counts distinct unseen values in the window, and `ratio_unseen_X` is the share of its lines with an unseen value. `n_execve` and the other execve features count `SYSCALL` records with `syscall=59`, which carry `uid` and `exe`. The VPN placeholder user `UNDEF` is no user.

Features that turn out to be constant or missing in the real data are dropped per `(testbed, log_type)`, and `features_report.json` lists them. Constant means one value over the windows of all periods: `n_unseen_*` features are 0 on every fit window by construction, so a check on the fit period alone would drop all of them (changed: see status.md D25). Log this in status.md.

`audit` windows also hold `n_unseen_units`: the distinct `unit=` names of `SERVICE_START` and `SERVICE_STOP` records (read from the message, `\bunit=([^ ']+)`, because the template masks them) that are not in the fit vocabulary `units`. It is built, gated (D15) and dropped (D25) like every `n_unseen_*` feature, and it is an **optional** feature (`features.OPTIONAL_FEATURES`): the models use it only when `ml.optional_features` lists it, which v2 (`configs/v2.yaml`) does and v1 does not, so v1 scores are unchanged, and the agents never see it (changed: see status.md D76, D78, D79).

Vocabulary, rarity and "unseen" features (`n_unseen_templates`, `ratio_unseen_templates`, `mean_template_rarity`, `max_template_rarity`, and every `*_unseen_*` feature in the table) are dropped for a `(testbed, log_type)` whose fit period has fewer than `ml.min_fit_lines` parsed lines (`configs/default.yaml`, default 200) (changed: see status.md D15).
Transform: `log1p` on counts (features named `n_*`), then `RobustScaler` fit on the `fit` windows of a log type, pooled across hosts. Windows keep raw values; the scaler is saved to `data/processed/<testbed>/scalers/<log_type>.json` for M5, and only for baseline-capable types (§6.4). Vocabularies go to `vocabularies/<log_type>.parquet` (changed: see status.md D26).
The DNS features `mean_qname_len`, `max_label_len`, `mean_label_entropy`, `max_label_entropy`, `ratio_unique_qnames` and `top_domain_share` are one-sided: negative scaled values are clipped at 0 (`features.one_sided_features`), on every testbed. They rise with an attack by nature, and the baseline holds the tunnel, so a value below it only means the tunnel stopped. Raw window values are not clipped. Unclipped DNS numbers are reported as a secondary variant and used for no selection (changed: see status.md D29). That variant is for russellmitchell and santos only: on `wardbeck` and `harrison` it would need a second scoring pass (changed: see status.md D61).

### 6.4 Anomaly models (`logtriage/ml/models.py`)

Per `(testbed, log_type)`, fit on **fit-period windows** only:

- `IsolationForest(n_estimators=300, contamination="auto", random_state=seed)`
- `LocalOutlierFactor(n_neighbors=35, novelty=True)` (subsample to ≤ 50k training windows if needed), fit on the distinct rows of the fit windows, with `n_neighbors` capped at their number minus one (changed: see status.md D31)
- PCA reconstruction error with `n_components` explaining 95% variance

Higher score = more anomalous for all three (negate sklearn scores where needed).
A `(testbed, log_type)` is **baseline-capable** only if it has at least `ml.min_fit_lines` (200) parsed fit-period lines and at least `ml.min_calib_lines` (50) parsed calib-period lines. For any other type no model is fit: it is excluded from the ensemble and from incidents, reported as "no baseline, not detectable", and kept in parsed data and agent tools. Today this covers `apache_error` on both testbeds, russellmitchell 13 fit and 0 calib lines, santos 0 and 10 (changed: see status.md D15, D19).
Hyperparameter search (small grid) only on the dev testbed, choosing by phase recall at a fixed incident budget (§6.5). Because this needs labels, the search lives in `logtriage/eval/tuning.py`, which calls the `ml` functions; `ml/` itself never reads labels. The chosen values are written to `configs/default.yaml` and reused unchanged on the test testbed.

### 6.5 Calibration, ensemble, threshold (`logtriage/ml/ensemble.py`)

- For each model, `pct_m(x)` = empirical CDF of the model's scores on the calibration slice. Calibrate per `(host, log_type)` when that stream has ≥ 200 calibration windows, otherwise per `log_type`.
- A log type with fewer than `ml.min_calib_windows` (200) calibration windows adds out-of-fold scores of its fit windows to its reference: `ml.oof_folds` contiguous time blocks, each scored by models fit on the other blocks. The final models stay fit on all fit windows, and baseline capability (§6.4) does not change (changed: see status.md D28).
- `ml.thin_calibration: cross_fit` (candidate (a) of `reports/v2_plan.md`, D75) replaces that reference for a thin type: its fold models alone score it, each against its own held-out block and the calib windows. It was implemented and measured on dev and **not chosen** for v2, so v1 and v2 both keep D28 (changed: see status.md D78).
- `score = mean(pct_if, pct_lof, pct_pca)`.
- `is_anomalous = score ≥ q`. `q` is chosen on dev (in `eval/tuning.py`) from {0.95, 0.97, 0.98, 0.99, 0.995, 0.999} to maximize phase recall subject to incidents/day ≤ the budget fixed in M3 (default 25); ties → fewer incidents. The same `q` is used on test. v2 adds 0.996, 0.997 and 0.998 to the grid and was chosen at `q` 0.996, gap 30 (changed: see status.md D78).

### 6.6 Incident grouping (`logtriage/ml/incidents.py`)

- Nodes = anomalous windows of the evaluation period (all log types), sorted by `window_start`. Fit and calib windows only build the baseline (changed: see status.md D30).
- Link two windows if `|Δt| ≤ gap_minutes` (default 10, tunable on dev from {5, 10, 15, 30}) **and** (same host **or** they share a `src_ip` or `user`).
- "Common" entities do not link: an IP or user that appears in > 50% of the fit-period windows of its log type (e.g. a DNS forwarder, a monitoring host) is ignored for linking. This prevents one busy entity from chaining unrelated windows together.
- Connected components (union-find) = incidents.
- `priority = max_score * (1 + 0.1 * (n_log_types - 1)) + 0.01 * log1p(n_windows)`. Incident list is sorted by priority desc.
- Ablation (optional, for the report): DBSCAN on the time axis only, to show the course method.

### 6.7 Supervised reference (`logtriage/ml/supervised.py`)

- Per baseline-capable log type, RandomForest (`class_weight="balanced_subsample"`) and XGBoost (`scale_pos_weight` = n_neg/n_pos) on window features, with the fixed values of `ml.supervised` and no search. Features are the columns kept on both testbeds, as raw window values, without identity columns. `apache_error` is not evaluated (changed: see status.md D32, D33, D36).
- Train on russellmitchell calib and eval windows (labels: window has ≥ 1 labeled line), without label-ambiguous windows, and test on the santos evaluation period. A variant trained on all dev periods is secondary (changed: see status.md D34, D35).
- Report PR-AUC, F1 at the threshold that maximizes F1 on out-of-fold (time-blocked CV) predictions on dev, and feature importance. Blocks are cut per class: the windows of each class, in time order, form `cv_blocks` contiguous equal-count slices, fold i holds out slice i of both classes, and training rows within `purge_minutes` of a held-out span are purged. Folds without a held-out positive or without both classes in training are dropped. A type with fewer than `min_positives` dev positives is "not trainable" and reported n/a, with no fallback (changed: see status.md D37).
- `pooled` keeps the §10.2 scope, so it is n/a for a model missing a type; `pooled_trained` compares all methods on the types that have a model. Pooled PR-AUC uses uncalibrated per-type probabilities (changed: see status.md D38).
- Dev OOF first, then the frozen config scores santos once (changed: see status.md D39). Each test testbed is scored once the same way, with the same models, thresholds and feature list, into `supervised_<testbed>.csv` (changed: see status.md D57). A frozen column of a trained model that a testbed lacks is restored as 0 only if it is an "unseen" feature dropped as constant, since that is its true value; any other gap stops the run before it is recorded (changed: see status.md D59).
- On `dns` this threshold is uninformative, because negatives exist only in the last block of the dev timeline; thresholds stay as used (changed: see status.md D40).
- Label it "supervised reference" (few positives, one attack instance). It is not guaranteed to be an upper bound.

### 6.8 Visualization (`logtriage/eval/viz.py`)

Lives in `eval/` because the plots are colored by ground truth. PCA and t-SNE of windows (all attack windows + up to 5k sampled normal windows), colored by phase. Score timeline per host with phase intervals shaded (eval only).

---

## 7. Agent layer

### 7.1 LLM policy (`logtriage/agents/llm.py`)

- OpenAI-compatible client via `langchain_openai.ChatOpenAI(base_url=cfg.llm.base_url, model=cfg.llm.model, api_key=env)`. Defaults: `base_url=https://api.deepseek.com`, `model=deepseek-flash`, `temperature=0` for evaluation runs, and `thinking: disabled`, because thinking mode ignores `temperature` (changed: see status.md D44).
- Verify the model string and parameters against DeepSeek's API docs in M8. Record the result in status.md.
- One model for all roles. `deepseek-flash` is a rolling alias, so each report records `system_fingerprint` (changed: see status.md D44). A switch to `deepseek-v4-pro` (if ever) is a config change, and it **requires re-running the full LLM evaluation (M11)** so reported numbers match the demo model.
- Structured outputs: request JSON (`response_format={"type": "json_object"}`; the prompt must contain the word "json" and the schema), parse with Pydantic. On validation failure retry up to 2 times, feeding the validation error back. An empty response from the endpoint is sent again within the same limit (changed: see status.md D69).
- Tool calling: native function calling. M8 MUST include a live smoke test (`@pytest.mark.live`) proving a full tool-call round trip works with the configured model. If the model returns reasoning fields that must be echoed back in multi-turn tool use, handle it in `llm.py`.
- **Cache**: SQLite cache in `data/cache/llm.sqlite` keyed by `sha256(model, messages, tools, params)`. Evaluation reruns hit the cache. A `--no-cache` flag bypasses it.
- **Cost**: record `tokens_in`, `tokens_out`, cache-hit tokens per call. Price table in `configs/default.yaml` (`llm.pricing_usd_per_1m: {off_peak, peak}`, each `{input, cached_input, output}`, chosen by `llm.peak_hours_utc`) (changed: see status.md D45). Verify the prices on DeepSeek's pricing page in M8. Budget guard `llm.max_usd_per_run` (default 5) aborts a run cleanly when exceeded, and `llm.max_usd_total` (10) does the same for cumulative spend (changed: see status.md D45).

### 7.2 Graph (`logtriage/agents/graph.py`)

LangGraph `StateGraph` over `IncidentState` (Pydantic): incident, evidence, tool_log, candidates (from RAG), report draft, verifier feedback, round, cost.

```
load_incident (code)
  → investigator (LLM, ReAct with tools)
  → mapper (code retrieves top-10 techniques, then 1 LLM call picks ≤3)
  → reporter (LLM, JSON)
  → verifier (code check + LLM check)
       ├─ unsupported claims and round < 2 → reporter (with feedback)
       └─ else → finalize (code: drop remaining unsupported claims, save JSON, add to incident memory)
```

Finalize rules: removed claims are listed in `unsupported_claims_removed`. If every summary claim is removed, set `verdict="uncertain"` and `confidence ≤ 0.3`. A technique whose justification is unsupported is removed.

The "Supervisor" in the proposal is this deterministic graph plus `run_incidents()` in `logtriage/agents/runner.py`, which pulls incidents by priority from the queue.

Limits (config): investigator ≤ 8 tool calls, evidence ≤ 30 lines, each tool output ≤ 4k characters, reporter ≤ 2 rewrite rounds.

### 7.3 Tools (`logtriage/agents/tools.py`)

All tools read only `agent.duckdb`, through `store.connect_agent`: `read_only=True`, `enable_external_access=false`, `lock_configuration=true`, no label tables (changed: see status.md D41), one thread so that results repeat (changed: see status.md D46). Optional window features (`store.OPTIONAL_FEATURES`, today `n_unseen_units`) are dropped from every agent table, like `period`, in v1 and v2 alike, so the agent tables keep the v1 schema and only detection differs between versions (changed: see status.md D79). Each returns compact text and the line_ids it surfaced. Lines shown to the LLM get eids registered in state.

| tool | behavior |
|---|---|
| `log_search(host, start, end, log_type=None, contains=None, limit=50)` | Raw lines in the range. Dedup by `template_id` (show 1 example + count per template), unseen templates first, then by rarity. |
| `run_sql(query)` | One `SELECT`/`WITH` statement only, checked on DuckDB's parse tree by `agents/sql_guard.py`: table functions, file paths and unknown tables are rejected (changed: see status.md D41). Auto `LIMIT 200`, 10 s timeout, read-only connection. Schema description in the tool docstring. |
| `ip_profile(ip)` | Per log type and host: first/last seen, counts, top templates. For VPN-internal IPs also returns the external IP and VPN user from VPN session logs (and vice versa). |
| `attack_search(text, k=5)` | Hybrid search over the ATT&CK index (§8.1) (changed: see status.md D43). |
| `similar_incidents(text, k=3)` | Vector search over finalized reports (§8.2). |

Window anomaly scores and incident metadata are given to the Investigator in the initial context (not via a tool).

### 7.4 Roles and prompts (`logtriage/agents/prompts/*.md`, versioned)

Prompts are Markdown files with a `prompt_version` header; the version is stored in report meta.

- **Investigator**: goal = explain what happened in the incident window and its context (who, what, from where, before/after). It MUST call at least `log_search` once, and it ends by returning JSON `{"behavior_summary": str, "evidence": [{"eid", "note"}]}`. `behavior_summary` is a neutral description of observed behavior, used as the retrieval query; it is not a report claim.
- **Mapper**: input = `behavior_summary` + selected evidence + top-10 techniques retrieved with `behavior_summary` as the query (id, name, short description). Output = ≤ 3 techniques **from the retrieved list**, ranked, each with a justification citing eids. (RAG-off ablation: no retrieved list, the model answers from memory.)
- **Reporter**: produces `IncidentReport` JSON. Every claim cites ≥ 1 eid. It must state uncertainty (verdict `uncertain` allowed). Zero-shot by default; the few-shot variant (2 short synthetic examples, not from the test testbed) is an ablation.
- **Verifier**:
  1. Code check: each claim's eids exist in the evidence.
  2. LLM check, in one call per round: for each claim, given only the cited lines → `supported` / `unsupported` + reason.
  Unsupported claims go back to the Reporter with reasons. "The evidence" is the list the Investigator selected, which is all the Reporter sees, so an eid that was only shown in tool output counts as unknown (changed: see status.md D48).

### 7.5 Chat agent (`logtriage/agents/chat.py`)

ReAct agent with the same tools plus the current report in context. Memory via LangGraph `SqliteSaver` checkpointer (`data/cache/chat.sqlite`), one thread per incident. Answers must cite eids or line_ids for factual claims.

The loop is a small LangGraph on `LLMClient`, not `create_react_agent`, so every call keeps the cache, ledger and budget guards. The final answer is JSON: `claims` (each a `Claim`, ≥ 1 citation) and an uncited `remark` for what is not a fact about the incident. Code rejects a citation of a line the thread never showed, and after `llm.json_retries` the turn ends with no answer. It checks that a line exists, not that it shows the claim. Report eids keep their meaning, and new lines number after the highest one. The model sees only named report fields, never `meta` or removed claims. `chat-1` loads apart from the frozen roles. The chat writes no report and nothing to the incident memory (changed: see status.md D49).

---

## 8. RAG

### 8.1 ATT&CK index (`logtriage/rag/attack_index.py`)

- Use the pinned local `enterprise-attack.json` (`rag.attack_sha256`); `index-attack` downloads no bundle and refuses any other file. Its ATT&CK version is in status.md. Exclude revoked/deprecated objects (changed: see status.md D42).
- Document per technique/sub-technique: `"{id} {name}. {description}"` (strip citations/markdown), metadata: id, name, tactics, is_subtechnique.
- Embeddings: `sentence-transformers` `BAAI/bge-small-en-v1.5` at `rag.embedding_revision` (changed: see status.md D52) (normalize; use the query instruction prefix for queries). Store in Chroma persistent at `data/index/chroma`, collection `attack`.
- Search fuses the dense ranking with a BM25 ranking (`k1` 1.5, `b` 0.75, lowercase alphanumeric tokens) by Reciprocal Rank Fusion (`k` 60, equal weights) (changed: see status.md D43).
- Test: the gold IDs (§11) all exist in the index and are not revoked.

### 8.2 Incident memory (`logtriage/rag/incident_store.py`)

Chroma collection `incidents`: one document per finalized report (summary claims + techniques + verdict), metadata testbed/incident_id/start. In evaluation, a report may only retrieve reports of incidents that **started earlier** in the same run (filter by testbed, start and `run`), so there is no look-ahead (changed: see status.md D42, D63).

---

## 9. Interface and deployment

### 9.1 Streamlit (`logtriage/app/`)

Pages:
1. **Incidents**: table sorted by priority (id, time, hosts, log types, score, verdict, confidence).
2. **Incident detail**: timeline (plotly) of windows and scores per host/log type, the report with claims and expandable evidence lines (eid → raw line), techniques with links to attack.mitre.org.
3. **Chat**: chat agent for the selected incident.
4. **Monitoring**: per-incident cost, latency, tokens, verifier rounds; totals.

**Replay mode**: a simulated clock (start time, speed factor, e.g. 60× or 600×). Only windows/incidents with `end ≤ clock` are shown; reports appear when their incident closes (precomputed reports are revealed, or computed live if `--live`). A window ends `features.window_seconds` after `window_start`. The default start is `app.replay_lead_minutes` before the earliest incident, from detection output, never from `periods.json` (changed: see status.md D50). `--live` computes only reports that are missing, and it is refused on the test testbed, which uses saved reports alone (changed: see status.md D51).

The pages live in `app/views/`: a folder named `pages` beside the entry script turns on Streamlit's legacy routing, which can run a page without the entry script. The app opens only `agent.duckdb`, on one `store.connect_agent` connection per process, and binds to `app.host`, local by default (changed: see status.md D50).

The UI never shows labels except on an optional "Evaluation" page clearly marked as ground truth.

### 9.2 Docker

- `Dockerfile` (python:3.11-slim, uv, CPU-only torch wheel for sentence-transformers), `docker-compose.yml` with service `app` (Streamlit on 8501, published on the host's loopback only), volumes `./data:/app/data`, `./configs:/app/configs`, env file `.env`, optional so that a clean clone starts (changed: see status.md D54). `.dockerignore` keeps `.env`, `data/` and `.git` out of the build context.
- `docker compose up` MUST start the dashboard from existing processed data, for `LOGTRIAGE_TESTBED` (default santos). The container needs `LOGTRIAGE_APP__HOST=0.0.0.0`, as `app.host` is local by default (changed: see status.md D50). Building data runs via the CLI (`docker compose run app logtriage prepare ...` or locally).
- The image holds the embedding model at `rag.embedding_revision` and sets offline mode, so `up` needs no network; only the chat needs it, to reach the LLM (changed: see status.md D52).
- The container never scores a test testbed, even with `--rerun-reason`: `detect`, the supervised test stage and `investigate` refuse every testbed but dev where `/etc/logtriage-container` exists (changed: see status.md D53, D57).
- `agent.duckdb` holds tables, so it works from any working directory and mount point; `eval.duckdb` keeps paths relative to the repository root, and the dashboard does not open it (changed: see status.md D41).

### 9.3 CLI (`logtriage/cli.py`)

`download`, `inventory`, `prepare` (parse + drain + labels + features), `detect` (fit + score + incidents), `index-attack`, `investigate` (agents over incidents), `ablate` and `llm-only` (M11, santos only, once per stage) (changed: see status.md D65, D66), `evaluate`, `app`. Every command takes `--testbed` and `--config`. `app` also takes `--live` (changed: see status.md D51).

Each test testbed runs `detect`, the supervised test stage and `investigate` once. A repeat needs `--rerun-reason`, and every run is written to `reports/results/test_runs.csv` by `logtriage/guards.py`. That ledger carries the guard because `prepare` deletes `scores.parquet` and `incidents.parquet` (changed: see status.md D57). Since M12 `prepare` is guarded the same way: once per test testbed, a ledger row before any output, a repeat or existing processed files need `--rerun-reason`, and the container refuses it (changed: see status.md D83). Since M12 the ledger also records each run's `mode` (v1 or v2), `commit` and the sha256 of its config file and of the file it extends; `detect` with `configs/v2.yaml` is the v2 mode, writes to `data/processed/<testbed>/v2/` and is recorded as `detect:v2`, once (changed: see status.md D86). `investigate` with `configs/v2.yaml` investigates v2's incidents from `v2/agent.duckdb`, writes to `v2/reports/` and `reports/results/agents_<testbed>_v2.csv`, keeps its incident memory in `v2/memory/`, and is recorded as `investigate:v2`, once; on the M12 testbeds a paid answer from another model than the M11 one stops it (changed: see status.md D89, D90).

---

## 10. Evaluation (`logtriage/eval/`)

All numbers on the **santos evaluation period** unless stated. Dev numbers are reported separately as "dev". §10.7 adds the extra test testbeds; §10.1–§10.6 and the targets stay as they are (changed: see status.md D56).

### 10.1 Ground truth derivations

- Window is `attack` if it contains ≥ 1 labeled line. Window phases = phases of its labeled lines.
- Incident is `malicious` if any of its windows is an attack window; its phases = union of window phases.
- **Phases with traces** = phases having ≥ 1 labeled line in the processed log types of the testbed (fixed in M3; this is the recall denominator). The denominator is computed over baseline-capable log types (§6.4); phases excluded by this are listed explicitly in `reports/targets.md`, and the conservative variant over all parsed log types is reported as secondary (changed: see status.md D15, D19).

- **Label-ambiguous**: every window of log type `dns` on host `inet-dns`, because that host holds unlabeled copies of the exfiltration. An incident is label-ambiguous if it has such a window and no attack window. `reports/targets.md` gives the exact rule (changed: see status.md D17).

### 10.2 Metrics

| Metric | Definition |
|---|---|
| Window P/R/F1, PR-AUC | per log type and pooled, using `score` and `is_anomalous`. `dns` results are also reported separately because of the contaminated baseline (changed: see status.md D16). Label-ambiguous windows are left out, and a secondary number includes them (changed: see status.md D17) |
| Phase recall | a phase is detected if ≥ 1 anomalous window that belongs to an incident contains a labeled line of that phase; recall = detected / phases with traces. Secondary variant: the same without `dnsteal_exfil`, in both counts (changed: see status.md D16) |
| Alert reduction | per day: incidents vs anomalous windows vs IDS alerts (AIT-ADS, same period) vs IDS alerts grouped with the same gap rule (§6.6, entity = host) |
| Verdict | confusion matrix (3 predicted classes × 2 true). F1 with `uncertain` counted as non-benign. Label-ambiguous incidents are left out, and a secondary number includes them (changed: see status.md D17) |
| ATT&CK top-1/top-3 | per malicious incident: hit if any predicted technique in top-k ∈ union of gold sets of the incident's phases. Strict = exact ID. Lenient (secondary) = parent technique match. |
| Faithfulness (primary) | manual annotation: share of claims supported by their cited lines, on a sample of ≥ 100 claims, rated by the team blind to the condition (Verifier on/off). NOT MEASURED: there are no human annotators; "AI-annotated faithfulness" is reported instead, by two independent subagents with κ, and is not this metric (changed: see status.md D67). Each cited line is shown to the raters as its Evidence (§5.7): host, log type, file, time and raw text; the earlier raw-text-only reading is kept beside it (changed: see status.md D71) |
| Faithfulness (auto) | Verifier LLM judgment (reported, but labelled as self-assessment) |
| Hallucinated citations | share of claims citing non-existent eids before the Verifier |
| Cost/latency | USD and seconds per incident (mean, p90), tokens |
| Human evaluation | usefulness and readability 1–5, ≥ 2 raters, ≥ 20 reports; report mean and agreement (Cohen's κ on binarized scores). NOT PERFORMED, with no AI substitute (changed: see status.md D68) |

### 10.3 Baselines

1. **IDS**: AIT-ADS alerts for santos. Phase recall = phase detected if ≥ 1 alert with that phase label (prefer the event-based label over the time-based one). AIT-ADS has no per-alert label, so the event-based label is derived: an alert carries a phase if its log text equals a labeled line's raw text, host not compared. Event recall (lower bound, primary) and time-based recall (upper bound) are both reported (changed: see status.md D64). Alert counts as above.
2. **ML only**: incidents without agents (verdict = malicious for all). Gives verdict and alert-reduction numbers.
3. **LLM only**: stratified sample of 40 windows' raw lines (20 attack, 20 normal; ≤ 300 lines per sample, chronological). Prompt for verdict + top-3 techniques. Report the same metrics on the sample and the extrapolated cost for the full evaluation period. The draw and the run are fixed in `reports/m11_design.md` §3c (changed: see status.md D66).
4. **Supervised reference**: §6.7.

### 10.4 Ablations (on all santos incidents, or the top 100 by priority if more)

Verifier on/off · RAG on/off in Mapper · zero-shot vs few-shot Reporter. Same incidents, same model, `temperature=0`, cache keyed per condition. Run by `logtriage ablate`, once per condition, apart from the official reports and memory; with n = 3 the results are illustrative (changed: see status.md D65). A paid M11 stage that fails from an API or infrastructure error before writing any output may be retried once, after at least 10 minutes (changed: see status.md D69).

### 10.5 Targets

Finalized in M3 and **frozen** in `reports/targets.md`, unchanged from the proposal (changed: see status.md D20, D21):
- Phase recall ≥ 80% of phases with traces.
- Incidents/day ≤ 25 and ≥ 90% fewer than raw IDS alerts. The budget of 25 is `ml.incidents_per_day_budget`.
- ATT&CK top-3 (strict) ≥ 70%.
- Manual faithfulness ≥ 90% with the Verifier, and higher than without. NOT MEASURED; the target stands as frozen and is not reported as met or missed (changed: see status.md D67).

### 10.6 Outputs

`reports/results/*.csv` + `reports/figures/*.png` (small, committed), a `reports/results.md` summary table generated by `logtriage evaluate`. Files of once-only stages are inputs, read as saved (changed: see status.md D70).

### 10.7 Extra test testbeds (changed: see status.md D56)

Fixed before any result of `wardbeck` or `harrison` exists. Metric definitions (§10.2) and targets (§10.5, `reports/targets.md`) do not change. The santos-only reading against the frozen targets stays the **primary** reading; everything below is additional.

- **Per testbed, always:** every §10.2 metric is reported for each of santos, `wardbeck` and `harrison`. The testbed-specific denominators are in `reports/targets_extra.md`.
- **Pooled summary row** over the three test testbeds; russellmitchell is never in it:

| Metric | Pooled as |
|---|---|
| Phase recall | sum of detected phases / sum of denominators, primary and both secondary variants of §10.1, §10.2 |
| Incidents/day, alert reduction | not pooled: per testbed, each against the budget of 25 |
| ATT&CK top-1/top-3 | over all malicious incidents of the three |
| Verdict | over all malicious incidents of the three; the benign column of the §10.2 confusion matrix adds the other incidents of the three, as F1 needs it; label-ambiguous incidents follow D17 (changed: see status.md D62) |
| Manual faithfulness | one sample of claims from the reports of the three, rated once. NOT MEASURED; AI-annotated faithfulness covers every claim of the three instead (changed: see status.md D67) |

- Ablations (§10.4) and the LLM-only baseline (§10.3) stay on santos: each test testbed runs the agents once.
- Data is never pooled: no model, scaler, vocabulary, percentile reference or threshold is shared between testbeds.
- The three testbeds of this section are fixed (`config.M11_TESTBEDS`). The unseen testbeds of M12 join `test_testbeds`, so every guard covers them, but not this pooled row or `logtriage evaluate`; they are reported by `reports/v2_plan.md` §5–§7 (changed: see status.md D83).

---

## 11. Gold ATT&CK mapping (initial) — `configs/gold_attack_mapping.yaml`

Acceptable sets; the first ID is the primary. Verify against the pinned ATT&CK version (automated existence test + manual review recorded in status.md).

| phase | acceptable techniques |
|---|---|
| `network_scans` | T1046, T1018 |
| `service_scans` | T1046 |
| `dirb` | T1595.003 |
| `wpscan` | T1595.002, T1595.003 |
| `webshell` | T1190, T1505.003 |
| `cracking` | T1110.002 |
| `reverse_shell` | T1059.004, T1059 |
| `privilege_escalation` | T1078.003, T1548.003, T1078 |
| `service_stop` | T1489 |
| `dnsteal` | T1048.003, T1048, T1071.004 |
| `dnsteal_exfil` | T1048.003, T1048, T1071.004 (changed: see status.md D18) |

Phases present in the data but missing here are added in M3 with a logged decision. `vpn_access` is not a phase of these testbeds, because §5.3 adds it only for unassigned VPN lines and there are none, so it has no entry (changed: see status.md D18).

---

## 12. Repository layout

```
.
├── CLAUDE.md  plan.md  status.md  README.md
├── pyproject.toml  uv.lock  .gitignore  .env.example
├── Dockerfile  docker-compose.yml  .dockerignore
├── .github/workflows/ci.yml
├── configs/        default.yaml  sources.yaml  gold_attack_mapping.yaml
├── data_meta/      phases_<testbed>.csv            # small, committed
├── src/logtriage/
│   ├── config.py  cli.py  prepare.py  guards.py (changed: see status.md D57)
│   ├── data/       download.py inventory.py timeutil.py periods.py drain.py labels.py
│   │               windows.py features.py store.py parsers/{common,apache,auth,dns,audit,vpn}.py
│   ├── ml/         models.py ensemble.py incidents.py detect.py supervised.py
│   ├── rag/        attack_index.py incident_store.py
│   ├── agents/     llm.py cache.py schemas.py prompting.py sql_guard.py tools.py graph.py runner.py chat.py prompts/ (changed: see status.md D48)
│   ├── eval/       metrics.py detection.py tuning.py viz.py eda.py baselines.py ablations.py human_eval.py report.py results_text.py tables.py llm_baseline.py faithfulness.py extra_testbeds.py (changed: see status.md D57, D70)
│   └── app/        streamlit_app.py replay.py data.py charts.py ui.py views/ (changed: see status.md D50)
├── notebooks/      01_eda.ipynb 02_preparation.ipynb 03_ml_models.ipynb 04_agents.ipynb 05_evaluation.ipynb
├── tests/          fixtures/ (tiny hand-made log snippets per type + label files) test_*.py
├── reports/        targets.md targets_extra.md results.md results/ figures/ faithfulness/ inventory_<testbed>.md (changed: see status.md D56, D67)
└── data/           (gitignored) raw/ processed/ index/ cache/
```

`.gitignore` MUST include: `data/`, `.env`, `*.sqlite`, `.venv/`, `__pycache__/`, `.ipynb_checkpoints/`, `*.parquet`, `*.duckdb`, `*.zip`.

---

## 13. Milestones

Each milestone = one branch `m<N>-<slug>`. Acceptance criteria are MUST. Notebooks are executed at the milestone that owns them and committed with outputs (keep outputs small: no raw dumps > 100 rows, figures as PNG).

### M0 — Bootstrap (`m0-bootstrap`)
Read: §3, §9.3, §12, §14.
Tasks: pyproject + uv, package skeleton (§12), config loader with `default.yaml`, Typer CLI with stub commands, ruff config, pytest with one smoke test, CI workflow, `.gitignore`, `.env.example`, README (purpose, setup, data license, how to run).
Accept: `uv run pytest` and `uv run ruff check .` pass; `uv run logtriage --help` lists all commands.

### M1 — Data acquisition and inventory (`m1-data`)
Read: §4, §5.3.
Tasks: `download` (Zenodo API, MD5, selective extraction) for russellmitchell, santos, ait_ads; `inventory`: hosts, files, sizes, line counts, which files have labels, label counts per raw label; write `configs/sources.yaml`; build `data_meta/phases_<testbed>.csv`.
Accept: `reports/inventory_<testbed>.md` for both testbeds; `sources.yaml` maps every labeled file of the five families; phases CSVs committed; status.md lists any other labeled log types and the disk usage.

### M2 — Parsing, Drain3, labels (`m2-parse`)
Read: §4.3, §5.1, §5.2, §5.3, §6.1, §6.2.
Tasks: `periods.py`, parsers, time normalization, `line_id`, simulation filter, frozen + online Drain3, `labels.parquet` with phases, DuckDB `agent.duckdb` / `eval.duckdb`, `prepare` command.
Accept: unit tests per parser on fixtures (incl. year handling, empty lines, line numbering); `periods.json` for both testbeds; label line base (0/1) verified and logged; parse rate ≥ 99% per file; 100% of label `line` numbers resolve to a parsed line; ≥ 95% of labeled lines fall in a phase interval (§5.3); label-isolation test (§5.2) exists and passes; re-running `prepare` gives identical template ids; Drain3 throughput logged.

### M3 — EDA and frozen targets (`m3-eda`)
Read: §4.3, §10.1, §10.5, §11.
Tasks: `01_eda.ipynb`: line counts per day/log type/host, attack share (class imbalance), phase timeline vs log types with traces, label-gap analysis (attacker-IP lines in a phase window that are unlabeled, as an estimate), training/eval period check.
Accept: `reports/targets.md` with the frozen targets, the phase list, and the "phases with traces" denominator for both testbeds; gold mapping finalized; incidents/day budget fixed.

### M4 — Windows and features (`m4-features`)
Read: §4.3, §5.4, §6.3.
Tasks: windowing + features in DuckDB SQL, training vocabularies, scaling, `02_preparation.ipynb`.
Accept: tests for entropy, top_domain_share and unseen-vocab features on fixtures; vocabularies and scalers use fit-period data only (test); feature summary table per log type in the notebook.

### M5 — Anomaly detection and incidents (`m5-detect`)
Read: §4.3, §5.5, §5.6, §6.4–§6.6, §6.8, §10.1.
Tasks: models, calibration, ensemble, incident grouping, priority, `detect` command; threshold and gap tuning on dev in `eval/tuning.py`; visualizations; first part of `03_ml_models.ipynb`.
Accept: dev and test results for window P/R/F1/PR-AUC, phase recall and incidents/day printed by the notebook; chosen hyperparameters written to config and logged in status.md; test-testbed run uses no labels (isolation test still green).

### M6 — Supervised reference (`m6-supervised`)
Read: §6.7.
Tasks: RF + XGB, feature importance, finish `03_ml_models.ipynb`.
Accept: PR-AUC table on santos next to the unsupervised ensemble.

### M7 — ATT&CK index and agent tools (`m7-tools`)
Read: §5.1, §7.3, §8, §11.
Tasks: ATT&CK download + index, `index-attack` command, the five tools with the read-only DuckDB connection and SQL guard, incident store.
Note: `log_search` must not surface `parse_ok=False` lines whose `ts` was inherited, or must clearly mark them (changed: see status.md D14).
Accept: unit tests: SQL guard rejects INSERT/UPDATE/DELETE/ATTACH/COPY/PRAGMA/CREATE and multiple statements; tool outputs respect caps; `ip_profile` resolves VPN ↔ external IP on fixtures. `data` tests: gold IDs exist in the index and are not revoked; retrieval sanity (query "many DNS queries with long random subdomains to one domain" returns a T1048* or T1071.004 in the top 5). ATT&CK version logged in status.md.

### M8 — Agent graph (`m8-agents`)
Read: §5.7, §7.1, §7.2, §7.4.
Tasks: LLM client + cache + cost tracking + budget guard, schemas, prompts, graph, runner, `investigate` command, `04_agents.ipynb` with 3 example incidents.
Accept: unit tests of the full graph with a fake LLM (incl. verifier loop and max 2 rounds, retry on invalid JSON, unknown-eid claim marked unsupported); live smoke test passes (tool round trip + one full incident); model string, pricing and ATT&CK version logged in status.md; reports for all santos incidents generated; total cost logged.

### M9 — Chat, dashboard, replay (`m9-ui`)
Read: §7.5, §9.1, §9.3.
Accept: `uv run logtriage app` shows all four pages on santos data; replay works at 600×; chat answers a follow-up with citations (manual check noted in status.md); no label data in agent/chat context (test).

### M10 — Docker (`m10-docker`)
Read: §9.2.
Accept: on a clean clone with `data/` present, `docker compose up` serves the dashboard; README documents it.

### M10b — Extra test testbeds (`m10b-testbeds`) (changed: see status.md D55, D56)
Read: §2, §4, §5.2, §5.3, §6.3–§6.5, §10, §11, §14.
Preparation only: no `detect`, supervised run, `investigate`, `evaluate`, scoring notebook or LLM call on any testbed. Tuning stays on russellmitchell.
Tasks: draw two testbeds before any download, config list, pooling rules (§10.7), guards on all test testbeds, download, inventory, `prepare`, EDA, and the D28 exposure from window counts.
Accept: draw committed before any download; parse rate ≥ 99% per file or reported; russellmitchell and santos processed files unchanged by sha256; a test per guard; `reports/targets_extra.md` committed, with its hash in status.md.

### M11 — Evaluation (`m11-eval`)
Read: §10, §11.
Tasks: metrics, baselines, ablations, LLM-only baseline, AI-annotated faithfulness, `evaluate` command, `05_evaluation.ipynb`, `reports/results.md` (changed: see status.md D67, D68).
Accept: every metric in §10.2 and every baseline/ablation in §10.3–10.4 has a number, except manual faithfulness, marked NOT MEASURED, and human evaluation, marked NOT PERFORMED, in results.md and status.md (changed: see status.md D67, D68); results regenerate from cache with one command.

### M12 — v2: detection improvement on dev, measured once on shaw and fox against v1 (`m12-v2`) (changed: see status.md D74, D77, D85)
Read: §4.3, §6.3–§6.6, §10.1, §10.5, §10.7, §14.3, `reports/v2_plan.md`.
Tasks: diagnose dev phase misses from saved files; write `reports/v2_plan.md` (candidates, selection rule, shaw protocol, cost, what counts as helping) and commit it before any candidate is measured; implement the candidates in `ml/`, label-free and the same rule on every testbed; select on russellmitchell only by the §6.5 rule; then shaw and fox, the first two feasible unseen testbeds of the D55 order (wheeler fails the D55 criteria): prepare, EDA and frozen denominators in `reports/targets_shaw.md` and `reports/targets_fox.md` before any detection, then v1 and v2 each run once on each through `guards.py`. Agents stay as in v1 (frozen prompts, retrieval, `deepseek-flash`); only detection changes.
Accept: `reports/v2_plan.md` committed before the first candidate number; v2 chosen on dev by the pre-declared rule; on shaw and on fox, v1 and v2 each run once with ledger rows; results reported against the readings fixed in `reports/v2_plan.md`. v1 results on santos, `wardbeck` and `harrison` stay the official v1 results; any v2 number there is secondary "seen data" only.
Dropped: the DeepLog stretch. Memory evaluation is moot, since `similar_incidents` was never called (status.md Open questions).
Status (changed: see status.md D86–D93): v2 frozen on dev (D78: b+d, `q` 0.996, gap 30); shaw and fox prepared and frozen; v1 and v2 each ran `detect` and `investigate` once on both, v1 also the supervised stage. `reports/results_v2.md`, generated by `python -m logtriage.eval.results_v2`, reads §7 as written: v1 8 of 17 phases, v2 9 of 17 ("helps", one phase, through candidate b). `configs/default.yaml` stays v1 and v2 ships as the opt-in `configs/v2.yaml` (D93). Faithfulness is not measured on shaw or fox (D91).

### M13 — Finalize (`m13-final`)
README complete (architecture figure, results table, how to reproduce), all notebooks executed in order from a clean state, license/attribution, final status.md, an AI browser check of the dashboard pages (changed: see status.md D68).
Accept: fresh-clone reproduction steps verified; tag `v1.0`.

Order constraints: M7 may start after M2 (in parallel with M3–M6 on its own branch). Everything else is sequential.

---

## 14. Git workflow and Definition of Done

### 14.1 Workflow (Claude Code manages the repo)

1. Start of milestone: `git switch main && git pull` (if a remote exists), then `git switch -c m<N>-<slug>`.
2. Commit small, coherent steps with Conventional Commits: `feat(data): ...`, `fix(ml): ...`, `test: ...`, `docs: ...`, `chore: ...`, `refactor: ...`. Reference plan sections in the body when relevant.
3. Before merging: `uv run ruff check . && uv run ruff format --check . && uv run pytest -m "not live"` all green (live tests additionally when the milestone requires them, e.g. M8), acceptance criteria met, status.md updated.
4. Merge: `git switch main && git merge --no-ff m<N>-<slug> -m "merge: M<N> <title>"`, `git tag m<N>-done`, push main and tags if a remote exists, delete the branch (local and remote).
5. Never force-push, never rewrite main history, never commit with failing tests on main.
6. If no remote is configured, work locally and note it once in status.md "Open questions".
7. Large or generated files: never commit `data/`; committed artifacts must be < 5 MB each.

### 14.2 Definition of Done (every milestone)

- Acceptance criteria met and checked off in status.md.
- Tests for new logic (pure functions tested on fixtures, no network, no real LLM).
- Docstrings on public functions; config values instead of magic numbers.
- status.md updated: milestone state, key numbers, decisions, next step.

### 14.3 Changing the plan

If the data or tests show that a decision here is wrong or impossible:
1. Make the smallest change that works.
2. Add an entry to the status.md Decision log (`date, ID, what changed, why, evidence`).
3. Update the affected plan section in the same commit, and mark the change with `(changed: see status.md Dxx)`.
Never change §10 evaluation definitions or `reports/targets.md` after M3 to make results look better. If a definition is buggy, fix it, log it, and report it in results.md.

---

## 15. Reproducibility checklist

- All randomness seeded from config.
- All tunable values in `configs/default.yaml`; chosen values written back and logged.
- Pinned dependency versions in `uv.lock`.
- ATT&CK version, model string, prices and prompt versions recorded in status.md and in report meta.
- LLM cache makes evaluation reruns deterministic and nearly free.
