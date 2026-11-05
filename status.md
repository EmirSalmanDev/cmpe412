# Status

Keep this file short and current. Update it at the end of every session and at every milestone merge.
Format rules: newest entries first in the logs; numbers with their testbed; link plan sections as §N.

## Now
- **Current milestone:** M1 — Data acquisition and inventory (not started)
- **Branch:** —
- **Next step:** Create branch `m1-data` and do the M1 tasks in plan §13.
- **Blockers:** none

## Milestones
- [x] M0 Bootstrap
- [ ] M1 Data acquisition and inventory
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
- Simulation / training / calibration / eval periods per testbed: —
- Chosen hyperparameters (q, gap_minutes, LOF k, ...): —
- Disk usage of raw + processed data: —
- Git remote: origin, https://github.com/EmirSalmanDev/cmpe412.git

## Key results
(Add headline numbers per milestone, e.g. "M5 santos: phase recall 7/9, 18 incidents/day".)

## Decision log
Format: `YYYY-MM-DD · Dxx · what changed · why · evidence`. D1–D7 are the approved design decisions in plan §2.
- 2026-11-05 · M0 · Ruff excludes `*.md` · ruff 0.17 formats Python blocks in Markdown, so `ruff format .` rewrote the §5.7 block in plan.md; the change was restored before any commit and plan.md is unchanged
- 2026-11-05 · M0 · `.gitignore` adds `!src/logtriage/data/` after the required `data/` entry · `data/` matches at any depth and would have ignored the package from §12
- 2026-11-05 · M0 · Added `pydantic-settings`, which is not in the §3 list · The config loader needs Pydantic settings with `.env` support
- 2026-11-05 · M0 · Precedence is environment, `.env`, YAML, defaults; overrides use `LOGTRIAGE_` with `__` for nesting; `load_settings` drops any API key found in YAML · §3 asks for env overrides but sets no naming; the key must come only from env
- 2026-11-05 · M0 · CLI defaults are `--testbed russellmitchell` and `--config configs/default.yaml`, relative to the repo root · Dev testbed is the safe default
- 2026-11-05 · D1–D7 · Approved before development (window key, VPN, calibrated ensemble, gap grouping, Drain3 + line_id + UTC, deterministic supervisor + validated LLM outputs, gold mapping sets + metric definitions) · Proposal review · plan §2

## Open questions
(Things that need a human decision. Keep working on other parts meanwhile.)
- CLAUDE.md is listed in §12 but `~/.gitignore_global` ignores it, so it is not committed and a fresh clone will not have it. It was not force-added. Should it be versioned?

## Session log
Format: `YYYY-MM-DD · milestone · what was done · next`.
- 2026-11-05 · M0 · Project config, package skeleton, config loader, CLI stubs, smoke tests, CI, README done; ruff clean, 12 tests pass · Start M1 on `m1-data`
- 2026-11-05 · — · Plan, CLAUDE.md and status.md written · Start M0
