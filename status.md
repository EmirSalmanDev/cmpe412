# Status

Keep this file short and current. Update it at the end of every session and at every milestone merge.
Format rules: newest entries first in the logs; numbers with their testbed; link plan sections as §N.

## Now
- **Current milestone:** M0 — Bootstrap (not started)
- **Branch:** —
- **Next step:** Create branch `m0-bootstrap` and do the M0 tasks in plan §13.
- **Blockers:** none

## Milestones
- [ ] M0 Bootstrap
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
- Git remote: —

## Key results
(Add headline numbers per milestone, e.g. "M5 santos: phase recall 7/9, 18 incidents/day".)

## Decision log
Format: `YYYY-MM-DD · Dxx · what changed · why · evidence`. D1–D7 are the approved design decisions in plan §2.
- 2026-11-05 · D1–D7 · Approved before development (window key, VPN, calibrated ensemble, gap grouping, Drain3 + line_id + UTC, deterministic supervisor + validated LLM outputs, gold mapping sets + metric definitions) · Proposal review · plan §2

## Open questions
(Things that need a human decision. Keep working on other parts meanwhile.)
- —

## Session log
Format: `YYYY-MM-DD · milestone · what was done · next`.
- 2026-11-05 · — · Plan, CLAUDE.md and status.md written · Start M0
