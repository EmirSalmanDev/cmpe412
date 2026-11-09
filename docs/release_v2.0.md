# LogTriage Agent v2.0

Draft release notes, to be pasted into the GitHub release by the repository owner.

## What is new

v2.0 adds **v2, an opt-in detection configuration** (`configs/v2.yaml`). v1 stays the default and the official version: `configs/default.yaml` is unchanged, and so are v1's results in `reports/results.md`.

- **What v2 changes:** detection only. A finer threshold grid, with `q` 0.996 instead of 0.999, and a new `audit` feature, `n_unseen_units`, which counts systemd units not seen in training. Both were chosen on the dev testbed (russellmitchell) only. The agents, prompts, retrieval and model are the same as v1's.
- **How to use it:** pass `--config configs/v2.yaml` to `logtriage detect` and `logtriage investigate`. v2 writes to `data/processed/<testbed>/v2/` with its own incident memory, so it never touches v1's outputs.
- **Two new unseen test testbeds,** shaw and fox, with targets frozen before any detection (`reports/targets_shaw.md`, `reports/targets_fox.md`). wheeler was checked first and failed the dataset feasibility criteria, so fox replaced it.
- **Guards:** `prepare` now runs once per test testbed, and the run ledger records the mode, the commit and the config hash of every run.

## Result

Measured once per version on shaw and fox (`reports/results_v2.md`):

- v2 credits **9 of 17** attack phases, v1 **8 of 17**. The one gain is fox `cracking`, through the lower `q`; the new `audit` feature transferred nothing to either testbed.
- v2 more than doubled incidents on fox, 11 to 24, still within the budget of 25 per day.
- Neither version reaches the 80% phase-recall target on either testbed.
- Agent-level metrics did not improve: summed over shaw and fox, ATT&CK top-3 strict goes from 1 of 3 malicious incidents to 0 of 2, and verdict F1 from 0.261 to 0.100, because v2 adds incidents with no attack in them (uncertain on true benign, 17 to 36). The counts are small, and no cause is claimed for the ATT&CK change.
- The IDS baseline's phase recall (shaw 7/8 to 8/8, fox 7/9 to 9/9) is higher than either version's (v1: shaw 3/8, fox 5/9; v2: shaw 3/8, fox 6/9), as in v1's results.
- This is an observation from one run per testbed, not a statistical result. Faithfulness was not measured on shaw or fox.

The four LLM runs of M12 (v1 and v2 `investigate` on shaw and fox, 59 reports) cost 0.7353 USD, all at peak rates.

## Not changed

- v1's official results for santos, `wardbeck` and `harrison`, and the frozen targets of `reports/targets.md`.
- No v2 number exists for santos, `wardbeck` or `harrison`, since those testbeds were already seen.

The project was built by AI (Claude Code), directed by the repository owner. No human annotators or raters took part.
