# LogTriage Agent

ML anomaly detection on AIT-LDS security logs + a LangGraph agent (DeepSeek V4 Flash) that writes evidence-cited, ATT&CK-mapped incident reports.

## Every session
1. Read `status.md` first. It says the current milestone and next step.
2. Read only the `plan.md` sections listed for that milestone (§13). `plan.md` is the source of truth for design, schemas and acceptance criteria.
3. Before ending: update `status.md` and commit it.

## Hard rules
- Labels (`labels.parquet`, phases, window/incident ground truth) are read only by the modules allowed in plan §5.2 (eval, tuning on dev, supervised reference, EDA). Never in features, unsupervised models, agent tools, prompts or the agent/chat context. Period boundaries come from `periods.json` (plan §4.3).
- Every log line keeps `line_id = host|file|line_no` (1-based line number in the original file) from parsing to the report. Never renumber.
- All timestamps are tz-aware UTC. Dev testbed = `russellmitchell`, test = `santos`, extra test = `wardbeck`, `harrison`, unseen test (M12) = `shaw`, `fox`: five test testbeds (`test_testbeds` in the config). Tune only on dev.
- Never commit `data/`, `.env`, secrets or files > 5 MB. The API key comes only from env `DEEPSEEK_API_KEY`.
- If `data/` (or part of it) is missing, never recreate test-testbed data: no `prepare`, `detect`, `investigate` or supervised stage on any test testbed (`santos`, `wardbeck`, `harrison`, `shaw`, `fox`), and never use `--rerun-reason`. Stop and read `docs/data_bundle/DATA_README.md` (do not read `docs/data_bundle/MANIFEST.txt` into context, it is about 28k tokens; use the verify command from DATA_README instead). Ask the user to download the zip from the README link ("Getting the data") in a browser and put it in the repository root, then extract it there and verify it.
- Unit tests use `tests/fixtures/`, no network, no real LLM (use fakes). Mark tests needing the real API `@pytest.mark.live`, tests needing `data/` or downloaded models `@pytest.mark.data`.
- Teammates: the project is complete. A teammate's session does not create milestone branches, merge to `main`, tag or push to `main` unless the maintainer asks; work on a personal branch or a fork. The test-testbed rules above apply in full.
- If a plan decision is wrong, follow plan §14.3: change it, log it in status.md, update plan.md in the same commit. Never deviate silently. Never change evaluation definitions or frozen targets to improve results.

## Commands
```
uv sync
uv run pytest -m "not live"
uv run ruff check . && uv run ruff format .
uv run logtriage --help
```

## Git (you own the repo; details in plan §14)
- One branch per milestone: `m<N>-<slug>` from `main`. Small Conventional Commits (`feat(data): ...`).
- Merge to `main` with `--no-ff` only when ruff + tests pass and the acceptance criteria are met. Then tag `m<N>-done`, push if a remote exists, delete the branch.
- Never force-push or rewrite `main` history.
- Never add `Co-Authored-By`, `Claude-Session` or "Generated with Claude Code" lines to commits, tags or PR text. Claude and Anthropic must not appear as author, co-author or contributor (D95). `.claude/settings.json` sets `attribution` to empty strings for the same reason.
