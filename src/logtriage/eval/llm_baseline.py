"""LLM-only baseline (plan 10.3, D66, m11_design.md 3c): raw lines of 40 santos windows, no agents.

The draw reads ground truth, because the sample is stratified by it. The calls never do: they read
only the key columns of the sample file, so the model sees a host, a log type and raw lines.
"""

import math
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import duckdb
import numpy as np
import pandas as pd
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from logtriage import guards
from logtriage.agents.cache import LlmCache
from logtriage.agents.llm import LLMClient, build_chat_model
from logtriage.agents.prompting import load_prompt, wrap_untrusted
from logtriage.agents.schemas import TechniqueId
from logtriage.config import DEV_TESTBED, Settings
from logtriage.data.store import connect_agent
from logtriage.eval import eda
from logtriage.eval.ablations import EXPECTED_FINGERPRINT, RefusingBackend
from logtriage.eval.detection import truth_context
from logtriage.eval.metrics import (
    TOP_K,
    VERDICTS,
    attack_hit,
    load_gold_mapping,
    verdict_scores,
    with_truth,
)
from logtriage.eval.tables import capable_log_types, recall_variants

TESTBED = "santos"
SAMPLE_FILE = "llm_only_sample.csv"
RESULTS_FILE = "llm_only_results.csv"
CHECK_FILE = "llm_only_dev_check.csv"
METRICS_FILE = "eval_llm_only.csv"
COST_FILE = "llm_only_cost.csv"
ROLE = "llm_only"
PROMPT = "llm_only"
CONDITION = {"llm_only": True}
PER_STRATUM = 20
PER_LOG_TYPE = 4
MAX_LINES = 300
DEV_WINDOWS = 2
# Far above the 0.17 USD estimated at the extreme (m11_design.md 3c), so it only stops a fault.
MAX_USD = 0.25
KEY_COLUMNS = ["position", "window_start", "host", "log_type"]


class LlmOnlyAnswer(BaseModel):
    """What the model returns for one window."""

    verdict: Literal["malicious", "benign", "uncertain"]
    techniques: list[TechniqueId] = Field(default_factory=list, max_length=3)


@dataclass
class SampleRun:
    """Answers of a run, in order of the sample."""

    rows: list[dict[str, Any]] = field(default_factory=list)
    spent_usd: float = 0.0


def results_dir(settings: Settings) -> Path:
    """Return `reports/results`."""
    return settings.paths.reports_dir / "results"


def evaluation_population(table: pd.DataFrame) -> pd.DataFrame:
    """Return the windows that may be drawn, in the order of the draw (m11_design.md 3c).

    Args:
        table: Output of `with_truth`: the evaluation windows with a score.

    Returns:
        The windows without the label-ambiguous ones, sorted by key.
    """
    kept = table[~table["is_ambiguous"]]
    order = ["window_start", "host", "log_type"]
    return kept.sort_values(order, kind="stable").reset_index(drop=True)


def draw_attack(
    population: pd.DataFrame, phases: list[str], rng: np.random.Generator, size: int
) -> list[int]:
    """Take windows from one pool per phase, in turn, so that rare phases are in the sample.

    Args:
        population: Output of `evaluation_population`.
        phases: Phases of the primary denominator, in time order.
        rng: The generator of the draw.
        size: Windows to take.

    Returns:
        Row positions in `population`, at most `size`.
    """
    attack = population[population["is_attack"]]
    pools: list[list[int]] = []
    for phase in phases:
        pool = [int(i) for i in attack.index if phase in attack.at[i, "phases"]]
        rng.shuffle(pool)
        pools.append(pool)
    taken: list[int] = []
    while len(taken) < size and any(pools):
        for pool in pools:
            while pool:
                item = pool.pop(0)
                if item not in taken:
                    taken.append(item)
                    break
            if len(taken) == size:
                break
    return taken


def draw_normal(
    population: pd.DataFrame, rng: np.random.Generator, size: int, each: int
) -> list[int]:
    """Take `each` windows per log type, in alphabetical order; a short pool passes on the rest.

    Args:
        population: Output of `evaluation_population`.
        rng: The generator of the draw.
        size: Windows to take.
        each: Windows per log type.

    Returns:
        Row positions in `population`, at most `size`.
    """
    normal = population[~population["is_attack"]]
    pools: list[list[int]] = []
    for name in sorted(normal["log_type"].unique()):
        pool = [int(i) for i in normal.index[normal["log_type"] == name]]
        rng.shuffle(pool)
        pools.append(pool)
    taken: list[int] = []
    for pool in pools:
        taken += pool[:each]
        del pool[:each]
    while len(taken) < size and any(pools):
        for pool in pools:
            if pool and len(taken) < size:
                taken.append(pool.pop(0))
    return taken[:size]


def draw_sample(population: pd.DataFrame, phases: list[str], seed: int) -> pd.DataFrame:
    """Draw 20 attack and 20 normal windows with one generator (m11_design.md 3c).

    Args:
        population: Output of `evaluation_population`.
        phases: Phases of the primary denominator, in time order.
        seed: The project seed.

    Returns:
        The windows, shuffled, with `position`, `stratum` and `phases`.
    """
    rng = np.random.default_rng(seed)
    attack = draw_attack(population, phases, rng, PER_STRATUM)
    normal = draw_normal(population, rng, PER_STRATUM, PER_LOG_TYPE)
    chosen = np.array(attack + normal)
    rng.shuffle(chosen)
    sample = population.loc[chosen, ["window_start", "host", "log_type", "is_attack", "phases"]]
    sample = sample.reset_index(drop=True)
    sample.insert(0, "position", range(1, len(sample) + 1))
    sample.insert(4, "stratum", np.where(sample["is_attack"], "attack", "normal"))
    sample["phases"] = sample["phases"].map(" ".join)
    return sample.drop(columns="is_attack")


def window_lines(
    con: duckdb.DuckDBPyConnection, key: dict[str, Any], seconds: int, cap: int = MAX_LINES
) -> list[str]:
    """Return the raw parsed lines of a window, chronological, the first `cap` of them.

    Args:
        con: A connection with the `lines` table.
        key: `host`, `log_type` and `window_start`.
        seconds: Window length.
        cap: Most lines kept.

    Returns:
        The raw lines.
    """
    rows = con.execute(
        f"""
        SELECT raw FROM lines
        WHERE parse_ok AND host = ? AND log_type = ?
          AND time_bucket(INTERVAL {int(seconds)} SECOND, ts) = ?
        ORDER BY ts, line_no LIMIT {int(cap)}
        """,
        [key["host"], key["log_type"], key["window_start"]],
    ).fetchall()
    return [row[0] for row in rows]


def line_coverage(
    con: duckdb.DuckDBPyConnection, sample: pd.DataFrame, seconds: int, cap: int = MAX_LINES
) -> pd.DataFrame:
    """Return lines and labeled lines of each sampled window, kept and in all.

    Args:
        con: A connection to `eval.duckdb`.
        sample: Output of `draw_sample`.
        seconds: Window length.
        cap: Most lines kept.

    Returns:
        `lines`, `lines_kept`, `labeled_lines`, `labeled_kept`, in the order of the sample.
    """
    rows = []
    for key in sample.to_dict("records"):
        found = con.execute(
            f"""
            SELECT b.line_id IS NOT NULL AS labeled FROM lines l
            LEFT JOIN (SELECT DISTINCT line_id FROM labels) b USING (line_id)
            WHERE l.parse_ok AND l.host = ? AND l.log_type = ?
              AND time_bucket(INTERVAL {int(seconds)} SECOND, l.ts) = ?
            ORDER BY l.ts, l.line_no
            """,
            [key["host"], key["log_type"], key["window_start"]],
        ).fetchall()
        labeled = [row[0] for row in found]
        rows.append(
            {
                "lines": len(labeled),
                "lines_kept": min(len(labeled), cap),
                "labeled_lines": sum(labeled),
                "labeled_kept": sum(labeled[:cap]),
            }
        )
    return pd.DataFrame(rows)


def run_draw(settings: Settings) -> Path:
    """Draw the sample and write it. It runs once: the file is committed before any call.

    Args:
        settings: Loaded settings.

    Returns:
        The sample file.

    Raises:
        ValueError: If the sample already exists.
    """
    path = results_dir(settings) / SAMPLE_FILE
    if path.exists():
        raise ValueError(f"{path} exists: the sample is drawn once")
    directory = settings.paths.processed_dir / TESTBED
    scores = pd.read_parquet(directory / "scores.parquet")
    periods = eda.testbed_periods(TESTBED, settings)
    capable = capable_log_types(directory)
    seconds = settings.features.window_seconds
    with eda.connect(TESTBED, settings) as con:
        context = truth_context(con, periods, capable, settings)
        denominators = eda.phase_denominators(con, eda.phase_traces(con, periods), capable)
        order = con.execute("SELECT phase FROM phases ORDER BY start_utc").fetchall()
        primary = recall_variants(denominators)["primary"]
        phases = [row[0] for row in order if row[0] in primary]
        population = evaluation_population(with_truth(scores, context.truth))
        sample = draw_sample(population, list(dict.fromkeys(phases)), settings.seed)
        sample = pd.concat([sample, line_coverage(con, sample, seconds)], axis=1)
    path.parent.mkdir(parents=True, exist_ok=True)
    sample.to_csv(path, index=False)
    return path


def read_keys(path: Path) -> pd.DataFrame:
    """Read the key columns of the sample, and nothing a prompt must not see."""
    keys = pd.read_csv(path, usecols=KEY_COLUMNS)
    keys["window_start"] = pd.to_datetime(keys["window_start"], utc=True)
    return keys.sort_values("position").reset_index(drop=True)


def window_prompt(host: str, log_type: str, lines: list[str], system: str) -> list:
    """Return the messages of one window (m11_design.md 3c)."""
    data = f"Host: {host}\nLog type: {log_type}\nLines:\n" + "\n".join(lines)
    return [SystemMessage(system), HumanMessage(wrap_untrusted(data))]


def ask_windows(
    keys: pd.DataFrame, con: duckdb.DuckDBPyConnection, client: LLMClient, seconds: int
) -> SampleRun:
    """Ask the model about each window, in order.

    Args:
        keys: The key columns.
        con: A connection with the `lines` table.
        client: The client.
        seconds: Window length.

    Returns:
        One row per window.

    Raises:
        LLMOutputError: At the first window with no valid answer; nothing is written then.
    """
    system = load_prompt(PROMPT).text
    run = SampleRun()
    for key in keys.to_dict("records"):
        lines = window_lines(con, key, seconds)
        client.begin_incident()
        answer = client.structured(
            ROLE, window_prompt(key["host"], key["log_type"], lines, system), LlmOnlyAnswer
        )
        tally = client.tally
        run.rows.append(
            {
                **key,
                "lines_sent": len(lines),
                "verdict": answer.verdict,
                "techniques": " ".join(answer.techniques),
                "llm_calls": tally.calls,
                "cached_calls": tally.cached_calls,
                "tokens_in": tally.tokens_in,
                "tokens_cached": tally.tokens_cached,
                "tokens_out": tally.tokens_out,
                "cost_usd": tally.cost_usd,
                "latency_s": tally.llm_latency_s,
                "fingerprints": " ".join(tally.fingerprints),
            }
        )
    run.spent_usd = client.run_spent
    return run


def dev_keys(settings: Settings) -> pd.DataFrame:
    """Pick 2 dev windows for the format check, from scores alone, with no ground truth."""
    directory = settings.paths.processed_dir / DEV_TESTBED
    scores = pd.read_parquet(directory / "scores.parquet")
    table = scores[scores["period"] == "eval"][["window_start", "host", "log_type"]]
    table = table.sort_values(["window_start", "host", "log_type"]).reset_index(drop=True)
    rng = np.random.default_rng(settings.seed)
    picks = table.iloc[sorted(rng.choice(len(table), DEV_WINDOWS, replace=False))].copy()
    picks.insert(0, "position", range(1, len(picks) + 1))
    return picks.reset_index(drop=True)


def _client(settings: Settings, cache: LlmCache, backend: Any, replay: bool) -> LLMClient:
    """Return the client of a paid run, or one that cannot pay."""
    config = settings.llm.model_copy(update={"max_usd_per_run": MAX_USD})
    return LLMClient(
        RefusingBackend() if replay else (backend or build_chat_model(settings)),
        cache,
        config,
        CONDITION,
        cache_only=replay,
        expected_fingerprint=None if replay else EXPECTED_FINGERPRINT,
    )


def _ask(
    testbed: str,
    keys: pd.DataFrame,
    settings: Settings,
    backend: Any,
    replay: bool,
    connect: Callable[[Path], duckdb.DuckDBPyConnection] = connect_agent,
) -> SampleRun:
    """Open the agent database and the cache, and ask."""
    cache = LlmCache(settings.paths.cache_dir / "llm.sqlite")
    con = connect(settings.paths.processed_dir / testbed / "agent.duckdb")
    try:
        client = _client(settings, cache, backend, replay)
        return ask_windows(keys, con, client, settings.features.window_seconds)
    finally:
        con.close()
        cache.close()


def _check_stage(stage: str, testbed: str, reason: str, settings: Settings) -> None:
    """Refuse a paid stage that may not run: the container first (D53)."""
    guards.check_container(testbed)
    if not settings.agents.prompts_frozen:
        raise ValueError("freeze the prompts first (agents.prompts_frozen)")
    if not reason.strip():
        raise ValueError(f"{stage} needs a reason")


def _write(run: SampleRun, path: Path) -> None:
    """Write the rows of a run."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(run.rows).to_csv(path, index=False, float_format="%.6f")


def run_check(settings: Settings, reason: str, backend: Any = None) -> SampleRun:
    """Check the output format once, on 2 dev windows, before santos runs (D66)."""
    _check_stage(guards.LLM_ONLY_CHECK, DEV_TESTBED, reason, settings)
    guards.check_once(guards.LLM_ONLY_CHECK, DEV_TESTBED, settings)
    guards.record_stage(guards.LLM_ONLY_CHECK, DEV_TESTBED, settings, reason)
    run = _ask(DEV_TESTBED, dev_keys(settings), settings, backend, replay=False)
    _write(run, results_dir(settings) / CHECK_FILE)
    return run


def run_sample(
    settings: Settings, reason: str, backend: Any = None, retry: bool = False
) -> SampleRun:
    """Ask the model about the 40 santos windows, once (D66). A failure writes no output.

    Args:
        settings: Loaded settings.
        reason: Why it runs; it goes in the ledger.
        backend: Chat model; the configured one if None.
        retry: The one retry after an API failure (D69). It is told the time of the failure by
            the ledger file of the stage.

    Returns:
        The answers.
    """
    _check_stage(guards.LLM_ONLY, TESTBED, reason, settings)
    output = results_dir(settings) / RESULTS_FILE
    stage = guards.LLM_ONLY
    marker = settings.paths.cache_dir / "llm_only_failed_at.txt"
    if retry:
        failed = pd.Timestamp(marker.read_text(encoding="utf-8").strip()).to_pydatetime()
        guards.check_retry(stage, TESTBED, settings, failed, [output])
        stage = guards.retry_name(stage)
    else:
        guards.check_once(stage, TESTBED, settings)
    keys = read_keys(results_dir(settings) / SAMPLE_FILE)
    guards.record_stage(stage, TESTBED, settings, reason)
    try:
        run = _ask(TESTBED, keys, settings, backend, replay=False)
    except BaseException:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(pd.Timestamp.now(tz="UTC").isoformat(), encoding="utf-8")
        raise
    _write(run, output)
    return run


def replay_outputs(settings: Settings) -> None:
    """Write the answers of both stages again from the cache; any miss raises.

    Args:
        settings: Loaded settings.

    Raises:
        CacheMissError: If a call would have to be paid.
    """
    sample = read_keys(results_dir(settings) / SAMPLE_FILE)
    _write(_ask(TESTBED, sample, settings, None, True), results_dir(settings) / RESULTS_FILE)
    check = _ask(DEV_TESTBED, dev_keys(settings), settings, None, True)
    _write(check, results_dir(settings) / CHECK_FILE)


def sample_metrics(
    sample: pd.DataFrame, results: pd.DataFrame, gold: dict[str, list[str]]
) -> dict[str, Any]:
    """Return verdict and ATT&CK metrics on the sample (plan 10.3).

    Args:
        sample: The whole sample file.
        results: The answers.
        gold: Gold mapping.

    Returns:
        The confusion matrix with `uncertain` as non-benign, and ATT&CK hits on attack windows,
        scored against the union of the gold sets of the phases of each window.
    """
    joined = sample.merge(results[["position", "verdict", "techniques"]], on="position")
    if len(joined) != len(sample):
        raise ValueError("answers and sample differ")
    counts: dict[str, Any] = {}
    for verdict in VERDICTS:
        chosen = joined[joined["verdict"] == verdict]
        counts[f"{verdict}_true_malicious"] = int((chosen["stratum"] == "attack").sum())
        counts[f"{verdict}_true_benign"] = int((chosen["stratum"] == "normal").sum())
    entry: dict[str, Any] = {"windows": len(joined), **counts, **verdict_scores(counts)}
    attack = joined[joined["stratum"] == "attack"]
    predicted = attack["techniques"].fillna("").map(str.split)
    wanted = attack["phases"].map(lambda text: {t for p in text.split() for t in gold[p]})
    entry["attack_windows"] = len(attack)
    for k in TOP_K:
        for kind, lenient in (("strict", False), ("lenient", True)):
            hits = [attack_hit(p, w, k, lenient) for p, w in zip(predicted, wanted, strict=True)]
            entry[f"top{k}_{kind}_hits"] = int(sum(hits))
            entry[f"top{k}_{kind}"] = sum(hits) / len(hits) if hits else float("nan")
    return entry


def cost_summary(results: pd.DataFrame) -> dict[str, float]:
    """Return tokens, cost and latency of the sample."""
    return {
        "tokens_in": int(results["tokens_in"].sum()),
        "tokens_cached": int(results["tokens_cached"].sum()),
        "tokens_out": int(results["tokens_out"].sum()),
        "cost_usd": float(results["cost_usd"].sum()),
        "cost_mean_usd": float(results["cost_usd"].mean()),
        "latency_mean_s": float(results["latency_s"].mean()),
        "latency_p90_s": float(np.percentile(results["latency_s"], 90)),
    }


def token_rates(results: pd.DataFrame) -> tuple[float, dict[str, float], float]:
    """Measure the fixed input tokens per call, the tokens per line and the output per call.

    The fixed part is the smallest call, a little high because that call holds 2 lines. A line
    rate is what is left of a log type's calls, per line. A regression was tried first: long
    exfiltration lines pushed its intercept to 864 tokens and its `auth` slope below 0.

    Args:
        results: The answers.

    Returns:
        Fixed tokens, tokens per line by log type, and mean output tokens per call.
    """
    fixed = float(results["tokens_in"].min())
    rates = {}
    for name, part in results.groupby("log_type"):
        rates[str(name)] = float((part["tokens_in"] - fixed).sum() / part["lines_sent"].sum())
    return fixed, rates, float(results["tokens_out"].mean())


def period_counts(settings: Settings) -> tuple[pd.Series, int, int]:
    """Count the lines and the calls of the whole evaluation period, without ground truth.

    Args:
        settings: Loaded settings.

    Returns:
        Lines by log type, calls (`sum(ceil(n / 300))` over the windows) and windows.
    """
    directory = settings.paths.processed_dir / TESTBED
    scores = pd.read_parquet(directory / "scores.parquet")
    windows = scores[scores["period"] == "eval"][["host", "log_type", "window_start"]]
    seconds = int(settings.features.window_seconds)
    con = connect_agent(directory / "agent.duckdb")
    try:
        counts = con.execute(
            f"""
            SELECT host, log_type, time_bucket(INTERVAL {seconds} SECOND, ts) AS window_start,
                   count(*) AS n FROM lines WHERE parse_ok GROUP BY ALL
            """
        ).df()
    finally:
        con.close()
    merged = windows.merge(counts, how="left", on=["host", "log_type", "window_start"])
    merged["n"] = merged["n"].fillna(0).astype(int)
    calls = int(merged["n"].map(lambda n: max(1, math.ceil(n / MAX_LINES))).sum())
    return merged.groupby("log_type")["n"].sum(), calls, len(merged)


def extrapolated_cost(results: pd.DataFrame, settings: Settings) -> pd.DataFrame:
    """Return the cost of the whole evaluation period, at both rates, no cached discount (3c).

    Args:
        results: The answers.
        settings: Loaded settings.

    Returns:
        One row per rate band.
    """
    fixed, rates, out_per_call = token_rates(results)
    lines, calls, windows = period_counts(settings)
    tokens_in = sum(rates.get(name, 0.0) * count for name, count in lines.items()) + fixed * calls
    tokens_out = out_per_call * calls
    prices = settings.llm.pricing_usd_per_1m
    rows = []
    for band, rate in (("off_peak", prices.off_peak), ("peak", prices.peak)):
        rows.append(
            {
                "band": band,
                "windows": windows,
                "lines": int(lines.sum()),
                "calls": calls,
                "fixed_tokens_per_call": fixed,
                "output_tokens_per_call": out_per_call,
                **{f"tokens_per_line_{name}": value for name, value in rates.items()},
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "cost_usd": (tokens_in * rate.input + tokens_out * rate.output) / 1_000_000,
            }
        )
    return pd.DataFrame(rows)


def metric_tables(settings: Settings) -> dict[str, pd.DataFrame]:
    """Return the tables of the baseline, from the sample and the saved answers."""
    directory = results_dir(settings)
    sample = pd.read_csv(directory / SAMPLE_FILE, keep_default_na=False)
    results = pd.read_csv(directory / RESULTS_FILE, keep_default_na=False)
    gold = load_gold_mapping(settings.paths.gold_mapping_file)
    entry = {**sample_metrics(sample, results, gold), **cost_summary(results)}
    return {
        METRICS_FILE.removesuffix(".csv"): pd.DataFrame([entry]),
        COST_FILE.removesuffix(".csv"): extrapolated_cost(results, settings),
    }
