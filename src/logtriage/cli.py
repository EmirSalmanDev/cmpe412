"""Typer command line interface (plan 9.3)."""

import logging
import os
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Annotated

import typer

from logtriage.agents.llm import (
    BudgetExceededError,
    CacheMissError,
    EmptyResponseError,
    FingerprintChangedError,
    LLMOutputError,
)
from logtriage.agents.runner import run_incidents
from logtriage.app.data import AppOptions, database_path
from logtriage.app.replay import check_live
from logtriage.config import DEFAULT_CONFIG_PATH, DEV_TESTBED, Settings, load_settings
from logtriage.data.download import InsufficientDiskError, run_download
from logtriage.data.inventory import run_inventory
from logtriage.eval import llm_baseline
from logtriage.eval.ablations import RECHECK, RETRY, run_ablation
from logtriage.eval.report import PaidCallError, run_evaluate
from logtriage.ml.detect import run_detect
from logtriage.prepare import refresh_databases, run_prepare
from logtriage.rag.attack_index import run_index_attack

app = typer.Typer(no_args_is_help=True, help="LogTriage Agent command line interface.")

STREAMLIT_SCRIPT = Path(__file__).parent / "app" / "streamlit_app.py"

TestbedOption = Annotated[str, typer.Option("--testbed", help="Testbed name.")]
ConfigOption = Annotated[Path, typer.Option("--config", help="Path to the YAML config file.")]


@app.callback()
def main() -> None:
    """LogTriage Agent command line interface."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def _report_failure(command: str, error: BaseException) -> None:
    """Print the whole traceback of a failed command, then its one-line message (D69)."""
    trace = "".join(traceback.format_exception(error))
    typer.echo(trace, err=True)
    typer.echo(f"{command} failed: {error}", err=True)


@app.command()
def download(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Download and selectively extract a testbed, or AIT-ADS with `--testbed ait_ads`."""
    try:
        run_download(testbed, load_settings(config))
    except (ValueError, InsufficientDiskError) as error:
        _report_failure("download", error)
        raise typer.Exit(code=1) from error


@app.command()
def inventory(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Write the inventory report and the attack phases file of a testbed."""
    try:
        report = run_inventory(testbed, load_settings(config))
    except (ValueError, FileNotFoundError) as error:
        _report_failure("inventory", error)
        raise typer.Exit(code=1) from error
    typer.echo(f"wrote {report}")


@app.command()
def prepare(
    testbed: TestbedOption = DEV_TESTBED,
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    rerun_reason: Annotated[
        str | None, typer.Option("--rerun-reason", help="Why a test testbed is prepared again.")
    ] = None,
) -> None:
    """Parse logs, then build templates, windows, label tables and the DuckDB files."""
    try:
        out_dir = run_prepare(testbed, load_settings(config), rerun_reason)
    except (ValueError, FileNotFoundError) as error:
        _report_failure("prepare", error)
        raise typer.Exit(code=1) from error
    typer.echo(f"wrote {out_dir}")


@app.command()
def detect(
    testbed: TestbedOption = DEV_TESTBED,
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    rerun_reason: Annotated[
        str | None, typer.Option("--rerun-reason", help="Why a test testbed is scored again.")
    ] = None,
) -> None:
    """Fit anomaly models, score windows and build incidents."""
    settings = load_settings(config)
    try:
        out_dir = run_detect(testbed, settings, rerun_reason)
        refresh_databases(testbed, settings)
    except (ValueError, FileNotFoundError) as error:
        _report_failure("detect", error)
        raise typer.Exit(code=1) from error
    typer.echo(f"wrote {out_dir}")


@app.command("index-attack")
def index_attack(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Build the MITRE ATT&CK retrieval index from the pinned local bundle."""
    try:
        count = run_index_attack(load_settings(config))
    except (ValueError, FileNotFoundError) as error:
        _report_failure("index-attack", error)
        raise typer.Exit(code=1) from error
    typer.echo(f"indexed {count} techniques")


@app.command()
def investigate(
    testbed: TestbedOption = DEV_TESTBED,
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    incident: Annotated[
        list[str] | None, typer.Option("--incident", help="Only this incident; repeatable.")
    ] = None,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Bypass the LLM cache.")] = False,
    rerun_reason: Annotated[
        str | None, typer.Option("--rerun-reason", help="Why a test testbed runs again.")
    ] = None,
) -> None:
    """Run the agents over incidents, highest priority first."""
    try:
        summary = run_incidents(
            testbed,
            load_settings(config),
            incident_ids=incident,
            use_cache=not no_cache,
            rerun_reason=rerun_reason,
        )
    except (ValueError, FileNotFoundError, KeyError) as error:
        _report_failure("investigate", error)
        raise typer.Exit(code=1) from error
    typer.echo(
        f"{len(summary.finished)} reports, {len(summary.failed)} failed, "
        f"{summary.spent_usd:.4f} USD this run, {summary.total_spent_usd:.4f} USD in total"
    )
    if summary.aborted:
        typer.echo(f"stopped: {summary.aborted}", err=True)
        raise typer.Exit(code=2)


@app.command()
def ablate(
    condition: Annotated[
        str, typer.Option("--condition", help="base, verifier0, rag0, few_shot1.")
    ],
    reason: Annotated[str, typer.Option("--reason", help="Why it runs, for the ledger.")],
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    retry: Annotated[
        bool, typer.Option("--retry", help="The one retry after an API failure (D69).")
    ] = False,
    recheck: Annotated[
        bool, typer.Option("--recheck", help="Replay base again, to prove keys held (D69).")
    ] = False,
) -> None:
    """Run one ablation condition on santos, once, apart from the official reports (D65)."""
    attempt = RETRY if retry else RECHECK if recheck else None
    try:
        summary = run_ablation(condition, reason, load_settings(config), attempt=attempt)
    except (
        ValueError,
        FileNotFoundError,
        KeyError,
        CacheMissError,
        FingerprintChangedError,
        EmptyResponseError,
    ) as error:
        _report_failure("ablate", error)
        raise typer.Exit(code=1) from error
    typer.echo(
        f"{condition}: {len(summary.finished)} reports, {len(summary.failed)} failed, "
        f"{summary.spent_usd:.4f} USD this run, {summary.total_spent_usd:.4f} USD in total"
    )
    if summary.aborted:
        typer.echo(f"stopped: {summary.aborted}", err=True)
        raise typer.Exit(code=2)


@app.command("llm-only")
def llm_only(
    stage: Annotated[str, typer.Option("--stage", help="draw, check or run.")],
    reason: Annotated[str, typer.Option("--reason", help="Why it runs, for the ledger.")] = "",
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    retry: Annotated[
        bool, typer.Option("--retry", help="The one retry after an API failure (D69).")
    ] = False,
) -> None:
    """Draw the LLM-only sample, check its format on dev, or run it on santos once (D66)."""
    settings = load_settings(config)
    try:
        if stage == "draw":
            typer.echo(f"wrote {llm_baseline.run_draw(settings)}")
            return
        if stage == "check":
            run = llm_baseline.run_check(settings, reason)
        elif stage == "run":
            run = llm_baseline.run_sample(settings, reason, retry=retry)
        else:
            raise ValueError(f"unknown stage {stage}")
    except (
        ValueError,
        FileNotFoundError,
        KeyError,
        LLMOutputError,
        FingerprintChangedError,
        BudgetExceededError,
    ) as error:
        _report_failure("llm-only", error)
        raise typer.Exit(code=1) from error
    typer.echo(f"{stage}: {len(run.rows)} windows, {run.spent_usd:.4f} USD this run")


@app.command()
def evaluate(config: ConfigOption = DEFAULT_CONFIG_PATH) -> None:
    """Regenerate every derived table and `reports/results.md`, from saved outputs and the cache."""
    try:
        summary = run_evaluate(load_settings(config))
    except (ValueError, FileNotFoundError, KeyError, CacheMissError, PaidCallError) as error:
        _report_failure("evaluate", error)
        raise typer.Exit(code=1) from error
    typer.echo(f"wrote {len(summary.tables)} tables and {summary.results}")


def streamlit_command(settings: Settings) -> list[str]:
    """Return the command that starts the dashboard (plan 9.1).

    Args:
        settings: Loaded settings.

    Returns:
        The command. It sends no usage statistics and watches no files, because the watcher walks
        the modules of `torch` and fails on them.
    """
    return [
        sys.executable, "-m", "streamlit", "run", str(STREAMLIT_SCRIPT),
        "--server.address", settings.app.host,
        "--server.port", str(settings.app.port),
        "--server.fileWatcherType", "none",
        "--browser.gatherUsageStats", "false",
        "--theme.base", "light",
    ]  # fmt: skip


@app.command("app")
def run_app(
    testbed: TestbedOption = DEV_TESTBED,
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    live: Annotated[
        bool,
        typer.Option("--live", help="Replay computes missing reports. Refused on test testbeds."),
    ] = False,
) -> None:
    """Start the Streamlit interface."""
    settings = load_settings(config)
    try:
        if live:
            check_live(testbed, settings)
        if not database_path(settings, testbed).is_file():
            raise ValueError(f"{testbed}: no agent database, run `logtriage prepare` first")
    except ValueError as error:
        _report_failure("app", error)
        raise typer.Exit(code=1) from error
    options = AppOptions(testbed, config, live)
    env = {**os.environ, **options.to_env()}
    result = subprocess.run(streamlit_command(settings), env=env, check=False)
    raise typer.Exit(code=result.returncode)
