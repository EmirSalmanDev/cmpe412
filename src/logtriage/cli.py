"""Typer command line interface (plan 9.3). Commands are stubs until their milestones."""

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer

from logtriage.agents.runner import run_incidents
from logtriage.app.data import AppOptions, database_path
from logtriage.app.replay import check_live
from logtriage.config import DEFAULT_CONFIG_PATH, DEV_TESTBED, Settings, load_settings
from logtriage.data.download import InsufficientDiskError, run_download
from logtriage.data.inventory import run_inventory
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


def _not_implemented(command: str, testbed: str, config: Path) -> None:
    """Print the stub message for a command."""
    typer.echo(f"{command}: not implemented yet (testbed={testbed}, config={config})")


@app.command()
def download(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Download and selectively extract a testbed, or AIT-ADS with `--testbed ait_ads`."""
    try:
        run_download(testbed, load_settings(config))
    except (ValueError, InsufficientDiskError) as error:
        typer.echo(f"download failed: {error}", err=True)
        raise typer.Exit(code=1) from error


@app.command()
def inventory(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Write the inventory report and the attack phases file of a testbed."""
    try:
        report = run_inventory(testbed, load_settings(config))
    except (ValueError, FileNotFoundError) as error:
        typer.echo(f"inventory failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(f"wrote {report}")


@app.command()
def prepare(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Parse logs, then build templates, windows, label tables and the DuckDB files."""
    try:
        out_dir = run_prepare(testbed, load_settings(config))
    except (ValueError, FileNotFoundError) as error:
        typer.echo(f"prepare failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(f"wrote {out_dir}")


@app.command()
def detect(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Fit anomaly models, score windows and build incidents."""
    settings = load_settings(config)
    try:
        out_dir = run_detect(testbed, settings)
        refresh_databases(testbed, settings)
    except (ValueError, FileNotFoundError) as error:
        typer.echo(f"detect failed: {error}", err=True)
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
        typer.echo(f"index-attack failed: {error}", err=True)
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
        str | None, typer.Option("--rerun-reason", help="Why the test testbed runs again.")
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
        typer.echo(f"investigate failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(
        f"{len(summary.finished)} reports, {len(summary.failed)} failed, "
        f"{summary.spent_usd:.4f} USD this run, {summary.total_spent_usd:.4f} USD in total"
    )
    if summary.aborted:
        typer.echo(f"stopped: {summary.aborted}", err=True)
        raise typer.Exit(code=2)


@app.command()
def evaluate(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Compute evaluation metrics and reports."""
    _not_implemented("evaluate", testbed, config)


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
        typer.Option(
            "--live", help="Replay computes missing reports. Refused on the test testbed."
        ),
    ] = False,
) -> None:
    """Start the Streamlit interface."""
    settings = load_settings(config)
    try:
        if live:
            check_live(testbed)
        if not database_path(settings, testbed).is_file():
            raise ValueError(f"{testbed}: no agent database, run `logtriage prepare` first")
    except ValueError as error:
        typer.echo(f"app failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    options = AppOptions(testbed, config, live)
    env = {**os.environ, **options.to_env()}
    result = subprocess.run(streamlit_command(settings), env=env, check=False)
    raise typer.Exit(code=result.returncode)
