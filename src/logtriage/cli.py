"""Typer command line interface (plan 9.3). Commands are stubs until their milestones."""

import logging
from pathlib import Path
from typing import Annotated

import typer

from logtriage.config import DEFAULT_CONFIG_PATH, DEV_TESTBED, load_settings
from logtriage.data.download import InsufficientDiskError, run_download
from logtriage.data.inventory import run_inventory

app = typer.Typer(no_args_is_help=True, help="LogTriage Agent command line interface.")

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
    """Parse logs, then run Drain3, labels and features."""
    _not_implemented("prepare", testbed, config)


@app.command()
def detect(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Fit anomaly models, score windows and build incidents."""
    _not_implemented("detect", testbed, config)


@app.command("index-attack")
def index_attack(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Build the MITRE ATT&CK retrieval index."""
    _not_implemented("index-attack", testbed, config)


@app.command()
def investigate(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Run the agents over incidents."""
    _not_implemented("investigate", testbed, config)


@app.command()
def evaluate(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Compute evaluation metrics and reports."""
    _not_implemented("evaluate", testbed, config)


@app.command("app")
def run_app(
    testbed: TestbedOption = DEV_TESTBED, config: ConfigOption = DEFAULT_CONFIG_PATH
) -> None:
    """Start the Streamlit interface."""
    _not_implemented("app", testbed, config)
