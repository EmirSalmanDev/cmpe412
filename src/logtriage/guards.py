"""Guards of the test testbeds: each is scored once, and never in the container (D39, D47, D53).

Every scored run on a test testbed is written to a committed ledger, `reports/results/
test_runs.csv`. Output files alone cannot carry this guard: `prepare` deletes `scores.parquet`
and `incidents.parquet`, so `prepare` then `detect` would look like a first run (D57).
"""

import csv
import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from logtriage.config import DEV_TESTBED, Settings

logger = logging.getLogger(__name__)

# Written by the Dockerfile. A file, because an environment variable can be set by hand (D51, D53).
CONTAINER_MARKER = Path("/etc/logtriage-container")
RUNS_FILE = "test_runs.csv"
RUN_FIELDS = ["testbed", "stage", "utc", "reason"]
DETECT = "detect"
SUPERVISED = "supervised"
INVESTIGATE = "investigate"
ABLATION = "ablation"
LLM_ONLY = "llm_only"
LLM_ONLY_CHECK = "llm_only_check"


def is_test_testbed(testbed: str, settings: Settings) -> bool:
    """Return True if a testbed is in `test_testbeds`."""
    return testbed in settings.test_testbeds


def check_container(testbed: str) -> None:
    """Refuse every testbed but dev where the image's marker exists, whatever the reason given.

    It compares with the dev constant and not with `test_testbeds`, because `configs/` is mounted
    in the container and can be changed by hand (D53).

    Raises:
        ValueError: In the container, on any testbed but dev.
    """
    if testbed != DEV_TESTBED and CONTAINER_MARKER.exists():
        raise ValueError(f"{testbed}: the container never scores a test testbed")


def runs_path(settings: Settings) -> Path:
    """Return the path of the ledger."""
    return settings.paths.reports_dir / "results" / RUNS_FILE


def recorded_runs(settings: Settings) -> list[dict[str, str]]:
    """Return the rows of the ledger, oldest first, or none if it does not exist."""
    path = runs_path(settings)
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def check_run(
    stage: str, testbed: str, settings: Settings, outputs: Iterable[Path], reason: str | None
) -> None:
    """Allow a stage on a test testbed once; a repeat needs a reason. Other testbeds pass.

    Args:
        stage: `detect`, `supervised` or `investigate`.
        testbed: Testbed name.
        settings: Loaded settings.
        outputs: Files that show the stage already ran, ledger or not.
        reason: Why the stage runs again. `record_run` logs it, and status.md must explain it.

    Raises:
        ValueError: In the container, or if the stage ran and no reason is given.
    """
    check_container(testbed)
    if not is_test_testbed(testbed, settings):
        return
    logged = any(
        row["testbed"] == testbed and row["stage"] == stage for row in recorded_runs(settings)
    )
    if (logged or any(path.exists() for path in outputs)) and not reason:
        raise ValueError(
            f"{testbed}: {stage} already ran; a re-run needs --rerun-reason, logged in status.md"
        )


def check_once(stage: str, testbed: str, settings: Settings) -> None:
    """Allow a paid evaluation stage once on any testbed, with no override (D65, D66).

    It is not `check_run`: these stages have no `--rerun-reason`, and they run on dev as well.

    Raises:
        ValueError: In the container, or if the ledger already holds the stage.
    """
    check_container(testbed)
    if any(row["testbed"] == testbed and row["stage"] == stage for row in recorded_runs(settings)):
        raise ValueError(f"{testbed}: {stage} already ran, and it never runs twice")


def record_stage(stage: str, testbed: str, settings: Settings, reason: str) -> None:
    """Add a paid evaluation stage to the ledger before it starts, on any testbed (D65, D66)."""
    if not reason.strip():
        raise ValueError(f"{stage}: a ledger row needs a reason")
    _append_run(stage, testbed, settings, reason)


def record_run(stage: str, testbed: str, settings: Settings, reason: str | None) -> None:
    """Add a run on a test testbed to the ledger, before it starts, so a crash counts as a run."""
    if not is_test_testbed(testbed, settings):
        return
    _append_run(stage, testbed, settings, reason)
    if reason:
        logger.warning("%s on %s runs again: %s", stage, testbed, reason)


def _append_run(stage: str, testbed: str, settings: Settings, reason: str | None) -> None:
    """Write one row of the ledger."""
    path = runs_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not path.is_file()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RUN_FIELDS)
        if is_new:
            writer.writeheader()
        utc = datetime.now(UTC).isoformat(timespec="seconds")
        writer.writerow({"testbed": testbed, "stage": stage, "utc": utc, "reason": reason or ""})
