"""Guards of the test testbeds: each is scored once, and never in the container (D39, D47, D53).

Every scored run on a test testbed is written to a committed ledger, `reports/results/
test_runs.csv`. Output files alone cannot carry this guard: `prepare` deletes `scores.parquet`
and `incidents.parquet`, so `prepare` then `detect` would look like a first run (D57).
"""

import csv
import hashlib
import logging
import subprocess
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from logtriage.config import DEV_TESTBED, V1_MODE, V2_MODE, Settings

logger = logging.getLogger(__name__)

# Written by the Dockerfile. A file, because an environment variable can be set by hand (D51, D53).
CONTAINER_MARKER = Path("/etc/logtriage-container")
RUNS_FILE = "test_runs.csv"
# `mode`, `commit`, `config_sha256` and `base_sha256` joined in M12 (D86); older rows leave them
# empty. `config_sha256` is the named config file, `base_sha256` the file it extends, if any.
RUN_FIELDS = [
    "testbed",
    "stage",
    "utc",
    "reason",
    "mode",
    "commit",
    "config_sha256",
    "base_sha256",
]
UNKNOWN_COMMIT = "unknown"
PREPARE = "prepare"
DETECT = "detect"
SUPERVISED = "supervised"
INVESTIGATE = "investigate"
ABLATION = "ablation"
LLM_ONLY = "llm_only"
LLM_ONLY_CHECK = "llm_only_check"
# These run once on a test testbed, and no retry rule ever covers them (D57, D69). `prepare`
# joined in M12, so a new test testbed is prepared exactly once (D83). The v2 stages have their
# own names, so v1 and v2 each run once (D86, `reports/v2_plan.md` §5).
ONCE_ONLY = (PREPARE, DETECT, SUPERVISED, INVESTIGATE)
RETRY_SUFFIX = "retry1"
RETRY_WAIT = timedelta(minutes=10)


def mode_stage(stage: str, mode: str) -> str:
    """Return the ledger stage of a stage in a detection mode: `detect`, or `detect:v2`."""
    if mode not in (V1_MODE, V2_MODE):
        raise ValueError(f"{mode}: unknown mode")
    return stage if mode == V1_MODE else f"{stage}:{mode}"


def is_once_only(stage: str) -> bool:
    """Return True for a stage that runs once, in either mode, with no retry rule."""
    return stage.split(":", 1)[0] in ONCE_ONLY


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
        stage: `prepare`, `detect`, `supervised` or `investigate`.
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


def retry_name(stage: str) -> str:
    """Return the ledger stage of the single retry of a stage."""
    return f"{stage}:{RETRY_SUFFIX}"


def is_paid_evaluation_stage(stage: str) -> bool:
    """Return True for an ablation or LLM-only stage, the only ones a retry can cover (D69)."""
    return not is_once_only(stage) and (
        stage.startswith(f"{ABLATION}:") or stage in (LLM_ONLY, LLM_ONLY_CHECK)
    )


def check_retry(
    stage: str,
    testbed: str,
    settings: Settings,
    failed_at: datetime,
    outputs: Iterable[Path],
    now: datetime | None = None,
) -> None:
    """Allow one retry of a paid M11 stage that failed before writing any output (D69).

    Args:
        stage: The stage that failed, as the ledger holds it.
        testbed: Testbed name.
        settings: Loaded settings.
        failed_at: When it ended, tz-aware.
        outputs: What it would have written.
        now: The current time; the clock if None.

    Raises:
        ValueError: In the container; for any other stage; if the stage never ran; on a second
            retry; if it wrote any output; or before `RETRY_WAIT` has passed.
    """
    check_container(testbed)
    if not is_paid_evaluation_stage(stage):
        raise ValueError(f"{stage}: only ablation and LLM-only stages can be retried (D69)")
    stages = {row["stage"] for row in recorded_runs(settings) if row["testbed"] == testbed}
    if stage not in stages:
        raise ValueError(f"{testbed}: {stage} never ran, so there is nothing to retry")
    if retry_name(stage) in stages:
        raise ValueError(f"{testbed}: {stage} already had its one retry: stop and report (D69)")
    if any(path.exists() for path in outputs):
        raise ValueError(f"{testbed}: {stage} wrote output, so it cannot be retried (D69)")
    waited = (now or datetime.now(UTC)) - failed_at
    if waited < RETRY_WAIT:
        raise ValueError(f"{stage}: wait {RETRY_WAIT} after the failure, only {waited} passed")


def record_stage(stage: str, testbed: str, settings: Settings, reason: str, mode: str = "") -> None:
    """Add a paid evaluation stage to the ledger before it starts, on any testbed (D65, D66)."""
    if not reason.strip():
        raise ValueError(f"{stage}: a ledger row needs a reason")
    _append_run(stage, testbed, settings, reason, mode)


def record_run(
    stage: str, testbed: str, settings: Settings, reason: str | None, mode: str = ""
) -> None:
    """Add a run on a test testbed to the ledger, before it starts, so a crash counts as a run.

    Args:
        stage: The ledger stage, with its mode suffix for v2 (`mode_stage`).
        testbed: Testbed name.
        settings: Loaded settings; their config files are hashed into the row.
        reason: Why the stage runs again, or None.
        mode: `v1` or `v2` for a detection-dependent stage, empty for `prepare`.
    """
    if not is_test_testbed(testbed, settings):
        return
    _append_run(stage, testbed, settings, reason, mode)
    if reason:
        logger.warning("%s on %s runs again: %s", stage, testbed, reason)


def file_sha256(path: Path) -> str:
    """Return the sha256 of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_commit() -> str:
    """Return the checked-out commit, with `+dirty` if tracked code or configs differ from it."""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        changed = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no", "--", "src", "configs"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return UNKNOWN_COMMIT
    return f"{commit}+dirty" if changed else commit


def run_fields(settings: Settings, mode: str) -> dict[str, str]:
    """Return the mode, commit and config hashes of a ledger row (D86)."""
    files = settings.config_files
    return {
        "mode": mode,
        "commit": current_commit(),
        "config_sha256": file_sha256(files[0]) if files else "",
        "base_sha256": file_sha256(files[1]) if len(files) > 1 else "",
    }


def _upgrade_header(path: Path) -> None:
    """Rewrite a ledger with an older header under `RUN_FIELDS`; old rows keep their values."""
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames == RUN_FIELDS:
            return
        rows = list(reader)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RUN_FIELDS)
        writer.writeheader()
        writer.writerows({name: row.get(name) or "" for name in RUN_FIELDS} for row in rows)


def _append_run(
    stage: str, testbed: str, settings: Settings, reason: str | None, mode: str
) -> None:
    """Write one row of the ledger."""
    path = runs_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not path.is_file()
    if not is_new:
        _upgrade_header(path)
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RUN_FIELDS)
        if is_new:
            writer.writeheader()
        utc = datetime.now(UTC).isoformat(timespec="seconds")
        writer.writerow(
            {
                "testbed": testbed,
                "stage": stage,
                "utc": utc,
                "reason": reason or "",
                **run_fields(settings, mode),
            }
        )
