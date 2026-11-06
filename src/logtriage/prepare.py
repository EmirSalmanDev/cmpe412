"""The `prepare` pipeline: periods, parsing, templates, features and databases (plan 9.3)."""

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

from logtriage.config import Settings, load_sources
from logtriage.data.drain import add_templates
from logtriage.data.features import build_windows
from logtriage.data.labels import (
    build_eval_db,
    build_labels,
    phase_report,
    read_phases_csv,
    write_labels,
)
from logtriage.data.parsers import find_log_files, parse_file
from logtriage.data.parsers.common import ParseContext
from logtriage.data.periods import (
    Periods,
    compute_periods,
    read_simulation_interval,
    write_periods,
)
from logtriage.data.store import (
    DETECTION_TABLES,
    build_agent_db,
    template_digest,
    write_lines,
)

logger = logging.getLogger(__name__)


def _prepare_lines(
    testbed: str, testbed_dir: Path, out_dir: Path, periods: Periods, settings: Settings
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse, template and write every log type; return `line_id` to `ts` and the report."""
    sources = load_sources(settings.paths.sources_file)
    context = ParseContext(sim_start=periods.sim_start)
    files = find_log_files(testbed_dir, sources)
    timestamps: dict[str, Any] = {}
    report: dict[str, Any] = {"files": [], "log_types": {}}
    for log_type in sources.log_types:
        rows: list[dict[str, Any]] = []
        for log_file in (item for item in files if item.log_type == log_type):
            kept, stats = parse_file(log_file, testbed, context, periods.sim_end)
            rows += kept
            report["files"].append({**asdict(stats), "parse_rate": stats.parse_rate})
        rows.sort(key=lambda row: (row["ts"], row["host"], row["file"], row["line_no"]))
        drain = add_templates(rows, periods.fit_end, settings.drain, out_dir / "drain", log_type)
        write_lines(rows, out_dir / f"lines_{log_type}.parquet")
        timestamps.update((row["line_id"], row["ts"]) for row in rows)
        report["log_types"][log_type] = {
            **asdict(drain),
            "lines_per_second": drain.lines_per_second,
            "template_digest": template_digest(rows),
        }
        logger.info(
            "%s %s: %d lines, %d templates, %.0f lines/s",
            testbed,
            log_type,
            drain.lines,
            drain.online_templates,
            drain.lines_per_second,
        )
    return timestamps, report


def refresh_databases(testbed: str, settings: Settings) -> None:
    """Rebuild `agent.duckdb` and `eval.duckdb` so that they show every table on disk.

    `detect` calls this through the CLI, because `logtriage.ml` may not touch ground truth.
    """
    out_dir = settings.paths.processed_dir / testbed
    build_agent_db(out_dir)
    build_eval_db(out_dir, settings.paths.data_meta_dir / f"phases_{testbed}.csv")


def run_prepare(testbed: str, settings: Settings) -> Path:
    """Build everything under `data/processed/<testbed>/`.

    Args:
        testbed: Testbed name.
        settings: Loaded settings.

    Returns:
        The output directory.

    Raises:
        FileNotFoundError: If the testbed or its phases file is missing.
    """
    testbed_dir = settings.paths.raw_dir / testbed
    out_dir = settings.paths.processed_dir / testbed
    phases_csv = settings.paths.data_meta_dir / f"phases_{testbed}.csv"
    if not phases_csv.is_file() or not (testbed_dir / "dataset.yaml").is_file():
        raise FileNotFoundError(f"{testbed}: run `logtriage download` and `logtriage inventory`")
    phases = read_phases_csv(phases_csv)
    sim_start, sim_end = read_simulation_interval(testbed_dir / "dataset.yaml")
    periods = compute_periods(
        testbed, sim_start, sim_end, phases, settings.phases.published_source, settings.periods
    )
    write_periods(periods, out_dir / "periods.json")
    logger.info("%s: training %.1f h", testbed, periods.training_hours)

    timestamps, report = _prepare_lines(testbed, testbed_dir, out_dir, periods, settings)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (out_dir / "prepare_report.json").write_text(text, encoding="utf-8")
    for name in DETECTION_TABLES:  # they describe the windows that are about to be replaced
        (out_dir / f"{name}.parquet").unlink(missing_ok=True)
    build_windows(out_dir, periods, settings)
    build_agent_db(out_dir)

    sources = load_sources(settings.paths.sources_file)
    rows, labels = build_labels(testbed_dir, timestamps, phases, sources, settings.phases)
    write_labels(rows, labels, out_dir)
    build_eval_db(out_dir, phases_csv)
    for item in phase_report(labels):
        logger.info("%s labels: %s", testbed, item)
    return out_dir
