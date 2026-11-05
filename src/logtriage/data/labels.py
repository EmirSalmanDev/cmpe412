"""Ground-truth labels and attack phases, for evaluation only (plan 5.2, 5.3).

This is the only `logtriage.data` module that reads label files or phase intervals, apart
from `periods.py`.
"""

import csv
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from logtriage.config import LogSources, PhasesConfig
from logtriage.data.store import create_views, data_views

LABELS_FILE = "labels.parquet"
LABELS_SCHEMA = pa.schema(
    [
        ("line_id", pa.string()),
        ("labels", pa.list_(pa.string())),
        ("rules", pa.string()),
        ("phase", pa.string()),
    ]
)
UNASSIGNED = "unassigned"
PHASE_COLUMNS = ("testbed", "phase", "start_utc", "end_utc", "source")


@dataclass
class LabelSummary:
    """Aggregate counts of one label file."""

    labeled_lines: int = 0
    label_counts: Counter[str] = field(default_factory=Counter)


@dataclass(frozen=True)
class Phase:
    """An attack phase interval. Timestamps are tz-aware UTC."""

    testbed: str
    phase: str
    start: datetime
    end: datetime
    source: str


@dataclass(frozen=True)
class PhaseCheck:
    """Comparison of a phase start with an attack step that should coincide with it."""

    phase: str
    step: str
    phase_start: datetime
    step_time: datetime | None

    @property
    def delta_seconds(self) -> float | None:
        """Phase start minus step time in seconds, or None if the step is not logged."""
        if self.step_time is None:
            return None
        return (self.phase_start - self.step_time).total_seconds()


def summarize_label_file(path: Path) -> LabelSummary:
    """Count labeled lines and raw labels in a JSON Lines label file, streaming it."""
    summary = LabelSummary()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                summary.labeled_lines += 1
                summary.label_counts.update(json.loads(line)["labels"])
    return summary


def read_phase_intervals(path: Path, testbed: str, source: str) -> list[Phase]:
    """Read one testbed's phases from the AIT-ADS `labels.csv`, sorted by start time.

    Args:
        path: CSV with the columns `scenario, attack, start, end` (epoch seconds).
        testbed: Scenario to keep.
        source: Value for the `source` column of the phases file.

    Returns:
        The phases of the testbed.

    Raises:
        ValueError: If the file has no rows for the testbed.
    """
    with path.open(encoding="utf-8", newline="") as handle:
        phases = [
            Phase(
                testbed=testbed,
                phase=row["attack"],
                start=datetime.fromtimestamp(float(row["start"]), tz=UTC),
                end=datetime.fromtimestamp(float(row["end"]), tz=UTC),
                source=source,
            )
            for row in csv.DictReader(handle)
            if row["scenario"] == testbed
        ]
    if not phases:
        raise ValueError(f"{path}: no phases for testbed {testbed!r}")
    return sorted(phases, key=lambda phase: phase.start)


def read_attack_steps(path: Path) -> dict[str, datetime]:
    """Read `attacks.log` into step name to first time, in UTC."""
    steps: dict[str, datetime] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                timestamp, step = line.rstrip().rsplit(" ", 1)
                steps.setdefault(step, datetime.fromisoformat(timestamp).astimezone(UTC))
    return steps


def read_exfil_interval(path: Path) -> tuple[datetime, datetime]:
    """Return the first and last time the attacker received exfiltrated data.

    Args:
        path: JSON Lines `dnsteal.log` of the attacker host.

    Returns:
        First and last `Received data` event, in UTC.

    Raises:
        ValueError: If the log has no such event.
    """
    first: float | None = None
    last: float | None = None
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "Received data":
                first = event["timestamp"] if first is None else first
                last = event["timestamp"]
    if first is None or last is None:
        raise ValueError(f"{path}: no received data events")
    return datetime.fromtimestamp(first, tz=UTC), datetime.fromtimestamp(last, tz=UTC)


def cross_check_phases(
    phases: Iterable[Phase], steps: dict[str, datetime], phase_steps: dict[str, list[str]]
) -> list[PhaseCheck]:
    """Compare phase starts with the attack steps that should coincide with them.

    Args:
        phases: Phases to check.
        steps: Attack steps from `read_attack_steps`.
        phase_steps: Phase name to attack steps. Phases not listed have no matching step.

    Returns:
        One check per phase and step.
    """
    return [
        PhaseCheck(phase=phase.phase, step=step, phase_start=phase.start, step_time=steps.get(step))
        for phase in phases
        for step in phase_steps.get(phase.phase, [])
    ]


def render_phase_section(
    phases: Iterable[Phase], checks: Iterable[PhaseCheck], tolerance_seconds: float
) -> str:
    """Render the phases and their cross-check as a Markdown section."""
    lines = [
        "## Attack phases",
        "",
        "| phase | start UTC | end UTC | source |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {p.phase} | {p.start.isoformat()} | {p.end.isoformat()} | {p.source} |" for p in phases
    ]
    lines += [
        "",
        "## Phase cross-check against attacks.log",
        "",
        f"A phase passes if it starts within {tolerance_seconds:.0f} s of its attack step.",
        "`exfil_last_received` is the last chunk in the attacker's `dnsteal.log`.",
        "",
        "`service_stop` marks the victim-side exfiltration stopping, so it follows that last",
        "chunk. `dnsteal_stop` is the attacker's listener shutting down, which can be much",
        "later, so a mismatch on that row is expected. The AIT-ADS `dnsteal` interval starts",
        "as the exfiltration ends and holds at most its last lines; `dnsteal_exfil` covers",
        "the traffic itself.",
        "",
        "| phase | attack step | step time UTC | phase start minus step (s) | result |",
        "|---|---|---|---|---|",
    ]
    for check in checks:
        delta = check.delta_seconds
        if delta is None:
            lines.append(f"| {check.phase} | {check.step} | not logged | - | NOT LOGGED |")
            continue
        result = "ok" if abs(delta) <= tolerance_seconds else "MISMATCH"
        time = check.step_time.isoformat() if check.step_time else "-"
        lines.append(f"| {check.phase} | {check.step} | {time} | {delta:.1f} | {result} |")
    return "\n".join(lines)


def write_phases_csv(phases: Iterable[Phase], path: Path) -> None:
    """Write phases to `data_meta/phases_<testbed>.csv` (plan 5.3)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(PHASE_COLUMNS)
        for phase in phases:
            writer.writerow(
                [
                    phase.testbed,
                    phase.phase,
                    phase.start.isoformat(),
                    phase.end.isoformat(),
                    phase.source,
                ]
            )


def read_phases_csv(path: Path) -> list[Phase]:
    """Read `data_meta/phases_<testbed>.csv`, sorted by start time."""
    with path.open(encoding="utf-8", newline="") as handle:
        phases = [
            Phase(
                testbed=row["testbed"],
                phase=row["phase"],
                start=datetime.fromisoformat(row["start_utc"]),
                end=datetime.fromisoformat(row["end_utc"]),
                source=row["source"],
            )
            for row in csv.DictReader(handle)
        ]
    return sorted(phases, key=lambda phase: phase.start)


def assign_phase(
    ts: datetime, raw_labels: Iterable[str], phases: Iterable[Phase], config: PhasesConfig
) -> str:
    """Return the phase of a labeled line (plan 5.3).

    The exfil phase overlaps the others, so only lines with the exfil label can take it, and
    for them it comes first. An interval holding `ts` wins over the tolerance; failing that,
    the nearest interval within the tolerance wins.

    Args:
        ts: Event time of the line.
        raw_labels: Raw AIT labels of the line.
        phases: Phases of the testbed.
        config: Phase settings.

    Returns:
        A phase name, or `unassigned`.
    """
    tolerance = timedelta(seconds=config.tolerance_seconds)
    can_be_exfil = config.exfil_label in raw_labels
    candidates = [phase for phase in phases if can_be_exfil or phase.phase != config.exfil_phase]
    candidates.sort(key=lambda phase: phase.phase != config.exfil_phase)
    for phase in candidates:
        if phase.start <= ts < phase.end:
            return phase.phase
    distances = []
    for phase in candidates:
        distance = phase.start - ts if ts < phase.start else ts - phase.end
        if distance <= tolerance:
            distances.append((distance, phase.phase))
    return min(distances)[1] if distances else UNASSIGNED


def build_labels(
    testbed_dir: Path,
    lines: Mapping[str, datetime],
    phases: list[Phase],
    sources: LogSources,
    config: PhasesConfig,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Join the label files to the parsed lines and assign phases (plan 5.2).

    Label `line` numbers are 1-based, like `line_no` (status.md, M2). Label files outside the
    log families are skipped, because their lines are not parsed.

    Args:
        testbed_dir: `data/raw/<testbed>`.
        lines: `line_id` to `ts` of the parsed lines.
        phases: Rows of `data_meta/phases_<testbed>.csv`.
        sources: Log source patterns.
        config: Phase settings.

    Returns:
        Rows of `labels.parquet` and a report of the resolved and in-phase counts.
    """
    rows: list[dict[str, Any]] = []
    per_file: dict[str, dict[str, Any]] = {}
    skipped: list[str] = []
    labels_dir = testbed_dir / "labels"
    for path in sorted(item for item in labels_dir.rglob("*") if item.is_file()):
        relative = path.relative_to(labels_dir).as_posix()
        log_type = sources.log_type(f"gather/{relative}")
        if log_type is None:
            skipped.append(relative)
            continue
        host, file = relative.split("/", 1)
        counts = Counter[str]()
        phase_counts = Counter[str]()
        with path.open(encoding="utf-8") as handle:
            for text in handle:
                if not text.strip():
                    continue
                entry = json.loads(text)
                counts["labeled"] += 1
                line_id = f"{host}|{file}|{entry['line']}"
                if line_id not in lines:
                    continue
                counts["resolved"] += 1
                phase = assign_phase(lines[line_id], entry["labels"], phases, config)
                phase_counts[phase] += 1
                rows.append(
                    {
                        "line_id": line_id,
                        "labels": entry["labels"],
                        "rules": json.dumps(entry["rules"], sort_keys=True),
                        "phase": phase,
                    }
                )
        per_file[relative] = {
            "log_type": log_type,
            "labeled": counts["labeled"],
            "resolved": counts["resolved"],
            "phases": dict(sorted(phase_counts.items())),
        }
    resolved = sum(item["resolved"] for item in per_file.values())
    assigned = sum(row["phase"] != UNASSIGNED for row in rows)
    report = {
        "labeled": sum(item["labeled"] for item in per_file.values()),
        "resolved": resolved,
        "in_phase": assigned,
        "in_phase_rate": assigned / resolved if resolved else 0.0,
        "skipped_files": skipped,
        "files": per_file,
    }
    return rows, report


def write_labels(rows: list[dict[str, Any]], report: dict[str, Any], directory: Path) -> None:
    """Write `labels.parquet` and `label_report.json`."""
    pq.write_table(pa.Table.from_pylist(rows, schema=LABELS_SCHEMA), directory / LABELS_FILE)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (directory / "label_report.json").write_text(text, encoding="utf-8")


def build_eval_db(directory: Path, phases_csv: Path) -> None:
    """Create `eval.duckdb`: every line view plus the label and phase tables (plan 5)."""
    views = data_views(directory)
    views["labels"] = f"SELECT * FROM read_parquet('{directory / LABELS_FILE}')"
    views["phases"] = f"SELECT * FROM read_csv('{phases_csv}')"
    create_views(directory / "eval.duckdb", views)


def phase_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Summarize `build_labels` per log type: labeled, resolved and in-phase lines."""
    summary: dict[str, Counter[str]] = {}
    for item in report["files"].values():
        counts = summary.setdefault(item["log_type"], Counter())
        counts["labeled"] += item["labeled"]
        counts["resolved"] += item["resolved"]
        counts["unassigned"] += item["phases"].get(UNASSIGNED, 0)
    return [
        {"log_type": log_type, **counts, "in_phase": counts["resolved"] - counts["unassigned"]}
        for log_type, counts in sorted(summary.items())
    ]
