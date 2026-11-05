"""Ground-truth labels and attack phases, for evaluation only (plan 5.2, 5.3).

This is the only `logtriage.data` module that reads label files or phase intervals, apart
from `periods.py`.
"""

import csv
import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

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
    """Comparison of a phase start with the attack step that should open it."""

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


def cross_check_phases(
    phases: Iterable[Phase], steps: dict[str, datetime], phase_steps: dict[str, str]
) -> list[PhaseCheck]:
    """Compare phase starts with the attack steps that should open them.

    Args:
        phases: Phases to check.
        steps: Attack steps from `read_attack_steps`.
        phase_steps: Phase name to attack step. Phases not listed have no matching step.

    Returns:
        One check per phase that has a matching step.
    """
    return [
        PhaseCheck(
            phase=phase.phase,
            step=phase_steps[phase.phase],
            phase_start=phase.start,
            step_time=steps.get(phase_steps[phase.phase]),
        )
        for phase in phases
        if phase.phase in phase_steps
    ]


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
