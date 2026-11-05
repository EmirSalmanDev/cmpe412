"""Simulation, training, calibration and evaluation periods (plan 4.3).

Computes the boundaries once and writes `periods.json`. All other code reads that file,
never the phases.
"""

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from logtriage.config import PeriodsConfig
from logtriage.data.labels import Phase


@dataclass(frozen=True)
class Periods:
    """Period boundaries of a testbed. Timestamps are tz-aware UTC, intervals half-open."""

    testbed: str
    sim_start: datetime
    sim_end: datetime
    first_attack: datetime
    gap_hours: float
    train_start: datetime
    train_end: datetime
    fit_end: datetime
    eval_start: datetime
    eval_end: datetime

    @property
    def training_hours(self) -> float:
        """Length of the training period."""
        return (self.train_end - self.train_start).total_seconds() / 3600


def read_simulation_interval(path: Path) -> tuple[datetime, datetime]:
    """Read `dataset.yaml`. Its timestamps carry no zone and are UTC."""
    with path.open(encoding="utf-8") as handle:
        dataset = yaml.safe_load(handle)
    return (
        datetime.fromisoformat(dataset["start"]).replace(tzinfo=UTC),
        datetime.fromisoformat(dataset["end"]).replace(tzinfo=UTC),
    )


def compute_periods(
    testbed: str,
    sim_start: datetime,
    sim_end: datetime,
    phases: list[Phase],
    published_source: str,
    config: PeriodsConfig,
) -> Periods:
    """Compute the boundaries of plan 4.3.

    Args:
        testbed: Testbed name.
        sim_start: Start of the simulation.
        sim_end: End of the simulation.
        phases: Phases of the testbed.
        published_source: `source` value of the rows that define `first_attack`.
        config: Gap and split settings.

    Returns:
        The boundaries.

    Raises:
        ValueError: If there is no published phase or the training period stays empty.
    """
    starts = [phase.start for phase in phases if phase.source == published_source]
    if not starts:
        raise ValueError(f"{testbed}: no phases with source {published_source!r}")
    first_attack = min(starts)
    gap_hours = config.gap_hours
    if first_attack - timedelta(hours=gap_hours) - sim_start < timedelta(
        hours=config.min_training_hours
    ):
        gap_hours = config.fallback_gap_hours
    train_end = first_attack - timedelta(hours=gap_hours)
    if train_end <= sim_start:
        raise ValueError(f"{testbed}: no training period before {train_end.isoformat()}")
    return Periods(
        testbed=testbed,
        sim_start=sim_start,
        sim_end=sim_end,
        first_attack=first_attack,
        gap_hours=gap_hours,
        train_start=sim_start,
        train_end=train_end,
        fit_end=sim_start + (train_end - sim_start) * config.fit_fraction,
        eval_start=train_end,
        eval_end=sim_end,
    )


def write_periods(periods: Periods, path: Path) -> None:
    """Write `periods.json`."""
    values = {
        key: value.isoformat() if isinstance(value, datetime) else value
        for key, value in asdict(periods).items()
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, indent=2) + "\n", encoding="utf-8")


def load_periods(path: Path) -> Periods:
    """Read `periods.json`."""
    values = json.loads(path.read_text(encoding="utf-8"))
    return Periods(
        **{
            key: datetime.fromisoformat(value) if key not in ("testbed", "gap_hours") else value
            for key, value in values.items()
        }
    )
