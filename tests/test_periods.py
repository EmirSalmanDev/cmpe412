"""Tests for the period boundaries of plan 4.3."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logtriage.config import PeriodsConfig
from logtriage.data.labels import Phase
from logtriage.data.periods import (
    compute_periods,
    load_periods,
    read_simulation_interval,
    write_periods,
)

SOURCE = "ait_ads:labels.csv"
START = datetime(2022, 1, 14, tzinfo=UTC)
END = datetime(2022, 1, 18, tzinfo=UTC)


def phase(name: str, start: datetime, source: str = SOURCE) -> Phase:
    return Phase("tiny", name, start, start + timedelta(minutes=1), source)


def periods_for(first_attack: datetime, config: PeriodsConfig | None = None):
    return compute_periods(
        "tiny", START, END, [phase("scan", first_attack)], SOURCE, config or PeriodsConfig()
    )


def test_boundaries() -> None:
    periods = periods_for(START + timedelta(hours=74))
    assert periods.train_start == START
    assert periods.train_end == START + timedelta(hours=50)
    assert periods.fit_end == START + timedelta(hours=40)
    assert periods.eval_start == periods.train_end
    assert periods.eval_end == END
    assert periods.gap_hours == 24
    assert periods.training_hours == 50


def test_first_attack_ignores_rows_that_are_not_published() -> None:
    early = START - timedelta(hours=10)
    late = START + timedelta(hours=74)
    periods = compute_periods(
        "tiny",
        START,
        END,
        [phase("dnsteal_exfil", early, "attacker_0:dnsteal.log"), phase("scan", late)],
        SOURCE,
        PeriodsConfig(),
    )
    assert periods.first_attack == late


def test_short_training_uses_the_fallback_gap() -> None:
    periods = periods_for(START + timedelta(hours=40))
    assert periods.gap_hours == 6
    assert periods.train_end == START + timedelta(hours=34)


def test_boundaries_come_from_config() -> None:
    config = PeriodsConfig(gap_hours=12, fit_fraction=0.5)
    periods = periods_for(START + timedelta(hours=72), config)
    assert periods.train_end == START + timedelta(hours=60)
    assert periods.fit_end == START + timedelta(hours=30)


def test_no_training_period_is_an_error() -> None:
    with pytest.raises(ValueError, match="no training period"):
        periods_for(START + timedelta(hours=2))


def test_no_published_phase_is_an_error() -> None:
    with pytest.raises(ValueError, match="no phases"):
        compute_periods("tiny", START, END, [phase("x", START, "other")], SOURCE, PeriodsConfig())


def test_periods_round_trip(tmp_path: Path) -> None:
    periods = periods_for(START + timedelta(hours=74, seconds=17))
    path = tmp_path / "out" / "periods.json"
    write_periods(periods, path)
    assert load_periods(path) == periods
    assert load_periods(path).fit_end.tzinfo is not None


def test_simulation_interval_is_utc(tmp_path: Path) -> None:
    path = tmp_path / "dataset.yaml"
    path.write_text("name: x\nstart: '2022-01-14T00:00:00'\nend: '2022-01-18T00:00:00'\n")
    assert read_simulation_interval(path) == (START, END)


def test_ml_defaults_match_the_committed_config() -> None:
    from logtriage.config import MLConfig, load_settings

    config = load_settings(Path(__file__).parents[1] / "configs" / "default.yaml", None).ml
    assert (config.min_fit_lines, config.min_calib_lines) == (200, 50)
    assert config.incidents_per_day_budget == MLConfig().incidents_per_day_budget == 25
