"""IDS alert rates and the budget check, on hand-made alert files."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from logtriage.data.periods import Periods
from logtriage.eval import baselines

T0 = datetime(2022, 1, 1, tzinfo=UTC)
PERIODS = Periods(
    testbed="tiny",
    sim_start=T0,
    sim_end=T0 + timedelta(days=4),
    first_attack=T0 + timedelta(days=3),
    gap_hours=24.0,
    train_start=T0,
    train_end=T0 + timedelta(days=2),
    fit_end=T0 + timedelta(days=1.6),
    eval_start=T0 + timedelta(days=2),
    eval_end=T0 + timedelta(days=4),
)


def wazuh(stamp: str, location: str, groups: list[str]) -> str:
    return json.dumps({"@timestamp": stamp, "location": location, "rule": {"groups": groups}})


def write_alerts(directory: Path) -> None:
    (directory / "tiny_wazuh.json").write_text(
        "\n".join(
            [
                wazuh("2022-01-01T10:00:00.000000Z", "/var/log/syslog", ["syslog"]),
                wazuh("2022-01-03T10:00:00.000000Z", "/var/log/suricata/eve.json", ["suricata"]),
                wazuh("2022-01-03T10:00:00.000000Z", "/var/log/suricata/fast.log", ["ids"]),
                wazuh("2022-01-04T10:00:00.000000Z", "/var/log/mail.log", ["mail"]),
                wazuh("2022-01-04T10:00:00.000000Z", "/var/log/mail.info", ["mail"]),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    stamp = (T0 + timedelta(days=3)).timestamp()
    aminer = {"LogData": {"Timestamps": [stamp], "DetectionTimestamp": [stamp]}}
    (directory / "tiny_aminer.json").write_text(json.dumps(aminer) + "\n", encoding="utf-8")


def test_alerts_load_with_utc_times_and_their_source(tmp_path: Path) -> None:
    write_alerts(tmp_path)
    alerts = baselines.load_ids_alerts(tmp_path, "tiny")
    assert alerts["source"].tolist() == [
        "wazuh",
        "suricata",
        "suricata",
        "wazuh",
        "wazuh",
        "aminer",
    ]
    assert alerts["ts"].iloc[0] == datetime(2022, 1, 1, 10, tzinfo=UTC)
    assert alerts["ts"].iloc[-1] == T0 + timedelta(days=3)


def test_alert_rates_use_the_evaluation_period_and_its_length(tmp_path: Path) -> None:
    write_alerts(tmp_path)
    alerts = baselines.load_ids_alerts(tmp_path, "tiny")
    table = baselines.alert_rates(alerts, PERIODS).set_index("scope")
    assert table.loc["all raw alerts", "alerts"] == 5
    assert table.loc["all raw alerts", "alerts_per_day"] == 2.5
    assert table.loc["without mirrored files", "alerts"] == 3
    assert table.loc["suricata only", "alerts"] == 2
    assert table.loc["aminer only", "alerts"] == 1


def test_evaluation_filter_is_half_open() -> None:
    alerts = pd.DataFrame(
        {"ts": [PERIODS.eval_start, PERIODS.eval_end], "source": ["wazuh", "wazuh"]}
    )
    assert len(baselines.in_evaluation(alerts, PERIODS)) == 1


def test_daily_alerts_have_a_total_per_day(tmp_path: Path) -> None:
    write_alerts(tmp_path)
    table = baselines.daily_alerts(baselines.load_ids_alerts(tmp_path, "tiny"), PERIODS)
    assert table.loc["2022-01-03", "total"] == 2
    assert table.loc["2022-01-04", "total"] == 3


@pytest.mark.parametrize(
    ("alerts_per_day", "budget", "largest", "feasible"),
    [(1000.0, 25, 100, True), (250.0, 25, 25, True), (240.0, 25, 24, False)],
)
def test_budget_check_follows_the_arithmetic(
    alerts_per_day: float, budget: int, largest: int, feasible: bool
) -> None:
    check = baselines.BudgetCheck(alerts_per_day, budget, 0.9)
    assert check.largest_budget == largest
    assert check.feasible is feasible
    assert check.reduction_at_budget == pytest.approx(1 - budget / alerts_per_day)
