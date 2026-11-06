"""Detection metrics and tuning on hand-made ground truth (plan 10.1, 10.2, 6.5)."""

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from logtriage.data.store import connect
from logtriage.eval import tuning
from logtriage.eval.detection import anomalous_by_hour
from logtriage.eval.metrics import (
    detected_phases,
    phase_credit,
    phase_recall,
    window_metrics,
    window_truth,
    with_truth,
)
from logtriage.eval.tuning import select, write_chosen

T0 = datetime(2022, 1, 15, tzinfo=UTC)


def stamp(minute: int) -> pd.Timestamp:
    return pd.Timestamp(T0 + timedelta(minutes=minute))


def row(
    minute: int,
    log_type: str = "apache_access",
    host: str = "web",
    score: float = 0.5,
    anomalous: bool = False,
    incident: str | None = None,
    period: str = "eval",
) -> dict:
    return {
        "host": host,
        "log_type": log_type,
        "window_start": stamp(minute),
        "score": score,
        "is_anomalous": anomalous,
        "incident_id": incident,
        "period": period,
    }


def truth(*items: tuple[int, str, str, list[str]]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"host": host, "log_type": log_type, "window_start": stamp(minute), "phases": phases}
            for minute, log_type, host, phases in items
        ]
    )


def test_window_truth_groups_labeled_lines_into_windows() -> None:
    with connect() as con:
        con.execute(
            """
            CREATE TABLE lines AS SELECT * FROM (VALUES
                ('a', 'web', 'apache_access', TIMESTAMPTZ '2022-01-15 00:00:10+00', true),
                ('b', 'web', 'apache_access', TIMESTAMPTZ '2022-01-15 00:00:50+00', true),
                ('c', 'web', 'apache_access', TIMESTAMPTZ '2022-01-15 00:01:00+00', true),
                ('d', 'web', 'apache_access', TIMESTAMPTZ '2022-01-15 00:02:00+00', true)
            ) t(line_id, host, log_type, ts, parse_ok);
            CREATE TABLE labels AS SELECT * FROM (VALUES
                ('a', 'wpscan'), ('b', 'dirb'), ('c', 'dirb')) t(line_id, phase);
            """
        )
        table = window_truth(con, 60).sort_values("window_start")
    assert [list(item) for item in table["phases"]] == [["dirb", "wpscan"], ["dirb"]]
    assert table["window_start"].dt.minute.tolist() == [0, 1]


def test_with_truth_keeps_eval_windows_and_marks_attacks() -> None:
    scores = pd.DataFrame([row(0, period="calib"), row(1), row(2)])
    table = with_truth(scores, truth((2, "apache_access", "web", ["dirb"])))
    assert table["is_attack"].tolist() == [False, True]
    assert table["phases"].tolist() == [[], ["dirb"]]


def test_only_dns_on_inet_dns_is_ambiguous() -> None:
    scores = pd.DataFrame(
        [row(0, "dns", "inet-dns"), row(1, "dns", "inet-firewall"), row(2, "auth", "inet-dns")]
    )
    table = with_truth(scores, truth((9, "dns", "x", ["y"])))
    assert table["is_ambiguous"].tolist() == [True, False, False]


def scored_table() -> pd.DataFrame:
    scores = pd.DataFrame(
        [
            row(0, score=0.99, anomalous=True, incident="i1"),
            row(1, score=0.98, anomalous=True, incident="i1"),
            row(2, score=0.97),
            row(3, score=0.10),
            row(4, "dns", "inet-dns", 0.99, True, "i2"),
            row(5, "dns", "inet-firewall", 0.20),
        ]
    )
    return with_truth(
        scores,
        truth(
            (0, "apache_access", "web", ["dirb"]),
            (2, "apache_access", "web", ["wpscan"]),
            (5, "dns", "inet-firewall", ["dnsteal_exfil"]),
        ),
    )


def test_window_metrics_leave_out_ambiguous_windows() -> None:
    metrics = window_metrics(scored_table())
    pooled = metrics.loc["pooled"]
    assert pooled["windows"] == 5
    assert pooled["attack"] == 3
    assert pooled["precision"] == pytest.approx(1 / 2)
    assert pooled["recall"] == pytest.approx(1 / 3)
    assert pooled["f1"] == pytest.approx(0.4)
    assert list(metrics.index) == ["pooled", "apache_access", "dns"]


def test_the_secondary_number_counts_ambiguous_windows_as_normal() -> None:
    pooled = window_metrics(scored_table(), include_ambiguous=True).loc["pooled"]
    assert pooled["windows"] == 6
    assert pooled["precision"] == pytest.approx(1 / 3)


def test_pr_auc_ranks_by_score() -> None:
    assert window_metrics(scored_table()).loc["apache_access", "pr_auc"] == pytest.approx(
        (1.0 + 2 / 3) / 2
    )


def test_a_slice_without_attacks_has_no_pr_auc() -> None:
    table = with_truth(pd.DataFrame([row(0, "auth"), row(1, "auth")]), truth((9, "x", "y", ["z"])))
    assert np.isnan(window_metrics(table).loc["auth", "pr_auc"])


def test_a_phase_needs_an_anomalous_window_in_an_incident() -> None:
    scores = pd.DataFrame(
        [
            row(0, anomalous=True, incident="i1"),
            row(1, anomalous=True, incident=None),
            row(2, anomalous=False, incident=None),
        ]
    )
    table = with_truth(
        scores,
        truth(
            (0, "apache_access", "web", ["dirb"]),
            (1, "apache_access", "web", ["wpscan"]),
            (2, "apache_access", "web", ["cracking"]),
        ),
    )
    assert list(detected_phases(table).index) == ["dirb"]


def test_a_window_with_two_phases_detects_both() -> None:
    table = with_truth(
        pd.DataFrame([row(0, anomalous=True, incident="i1")]),
        truth((0, "apache_access", "web", ["dirb", "wpscan"])),
    )
    assert sorted(detected_phases(table).index) == ["dirb", "wpscan"]


def test_phase_recall_and_the_variant_without_exfiltration() -> None:
    detected = pd.DataFrame({"dns": [3, 1]}, index=["dnsteal_exfil", "dirb"])
    result = phase_recall(detected, ["dnsteal_exfil", "dirb", "wpscan", "webshell"])
    assert (result["detected"], result["phases"]) == (2, 4)
    assert result["recall"] == 0.5
    assert result["missed"] == ["webshell", "wpscan"]
    assert (result["detected_without_exfil"], result["phases_without_exfil"]) == (1, 3)


def test_a_phase_outside_the_denominator_does_not_count() -> None:
    detected = pd.DataFrame({"dns": [1]}, index=["reverse_shell"])
    assert phase_recall(detected, ["dirb"])["detected"] == 0


def test_phase_credit_shows_phases_found_only_through_dns() -> None:
    detected = pd.DataFrame(
        {"apache_access": [0, 2, 0], "dns": [5, 1, 0]}, index=["network_scans", "wpscan", "x"]
    )
    table = phase_credit(detected, ["network_scans", "wpscan", "dirb"])
    assert table["dns_only"].tolist() == [True, False, False]
    assert table["detected"].tolist() == [True, True, False]


def test_phase_credit_without_any_dns_window() -> None:
    detected = pd.DataFrame({"auth": [1]}, index=["cracking"])
    assert not phase_credit(detected, ["cracking"])["dns_only"].any()


def test_anomalous_by_hour_uses_eval_windows() -> None:
    scores = pd.DataFrame(
        [row(0, anomalous=True), row(1), row(70, anomalous=True), row(2, "auth", period="fit")]
    )
    table = anomalous_by_hour(scores)
    assert table.loc[0, "apache_access"] == 0.5
    assert table.loc[1, "apache_access"] == 1.0
    assert "auth" not in table.columns


def grid(*rows: tuple[float, int, float, int]) -> pd.DataFrame:
    names = ["q", "gap_minutes", "phase_recall", "incidents"]
    return pd.DataFrame(rows, columns=names).assign(incidents_per_day=lambda t: t["incidents"] / 2)


def test_select_takes_the_best_recall_within_the_budget() -> None:
    chosen = select(grid((0.95, 5, 1.0, 100), (0.99, 5, 0.8, 40), (0.999, 5, 0.5, 10)), 25)
    assert chosen["q"] == 0.99


def test_select_breaks_ties_with_fewer_incidents() -> None:
    chosen = select(grid((0.99, 5, 0.8, 40), (0.98, 30, 0.8, 30)), 25)
    assert chosen["q"] == 0.98


def test_select_then_prefers_the_higher_q_and_the_smaller_gap() -> None:
    chosen = select(grid((0.98, 5, 0.8, 30), (0.99, 15, 0.8, 30), (0.99, 10, 0.8, 30)), 25)
    assert (chosen["q"], chosen["gap_minutes"]) == (0.99, 10)


def test_the_budget_is_inclusive() -> None:
    assert select(grid((0.99, 5, 0.8, 50)), 25)["q"] == 0.99


def test_select_raises_when_nothing_fits() -> None:
    with pytest.raises(ValueError, match="no combination"):
        select(grid((0.99, 5, 0.8, 500)), 25)


def test_write_chosen_keeps_the_rest_of_the_file(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(
        "ml:\n  # keep me\n  q: 0.99\n  q_grid: [0.9]\n  gap_minutes: 10\n  gap_grid: [5]\n",
        encoding="utf-8",
    )
    write_chosen(path, 0.995, 30)
    assert path.read_text(encoding="utf-8") == (
        "ml:\n  # keep me\n  q: 0.995\n  q_grid: [0.9]\n  gap_minutes: 30\n  gap_grid: [5]\n"
    )


def test_tuning_can_only_reach_the_dev_testbed() -> None:
    source = inspect.getsource(tuning)
    assert "TEST_TESTBED" not in source and "santos" not in source
    assert "testbed" not in inspect.signature(tuning.tune).parameters
