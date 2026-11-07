"""M11 metrics from saved outputs, on hand-made ground truth (plan 10.2, 10.3, 10.7, D17, D62)."""

import ast
import json
import math
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from logtriage.config import load_settings
from logtriage.eval import baselines, tables
from logtriage.eval.detection import DetectionResult
from logtriage.eval.metrics import (
    attack_hit,
    attack_incidents,
    attack_summary,
    citation_summary,
    cost_summary,
    incident_truth,
    parent_technique,
    priced_at,
    token_cost,
    verdict_counts,
    verdict_scores,
    window_table,
    with_truth,
)
from logtriage.ml.incidents import link_windows

T0 = datetime(2022, 1, 15, tzinfo=UTC)
OFF_PEAK = {"input": 0.15, "cached_input": 0.003, "output": 0.6}
PEAK = {"input": 0.3, "cached_input": 0.006, "output": 1.2}
GOLD = {
    "dirb": ["T1595.003"],
    "webshell": ["T1190", "T1505.003"],
    "privilege_escalation": ["T1078.003", "T1548.003", "T1078"],
    "dnsteal_exfil": ["T1048.003", "T1048", "T1071.004"],
}


def stamp(minute: float) -> pd.Timestamp:
    return pd.Timestamp(T0 + timedelta(minutes=minute))


def window(
    minute: int,
    log_type: str = "apache_access",
    host: str = "web",
    score: float = 0.5,
    incident: str | None = None,
    anomalous: bool | None = None,
) -> dict:
    return {
        "host": host,
        "log_type": log_type,
        "window_start": stamp(minute),
        "score": score,
        "is_anomalous": incident is not None if anomalous is None else anomalous,
        "incident_id": incident,
        "period": "eval",
    }


def truth_rows(*items: tuple[int, str, str, list[str]]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"host": host, "log_type": log_type, "window_start": stamp(minute), "phases": phases}
            for minute, log_type, host, phases in items
        ]
    )


def labeled_table() -> pd.DataFrame:
    """Three incidents: malicious, ambiguous, and false positive; plus quiet windows."""
    scores = pd.DataFrame(
        [
            window(0, score=0.99, incident="a-1"),
            window(1, "dns", "inet-dns", score=0.98, incident="a-1"),
            window(2, "dns", "inet-dns", score=0.97, incident="a-2"),
            window(3, "auth", "mail", score=0.96, incident="a-3"),
            window(4, score=0.1),
            window(5, "dns", "inet-firewall", score=0.2),
        ]
    )
    return with_truth(
        scores,
        truth_rows(
            (0, "apache_access", "web", ["dirb"]),
            (5, "dns", "inet-firewall", ["dnsteal_exfil"]),
        ),
    )


def test_an_incident_with_an_attack_window_is_never_ambiguous() -> None:
    truth = incident_truth(labeled_table())
    assert truth["malicious"].to_dict() == {"a-1": True, "a-2": False, "a-3": False}
    assert truth["ambiguous"].to_dict() == {"a-1": False, "a-2": True, "a-3": False}
    assert truth["phases"].to_dict() == {"a-1": ["dirb"], "a-2": [], "a-3": []}


def test_the_verdict_matrix_leaves_out_ambiguous_incidents() -> None:
    truth = incident_truth(labeled_table())
    verdicts = pd.Series({"a-1": "uncertain", "a-2": "malicious", "a-3": "benign"})
    counts = verdict_counts(truth, verdicts)
    assert counts["uncertain_true_malicious"] == 1
    assert counts["benign_true_benign"] == 1
    assert counts["malicious_true_benign"] == 0
    assert sum(counts.values()) == 2


def test_the_secondary_matrix_counts_ambiguous_incidents_as_benign() -> None:
    truth = incident_truth(labeled_table())
    verdicts = pd.Series({"a-1": "uncertain", "a-2": "malicious", "a-3": "benign"})
    counts = verdict_counts(truth, verdicts, include_ambiguous=True)
    assert counts["malicious_true_benign"] == 1
    assert sum(counts.values()) == 3


def test_a_missing_verdict_fails_loudly() -> None:
    truth = incident_truth(labeled_table())
    with pytest.raises(ValueError, match="no verdict"):
        verdict_counts(truth, pd.Series({"a-1": "malicious"}))


def test_an_unknown_verdict_fails_loudly() -> None:
    truth = incident_truth(labeled_table())
    verdicts = pd.Series({"a-1": "maybe", "a-2": "benign", "a-3": "benign"})
    with pytest.raises(ValueError, match="unknown verdicts"):
        verdict_counts(truth, verdicts)


def test_verdict_f1_counts_uncertain_as_non_benign() -> None:
    counts = {
        "malicious_true_malicious": 1,
        "uncertain_true_malicious": 2,
        "benign_true_malicious": 1,
        "malicious_true_benign": 1,
        "uncertain_true_benign": 2,
        "benign_true_benign": 5,
    }
    scores = verdict_scores(counts)
    assert scores["precision"] == pytest.approx(3 / 6)
    assert scores["recall"] == pytest.approx(3 / 4)
    assert scores["f1"] == pytest.approx(2 * 0.5 * 0.75 / 1.25)


def test_verdict_scores_are_nan_with_nothing_to_score() -> None:
    counts = dict.fromkeys(
        (
            f"{v}_true_{t}"
            for v in ("malicious", "uncertain", "benign")
            for t in ("malicious", "benign")
        ),
        0,
    )
    assert all(math.isnan(value) for value in verdict_scores(counts).values())


def test_a_parent_technique_is_the_part_before_the_dot() -> None:
    assert parent_technique("T1548.003") == "T1548"
    assert parent_technique("T1046") == "T1046"


@pytest.mark.parametrize(
    ("predicted", "wanted", "k", "lenient", "hit"),
    [
        (["T1046"], {"T1046"}, 1, False, True),
        (["T1110", "T1046"], {"T1046"}, 1, False, False),
        (["T1110", "T1046"], {"T1046"}, 3, False, True),
        (["A", "B", "C", "T1046"], {"T1046"}, 3, False, False),
        (["T1595.002"], {"T1595.003"}, 1, False, False),
        (["T1595.002"], {"T1595.003"}, 1, True, True),
        (["T1595"], {"T1595.003"}, 1, True, True),
        (["T1595.003"], {"T1595"}, 1, True, True),
        (["T1110.001"], {"T1595.003"}, 3, True, False),
        ([], {"T1046"}, 3, True, False),
    ],
)
def test_attack_hit(
    predicted: list[str], wanted: set[str], k: int, lenient: bool, hit: bool
) -> None:
    assert attack_hit(predicted, wanted, k, lenient) is hit


def report(
    techniques: list[str],
    verdict: str = "malicious",
    retrieved: list[str] | None = None,
    **meta: float,
) -> dict:
    return {
        "verdict": verdict,
        "techniques": [{"technique_id": item} for item in techniques],
        "meta": {"retrieved_techniques": retrieved or techniques, **meta},
    }


def test_attack_uses_the_union_of_the_gold_sets_of_the_phases() -> None:
    truth = pd.DataFrame(
        {
            "malicious": [True, True, False],
            "ambiguous": [False, False, False],
            "phases": [["dirb", "webshell"], ["dirb"], []],
        },
        index=["a-1", "a-2", "a-3"],
    )
    reports = {
        "a-1": report(["T1110", "T1041", "T1190"], retrieved=["T1110"]),
        "a-2": report(["T1595.002"]),
        "a-3": report(["T1190"]),
    }
    rows = attack_incidents(truth, reports, GOLD)
    assert rows["incident_id"].tolist() == ["a-1", "a-2"]
    assert rows["top1_strict"].tolist() == [False, False]
    assert rows["top3_strict"].tolist() == [True, False]
    assert rows["top1_lenient"].tolist() == [False, True]
    assert rows["top3_lenient"].tolist() == [True, True]
    assert rows["gold_retrieved"].tolist() == [False, False]
    summary = attack_summary(rows)
    assert summary["malicious_incidents"] == 2
    assert summary["top3_strict_hits"] == 1
    assert summary["top3_strict"] == 0.5
    assert summary["top3_lenient"] == 1.0


def test_attack_summary_of_no_incident_is_nan() -> None:
    truth = pd.DataFrame({"malicious": [False], "ambiguous": [False], "phases": [[]]}, index=["x"])
    summary = attack_summary(attack_incidents(truth, {"x": report([])}, GOLD))
    assert summary["malicious_incidents"] == 0
    assert math.isnan(summary["top3_strict"])


def test_hallucinated_citations_are_a_share_of_first_draft_claims() -> None:
    reports = [
        report([], draft_claims=10, draft_unknown_eid_claims=1),
        report([], draft_claims=30, draft_unknown_eid_claims=0),
    ]
    summary = citation_summary(reports)
    assert summary == {
        "reports": 2,
        "draft_claims": 40,
        "unknown_eid_claims": 1,
        "hallucinated_share": 1 / 40,
    }


def test_token_cost_prices_cached_tokens_apart() -> None:
    meta = {"tokens_in": 48608, "tokens_cached": 17408, "tokens_out": 3439}
    assert token_cost(meta, PEAK) == pytest.approx(0.013591248)
    assert token_cost(meta, OFF_PEAK) == pytest.approx(0.013591248 / 2)


@pytest.mark.parametrize(
    ("cost", "expected"),
    [(0.013591248, "peak"), (0.006795624, "off_peak"), (0.01, "mixed")],
)
def test_priced_at_names_the_rates_of_a_logged_cost(cost: float, expected: str) -> None:
    meta = {"tokens_in": 48608, "tokens_cached": 17408, "tokens_out": 3439, "cost_usd": cost}
    assert priced_at(meta, OFF_PEAK, PEAK) == expected


def cost_report(cost: float, latency: float) -> dict:
    tokens = {"tokens_in": 1000, "tokens_cached": 0, "tokens_out": 100, "llm_calls": 8}
    return report([], cost_usd=cost, latency_s=latency, **tokens)


def test_cost_summary_matches_the_p90_of_status() -> None:
    """Santos in status.md: p90 0.0152 of these three costs, 53.9 s of these latencies."""
    reports = [
        cost_report(0.013591, 22.65),
        cost_report(0.014624, 60.0),
        cost_report(0.015364, 29.5),
    ]
    summary = cost_summary(reports, OFF_PEAK, PEAK)
    assert summary["cost_mean_usd"] == pytest.approx(0.0145263, abs=1e-6)
    assert summary["cost_p90_usd"] == pytest.approx(0.015216, abs=1e-6)
    assert summary["latency_p90_s"] == pytest.approx(53.9)
    assert summary["reports"] == 3
    assert summary["llm_calls_mean"] == 8


def test_off_peak_cost_does_not_depend_on_the_logged_price() -> None:
    expensive = cost_summary([cost_report(9.0, 1.0)], OFF_PEAK, PEAK)
    cheap = cost_summary([cost_report(0.0, 1.0)], OFF_PEAK, PEAK)
    assert expensive["off_peak_total_usd"] == cheap["off_peak_total_usd"] == pytest.approx(0.00021)


def test_window_table_adds_the_pool_without_dns() -> None:
    table = window_table(labeled_table())
    assert list(table.index) == ["pooled", "apache_access", "auth", "dns", "pooled_without_dns"]
    assert table.loc["pooled", "windows"] == 4
    assert table.loc["pooled_without_dns", "windows"] == 3
    assert table.loc["dns", "windows"] == 1


def test_the_secondary_window_table_includes_ambiguous_windows() -> None:
    table = window_table(labeled_table(), include_ambiguous=True)
    assert table.loc["pooled", "windows"] == 6
    assert table.loc["dns", "windows"] == 3
    assert table.loc["dns", "anomalous"] == 2


def alerts(*items: tuple[float, str]) -> pd.DataFrame:
    rows = [{"ts": stamp(minute), "host": host} for minute, host in items]
    return pd.DataFrame(rows)


def test_alerts_group_by_host_and_gap() -> None:
    table = alerts((0, "a"), (30, "a"), (61, "a"), (5, "b"), (6, "a"))
    groups = baselines.group_alerts(table, 30)
    assert groups.nunique() == 3
    assert groups[0] == groups[1] == groups[4]
    assert groups[2] != groups[0]
    assert groups[3] not in (groups[0], groups[2])


def test_the_gap_is_inclusive() -> None:
    assert baselines.group_alerts(alerts((0, "a"), (30, "a")), 30).nunique() == 1
    assert baselines.group_alerts(alerts((0, "a"), (30.5, "a")), 30).nunique() == 2


def test_an_alert_with_no_host_cannot_be_grouped() -> None:
    table = alerts((0, "a"))
    table.loc[0, "host"] = None
    with pytest.raises(ValueError, match="host"):
        baselines.group_alerts(table, 30)


def test_alert_groups_equal_the_incident_rule_with_the_host_as_only_entity() -> None:
    random = np.random.default_rng(42)
    minutes = np.sort(random.integers(0, 3000, 200))
    hosts = random.choice(["a", "b", "c"], 200)
    table = pd.DataFrame(
        {
            "ts": [stamp(int(minute)) for minute in minutes],
            "window_start": [stamp(int(minute)) for minute in minutes],
            "host": hosts,
            "log_type": "x",
            "src_ips": [[] for _ in minutes],
            "users": [[] for _ in minutes],
        }
    )
    expected = len(set(link_windows(table, set(), timedelta(minutes=30))))
    assert baselines.group_alerts(table, 30).nunique() == expected


def id_alerts() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "ts": [stamp(0), stamp(1), stamp(10), stamp(20)],
            "source": ["wazuh", "aminer", "suricata", "wazuh"],
            "texts": [("line a",), ("other", "line b"), (), ("line c",)],
        }
    )


def labeled_lines() -> pd.DataFrame:
    return pd.DataFrame(
        {"raw": ["line a", "line a", "line b"], "phase": ["dirb", "dirb", "wpscan"]}
    )


def test_an_event_label_needs_the_alert_to_quote_a_labeled_line() -> None:
    found = baselines.event_phases(id_alerts(), labeled_lines())
    assert sorted(zip(found["alert"], found["phase"], found["source"], strict=True)) == [
        (0, "dirb", "wazuh"),
        (1, "wpscan", "aminer"),
    ]


def test_a_time_label_is_a_closed_interval() -> None:
    intervals = pd.DataFrame(
        {
            "phase": ["dirb", "wpscan"],
            "start_utc": [stamp(0), stamp(1)],
            "end_utc": [stamp(1), stamp(5)],
        }
    )
    found = baselines.time_phases(id_alerts(), intervals)
    assert sorted(zip(found["alert"], found["phase"], strict=True)) == [
        (0, "dirb"),
        (1, "dirb"),
        (1, "wpscan"),
    ]


def test_the_phase_table_counts_each_label_and_source() -> None:
    intervals = pd.DataFrame(
        {
            "phase": ["dirb", "cracking"],
            "start_utc": [stamp(0), stamp(9)],
            "end_utc": [stamp(1), stamp(11)],
        }
    )
    event = baselines.event_phases(id_alerts(), labeled_lines())
    timed = baselines.time_phases(id_alerts(), intervals)
    table = baselines.ids_phase_table(event, timed, ["dirb", "wpscan", "cracking"])
    assert table["event_alerts"].tolist() == [1, 1, 0]
    assert table["event_aminer"].tolist() == [0, 1, 0]
    assert table["event_suricata"].sum() == 0
    assert table["time_alerts"].tolist() == [2, 0, 1]


def wazuh_line(ip: str, full_log: str | None) -> str:
    alert = {
        "@timestamp": "2022-01-15T00:00:00.000000Z",
        "location": "/var/log/auth.log",
        "rule": {"groups": ["syslog"]},
        "agent": {"ip": ip, "name": "wazuh-client"},
    }
    return json.dumps({**alert, "full_log": full_log} if full_log else alert)


def test_alerts_load_with_their_host_and_text(tmp_path: Path) -> None:
    (tmp_path / "t_wazuh.json").write_text(
        wazuh_line("10.0.0.1", "text") + "\n" + wazuh_line("10.0.0.2", None) + "\n",
        encoding="utf-8",
    )
    stamp_value = T0.timestamp()
    aminer = {
        "LogData": {"Timestamps": [stamp_value], "RawLogData": ["one", "two"]},
        "AMiner": {"ID": "10.0.0.3"},
    }
    (tmp_path / "t_aminer.json").write_text(json.dumps(aminer) + "\n", encoding="utf-8")
    table = baselines.load_ids_alerts(tmp_path, "t")
    assert table["host"].tolist() == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert table["texts"].tolist() == [("text",), (), ("one", "two")]


def inputs(
    name: str, group: str, table: pd.DataFrame, reports: dict, alert_rows: pd.DataFrame
) -> tables.TestbedInputs:
    incidents = int(table["incident_id"].nunique())
    denominators = pd.DataFrame(
        {
            "phase": ["dnsteal_exfil", "dirb", "webshell", "reverse_shell"],
            "primary": [True, True, True, False],
            "all_parsed": [True, True, True, True],
        }
    )
    credit = pd.DataFrame(
        {"apache_access": [0, 1], "detected": [False, True], "dns_only": [False, False]},
        index=["dnsteal_exfil", "dirb"],
    )
    result = DetectionResult(
        table=table,
        windows=pd.DataFrame(),
        windows_with_ambiguous=pd.DataFrame(),
        credit=credit,
        recall={},
        incidents=incidents,
        incidents_per_day=incidents / 2.0,
    )
    return tables.TestbedInputs(
        name=name,
        group=group,
        result=result,
        denominators=denominators,
        reports=reports,
        alerts=alert_rows,
        labeled=labeled_lines(),
        intervals=pd.DataFrame(
            {"phase": ["dirb"], "start_utc": [stamp(0)], "end_utc": [stamp(30)]}
        ),
        days=2.0,
    )


def full_report(techniques: list[str], verdict: str, cost: float = 0.0) -> dict:
    meta = {
        "draft_claims": 10,
        "draft_unknown_eid_claims": 1,
        "cost_usd": cost,
        "latency_s": 2.0,
        "tokens_in": 100,
        "tokens_cached": 0,
        "tokens_out": 10,
        "llm_calls": 8,
    }
    return report(techniques, verdict, **meta)


@pytest.fixture
def three_testbeds() -> list[tables.TestbedInputs]:
    """Two test testbeds and dev, built alike, so a pooled row shows exactly what it took in."""
    items = []
    for name, group in (("one", tables.TEST), ("two", tables.TEST), ("dev", tables.DEV)):
        reports = {
            "a-1": full_report(["T1595.003"], "uncertain"),
            "a-2": full_report([], "malicious"),
            "a-3": full_report([], "benign"),
        }
        frame = pd.DataFrame(
            {
                "ts": [stamp(0), stamp(1), stamp(100)],
                "host": ["h", "h", "h"],
                "source": ["wazuh", "aminer", "suricata"],
                "texts": [("line a",), ("line b",), ()],
            }
        )
        items.append(inputs(name, group, labeled_table(), reports, frame))
    return items


def test_pooled_phase_recall_sums_counts_and_leaves_out_dev(
    three_testbeds: list[tables.TestbedInputs],
) -> None:
    table = tables.phase_recall_table(three_testbeds)
    pooled = table[(table["testbed"] == "pooled")].set_index("variant")
    assert pooled.loc["primary", ["detected", "phases"]].tolist() == [2, 6]
    assert pooled.loc["all_parsed", ["detected", "phases"]].tolist() == [2, 8]
    assert pooled.loc["without_exfil", ["detected", "phases"]].tolist() == [2, 4]


def test_the_phase_table_names_the_missed_phases(
    three_testbeds: list[tables.TestbedInputs],
) -> None:
    table = tables.phase_recall_table(three_testbeds)
    row = table[(table["testbed"] == "one") & (table["variant"] == "primary")].iloc[0]
    assert (row["detected"], row["phases"]) == (1, 3)
    assert row["missed"] == "dnsteal_exfil webshell"


def test_the_unclipped_secondary_is_quoted_for_dev_and_santos_only(
    three_testbeds: list[tables.TestbedInputs],
) -> None:
    table = tables.phase_recall_table(three_testbeds)
    quoted = table[table["variant"] == "unclipped_dns"]
    assert set(quoted["testbed"]) == {"russellmitchell", "santos"}
    assert set(quoted["source"]) == {tables.UNCLIPPED_SOURCE}
    assert quoted.set_index("testbed")["detected"].to_dict() == {"russellmitchell": 6, "santos": 7}


def test_window_and_alert_tables_have_no_pooled_testbed(
    three_testbeds: list[tables.TestbedInputs],
) -> None:
    assert "pooled" not in set(tables.windows_table(three_testbeds)["testbed"])
    assert "pooled" not in set(tables.alert_reduction_table(three_testbeds, 30, 25)["testbed"])


def test_alert_reduction_compares_the_same_period(
    three_testbeds: list[tables.TestbedInputs],
) -> None:
    row = tables.alert_reduction_table(three_testbeds, 30, 25).iloc[0]
    assert row["incidents"] == 3
    assert row["anomalous_windows"] == 4
    assert row["raw_alerts"] == 3
    assert row["grouped_alerts"] == 2
    assert row["incidents_per_day"] == 1.5
    assert row["grouped_alerts_per_day"] == 1.0
    assert row["reduction_vs_windows"] == pytest.approx(0.25)
    assert row["reduction_vs_raw_alerts"] == 0
    assert row["reduction_vs_grouped_alerts"] == pytest.approx(-0.5)
    assert row["within_budget"]
    assert not row["meets_reduction"]


def test_pooled_verdicts_sum_the_matrices_and_leave_out_dev(
    three_testbeds: list[tables.TestbedInputs],
) -> None:
    table = tables.verdict_table(three_testbeds)
    agents = table[(table["method"] == "agents") & (table["variant"] == "primary")]
    pooled = agents[agents["testbed"] == "pooled"].iloc[0]
    assert pooled["incidents"] == 4
    assert pooled["uncertain_true_malicious"] == 2
    assert pooled["benign_true_benign"] == 2
    assert pooled["f1"] == 1.0


def test_ml_only_calls_everything_malicious(three_testbeds: list[tables.TestbedInputs]) -> None:
    table = tables.verdict_table(three_testbeds)
    row = table[
        (table["method"] == "ml_only")
        & (table["variant"] == "with_ambiguous")
        & (table["testbed"] == "one")
    ].iloc[0]
    assert row["malicious_true_malicious"] == 1
    assert row["malicious_true_benign"] == 2
    assert row["precision"] == pytest.approx(1 / 3)
    assert row["recall"] == 1.0


def test_pooled_attack_takes_the_incidents_of_the_test_testbeds(
    three_testbeds: list[tables.TestbedInputs],
) -> None:
    summary, incidents = tables.attack_tables(three_testbeds, GOLD)
    assert len(incidents) == 3
    row = summary.set_index("testbed").loc["pooled"]
    assert row["malicious_incidents"] == 2
    assert row["top1_strict_hits"] == 2


def test_pooled_citations_leave_out_dev(three_testbeds: list[tables.TestbedInputs]) -> None:
    table = tables.citations_table(three_testbeds).set_index("testbed")
    assert table.loc["pooled", "draft_claims"] == 60
    assert table.loc["pooled", "unknown_eid_claims"] == 6
    assert table.loc["dev", "group"] == "dev"


def test_ids_tables_pool_each_label_apart(three_testbeds: list[tables.TestbedInputs]) -> None:
    recall, phases = tables.ids_tables(three_testbeds)
    pooled = recall[recall["testbed"] == "pooled"].set_index(["label", "variant"])
    assert pooled.loc[("event", "primary"), "detected"] == 2
    assert pooled.loc[("time", "primary"), "detected"] == 2
    assert pooled.loc[("event", "primary"), "phases"] == 6
    assert phases["counted"].sum() == 9


def test_every_table_is_built_and_written(
    three_testbeds: list[tables.TestbedInputs], tmp_path: Path
) -> None:
    settings = load_settings(env_file=None)
    built = tables.build_tables(three_testbeds, settings)
    tables.write_tables(built, tmp_path)
    assert {path.stem for path in tmp_path.glob("*.csv")} == set(built)
    assert all(len(table) for table in built.values())


def test_load_reports_skips_the_run_summary(tmp_path: Path) -> None:
    folder = tmp_path / "reports"
    folder.mkdir()
    (folder / "run_summary.json").write_text("{}", encoding="utf-8")
    (folder / "x-0001.json").write_text('{"verdict": "benign"}', encoding="utf-8")
    assert tables.load_reports(tmp_path, "x") == {"x-0001": {"verdict": "benign"}}


def test_the_tables_module_imports_no_detection_code() -> None:
    """A test testbed runs each stage once, so the metrics must not be able to score (D57)."""
    source = Path(tables.__file__).read_text(encoding="utf-8")
    modules = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules |= {item.name for item in node.names}
        elif isinstance(node, ast.ImportFrom):
            modules.add(node.module or "")
    assert not [name for name in modules if name.startswith(("logtriage.ml", "logtriage.agents"))]


def test_importing_the_tables_loads_no_scoring_module() -> None:
    code = (
        "import sys, logtriage.eval.tables;"
        "print([m for m in sys.modules if m.startswith(('logtriage.ml', 'logtriage.agents'))])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"
