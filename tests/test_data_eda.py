"""M3 acceptance on the real data: the numbers in `reports/targets.md` hold."""

import re
from pathlib import Path

import pytest

from logtriage.config import load_settings
from logtriage.eval import baselines, eda

pytestmark = pytest.mark.data

ROOT = Path(__file__).parents[1]
SETTINGS = load_settings(ROOT / "configs" / "default.yaml", None)
TESTBEDS = ("russellmitchell", "santos")
TARGETS = (ROOT / "reports" / "targets.md").read_text(encoding="utf-8")


@pytest.fixture(params=TESTBEDS)
def testbed(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.chdir(ROOT)
    return request.param


def capable_log_types(con, periods) -> list[str]:
    table = eda.baseline_table(eda.period_lines(con, periods), SETTINGS.ml)
    return list(table.index[table["baseline_capable"]])


def test_only_apache_error_lacks_a_baseline(testbed: str) -> None:
    periods = eda.testbed_periods(testbed, SETTINGS)
    with eda.connect(testbed, SETTINGS) as con:
        capable = capable_log_types(con, periods)
    assert sorted(capable) == ["apache_access", "audit", "auth", "dns", "vpn"]


def test_training_holds_no_label_other_than_dns_exfiltration(testbed: str) -> None:
    periods = eda.testbed_periods(testbed, SETTINGS)
    with eda.connect(testbed, SETTINGS) as con:
        table = eda.training_labels(con, periods)
    assert table[["log_type", "phase"]].values.tolist() == [["dns", "dnsteal_exfil"]]


def test_targets_file_states_the_computed_denominators(testbed: str) -> None:
    periods = eda.testbed_periods(testbed, SETTINGS)
    with eda.connect(testbed, SETTINGS) as con:
        traces = eda.phase_traces(con, periods)
        table = eda.phase_denominators(con, traces, capable_log_types(con, periods))
    summary = eda.denominator_summary(table)
    rows = re.findall(rf"^\| {testbed} \| .+? \| (\d+) \| (\d+) \|$", TARGETS, flags=re.M)
    assert [tuple(map(int, row)) for row in rows] == list(
        zip(summary["phases"], summary["required"], strict=True)
    )
    assert not (table["all_parsed"] & ~table["primary"]).any()


def test_exfiltration_domain_match_agrees_with_the_labels(testbed: str) -> None:
    with eda.connect(testbed, SETTINGS) as con:
        table = eda.exfil_gap(con, eda.exfil_domains(con)).set_index("host")
    assert table.loc["inet-firewall", "unlabeled"] == 0
    assert table.loc["inet-firewall", "labeled_exfil_outside"] == 0
    assert table.loc["inet-dns", "labeled"] == 0
    assert table.loc["inet-dns", "unlabeled"] > 0


def test_budget_is_feasible_for_every_alert_scope(testbed: str) -> None:
    periods = eda.testbed_periods(testbed, SETTINGS)
    alerts = baselines.load_ids_alerts(ROOT / "data" / "raw" / "ait_ads", testbed)
    rates = baselines.alert_rates(alerts, periods)
    table = baselines.budget_table(rates, SETTINGS.ml.incidents_per_day_budget)
    assert table["feasible"].all()
