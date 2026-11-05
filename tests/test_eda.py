"""EDA logic on a hand-made `eval.duckdb` stand-in: no data files needed."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from logtriage.config import MLConfig, Settings
from logtriage.data.periods import Periods, is_baseline_capable
from logtriage.data.store import connect
from logtriage.eval import eda
from logtriage.eval.metrics import required_detections

T0 = datetime(2022, 1, 1, tzinfo=UTC)
PERIODS = Periods(
    testbed="tiny",
    sim_start=T0,
    sim_end=T0 + timedelta(hours=100),
    first_attack=T0 + timedelta(hours=60),
    gap_hours=24.0,
    train_start=T0,
    train_end=T0 + timedelta(hours=36),
    fit_end=T0 + timedelta(hours=28.8),
    eval_start=T0 + timedelta(hours=36),
    eval_end=T0 + timedelta(hours=100),
)
EXFIL_NAME = "aaaa.bbbb.evil.biz"
TUNNEL, EXTERNAL = "172.19.1.1", "192.168.9.9"


def at(hours: float) -> datetime:
    return T0 + timedelta(hours=hours)


def dns_fields(qname: str, action: str = "query") -> str:
    return json.dumps({"qname": qname, "action": action})


class Lab:
    """Builds the `lines`, `labels` and `phases` tables of a test."""

    def __init__(self) -> None:
        self.con = connect()
        self.con.execute(
            "CREATE TABLE lines (line_id VARCHAR, log_type VARCHAR, host VARCHAR, file VARCHAR, "
            "ts TIMESTAMPTZ, raw VARCHAR, fields VARCHAR, src_ip VARCHAR, parse_ok BOOLEAN)"
        )
        self.con.execute("CREATE TABLE labels (line_id VARCHAR, labels VARCHAR[], phase VARCHAR)")
        self.con.execute(
            "CREATE TABLE phases (phase VARCHAR, start_utc TIMESTAMPTZ, end_utc TIMESTAMPTZ, "
            "source VARCHAR)"
        )
        self.count = 0

    def line(
        self,
        log_type: str,
        host: str,
        hours: float,
        raw: str = "text",
        fields: str = "{}",
        src_ip: str | None = None,
        parse_ok: bool = True,
        labels: list[str] | None = None,
        phase: str | None = None,
    ) -> str:
        self.count += 1
        line_id = f"{host}|logs/x|{self.count}"
        self.con.execute(
            "INSERT INTO lines VALUES (?, ?, ?, 'logs/x', ?, ?, ?, ?, ?)",
            [line_id, log_type, host, at(hours), raw, fields, src_ip, parse_ok],
        )
        if labels is not None:
            self.con.execute("INSERT INTO labels VALUES (?, ?, ?)", [line_id, labels, phase])
        return line_id

    def phase(
        self, name: str, start: float, end: float, source: str = eda.PUBLISHED_SOURCE
    ) -> None:
        self.con.execute(
            "INSERT INTO phases VALUES (?, ?, ?, ?)", [name, at(start), at(end), source]
        )


@pytest.fixture
def lab() -> Lab:
    return Lab()


def test_connect_uses_utc_whatever_the_machine_zone_is(tmp_path: Path) -> None:
    directory = tmp_path / "tiny"
    directory.mkdir()
    connect(directory / "eval.duckdb").close()
    settings = Settings()
    settings.paths.processed_dir = tmp_path
    with eda.connect("tiny", settings) as con:
        assert con.execute("SELECT current_setting('TimeZone')").fetchone()[0] == "UTC"


def test_line_counts_group_by_utc_day(lab: Lab) -> None:
    lab.line("auth", "a", 1)
    lab.line("auth", "a", 23.5)
    lab.line("auth", "a", 24.5)
    table = eda.line_counts(lab.con)
    assert table.loc[("auth", "a"), "2022-01-01"] == 2
    assert table.loc[("auth", "a"), "2022-01-02"] == 1
    assert table.loc[("auth", "a"), "total"] == 3


def test_period_lines_count_parsed_lines_only(lab: Lab) -> None:
    lab.line("auth", "a", 1)
    lab.line("auth", "a", 30)
    lab.line("auth", "a", 40)
    lab.line("auth", "a", 40, parse_ok=False)
    row = eda.period_lines(lab.con, PERIODS).loc["auth"]
    assert (row["fit"], row["calib"], row["eval"]) == (1, 1, 1)


@pytest.mark.parametrize(
    ("fit", "calib", "expected"),
    [(200, 50, True), (199, 50, False), (200, 49, False), (13, 0, False), (0, 10, False)],
)
def test_baseline_capability_needs_both_thresholds(fit: int, calib: int, expected: bool) -> None:
    assert is_baseline_capable(fit, calib, MLConfig()) is expected
    table = pd.DataFrame({"fit": [fit], "calib": [calib], "eval": [1]}, index=["x"])
    assert bool(eda.baseline_table(table, MLConfig()).loc["x", "baseline_capable"]) is expected


def test_attack_share_without_exfil_removes_it_from_both_sides(lab: Lab) -> None:
    lab.line("dns", "fw", 40, labels=["dnsteal"], phase="dnsteal_exfil")
    lab.line("dns", "fw", 41, labels=["dnsteal"], phase="dnsteal_exfil")
    lab.line("dns", "fw", 42, labels=["dns_scan"], phase="network_scans")
    lab.line("dns", "fw", 43)
    table = eda.attack_share(lab.con, PERIODS).set_index(["scope", "log_type"])
    assert table.loc[("evaluation", "all"), "attack_share"] == 0.75
    row = table.loc[("evaluation", "all without exfil")]
    assert (row["lines"], row["attack_lines"], row["normal_per_attack"]) == (2, 1, 1.0)


def test_phase_denominators_separate_the_variants(lab: Lab) -> None:
    lab.phase("in_training_only", 1, 2)
    lab.phase("no_baseline_only", 40, 41)
    lab.phase("no_traces", 42, 43)
    lab.phase("counted", 44, 45)
    lab.line("dns", "fw", 1.5, labels=["x"], phase="in_training_only")
    lab.line("apache_error", "w", 40.5, labels=["x"], phase="no_baseline_only")
    lab.line("dns", "fw", 44.5, labels=["x"], phase="counted")
    lab.line("apache_error", "w", 44.5, labels=["x"], phase="counted")
    traces = eda.phase_traces(lab.con, PERIODS)
    table = eda.phase_denominators(lab.con, traces, ["dns"]).set_index("phase")
    assert not table.loc["in_training_only", "all_parsed"]
    assert table.loc["no_baseline_only", "all_parsed"]
    assert not table.loc["no_baseline_only", "primary"]
    assert not table.loc["no_traces", "all_parsed"]
    assert table.loc["counted", "primary"]
    assert table.loc["counted", "log_types"] == "apache_error, dns"
    assert table.loc["counted", "baseline_log_types"] == "dns"


def test_denominator_summary_rounds_required_detections_up() -> None:
    table = pd.DataFrame(
        {
            "phase": [f"p{i}" for i in range(8)] + [eda.EXFIL_PHASE],
            "primary": [True] * 9,
            "all_parsed": [True] * 9,
        }
    )
    rows = eda.denominator_summary(table).set_index("variant")
    assert rows["phases"].tolist() == [9, 9, 8]
    assert rows["required"].tolist() == [8, 8, 7]


@pytest.mark.parametrize(("phases", "required"), [(10, 8), (9, 8), (8, 7), (5, 4), (1, 1), (0, 0)])
def test_required_detections_is_a_ceiling(phases: int, required: int) -> None:
    assert required_detections(phases, 0.8) == required


def test_attacker_ips_leave_out_compromised_hosts(lab: Lab) -> None:
    lab.line("apache_access", "w", 40, src_ip=TUNNEL, labels=["attacker_http"], phase="dirb")
    lab.line("vpn", "vpn", 40, src_ip=EXTERNAL, labels=["attacker_vpn"], phase="network_scans")
    lab.line("dns", "fw", 1, src_ip="10.0.0.3", labels=["dnsteal"], phase="dnsteal_exfil")
    assert eda.attacker_ips(lab.con) == {TUNNEL: "tunnel", EXTERNAL: "external"}


def test_exfil_domains_ignore_rare_domains(lab: Lab) -> None:
    for _ in range(200):
        lab.line("dns", "fw", 1, fields=dns_fields(EXFIL_NAME), labels=["dnsteal"])
    lab.line("dns", "fw", 1, fields=dns_fields("www.example.com"), labels=["dnsteal"])
    assert eda.exfil_domains(lab.con) == ["evil.biz"]


def test_exfil_gap_finds_unlabeled_lines_and_reports_how_the_match_did(lab: Lab) -> None:
    lab.line("dns", "fw", 1, fields=dns_fields(EXFIL_NAME), labels=["dnsteal"])
    lab.line("dns", "fw", 1, fields=dns_fields("no-such-domain.org"), labels=["dnsteal"])
    lab.line("dns", "fw", 1, fields=dns_fields("ok.example.com"))
    lab.line("dns", "resolver", 1, fields=dns_fields(EXFIL_NAME))
    lab.line("dns", "resolver", 1, fields=dns_fields(EXFIL_NAME, "forwarded"))
    lab.line("dns", "resolver", 1, fields=dns_fields("ok.example.com"))
    table = eda.exfil_gap(lab.con, ["evil.biz"]).set_index("host")
    assert table.loc["resolver", "unlabeled"] == 2
    assert table.loc["resolver", "exfil_queries"] == 1
    assert table.loc["resolver", "exfil_share"] == pytest.approx(2 / 3)
    assert table.loc["fw", "labeled"] == 1
    assert table.loc["fw", "unlabeled"] == 0
    assert table.loc["fw", "labeled_exfil_outside"] == 1


def test_attacker_line_takes_the_phase_holding_it_not_an_earlier_window(lab: Lab) -> None:
    # The phases touch, so with the 60 s margin this line is in both windows.
    lab.phase("first", 40, 41)
    lab.phase("second", 41, 41.5)
    lab.line("apache_access", "w", 41.01, raw=f"{TUNNEL} GET /")
    rows = eda.attacker_ip_lines(lab.con, {TUNNEL: "tunnel"}, ["evil.biz"])
    assert rows["phase"].tolist() == ["second"]


def test_attacker_line_within_the_tolerance_of_a_phase_counts_as_inside(lab: Lab) -> None:
    lab.phase("first", 40, 41)
    lab.line("apache_access", "w", 41 + 30 / 3600, raw=f"{TUNNEL} GET /")
    lab.line("apache_access", "w", 41 + 90 / 3600, raw=f"{TUNNEL} GET /")
    rows = eda.attacker_ip_lines(lab.con, {TUNNEL: "tunnel"}, ["evil.biz"])
    assert sorted(rows["phase"].fillna("outside")) == ["first", "outside"]


def test_attacker_lines_skip_exfil_and_other_addresses(lab: Lab) -> None:
    lab.phase("first", 40, 41)
    forwarded = f"forwarded {EXFIL_NAME} to {EXTERNAL}"
    lab.line("dns", "resolver", 40.5, raw=forwarded, fields=dns_fields(EXFIL_NAME, "forwarded"))
    lab.line("auth", "h", 40.5, raw=f"from 1{EXTERNAL} port 22")
    lab.line("auth", "h", 40.5, raw=f"from {EXTERNAL}0 port 22")
    lab.line("auth", "h", 40.5, raw=f"from {EXTERNAL} port 22")
    rows = eda.attacker_ip_lines(lab.con, {TUNNEL: "tunnel", EXTERNAL: "external"}, ["evil.biz"])
    assert rows[["role", "log_type", "lines"]].values.tolist() == [["external", "auth", 1]]


def test_attacker_gap_summary_gives_low_and_high_estimates() -> None:
    lines = pd.DataFrame(
        {
            "role": ["external", "tunnel", "tunnel"],
            "phase": ["a", "a", None],
            "lines": [10, 90, 500],
            "labeled": [8, 60, 0],
        }
    )
    table = eda.attacker_gap_summary(lines).set_index("role")
    assert table.loc["external", "unlabeled"] == 2
    assert table.loc["all roles", "unlabeled"] == 32
    assert table.loc["all roles", "gap_share"] == pytest.approx(0.32)
    assert table.loc["tunnel", "unlabeled_outside_windows"] == 500
    assert table.loc["all roles", "unlabeled_outside_windows"] == 500


def test_attacker_gap_by_ignores_lines_outside_the_windows() -> None:
    lines = pd.DataFrame(
        {
            "role": ["tunnel", "tunnel"],
            "phase": ["a", None],
            "lines": [10, 500],
            "labeled": [8, 0],
        }
    )
    table = eda.attacker_gap_by(lines, ["phase"])
    assert table[["phase", "lines", "unlabeled"]].values.tolist() == [["a", 10, 2]]


def test_stderr_gap_splits_attacker_output_from_noise(lab: Lab) -> None:
    wget = "--2022-01-24 03:59:22--  https://example.org/x.tar.gz"
    lab.line("apache_error", "web", 5, raw=wget, parse_ok=False)
    lab.line("apache_error", "web", 5, raw="  50K .......... 10%", parse_ok=False)
    lab.line("apache_error", "web", 5, raw="", parse_ok=False)
    lab.line("apache_error", "cloud", 5, raw=f"{eda.STDERR_NOISE}/msg.lock", parse_ok=False)
    table = eda.stderr_gap(lab.con).set_index("kind")
    assert table.loc["attacker output", "lines"] == 2
    assert table.loc["attacker output", "first_written"] == "2022-01-24 03:59:22"
    assert table.loc["attacker output", "inherited_ts"] == "2022-01-01 05:00:00"
    assert table.loc["noise", "lines"] == 1


def test_dns_contamination_measures_each_training_hour(lab: Lab) -> None:
    lab.line("dns", "inet-firewall", 1.1, fields=dns_fields(EXFIL_NAME), labels=["dnsteal"])
    lab.line("dns", "inet-firewall", 1.2, fields=dns_fields("ok.example.com"))
    lab.line("dns", "inet-dns", 1.3, fields=dns_fields(EXFIL_NAME))
    lab.line("dns", "inet-firewall", 30.5, fields=dns_fields("ok.example.com"))
    lab.line("dns", "inet-firewall", 40, fields=dns_fields(EXFIL_NAME), labels=["dnsteal"])
    table = eda.dns_contamination(lab.con, PERIODS, ["evil.biz"])
    assert table["period"].tolist() == ["fit", "calib"]
    assert table["labeled_host_share"].tolist() == [0.5, 0.0]
    assert table["all_hosts_share"].iloc[0] == pytest.approx(2 / 3)
    summary = eda.contamination_summary(table).set_index("period")
    assert summary.loc["training", "hours"] == 2
    assert summary.loc["training", "hours_with_exfil"] == 1
    assert summary.loc["training", "labeled_host_share"] == pytest.approx(1 / 3)


def test_period_summary_reports_the_normal_lead_in(lab: Lab) -> None:
    table = eda.period_summary(PERIODS).set_index("period")
    assert table.loc["training", "hours"] == 36
    assert table.loc["evaluation before first attack", "hours"] == 24


def test_training_labels_stop_at_the_end_of_training(lab: Lab) -> None:
    lab.line("dns", "fw", 1, labels=["dnsteal"], phase="dnsteal_exfil")
    lab.line("dns", "fw", 40, labels=["dnsteal"], phase="dnsteal_exfil")
    table = eda.training_labels(lab.con, PERIODS)
    assert table["labeled"].tolist() == [1]
