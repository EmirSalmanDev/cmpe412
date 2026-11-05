"""Window features (plan 6.3)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from logtriage.config import DrainConfig, FeaturesConfig, MLConfig, Settings
from logtriage.data.drain import add_templates
from logtriage.data.features import (
    FEATURE_SETS,
    FEATURE_TABLE,
    SCALER_DIR,
    VOCABULARY_DIR,
    FeatureScaler,
    aggregate_windows,
    build_vocabularies,
    build_windows,
    count_parsed_lines,
    create_derived_table,
    create_macros,
    feature_columns,
    feature_summary,
    fit_scaler,
    has_vocabulary,
    is_vocabulary_feature,
    usable_features,
)
from logtriage.data.parsers import LogFile, parse_file
from logtriage.data.parsers.common import ParseContext
from logtriage.data.periods import Periods
from logtriage.data.store import build_agent_db, connect, write_lines
from logtriage.data.windows import PARSED_VIEW, create_parsed_view, period_sql

FIXTURES = Path(__file__).parent / "fixtures" / "features"
ML = MLConfig(min_fit_lines=200)
SIM_START = datetime(2022, 1, 14, tzinfo=UTC)
SIM_END = SIM_START + timedelta(hours=1)
FIT_END = SIM_START + timedelta(minutes=10, seconds=30)
TRAIN_END = SIM_START + timedelta(minutes=20, seconds=30)
PERIODS = Periods(
    testbed="tiny",
    sim_start=SIM_START,
    sim_end=SIM_END,
    first_attack=SIM_END,
    gap_hours=24.0,
    train_start=SIM_START,
    train_end=TRAIN_END,
    fit_end=FIT_END,
    eval_start=TRAIN_END,
    eval_end=SIM_END,
)
SOURCES = {
    "apache_access": "apache_access.log",
    "apache_error": "apache_error.log",
    "auth": "auth.log",
    "dns": "dnsmasq.log",
    "audit": "audit.log",
    "vpn": "openvpn.log",
}


def fixture_rows(log_type: str) -> list[dict]:
    """Parse the fixture log of a log type."""
    fixture = SOURCES[log_type]
    log_file = LogFile(FIXTURES / fixture, "h", f"logs/{fixture}", log_type)
    rows, _ = parse_file(log_file, "tiny", ParseContext(sim_start=SIM_START), SIM_END)
    return sorted(rows, key=lambda row: (row["ts"], row["line_no"]))


def write_rows(rows: list[dict], directory: Path, log_type: str) -> Path:
    """Run parsed rows through Drain3 into a lines table."""
    add_templates(rows, FIT_END, DrainConfig(), directory / "drain", log_type)
    path = directory / f"lines_{log_type}.parquet"
    write_lines(rows, path)
    return path


def settings_for(**ml: int) -> Settings:
    """Settings with thresholds that suit the small fixtures."""
    return Settings(ml=MLConfig(**{"min_fit_lines": 2, "min_calib_lines": 1, **ml}))


def build(directory: Path, settings: Settings | None = None, edit=None) -> dict:
    """Build the windows of all fixture logs, after applying `edit` to the parsed rows."""
    directory.mkdir(exist_ok=True)
    for log_type in SOURCES:
        rows = fixture_rows(log_type)
        write_rows(edit(rows) if edit else rows, directory, log_type)
    return build_windows(directory, PERIODS, settings or settings_for())


def read_windows(directory: Path, log_type: str) -> pd.DataFrame:
    """Read a windows table."""
    return pd.read_parquet(directory / f"windows_{log_type}.parquet")


def read_vocabulary(directory: Path, log_type: str, name: str) -> set[str]:
    """Read the values of a vocabulary."""
    table = pd.read_parquet(directory / VOCABULARY_DIR / f"{log_type}.parquet")
    return set(table.loc[table["vocabulary"] == name, "value"])


def later_lines_changed(rows: list[dict]) -> list[dict]:
    """Replace the content of every line after the fit period, and add a burst of lines."""
    changed = []
    for row in rows:
        if row["ts"] < FIT_END or not row["parse_ok"]:
            changed.append(row)
            continue
        fields = json.loads(row["fields"])
        fields |= {key: f"later-{key}" for key in ("path", "user_agent", "exe")}
        if "qname" in fields:
            fields["qname"] = "later.domain.org"
        burst = [
            {
                **row,
                "line_no": row["line_no"] * 1000 + number,
                "line_id": f"{row['line_id']}-{number}",
                "src_ip": "10.9.9.9",
                "user": "later-user",
                "fields": json.dumps(fields),
                "message": f"later message {number}",
            }
            for number in range(50)
        ]
        changed += burst
    return changed


def fit_lines_changed(rows: list[dict]) -> list[dict]:
    """Replace the content of the fit-period lines."""
    return [
        {**row, "src_ip": "10.8.8.8", "user": "fit-user"} if row["ts"] < FIT_END else row
        for row in rows
    ]


def window(frame: pd.DataFrame, minute: int) -> pd.Series:
    """Return the row of the window that starts at a minute of the simulation."""
    start = pd.Timestamp(SIM_START + timedelta(minutes=minute))
    return frame[frame["window_start"] == start].iloc[0]


@pytest.fixture
def dns_windows(tmp_path: Path) -> pd.DataFrame:
    path = write_rows(fixture_rows("dns"), tmp_path, "dns")
    features = FEATURE_SETS["dns"]
    with connect() as con:
        create_parsed_view(con, path, 60)
        create_macros(con, FeaturesConfig().second_level_suffixes)
        create_derived_table(con, features)
        build_vocabularies(con, features, FIT_END)
        aggregate_windows(con, features.aggregates)
        return con.sql(f"SELECT * FROM {FEATURE_TABLE}").to_arrow_table().to_pandas()


@pytest.fixture
def macros():
    with connect() as con:
        create_macros(con, FeaturesConfig().second_level_suffixes)
        yield con


@pytest.mark.parametrize(
    ("text", "bits"),
    [("aaaa", 0.0), ("aabb", 1.0), ("abcd", 2.0), ("aaab", 0.8112781), ("", 0.0), ("Aa", 1.0)],
)
def test_shannon_entropy(macros, text: str, bits: float) -> None:
    value = macros.execute("SELECT shannon_entropy(?)", [text]).fetchone()[0]
    assert value == pytest.approx(bits)


@pytest.mark.parametrize(
    ("qname", "domain"),
    [
        ("www.example.com", "example.com"),
        ("WWW.Example.COM.", "example.com"),
        ("example.com", "example.com"),
        ("news.thesun.co.uk", "thesun.co.uk"),
        ("cdn.detik.net.id", "detik.net.id"),
        ("login.sina.com.cn", "sina.com.cn"),
        ("www.google.at", "google.at"),
        ("co.uk", "co.uk"),
        ("mail", "mail"),
        ("180.231.168.192.in-addr.arpa", "in-addr.arpa"),
        ("3x6-.596-.Iun*W-.kennedy-mendoza.info", "kennedy-mendoza.info"),
    ],
)
def test_registered_domain(macros, qname: str, domain: str) -> None:
    assert macros.execute("SELECT registered_domain(?)", [qname]).fetchone()[0] == domain


@pytest.mark.parametrize(
    ("qname", "parts"),
    [
        ("www.example.com", ["www", "example"]),
        ("news.thesun.co.uk", ["news", "thesun"]),
        ("example.com", ["example"]),
        ("mail", ["mail"]),
        ("a..b.com.", ["a", "b"]),
        ("Ab.Cd.net", ["Ab", "Cd"]),
    ],
)
def test_name_parts(macros, qname: str, parts: list[str]) -> None:
    assert macros.execute("SELECT name_parts(?)", [qname]).fetchone()[0] == parts


def test_dns_features_count_query_lines_only(dns_windows: pd.DataFrame) -> None:
    row = window(dns_windows, 1)
    assert row["n_queries"] == 4
    assert row["n_unique_clients"] == 2
    assert row["mean_qname_len"] == pytest.approx((15 + 16 + 16 + 17) / 4)


def test_dns_window_without_a_query_has_zeros(dns_windows: pd.DataFrame) -> None:
    row = window(dns_windows, 2)
    assert row[list(FEATURE_SETS["dns"].aggregates)].astype(float).sum() == 0


def test_top_domain_share_is_the_share_of_the_most_queried_domain(
    dns_windows: pd.DataFrame,
) -> None:
    assert window(dns_windows, 1)["top_domain_share"] == pytest.approx(3 / 4)
    assert window(dns_windows, 30)["top_domain_share"] == pytest.approx(1 / 3)


def test_ratio_unique_qnames_ignores_case_and_the_trailing_dot(
    dns_windows: pd.DataFrame,
) -> None:
    assert window(dns_windows, 1)["ratio_unique_qnames"] == pytest.approx(3 / 4)


def test_label_entropy_covers_every_part_left_of_the_suffix(dns_windows: pd.DataFrame) -> None:
    row = window(dns_windows, 30)
    # aabb 1.0, abcd 2.0, z 0.0; mail 2.0; www 0.0, example 2.5216406.
    assert row["max_label_len"] == 7
    assert row["max_label_entropy"] == pytest.approx(2.5216406)
    assert row["mean_label_entropy"] == pytest.approx((1 + 2 + 0 + 2 + 0 + 2.5216406) / 6)


def test_unseen_domains_use_the_fit_vocabulary(dns_windows: pd.DataFrame) -> None:
    assert window(dns_windows, 1)["n_unseen_domains"] == 0
    assert window(dns_windows, 15)["n_unseen_domains"] == 1
    assert window(dns_windows, 30)["n_unseen_domains"] == 2


def test_lines_that_did_not_parse_add_no_window(dns_windows: pd.DataFrame) -> None:
    assert len(dns_windows) == 4


@pytest.mark.parametrize(
    "name",
    [
        "n_unseen_templates",
        "ratio_unseen_templates",
        "mean_template_rarity",
        "max_template_rarity",
        "ratio_unseen_paths",
        "ratio_unseen_ua",
        "n_unseen_src_ip",
        "n_unseen_users",
        "n_unseen_domains",
        "n_unseen_exe",
    ],
)
def test_every_d15_feature_counts_as_a_vocabulary_feature(name: str) -> None:
    assert is_vocabulary_feature(name)


@pytest.mark.parametrize("name", ["n_lines", "n_unique_templates", "n_unique_src_ip", "n_req"])
def test_plain_counts_are_not_vocabulary_features(name: str) -> None:
    assert not is_vocabulary_feature(name)


def test_threshold_is_inclusive() -> None:
    assert has_vocabulary(200, ML)
    assert not has_vocabulary(199, ML)


def test_features_drop_below_the_threshold_only() -> None:
    names = ["n_lines", "mean_template_rarity", "n_unique_src_ip", "n_unseen_src_ip"]
    assert usable_features(names, 200, ML) == names
    assert usable_features(names, 199, ML) == ["n_lines", "n_unique_src_ip"]
    assert usable_features(names, 0, ML) == ["n_lines", "n_unique_src_ip"]


def test_only_parsed_lines_in_the_interval_count_toward_the_threshold(tmp_path: Path) -> None:
    start = datetime(2022, 1, 14, tzinfo=UTC)
    end = datetime(2022, 1, 14, 0, 10, tzinfo=UTC)
    rows = [
        {"line_id": "a", "ts": start, "parse_ok": True},
        {"line_id": "b", "ts": start, "parse_ok": False},
        {"line_id": "c", "ts": end, "parse_ok": True},
    ]
    path = tmp_path / "lines_vpn.parquet"
    write_lines(rows, path)
    with connect() as con:
        create_parsed_view(con, path, 60)
        assert count_parsed_lines(con, start, end) == 1


def test_apache_features(tmp_path: Path) -> None:
    build(tmp_path)
    windows = read_windows(tmp_path, "apache_access")
    fit = window(windows, 1)
    assert fit["n_req"] == 3
    assert fit["ratio_post"] == pytest.approx(1 / 3)
    assert fit["n_unique_paths"] == 2
    assert fit["mean_path_len"] == pytest.approx((16 + 16 + 6) / 3)
    assert fit["max_path_len"] == 16
    late = window(windows, 30)
    assert late["ratio_4xx"] == pytest.approx(2 / 4)
    assert late["ratio_404"] == pytest.approx(1 / 4)
    assert late["ratio_5xx"] == pytest.approx(1 / 4)
    assert late["n_unique_ua"] == 2
    assert late["n_unique_src_ip"] == 2


def test_apache_unseen_features(tmp_path: Path) -> None:
    build(tmp_path)
    windows = read_windows(tmp_path, "apache_access")
    late = window(windows, 30)
    # /admin.php is new. /index.html is known without its query string, and "-" has no path.
    assert late["ratio_unseen_paths"] == pytest.approx(1 / 4)
    assert late["ratio_unseen_ua"] == pytest.approx(2 / 4)
    assert late["n_unseen_src_ip"] == 1
    assert window(windows, 15)["ratio_unseen_ua"] == 1


def test_apache_error_counts_error_levels(tmp_path: Path) -> None:
    build(tmp_path)
    windows = read_windows(tmp_path, "apache_error")
    assert window(windows, 1)["n_errors"] == 1
    assert window(windows, 1)["n_lines"] == 2
    assert window(windows, 30)["n_errors"] == 2
    assert window(windows, 30)["n_unique_clients"] == 2


def test_stderr_lines_stay_out_of_the_windows(tmp_path: Path) -> None:
    build(tmp_path)
    assert read_windows(tmp_path, "apache_error")["n_lines"].sum() == 4


def test_auth_features(tmp_path: Path) -> None:
    build(tmp_path)
    windows = read_windows(tmp_path, "auth")
    fit = window(windows, 1)
    assert fit["n_success_login"] == 1
    assert fit["n_session_open"] == 2
    assert fit["n_unseen_users"] == 0
    assert window(windows, 15)["n_sudo"] == 1
    late = window(windows, 30)
    assert late["n_failed_login"] == 1
    assert late["n_su"] == 2
    assert late["n_unique_users"] == 2
    assert late["n_unseen_users"] == 1
    assert late["n_events_by_web_user"] == 2


def test_audit_features(tmp_path: Path) -> None:
    build(tmp_path)
    windows = read_windows(tmp_path, "audit")
    assert window(windows, 1)["n_user_auth_events"] == 2
    assert window(windows, 15)["n_unseen_exe"] == 1
    late = window(windows, 30)
    assert late["n_execve"] == 2
    assert late["n_execve_web_user"] == 1
    assert late["n_root_execve"] == 1
    assert late["n_unique_exe"] == 3
    assert late["n_unseen_exe"] == 2


def test_vpn_features(tmp_path: Path) -> None:
    build(tmp_path)
    windows = read_windows(tmp_path, "vpn")
    fit = window(windows, 1)
    assert fit["n_new_sessions"] == 1
    assert fit["n_auth_success"] == 1
    assert fit["n_unseen_src_ip"] == 0
    assert window(windows, 15)["n_auth_fail"] == 1
    assert window(windows, 15)["n_unseen_src_ip"] == 1
    late = window(windows, 30)
    assert late["n_unique_src_ip"] == 2
    assert late["n_unseen_src_ip"] == 2
    assert late["n_unseen_users"] == 1  # mallory; UNDEF is a placeholder


def test_common_features(tmp_path: Path) -> None:
    build(tmp_path)
    late = window(read_windows(tmp_path, "auth"), 30)
    assert late["n_lines"] == 3
    assert late["n_unique_templates"] >= 2
    assert late["ratio_unseen_templates"] == pytest.approx(late["n_unseen_templates"] / 3)
    assert late["mean_template_rarity"] > 0
    assert late["max_template_rarity"] >= late["mean_template_rarity"] - 1e-9


def test_window_key_and_entities(tmp_path: Path) -> None:
    build(tmp_path)
    windows = read_windows(tmp_path, "apache_access")
    assert not windows.duplicated(["testbed", "host", "log_type", "window_start"]).any()
    assert list(window(windows, 30)["src_ips"]) == ["10.0.0.2", "10.0.0.9"]
    assert list(window(windows, 30)["users"]) == []
    assert str(windows["window_start"].dt.tz) == "UTC"


def test_entity_lists_keep_the_most_frequent_values(tmp_path: Path) -> None:
    settings = settings_for()
    settings.features.top_entities = 1
    build(tmp_path, settings)
    assert list(window(read_windows(tmp_path, "apache_access"), 1)["src_ips"]) == ["10.0.0.2"]


def test_window_period_is_where_the_window_ends(tmp_path: Path) -> None:
    rows = [(minute, second) for minute, second in ((10, 0), (10, 29), (20, 0), (20, 29), (21, 0))]

    def at_boundaries(parsed: list[dict]) -> list[dict]:
        base = next(row for row in parsed if row["parse_ok"])
        return [
            {
                **base,
                "line_no": number,
                "line_id": f"h|f|{number}",
                "ts": SIM_START + timedelta(minutes=minute, seconds=second),
            }
            for number, (minute, second) in enumerate(rows, 1)
        ]

    write_rows(at_boundaries(fixture_rows("vpn")), tmp_path, "vpn")
    with connect() as con:
        create_parsed_view(con, tmp_path / "lines_vpn.parquet", 60)
        got = con.execute(
            f"SELECT DISTINCT minute(window_start), {period_sql(60, PERIODS)} "
            f"FROM {PARSED_VIEW} ORDER BY 1"
        ).fetchall()
    # 00:10 crosses fit_end and 00:20 crosses train_end, so each goes to the later period.
    assert got == [(10, "calib"), (20, "eval"), (21, "eval")]


def test_fit_windows_hold_fit_lines_only(tmp_path: Path) -> None:
    build(tmp_path)
    for log_type in SOURCES:
        windows = read_windows(tmp_path, log_type)
        ends = windows.loc[windows["period"] == "fit", "window_start"] + timedelta(seconds=60)
        assert (ends <= pd.Timestamp(FIT_END)).all()


def test_vocabularies_hold_fit_period_values_only(tmp_path: Path) -> None:
    build(tmp_path)
    assert read_vocabulary(tmp_path, "dns", "domains") == {"example.com", "thesun.co.uk"}
    assert read_vocabulary(tmp_path, "apache_access", "paths") == {"/index.html", "/login"}
    assert read_vocabulary(tmp_path, "apache_access", "ua") == {"Mozilla", "curl"}
    assert read_vocabulary(tmp_path, "apache_access", "src_ip") == {"10.0.0.2", "10.0.0.3"}
    assert read_vocabulary(tmp_path, "auth", "users") == {"alice", "root"}
    assert read_vocabulary(tmp_path, "audit", "exe") == {"/usr/sbin/sshd", "/lib/systemd/systemd"}
    assert read_vocabulary(tmp_path, "vpn", "users") == {"alice"}


def test_a_line_at_fit_end_is_not_a_fit_line(tmp_path: Path) -> None:
    def move_to_fit_end(rows: list[dict]) -> list[dict]:
        late = rows[-1]
        return [*rows[:-1], {**late, "ts": FIT_END, "src_ip": "10.7.7.7"}]

    write_rows(move_to_fit_end(fixture_rows("vpn")), tmp_path, "vpn")
    features = FEATURE_SETS["vpn"]
    with connect() as con:
        create_parsed_view(con, tmp_path / "lines_vpn.parquet", 60)
        create_derived_table(con, features)
        build_vocabularies(con, features, FIT_END)
        values = {row[0] for row in con.execute("SELECT value FROM vocabulary").fetchall()}
    assert "10.7.7.7" not in values


def test_later_lines_change_neither_vocabularies_nor_scalers(tmp_path: Path) -> None:
    base, changed = tmp_path / "base", tmp_path / "changed"
    build(base)
    report = build(changed, edit=later_lines_changed)
    assert (
        read_windows(changed, "dns")["n_lines"].sum() > read_windows(base, "dns")["n_lines"].sum()
    )
    for log_type, entry in report.items():
        if entry["vocabulary_sizes"]:
            before = pd.read_parquet(base / VOCABULARY_DIR / f"{log_type}.parquet")
            after = pd.read_parquet(changed / VOCABULARY_DIR / f"{log_type}.parquet")
            pd.testing.assert_frame_equal(before, after)
        if entry["baseline_capable"]:
            before = FeatureScaler.load(base / SCALER_DIR / f"{log_type}.json")
            after = FeatureScaler.load(changed / SCALER_DIR / f"{log_type}.json")
            shared = [name for name in before.columns if name in after.columns]
            for name in shared:
                position = (before.columns.index(name), after.columns.index(name))
                assert before.center[position[0]] == after.center[position[1]]
                assert before.scale[position[0]] == after.scale[position[1]]


def test_fit_lines_do_change_the_vocabularies(tmp_path: Path) -> None:
    build(tmp_path, edit=fit_lines_changed)
    assert read_vocabulary(tmp_path, "vpn", "src_ip") == {"10.8.8.8"}
    assert read_vocabulary(tmp_path, "auth", "users") == {"fit-user"}


def test_scaler_uses_fit_windows_only() -> None:
    windows = pd.DataFrame(
        {
            "period": ["fit"] * 5 + ["calib", "eval"],
            "n_lines": [0.0, 1.0, 3.0, 7.0, 15.0, 1e6, 1e6],
            "ratio_x": [0.0, 0.25, 0.5, 0.75, 1.0, 50.0, 50.0],
        }
    )
    scaler = fit_scaler(windows)
    assert scaler.columns == ["n_lines", "ratio_x"]
    assert scaler.count_columns == ["n_lines"]
    assert scaler.center == pytest.approx([np.log1p(3.0), 0.5])
    assert scaler.scale == pytest.approx([np.log1p(7.0) - np.log1p(1.0), 0.5])
    assert fit_scaler(windows.iloc[:5]) == scaler


def test_scaler_applies_log1p_to_counts_only() -> None:
    windows = pd.DataFrame(
        {
            "period": ["fit"] * 3,
            "n_lines": [0.0, 1.0, 3.0],
            "ratio_x": [0.0, 0.5, 1.0],
        }
    )
    scaled = fit_scaler(windows).transform(windows)
    assert scaled[1].tolist() == pytest.approx([0.0, 0.0])
    assert np.isfinite(scaled).all()


def test_scaler_handles_a_feature_that_is_zero_on_every_fit_window() -> None:
    windows = pd.DataFrame({"period": ["fit", "fit", "eval"], "n_unseen_x": [0.0, 0.0, 3.0]})
    scaler = fit_scaler(windows)
    assert scaler.center == [0.0]
    assert scaler.scale == [1.0]
    assert scaler.transform(windows)[2, 0] == pytest.approx(np.log1p(3.0))


def test_scaler_needs_fit_windows() -> None:
    with pytest.raises(ValueError, match="no fit windows"):
        fit_scaler(pd.DataFrame({"period": ["eval"], "n_lines": [1.0]}))


def test_scaler_survives_a_round_trip(tmp_path: Path) -> None:
    scaler = FeatureScaler(["n_lines"], ["n_lines"], [1.0], [2.0])
    scaler.save(tmp_path / "scalers" / "x.json")
    assert FeatureScaler.load(tmp_path / "scalers" / "x.json") == scaler


def test_a_type_below_min_fit_lines_loses_its_vocabulary_features(tmp_path: Path) -> None:
    report = build(tmp_path, settings_for(min_fit_lines=4))
    assert report["vpn"]["fit_lines"] == 3
    columns = read_windows(tmp_path, "vpn").columns
    assert not [name for name in columns if is_vocabulary_feature(name)]
    assert "n_unique_templates" in columns
    assert report["vpn"]["dropped_vocabulary"]
    assert not (tmp_path / VOCABULARY_DIR / "vpn.parquet").exists()
    assert not (tmp_path / SCALER_DIR / "vpn.json").exists()
    assert report["vpn"]["baseline_capable"] is False


def test_a_type_with_no_fit_lines_keeps_finite_values(tmp_path: Path) -> None:
    def no_fit_lines(rows: list[dict]) -> list[dict]:
        return [row for row in rows if row["ts"] >= FIT_END]

    report = build(tmp_path, edit=no_fit_lines)
    assert report["apache_error"]["fit_lines"] == 0
    windows = read_windows(tmp_path, "apache_error")
    assert set(windows["period"]) == {"eval"}
    assert np.isfinite(windows[feature_columns(windows)].to_numpy(dtype=float)).all()


def test_a_constant_feature_is_dropped_but_unseen_ones_stay(tmp_path: Path) -> None:
    report = build(tmp_path)
    assert "ratio_post" in report["apache_access"]["features"]
    assert "n_unique_clients" not in report["apache_access"]["features"]
    # 0 on every fit window by construction, yet it is the signal of later periods.
    assert "n_unseen_domains" in report["dns"]["features"]
    assert "n_failed_login" in report["auth"]["features"]
    assert "ratio_5xx" in report["apache_access"]["features"]
    assert report["audit"]["dropped_constant"] == []


def test_constant_features_are_reported(tmp_path: Path) -> None:
    def no_execve(rows: list[dict]) -> list[dict]:
        return [row for row in rows if "syscall=59" not in row["message"]]

    report = build(tmp_path, edit=no_execve)
    expected = {"n_execve", "n_execve_web_user", "n_root_execve"}
    assert expected <= set(report["audit"]["dropped_constant"])
    assert not expected & set(read_windows(tmp_path, "audit").columns)


def test_n_lines_stays_even_when_constant(tmp_path: Path) -> None:
    report = build(tmp_path)
    assert "n_lines" in report["apache_error"]["features"]


def test_a_rebuild_removes_stale_scalers(tmp_path: Path) -> None:
    build(tmp_path)
    assert (tmp_path / SCALER_DIR / "vpn.json").exists()
    build(tmp_path, settings_for(min_fit_lines=4))
    assert not (tmp_path / SCALER_DIR / "vpn.json").exists()


def test_rebuilding_gives_identical_windows(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    build(first)
    build(second)
    for log_type in SOURCES:
        pd.testing.assert_frame_equal(read_windows(first, log_type), read_windows(second, log_type))


def test_report_is_written(tmp_path: Path) -> None:
    report = build(tmp_path)
    written = json.loads((tmp_path / "features_report.json").read_text(encoding="utf-8"))
    assert written == report
    assert set(written) == set(SOURCES)


def test_feature_summary_has_one_row_per_feature(tmp_path: Path) -> None:
    build(tmp_path)
    windows = read_windows(tmp_path, "dns")
    summary = feature_summary(windows)
    assert list(summary.index) == feature_columns(windows)
    assert list(summary.columns) == ["mean_fit", "mean_calib", "mean_eval", "max", "share_nonzero"]
    assert summary.loc["n_queries", "max"] == 4


def test_window_views_join_both_databases(tmp_path: Path) -> None:
    build(tmp_path)
    build_agent_db(tmp_path)
    with connect(tmp_path / "agent.duckdb", read_only=True) as agent:
        names = {row[0] for row in agent.execute("SHOW TABLES").fetchall()}
        rows = agent.execute("SELECT count(DISTINCT log_type) FROM windows").fetchone()
    assert {"windows", "windows_dns", "lines", "lines_dns"} <= names
    assert rows == (6,)
