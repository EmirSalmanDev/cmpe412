"""Window features (plan 6.3)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from logtriage.config import DrainConfig, FeaturesConfig, MLConfig
from logtriage.data.drain import add_templates
from logtriage.data.features import (
    FEATURE_SETS,
    FEATURE_TABLE,
    aggregate_windows,
    build_vocabularies,
    count_parsed_lines,
    create_derived_table,
    create_macros,
    has_vocabulary,
    is_vocabulary_feature,
    usable_features,
)
from logtriage.data.parsers import LogFile, parse_file
from logtriage.data.parsers.common import ParseContext
from logtriage.data.store import connect, write_lines
from logtriage.data.windows import create_parsed_view

FIXTURES = Path(__file__).parent / "fixtures" / "features"
ML = MLConfig(min_fit_lines=200)
SIM_START = datetime(2022, 1, 14, tzinfo=UTC)
SIM_END = SIM_START + timedelta(hours=1)
FIT_END = SIM_START + timedelta(minutes=10)


def lines_parquet(tmp_path: Path, fixture: str, log_type: str, host: str = "h") -> Path:
    """Run a fixture log through the real parser and Drain3 into a lines table."""
    log_file = LogFile(FIXTURES / fixture, host, f"logs/{fixture}", log_type)
    rows, _ = parse_file(log_file, "tiny", ParseContext(sim_start=SIM_START), SIM_END)
    rows.sort(key=lambda row: (row["ts"], row["line_no"]))
    add_templates(rows, FIT_END, DrainConfig(), tmp_path / "drain", log_type)
    path = tmp_path / f"lines_{log_type}.parquet"
    write_lines(rows, path)
    return path


def window(frame: pd.DataFrame, minute: int) -> pd.Series:
    """Return the row of the window that starts at a minute of the simulation."""
    start = pd.Timestamp(SIM_START + timedelta(minutes=minute))
    return frame[frame["window_start"] == start].iloc[0]


@pytest.fixture
def dns_windows(tmp_path: Path) -> pd.DataFrame:
    path = lines_parquet(tmp_path, "dnsmasq.log", "dns")
    features = FEATURE_SETS["dns"]
    with connect() as con:
        create_parsed_view(con, path, 60)
        create_macros(con, FeaturesConfig().second_level_suffixes)
        create_derived_table(con, features)
        build_vocabularies(con, features, FIT_END)
        aggregate_windows(con, features.aggregates)
        return con.execute(f"SELECT * FROM {FEATURE_TABLE}").df()


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
