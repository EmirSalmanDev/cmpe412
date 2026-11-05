"""Window features (plan 6.3)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from logtriage.config import MLConfig
from logtriage.data.features import (
    count_parsed_lines,
    has_vocabulary,
    is_vocabulary_feature,
    usable_features,
)
from logtriage.data.store import connect, write_lines
from logtriage.data.windows import create_parsed_view

ML = MLConfig(min_fit_lines=200)


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
