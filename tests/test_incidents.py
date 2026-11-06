"""Incident grouping (plan 5.6, 6.6)."""

import json
import math
from datetime import UTC, datetime, timedelta
from itertools import combinations

import numpy as np
import pandas as pd
import pytest

from logtriage.ml.incidents import (
    UnionFind,
    common_entities,
    group_incidents,
    link_windows,
    priority,
)

T0 = datetime(2022, 1, 14, tzinfo=UTC)
GAP = timedelta(minutes=10)


def window(minute: int, host: str = "h", ips=(), users=(), log_type="vpn", score=0.99) -> dict:
    return {
        "testbed": "tiny",
        "host": host,
        "log_type": log_type,
        "window_start": pd.Timestamp(T0 + timedelta(minutes=minute)),
        "src_ips": list(ips),
        "users": list(users),
        "score": score,
    }


def components(rows: list[dict], common=frozenset()) -> list[int]:
    """Number the components by first appearance, for easy comparison."""
    found = link_windows(pd.DataFrame(rows), set(common), GAP).tolist()
    order = list(dict.fromkeys(found))
    return [order.index(value) for value in found]


def test_union_find_merges_and_compresses() -> None:
    sets = UnionFind(4)
    sets.union(0, 1)
    sets.union(2, 3)
    sets.union(1, 3)
    assert len({sets.find(item) for item in range(4)}) == 1


def test_same_host_within_the_gap_links() -> None:
    assert components([window(0), window(10)]) == [0, 0]


def test_same_host_beyond_the_gap_does_not_link() -> None:
    assert components([window(0), window(11)]) == [0, 1]


def test_other_hosts_without_a_shared_entity_do_not_link() -> None:
    assert components([window(0, "a", ["1.1.1.1"]), window(1, "b", ["2.2.2.2"])]) == [0, 1]


def test_a_shared_ip_links_across_hosts_and_log_types() -> None:
    rows = [window(0, "a", ["1.1.1.1"]), window(1, "b", ["1.1.1.1"], log_type="dns")]
    assert components(rows) == [0, 0]


def test_a_shared_user_links_across_hosts() -> None:
    assert components([window(0, "a", users=["eve"]), window(1, "b", users=["eve"])]) == [0, 0]


def test_a_user_does_not_link_to_an_ip_of_the_same_text() -> None:
    assert components([window(0, "a", ["x"]), window(1, "b", users=["x"])]) == [0, 1]


def test_a_shared_entity_beyond_the_gap_does_not_link() -> None:
    assert components([window(0, "a", ["1.1.1.1"]), window(11, "b", ["1.1.1.1"])]) == [0, 1]


def test_a_common_entity_does_not_link() -> None:
    rows = [window(0, "a", ["1.1.1.1"]), window(1, "b", ["1.1.1.1"])]
    assert components(rows, {("vpn", "ip", "1.1.1.1")}) == [0, 1]


def test_an_entity_is_common_only_in_its_own_log_type() -> None:
    rows = [
        window(0, "a", ["1.1.1.1"], log_type="dns"),
        window(1, "b", ["1.1.1.1"], log_type="auth"),
        window(2, "c", ["1.1.1.1"], log_type="auth"),
    ]
    assert components(rows, {("dns", "ip", "1.1.1.1")}) == [0, 1, 1]


def test_links_chain_transitively() -> None:
    assert components([window(0), window(8), window(16), window(24)]) == [0, 0, 0, 0]


def test_the_sweep_matches_every_pair() -> None:
    rng = np.random.default_rng(3)
    rows = sorted(
        (
            window(
                int(rng.integers(0, 200)),
                f"h{rng.integers(0, 6)}",
                [f"ip{rng.integers(0, 8)}"] if rng.random() < 0.7 else [],
                [f"u{rng.integers(0, 4)}"] if rng.random() < 0.3 else [],
            )
            for _ in range(120)
        ),
        key=lambda row: row["window_start"],
    )
    sets = UnionFind(len(rows))
    for first, second in combinations(range(len(rows)), 2):
        a, b = rows[first], rows[second]
        shared = set(a["src_ips"]) & set(b["src_ips"]) or set(a["users"]) & set(b["users"])
        close = abs(a["window_start"] - b["window_start"]) <= GAP
        if close and (a["host"] == b["host"] or shared):
            sets.union(first, second)
    expected = [sets.find(item) for item in range(len(rows))]
    order = list(dict.fromkeys(expected))
    assert components(rows) == [order.index(value) for value in expected]


def test_common_entities_need_more_than_the_share() -> None:
    fit = pd.DataFrame(
        {
            "src_ips": [["a", "b"], ["a"], ["a"], ["b", "c"]],
            "users": [["u"], ["u"], [], []],
        }
    )
    assert common_entities(fit, 0.5) == {("ip", "a")}


def test_common_entities_of_an_empty_list_column() -> None:
    fit = pd.DataFrame({"src_ips": [[], []], "users": [[], []]})
    assert common_entities(fit, 0.5) == set()


def test_priority_formula() -> None:
    expected = 0.9 * 1.2 + 0.01 * math.log1p(4)
    assert priority(0.9, 3, 4) == pytest.approx(expected)


def incidents_of(rows: list[dict], common=frozenset(), gap=10):
    frame = pd.DataFrame(rows)
    return frame, *group_incidents(frame, set(common), gap, 60, "tiny")


def test_incident_columns() -> None:
    rows = [
        window(0, "a", ["1.1.1.1", "2.2.2.2"], ["eve"], "vpn", 0.97),
        window(3, "b", ["1.1.1.1"], [], "dns", 0.99),
    ]
    _, table, _ = incidents_of(rows)
    assert len(table) == 1
    row = table.iloc[0]
    assert row["incident_id"] == "tiny-0001"
    assert row["start"] == pd.Timestamp(T0)
    assert row["end"] == pd.Timestamp(T0 + timedelta(minutes=4))
    assert row["hosts"] == ["a", "b"]
    assert row["log_types"] == ["dns", "vpn"]
    assert row["src_ips"] == ["1.1.1.1", "2.2.2.2"]
    assert row["users"] == ["eve"]
    assert row["n_windows"] == 2
    assert row["max_score"] == 0.99
    assert row["mean_score"] == pytest.approx(0.98)
    assert row["priority"] == pytest.approx(priority(0.99, 2, 2))


def test_window_keys_are_json_and_name_every_window() -> None:
    _, table, _ = incidents_of([window(0, "a", ["x"]), window(1, "b", ["x"], log_type="dns")])
    keys = json.loads(table.iloc[0]["window_keys"])
    assert keys == [
        ["tiny", "a", "vpn", pd.Timestamp(T0).isoformat()],
        ["tiny", "b", "dns", pd.Timestamp(T0 + timedelta(minutes=1)).isoformat()],
    ]


def test_ids_follow_start_time_and_rows_follow_priority() -> None:
    rows = [window(0, "a", score=0.95), window(60, "b", score=1.0)]
    _, table, _ = incidents_of(rows)
    assert table["incident_id"].tolist() == ["tiny-0002", "tiny-0001"]
    assert table.iloc[0]["start"] == pd.Timestamp(T0 + timedelta(minutes=60))


def test_every_window_gets_its_incident_id() -> None:
    frame, table, ids = incidents_of([window(60, "b"), window(0, "a")])
    assert ids.tolist() == ["tiny-0002", "tiny-0001"]
    assert ids.index.tolist() == frame.index.tolist()
    assert set(ids) == set(table["incident_id"])


def test_no_anomalous_window_gives_no_incident() -> None:
    empty = pd.DataFrame(columns=list(window(0)))
    table, ids = group_incidents(empty, set(), 10, 60, "tiny")
    assert table.empty and ids.empty
    assert "priority" in table.columns
