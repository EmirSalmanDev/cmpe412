"""Grouping anomalous windows into incidents (plan 6.6)."""

import json
import math
from collections import Counter
from collections.abc import Iterable
from datetime import timedelta

import numpy as np
import pandas as pd

KEY = ["testbed", "host", "log_type", "window_start"]
ENTITY_COLUMNS = {"src_ips": "ip", "users": "user"}
INCIDENT_COLUMNS = [
    "incident_id",
    "start",
    "end",
    "hosts",
    "log_types",
    "src_ips",
    "users",
    "n_windows",
    "max_score",
    "mean_score",
    "priority",
    "window_keys",
]


class UnionFind:
    """Disjoint sets over the integers `0..size-1`."""

    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        """Return the representative of an item, compressing the path."""
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, first: int, second: int) -> None:
        """Merge the sets of two items."""
        self.parent[self.find(first)] = self.find(second)


def common_entities(fit_windows: pd.DataFrame, share: float) -> set[tuple[str, str]]:
    """Return the `(kind, value)` entities in more than `share` of a log type's fit windows.

    Args:
        fit_windows: The fit windows of one log type.
        share: Share of windows above which an entity is common.

    Returns:
        The common entities.
    """
    found: set[tuple[str, str]] = set()
    for column, kind in ENTITY_COLUMNS.items():
        counts = Counter(value for values in fit_windows[column] for value in set(values))
        found |= {(kind, value) for value, n in counts.items() if n / len(fit_windows) > share}
    return found


def window_entities(row: pd.Series, common: set[tuple[str, str, str]]) -> Iterable[tuple[str, str]]:
    """Yield the linking entities of a window: all but those common in its log type."""
    for column, kind in ENTITY_COLUMNS.items():
        for value in row[column]:
            if (row["log_type"], kind, value) not in common:
                yield kind, value


def link_windows(
    windows: pd.DataFrame, common: set[tuple[str, str, str]], gap: timedelta
) -> np.ndarray:
    """Return a component number per window, following the linking rule of plan 6.6.

    Two windows link when `|dt| <= gap` and they share a host or an entity. Each host and entity
    only needs a link to its previous window: anything closer in time is between the two, so
    the components are the same as with every pair.

    Args:
        windows: Anomalous windows sorted by `window_start`, with `host`, `log_type`,
            `window_start`, `src_ips` and `users`.
        common: `(log_type, kind, value)` entities that do not link.
        gap: Largest time between two linked windows.

    Returns:
        One integer per row; equal numbers mean the same incident.
    """
    sets = UnionFind(len(windows))
    last_seen: dict[tuple[str, str], int] = {}
    starts = windows["window_start"].to_list()
    for position, (_, row) in enumerate(windows.iterrows()):
        for link in [("host", row["host"]), *window_entities(row, common)]:
            previous = last_seen.get(link)
            if previous is not None and starts[position] - starts[previous] <= gap:
                sets.union(position, previous)
            last_seen[link] = position
    return np.array([sets.find(position) for position in range(len(windows))])


def priority(max_score: float, n_log_types: int, n_windows: int) -> float:
    """Return the incident priority of plan 6.6."""
    return max_score * (1 + 0.1 * (n_log_types - 1)) + 0.01 * math.log1p(n_windows)


def _ranked(values: Iterable[str]) -> list[str]:
    """Return distinct values by falling count, ties in value order."""
    counts = Counter(values)
    return sorted(counts, key=lambda value: (-counts[value], value))


def _incident(testbed: str, number: int, part: pd.DataFrame, length: timedelta) -> dict:
    """Build the row of one incident from its windows."""
    log_types = sorted(set(part["log_type"]))
    max_score = float(part["score"].max())
    keys = [
        [testbed, row.host, row.log_type, row.window_start.isoformat()] for row in part.itertuples()
    ]
    return {
        "incident_id": f"{testbed}-{number:04d}",
        "start": part["window_start"].min(),
        "end": part["window_start"].max() + length,
        "hosts": sorted(set(part["host"])),
        "log_types": log_types,
        "src_ips": _ranked(value for values in part["src_ips"] for value in values),
        "users": _ranked(value for values in part["users"] for value in values),
        "n_windows": len(part),
        "max_score": max_score,
        "mean_score": float(part["score"].mean()),
        "priority": priority(max_score, len(log_types), len(part)),
        "window_keys": json.dumps(keys),
    }


def group_incidents(
    anomalous: pd.DataFrame,
    common: set[tuple[str, str, str]],
    gap_minutes: int,
    window_seconds: int,
    testbed: str,
) -> tuple[pd.DataFrame, pd.Series]:
    """Group anomalous windows into incidents (plan 5.6, 6.6).

    Args:
        anomalous: Anomalous windows with key, `score`, `src_ips` and `users`.
        common: `(log_type, kind, value)` entities that do not link.
        gap_minutes: Largest gap between linked windows.
        window_seconds: Window length, for the incident end.
        testbed: Testbed name.

    Returns:
        The incidents, sorted by priority, and the incident id of each row of `anomalous`.
    """
    ordered = anomalous.sort_values(["window_start", "host", "log_type"])
    components = link_windows(ordered, common, timedelta(minutes=gap_minutes))
    length = timedelta(seconds=window_seconds)
    first_seen = pd.Series(components).drop_duplicates().to_list()
    rows, ids = [], pd.Series(index=ordered.index, dtype=object)
    for number, component in enumerate(first_seen, 1):
        part = ordered[components == component]
        rows.append(_incident(testbed, number, part, length))
        ids.loc[part.index] = rows[-1]["incident_id"]
    table = pd.DataFrame(rows, columns=INCIDENT_COLUMNS)
    table = table.sort_values(["priority", "incident_id"], ascending=[False, True])
    return table.reset_index(drop=True), ids.reindex(anomalous.index)
